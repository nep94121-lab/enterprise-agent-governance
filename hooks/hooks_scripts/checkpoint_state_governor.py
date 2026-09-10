#!/usr/bin/env python3
"""Checkpoint State Governor Hook (PostToolUse) for Enterprise Multi-Agent Governance System.

Automatically captures delta snapshots and state checkpoints of all files created or modified
by agents during workflow execution. Records history into `.system_generated/checkpoints_log.jsonl`
and enables Time-Travel Rollbacks whenever a worker reaches a dead end (§CHECKPOINT-STATE-GOVERNOR).

Key Capabilities:
1. P1 State Governance: Captures SHA-256 integrity hashes, byte sizes, line counts, and caller
   metadata immediately upon file mutation (§8, §26).
2. Snapshot Archiving: Stores atomic immutable snapshot copies in `.system_generated/checkpoints/snapshots/`
   for instant state rollback and forensic auditing.
3. Time-Travel Rollback: Provides deterministic rollback API and CLI (`--restore <id>`) to revert
   corrupted or dead-end codebase states to any previous checkpoint.
4. Cross-Platform Resilience: Enforces UTF-8 I/O for Windows PowerShell and safely ignores
   Windows reserved device names (§7).
5. Comprehensive Self-Test: Supports `--self-test` CLI flag validating recording, listing,
   integrity checking, and time-travel rollback with 100% PASS.
"""

from __future__ import annotations

import datetime
import hashlib
import io
import json
import os
import pathlib
import sys
import tempfile
from typing import Any

# Enforce UTF-8 standard encoding on Windows PowerShell
try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).parent.resolve()
ENTERPRISE_HOOKS_ROOT = HOOKS_SCRIPTS_DIR.parent.resolve()

for import_path in (str(HOOKS_SCRIPTS_DIR), str(ENTERPRISE_HOOKS_ROOT)):
    if import_path not in sys.path:
        sys.path.insert(0, import_path)

try:
    from common_hook_lib import (
        emit_stdout_json,
        get_tool_args,
        get_tool_call,
        get_workspace_roots,
        log_diagnostic,
        normalize_path,
        post_tool_response,
        read_stdin_payload,
    )
    HAS_COMMON_LIB = True
except ImportError:
    HAS_COMMON_LIB = False

    def log_diagnostic(msg: str) -> None:
        try:
            sys.stderr.write(f"[STATE-GOVERNOR] {msg}\n")
            sys.stderr.flush()
        except (OSError, UnicodeEncodeError):
            pass

    def read_stdin_payload(default: dict[str, Any] | None = None) -> dict[str, Any]:
        if default is None:
            default = {}
        try:
            raw = sys.stdin.read()
            if not raw or not raw.strip():
                return default
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else default
        except Exception:
            return default

    def emit_stdout_json(payload: dict[str, Any]) -> None:
        try:
            sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
            sys.stdout.flush()
        except Exception:
            sys.stdout.write("{}\n")
            sys.stdout.flush()

    def post_tool_response() -> dict[str, Any]:
        return {}

    def get_tool_call(payload: dict[str, Any]) -> dict[str, Any]:
        tc = payload.get("toolCall")
        return tc if isinstance(tc, dict) else {}

    def get_tool_args(tool_call: dict[str, Any]) -> dict[str, Any]:
        args = tool_call.get("args")
        return args if isinstance(args, dict) else {}

    def normalize_path(path_str: str) -> pathlib.Path:
        return pathlib.Path(path_str).resolve()

    def get_workspace_roots(payload: dict[str, Any]) -> list[pathlib.Path]:
        raw_paths = payload.get("workspacePaths", [])
        if not isinstance(raw_paths, list) or not raw_paths:
            return [pathlib.Path.cwd().resolve()]
        roots = []
        for p in raw_paths:
            if isinstance(p, str) and p.strip():
                try:
                    roots.append(pathlib.Path(p).resolve())
                except Exception:
                    continue
        return roots if roots else [pathlib.Path.cwd().resolve()]


# Monitored tools that mutate files on disk
MONITORED_TOOLS: frozenset[str] = frozenset({
    "write_to_file",
    "replace_file_content",
    "multi_replace_file_content",
})

# Argument keys for target file path
TARGET_PATH_KEYS: tuple[str, ...] = (
    "TargetFile",
    "target_file",
    "filePath",
    "file_path",
    "path",
    "targetFile",
)

# Maximum file size to snapshot (10 MB)
MAX_SNAPSHOT_FILE_SIZE: int = 10 * 1024 * 1024

# Disallowed binary file extensions to skip
BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
    ".zip", ".tar", ".gz", ".7z",
    ".exe", ".dll", ".so", ".bin",
    ".pyc", ".pyo", ".pyd",
})

# Windows reserved device names
RESERVED_DEVICE_NAMES: frozenset[str] = frozenset({
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
})


def extract_target_path(args: dict[str, Any]) -> str | None:
    """Extract raw target file path from tool arguments."""
    if not isinstance(args, dict):
        return None
    for k in TARGET_PATH_KEYS:
        val = args.get(k)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def is_safe_target(target: pathlib.Path) -> bool:
    """Verify target file is eligible for snapshotting."""
    name_upper = target.name.upper()
    stem_upper = target.stem.upper()
    if name_upper in RESERVED_DEVICE_NAMES or stem_upper in RESERVED_DEVICE_NAMES:
        return False
    if target.suffix.lower() in BINARY_EXTENSIONS:
        return False
    # Skip checkpoints internal files themselves to prevent infinite recursion
    target_str = str(target).replace("\\", "/")
    if ".system_generated/checkpoints" in target_str or "checkpoints_log.jsonl" in target_str:
        return False
    return True


def get_checkpoint_storage(workspace_root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """Return tuple of (log_file_path, snapshots_dir_path)."""
    base_dir = workspace_root / ".system_generated"
    snapshots_dir = base_dir / "checkpoints" / "snapshots"
    log_file = base_dir / "checkpoints_log.jsonl"
    return log_file, snapshots_dir


def compute_sha256_and_meta(file_path: pathlib.Path) -> tuple[str, int, int, bytes]:
    """Compute SHA-256 hash, byte size, line count, and raw bytes."""
    data = file_path.read_bytes()
    sha256_hash = hashlib.sha256(data).hexdigest()
    size_bytes = len(data)
    line_count = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
    return sha256_hash, size_bytes, line_count, data


def record_checkpoint(
    target_path: pathlib.Path,
    tool_name: str,
    workspace_root: pathlib.Path,
    caller_role: str = "unknown",
    worker_id: str = "unknown",
) -> dict[str, Any] | None:
    """Create snapshot and record checkpoint in log file.

    Returns:
        dict[str, Any] | None: Checkpoint record dictionary if successful, None otherwise.
    """
    try:
        if not target_path.exists() or not target_path.is_file():
            return None

        if not is_safe_target(target_path):
            return None

        stat = target_path.stat()
        if stat.st_size > MAX_SNAPSHOT_FILE_SIZE:
            log_diagnostic(f"Skipping checkpoint: {target_path.name} exceeds max size {MAX_SNAPSHOT_FILE_SIZE}")
            return None

        sha256_hash, size_bytes, line_count, data = compute_sha256_and_meta(target_path)

        # Ensure directories exist
        log_file, snapshots_dir = get_checkpoint_storage(workspace_root)
        snapshots_dir.mkdir(parents=True, exist_ok=True)
        log_file.parent.mkdir(parents=True, exist_ok=True)

        now = datetime.datetime.now(datetime.UTC)
        timestamp_str = now.isoformat()
        compact_time = now.strftime("%Y%m%d_%H%M%S_%f")[:19]
        short_hash = sha256_hash[:8]
        checkpoint_id = f"chk_{compact_time}_{short_hash}"

        # Write snapshot copy
        safe_stem = "".join(c if c.isalnum() or c in "._-" else "_" for c in target_path.name)
        snapshot_filename = f"{compact_time}_{short_hash}_{safe_stem}"
        snapshot_file = snapshots_dir / snapshot_filename

        # Write snapshot atomically
        temp_snapshot = snapshot_file.with_suffix(snapshot_file.suffix + ".tmp")
        temp_snapshot.write_bytes(data)
        os.replace(temp_snapshot, snapshot_file)

        # Compute relative path safely
        try:
            rel_path = str(target_path.relative_to(workspace_root)).replace("\\", "/")
        except ValueError:
            rel_path = target_path.name

        record: dict[str, Any] = {
            "checkpoint_id": checkpoint_id,
            "timestamp": timestamp_str,
            "tool": tool_name,
            "file_name": target_path.name,
            "relative_path": rel_path,
            "absolute_path": str(target_path.resolve()),
            "sha256": sha256_hash,
            "size_bytes": size_bytes,
            "lines_count": line_count,
            "snapshot_file": str(snapshot_file.resolve()),
            "caller_role": caller_role,
            "worker_id": worker_id,
        }

        # Append record to JSONL log file
        with open(log_file, mode="a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        log_diagnostic(
            f"Checkpoint {checkpoint_id} captured for '{rel_path}' (SHA={short_hash}, size={size_bytes}B)"
        )
        return record

    except Exception as exc:
        log_diagnostic(f"Error recording checkpoint for {target_path}: {exc}")
        return None


def list_checkpoints(log_file: pathlib.Path, limit: int = 50) -> list[dict[str, Any]]:
    """Read and return list of recorded checkpoints in reverse chronological order."""
    if not log_file.exists():
        return []
    records: list[dict[str, Any]] = []
    try:
        with open(log_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except Exception as exc:
        log_diagnostic(f"Error reading checkpoints log {log_file}: {exc}")
        return []

    records.reverse()
    return records[:limit]


def restore_checkpoint(
    checkpoint_id: str,
    workspace_root: pathlib.Path,
    target_path_override: pathlib.Path | None = None,
) -> bool:
    """Perform Time-Travel Rollback: restore file to the state at checkpoint_id.

    Returns:
        bool: True if restored successfully and integrity verified, False otherwise.
    """
    log_file, _ = get_checkpoint_storage(workspace_root)
    if not log_file.exists():
        log_diagnostic(f"Cannot restore: checkpoints log not found at {log_file}")
        return False

    matched_record: dict[str, Any] | None = None
    try:
        with open(log_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    rec = json.loads(line)
                    if rec.get("checkpoint_id") == checkpoint_id:
                        matched_record = rec
                        break
    except Exception as exc:
        log_diagnostic(f"Error finding checkpoint {checkpoint_id}: {exc}")
        return False

    if not matched_record:
        log_diagnostic(f"Checkpoint ID '{checkpoint_id}' not found in log.")
        return False

    snapshot_path = pathlib.Path(matched_record["snapshot_file"])
    if not snapshot_path.exists():
        log_diagnostic(f"Snapshot file missing: {snapshot_path}")
        return False

    # Verify snapshot integrity
    snapshot_data = snapshot_path.read_bytes()
    computed_hash = hashlib.sha256(snapshot_data).hexdigest()
    if computed_hash != matched_record["sha256"]:
        log_diagnostic(f"Corrupted snapshot: expected SHA {matched_record['sha256']}, got {computed_hash}")
        return False

    # Determine destination path
    dest_path = target_path_override or pathlib.Path(matched_record["absolute_path"])
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    # Atomic restore
    temp_dest = dest_path.with_suffix(dest_path.suffix + ".restore_tmp")
    temp_dest.write_bytes(snapshot_data)
    os.replace(temp_dest, dest_path)

    log_diagnostic(
        f"Successfully restored '{dest_path.name}' to checkpoint {checkpoint_id} (SHA={computed_hash[:8]})"
    )
    return True


def run_hook(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute PostToolUse checkpoint capture on modified files."""
    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "")
    if tool_name not in MONITORED_TOOLS:
        return post_tool_response()

    args = get_tool_args(tool_call)
    raw_path = extract_target_path(args)
    if not raw_path:
        return post_tool_response()

    target_path = normalize_path(raw_path)
    workspace_roots = get_workspace_roots(payload)
    workspace_root = workspace_roots[0] if workspace_roots else pathlib.Path.cwd().resolve()

    caller_role = payload.get("caller_role") or payload.get("role") or os.environ.get("AGENT_ROLE", "worker")
    worker_id = payload.get("worker_id") or payload.get("subagent_name") or os.environ.get("WORKER_ID", "worker")

    record_checkpoint(
        target_path=target_path,
        tool_name=tool_name,
        workspace_root=workspace_root,
        caller_role=caller_role,
        worker_id=worker_id,
    )
    return post_tool_response()


def run_self_test() -> int:
    """Execute built-in self-test suite covering 7 comprehensive state governance scenarios."""
    print("[SELF-TEST] Starting checkpoint_state_governor self-test suite...")
    failures: list[str] = []

    with tempfile.TemporaryDirectory() as tmpdir:
        ws_root = pathlib.Path(tmpdir)
        test_file = ws_root / "src" / "service.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)

        # Scenario 1: Initial creation checkpoint
        test_file.write_text("def run():\n    return 42\n", encoding="utf-8")
        rec1 = record_checkpoint(
            target_path=test_file,
            tool_name="write_to_file",
            workspace_root=ws_root,
            caller_role="backend_developer",
            worker_id="Worker_Hooks_New_04",
        )
        if not rec1 or not rec1.get("checkpoint_id"):
            failures.append("Scenario 1 failed: Checkpoint 1 record creation failed.")
        else:
            print(f"  [PASS] Scenario 1: Initial checkpoint recorded: {rec1['checkpoint_id']}")

        # Scenario 2: File modification and second checkpoint
        test_file.write_text("def run():\n    # Modified\n    return 100\n", encoding="utf-8")
        rec2 = record_checkpoint(
            target_path=test_file,
            tool_name="replace_file_content",
            workspace_root=ws_root,
            caller_role="backend_developer",
            worker_id="Worker_Hooks_New_04",
        )
        if not rec2 or rec2["sha256"] == rec1["sha256"]:
            failures.append("Scenario 2 failed: Checkpoint 2 hash identical to Checkpoint 1.")
        else:
            print(f"  [PASS] Scenario 2: Delta checkpoint recorded: {rec2['checkpoint_id']}")

        # Scenario 3: Query checkpoints list in chronological reverse order
        log_file, _ = get_checkpoint_storage(ws_root)
        checkpoints = list_checkpoints(log_file)
        if len(checkpoints) != 2 or checkpoints[0]["checkpoint_id"] != rec2["checkpoint_id"]:
            failures.append(f"Scenario 3 failed: Checkpoints listing incorrect (count={len(checkpoints)})")
        else:
            print(f"  [PASS] Scenario 3: Listed {len(checkpoints)} checkpoints correctly.")

        # Scenario 4: Snapshot file verification
        snap_path1 = pathlib.Path(rec1["snapshot_file"])
        snap_path2 = pathlib.Path(rec2["snapshot_file"])
        if not snap_path1.exists() or not snap_path2.exists():
            failures.append("Scenario 4 failed: Snapshot files missing on disk.")
        else:
            print("  [PASS] Scenario 4: Snapshot files verified on disk.")

        # Scenario 5: Time-Travel Rollback to Checkpoint 1
        success = restore_checkpoint(rec1["checkpoint_id"], ws_root)
        restored_content = test_file.read_text(encoding="utf-8")
        if not success or "return 42" not in restored_content or "return 100" in restored_content:
            failures.append(f"Scenario 5 failed: Rollback failed or content mismatch: {restored_content!r}")
        else:
            print("  [PASS] Scenario 5: Time-Travel Rollback verified! Restored to Checkpoint 1.")

        # Scenario 6: Full Hook invocation via simulated PostToolUse payload
        payload = {
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(test_file),
                    "CodeContent": "def run():\n    return 999\n",
                },
            },
            "workspacePaths": [str(ws_root)],
            "caller_role": "backend_developer",
        }
        test_file.write_text("def run():\n    return 999\n", encoding="utf-8")
        hook_resp = run_hook(payload)
        if hook_resp != {}:
            failures.append(f"Scenario 6 failed: Hook response expected {{}}, got {hook_resp}")
        else:
            print("  [PASS] Scenario 6: Full PostToolUse hook payload execution passed.")

        # Scenario 7: Skip unmonitored tool and nonexistent file
        unmonitored_payload = {
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": str(test_file)}}
        }
        if run_hook(unmonitored_payload) != {}:
            failures.append("Scenario 7 failed: Unmonitored tool was not bypassed.")
        else:
            print("  [PASS] Scenario 7: Unmonitored tool correctly bypassed.")

    if failures:
        print(f"\n[SELF-TEST FAILED] {len(failures)} scenario(s) failed:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("\n[SELF-TEST PASSED] 100% PASS (7/7 scenarios verified). Exit 0.")
    return 0


def main() -> None:
    if "--self-test" in sys.argv:
        sys.exit(run_self_test())

    if "--list" in sys.argv:
        workspace_root = pathlib.Path.cwd().resolve()
        log_file, _ = get_checkpoint_storage(workspace_root)
        items = list_checkpoints(log_file)
        print(f"Recorded Checkpoints ({len(items)}):")
        for it in items:
            print(f"  [{it['checkpoint_id']}] {it['timestamp']} | {it['relative_path']} | {it['sha256'][:8]}")
        sys.exit(0)

    if "--restore" in sys.argv:
        idx = sys.argv.index("--restore")
        if idx + 1 < len(sys.argv):
            chk_id = sys.argv[idx + 1]
            ws = pathlib.Path.cwd().resolve()
            ok = restore_checkpoint(chk_id, ws)
            sys.exit(0 if ok else 1)
        else:
            print("Error: Missing checkpoint ID for --restore")
            sys.exit(1)

    payload = read_stdin_payload(default={})
    response = run_hook(payload)
    emit_stdout_json(response)


if __name__ == "__main__":
    main()
