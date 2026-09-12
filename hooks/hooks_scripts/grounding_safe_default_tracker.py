#!/usr/bin/env python3
"""
Grounding Safe Default Tracker for Enterprise Governance System.

Tracks safe default actions (such as 60s timer expiration fallbacks)
using canonical absolute file paths and atomic write operations with cross-process locking.
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass


class CrossProcessLock:
    """Robust cross-process file lock supporting Windows (msvcrt) and POSIX (fcntl)."""

    def __init__(self, lock_file: Path | str, timeout: float = 10.0):
        self.lock_file = Path(lock_file)
        self.timeout = timeout
        self.fd: int | None = None

    def __enter__(self) -> CrossProcessLock:
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(str(self.lock_file), os.O_RDWR | os.O_CREAT)
        start_time = time.monotonic()
        while True:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() - start_time > self.timeout:
                    if self.fd is not None:
                        try:
                            os.close(self.fd)
                        except OSError:
                            pass
                    self.fd = None
                    raise TimeoutError(f"Timed out waiting for file lock: {self.lock_file}")
                time.sleep(0.02)

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.fd is not None:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    os.lseek(self.fd, 0, os.SEEK_SET)
                    msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
            except OSError:
                pass
            finally:
                try:
                    os.close(self.fd)
                except OSError:
                    pass
                self.fd = None


def get_canonical_log_path(workspace_hint: str | Path | None = None) -> Path:
    """Resolve canonical absolute path for safe_defaults_log.json."""
    env_override = os.environ.get("SAFE_DEFAULTS_LOG_PATH") or os.environ.get("GROUNDING_SAFE_DEFAULTS_LOG")
    if env_override:
        return Path(env_override).resolve()

    if workspace_hint:
        return (Path(workspace_hint).resolve() / "safe_defaults_log.json").resolve()

    ws_env = os.environ.get("WORKSPACE_ROOT") or os.environ.get("PROJECT_ROOT")
    if ws_env:
        return (Path(ws_env).resolve() / "safe_defaults_log.json").resolve()

    # Enterprise hooks logs directory
    enterprise_logs = Path(__file__).resolve().parent.parent / "logs"
    if enterprise_logs.exists() and enterprise_logs.is_dir():
        return (enterprise_logs / "safe_defaults_log.json").resolve()

    return (Path.cwd().resolve() / "safe_defaults_log.json").resolve()


# Module-level LOG_FILE maintained as canonical absolute path for backward compatibility
LOG_FILE = str(get_canonical_log_path())


def log_safe_default(
    tool_name: str,
    tool_args: dict[str, Any],
    log_file: Path | str | None = None,
    workspace_hint: str | Path | None = None,
) -> Path:
    """Log safe default activation atomically under cross-process lock."""
    target_log = Path(log_file).resolve() if log_file else get_canonical_log_path(workspace_hint)
    target_log.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": "Safe Default Activated",
        "tool": tool_name,
        "args": tool_args,
        "reason": "60s timer expired without user response.",
    }

    lock_file = target_log.parent / f".{target_log.name}.lock"
    temp_file = target_log.parent / f".{target_log.name}.tmp.{os.getpid()}.{time.time_ns()}"

    with CrossProcessLock(lock_file, timeout=10.0):
        logs: list[dict[str, Any]] = []
        if target_log.exists():
            try:
                with open(target_log, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    if isinstance(loaded, list):
                        logs = loaded
                    elif isinstance(loaded, dict):
                        logs = [loaded]
            except (json.JSONDecodeError, OSError) as exc:
                # Backup corrupted file to prevent silent permanent data loss
                try:
                    backup_path = target_log.with_suffix(f".corrupted.{int(time.time())}.bak")
                    shutil.copy2(target_log, backup_path)
                    sys.stderr.write(f"[WARNING] Corrupted log file backed up to {backup_path}: {exc}\n")
                except Exception:
                    pass
                logs = []

        logs.append(entry)

        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except (OSError, AttributeError):
                    pass

            for attempt in range(10):
                try:
                    os.replace(temp_file, target_log)
                    break
                except PermissionError:
                    if attempt < 9:
                        time.sleep(0.02 * (attempt + 1))
                    else:
                        raise
        finally:
            if temp_file.exists():
                try:
                    temp_file.unlink(missing_ok=True)
                except OSError:
                    pass

    return target_log


def run_self_tests() -> bool:
    """Self-test suite for grounding_safe_default_tracker.py."""
    print("======================================================================")
    print("Running Grounding Safe Default Tracker Self-Test Suite")
    print("======================================================================\n")

    test_dir = Path(__file__).resolve().parent.parent / "tmp" / f"test_safe_default_{os.getpid()}"
    test_dir.mkdir(parents=True, exist_ok=True)
    test_log = test_dir / "safe_defaults_log.json"

    try:
        # 1. Test canonical absolute path resolution
        canon_path = get_canonical_log_path(str(test_dir))
        assert canon_path.is_absolute(), f"Path should be absolute: {canon_path}"
        assert canon_path == test_log.resolve(), f"Mismatch in canonical path: {canon_path}"
        print("[PASS] Test 1: Canonical path correctly resolved as absolute.")

        # 2. Test initial write
        written_path = log_safe_default("schedule", {"duration": 60}, log_file=test_log)
        assert written_path.exists(), "Log file was not created"
        with open(written_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert len(data) == 1, f"Expected 1 entry, got {len(data)}"
        assert data[0]["tool"] == "schedule"
        print("[PASS] Test 2: Atomic initial write created valid JSON entry.")

        # 3. Test appending subsequent records
        log_safe_default("ask_question", {"timeout": True}, log_file=test_log)
        with open(written_path, "r", encoding="utf-8") as f:
            data2 = json.load(f)
        assert len(data2) == 2, f"Expected 2 entries, got {len(data2)}"
        assert data2[1]["tool"] == "ask_question"
        print("[PASS] Test 3: Subsequent safe default correctly appended.")

        # 4. Test corruption handling / backup preservation
        with open(test_log, "w", encoding="utf-8") as f:
            f.write("{corrupted json content")
        log_safe_default("schedule", {"recovered": True}, log_file=test_log)
        with open(test_log, "r", encoding="utf-8") as f:
            data3 = json.load(f)
        assert len(data3) == 1, "Expected recovery to start clean list with new entry"
        backups = list(test_dir.glob("*.corrupted.*.bak"))
        assert len(backups) > 0, "Corrupted file backup was not created"
        print("[PASS] Test 4: Corrupted file safely backed up and recovered without crashing.")

        print("\n[SELF-TEST] grounding_safe_default_tracker.py: All tests PASSED with 100% success!")
        return True
    finally:
        if test_dir.exists():
            shutil.rmtree(test_dir, ignore_errors=True)


def main() -> None:
    if "--self-test" in sys.argv:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    event = ""
    data: dict[str, Any] = {}

    if len(sys.argv) >= 3:
        event = sys.argv[1]
        try:
            data = json.loads(sys.argv[2])
        except Exception:
            return
    else:
        try:
            max_bytes = 10 * 1024 * 1024
            raw_stdin = sys.stdin.read(max_bytes + 1)
            if len(raw_stdin) > max_bytes:
                sys.stderr.write(f"Payload exceeds limit of {max_bytes} bytes\n")
                return
            if raw_stdin.strip():
                data = json.loads(raw_stdin)
                event = str(data.get("event") or data.get("hook_event_name") or "PostToolUse")
        except Exception:
            return

    # Check for PostToolUse or PreToolUse event
    if event and event not in ("PostToolUse", "PreToolUse"):
        return

    tool_name = (
        data.get("toolName")
        or data.get("tool_name")
        or (data.get("toolCall", {}) if isinstance(data.get("toolCall"), dict) else {}).get("name")
    )
    tool_args = (
        data.get("toolArgs")
        or data.get("tool_args")
        or (data.get("toolCall", {}) if isinstance(data.get("toolCall"), dict) else {}).get("args", {})
    )
    workspace_paths = data.get("workspacePaths", [])
    workspace_hint = workspace_paths[0] if (isinstance(workspace_paths, list) and workspace_paths) else None

    if tool_name in ("schedule", "ask_question"):
        log_safe_default(str(tool_name), tool_args if isinstance(tool_args, dict) else {}, workspace_hint=workspace_hint)


if __name__ == "__main__":
    main()
