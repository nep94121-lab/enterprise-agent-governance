#!/usr/bin/env python3
"""File Ownership Guard Hook (PreToolUse) for Enterprise Multi-Agent Governance System.

Enforces Exclusive File Ownership (§EXCLUSIVE-FILE-OWNERSHIP):
1. Reads the File Ownership table from progress.md in the workspace.
2. Maps each file to its designated Subagent owner.
3. If a Worker Subagent attempts to write/modify a file owned by another Worker:
   -> HARD DENY (chặn ngay lập tức, 0 ngoại lệ theo lệnh của Sếp).
4. Eliminates 100% of race conditions and merge conflicts when multiple subagents run in parallel.
5. PM Orchestrator is permitted to modify tracking files (progress.md, GATE_STATUS.md, etc.).
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import re
import subprocess
import sys
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

if str(HOOKS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_SCRIPTS_DIR))
if str(ENTERPRISE_HOOKS_ROOT) not in sys.path:
    sys.path.insert(0, str(ENTERPRISE_HOOKS_ROOT))

from common_hook_lib import (  # noqa: E402
    emit_stdout_json,
    get_tool_args,
    get_tool_call,
    get_workspace_roots,
    log_diagnostic,
    pre_tool_response,
    read_stdin_payload,
)

MONITORED_TOOLS: frozenset[str] = frozenset({
    "write_to_file",
    "replace_file_content",
    "multi_replace_file_content",
})

TARGET_PATH_KEYS: tuple[str, ...] = (
    "TargetFile",
    "target_file",
    "filePath",
    "file_path",
    "path",
)

PM_OWNED_FILES: frozenset[str] = frozenset({
    "progress.md",
    "gate_status.md",
    "dead_ends.md",
    "handoff.md",
    "implementation_plan.md",
})


def extract_target_path(args: dict[str, Any]) -> str | None:
    """Extract raw target file path from tool arguments."""
    for k in TARGET_PATH_KEYS:
        val = args.get(k)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def normalize_identifier(val: str) -> str:
    """Normalize agent or file identifier for fuzzy matching."""
    return re.sub(r"[^a-zA-Z0-9_.]", "", val).lower()


def detect_caller_identity(payload: dict[str, Any]) -> str:
    """Detect caller identity/role from payload or environment."""
    for key in ("caller_role", "role", "subagent_name", "subagent_role"):
        v = payload.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()

    env_role = os.environ.get("AGENT_ROLE", "").strip()
    if env_role:
        return env_role

    # Check transcript first line
    conv_id = payload.get("conversationId") or os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
    if conv_id and isinstance(conv_id, str):
        brain_dir = pathlib.Path.home() / ".gemini" / "antigravity" / "brain" / conv_id / ".system_generated" / "logs"
        transcript = brain_dir / "transcript.jsonl"
        if transcript.is_file():
            try:
                with open(transcript, "r", encoding="utf-8", errors="replace") as f:
                    first_line = f.readline()
                    if first_line:
                        data = json.loads(first_line)
                        content = str(data.get("content", ""))
                        m = re.search(r"vai trò:\s*([^\n\r]+)", content, re.IGNORECASE)
                        if m:
                            return m.group(1).strip()
            except Exception as exc:
                log_diagnostic(f"Transcript inspection error in file ownership: {exc}")

    return "unknown_agent"


def parse_ownership_table(progress_path: pathlib.Path) -> dict[str, list[str]]:
    """Parse Exclusive File Ownership table or list from progress.md.

    Returns dict mapping normalized subagent role -> list of assigned filenames (normalized).
    """
    ownership: dict[str, list[str]] = {}
    if not progress_path.is_file():
        return ownership

    try:
        content = progress_path.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()

        # Parse markdown table rows: | Subagent | File(s) Owned | ... |
        in_ownership_section = False
        for line in lines:
            clean = line.strip()
            if "file ownership" in clean.lower():
                in_ownership_section = True
                continue

            # Check for list format: - worker -> file1, file2
            list_match = re.match(r"^[-*]\s*([a-zA-Z0-9_-]+)\s*(?:->|:)\s*(.+)$", clean)
            if list_match:
                agent_raw = list_match.group(1).strip()
                files_raw = list_match.group(2).strip()
                extracted_files = [
                    normalize_identifier(pathlib.Path(f.strip().strip("`").strip("'").strip('"')).name)
                    for f in re.split(r"[,;]\s*", files_raw)
                    if f.strip()
                ]
                agent_norm = normalize_identifier(agent_raw)
                ownership.setdefault(agent_norm, []).extend(extracted_files)
                continue

            # Check for table row: | Subagent | File(s) Owned | ... |
            if clean.startswith("|") and ("---" not in clean) and in_ownership_section:
                parts = [p.strip() for p in clean.split("|")[1:-1]]
                if len(parts) >= 2:
                    agent_raw = parts[0]
                    files_raw = parts[1]
                    if "subagent" in agent_raw.lower() or "worker" in agent_raw.lower():
                        continue  # header row
                    extracted_files = [
                        normalize_identifier(pathlib.Path(f.strip().strip("`").strip("'").strip('"')).name)
                        for f in re.split(r"[,;]\s*", files_raw)
                        if f.strip()
                    ]
                    agent_norm = normalize_identifier(agent_raw)
                    if agent_norm and extracted_files:
                        ownership.setdefault(agent_norm, []).extend(extracted_files)

    except Exception as exc:
        log_diagnostic(f"Error parsing ownership table from {progress_path}: {exc}")

    return ownership


def find_file_owner(target_filename: str, ownership_map: dict[str, list[str]]) -> str | None:
    """Find the designated owner of target_filename in ownership map."""
    norm_target = normalize_identifier(pathlib.Path(target_filename).name)
    for owner, files in ownership_map.items():
        if norm_target in files:
            return owner
    return None


def is_caller_owner(caller_identity: str, designated_owner: str) -> bool:
    """Fuzzy check if caller matches the designated owner."""
    c_norm = normalize_identifier(caller_identity)
    o_norm = normalize_identifier(designated_owner)

    if c_norm == o_norm:
        return True
    if c_norm in o_norm or o_norm in c_norm:
        return True

    # Common aliases (ws2 -> backend, ws1 -> devops, ws3 -> techlead, ws4 -> qa)
    alias_map = {
        "backend": "ws2",
        "devops": "ws1",
        "techlead": "ws3",
        "qa": "ws4",
    }
    for k, v in alias_map.items():
        if (k in c_norm and v in o_norm) or (k in o_norm and v in c_norm):
            return True

    return False


def evaluate_file_ownership(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate whether file modification satisfies Exclusive File Ownership."""
    if not isinstance(payload, dict):
        return pre_tool_response("allow", "Payload is not a dictionary.")

    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""

    if tool_name not in MONITORED_TOOLS:
        return pre_tool_response("allow", f"Tool '{tool_name}' is not monitored for file ownership.")

    args = get_tool_args(tool_call)
    raw_target = extract_target_path(args)
    if not raw_target:
        return pre_tool_response("allow", "No target file found in tool args.")

    target_basename = pathlib.Path(raw_target).name.lower()
    caller = detect_caller_identity(payload)
    caller_norm = normalize_identifier(caller)

    # 1. PM Orchestrator is allowed to edit tracking/management files
    is_pm = any(k in caller_norm for k in ("pm", "orchestrator", "project_manager"))
    if is_pm and (target_basename in PM_OWNED_FILES or "activity_logs" in raw_target.lower()):
        return pre_tool_response("allow", f"PM Orchestrator authorized to update tracking file '{target_basename}'.")

    # 2. Private role progress log / temporary scratch files
    if f"progress_{caller_norm}" in target_basename or "scratch" in raw_target.lower():
        return pre_tool_response("allow", "Private role progress log or scratch file permitted.")

    # 3. Locate progress.md and parse ownership table
    workspace_roots = get_workspace_roots(payload)
    progress_file: pathlib.Path | None = None
    for r in workspace_roots:
        candidate = r / "progress.md"
        if candidate.is_file():
            progress_file = candidate
            break
    if not progress_file and not payload.get("workspacePaths"):
        candidate_cwd = pathlib.Path.cwd().resolve() / "progress.md"
        if candidate_cwd.is_file():
            progress_file = candidate_cwd

    if not progress_file:
        # No progress file found -> allow (no ownership declared)
        return pre_tool_response("allow", "No progress.md found; ownership enforcement bypassed.")

    ownership_map = parse_ownership_table(progress_file)
    if not ownership_map:
        # No ownership table in progress.md -> allow
        return pre_tool_response("allow", "No ownership table declared in progress.md; write allowed.")

    designated_owner = find_file_owner(target_basename, ownership_map)
    if not designated_owner:
        # File is not declared in the exclusive ownership table -> allow
        return pre_tool_response("allow", f"File '{target_basename}' is not restricted in ownership table.")

    # 4. Check if current caller owns this file
    if is_caller_owner(caller, designated_owner):
        log_diagnostic(f"Authorized: Caller '{caller}' owns '{target_basename}'.")
        return pre_tool_response("allow", f"Caller '{caller}' is verified owner of '{target_basename}'.")

    # 5. HARD DENY - Boss's strict order (0 exceptions)
    reason = (
        "CƯỠNG CHẾ ĐỘC QUYỀN SỞ HỮU FILE (§EXCLUSIVE-FILE-OWNERSHIP): LỆNH TỪ SẾP (HARD DENY - 0 NGOẠI LỆ)!\n"
        f"Subagent '{caller}' CẤM sửa file '{raw_target}'!\n"
        f"File này đã được phân bổ độc quyền cho '{designated_owner}'.\n"
        "Mọi hành vi vi phạm ranh giới sở hữu file đều bị CHẶN NGAY LẬP TỨC để triệt tiêu 100% "
        "rủi ro Race Condition / Merge Conflict khi đa luồng chạy song song!"
    )
    log_diagnostic(f"HARD DENIED: Caller '{caller}' attempted to edit '{target_basename}' owned by '{designated_owner}'.")
    return pre_tool_response("deny", reason)


def run_self_tests() -> bool:
    """Self-test runner covering File Ownership scenarios."""
    print("======================================================================")
    print("Running File Ownership Guard Self-Test Suite")
    print("======================================================================\n")

    import tempfile
    test_results: list[tuple[str, bool, str]] = []

    def record(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        test_results.append((name, passed, detail))
        print(f"[{status}] {name}{f' - {detail}' if detail and not passed else ''}")

    with tempfile.TemporaryDirectory() as temp_dir:
        t_root = pathlib.Path(temp_dir)

        progress_content = """# Bảng Exclusive File Ownership
| Subagent | File(s) Owned | Trạng Thái |
|---|---|---|
| DevOps_WS1 | `PM_RULES.md`, `AGENTS.md` | Đang chạy |
| Backend_WS2 | `turn_1_gate_enforcer.py`, `hooks.json` | Đang chạy |
| TechLead_WS3 | `task_contract_spec.md` | Đang chạy |
| QA_WS4 | `test_turn_1.py` | Đang chạy |
"""
        (t_root / "progress.md").write_text(progress_content, encoding="utf-8")

        # TC1: Deny QA_WS4 modifying turn_1_gate_enforcer.py (owned by Backend_WS2)
        r1 = evaluate_file_ownership({
            "caller_role": "QA_WS4",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(t_root / "turn_1_gate_enforcer.py"), "CodeContent": "x"},
            },
            "workspacePaths": [str(t_root)],
        })
        record(
            "TC1: Hard DENY Worker B modifying file of Worker A",
            r1.get("decision") == "deny" and "HARD DENY" in r1.get("reason", ""),
        )

        # TC2: Allow Backend_WS2 modifying turn_1_gate_enforcer.py (assigned file)
        r2 = evaluate_file_ownership({
            "caller_role": "Backend_WS2",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(t_root / "turn_1_gate_enforcer.py"), "CodeContent": "x"},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC2: Allow Worker modifying assigned file", r2.get("decision") == "allow")

        # TC3: Allow PM Orchestrator modifying progress.md
        r3 = evaluate_file_ownership({
            "caller_role": "PM_Orchestrator",
            "toolCall": {
                "name": "replace_file_content",
                "args": {"TargetFile": str(t_root / "progress.md"), "ReplacementContent": "y"},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC3: Allow PM modifying progress.md", r3.get("decision") == "allow")

        # TC4: Allow Backend editing role progress log progress_backend_ws2.md
        r4 = evaluate_file_ownership({
            "caller_role": "Backend_WS2",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(t_root / "progress_backend_ws2.md"), "CodeContent": "log"},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC4: Allow editing role progress log", r4.get("decision") == "allow")

        # TC5: Allow when no ownership table is configured
        with tempfile.TemporaryDirectory() as empty_dir:
            e_root = pathlib.Path(empty_dir)
            r5 = evaluate_file_ownership({
                "caller_role": "Backend_WS2",
                "toolCall": {
                    "name": "write_to_file",
                    "args": {"TargetFile": str(e_root / "other.py")},
                },
                "workspacePaths": [str(e_root)],
            })
            record("TC5: Bypass when no ownership table exists", r5.get("decision") == "allow")

        # TC6: Deny Backend_WS2 modifying AGENTS.md (owned by DevOps_WS1)
        r6 = evaluate_file_ownership({
            "caller_role": "Backend_WS2",
            "toolCall": {
                "name": "replace_file_content",
                "args": {"TargetFile": str(t_root / "AGENTS.md"), "ReplacementContent": "z"},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC6: Deny Backend modifying AGENTS.md", r6.get("decision") == "deny")

        # TC7: Allow non-modifying tools (run_command, view_file)
        r7 = evaluate_file_ownership({
            "caller_role": "QA_WS4",
            "toolCall": {"name": "run_command", "args": {"CommandLine": "dir"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC7: Allow non-modifying tools", r7.get("decision") == "allow")

        # TC8: Malformed payload safety fallback
        r8 = evaluate_file_ownership({})
        record("TC8: Malformed payload safety fallback", r8.get("decision") == "allow")

        # TC9: Subprocess streaming verification
        proc = subprocess.run(
            [sys.executable, str(pathlib.Path(__file__).resolve())],
            input=json.dumps({
                "caller_role": "QA_WS4",
                "toolCall": {
                    "name": "write_to_file",
                    "args": {"TargetFile": str(t_root / "turn_1_gate_enforcer.py"), "CodeContent": "x"},
                },
                "workspacePaths": [str(t_root)],
            }),
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        sub_out = json.loads(proc.stdout) if proc.stdout.strip() else {}
        record("TC9: Subprocess streaming verification", proc.returncode == 0 and sub_out.get("decision") == "deny")

    all_passed = all(p for _, p, _ in test_results)
    total_cases = len(test_results)
    total_passed = sum(1 for _, p, _ in test_results)
    print("\n----------------------------------------------------------------------")
    print(f"Self-Test Summary: {total_passed}/{total_cases} scenarios passed ({'100%' if all_passed else 'FAILED'}).")
    print("----------------------------------------------------------------------\n")
    return all_passed


def main() -> None:
    """Main CLI entrypoint."""
    if "--self-test" in sys.argv:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    payload = read_stdin_payload(default={})
    response = evaluate_file_ownership(payload)
    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()
