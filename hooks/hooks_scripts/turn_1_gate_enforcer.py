#!/usr/bin/env python3
"""Turn-1 Gate Enforcer Hook (PreToolUse) for Enterprise Multi-Agent Governance System.

Enforces the Zero-Tolerance Turn-1 Action Gate:
1. Every agent (Top-Level Agent, PM Orchestrator, Dev Sub-agent) MUST view its designated rules
   file before calling any modifying or technical tools.
2. The agent MUST record 'CANARY_VERIFIED: [TOKEN]' in line 1 of progress.md (or role progress file).
3. Any tool call (except viewing a rules file, or writing CANARY_VERIFIED to progress.md) is
   STRICTLY DENIED until Turn-1 verification is confirmed.
"""

from __future__ import annotations

import io
import json
import os
import pathlib
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

RULES_FILE_NAMES: frozenset[str] = frozenset({
    "agents.md",
    "pm_rules.md",
    "backend_rules.md",
    "frontend_rules.md",
    "qa_rules.md",
    "tech_lead_rules.md",
    "devops_rules.md",
})

RULES_PATH_PATTERNS: tuple[str, ...] = (
    "rules_by_role",
    "config/rules",
    "config\\rules",
    "enterprise-hooks/rules",
    "enterprise-hooks\\rules",
)


def is_rules_file(target_path_str: str | None) -> bool:
    """Check if target path is a recognized rules file."""
    if not target_path_str or not isinstance(target_path_str, str):
        return False
    norm = target_path_str.strip().replace("\\", "/").lower()
    name = pathlib.Path(norm).name
    if name in RULES_FILE_NAMES:
        return True
    return any(pat in norm for pat in RULES_PATH_PATTERNS) and norm.endswith(".md")


def extract_target_path(args: dict[str, Any]) -> str | None:
    """Extract target file path from tool arguments."""
    for key in ("AbsolutePath", "TargetFile", "target_file", "filePath", "file_path", "path"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def check_canary_in_file(file_path: pathlib.Path) -> bool:
    """Check if file exists and starts with CANARY_VERIFIED."""
    try:
        if not file_path.is_file():
            return False
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for _ in range(5):
                line = f.readline()
                if not line:
                    break
                if "CANARY_VERIFIED:" in line:
                    return True
        return False
    except Exception as exc:
        log_diagnostic(f"Error reading progress file {file_path}: {exc}")
        return False


def has_turn_1_verified(
    workspace_roots: list[pathlib.Path],
    payload: dict[str, Any],
) -> bool:
    """Verify whether Turn-1 gate has been satisfied via files or transcript."""
    # 1. Check environment / payload override for test injection
    if payload.get("canary_verified") is True:
        return True
    if os.environ.get("CANARY_VERIFIED") == "1":
        return True

    # 2. Check progress files in workspace roots (or fallback to CWD only if omitted)
    if workspace_roots:
        check_dirs = list(workspace_roots)
    else:
        check_dirs = [pathlib.Path.cwd().resolve()]

    for root_dir in check_dirs:
        # Check standard progress.md
        std_progress = root_dir / "progress.md"
        if check_canary_in_file(std_progress):
            return True

        # Check progress_*.md in root
        try:
            for p_file in root_dir.glob("progress_*.md"):
                if check_canary_in_file(p_file):
                    return True
        except Exception:
            pass

    return False


def evaluate_turn_1_gate(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate if tool call complies with Turn-1 Gate."""
    if not isinstance(payload, dict):
        return pre_tool_response("allow", "Payload is not a dictionary.")

    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""
    if not isinstance(tool_name, str) or not tool_name:
        return pre_tool_response("allow", "Invalid tool call.")

    args = get_tool_args(tool_call)
    target_path_str = extract_target_path(args)

    # 1. Viewing rules file is ALWAYS allowed at Turn 1
    if tool_name == "view_file" and is_rules_file(target_path_str):
        return pre_tool_response("allow", "Viewing rules file is permitted for Turn-1 Gate.")

    # 2. Writing CANARY_VERIFIED to progress.md is permitted
    if tool_name in ("write_to_file", "replace_file_content", "multi_replace_file_content"):
        content = str(args.get("CodeContent", "") or args.get("ReplacementContent", ""))
        if target_path_str:
            t_name = pathlib.Path(target_path_str).name.lower()
            if ("progress" in t_name and t_name.endswith(".md")) and ("CANARY_VERIFIED:" in content):
                return pre_tool_response("allow", "Recording CANARY_VERIFIED into progress file is permitted.")

    # 3. Check if Turn-1 has been verified
    workspace_roots = get_workspace_roots(payload)
    if has_turn_1_verified(workspace_roots, payload):
        return pre_tool_response("allow", "Turn-1 Gate verified (CANARY_VERIFIED active).")

    # 4. Deny everything else with actionable instructions
    reason = (
        "CỔNG BẮT BUỘC TURN 1 (ENFORCED TURN-1 ACTION GATE): Thao tác bị CHẶN! Bạn chưa hoàn thành thủ tục Turn 1:\n"
        "1. BẮT BUỘC dùng công cụ 'view_file' mở đọc toàn văn tệp quy tắc chuyên môn (AGENTS.md / PM_RULES.md / BACKEND_RULES.md...).\n"
        "2. Trích xuất CANARY_TOKEN và ghi nhận 'CANARY_VERIFIED: [TOKEN]' vào dòng đầu tiên của progress.md.\n"
        "Mọi hành động gọi tool kỹ thuật, viết code, sửa file hoặc chạy lệnh đều bị từ chối cho đến khi hoàn tất 2 bước trên!"
    )
    log_diagnostic(f"BLOCKED tool '{tool_name}' at Turn-1 Gate: Canary not verified.")
    return pre_tool_response("deny", reason)


def run_self_tests() -> bool:
    """Self-test runner covering Turn-1 scenarios."""
    print("======================================================================")
    print("Running Turn-1 Gate Enforcer Self-Test Suite")
    print("======================================================================\n")

    import tempfile
    test_results: list[tuple[str, bool, str]] = []

    def record(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        test_results.append((name, passed, detail))
        print(f"[{status}] {name}{f' - {detail}' if detail and not passed else ''}")

    with tempfile.TemporaryDirectory() as temp_dir:
        t_root = pathlib.Path(temp_dir)

        # TC1: Deny write_to_file on app.py before canary
        r1 = evaluate_turn_1_gate({
            "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(t_root / "app.py"), "CodeContent": "print(1)"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC1: Deny write_to_file before canary", r1.get("decision") == "deny")

        # TC2: Allow view_file on BACKEND_RULES.md
        r2 = evaluate_turn_1_gate({
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": "C:/rules/BACKEND_RULES.md"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC2: Allow view_file on rules file", r2.get("decision") == "allow")

        # TC3: Deny run_command before canary
        r3 = evaluate_turn_1_gate({
            "toolCall": {"name": "run_command", "args": {"CommandLine": "dir"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC3: Deny run_command before canary", r3.get("decision") == "deny")

        # TC4: Allow write_to_file on progress.md with CANARY_VERIFIED
        r4 = evaluate_turn_1_gate({
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(t_root / "progress.md"),
                    "CodeContent": "CANARY_VERIFIED: CANARY-TEST-123\n# Progress",
                },
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC4: Allow write_to_file on progress.md with CANARY_VERIFIED", r4.get("decision") == "allow")

        # Create progress.md on disk with canary token
        (t_root / "progress.md").write_text("CANARY_VERIFIED: CANARY-TEST-123\n# Progress", encoding="utf-8")

        # TC5: Allow write_to_file on app.py after canary
        r5 = evaluate_turn_1_gate({
            "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(t_root / "app.py"), "CodeContent": "print(1)"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC5: Allow write_to_file after canary", r5.get("decision") == "allow")

        # TC6: Allow run_command after canary
        r6 = evaluate_turn_1_gate({
            "toolCall": {"name": "run_command", "args": {"CommandLine": "pytest"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC6: Allow run_command after canary", r6.get("decision") == "allow")

        # TC7: Allow view_file on AGENTS.md
        r7 = evaluate_turn_1_gate({
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": "C:/config/rules/AGENTS.md"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC7: Allow view_file on AGENTS.md", r7.get("decision") == "allow")

        # TC8: Allow view_file on PM_RULES.md
        r8 = evaluate_turn_1_gate({
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": "C:/rules_by_role/pm_orchestrator/PM_RULES.md"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC8: Allow view_file on PM_RULES.md", r8.get("decision") == "allow")

        # TC9: In an unverified workspace, deny view_file on non-rules file
        with tempfile.TemporaryDirectory() as empty_dir:
            e_root = pathlib.Path(empty_dir)
            r9 = evaluate_turn_1_gate({
                "toolCall": {"name": "view_file", "args": {"AbsolutePath": str(e_root / "secret.txt")}},
                "workspacePaths": [str(e_root)],
            })
            record("TC9: Deny view_file on secret.txt before canary", r9.get("decision") == "deny")

            # TC10: Deny invoke_subagent before canary
            r10 = evaluate_turn_1_gate({
                "toolCall": {"name": "invoke_subagent", "args": {"Subagents": [{"Role": "Dev", "TypeName": "self"}]}},
                "workspacePaths": [str(e_root)],
            })
            record("TC10: Deny invoke_subagent before canary", r10.get("decision") == "deny")

            # TC11: Deny replace_file_content before canary
            r11 = evaluate_turn_1_gate({
                "toolCall": {"name": "replace_file_content", "args": {"TargetFile": str(e_root / "main.py")}},
                "workspacePaths": [str(e_root)],
            })
            record("TC11: Deny replace_file_content before canary", r11.get("decision") == "deny")

        # TC12: Allow invoke_subagent after canary
        r12 = evaluate_turn_1_gate({
            "toolCall": {"name": "invoke_subagent", "args": {"Subagents": [{"Role": "Dev", "TypeName": "self"}]}},
            "workspacePaths": [str(t_root)],
        })
        record("TC12: Allow invoke_subagent after canary", r12.get("decision") == "allow")

        # TC13: Malformed payload safety fallback
        r13 = evaluate_turn_1_gate({})
        record("TC13: Malformed payload safety fallback", r13.get("decision") == "allow")

        # TC14: Override via canary_verified in payload
        r14 = evaluate_turn_1_gate({
            "toolCall": {"name": "run_command", "args": {"CommandLine": "echo 1"}},
            "canary_verified": True,
        })
        record("TC14: Direct payload canary_verified flag", r14.get("decision") == "allow")

        # TC15: Subprocess execution check
        proc = subprocess.run(
            [sys.executable, str(pathlib.Path(__file__).resolve())],
            input=json.dumps({
                "toolCall": {"name": "run_command", "args": {"CommandLine": "whoami"}},
                "workspacePaths": [tempfile.gettempdir()],
            }),
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        sub_out = json.loads(proc.stdout) if proc.stdout.strip() else {}
        record("TC15: Subprocess execution streaming", proc.returncode == 0 and "decision" in sub_out)

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
    response = evaluate_turn_1_gate(payload)
    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()
