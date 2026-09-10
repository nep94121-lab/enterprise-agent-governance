#!/usr/bin/env python3
"""Phase Gate Tracker Hook (PreToolUse / PostToolUse) for Enterprise Multi-Agent Governance System.

Enforces the 7-Phase Sequential Workflow (§7-PHASE-GATE-ORDER):
1. Phase 1: Discovery Gate
2. Phase 2: Exploration Gate
3. Phase 3: Questions & Edge Cases Gate
4. Phase 4: Architecture Design Gate
5. Phase 5: Implementation Gate (Dev Workers)
6. Phase 6: Quality Review & Parallel Multi-Auditor Panel Gate (QA Auditors)
7. Phase 7: Mathematical Summary & Handoff Gate (Aggregator)

Enforcement Logic:
- Gating PreToolUse on 'invoke_subagent':
  * Inspects GATE_STATUS.md in workspace roots.
  * Blocks dispatching Phase 5 Workers until Phase 1..4 are PASSED.
  * Blocks dispatching Phase 6 Reviewers/Auditors until Phase 5 is PASSED.
  * Blocks dispatching Phase 7 Aggregators until Phase 6 is PASSED.
  * Blocks any phase transition if a preceding phase is BLOCKED.
- PostToolUse returns standard empty dict {} for Antigravity lifecycle compliance.
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
    post_tool_response,
    pre_tool_response,
    read_stdin_payload,
)


def parse_gate_status(gate_status_path: pathlib.Path) -> dict[int, str]:
    """Parse GATE_STATUS.md and extract status for each phase (1 to 7).

    Returns a dict mapping phase number (1..7) to its status string:
    'PASSED', 'IN_PROGRESS', 'PENDING', 'BLOCKED'.
    """
    statuses: dict[int, str] = {}
    if not gate_status_path.is_file():
        return statuses

    try:
        content = gate_status_path.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            clean_line = line.strip()
            if not clean_line.startswith("|"):
                continue

            # Look for Phase N pattern
            m = re.search(r"Phase\s+([1-7])", clean_line, re.IGNORECASE)
            if not m:
                continue
            phase_num = int(m.group(1))

            upper_line = clean_line.upper()
            if "PASSED" in upper_line or "DONE" in upper_line or "COMPLETED" in upper_line:
                statuses[phase_num] = "PASSED"
            elif "BLOCKED" in upper_line or "FAILED" in upper_line:
                statuses[phase_num] = "BLOCKED"
            elif "IN_PROGRESS" in upper_line or "IN PROGRESS" in upper_line:
                statuses[phase_num] = "IN_PROGRESS"
            else:
                statuses[phase_num] = "PENDING"
    except Exception as exc:
        log_diagnostic(f"Error parsing GATE_STATUS.md at {gate_status_path}: {exc}")

    return statuses


def detect_target_phase(subagents: list[dict[str, Any]]) -> int:
    """Detect which phase the subagents being invoked correspond to."""
    detected_phases: list[int] = []

    for sa in subagents:
        if not isinstance(sa, dict):
            continue
        role = str(sa.get("Role", "")).lower()
        prompt = str(sa.get("Prompt", "")).lower()
        type_name = str(sa.get("TypeName", "")).lower()
        combined = f"{role} {prompt} {type_name}"

        if any(k in combined for k in ("aggregator", "summary", "handoff", "thư ký", "phase 7")):
            detected_phases.append(7)
        elif any(k in combined for k in ("qa", "review", "auditor", "challenger", "inspector", "phase 6", "kiểm toán")):
            detected_phases.append(6)
        elif any(k in combined for k in ("backend", "frontend", "devops", "developer", "implementation", "coder", "fixer", "worker", "phase 5")):
            detected_phases.append(5)
        elif any(k in combined for k in ("architecture", "thiết kế", "pipeline", "phase 4")):
            detected_phases.append(4)
        elif any(k in combined for k in ("edge case", "ca biên", "phase 3")):
            detected_phases.append(3)
        elif any(k in combined for k in ("explorer", "research", "khảo sát", "phase 2")):
            detected_phases.append(2)
        else:
            # Default to Phase 5 if worker type is self
            if type_name == "self":
                detected_phases.append(5)
            else:
                detected_phases.append(2)

    return max(detected_phases) if detected_phases else 5


def evaluate_phase_gates(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate whether invoke_subagent complies with 7 Phase Gate sequence."""
    if not isinstance(payload, dict):
        return pre_tool_response("allow", "Payload is not a dictionary.")

    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""

    if tool_name != "invoke_subagent":
        return pre_tool_response("allow", f"Tool '{tool_name}' is not invoke_subagent.")

    args = get_tool_args(tool_call)
    subagents = args.get("Subagents", [])
    if not isinstance(subagents, list) or not subagents:
        return pre_tool_response("allow", "No subagents in tool call.")

    # Locate GATE_STATUS.md in workspace roots (or fallback to CWD only if omitted)
    workspace_roots = get_workspace_roots(payload)
    gate_file: pathlib.Path | None = None
    for r in workspace_roots:
        candidate = r / "GATE_STATUS.md"
        if candidate.is_file():
            gate_file = candidate
            break
    if not gate_file and not payload.get("workspacePaths"):
        candidate_cwd = pathlib.Path.cwd().resolve() / "GATE_STATUS.md"
        if candidate_cwd.is_file():
            gate_file = candidate_cwd

    target_phase = detect_target_phase(subagents)

    # If GATE_STATUS.md is missing:
    if not gate_file:
        if target_phase in (1, 2):
            log_diagnostic("Phase 1/2 exploratory invocation permitted without GATE_STATUS.md.")
            return pre_tool_response("allow", "Exploratory invocation permitted before GATE_STATUS.md creation.")
        # Workers or Reviewers dispatched without GATE_STATUS.md is prohibited
        reason = (
            "VI PHẠM QUY TRÌNH 7 PHASE GATES (§7-PHASE-GATE-ORDER): Chưa tìm thấy file GATE_STATUS.md! "
            f"Cấm dispatch Sub-agents cho Phase {target_phase} khi chưa khởi tạo quy trình 7 Phase Gates. "
            "PM Orchestrator bắt buộc phải tạo file GATE_STATUS.md và hoàn thành các Phase khám phá/thiết kế trước."
        )
        log_diagnostic(f"BLOCKED Phase {target_phase} dispatch: Missing GATE_STATUS.md.")
        return pre_tool_response("deny", reason)

    # Parse statuses
    statuses = parse_gate_status(gate_file)

    # Check for any BLOCKED phase prior to target_phase
    for p in range(1, target_phase):
        if statuses.get(p) == "BLOCKED":
            reason = (
                f"VI PHẠM QUY TRÌNH 7 PHASE GATES (§7-PHASE-GATE-ORDER): Phase {p} đang ở trạng thái BLOCKED! "
                f"Không thể tiếp tục dispatch Sub-agents cho Phase {target_phase} khi lỗi chưa được giải quyết."
            )
            log_diagnostic(f"BLOCKED Phase {target_phase} dispatch: Phase {p} is BLOCKED.")
            return pre_tool_response("deny", reason)

    # Phase 5 (Implementation Gate) requires Phase 1..4 to be PASSED
    if target_phase == 5:
        unpassed = [p for p in range(1, 5) if statuses.get(p) != "PASSED"]
        if unpassed:
            reason = (
                f"VI PHẠM QUY TRÌNH 7 PHASE GATES (§7-PHASE-GATE-ORDER): Cấm nhảy cóc sang Phase 5 (Implementation) "
                f"khi các Phase {unpassed} chưa đạt trạng thái PASSED trong GATE_STATUS.md! "
                "PM Orchestrator bắt buộc phải hoàn thành Discovery, Exploration, Questions và Architecture trước khi viết code."
            )
            log_diagnostic(f"BLOCKED Phase 5 dispatch: Prior phases not passed: {unpassed}.")
            return pre_tool_response("deny", reason)

    # Phase 6 (Quality Review & Auditor Gate) requires Phase 5 to be PASSED
    if target_phase == 6:
        if statuses.get(5) != "PASSED":
            reason = (
                "VI PHẠM QUY TRÌNH 7 PHASE GATES (§7-PHASE-GATE-ORDER): Cấm nhảy cóc sang Phase 6 (Quality Review) "
                "khi Phase 5 (Implementation) chưa đạt trạng thái PASSED trong GATE_STATUS.md!"
            )
            log_diagnostic("BLOCKED Phase 6 dispatch: Phase 5 is not PASSED.")
            return pre_tool_response("deny", reason)

    # Phase 7 (Summary & Handoff Gate) requires Phase 6 to be PASSED
    if target_phase == 7:
        if statuses.get(6) != "PASSED":
            reason = (
                "VI PHẠM QUY TRÌNH 7 PHASE GATES (§7-PHASE-GATE-ORDER): Cấm nhảy cóc sang Phase 7 (Summary & Handoff) "
                "khi Phase 6 (Quality Review) chưa đạt trạng thái PASSED trong GATE_STATUS.md!"
            )
            log_diagnostic("BLOCKED Phase 7 dispatch: Phase 6 is not PASSED.")
            return pre_tool_response("deny", reason)

    return pre_tool_response("allow", f"Phase {target_phase} dispatch complies with 7 Phase Gate sequence.")


def run_self_tests() -> bool:
    """Self-test runner covering Phase Gate scenarios."""
    print("======================================================================")
    print("Running Phase Gate Tracker Self-Test Suite")
    print("======================================================================\n")

    import tempfile
    test_results: list[tuple[str, bool, str]] = []

    def record(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        test_results.append((name, passed, detail))
        print(f"[{status}] {name}{f' - {detail}' if detail and not passed else ''}")

    with tempfile.TemporaryDirectory() as temp_dir:
        t_root = pathlib.Path(temp_dir)

        # TC1: Missing GATE_STATUS.md -> allow exploratory subagent
        r1 = evaluate_phase_gates({
            "toolCall": {
                "name": "invoke_subagent",
                "args": {"Subagents": [{"Role": "Codebase Explorer", "TypeName": "research"}]},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC1: Allow exploratory subagent when GATE_STATUS.md missing", r1.get("decision") == "allow")

        # TC2: Missing GATE_STATUS.md -> deny Phase 5 dev worker
        r2 = evaluate_phase_gates({
            "toolCall": {
                "name": "invoke_subagent",
                "args": {"Subagents": [{"Role": "Backend Developer", "TypeName": "self"}]},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC2: Deny Phase 5 worker when GATE_STATUS.md missing", r2.get("decision") == "deny")

        # Create GATE_STATUS.md with Phase 1..3 PASSED, Phase 4 PENDING
        gate_content_pending = """# GATE STATUS
| Phase Gate | Status |
|---|---|
| Phase 1: Discovery | PASSED |
| Phase 2: Exploration | PASSED |
| Phase 3: Questions | PASSED |
| Phase 4: Architecture | PENDING |
| Phase 5: Implementation | PENDING |
| Phase 6: Quality Review | PENDING |
| Phase 7: Handoff | PENDING |
"""
        (t_root / "GATE_STATUS.md").write_text(gate_content_pending, encoding="utf-8")

        # TC3: Deny Phase 5 when Phase 4 is PENDING
        r3 = evaluate_phase_gates({
            "toolCall": {
                "name": "invoke_subagent",
                "args": {"Subagents": [{"Role": "Backend Developer", "TypeName": "self"}]},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC3: Deny Phase 5 when Phase 4 is PENDING", r3.get("decision") == "deny")

        # Update GATE_STATUS.md: Phase 1..4 PASSED
        gate_content_p4_passed = """# GATE STATUS
| Phase Gate | Status |
|---|---|
| Phase 1: Discovery | PASSED |
| Phase 2: Exploration | PASSED |
| Phase 3: Questions | PASSED |
| Phase 4: Architecture | PASSED |
| Phase 5: Implementation | IN_PROGRESS |
| Phase 6: Quality Review | PENDING |
| Phase 7: Handoff | PENDING |
"""
        (t_root / "GATE_STATUS.md").write_text(gate_content_p4_passed, encoding="utf-8")

        # TC4: Allow Phase 5 when Phase 1..4 are PASSED
        r4 = evaluate_phase_gates({
            "toolCall": {
                "name": "invoke_subagent",
                "args": {"Subagents": [{"Role": "Backend Developer", "TypeName": "self"}]},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC4: Allow Phase 5 when Phase 1..4 are PASSED", r4.get("decision") == "allow")

        # TC5: Deny Phase 6 when Phase 5 is IN_PROGRESS (not PASSED)
        r5 = evaluate_phase_gates({
            "toolCall": {
                "name": "invoke_subagent",
                "args": {"Subagents": [{"Role": "QA Auditor Panel", "TypeName": "self"}]},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC5: Deny Phase 6 when Phase 5 is not PASSED", r5.get("decision") == "deny")

        # Update GATE_STATUS.md: Phase 5 PASSED
        gate_content_p5_passed = """# GATE STATUS
| Phase Gate | Status |
|---|---|
| Phase 1: Discovery | PASSED |
| Phase 2: Exploration | PASSED |
| Phase 3: Questions | PASSED |
| Phase 4: Architecture | PASSED |
| Phase 5: Implementation | PASSED |
| Phase 6: Quality Review | IN_PROGRESS |
| Phase 7: Handoff | PENDING |
"""
        (t_root / "GATE_STATUS.md").write_text(gate_content_p5_passed, encoding="utf-8")

        # TC6: Allow Phase 6 when Phase 5 is PASSED
        r6 = evaluate_phase_gates({
            "toolCall": {
                "name": "invoke_subagent",
                "args": {"Subagents": [{"Role": "QA Auditor Panel", "TypeName": "self"}]},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC6: Allow Phase 6 when Phase 5 is PASSED", r6.get("decision") == "allow")

        # TC7: Deny when a prior phase is BLOCKED
        gate_content_blocked = """# GATE STATUS
| Phase Gate | Status |
|---|---|
| Phase 1: Discovery | PASSED |
| Phase 2: Exploration | BLOCKED |
| Phase 3: Questions | PENDING |
| Phase 4: Architecture | PENDING |
| Phase 5: Implementation | PENDING |
| Phase 6: Quality Review | PENDING |
| Phase 7: Handoff | PENDING |
"""
        (t_root / "GATE_STATUS.md").write_text(gate_content_blocked, encoding="utf-8")
        r7 = evaluate_phase_gates({
            "toolCall": {
                "name": "invoke_subagent",
                "args": {"Subagents": [{"Role": "Architecture Designer", "TypeName": "self"}]},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC7: Deny when prior phase is BLOCKED", r7.get("decision") == "deny")

        # TC8: Allow non-invoke_subagent tool (run_command)
        r8 = evaluate_phase_gates({
            "toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC8: Allow non-invoke_subagent tools", r8.get("decision") == "allow")

        # TC9: Malformed payload safety fallback
        r9 = evaluate_phase_gates({})
        record("TC9: Malformed payload safety fallback", r9.get("decision") == "allow")

        # TC10: Subprocess streaming verification
        proc = subprocess.run(
            [sys.executable, str(pathlib.Path(__file__).resolve())],
            input=json.dumps({
                "toolCall": {
                    "name": "invoke_subagent",
                    "args": {"Subagents": [{"Role": "Backend Developer", "TypeName": "self"}]},
                },
                "workspacePaths": [str(t_root)],
            }),
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        sub_out = json.loads(proc.stdout) if proc.stdout.strip() else {}
        record("TC10: Subprocess streaming verification", proc.returncode == 0 and sub_out.get("decision") == "deny")

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

    if "--post" in sys.argv:
        emit_stdout_json(post_tool_response())
        sys.exit(0)

    payload = read_stdin_payload(default={})
    response = evaluate_phase_gates(payload)
    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()
