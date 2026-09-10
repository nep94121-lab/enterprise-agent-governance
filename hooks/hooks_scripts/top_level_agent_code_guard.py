#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
top_level_agent_code_guard.py — Physical PreToolUse Hook to Block Agent Chinh from Writing Code
Strictly enforces that the Top-Level Agent (Agent Chinh) CANNOT touch source code files (.py, .js, .ts, etc.).

INVARIANTS ENFORCED:
1. Hard Block on Code Modification by Agent Chinh:
   If the caller is the Top-Level Agent (or root conversation session) and attempts to write or edit
   any source code file (.py, .js, .ts, .go, .rs, .java, .cpp, .cs), the hook TERMINATES with exit code 1 (HARD DENY).
2. Permitted Files for Agent Chinh:
   Only management and specification documents:
   - *.md (request_artifact.md, progress.md, GATE_STATUS.md, DEAD_ENDS.md, handoff.md, activity_logs/*.md, research reports)
   - *.json (configuration and metadata)
3. Delegation Enforcement:
   Forces Agent Chinh to delegate all coding and debugging to Lead PM and Dev Subagents.
"""

import os
import sys
import json
import argparse

CODE_EXTENSIONS = frozenset({
    '.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs', '.java',
    '.c', '.cpp', '.cs', '.php', '.rb', '.sh', '.ps1', '.bat'
})

ALLOWED_AGENT_CHINH_BASENAMES = frozenset({
    'progress.md', 'gate_status.md', 'dead_ends.md', 'handoff.md',
    'request_artifact.md', 'dispatch.md', 'briefing.md', 'project_memory.md'
})

def is_source_code_file(filepath: str) -> bool:
    if not filepath:
        return False
    ext = os.path.splitext(filepath)[1].lower()
    return ext in CODE_EXTENSIONS

def is_management_artifact(filepath: str) -> bool:
    if not filepath:
        return False
    norm = filepath.replace('\\', '/').lower()
    base = os.path.basename(norm)

    if base in ALLOWED_AGENT_CHINH_BASENAMES:
        return True
    if '/activity_logs/' in norm and norm.endswith('.md'):
        return True
    if norm.endswith('.md') or norm.endswith('.json') or norm.endswith('.jsonl') or norm.endswith('.yaml') or norm.endswith('.yml'):
        return True
    return False

def validate_agent_chinh_action(target_file: str, is_worker_context: bool = False) -> tuple[bool, str]:
    """
    Blocks Agent Chinh from modifying source code.
    If is_worker_context is True (i.e. called by a dedicated Dev Worker in .agents/), allowed.
    """
    if not target_file:
        return True, "No target file specified"

    # Normalize path
    norm_path = target_file.replace('\\', '/')

    # Check if this tool call originates from a dedicated Dev Worker inside .agents/
    # Dev workers operate on services/ or tests/
    if is_worker_context:
        return True, "Worker context permitted"

    # If target is source code and NOT a management doc -> HARD BLOCK!
    if is_source_code_file(norm_path):
        # Even if it's a python hook inside hooks_scripts, if Agent Chinh is manually coding it, check policy
        return False, f"❌ [PHYSICAL HOOK HARD BLOCKED]: AGENT CHÍNH BỊ CẤM TUYỆT ĐỐI TỰ VIẾT HOẶC SỬA MÃ NGUỒN ('{target_file}')! Bạn là Agent cấp cao, phải giao việc cho Lead PM và Subagents thực hiện!"

    if not is_management_artifact(norm_path):
        return False, f"❌ [PHYSICAL HOOK HARD BLOCKED]: File '{target_file}' không phải là tài liệu quản trị hợp lệ cho Agent Chính."

    return True, "PASSED: Management artifact allowed"

def run_hook():
    """Hook entry point for PreToolUse events"""
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            sys.exit(0)
        data = json.loads(raw_input)
    except Exception:
        sys.exit(0)

    tool_name = data.get("tool_name", "")
    tool_args = data.get("tool_args", {})
    context = data.get("context", {})

    # Extract target file
    target_file = tool_args.get("TargetFile") or tool_args.get("path") or tool_args.get("file_path") or ""

    # Determine if this call is from a leaf Dev Subagent or from Agent Chinh
    caller_role = context.get("role", "")
    is_worker = any(kw in caller_role.lower() for kw in ["backend", "frontend", "dev", "worker", "debugger", "patcher"])

    passed, reason = validate_agent_chinh_action(target_file, is_worker_context=is_worker)
    if not passed:
        print(f"\n{reason}\n", file=sys.stderr)
        # Emit rejection for the hook system
        rejection_response = {
            "decision": "DENY",
            "reason": reason,
            "message": reason
        }
        print(json.dumps(rejection_response))
        sys.exit(1)

    sys.exit(0)

def self_test():
    print("=== RUNNING SELF-TEST: top_level_agent_code_guard.py ===")

    # Test 1: Agent Chinh writing python service code -> HARD BLOCKED
    passed, reason = validate_agent_chinh_action("services/order_management/main.py", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 1 Failed: {reason}"
    print("Test 1 Passed: Agent Chinh writing service code is HARD BLOCKED.")

    # Test 2: Agent Chinh writing test code -> HARD BLOCKED
    passed, reason = validate_agent_chinh_action("tests/test_auth.py", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 2 Failed: {reason}"
    print("Test 2 Passed: Agent Chinh writing test code is HARD BLOCKED.")

    # Test 3: Agent Chinh writing request_artifact.md -> ALLOWED
    passed, reason = validate_agent_chinh_action(str(pathlib.Path.cwd() / "request_artifact.md"), is_worker_context=False)
    assert passed, f"Test 3 Failed: {reason}"
    print("Test 3 Passed: Agent Chinh writing request_artifact.md is allowed.")

    # Test 4: Agent Chinh writing progress.md or activity_logs -> ALLOWED
    passed, reason = validate_agent_chinh_action("activity_logs/2026-09-09.md", is_worker_context=False)
    assert passed, f"Test 4 Failed: {reason}"
    print("Test 4 Passed: Agent Chinh writing activity log is allowed.")

    # Test 5: Dev Worker writing service code -> ALLOWED
    passed, reason = validate_agent_chinh_action("services/order_management/main.py", is_worker_context=True)
    assert passed, f"Test 5 Failed: {reason}"
    print("Test 5 Passed: Dev Worker writing service code is permitted.")

    print("\nALL 5 TESTS PASSED WITH 100% SUCCESS!")
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true", help="Run automated self-tests")
    args, _ = parser.parse_known_args()

    if args.self_test:
        sys.exit(self_test())
    else:
        run_hook()
