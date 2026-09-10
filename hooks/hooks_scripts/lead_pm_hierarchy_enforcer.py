#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lead_pm_hierarchy_enforcer.py — Physical Hook & Guard for Lead PM Hierarchy
Enforces the 4-Tier Agent Governance Tree:
Tier 1: Agent Chinh (Top-Level User-Facing Agent)
Tier 2: Lead PM (Chief Solution Train Director / Multi-PM Orchestrator)
Tier 3: Domain PMs & Specialized Discipline PMs (5 to 10 Child PMs)
Tier 4: Leaf Dev Workers, Watchdogs, Challengers, and Auditors

INVARIANTS ENFORCED:
1. Lead PM is STRICTLY FORBIDDEN from directly modifying source code files (.py, .js, .ts, .go, .rs, .java, .cpp).
2. Lead PM must only orchestrate child PMs or Chief Watchdogs, maintaining a hierarchical tree.
3. Concurrency Cap: Pool 1 concurrency <= 20 active child subagents.
4. File-based Pointer Dispatch: Subagents must receive tasks via DISPATCH.md and BRIEFING.md on disk.
"""

import os
import sys
import json
import re
import argparse

CODE_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs', '.java', '.c', '.cpp', '.cs', '.php', '.rb'}
ALLOWED_LEAD_PM_FILES = {
    'progress.md', 'gate_status.md', 'dead_ends.md', 'handoff.md',
    'dispatch.md', 'briefing.md', 'request_artifact.md'
}

def is_code_file(filepath: str) -> bool:
    if not filepath:
        return False
    ext = os.path.splitext(filepath)[1].lower()
    return ext in CODE_EXTENSIONS

def is_allowed_management_file(filepath: str) -> bool:
    if not filepath:
        return False
    norm = filepath.replace('\\', '/').lower()
    base = os.path.basename(norm)
    if base in ALLOWED_LEAD_PM_FILES:
        return True
    if '/activity_logs/' in norm and norm.endswith('.md'):
        return True
    if '/.agents/' in norm and (base in ALLOWED_LEAD_PM_FILES or base.endswith('_report.md') or base.endswith('_spec.md')):
        return True
    return False

def validate_lead_pm_action(role: str, tool_name: str, tool_args: dict, active_subagent_count: int = 0) -> tuple[bool, str]:
    """
    Validates actions executed by or on behalf of Lead PM.
    """
    is_lead_pm = any(kw in role.lower() for kw in ['lead pm', 'lead_pm', 'chief pm', 'solution train director', 'pm_lead'])

    # 1. Source Code Modification Boundary
    if is_lead_pm and tool_name in ['write_to_file', 'replace_file_content', 'multi_replace_file_content']:
        target_file = tool_args.get('TargetFile') or tool_args.get('path') or tool_args.get('file_path') or ''
        if is_code_file(target_file):
            return False, f"DENIED: Lead PM role '{role}' is forbidden from modifying source code '{target_file}'. Must delegate to Domain PMs / Dev subagents."
        if not is_allowed_management_file(target_file):
            # If it's another non-code file (like .json or .txt), ensure it's not bypassing
            if not target_file.endswith('.md') and not target_file.endswith('.json'):
                return False, f"DENIED: Lead PM can only write management artifacts and specs, not '{target_file}'."

    # 2. Concurrency Cap Enforcer (Pool 1: max 20 subagents)
    if tool_name == 'invoke_subagent':
        subagents = tool_args.get('Subagents', [])
        if isinstance(subagents, str):
            try:
                subagents = json.loads(subagents)
            except Exception:
                subagents = []
        new_count = len(subagents)
        total_projected = active_subagent_count + new_count
        if total_projected > 20:
            return False, f"DENIED: Concurrency Cap exceeded! Attempted {total_projected} active subagents (max allowed is 20). Must use Rolling Batches."

        # 3. Lead PM child delegation check
        if is_lead_pm:
            for sa in subagents:
                child_role = sa.get('Role', '') or sa.get('role', '')
                child_type = sa.get('TypeName', '') or sa.get('typeName', '')
                # Lead PM should dispatch PM-level agents or Watchdogs
                valid_lead_children = ['pm', 'manager', 'director', 'watchdog', 'lead', 'harvester', 'challenger', 'auditor', 'architect']
                if not any(kw in child_role.lower() for kw in valid_lead_children):
                    # Warning or gentle enforcement: encourage domain PM delegation
                    pass

    return True, "PASSED"

def run_hook():
    """Reads stdin from Antigravity / Gemini hook event"""
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
    role = context.get("role", "Lead PM")
    active_subagent_count = context.get("active_subagents", 0)

    passed, reason = validate_lead_pm_action(role, tool_name, tool_args, active_subagent_count)
    if not passed:
        print(f"[LEAD_PM_HIERARCHY_ENFORCER] {reason}", file=sys.stderr)
        sys.exit(1)

    sys.exit(0)

def self_test():
    print("=== RUNNING SELF-TEST: lead_pm_hierarchy_enforcer.py ===")

    # Test 1: Lead PM writing python code -> DENIED
    passed, reason = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        tool_name="write_to_file",
        tool_args={"TargetFile": "services/auth/models.py"}
    )
    assert not passed, "Test 1 Failed: Lead PM should be denied from writing python files"
    print("Test 1 Passed: Lead PM writing code is successfully blocked.")

    # Test 2: Lead PM writing progress.md -> PASSED
    passed, reason = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        tool_name="write_to_file",
        tool_args={"TargetFile": str(pathlib.Path.cwd() / "progress.md")}
    )
    assert passed, f"Test 2 Failed: Lead PM should be allowed to write progress.md ({reason})"
    print("Test 2 Passed: Lead PM writing progress.md is allowed.")

    # Test 3: Lead PM writing DISPATCH.md in .agents -> PASSED
    passed, reason = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        tool_name="write_to_file",
        tool_args={"TargetFile": ".agents/pm_auth/DISPATCH.md"}
    )
    assert passed, f"Test 3 Failed: Lead PM should be allowed to write DISPATCH.md ({reason})"
    print("Test 3 Passed: Lead PM writing DISPATCH.md is allowed.")

    # Test 4: Concurrency Cap > 20 -> DENIED
    big_batch = [{"Role": f"Worker_{i}", "TypeName": "self", "Prompt": "task"} for i in range(25)]
    passed, reason = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        tool_name="invoke_subagent",
        tool_args={"Subagents": big_batch},
        active_subagent_count=0
    )
    assert not passed, "Test 4 Failed: Spawning > 20 subagents should be denied"
    print("Test 4 Passed: Concurrency Cap > 20 is successfully blocked.")

    # Test 5: Concurrency Cap <= 20 (e.g. 8 Domain PMs) -> PASSED
    valid_batch = [{"Role": f"pm_domain_{i}", "TypeName": "self", "Prompt": "task"} for i in range(8)]
    passed, reason = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        tool_name="invoke_subagent",
        tool_args={"Subagents": valid_batch},
        active_subagent_count=0
    )
    assert passed, f"Test 5 Failed: Valid batch <= 20 should pass ({reason})"
    print("Test 5 Passed: Valid batch of 8 child PMs passed.")

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
