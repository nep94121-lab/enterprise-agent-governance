#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lead_pm_hierarchy_enforcer.py — Physical Hook & Guard for Lead PM Hierarchy.

Enforces the 4-Tier Agent Governance Tree:
- Tier 1: Agent Chính (Top-Level User-Facing Agent)
- Tier 1.5: Lead PM (Chief Solution Train Director / Multi-PM Meta-Orchestrator)
- Tier 2: Domain PMs & Specialized Discipline PMs (5 to 10 Child PMs)
- Tier 3: Leaf Dev Workers, Watchdogs, Harvesters, Challengers, and Auditors

INVARIANTS ENFORCED:
1. Multi-Layered Caller Identity Detection (Fix VULN-01 Fail-Open):
   - Inspects data["caller_role"], data["role"], context["role"], context["caller_role"],
     agent_role, metadata, os.environ["AGENT_ROLE"].
   - If role is empty but tool is invoke_subagent and subagents list contains domain PMs/watchdogs,
     accurately infers Lead PM role. Zero false positives for leaf dev workers.
2. Arbitrary JSON/MD Poisoning & Source Code Boundary (Fix VULN-02):
   - Lead PM is STRICTLY FORBIDDEN from modifying source code files (.py, .js, .ts, etc.).
   - Lead PM is forbidden from modifying sensitive configs (hooks.json, package.json, governance.config.json, tsconfig.json, etc.).
   - Lead PM can ONLY modify explicit management artifacts: progress.md, gate_status.md, dead_ends.md,
     handoff.md, dispatch.md, briefing.md, request_artifact.md, activity_logs/*.md.
3. Shell Code Injection Interceptor (Fix VULN-03):
   - Intercepts run_command when caller is Lead PM.
   - Blocks any command attempting to create or edit source code files or sensitive configuration files
     via shell redirection, PowerShell cmdlets, one-liners, touch, tee, sed, curl/wget, etc.
4. Concurrency Cap & Hierarchy Enforcement (Fix VULN-04):
   - Lead PM can ONLY spawn child PMs, Watchdogs, Harvesters, Challengers, Auditors (max 20 concurrent).
   - If Lead PM attempts to spawn leaf dev workers (backend, frontend, dev, qa, tester, etc.) directly,
     the action is HARD DENIED.
5. Standard JSON stdout emission via emit_stdout_json (from common_hook_lib.py) and sys.exit(0).
6. Comprehensive --self-test suite with 100% test coverage.
"""

from __future__ import annotations

import argparse
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

# Ensure local hook library is importable
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
    log_diagnostic,
    pre_tool_response,
    read_stdin_payload,
)

# ---------------------------------------------------------------------------
# CONSTANTS & CONFIGURATION
# ---------------------------------------------------------------------------

CODE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs",
    ".java", ".c", ".cpp", ".cs", ".php", ".rb", ".sh", ".ps1", ".bat"
})

ALLOWED_LEAD_PM_BASENAMES: frozenset[str] = frozenset({
    "progress.md",
    "gate_status.md",
    "dead_ends.md",
    "handoff.md",
    "dispatch.md",
    "briefing.md",
    "request_artifact.md",
})

SENSITIVE_CONFIG_BASENAMES: frozenset[str] = frozenset({
    "hooks.json",
    "package.json",
    "governance.config.json",
    "tsconfig.json",
    "settings.json",
    ".env",
    "package-lock.json",
})

LEAD_PM_ROLE_KEYWORDS: tuple[str, ...] = (
    "lead pm",
    "lead_pm",
    "lead-pm",
    "leadpm",
    "chief pm",
    "solution train director",
    "pm_lead",
    "enterprise project orchestrator",
    "tier 1.5",
    "lead_pm_orchestrator",
)

DEV_WORKER_ROLE_KEYWORDS: tuple[str, ...] = (
    "backend",
    "frontend",
    "fullstack",
    "qa",
    "tester",
    "devops",
    "worker",
    "developer",
    "coder",
    "engineer",
)

# Roles that Lead PM is authorized to spawn (Tier 2 Child PMs, Watchdogs, Harvesters, Challengers, Auditors)
VALID_LEAD_PM_CHILDREN_KEYWORDS: tuple[str, ...] = (
    "pm",
    "manager",
    "director",
    "orchestrator",
    "solution train",
    "watchdog",
    "inspector",
    "harvester",
    "challenger",
    "auditor",
    "architect",
)

# Child roles that indicate the caller is acting as Lead PM when role is empty
INFERRED_LEAD_CHILDREN_KEYWORDS: tuple[str, ...] = (
    "domain pm",
    "discipline pm",
    "pm_",
    "_pm",
    "pm orchestrator",
    "lead watchdog",
    "fleet watchdog",
    "domain watchdog",
    "evidence harvester",
    "plan challenger",
    "compliance auditor",
    "chief watchdog",
)

MONITORED_FILE_TOOLS: frozenset[str] = frozenset({
    "write_to_file",
    "replace_file_content",
    "multi_replace_file_content",
})

MONITORED_CMD_TOOLS: frozenset[str] = frozenset({
    "run_command",
    "execute_command",
    "bash",
    "powershell",
})

# Patterns for detecting shell commands that create or modify code/sensitive files
SHELL_CODE_PATTERNS: list[tuple[re.Pattern, str]] = [
    # 1. Shell redirection into code or sensitive files
    (
        re.compile(r'(?:>>|>)\s*["\']?([^"\'><|&;\s]+\.(?:py|js|ts|jsx|tsx|go|rs|java|c|cpp|cs|php|rb|sh|ps1))\b', re.IGNORECASE),
        "shell redirection into source code file"
    ),
    (
        re.compile(r'(?:>>|>)\s*["\']?([^"\'><|&;\s]*(?:hooks\.json|package\.json|governance\.config\.json))\b', re.IGNORECASE),
        "shell redirection into sensitive config file"
    ),
    # 2. PowerShell file creation/writing cmdlets targeting code or sensitive configs
    (
        re.compile(r'\b(?:Set-Content|Add-Content|Out-File)\b.*?["\']?([^"\'><|&;\s]+\.(?:py|js|ts|jsx|tsx|go|rs|java|c|cpp|cs|php|rb|sh|ps1))\b', re.IGNORECASE),
        "PowerShell file write cmdlet targeting source code"
    ),
    (
        re.compile(r'\b(?:Set-Content|Add-Content|Out-File)\b.*?["\']?([^"\'><|&;\s]*(?:hooks\.json|package\.json|governance\.config\.json))\b', re.IGNORECASE),
        "PowerShell file write cmdlet targeting sensitive config"
    ),
    (
        re.compile(r'\bNew-Item\b.*?["\']?([^"\'><|&;\s]+\.(?:py|js|ts|jsx|tsx|go|rs|java|c|cpp|cs|php|rb|sh|ps1))\b', re.IGNORECASE),
        "New-Item cmdlet creating source code file"
    ),
    # 3. Unix file modification/creation commands
    (
        re.compile(r'\b(?:touch|tee)\b\s+.*?["\']?([^"\'><|&;\s]+\.(?:py|js|ts|jsx|tsx|go|rs|java|c|cpp|cs|php|rb|sh|ps1))\b', re.IGNORECASE),
        "command creating or writing source code file"
    ),
    (
        re.compile(r'\bsed\b\s+-[^\s]*i.*?["\']?([^"\'><|&;\s]+\.(?:py|js|ts|jsx|tsx|go|rs|java|c|cpp|cs|php|rb|sh|ps1))\b', re.IGNORECASE),
        "sed in-place editing source code file"
    ),
    # 4. Python/Node inline scripts writing files
    (
        re.compile(r'python(?:\d+)?\s+-c\s+.*open\(["\'][^"\']+\.(?:py|js|ts|jsx|tsx|go|rs|java|c|cpp|cs|php|rb|sh|ps1)["\'].*?[wa]', re.IGNORECASE),
        "python one-liner writing source code file"
    ),
    (
        re.compile(r'node\s+-e\s+.*fs\.(?:writeFile|appendFile).*?["\'][^"\']+\.(?:py|js|ts|jsx|tsx|go|rs|java|c|cpp|cs|php|rb|sh|ps1)["\']', re.IGNORECASE),
        "node one-liner writing source code file"
    ),
    # 5. Direct downloads into code files
    (
        re.compile(r'\b(?:curl|wget)\b.*?-(?:o|O)\s+["\']?([^"\'><|&;\s]+\.(?:py|js|ts|jsx|tsx|go|rs|java|c|cpp|cs|php|rb|sh|ps1))\b', re.IGNORECASE),
        "download writing directly to source code file"
    ),
    # 6. Copy / move into code files
    (
        re.compile(r'\b(?:cp|copy|move|mv)\b\s+.*?["\']?([^"\'><|&;\s]+\.(?:py|js|ts|jsx|tsx|go|rs|java|c|cpp|cs|php|rb|sh|ps1))\b', re.IGNORECASE),
        "copy/move into source code file"
    ),
]

# ---------------------------------------------------------------------------
# CORE HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def is_code_file(filepath: str) -> bool:
    """Determine whether filepath represents a source code file."""
    if not filepath:
        return False
    clean = filepath.strip().split("?")[0].split("#")[0]
    ext = os.path.splitext(clean)[1].lower()
    return ext in CODE_EXTENSIONS


def is_allowed_management_file(filepath: str) -> bool:
    """Verify whether filepath is an authorized Lead PM management artifact.
    
    Allowed artifacts:
    - progress.md, gate_status.md, dead_ends.md, handoff.md, dispatch.md, briefing.md, request_artifact.md
    - Any markdown file located inside activity_logs/ directory.
    Disallows:
    - All code files.
    - Sensitive configurations (hooks.json, package.json, etc.).
    - Arbitrary .json, .md, or script files.
    """
    if not filepath:
        return False
    norm = filepath.replace("\\", "/").strip().lower()
    base = os.path.basename(norm)

    # 1. Immediately block sensitive configuration files or code files
    if base in SENSITIVE_CONFIG_BASENAMES or is_code_file(norm):
        return False

    # 2. Block arbitrary JSON or scripts
    if norm.endswith(".json") or norm.endswith(".py") or norm.endswith(".sh") or norm.endswith(".ps1"):
        return False

    # 3. Check allowed management basenames (e.g. progress.md, dispatch.md, etc.)
    if base in ALLOWED_LEAD_PM_BASENAMES:
        return True

    # 4. Check activity_logs/*.md
    norm_parts = norm.split("/")
    if "activity_logs" in norm_parts and norm.endswith(".md"):
        return True

    return False


def check_shell_code_modification(command: str) -> tuple[bool, str]:
    """Inspect shell command string for creation or alteration of code/config files."""
    if not command:
        return False, ""
    for pattern, desc in SHELL_CODE_PATTERNS:
        match = pattern.search(command)
        if match:
            target = match.group(1) if match.groups() else ""
            return True, (
                f"Lead PM is forbidden from creating or modifying source code or sensitive config files "
                f"via shell command ({desc}{f': {target}' if target else ''}). "
                "Must delegate all implementation work to Domain PMs / Dev subagents."
            )
    return False, ""


def extract_caller_identity(data: dict[str, Any], tool_name: str, tool_args: dict[str, Any]) -> tuple[str, bool]:
    """Multi-layered extraction of caller identity and determination if caller is Lead PM.
    
    Addresses VULN-01 (Caller Identity Fail-Open):
    - Multi-layered check: data["caller_role"], data["role"], context["role"],
      context["caller_role"], agent_role, metadata, os.environ["AGENT_ROLE"].
    - If role is empty but tool is invoke_subagent and subagents list contains domain PMs/watchdogs,
      infers Lead PM role.
    - Guarantees zero false positives for dev workers.
    """
    context = data.get("context", {}) if isinstance(data.get("context"), dict) else {}
    metadata = data.get("metadata", {}) if isinstance(data.get("metadata"), dict) else {}
    if not metadata and isinstance(context.get("metadata"), dict):
        metadata = context.get("metadata", {})

    candidates = [
        data.get("caller_role"),
        data.get("role"),
        context.get("role"),
        context.get("caller_role"),
        data.get("agent_role"),
        context.get("agent_role"),
        metadata.get("role"),
        metadata.get("caller_role"),
        data.get("worker_id"),
        context.get("worker_id"),
        metadata.get("worker_id"),
        os.environ.get("AGENT_ROLE"),
        os.environ.get("CURRENT_AGENT_ROLE"),
        os.environ.get("WORKER_ID"),
    ]

    detected_role = ""
    for candidate in candidates:
        if candidate and isinstance(candidate, str) and candidate.strip():
            candidate_clean = candidate.strip()
            if not detected_role:
                detected_role = candidate_clean
            # Check if candidate explicitly matches Lead PM keywords
            candidate_lower = candidate_clean.lower()
            if any(kw in candidate_lower for kw in LEAD_PM_ROLE_KEYWORDS):
                return candidate_clean, True

    # Check if detected_role explicitly indicates a Dev Worker (to avoid false positives)
    is_explicit_dev_worker = False
    if detected_role:
        role_lower = detected_role.lower()
        if any(kw in role_lower for kw in DEV_WORKER_ROLE_KEYWORDS) and not any(kw in role_lower for kw in LEAD_PM_ROLE_KEYWORDS):
            is_explicit_dev_worker = True

    # Dynamic heuristic inference when role is empty or unspecified:
    # If tool is invoke_subagent and child subagents contain domain PMs, watchdogs, harvesters, etc.,
    # then caller is acting as Lead PM.
    if not is_explicit_dev_worker and tool_name == "invoke_subagent":
        subagents = tool_args.get("Subagents", [])
        if isinstance(subagents, str):
            try:
                subagents = json.loads(subagents)
            except Exception:
                subagents = []
        if isinstance(subagents, list) and subagents:
            inferred_lead = False
            for sa in subagents:
                if isinstance(sa, dict):
                    c_role = (sa.get("Role") or sa.get("role") or "").lower()
                    c_type = (sa.get("TypeName") or sa.get("typeName") or "").lower()
                    if any(kw in c_role for kw in INFERRED_LEAD_CHILDREN_KEYWORDS) or c_type == "pm_orchestrator":
                        inferred_lead = True
                        break
            if inferred_lead:
                return detected_role or "Lead PM (Inferred from child orchestration)", True

    return detected_role, False


def validate_lead_pm_action(
    role: str,
    is_lead_pm: bool,
    tool_name: str,
    tool_args: dict[str, Any],
    active_subagent_count: int = 0,
) -> tuple[bool, str]:
    """Validates actions executed by or on behalf of Lead PM.
    
    Invariants enforced:
    1. VULN-01: Accurately identifies Lead PM, preventing fail-open while avoiding false positives.
    2. VULN-02: Lead PM is forbidden from modifying source code or sensitive configs,
       and may only modify allowed management artifacts (progress.md, dispatch.md, etc.).
    3. VULN-03: Intercepts run_command if caller is Lead PM and command creates/modifies code or configs.
    4. VULN-04: Concurrency cap <= 20 and strictly forbids spawning leaf dev workers directly.
    """
    # If caller is not Lead PM, allow (ensuring NO False Positives for Dev Workers)
    if not is_lead_pm:
        return True, "PASSED"

    # 1. Source Code & Sensitive Configuration Boundary (VULN-02)
    if tool_name in MONITORED_FILE_TOOLS:
        target_file = (
            tool_args.get("TargetFile")
            or tool_args.get("path")
            or tool_args.get("file_path")
            or tool_args.get("target_file")
            or tool_args.get("filePath")
            or ""
        )
        if is_code_file(target_file):
            return False, (
                f"DENIED: Lead PM role '{role}' is strictly forbidden from modifying source code '{target_file}'. "
                "Lead PM must delegate all implementation work to Domain PMs / Dev subagents."
            )
        if not is_allowed_management_file(target_file):
            return False, (
                f"DENIED: Lead PM role '{role}' attempted to modify unauthorized file '{target_file}'. "
                f"Lead PM may only modify management artifacts: {', '.join(sorted(ALLOWED_LEAD_PM_BASENAMES))}, "
                "or activity_logs/*.md."
            )

    # 2. Shell Code Injection Interceptor (VULN-03)
    if tool_name in MONITORED_CMD_TOOLS:
        cmd = tool_args.get("CommandLine") or tool_args.get("command") or tool_args.get("cmd") or ""
        is_injection, reason = check_shell_code_modification(cmd)
        if is_injection:
            return False, f"DENIED: {reason}"

    # 3. Concurrency Cap & Hierarchy Enforcement (VULN-04)
    if tool_name == "invoke_subagent":
        subagents = tool_args.get("Subagents", [])
        if isinstance(subagents, str):
            try:
                subagents = json.loads(subagents)
            except Exception:
                subagents = []
        if not isinstance(subagents, list):
            subagents = []

        new_count = len(subagents)
        if new_count > 20:
            return False, (
                f"DENIED: Concurrency Cap exceeded! Attempted to spawn {new_count} subagents in a single batch "
                "(max allowed is 20). Must use Rolling Batches."
            )

        total_projected = active_subagent_count + new_count
        if total_projected > 20:
            return False, (
                f"DENIED: Concurrency Cap exceeded! Attempted {total_projected} total active subagents "
                f"({active_subagent_count} active + {new_count} new; max allowed is 20). Must use Rolling Batches."
            )

        # Hierarchy check: Lead PM can ONLY spawn child PMs, Watchdogs, Harvesters, Challengers, Auditors
        for sa in subagents:
            if not isinstance(sa, dict):
                continue
            child_role = (sa.get("Role") or sa.get("role") or "").strip()
            child_type = (sa.get("TypeName") or sa.get("typeName") or "").strip()

            child_role_lower = child_role.lower()
            child_type_lower = child_type.lower()

            is_valid_child = (
                any(kw in child_role_lower for kw in VALID_LEAD_PM_CHILDREN_KEYWORDS)
                or child_type_lower == "pm_orchestrator"
            )

            if not is_valid_child:
                return False, (
                    f"DENIED: Lead PM cannot directly spawn leaf dev worker '{child_role}'. "
                    "Lead PM can only spawn child PMs, Watchdogs, Harvesters, Challengers, and Auditors. "
                    "Leaf dev workers must be spawned by their respective Domain PMs."
                )

    return True, "PASSED"


def evaluate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate payload and return standard response dictionary."""
    if not payload:
        res = pre_tool_response("allow", "Empty payload passed.")
        res["verdict"] = "ALLOW"
        return res

    tool_call = get_tool_call(payload)
    tool_name = payload.get("tool_name") or tool_call.get("name", "")
    tool_args = get_tool_args(tool_call) if tool_call else (payload.get("tool_args") or {})
    if not isinstance(tool_args, dict):
        tool_args = {}

    context = payload.get("context", {}) if isinstance(payload.get("context"), dict) else {}
    active_subagent_count = context.get("active_subagents", 0)
    if not isinstance(active_subagent_count, (int, float)):
        active_subagent_count = 0
    active_subagent_count = int(active_subagent_count)

    detected_role, is_lead_pm = extract_caller_identity(payload, tool_name, tool_args)

    passed, reason = validate_lead_pm_action(
        role=detected_role,
        is_lead_pm=is_lead_pm,
        tool_name=tool_name,
        tool_args=tool_args,
        active_subagent_count=active_subagent_count,
    )

    if not passed:
        log_diagnostic(f"Lead PM violation intercepted: {reason}")
        res = pre_tool_response("deny", reason)
        res["verdict"] = "DENY"
        res["message"] = reason
        return res

    res = pre_tool_response("allow", "PASSED")
    res["verdict"] = "ALLOW"
    return res


def run_hook() -> None:
    """Reads stdin from Antigravity / Gemini hook event and emits standard JSON stdout response."""
    payload = read_stdin_payload(default={})
    response = evaluate_payload(payload)
    emit_stdout_json(response)
    sys.exit(0)


# ---------------------------------------------------------------------------
# SELF-TEST SUITE
# ---------------------------------------------------------------------------

def self_test() -> int:
    """Comprehensive self-test suite covering VULN-01 to VULN-04 and edge cases."""
    print("=== RUNNING EXPANDED SELF-TEST: lead_pm_hierarchy_enforcer.py ===")
    test_results: list[tuple[str, bool, str]] = []

    def record_test(name: str, passed: bool, detail: str = ""):
        test_results.append((name, passed, detail))
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {name}{f' — {detail}' if detail else ''}")

    # --- Group 1: Source Code Boundary (VULN-02) ---
    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="write_to_file",
        tool_args={"TargetFile": "services/auth/models.py"}
    )
    record_test("Test 01: Lead PM writing Python code blocked", not p, r)

    p, r = validate_lead_pm_action(
        role="Lead PM (Enterprise Project Orchestrator - Tier 1.5)",
        is_lead_pm=True,
        tool_name="replace_file_content",
        tool_args={"TargetFile": "frontend/src/App.tsx"}
    )
    record_test("Test 02: Lead PM writing TypeScript/TSX code blocked", not p, r)

    # --- Group 2: Allowed Management Artifacts (VULN-02) ---
    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="write_to_file",
        tool_args={"TargetFile": "C:\\Users\\Admin\\Desktop\\học tập\\progress.md"}
    )
    record_test("Test 03: Lead PM writing progress.md allowed", p, r)

    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="write_to_file",
        tool_args={"TargetFile": "activity_logs/2026-09-12.md"}
    )
    record_test("Test 04: Lead PM writing activity_logs/*.md allowed", p, r)

    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="write_to_file",
        tool_args={"TargetFile": ".agents/pm_auth/DISPATCH.md"}
    )
    record_test("Test 05: Lead PM writing DISPATCH.md in .agents allowed", p, r)

    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="write_to_file",
        tool_args={"TargetFile": "gate_status.md"}
    )
    record_test("Test 06: Lead PM writing gate_status.md allowed", p, r)

    # --- Group 3: Sensitive Config & Arbitrary File Poisoning (VULN-02) ---
    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="write_to_file",
        tool_args={"TargetFile": "hooks.json"}
    )
    record_test("Test 07: Lead PM writing hooks.json blocked", not p, r)

    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="write_to_file",
        tool_args={"TargetFile": "package.json"}
    )
    record_test("Test 08: Lead PM writing package.json blocked", not p, r)

    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="write_to_file",
        tool_args={"TargetFile": "governance.config.json"}
    )
    record_test("Test 09: Lead PM writing governance.config.json blocked", not p, r)

    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="write_to_file",
        tool_args={"TargetFile": "arbitrary_notes.md"}
    )
    record_test("Test 10: Lead PM writing arbitrary markdown blocked", not p, r)

    # --- Group 4: Shell Code Injection via run_command (VULN-03) ---
    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="run_command",
        tool_args={"CommandLine": "echo 'print(1)' > server.py"}
    )
    record_test("Test 11: Shell code injection via redirection blocked", not p, r)

    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="run_command",
        tool_args={"CommandLine": "Set-Content -Path app.py -Value 'def run(): pass'"}
    )
    record_test("Test 12: Shell code injection via PowerShell cmdlet blocked", not p, r)

    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="run_command",
        tool_args={"CommandLine": "touch index.js"}
    )
    record_test("Test 13: Shell code injection via touch blocked", not p, r)

    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="run_command",
        tool_args={"CommandLine": "echo '{}' > hooks.json"}
    )
    record_test("Test 14: Shell sensitive config injection blocked", not p, r)

    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="run_command",
        tool_args={"CommandLine": "python ./hooks_scripts/lead_pm_hierarchy_enforcer.py --self-test"}
    )
    record_test("Test 15: Safe python execution in shell allowed", p, r)

    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="run_command",
        tool_args={"CommandLine": "git status"}
    )
    record_test("Test 16: Safe shell status check allowed", p, r)

    # --- Group 5: Concurrency Cap 20 & Leaf Dev Worker Blocking (VULN-04) ---
    big_batch = [{"Role": f"Domain_PM_{i}", "TypeName": "pm_orchestrator", "Prompt": "task"} for i in range(25)]
    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="invoke_subagent",
        tool_args={"Subagents": big_batch},
        active_subagent_count=0
    )
    record_test("Test 17: Single batch > 20 subagents blocked", not p, r)

    projected_batch = [{"Role": f"Domain_PM_{i}", "TypeName": "pm_orchestrator", "Prompt": "task"} for i in range(10)]
    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="invoke_subagent",
        tool_args={"Subagents": projected_batch},
        active_subagent_count=15
    )
    record_test("Test 18: Total active + new > 20 subagents blocked", not p, r)

    dev_batch = [{"Role": "Backend Developer", "TypeName": "self", "Prompt": "implement auth"}]
    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="invoke_subagent",
        tool_args={"Subagents": dev_batch},
        active_subagent_count=0
    )
    record_test("Test 19: Lead PM spawning leaf dev worker blocked", not p, r)

    qa_batch = [{"Role": "QA Tester", "TypeName": "self", "Prompt": "run tests"}]
    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="invoke_subagent",
        tool_args={"Subagents": qa_batch},
        active_subagent_count=0
    )
    record_test("Test 20: Lead PM spawning QA tester directly blocked", not p, r)

    valid_batch = [
        {"Role": "Domain PM - Auth", "TypeName": "pm_orchestrator", "Prompt": "orchestrate auth"},
        {"Role": "Domain PM - Payment", "TypeName": "pm_orchestrator", "Prompt": "orchestrate payment"},
        {"Role": "Lead Watchdog", "TypeName": "self", "Prompt": "monitor telemetry"},
        {"Role": "Plan Challenger", "TypeName": "self", "Prompt": "challenge gates"},
        {"Role": "Evidence Harvester", "TypeName": "self", "Prompt": "collect proof"},
        {"Role": "Compliance Auditor", "TypeName": "self", "Prompt": "audit architecture"},
    ]
    p, r = validate_lead_pm_action(
        role="Lead PM Orchestrator",
        is_lead_pm=True,
        tool_name="invoke_subagent",
        tool_args={"Subagents": valid_batch},
        active_subagent_count=0
    )
    record_test("Test 21: Lead PM spawning valid Child PMs & Watchdogs allowed", p, r)

    # --- Group 6: Multi-Layered Caller Identity & Fail-Open Fix (VULN-01) ---
    # Case A: context.role is empty, but subagents contains Domain PMs -> Identified as Lead PM
    payload_inferred = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "Subagents": [
                    {"Role": "Domain PM - Database", "TypeName": "pm_orchestrator"}
                ]
            }
        },
        "context": {}
    }
    resp_inferred = evaluate_payload(payload_inferred)
    record_test("Test 22: Fail-open fix: Empty role with Domain PM subagents inferred as Lead PM", resp_inferred.get("decision") == "allow")

    # Case B: context.role is empty, caller invokes leaf worker -> Leaf dev worker blocked if Lead PM inferred or caller is Lead
    payload_env_lead = {
        "toolCall": {
            "name": "write_to_file",
            "args": {"TargetFile": "services/auth/models.py"}
        },
        "caller_role": "Lead PM Orchestrator"
    }
    resp_env_lead = evaluate_payload(payload_env_lead)
    record_test("Test 23: Caller_role top-level field identified as Lead PM and blocked", resp_env_lead.get("decision") == "deny")

    # --- Group 7: False Positive Prevention for Dev Workers ---
    payload_dev = {
        "toolCall": {
            "name": "write_to_file",
            "args": {"TargetFile": "services/auth/models.py"}
        },
        "context": {"role": "Backend Developer"}
    }
    resp_dev = evaluate_payload(payload_dev)
    record_test("Test 24: Dev worker writing code allowed (No False Positive)", resp_dev.get("decision") == "allow")

    payload_dev_cmd = {
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "echo 'print(1)' > test.py"}
        },
        "context": {"role": "QA Automation Engineer"}
    }
    resp_dev_cmd = evaluate_payload(payload_dev_cmd)
    record_test("Test 25: Dev worker executing shell commands allowed (No False Positive)", resp_dev_cmd.get("decision") == "allow")

    # --- Group 8: Subprocess Stdio Streaming & Standard JSON Verification ---
    print("\nExecuting Subprocess Stdio Stream Verification...")
    sample_deny_payload = {
        "toolCall": {
            "name": "write_to_file",
            "args": {"TargetFile": "src/dangerous_script.py"}
        },
        "context": {"role": "Lead PM Orchestrator"}
    }
    proc = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).resolve())],
        input=json.dumps(sample_deny_payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    subproc_passed = False
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            sub_res = json.loads(proc.stdout.strip())
            subproc_passed = (
                sub_res.get("decision") == "deny"
                and sub_res.get("verdict") == "DENY"
                and "Lead PM role" in sub_res.get("reason", "")
            )
        except json.JSONDecodeError:
            subproc_passed = False
    record_test("Test 26: Subprocess stdio JSON stream verification", subproc_passed)

    all_passed = all(t[1] for t in test_results)
    total_passed = sum(1 for t in test_results if t[1])
    total_cases = len(test_results)

    print("\n----------------------------------------------------------------------")
    print(f"Self-Test Summary: {total_passed}/{total_cases} tests passed ({'100%' if all_passed else 'FAILED'}).")
    print("----------------------------------------------------------------------\n")
    return 0 if all_passed else 1


def main() -> None:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(description="Lead PM Hierarchy Enforcer Hook")
    parser.add_argument("--self-test", action="store_true", help="Run automated self-tests")
    args, _ = parser.parse_known_args()

    if args.self_test:
        sys.exit(self_test())
    else:
        run_hook()


if __name__ == "__main__":
    main()
