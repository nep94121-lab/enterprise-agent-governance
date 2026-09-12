#!/usr/bin/env python3
"""Turn-1 Gate Enforcer Hook (PreToolUse) for Enterprise Multi-Agent Governance System.

Enforces the Zero-Tolerance Turn-1 Action Gate:
1. Every agent (Top-Level Agent, PM Orchestrator, Dev Sub-agent) MUST view its designated rules
   file before calling any modifying or technical tools.
2. The agent MUST record 'CANARY_VERIFIED: [TOKEN]' in line 1 of progress.md (or role progress file).
3. Any tool call (except viewing a rules file, or writing CANARY_VERIFIED to progress.md) is
   STRICTLY DENIED until Turn-1 verification is confirmed.

Hardened Features (W5):
- Stale State Bypass Remediation: Cross-verifies active transcript for 'view_file' on rules
  and validates progress.md mtime against session start time (defeating pre-existing file bypass).
- Comprehensive Rules Catalog: Includes lead_pm_rules.md, lead_watchdog_rules.md, watchdog_rules.md,
  pm_challenger_rules.md, explorer_rules.md, agents.md, pm_rules.md, and all dev/specialist rules.
- Universal Tool Call Parsing: Standardizes toolCall.name, tool_name, toolName, namespace prefixes.
- Zero-Tolerance Fail-Closed Security: Blocks unverified calls with malformed or missing tool names.
"""

from __future__ import annotations

import datetime
import io
import json
import os
import pathlib
import subprocess
import sys
import time
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
    get_workspace_roots,
    log_diagnostic,
    pre_tool_response,
    read_stdin_payload,
)

RULES_FILE_NAMES: frozenset[str] = frozenset({
    # Core Tier 1 Rules
    "agents.md",
    # Tier 1.5 & Lead Roles
    "lead_pm_rules.md",
    "lead_pm_rules_index.md",
    "lead_watchdog_rules.md",
    "watchdog_rules.md",
    "pm_challenger_rules.md",
    "explorer_rules.md",
    # Tier 2 PM Rules
    "pm_rules.md",
    # Tier 3 Dev & Specialist Rules
    "backend_rules.md",
    "frontend_rules.md",
    "qa_rules.md",
    "tech_lead_rules.md",
    "devops_rules.md",
    "appsec_rules.md",
    "data_ml_rules.md",
    "enterprise_sop_rules.md",
})

RULES_PATH_PATTERNS: tuple[str, ...] = (
    "rules_by_role",
    "config/rules",
    "config\\rules",
    "enterprise-hooks/rules",
    "enterprise-hooks\\rules",
    "enterprise-hooks/rules_by_role",
    "enterprise-hooks\\rules_by_role",
    "lead_pm",
    "lead_watchdog",
    "watchdog_inspector",
    "pm_challenger",
    "codebase_explorer",
    "pm_orchestrator",
    "backend_developer",
    "frontend_developer",
    "qa_adversarial_tester",
    "tech_lead_orchestrator",
    "devops_security",
    "appsec_sentinel",
    "data_ml_engineer",
)


def is_rules_file(target_path_str: str | None) -> bool:
    """Check if target path is a recognized rules file."""
    if not target_path_str or not isinstance(target_path_str, str):
        return False
    norm = target_path_str.strip().strip('"').strip("'").replace("\\", "/").lower()
    name = pathlib.Path(norm).name
    if name in RULES_FILE_NAMES:
        return True
    if name.endswith("_rules.md") or name.endswith("_rules_index.md"):
        return True
    return any(pat in norm for pat in RULES_PATH_PATTERNS) and norm.endswith(".md")


def extract_target_path(args: dict[str, Any] | Any) -> str | None:
    """Extract target file path from tool arguments."""
    if not isinstance(args, dict):
        return None
    for key in ("AbsolutePath", "TargetFile", "target_file", "filePath", "file_path", "path"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip().strip('"').strip("'")
    return None


def extract_tool_name_and_args(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Extract normalized tool name and arguments dictionary safely from payload.

    Supports both payload['toolCall'] and top-level payload['tool_name'] / payload['toolName'].
    Standardizes namespace prefixes (e.g. 'default_api:view_file' -> 'view_file').
    """
    if not isinstance(payload, dict):
        return "", {}

    tool_call = payload.get("toolCall")
    if not isinstance(tool_call, dict):
        tool_call = {}

    raw_name = (
        tool_call.get("name")
        or tool_call.get("toolName")
        or tool_call.get("tool")
        or tool_call.get("function", {}).get("name")
        or payload.get("tool_name")
        or payload.get("toolName")
        or payload.get("name")
        or payload.get("tool")
        or ""
    )
    if not isinstance(raw_name, str):
        raw_name = str(raw_name)

    # Normalize tool name (lowercase, strip namespace e.g. 'default_api:')
    tool_name = raw_name.strip().split(":")[-1].lower()

    # Extract args: prioritize toolCall['args'], then payload['args']
    raw_args = (
        tool_call.get("args")
        or tool_call.get("arguments")
        or tool_call.get("parameters")
        or payload.get("args")
        or payload.get("arguments")
        or payload.get("parameters")
        or {}
    )
    if isinstance(raw_args, str):
        try:
            parsed = json.loads(raw_args)
            args = parsed if isinstance(parsed, dict) else {}
        except Exception:
            args = {}
    elif isinstance(raw_args, dict):
        args = raw_args
    else:
        args = {}

    return tool_name, args


def get_transcript_path(payload: dict[str, Any]) -> pathlib.Path | None:
    """Resolve active transcript.jsonl path from payload, environment, or brain directory."""
    # 1. Direct payload or environment transcriptPath
    for key in ("transcriptPath", "transcript_path", "transcript"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            p = pathlib.Path(val.strip().strip('"').strip("'"))
            if p.is_file():
                # Verify that it is a legitimate transcript log file
                p_lower = str(p).lower().replace("\\", "/")
                if "transcript" in p.name.lower() or ".system_generated" in p_lower or "logs" in p_lower:
                    return p
                log_diagnostic(f"Ignoring untrusted transcriptPath candidate: {p}")

    env_tp = os.environ.get("ANTIGRAVITY_TRANSCRIPT_PATH")
    if env_tp and os.path.isfile(env_tp):
        return pathlib.Path(env_tp)

    # 2. Lookup via conversationId
    conv_id = (
        payload.get("conversationId")
        or payload.get("conversation_id")
        or os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
    )
    brain_root = os.environ.get(
        "GEMINI_BRAIN_DIR",
        str(pathlib.Path.home() / ".gemini" / "antigravity" / "brain"),
    )
    brain_path = pathlib.Path(brain_root)

    if conv_id and isinstance(conv_id, str) and brain_path.is_dir():
        cand = brain_path / conv_id / ".system_generated" / "logs" / "transcript.jsonl"
        if cand.is_file():
            return cand

    # 3. Fallback: Most recently updated conversation transcript in brain directory
    if brain_path.is_dir():
        try:
            conv_dirs = [d for d in brain_path.iterdir() if d.is_dir() and d.name != "tempmediaStorage"]
            conv_dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
            for cd in conv_dirs[:5]:
                cand = cd / ".system_generated" / "logs" / "transcript.jsonl"
                if cand.is_file():
                    if (time.time() - cand.stat().st_mtime) < 10800:
                        return cand
        except Exception as exc:
            log_diagnostic(f"Error scanning brain directory for transcript: {exc}")

    return None


def get_session_start_time(
    payload: dict[str, Any],
    transcript_path: pathlib.Path | None = None,
) -> float | None:
    """Determine session start epoch timestamp."""
    # 1. Direct payload field
    for key in ("sessionStartTime", "session_start_time", "session_start", "sessionStart"):
        val = payload.get(key)
        if isinstance(val, (int, float)) and val > 0:
            return float(val)
        if isinstance(val, str) and val.strip():
            clean_str = val.strip()
            try:
                return float(clean_str)
            except ValueError:
                try:
                    dt = datetime.datetime.fromisoformat(clean_str.replace("Z", "+00:00"))
                    return dt.timestamp()
                except Exception:
                    pass

    # 2. Environment variable
    env_start = os.environ.get("SESSION_START_TIME") or os.environ.get("ANTIGRAVITY_SESSION_START")
    if env_start:
        clean_env = env_start.strip()
        try:
            return float(clean_env)
        except ValueError:
            try:
                dt = datetime.datetime.fromisoformat(clean_env.replace("Z", "+00:00"))
                return dt.timestamp()
            except Exception:
                pass

    # 3. Parse step 0 created_at from transcript
    if transcript_path and transcript_path.is_file():
        try:
            with open(transcript_path, "r", encoding="utf-8", errors="replace") as f:
                for _ in range(5):
                    line = f.readline()
                    if not line or not line.strip():
                        continue
                    try:
                        data = json.loads(line.strip())
                        if isinstance(data, dict):
                            created_at = data.get("created_at") or data.get("timestamp")
                            if created_at and isinstance(created_at, str):
                                dt = datetime.datetime.fromisoformat(created_at.strip().replace("Z", "+00:00"))
                                return dt.timestamp()
                    except Exception:
                        continue
        except Exception as exc:
            log_diagnostic(f"Error reading session start time from transcript {transcript_path}: {exc}")

        # Fallback to transcript file creation/mtime
        try:
            stat = transcript_path.stat()
            return getattr(stat, "st_ctime", stat.st_mtime)
        except Exception:
            pass

    return None


def has_viewed_rules_in_transcript(transcript_path: pathlib.Path | None) -> bool:
    """Check if transcript records a view_file call targeting a valid rules file."""
    if not transcript_path or not transcript_path.is_file():
        return False

    try:
        with open(transcript_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    data = json.loads(line_str)
                except Exception:
                    continue

                if not isinstance(data, dict):
                    continue

                t_calls = data.get("tool_calls") or data.get("toolCalls")
                if not isinstance(t_calls, list):
                    if isinstance(data.get("toolCall"), dict):
                        t_calls = [data["toolCall"]]
                    elif data.get("type") in ("TOOL_USE", "tool_call"):
                        t_calls = [data]
                    else:
                        continue

                for tc in t_calls:
                    if not isinstance(tc, dict):
                        continue
                    raw_name = (
                        tc.get("name")
                        or tc.get("toolName")
                        or tc.get("tool")
                        or tc.get("function", {}).get("name")
                        or ""
                    )
                    t_name = str(raw_name).strip().split(":")[-1].lower()
                    if t_name == "view_file":
                        raw_args = tc.get("args") or tc.get("arguments") or tc.get("parameters") or {}
                        if isinstance(raw_args, str):
                            try:
                                parsed = json.loads(raw_args)
                                args = parsed if isinstance(parsed, dict) else {}
                            except Exception:
                                args = {}
                        elif isinstance(raw_args, dict):
                            args = raw_args
                        else:
                            args = {}

                        target_path = extract_target_path(args)
                        if target_path and is_rules_file(target_path):
                            return True
    except Exception as exc:
        log_diagnostic(f"Error checking rules in transcript {transcript_path}: {exc}")

    return False


def check_canary_in_file(
    file_path: pathlib.Path,
    session_start_time: float | None = None,
) -> bool:
    """Check if file exists, starts with CANARY_VERIFIED, and is not stale.

    If session_start_time is provided, file's mtime must be >= session_start_time - 2.0s
    to prevent stale state bypass across sessions.
    """
    try:
        if not file_path.is_file():
            return False

        stat = file_path.stat()
        mtime = stat.st_mtime

        if session_start_time is not None:
            # 2.0 seconds tolerance for filesystem timestamp granularity / clock skew
            if mtime < (session_start_time - 2.0):
                log_diagnostic(
                    f"STALE progress file detected at {file_path}: "
                    f"mtime={mtime:.2f} < session_start_time={session_start_time:.2f}. Stale bypass blocked."
                )
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
    """Verify whether Turn-1 gate has been satisfied via files or transcript.

    Remediates Stale State Bypass:
    1. Checks if current session transcript recorded 'view_file' on a rules file.
    2. Validates that progress.md has CANARY_VERIFIED and is not stale (mtime >= session_start_time).
    """
    # 1. Check environment / payload override for test injection
    if payload.get("canary_verified") is True:
        return True
    if os.environ.get("CANARY_VERIFIED") == "1":
        return True

    transcript_path = get_transcript_path(payload)
    session_start_time = get_session_start_time(payload, transcript_path)
    viewed_rules = has_viewed_rules_in_transcript(transcript_path)

    # 2. Check progress files in workspace roots (or fallback to CWD only if omitted)
    if workspace_roots:
        check_dirs = list(workspace_roots)
    else:
        check_dirs = [pathlib.Path.cwd().resolve()]

    has_fresh_canary = False
    has_any_canary = False

    for root_dir in check_dirs:
        candidates = [root_dir / "progress.md"]
        try:
            candidates.extend(root_dir.glob("progress_*.md"))
        except Exception:
            pass

        for p_file in candidates:
            # Check with freshness constraint
            if check_canary_in_file(p_file, session_start_time=session_start_time):
                has_fresh_canary = True
                break
            # Also check if canary exists (even if stale)
            if check_canary_in_file(p_file, session_start_time=None):
                has_any_canary = True

        if has_fresh_canary:
            break

    # If transcript proves view_file was called on a valid rules file in this session,
    # AND progress.md contains CANARY_VERIFIED (fresh or existing): Verified!
    if viewed_rules and (has_fresh_canary or has_any_canary):
        return True

    # If progress.md was written/updated in the current session with CANARY_VERIFIED: Verified!
    if has_fresh_canary:
        return True

    return False


def evaluate_turn_1_gate(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate if tool call complies with Turn-1 Gate.

    Enforces Zero-Tolerance Fail-Closed security:
    - If payload is malformed or tool name cannot be resolved before verification -> DENY.
    - Viewing a rules file is ALWAYS allowed at Turn 1.
    - Writing CANARY_VERIFIED to progress.md is ALWAYS allowed.
    - All other technical tool calls are DENIED until Turn-1 is verified.
    """
    if not isinstance(payload, dict):
        log_diagnostic("BLOCKED: Payload is not a dictionary (Fail-Closed).")
        return pre_tool_response(
            "deny",
            "CỔNG BẮT BUỘC TURN 1 (ENFORCED TURN-1 ACTION GATE): Payload không hợp lệ (Fail-Closed). "
            "Yêu cầu hoàn tất Turn 1 trước khi gọi công cụ."
        )

    tool_name, args = extract_tool_name_and_args(payload)
    target_path_str = extract_target_path(args)

    # 1. Viewing rules file is ALWAYS allowed at Turn 1
    if tool_name == "view_file" and is_rules_file(target_path_str):
        return pre_tool_response("allow", "Viewing rules file is permitted for Turn-1 Gate.")

    # 2. Writing CANARY_VERIFIED to progress.md is permitted
    if tool_name in ("write_to_file", "replace_file_content", "multi_replace_file_content"):
        content = str(args.get("CodeContent", "") or args.get("ReplacementContent", ""))
        if target_path_str:
            t_name = pathlib.Path(target_path_str.strip().strip('"').strip("'")).name.lower()
            if ("progress" in t_name and t_name.endswith(".md")) and ("CANARY_VERIFIED:" in content):
                return pre_tool_response("allow", "Recording CANARY_VERIFIED into progress file is permitted.")

    # 3. Fail-closed: If tool_name is missing or cannot be determined, deny
    if not tool_name:
        log_diagnostic("BLOCKED: Tool name is missing or cannot be resolved (Fail-Closed).")
        return pre_tool_response(
            "deny",
            "CỔNG BẮT BUỘC TURN 1 (ENFORCED TURN-1 ACTION GATE): Không xác định được tên công cụ (Fail-Closed). "
            "BẮT BUỘC hoàn tất thủ tục Turn 1 bằng 'view_file' trên file rules trước."
        )

    # 4. Check if Turn-1 has been verified
    workspace_roots = get_workspace_roots(payload)
    if has_turn_1_verified(workspace_roots, payload):
        return pre_tool_response("allow", "Turn-1 Gate verified (CANARY_VERIFIED active).")

    # 5. Deny everything else with actionable instructions
    reason = (
        "CỔNG BẮT BUỘC TURN 1 (ENFORCED TURN-1 ACTION GATE): Thao tác bị CHẶN! Bạn chưa hoàn thành thủ tục Turn 1:\n"
        "1. BẮT BUỘC dùng công cụ 'view_file' mở đọc toàn văn tệp quy tắc chuyên môn (AGENTS.md / LEAD_PM_RULES.md / PM_RULES.md / BACKEND_RULES.md...).\n"
        "2. Trích xuất CANARY_TOKEN và ghi nhận 'CANARY_VERIFIED: [TOKEN]' vào dòng đầu tiên của progress.md.\n"
        "Mọi hành động gọi tool kỹ thuật, viết code, sửa file hoặc chạy lệnh đều bị từ chối cho đến khi hoàn tất 2 bước trên!"
    )
    log_diagnostic(f"BLOCKED tool '{tool_name}' at Turn-1 Gate: Canary not verified.")
    return pre_tool_response("deny", reason)


def run_self_tests() -> bool:
    """Comprehensive Self-Test Suite covering all hardened Turn-1 scenarios."""
    print("======================================================================")
    print("Running Turn-1 Gate Enforcer Hardened Self-Test Suite (W5)")
    print("======================================================================\n")

    import tempfile
    test_results: list[tuple[str, bool, str]] = []

    def record(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        test_results.append((name, passed, detail))
        print(f"[{status}] {name}{f' - {detail}' if detail and not passed else ''}")

    with tempfile.TemporaryDirectory() as temp_dir:
        t_root = pathlib.Path(temp_dir)

        # TC1: Deny write_to_file on app.py before canary (toolCall.name)
        r1 = evaluate_turn_1_gate({
            "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(t_root / "app.py"), "CodeContent": "print(1)"}},
            "workspacePaths": [str(t_root)],
            "sessionStartTime": time.time(),
        })
        record("TC1: Deny write_to_file before canary", r1.get("decision") == "deny")

        # TC2: Deny run_command before canary using top-level tool_name (Normalization check)
        r2 = evaluate_turn_1_gate({
            "tool_name": "run_command",
            "args": {"CommandLine": "dir"},
            "workspacePaths": [str(t_root)],
            "sessionStartTime": time.time(),
        })
        record("TC2: Deny run_command via top-level tool_name before canary", r2.get("decision") == "deny")

        # TC3: Allow view_file on BACKEND_RULES.md
        r3 = evaluate_turn_1_gate({
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": "C:/rules/BACKEND_RULES.md"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC3: Allow view_file on BACKEND_RULES.md", r3.get("decision") == "allow")

        # TC4: Allow view_file on LEAD_PM_RULES.md
        r4 = evaluate_turn_1_gate({
            "tool_name": "view_file",
            "args": {"AbsolutePath": "~/.gemini/config/enterprise-hooks/rules_by_role/lead_pm/LEAD_PM_RULES.md"},
            "workspacePaths": [str(t_root)],
        })
        record("TC4: Allow view_file on LEAD_PM_RULES.md", r4.get("decision") == "allow")

        # TC4b: Allow view_file on LEAD_PM_RULES_INDEX.md
        r4b = evaluate_turn_1_gate({
            "tool_name": "view_file",
            "args": {"AbsolutePath": "~/.gemini/config/enterprise-hooks/rules_by_role/lead_pm/LEAD_PM_RULES_INDEX.md"},
            "workspacePaths": [str(t_root)],
        })
        record("TC4b: Allow view_file on LEAD_PM_RULES_INDEX.md", r4b.get("decision") == "allow")

        # TC5: Allow view_file on LEAD_WATCHDOG_RULES.md
        r5 = evaluate_turn_1_gate({
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": "C:/rules_by_role/lead_watchdog/LEAD_WATCHDOG_RULES.md"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC5: Allow view_file on LEAD_WATCHDOG_RULES.md", r5.get("decision") == "allow")

        # TC6: Allow view_file on WATCHDOG_RULES.md
        r6 = evaluate_turn_1_gate({
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": "C:/rules_by_role/watchdog_inspector/WATCHDOG_RULES.md"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC6: Allow view_file on WATCHDOG_RULES.md", r6.get("decision") == "allow")

        # TC7: Allow view_file on PM_CHALLENGER_RULES.md
        r7 = evaluate_turn_1_gate({
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": "C:/rules_by_role/pm_challenger/PM_CHALLENGER_RULES.md"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC7: Allow view_file on PM_CHALLENGER_RULES.md", r7.get("decision") == "allow")

        # TC8: Allow view_file on EXPLORER_RULES.md
        r8 = evaluate_turn_1_gate({
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": "C:/rules_by_role/codebase_explorer/EXPLORER_RULES.md"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC8: Allow view_file on EXPLORER_RULES.md", r8.get("decision") == "allow")

        # TC9: Allow view_file on AGENTS.md
        r9 = evaluate_turn_1_gate({
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": "C:/config/rules/AGENTS.md"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC9: Allow view_file on AGENTS.md", r9.get("decision") == "allow")

        # TC10: Allow view_file on PM_RULES.md
        r10 = evaluate_turn_1_gate({
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": "C:/rules_by_role/pm_orchestrator/PM_RULES.md"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC10: Allow view_file on PM_RULES.md", r10.get("decision") == "allow")

        # TC11: Allow view_file on remaining dev rules
        dev_rule_files = ["FRONTEND_RULES.md", "QA_RULES.md", "TECH_LEAD_RULES.md", "DEVOPS_RULES.md"]
        tc11_pass = True
        for rf in dev_rule_files:
            res = evaluate_turn_1_gate({
                "toolCall": {"name": "view_file", "args": {"AbsolutePath": f"C:/rules/{rf}"}},
                "workspacePaths": [str(t_root)],
            })
            if res.get("decision") != "allow":
                tc11_pass = False
                break
        record("TC11: Allow view_file on all dev/specialist rules", tc11_pass)

        # TC12: Allow write_to_file on progress.md with CANARY_VERIFIED
        r12 = evaluate_turn_1_gate({
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(t_root / "progress.md"),
                    "CodeContent": "CANARY_VERIFIED: CANARY-TEST-123\n# Progress",
                },
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC12: Allow write_to_file on progress.md with CANARY_VERIFIED", r12.get("decision") == "allow")

        # TC13: Fail-closed on empty payload before canary
        r13 = evaluate_turn_1_gate({})
        record("TC13: Fail-closed: Deny malformed / empty payload", r13.get("decision") == "deny")

        # TC14: Fail-closed on missing tool_name before canary
        r14 = evaluate_turn_1_gate({"args": {"TargetFile": "test.txt"}})
        record("TC14: Fail-closed: Deny missing tool_name", r14.get("decision") == "deny")

        # TC15: Stale State Bypass Test - Pre-existing progress.md from previous session MUST BE DENIED
        now = time.time()
        stale_time = now - 3600.0  # 1 hour ago
        p_file = t_root / "progress.md"
        p_file.write_text("CANARY_VERIFIED: STALE-CANARY\n# Progress", encoding="utf-8")
        os.utime(p_file, (stale_time, stale_time))
        empty_tr = t_root / "empty_transcript.jsonl"
        empty_tr.write_text("", encoding="utf-8")

        r15 = evaluate_turn_1_gate({
            "tool_name": "run_command",
            "args": {"CommandLine": "pytest"},
            "workspacePaths": [str(t_root)],
            "sessionStartTime": now,
            "transcriptPath": str(empty_tr),
        })
        record("TC15: Stale State: Deny tool call when progress.md is from older session", r15.get("decision") == "deny")

        # TC16: Stale State Remediation - When progress.md is updated in current session, ALLOW
        fresh_time = now + 1.0
        p_file.write_text("CANARY_VERIFIED: FRESH-CANARY\n# Progress", encoding="utf-8")
        os.utime(p_file, (fresh_time, fresh_time))

        r16 = evaluate_turn_1_gate({
            "tool_name": "run_command",
            "args": {"CommandLine": "pytest"},
            "workspacePaths": [str(t_root)],
            "sessionStartTime": now,
        })
        record("TC16: Fresh State: Allow tool call when progress.md is fresh in current session", r16.get("decision") == "allow")

        # TC17: Transcript Verification - Mock transcript with view_file on rules allows execution
        transcript_file = t_root / "test_transcript.jsonl"
        transcript_data = [
            {"step_index": 0, "type": "USER_INPUT", "created_at": "2026-09-12T00:00:00Z", "content": "Start"},
            {
                "step_index": 1,
                "type": "PLANNER_RESPONSE",
                "tool_calls": [{"name": "view_file", "args": {"AbsolutePath": "C:/rules_by_role/lead_pm/LEAD_PM_RULES.md"}}],
            },
        ]
        with open(transcript_file, "w", encoding="utf-8") as tf:
            for item in transcript_data:
                tf.write(json.dumps(item) + "\n")

        # Stale progress.md but transcript PROVES rules were read in current session!
        os.utime(p_file, (stale_time, stale_time))
        r17 = evaluate_turn_1_gate({
            "toolCall": {"name": "run_command", "args": {"CommandLine": "dir"}},
            "workspacePaths": [str(t_root)],
            "transcriptPath": str(transcript_file),
            "sessionStartTime": now,
        })
        record("TC17: Transcript Proof: Allow when transcript records view_file on rules", r17.get("decision") == "allow")

        # TC18: Transcript Verification Negative - Transcript lacks rules read, progress.md is stale -> DENY
        empty_transcript = t_root / "empty_transcript.jsonl"
        with open(empty_transcript, "w", encoding="utf-8") as tf:
            tf.write(json.dumps({"step_index": 0, "type": "USER_INPUT", "content": "Hi"}) + "\n")

        r18 = evaluate_turn_1_gate({
            "toolCall": {"name": "run_command", "args": {"CommandLine": "dir"}},
            "workspacePaths": [str(t_root)],
            "transcriptPath": str(empty_transcript),
            "sessionStartTime": now,
        })
        record("TC18: Transcript Proof Negative: Deny when transcript lacks view_file and progress is stale", r18.get("decision") == "deny")

        # Reset progress.md to fresh
        os.utime(p_file, (time.time() + 10, time.time() + 10))

        # TC19: Allow write_to_file on code after fresh canary
        r19 = evaluate_turn_1_gate({
            "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(t_root / "app.py"), "CodeContent": "print(1)"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC19: Allow write_to_file on code after canary", r19.get("decision") == "allow")

        # TC20: Allow invoke_subagent after fresh canary
        r20 = evaluate_turn_1_gate({
            "toolCall": {"name": "invoke_subagent", "args": {"Subagents": [{"Role": "Dev", "TypeName": "self"}]}},
            "workspacePaths": [str(t_root)],
        })
        record("TC20: Allow invoke_subagent after canary", r20.get("decision") == "allow")

        # TC21: Direct payload override
        r21 = evaluate_turn_1_gate({
            "toolCall": {"name": "run_command", "args": {"CommandLine": "echo 1"}},
            "canary_verified": True,
        })
        record("TC21: Direct payload canary_verified flag", r21.get("decision") == "allow")

        # TC22: Namespace prefix support (default_api:view_file and default_api:run_command)
        r22_a = evaluate_turn_1_gate({
            "toolCall": {"name": "default_api:view_file", "args": {"AbsolutePath": "C:/rules_by_role/backend_developer/BACKEND_RULES.md"}},
            "workspacePaths": [str(t_root)],
        })
        r22_b = evaluate_turn_1_gate({
            "toolCall": {"name": "default_api:run_command", "args": {"CommandLine": "echo 1"}},
            "workspacePaths": [str(t_root)],
            "canary_verified": True,
        })
        record("TC22: Tool namespace prefix support", r22_a.get("decision") == "allow" and r22_b.get("decision") == "allow")

        # TC23: Subprocess execution streaming check
        proc = subprocess.run(
            [sys.executable, str(pathlib.Path(__file__).resolve())],
            input=json.dumps({
                "toolCall": {"name": "run_command", "args": {"CommandLine": "whoami"}},
                "workspacePaths": [tempfile.gettempdir()],
                "canary_verified": True,
            }),
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        sub_out = json.loads(proc.stdout) if proc.stdout.strip() else {}
        record("TC23: Subprocess execution streaming", proc.returncode == 0 and sub_out.get("decision") == "allow")

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
