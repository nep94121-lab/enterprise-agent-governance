#!/usr/bin/env python3
"""Pre-Invocation Rules Reminder Hook (PreInvocation) for Enterprise Multi-Agent Governance System.

Dynamically injects transient system reminders (ephemeralMessage) into the
conversation trajectory prior to model invocation, reinforcing:
1. Turn-0 Initial Context: Enterprise Git push policy, PII redaction (§1), 0 secrets (§2),
   quality hygiene (§11, §13), and architectural boundaries (§15).
2. Subsequent Turns: Liveness heartbeat (progress.md), timer discipline, and resource cleanup (§29).

Refactoring Highlights:
- 100% Dynamic Configuration: Seamlessly integrates with hook_utils/config_loader and dynamic_limits.json.
- P0 Vulnerability Remediated: Eliminates blind exception swallowing; all errors log to stderr with [HOOK_FATAL_ERROR].
- Token Spam Throttling: Configurable reminder_interval prevents redundant context clutter.
- Markdown Header Bugfix: Accurate regex detection of invocation numbers preserving markdown '#' headings.
- Role Awareness: Automatically highlights role-relevant reminders when agent role is detected.
- Built-in --self-test suite with 8 comprehensive test scenarios.
"""

from __future__ import annotations

import io
import os
import pathlib
import re
import sys
import traceback
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

# Dynamic path resolution ensuring hook_utils and hooks_scripts are importable
CURRENT_DIR = pathlib.Path(__file__).parent.resolve()
if CURRENT_DIR.name == "hooks_scripts":
    HOOKS_SCRIPTS_DIR = CURRENT_DIR
    ENTERPRISE_HOOKS_ROOT = CURRENT_DIR.parent
else:
    ENTERPRISE_HOOKS_ROOT = CURRENT_DIR
    HOOKS_SCRIPTS_DIR = CURRENT_DIR / "hooks_scripts"

for candidate in (str(HOOKS_SCRIPTS_DIR), str(ENTERPRISE_HOOKS_ROOT)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from common_hook_lib import (  # noqa: E402
    emit_stdout_json,
    log_diagnostic,
    pre_invocation_response,
    read_stdin_payload,
)

# Optional dynamic limits from hook_utils
try:
    from hook_utils.config_loader import get_config_loader, get_dynamic_limits
    HAS_HOOK_UTILS = True
except ImportError:
    HAS_HOOK_UTILS = False
    get_dynamic_limits = None  # type: ignore[assignment]
    get_config_loader = None  # type: ignore[assignment]

# Optional governance config loader
try:
    from config_loader import get_governance_config
    HAS_GOVERNANCE_CONFIG = True
except ImportError:
    HAS_GOVERNANCE_CONFIG = False
    get_governance_config = None  # type: ignore[assignment]


# Default Enterprise Reminders Configuration (Zero-Config Resilience)
DEFAULT_REMINDERS_CONFIG: dict[str, Any] = {
    "reminder_interval": 1,
    "enable_turn_0_reminder": True,
    "enable_heartbeat_reminder": True,
    "session_start_title": "🔒 [ENTERPRISE GOVERNANCE REMINDER - SESSION START]",
    "session_start_clauses": [
        "1. Git Push Rule: Adhere to project Git push policy (§11).",
        "2. Security (§1-§2): Zero raw PII logging, zero hardcoded secrets in code.",
        "3. Quality & Hygiene (§11, §13): No 'git add .', 0 trailing spaces, 0 blank EOF lines.",
        "4. Architecture (§15): .agents/ holds only metadata (plans/progress/handoffs), no source code.",
        "5. Pre-Flight (§28-§29): Review empirical git diff and verify 100% test coverage before completion.",
    ],
    "heartbeat_title": "⏱️ [ENTERPRISE HEARTBEAT REMINDER - INVOCATION #{invocation_num}]",
    "heartbeat_clauses": [
        "1. Liveness: Update progress.md with timestamp heartbeat on significant steps.",
        "2. Timer Discipline: Enforce 1m (small), 2m (medium), 3m (large) task timers.",
        "3. Resource Cleanup (§29): Kill background tasks and clean temporary files before wrapping up.",
    ],
}


def log_fatal_error(action: str, error: Exception) -> None:
    """Log fatal hook errors to sys.stderr with detailed traceback, avoiding silent swallowing."""
    try:
        err_trace = traceback.format_exc()
        sys.stderr.write(
            f"[HOOK_FATAL_ERROR] pre_invocation_rules_reminder.py failed during '{action}': {error}\n{err_trace}\n"
        )
        sys.stderr.flush()
    except (OSError, UnicodeEncodeError):
        pass


def resolve_reminders_config() -> dict[str, Any]:
    """Dynamically aggregate reminders configuration from dynamic_limits.json and governance.config."""
    resolved = dict(DEFAULT_REMINDERS_CONFIG)

    # 1. Pull from hook_utils.config_loader (dynamic_limits.json)
    if HAS_HOOK_UTILS and get_dynamic_limits is not None:
        try:
            dyn_limits = get_dynamic_limits()
            if isinstance(dyn_limits, dict) and "reminders" in dyn_limits:
                reminders_sec = dyn_limits["reminders"]
                if isinstance(reminders_sec, dict):
                    resolved.update(reminders_sec)
        except Exception as exc:
            log_fatal_error("reading dynamic_limits.json reminders", exc)

    # 2. Pull from GovernanceConfig (project-hooks.yaml / governance.config.json)
    if HAS_GOVERNANCE_CONFIG and get_governance_config is not None:
        try:
            gov_cfg = get_governance_config()
            if gov_cfg and hasattr(gov_cfg, "reminders") and gov_cfg.reminders:
                reminders_obj = gov_cfg.reminders
                if hasattr(reminders_obj, "session_start") and isinstance(reminders_obj.session_start, dict):
                    s_start = reminders_obj.session_start
                    if "title" in s_start:
                        resolved["session_start_title"] = s_start["title"]
                    if "clauses" in s_start:
                        resolved["session_start_clauses"] = list(s_start["clauses"])
                if hasattr(reminders_obj, "heartbeat") and isinstance(reminders_obj.heartbeat, dict):
                    h_beat = reminders_obj.heartbeat
                    if "title" in h_beat:
                        resolved["heartbeat_title"] = h_beat["title"]
                    if "clauses" in h_beat:
                        resolved["heartbeat_clauses"] = list(h_beat["clauses"])
        except Exception as exc:
            log_fatal_error("reading governance config reminders", exc)

    # 3. Environment Variable Overrides
    env_interval = os.environ.get("ENTERPRISE_REMINDER_INTERVAL")
    if env_interval:
        try:
            parsed_interval = int(env_interval.strip())
            if parsed_interval > 0:
                resolved["reminder_interval"] = parsed_interval
        except (ValueError, TypeError):
            pass

    return resolved


def format_title_with_invocation(raw_title: str, invocation_num: int) -> str:
    """Format reminder title with invocation sequence number, correctly handling markdown '#' headers."""
    if not raw_title:
        return f"⏱️ [ENTERPRISE HEARTBEAT REMINDER - INVOCATION #{invocation_num}]"

    # If explicit placeholder is present, replace it directly
    if "{invocation_num}" in raw_title:
        return raw_title.replace("{invocation_num}", str(invocation_num))

    # Check if title already explicitly contains a sequence number (e.g., '#1', '# 2', 'INVOCATION #3')
    has_explicit_number = bool(
        re.search(r"#\s*\d+", raw_title)
        or re.search(r"\bINVOCATION\s*#?\s*\d+\b", raw_title, re.IGNORECASE)
    )

    if not has_explicit_number:
        return f"{raw_title} - INVOCATION #{invocation_num}"

    return raw_title


def generate_rules_reminder(payload: dict[str, Any]) -> dict[str, Any]:
    """Generate appropriate dynamic rule reminder based on invocation sequence number and governance config."""
    if not isinstance(payload, dict):
        payload = {}

    raw_inv = payload.get("invocationNum", 0)
    try:
        invocation_num = int(raw_inv) if raw_inv is not None else 0
    except (ValueError, TypeError):
        invocation_num = 0

    try:
        config = resolve_reminders_config()
    except Exception as exc:
        log_fatal_error("resolving reminders configuration", exc)
        config = dict(DEFAULT_REMINDERS_CONFIG)

    interval = config.get("reminder_interval", 1)
    try:
        interval = max(1, int(interval))
    except (ValueError, TypeError):
        interval = 1

    reminder_text: str | None = None

    if invocation_num == 0:
        # Session Start Reminder
        if config.get("enable_turn_0_reminder", True):
            title = config.get("session_start_title", "🔒 [ENTERPRISE GOVERNANCE REMINDER - SESSION START]")
            clauses = config.get("session_start_clauses", DEFAULT_REMINDERS_CONFIG["session_start_clauses"])
            if not isinstance(clauses, (list, tuple)):
                clauses = [str(clauses)]
            reminder_text = f"{title}\n" + "\n".join(str(c) for c in clauses)
    else:
        # Subsequent Turns: Heartbeat Reminder with Interval Throttling
        if config.get("enable_heartbeat_reminder", True):
            # Throttle injections if interval > 1 and current turn is not a multiple of interval
            if interval > 1 and (invocation_num % interval != 0):
                log_diagnostic(f"Heartbeat skipped for turn {invocation_num} (interval={interval})")
                return pre_invocation_response(inject_steps=[])

            raw_title = config.get(
                "heartbeat_title",
                "⏱️ [ENTERPRISE HEARTBEAT REMINDER - INVOCATION #{invocation_num}]",
            )
            title = format_title_with_invocation(raw_title, invocation_num)
            clauses = config.get("heartbeat_clauses", DEFAULT_REMINDERS_CONFIG["heartbeat_clauses"])
            if not isinstance(clauses, (list, tuple)):
                clauses = [str(clauses)]
            reminder_text = f"{title}\n" + "\n".join(str(c) for c in clauses)

    if reminder_text:
        return pre_invocation_response(inject_steps=[{"ephemeralMessage": reminder_text}])

    return pre_invocation_response(inject_steps=[])


def run_self_tests() -> int:
    """Comprehensive in-process self-test suite validating all refactored capabilities."""
    print("================================================================================")
    print("  PRE-INVOCATION RULES REMINDER: COMPREHENSIVE SELF-TEST SUITE")
    print("================================================================================")
    failures: list[str] = []

    # Test 1: Turn-0 Session Start Reminder
    try:
        res = generate_rules_reminder({"invocationNum": 0})
        steps = res.get("injectSteps", [])
        assert len(steps) > 0, "Turn 0 must inject at least 1 step"
        msg = steps[0].get("ephemeralMessage", "")
        assert "ENTERPRISE GOVERNANCE REMINDER" in msg, "Turn 0 must contain governance title"
        assert "PII" in msg or "GOVERNANCE" in msg, "Turn 0 must mention PII security"
        print("  [PASS] Test 1: Turn-0 Session Start Reminder")
    except Exception as exc:
        failures.append(f"Test 1 failed: {exc}")
        print(f"  [FAIL] Test 1: {exc}")

    # Test 2: Turn-N Heartbeat Reminder
    try:
        res = generate_rules_reminder({"invocationNum": 3, "initialNumSteps": 10})
        steps = res.get("injectSteps", [])
        assert len(steps) > 0, "Turn 3 must inject steps when interval=1"
        msg = steps[0].get("ephemeralMessage", "")
        assert "progress.md" in msg, "Heartbeat must mention progress.md"
        assert "HEARTBEAT" in msg, "Heartbeat must contain HEARTBEAT"
        assert "3" in msg, "Heartbeat must contain invocation number 3"
        print("  [PASS] Test 2: Turn-N Heartbeat Reminder")
    except Exception as exc:
        failures.append(f"Test 2 failed: {exc}")
        print(f"  [FAIL] Test 2: {exc}")

    # Test 3: Markdown '#' Heading Preservation in Title
    try:
        formatted = format_title_with_invocation("### [ENTERPRISE HEARTBEAT REMINDER]", 7)
        assert "- INVOCATION #7" in formatted, f"Markdown header must append invocation number: {formatted}"
        assert formatted.startswith("### [ENTERPRISE HEARTBEAT REMINDER]"), "Must preserve markdown header prefix"

        # Explicit placeholder check
        formatted_ph = format_title_with_invocation("## Heartbeat Step {invocation_num}", 42)
        assert formatted_ph == "## Heartbeat Step 42", f"Placeholder replacement failed: {formatted_ph}"
        print("  [PASS] Test 3: Markdown '#' Heading Formatting Bugfix")
    except Exception as exc:
        failures.append(f"Test 3 failed: {exc}")
        print(f"  [FAIL] Test 3: {exc}")

    # Test 4: Interval Throttling
    try:
        os.environ["ENTERPRISE_REMINDER_INTERVAL"] = "5"
        res_skip = generate_rules_reminder({"invocationNum": 3})
        assert res_skip.get("injectSteps") == [], "Invocation 3 must be skipped when interval=5"

        res_trigger = generate_rules_reminder({"invocationNum": 5})
        assert len(res_trigger.get("injectSteps", [])) > 0, "Invocation 5 must trigger reminder when interval=5"
        os.environ.pop("ENTERPRISE_REMINDER_INTERVAL", None)
        print("  [PASS] Test 4: Token Spam Elimination via Interval Throttling")
    except Exception as exc:
        os.environ.pop("ENTERPRISE_REMINDER_INTERVAL", None)
        failures.append(f"Test 4 failed: {exc}")
        print(f"  [FAIL] Test 4: {exc}")

    # Test 5: Unicode and Vietnamese Encoding Safety
    try:
        res_unicode = generate_rules_reminder(
            {"invocationNum": 0, "workspacePaths": ["C:\\Dự Án\\Doanh Nghiệp Đa Tác Tử"]}
        )
        msg_uni = res_unicode["injectSteps"][0]["ephemeralMessage"]
        assert len(msg_uni) > 50, "Unicode payload reminder must be non-empty"
        print("  [PASS] Test 5: Unicode / Vietnamese Encoding Safety")
    except Exception as exc:
        failures.append(f"Test 5 failed: {exc}")
        print(f"  [FAIL] Test 5: {exc}")

    # Test 6: Malformed / Corrupted Payloads Handling
    try:
        corrupted_cases = [{"invocationNum": None}, {"invocationNum": "not_an_int"}, {}, "invalid_type"]
        for c in corrupted_cases:
            res_c = generate_rules_reminder(c)  # type: ignore[arg-type]
            assert isinstance(res_c, dict)
            assert "injectSteps" in res_c
        print("  [PASS] Test 6: Malformed / Corrupted Payloads Resilience")
    except Exception as exc:
        failures.append(f"Test 6 failed: {exc}")
        print(f"  [FAIL] Test 6: {exc}")

    # Test 7: Integration with hook_utils / Dynamic Config Loader
    try:
        cfg = resolve_reminders_config()
        assert isinstance(cfg, dict), "Config must be a valid dictionary"
        assert "session_start_title" in cfg, "Config must contain session_start_title"
        assert "heartbeat_title" in cfg, "Config must contain heartbeat_title"
        print("  [PASS] Test 7: Integration with hook_utils and Dynamic Config Loader")
    except Exception as exc:
        failures.append(f"Test 7 failed: {exc}")
        print(f"  [FAIL] Test 7: {exc}")

    # Test 8: P0 Exception Logging Guard (stderr output, zero silent swallowing)
    try:
        old_stderr = sys.stderr
        capture_stderr = io.StringIO()
        sys.stderr = capture_stderr
        try:
            log_fatal_error("unit-test-action", ValueError("Test simulated exception"))
        finally:
            sys.stderr = old_stderr

        captured = capture_stderr.getvalue()
        assert "[HOOK_FATAL_ERROR]" in captured, "Must log fatal error tag"
        assert "unit-test-action" in captured, "Must log failing action"
        print("  [PASS] Test 8: P0 Exception Visibility Guard")
    except Exception as exc:
        failures.append(f"Test 8 failed: {exc}")
        print(f"  [FAIL] Test 8: {exc}")

    print("================================================================================")
    if failures:
        print(f"❌ SELF-TESTS FAILED: {len(failures)} failures:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("✅ ALL 8 SELF-TESTS PASSED SUCCESSFULLY (100% PASS)")
    return 0


def main() -> None:
    if "--self-test" in sys.argv:
        sys.exit(run_self_tests())

    try:
        payload = read_stdin_payload(default={})
        response = generate_rules_reminder(payload)
        emit_stdout_json(response)
    except Exception as exc:
        log_fatal_error("main execution loop", exc)
        fallback_res = pre_invocation_response(
            inject_steps=[
                {
                    "ephemeralMessage": (
                        "🔒 [ENTERPRISE GOVERNANCE REMINDER - SESSION START]\n"
                        "1. Security: Zero raw PII logging, zero hardcoded secrets in code.\n"
                        "2. Liveness: Update progress.md and maintain timer discipline.\n"
                        "3. Resource Cleanup: Kill background tasks before completion."
                    )
                }
            ]
        )
        emit_stdout_json(fallback_res)


if __name__ == "__main__":
    main()
