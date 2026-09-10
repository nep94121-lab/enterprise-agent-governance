#!/usr/bin/env python3
"""Pre-Stop Enterprise Checklist Audit Hook (Stop) for Enterprise Multi-Agent Governance System.

Audits termination criteria prior to agent completion:
1. Verifies fullyIdle status (no lingering background tasks or zombie processes).
2. Verifies background tasks / active tasks in payload.
3. Audits workspace cleanliness and zero-garbage invariants (§29).
4. Zero-Hardcode architecture: dynamic limits and rules sourced via hook_utils.config_loader.
5. Robust boolean coercion & payload sanitization.
6. Safe subprocess execution: parameter array, shell=False, timeouts, UTF-8 decoding.
7. Robust porcelain line parsing without false positives (fixes P0 where 'temp' in substring matched 'templates' or 'attempt').

Returns 'continue' to prevent premature stop if criteria are unmet, or 'allow' if verified.
Supports built-in self-test suite via '--self-test' flag.
"""

from __future__ import annotations

import fnmatch
import io
import json
import pathlib
import subprocess
import sys
from typing import Any

# Enforce UTF-8 standard encoding across all platforms (Windows PowerShell safety)
try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

# Ensure local hooks library and root enterprise-hooks package are importable
HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).parent.resolve()
ENTERPRISE_ROOT = HOOKS_SCRIPTS_DIR.parent.resolve()
if str(HOOKS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_SCRIPTS_DIR))
if str(ENTERPRISE_ROOT) not in sys.path:
    sys.path.insert(0, str(ENTERPRISE_ROOT))

from common_hook_lib import (  # noqa: E402
    emit_stdout_json,
    get_workspace_roots,
    log_diagnostic,
    read_stdin_payload,
    stop_response,
)

# Optional dynamic config loader from hook_utils
try:
    from hook_utils import (  # noqa: E402
        get_dynamic_limits,
        get_execution_timeouts,
        get_pre_stop_audit_config,
    )
except ImportError:
    try:
        from hook_utils.config_loader import (  # noqa: E402
            get_dynamic_limits,
            get_execution_timeouts,
            get_pre_stop_audit_config,
        )
    except ImportError:
        get_dynamic_limits = None
        get_execution_timeouts = None
        get_pre_stop_audit_config = None

try:
    from config_loader import get_governance_config  # noqa: E402
except ImportError:
    get_governance_config = None


# Default Governance Parameters (Zero-Config Resilience Fallback)
DEFAULT_PRE_STOP_CONFIG: dict[str, Any] = {
    "enabled": True,
    "enforce_fully_idle": True,
    "check_background_tasks": True,
    "check_git_cleanliness": True,
    "git_status_timeout_seconds": 10.0,
    "untracked_junk_extensions": [
        ".tmp",
        ".bak",
        ".swp",
        ".temp",
        ".orig",
        ".rej",
        ".pyc",
    ],
    "untracked_junk_prefixes": [
        "temp_",
        "tmp_",
        "~$",
    ],
    "untracked_junk_patterns": [
        "*.tmp",
        "*.bak",
        "*.swp",
        "*~",
        "*.temp",
        "temp_*",
        "tmp_*",
        "~*",
    ],
    "ignored_paths": [
        ".git",
        "node_modules",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        ".venv",
        "venv",
        ".gemini",
    ],
    "allowed_exceptions": [
        "templates",
        "template",
        "attempt",
    ],
    "rejection_messages": {
        "active_tasks": (
            "❌ PRE-STOP AUDIT FAILED: Active background tasks or asynchronous processes are still running. "
            "Please terminate all background processes using 'manage_task' action='kill' or wait for completion (§29)."
        ),
        "untracked_junk": (
            "❌ PRE-STOP AUDIT FAILED (Zero-Garbage §29): Untracked temporary/junk artifacts detected in working tree: "
            "{junk_list}. Please clean up temporary files (.tmp, .bak, temp) before terminating."
        ),
    },
}

TRUTHY_VALUES: frozenset[str] = frozenset({"true", "1", "yes", "on", "y", "t"})
FALSY_VALUES: frozenset[str] = frozenset({"false", "0", "no", "off", "n", "f"})


def load_audit_configuration() -> dict[str, Any]:
    """Retrieve dynamic pre-stop audit configuration with multi-source fallback."""
    config = dict(DEFAULT_PRE_STOP_CONFIG)

    # 1. Primary dynamic configuration from hook_utils
    if get_pre_stop_audit_config is not None:
        try:
            dynamic_cfg = get_pre_stop_audit_config()
            if isinstance(dynamic_cfg, dict):
                config.update(dynamic_cfg)
        except Exception as exc:
            log_diagnostic(f"Failed to load dynamic pre-stop config from hook_utils: {exc}")

    # 2. Execution timeout override from dynamic_limits
    if get_execution_timeouts is not None:
        try:
            timeouts = get_execution_timeouts()
            if isinstance(timeouts, dict) and "light_command_timeout_seconds" in timeouts:
                config.setdefault("git_status_timeout_seconds", timeouts["light_command_timeout_seconds"])
        except Exception as exc:
            log_diagnostic(f"Failed to read execution timeouts: {exc}")

    return config


def coerce_boolean(val: Any, default: bool = True) -> bool:
    """Coerce boolean or loose string/numeric representation safely."""
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        clean = val.strip().lower()
        if clean in FALSY_VALUES:
            return False
        if clean in TRUTHY_VALUES:
            return True
        return clean not in FALSY_VALUES
    return bool(val)


def is_junk_artifact(
    rel_path_str: str,
    junk_patterns: list[str],
    junk_extensions: list[str],
    junk_prefixes: list[str],
    allowed_exceptions: list[str],
    ignored_paths: list[str],
) -> bool:
    """Classify if untracked porcelain path represents temporary/junk artifact without false positives."""
    clean_str = rel_path_str.strip().strip('"').strip("'")
    if not clean_str:
        return False

    norm_path = pathlib.PurePath(clean_str.replace("\\", "/"))
    file_name = norm_path.name
    lower_name = file_name.lower()
    full_lower = str(norm_path).lower()

    # Exclude ignored directory/path components (.git, node_modules, etc.)
    for ignored in ignored_paths:
        ignored_clean = ignored.strip().lower()
        if any(part.lower() == ignored_clean for part in norm_path.parts):
            return False

    # Check allowed exceptions (e.g. template, templates, attempt) to avoid false positives
    for exc in allowed_exceptions:
        exc_clean = exc.strip().lower()
        if exc_clean in norm_path.stem.lower() and not any(lower_name.endswith(ext.lower()) for ext in junk_extensions):
            return False

    # 1. Check exact suffix / extension match (.tmp, .bak, .swp, .temp)
    for ext in junk_extensions:
        ext_clean = ext.lower() if ext.startswith(".") else f".{ext.lower()}"
        if lower_name.endswith(ext_clean):
            return True

    # 2. Check filename prefix match (temp_xxx, tmp_xxx, ~$xxx)
    for pfx in junk_prefixes:
        if lower_name.startswith(pfx.lower()):
            return True

    # 3. Check fnmatch glob patterns against full path and filename
    for pat in junk_patterns:
        if fnmatch.fnmatch(lower_name, pat.lower()) or fnmatch.fnmatch(full_lower, pat.lower()):
            return True

    # 4. Check dedicated temporary folder components (e.g. "temp/...", "tmp/...", ".tmp/...")
    for part in norm_path.parts[:-1]:
        part_lower = part.lower()
        if part_lower in ("temp", "tmp", ".tmp", ".temp"):
            return True

    return False


def check_workspace_cleanliness(
    workspace_path: pathlib.Path,
    config: dict[str, Any],
) -> list[str]:
    """Inspect untracked files in git repository at workspace_path."""
    if not workspace_path.exists() or not workspace_path.is_dir():
        return []

    timeout_sec = config.get("git_status_timeout_seconds", 10.0)
    try:
        timeout_sec = float(timeout_sec)
    except (ValueError, TypeError):
        timeout_sec = 10.0

    junk_patterns = list(config.get("untracked_junk_patterns", []))
    junk_extensions = list(config.get("untracked_junk_extensions", []))
    junk_prefixes = list(config.get("untracked_junk_prefixes", []))
    allowed_exceptions = list(config.get("allowed_exceptions", []))
    ignored_paths = list(config.get("ignored_paths", []))

    try:
        git_res = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
            cwd=str(workspace_path),
            shell=False,
            check=False,
        )
        if git_res.returncode != 0:
            return []

        lines = [line.strip() for line in git_res.stdout.splitlines() if line.strip()]
        untracked_junk: list[str] = []

        for line in lines:
            if not line.startswith("??"):
                continue
            raw_path = line[2:].strip()
            if is_junk_artifact(
                raw_path,
                junk_patterns=junk_patterns,
                junk_extensions=junk_extensions,
                junk_prefixes=junk_prefixes,
                allowed_exceptions=allowed_exceptions,
                ignored_paths=ignored_paths,
            ):
                untracked_junk.append(line)

        return untracked_junk

    except (FileNotFoundError, subprocess.TimeoutExpired, OSError, subprocess.SubprocessError) as exc:
        log_diagnostic(f"Git status check skipped for {workspace_path}: {exc}")
        return []


def audit_pre_stop(payload: dict) -> dict:
    """Audit pre-stop conditions and determine if agent is clear to terminate."""
    if not isinstance(payload, dict):
        payload = {}

    config = load_audit_configuration()
    if not config.get("enabled", True):
        log_diagnostic("Pre-stop checklist audit is disabled via configuration.")
        res = stop_response("allow", "Pre-stop enterprise audit is disabled.")
        res["verdict"] = "ALLOW"
        return res

    # 1. Background task idle verification (Zero-Zombie Process Rule)
    raw_idle = payload.get("fullyIdle", True)
    fully_idle = coerce_boolean(raw_idle, default=True)

    # Inspect active tasks / background tasks in payload
    active_tasks = payload.get("activeTasks")
    if active_tasks:
        if isinstance(active_tasks, list) and len(active_tasks) > 0:
            fully_idle = False
        elif isinstance(active_tasks, (int, float)) and active_tasks > 0:
            fully_idle = False

    bg_tasks = payload.get("backgroundTasks")
    if bg_tasks:
        if isinstance(bg_tasks, list) and len(bg_tasks) > 0:
            fully_idle = False
        elif isinstance(bg_tasks, (int, float)) and bg_tasks > 0:
            fully_idle = False

    termination_reason = str(payload.get("terminationReason", "unknown"))
    error_msg = str(payload.get("error", ""))

    log_diagnostic(
        f"Pre-stop audit initiated. Reason: '{termination_reason}', fullyIdle: {fully_idle}, error: '{error_msg}'"
    )

    if config.get("enforce_fully_idle", True) and not fully_idle:
        rejection_msgs = config.get("rejection_messages", {})
        default_reason = (
            "❌ PRE-STOP AUDIT FAILED: Active background tasks or asynchronous processes are still running. "
            "Please terminate all background processes using 'manage_task' action='kill' or wait for completion (§29)."
        )
        reason = rejection_msgs.get("active_tasks", default_reason)
        log_diagnostic("Blocked termination due to non-idle background tasks.")
        res = stop_response("continue", reason)
        res["verdict"] = "CONTINUE"
        return res

    # 2. Error inspection (diagnostic logging)
    if error_msg:
        log_diagnostic(f"Stop triggered with error: {error_msg}")

    # 3. Workspace cleanliness check across workspace roots (§29 Zero-Garbage)
    workspace_roots = get_workspace_roots(payload)
    if config.get("check_git_cleanliness", True):
        all_untracked_junk: list[str] = []

        for root in workspace_roots:
            junk = check_workspace_cleanliness(root, config)
            all_untracked_junk.extend(junk)

        if all_untracked_junk:
            rejection_msgs = config.get("rejection_messages", {})
            template = rejection_msgs.get(
                "untracked_junk",
                "❌ PRE-STOP AUDIT FAILED (Zero-Garbage §29): Untracked temporary/junk artifacts detected in working tree: "
                "{junk_list}. Please clean up temporary files (.tmp, .bak, temp) before terminating.",
            )
            reason = template.replace("{junk_list}", str(all_untracked_junk))
            log_diagnostic(f"Blocked termination due to untracked temporary artifacts: {all_untracked_junk}")
            res = stop_response("continue", reason)
            res["verdict"] = "CONTINUE"
            return res

    # 4. Safe Defaults audit report
    safe_defaults_report = ""
    for root in workspace_roots:
        safe_log_path = root / "safe_defaults_log.json"
        if safe_log_path.exists():
            try:
                with open(safe_log_path, "r", encoding="utf-8") as f:
                    safe_log_data = json.load(f)
                if safe_log_data:
                    safe_defaults_report += f"\n- {root.name}: {len(safe_log_data)} Safe Defaults applied. Please review them in {safe_log_path.name}."
            except Exception as e:
                log_diagnostic(f"Failed to read {safe_log_path}: {e}")

    final_message = "Pre-stop enterprise audit passed successfully."
    if safe_defaults_report:
        final_message += "\n\n⚠️ SAFE DEFAULTS REMINDER ⚠️\nThe following Safe Defaults were automatically chosen in this session:"
        final_message += safe_defaults_report

    log_diagnostic("✅ Pre-stop checklist audit PASSED. Agent termination approved.")
    res = stop_response("allow", final_message)
    res["verdict"] = "ALLOW"
    return res


def run_self_tests() -> bool:
    """Execute comprehensive self-test suite covering all edge cases, boolean coercion, and P0 bug fixes."""
    print("======================================================================")
    print("🧪 PRE-STOP ENTERPRISE CHECKLIST AUDIT SELF-TEST SUITE")
    print("======================================================================")

    test_results: list[tuple[str, bool, str]] = []

    def record_test(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {name}{f' - {detail}' if detail else ''}")
        test_results.append((name, passed, detail))

    # Test 1-4: Boolean coercion for allowed termination
    for val in (True, 1, "true", "TRUE", "yes", "1"):
        res = audit_pre_stop({"fullyIdle": val})
        passed = res.get("decision") == "allow" and res.get("verdict") == "ALLOW"
        record_test(f"Allow termination when fullyIdle={val!r}", passed)

    # Test 5-8: Boolean coercion for blocked termination
    for val in (False, 0, "false", "FALSE", "no", "0"):
        res = audit_pre_stop({"fullyIdle": val})
        passed = (
            res.get("decision") == "continue"
            and res.get("verdict") == "CONTINUE"
            and "active background tasks" in res.get("reason", "").lower()
        )
        record_test(f"Block termination when fullyIdle={val!r}", passed)

    # Test 9: Active tasks list detection
    res_tasks = audit_pre_stop({"fullyIdle": True, "activeTasks": ["task-123"]})
    record_test(
        "Block termination when activeTasks is non-empty list",
        res_tasks.get("decision") == "continue",
    )

    # Test 10: Background tasks count detection
    res_bg = audit_pre_stop({"fullyIdle": True, "backgroundTasks": 3})
    record_test(
        "Block termination when backgroundTasks > 0",
        res_bg.get("decision") == "continue",
    )

    # Test 11: Empty / Malformed payload fallback
    res_empty = audit_pre_stop({})
    record_test("Safe allow on empty payload", res_empty.get("decision") == "allow")

    res_none = audit_pre_stop(None)  # type: ignore
    record_test("Safe allow on None payload", res_none.get("decision") == "allow")

    # Test 12: Config loader integration verification
    cfg = load_audit_configuration()
    config_ok = (
        isinstance(cfg, dict)
        and "untracked_junk_patterns" in cfg
        and "untracked_junk_extensions" in cfg
        and "git_status_timeout_seconds" in cfg
    )
    record_test("Dynamic config loader returns valid schema", config_ok)

    # Test 13: P0 False Positive Immunity (templates, attempt, etc.)
    junk_patterns = cfg.get("untracked_junk_patterns", [])
    junk_extensions = cfg.get("untracked_junk_extensions", [])
    junk_prefixes = cfg.get("untracked_junk_prefixes", [])
    allowed_exceptions = cfg.get("allowed_exceptions", [])
    ignored_paths = cfg.get("ignored_paths", [])

    fp_samples = [
        "templates/index.html",
        "app/template_controller.py",
        "views/email_templates/welcome.html",
        "attempt_recorder.py",
        "user_attempt.json",
        "models/template.ts",
    ]
    fp_all_clean = True
    for sample in fp_samples:
        is_junk = is_junk_artifact(
            sample,
            junk_patterns=junk_patterns,
            junk_extensions=junk_extensions,
            junk_prefixes=junk_prefixes,
            allowed_exceptions=allowed_exceptions,
            ignored_paths=ignored_paths,
        )
        if is_junk:
            fp_all_clean = False
            record_test(f"P0 Check: False positive on {sample}", False, "Flagged as junk incorrectly")
    if fp_all_clean:
        record_test("P0 Check: Zero false positives on legitimate template/attempt files", True)

    # Test 14: True positive detection on junk artifacts
    tp_samples = [
        "scratch.tmp",
        "backup_code.bak",
        "editor_state.swp",
        "temp_data.csv",
        "tmp_export.json",
        "temp/dump.sql",
        ".tmp/cache.bin",
    ]
    tp_all_detected = True
    for sample in tp_samples:
        is_junk = is_junk_artifact(
            sample,
            junk_patterns=junk_patterns,
            junk_extensions=junk_extensions,
            junk_prefixes=junk_prefixes,
            allowed_exceptions=allowed_exceptions,
            ignored_paths=ignored_paths,
        )
        if not is_junk:
            tp_all_detected = False
            record_test(f"P0 Check: Missed junk artifact on {sample}", False, "Failed to flag junk")
    if tp_all_detected:
        record_test("P0 Check: Accurate classification of temporary/junk artifacts", True)

    # Test 15: Subprocess stdio streaming verification
    subproc_passed = False
    try:
        proc = subprocess.run(
            [sys.executable, str(pathlib.Path(__file__).resolve())],
            input=json.dumps({"fullyIdle": False}, ensure_ascii=False),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
            check=False,
        )
        out_json = json.loads(proc.stdout.strip())
        subproc_passed = (
            proc.returncode == 0
            and out_json.get("decision") == "continue"
            and out_json.get("verdict") == "CONTINUE"
        )
    except Exception as exc:
        record_test("Subprocess stdio streaming verification", False, str(exc))
    else:
        record_test("Subprocess stdio streaming verification", subproc_passed)

    all_passed = all(t[1] for t in test_results)
    total_passed = sum(1 for t in test_results if t[1])
    total_cases = len(test_results)

    print("\n----------------------------------------------------------------------")
    print(f"Self-Test Summary: {total_passed}/{total_cases} tests passed ({'100%' if all_passed else 'FAILED'}).")
    print("----------------------------------------------------------------------\n")
    return all_passed


def main() -> None:
    """Main CLI entrypoint for Pre-Stop Checklist Audit Hook."""
    if "--self-test" in sys.argv:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    payload = read_stdin_payload(default={})
    response = audit_pre_stop(payload)
    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()
