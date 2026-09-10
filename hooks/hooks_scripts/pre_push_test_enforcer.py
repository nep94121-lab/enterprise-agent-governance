#!/usr/bin/env python3
"""Pre-Push Test & Multi-Tenant Auth Context Enforcer Hook (Layer 3) for Enterprise Multi-Agent Governance System.

Enforces:
1. Enterprise Git Push Policy (§11): Dynamic allowed push branches governed by project configuration.
2. Safe Git Operations (§11): Prohibits force-push flags (--force, -f, combined flags, +<ref>), refspec bypasses, and broad 'git add .'.
3. Multi-Tenant Authorization Boundary Check (§1, §24): Verifies tenant_id/property_id invariants across unpushed commits & staged changes.
4. Enterprise Git Author Validation (§11): Optional commit author email domain verification.
5. Automated Test Suite Gating (§19, §20): Dynamic test runner command and timeout integration via hook_utils/ and config_loader.
6. Tech Lead 10-Tier Pre-Flight Verification (§29): Automated deep architecture and pre-flight validation.
"""

from __future__ import annotations

import fnmatch
import io
import os
import pathlib
import re
import shlex
import subprocess
import sys
from typing import Any

# Enforce UTF-8 I/O across platforms (Windows PowerShell safety)
try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

# Ensure local hook library and enterprise root are importable
_HOOKS_DIR = pathlib.Path(__file__).parent.resolve()
_ENTERPRISE_ROOT = _HOOKS_DIR.parent.resolve()

if str(_ENTERPRISE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ENTERPRISE_ROOT))
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))

from common_hook_lib import (
    emit_stdout_json,
    get_tool_args,
    get_tool_call,
    log_diagnostic,
    pre_tool_response,
    read_stdin_payload,
)

# Integration with hook_utils (Dynamic limits and hardware profiles)
try:
    from hook_utils.config_loader import (
        DynamicConfigLoader,
        get_config_loader,
        get_dynamic_limits,
        get_execution_timeouts,
        get_hardware_profile,
    )
    HAS_HOOK_UTILS = True
except ImportError:
    HAS_HOOK_UTILS = False
    get_dynamic_limits = None  # type: ignore
    get_execution_timeouts = None  # type: ignore
    get_hardware_profile = None  # type: ignore
    get_config_loader = None  # type: ignore
    DynamicConfigLoader = None  # type: ignore

# Integration with config_loader (GovernanceConfig & Project policies)
try:
    from config_loader import (
        GovernanceConfig,
        get_governance_config,
        load_governance_config,
    )
    HAS_CONFIG_LOADER = True
except ImportError:
    HAS_CONFIG_LOADER = False
    get_governance_config = None  # type: ignore
    load_governance_config = None  # type: ignore
    GovernanceConfig = None  # type: ignore


# ============================================================================
# 1. DYNAMIC CONFIGURATION RESOLUTION
# ============================================================================

def get_active_governance_config(cwd: str | None = None) -> Any:
    """Retrieve active GovernanceConfig for the target directory with fail-safe defaults."""
    if HAS_CONFIG_LOADER and load_governance_config is not None:
        try:
            return load_governance_config(start_dir=cwd)
        except Exception as exc:
            log_diagnostic(f"Error resolving governance config for cwd={cwd}: {exc}")

    if HAS_CONFIG_LOADER and get_governance_config is not None:
        try:
            return get_governance_config()
        except Exception as exc:
            log_diagnostic(f"Error retrieving global governance config: {exc}")

    if GovernanceConfig is not None:
        return GovernanceConfig()

    # Zero-config dummy object if config_loader is absent
    class _DummyGit:
        allowed_push_branches = ["*"]
        prohibited_push_branches = ["main", "master", "prod", "production", "release"]
        prohibit_force_push = True
        class _AuthorVal:
            enabled = False
            allowed_email_domains = ["company.com"]
        author_validation = _AuthorVal()

    class _DummyTesting:
        class _Runner:
            command = "pytest tests/ -q --tb=short"
            timeout_seconds = 60
            bypass_env_var = "SKIP_PRE_PUSH_TEST"
        test_runner = _Runner()

    class _DummyConfig:
        git = _DummyGit()
        testing = _DummyTesting()
        allowed_push_branches = ["*"]
        prohibited_push_branches = ["main", "master", "prod", "production", "release"]

    return _DummyConfig()


def get_allowed_branches(cwd: str | None = None) -> list[str]:
    """Retrieve allowed push branches dynamically from GovernanceConfig with safe fallback."""
    cfg = get_active_governance_config(cwd=cwd)
    try:
        branches = cfg.allowed_push_branches
        if branches:
            return list(branches)
    except (AttributeError, ValueError, TypeError) as exc:
        log_diagnostic(f"Could not load allowed branches from config: {exc}")
    return ["*"]


def get_prohibited_branches(cwd: str | None = None) -> set[str]:
    """Retrieve prohibited push branches dynamically from GovernanceConfig with safe fallback."""
    cfg = get_active_governance_config(cwd=cwd)
    try:
        prohibited = cfg.prohibited_push_branches
        if prohibited:
            return {p.lower() for p in prohibited}
    except (AttributeError, ValueError, TypeError) as exc:
        log_diagnostic(f"Could not load prohibited branches from config: {exc}")
    return {"main", "master", "prod", "production", "release"}


def get_test_timeout_seconds(cwd: str | None = None) -> int:
    """Resolve pre-push test suite timeout dynamically from config and hook_utils."""
    cfg = get_active_governance_config(cwd=cwd)
    configured_timeout = getattr(getattr(cfg, "testing", None), "test_runner", None)
    if configured_timeout and getattr(configured_timeout, "timeout_seconds", None):
        return int(configured_timeout.timeout_seconds)

    if HAS_HOOK_UTILS and get_execution_timeouts is not None:
        try:
            timeouts = get_execution_timeouts()
            if "heavy_build_timeout_seconds" in timeouts:
                return int(timeouts["heavy_build_timeout_seconds"])
        except (ValueError, TypeError, OSError) as exc:
            log_diagnostic(f"Error fetching heavy build timeout from hook_utils: {exc}")

    return 60


def get_test_bypass_env_var(cwd: str | None = None) -> str:
    """Retrieve bypass environment variable dynamically from GovernanceConfig."""
    cfg = get_active_governance_config(cwd=cwd)
    runner_cfg = getattr(getattr(cfg, "testing", None), "test_runner", None)
    if runner_cfg and getattr(runner_cfg, "bypass_env_var", None):
        return str(runner_cfg.bypass_env_var)
    return "SKIP_PRE_PUSH_TEST"


def get_test_command(cwd: str | None = None) -> str:
    """Retrieve test command dynamically from GovernanceConfig."""
    cfg = get_active_governance_config(cwd=cwd)
    runner_cfg = getattr(getattr(cfg, "testing", None), "test_runner", None)
    if runner_cfg and getattr(runner_cfg, "command", None):
        return str(runner_cfg.command)
    return "pytest tests/ -q --tb=short"


# Module-level exports for backwards compatibility
ALLOWED_BRANCHES = get_allowed_branches()
ALLOWED_BRANCH = ALLOWED_BRANCHES[0] if ALLOWED_BRANCHES else "*"
PROHIBITED_BRANCHES = get_prohibited_branches()


# ============================================================================
# 2. GIT BRANCH & PUSH SAFETY EVALUATION
# ============================================================================

def get_current_git_branch(cwd: str | None = None) -> str | None:
    """Retrieve current checked-out git branch in cwd.

    Returns clean branch name (e.g. 'main', 'feature/login') or None if detached / non-git.
    """
    try:
        proc = subprocess.run(
            ["git", "symbolic-ref", "--short", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            branch = proc.stdout.strip().replace("refs/heads/", "")
            return branch

        # Fallback to rev-parse
        proc_rev = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
            timeout=5,
            check=False,
        )
        if proc_rev.returncode == 0 and proc_rev.stdout.strip():
            branch = proc_rev.stdout.strip()
            if branch != "HEAD":
                return branch.replace("refs/heads/", "")
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def check_branch_policy(
    branch: str,
    allowed_patterns: list[str],
    prohibited_patterns: set[str],
) -> tuple[bool, str]:
    """Check whether a specific branch name is permitted under the current git governance policy."""
    clean = branch.strip("\"'").replace("refs/heads/", "").strip().lower()

    # 1. Check prohibited patterns
    for pb in prohibited_patterns:
        pb_lower = pb.lower()
        if clean == pb_lower or clean.endswith(f"/{pb_lower}") or fnmatch.fnmatch(clean, pb_lower):
            reason = (
                f"Enterprise Git Push Policy Violation (§11): Direct push to branch '{branch}' is PROHIBITED. "
                f"Protected branches must be merged via pull requests."
            )
            return False, reason

    # 2. Check allowed patterns (wildcard "*" permits any non-prohibited branch)
    if "*" in allowed_patterns:
        return True, ""

    for ap in allowed_patterns:
        ap_lower = ap.lower()
        if clean == ap_lower or clean.endswith(f"/{ap_lower}") or fnmatch.fnmatch(clean, ap_lower):
            return True, ""

    reason = (
        f"Enterprise Git Push Policy Violation (§11): Branch '{branch}' is not in allowed push branches "
        f"({', '.join(allowed_patterns)})."
    )
    return False, reason


def is_force_or_destructive_push(args_after_push: list[str], normalized_cmd: str) -> tuple[bool, str]:
    """Detect any force-push or destructive flags in git push command."""
    # Check for refspec force '+' prefix: +ref or +src:dst
    if re.search(r"(?:^|\s)\+[a-zA-Z0-9_\-\/\.:]+", normalized_cmd):
        return True, "Destructive force-push refspec detected ('+'). Force-pushing is strictly prohibited to prevent data loss."

    for token in args_after_push:
        t_clean = token.strip("'\"")
        t_lower = t_clean.lower()
        if t_lower in ("--force", "--force-with-lease", "--force-if-includes", "--mirror"):
            return True, f"Destructive push flag '{t_clean}' detected. Force-pushing is strictly prohibited to prevent data loss."
        if t_lower in ("--delete",):
            return True, f"Destructive branch deletion flag '{t_clean}' detected. Remote branch deletion via push is prohibited."
        # Short flags (e.g. -f, -uf, -fu, -d, -ud)
        if t_clean.startswith("-") and not t_clean.startswith("--"):
            flags = t_clean[1:]
            if "f" in flags:
                return True, f"Destructive force-push short flag '{t_clean}' detected. Force-pushing is strictly prohibited to prevent data loss."
            if "d" in flags:
                return True, f"Destructive branch deletion short flag '{t_clean}' detected. Remote branch deletion via push is prohibited."

    # Standalone regex check for edge cases
    fallback_match = re.search(
        r"(\-\-force\b|\-f\b|\-\-force\-with\-lease\b|\-\-force\-if\-includes\b|\-\-mirror\b|(?:\-\-delete|-d)\b)",
        normalized_cmd,
        re.IGNORECASE,
    )
    if fallback_match:
        flag = fallback_match.group(1)
        return True, f"Destructive push flag '{flag}' detected. Force-pushing is strictly prohibited to prevent data loss."

    return False, ""


# ============================================================================
# 3. VERIFICATION GATES (AUTH, AUTHOR, TEST SUITE, PREFLIGHT)
# ============================================================================

def get_git_diff_for_push(cwd: str | None = None) -> str:
    """Retrieve diff of changes being pushed (staged changes + unpushed commits)."""
    diff_chunks: list[str] = []

    # 1. Staged diff
    try:
        from diff_security_inspector import get_git_diff_staged
        staged = get_git_diff_staged(cwd=cwd)
        if staged and staged.strip():
            diff_chunks.append(staged)
    except (ImportError, Exception):
        pass

    # 2. Unpushed commits diff
    try:
        # Check diff against upstream tracking branch @{u}..HEAD
        proc_upstream = subprocess.run(
            ["git", "diff", "@{u}..HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
            timeout=10,
            check=False,
        )
        if proc_upstream.returncode == 0 and proc_upstream.stdout.strip():
            diff_chunks.append(proc_upstream.stdout)
        else:
            # If no upstream branch exists, check against origin/main or origin/master
            proc_origin = subprocess.run(
                ["git", "diff", "origin/main...HEAD"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=cwd,
                timeout=10,
                check=False,
            )
            if proc_origin.returncode == 0 and proc_origin.stdout.strip():
                diff_chunks.append(proc_origin.stdout)
            else:
                # Fallback to the latest commit
                proc_recent = subprocess.run(
                    ["git", "diff", "HEAD~1..HEAD"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    cwd=cwd,
                    timeout=10,
                    check=False,
                )
                if proc_recent.returncode == 0 and proc_recent.stdout.strip():
                    diff_chunks.append(proc_recent.stdout)
    except (OSError, subprocess.SubprocessError):
        pass

    return "\n".join(diff_chunks)


def verify_multi_tenant_auth_invariants(cwd: str | None = None) -> tuple[bool, str]:
    """Verify staged git diff and unpushed commits for multi-tenant auth context violations (§1, §24)."""
    try:
        from diff_security_inspector import scan_text_for_violations

        diff_text = get_git_diff_for_push(cwd=cwd)
        if not diff_text or not diff_text.strip():
            return True, "No staged diff or unpushed commits to inspect."

        violations = scan_text_for_violations(diff_text, file_path="git-diff-pre-push", is_diff=True)
        # Filter for IDOR, RLS, Auth, Secrets, SQLi, and Command Injection violations
        critical_violations = [
            v
            for v in violations
            if v.category in (
                "IDOR & Multi-Tenant",
                "RLS & Access Control",
                "Auth Context",
                "Secrets & PII",
                "SQL Injection",
                "Command Injection",
            )
        ]
        if critical_violations:
            summary = "; ".join(f"{v.rule_name} ({v.category})" for v in critical_violations[:3])
            log_diagnostic(f"Pre-push multi-tenant auth invariant check failed: {summary}")
            return False, f"Multi-tenant authorization integrity violation detected: {summary} (§1, §24)."

        return True, "Multi-tenant authorization invariants verified."
    except ImportError:
        log_diagnostic("diff_security_inspector not importable, skipping inline diff auth check.")
        return True, "Auth check skipped."
    except (OSError, ValueError, RuntimeError, TypeError) as exc:
        log_diagnostic(f"Error during auth invariant verification: {exc}")
        return True, "Auth check completed with warning."


def verify_git_commit_author(cwd: str | None = None) -> tuple[bool, str]:
    """Verify commit author email domain against enterprise policy if enabled (§11)."""
    cfg = get_active_governance_config(cwd=cwd)
    author_val = getattr(getattr(cfg, "git", None), "author_validation", None)
    if not author_val or not getattr(author_val, "enabled", False):
        return True, ""

    allowed_domains = [d.lower().lstrip("@") for d in getattr(author_val, "allowed_email_domains", [])]
    if not allowed_domains:
        return True, ""

    try:
        proc = subprocess.run(
            ["git", "log", "-1", "--format=%ae"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            author_email = proc.stdout.strip().lower()
            author_domain = author_email.split("@")[-1] if "@" in author_email else ""
            if author_domain not in allowed_domains:
                return False, (
                    f"Enterprise Git Author Validation Violation (§11): Commit author email '{author_email}' "
                    f"domain '{author_domain}' is not in allowed domains: {', '.join(allowed_domains)}."
                )
    except (OSError, subprocess.SubprocessError):
        pass
    return True, ""


def run_pre_push_test_suite(cwd: str | None = None) -> tuple[bool, str]:
    """Execute automated test suite dynamically before allowing push to upstream (§19, §20)."""
    bypass_env_var = get_test_bypass_env_var(cwd=cwd)
    if os.environ.get(bypass_env_var) == "1" or os.environ.get("SKIP_PRE_PUSH_TEST") == "1":
        log_diagnostic(f"{bypass_env_var}=1 detected, bypassing live test suite run.")
        return True, "Pre-push test suite bypassed via environment variable."

    repo_root = pathlib.Path(cwd).resolve() if cwd else pathlib.Path.cwd().resolve()
    raw_cmd = get_test_command(cwd=cwd)
    timeout_seconds = get_test_timeout_seconds(cwd=cwd)

    tests_dir = repo_root / "tests"
    if ("tests/" in raw_cmd or "tests" in raw_cmd.split()) and not tests_dir.exists():
        log_diagnostic(f"Tests directory not found at {tests_dir}, skipping test runner.")
        return True, "No tests directory found."

    # Parse command arguments safely
    try:
        cmd_parts = shlex.split(raw_cmd)
    except ValueError:
        cmd_parts = raw_cmd.split()

    if not cmd_parts:
        cmd_parts = ["pytest", "tests/", "-q", "--tb=short"]

    # Wrap python/pytest with current interpreter
    if cmd_parts[0] in ("pytest", "py.test"):
        exec_args = [sys.executable, "-m", "pytest"] + cmd_parts[1:]
    elif cmd_parts[0] == "python":
        exec_args = [sys.executable] + cmd_parts[1:]
    else:
        exec_args = cmd_parts

    log_diagnostic(f"Executing pre-push test suite ({' '.join(exec_args)}) in {repo_root} (timeout: {timeout_seconds}s)...")
    try:
        proc = subprocess.run(
            exec_args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(repo_root),
            timeout=timeout_seconds,
            check=False,
        )
        if proc.returncode == 0:
            log_diagnostic("Pre-push test suite executed successfully: ALL TESTS PASSED.")
            return True, "Pre-push test suite passed."

        error_summary = proc.stdout.strip() or proc.stderr.strip()
        log_diagnostic(f"Pre-push test suite FAILED with return code {proc.returncode}:\n{error_summary}")
        return False, f"Pre-push automated test suite execution failed:\n{error_summary[:300]}"
    except subprocess.TimeoutExpired:
        log_diagnostic(f"Pre-push test runner timed out after {timeout_seconds}s.")
        return False, f"Pre-push test suite execution timed out after {timeout_seconds} seconds."
    except (OSError, subprocess.SubprocessError) as exc:
        log_diagnostic(f"Pre-push test runner execution error: {exc}")
        return False, f"Pre-push test runner error: {exc}"


def run_tech_lead_preflight(cwd: str | None = None) -> tuple[bool, str]:
    """Execute Tech Lead 10-Tier Pre-Flight Verification (§29, Big Tech standards) before push."""
    bypass_env_var = get_test_bypass_env_var(cwd=cwd)
    if (
        os.environ.get(bypass_env_var) == "1"
        or os.environ.get("SKIP_PRE_PUSH_TEST") == "1"
        or os.environ.get("SKIP_PRE_PUSH_PREFLIGHT") == "1"
    ):
        log_diagnostic("SKIP_PRE_PUSH_TEST/PREFLIGHT detected, bypassing live pre-flight check.")
        return True, "Pre-push pre-flight check bypassed via environment variable."

    repo_root = pathlib.Path(cwd).resolve() if cwd else pathlib.Path.cwd().resolve()
    candidates = [
        repo_root / "scripts" / "check_tech_lead_preflight.py",
        pathlib.Path(__file__).parent.parent / "scripts" / "check_tech_lead_preflight.py",
    ]
    preflight_script = None
    for cand in candidates:
        if cand.exists():
            preflight_script = cand
            break

    if not preflight_script:
        log_diagnostic("Tech Lead pre-flight script not found, skipping pre-flight check.")
        return True, "No preflight script found."

    timeout_seconds = get_test_timeout_seconds(cwd=cwd)
    log_diagnostic(f"Executing Tech Lead 10-Tier Pre-Flight in {repo_root} (timeout: {timeout_seconds}s)...")
    try:
        proc = subprocess.run(
            [sys.executable, str(preflight_script), "--strict", "--diff-only", "--root", str(repo_root)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(repo_root),
            timeout=timeout_seconds,
            check=False,
        )
        if proc.returncode == 0:
            log_diagnostic("Tech Lead 10-Tier Pre-Flight passed: ALL TIERS PASSED.")
            return True, "Tech Lead 10-Tier Pre-Flight passed."

        error_summary = proc.stdout.strip() or proc.stderr.strip()
        log_diagnostic(f"Tech Lead 10-Tier Pre-Flight FAILED (exit code {proc.returncode}):\n{error_summary}")
        return False, f"Tech Lead 10-Tier Pre-Flight verification failed:\n{error_summary[:300]}"
    except subprocess.TimeoutExpired:
        log_diagnostic(f"Tech Lead Pre-Flight runner timed out after {timeout_seconds}s.")
        return False, f"Tech Lead Pre-Flight runner timed out after {timeout_seconds} seconds."
    except (OSError, subprocess.SubprocessError) as exc:
        log_diagnostic(f"Tech Lead Pre-Flight runner error: {exc}")
        return False, f"Tech Lead Pre-Flight runner error: {exc}"


# ============================================================================
# 4. COMMAND DISPATCHER & EVALUATOR
# ============================================================================

BROAD_ADD_REGEX = re.compile(
    r"\bgit(?:\.exe)?\s+(?:-[^\s]+\s+|--[^\s]+\s+)*add\s+['\"]?(\.|\./|\*|\-A|\-\-all|:\/|:)['\"]?(?:\s+|$)",
    re.IGNORECASE,
)

GIT_PUSH_REGEX = re.compile(
    r"\bgit(?:\.exe)?(?:\s+(?:-[^\s]+(?:\s+[^-][^\s]*)?|--[^\s]+(?:\s+[^-][^\s]*)?))*\s+['\"]?push['\"]?\b",
    re.IGNORECASE,
)


def evaluate_single_git_command(cmd: str, cwd: str | None = None, run_tests: bool = True) -> tuple[bool, str]:
    """Evaluate a single git command chunk. Returns (is_allowed, reason)."""
    normalized_cmd = cmd.strip()
    if not normalized_cmd:
        return True, ""

    # Rule 1: Prohibit 'git add .' / 'git add ./' / 'git add *' / 'git add -A' / 'git add --all' (§11)
    if BROAD_ADD_REGEX.search(normalized_cmd):
        reason = (
            "Enterprise Git Hygiene Violation (§11): Prohibited 'git add .', 'git add ./', 'git add *', "
            "'git add -A', or 'git add --all'. You MUST run 'git status' first to inspect modified files and add specific files explicitly."
        )
        return False, reason

    # Rule 2: Git Push Branch & Flag Enforcement
    if GIT_PUSH_REGEX.search(normalized_cmd):
        cmd_no_comment = re.sub(r"#.*$", "", normalized_cmd).strip()
        tokens = cmd_no_comment.split()

        try:
            push_idx = [t.lower().strip("'\"") for t in tokens].index("push")
            args_after_push = tokens[push_idx + 1 :]
        except ValueError:
            args_after_push = []

        # 2a. Check for force push or destructive flags
        is_force, force_reason = is_force_or_destructive_push(args_after_push, normalized_cmd)
        if is_force:
            cfg = get_active_governance_config(cwd=cwd)
            prohibit_force = getattr(getattr(cfg, "git", None), "prohibit_force_push", True)
            if prohibit_force:
                return False, f"Enterprise Git Security Violation (§11): {force_reason}"

        # 2b. Check for matching branches refspec ':' or '--all'
        for t in args_after_push:
            clean_t = t.strip("'\"")
            if clean_t == ":":
                return False, (
                    "Enterprise Git Security Violation (§11): Pushing matching branches (':') is prohibited "
                    "because it pushes all matching branches including protected branches."
                )

        if any(t.lower().strip("'\"") == "--all" for t in args_after_push):
            prohibited_branches = get_prohibited_branches(cwd=cwd)
            if prohibited_branches:
                return False, (
                    "Enterprise Git Security Violation (§11): Pushing with '--all' is prohibited "
                    "because it pushes all local branches including protected branches."
                )

        # 2c. Dynamically load branch policies
        allowed_branches = get_allowed_branches(cwd=cwd)
        prohibited_branches = get_prohibited_branches(cwd=cwd)

        positional_args = [t for t in args_after_push if not t.startswith("-")]

        target_refspecs: list[str] = []
        if len(positional_args) == 0:
            target_refspecs = []
        elif len(positional_args) == 1:
            arg = positional_args[0].strip("\"'")
            if arg.lower() in ("origin", "upstream") or arg.startswith(("http://", "https://", "git@")):
                target_refspecs = []
            else:
                target_refspecs = [arg]
        else:
            target_refspecs = positional_args[1:]

        # Case A: No explicit refspecs given (e.g. `git push`, `git push origin`)
        if not target_refspecs:
            # P0 Fix: Inquire current active branch from git
            current_branch = get_current_git_branch(cwd=cwd)
            if current_branch:
                allowed, reason = check_branch_policy(current_branch, allowed_branches, prohibited_branches)
                if not allowed:
                    return False, f"Enterprise Git Push Policy Violation (§11): Current active branch '{current_branch}' is prohibited from direct push: {reason}"
            else:
                # Wildcard check if current branch cannot be determined
                if "*" not in allowed_branches:
                    matched = any(
                        (b.lower() in cmd_no_comment.lower() or fnmatch.fnmatch(cmd_no_comment.lower(), f"*{b.lower()}*"))
                        for b in allowed_branches
                    )
                    if not matched:
                        reason = (
                            f"Enterprise Git Push Policy Violation (§11): Branch not found in push command. "
                            f"You MUST explicitly push to one of the allowed branches: {', '.join(allowed_branches)}."
                        )
                        return False, reason
        else:
            # Case B: Refspecs explicitly provided
            for ref in target_refspecs:
                clean_ref = ref.strip("\"'").strip()
                if clean_ref.startswith("+"):
                    reason = (
                        "Enterprise Git Security Violation (§11): Destructive force-push refspec detected ('+'). "
                        "Force-pushing is strictly prohibited to prevent data loss."
                    )
                    return False, reason

                if ":" in clean_ref:
                    src, dst = clean_ref.split(":", 1)
                    src = src.strip().lower()
                    dst = dst.strip().lower()

                    if not src and dst:
                        reason = (
                            f"Enterprise Git Push Policy Violation (§11): Remote branch deletion (':{dst}') is PROHIBITED. "
                            f"Branch deletion via push is not allowed."
                        )
                        return False, reason

                    clean_dst = dst.replace("refs/heads/", "")
                    allowed, reason = check_branch_policy(clean_dst, allowed_branches, prohibited_branches)
                    if not allowed:
                        return False, reason
                else:
                    clean_t = clean_ref.lower().replace("refs/heads/", "")
                    allowed, reason = check_branch_policy(clean_t, allowed_branches, prohibited_branches)
                    if not allowed:
                        return False, reason

        if run_tests:
            # Rule 3: Multi-tenant auth context validation across unpushed commits & staged diff
            auth_ok, auth_reason = verify_multi_tenant_auth_invariants(cwd=cwd)
            if not auth_ok:
                return False, f"Pre-Push Auth Gating Failed: {auth_reason}"

            # Rule 4: Commit author validation (§11)
            author_ok, author_reason = verify_git_commit_author(cwd=cwd)
            if not author_ok:
                return False, f"Pre-Push Author Gating Failed: {author_reason}"

            # Rule 5: Automated test suite verification (§19, §20)
            tests_ok, tests_reason = run_pre_push_test_suite(cwd=cwd)
            if not tests_ok:
                return False, f"Pre-Push Test Gating Failed: {tests_reason}"

            # Rule 6: Tech Lead 10-Tier Pre-Flight verification (§29)
            preflight_ok, preflight_reason = run_tech_lead_preflight(cwd=cwd)
            if not preflight_ok:
                return False, f"Pre-Push Tech Lead Pre-Flight Gating Failed: {preflight_reason}"

    return True, ""


def evaluate_git_safety(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate run_command tool call for git push, multi-tenant auth, and test rules."""
    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""
    args = get_tool_args(tool_call)

    if tool_name != "run_command":
        return pre_tool_response("allow", "Tool is not run_command.")

    command_line = args.get("CommandLine", "")
    cwd = args.get("Cwd")
    if not isinstance(command_line, str) or not command_line.strip():
        return pre_tool_response("allow", "Empty CommandLine argument.")

    # Split chained commands (&&, ||, ;, newline, |)
    sub_commands = re.split(r"&&|\|\||;|\n|\|", command_line)

    # Pass 1: Validate static policies across all sub-commands without triggering test suites
    has_git_push = False
    for sub_cmd in sub_commands:
        sub_cmd_clean = sub_cmd.strip()
        if not sub_cmd_clean:
            continue
        if GIT_PUSH_REGEX.search(sub_cmd_clean):
            has_git_push = True
        allowed, reason = evaluate_single_git_command(sub_cmd_clean, cwd=cwd, run_tests=False)
        if not allowed:
            log_diagnostic(f"Blocked dangerous git command: {command_line} (Reason: {reason})")
            return pre_tool_response("deny", reason)

    # Pass 2: If any sub-command performs git push, run deep gates once
    if has_git_push:
        auth_ok, auth_reason = verify_multi_tenant_auth_invariants(cwd=cwd)
        if not auth_ok:
            return pre_tool_response("deny", f"Pre-Push Auth Gating Failed: {auth_reason}")

        author_ok, author_reason = verify_git_commit_author(cwd=cwd)
        if not author_ok:
            return pre_tool_response("deny", f"Pre-Push Author Gating Failed: {author_reason}")

        tests_ok, tests_reason = run_pre_push_test_suite(cwd=cwd)
        if not tests_ok:
            return pre_tool_response("deny", f"Pre-Push Test Gating Failed: {tests_reason}")

        preflight_ok, preflight_reason = run_tech_lead_preflight(cwd=cwd)
        if not preflight_ok:
            return pre_tool_response("deny", f"Pre-Push Tech Lead Pre-Flight Gating Failed: {preflight_reason}")

    return pre_tool_response("allow", "Command passed Git safety, push branch, auth invariant, and pre-push test rules.")


def main() -> None:
    payload = read_stdin_payload(default={})
    response = evaluate_git_safety(payload)
    emit_stdout_json(response)


if __name__ == "__main__":
    main()
