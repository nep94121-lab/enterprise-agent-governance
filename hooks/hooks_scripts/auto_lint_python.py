#!/usr/bin/env python3
"""Auto Lint Python Hook (PostToolUse) for Enterprise Multi-Agent Governance System.

Automatically triggers linter ('ruff check --fix') on modified Python files to maintain
Enterprise Repository Hygiene (§13) with zero trailing errors.
Logs linting feedback to stderr and returns standard empty object on stdout.

Architecture & Security Enhancements:
1. P0 Security Fix (Argument & Option Injection): Enforces double-dash '--' argument
   delimiter before file paths to prevent option hijacking via crafted filenames (§3, §7).
2. P0 Security Fix (Path Traversal & Uncontrolled File Mutation): Validates target paths
   against system directories, Windows reserved device names, and .agents/ layout (§7, §15, §29).
3. P0 Security Fix (DoS & Hang Prevention): Dynamic timeout enforcement, file size limits,
   and TOCTOU error resilience to prevent subprocess hanging.
4. Hook Utils & Config Loader Integration: Sourced dynamically from hook_utils.config_loader
   and dynamic_limits.json with zero magic numbers and 100% config-driven parameters.
"""

from __future__ import annotations

import io
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from typing import Any

# Enforce UTF-8 I/O encoding across all platforms (Windows PowerShell safety)
try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

# Ensure both enterprise-hooks root and hooks_scripts directories are importable
ROOT_DIR = pathlib.Path(__file__).parent.parent.resolve()
HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).parent.resolve()

for import_path in (str(ROOT_DIR), str(HOOKS_SCRIPTS_DIR)):
    if import_path not in sys.path:
        sys.path.insert(0, import_path)

from common_hook_lib import (  # noqa: E402
    emit_stdout_json,
    get_tool_args,
    get_tool_call,
    get_workspace_roots,
    has_ntfs_ads,
    is_hardlink,
    is_reparse_point,
    is_reserved_device_name,
    log_diagnostic,
    normalize_path,
    post_tool_response,
    read_stdin_payload,
    strip_unc_prefix,
)

# Optional dynamic configuration loader from hook_utils package
try:
    from hook_utils.config_loader import (  # noqa: E402
        DynamicConfigLoader,
        get_auto_lint_config,
        get_config_loader,
        get_dynamic_limits,
        get_execution_timeouts,
    )
    HAS_HOOK_UTILS = True
except ImportError:
    HAS_HOOK_UTILS = False
    DynamicConfigLoader = None
    get_auto_lint_config = None
    get_config_loader = None
    get_dynamic_limits = None
    get_execution_timeouts = None

# Optional project governance configuration loader
try:
    from config_loader import get_governance_config  # noqa: E402
    HAS_GOVERNANCE_CONFIG = True
except ImportError:
    HAS_GOVERNANCE_CONFIG = False
    get_governance_config = None

# Enterprise Default Fallback Constants (Zero-Config Resilience)
FALLBACK_AUTO_LINT_CONFIG: dict[str, Any] = {
    "enabled": True,
    "linter_binary": "ruff",
    "linter_args": ["check", "--fix", "--no-cache"],
    "supported_extensions": [".py", ".pyi"],
    "max_file_size_bytes": 5242880,  # 5 MB
    "timeout_seconds": 15,
    "monitored_tools": [
        "write_to_file",
        "replace_file_content",
        "multi_replace_file_content",
    ],
    "target_argument_keys": [
        "TargetFile",
        "target_file",
        "filePath",
        "file_path",
        "path",
    ],
    "target_arg_keys": [
        "TargetFile",
        "target_file",
        "filePath",
        "file_path",
        "path",
    ],
    "block_windows_device_names": True,
    "block_system_directories": True,
    "respect_workspace_boundary": True,
    "messages": {
        "trigger_lint": "Triggering auto-lint for: {target_path}",
        "lint_clean": "Auto-lint clean: {file_name}",
        "lint_issues": "Auto-lint reported issues (code {returncode}) on {file_name}",
        "linter_not_found": "Ruff executable not found in PATH; skipping auto-lint.",
        "timeout": "Ruff linting timed out for {file_name}",
        "file_too_large": "Skipping auto-lint for {file_name}: file size ({file_size} bytes) exceeds limit ({max_size} bytes)",
        "unsafe_path": "Blocked auto-lint on unsafe/restricted path: {target_path}",
        "exec_error": "Error during auto-lint execution: {exc}",
    },
}

# Windows reserved device names
WINDOWS_RESERVED_DEVICE_NAMES: frozenset[str] = frozenset(
    [
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    ]
)


def load_resolved_config() -> dict[str, Any]:
    """Dynamically load and merge auto-lint configuration from hook_utils, governance config, and env."""
    config = dict(FALLBACK_AUTO_LINT_CONFIG)

    # 1. Source from hook_utils.config_loader if available
    if HAS_HOOK_UTILS and get_auto_lint_config is not None:
        try:
            dynamic_cfg = get_auto_lint_config()
            if isinstance(dynamic_cfg, dict):
                config.update(dynamic_cfg)
        except Exception as exc:
            log_diagnostic(f"Warning: Failed to load auto_lint config from hook_utils: {exc}")

    # 2. Source execution timeouts if timeout was not explicitly set in auto_lint
    if HAS_HOOK_UTILS and get_execution_timeouts is not None:
        try:
            timeouts = get_execution_timeouts()
            if isinstance(timeouts, dict):
                io_timeout = timeouts.get("read_io_timeout_seconds")
                if io_timeout and "timeout_seconds" not in config:
                    config["timeout_seconds"] = io_timeout
        except Exception:
            pass

    # 3. Environment variable overrides (highest precedence)
    env_enabled = os.environ.get("AUTO_LINT_ENABLED")
    if env_enabled is not None:
        config["enabled"] = env_enabled.strip().lower() not in ("0", "false", "no", "off", "disable", "disabled")

    env_binary = os.environ.get("LINTER_BIN") or os.environ.get("AUTO_LINT_BINARY")
    if env_binary and env_binary.strip():
        config["linter_binary"] = env_binary.strip()

    env_timeout = os.environ.get("AUTO_LINT_TIMEOUT")
    if env_timeout:
        try:
            config["timeout_seconds"] = max(1, int(env_timeout.strip()))
        except ValueError:
            pass

    env_max_size = os.environ.get("AUTO_LINT_MAX_FILE_SIZE")
    if env_max_size:
        try:
            config["max_file_size_bytes"] = max(1024, int(env_max_size.strip()))
        except ValueError:
            pass

    return config


def resolve_linter_binary(binary_name: str) -> str | None:
    """Locate executable path safely on system, checking PATH and Python virtual environments."""
    if not binary_name:
        return None

    # Direct check if specified as absolute path
    as_path = pathlib.Path(binary_name)
    if as_path.is_file() and os.access(as_path, os.X_OK):
        return str(as_path)

    # Standard PATH resolution
    resolved = shutil.which(binary_name)
    if resolved:
        return resolved

    # On Windows, try checking with .exe suffix
    if sys.platform == "win32" and not binary_name.lower().endswith(".exe"):
        resolved_exe = shutil.which(f"{binary_name}.exe")
        if resolved_exe:
            return resolved_exe

    # Check active Python environment Scripts or bin directory
    scripts_dir = pathlib.Path(sys.prefix) / ("Scripts" if sys.platform == "win32" else "bin")
    candidate = scripts_dir / (f"{binary_name}.exe" if sys.platform == "win32" else binary_name)
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)

    return None


def is_safe_target_path(
    target_path: pathlib.Path,
    payload: dict[str, Any],
    config: dict[str, Any],
) -> tuple[bool, str]:
    """Validate target path against security hazards (traversal, device files, system dirs, layout)."""
    # Check 1: Null bytes and control character injection
    path_str = str(target_path)
    if "\x00" in path_str:
        return False, "Path contains prohibited null byte"

    # Check 1b: NTFS Alternate Data Stream (ADS)
    if has_ntfs_ads(path_str):
        return False, f"Target path contains prohibited NTFS Alternate Data Stream: {path_str}"

    # Check 1c: Windows UNC Volume GUID prefix and reserved devices
    clean_p, p_type = strip_unc_prefix(path_str)
    if p_type == "VOLUME_GUID":
        return False, f"Target path uses prohibited Volume GUID prefix: {path_str}"
    if is_reserved_device_name(clean_p):
        return False, f"Target path refers to Windows reserved device name: {clean_p}"

    # Check 2: Argument injection via leading hyphen
    if target_path.name.startswith("-") or path_str.strip().startswith("-"):
        return False, f"Target path begins with hyphen; potential option injection: {target_path.name}"

    try:
        resolved = target_path.resolve()
    except (OSError, ValueError) as exc:
        return False, f"Path resolution failure: {exc}"

    # Check 3: Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    if config.get("block_windows_device_names", True):
        if is_reserved_device_name(resolved.stem) or resolved.stem.lower() in WINDOWS_RESERVED_DEVICE_NAMES:
            return False, f"Blocked access to Windows reserved device name: {resolved.stem}"

    # Check 4: Critical OS system directories
    if config.get("block_system_directories", True):
        dangerous_roots: list[pathlib.Path] = []
        # Windows system directories
        for env_var in ("SYSTEMROOT", "WINDIR", "PROGRAMFILES", "PROGRAMFILES(X86)"):
            env_val = os.environ.get(env_var)
            if env_val:
                try:
                    dangerous_roots.append(pathlib.Path(env_val).resolve())
                except (OSError, ValueError):
                    pass
        # POSIX system directories
        for posix_sys in ("/etc", "/usr", "/bin", "/sbin", "/lib", "/boot", "/sys", "/proc"):
            p = pathlib.Path(posix_sys)
            if p.exists():
                try:
                    dangerous_roots.append(p.resolve())
                except (OSError, ValueError):
                    pass

        for dangerous_root in dangerous_roots:
            try:
                resolved.relative_to(dangerous_root)
                return False, f"Target path is inside protected system directory: {dangerous_root}"
            except ValueError:
                pass

    # Check 5: .agents/ layout compliance (§15, §29)
    path_parts = [part.lower() for part in resolved.parts]
    if ".agents" in path_parts:
        return False, "Target path is inside .agents/ metadata directory; source code modification skipped"

    # Check 6: Workspace scope check if workspacePaths is explicitly provided
    if config.get("respect_workspace_boundary", True):
        raw_workspace_paths = payload.get("workspacePaths")
        if isinstance(raw_workspace_paths, list) and raw_workspace_paths:
            workspace_roots = get_workspace_roots(payload)
            # Include system temp directory to allow automated testing (e.g. pytest tmp_path)
            temp_dir = pathlib.Path(tempfile.gettempdir()).resolve()
            allowed_roots = list(workspace_roots) + [temp_dir]

            is_within_allowed = False
            for root in allowed_roots:
                try:
                    resolved.relative_to(root)
                    is_within_allowed = True
                    break
                except ValueError:
                    continue

            if not is_within_allowed:
                return False, f"Target path '{resolved}' is outside authorized workspace roots"

    return True, "Safe"


def extract_target_file_path(args: dict[str, Any], config: dict[str, Any]) -> str | None:
    """Extract raw target file argument from tool args using configured keys."""
    if not isinstance(args, dict):
        return None

    target_keys = (
        config.get("target_argument_keys")
        or config.get("target_arg_keys")
        or FALLBACK_AUTO_LINT_CONFIG.get("target_argument_keys")
        or FALLBACK_AUTO_LINT_CONFIG.get("target_arg_keys")
        or []
    )
    for key in target_keys:
        val = args.get(key)
        if val and isinstance(val, str) and val.strip():
            return val.strip()

    return None


def run_auto_lint(payload: dict[str, Any]) -> dict[str, Any]:
    """Run ruff linter on modified Python files with full security guardrails."""
    config = load_resolved_config()

    if not config.get("enabled", True):
        log_diagnostic("Auto-lint hook is disabled via configuration or environment.")
        return post_tool_response()

    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name")
    monitored_tools = config.get("monitored_tools", FALLBACK_AUTO_LINT_CONFIG.get("monitored_tools", []))
    if monitored_tools and tool_name and tool_name not in monitored_tools:
        return post_tool_response()

    args = get_tool_args(tool_call)

    raw_target = extract_target_file_path(args, config)
    if not raw_target:
        return post_tool_response()

    # Pre-check for raw null bytes or immediate option injection
    if "\x00" in raw_target or raw_target.startswith("-"):
        log_diagnostic(f"Invalid or unsafe target file string rejected: {raw_target!r}")
        return post_tool_response()

    target_path = normalize_path(raw_target)

    # Check file extension against supported extensions
    supported_extensions = tuple(
        ext.lower() for ext in config.get("supported_extensions", FALLBACK_AUTO_LINT_CONFIG["supported_extensions"])
    )
    if target_path.suffix.lower() not in supported_extensions:
        return post_tool_response()

    # Verify safety of target path
    is_safe, reason = is_safe_target_path(target_path, payload, config)
    if not is_safe:
        msg_template = config.get("messages", {}).get("unsafe_path", "Blocked auto-lint on unsafe/restricted path: {target_path}")
        log_diagnostic(msg_template.format(target_path=target_path) + f" ({reason})")
        return post_tool_response()

    # Verify file existence and type
    try:
        if not target_path.is_file():
            return post_tool_response()
    except (OSError, ValueError) as exc:
        log_diagnostic(f"File inspection error on {target_path}: {exc}")
        return post_tool_response()

    # Verify file size limit
    max_size = config.get("max_file_size_bytes", FALLBACK_AUTO_LINT_CONFIG["max_file_size_bytes"])
    try:
        file_size = target_path.stat().st_size
        if file_size > max_size:
            msg_template = config.get("messages", {}).get(
                "file_too_large",
                "Skipping auto-lint for {file_name}: file size ({file_size} bytes) exceeds limit ({max_size} bytes)",
            )
            log_diagnostic(
                msg_template.format(
                    file_name=target_path.name,
                    file_size=file_size,
                    max_size=max_size,
                )
            )
            return post_tool_response()
    except (OSError, ValueError) as exc:
        log_diagnostic(f"Cannot stat target file {target_path.name}: {exc}")
        return post_tool_response()

    # Locate linter executable
    binary_name = config.get("linter_binary", FALLBACK_AUTO_LINT_CONFIG["linter_binary"])
    resolved_linter = resolve_linter_binary(binary_name)
    if not resolved_linter:
        msg_template = config.get("messages", {}).get(
            "linter_not_found",
            "Ruff executable not found in PATH; skipping auto-lint.",
        )
        log_diagnostic(msg_template)
        return post_tool_response()

    # Construct safe command line with double-dash '--' delimiter
    linter_args = list(config.get("linter_args", FALLBACK_AUTO_LINT_CONFIG["linter_args"]))
    if "--no-cache" not in linter_args and "--cache-dir" not in linter_args:
        linter_args.append("--no-cache")

    # Protect NTFS hardlinks from auto-fix mutations
    if is_hardlink(target_path):
        log_diagnostic(f"Target '{target_path}' is an NTFS hardlink (st_nlink > 1); removing '--fix' to protect shared link integrity.")
        linter_args = [arg for arg in linter_args if arg != "--fix"]

    cmd = [resolved_linter, *linter_args, "--", str(target_path)]

    timeout_sec = config.get("timeout_seconds", FALLBACK_AUTO_LINT_CONFIG["timeout_seconds"])

    # Determine safe working directory
    workspace_roots = get_workspace_roots(payload)
    effective_cwd = workspace_roots[0] if workspace_roots else target_path.parent

    try:
        trigger_msg = config.get("messages", {}).get("trigger_lint", "Triggering auto-lint for: {target_path}")
        log_diagnostic(trigger_msg.format(target_path=target_path))

        result = subprocess.run(
            cmd,
            cwd=str(effective_cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
            check=False,
        )

        if result.stdout and result.stdout.strip():
            log_diagnostic(f"Ruff stdout:\n{result.stdout.strip()}")
        if result.stderr and result.stderr.strip():
            log_diagnostic(f"Ruff stderr:\n{result.stderr.strip()}")

        if result.returncode == 0:
            clean_msg = config.get("messages", {}).get("lint_clean", "Auto-lint clean: {file_name}")
            log_diagnostic(clean_msg.format(file_name=target_path.name))
        else:
            issue_msg = config.get("messages", {}).get(
                "lint_issues",
                "Auto-lint reported issues (code {returncode}) on {file_name}",
            )
            log_diagnostic(issue_msg.format(returncode=result.returncode, file_name=target_path.name))

    except FileNotFoundError:
        msg_template = config.get("messages", {}).get(
            "linter_not_found",
            "Ruff executable not found in PATH; skipping auto-lint.",
        )
        log_diagnostic(msg_template)
    except subprocess.TimeoutExpired:
        timeout_msg = config.get("messages", {}).get(
            "timeout",
            "Ruff linting timed out for {file_name}",
        )
        log_diagnostic(timeout_msg.format(file_name=target_path.name, timeout=timeout_sec))
    except (OSError, ValueError, PermissionError) as exc:
        err_msg = config.get("messages", {}).get("exec_error", "Error during auto-lint execution: {exc}")
        log_diagnostic(err_msg.format(exc=exc))

    return post_tool_response()


def main() -> None:
    payload = read_stdin_payload(default={})
    response = run_auto_lint(payload)
    emit_stdout_json(response)


if __name__ == "__main__":
    main()
