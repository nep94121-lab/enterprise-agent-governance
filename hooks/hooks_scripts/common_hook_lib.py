#!/usr/bin/env python3
"""Common Hook Library for Enterprise Multi-Agent Governance System.

Provides standard I/O processing, UTF-8 safety for Windows PowerShell,
fail-safe payload parsing, diagnostic stderr logging, and security helpers.
"""

from __future__ import annotations

import io
import json
import pathlib
import sys
from typing import Any

# Enforce UTF-8 I/O encoding across all platforms (especially Windows PowerShell)
try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass


__all__ = [
    "MAX_STDIN_BYTES",
    "PayloadLimitExceededError",
    "make_payload_too_large_response",
    "read_bounded_stdin",
    "read_stdin_payload",
    "strict_json_loads",
    "emit_stdout_json",
    "log_diagnostic",
    "strip_unc_prefix",
    "has_ntfs_ads",
    "is_reserved_device_name",
    "is_reparse_point",
    "is_hardlink",
    "get_file_identity",
    "normalize_path",
    "get_workspace_roots",
    "is_within_workspace",
    "get_tool_call",
    "get_tool_args",
    "extract_tool_invocation",
    "pre_tool_response",
    "post_tool_response",
    "pre_invocation_response",
    "post_invocation_response",
    "stop_response",
]


def log_diagnostic(message: str) -> None:
    """Log formatted diagnostic information to sys.stderr (never polluting stdout)."""
    try:
        sys.stderr.write(f"[HOOK-DIAGNOSTIC] {message}\n")
        sys.stderr.flush()
    except (OSError, UnicodeEncodeError):
        pass


def emit_stdout_json(payload: dict[str, Any]) -> None:
    """Serialize and print exact JSON payload to sys.stdout and flush immediately."""
    try:
        output_str = json.dumps(payload, ensure_ascii=False)
        sys.stdout.write(output_str + "\n")
        sys.stdout.flush()
    except (OSError, TypeError, ValueError) as exc:
        log_diagnostic(f"Error writing to stdout: {exc}")
        # Emergency fallback
        sys.stdout.write("{}\n")
        sys.stdout.flush()


MAX_STDIN_BYTES: int = 10 * 1024 * 1024  # 10 MB maximum buffer size


def make_payload_too_large_response(
    max_bytes: int = MAX_STDIN_BYTES,
    reason: str | None = None,
) -> dict[str, Any]:
    """Construct standardized Fail-Closed DENY response payload when input exceeds size cap."""
    if not reason:
        limit_mb = max_bytes / (1024 * 1024)
        limit_str = f"{limit_mb:g}MB" if max_bytes % (1024 * 1024) == 0 else f"{max_bytes} bytes"
        reason = f"Payload exceeds {limit_str} limit"
    return {
        "decision": "DENY",
        "verdict": "DENY",
        "reason": reason,
    }


class PayloadLimitExceededError(ValueError):
    """Exception raised when input exceeds maximum allowed buffer size."""

    def __init__(self, message: str = "Payload exceeds 10MB limit", max_bytes: int = MAX_STDIN_BYTES):
        super().__init__(message)
        self.message = message
        self.max_bytes = max_bytes
        self.deny_response = make_payload_too_large_response(max_bytes, message)


def read_bounded_stdin(
    max_bytes: int = MAX_STDIN_BYTES,
    exit_on_overflow: bool = True,
) -> str:
    """Read bounded string from sys.stdin up to max_bytes with Fail-Closed defense against memory exhaustion.

    If the input on sys.stdin exceeds max_bytes:
    - If exit_on_overflow is True (default): logs diagnostic, writes standardized DENY JSON
      to sys.stdout, and exits immediately with code 0 (Fail-Closed hook protocol).
    - If exit_on_overflow is False: raises PayloadLimitExceededError.

    Returns:
        The raw string read from sys.stdin (bounded to max_bytes).
    """
    raw_data = sys.stdin.read(max_bytes + 1)
    is_overflow = len(raw_data) > max_bytes
    if not is_overflow and raw_data:
        try:
            is_overflow = len(raw_data.encode("utf-8", errors="replace")) > max_bytes
        except Exception:
            pass

    if is_overflow:
        limit_mb = max_bytes / (1024 * 1024)
        limit_str = f"{limit_mb:g}MB" if max_bytes % (1024 * 1024) == 0 else f"{max_bytes} bytes"
        log_diagnostic(
            f"STDIN payload exceeded maximum limit ({limit_str} = {max_bytes} bytes). "
            "Rejecting unbounded input with Fail-Closed DENY."
        )
        deny_resp = make_payload_too_large_response(max_bytes)
        if exit_on_overflow:
            emit_stdout_json(deny_resp)
            sys.exit(0)
        raise PayloadLimitExceededError(f"Payload exceeds {limit_str} limit", max_bytes=max_bytes)

    return raw_data


def strict_json_loads(data_str: str, allow_duplicate_keys: bool = False) -> Any:
    """Parse JSON string with duplicate key validation.

    If allow_duplicate_keys is False and duplicate keys are found in an object,
    raises ValueError indicating the duplicate key.
    """
    if allow_duplicate_keys:
        return json.loads(data_str)

    def _reject_duplicates_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        d: dict[str, Any] = {}
        for k, v in pairs:
            if k in d:
                raise ValueError(f"Duplicate key detected in JSON payload: {k!r}")
            d[k] = v
        return d

    return json.loads(data_str, object_pairs_hook=_reject_duplicates_hook)


def read_stdin_payload(
    default: dict[str, Any] | None = None,
    strict_keys: bool = False,
    max_bytes: int = MAX_STDIN_BYTES,
    exit_on_overflow: bool = True,
) -> dict[str, Any]:
    """Read and parse JSON payload from sys.stdin with buffer cap and duplicate key defense.

    Fail-Closed on buffer overflow:
    If payload > max_bytes, rejects execution with DENY response (exits via hook protocol
    if exit_on_overflow=True, or returns DENY payload dictionary if exit_on_overflow=False).

    Returns default (or empty dict) on EOF, empty input, or JSON parse error.
    Fail-safe: Never raises unhandled exceptions.
    """
    if default is None:
        default = {}
    try:
        raw_data = read_bounded_stdin(max_bytes=max_bytes, exit_on_overflow=exit_on_overflow)
        if not raw_data or not raw_data.strip():
            log_diagnostic("Empty stdin received, returning default fallback payload.")
            return default

        # Strict or tolerant JSON parsing
        try:
            parsed = strict_json_loads(raw_data, allow_duplicate_keys=not strict_keys)
        except ValueError as val_err:
            if "Duplicate key detected" in str(val_err):
                log_diagnostic(f"Integrity warning: {val_err}")
                if strict_keys:
                    return default
                # Fall back to standard parsing if non-strict
                parsed = json.loads(raw_data)
            else:
                raise

        if isinstance(parsed, dict):
            return parsed
        log_diagnostic(f"Payload is not a JSON object (type={type(parsed).__name__}), returning default.")
        return default
    except PayloadLimitExceededError as exc:
        log_diagnostic(f"Payload limit exceeded (Fail-Closed): {exc}")
        return exc.deny_response
    except json.JSONDecodeError as exc:
        log_diagnostic(f"JSON decode error on stdin: {exc}")
        return default
    except MemoryError as exc:
        log_diagnostic(f"MemoryError while reading/parsing stdin: {exc}")
        deny_resp = make_payload_too_large_response(max_bytes, "Memory exhaustion while reading stdin (Fail-Closed)")
        if exit_on_overflow:
            emit_stdout_json(deny_resp)
            sys.exit(0)
        return deny_resp
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        log_diagnostic(f"Unexpected error reading stdin: {exc}")
        return default


import os
import re
import stat

WINDOWS_RESERVED_DEVICE_NAMES: frozenset[str] = frozenset({
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    "CONIN$", "CONOUT$",
})

FILE_ATTRIBUTE_REPARSE_POINT: int = 0x00000400
FILE_ATTRIBUTE_OFFLINE: int = 0x00001000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: int = 0x00400000


def strip_unc_prefix(path_str: str) -> tuple[str, str]:
    """Strip or normalize Windows UNC / device prefixes (\\\\?\\, \\\\.\\, etc.).

    Returns: (clean_path, prefix_type)
    - \\\\?\\C:\\path -> C:\\path, 'DEVICE'
    - \\\\.\\C:\\path -> C:\\path, 'DEVICE'
    - \\\\?\\UNC\\server\\share\\path -> \\\\server\\share\\path, 'UNC'
    - \\\\.\\UNC\\server\\share\\path -> \\\\server\\share\\path, 'UNC'
    - //?/C:/path -> C:/path, 'DEVICE'
    - \\\\?\\Volume{guid}\\... -> preserved, 'VOLUME_GUID'
    """
    s = str(path_str)
    # Normalize forward slashes in UNC prefix
    if s.startswith(("//?/", "//./")):
        s = "\\\\" + s[2:4] + "\\" + s[4:]
    elif s.startswith(("\\\\?/", "\\\\./")):
        s = s[:4].replace("/", "\\") + s[4:]

    if s.startswith(("\\\\?\\UNC\\", "\\\\.\\UNC\\")):
        return "\\\\" + s[8:], "UNC"
    if s.startswith(("//?/UNC/", "//./UNC/")):
        return "//" + s[8:], "UNC"

    if re.match(r"^\\\\[\?\.]\\(?:Volume\{[a-fA-F0-9\-]+\}|HarddiskVolume\d+)", s, re.IGNORECASE):
        return s[4:], "VOLUME_GUID"

    if s.startswith(("\\\\?\\", "\\\\.\\")):
        return s[4:], "DEVICE"

    return s, ""


def has_ntfs_ads(path_str: str) -> bool:
    """Detect if path contains NTFS Alternate Data Stream (ADS) separator (:).

    Valid ':' is only allowed at index 1 for a drive letter (e.g., C:).
    Any other ':' indicates an ADS stream or invalid NTFS syntax.
    """
    clean_path, p_type = strip_unc_prefix(path_str)
    if p_type == "VOLUME_GUID":
        return False
    if len(clean_path) >= 2 and clean_path[0].isalpha() and clean_path[1] == ":":
        remainder = clean_path[2:]
    else:
        remainder = clean_path
    return ":" in remainder


def is_reserved_device_name(path_str: str) -> bool:
    """Check if any path component matches a Windows DOS reserved device name."""
    clean_path, _ = strip_unc_prefix(path_str)
    p = pathlib.Path(clean_path)
    for part in p.parts:
        stem = pathlib.Path(part).stem.upper()
        if stem in WINDOWS_RESERVED_DEVICE_NAMES or part.upper() in WINDOWS_RESERVED_DEVICE_NAMES:
            return True
    return False


def is_reparse_point(path: pathlib.Path | str) -> bool:
    """Check if target path is a Windows Reparse Point (symlink, junction, mount point)."""
    p = pathlib.Path(path) if isinstance(path, str) else path
    try:
        if p.is_symlink():
            return True
        st = os.lstat(p)
        attrs = getattr(st, "st_file_attributes", 0)
        return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    except (OSError, ValueError):
        return False


def is_hardlink(path: pathlib.Path | str) -> bool:
    """Check if target path is an existing file with multiple hardlinks (st_nlink > 1)."""
    p = pathlib.Path(path) if isinstance(path, str) else path
    try:
        if p.is_file() and not p.is_symlink():
            st = p.stat()
            return st.st_nlink > 1
        return False
    except (OSError, ValueError):
        return False


def get_file_identity(path: pathlib.Path | str) -> tuple[int, int] | None:
    """Retrieve unique device and inode/FileIndex identifier (st_dev, st_ino)."""
    p = pathlib.Path(path) if isinstance(path, str) else path
    try:
        st = p.stat()
        return (st.st_dev, st.st_ino)
    except (OSError, ValueError):
        return None


def normalize_path(path_str: str) -> pathlib.Path:
    """Normalize and resolve path safely for cross-platform matching."""
    try:
        clean_path, _ = strip_unc_prefix(str(path_str))
        real_str = os.path.realpath(clean_path)
        clean_real, _ = strip_unc_prefix(real_str)
        return pathlib.Path(clean_real)
    except (OSError, ValueError):
        try:
            return pathlib.Path(path_str).resolve()
        except (OSError, ValueError):
            return pathlib.Path(path_str)


def get_workspace_roots(payload: dict[str, Any]) -> list[pathlib.Path]:
    """Extract list of resolved workspace root paths from payload."""
    raw_paths = payload.get("workspacePaths", [])
    if not isinstance(raw_paths, list) or not raw_paths:
        return [normalize_path(str(pathlib.Path.cwd()))]
    roots: list[pathlib.Path] = []
    for p in raw_paths:
        if isinstance(p, str) and p.strip():
            try:
                roots.append(normalize_path(p.strip()))
            except (OSError, ValueError):
                continue
    return roots if roots else [normalize_path(str(pathlib.Path.cwd()))]


def is_within_workspace(target_path: pathlib.Path, workspace_roots: list[pathlib.Path]) -> bool:
    """Check if target_path is located within any of the workspace roots."""
    try:
        str_p = str(target_path)
        if has_ntfs_ads(str_p) or is_reserved_device_name(str_p):
            return False

        clean_target, p_type = strip_unc_prefix(str_p)
        if p_type == "VOLUME_GUID":
            return False

        resolved_target_str = os.path.realpath(clean_target)
        resolved_clean, _ = strip_unc_prefix(resolved_target_str)
        target_norm = os.path.normcase(os.path.normpath(resolved_clean))

        for root in workspace_roots:
            root_real = os.path.realpath(str(root))
            root_clean, _ = strip_unc_prefix(root_real)
            root_norm = os.path.normcase(os.path.normpath(root_clean))

            if not root_norm.endswith(os.sep):
                root_norm_sep = root_norm + os.sep
            else:
                root_norm_sep = root_norm

            if target_norm == root_norm or target_norm.startswith(root_norm_sep):
                return True
        return False
    except (OSError, ValueError):
        return False


def get_tool_call(payload: dict[str, Any] | Any) -> dict[str, Any]:
    """Extract toolCall dictionary safely from payload even if None or non-dict."""
    if not isinstance(payload, dict):
        return {}
    tc = payload.get("toolCall")
    return tc if isinstance(tc, dict) else {}


def get_tool_args(tool_call: dict[str, Any] | Any) -> dict[str, Any]:
    """Extract args dictionary safely from toolCall even if None or non-dict."""
    if not isinstance(tool_call, dict):
        return {}
    args = tool_call.get("args")
    return args if isinstance(args, dict) else {}


def extract_tool_invocation(payload: dict[str, Any] | Any) -> tuple[str, dict[str, Any]]:
    """Uniformly extract (tool_name, tool_args) across all Antigravity payload formats.

    Handles:
    - Standard: {"toolCall": {"name": "...", "args": {...}}}
    - Direct: {"tool_name": "...", "tool_args": {...}}
    - Root-level fallback keys if args is empty or missing.
    """
    if not isinstance(payload, dict):
        return "", {}

    tool_call = get_tool_call(payload)
    tool_name = (
        tool_call.get("name")
        or payload.get("tool_name")
        or payload.get("tool")
        or payload.get("name")
        or ""
    )
    tool_args = (
        get_tool_args(tool_call)
        or payload.get("tool_args")
        or payload.get("arguments")
        or payload.get("args")
        or {}
    )
    if not isinstance(tool_args, dict):
        tool_args = {}

    # Root fallback for critical command / path arguments if omitted from args
    enriched_args = dict(tool_args)
    for root_key in ("CommandLine", "command", "cmd", "TargetFile", "target_file", "path", "filePath", "file_path", "Subagents", "subagents"):
        if root_key not in enriched_args and root_key in payload:
            enriched_args[root_key] = payload[root_key]

    return str(tool_name).strip(), enriched_args


# Response Helper Functions
def pre_tool_response(
    decision: str,
    reason: str = "",
    permission_overrides: list[str] | None = None,
) -> dict[str, Any]:
    """Construct standard PreToolUse response payload."""
    res: dict[str, Any] = {"decision": decision}
    if reason:
        res["reason"] = reason
    if permission_overrides:
        res["permissionOverrides"] = permission_overrides
    return res


def post_tool_response() -> dict[str, Any]:
    """Construct standard PostToolUse response payload (strictly empty object)."""
    return {}


def pre_invocation_response(inject_steps: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Construct standard PreInvocation response payload."""
    return {"injectSteps": inject_steps if inject_steps is not None else []}


def post_invocation_response(
    inject_steps: list[dict[str, Any]] | None = None,
    termination_behavior: str = "",
) -> dict[str, Any]:
    """Construct standard PostInvocation response payload."""
    return {
        "injectSteps": inject_steps if inject_steps is not None else [],
        "terminationBehavior": termination_behavior,
    }


def stop_response(decision: str = "allow", reason: str = "") -> dict[str, Any]:
    """Construct standard Stop response payload."""
    res: dict[str, Any] = {"decision": decision}
    if reason:
        res["reason"] = reason
    return res
