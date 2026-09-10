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


def log_diagnostic(message: str) -> None:
    """Log formatted diagnostic information to sys.stderr (never polluting stdout)."""
    try:
        sys.stderr.write(f"[HOOK-DIAGNOSTIC] {message}\n")
        sys.stderr.flush()
    except (OSError, UnicodeEncodeError):
        pass


def read_stdin_payload(default: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read and parse JSON payload from sys.stdin.

    Returns default (or empty dict) on EOF, empty input, or JSON parse error.
    Fail-safe: Never raises exceptions.
    """
    if default is None:
        default = {}
    try:
        raw_data = sys.stdin.read()
        if not raw_data or not raw_data.strip():
            log_diagnostic("Empty stdin received, returning default fallback payload.")
            return default
        parsed = json.loads(raw_data)
        if isinstance(parsed, dict):
            return parsed
        log_diagnostic(f"Payload is not a JSON object (type={type(parsed).__name__}), returning default.")
        return default
    except json.JSONDecodeError as exc:
        log_diagnostic(f"JSON decode error on stdin: {exc}")
        return default
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        log_diagnostic(f"Unexpected error reading stdin: {exc}")
        return default


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


def normalize_path(path_str: str) -> pathlib.Path:
    """Normalize and resolve path safely for cross-platform matching."""
    try:
        return pathlib.Path(path_str).resolve()
    except (OSError, ValueError):
        return pathlib.Path(path_str)


def get_workspace_roots(payload: dict[str, Any]) -> list[pathlib.Path]:
    """Extract list of resolved workspace root paths from payload."""
    raw_paths = payload.get("workspacePaths", [])
    if not isinstance(raw_paths, list) or not raw_paths:
        return [pathlib.Path.cwd().resolve()]
    roots: list[pathlib.Path] = []
    for p in raw_paths:
        if isinstance(p, str) and p.strip():
            try:
                roots.append(pathlib.Path(p).resolve())
            except (OSError, ValueError):
                continue
    return roots if roots else [pathlib.Path.cwd().resolve()]


def is_within_workspace(target_path: pathlib.Path, workspace_roots: list[pathlib.Path]) -> bool:
    """Check if target_path is located within any of the workspace roots."""
    try:
        resolved_target = target_path.resolve()
        for root in workspace_roots:
            try:
                resolved_target.relative_to(root)
                return True
            except ValueError:
                continue
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
