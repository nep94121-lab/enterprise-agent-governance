#!/usr/bin/env python3
"""Dangerous Command Guard Hook (PreToolUse) for Enterprise Multi-Agent Governance System.

Protects system infrastructure and data assets against accidental destruction
(accidental-data-loss-prevention rule, §3 injection and destruction defense).
Blocks destructive OS commands and unqualified database drops/truncations.

Refactored to eliminate 100% hardcoding and integrate with hook_utils.command_validator.
"""

from __future__ import annotations

import io
import pathlib
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

# Ensure local hook libraries are importable
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

from hook_utils import get_command_validator  # noqa: E402


def evaluate_dangerous_command(payload: dict[str, Any]) -> dict[str, Any]:
    """Scan proposed run_command CommandLine for dangerous patterns via hook_utils."""
    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""
    args = get_tool_args(tool_call)

    if tool_name != "run_command":
        return pre_tool_response("allow", "Tool is not run_command.")

    if not isinstance(args, dict):
        return pre_tool_response("allow", "Arguments is not a valid dict.")

    command_line = args.get("CommandLine", "")
    if not isinstance(command_line, str) or not command_line.strip():
        return pre_tool_response("allow", "Empty CommandLine argument.")

    validator = get_command_validator()
    decision, reason = validator.evaluate_command_string(command_line)

    if decision != "allow":
        log_diagnostic(f"Command Guard intervention [{decision}]: {command_line} -> {reason}")

    return pre_tool_response(decision, reason)


def main() -> None:
    if "--self-test" in sys.argv:
        validator = get_command_validator()
        success = validator.run_self_test()
        sys.exit(0 if success else 1)

    payload = read_stdin_payload(default={})
    response = evaluate_dangerous_command(payload)
    emit_stdout_json(response)


if __name__ == "__main__":
    main()
