#!/usr/bin/env python3
"""Berkeley Function Calling Leaderboard (BFCL) Tool Call AST Validator (PreToolUse).

Enforces strict AST schema validation, parameter typing, and structural invariants
on tool calls prior to execution for Enterprise Multi-Agent Governance.
Monitored tools:
  - write_to_file: requires TargetFile (str), CodeContent (str).
  - replace_file_content: requires TargetFile (str), TargetContent (str), ReplacementContent (str).
  - run_command: requires CommandLine (str, non-empty).

Prevents malformed parameters, hallucinated argument schemas, type mismatches,
and out-of-bounds line numbers before commands reach filesystem or shell.
"""

from __future__ import annotations

import io
import json
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

# Ensure hook libraries are importable
HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).parent.resolve()
ENTERPRISE_HOOKS_ROOT = HOOKS_SCRIPTS_DIR.parent.resolve()

for _import_path in (str(HOOKS_SCRIPTS_DIR), str(ENTERPRISE_HOOKS_ROOT)):
    if _import_path not in sys.path:
        sys.path.insert(0, _import_path)

# Import common_hook_lib with resilient fallbacks
try:
    from common_hook_lib import (
        emit_stdout_json,
        get_tool_args,
        get_tool_call,
        log_diagnostic,
        pre_tool_response,
        read_stdin_payload,
    )
except ImportError:
    def log_diagnostic(message: str) -> None:
        try:
            sys.stderr.write(f"[HOOK-DIAGNOSTIC] {message}\n")
            sys.stderr.flush()
        except (OSError, UnicodeEncodeError):
            pass

    def read_stdin_payload(default: dict[str, Any] | None = None) -> dict[str, Any]:
        if default is None:
            default = {}
        try:
            max_bytes = 10 * 1024 * 1024
            raw_data = sys.stdin.read(max_bytes + 1)
            if not raw_data or not raw_data.strip():
                return default
            if len(raw_data) > max_bytes:
                log_diagnostic(f"STDIN payload exceeded maximum limit ({len(raw_data)} > {max_bytes} bytes).")
                return default
            parsed = json.loads(raw_data)
            return parsed if isinstance(parsed, dict) else default
        except Exception:
            return default

    def emit_stdout_json(payload: dict[str, Any]) -> None:
        try:
            output_str = json.dumps(payload, ensure_ascii=False)
            sys.stdout.write(output_str + "\n")
            sys.stdout.flush()
        except Exception:
            sys.stdout.write("{}\n")
            sys.stdout.flush()

    def get_tool_call(payload: dict[str, Any] | Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            return {}
        tc = payload.get("toolCall")
        return tc if isinstance(tc, dict) else {}

    def get_tool_args(tool_call: dict[str, Any] | Any) -> dict[str, Any]:
        if not isinstance(tool_call, dict):
            return {}
        args = tool_call.get("args")
        return args if isinstance(args, dict) else {}

    def pre_tool_response(
        decision: str,
        reason: str = "",
        permission_overrides: list[str] | None = None,
    ) -> dict[str, Any]:
        res: dict[str, Any] = {"decision": decision}
        if reason:
            res["reason"] = reason
        if permission_overrides:
            res["permissionOverrides"] = permission_overrides
        return res


# Monitored Tools for BFCL AST Validation
MONITORED_TOOLS: frozenset[str] = frozenset({
    "write_to_file",
    "replace_file_content",
    "run_command",
})


def _is_strict_int(val: Any) -> bool:
    """Return True only if val is strictly an int, not a bool (bool inherits from int in Python)."""
    return isinstance(val, int) and not isinstance(val, bool)


def _is_strict_str(val: Any) -> bool:
    """Return True if val is a string."""
    return isinstance(val, str)


def _is_strict_bool(val: Any) -> bool:
    """Return True if val is strictly a boolean."""
    return isinstance(val, bool)


def validate_write_to_file_ast(args: dict[str, Any]) -> tuple[bool, str]:
    """Validate AST parameters for write_to_file.

    Required:
      - TargetFile: str (non-empty)
      - CodeContent: str
    Optional:
      - Overwrite: bool
      - Description: str
      - ArtifactMetadata: dict
    """
    # 1. TargetFile validation
    if "TargetFile" not in args:
        return False, "Missing required parameter 'TargetFile'."
    target_file = args.get("TargetFile")
    if not _is_strict_str(target_file):
        return False, f"Parameter 'TargetFile' must be a string, got {type(target_file).__name__}."
    if not target_file.strip():
        return False, "Parameter 'TargetFile' cannot be empty or whitespace-only."

    # 2. CodeContent validation
    if "CodeContent" not in args:
        return False, "Missing required parameter 'CodeContent'."
    code_content = args.get("CodeContent")
    if not _is_strict_str(code_content):
        return False, f"Parameter 'CodeContent' must be a string, got {type(code_content).__name__}."

    # 3. Optional Overwrite validation
    if "Overwrite" in args:
        overwrite = args.get("Overwrite")
        if not _is_strict_bool(overwrite):
            return False, f"Optional parameter 'Overwrite' must be a boolean, got {type(overwrite).__name__}."

    # 4. Optional Description validation
    if "Description" in args:
        desc = args.get("Description")
        if not _is_strict_str(desc):
            return False, f"Optional parameter 'Description' must be a string, got {type(desc).__name__}."

    # 5. Optional ArtifactMetadata validation
    if "ArtifactMetadata" in args:
        metadata = args.get("ArtifactMetadata")
        if not isinstance(metadata, dict):
            return False, f"Optional parameter 'ArtifactMetadata' must be a dict, got {type(metadata).__name__}."

    return True, "Valid write_to_file AST."


def validate_replace_file_content_ast(args: dict[str, Any]) -> tuple[bool, str]:
    """Validate AST parameters for replace_file_content.

    Required:
      - TargetFile: str (non-empty)
      - TargetContent: str
      - ReplacementContent: str
    Optional:
      - StartLine: int (>= 1)
      - EndLine: int (>= StartLine)
      - AllowMultiple: bool
      - Instruction: str
      - Description: str
    """
    # 1. TargetFile validation
    if "TargetFile" not in args:
        return False, "Missing required parameter 'TargetFile'."
    target_file = args.get("TargetFile")
    if not _is_strict_str(target_file):
        return False, f"Parameter 'TargetFile' must be a string, got {type(target_file).__name__}."
    if not target_file.strip():
        return False, "Parameter 'TargetFile' cannot be empty or whitespace-only."

    # 2. TargetContent validation
    if "TargetContent" not in args:
        return False, "Missing required parameter 'TargetContent'."
    target_content = args.get("TargetContent")
    if not _is_strict_str(target_content):
        return False, f"Parameter 'TargetContent' must be a string, got {type(target_content).__name__}."

    # 3. ReplacementContent validation
    if "ReplacementContent" not in args:
        return False, "Missing required parameter 'ReplacementContent'."
    replacement_content = args.get("ReplacementContent")
    if not _is_strict_str(replacement_content):
        return False, f"Parameter 'ReplacementContent' must be a string, got {type(replacement_content).__name__}."

    # 4. StartLine / EndLine validation
    start_line = args.get("StartLine")
    end_line = args.get("EndLine")

    if start_line is not None:
        if not _is_strict_int(start_line):
            return False, f"Parameter 'StartLine' must be an integer >= 1, got {type(start_line).__name__}."
        if start_line < 1:
            return False, f"Parameter 'StartLine' must be >= 1, got {start_line}."

    if end_line is not None:
        if not _is_strict_int(end_line):
            return False, f"Parameter 'EndLine' must be an integer >= 1, got {type(end_line).__name__}."
        if end_line < 1:
            return False, f"Parameter 'EndLine' must be >= 1, got {end_line}."

    if start_line is not None and end_line is not None:
        if start_line > end_line:
            return (
                False,
                f"Range constraint violated: StartLine ({start_line}) cannot be greater than EndLine ({end_line}).",
            )

    # 5. Optional AllowMultiple validation
    if "AllowMultiple" in args:
        allow_multiple = args.get("AllowMultiple")
        if not _is_strict_bool(allow_multiple):
            return False, f"Optional parameter 'AllowMultiple' must be a boolean, got {type(allow_multiple).__name__}."

    # 6. Optional Description validation
    if "Description" in args:
        desc = args.get("Description")
        if not _is_strict_str(desc):
            return False, f"Optional parameter 'Description' must be a string, got {type(desc).__name__}."

    # 7. Optional Instruction validation
    if "Instruction" in args:
        inst = args.get("Instruction")
        if not _is_strict_str(inst):
            return False, f"Optional parameter 'Instruction' must be a string, got {type(inst).__name__}."

    return True, "Valid replace_file_content AST."


def validate_run_command_ast(args: dict[str, Any]) -> tuple[bool, str]:
    """Validate AST parameters for run_command.

    Required:
      - CommandLine: str (non-empty)
    Optional:
      - Cwd: str
      - WaitMsBeforeAsync: int (>= 0)
      - IsDaemon: bool
    """
    # 1. CommandLine validation
    if "CommandLine" not in args:
        return False, "Missing required parameter 'CommandLine'."
    command_line = args.get("CommandLine")
    if not _is_strict_str(command_line):
        return False, f"Parameter 'CommandLine' must be a string, got {type(command_line).__name__}."
    if not command_line.strip():
        return False, "Parameter 'CommandLine' cannot be empty or whitespace-only."

    # 2. Optional Cwd validation
    if "Cwd" in args:
        cwd = args.get("Cwd")
        if not _is_strict_str(cwd):
            return False, f"Optional parameter 'Cwd' must be a string, got {type(cwd).__name__}."

    # 3. Optional WaitMsBeforeAsync validation
    if "WaitMsBeforeAsync" in args:
        wait_ms = args.get("WaitMsBeforeAsync")
        if not _is_strict_int(wait_ms):
            return False, f"Optional parameter 'WaitMsBeforeAsync' must be an integer, got {type(wait_ms).__name__}."
        if wait_ms < 0:
            return False, f"Optional parameter 'WaitMsBeforeAsync' cannot be negative, got {wait_ms}."

    # 4. Optional IsDaemon validation
    if "IsDaemon" in args:
        is_daemon = args.get("IsDaemon")
        if not _is_strict_bool(is_daemon):
            return False, f"Optional parameter 'IsDaemon' must be a boolean, got {type(is_daemon).__name__}."

    return True, "Valid run_command AST."


def validate_tool_call_ast(tool_name: str, args: Any) -> tuple[bool, str]:
    """Validate tool call arguments AST based on tool signature.

    Returns:
      (is_valid, reason)
    """
    if tool_name not in MONITORED_TOOLS:
        return True, f"Tool '{tool_name}' is outside BFCL AST validation scope."

    if not isinstance(args, dict):
        return False, f"Arguments for tool '{tool_name}' must be a dictionary, got {type(args).__name__}."

    if tool_name == "write_to_file":
        return validate_write_to_file_ast(args)
    elif tool_name == "replace_file_content":
        return validate_replace_file_content_ast(args)
    elif tool_name == "run_command":
        return validate_run_command_ast(args)

    return True, f"Tool '{tool_name}' passed AST validation."


def evaluate_tool_call(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate PreToolUse payload for BFCL AST compliance."""
    tool_call = get_tool_call(payload)
    if not tool_call or not isinstance(tool_call, dict):
        return pre_tool_response("allow", "No toolCall found in payload.")

    tool_name = tool_call.get("name", "")
    args = get_tool_args(tool_call)

    is_valid, reason = validate_tool_call_ast(tool_name, args)

    if not is_valid:
        error_msg = f"[BFCL_AST_VALIDATION_ERROR] Tool '{tool_name}': {reason}"
        log_diagnostic(f"[BFCL-AST-DENY] {error_msg}")
        return pre_tool_response("deny", error_msg)

    return pre_tool_response("allow", f"BFCL AST schema validation passed for '{tool_name}'.")


def run_self_test() -> bool:
    """Run comprehensive test suite verifying BFCL tool call AST validation."""
    sys.stderr.write("Running bfcl_tool_call_ast_validator self-test...\n")

    test_cases: list[dict[str, Any]] = [
        # 1. Valid write_to_file
        {
            "name": "Valid write_to_file",
            "tool": "write_to_file",
            "args": {"TargetFile": "src/main.py", "CodeContent": "print('hello')", "Overwrite": True},
            "expect_valid": True,
        },
        # 2. Missing CodeContent in write_to_file
        {
            "name": "Missing CodeContent in write_to_file",
            "tool": "write_to_file",
            "args": {"TargetFile": "src/main.py"},
            "expect_valid": False,
            "error_keyword": "Missing required parameter 'CodeContent'",
        },
        # 3. Wrong type for TargetFile (int)
        {
            "name": "Wrong type for TargetFile in write_to_file",
            "tool": "write_to_file",
            "args": {"TargetFile": 12345, "CodeContent": "content"},
            "expect_valid": False,
            "error_keyword": "TargetFile' must be a string",
        },
        # 4. Empty TargetFile string
        {
            "name": "Empty TargetFile in write_to_file",
            "tool": "write_to_file",
            "args": {"TargetFile": "   ", "CodeContent": "content"},
            "expect_valid": False,
            "error_keyword": "cannot be empty",
        },
        # 5. Overwrite as string instead of boolean
        {
            "name": "Overwrite string instead of bool",
            "tool": "write_to_file",
            "args": {"TargetFile": "src/app.py", "CodeContent": "code", "Overwrite": "true"},
            "expect_valid": False,
            "error_keyword": "must be a boolean",
        },
        # 6. Valid replace_file_content
        {
            "name": "Valid replace_file_content",
            "tool": "replace_file_content",
            "args": {
                "TargetFile": "src/app.py",
                "TargetContent": "old_code()",
                "ReplacementContent": "new_code()",
                "StartLine": 10,
                "EndLine": 20,
            },
            "expect_valid": True,
        },
        # 7. Missing ReplacementContent in replace_file_content
        {
            "name": "Missing ReplacementContent in replace_file_content",
            "tool": "replace_file_content",
            "args": {"TargetFile": "src/app.py", "TargetContent": "old_code()"},
            "expect_valid": False,
            "error_keyword": "Missing required parameter 'ReplacementContent'",
        },
        # 8. StartLine > EndLine inversion error
        {
            "name": "StartLine > EndLine in replace_file_content",
            "tool": "replace_file_content",
            "args": {
                "TargetFile": "src/app.py",
                "TargetContent": "old",
                "ReplacementContent": "new",
                "StartLine": 50,
                "EndLine": 10,
            },
            "expect_valid": False,
            "error_keyword": "Range constraint violated",
        },
        # 9. StartLine is string instead of int
        {
            "name": "StartLine as string in replace_file_content",
            "tool": "replace_file_content",
            "args": {
                "TargetFile": "src/app.py",
                "TargetContent": "old",
                "ReplacementContent": "new",
                "StartLine": "10",
            },
            "expect_valid": False,
            "error_keyword": "StartLine' must be an integer",
        },
        # 10. StartLine is bool (True)
        {
            "name": "StartLine as bool in replace_file_content",
            "tool": "replace_file_content",
            "args": {
                "TargetFile": "src/app.py",
                "TargetContent": "old",
                "ReplacementContent": "new",
                "StartLine": True,
            },
            "expect_valid": False,
            "error_keyword": "StartLine' must be an integer",
        },
        # 11. Valid run_command
        {
            "name": "Valid run_command",
            "tool": "run_command",
            "args": {"CommandLine": "git status", "WaitMsBeforeAsync": 2000},
            "expect_valid": True,
        },
        # 12. Missing CommandLine in run_command
        {
            "name": "Missing CommandLine in run_command",
            "tool": "run_command",
            "args": {"WaitMsBeforeAsync": 2000},
            "expect_valid": False,
            "error_keyword": "Missing required parameter 'CommandLine'",
        },
        # 13. Empty CommandLine string
        {
            "name": "Empty CommandLine in run_command",
            "tool": "run_command",
            "args": {"CommandLine": "   "},
            "expect_valid": False,
            "error_keyword": "cannot be empty",
        },
        # 14. Negative WaitMsBeforeAsync
        {
            "name": "Negative WaitMsBeforeAsync in run_command",
            "tool": "run_command",
            "args": {"CommandLine": "dir", "WaitMsBeforeAsync": -500},
            "expect_valid": False,
            "error_keyword": "cannot be negative",
        },
        # 15. Unmonitored tool (view_file)
        {
            "name": "Unmonitored tool outside validation scope",
            "tool": "view_file",
            "args": {"AbsolutePath": "C:/some/file.txt"},
            "expect_valid": True,
        },
        # 16. Args not a dict
        {
            "name": "Args is a list instead of dict",
            "tool": "run_command",
            "args": ["git", "status"],
            "expect_valid": False,
            "error_keyword": "must be a dictionary",
        },
    ]

    all_passed = True
    for idx, tc in enumerate(test_cases, start=1):
        is_valid, reason = validate_tool_call_ast(tc["tool"], tc["args"])

        if is_valid != tc["expect_valid"]:
            sys.stderr.write(
                f"  FAILED Case #{idx} [{tc['name']}]: expected valid={tc['expect_valid']}, got {is_valid} ({reason})\n"
            )
            all_passed = False
            continue

        if not is_valid and "error_keyword" in tc:
            if tc["error_keyword"].lower() not in reason.lower():
                sys.stderr.write(
                    f"  FAILED Case #{idx} [{tc['name']}]: expected error keyword '{tc['error_keyword']}', got '{reason}'\n"
                )
                all_passed = False
                continue

        sys.stderr.write(f"  PASSED Case #{idx} [{tc['name']}]\n")

    # Verify evaluate_tool_call hook payload handling
    valid_payload = {
        "toolCall": {
            "name": "write_to_file",
            "args": {"TargetFile": "app.py", "CodeContent": "x = 1"},
        }
    }
    resp_allow = evaluate_tool_call(valid_payload)
    assert resp_allow.get("decision") == "allow", "Valid payload must result in decision 'allow'"

    invalid_payload = {
        "toolCall": {
            "name": "write_to_file",
            "args": {"TargetFile": "app.py"},
        }
    }
    resp_deny = evaluate_tool_call(invalid_payload)
    assert resp_deny.get("decision") == "deny", "Invalid payload must result in decision 'deny'"

    if all_passed:
        sys.stderr.write("[SELF-TEST PASS] bfcl_tool_call_ast_validator passed all tests.\n")
        return True
    else:
        sys.stderr.write("[SELF-TEST FAIL] bfcl_tool_call_ast_validator encountered failures.\n")
        return False


def main() -> None:
    """CLI Hook Entrypoint."""
    if "--self-test" in sys.argv:
        success = run_self_test()
        sys.exit(0 if success else 1)

    payload = read_stdin_payload(default={})
    response = evaluate_tool_call(payload)
    emit_stdout_json(response)


if __name__ == "__main__":
    main()
