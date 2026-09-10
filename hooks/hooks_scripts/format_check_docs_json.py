#!/usr/bin/env python3
"""Format Check Docs & JSON Hook (PostToolUse) for Enterprise Multi-Agent Governance System.

Enforces Repository Hygiene (§13) & Backend Standards (§7, §8, §18):
1. Markdown files: 0 trailing whitespace (use <br> for line breaks), normalized EOF newlines,
   preservation of platform line ending conventions (CRLF vs LF), atomic temp-file replace,
   and strict non-destructive UTF-8 decode safety (never overwrite on decode errors).
2. JSON files: Valid syntax validation with bounded memory limits and DoS protection.
3. 100% Dynamic Configuration via hook_utils/config_loader and dynamic_limits.json
   with Zero-Config fallback (zero hardcoded values).
Logs diagnostic warnings to stderr and returns standard empty object on stdout.
"""

from __future__ import annotations

import copy
import json
import os
import pathlib
import sys
import tempfile
from typing import Any

# Ensure both hooks_scripts and repository root (parent of hook_utils) are in sys.path
_CURRENT_DIR = pathlib.Path(__file__).parent.resolve()
_REPO_ROOT = _CURRENT_DIR.parent.resolve()

if str(_CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(_CURRENT_DIR))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from common_hook_lib import (  # noqa: E402
    emit_stdout_json,
    get_tool_args,
    get_tool_call,
    log_diagnostic,
    normalize_path,
    post_tool_response,
    read_stdin_payload,
)

# Optional dynamic config loader integration
try:
    from hook_utils.config_loader import get_format_check_config  # noqa: E402
except ImportError:
    try:
        from hook_utils import get_format_check_config  # noqa: E402
    except ImportError:
        get_format_check_config = None

try:
    from config_loader import get_governance_config  # noqa: E402
except ImportError:
    get_governance_config = None


# Default Governance Parameters (Zero-Config Resilience)
DEFAULT_FORMAT_CONFIG: dict[str, Any] = {
    "enabled": True,
    "max_file_size_bytes": 10485760,  # 10 MB limit
    "file_encoding": "utf-8",
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
        "paths",
        "files",
    ],
    "markdown": {
        "enabled": True,
        "extensions": [".md", ".markdown", ".mdown", ".mkd"],
        "strip_trailing_spaces": True,
        "normalize_eof_newlines": True,
        "preserve_empty_files": True,
        "trailing_whitespace_chars": " \t\r",
    },
    "json": {
        "enabled": True,
        "extensions": [".json", ".jsonc"],
        "validate_syntax": True,
        "allow_empty": False,
    },
    "error_messages": {
        "syntax_error": "JSON Syntax Error in {file_name}: line {line}, col {col}: {msg}",
        "file_too_large": "Format Check: File {file_name} ({size} bytes) exceeds max limit ({max_size} bytes). Skipping.",
        "decode_error": "Format Check: Decoding error on {file_name}: {exc}. Skipping auto-formatting to prevent data corruption.",
        "generic_error": "Error checking markdown formatting on {file_name}: {exc}",
        "json_read_error": "Error reading JSON file {file_name}: {exc}",
        "cleaned_success": "Repository Hygiene (§13): Cleaned {count} trailing spaces and normalized EOF in {file_name}.",
        "clean_success": "Markdown format clean: {file_name}",
        "json_valid": "JSON syntax valid: {file_name}",
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> None:
    """Recursively merge override dictionary into base dictionary."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = copy.deepcopy(value)


def load_active_config() -> dict[str, Any]:
    """Dynamically load and merge format_check configuration.

    Priority:
    1. hook_utils.config_loader (hot-reloadable from dynamic_limits.json)
    2. governance.config (if format_check section exists)
    3. DEFAULT_FORMAT_CONFIG fallback (Zero-Config Resilience)
    """
    config = copy.deepcopy(DEFAULT_FORMAT_CONFIG)

    if get_format_check_config is not None:
        try:
            dynamic_cfg = get_format_check_config()
            if isinstance(dynamic_cfg, dict) and dynamic_cfg:
                _deep_merge(config, dynamic_cfg)
        except Exception as exc:
            log_diagnostic(f"Failed loading dynamic limits for format_check: {exc}")

    if get_governance_config is not None:
        try:
            gov_cfg = get_governance_config()
            if isinstance(gov_cfg, dict):
                gov_format = gov_cfg.get("format_check")
                if isinstance(gov_format, dict):
                    _deep_merge(config, gov_format)
        except Exception as exc:
            log_diagnostic(f"Failed reading governance config for format_check: {exc}")

    return config


def _atomic_write_text(file_path: pathlib.Path, content: str, encoding: str = "utf-8") -> None:
    """Write content to file atomically using a temporary file in the same directory."""
    parent_dir = file_path.parent
    temp_fd, temp_path_str = tempfile.mkstemp(
        dir=str(parent_dir),
        prefix=".fmt_tmp_",
        suffix=file_path.suffix,
    )
    temp_path = pathlib.Path(temp_path_str)
    try:
        with os.fdopen(temp_fd, "w", encoding=encoding, newline="") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, file_path)
    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise


def inspect_and_format_markdown(file_path: pathlib.Path, config: dict[str, Any]) -> None:
    """Check and auto-fix trailing spaces and EOF blank lines in Markdown files."""
    md_cfg = config.get("markdown", {})
    if not md_cfg.get("enabled", True):
        return

    err_msgs = config.get("error_messages", {})
    max_size = config.get("max_file_size_bytes", 10485760)
    encoding = config.get("file_encoding", "utf-8")

    try:
        file_size = file_path.stat().st_size
        if file_size > max_size:
            msg = err_msgs.get(
                "file_too_large",
                "Format Check: File {file_name} ({size} bytes) exceeds max limit ({max_size} bytes). Skipping.",
            ).format(file_name=file_path.name, size=file_size, max_size=max_size)
            log_diagnostic(msg)
            return

        # P0 Fix: Strict decoding check to prevent irreversible data loss / corrupt replacement
        try:
            raw_bytes = file_path.read_bytes()
            raw_content = raw_bytes.decode(encoding=encoding, errors="strict")
        except UnicodeDecodeError as decode_exc:
            msg = err_msgs.get(
                "decode_error",
                "Format Check: Decoding error on {file_name}: {exc}. Skipping auto-formatting to prevent data corruption.",
            ).format(file_name=file_path.name, exc=decode_exc)
            log_diagnostic(msg)
            return

        # P0 Fix: Empty file preservation
        if not raw_content:
            if md_cfg.get("preserve_empty_files", True):
                msg = err_msgs.get("clean_success", "Markdown format clean: {file_name}").format(
                    file_name=file_path.name
                )
                log_diagnostic(msg)
                return

        # Detect line endings (Windows CRLF vs POSIX LF)
        newline_char = "\r\n" if "\r\n" in raw_content else "\n"

        trailing_chars = md_cfg.get("trailing_whitespace_chars", " \t\r")
        strip_trailing = md_cfg.get("strip_trailing_spaces", True)
        normalize_eof = md_cfg.get("normalize_eof_newlines", True)

        lines = raw_content.splitlines()
        trailing_space_count = 0
        cleaned_lines: list[str] = []

        for line in lines:
            if strip_trailing:
                stripped = line.rstrip(trailing_chars)
                if len(stripped) < len(line):
                    trailing_space_count += 1
                cleaned_lines.append(stripped)
            else:
                cleaned_lines.append(line)

        if normalize_eof:
            cleaned_text = newline_char.join(cleaned_lines).rstrip(" \t\r\n") + newline_char
        else:
            cleaned_text = newline_char.join(cleaned_lines)

        # Only modify the file if actual content or line endings needed formatting
        if trailing_space_count > 0 or cleaned_text != raw_content:
            # P0 Fix: Atomic temp-file replacement to prevent partial write or file corruption
            _atomic_write_text(file_path, cleaned_text, encoding=encoding)
            msg = err_msgs.get(
                "cleaned_success",
                "Repository Hygiene (§13): Cleaned {count} trailing spaces and normalized EOF in {file_name}.",
            ).format(count=trailing_space_count, file_name=file_path.name)
            log_diagnostic(msg)
        else:
            msg = err_msgs.get("clean_success", "Markdown format clean: {file_name}").format(
                file_name=file_path.name
            )
            log_diagnostic(msg)

    except (OSError, UnicodeEncodeError) as exc:
        msg = err_msgs.get("generic_error", "Error checking markdown formatting on {file_name}: {exc}").format(
            file_name=file_path.name, exc=exc
        )
        log_diagnostic(msg)


def inspect_json(file_path: pathlib.Path, config: dict[str, Any]) -> None:
    """Validate JSON file syntax."""
    json_cfg = config.get("json", {})
    if not json_cfg.get("enabled", True) or not json_cfg.get("validate_syntax", True):
        return

    err_msgs = config.get("error_messages", {})
    max_size = json_cfg.get("max_file_size_bytes", config.get("max_file_size_bytes", 10485760))
    encoding = config.get("file_encoding", "utf-8")

    try:
        file_size = file_path.stat().st_size
        if file_size > max_size:
            msg = err_msgs.get(
                "file_too_large",
                "Format Check: File {file_name} ({size} bytes) exceeds max limit ({max_size} bytes). Skipping.",
            ).format(file_name=file_path.name, size=file_size, max_size=max_size)
            log_diagnostic(msg)
            return

        raw_content = file_path.read_bytes().decode(encoding=encoding, errors="replace")
        if not raw_content.strip():
            if not json_cfg.get("allow_empty", False):
                log_diagnostic(
                    err_msgs.get(
                        "syntax_error",
                        "JSON Syntax Error in {file_name}: line {line}, col {col}: {msg}",
                    ).format(file_name=file_path.name, line=1, col=1, msg="Expecting value: empty JSON document")
                )
                return

        json.loads(raw_content)
        msg = err_msgs.get("json_valid", "JSON syntax valid: {file_name}").format(file_name=file_path.name)
        log_diagnostic(msg)
    except json.JSONDecodeError as exc:
        msg = err_msgs.get(
            "syntax_error",
            "JSON Syntax Error in {file_name}: line {line}, col {col}: {msg}",
        ).format(file_name=file_path.name, line=exc.lineno, col=exc.colno, msg=exc.msg)
        log_diagnostic(msg)
    except (OSError, UnicodeDecodeError, UnicodeEncodeError) as exc:
        msg = err_msgs.get("json_read_error", "Error reading JSON file {file_name}: {exc}").format(
            file_name=file_path.name, exc=exc
        )
        log_diagnostic(msg)


def extract_target_files(args: dict[str, Any], config: dict[str, Any]) -> list[pathlib.Path]:
    """Extract and normalize all target file paths from toolCall arguments."""
    target_keys = config.get(
        "target_argument_keys",
        ["TargetFile", "target_file", "filePath", "file_path", "path", "paths", "files"],
    )
    raw_targets: list[str] = []

    for key in target_keys:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            raw_targets.append(val.strip())
        elif isinstance(val, (list, tuple)):
            for item in val:
                if isinstance(item, str) and item.strip():
                    raw_targets.append(item.strip())

    # Deduplicate while preserving order
    seen: set[str] = set()
    normalized_paths: list[pathlib.Path] = []
    for raw in raw_targets:
        if raw not in seen:
            seen.add(raw)
            try:
                p = normalize_path(raw)
                if p.is_file():
                    normalized_paths.append(p)
            except (OSError, ValueError):
                continue

    return normalized_paths


def evaluate_format_check(payload: dict) -> dict:
    """Evaluate format on modified documentation and JSON files."""
    config = load_active_config()
    if not config.get("enabled", True):
        return post_tool_response()

    tool_call = get_tool_call(payload)
    args = get_tool_args(tool_call)

    target_paths = extract_target_files(args, config)
    if not target_paths:
        return post_tool_response()

    md_extensions = set(config.get("markdown", {}).get("extensions", [".md", ".markdown"]))
    json_extensions = set(config.get("json", {}).get("extensions", [".json"]))

    for target_path in target_paths:
        ext = target_path.suffix.lower()
        if ext in md_extensions:
            inspect_and_format_markdown(target_path, config)
        elif ext in json_extensions:
            inspect_json(target_path, config)

    return post_tool_response()


def main() -> None:
    payload = read_stdin_payload(default={})
    response = evaluate_format_check(payload)
    emit_stdout_json(response)


if __name__ == "__main__":
    main()
