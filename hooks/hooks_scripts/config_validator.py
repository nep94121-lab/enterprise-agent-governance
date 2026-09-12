#!/usr/bin/env python3
"""
hooks_scripts/config_validator.py
Validate hooks.json configuration.

Supports both:
1. Antigravity Enterprise schema (direct mapping: hook_id -> {enabled, PreToolUse, PostToolUse, etc.})
2. Wrapped schema ({version, hooks: {...}, global_settings: {...}})
"""

import json
import re
import sys
from pathlib import Path
from typing import Any


class ConfigValidator:
    """Validates hooks.json configuration structure and values."""

    VALID_VERSIONS = [1, 2]
    # Antigravity 5 core lifecycle events + extension events
    VALID_EVENTS = [
        "PreToolUse", "PostToolUse",
        "PreInvocation", "PostInvocation",
        "Stop",
        "TokenBudget", "TokenBudgetWarning",
        "LLMDiff", "LLMResponse",
        "MCPToolExecution", "MCPServerStart", "MCPServerError",
    ]
    VALID_TRIGGERS = VALID_EVENTS  # Alias for backward compatibility
    VALID_HOOK_TYPES = ["command"]
    VALID_ON_FAILURE = ["log_and_continue", "log_and_block", "fail"]
    VALID_LOG_LEVELS = ["debug", "info", "warning", "error"]
    VALID_ERROR_ACTIONS = ["log_and_continue", "log_and_block", "fail"]

    def __init__(self, config_path: str | None = None, base_dir: Path | None = None):
        self.config_path = config_path or self._find_config()
        self.base_dir = base_dir or Path(self.config_path).resolve().parent
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.config: dict[str, Any] = {}

    def _find_config(self) -> str:
        """Find hooks.json in current directory or parent directories."""
        search_paths = [
            Path.cwd() / "hooks.json",
            Path.cwd().parent / "hooks.json",
            Path(__file__).resolve().parent.parent / "hooks.json",
        ]
        for path in search_paths:
            if path.exists():
                return str(path)
        return "hooks.json"

    def load_config(self) -> bool:
        """Load and parse the JSON configuration file with duplicate key detection."""
        try:
            def _detect_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                d: dict[str, Any] = {}
                for k, v in pairs:
                    if k in d:
                        self.errors.append(f"Duplicate key '{k}' detected in configuration: {self.config_path}")
                    d[k] = v
                return d

            with open(self.config_path, encoding="utf-8") as f:
                self.config = json.load(f, object_pairs_hook=_detect_duplicates)
            if self.errors:
                return False
            return True
        except FileNotFoundError:
            self.errors.append(f"Configuration file not found: {self.config_path}")
            return False
        except json.JSONDecodeError as e:
            self.errors.append(f"Invalid JSON in configuration: {e}")
            return False

    def validate(self) -> bool:
        """Run all validation checks. Returns True if valid."""
        load_errors = [e for e in self.errors if "Duplicate key" in e]
        self.errors.clear()
        self.errors.extend(load_errors)
        self.warnings.clear()
        if self.errors:
            return False

        if not isinstance(self.config, dict):
            self.errors.append(f"Configuration root must be an object, got {type(self.config).__name__}")
            return False

        if not self.config:
            self.errors.append("No configuration loaded or configuration is empty")
            return False

        # Detect schema style:
        # Style A: Wrapped schema with 'hooks' key (e.g. {"version": 1, "hooks": {...}})
        # Style B: Direct schema mapping hook identifiers directly (e.g. {"scope-boundary-enforcer": {...}})
        if "hooks" in self.config and isinstance(self.config["hooks"], dict):
            self._validate_version()
            hooks_dict = self.config["hooks"]
            if "global_settings" in self.config:
                self._validate_global_settings()
        else:
            # Direct mapping format (Standard Antigravity hooks.json)
            if "version" in self.config:
                self._validate_version()
            if "global_settings" in self.config:
                self._validate_global_settings()
            hooks_dict = {
                k: v for k, v in self.config.items()
                if k not in ("version", "global_settings", "$schema")
            }

        if not hooks_dict:
            self.errors.append("No hooks defined in configuration")
            return False

        for hook_name, hook_config in hooks_dict.items():
            self._validate_hook(hook_name, hook_config)

        return len(self.errors) == 0

    def _validate_version(self) -> None:
        """Validate the version field if present."""
        if "version" not in self.config:
            return

        version = self.config["version"]
        if not isinstance(version, int):
            self.errors.append(f"'version' must be an integer, got {type(version).__name__}")
        elif version not in self.VALID_VERSIONS:
            self.errors.append(f"'version' must be one of {self.VALID_VERSIONS}, got {version}")

    def _validate_hook(self, name: str, config: Any) -> None:
        """Validate a single hook configuration (supports both modern and legacy shapes)."""
        if not isinstance(config, dict):
            self.errors.append(f"Hook '{name}': must be an object")
            return

        # Check legacy schema format: has 'trigger' field
        if "trigger" in config:
            self._validate_legacy_hook(name, config)
            return

        # Modern Antigravity Enterprise schema:
        # 1. Optional 'enabled' boolean
        if "enabled" in config and not isinstance(config["enabled"], bool):
            self.errors.append(f"Hook '{name}': 'enabled' must be a boolean")

        # 2. Extract event sections
        found_events = [k for k in config.keys() if k in self.VALID_EVENTS]
        non_event_keys = [
            k for k in config.keys()
            if k not in self.VALID_EVENTS and k not in ("enabled", "description", "name")
        ]

        for extra_key in non_event_keys:
            self.errors.append(
                f"Hook '{name}': unknown field or invalid event '{extra_key}'. "
                f"Valid events: {', '.join(self.VALID_EVENTS)}"
            )

        if not found_events:
            self.warnings.append(f"Hook '{name}': no lifecycle events defined")
            return

        for event in found_events:
            self._validate_event_handlers(name, event, config[event])

    def _validate_event_handlers(self, hook_name: str, event: str, handlers: Any) -> None:
        """Validate the list of handlers for a specific lifecycle event."""
        if not isinstance(handlers, list):
            self.errors.append(f"Hook '{hook_name}' event '{event}': must be an array of handlers")
            return

        if len(handlers) == 0:
            self.warnings.append(f"Hook '{hook_name}' event '{event}': handlers list is empty")
            return

        for idx, item in enumerate(handlers):
            if not isinstance(item, dict):
                self.errors.append(f"Hook '{hook_name}' event '{event}' handler[{idx}]: must be an object")
                continue

            # Handler pattern A: Object with 'hooks' list (and optional 'matcher')
            if "hooks" in item:
                matcher = item.get("matcher")
                if matcher is not None:
                    if not isinstance(matcher, str):
                        self.errors.append(
                            f"Hook '{hook_name}' event '{event}' handler[{idx}]: 'matcher' must be a string"
                        )
                    else:
                        self._validate_regex_pattern(hook_name, event, idx, matcher)

                sub_hooks = item["hooks"]
                if not isinstance(sub_hooks, list):
                    self.errors.append(
                        f"Hook '{hook_name}' event '{event}' handler[{idx}]: 'hooks' must be an array"
                    )
                elif len(sub_hooks) == 0:
                    self.warnings.append(
                        f"Hook '{hook_name}' event '{event}' handler[{idx}]: 'hooks' array is empty"
                    )
                else:
                    for sub_idx, sub_hook in enumerate(sub_hooks):
                        self._validate_hook_action(hook_name, event, f"{idx}.hooks[{sub_idx}]", sub_hook)

            # Handler pattern B: Direct hook action object with 'command' or 'type'
            elif "command" in item or "type" in item:
                matcher = item.get("matcher")
                if matcher is not None:
                    if not isinstance(matcher, str):
                        self.errors.append(
                            f"Hook '{hook_name}' event '{event}' handler[{idx}]: 'matcher' must be a string"
                        )
                    else:
                        self._validate_regex_pattern(hook_name, event, idx, matcher)
                self._validate_hook_action(hook_name, event, str(idx), item)

            else:
                self.errors.append(
                    f"Hook '{hook_name}' event '{event}' handler[{idx}]: "
                    f"must contain either 'hooks' array or 'command' string"
                )

    def _validate_hook_action(self, hook_name: str, event: str, location: str, action: Any) -> None:
        """Validate a single hook command execution action."""
        if not isinstance(action, dict):
            self.errors.append(f"Hook '{hook_name}' event '{event}' [{location}]: action must be an object")
            return

        # Type validation
        hook_type = action.get("type", "command")
        if not isinstance(hook_type, str):
            self.errors.append(f"Hook '{hook_name}' event '{event}' [{location}]: 'type' must be a string")
        elif hook_type not in self.VALID_HOOK_TYPES:
            self.errors.append(
                f"Hook '{hook_name}' event '{event}' [{location}]: invalid type '{hook_type}'. "
                f"Valid types: {', '.join(self.VALID_HOOK_TYPES)}"
            )

        # Command validation
        if "command" not in action:
            self.errors.append(f"Hook '{hook_name}' event '{event}' [{location}]: missing required field 'command'")
        else:
            cmd = action["command"]
            if not isinstance(cmd, str) or not cmd.strip():
                self.errors.append(
                    f"Hook '{hook_name}' event '{event}' [{location}]: 'command' must be a non-empty string"
                )
            else:
                self._validate_command_script(hook_name, event, location, cmd)

        # Timeout validation (timeout in seconds, positive number)
        timeout = action.get("timeout")
        if timeout is not None:
            if not isinstance(timeout, (int, float)):
                self.errors.append(
                    f"Hook '{hook_name}' event '{event}' [{location}]: 'timeout' must be a number"
                )
            elif timeout <= 0:
                self.errors.append(
                    f"Hook '{hook_name}' event '{event}' [{location}]: 'timeout' must be positive"
                )

    def _validate_command_script(self, hook_name: str, event: str, location: str, cmd: str) -> None:
        """Check if python scripts referenced in commands actually exist on disk."""
        tokens = cmd.split()
        py_tokens = [t for t in tokens if t.endswith(".py")]
        for py_script in py_tokens:
            script_path = self.base_dir / py_script
            # Also check relative to hooks_scripts directory
            if not script_path.exists():
                alt_path = self.base_dir / "hooks_scripts" / Path(py_script).name
                if not alt_path.exists():
                    self.warnings.append(
                        f"Hook '{hook_name}' event '{event}' [{location}]: "
                        f"referenced script '{py_script}' not found at '{script_path}' or '{alt_path}'"
                    )

    def _validate_regex_pattern(self, hook_name: str, event: str, idx: int, pattern: str) -> None:
        """Verify regex pattern syntax is valid."""
        try:
            re.compile(pattern)
        except re.error as e:
            self.errors.append(
                f"Hook '{hook_name}' event '{event}' handler[{idx}]: invalid regex matcher '{pattern}': {e}"
            )

    # -------------------------------------------------------------------------
    # Legacy schema compatibility methods
    # -------------------------------------------------------------------------
    def _validate_legacy_hook(self, name: str, config: dict) -> None:
        """Validate legacy hook format containing 'trigger', 'matchers', etc."""
        self._validate_trigger(name, config.get("trigger"))
        if "matchers" in config:
            self._validate_legacy_matchers(name, config)
        if "error_handling" in config:
            self._validate_error_handling(name, config)

    def _validate_trigger(self, hook_name: str, trigger: Any) -> None:
        """Validate the trigger field."""
        if trigger is None:
            return
        if not isinstance(trigger, str):
            self.errors.append(f"Hook '{hook_name}': 'trigger' must be a string")
            return
        if trigger not in self.VALID_TRIGGERS:
            self.errors.append(
                f"Hook '{hook_name}': invalid trigger '{trigger}'. "
                f"Valid triggers: {', '.join(self.VALID_TRIGGERS)}"
            )

    def _validate_legacy_matchers(self, hook_name: str, config: dict) -> None:
        """Validate legacy matchers array."""
        matchers = config["matchers"]
        if not isinstance(matchers, list):
            self.errors.append(f"Hook '{hook_name}': 'matchers' must be an array")
            return

        if len(matchers) == 0:
            self.warnings.append(f"Hook '{hook_name}': 'matchers' is empty")

        for i, matcher in enumerate(matchers):
            if not isinstance(matcher, dict):
                self.errors.append(f"Hook '{hook_name}': matcher[{i}] must be an object")
                continue
            if "pattern" not in matcher:
                self.errors.append(f"Hook '{hook_name}': matcher[{i}] missing 'pattern'")
                continue
            pattern = matcher["pattern"]
            if not isinstance(pattern, str):
                self.errors.append(f"Hook '{hook_name}': matcher[{i}] 'pattern' must be a string")
            else:
                try:
                    re.compile(pattern)
                except re.error as e:
                    self.errors.append(f"Hook '{hook_name}': matcher[{i}] invalid regex '{pattern}': {e}")

            timeout = matcher.get("timeout_ms")
            if timeout is not None:
                if not isinstance(timeout, (int, float)):
                    self.errors.append(f"Hook '{hook_name}': matcher[{i}] 'timeout_ms' must be a number")
                elif timeout <= 0:
                    self.errors.append(f"Hook '{hook_name}': matcher[{i}] 'timeout_ms' must be positive")

            continue_on_error = matcher.get("continue_on_error")
            if continue_on_error is not None and not isinstance(continue_on_error, bool):
                self.errors.append(f"Hook '{hook_name}': matcher[{i}] 'continue_on_error' must be boolean")

    def _validate_error_handling(self, hook_name: str, config: dict) -> None:
        """Validate the error_handling section."""
        if "error_handling" not in config:
            return

        error_handling = config["error_handling"]
        if not isinstance(error_handling, dict):
            self.errors.append(f"Hook '{hook_name}': 'error_handling' must be an object")
            return

        on_failure = error_handling.get("on_failure")
        if on_failure is not None:
            if not isinstance(on_failure, str):
                self.errors.append(f"Hook '{hook_name}': 'on_failure' must be a string")
            elif on_failure not in self.VALID_ON_FAILURE:
                self.errors.append(
                    f"Hook '{hook_name}': invalid 'on_failure' value '{on_failure}'. "
                    f"Valid: {', '.join(self.VALID_ON_FAILURE)}"
                )

        max_retries = error_handling.get("max_retries")
        if max_retries is not None:
            if not isinstance(max_retries, int):
                self.errors.append(f"Hook '{hook_name}': 'max_retries' must be an integer")
            elif max_retries < 0:
                self.errors.append(f"Hook '{hook_name}': 'max_retries' must be non-negative")

        retry_delay = error_handling.get("retry_delay_ms")
        if retry_delay is not None:
            if not isinstance(retry_delay, (int, float)):
                self.errors.append(f"Hook '{hook_name}': 'retry_delay_ms' must be a number")
            elif retry_delay < 0:
                self.errors.append(f"Hook '{hook_name}': 'retry_delay_ms' must be non-negative")

    def _validate_global_settings(self) -> None:
        """Validate the global_settings section if present."""
        if "global_settings" not in self.config:
            return

        settings = self.config["global_settings"]
        if not isinstance(settings, dict):
            self.errors.append("'global_settings' must be an object")
            return

        if "enable_all_hooks" in settings:
            val = settings["enable_all_hooks"]
            if not isinstance(val, bool):
                self.errors.append("'enable_all_hooks' must be a boolean")

        if "default_timeout_ms" in settings:
            val = settings["default_timeout_ms"]
            if not isinstance(val, (int, float)):
                self.errors.append("'default_timeout_ms' must be a number")
            elif val <= 0:
                self.errors.append("'default_timeout_ms' must be positive")

        if "default_error_action" in settings:
            val = settings["default_error_action"]
            if val not in self.VALID_ERROR_ACTIONS:
                self.errors.append(
                    f"Invalid 'default_error_action': '{val}'. "
                    f"Valid: {', '.join(self.VALID_ERROR_ACTIONS)}"
                )

        if "log_level" in settings:
            val = settings["log_level"]
            if val not in self.VALID_LOG_LEVELS:
                self.errors.append(
                    f"Invalid 'log_level': '{val}'. "
                    f"Valid: {', '.join(self.VALID_LOG_LEVELS)}"
                )

        if "token_budget_threshold" in settings:
            val = settings["token_budget_threshold"]
            if not isinstance(val, (int, float)):
                self.errors.append("'token_budget_threshold' must be a number")
            elif not 0 <= val <= 1:
                self.errors.append("'token_budget_threshold' must be between 0 and 1")

    def print_report(self) -> None:
        """Print validation report to stdout."""
        print(f"\n{'='*60}")
        print("Configuration Validator Report")
        print(f"{'='*60}")
        print(f"File: {self.config_path}")

        if self.warnings:
            print(f"\nWarnings ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  [WARN] {warning}")

        if self.errors:
            print(f"\nErrors ({len(self.errors)}):")
            for error in self.errors:
                print(f"  [ERROR] {error}")
        else:
            print("\nStatus: VALID")

        print(f"\n{'='*60}\n")


def main() -> int:
    """Main entry point for CLI usage."""
    config_path = sys.argv[1] if len(sys.argv) > 1 else None

    validator = ConfigValidator(config_path)

    if not validator.load_config():
        validator.print_report()
        return 1

    is_valid = validator.validate()
    validator.print_report()

    return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
