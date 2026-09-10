#!/usr/bin/env python3
"""Enterprise Hook Utilities - Dynamic Config Loader.

Hot-reloadable dynamic configuration loader with mtime cache for enterprise hooks.
Eliminates magic numbers by sourcing limits from dynamic_limits.json with <= 5ms reload latency.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import pathlib
import threading
from typing import Any

logger = logging.getLogger("enterprise_hooks.config_loader")

# Default fallback configuration (Zero-Config Resilience)
DEFAULT_DYNAMIC_LIMITS: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "hardware_profile": {
        "cpu_cores_physical": 4,
        "cpu_threads_logical": 8,
        "optimal_cpu_load_min_percent": 60.0,
        "optimal_cpu_load_max_percent": 85.0,
    },
    "concurrency_rules": {
        "pool_1_cloud_thinking_max_subagents": 20,
        "pool_2_local_burst_concurrent_slots": 3,
        "cooldown_sleep_seconds_on_high_load": 1.0,
        "atomic_workload_threshold": 2,
        "sliding_window_seconds": 1800,
        "workspace_backlog_threshold": 5,
    },
    "execution_timeouts": {
        "read_io_timeout_seconds": 15,
        "light_command_timeout_seconds": 30,
        "heavy_build_timeout_seconds": 180,
    },
    "test_runner": {
        "timeout_seconds": 30,
        "max_summary_lines": 10,
        "max_output_chars": 1000,
        "excluded_filenames": ["__init__.py", "conftest.py", "setup.py", "fixtures.py"],
    },
    "circuit_breaker": {
        "failure_threshold": 5,
        "recovery_timeout_seconds": 30.0,
        "half_open_max_trials": 3,
        "consecutive_success_threshold": 2,
        "rolling_window_size": 20,
        "failure_rate_threshold": 0.5,
    },
    "audit_trail": {
        "log_dir": "logs/audit",
        "max_file_size_mb": 100,
        "rotation_enabled": True,
        "index_enabled": True,
        "max_index_entries": 10000,
        "sanitize_pii": True,
        "lock_timeout_seconds": 10.0,
        "query_default_limit": 1000,
    },
    "regression_detector": {
        "hash_algorithm": "sha256",
        "snapshot_store_dir": ".regression_snapshots",
        "max_diff_lines": 5000,
        "max_file_size_bytes": 10485760,
        "block_on_untracked_drift": True,
        "block_on_checksum_mismatch": True,
        "syntax_verification_enabled": True,
        "protected_paths": [
            "rules_by_role",
            "governance.config.schema.json",
        ],
        "excluded_patterns": [
            ".git",
            "__pycache__",
            "*.pyc",
            ".pytest_cache",
            ".ruff_cache",
            "node_modules",
            ".venv",
            "venv",
            ".anti_sequential",
            ".burst_guard",
            ".regression_snapshots",
        ],
    },
    "context_compression": {
        "enabled": True,
        "min_savings_ratio_percent": 15.0,
        "target_savings_ratio_percent": 25.0,
        "max_consecutive_blank_lines": 1,
        "max_separator_chars": 3,
        "condense_markdown_tables": True,
        "condense_code_comments": True,
        "max_table_col_width": 40,
        "deduplicate_repeated_lines": True,
        "collapse_duplicate_log_threshold": 3,
        "mask_sensitive_pii": True,
        "truncate_base64_threshold_chars": 100,
        "preserve_code_blocks": True,
    },
    "hallucination_guard": {
        "enabled": True,
        "strict_mode": True,
        "inspect_tools": [
            "view_file",
            "replace_file_content",
            "read_file",
            "get_code_snippet",
        ],
        "file_creation_tools": [
            "write_to_file",
        ],
        "check_command_scripts": True,
        "suggest_corrections": True,
        "max_suggestions": 3,
        "fuzzy_cutoff": 0.6,
        "allowed_virtual_schemes": [
            "memory:",
            "virtual:",
            "tmp:",
            "temp:",
        ],
    },
    "token_budget": {
        "enabled": True,
        "default_context_window": 1000000,
        "warning_threshold_ratio": 0.80,
        "critical_threshold_ratio": 0.95,
        "exhausted_threshold_ratio": 1.0,
        "max_rule_file_tokens": 4000,
        "max_role_tokens": 12000,
        "target_role_tokens": 7000,
        "max_single_message_tokens": 8000,
        "verbosity_warning_tokens": 6000,
        "ratios": {
            "ascii_chars_per_token": 4.0,
            "code_symbol_chars_per_token": 2.5,
            "vietnamese_accented_chars_per_token": 1.5,
            "cjk_chars_per_token": 1.2,
            "whitespace_chars_per_token": 4.0,
            "default_chars_per_token": 3.5,
        },
        "role_budgets": {
            "pm_orchestrator": 15000,
            "backend_developer": 12000,
            "frontend_developer": 12000,
            "devops_security": 12000,
            "qa_challenger": 15000,
            "tech_lead_auditor": 12000,
            "pm": 15000,
            "dev": 12000,
            "qa": 15000,
            "tl": 12000,
        },
        "state_storage_dir": ".token_budget",
        "state_file_name": "governor_state.json",
        "rolling_window_seconds": 3600,
    },
    "mcp_health_checker": {
        "check_interval_seconds": 60,
        "failure_threshold": 3,
        "degraded_threshold": 1,
        "latency_window_size": 100,
        "max_window_size": 1000,
        "enable_trend_analysis": True,
        "default_warning_latency_ms": 1000.0,
        "default_critical_latency_ms": 5000.0,
        "default_availability_warning": 95.0,
        "default_availability_critical": 90.0,
        "timeout_seconds": 5.0,
        "min_samples_for_trend": 10,
        "trend_change_threshold": 10.0,
        "trend_confidence_divisor": 50.0,
        "trend_confidence_min": 0.7,
        "max_results_history": 100,
        "max_alerts_history": 1000,
        "default_history_limit": 100,
        "availability_recommendation_threshold": 95.0,
    },
    "self_healing": {
        "enabled": True,
        "max_healing_attempts": 3,
        "auto_fix_allowed": True,
        "confidence_threshold": 0.8,
        "max_suggestions_per_error": 5,
        "matrix_config_file": "self_healing_matrix.json",
        "cooldown_seconds_between_retries": 1.5,
    },
    "scope_boundary": {
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
            "destination",
        ],
        "metadata_directories": [
            ".agents",
        ],
        "allowed_metadata_extensions": [
            ".md",
            ".json",
            ".jsonl",
            ".ndjson",
            ".yaml",
            ".yml",
            ".txt",
            ".log",
            ".csv",
            ".toml",
            ".xml",
            ".dot",
            ".svg",
            ".png",
            ".jpg",
            ".jpeg",
            ".gitkeep",
            ".gitignore",
        ],
        "prohibited_source_extensions": [
            ".py",
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".sh",
            ".ps1",
            ".bat",
            ".cmd",
            ".c",
            ".cpp",
            ".rs",
            ".go",
            ".java",
            ".sql",
            ".php",
            ".rb",
            ".cs",
            ".kt",
            ".kts",
            ".swift",
            ".dart",
            ".lua",
            ".r",
            ".m",
            ".zig",
            ".nim",
            ".scala",
            ".ex",
            ".exs",
            ".erl",
            ".clj",
        ],
    },
    "trajectory_guard": {
        "enabled": True,
        "high_step_warning_threshold": 35,
        "critical_step_threshold": 50,
        "consecutive_tool_loop_threshold": 3,
        "ping_pong_loop_threshold": 3,
        "repeated_call_alert_enabled": True,
        "inject_warning_on_loop": True,
        "inject_warning_on_critical_steps": True,
        "max_history_window": 20,
        "state_storage_dir": ".trajectory_guard",
        "state_file_name": "trajectory_state.json",
    },
    "pre_stop_audit": {
        "enabled": True,
        "enforce_fully_idle": True,
        "check_background_tasks": True,
        "check_git_cleanliness": True,
        "git_status_timeout_seconds": 10,
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
    },
    "auto_lint": {
        "enabled": True,
        "linter_binary": "ruff",
        "linter_args": ["check", "--fix", "--no-cache"],
        "supported_extensions": [".py", ".pyi"],
        "max_file_size_bytes": 5242880,
        "timeout_seconds": 15,
        "monitored_tools": [
            "write_to_file",
            "replace_file_content",
            "multi_replace_file_content",
        ],
        "target_arg_keys": [
            "TargetFile",
            "target_file",
            "path",
            "file_path",
            "filePath",
        ],
        "target_argument_keys": [
            "TargetFile",
            "target_file",
            "path",
            "file_path",
            "filePath",
        ],
        "block_windows_device_names": True,
        "block_system_directories": True,
        "respect_workspace_boundary": True,
    },
    "dangerous_commands": {
        "enabled": True,
        "git_hygiene": {
            "enabled": True,
            "decision": "deny",
            "reason_template": "Enterprise Git Hygiene Violation (§11): Prohibited '{description}'. You MUST run 'git status' first to inspect modified files and add specific files explicitly.",
            "patterns": [
                {
                    "pattern": r"\bgit(?:\.exe)?\s+(?:-[^\s]+\s+|--[^\s]+\s+)*add\s+(?:-[^\s]+\s+|--[^\s]+\s+)*(?:\.|\./|\*|\-A|\-\-(?:all|update)|\-u|:/|[\"'](?:\.|\./|\*|:/)[\"'])(\s+|$)",
                    "description": "Blanket git add staging (git add ., *, -A, --all)",
                },
            ],
        },
        "os_destruction": {
            "enabled": True,
            "decision": "force_ask",
            "reason_template": "Destructive Operation Guard (Accidental Data Loss Prevention, §3): Detected dangerous pattern '{description}'. Execution requires explicit user confirmation.",
            "patterns": [
                {
                    "pattern": r"\brm(?:\.exe)?\s+(?:-[^\s]+\s+|--[^\s]+\s+)*(?:-[a-zA-Z0-9]*[rR][a-zA-Z0-9]*|--recursive)\b(?:\s+-[^\s]+|\s+--[^\s]+)*\s+[\"']?(?:/|/\*|\*|~|[a-zA-Z]:(?:\\|/)?|[a-zA-Z]:/\*|\.\.|\.|\./)[\"']?(?=\s|$)",
                    "description": "Recursive directory deletion of critical path",
                },
                {
                    "pattern": r"\brm(?:\.exe)?\s+(?:-[^\s]+\s+|--[^\s]+\s+)*[\"']?(?:/|/\*|\*|~|[a-zA-Z]:(?:\\|/)?|[a-zA-Z]:/\*|\.\.|\.|\./)[\"']?(?:\s+-[^\s]+|\s+--[^\s]+)*(?:\s+-[a-zA-Z0-9]*[rR][a-zA-Z0-9]*|\s+--recursive)\b",
                    "description": "Recursive directory deletion of critical path",
                },
                {
                    "pattern": r"\b(?:rmdir|rd)(?:\.exe)?\s+(?:/[a-zA-Z0-9]+\s+)*(?:/[sS]\s+/[qQ]|/[qQ]\s+/[sS])\s+[\"']?(?:[a-zA-Z]:(?:\\|/)?|\\|/|\*|\.\.)[\"']?",
                    "description": "Windows destructive directory wipe (rmdir/rd)",
                },
                {
                    "pattern": r"\b(?:rmdir|rd)(?:\.exe)?\s+[\"']?(?:[a-zA-Z]:(?:\\|/)?|\\|/|\*|\.\.)[\"']?\s+(?:/[a-zA-Z0-9]+\s+)*(?:/[sS]\s+/[qQ]|/[qQ]\s+/[sS])",
                    "description": "Windows destructive directory wipe (rmdir/rd)",
                },
                {
                    "pattern": r"\b(?:rmdir|rd)(?:\.exe)?\s+(?:/[a-zA-Z0-9]+\s+)*(?:/[sS])\b",
                    "description": "Windows recursive directory wipe (rmdir/rd)",
                },
                {
                    "pattern": r"\b(?:del|erase)(?:\.exe)?\s+(?:/[a-zA-Z0-9]+\s+)*(?:/[fFsSqQ])\s+.*[\"']?(?:[a-zA-Z]:(?:\\|/|\*)?|\*|\.\.|/|\\)[\"']?",
                    "description": "Windows silent forced disk/directory wipe (del/erase)",
                },
                {
                    "pattern": r"\b(?:del|erase)(?:\.exe)?\s+[\"']?(?:[a-zA-Z]:(?:\\|/|\*)?|\*|\.\.|/|\\)[\"']?\s+(?:/[a-zA-Z0-9]+\s+)*(?:/[fFsSqQ])",
                    "description": "Windows silent forced disk/directory wipe (del/erase)",
                },
                {
                    "pattern": r"\b(?:Remove-Item|ri)\b(?=.*(?:-[a-zA-Z0-9]*r[a-zA-Z0-9]*|-recurse\b))(?=.*(?:-[a-zA-Z0-9]*f[a-zA-Z0-9]*|-force\b)).*[\"']?(?:[a-zA-Z]:(?:\\|/|\*)?|\\|/|\*|\.\.)[\"']?",
                    "description": "PowerShell destructive recursive deletion (Remove-Item)",
                },
                {
                    "pattern": r"\b(?:Remove-Item|ri)\b(?=.*(?:-[a-zA-Z0-9]*r[a-zA-Z0-9]*|-recurse\b)).*[\"']?(?:[a-zA-Z]:(?:\\|/|\*)?|\\|/|\*|\.\.)[\"']?",
                    "description": "PowerShell recursive directory wipe (Remove-Item)",
                },
                {
                    "pattern": r"\bformat(?:\.exe)?\s+(?:/[a-zA-Z0-9:]+\s+)*[\"']?[a-zA-Z]:",
                    "description": "Disk formatting command",
                },
                {
                    "pattern": r"\bdiskpart(?:\.exe)?\b",
                    "description": "Disk partition utility invocation",
                },
                {
                    "pattern": r"\bmkfs(?:\.[a-z0-9]+)?\b",
                    "description": "Filesystem creation/format utility",
                },
                {
                    "pattern": r"\bdd\b.*?\bof=(?:/dev/|\\\\\.?\\[a-zA-Z]:)",
                    "description": "Raw block device write via dd",
                },
                {
                    "pattern": r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
                    "description": "Fork bomb script pattern",
                },
                {
                    "pattern": r"\bchmod\b(?=.*(?:-[a-zA-Z0-9]*[rR][a-zA-Z0-9]*|--recursive))(?=.*\b777\b).*?\s+(?:/|/\*|\*|~)(?:\s|$)",
                    "description": "Unsafe global filesystem permission rewrite",
                },
                {
                    "pattern": r"\bchown\b(?=.*(?:-[a-zA-Z0-9]*[rR][a-zA-Z0-9]*|--recursive)).*?\s+(?:/|/\*|\*|~)(?:\s|$)",
                    "description": "Unsafe global root filesystem ownership rewrite",
                },
            ],
        },
        "db_destruction": {
            "enabled": True,
            "decision": "force_ask",
            "reason_template": "Destructive Database Guard (Accidental Data Loss Prevention, §3): Detected dangerous pattern '{description}'. Execution requires explicit user confirmation.",
            "patterns": [
                {
                    "pattern": r"\bDROP\s+DATABASE\b",
                    "description": "DROP DATABASE command",
                },
                {
                    "pattern": r"\bDROP\s+SCHEMA\b",
                    "description": "DROP SCHEMA command",
                },
                {
                    "pattern": r"\bDROP\s+TABLE\b",
                    "description": "DROP TABLE command",
                },
                {
                    "pattern": r"\bTRUNCATE(?:\s+TABLE)?\b",
                    "description": "TRUNCATE TABLE command",
                },
                {
                    "pattern": r"\bDELETE\s+FROM\s+(?:[a-zA-Z0-9_.]+|[\"\[`][^\"\]`]+[\"\]`])\s*(?:;|$|WHERE\s+(?:1\s*=\s*1|true|1|'1'\s*=\s*'1'|'a'\s*=\s*'a')\b)",
                    "description": "Unbounded table deletion without WHERE clause",
                },
                {
                    "pattern": r"\bDROP\s+EXTENSION\b",
                    "description": "DROP EXTENSION command",
                },
            ],
        },
        "cloud_destruction": {
            "enabled": True,
            "decision": "force_ask",
            "reason_template": "Destructive Operation Guard (Accidental Data Loss Prevention, §3): Detected dangerous pattern '{description}'. Execution requires explicit user confirmation.",
            "patterns": [
                {
                    "pattern": r"\bgcloud\s+projects\s+delete\b",
                    "description": "GCloud project deletion",
                },
                {
                    "pattern": r"\bgsutil\s+rm\s+-[rR]+\s+gs://",
                    "description": "Broad Cloud Storage bucket wipe",
                },
                {
                    "pattern": r"\bgcloud\s+storage\s+rm\b.*?(?:-[a-zA-Z0-9]*r|--recursive)\s+gs://",
                    "description": "Broad Cloud Storage bucket wipe",
                },
                {
                    "pattern": r"\baws\s+s3\s+(?:rm|rb)\s+s3://.*?(?:--recursive|--force)",
                    "description": "AWS S3 broad bucket or object wipe",
                },
                {
                    "pattern": r"\baz\s+group\s+delete\b",
                    "description": "Azure resource group deletion",
                },
            ],
        },
    },
    "format_check": {
        "enabled": True,
        "max_file_size_bytes": 10485760,
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
    },
    "diff_security": {
        "enabled": True,
        "protected_tables": [
            "users",
            "accounts",
            "orders",
            "contracts",
            "invoices",
            "tenants",
            "residents",
        ],
        "protected_models": [
            "User",
            "Account",
            "Order",
            "Contract",
            "Invoice",
            "Tenant",
            "Resident",
        ],
        "tenant_id_fields": [
            "tenant_id",
            "organization_id",
            "project_id",
            "ownership_id",
            "account_id",
            "property_id",
            "user_id",
        ],
        "protected_route_prefixes": [
            "/api/v1/protected",
            "/admin",
            "/api/v1/billing",
        ],
        "allowed_secret_substrings": [
            "your_secret",
            "your-secret",
            "your_api_key",
            "my_secret",
            "test_secret",
            "placeholder_key",
            "dummy_token",
            "<your_",
            "${env:",
            "process.env",
            "os.environ",
            "settings.",
            "config.",
        ],
        "block_on_critical": True,
        "git_diff_timeout_seconds": 10,
    },
}



def resolve_config_path(custom_path: pathlib.Path | str | None = None) -> pathlib.Path:
    """Resolve dynamic_limits.json location with prioritized fallback paths."""
    if custom_path:
        return pathlib.Path(custom_path).resolve()

    env_path = os.environ.get("DYNAMIC_LIMITS_CONFIG_PATH")
    if env_path:
        return pathlib.Path(env_path).resolve()

    # Relative to this file's parent package directory (enterprise-hooks root)
    candidate_parent = pathlib.Path(__file__).parent.parent / "dynamic_limits.json"
    if candidate_parent.exists():
        return candidate_parent.resolve()

    # User profile location
    candidate_home = pathlib.Path.home() / ".gemini" / "config" / "enterprise-hooks" / "dynamic_limits.json"
    if candidate_home.exists():
        return candidate_home.resolve()

    # Fallback default target path
    return candidate_parent.resolve()


class DynamicConfigLoader:
    """Hot-reloadable config manager tracking file modification time (mtime)."""

    def __init__(self, config_path: pathlib.Path | str | None = None) -> None:
        self.config_path: pathlib.Path = resolve_config_path(config_path)
        self._cached_config: dict[str, Any] | None = None
        self._last_mtime: float = -1.0
        self._lock = threading.Lock()

    def get_config(self, force_reload: bool = False) -> dict[str, Any]:
        """Return the current parsed config.

        Reloads from disk if mtime has changed or if forced.
        Latency is < 0.1ms on cache hits and <= 5ms on reload.
        """
        with self._lock:
            try:
                if not self.config_path.exists():
                    logger.debug("Config file %s does not exist, using fallback", self.config_path)
                    return copy.deepcopy(DEFAULT_DYNAMIC_LIMITS)

                current_mtime = self.config_path.stat().st_mtime
                if force_reload or self._cached_config is None or current_mtime != self._last_mtime:
                    try:
                        raw_text = self.config_path.read_text(encoding="utf-8")
                        parsed = json.loads(raw_text)
                        if isinstance(parsed, dict):
                            self._cached_config = parsed
                            self._last_mtime = current_mtime
                            logger.debug("Successfully loaded dynamic config from %s (mtime=%f)", self.config_path, current_mtime)
                        else:
                            logger.warning("Config root is not a dict: %s", type(parsed))
                            if self._cached_config is None:
                                self._cached_config = copy.deepcopy(DEFAULT_DYNAMIC_LIMITS)
                    except (json.JSONDecodeError, OSError) as load_err:
                        logger.error("Failed to parse config %s: %s", self.config_path, load_err)
                        if self._cached_config is None:
                            self._cached_config = copy.deepcopy(DEFAULT_DYNAMIC_LIMITS)

                return copy.deepcopy(self._cached_config)

            except Exception as exc:
                logger.error("Unexpected error in config loader: %s", exc)
                return copy.deepcopy(DEFAULT_DYNAMIC_LIMITS)

    def get_section(self, section_name: str, default: Any = None) -> Any:
        """Fetch a top-level section from dynamic configuration."""
        config = self.get_config()
        return config.get(section_name, default)

    def is_modified(self) -> bool:
        """Check if configuration file has been modified on disk."""
        try:
            if not self.config_path.exists():
                return False
            return self.config_path.stat().st_mtime != self._last_mtime
        except OSError:
            return False

    def reset_cache(self) -> None:
        """Invalidate cache for testing or reset purposes."""
        with self._lock:
            self._cached_config = None
            self._last_mtime = -1.0


# Global singleton instance
_GLOBAL_LOADER: DynamicConfigLoader | None = None
_GLOBAL_LOADER_LOCK = threading.Lock()


def get_config_loader(config_path: pathlib.Path | str | None = None) -> DynamicConfigLoader:
    """Obtain or initialize the global DynamicConfigLoader singleton."""
    global _GLOBAL_LOADER
    with _GLOBAL_LOADER_LOCK:
        if _GLOBAL_LOADER is None or (config_path and resolve_config_path(config_path) != _GLOBAL_LOADER.config_path):
            _GLOBAL_LOADER = DynamicConfigLoader(config_path)
        return _GLOBAL_LOADER


def get_dynamic_limits(config_path: pathlib.Path | str | None = None, force_reload: bool = False) -> dict[str, Any]:
    """Return current dynamic limits configuration."""
    loader = get_config_loader(config_path)
    return loader.get_config(force_reload=force_reload)


def get_hardware_profile(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve hardware_profile sub-dictionary."""
    limits = get_dynamic_limits(config_path)
    return limits.get("hardware_profile", DEFAULT_DYNAMIC_LIMITS["hardware_profile"])


def get_concurrency_rules(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve concurrency_rules sub-dictionary."""
    limits = get_dynamic_limits(config_path)
    return limits.get("concurrency_rules", DEFAULT_DYNAMIC_LIMITS["concurrency_rules"])


def get_execution_timeouts(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve execution_timeouts sub-dictionary."""
    limits = get_dynamic_limits(config_path)
    return limits.get("execution_timeouts", DEFAULT_DYNAMIC_LIMITS["execution_timeouts"])


def get_circuit_breaker_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve circuit_breaker sub-dictionary."""
    limits = get_dynamic_limits(config_path)
    return limits.get("circuit_breaker", DEFAULT_DYNAMIC_LIMITS["circuit_breaker"])


def get_audit_trail_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve audit_trail sub-dictionary."""
    limits = get_dynamic_limits(config_path)
    return limits.get("audit_trail", DEFAULT_DYNAMIC_LIMITS["audit_trail"])


def get_regression_detector_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve regression_detector sub-dictionary."""
    limits = get_dynamic_limits(config_path)
    return limits.get("regression_detector", DEFAULT_DYNAMIC_LIMITS["regression_detector"])


def get_context_compression_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve context_compression sub-dictionary."""
    limits = get_dynamic_limits(config_path)
    return limits.get("context_compression", DEFAULT_DYNAMIC_LIMITS["context_compression"])


def get_hallucination_guard_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve hallucination_guard sub-dictionary."""
    limits = get_dynamic_limits(config_path)
    return limits.get("hallucination_guard", DEFAULT_DYNAMIC_LIMITS["hallucination_guard"])


def get_token_budget_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve token_budget sub-dictionary."""
    limits = get_dynamic_limits(config_path)
    return limits.get("token_budget", DEFAULT_DYNAMIC_LIMITS["token_budget"])


def get_mcp_health_checker_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve mcp_health_checker sub-dictionary."""
    limits = get_dynamic_limits(config_path)
    return limits.get("mcp_health_checker", DEFAULT_DYNAMIC_LIMITS["mcp_health_checker"])


def get_self_healing_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve self_healing sub-dictionary."""
    limits = get_dynamic_limits(config_path)
    return limits.get("self_healing", DEFAULT_DYNAMIC_LIMITS["self_healing"])


def get_scope_boundary_rules(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve scope_boundary sub-dictionary with zero-config fallback."""
    limits = get_dynamic_limits(config_path)
    return limits.get("scope_boundary", DEFAULT_DYNAMIC_LIMITS["scope_boundary"])


def get_trajectory_guard_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve trajectory_guard sub-dictionary with zero-config fallback."""
    limits = get_dynamic_limits(config_path)
    return limits.get("trajectory_guard", DEFAULT_DYNAMIC_LIMITS["trajectory_guard"])


def get_pre_stop_audit_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve pre_stop_audit sub-dictionary with zero-config fallback."""
    limits = get_dynamic_limits(config_path)
    return limits.get("pre_stop_audit", DEFAULT_DYNAMIC_LIMITS["pre_stop_audit"])


def get_test_runner_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve test_runner sub-dictionary with zero-config fallback."""
    limits = get_dynamic_limits(config_path)
    default = DEFAULT_DYNAMIC_LIMITS.get("test_runner", {
        "timeout_seconds": 30,
        "max_summary_lines": 10,
        "max_output_chars": 1000,
        "excluded_filenames": ["__init__.py", "conftest.py", "setup.py", "fixtures.py"],
    })
    return limits.get("test_runner", default)


def get_session_compaction_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve session_compaction sub-dictionary with zero-config fallback."""
    limits = get_dynamic_limits(config_path)
    default = DEFAULT_DYNAMIC_LIMITS.get("session_compaction", {
        "enabled": True,
        "default_max_tokens": 1000000,
        "default_max_messages": 200,
        "summarization_threshold": 0.70,
        "compaction_threshold": 0.80,
        "target_capacity_ratio": 0.50,
        "min_messages_to_summarize": 10,
        "max_summary_preview_length": 200,
        "state_storage_dir": ".session_compactor",
        "model_context_windows": {
            "flash": 1048576,
            "pro": 2097152,
            "gemini-2.0-flash": 1048576,
            "gemini-2.5-flash": 1048576,
            "gemini-3.0-flash": 1048576,
            "gemini-3.8-flash": 1048576,
            "gemini-1.5-pro": 2097152,
            "gemini-2.5-pro": 2097152,
            "gemini-3.1-pro": 2097152,
            "default": 1000000,
        },
        "critical_keywords": [
            "error", "exception", "failed", "fatal", "critical",
            "important", "must", "required", "do not", "never",
            "decision", "conclusion", "final", "approved",
        ],
        "high_importance_keywords": [
            "result", "completed", "success", "implemented",
            "created", "modified", "updated", "changed",
            "answer", "response", "output",
        ],
        "low_importance_keywords": [
            "ok", "okay", "sure", "yes", "no", "thanks",
            "please", "help", "what about", "maybe",
        ],
    })
    return limits.get("session_compaction", default)


def get_auto_lint_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve auto_lint sub-dictionary with zero-config fallback."""
    limits = get_dynamic_limits(config_path)
    return limits.get("auto_lint", DEFAULT_DYNAMIC_LIMITS["auto_lint"])


def get_dangerous_command_rules(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve dangerous_commands sub-dictionary with zero-config fallback."""
    limits = get_dynamic_limits(config_path)
    return limits.get("dangerous_commands", DEFAULT_DYNAMIC_LIMITS["dangerous_commands"])


def get_format_check_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve format_check sub-dictionary with zero-config fallback."""
    limits = get_dynamic_limits(config_path)
    return limits.get("format_check", DEFAULT_DYNAMIC_LIMITS["format_check"])


def get_diff_security_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Retrieve diff_security sub-dictionary with zero-config fallback."""
    limits = get_dynamic_limits(config_path)
    return limits.get("diff_security", DEFAULT_DYNAMIC_LIMITS["diff_security"])


def reload_if_modified(config_path: pathlib.Path | str | None = None) -> tuple[dict[str, Any], bool]:
    """Reload configuration if modified, returning (config, was_reloaded)."""
    loader = get_config_loader(config_path)
    modified = loader.is_modified()
    config = loader.get_config(force_reload=modified)
    return config, modified
