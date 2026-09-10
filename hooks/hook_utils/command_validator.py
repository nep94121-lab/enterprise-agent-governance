#!/usr/bin/env python3
"""Enterprise Hook Utilities - Command Safety Validator.

Universal Multi-Agent Governance System - Physical Runtime Layer 1 Guardrail.
Protects against OS destruction, database destruction, blanket Git staging,
and cloud infrastructure wipeout.
Eliminates 100% hardcoding by sourcing rules and patterns dynamically from
DynamicConfigLoader (dynamic_limits.json) with Zero-Config Resilience.
"""

from __future__ import annotations

import io
import logging
import re
import shlex
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

from .config_loader import get_dangerous_command_rules

logger = logging.getLogger("enterprise_hooks.command_validator")

# SQL block comment and line comment stripper
SQL_BLOCK_COMMENT_REGEX = re.compile(r"/\*[\s\S]*?\*/")
SQL_LINE_COMMENT_REGEX = re.compile(r"--[^\r\n]*(?:\r?\n|$)")

# Command chaining split regex (splits on &&, ||, ;, and | while respecting quotes)
CHAINING_OPERATOR_REGEX = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")


def strip_sql_comments(query: str) -> str:
    """Normalize SQL by stripping block and line comments and collapsing whitespace."""
    no_block = SQL_BLOCK_COMMENT_REGEX.sub(" ", query)
    no_line = SQL_LINE_COMMENT_REGEX.sub(" ", no_block)
    return " ".join(no_line.split())


def split_command_segments(command_line: str) -> list[str]:
    """Extract individual command segments from compound chained commands."""
    if not command_line or not command_line.strip():
        return []

    # Fast check: if no chaining operator present, return single segment
    if not any(op in command_line for op in ("&&", "||", ";", "|")):
        return [command_line.strip()]

    # Use shlex to accurately split by operators while preserving quotes
    try:
        lexer = shlex.shlex(command_line, posix=False)
        lexer.whitespace_split = False
        lexer.commenters = ""
        tokens = list(lexer)

        segments: list[str] = []
        current: list[str] = []
        skip_ops = {"&&", "||", ";", "|", "&"}

        for token in tokens:
            if token in skip_ops:
                if current:
                    segments.append("".join(current).strip())
                    current = []
            else:
                current.append(token + " ")

        if current:
            segments.append("".join(current).strip())

        return [seg for seg in segments if seg]
    except Exception:
        # Fallback to regex split if shlex fails on Windows-specific escapes
        raw_parts = CHAINING_OPERATOR_REGEX.split(command_line)
        return [p.strip() for p in raw_parts if p.strip()]


class CommandSafetyValidator:
    """Dynamic Command Safety Validator engine for Enterprise Hooks."""

    _instance: CommandSafetyValidator | None = None

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config_override = config
        self._pattern_cache: dict[str, re.Pattern] = {}

    @classmethod
    def get_instance(cls) -> CommandSafetyValidator:
        """Singleton accessor."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _get_rules(self) -> dict[str, Any]:
        """Fetch rules from dynamic config loader or injected override."""
        if self._config_override is not None:
            return self._config_override
        return get_dangerous_command_rules()

    def _get_compiled_regex(self, pattern_str: str) -> re.Pattern:
        """Cache compiled regexes to eliminate repeated compilation overhead."""
        if pattern_str not in self._pattern_cache:
            self._pattern_cache[pattern_str] = re.compile(pattern_str, re.IGNORECASE)
        return self._pattern_cache[pattern_str]

    def evaluate_command_string(self, command_line: str) -> tuple[str, str]:
        """Evaluate a raw command line string.

        Returns:
            tuple of (decision, reason) where decision is 'allow', 'deny', or 'force_ask'.
        """
        if not isinstance(command_line, str) or not command_line.strip():
            return "allow", "Empty CommandLine argument."

        rules = self._get_rules()
        if not rules.get("enabled", True):
            return "allow", "Dangerous command guard is disabled via dynamic configuration."

        segments = split_command_segments(command_line)
        # Check both the full command line and each segment
        evaluation_targets = [command_line] + segments

        # 1. Check Git Hygiene (§11 - Blanket staging prohibited) -> Deny
        git_config = rules.get("git_hygiene", {})
        if git_config.get("enabled", True):
            decision = git_config.get("decision", "deny")
            template = git_config.get(
                "reason_template",
                "Enterprise Git Hygiene Violation (§11): Prohibited '{description}'. "
                "You MUST run 'git status' first to inspect modified files and add specific files explicitly.",
            )
            for item in git_config.get("patterns", []):
                pattern_str = item.get("pattern", "")
                desc = item.get("description", "Prohibited git operation")
                if not pattern_str:
                    continue
                rx = self._get_compiled_regex(pattern_str)
                for target in evaluation_targets:
                    if rx.search(target):
                        reason = template.format(description=desc)
                        logger.warning("Git hygiene violation detected (%s): %s", desc, command_line)
                        return decision, reason

        # 2. Check Cloud Destruction Patterns -> Force Ask
        cloud_config = rules.get("cloud_destruction", {})
        if cloud_config.get("enabled", True):
            decision = cloud_config.get("decision", "force_ask")
            template = cloud_config.get(
                "reason_template",
                "Destructive Operation Guard (Accidental Data Loss Prevention, §3): "
                "Detected dangerous pattern '{description}'. Execution requires explicit user confirmation.",
            )
            for item in cloud_config.get("patterns", []):
                pattern_str = item.get("pattern", "")
                desc = item.get("description", "Cloud infrastructure destruction")
                if not pattern_str:
                    continue
                rx = self._get_compiled_regex(pattern_str)
                for target in evaluation_targets:
                    if rx.search(target):
                        reason = template.format(description=desc)
                        logger.warning("Cloud destruction pattern detected (%s): %s", desc, command_line)
                        return decision, reason

        # 3. Check DB Destruction Patterns -> Force Ask
        db_config = rules.get("db_destruction", {})
        if db_config.get("enabled", True):
            decision = db_config.get("decision", "force_ask")
            template = db_config.get(
                "reason_template",
                "Destructive Database Guard (Accidental Data Loss Prevention, §3): "
                "Detected dangerous pattern '{description}'. Execution requires explicit user confirmation.",
            )
            # Create comment-normalized variations for SQL evaluation
            normalized_targets = evaluation_targets + [strip_sql_comments(t) for t in evaluation_targets]
            for item in db_config.get("patterns", []):
                pattern_str = item.get("pattern", "")
                desc = item.get("description", "Destructive database command")
                if not pattern_str:
                    continue
                rx = self._get_compiled_regex(pattern_str)
                for target in normalized_targets:
                    if rx.search(target):
                        reason = template.format(description=desc)
                        logger.warning("Database destruction pattern detected (%s): %s", desc, command_line)
                        return decision, reason

        # 4. Check OS Destruction Patterns -> Force Ask
        os_config = rules.get("os_destruction", {})
        if os_config.get("enabled", True):
            decision = os_config.get("decision", "force_ask")
            template = os_config.get(
                "reason_template",
                "Destructive Operation Guard (Accidental Data Loss Prevention, §3): "
                "Detected dangerous pattern '{description}'. Execution requires explicit user confirmation.",
            )
            for item in os_config.get("patterns", []):
                pattern_str = item.get("pattern", "")
                desc = item.get("description", "Destructive OS command")
                if not pattern_str:
                    continue
                rx = self._get_compiled_regex(pattern_str)
                for target in evaluation_targets:
                    if rx.search(target):
                        reason = template.format(description=desc)
                        logger.warning("OS destruction pattern detected (%s): %s", desc, command_line)
                        return decision, reason

        return "allow", "Command passed dangerous pattern security scan."

    def evaluate_tool_call(self, tool_name: str, args: dict[str, Any] | None) -> tuple[str, str]:
        """Evaluate a toolCall structure."""
        if tool_name != "run_command":
            return "allow", "Tool is not run_command."

        if not isinstance(args, dict):
            return "allow", "Arguments is not a valid dict."

        command_line = args.get("CommandLine", "")
        return self.evaluate_command_string(command_line)

    def evaluate_payload(self, payload: dict[str, Any]) -> tuple[str, str]:
        """Evaluate a standard PreToolUse hook payload."""
        if not isinstance(payload, dict):
            return "allow", "Payload is not a dict."

        tool_call = payload.get("toolCall")
        if not isinstance(tool_call, dict):
            return "allow", "toolCall is not a dict or is None."

        tool_name = tool_call.get("name", "")
        args = tool_call.get("args")
        return self.evaluate_tool_call(tool_name, args)

    def run_self_test(self) -> bool:
        """Run built-in verification suite testing all categories and P0 bypasses."""
        test_cases: list[tuple[str, str, str]] = [
            # Safe commands
            ("Safe pytest", "pytest tests/test_hooks.py -v", "allow"),
            ("Safe build", "npm run build", "allow"),
            ("Safe git status", "git status", "allow"),
            ("Safe selective SQL", "python -c \"db.execute('DELETE FROM users WHERE id = 123')\"", "allow"),
            ("Safe selective SQL 2", "DELETE FROM logs WHERE created_at < '2020-01-01';", "allow"),
            # Git hygiene violations (§11)
            ("Git add dot", "git add .", "deny"),
            ("Git add all", "git add --all", "deny"),
            ("Git add star", "git add *", "deny"),
            ("Git add root bypass", "git add :/", "deny"),
            ("Git add update", "git add -u", "deny"),
            ("Git add quoted dot", "git add '.'", "deny"),
            # Destructive rm variants (flags before, after, quoted, long flags)
            ("rm -rf root", "rm -rf /", "force_ask"),
            ("rm -rf star", "rm -rf *", "force_ask"),
            ("rm -rf home", "rm -rf ~", "force_ask"),
            ("rm -rf parent", "rm -rf ..", "force_ask"),
            ("rm -rf drive", "rm -rf C:\\", "force_ask"),
            ("rm -rf drive wild", "rm -rf C:/*", "force_ask"),
            ("rm -r -f root", "rm -r -f /", "force_ask"),
            ("rm --recursive --force root", "rm --recursive --force /", "force_ask"),
            ("rm target before flags (P0)", "rm / -rf", "force_ask"),
            ("rm target before flags star (P0)", "rm * -rf", "force_ask"),
            ("rm quoted path (P0)", 'rm -rf "/"', "force_ask"),
            ("rm quoted drive (P0)", 'rm -rf "C:\\"', "force_ask"),
            ("rm no-preserve-root", "rm --no-preserve-root -rf /", "force_ask"),
            # Windows CMD destructive commands
            ("rmdir flags first", "rmdir /s /q C:\\", "force_ask"),
            ("rd flags first", "rd /s /q C:\\", "force_ask"),
            ("rd target first (P0)", "rd C:\\ /s /q", "force_ask"),
            ("rd quoted target (P0)", 'rd "C:\\" /s /q', "force_ask"),
            ("del /f /s /q", "del /f /s /q C:\\*", "force_ask"),
            ("erase /f /s /q", "erase /f /s /q C:\\", "force_ask"),
            # PowerShell Remove-Item variants
            ("Remove-Item flags first", "Remove-Item -Recurse -Force C:\\", "force_ask"),
            ("Remove-Item target first (P0)", "Remove-Item C:\\ -Recurse -Force", "force_ask"),
            ("Remove-Item quoted target (P0)", 'Remove-Item "C:\\" -Recurse -Force', "force_ask"),
            ("ri alias target first (P0)", "ri C:\\ -Recurse -Force", "force_ask"),
            ("Remove-Item -Path param (P0)", "Remove-Item -Path C:\\ -Recurse -Force", "force_ask"),
            # Disk utilities
            ("format C:", "format C:", "force_ask"),
            ("format with flags first (P0)", "format /FS:NTFS C:", "force_ask"),
            ("diskpart", "diskpart /s script.txt", "force_ask"),
            ("mkfs", "mkfs.ext4 /dev/sda1", "force_ask"),
            ("dd if before of", "dd if=/dev/zero of=/dev/sda", "force_ask"),
            ("dd of before if (P0)", "dd of=/dev/sda if=/dev/zero", "force_ask"),
            ("fork bomb", ":(){ :|:& };:", "force_ask"),
            ("chmod recursive root", "chmod -R 777 /", "force_ask"),
            ("chmod flags after perms (P0)", "chmod 777 -R /", "force_ask"),
            ("chown recursive root", "chown -R root /", "force_ask"),
            # Database destruction & comment obfuscation
            ("DROP DATABASE", "DROP DATABASE enterprise_db;", "force_ask"),
            ("DROP SCHEMA", "DROP SCHEMA public CASCADE;", "force_ask"),
            ("DROP TABLE", "DROP TABLE users;", "force_ask"),
            ("TRUNCATE TABLE", "TRUNCATE TABLE contracts;", "force_ask"),
            ("Unbounded DELETE", "DELETE FROM users;", "force_ask"),
            ("DELETE WHERE 1=1", "DELETE FROM users WHERE 1=1;", "force_ask"),
            ("DELETE WHERE 1 = 1", "DELETE FROM users WHERE 1 = 1;", "force_ask"),
            ("DELETE WHERE true (P0)", "DELETE FROM users WHERE true;", "force_ask"),
            ("DELETE quoted table (P0)", 'DELETE FROM "users";', "force_ask"),
            ("DROP/**/TABLE obfuscation", "DROP/**/TABLE payments;", "force_ask"),
            ("DROP/*comment*/SCHEMA obfuscation", "DROP/*comment*/SCHEMA audit;", "force_ask"),
            ("DROP --line comment (P0)", "DROP --comment\nTABLE users;", "force_ask"),
            # Cloud destruction
            ("gcloud projects delete", "gcloud projects delete enterprise-prod", "force_ask"),
            ("gsutil rm -r", "gsutil rm -r gs://enterprise-backups", "force_ask"),
            ("gcloud storage rm -r (P0)", "gcloud storage rm -r gs://enterprise-backups", "force_ask"),
            ("aws s3 rm --recursive", "aws s3 rm s3://enterprise-backups --recursive", "force_ask"),
            # Chained commands (P0)
            ("Chained command safe && dangerous", "echo ok && rm -rf /", "force_ask"),
            ("Chained command safe ; git add .", "make build ; git add .", "deny"),
        ]

        passed = 0
        total = len(test_cases)
        for name, cmd, expected in test_cases:
            decision, reason = self.evaluate_command_string(cmd)
            if decision == expected:
                passed += 1
            else:
                sys.stderr.write(f"FAIL: {name} (Cmd: {cmd}) -> Expected {expected}, got {decision} ({reason})\n")

        success = (passed == total)
        sys.stderr.write(f"\n[SELF-TEST] CommandSafetyValidator: {passed}/{total} passed (Success={success})\n")
        return success


def evaluate_command_safety(command_line: str, config: dict[str, Any] | None = None) -> tuple[str, str]:
    """Convenience functional interface."""
    validator = CommandSafetyValidator(config)
    return validator.evaluate_command_string(command_line)


def get_command_validator() -> CommandSafetyValidator:
    """Convenience singleton getter."""
    return CommandSafetyValidator.get_instance()
