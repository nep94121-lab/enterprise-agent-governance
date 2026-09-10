#!/usr/bin/env python3
"""Static Diff & Security Inspector Hook (Layer 2) for Enterprise Multi-Agent Governance System.

Inspects git diffs, file modifications, and tool call inputs to detect 6 critical
enterprise security violation categories:
1. Secrets, API Keys, JWT Tokens, Private Keys, Passwords, and raw PII (§1, §2).
2. Raw SQL injection, f-string SQL, string formatting in queries (§3).
3. IDOR vulnerabilities and missing multi-tenant ownership filters (§1, §24).
4. Supabase RLS bypass, client-side service_role, wildcard CORS with credentials (§4, §5).
5. Command injection via shell=True, os.system, or dangerous subprocesses (§3).
6. Missing authorization context, implicit None-user assignments in endpoints (§2, §26).

Zero Hardcoding Architecture:
- Dynamically integrates with hook_utils/config_loader and GovernanceConfig.
- Resolves all tables, models, tenant fields, route prefixes, and secret substrings at runtime.
- Eliminates ReDoS / catastrophic backtracking and truncated regex patterns.
- Tolerates nested parentheses, multi-line arguments, and dynamic model/table bindings.

Supports:
- PreToolUse: Gating git commit/push and file write operations (returns decision allow/deny).
- PostToolUse: Post-modification security scanning (returns strictly {} on stdout, logs diagnostics to stderr).
- CLI Standalone: Supports --diff, --file, --text, and stdin for independent audits and CI pipelines.
"""

from __future__ import annotations

import argparse
import copy
import io
import os
import pathlib
import re
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

# Ensure local hook scripts and hook_utils packages are importable
_HOOKS_DIR = pathlib.Path(__file__).parent.resolve()
_REPO_ROOT = _HOOKS_DIR.parent.resolve()
for _p in [str(_HOOKS_DIR), str(_REPO_ROOT)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from common_hook_lib import (  # noqa: E402
    emit_stdout_json,
    get_tool_args,
    get_tool_call,
    log_diagnostic,
    post_tool_response,
    pre_tool_response,
    read_stdin_payload,
)

# Safe imports for GovernanceConfig and hook_utils
try:
    from hook_utils.config_loader import get_diff_security_config, get_dynamic_limits  # noqa: E402
except ImportError:
    get_diff_security_config = None
    get_dynamic_limits = None

try:
    from config_loader import get_governance_config  # noqa: E402
except ImportError:
    get_governance_config = None


# ============================================================================
# 1. DYNAMIC ZERO-HARDCODE CONFIGURATION ENGINE
# ============================================================================

STANDARD_TENANT_FIELDS: list[str] = [
    "tenant_id",
    "organization_id",
    "project_id",
    "ownership_id",
    "account_id",
    "property_id",
    "user_id",
]

DEFAULT_SECURITY_CONFIG: dict[str, Any] = {
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
    "tenant_id_fields": list(STANDARD_TENANT_FIELDS),
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
}


def load_active_security_config(config_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    """Dynamically resolve security configuration with prioritized fail-safe fallbacks.

    Priority hierarchy:
    1. Environment Variable Overrides (Highest Precedence)
    2. GovernanceConfig via config_loader (project-hooks.yaml / governance.config.json)
    3. hook_utils/config_loader (dynamic_limits.json)
    4. DEFAULT_SECURITY_CONFIG (Zero-Config Resilience)
    """
    resolved: dict[str, Any] = copy.deepcopy(DEFAULT_SECURITY_CONFIG)

    # 1. Load from hook_utils.config_loader if available
    if get_diff_security_config is not None:
        try:
            hook_utils_cfg = get_diff_security_config(config_path)
            if isinstance(hook_utils_cfg, dict):
                for key, val in hook_utils_cfg.items():
                    if val is not None:
                        resolved[key] = copy.deepcopy(val)
        except Exception as exc:
            log_diagnostic(f"Failed loading security config from hook_utils: {exc}")

    # 2. Load from GovernanceConfig if available
    if get_governance_config is not None:
        try:
            gov_cfg = get_governance_config(config_path)
            if gov_cfg is not None:
                # Tables
                sec_obj = getattr(gov_cfg, "security", None)
                mt_obj = getattr(sec_obj, "multi_tenant", None) if sec_obj else None
                tables = getattr(mt_obj, "protected_tables", None) or getattr(gov_cfg, "protected_tables", None)
                if tables:
                    resolved["protected_tables"] = list(tables)

                # Models
                models = getattr(mt_obj, "protected_models", None) or getattr(gov_cfg, "protected_models", None)
                if models:
                    resolved["protected_models"] = list(models)

                # Tenant ID fields: union with standard tenant fields so user_id/property_id aren't dropped
                fields = getattr(mt_obj, "tenant_id_fields", None) or getattr(gov_cfg, "tenant_id_fields", None)
                if fields:
                    merged_fields = list(dict.fromkeys(list(fields) + STANDARD_TENANT_FIELDS))
                    resolved["tenant_id_fields"] = merged_fields

                # Protected routes
                routes = getattr(mt_obj, "protected_route_prefixes", None) or getattr(gov_cfg, "protected_route_prefixes", None)
                if routes:
                    resolved["protected_route_prefixes"] = list(routes)

                # Allowed secret placeholders
                sc_obj = getattr(sec_obj, "secrets_scanner", None) if sec_obj else None
                subs = getattr(sc_obj, "allowed_substrings", None)
                if subs:
                    merged_subs = list(dict.fromkeys(resolved.get("allowed_secret_substrings", []) + list(subs)))
                    resolved["allowed_secret_substrings"] = merged_subs
        except Exception as exc:
            log_diagnostic(f"Failed loading security config from GovernanceConfig: {exc}")

    # 3. Environment Variable Overrides
    def _parse_env_list(env_var: str) -> list[str] | None:
        raw = os.environ.get(env_var)
        if raw:
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            if parts:
                return parts
        return None

    env_tables = _parse_env_list("PROTECTED_TABLES")
    if env_tables:
        resolved["protected_tables"] = env_tables

    env_models = _parse_env_list("PROTECTED_MODELS")
    if env_models:
        resolved["protected_models"] = env_models

    env_fields = _parse_env_list("TENANT_ID_FIELDS")
    if env_fields:
        resolved["tenant_id_fields"] = env_fields

    env_routes = _parse_env_list("PROTECTED_ROUTE_PREFIXES")
    if env_routes:
        resolved["protected_route_prefixes"] = env_routes

    env_subs = _parse_env_list("ALLOWED_SECRET_SUBSTRINGS")
    if env_subs:
        resolved["allowed_secret_substrings"] = env_subs

    return resolved


def get_protected_tables_list() -> list[str]:
    """Retrieve protected tables dynamically without hardcoding."""
    return list(load_active_security_config().get("protected_tables", []))


def get_protected_models_list() -> list[str]:
    """Retrieve protected ORM models dynamically without hardcoding."""
    return list(load_active_security_config().get("protected_models", []))


def get_tenant_id_fields_list() -> list[str]:
    """Retrieve tenant identifier fields dynamically without hardcoding."""
    return list(load_active_security_config().get("tenant_id_fields", []))


def get_protected_route_prefixes_list() -> list[str]:
    """Retrieve protected API route prefixes dynamically without hardcoding."""
    return list(load_active_security_config().get("protected_route_prefixes", []))


def get_allowed_secret_substrings_list() -> list[str]:
    """Retrieve allowed secret substrings dynamically without hardcoding."""
    return list(load_active_security_config().get("allowed_secret_substrings", []))


def build_tables_pattern(tables: list[str]) -> str:
    escaped = [re.escape(t) for t in tables if t]
    return rf"(?:{'|'.join(escaped)})" if escaped else r"(?:users|accounts|orders|contracts|invoices|tenants|residents)"


def build_models_pattern(models: list[str]) -> str:
    escaped = [re.escape(m) for m in models if m]
    return rf"(?:{'|'.join(escaped)})" if escaped else r"(?:User|Account|Order|Contract|Invoice|Tenant|Resident)"


def build_tenant_filter_regex(fields: list[str]) -> re.Pattern:
    all_fields = list(dict.fromkeys(fields + STANDARD_TENANT_FIELDS))
    escaped = [re.escape(f) for f in all_fields if f]
    sub = r"\b(?:" + "|".join(escaped) + r")\b|WHERE\s+1=0"
    return re.compile(sub, re.IGNORECASE)


def build_routes_regex(prefixes: list[str]) -> str:
    escaped: list[str] = []
    for p in prefixes:
        cleaned = p.lstrip("/").strip()
        if cleaned:
            escaped.append(re.escape(cleaned))
    return rf"(?:{'|'.join(escaped)})" if escaped else r"(?:api\/v1\/protected|admin|api\/v1\/billing)"


# ============================================================================
# 2. SECURITY RULES PATTERNS & REGEX DEFINITIONS (6 CATEGORIES)
# ============================================================================

# Category 1: Secrets, Tokens, Keys, and PII
SECRETS_PATTERNS: list[tuple[str, str, str]] = [
    (
        r"\bAKIA[0-9A-Z]{16}\b",
        "AWS Access Key ID",
        "Hardcoded AWS Access Key ID detected. Use environment variables or secrets manager (§2).",
    ),
    (
        r"\bghp_[0-9a-zA-Z]{36}\b|\bgithub_pat_[0-9a-zA-Z_]{82}\b",
        "GitHub Personal Access Token",
        "Hardcoded GitHub token detected. Store tokens securely in .env (§2).",
    ),
    (
        r"\beyJhbGciOi[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b",
        "Hardcoded JWT Token / API Key",
        "Hardcoded JWT token or API key detected. Avoid checking tokens into source code (§2).",
    ),
    (
        r"\bsbp_[0-9a-f]{40}\b",
        "Supabase Management Token",
        "Hardcoded Supabase personal access token detected (§2).",
    ),
    (
        r"-----BEGIN (?:[A-Z0-9_\-]+\s+)*KEY-----",
        "Private Cryptographic Key",
        "Embedded private key detected. Private keys must never be stored in source code (§2).",
    ),
    (
        r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b",
        "Slack API Token",
        "Hardcoded Slack API token detected (§2).",
    ),
    (
        r"\b[a-zA-Z0-9_]*(?:password|passwd|secret|api_key|apikey|access_token|auth_token|client_secret)\s*[:=]\s*[\"'][a-zA-Z0-9_\-!@#$%^&*()+=]{8,}[\"']",
        "Hardcoded Password or Secret Assignment",
        "Direct assignment of hardcoded credential or secret. Use pydantic-settings and .env (§2).",
    ),
    (
        r"data:image\/(?:png|jpeg|jpg);base64,[a-zA-Z0-9+/=]{100,}|raw_signature_base64\s*[:=]\s*[\"'][a-zA-Z0-9+/=]{100,}[\"']",
        "Raw Base64 Biometric / PII Data",
        "Raw base64 signature, biometric, or image data in code/logs (§1 PII Protection).",
    ),
]

# Category 2: Raw SQL Injection & String Formatting
# Robust against nested f-string quotes, prefix variants (rf, fr, F), and string concatenations
SQLI_PATTERNS_LINE: list[tuple[str, str, str]] = [
    (
        r"[rR]?[fF][\"'][^\"']*\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DELETE|DROP|ALTER)\b|(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DELETE|DROP|ALTER)\b[^;\n]*[rR]?[fF][\"']",
        "f-string SQL Injection",
        "Unsafe f-string in SQL statement. Use parameterized queries or ORM expressions (§3).",
    ),
    (
        r"(?:execute|query|raw|exec_sql|execute_query)\s*\(\s*[rR]?[fF][\"']",
        "f-string in Database Execute Call",
        "Calling db.execute/query with f-string query is vulnerable to SQL injection (§3).",
    ),
    (
        r"(?:SELECT|INSERT|UPDATE|DELETE)\s+[^;\n]*(?:%[sdiufeoxX]|%\([a-zA-Z0-9_]+\)[sdiufeoxX]|\.format\()",
        "String Formatting in SQL Statement",
        "Using % formatting or .format() in SQL query. Use parameterized query arguments (§3).",
    ),
    (
        r"(?:execute|query|raw|exec_sql|execute_query)\s*\(\s*(?:\"(?:\\.|[^\"\\])*\b(?:SELECT|INSERT|UPDATE|DELETE)\b(?:\\.|[^\"\\])*\"|'(?:\\.|[^\'\\])*\b(?:SELECT|INSERT|UPDATE|DELETE)\b(?:\\.|[^\'\\])*')\s*\+\s*[a-zA-Z0-9_]",
        "String Concatenation in SQL Execute",
        "Concatenating raw variables into SQL query string. Use parameterized query binding (§3).",
    ),
]

SQLI_PATTERNS_BLOCK: list[tuple[str, str, str]] = [
    (
        r"[rR]?[fF](?:\"\"\"|''')(?:(?!\"\"\"|''')[\s\S])*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b(?:(?!\"\"\"|''')[\s\S])*(?:\"\"\"|''')",
        "Multiline f-string SQL Injection",
        "Unsafe multiline f-string in SQL statement. Use parameterized queries or ORM expressions (§3).",
    ),
    (
        r"(?:execute|query|raw|exec_sql|execute_query)\s*\(\s*[rR]?[fF](?:\"\"\"|''')",
        "Multiline f-string in Database Execute Call",
        "Calling db.execute/query with multiline f-string is vulnerable to SQL injection (§3).",
    ),
    (
        r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b(?:(?!;|\n\s*\n)[\s\S])*?(?:%[sdiufeoxX]|%\([a-zA-Z0-9_]+\)[sdiufeoxX]|\.format\()",
        "Multiline String Formatting in SQL Statement",
        "Using % formatting or .format() in SQL query. Use parameterized query arguments (§3).",
    ),
]

SQLI_PATTERNS = SQLI_PATTERNS_LINE + SQLI_PATTERNS_BLOCK

# Dynamic pattern placeholders (evaluated per scan for zero-hardcode resilience)
IDOR_PATTERNS: list[tuple[str, str, str]] = [
    (
        r"(?:SELECT|FROM|UPDATE|DELETE\s+FROM)\s+.*(?!.*(?:tenant_id|property_id|user_id|ownership_id|WHERE\s+1=0))",
        "Missing Multi-Tenant Filter in SQL",
        "Querying multi-tenant protected table without tenant_id, property_id, or ownership_id filter (§1, §24 IDOR Defense).",
    ),
    (
        r"(?:db|session|s)\.query\(.*\)(?!.*\.filter\(.*(?:tenant_id|property_id|user_id|ownership_id))",
        "Missing Tenant Filter in ORM Query",
        "ORM query on protected model without tenant/property boundary filter (§1, §24).",
    ),
]

# Category 4: Bypass RLS, Client-Side service_role, and Insecure CORS
# Eliminates regex cụt: safe against nested parens, no catastrophic backtracking
RLS_CORS_PATTERNS: list[tuple[str, str, str]] = [
    (
        r"(?:allow_origins|allowOrigins)\s*[:=]\s*\[\s*[\"']\*[\"']\s*\].*?(?:allow_credentials|allowCredentials)\s*[:=]\s*(?:True|true)|(?:allow_credentials|allowCredentials)\s*[:=]\s*(?:True|true).*?(?:allow_origins|allowOrigins)\s*[:=]\s*\[\s*[\"']\*[\"']\s*\]",
        "Insecure Wildcard CORS with Credentials",
        "allow_origins=['*'] combined with allow_credentials=True creates critical CORS vulnerability (§4).",
    ),
    (
        r"(?:createClient|SupabaseClient)\s*\([^;]{0,300}?(?:service_role|SUPABASE_SERVICE_ROLE_KEY)",
        "Client-Side Supabase service_role Usage",
        "Using Supabase service_role key in frontend/client-side bypasses Row Level Security (§1, §2).",
    ),
    (
        r"ALTER\s+TABLE\s+[^;\n]+\s+(?:DISABLE\s+ROW\s+LEVEL\s+SECURITY|NO\s+FORCE\s+ROW\s+LEVEL\s+SECURITY)",
        "Disabling Row Level Security (RLS)",
        "Disabling RLS on database tables is strictly prohibited in multi-tenant architecture (§1, §24).",
    ),
    (
        r"\bBYPASS\s+RLS\b",
        "Explicit RLS Bypass Directive",
        "Bypassing Row Level Security is prohibited outside isolated system migrations (§24).",
    ),
]

# Category 5: Command Injection & shell=True
# Linear time complexity: uses [^;]{0,300}? to prevent ReDoS while catching multiline & nested parens
COMMAND_INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    (
        r"subprocess\.(?:Popen|run|call|check_call|check_output)\s*\([^;]{0,300}?\bshell\s*=\s*(?:True|1)\b",
        "Subprocess Invocation with shell=True",
        "Using shell=True in subprocess calls exposes the system to command injection (§3).",
    ),
    (
        r"\bos\.system\s*\(",
        "Unsafe os.system Call",
        "os.system is deprecated and unsafe. Use subprocess.run with arguments list and shell=False (§3).",
    ),
    (
        r"\bos\.popen\s*\(",
        "Unsafe os.popen Call",
        "os.popen is unsafe against command injection. Use subprocess.run (§3).",
    ),
]

# Dynamic Auth Context Patterns placeholder
AUTH_CONTEXT_PATTERNS: list[tuple[str, str, str]] = [
    (
        r"(?:user_id|tenant_id|property_id|organization_id|ownership_id)\s*=\s*None\s*(?:#.*)?\n\s*(?:return|pass|continue|db\.|session\.)",
        "Implicit Null Auth Assignment",
        "Implicitly assigning None to user/tenant ID without returning 401/403 creates auth bypass (§2, §26).",
    ),
]

# Legacy placeholder export for backward compatibility
ALLOWED_SECRET_SUBSTRINGS = set(DEFAULT_SECURITY_CONFIG["allowed_secret_substrings"])


# ============================================================================
# 3. CORE INSPECTION ENGINE
# ============================================================================

class SecurityViolation:
    """Represents a single security violation detected during diff inspection."""

    def __init__(
        self,
        category: str,
        rule_name: str,
        description: str,
        line_number: int | None = None,
        snippet: str = "",
        file_path: str = "",
    ) -> None:
        self.category = category
        self.rule_name = rule_name
        self.description = description
        self.line_number = line_number
        self.snippet = snippet.strip()
        self.file_path = file_path

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "rule_name": self.rule_name,
            "description": self.description,
            "line_number": self.line_number,
            "snippet": self.snippet[:200],
            "file_path": self.file_path,
        }

    def __repr__(self) -> str:
        loc = f"{self.file_path}:{self.line_number}" if self.line_number else self.file_path
        return f"[{self.category}] {self.rule_name} at {loc}: {self.description}"


def is_false_positive_secret(
    matched_text: str,
    rule_name: str,
    allowed_substrings: list[str] | None = None,
) -> bool:
    """Check if matched secret string is an obvious safe placeholder or template variable."""
    if "Assignment" not in rule_name:
        return False
    lower = matched_text.lower()
    placeholders = allowed_substrings if allowed_substrings is not None else get_allowed_secret_substrings_list()
    for placeholder in placeholders:
        if placeholder.lower() in lower:
            return True
    return False


def scan_text_for_violations(
    text: str,
    file_path: str = "",
    is_diff: bool = False,
    config_override: dict[str, Any] | None = None,
) -> list[SecurityViolation]:
    """Scan arbitrary source text or git diff hunk for security violations across all 6 categories.

    100% Zero Hardcoding: Reads models, tables, tenant fields, route prefixes, and placeholders
    dynamically from active configuration.
    """
    violations: list[SecurityViolation] = []
    if not text or not text.strip():
        return violations

    # Dynamically load fresh configuration
    cfg = config_override or load_active_security_config()
    tables_list = list(cfg.get("protected_tables", []))
    models_list = list(cfg.get("protected_models", []))
    fields_list = list(dict.fromkeys(list(cfg.get("tenant_id_fields", [])) + STANDARD_TENANT_FIELDS))
    route_prefixes = list(cfg.get("protected_route_prefixes", []))
    allowed_substrings = list(cfg.get("allowed_secret_substrings", []))

    idor_tables_pattern = build_tables_pattern(tables_list)
    orm_models_pattern = build_models_pattern(models_list)
    idor_filter_pattern = build_tenant_filter_regex(fields_list)

    # Tolerates optional quotes (", ', `, [) around table names
    idor_sql_target_pattern = re.compile(
        rf"\b(?:SELECT|FROM|JOIN|UPDATE|DELETE(?:\s+FROM)?)\s+[\"`'\[]?{idor_tables_pattern}[\"`'\]]?\b",
        re.IGNORECASE,
    )
    # Tolerates db.query, session.query, s.query, self.db.query, and select(Model)
    orm_query_pattern = re.compile(
        rf"(?:db|session|s|self\.db|self\.session)\.query\(\s*{orm_models_pattern}\b|\bselect\(\s*{orm_models_pattern}\b",
        re.IGNORECASE,
    )
    routes_pattern = build_routes_regex(route_prefixes)
    auth_route_pattern = re.compile(
        rf"@(?:router|app|api_router)\.(?:get|post|put|delete|patch)\s*\(\s*[\"']\/{routes_pattern}[^\"']*[\"'](?!(?:[^()]*|\([^()]*\))*(?:Depends|Security|auth_required|get_current))",
        re.IGNORECASE,
    )

    # Dynamic auth context pattern for tenant fields
    escaped_fields = [re.escape(f) for f in fields_list if f]
    dynamic_fields_re = "|".join(escaped_fields) if escaped_fields else r"user_id|tenant_id|property_id"
    auth_null_pattern = re.compile(
        rf"(?:{dynamic_fields_re})\s*=\s*None\s*(?:#.*)?\n\s*(?:return|pass|continue|db\.|session\.)",
        re.MULTILINE | re.IGNORECASE,
    )

    lines = text.splitlines()

    # Pre-filter lines if scanning a git diff: only inspect added lines (starting with '+')
    lines_to_inspect: list[tuple[int, str]] = []
    if is_diff:
        for idx, line in enumerate(lines, start=1):
            if line.startswith("+") and not line.startswith("+++"):
                lines_to_inspect.append((idx, line[1:]))
    else:
        for idx, line in enumerate(lines, start=1):
            lines_to_inspect.append((idx, line))

    full_inspect_text = "\n".join(content for _, content in lines_to_inspect)

    # 1. Secrets & PII Scan (Line-by-line & Multi-line for Keys)
    for pattern, name, desc in SECRETS_PATTERNS:
        if "KEY-----" in pattern or "raw_signature" in pattern:
            match = re.search(pattern, full_inspect_text, re.DOTALL | re.IGNORECASE)
            if match and not is_false_positive_secret(match.group(0), name, allowed_substrings):
                violations.append(
                    SecurityViolation(
                        category="Secrets & PII",
                        rule_name=name,
                        description=desc,
                        line_number=None,
                        snippet=match.group(0)[:100],
                        file_path=file_path,
                    )
                )
        else:
            for line_no, line_content in lines_to_inspect:
                match = re.search(pattern, line_content, re.IGNORECASE)
                if match:
                    matched_str = match.group(0)
                    if not is_false_positive_secret(matched_str, name, allowed_substrings):
                        violations.append(
                            SecurityViolation(
                                category="Secrets & PII",
                                rule_name=name,
                                description=desc,
                                line_number=line_no,
                                snippet=line_content,
                                file_path=file_path,
                            )
                        )

    # 2. SQL Injection Scan (Both Line-level and Multiline Block-level)
    for pattern, name, desc in SQLI_PATTERNS_LINE:
        for line_no, line_content in lines_to_inspect:
            if re.search(pattern, line_content, re.IGNORECASE):
                violations.append(
                    SecurityViolation(
                        category="SQL Injection",
                        rule_name=name,
                        description=desc,
                        line_number=line_no,
                        snippet=line_content,
                        file_path=file_path,
                    )
                )

    for pattern, name, desc in SQLI_PATTERNS_BLOCK:
        for match in re.finditer(pattern, full_inspect_text, re.DOTALL | re.IGNORECASE):
            matched_str = match.group(0)
            line_no = full_inspect_text[:match.start()].count("\n") + 1
            if not any(v.category == "SQL Injection" and v.line_number == line_no for v in violations):
                violations.append(
                    SecurityViolation(
                        category="SQL Injection",
                        rule_name=name,
                        description=desc,
                        line_number=line_no,
                        snippet=matched_str[:120],
                        file_path=file_path,
                    )
                )

    # 3. IDOR & Multi-Tenant Scan (Statement Scope & Block Scope)
    # 3A. ORM Query Scanning
    orm_matches = list(orm_query_pattern.finditer(full_inspect_text))
    for m in orm_matches:
        start_pos = m.start()
        line_no = full_inspect_text[:start_pos].count("\n") + 1
        end_pos = len(full_inspect_text)
        for term_match in re.finditer(r';|\n(?=\s*(?:def|class|@|return|\b[a-zA-Z_][a-zA-Z0-9_]*\s*=))', full_inspect_text[start_pos:]):
            end_pos = start_pos + term_match.start()
            break
        orm_block = full_inspect_text[start_pos:min(end_pos, start_pos + 600)]
        if not idor_filter_pattern.search(orm_block):
            violations.append(
                SecurityViolation(
                    category="IDOR & Multi-Tenant",
                    rule_name="Missing Tenant Filter in ORM Query",
                    description="ORM query on protected model without tenant/property boundary filter (§1, §24).",
                    line_number=line_no,
                    snippet=orm_block.splitlines()[0] if orm_block else "",
                    file_path=file_path,
                )
            )

    # 3B. Raw SQL Statement Scanning with Statement Scope
    inspected_spans: list[tuple[int, int]] = []

    # Check parenthesized string blocks (e.g. query = ("SELECT ..." "FROM users " "WHERE ..."))
    paren_str_pattern = re.compile(
        r'\(\s*(?:[fFrRuUbB]?(?:"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')\s*)+\)',
        re.DOTALL,
    )
    for m in paren_str_pattern.finditer(full_inspect_text):
        inspected_spans.append((m.start(), m.end()))
        block_text = m.group(0)
        if idor_sql_target_pattern.search(block_text) and not idor_filter_pattern.search(block_text):
            line_no = full_inspect_text[:m.start()].count("\n") + 1
            violations.append(
                SecurityViolation(
                    category="IDOR & Multi-Tenant",
                    rule_name="Missing Multi-Tenant Filter in SQL",
                    description="Querying multi-tenant protected table without tenant_id, property_id, or ownership_id filter (§1, §24 IDOR Defense).",
                    line_number=line_no,
                    snippet=block_text.splitlines()[0],
                    file_path=file_path,
                )
            )

    # Check triple-quoted and single-quoted strings not enclosed in parenthesized string blocks
    quote_pattern = re.compile(
        r'[fFrRuUbB]?(?:"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')',
        re.DOTALL,
    )
    for m in quote_pattern.finditer(full_inspect_text):
        if any(span_start <= m.start() and m.end() <= span_end for span_start, span_end in inspected_spans):
            continue
        block_text = m.group(0)
        if idor_sql_target_pattern.search(block_text) and not idor_filter_pattern.search(block_text):
            line_no = full_inspect_text[:m.start()].count("\n") + 1
            violations.append(
                SecurityViolation(
                    category="IDOR & Multi-Tenant",
                    rule_name="Missing Multi-Tenant Filter in SQL",
                    description="Querying multi-tenant protected table without tenant_id, property_id, or ownership_id filter (§1, §24 IDOR Defense).",
                    line_number=line_no,
                    snippet=block_text.splitlines()[0],
                    file_path=file_path,
                )
            )

    # 4. RLS & CORS Scan
    for pattern, name, desc in RLS_CORS_PATTERNS:
        match = re.search(pattern, full_inspect_text, re.DOTALL | re.IGNORECASE)
        if match:
            violations.append(
                SecurityViolation(
                    category="RLS & Access Control",
                    rule_name=name,
                    description=desc,
                    line_number=None,
                    snippet=match.group(0)[:120],
                    file_path=file_path,
                )
            )

    # 5. Command Injection Scan (Vá P0: Line-level + Multiline Full-Text Scan without ReDoS)
    for pattern, name, desc in COMMAND_INJECTION_PATTERNS:
        # Line-by-line inspection
        for line_no, line_content in lines_to_inspect:
            if re.search(pattern, line_content):
                violations.append(
                    SecurityViolation(
                        category="Command Injection",
                        rule_name=name,
                        description=desc,
                        line_number=line_no,
                        snippet=line_content,
                        file_path=file_path,
                    )
                )

        # Multiline block check for subprocess calls spanning multiple lines
        if "subprocess" in pattern and "shell" in full_inspect_text:
            for match in re.finditer(pattern, full_inspect_text, re.DOTALL):
                line_no = full_inspect_text[:match.start()].count("\n") + 1
                if not any(v.category == "Command Injection" and v.line_number == line_no for v in violations):
                    violations.append(
                        SecurityViolation(
                            category="Command Injection",
                            rule_name=name,
                            description=desc,
                            line_number=line_no,
                            snippet=match.group(0)[:120],
                            file_path=file_path,
                        )
                    )

    # 6. Auth Context Scan (Dynamic fields)
    auth_match = auth_null_pattern.search(full_inspect_text)
    if auth_match:
        violations.append(
            SecurityViolation(
                category="Auth Context",
                rule_name="Implicit Null Auth Assignment",
                description="Implicitly assigning None to user/tenant ID without returning 401/403 creates auth bypass (§2, §26).",
                line_number=None,
                snippet=auth_match.group(0)[:120],
                file_path=file_path,
            )
        )

    # 6B. Dynamic Protected API Route Scan
    route_match = auth_route_pattern.search(full_inspect_text)
    if route_match:
        violations.append(
            SecurityViolation(
                category="Auth Context",
                rule_name="Protected API Route Missing Auth Dependency",
                description="Protected multi-tenant endpoint lacks authentication/authorization dependency guard (§1, §2).",
                line_number=None,
                snippet=route_match.group(0)[:120],
                file_path=file_path,
            )
        )

    return violations


def get_git_diff_staged(cwd: str | None = None, timeout_seconds: int = 10) -> str:
    """Retrieve staged git diff or working tree diff safely."""
    try:
        proc = subprocess.run(
            ["git", "diff", "--staged"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
            timeout=timeout_seconds,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout

        proc_unstaged = subprocess.run(
            ["git", "diff", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
            timeout=timeout_seconds,
            check=False,
        )
        if proc_unstaged.returncode == 0 and proc_unstaged.stdout.strip():
            return proc_unstaged.stdout

        # Fallback for initial repository without HEAD
        proc_raw = subprocess.run(
            ["git", "diff"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
            timeout=timeout_seconds,
            check=False,
        )
        if proc_raw.returncode == 0:
            return proc_raw.stdout
        return ""
    except (OSError, subprocess.SubprocessError):
        return ""


# ============================================================================
# 4. ANTIGRAVITY HOOK EVENT HANDLERS
# ============================================================================

GIT_COMMIT_PUSH_REGEX = (
    r"\bgit(?:\.exe)?(?:\s+(?:-[^\s]+(?:\s+[^-][^\s]*)?|--[^\s]+(?:\s+[^-][^\s]*)?))*\s+['\"]?(?:commit|push)['\"]?\b"
)


def evaluate_diff_security_pre_tool(payload: dict[str, Any]) -> dict[str, Any]:
    """PreToolUse handler: Intercepts git commit/push or file modifications to block violations."""
    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""
    args = get_tool_args(tool_call)

    violations: list[SecurityViolation] = []
    cfg = load_active_security_config()
    diff_timeout = int(cfg.get("git_diff_timeout_seconds", 10))

    if tool_name == "run_command":
        cmd_line = args.get("CommandLine") or args.get("command") or args.get("cmd") or ""
        if isinstance(cmd_line, str) and re.search(GIT_COMMIT_PUSH_REGEX, cmd_line, re.IGNORECASE):
            cwd = args.get("Cwd") or args.get("cwd")
            diff_text = get_git_diff_staged(cwd=cwd, timeout_seconds=diff_timeout)
            if diff_text:
                violations.extend(scan_text_for_violations(diff_text, file_path="git-diff-staged", is_diff=True, config_override=cfg))

    elif tool_name in ("write_to_file", "replace_file_content", "multi_replace_file_content", "edit_file", "write_file"):
        target_file = (
            args.get("TargetFile")
            or args.get("target_file")
            or args.get("filePath")
            or args.get("path")
            or ""
        )
        content_to_check = ""

        if tool_name in ("write_to_file", "write_file"):
            content_to_check = args.get("CodeContent") or args.get("code_content") or args.get("content") or ""
        elif tool_name in ("replace_file_content", "edit_file"):
            content_to_check = args.get("ReplacementContent") or args.get("replacement_content") or args.get("content") or ""
        elif tool_name == "multi_replace_file_content":
            chunks = args.get("ReplacementChunks") or args.get("replacement_chunks") or []
            if isinstance(chunks, list):
                content_to_check = "\n".join(
                    c.get("ReplacementContent") or c.get("replacement_content") or ""
                    for c in chunks
                    if isinstance(c, dict)
                )

        if isinstance(content_to_check, str) and content_to_check.strip():
            violations.extend(scan_text_for_violations(content_to_check, file_path=str(target_file), is_diff=False, config_override=cfg))

    if violations:
        summary_reasons = [f"{v.rule_name} ({v.category})" for v in violations[:3]]
        reason_msg = (
            f"Enterprise Layer 2 Security Violation: Detected {len(violations)} security issue(s): "
            f"{'; '.join(summary_reasons)}. Fix violations before proceeding."
        )
        log_diagnostic(f"BLOCKED by diff_security_inspector: {reason_msg}")
        for v in violations:
            log_diagnostic(f"  - Violation: {v}")

        return {
            "decision": "deny",
            "reason": reason_msg,
            "violations": [v.to_dict() for v in violations],
        }

    return pre_tool_response("allow", "Diff security inspection passed with 0 violations.")


def evaluate_diff_security_post_tool(payload: dict[str, Any]) -> dict[str, Any]:
    """PostToolUse handler: Scans modified files on disk and logs diagnostics (returns strictly {})."""
    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""
    args = get_tool_args(tool_call)

    if tool_name in ("write_to_file", "replace_file_content", "multi_replace_file_content", "edit_file", "write_file"):
        raw_target = (
            args.get("TargetFile")
            or args.get("target_file")
            or args.get("filePath")
            or args.get("path")
        )
        if isinstance(raw_target, str) and raw_target.strip():
            target_path = pathlib.Path(raw_target)
            if target_path.exists() and target_path.is_file():
                try:
                    content = target_path.read_text(encoding="utf-8", errors="replace")
                    violations = scan_text_for_violations(content, file_path=str(target_path), is_diff=False)
                    if violations:
                        log_diagnostic(
                            f"[PostToolUse Warning] {len(violations)} security violation(s) found in {raw_target}:"
                        )
                        for v in violations:
                            log_diagnostic(f"  [!] {v}")
                    else:
                        log_diagnostic(f"[PostToolUse Clean] {raw_target} passed Layer 2 static scan.")
                except OSError as exc:
                    log_diagnostic(f"Could not read file {raw_target} for post-scan: {exc}")

    return post_tool_response()


# ============================================================================
# 5. CLI ENTRYPOINT & STANDALONE EXECUTION
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="Static Diff & Security Inspector (Layer 2 Hook)")
    parser.add_argument("--diff", type=str, help="Git diff content to inspect")
    parser.add_argument("--file", type=str, help="File path to inspect")
    parser.add_argument("--text", type=str, help="Raw text content to inspect")
    parser.add_argument("--post", action="store_true", help="Run in PostToolUse mode")
    args, _ = parser.parse_known_args()

    if args.diff is not None or args.file is not None or args.text is not None:
        violations: list[SecurityViolation] = []
        if args.diff is not None:
            violations.extend(scan_text_for_violations(args.diff, file_path="cli-diff", is_diff=True))
        elif args.file is not None:
            p = pathlib.Path(args.file)
            if p.exists() and p.is_file():
                content = p.read_text(encoding="utf-8", errors="replace")
                violations.extend(scan_text_for_violations(content, file_path=str(p), is_diff=False))
            else:
                log_diagnostic(f"File not found: {args.file}")
        elif args.text is not None:
            violations.extend(scan_text_for_violations(args.text, file_path="cli-text", is_diff=False))

        result = {
            "action": "block" if violations else "allow",
            "violations_count": len(violations),
            "violations": [v.to_dict() for v in violations],
            "message": f"Found {len(violations)} violation(s)" if violations else "Clean: 0 violations",
        }
        emit_stdout_json(result)
        sys.exit(1 if violations else 0)

    payload = read_stdin_payload(default={})

    if args.post:
        response = evaluate_diff_security_post_tool(payload)
    else:
        response = evaluate_diff_security_pre_tool(payload)

    emit_stdout_json(response)


if __name__ == "__main__":
    main()
