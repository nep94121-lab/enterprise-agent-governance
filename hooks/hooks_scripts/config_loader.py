#!/usr/bin/env python3
"""Universal Multi-Agent Governance Kit — Runtime Configuration Loader.

Provides centralized configuration loading, multi-format parsing (YAML/JSON),
upward directory traversal auto-discovery, environment variable overrides,
graceful fallback defaults (Zero-Config Resilience), syntax error tolerance,
and comprehensive schema validation across all lifecycle hooks.
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import sys
from dataclasses import dataclass, field
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

# Optional PyYAML import with fail-safe fallback
try:
    import yaml
    HAS_YAML = True
except ImportError:
    yaml = None
    HAS_YAML = False


# Standard enterprise roles recognized across the Governance Kit
STANDARD_ROLES: tuple[str, ...] = (
    "pm_orchestrator",
    "backend_developer",
    "frontend_developer",
    "devops_security",
    "qa_challenger",
    "tech_lead_auditor",
    "codebase_explorer",
    "lead_watchdog",
    "watchdog_inspector",
    "pm_challenger",
    "appsec_sentinel",
    "data_ml_engineer",
    "state_checkpoint_curator",
    "mobile_app_developer",
)


def log_config_info(message: str) -> None:
    """Log diagnostic info message to sys.stderr (never polluting stdout)."""
    try:
        sys.stderr.write(f"[CONFIG] {message}\n")
        sys.stderr.flush()
    except (OSError, UnicodeEncodeError):
        pass


def log_config_warning(message: str) -> None:
    """Log diagnostic warning message to sys.stderr (never polluting stdout)."""
    try:
        sys.stderr.write(f"[CONFIG] Warning: {message}\n")
        sys.stderr.flush()
    except (OSError, UnicodeEncodeError):
        pass


@dataclass
class SchemaValidationError:
    """Detailed validation error with path, invalid value, and explanatory message."""

    path: str
    invalid_value: Any
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message} (got {self.invalid_value!r})"


@dataclass
class ProjectConfig:
    """Metadata configuration for the target project."""

    name: str = "Enterprise Application"
    id: str = "PROJ-001"
    description: str = "Enterprise application governed by Multi-Agent Governance Kit"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProjectConfig:
        return cls(
            name=str(data.get("name", "Enterprise Application")),
            id=str(data.get("id", "PROJ-001")),
            description=str(data.get("description", "Enterprise application governed by Multi-Agent Governance Kit")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "id": self.id,
            "description": self.description,
        }


@dataclass
class GitAuthorValidationConfig:
    """Configuration for Git commit author domain validation."""

    enabled: bool = False
    allowed_email_domains: list[str] = field(default_factory=lambda: ["company.com"])

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GitAuthorValidationConfig:
        domains = data.get("allowed_email_domains", ["company.com"])
        if isinstance(domains, str):
            domains = [domains]
        return cls(
            enabled=bool(data.get("enabled", False)),
            allowed_email_domains=list(domains),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "allowed_email_domains": list(self.allowed_email_domains),
        }


@dataclass
class GitConfig:
    """Git branch governance, push restrictions, and force-push guards."""

    allowed_push_branches: list[str] = field(default_factory=lambda: ["*"])
    prohibited_push_branches: list[str] = field(
        default_factory=lambda: ["main", "master", "prod", "production", "release"]
    )
    prohibit_force_push: bool = True
    author_validation: GitAuthorValidationConfig = field(default_factory=GitAuthorValidationConfig)

    @property
    def allowed_branches(self) -> list[str]:
        return self.allowed_push_branches

    @property
    def prohibited_branches(self) -> list[str]:
        return self.prohibited_push_branches

    @property
    def block_force_push(self) -> bool:
        return self.prohibit_force_push

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GitConfig:
        allowed = data.get("allowed_push_branches") or data.get("allowed_branches") or ["*"]
        if isinstance(allowed, str):
            allowed = [allowed]
        elif isinstance(allowed, (list, tuple, set)):
            allowed = [str(x) for x in allowed]
        else:
            allowed = [str(allowed)]

        prohibited = data.get("prohibited_push_branches") or data.get("prohibited_branches") or [
            "main", "master", "prod", "production", "release"
        ]
        if isinstance(prohibited, str):
            prohibited = [prohibited]
        elif isinstance(prohibited, (list, tuple, set)):
            prohibited = [str(x) for x in prohibited]
        else:
            prohibited = [str(prohibited)]

        force_flag = data.get("prohibit_force_push")
        if force_flag is None:
            force_flag = data.get("block_force_push", True)
        if isinstance(force_flag, str):
            force_flag = force_flag.strip().lower() in ("true", "1", "yes")

        author_val_data = data.get("author_validation", {})
        author_val = (
            GitAuthorValidationConfig.from_dict(author_val_data)
            if isinstance(author_val_data, dict)
            else GitAuthorValidationConfig()
        )

        return cls(
            allowed_push_branches=list(allowed),
            prohibited_push_branches=list(prohibited),
            prohibit_force_push=bool(force_flag),
            author_validation=author_val,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_push_branches": list(self.allowed_push_branches),
            "prohibited_push_branches": list(self.prohibited_push_branches),
            "prohibit_force_push": self.prohibit_force_push,
            "author_validation": self.author_validation.to_dict(),
        }


@dataclass
class MultiTenantConfig:
    """Boundary enforcements for multi-tenant IDOR defense."""

    enabled: bool = True
    tenant_id_fields: list[str] = field(
        default_factory=lambda: [
            "tenant_id",
            "organization_id",
            "project_id",
            "ownership_id",
            "account_id",
        ]
    )
    protected_tables: list[str] = field(
        default_factory=lambda: [
            "users",
            "accounts",
            "orders",
            "contracts",
            "invoices",
            "tenants",
            "residents",
        ]
    )
    protected_models: list[str] = field(
        default_factory=lambda: [
            "User",
            "Account",
            "Order",
            "Contract",
            "Invoice",
            "Tenant",
            "Resident",
        ]
    )
    protected_route_prefixes: list[str] = field(
        default_factory=lambda: [
            "/api/v1/protected",
            "/admin",
            "/api/v1/billing",
        ]
    )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MultiTenantConfig:
        def _to_list(val: Any, default: list[str]) -> list[str]:
            if val is None:
                return default
            if isinstance(val, str):
                return [val]
            if isinstance(val, (list, tuple, set)):
                return [str(item) for item in val]
            return [str(val)]

        return cls(
            enabled=bool(data.get("enabled", True)),
            tenant_id_fields=_to_list(
                data.get("tenant_id_fields"),
                ["tenant_id", "organization_id", "project_id", "ownership_id", "account_id"],
            ),
            protected_tables=_to_list(
                data.get("protected_tables"),
                ["users", "accounts", "orders", "contracts", "invoices", "tenants", "residents"],
            ),
            protected_models=_to_list(
                data.get("protected_models"),
                ["User", "Account", "Order", "Contract", "Invoice", "Tenant", "Resident"],
            ),
            protected_route_prefixes=_to_list(
                data.get("protected_route_prefixes"),
                ["/api/v1/protected", "/admin", "/api/v1/billing"],
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "tenant_id_fields": list(self.tenant_id_fields),
            "protected_tables": list(self.protected_tables),
            "protected_models": list(self.protected_models),
            "protected_route_prefixes": list(self.protected_route_prefixes),
        }


@dataclass
class SecretsScannerConfig:
    """Security scanner configuration for secrets and credentials detection."""

    enabled: bool = True
    block_on_critical: bool = True
    allowed_substrings: list[str] = field(
        default_factory=lambda: [
            "your_secret",
            "dummy_token",
            "placeholder_key",
            "test_secret",
        ]
    )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecretsScannerConfig:
        substrings = data.get("allowed_substrings", ["your_secret", "dummy_token", "placeholder_key", "test_secret"])
        if isinstance(substrings, str):
            substrings = [substrings]
        return cls(
            enabled=bool(data.get("enabled", True)),
            block_on_critical=bool(data.get("block_on_critical", True)),
            allowed_substrings=list(substrings),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "block_on_critical": self.block_on_critical,
            "allowed_substrings": list(self.allowed_substrings),
        }


@dataclass
class DatabaseConfig:
    """Database security configuration enforcing environment-only credentials."""

    enforce_env_only: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DatabaseConfig:
        return cls(enforce_env_only=bool(data.get("enforce_env_only", True)))

    def to_dict(self) -> dict[str, Any]:
        return {"enforce_env_only": self.enforce_env_only}


@dataclass
class SecurityConfig:
    """Composite security configuration (Multi-tenant, Secrets Scanner, Database)."""

    multi_tenant: MultiTenantConfig = field(default_factory=MultiTenantConfig)
    secrets_scanner: SecretsScannerConfig = field(default_factory=SecretsScannerConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityConfig:
        mt_data = data.get("multi_tenant", {})
        mt = MultiTenantConfig.from_dict(mt_data) if isinstance(mt_data, dict) else MultiTenantConfig()

        sc_data = data.get("secrets_scanner", {})
        sc = SecretsScannerConfig.from_dict(sc_data) if isinstance(sc_data, dict) else SecretsScannerConfig()

        db_data = data.get("database", {})
        db = DatabaseConfig.from_dict(db_data) if isinstance(db_data, dict) else DatabaseConfig()

        return cls(multi_tenant=mt, secrets_scanner=sc, database=db)

    def to_dict(self) -> dict[str, Any]:
        return {
            "multi_tenant": self.multi_tenant.to_dict(),
            "secrets_scanner": self.secrets_scanner.to_dict(),
            "database": self.database.to_dict(),
        }


@dataclass
class TestRunnerConfig:
    """Pre-push test runner execution configuration."""

    command: str = "pytest tests/ -q --tb=short"
    timeout_seconds: int = 60
    bypass_env_var: str = "SKIP_PRE_PUSH_TEST"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TestRunnerConfig:
        timeout = data.get("timeout_seconds", 60)
        try:
            timeout = int(timeout)
        except (ValueError, TypeError):
            timeout = 60
        return cls(
            command=str(data.get("command", "pytest tests/ -q --tb=short")),
            timeout_seconds=timeout,
            bypass_env_var=str(data.get("bypass_env_var", "SKIP_PRE_PUSH_TEST")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "timeout_seconds": self.timeout_seconds,
            "bypass_env_var": self.bypass_env_var,
        }


@dataclass
class TokenBudgetConfig:
    """Token budget limits per file and per agent role."""

    max_rule_file_tokens: int = 4000
    max_role_tokens: int = 12000
    warning_threshold: float = 0.8
    critical_threshold: float = 0.95
    roles: dict[str, int] = field(
        default_factory=lambda: {
            "pm_orchestrator": 12000,
            "backend_developer": 12000,
            "frontend_developer": 12000,
            "devops_security": 12000,
            "qa_challenger": 12000,
            "tech_lead_auditor": 12000,
            "codebase_explorer": 12000,
            "lead_watchdog": 12000,
            "watchdog_inspector": 12000,
            "pm_challenger": 12000,
            "appsec_sentinel": 12000,
            "data_ml_engineer": 12000,
            "state_checkpoint_curator": 12000,
            "mobile_app_developer": 12000,
        }
    )

    @property
    def max_file_tokens(self) -> int:
        return self.max_rule_file_tokens

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TokenBudgetConfig:
        max_file = data.get("max_rule_file_tokens")
        if max_file is None:
            max_file = data.get("max_file_tokens", 4000)
        try:
            max_file = int(max_file)
        except (ValueError, TypeError):
            max_file = 4000

        max_role = data.get("max_role_tokens", 12000)
        try:
            max_role = int(max_role)
        except (ValueError, TypeError):
            max_role = 12000

        warn = data.get("warning_threshold", 0.8)
        try:
            warn = float(warn)
        except (ValueError, TypeError):
            warn = 0.8

        crit = data.get("critical_threshold", 0.95)
        try:
            crit = float(crit)
        except (ValueError, TypeError):
            crit = 0.95

        roles_dict = {
            "pm_orchestrator": 12000,
            "backend_developer": 12000,
            "frontend_developer": 12000,
            "devops_security": 12000,
            "qa_challenger": 12000,
            "tech_lead_auditor": 12000,
            "codebase_explorer": 12000,
            "lead_watchdog": 12000,
            "watchdog_inspector": 12000,
            "pm_challenger": 12000,
            "appsec_sentinel": 12000,
            "data_ml_engineer": 12000,
            "state_checkpoint_curator": 12000,
            "mobile_app_developer": 12000,
        }
        if "roles" in data and isinstance(data["roles"], dict):
            for r_name, r_budget in data["roles"].items():
                try:
                    roles_dict[str(r_name)] = int(r_budget)
                except (ValueError, TypeError):
                    pass

        return cls(
            max_rule_file_tokens=max_file,
            max_role_tokens=max_role,
            warning_threshold=warn,
            critical_threshold=crit,
            roles=roles_dict,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_rule_file_tokens": self.max_rule_file_tokens,
            "max_file_tokens": self.max_rule_file_tokens,
            "max_role_tokens": self.max_role_tokens,
            "warning_threshold": self.warning_threshold,
            "critical_threshold": self.critical_threshold,
            "roles": dict(self.roles),
        }


@dataclass
class ConfidenceScoringConfig:
    """Confidence Scoring (0-100) threshold configuration for QA Challenger & Gate Review."""

    block_merge_threshold: int = 80
    default_threshold: int = 80

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConfidenceScoringConfig:
        threshold = data.get("block_merge_threshold")
        if threshold is None:
            threshold = data.get("default_threshold", 80)
        try:
            threshold = int(threshold)
        except (ValueError, TypeError):
            threshold = 80
        return cls(
            block_merge_threshold=threshold,
            default_threshold=threshold,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "block_merge_threshold": self.block_merge_threshold,
            "default_threshold": self.default_threshold,
        }


@dataclass
class TestingConfig:
    """Composite testing and quality assurance configuration."""

    test_runner: TestRunnerConfig = field(default_factory=TestRunnerConfig)
    token_budget: TokenBudgetConfig = field(default_factory=TokenBudgetConfig)
    confidence_scoring: ConfidenceScoringConfig = field(default_factory=ConfidenceScoringConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TestingConfig:
        tr_data = data.get("test_runner", {})
        tr = TestRunnerConfig.from_dict(tr_data) if isinstance(tr_data, dict) else TestRunnerConfig()

        tb_data = data.get("token_budget", {})
        tb = TokenBudgetConfig.from_dict(tb_data) if isinstance(tb_data, dict) else TokenBudgetConfig()

        cs_data = data.get("confidence_scoring", {})
        cs = ConfidenceScoringConfig.from_dict(cs_data) if isinstance(cs_data, dict) else ConfidenceScoringConfig()

        return cls(test_runner=tr, token_budget=tb, confidence_scoring=cs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_runner": self.test_runner.to_dict(),
            "token_budget": self.token_budget.to_dict(),
            "confidence_scoring": self.confidence_scoring.to_dict(),
        }


@dataclass
class RemindersConfig:
    """Dynamic lifecycle reminders injected into agent context."""

    session_start: dict[str, Any] = field(
        default_factory=lambda: {
            "title": "🔒 [ENTERPRISE GOVERNANCE REMINDER - SESSION START]",
            "clauses": [
                "Security (§1-§2): Zero raw PII logging, zero hardcoded secrets in code.",
                "Quality & Hygiene (§11, §13): No 'git add .', 0 trailing spaces, 0 blank EOF lines.",
                "Architecture (§15): .agents/ holds only metadata, no source code.",
                "Pre-Flight (§28-§29): Review empirical git diff and verify 100% test coverage.",
            ],
        }
    )
    heartbeat: dict[str, Any] = field(
        default_factory=lambda: {
            "title": "⏱️ [HEARTBEAT REMINDER]",
            "clauses": [
                "Liveness: Update progress.md with timestamp heartbeat on significant steps.",
                "Timer Discipline: Enforce 1m (small), 2m (medium), 3m (large) task timers.",
                "Resource Cleanup (§29): Kill background tasks and clean temporary files.",
            ],
        }
    )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RemindersConfig:
        res = cls()
        if "session_start" in data and isinstance(data["session_start"], dict):
            res.session_start = dict(data["session_start"])
        if "heartbeat" in data and isinstance(data["heartbeat"], dict):
            res.heartbeat = dict(data["heartbeat"])
        return res

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_start": dict(self.session_start),
            "heartbeat": dict(self.heartbeat),
        }


@dataclass
class GovernanceConfig:
    """Master governance configuration object with deep and flat accessors."""

    project: ProjectConfig = field(default_factory=ProjectConfig)
    git: GitConfig = field(default_factory=GitConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    testing: TestingConfig = field(default_factory=TestingConfig)
    reminders: RemindersConfig = field(default_factory=RemindersConfig)
    raw_config: dict[str, Any] = field(default_factory=dict)
    config_source: str | None = None

    def __init__(
        self,
        project: ProjectConfig | None = None,
        git: GitConfig | None = None,
        security: SecurityConfig | None = None,
        testing: TestingConfig | None = None,
        reminders: RemindersConfig | None = None,
        raw_config: dict[str, Any] | None = None,
        config_source: str | None = None,
        **kwargs: Any,
    ) -> None:
        self.project = project if project is not None else ProjectConfig()
        self.git = git if git is not None else GitConfig()
        self.security = security if security is not None else SecurityConfig()
        self.testing = testing if testing is not None else TestingConfig()
        self.reminders = reminders if reminders is not None else RemindersConfig()
        self.raw_config = raw_config if raw_config is not None else {}
        self.config_source = config_source

        # Handle flat kwargs for convenient direct instantiation
        if "project_name" in kwargs:
            self.project.name = str(kwargs["project_name"])
        if "project_id" in kwargs:
            self.project.id = str(kwargs["project_id"])
        if "allowed_push_branches" in kwargs:
            val = kwargs["allowed_push_branches"]
            self.git.allowed_push_branches = [val] if isinstance(val, str) else list(val)
        if "prohibited_push_branches" in kwargs:
            val = kwargs["prohibited_push_branches"]
            self.git.prohibited_push_branches = [val] if isinstance(val, str) else list(val)
        if "prohibit_force_push" in kwargs:
            self.git.prohibit_force_push = bool(kwargs["prohibit_force_push"])
        if "tenant_id_fields" in kwargs:
            self.security.multi_tenant.tenant_id_fields = list(kwargs["tenant_id_fields"])
        if "protected_tables" in kwargs:
            self.security.multi_tenant.protected_tables = list(kwargs["protected_tables"])
        if "protected_models" in kwargs:
            self.security.multi_tenant.protected_models = list(kwargs["protected_models"])
        if "protected_route_prefixes" in kwargs:
            self.security.multi_tenant.protected_route_prefixes = list(kwargs["protected_route_prefixes"])
        if "test_runner_command" in kwargs:
            self.testing.test_runner.command = str(kwargs["test_runner_command"])
        if "confidence_threshold" in kwargs:
            self.testing.confidence_scoring.block_merge_threshold = int(kwargs["confidence_threshold"])

    # Flat properties for universal hook backwards-compatibility
    @property
    def project_name(self) -> str:
        return self.project.name

    @project_name.setter
    def project_name(self, value: str) -> None:
        self.project.name = str(value)

    @property
    def project_id(self) -> str:
        return self.project.id

    @project_id.setter
    def project_id(self, value: str) -> None:
        self.project.id = str(value)

    @property
    def allowed_push_branches(self) -> list[str]:
        return self.git.allowed_push_branches

    @allowed_push_branches.setter
    def allowed_push_branches(self, value: list[str]) -> None:
        self.git.allowed_push_branches = list(value)

    @property
    def prohibited_push_branches(self) -> list[str]:
        return self.git.prohibited_push_branches

    @prohibited_push_branches.setter
    def prohibited_push_branches(self, value: list[str]) -> None:
        self.git.prohibited_push_branches = list(value)

    @property
    def prohibit_force_push(self) -> bool:
        return self.git.prohibit_force_push

    @prohibit_force_push.setter
    def prohibit_force_push(self, value: bool) -> None:
        self.git.prohibit_force_push = bool(value)

    @property
    def tenant_id_fields(self) -> list[str]:
        return self.security.multi_tenant.tenant_id_fields

    @tenant_id_fields.setter
    def tenant_id_fields(self, value: list[str]) -> None:
        self.security.multi_tenant.tenant_id_fields = list(value)

    @property
    def protected_tables(self) -> list[str]:
        return self.security.multi_tenant.protected_tables

    @protected_tables.setter
    def protected_tables(self, value: list[str]) -> None:
        self.security.multi_tenant.protected_tables = list(value)

    @property
    def protected_models(self) -> list[str]:
        return self.security.multi_tenant.protected_models

    @protected_models.setter
    def protected_models(self, value: list[str]) -> None:
        self.security.multi_tenant.protected_models = list(value)

    @property
    def protected_route_prefixes(self) -> list[str]:
        return self.security.multi_tenant.protected_route_prefixes

    @protected_route_prefixes.setter
    def protected_route_prefixes(self, value: list[str]) -> None:
        self.security.multi_tenant.protected_route_prefixes = list(value)

    @property
    def test_runner_command(self) -> str:
        return self.testing.test_runner.command

    @test_runner_command.setter
    def test_runner_command(self, value: str) -> None:
        self.testing.test_runner.command = str(value)

    @property
    def test_runner_timeout_seconds(self) -> int:
        return self.testing.test_runner.timeout_seconds

    @test_runner_timeout_seconds.setter
    def test_runner_timeout_seconds(self, value: int) -> None:
        self.testing.test_runner.timeout_seconds = int(value)

    @property
    def test_bypass_env_var(self) -> str:
        return self.testing.test_runner.bypass_env_var

    @test_bypass_env_var.setter
    def test_bypass_env_var(self, value: str) -> None:
        self.testing.test_runner.bypass_env_var = str(value)

    @property
    def token_budget(self) -> TokenBudgetConfig:
        return self.testing.token_budget

    @token_budget.setter
    def token_budget(self, value: TokenBudgetConfig | dict[str, Any]) -> None:
        if isinstance(value, TokenBudgetConfig):
            self.testing.token_budget = value
        elif isinstance(value, dict):
            self.testing.token_budget = TokenBudgetConfig.from_dict(value)

    @property
    def confidence_threshold(self) -> int:
        return self.testing.confidence_scoring.block_merge_threshold

    @confidence_threshold.setter
    def confidence_threshold(self, value: int) -> None:
        self.testing.confidence_scoring.block_merge_threshold = int(value)

    @property
    def confidence_scoring(self) -> ConfidenceScoringConfig:
        return self.testing.confidence_scoring

    @classmethod
    def from_dict(cls, data: dict[str, Any], config_source: str | None = None) -> GovernanceConfig:
        """Construct GovernanceConfig by merging dictionary with enterprise defaults."""
        if not isinstance(data, dict):
            return cls(config_source=config_source)

        # 1. Project section
        proj_data = data.get("project", {})
        if not isinstance(proj_data, dict):
            proj_data = {}
        # Merge top-level project_name if provided
        if "project_name" in data and "name" not in proj_data:
            proj_data["name"] = data["project_name"]
        if "project_id" in data and "id" not in proj_data:
            proj_data["id"] = data["project_id"]
        project = ProjectConfig.from_dict(proj_data)

        # 2. Git section
        git_data = data.get("git", {})
        if not isinstance(git_data, dict):
            git_data = {}
        if "allowed_push_branches" in data and "allowed_push_branches" not in git_data:
            git_data["allowed_push_branches"] = data["allowed_push_branches"]
        if "prohibited_push_branches" in data and "prohibited_push_branches" not in git_data:
            git_data["prohibited_push_branches"] = data["prohibited_push_branches"]
        if "prohibit_force_push" in data and "prohibit_force_push" not in git_data:
            git_data["prohibit_force_push"] = data["prohibit_force_push"]
        git = GitConfig.from_dict(git_data)

        # 3. Security section
        sec_data = data.get("security", {})
        if not isinstance(sec_data, dict):
            sec_data = {}
        # Handle flat multi-tenant definitions
        mt_data = sec_data.get("multi_tenant", {})
        if not isinstance(mt_data, dict):
            mt_data = {}
        if "tenant_id_fields" in data and "tenant_id_fields" not in mt_data:
            mt_data["tenant_id_fields"] = data["tenant_id_fields"]
        if "protected_tables" in data and "protected_tables" not in mt_data:
            mt_data["protected_tables"] = data["protected_tables"]
        if "protected_models" in data and "protected_models" not in mt_data:
            mt_data["protected_models"] = data["protected_models"]
        if "protected_route_prefixes" in data and "protected_route_prefixes" not in mt_data:
            mt_data["protected_route_prefixes"] = data["protected_route_prefixes"]
        sec_data["multi_tenant"] = mt_data
        security = SecurityConfig.from_dict(sec_data)

        # 4. Testing section
        testing_data = data.get("testing", {})
        if not isinstance(testing_data, dict):
            testing_data = {}
        # Handle flat test_runner / token_budget / confidence_scoring
        tr_data = testing_data.get("test_runner", {})
        if not isinstance(tr_data, dict):
            tr_data = {}
        if "test_runner_command" in data and "command" not in tr_data:
            tr_data["command"] = data["test_runner_command"]
        testing_data["test_runner"] = tr_data

        if "token_budget" in data and "token_budget" not in testing_data:
            testing_data["token_budget"] = data["token_budget"]

        cs_data = testing_data.get("confidence_scoring", {})
        if not isinstance(cs_data, dict):
            cs_data = {}
        if "confidence_threshold" in data and "block_merge_threshold" not in cs_data:
            cs_data["block_merge_threshold"] = data["confidence_threshold"]
        testing_data["confidence_scoring"] = cs_data

        testing = TestingConfig.from_dict(testing_data)

        # 5. Reminders section
        reminders_data = data.get("reminders", {})
        reminders = RemindersConfig.from_dict(reminders_data) if isinstance(reminders_data, dict) else RemindersConfig()

        return cls(
            project=project,
            git=git,
            security=security,
            testing=testing,
            reminders=reminders,
            raw_config=data,
            config_source=config_source,
        )

    def to_dict(self) -> dict[str, Any]:
        """Export full configuration hierarchy as a standard Python dictionary."""
        return {
            "project": self.project.to_dict(),
            "git": self.git.to_dict(),
            "security": self.security.to_dict(),
            "testing": self.testing.to_dict(),
            "reminders": self.reminders.to_dict(),
        }


def validate_config_schema(data: dict[str, Any]) -> tuple[bool, list[SchemaValidationError]]:
    """Validate dictionary structure, types, and values against enterprise boundary rules.

    Returns:
        (is_valid, errors): Tuple of boolean status and list of SchemaValidationError.
    """
    errors: list[SchemaValidationError] = []

    if not isinstance(data, dict):
        errors.append(
            SchemaValidationError(
                path="root",
                invalid_value=data,
                message="Root configuration must be a valid dictionary/object",
            )
        )
        return False, errors

    # 1. Validate confidence scoring threshold
    conf_val = None
    if "confidence_threshold" in data:
        conf_val = data["confidence_threshold"]
        conf_path = "confidence_threshold"
    elif "testing" in data and isinstance(data["testing"], dict):
        cs = data["testing"].get("confidence_scoring", {})
        if isinstance(cs, dict) and "block_merge_threshold" in cs:
            conf_val = cs["block_merge_threshold"]
            conf_path = "testing.confidence_scoring.block_merge_threshold"
        elif isinstance(cs, dict) and "default_threshold" in cs:
            conf_val = cs["default_threshold"]
            conf_path = "testing.confidence_scoring.default_threshold"

    if conf_val is not None:
        if not isinstance(conf_val, int) or isinstance(conf_val, bool):
            errors.append(
                SchemaValidationError(
                    path=conf_path,
                    invalid_value=conf_val,
                    message="Confidence score threshold must be an integer between 0 and 100",
                )
            )
        elif conf_val < 0 or conf_val > 100:
            errors.append(
                SchemaValidationError(
                    path=conf_path,
                    invalid_value=conf_val,
                    message="Confidence score must be between 0 and 100",
                )
            )

    # 2. Validate token budget
    tb_data = None
    if "token_budget" in data and isinstance(data["token_budget"], dict):
        tb_data = data["token_budget"]
        tb_prefix = "token_budget"
    elif "testing" in data and isinstance(data["testing"], dict):
        if "token_budget" in data["testing"] and isinstance(data["testing"]["token_budget"], dict):
            tb_data = data["testing"]["token_budget"]
            tb_prefix = "testing.token_budget"

    if tb_data:
        # Check max_rule_file_tokens
        max_file = tb_data.get("max_rule_file_tokens", tb_data.get("max_file_tokens"))
        if max_file is not None and (not isinstance(max_file, int) or isinstance(max_file, bool) or max_file <= 0):
            errors.append(
                SchemaValidationError(
                    path=f"{tb_prefix}.max_rule_file_tokens",
                    invalid_value=max_file,
                    message="Max rule file tokens must be a positive integer",
                )
            )

        # Check roles budget
        roles_val = tb_data.get("roles")
        if roles_val is not None:
            if not isinstance(roles_val, dict):
                errors.append(
                    SchemaValidationError(
                        path=f"{tb_prefix}.roles",
                        invalid_value=roles_val,
                        message="Roles token budget must be a dictionary mapping role names to integers",
                    )
                )
            else:
                for role_name, budget in roles_val.items():
                    if role_name not in STANDARD_ROLES:
                        errors.append(
                            SchemaValidationError(
                                path=f"{tb_prefix}.roles.{role_name}",
                                invalid_value=role_name,
                                message=(
                                    f"Invalid role '{role_name}', must be one of standard roles: "
                                    f"{', '.join(STANDARD_ROLES)}"
                                ),
                            )
                        )
                    if not isinstance(budget, int) or isinstance(budget, bool) or budget <= 0:
                        errors.append(
                            SchemaValidationError(
                                path=f"{tb_prefix}.roles.{role_name}",
                                invalid_value=budget,
                                message="Token budget must be a positive integer",
                            )
                        )

    # 3. Validate git branch configurations
    git_data = data.get("git")
    if git_data is not None and isinstance(git_data, dict):
        for field_name in ("allowed_push_branches", "prohibited_push_branches"):
            if field_name in git_data:
                val = git_data[field_name]
                if not isinstance(val, (list, tuple)):
                    errors.append(
                        SchemaValidationError(
                            path=f"git.{field_name}",
                            invalid_value=val,
                            message=f"{field_name} must be a list of strings",
                        )
                    )

    return len(errors) == 0, errors


# Alias for backwards compatibility
validate_config_dict = validate_config_schema


def find_config_file(start_path: str | pathlib.Path | None = None) -> pathlib.Path | None:
    """Auto-discover governance configuration file.

    Search hierarchy:
    1. Environment variable GOVERNANCE_CONFIG_PATH
    2. Candidate files in start_path:
       - project-hooks.yaml
       - project-hooks.yml
       - governance.config.json
       - .agents/project-hooks.yaml
       - .agents/governance.config.json
    3. Upward directory traversal from start_path to git root or filesystem boundary.
    """
    # 1. Environment variable override
    env_path = os.environ.get("GOVERNANCE_CONFIG_PATH")
    if env_path and env_path.strip():
        candidate = pathlib.Path(env_path.strip()).expanduser()
        if candidate.is_file():
            return candidate.resolve()
        # If specified path does not exist, log diagnostic and continue discovery
        log_config_warning(f"GOVERNANCE_CONFIG_PATH='{env_path}' does not exist on disk.")

    # 2. Determine initial directory
    if start_path is None:
        current_dir = pathlib.Path.cwd().resolve()
    else:
        current_dir = pathlib.Path(start_path).resolve()
        if current_dir.is_file():
            return current_dir

    candidate_filenames = (
        "project-hooks.yaml",
        "project-hooks.yml",
        "governance.config.json",
        pathlib.Path(".agents") / "project-hooks.yaml",
        pathlib.Path(".agents") / "project-hooks.yml",
        pathlib.Path(".agents") / "governance.config.json",
    )

    # 3. Upward traversal search loop
    visited_dirs: set[pathlib.Path] = set()
    while current_dir not in visited_dirs:
        visited_dirs.add(current_dir)

        # Check candidates in current_dir adhering to precedence order (YAML > JSON)
        for fname in candidate_filenames:
            target = current_dir / fname
            if target.is_file():
                return target.resolve()

        # Stop traversal if repository boundary (.git) is encountered
        if (current_dir / ".git").exists():
            break

        parent = current_dir.parent
        if parent == current_dir:
            break
        current_dir = parent

    return None


def _parse_file_content(path: pathlib.Path) -> dict[str, Any]:
    """Read and parse YAML or JSON file content with robust error handling.

    Raises:
        FileNotFoundError: If path does not exist.
        ValueError: If file is empty or content is not a dict.
        json.JSONDecodeError / yaml.YAMLError / UnicodeDecodeError: On syntax errors.
    """
    MAX_CONFIG_FILE_SIZE: int = 5 * 1024 * 1024  # 5MB limit

    try:
        f_stat = path.stat()
        if f_stat.st_size > MAX_CONFIG_FILE_SIZE:
            raise ValueError(
                f"Config file '{path.name}' exceeds maximum allowed size ({f_stat.st_size} > {MAX_CONFIG_FILE_SIZE} bytes)"
            )
    except OSError as exc:
        raise FileNotFoundError(f"Cannot access config file '{path.name}': {exc}")

    raw_bytes = path.read_bytes()
    if not raw_bytes or not raw_bytes.strip():
        raise ValueError(f"Config file '{path.name}' is empty (0 bytes)")

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnicodeDecodeError(exc.encoding, exc.object, exc.start, exc.end, f"Failed UTF-8 decode for '{path.name}'")

    if not text.strip():
        raise ValueError(f"Config file '{path.name}' contains only whitespace")

    def _reject_duplicates_json(data_str: str) -> Any:
        def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            d: dict[str, Any] = {}
            for k, v in pairs:
                if k in d:
                    raise ValueError(f"Duplicate key detected in config JSON: {k!r}")
                d[k] = v
            return d
        return json.loads(data_str, object_pairs_hook=_pairs_hook)

    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        if not HAS_YAML:
            # Fallback when PyYAML is unavailable: attempt JSON decoding
            try:
                data = _reject_duplicates_json(text)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(
                    f"PyYAML is not installed and file '{path.name}' cannot be parsed as JSON: {exc}"
                ) from exc
        else:
            data = yaml.safe_load(text)
    elif suffix == ".json":
        data = _reject_duplicates_json(text)
    else:
        # Unknown extension: try JSON first, then YAML
        try:
            data = _reject_duplicates_json(text)
        except (json.JSONDecodeError, ValueError):
            if HAS_YAML:
                data = yaml.safe_load(text)
            else:
                raise ValueError(f"Unsupported file extension '{suffix}' and PyYAML is not installed")

    if not isinstance(data, dict):
        raise TypeError(f"Config file '{path.name}' parsed to {type(data).__name__}, expected dictionary")

    return data


if HAS_YAML and yaml is not None:
    YAML_PARSE_ERRORS: tuple[type[Exception], ...] = (yaml.YAMLError,)
else:
    YAML_PARSE_ERRORS = ()


def load_governance_config(
    config_path: str | pathlib.Path | None = None,
    start_dir: str | pathlib.Path | None = None,
) -> GovernanceConfig:
    """Load governance configuration with Zero-Config Resilience.

    Never raises exceptions. Returns safe enterprise defaults on:
    - Missing config file (logs diagnostic info to stderr)
    - Empty config file (logs warning to stderr)
    - Syntax error in YAML/JSON (logs warning to stderr)
    - Binary or encoding error (logs warning to stderr)
    """
    target_path: pathlib.Path | None = None

    if config_path is not None:
        p = pathlib.Path(config_path).expanduser().resolve()
        if p.is_file():
            target_path = p
        else:
            log_config_warning(f"Specified config file '{config_path}' does not exist on disk.")

    if target_path is None:
        target_path = find_config_file(start_path=start_dir)

    # Graceful Fallback: No config file found
    if target_path is None:
        log_config_info("No config found, using Enterprise defaults")
        return GovernanceConfig(config_source=None)

    # Attempt to read and parse the discovered config file
    try:
        raw_dict = _parse_file_content(target_path)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        log_config_warning(f"Malformed config file in '{target_path.name}': {exc}, using Enterprise defaults")
        return GovernanceConfig(config_source=str(target_path))
    except UnicodeDecodeError as exc:
        log_config_warning(f"Binary or non-UTF8 content in '{target_path.name}': {exc}, using Enterprise defaults")
        return GovernanceConfig(config_source=str(target_path))
    except YAML_PARSE_ERRORS as exc:
        log_config_warning(f"Failed to load '{target_path.name}': {exc}, using Enterprise defaults")
        return GovernanceConfig(config_source=str(target_path))
    except (OSError, KeyError) as exc:
        log_config_warning(f"Failed to load '{target_path.name}': {exc}, using Enterprise defaults")
        return GovernanceConfig(config_source=str(target_path))

    try:
        return GovernanceConfig.from_dict(raw_dict, config_source=str(target_path))
    except Exception as exc:
        log_config_warning(f"Failed to load '{target_path.name}': {exc}, using Enterprise defaults")
        return GovernanceConfig(config_source=str(target_path))


_CACHED_CONFIG: GovernanceConfig | None = None


def get_governance_config(
    config_path: str | pathlib.Path | None = None,
    reload: bool = False,
) -> GovernanceConfig:
    """Obtain active GovernanceConfig instance, utilizing singleton cache unless reload=True."""
    global _CACHED_CONFIG
    if _CACHED_CONFIG is None or reload or config_path is not None:
        _CACHED_CONFIG = load_governance_config(config_path=config_path)
    return _CACHED_CONFIG


if __name__ == "__main__":
    cfg = get_governance_config()
    print(f"Loaded GovernanceConfig for: {cfg.project_name} (source: {cfg.config_source or 'DEFAULT'})")
    print(f"Allowed branches: {cfg.allowed_push_branches}")
    print(f"Prohibited branches: {cfg.prohibited_push_branches}")
    print(f"Force-push prohibited: {cfg.prohibit_force_push}")
    print(f"Protected tables: {len(cfg.protected_tables)} tables")
    print(f"Confidence threshold: {cfg.confidence_threshold}")
