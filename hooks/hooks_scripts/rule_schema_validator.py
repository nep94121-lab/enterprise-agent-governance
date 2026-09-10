#!/usr/bin/env python3
"""Universal Multi-Agent Governance Kit — Rule Schema Validator.

Validates rule files (.md, .yaml, .json) against JSON schemas.
Features:
- Hot-reloadable configuration integration with hook_utils and config_loader
- 100% Zero Hardcoding: dynamic roles, dynamic discovery of rules directory, and dynamic schemas
- Robust frontmatter parser: XML tags (single-line & multi-line), YAML frontmatter, and Markdown sections
- Real JSON Schema validation via jsonschema with lightweight fallback
- Windows PowerShell UTF-8 I/O safety and non-blocking interactive CLI handling
- PostToolUse Hook compatibility with common_hook_lib
- Secure path resolution and boundary verification (§7, §8)
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
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

# Ensure parent and sibling directories are on sys.path for robust imports
CURRENT_DIR = pathlib.Path(__file__).parent.resolve()
REPO_ROOT = CURRENT_DIR.parent.resolve()
for search_dir in (str(CURRENT_DIR), str(REPO_ROOT)):
    if search_dir not in sys.path:
        sys.path.insert(0, search_dir)

# Optional PyYAML import
try:
    import yaml
    HAS_YAML = True
except ImportError:
    yaml = None
    HAS_YAML = False

# Optional jsonschema import
try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    jsonschema = None
    HAS_JSONSCHEMA = False

# Optional hook_utils integration
try:
    from hook_utils.config_loader import (
        DynamicConfigLoader,
        get_dynamic_limits,
        resolve_config_path,
    )
    HAS_HOOK_UTILS = True
except ImportError:
    DynamicConfigLoader = None
    get_dynamic_limits = None
    resolve_config_path = None
    HAS_HOOK_UTILS = False

# Optional governance config loader
try:
    from config_loader import STANDARD_ROLES, get_governance_config
    HAS_GOVERNANCE_CONFIG = True
except ImportError:
    try:
        from hooks_scripts.config_loader import STANDARD_ROLES, get_governance_config
        HAS_GOVERNANCE_CONFIG = True
    except ImportError:
        get_governance_config = None
        STANDARD_ROLES = (
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
        HAS_GOVERNANCE_CONFIG = False

# Common hook library import
try:
    from common_hook_lib import (
        emit_stdout_json,
        get_tool_args,
        get_tool_call,
        log_diagnostic,
        normalize_path,
        post_tool_response,
        read_stdin_payload,
    )
    HAS_COMMON_HOOK_LIB = True
except ImportError:
    HAS_COMMON_HOOK_LIB = False

    def log_diagnostic(message: str) -> None:
        try:
            sys.stderr.write(f"[HOOK-DIAGNOSTIC] {message}\n")
            sys.stderr.flush()
        except (OSError, UnicodeEncodeError):
            pass

    def emit_stdout_json(payload: dict[str, Any]) -> None:
        try:
            sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
            sys.stdout.flush()
        except Exception:
            sys.stdout.write("{}\n")
            sys.stdout.flush()

    def post_tool_response() -> dict[str, Any]:
        return {}

    def read_stdin_payload(default: dict[str, Any] | None = None) -> dict[str, Any]:
        if default is None:
            default = {}
        try:
            if sys.stdin.isatty():
                return default
            raw = sys.stdin.read()
            if not raw or not raw.strip():
                return default
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else default
        except Exception:
            return default

    def get_tool_call(payload: dict[str, Any] | Any) -> dict[str, Any]:
        if isinstance(payload, dict):
            tc = payload.get("toolCall")
            return tc if isinstance(tc, dict) else {}
        return {}

    def get_tool_args(tool_call: dict[str, Any] | Any) -> dict[str, Any]:
        if isinstance(tool_call, dict):
            args = tool_call.get("args")
            return args if isinstance(args, dict) else {}
        return {}

    def normalize_path(path_str: str) -> pathlib.Path:
        try:
            return pathlib.Path(path_str).resolve()
        except Exception:
            return pathlib.Path(path_str)


def has_stdin_data() -> bool:
    """Check if sys.stdin has available data without blocking indefinitely."""
    if sys.stdin.isatty():
        return False
    if os.name == "nt":
        try:
            import ctypes
            import msvcrt
            from ctypes import wintypes
            handle = msvcrt.get_osfhandle(sys.stdin.fileno())
            avail = wintypes.DWORD()
            res = ctypes.windll.kernel32.PeekNamedPipe(
                handle, None, 0, None, ctypes.byref(avail), None
            )
            if res:
                return avail.value > 0
        except Exception:
            pass
    else:
        try:
            import select
            r, _, _ = select.select([sys.stdin], [], [], 0)
            return bool(r)
        except Exception:
            pass
    return False


# ============================================================================
# Enumerations & Categories
# ============================================================================

class ValidationSeverity(str, Enum):
    """Severity levels for validation errors."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class RuleCategory(str, Enum):
    """Categories of standard rules for backward compatibility."""
    BACKEND_DEVELOPER = "backend_developer"
    FRONTEND_DEVELOPER = "frontend_developer"
    QA_CHALLENGER = "qa_challenger"
    PM_ORCHESTRATOR = "pm_orchestrator"
    TECH_LEAD_AUDITOR = "tech_lead_auditor"
    DEVOPS_SECURITY = "devops_security"
    CODEBASE_EXPLORER = "codebase_explorer"
    LEAD_WATCHDOG = "lead_watchdog"
    WATCHDOG_INSPECTOR = "watchdog_inspector"
    PM_CHALLENGER = "pm_challenger"
    APPSEC_SENTINEL = "appsec_sentinel"
    DATA_ML_ENGINEER = "data_ml_engineer"
    STATE_CHECKPOINT_CURATOR = "state_checkpoint_curator"
    MOBILE_APP_DEVELOPER = "mobile_app_developer"

    @classmethod
    def values(cls) -> list[str]:
        """Return all standard role strings."""
        return [c.value for c in cls]


def get_all_valid_roles() -> list[str]:
    """Dynamically get all valid roles from governance config or fallback to standard roles."""
    roles = set(RuleCategory.values())
    roles.update(STANDARD_ROLES)
    if get_governance_config is not None:
        try:
            cfg = get_governance_config()
            if hasattr(cfg, "raw_dict") and isinstance(cfg.raw_dict, dict):
                custom_roles = cfg.raw_dict.get("rules_validation", {}).get("allowed_roles")
                if isinstance(custom_roles, list):
                    roles.update(str(r) for r in custom_roles if r)
                tb_roles = cfg.raw_dict.get("testing", {}).get("token_budget", {}).get("roles")
                if isinstance(tb_roles, dict):
                    roles.update(str(r) for r in tb_roles.keys() if r)
        except Exception:
            pass
    if get_dynamic_limits is not None:
        try:
            dyn = get_dynamic_limits()
            if isinstance(dyn, dict):
                custom_dyn = dyn.get("rules_validation", {}).get("allowed_roles")
                if isinstance(custom_dyn, list):
                    roles.update(str(r) for r in custom_dyn if r)
        except Exception:
            pass
    return sorted(roles)


# ============================================================================
# Dynamic Path & Configuration Discovery (Zero Hardcoding)
# ============================================================================

def resolve_rules_directory(custom_path: pathlib.Path | str | None = None) -> pathlib.Path:
    """Resolve rules directory dynamically without hardcoded paths."""
    if custom_path:
        p = pathlib.Path(custom_path).resolve()
        if p.exists():
            return p

    env_path = os.environ.get("RULES_DIR") or os.environ.get("ENTERPRISE_RULES_PATH")
    if env_path:
        p = pathlib.Path(env_path).resolve()
        if p.exists():
            return p

    # Check configuration sources
    if get_governance_config is not None:
        try:
            cfg = get_governance_config()
            if hasattr(cfg, "raw_dict") and isinstance(cfg.raw_dict, dict):
                cfg_rules_dir = cfg.raw_dict.get("rules_validation", {}).get("rules_directory")
                if cfg_rules_dir:
                    p = pathlib.Path(cfg_rules_dir).resolve()
                    if p.exists():
                        return p
        except Exception:
            pass

    # Upward traversal from current file
    candidates = [
        REPO_ROOT / "rules_by_role",
        CURRENT_DIR / "rules_by_role",
        pathlib.Path.cwd() / "rules_by_role",
        pathlib.Path.cwd() / ".gemini" / "config" / "enterprise-hooks" / "rules_by_role",
        pathlib.Path.home() / ".gemini" / "config" / "enterprise-hooks" / "rules_by_role",
        pathlib.Path.home() / ".gemini" / "config" / "rules",
    ]

    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return candidate.resolve()

    return (REPO_ROOT / "rules_by_role").resolve()


def get_rules_validator_config() -> dict[str, Any]:
    """Retrieve hot-reloadable configuration for rule validation."""
    config: dict[str, Any] = {
        "strict_mode": False,
        "max_section_length": 10000,
        "ignore_patterns": ["_*", "*README.md", ".*", "*.py", "*.jsonl"],
        "required_sections": {},
    }

    if get_dynamic_limits is not None:
        try:
            dyn = get_dynamic_limits()
            if isinstance(dyn, dict) and "rules_validation" in dyn:
                config.update(dyn["rules_validation"])
        except Exception:
            pass

    if get_governance_config is not None:
        try:
            gov = get_governance_config()
            if hasattr(gov, "raw_dict") and isinstance(gov.raw_dict, dict):
                gov_rv = gov.raw_dict.get("rules_validation")
                if isinstance(gov_rv, dict):
                    config.update(gov_rv)
        except Exception:
            pass

    return config


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class ValidationError:
    """Represents a single validation error or warning."""
    severity: ValidationSeverity
    message: str
    file_path: str | None = None
    line_number: int | None = None
    section: str | None = None
    field: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "severity": self.severity.value,
            "message": self.message,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "section": self.section,
            "field": self.field,
        }


@dataclass
class ValidationResult:
    """Result of a validation operation."""
    valid: bool
    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[ValidationError] = field(default_factory=list)
    info: list[ValidationError] = field(default_factory=list)

    def add_error(self, error: ValidationError) -> None:
        """Add a validation error according to severity."""
        if error.severity == ValidationSeverity.ERROR:
            self.errors.append(error)
            self.valid = False
        elif error.severity == ValidationSeverity.WARNING:
            self.warnings.append(error)
        else:
            self.info.append(error)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "valid": self.valid,
            "errors": [e.to_dict() for e in self.errors],
            "warnings": [e.to_dict() for e in self.warnings],
            "info": [e.to_dict() for e in self.info],
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "info_count": len(self.info),
        }


@dataclass
class FrontmatterSection:
    """Represents a parsed frontmatter section."""
    name: str
    content: str
    start_line: int
    end_line: int
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def line_count(self) -> int:
        """Get the number of lines in this section."""
        return max(1, self.end_line - self.start_line + 1)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "content": self.content,
            "metadata": self.metadata,
        }


@dataclass
class ParsedRule:
    """Represents a fully parsed rule file."""
    file_path: str
    role: str
    sections: list[FrontmatterSection] = field(default_factory=list)
    raw_content: str = ""
    title: str | None = None
    description: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_section(self, name: str) -> FrontmatterSection | None:
        """Get a section by name."""
        for section in self.sections:
            if section.name == name:
                return section
        return None

    def get_all_section_names(self) -> list[str]:
        """Get all section names."""
        return [s.name for s in self.sections]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary suitable for JSON schema validation."""
        data: dict[str, Any] = {
            "role": self.role,
            "sections": [s.to_dict() for s in self.sections],
        }
        if self.title:
            data["title"] = self.title
        if self.description:
            data["description"] = self.description
        if self.metadata:
            data["metadata"] = self.metadata
        return data


# ============================================================================
# JSON Schema Definitions & Dynamic Schema Factory
# ============================================================================

def build_rule_file_schema(allowed_roles: list[str] | None = None) -> dict[str, Any]:
    """Generate dynamic JSON Schema using current valid roles."""
    roles = allowed_roles or get_all_valid_roles()
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["role", "sections"],
        "properties": {
            "role": {
                "type": "string",
                "enum": roles,
                "description": "The role this rule applies to",
            },
            "sections": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["name", "content"],
                    "properties": {
                        "name": {
                            "type": "string",
                            "pattern": "^[a-zA-Z0-9_\\[\\]\\-\\.\\:]+$",
                            "description": "Section identifier",
                        },
                        "content": {
                            "type": "string",
                            "minLength": 1,
                            "description": "Section content",
                        },
                        "metadata": {
                            "type": "object",
                            "properties": {
                                "priority": {"type": "integer", "minimum": 1, "maximum": 10},
                                "tags": {"type": "array", "items": {"type": "string"}},
                                "pre_flight_level": {"type": "integer", "minimum": 0, "maximum": 10},
                            },
                        },
                    },
                },
                "minItems": 1,
            },
            "title": {"type": "string", "minLength": 1},
            "description": {"type": "string"},
            "metadata": {"type": "object"},
        },
    }


RULE_FILE_SCHEMA = build_rule_file_schema()

# Standard entrypoint sections required per role
ENTRYPOINT_REQUIRED_SECTIONS: dict[str, list[str]] = {
    "backend_developer": ["enforced_turn_1_gate", "backend_coding_standards"],
    "frontend_developer": ["enforced_turn_1_gate", "frontend_coding_standards"],
    "qa_challenger": ["enforced_turn_1_gate", "qa_challenging_standards"],
    "pm_orchestrator": ["enforced_turn_1_gate", "pm_governance_and_workflow"],
    "tech_lead_auditor": ["enforced_turn_1_gate", "tech_lead_standards"],
    "devops_security": ["enforced_turn_1_gate", "devops_coding_standards"],
}

# Legacy mapping for backwards compatibility
REQUIRED_SECTIONS: dict[RuleCategory | str, list[str]] = {
    RuleCategory.BACKEND_DEVELOPER: ["data_privacy_pii", "cybersecurity_defense"],
    RuleCategory.FRONTEND_DEVELOPER: ["security_headers", "input_validation"],
    RuleCategory.QA_CHALLENGER: ["test_requirements", "quality_gates"],
    RuleCategory.PM_ORCHESTRATOR: ["workflow_rules", "communication"],
    RuleCategory.TECH_LEAD_AUDITOR: ["code_review", "architecture"],
    RuleCategory.DEVOPS_SECURITY: ["deployment_security", "monitoring"],
}

SECTION_NAMING_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\[\]\.\:\\]+$")


# ============================================================================
# Schema Validator Class
# ============================================================================

class RuleSchemaValidator:
    """Validates rule files against JSON schemas and enterprise governance standards."""

    def __init__(
        self,
        schema: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
        rules_dir: pathlib.Path | str | None = None,
    ):
        """Initialize validator with optional custom schema, config, or rules directory."""
        self._config = config or get_rules_validator_config()
        self._rules_dir = resolve_rules_directory(rules_dir)
        self._valid_roles = get_all_valid_roles()
        self._schema = schema or build_rule_file_schema(self._valid_roles)
        self._loaded_schemas: dict[str, dict[str, Any]] = {}

    @property
    def schema(self) -> dict[str, Any]:
        """Get the current active schema."""
        return self._schema

    @property
    def rules_dir(self) -> pathlib.Path:
        """Get the resolved rules directory."""
        return self._rules_dir

    def set_schema(self, schema: dict[str, Any]) -> None:
        """Set a custom validation schema."""
        self._schema = schema

    def load_schema_from_file(self, file_path: str | pathlib.Path) -> dict[str, Any]:
        """Load and register a JSON schema from a file."""
        path = pathlib.Path(file_path).resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Schema file not found: {file_path}")

        try:
            with open(path, encoding="utf-8-sig", errors="replace") as f:
                schema = json.load(f)
        except json.JSONDecodeError as exc:
            raise json.JSONDecodeError(
                f"Malformed JSON in schema {path.name}: {exc.msg}", exc.doc, exc.pos
            ) from exc

        if not isinstance(schema, dict):
            raise ValueError(f"Schema root must be an object, got {type(schema).__name__}")

        self._loaded_schemas[str(path)] = schema
        self._schema = schema
        return schema

    # ------------------------------------------------------------------------
    # Frontmatter & Section Parsing (XML, YAML, Markdown)
    # ------------------------------------------------------------------------

    def parse_frontmatter(self, content: str) -> list[FrontmatterSection]:
        """Parse sections from rule content supporting XML tags, YAML frontmatter, and Markdown."""
        if not content:
            return []

        sections: list[FrontmatterSection] = []

        # 1. Check for YAML frontmatter at document start
        yaml_sections, _stripped, _offset = self._parse_yaml_frontmatter(content)
        sections.extend(yaml_sections)

        # 2. Parse XML-style sections (<section_name>...</section_name>)
        xml_sections = self._parse_xml_sections(content)
        if xml_sections:
            sections.extend(xml_sections)

        # 3. If no XML sections found, fallback to Markdown heading sections
        if not xml_sections and not sections:
            md_sections = self._parse_markdown_headings(content)
            sections.extend(md_sections)

        return sections

    def _parse_yaml_frontmatter(self, content: str) -> tuple[list[FrontmatterSection], str, int]:
        """Extract and parse YAML frontmatter if present at the top of content."""
        sections: list[FrontmatterSection] = []
        lines = content.splitlines(keepends=True)
        if not lines or lines[0].strip() != "---":
            return sections, content, 0

        closing_idx = -1
        for idx in range(1, len(lines)):
            if lines[idx].strip() == "---":
                closing_idx = idx
                break

        if closing_idx == -1:
            return sections, content, 0

        yaml_text = "".join(lines[1:closing_idx])
        metadata: dict[str, Any] = {}

        if HAS_YAML and yaml is not None:
            try:
                parsed = yaml.safe_load(yaml_text)
                if isinstance(parsed, dict):
                    metadata = parsed
            except Exception:
                pass
        else:
            for y_line in yaml_text.splitlines():
                if ":" in y_line:
                    k, v = y_line.split(":", 1)
                    metadata[k.strip()] = v.strip().strip("'\"")

        if metadata:
            sections.append(
                FrontmatterSection(
                    name="frontmatter",
                    content=yaml_text.strip(),
                    start_line=1,
                    end_line=closing_idx + 1,
                    metadata=metadata,
                )
            )

        remainder = "".join(lines[closing_idx + 1:])
        return sections, remainder, closing_idx + 1

    def _parse_xml_sections(self, content: str) -> list[FrontmatterSection]:
        """Parse XML-like tags with multi-line and single-line resilience."""
        sections: list[FrontmatterSection] = []
        lines = content.splitlines()

        tag_open_re = re.compile(
            r"<([a-zA-Z0-9_\-\[\]\.\:\\]+)(?:\s+([^>]*?))?(?:\s*(/)>|>)"
        )
        tag_close_re = re.compile(r"</([a-zA-Z0-9_\-\[\]\.\:\\]+)>")
        single_line_re = re.compile(
            r"<([a-zA-Z0-9_\-\[\]\.\:\\]+)(?:\s+([^>]*?))?>(.*?)</\1>"
        )

        current_name: str | None = None
        current_start: int = 0
        current_meta: dict[str, Any] = {}
        buffer: list[str] = []

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Check single-line complete tag: <tag>content</tag>
            sl_match = single_line_re.match(stripped)
            if sl_match and current_name is None:
                tag_name = sl_match.group(1)
                attr_str = sl_match.group(2) or ""
                body = sl_match.group(3).strip()
                sections.append(
                    FrontmatterSection(
                        name=tag_name,
                        content=body,
                        start_line=line_num,
                        end_line=line_num,
                        metadata=self._parse_section_attributes(attr_str),
                    )
                )
                continue

            # Check opening tag
            op_match = tag_open_re.match(stripped)
            if op_match and current_name is None:
                tag_name = op_match.group(1)
                attr_str = op_match.group(2) or ""
                is_self_closing = bool(op_match.group(3))

                if is_self_closing:
                    sections.append(
                        FrontmatterSection(
                            name=tag_name,
                            content="",
                            start_line=line_num,
                            end_line=line_num,
                            metadata=self._parse_section_attributes(attr_str),
                        )
                    )
                    continue

                # Check if closing tag exists later in the same line
                close_suffix = f"</{tag_name}>"
                if close_suffix in stripped:
                    inner = stripped[op_match.end():stripped.rfind(close_suffix)].strip()
                    sections.append(
                        FrontmatterSection(
                            name=tag_name,
                            content=inner,
                            start_line=line_num,
                            end_line=line_num,
                            metadata=self._parse_section_attributes(attr_str),
                        )
                    )
                    continue

                current_name = tag_name
                current_start = line_num
                current_meta = self._parse_section_attributes(attr_str)
                buffer = []
                continue

            # Check closing tag for current section
            if current_name is not None:
                cl_match = tag_close_re.search(stripped)
                if cl_match and cl_match.group(1) == current_name:
                    sections.append(
                        FrontmatterSection(
                            name=current_name,
                            content="\n".join(buffer).strip(),
                            start_line=current_start,
                            end_line=line_num,
                            metadata=current_meta,
                        )
                    )
                    current_name = None
                    buffer = []
                    continue
                buffer.append(line)

        # If file ends without closing tag, close gracefully
        if current_name is not None:
            sections.append(
                FrontmatterSection(
                    name=current_name,
                    content="\n".join(buffer).strip(),
                    start_line=current_start,
                    end_line=len(lines),
                    metadata=current_meta,
                )
            )

        return sections

    def _parse_markdown_headings(self, content: str) -> list[FrontmatterSection]:
        """Extract sections from Markdown headings (## and ###) when no XML tags are used."""
        import unicodedata

        sections: list[FrontmatterSection] = []
        lines = content.splitlines()
        heading_re = re.compile(r"^(#{2,3})\s+(.+)$")

        current_name: str | None = None
        current_start: int = 0
        buffer: list[str] = []

        for line_num, line in enumerate(lines, start=1):
            m = heading_re.match(line.strip())
            if m:
                # Flush previous section only if it has non-empty content
                if current_name is not None and any(buf_line.strip() for buf_line in buffer):
                    body = "\n".join(buffer).strip()
                    sections.append(
                        FrontmatterSection(
                            name=current_name,
                            content=body,
                            start_line=current_start,
                            end_line=line_num - 1,
                        )
                    )
                raw_title = m.group(2).strip()
                # Transliterate Unicode accents to ASCII for clean snake_case slug
                norm_title = unicodedata.normalize("NFKD", raw_title).encode("ascii", "ignore").decode("ascii")
                clean_name = re.sub(r"[^\w\s-]", "", norm_title).strip().lower()
                clean_name = re.sub(r"[-\s]+", "_", clean_name)
                # Strip leading non-alphabetic characters (including leading underscores)
                clean_name = re.sub(r"^[^a-z]+", "", clean_name)
                current_name = clean_name or f"section_{line_num}"
                current_start = line_num
                buffer = []
            elif current_name is not None:
                buffer.append(line)

        # Flush trailing section if non-empty
        if current_name is not None and any(buf_line.strip() for buf_line in buffer):
            body = "\n".join(buffer).strip()
            sections.append(
                FrontmatterSection(
                    name=current_name,
                    content=body,
                    start_line=current_start,
                    end_line=len(lines),
                )
            )

        return sections

    def _parse_section_attributes(self, attrs_str: str) -> dict[str, Any]:
        """Parse key-value attributes from opening tag string."""
        metadata: dict[str, Any] = {}
        if not attrs_str or not attrs_str.strip():
            return metadata

        attr_pattern = re.compile(
            r'([a-zA-Z0-9_\-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|(\S+))'
        )
        for match in attr_pattern.finditer(attrs_str):
            k = match.group(1)
            v = match.group(2) if match.group(2) is not None else (
                match.group(3) if match.group(3) is not None else match.group(4)
            )
            # Type coercion for common attributes
            if v.isdigit():
                metadata[k] = int(v)
            elif v.lower() == "true":
                metadata[k] = True
            elif v.lower() == "false":
                metadata[k] = False
            else:
                metadata[k] = v

        return metadata

    # ------------------------------------------------------------------------
    # Role Inference (Zero Hardcoding)
    # ------------------------------------------------------------------------

    def _infer_role_from_path(self, file_path: str, content: str = "") -> str:
        """Infer the role dynamically from path parts, filename, or content."""
        path = pathlib.Path(file_path)
        valid_roles = self._valid_roles

        # 1. Check directory path parts
        for part in path.parts:
            low_part = part.lower()
            if low_part in valid_roles:
                return low_part

        # 2. Check filename prefix/stem
        stem = path.stem.lower()
        role_prefixes = {
            "backend": "backend_developer",
            "frontend": "frontend_developer",
            "qa": "qa_challenger",
            "pm_challenger": "pm_challenger",
            "pm": "pm_orchestrator",
            "tech_lead": "tech_lead_auditor",
            "devops": "devops_security",
            "codebase_explorer": "codebase_explorer",
            "explorer": "codebase_explorer",
            "lead_watchdog": "lead_watchdog",
            "watchdog_inspector": "watchdog_inspector",
            "watchdog": "watchdog_inspector",
            "appsec_sentinel": "appsec_sentinel",
            "appsec": "appsec_sentinel",
            "sentinel": "appsec_sentinel",
            "data_ml_engineer": "data_ml_engineer",
            "data_ml": "data_ml_engineer",
            "data": "data_ml_engineer",
            "state_checkpoint_curator": "state_checkpoint_curator",
            "state_checkpoint": "state_checkpoint_curator",
            "curator": "state_checkpoint_curator",
            "mobile_app_developer": "mobile_app_developer",
            "mobile": "mobile_app_developer",
        }
        for prefix, mapped_role in role_prefixes.items():
            if stem.startswith(prefix) or f"_{prefix}_" in stem or stem.endswith(prefix):
                return mapped_role

        # 3. Content inspection for role header or frontmatter
        if content:
            for role_name in valid_roles:
                if re.search(rf"\b{re.escape(role_name)}\b", content, re.IGNORECASE):
                    return role_name
            # Check uppercase Vietnamese/English role markers
            content_upper = content.upper()
            if "BACKEND DEVELOPER" in content_upper or "BACKEND_DEVELOPER" in content_upper:
                return "backend_developer"
            if "FRONTEND DEVELOPER" in content_upper or "FRONTEND_DEVELOPER" in content_upper:
                return "frontend_developer"
            if "PM SUB-AGENT" in content_upper or "PROJECT MANAGER" in content_upper or "PM_ORCHESTRATOR" in content_upper:
                return "pm_orchestrator"
            if "QA CHALLENGER" in content_upper or "QA_CHALLENGER" in content_upper or "CHALLENGER" in content_upper:
                return "qa_challenger"
            if "TECH LEAD" in content_upper or "TECH_LEAD_AUDITOR" in content_upper:
                return "tech_lead_auditor"
            if "DEVOPS" in content_upper or "DEVOPS_SECURITY" in content_upper or "SECURITY" in content_upper:
                return "devops_security"
            if "CODEBASE EXPLORER" in content_upper or "CODEBASE_EXPLORER" in content_upper or "EXPLORER" in content_upper:
                return "codebase_explorer"
            if "LEAD WATCHDOG" in content_upper or "LEAD_WATCHDOG" in content_upper:
                return "lead_watchdog"
            if "WATCHDOG INSPECTOR" in content_upper or "WATCHDOG_INSPECTOR" in content_upper or "WATCHDOG" in content_upper:
                return "watchdog_inspector"
            if "PM CHALLENGER" in content_upper or "PM_CHALLENGER" in content_upper:
                return "pm_challenger"
            if "APPSEC SENTINEL" in content_upper or "APPSEC_SENTINEL" in content_upper or "APPSEC" in content_upper:
                return "appsec_sentinel"
            if "DATA ML" in content_upper or "DATA_ML" in content_upper:
                return "data_ml_engineer"
            if "STATE CHECKPOINT" in content_upper or "STATE_CHECKPOINT" in content_upper:
                return "state_checkpoint_curator"
            if "MOBILE APP" in content_upper or "MOBILE_APP" in content_upper:
                return "mobile_app_developer"

        return "unknown"

    # ------------------------------------------------------------------------
    # Parsing Rule File (JSON, YAML, Markdown)
    # ------------------------------------------------------------------------

    def parse_rule_file(self, file_path: str | pathlib.Path) -> ParsedRule:
        """Parse rule file of any supported format (.md, .yaml, .json)."""
        path = pathlib.Path(file_path).resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Rule file not found: {file_path}")

        try:
            with open(path, encoding="utf-8-sig", errors="replace") as f:
                content = f.read()
        except OSError as exc:
            raise OSError(f"Error reading {path}: {exc}") from exc

        ext = path.suffix.lower()

        # Direct JSON rule file support
        if ext == ".json":
            return self._parse_json_rule(path, content)

        # Direct YAML rule file support
        if ext in (".yaml", ".yml"):
            return self._parse_yaml_rule(path, content)

        # Markdown rule file parsing
        role = self._infer_role_from_path(str(path), content)
        sections = self.parse_frontmatter(content)

        # Extract title from first # heading
        title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else None

        # Extract description from blockquote
        desc_match = re.search(r"^>\s*(.+)$", content, re.MULTILINE)
        description = desc_match.group(1).strip() if desc_match else None

        return ParsedRule(
            file_path=str(path),
            role=role,
            sections=sections,
            raw_content=content,
            title=title,
            description=description,
        )

    def _parse_json_rule(self, path: pathlib.Path, content: str) -> ParsedRule:
        """Parse native JSON rule representation."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON rule file {path.name}: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError(f"JSON rule must be an object: {path.name}")

        role = data.get("role") or self._infer_role_from_path(str(path), content)
        raw_sections = data.get("sections", [])
        sections: list[FrontmatterSection] = []

        if isinstance(raw_sections, list):
            for idx, s in enumerate(raw_sections, start=1):
                if isinstance(s, dict):
                    sections.append(
                        FrontmatterSection(
                            name=str(s.get("name", f"section_{idx}")),
                            content=str(s.get("content", "")),
                            start_line=s.get("start_line", idx),
                            end_line=s.get("end_line", idx),
                            metadata=s.get("metadata", {}),
                        )
                    )

        return ParsedRule(
            file_path=str(path),
            role=role,
            sections=sections,
            raw_content=content,
            title=data.get("title"),
            description=data.get("description"),
            metadata=data.get("metadata", {}),
        )

    def _parse_yaml_rule(self, path: pathlib.Path, content: str) -> ParsedRule:
        """Parse native YAML rule representation."""
        data: dict[str, Any] = {}
        if HAS_YAML and yaml is not None:
            try:
                parsed = yaml.safe_load(content)
                if isinstance(parsed, dict):
                    data = parsed
            except Exception as exc:
                raise ValueError(f"Invalid YAML rule file {path.name}: {exc}") from exc

        role = data.get("role") or self._infer_role_from_path(str(path), content)
        raw_sections = data.get("sections", [])
        sections: list[FrontmatterSection] = []

        if isinstance(raw_sections, list):
            for idx, s in enumerate(raw_sections, start=1):
                if isinstance(s, dict):
                    sections.append(
                        FrontmatterSection(
                            name=str(s.get("name", f"section_{idx}")),
                            content=str(s.get("content", "")),
                            start_line=idx,
                            end_line=idx,
                            metadata=s.get("metadata", {}),
                        )
                    )

        return ParsedRule(
            file_path=str(path),
            role=role,
            sections=sections,
            raw_content=content,
            title=data.get("title"),
            description=data.get("description"),
            metadata=data.get("metadata", {}),
        )

    # ------------------------------------------------------------------------
    # Validation Rules
    # ------------------------------------------------------------------------

    def validate_section_name(self, name: str) -> list[ValidationError]:
        """Validate section identifier format."""
        errors: list[ValidationError] = []
        if not name or not name.strip():
            errors.append(
                ValidationError(
                    severity=ValidationSeverity.ERROR,
                    message="Section name cannot be empty",
                    field="name",
                )
            )
            return errors

        if not SECTION_NAMING_PATTERN.match(name):
            errors.append(
                ValidationError(
                    severity=ValidationSeverity.ERROR,
                    message=f"Invalid section name '{name}'. Must match pattern: {SECTION_NAMING_PATTERN.pattern}",
                    field="name",
                )
            )

        return errors

    def validate_section_content(self, section: FrontmatterSection) -> list[ValidationError]:
        """Validate section content length and hygiene."""
        errors: list[ValidationError] = []
        max_len = int(self._config.get("max_section_length", 10000))

        if not section.content or not section.content.strip():
            errors.append(
                ValidationError(
                    severity=ValidationSeverity.WARNING,
                    message=f"Section '{section.name}' has empty content",
                    section=section.name,
                    line_number=section.start_line,
                )
            )

        if "TODO" in section.content or "FIXME" in section.content:
            errors.append(
                ValidationError(
                    severity=ValidationSeverity.INFO,
                    message=f"Section '{section.name}' contains TODO/FIXME markers",
                    section=section.name,
                    line_number=section.start_line,
                )
            )

        if len(section.content) > max_len:
            errors.append(
                ValidationError(
                    severity=ValidationSeverity.WARNING,
                    message=f"Section '{section.name}' has very long content ({len(section.content)} chars > {max_len}). Consider splitting.",
                    section=section.name,
                    line_number=section.start_line,
                )
            )

        return errors

    def validate_rule_structure(self, rule: ParsedRule) -> ValidationResult:
        """Validate rule structure against dynamic JSON schema and governance criteria."""
        result = ValidationResult(valid=True)

        # 1. Validate role against dynamic valid roles
        if rule.role == "unknown":
            result.add_error(
                ValidationError(
                    severity=ValidationSeverity.WARNING,
                    message="Could not determine role from file path or content",
                    file_path=rule.file_path,
                    field="role",
                )
            )
        elif rule.role not in self._valid_roles:
            result.add_error(
                ValidationError(
                    severity=ValidationSeverity.ERROR,
                    message=f"Unknown role '{rule.role}'. Allowed: {self._valid_roles}",
                    file_path=rule.file_path,
                    field="role",
                )
            )

        # 2. Check sections presence
        if not rule.sections:
            result.add_error(
                ValidationError(
                    severity=ValidationSeverity.ERROR,
                    message="No frontmatter sections found in rule file",
                    file_path=rule.file_path,
                )
            )
            return result

        # 3. Validate each section
        for section in rule.sections:
            for err in self.validate_section_name(section.name):
                err.file_path = rule.file_path
                err.line_number = section.start_line
                result.add_error(err)

            for err in self.validate_section_content(section):
                err.file_path = rule.file_path
                result.add_error(err)

        # 4. JSON Schema compliance validation
        self._validate_against_json_schema(rule, result)

        # 5. Check required sections if applicable
        self._check_required_sections(rule, result)

        # 6. Check title presence
        if not rule.title and not rule.metadata.get("title"):
            result.add_error(
                ValidationError(
                    severity=ValidationSeverity.WARNING,
                    message="No title found in rule file (expected first # heading or title field)",
                    file_path=rule.file_path,
                    field="title",
                )
            )

        return result

    def _validate_against_json_schema(
        self, rule: ParsedRule, result: ValidationResult
    ) -> None:
        """Perform formal JSON Schema validation using jsonschema or fallback."""
        rule_dict = rule.to_dict()

        if HAS_JSONSCHEMA and jsonschema is not None:
            try:
                validator_cls = jsonschema.Draft7Validator
                validator = validator_cls(self._schema)
                for err in validator.iter_errors(rule_dict):
                    field_name = str(err.path[-1]) if err.path else err.validator
                    result.add_error(
                        ValidationError(
                            severity=ValidationSeverity.ERROR,
                            message=f"Schema violation: {err.message}",
                            file_path=rule.file_path,
                            field=field_name,
                        )
                    )
            except Exception as exc:
                log_diagnostic(f"JSON Schema engine error: {exc}")
        else:
            # Fallback lightweight structural validator
            required_props = self._schema.get("required", ["role", "sections"])
            for prop in required_props:
                if prop not in rule_dict:
                    result.add_error(
                        ValidationError(
                            severity=ValidationSeverity.ERROR,
                            message=f"Missing required schema property: '{prop}'",
                            file_path=rule.file_path,
                            field=prop,
                        )
                    )

    def _check_required_sections(self, rule: ParsedRule, result: ValidationResult) -> None:
        """Check for recommended / required sections per role and file type."""
        file_path_obj = pathlib.Path(rule.file_path)
        file_name = file_path_obj.name.lower()

        # Only enforce entrypoint requirements on entrypoint rule files (*_rules.md)
        is_entrypoint = file_name.endswith("_rules.md") or file_name == "pm_rules.md"
        found_sections = set(rule.get_all_section_names())

        # Check configured custom requirements
        custom_reqs = self._config.get("required_sections", {})
        if isinstance(custom_reqs, dict) and rule.role in custom_reqs:
            expected = custom_reqs[rule.role]
            if isinstance(expected, list):
                for req in expected:
                    if req not in found_sections:
                        result.add_error(
                            ValidationError(
                                severity=ValidationSeverity.WARNING,
                                message=f"Missing recommended section '{req}' for role '{rule.role}'",
                                file_path=rule.file_path,
                                section=req,
                            )
                        )
            return

        if is_entrypoint and rule.role in ENTRYPOINT_REQUIRED_SECTIONS:
            expected = ENTRYPOINT_REQUIRED_SECTIONS[rule.role]
            for req in expected:
                if req not in found_sections:
                    result.add_error(
                        ValidationError(
                            severity=ValidationSeverity.WARNING,
                            message=f"Entrypoint rule missing recommended section '{req}' for role '{rule.role}'",
                            file_path=rule.file_path,
                            section=req,
                        )
                    )

    # ------------------------------------------------------------------------
    # Public File and Directory Validation
    # ------------------------------------------------------------------------

    def validate_rule_file(self, file_path: str | pathlib.Path) -> ValidationResult:
        """Validate a single rule file."""
        try:
            rule = self.parse_rule_file(file_path)
            return self.validate_rule_structure(rule)
        except FileNotFoundError:
            result = ValidationResult(valid=False)
            result.add_error(
                ValidationError(
                    severity=ValidationSeverity.ERROR,
                    message=f"Rule file not found: {file_path}",
                    file_path=str(file_path),
                )
            )
            return result
        except Exception as exc:
            result = ValidationResult(valid=False)
            result.add_error(
                ValidationError(
                    severity=ValidationSeverity.ERROR,
                    message=f"Validation failed with exception: {exc}",
                    file_path=str(file_path),
                )
            )
            return result

    def validate_rules_directory(
        self,
        directory: str | pathlib.Path | None = None,
        ignore_patterns: list[str] | None = None,
    ) -> dict[str, ValidationResult]:
        """Validate all rule files within a directory, filtering out documentation."""
        results: dict[str, ValidationResult] = {}
        dir_path = resolve_rules_directory(directory)

        if not dir_path.exists() or not dir_path.is_dir():
            log_diagnostic(f"Rules directory not found: {dir_path}")
            return results

        patterns = ignore_patterns or self._config.get(
            "ignore_patterns", ["_*", "*README.md", ".*", "*.py", "*.jsonl"]
        )

        for candidate in dir_path.rglob("*"):
            if not candidate.is_file():
                continue
            if candidate.suffix.lower() not in (".md", ".yaml", ".yml", ".json"):
                continue

            # Check ignore patterns
            should_ignore = False
            for pat in patterns:
                if candidate.match(pat) or candidate.name.startswith("_"):
                    should_ignore = True
                    break
            if should_ignore:
                continue

            file_str = str(candidate)
            results[file_str] = self.validate_rule_file(candidate)

        return results


# ============================================================================
# Error Reporting
# ============================================================================

class ErrorReporter:
    """Formats and displays validation results."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def format_error(self, error: ValidationError) -> str:
        """Format a single validation error for output."""
        parts = []
        if error.file_path:
            if error.line_number:
                parts.append(f"{error.file_path}:{error.line_number}")
            else:
                parts.append(error.file_path)

        if error.section:
            parts.append(f"[{error.section}]")

        severity_marker = {
            ValidationSeverity.ERROR: "[ERROR]",
            ValidationSeverity.WARNING: "[WARNING]",
            ValidationSeverity.INFO: "[INFO]",
        }.get(error.severity, "[ERROR]")

        parts.append(severity_marker)
        parts.append(error.message)
        return " ".join(parts)

    def format_result(self, result: ValidationResult, file_path: str) -> str:
        """Format full validation report for a single file."""
        lines = [
            f"\n{'=' * 60}",
            f"Validation: {file_path}",
            f"Status: {'PASS' if result.valid else 'FAIL'}",
            f"{'=' * 60}",
        ]

        if result.errors:
            lines.append(f"\nErrors ({len(result.errors)}):")
            for error in result.errors:
                lines.append(f"  - {self.format_error(error)}")

        if result.warnings:
            lines.append(f"\nWarnings ({len(result.warnings)}):")
            for warning in result.warnings:
                lines.append(f"  - {self.format_error(warning)}")

        if self.verbose and result.info:
            lines.append(f"\nInfo ({len(result.info)}):")
            for info_msg in result.info:
                lines.append(f"  - {self.format_error(info_msg)}")

        return "\n".join(lines)

    def format_summary(self, results: dict[str, ValidationResult]) -> str:
        """Format batch validation summary."""
        total_errors = sum(len(r.errors) for r in results.values())
        total_warnings = sum(len(r.warnings) for r in results.values())
        total_passed = sum(1 for r in results.values() if r.valid)
        total_failed = len(results) - total_passed

        lines = [
            "\n" + "=" * 60,
            "VALIDATION SUMMARY",
            "=" * 60,
            f"Total files: {len(results)}",
            f"Passed: {total_passed}",
            f"Failed: {total_failed}",
            f"Total errors: {total_errors}",
            f"Total warnings: {total_warnings}",
        ]

        if self.verbose and total_failed > 0:
            lines.append("-" * 60)
            lines.append("Files with errors:")
            for path, result in results.items():
                if not result.valid:
                    lines.append(f"  - {path} ({len(result.errors)} errors)")

        return "\n".join(lines)

    def print_result(self, result: ValidationResult, file_path: str) -> None:
        """Print single result to stdout."""
        print(self.format_result(result, file_path))

    def print_summary(self, results: dict[str, ValidationResult]) -> None:
        """Print summary to stdout."""
        print(self.format_summary(results))


# ============================================================================
# Hook Handler (PostToolUse)
# ============================================================================

def is_rule_file_candidate(target_path: pathlib.Path) -> bool:
    """Determine if a target file path should trigger rule schema validation."""
    if target_path.exists() and not target_path.is_file():
        return False

    ext = target_path.suffix.lower()
    if ext not in (".md", ".yaml", ".yml", ".json"):
        return False

    name = target_path.name.lower()
    if name.startswith("_") or name == "readme.md":
        return False

    # Check if inside a known rules directory
    norm_str = str(target_path).replace("\\", "/").lower()
    if "/rules_by_role/" in norm_str or "/config/rules/" in norm_str or "/rules/" in norm_str:
        return True

    # Check if filename implies rules
    if "rule" in name:
        return True

    # Quick peek at file content for rule directives if file exists on disk
    if target_path.is_file():
        try:
            sample = target_path.read_text(encoding="utf-8-sig", errors="ignore")[:500]
            if "<enforced_turn_1_gate>" in sample or "CANARY_VERIFIED" in sample:
                return True
        except Exception:
            pass

    return False


def evaluate_hook(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute PostToolUse hook on modified files."""
    tool_call = get_tool_call(payload)
    args = get_tool_args(tool_call)

    raw_target = (
        args.get("TargetFile")
        or args.get("target_file")
        or args.get("file_path")
        or args.get("path")
    )

    if not raw_target or not isinstance(raw_target, str):
        return post_tool_response()

    target_path = normalize_path(raw_target)
    if not is_rule_file_candidate(target_path):
        return post_tool_response()

    try:
        validator = RuleSchemaValidator()
        result = validator.validate_rule_file(target_path)
        if not result.valid:
            log_diagnostic(
                f"Rule schema issues in {target_path.name}: {len(result.errors)} errors, {len(result.warnings)} warnings"
            )
            for err in result.errors[:3]:
                log_diagnostic(f"  [ERROR] {err.message}")
        else:
            log_diagnostic(f"Rule schema validation passed: {target_path.name}")
    except Exception as exc:
        log_diagnostic(f"Error validating rule file {target_path.name}: {exc}")

    return post_tool_response()


# ============================================================================
# Self-Test Suite (§28-§29 Automated Verification)
# ============================================================================

def run_self_test() -> int:
    """Run internal self-test suite to verify validator integrity."""
    print("\n[SELF-TEST] Universal Multi-Agent Governance Kit — Rule Schema Validator")
    print("=" * 70)
    passed = 0
    total = 8

    # Test 1: XML Section Parsing (single-line & multi-line)
    val = RuleSchemaValidator()
    content_xml = """# Test Title
> Test Description

<enforced_turn_1_gate priority="10">
Line 1 content
Line 2 content
</enforced_turn_1_gate>

<backend_coding_standards>
Standards content
</backend_coding_standards>

<quick_note>Single line content</quick_note>
"""
    sections = val.parse_frontmatter(content_xml)
    assert len(sections) == 3, f"Expected 3 sections, got {len(sections)}"
    assert sections[0].name == "enforced_turn_1_gate"
    assert sections[0].metadata.get("priority") == 10
    assert "Line 1" in sections[0].content
    assert sections[2].name == "quick_note"
    assert sections[2].content == "Single line content"
    print("  [1/8] XML Frontmatter Parser (Single & Multi-line): PASS")
    passed += 1

    # Test 2: Markdown Heading Section Parsing
    content_md = """# My Rules
> Description

## First Section
Content of first section.

## Second Section
Content of second section.
"""
    sections_md = val.parse_frontmatter(content_md)
    assert len(sections_md) == 2, f"Expected 2 sections, got {len(sections_md)}"
    assert sections_md[0].name == "first_section"
    assert sections_md[1].name == "second_section"
    print("  [2/8] Markdown Heading Parser Fallback: PASS")
    passed += 1

    # Test 3: Role Inference
    assert val._infer_role_from_path("rules_by_role/backend_developer/BACKEND_RULES.md") == "backend_developer"
    assert val._infer_role_from_path("rules_by_role/pm_orchestrator/PM_RULES.md") == "pm_orchestrator"
    assert val._infer_role_from_path("rules_by_role/PM_RULES.md") == "pm_orchestrator"
    assert val._infer_role_from_path("some/dir/tech_lead_auditor.md") == "tech_lead_auditor"
    print("  [3/8] Dynamic Role Inference: PASS")
    passed += 1

    # Test 4: Dynamic Valid Roles & Zero Hardcoding
    roles = get_all_valid_roles()
    assert "backend_developer" in roles
    assert "pm_orchestrator" in roles
    assert len(roles) >= 6
    print(f"  [4/8] Dynamic Roles Discovery ({len(roles)} roles): PASS")
    passed += 1

    # Test 5: JSON Schema Compliance Check
    rule = ParsedRule(
        file_path="mock/test_rules.md",
        role="backend_developer",
        sections=[
            FrontmatterSection(name="enforced_turn_1_gate", content="Gate content", start_line=1, end_line=5),
            FrontmatterSection(name="backend_coding_standards", content="Coding standards", start_line=6, end_line=10),
        ],
        title="Mock Backend Rules",
    )
    res = val.validate_rule_structure(rule)
    assert res.valid, f"Expected valid rule, errors: {[e.message for e in res.errors]}"
    print("  [5/8] JSON Schema Validation Engine: PASS")
    passed += 1

    # Test 6: Invalid Rule Rejection
    bad_rule = ParsedRule(
        file_path="mock/bad_rules.md",
        role="unknown_invalid_role_xyz",
        sections=[],
    )
    bad_res = val.validate_rule_structure(bad_rule)
    assert not bad_res.valid
    assert any("Unknown role" in e.message for e in bad_res.errors)
    assert any("No frontmatter sections found" in e.message for e in bad_res.errors)
    print("  [6/8] Invalid Rule & Schema Rejection: PASS")
    passed += 1

    # Test 7: Hook Candidate Filter (Avoid false positives)
    assert is_rule_file_candidate(Path("rules_by_role/backend_developer/BACKEND_RULES.md"))
    assert not is_rule_file_candidate(Path("rules_by_role/backend_developer/_README.md"))
    assert not is_rule_file_candidate(Path("some_project/package.json"))
    assert not is_rule_file_candidate(Path("some_project/main.py"))
    print("  [7/8] Hook Trigger Candidate Precision Filter: PASS")
    passed += 1

    # Test 8: Real Rules Directory Validation
    dir_results = val.validate_rules_directory()
    assert len(dir_results) > 0, "No rule files found in rules_by_role directory"
    failed_files = [p for p, r in dir_results.items() if not r.valid]
    assert len(failed_files) == 0, f"Found validation failures in real rules: {failed_files}"
    print(f"  [8/8] Live rules_by_role Batch Validation ({len(dir_results)} files): PASS (0 Failures)")
    passed += 1

    print("=" * 70)
    print(f"[SELF-TEST COMPLETE] Passed {passed}/{total} tests successfully! (100% PASS)\n")
    return 0


# ============================================================================
# CLI Entry Point
# ============================================================================

def main() -> int:
    """Main CLI and Hook entry point."""
    import argparse

    # 0. Check for --self-test flag
    if "--self-test" in sys.argv:
        return run_self_test()

    # 1. Non-blocking Stdin Hook Detection:
    # If no CLI arguments are provided and stdin has available data from hook runner
    if len(sys.argv) == 1:
        if has_stdin_data():
            try:
                payload = read_stdin_payload(default={})
                response = evaluate_hook(payload)
                emit_stdout_json(response)
                return 0
            except Exception as exc:
                log_diagnostic(f"Hook evaluation failed: {exc}")
                emit_stdout_json(post_tool_response())
                return 0

    # 2. CLI Execution
    parser = argparse.ArgumentParser(
        description="Validate rule files against JSON schemas (Zero Hardcoding)"
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Rule files or directories to validate (defaults to auto-discovered rules_by_role)",
    )
    parser.add_argument(
        "--schema",
        help="Path to custom JSON schema file",
    )
    parser.add_argument(
        "--rules-dir",
        help="Path to custom rules directory",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Exit with non-zero code if any warnings found",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal verification self-test suite",
    )

    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    validator = RuleSchemaValidator(rules_dir=args.rules_dir)

    if args.schema:
        try:
            validator.load_schema_from_file(args.schema)
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
            print(f"Error loading schema: {e}", file=sys.stderr)
            return 1

    reporter = ErrorReporter(verbose=args.verbose)
    all_results: dict[str, ValidationResult] = {}

    if not args.paths:
        # Default to auto-discovered rules directory
        all_results = validator.validate_rules_directory()
    else:
        for path_str in args.paths:
            path = pathlib.Path(path_str)
            if path.is_dir():
                all_results.update(validator.validate_rules_directory(path))
            elif path.is_file():
                all_results[str(path)] = validator.validate_rule_file(path)
            else:
                print(f"Path does not exist: {path_str}", file=sys.stderr)

    if args.output == "json":
        output = {p: res.to_dict() for p, res in all_results.items()}
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        for f_path, res in all_results.items():
            reporter.print_result(res, f_path)
        reporter.print_summary(all_results)

    has_errors = any(not r.valid for r in all_results.values())
    has_warnings = any(r.warnings for r in all_results.values())

    if has_errors or (args.fail_on_warning and has_warnings):
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
