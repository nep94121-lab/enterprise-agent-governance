"""Universal Multi-Agent Governance Kit — Immutable Audit Trail & Telemetry Logger.

Provides an immutable audit trail system for tracking tool executions, governance
events, security decisions, and state changes with JSON Lines persistence, tamper-evident
SHA-256 checksums, cross-platform file locking (msvcrt on Windows, fcntl on POSIX),
dynamic configuration via hook_utils/config_loader, zero hardcoding, and PII/secret scrubbing.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import logging
import os
import pathlib
import random
import re
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
try:
    from datetime import UTC
except ImportError:
    UTC = timezone.utc
from enum import Enum
from pathlib import Path
from typing import Any

# Enforce UTF-8 across all platforms (Windows PowerShell safety)
try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

# Platform-specific file locking support
try:
    import fcntl
except ImportError:
    fcntl = None

try:
    import msvcrt
except ImportError:
    msvcrt = None

# Ensure hook_utils and common_hook_lib can be imported
_HOOKS_DIR = Path(__file__).parent.resolve()
_REPO_ROOT = _HOOKS_DIR.parent.resolve()
for _p in [str(_HOOKS_DIR), str(_REPO_ROOT)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Integration with hook_utils.config_loader (Zero Hardcoding)
try:
    from hook_utils.config_loader import get_audit_trail_config
except ImportError:
    try:
        from config_loader import get_governance_config
        def get_audit_trail_config(config_path: Path | str | None = None) -> dict[str, Any]:
            cfg = get_governance_config(config_path)
            raw = getattr(cfg, "raw_config", {}) if cfg else {}
            return raw.get("audit_trail", {})
    except ImportError:
        get_audit_trail_config = None

logger = logging.getLogger("enterprise_hooks.audit_logger")

# Fallback defaults (Zero-Config Resilience)
FALLBACK_AUDIT_CONFIG: dict[str, Any] = {
    "log_dir": "logs/audit",
    "max_file_size_mb": 100,
    "rotation_enabled": True,
    "index_enabled": True,
    "max_index_entries": 10000,
    "sanitize_pii": True,
    "lock_timeout_seconds": 10.0,
    "query_default_limit": 1000,
}


def load_audit_config(config_path: Path | str | None = None) -> dict[str, Any]:
    """Load audit trail configuration with dynamic config loader and environment overrides."""
    resolved_cfg = copy.deepcopy(FALLBACK_AUDIT_CONFIG)

    # 1. Load from hook_utils dynamic config if available
    if get_audit_trail_config is not None:
        try:
            dynamic_cfg = get_audit_trail_config(config_path)
            if isinstance(dynamic_cfg, dict):
                resolved_cfg.update(dynamic_cfg)
        except Exception as exc:
            logger.debug("Failed loading dynamic audit config: %s", exc)

    # 2. Environment Variable Overrides (Highest Precedence)
    if "AUDIT_LOG_DIR" in os.environ:
        resolved_cfg["log_dir"] = os.environ["AUDIT_LOG_DIR"]
    if "AUDIT_MAX_FILE_SIZE_MB" in os.environ:
        try:
            resolved_cfg["max_file_size_mb"] = int(os.environ["AUDIT_MAX_FILE_SIZE_MB"])
        except ValueError:
            pass
    if "AUDIT_ROTATION_ENABLED" in os.environ:
        resolved_cfg["rotation_enabled"] = os.environ["AUDIT_ROTATION_ENABLED"].strip().lower() in ("1", "true", "yes")
    if "AUDIT_INDEX_ENABLED" in os.environ:
        resolved_cfg["index_enabled"] = os.environ["AUDIT_INDEX_ENABLED"].strip().lower() in ("1", "true", "yes")
    if "AUDIT_MAX_INDEX_ENTRIES" in os.environ:
        try:
            resolved_cfg["max_index_entries"] = int(os.environ["AUDIT_MAX_INDEX_ENTRIES"])
        except ValueError:
            pass
    if "AUDIT_SANITIZE_PII" in os.environ:
        resolved_cfg["sanitize_pii"] = os.environ["AUDIT_SANITIZE_PII"].strip().lower() in ("1", "true", "yes")
    if "AUDIT_LOCK_TIMEOUT_SECONDS" in os.environ:
        try:
            resolved_cfg["lock_timeout_seconds"] = float(os.environ["AUDIT_LOCK_TIMEOUT_SECONDS"])
        except ValueError:
            pass
    if "AUDIT_QUERY_DEFAULT_LIMIT" in os.environ:
        try:
            resolved_cfg["query_default_limit"] = int(os.environ["AUDIT_QUERY_DEFAULT_LIMIT"])
        except ValueError:
            pass

    return resolved_cfg


def resolve_audit_log_dir(raw_dir: str | Path | None = None) -> Path:
    """Resolve audit log directory safely to prevent path traversal (§7)."""
    if raw_dir is None:
        cfg = load_audit_config()
        raw_dir = cfg.get("log_dir", "logs/audit")

    target = Path(raw_dir)
    if target.is_absolute():
        return target.resolve()

    # Relative to repository root
    return (_REPO_ROOT / target).resolve()


# ============================================================================
# BỔ SUNG HELPER CHUẨN HÓA TIMEZONE:
# ============================================================================
def to_utc_datetime(dt: datetime | str | None) -> datetime | None:
    """Normalize a datetime object or ISO string to offset-aware UTC datetime."""
    if dt is None:
        return None
    if isinstance(dt, str):
        try:
            clean_str = dt.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_str)
        except (ValueError, TypeError):
            return None
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ============================================================================
# PII & Secrets Redaction Engine (§1, §2)
# ============================================================================

SECRET_PATTERNS: list[tuple[re.Pattern, Any]] = [
    # Authorization header / Bearer token
    (re.compile(r'(?i)(?:bearer|token)\s+[a-zA-Z0-9_\-\.]{15,}'), 'Bearer [REDACTED_TOKEN]'),
    # API Keys: OpenAI, Anthropic, Gemini, GitHub
    (re.compile(r'sk-[a-zA-Z0-9_-]{20,}'), '[REDACTED_API_KEY]'),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), '[REDACTED_GEMINI_KEY]'),
    (re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,255}'), '[REDACTED_GITHUB_TOKEN]'),
    # Private Keys
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]'),
    # JWT Tokens
    (re.compile(r'eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+'), '[REDACTED_JWT]'),
    # Database connection strings with passwords
    (re.compile(r'(?i)((?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^:]+:)([^@]+)(@)'), r'\1[REDACTED_PASSWORD]\3'),
    # §1 Base64 Raw Data (> 128 characters)
    (re.compile(r'(?:[A-Za-z0-9+/]{4}){32,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'), lambda m: f"[REDACTED_BASE64 len={len(m.group(0))}]"),
]

SENSITIVE_KEY_NAMES: set[str] = {
    "password", "passwd", "pwd", "secret", "client_secret",
    "api_key", "apikey", "access_token", "auth_token", "private_key",
    "jwt", "token", "signature", "id_card", "passport", "biometric",
}


def sanitize_audit_value(value: Any) -> Any:
    """Recursively scrub secrets and PII from logged values."""
    if isinstance(value, dict):
        sanitized_dict: dict[str, Any] = {}
        for k, v in value.items():
            key_str = str(k).lower()
            if any(sens in key_str for sens in ("signature", "id_card", "passport", "biometric")):
                sanitized_dict[k] = f"[REDACTED_PII len={len(str(v))}]"
            elif any(sens in key_str for sens in ("password", "passwd", "pwd", "client_secret", "private_key", "api_key", "token")):
                sanitized_dict[k] = "[REDACTED_SECRET]"
            else:
                sanitized_dict[k] = sanitize_audit_value(v)
        return sanitized_dict
    elif isinstance(value, (list, tuple)):
        return [sanitize_audit_value(item) for item in value]
    elif isinstance(value, str):
        scrubbed = value
        for pattern, replacement in SECRET_PATTERNS:
            if callable(replacement):
                scrubbed = pattern.sub(replacement, scrubbed)
            else:
                scrubbed = pattern.sub(replacement, scrubbed)
        return scrubbed
    return value


# ============================================================================
# Cross-Platform Advisory File Locking
# ============================================================================

class CrossPlatformFileLock:
    """Cross-platform advisory file lock using msvcrt on Windows and fcntl on POSIX."""

    def __init__(self, fd: int, timeout: float = 10.0) -> None:
        self.fd = fd
        self.timeout = max(0.1, float(timeout))
        self.locked = False

    def acquire(self) -> bool:
        """Acquire non-blocking lock with bounded retry loop."""
        start = time.monotonic()
        while True:
            try:
                if sys.platform == "win32" and msvcrt is not None:
                    os.lseek(self.fd, 0, os.SEEK_SET)
                    msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                    self.locked = True
                    return True
                elif fcntl is not None:
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.locked = True
                    return True
                else:
                    # Fallback when fcntl is None (e.g. simulated environment)
                    self.locked = False
                    return True
            except (OSError, IOError):
                if time.monotonic() - start >= self.timeout:
                    logger.warning("Timed out waiting to acquire audit log file lock")
                    return False
                time.sleep(0.01 + random.uniform(0.005, 0.015))

    def release(self) -> None:
        """Release previously acquired lock."""
        if not self.locked:
            return
        try:
            if sys.platform == "win32" and msvcrt is not None:
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            elif fcntl is not None:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
        except (OSError, IOError):
            pass
        finally:
            self.locked = False


# ============================================================================
# Core Audit Data Structures
# ============================================================================

class AuditLevel(str, Enum):
    """Audit event severity levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    SECURITY = "security"


class AuditCategory(str, Enum):
    """Categories of auditable events."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    CONFIGURATION = "configuration"
    SYSTEM = "system"
    USER_ACTION = "user_action"
    SECURITY_EVENT = "security_event"
    BUSINESS_LOGIC = "business_logic"
    EXTERNAL_INTEGRATION = "external_integration"


@dataclass(frozen=True)
class AuditEntry:
    """Immutable audit trail entry with SHA-256 integrity verification."""
    entry_id: str
    timestamp: str
    level: str
    category: str
    action: str
    actor: str
    resource: str
    outcome: str
    details: dict[str, Any] = field(default_factory=dict)
    session_id: str | None = None
    correlation_id: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    checksum: str = ""

    def __post_init__(self) -> None:
        """Validate and compute checksum for immutability verification."""
        if not self.checksum:
            object.__setattr__(self, 'checksum', self._compute_checksum())

    def _compute_checksum(self) -> str:
        """Compute SHA-256 checksum of entry contents."""
        content = (
            f"{self.entry_id}|{self.timestamp}|{self.level}|{self.category}|"
            f"{self.action}|{self.actor}|{self.resource}|{self.outcome}|"
            f"{json.dumps(self.details, sort_keys=True)}|{self.session_id or ''}|"
            f"{self.correlation_id or ''}|{self.source_ip or ''}|{self.user_agent or ''}"
        )
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify entry has not been tampered with."""
        return self.checksum == self._compute_checksum()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "level": self.level,
            "category": self.category,
            "action": self.action,
            "actor": self.actor,
            "resource": self.resource,
            "outcome": self.outcome,
            "details": self.details,
            "session_id": self.session_id,
            "correlation_id": self.correlation_id,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "checksum": self.checksum,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        """Create entry from dictionary."""
        return cls(
            entry_id=data["entry_id"],
            timestamp=data["timestamp"],
            level=data["level"],
            category=data["category"],
            action=data["action"],
            actor=data["actor"],
            resource=data["resource"],
            outcome=data["outcome"],
            details=data.get("details", {}),
            session_id=data.get("session_id"),
            correlation_id=data.get("correlation_id"),
            source_ip=data.get("source_ip"),
            user_agent=data.get("user_agent"),
            checksum=data.get("checksum", ""),
        )


@dataclass
class AuditQuery:
    """Query parameters for filtering audit entries."""
    start_time: datetime | None = None
    end_time: datetime | None = None
    levels: set[AuditLevel] | None = None
    categories: set[AuditCategory] | None = None
    actions: set[str] | None = None
    actors: set[str] | None = None
    resources: set[str] | None = None
    outcomes: set[str] | None = None
    session_id: str | None = None
    correlation_id: str | None = None
    search_text: str | None = None
    limit: int = 1000
    offset: int = 0
    verify_integrity: bool = True


@dataclass
class AuditStatistics:
    """Audit trail statistics."""
    total_entries: int = 0
    entries_by_level: dict[str, int] = field(default_factory=dict)
    entries_by_category: dict[str, int] = field(default_factory=dict)
    entries_by_outcome: dict[str, int] = field(default_factory=dict)
    unique_actors: int = 0
    unique_resources: int = 0
    integrity_failures: int = 0
    first_entry_time: str | None = None
    last_entry_time: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_entries": self.total_entries,
            "entries_by_level": self.entries_by_level,
            "entries_by_category": self.entries_by_category,
            "entries_by_outcome": self.entries_by_outcome,
            "unique_actors": self.unique_actors,
            "unique_resources": self.unique_resources,
            "integrity_failures": self.integrity_failures,
            "first_entry_time": self.first_entry_time,
            "last_entry_time": self.last_entry_time,
        }


# ============================================================================
# Audit Logger Engine
# ============================================================================

class AuditLogger:
    """Immutable audit trail with JSON Lines persistence and query utilities."""

    def __init__(
        self,
        log_dir: str | Path | None = None,
        max_file_size_mb: int | None = None,
        rotation_enabled: bool | None = None,
        index_enabled: bool | None = None,
        max_index_entries: int | None = None,
        sanitize_pii: bool | None = None,
        lock_timeout_seconds: float | None = None,
    ) -> None:
        """Initialize AuditLogger with dynamic config fallback and zero hardcoding."""
        cfg = load_audit_config()

        # Dynamic fallback parameters
        resolved_log_dir = log_dir if log_dir is not None else cfg.get("log_dir", "logs/audit")
        self._log_dir = Path(resolved_log_dir)

        size_mb = max_file_size_mb if max_file_size_mb is not None else cfg.get("max_file_size_mb", 100)
        self._max_file_size = int(size_mb) * 1024 * 1024

        self._rotation_enabled = rotation_enabled if rotation_enabled is not None else bool(cfg.get("rotation_enabled", True))
        self._index_enabled = index_enabled if index_enabled is not None else bool(cfg.get("index_enabled", True))
        self._max_index_entries = int(max_index_entries if max_index_entries is not None else cfg.get("max_index_entries", 10000))
        self._sanitize_pii = sanitize_pii if sanitize_pii is not None else bool(cfg.get("sanitize_pii", True))
        self._lock_timeout = float(lock_timeout_seconds if lock_timeout_seconds is not None else cfg.get("lock_timeout_seconds", 10.0))

        # Thread safety lock
        self._lock = threading.RLock()

        # In-memory index bounded by max_index_entries (OOM prevention)
        self._entries_index: list[AuditEntry] = []
        self._current_file: Path | None = None
        self._entries_in_current_file = 0

        # Ensure target directory exists
        self._log_dir.mkdir(parents=True, exist_ok=True)

        # Load existing entries if indexing is enabled
        if self._index_enabled:
            self._rebuild_index()

        logger.info("Audit logger initialized at %s (rotation=%s, index=%s)", self._log_dir, self._rotation_enabled, self._index_enabled)

    def _rebuild_index(self) -> None:
        """Rebuild in-memory index from log files, bounded by max_index_entries."""
        with self._lock:
            self._entries_index = []
            log_files = sorted(self._log_dir.glob("audit_*.jsonl"))

            # Read files to load up to max_index_entries
            all_entries: list[AuditEntry] = []
            for log_file in log_files:
                try:
                    entries = self._read_entries_from_file(log_file)
                    all_entries.extend(entries)
                except Exception as exc:
                    logger.warning("Failed to load entries from %s: %s", log_file, exc)

            # Keep only the latest entries within capacity limit
            if len(all_entries) > self._max_index_entries:
                all_entries = all_entries[-self._max_index_entries:]

            self._entries_index = all_entries

    def _read_entries_from_file(self, file_path: Path) -> list[AuditEntry]:
        """Read all valid audit entries from a log file."""
        entries: list[AuditEntry] = []
        with open(file_path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entries.append(AuditEntry.from_dict(data))
                except Exception as exc:
                    logger.debug("Skipping unparseable line in %s: %s", file_path, exc)
        return entries

    def _next_rotated_file(self, today: str) -> Path:
        """Find the next available rotation sequence path for today."""
        seq = 1
        while True:
            rotated = self._log_dir / f"audit_{today}_{seq:04d}.jsonl"
            if not rotated.exists():
                return rotated
            seq += 1

    def _get_current_log_file(self) -> Path:
        """Get or create current log file with automatic rotation without explosion."""
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        base_log_file = self._log_dir / f"audit_{today}.jsonl"

        if not self._rotation_enabled:
            self._current_file = base_log_file
            return base_log_file

        # Kiểm tra file hiện tại có thuộc về ngày hôm nay hay không
        is_today_file = (
            self._current_file is not None
            and (
                self._current_file.stem == f"audit_{today}"
                or self._current_file.stem.startswith(f"audit_{today}_")
            )
        )

        if not is_today_file:
            # Tìm file log mới nhất trên đĩa cho ngày hôm nay
            rotated_files = sorted(self._log_dir.glob(f"audit_{today}_*.jsonl"))
            if rotated_files:
                candidate = rotated_files[-1]
            else:
                candidate = base_log_file

            # Nếu candidate đã đầy thì chuyển sang file tiếp theo
            try:
                if candidate.exists() and candidate.stat().st_size >= self._max_file_size:
                    candidate = self._next_rotated_file(today)
            except OSError:
                pass

            self._current_file = candidate
            self._entries_in_current_file = 0

        # Kiểm tra file active hiện tại nếu vượt ngưỡng dung lượng thì xoay vòng
        try:
            if self._current_file.exists() and self._current_file.stat().st_size >= self._max_file_size:
                self._current_file = self._next_rotated_file(today)
                self._entries_in_current_file = 0
        except OSError:
            pass

        return self._current_file

    def _generate_entry_id(self) -> str:
        """Generate cryptographically unique 32-character entry identifier."""
        timestamp = datetime.now(UTC).isoformat()
        hash_input = f"{timestamp}:{len(self._entries_index)}:{os.urandom(16).hex()}"
        return hashlib.sha256(hash_input.encode("utf-8")).hexdigest()[:32]

    def log(
        self,
        action: str,
        actor: str,
        resource: str,
        outcome: str,
        level: AuditLevel = AuditLevel.INFO,
        category: AuditCategory = AuditCategory.USER_ACTION,
        details: dict[str, Any] | None = None,
        session_id: str | None = None,
        correlation_id: str | None = None,
        source_ip: str | None = None,
        user_agent: str | None = None,
    ) -> AuditEntry:
        """Log an audit event with PII sanitization and cross-platform atomic locking."""
        timestamp = datetime.now(UTC).isoformat()
        entry_id = self._generate_entry_id()

        raw_details = details or {}
        sanitized_details = sanitize_audit_value(raw_details) if self._sanitize_pii else raw_details

        level_val = level.value if isinstance(level, AuditLevel) else str(level)
        cat_val = category.value if isinstance(category, AuditCategory) else str(category)

        entry = AuditEntry(
            entry_id=entry_id,
            timestamp=timestamp,
            level=level_val,
            category=cat_val,
            action=action,
            actor=actor,
            resource=resource,
            outcome=outcome,
            details=sanitized_details,
            session_id=session_id,
            correlation_id=correlation_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )

        entry_line = json.dumps(entry.to_dict(), sort_keys=True) + "\n"

        # Write to file under atomic lock
        with self._lock:
            log_file = self._get_current_log_file()
            with open(log_file, "a", encoding="utf-8") as f:
                lock = CrossPlatformFileLock(f.fileno(), timeout=self._lock_timeout)
                lock.acquire()
                try:
                    f.write(entry_line)
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    lock.release()

            if self._index_enabled:
                self._entries_index.append(entry)
                if len(self._entries_index) > self._max_index_entries:
                    self._entries_index.pop(0)

            self._entries_in_current_file += 1

        logger.debug("Audit entry logged: %s - %s", entry_id, action)
        return entry

    def query(self, query: AuditQuery) -> list[AuditEntry]:
        """Query audit entries with filtering."""
        if self._index_enabled:
            return self._query_from_index(query)
        return self._query_from_files(query)

    def _query_from_index(self, query: AuditQuery) -> list[AuditEntry]:
        """Query from in-memory index."""
        with self._lock:
            results: list[AuditEntry] = []
            for entry in self._entries_index:
                if not self._matches_query(entry, query):
                    continue
                results.append(entry)

            # Sort most recent first
            results.sort(key=lambda e: e.timestamp, reverse=True)
            start = query.offset
            end = query.offset + query.limit
            return results[start:end]

    def _query_from_files(self, query: AuditQuery) -> list[AuditEntry]:
        """Query directly from log files."""
        results: list[AuditEntry] = []
        seen_ids: set[str] = set()

        for log_file in sorted(self._log_dir.glob("audit_*.jsonl")):
            if self._should_skip_file(log_file, query):
                continue

            with open(log_file, encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        entry = AuditEntry.from_dict(data)

                        if entry.entry_id in seen_ids:
                            continue
                        seen_ids.add(entry.entry_id)

                        if self._matches_query(entry, query):
                            results.append(entry)
                    except Exception:
                        continue

        results.sort(key=lambda e: e.timestamp, reverse=True)
        start = query.offset
        end = query.offset + query.limit
        return results[start:end]

    def _should_skip_file(self, file_path: Path, query: AuditQuery) -> bool:
        """Skip file based on date prefix in filename if outside query time range."""
        if query.start_time is None and query.end_time is None:
            return False

        filename = file_path.stem
        parts = filename.split("_")
        if len(parts) < 2:
            return False

        date_part = parts[1]
        try:
            file_start = datetime.strptime(date_part[:8], "%Y%m%d").replace(tzinfo=timezone.utc)
            file_end = file_start + timedelta(days=1)

            if query.start_time:
                start_utc = to_utc_datetime(query.start_time)
                # Chỉ skip khi toàn bộ thời gian của file kết thúc trước query.start_time
                if start_utc and file_end <= start_utc:
                    return True

            if query.end_time:
                end_utc = to_utc_datetime(query.end_time)
                # Chỉ skip khi toàn bộ thời gian của file bắt đầu sau query.end_time
                if end_utc and file_start > end_utc:
                    return True
        except (ValueError, TypeError):
            pass

        return False

    def _matches_query(self, entry: AuditEntry, query: AuditQuery) -> bool:
        """Check if an entry matches the query filters with robust timezone handling."""
        if query.start_time or query.end_time:
            entry_time = to_utc_datetime(entry.timestamp)
            if entry_time is not None:
                if query.start_time:
                    start_utc = to_utc_datetime(query.start_time)
                    if start_utc and entry_time < start_utc:
                        return False

                if query.end_time:
                    end_utc = to_utc_datetime(query.end_time)
                    if end_utc and entry_time > end_utc:
                        return False
            else:
                return False

        if query.levels and AuditLevel(entry.level) not in query.levels:
            return False

        if query.categories and AuditCategory(entry.category) not in query.categories:
            return False

        if query.actions and entry.action not in query.actions:
            return False

        if query.actors and entry.actor not in query.actors:
            return False

        if query.resources and entry.resource not in query.resources:
            return False

        if query.outcomes and entry.outcome not in query.outcomes:
            return False

        if query.session_id and entry.session_id != query.session_id:
            return False

        if query.correlation_id and entry.correlation_id != query.correlation_id:
            return False

        if query.search_text:
            search_lower = query.search_text.lower()
            searchable = (
                f"{entry.action} {entry.actor} {entry.resource} "
                f"{entry.outcome} {json.dumps(entry.details)}"
            ).lower()
            if search_lower not in searchable:
                return False

        if query.verify_integrity and not entry.verify_integrity():
            logger.warning("Integrity check failed for entry %s", entry.entry_id)
            return False

        return True

    def iterate(self, query: AuditQuery) -> Iterator[AuditEntry]:
        """Memory-efficient iteration across log files."""
        for log_file in sorted(self._log_dir.glob("audit_*.jsonl")):
            if self._should_skip_file(log_file, query):
                continue

            with open(log_file, encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        entry = AuditEntry.from_dict(data)
                        if self._matches_query(entry, query):
                            yield entry
                    except Exception:
                        continue

    def get_statistics(self, since: datetime | None = None) -> AuditStatistics:
        """Calculate statistics across audit entries."""
        stats = AuditStatistics()
        actors: set[str] = set()
        resources: set[str] = set()

        query = AuditQuery(start_time=since, verify_integrity=False)

        for entry in self.iterate(query):
            stats.total_entries += 1
            stats.entries_by_level[entry.level] = stats.entries_by_level.get(entry.level, 0) + 1
            stats.entries_by_category[entry.category] = stats.entries_by_category.get(entry.category, 0) + 1
            stats.entries_by_outcome[entry.outcome] = stats.entries_by_outcome.get(entry.outcome, 0) + 1

            actors.add(entry.actor)
            resources.add(entry.resource)

            if not entry.verify_integrity():
                stats.integrity_failures += 1

            if stats.first_entry_time is None or entry.timestamp < stats.first_entry_time:
                stats.first_entry_time = entry.timestamp
            if stats.last_entry_time is None or entry.timestamp > stats.last_entry_time:
                stats.last_entry_time = entry.timestamp

        stats.unique_actors = len(actors)
        stats.unique_resources = len(resources)
        return stats

    def verify_trail_integrity(self) -> dict[str, Any]:
        """Verify cryptographic integrity of all entries across all log files."""
        report = {
            "valid": True,
            "total_entries": 0,
            "valid_entries": 0,
            "invalid_entries": [],
            "files_checked": 0,
        }

        for log_file in self._log_dir.glob("audit_*.jsonl"):
            report["files_checked"] += 1
            with open(log_file, encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        entry = AuditEntry.from_dict(data)
                        report["total_entries"] += 1

                        if entry.verify_integrity():
                            report["valid_entries"] += 1
                        else:
                            report["valid"] = False
                            report["invalid_entries"].append({
                                "entry_id": entry.entry_id,
                                "file": str(log_file),
                                "line": line_num,
                                "timestamp": entry.timestamp,
                            })
                    except Exception as e:
                        report["valid"] = False
                        report["invalid_entries"].append({
                            "file": str(log_file),
                            "line": line_num,
                            "error": str(e),
                        })

        return report

    def export(
        self,
        output_path: Path,
        query: AuditQuery | None = None,
        format: str = "jsonl",
    ) -> int:
        """Export audit entries to a file."""
        query = query or AuditQuery()
        query.verify_integrity = False

        count = 0
        with open(output_path, 'w', encoding='utf-8') as f:
            if format == "json":
                entries = [entry.to_dict() for entry in self.iterate(query)]
                json.dump(entries, f, indent=2)
                count = len(entries)
            else:
                for entry in self.iterate(query):
                    f.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")
                    count += 1

        logger.info("Exported %d audit entries to %s", count, output_path)
        return count

    def get_entry_by_id(self, entry_id: str) -> AuditEntry | None:
        """Retrieve a specific audit entry by ID."""
        if self._index_enabled:
            with self._lock:
                for entry in self._entries_index:
                    if entry.entry_id == entry_id:
                        return entry

        for log_file in self._log_dir.glob("audit_*.jsonl"):
            with open(log_file, encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if data.get("entry_id") == entry_id:
                            return AuditEntry.from_dict(data)
                    except Exception:
                        continue

        return None


# ============================================================================
# Convenience Functions
# ============================================================================

def log_authentication(
    logger: AuditLogger,
    actor: str,
    outcome: str,
    details: dict[str, Any] | None = None,
    **kwargs: Any,
) -> AuditEntry:
    """Log an authentication event."""
    return logger.log(
        action="authenticate",
        actor=actor,
        resource="auth_service",
        outcome=outcome,
        level=AuditLevel.INFO if outcome == "success" else AuditLevel.WARNING,
        category=AuditCategory.AUTHENTICATION,
        details=details,
        **kwargs,
    )


def log_authorization(
    logger: AuditLogger,
    actor: str,
    resource: str,
    action: str,
    outcome: str,
    details: dict[str, Any] | None = None,
    **kwargs: Any,
) -> AuditEntry:
    """Log an authorization decision."""
    return logger.log(
        action=action,
        actor=actor,
        resource=resource,
        outcome=outcome,
        level=AuditLevel.WARNING if outcome == "denied" else AuditLevel.INFO,
        category=AuditCategory.AUTHORIZATION,
        details=details,
        **kwargs,
    )


def log_data_access(
    logger: AuditLogger,
    actor: str,
    resource: str,
    action: str,
    details: dict[str, Any] | None = None,
    **kwargs: Any,
) -> AuditEntry:
    """Log a data access event."""
    return logger.log(
        action=action,
        actor=actor,
        resource=resource,
        outcome="success",
        level=AuditLevel.INFO,
        category=AuditCategory.DATA_ACCESS,
        details=details,
        **kwargs,
    )


def log_data_modification(
    logger: AuditLogger,
    actor: str,
    resource: str,
    action: str,
    outcome: str = "success",
    details: dict[str, Any] | None = None,
    **kwargs: Any,
) -> AuditEntry:
    """Log a data modification event."""
    return logger.log(
        action=action,
        actor=actor,
        resource=resource,
        outcome=outcome,
        level=AuditLevel.WARNING if outcome != "success" else AuditLevel.INFO,
        category=AuditCategory.DATA_MODIFICATION,
        details=details,
        **kwargs,
    )


def log_security_event(
    logger: AuditLogger,
    action: str,
    actor: str,
    resource: str,
    outcome: str,
    details: dict[str, Any] | None = None,
    severity: AuditLevel = AuditLevel.WARNING,
    **kwargs: Any,
) -> AuditEntry:
    """Log a security-related event."""
    return logger.log(
        action=action,
        actor=actor,
        resource=resource,
        outcome=outcome,
        level=severity,
        category=AuditCategory.SECURITY_EVENT,
        details=details,
        **kwargs,
    )


# ============================================================================
# Singleton & Configuration Factory
# ============================================================================

_audit_logger: AuditLogger | None = None
_singleton_lock = threading.Lock()


def get_audit_logger(
    log_dir: str | Path | None = None,
    **kwargs: Any,
) -> AuditLogger:
    """Get or initialize global audit logger singleton."""
    global _audit_logger
    with _singleton_lock:
        if _audit_logger is None:
            _audit_logger = AuditLogger(log_dir=log_dir, **kwargs)
        return _audit_logger


def configure_audit_logger(
    log_dir: str | Path | None = None,
    max_file_size_mb: int | None = None,
    rotation_enabled: bool | None = None,
    index_enabled: bool | None = None,
    **kwargs: Any,
) -> AuditLogger:
    """Configure and re-initialize global audit logger singleton."""
    global _audit_logger
    with _singleton_lock:
        _audit_logger = AuditLogger(
            log_dir=log_dir,
            max_file_size_mb=max_file_size_mb,
            rotation_enabled=rotation_enabled,
            index_enabled=index_enabled,
            **kwargs,
        )
        return _audit_logger


# ============================================================================
# CLI Hook Entrypoint (PreToolUse & PostToolUse)
# ============================================================================

def main() -> None:
    """CLI hook entrypoint for audit logging."""
    from common_hook_lib import (
        emit_stdout_json,
        get_tool_call,
        log_diagnostic,
        post_tool_response,
        pre_tool_response,
        read_stdin_payload,
    )

    payload = read_stdin_payload(default={})
    try:
        tool_call = get_tool_call(payload)
        tool_name = tool_call.get("name", "unknown") if isinstance(tool_call, dict) else "unknown"

        sanitized_details: dict[str, Any] = {}
        if tool_call and isinstance(tool_call, dict):
            sanitized_details["toolCall"] = sanitize_audit_value(tool_call)

        logger_inst = get_audit_logger()
        logger_inst.log(
            action=f"tool_execution:{tool_name}",
            actor="agent",
            resource=tool_name,
            outcome="success",
            category=AuditCategory.DATA_ACCESS,
            level=AuditLevel.INFO,
            details=sanitized_details,
        )
        log_diagnostic(f"Audit entry recorded for tool: {tool_name}")
    except Exception as exc:
        log_diagnostic(f"Audit logger hook error: {exc}")

    if "--pre" in sys.argv:
        emit_stdout_json(pre_tool_response("allow", "Audit log recorded."))
    else:
        emit_stdout_json(post_tool_response())


if __name__ == "__main__":
    main()
