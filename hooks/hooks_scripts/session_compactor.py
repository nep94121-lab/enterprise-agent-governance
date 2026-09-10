#!/usr/bin/env python3
"""Session Compactor for Multi-Agent Context Management.

Enterprise Multi-Agent Governance System - Dynamic Session Compaction Engine.
Provides intelligent compaction of conversation history based on:
1. Dynamic Configuration & Model Context Window Sensing (via hook_utils.config_loader).
2. Importance scoring of messages with word-boundary regex (Zero False Positives for technical terms).
3. Summarization triggers based on configurable token thresholds.
4. History pruning of low-importance entries with thread-safe atomic persistence.
5. Automatic compaction at threshold capacity with session-isolated multi-agent concurrency.
6. Real CLI PreInvocation hook execution with diagnostic reporting and built-in self-test suite.
"""

from __future__ import annotations

import copy
import io
import json
import os
import pathlib
import re
import sys
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
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
_this_file = globals().get("__file__")
if _this_file:
    CURRENT_DIR = pathlib.Path(_this_file).parent.resolve()
else:
    CURRENT_DIR = (pathlib.Path.cwd() / "hooks_scripts").resolve()
ENTERPRISE_HOOKS_ROOT = CURRENT_DIR.parent.resolve()

if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))
if str(ENTERPRISE_HOOKS_ROOT) not in sys.path:
    sys.path.insert(0, str(ENTERPRISE_HOOKS_ROOT))

# Common hook library import
try:
    from common_hook_lib import (
        emit_stdout_json,
        log_diagnostic,
        pre_invocation_response,
        read_stdin_payload,
    )
except ImportError:
    def log_diagnostic(message: str) -> None:
        try:
            sys.stderr.write(f"[HOOK-DIAGNOSTIC] {message}\n")
            sys.stderr.flush()
        except Exception:
            pass

    def emit_stdout_json(payload: dict[str, Any]) -> None:
        try:
            sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
            sys.stdout.flush()
        except Exception:
            sys.stdout.write("{}\n")
            sys.stdout.flush()

    def read_stdin_payload(default: dict[str, Any] | None = None) -> dict[str, Any]:
        return default or {}

    def pre_invocation_response(inject_steps: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        return {"injectSteps": inject_steps if inject_steps is not None else []}

# Dynamic Config Loader from hook_utils
try:
    from hook_utils.config_loader import (
        DynamicConfigLoader,
        get_dynamic_limits,
        get_session_compaction_config,
    )
    HAS_DYNAMIC_CONFIG = True
except ImportError:
    HAS_DYNAMIC_CONFIG = False

    def get_session_compaction_config(config_path: Any = None) -> dict[str, Any]:
        return {}

    def get_dynamic_limits(config_path: Any = None) -> dict[str, Any]:
        return {}


class ImportanceLevel(str, Enum):
    """Importance levels for session messages."""
    CRITICAL = "critical"   # Key decisions, errors, user instructions
    HIGH = "high"           # Tool results, important context
    MEDIUM = "medium"       # Regular interactions
    LOW = "low"             # Noise, redundant content


class CompactionStrategy(str, Enum):
    """Strategies for compaction."""
    SUMMARIZE = "summarize"  # Compress to summary
    PRUNE = "prune"          # Remove entries
    COMBINE = "combine"      # Merge similar entries


@dataclass
class SessionMessage:
    """Represents a message in the session history."""
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    role: str = ""               # user, assistant, system
    content: str = ""
    token_count: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    importance: ImportanceLevel = ImportanceLevel.MEDIUM
    importance_score: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)
    is_summarized: bool = False
    parent_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionMessage:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class CompactionResult:
    """Result of a compaction operation."""
    compaction_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    strategy: CompactionStrategy = CompactionStrategy.PRUNE
    messages_before: int = 0
    messages_after: int = 0
    tokens_before: int = 0
    tokens_after: int = 0
    tokens_freed: int = 0
    entries_removed: int = 0
    summary_generated: bool = False
    duration_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    success: bool = True
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ImportanceScore:
    """Score details for importance determination."""
    base_score: float
    content_factors: dict[str, float]
    final_score: float
    level: ImportanceLevel
    reasoning: str


def resolve_model_context_window(model_name: str | None = None, default_limit: int = 1000000) -> int:
    """Detect context window dynamically from model family metadata or dynamic limits."""
    cfg = get_session_compaction_config()
    model_windows = cfg.get("model_context_windows", {}) if isinstance(cfg, dict) else {}

    target = (model_name or os.environ.get("GEMINI_MODEL") or os.environ.get("MODEL") or "").lower().strip()

    # Direct match in config
    if target in model_windows:
        return int(model_windows[target])

    # Family prefix matching
    if "pro" in target:
        return int(model_windows.get("pro", 2097152))
    if "flash" in target:
        return int(model_windows.get("flash", 1048576))

    # General config default or fallback
    return int(model_windows.get("default", cfg.get("default_max_tokens", default_limit)))


class SessionCompactor:
    """Intelligent session history compactor with Zero-Hardcode Dynamic Limits.

    Features:
    - Importance scoring with word-boundary regex (preventing false positives on words like token, node, normal)
    - Thread-safe operations with per-session multi-agent isolation
    - Dynamic Context Window sensing matching model capabilities (Flash: 1M, Pro: 2M)
    - Atomic persistence protecting against partial writes or concurrency corruption
    - Automatic summarization triggers and history pruning
    - Real CLI PreInvocation hook execution
    """

    # Baseline defaults (exposed on class for full backward compatibility)
    CRITICAL_KEYWORDS = [
        "error", "exception", "failed", "fatal", "critical",
        "important", "must", "required", "do not", "never",
        "decision", "conclusion", "final", "approved",
    ]

    HIGH_IMPORTANCE_KEYWORDS = [
        "result", "completed", "success", "implemented",
        "created", "modified", "updated", "changed",
        "answer", "response", "output",
    ]

    LOW_IMPORTANCE_KEYWORDS = [
        "ok", "okay", "sure", "yes", "no", "thanks",
        "please", "help", "what about", "maybe",
    ]

    DEFAULT_SUMMARIZATION_THRESHOLD = 0.70  # 70% of max_tokens
    DEFAULT_COMPACTION_THRESHOLD = 0.80      # 80% of max_tokens
    DEFAULT_MAX_MESSAGES = 100
    DEFAULT_MAX_TOKENS = 1000000            # Dynamic 1M context window

    def __init__(
        self,
        max_tokens: int | None = None,
        max_messages: int | None = None,
        summarization_threshold: float | None = None,
        compaction_threshold: float | None = None,
        on_summarize: Callable[[list[SessionMessage]], str] | None = None,
        storage_path: str | Path | None = None,
        session_id: str | None = None,
        model_name: str | None = None,
        critical_keywords: list[str] | None = None,
        high_importance_keywords: list[str] | None = None,
        low_importance_keywords: list[str] | None = None,
    ) -> None:
        """Initialize session compactor with dynamic parameters and multi-tenant safety."""
        # 1. Load dynamic limits from hook_utils
        dyn_cfg = get_session_compaction_config() if HAS_DYNAMIC_CONFIG else {}

        self._model_name = model_name or os.environ.get("GEMINI_MODEL") or os.environ.get("MODEL") or "default"
        self._session_id = session_id or os.environ.get("CONVERSATION_ID") or "default"

        # 2. Resolve thresholds and limits dynamically
        if max_tokens is not None:
            self._max_tokens = int(max_tokens)
        else:
            env_tokens = os.environ.get("SESSION_COMPACTOR_MAX_TOKENS")
            if env_tokens and env_tokens.isdigit():
                self._max_tokens = int(env_tokens)
            else:
                self._max_tokens = resolve_model_context_window(self._model_name, self.DEFAULT_MAX_TOKENS)

        if max_messages is not None:
            self._max_messages = int(max_messages)
        else:
            env_msgs = os.environ.get("SESSION_COMPACTOR_MAX_MESSAGES")
            if env_msgs and env_msgs.isdigit():
                self._max_messages = int(env_msgs)
            else:
                self._max_messages = int(dyn_cfg.get("default_max_messages", self.DEFAULT_MAX_MESSAGES))

        if summarization_threshold is not None:
            self._summarization_threshold = float(summarization_threshold)
        else:
            env_sum = os.environ.get("SESSION_COMPACTOR_SUMMARIZE_THRESHOLD")
            self._summarization_threshold = (
                float(env_sum) if env_sum else float(dyn_cfg.get("summarization_threshold", self.DEFAULT_SUMMARIZATION_THRESHOLD))
            )

        if compaction_threshold is not None:
            self._compaction_threshold = float(compaction_threshold)
        else:
            env_comp = os.environ.get("SESSION_COMPACTOR_COMPACT_THRESHOLD")
            self._compaction_threshold = (
                float(env_comp) if env_comp else float(dyn_cfg.get("compaction_threshold", self.DEFAULT_COMPACTION_THRESHOLD))
            )

        self._target_capacity_ratio = float(dyn_cfg.get("target_capacity_ratio", 0.50))
        self._on_summarize = on_summarize

        # 3. Dynamic keywords with regex precompilation
        self._critical_keywords = list(critical_keywords or dyn_cfg.get("critical_keywords") or self.CRITICAL_KEYWORDS)
        self._high_keywords = list(high_importance_keywords or dyn_cfg.get("high_importance_keywords") or self.HIGH_IMPORTANCE_KEYWORDS)
        self._low_keywords = list(low_importance_keywords or dyn_cfg.get("low_importance_keywords") or self.LOW_IMPORTANCE_KEYWORDS)

        # Precompile word-boundary regex patterns to eliminate false positives
        self._critical_patterns = [
            re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE) for kw in self._critical_keywords
        ]
        self._high_patterns = [
            re.compile(r"\b" + re.escape(kw) + (r"\b" if len(kw) <= 4 else ""), re.IGNORECASE) for kw in self._high_keywords
        ]
        self._low_patterns = [
            re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE) for kw in self._low_keywords
        ]

        # 4. Session history & thread synchronization
        self._lock = threading.RLock()
        self._messages: deque[SessionMessage] = deque(maxlen=self._max_messages)
        self._total_tokens: int = 0
        self._compaction_log: list[CompactionResult] = []

        # 5. Storage with session isolation
        env_dir = os.environ.get("SESSION_COMPACTOR_STATE_DIR")
        target_storage = storage_path or env_dir
        self._storage_path = Path(target_storage).resolve() if target_storage else None

        self._load_state()

    @property
    def message_count(self) -> int:
        """Current number of messages in buffer."""
        with self._lock:
            return len(self._messages)

    @property
    def token_count(self) -> int:
        """Current total tokens in buffer."""
        with self._lock:
            return self._total_tokens

    @property
    def max_tokens(self) -> int:
        """Configured maximum token limit."""
        return self._max_tokens

    @property
    def max_messages(self) -> int:
        """Configured maximum message buffer capacity."""
        return self._max_messages

    @property
    def session_id(self) -> str:
        """Current session identifier."""
        return self._session_id

    @property
    def usage_percentage(self) -> float:
        """Current usage as percentage of max_tokens."""
        with self._lock:
            return self._total_tokens / self._max_tokens if self._max_tokens > 0 else 0.0

    def _get_storage_file(self) -> Path | None:
        """Resolve isolated storage file path for current session."""
        if not self._storage_path:
            return None
        safe_session = "".join(c for c in self._session_id if c.isalnum() or c in ("-", "_"))
        if not safe_session or safe_session == "default":
            # For backward compatibility with tests/existing state files
            legacy_file = self._storage_path / "session_compactor_state.json"
            if legacy_file.exists():
                return legacy_file
            return self._storage_path / "session_compactor_state_default.json"
        return self._storage_path / f"session_compactor_state_{safe_session}.json"

    def _load_state(self) -> None:
        """Load persisted state from disk with thread safety."""
        with self._lock:
            storage_file = self._get_storage_file()
            if not storage_file or not storage_file.exists():
                return

            try:
                raw_text = storage_file.read_text(encoding="utf-8")
                if not raw_text.strip():
                    return
                data = json.loads(raw_text)
                if not isinstance(data, dict):
                    return

                self._total_tokens = int(data.get("total_tokens", 0))
                loaded_messages = [
                    SessionMessage.from_dict(m) for m in data.get("messages", []) if isinstance(m, dict)
                ]
                self._messages = deque(loaded_messages, maxlen=self._max_messages)
            except (json.JSONDecodeError, OSError, KeyError, ValueError) as exc:
                log_diagnostic(f"SessionCompactor: Failed to load state from {storage_file}: {exc}")

    def _save_state(self) -> None:
        """Persist state to disk using atomic rename to prevent file corruption."""
        with self._lock:
            storage_file = self._get_storage_file()
            if not storage_file:
                return

            try:
                storage_file.parent.mkdir(parents=True, exist_ok=True)
                data = {
                    "session_id": self._session_id,
                    "model_name": self._model_name,
                    "max_tokens": self._max_tokens,
                    "max_messages": self._max_messages,
                    "total_tokens": self._total_tokens,
                    "messages": [m.to_dict() for m in self._messages],
                    "saved_at": datetime.now(UTC).isoformat(),
                }
                serialized = json.dumps(data, indent=2, ensure_ascii=False)

                # Atomic write pattern (§8 & §18 Resource & File Integrity) with multi-process collision prevention
                temp_file = storage_file.with_suffix(f".tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}")
                try:
                    temp_file.write_text(serialized, encoding="utf-8")
                    os.replace(temp_file, storage_file)
                finally:
                    if temp_file.exists():
                        try:
                            temp_file.unlink()
                        except OSError:
                            pass
            except (OSError, TypeError, ValueError) as exc:
                log_diagnostic(f"SessionCompactor: Failed to save state to {storage_file}: {exc}")

    # ========================================================================
    # Importance Scoring (Zero False Positives via Word-Boundary Regex)
    # ========================================================================

    def score_importance(self, message: SessionMessage) -> ImportanceScore:
        """Calculate importance score for a message using word-boundary regex."""
        content = message.content or ""
        content_factors: dict[str, float] = {}

        # Base score by role
        base_score = 0.5
        if message.role == "user":
            base_score = 0.6
        elif message.role == "assistant":
            base_score = 0.5
        elif message.role == "system":
            base_score = 0.7

        content_factors["role_base"] = base_score

        # Check for critical keywords with word boundary
        critical_count = sum(1 for pattern in self._critical_patterns if pattern.search(content))
        if critical_count > 0:
            critical_bonus = min(0.3, critical_count * 0.1)
            content_factors["critical_keywords"] = critical_bonus
            base_score += critical_bonus

        # Check for high importance keywords with word boundary
        high_count = sum(1 for pattern in self._high_patterns if pattern.search(content))
        if high_count > 0:
            high_bonus = min(0.15, high_count * 0.05)
            content_factors["high_keywords"] = high_bonus
            base_score += high_bonus

        # Check for low importance keywords (penalty) with strict word boundaries
        # Prevents penalizing 'node', 'token', 'normal' for 'no' or 'ok'
        low_count = sum(1 for pattern in self._low_patterns if pattern.search(content))
        if low_count > 0:
            low_penalty = min(0.2, low_count * 0.05)
            content_factors["low_keywords"] = -low_penalty
            base_score -= low_penalty

        # Length factor
        word_count = len(content.split())
        if word_count > 10:
            length_factor = min(0.1, (word_count - 10) * 0.002)
            content_factors["length"] = length_factor
            base_score += length_factor

        # Metadata importance flags
        if message.metadata.get("is_error", False):
            content_factors["error_flag"] = 0.2
            base_score += 0.2
        if message.metadata.get("is_decision", False):
            content_factors["decision_flag"] = 0.2
            base_score += 0.2

        # Clamp score to [0, 1]
        final_score = max(0.0, min(1.0, base_score))

        # Determine importance level
        if final_score >= 0.8:
            level = ImportanceLevel.CRITICAL
        elif final_score >= 0.6:
            level = ImportanceLevel.HIGH
        elif final_score >= 0.4:
            level = ImportanceLevel.MEDIUM
        else:
            level = ImportanceLevel.LOW

        reasoning = f"base={base_score:.2f}, factors={content_factors}"

        return ImportanceScore(
            base_score=base_score,
            content_factors=content_factors,
            final_score=final_score,
            level=level,
            reasoning=reasoning,
        )

    def score_message_content(self, content: str, role: str = "assistant") -> float:
        """Quick importance score for message content."""
        message = SessionMessage(role=role, content=content)
        return self.score_importance(message).final_score

    # ========================================================================
    # Summarization Triggers
    # ========================================================================

    def should_summarize(self) -> tuple[bool, str]:
        """Check if summarization should be triggered."""
        with self._lock:
            percentage = self.usage_percentage

            # Check token threshold
            if percentage >= self._summarization_threshold:
                return True, f"Token usage at {percentage:.1%} exceeds threshold ({self._summarization_threshold:.0%})"

            # Check message count
            if len(self._messages) >= self._max_messages * 0.8:
                return True, f"Message count {len(self._messages)} exceeds threshold ({int(self._max_messages * 0.8)})"

            return False, ""

    def get_messages_to_summarize(self) -> list[SessionMessage]:
        """Get messages that should be summarized (lowest importance, oldest first)."""
        with self._lock:
            if len(self._messages) < 10:
                return []

            scored_messages: list[tuple[float, float, SessionMessage]] = []
            for msg in list(self._messages):
                if not msg.is_summarized:
                    score = self.score_importance(msg).final_score
                    age = self._get_message_age(msg)
                    scored_messages.append((score, age, msg))

            # Sort by importance (lowest first), then age (oldest first)
            scored_messages.sort(key=lambda x: (x[0], x[1]))

            # Return bottom 50% of messages for summarization
            count = len(scored_messages) // 2
            return [msg for _, _, msg in scored_messages[:count]]

    def _get_message_age(self, message: SessionMessage) -> float:
        """Get age score for a message in seconds (older = higher score)."""
        try:
            msg_time = datetime.fromisoformat(message.timestamp.replace("Z", "+00:00"))
            age = datetime.now(UTC) - msg_time
            return age.total_seconds()
        except (ValueError, TypeError):
            return 0.0

    def summarize_messages(self, messages: list[SessionMessage]) -> str:
        """Summarize a list of messages using custom callback or structured template."""
        if self._on_summarize:
            return self._on_summarize(messages)

        if not messages:
            return ""

        summary_parts = []
        for msg in messages[:5]:
            content = msg.content
            if len(content) > 200:
                content = content[:200] + "..."
            summary_parts.append(f"[{msg.role}]: {content}")

        return f"Summarized {len(messages)} messages:\n" + "\n".join(summary_parts)

    # ========================================================================
    # History Pruning
    # ========================================================================

    def should_prune(self) -> tuple[bool, int]:
        """Check if pruning should occur."""
        with self._lock:
            percentage = self.usage_percentage

            if percentage < self._compaction_threshold:
                return False, 0

            # Calculate how many entries to remove to hit target capacity ratio
            target_tokens = int(self._max_tokens * self._target_capacity_ratio)
            excess_tokens = self._total_tokens - target_tokens

            if excess_tokens <= 0:
                return False, 0

            avg_tokens = self._total_tokens / len(self._messages) if self._messages else 100
            entries_to_remove = max(1, int(excess_tokens / avg_tokens))

            return True, entries_to_remove

    def get_messages_to_prune(self) -> list[SessionMessage]:
        """Get messages to prune (lowest importance, oldest first)."""
        with self._lock:
            should_prune, count = self.should_prune()
            if not should_prune or count == 0:
                return []

            scored = []
            for msg in list(self._messages):
                score = self.score_importance(msg).final_score
                scored.append((score, self._get_message_age(msg), msg))

            # Sort by importance (lowest first), then age (oldest first)
            scored.sort(key=lambda x: (x[0], x[1]))

            return [msg for _, _, msg in scored[:count]]

    def prune_history(self, messages_to_remove: list[SessionMessage]) -> int:
        """Remove messages from history safely and persist changes."""
        with self._lock:
            tokens_freed = 0
            ids_to_remove = {msg.message_id for msg in messages_to_remove}

            new_messages = deque(
                [m for m in self._messages if m.message_id not in ids_to_remove],
                maxlen=self._max_messages,
            )

            for msg in messages_to_remove:
                tokens_freed += msg.token_count

            self._messages = new_messages
            self._total_tokens = max(0, self._total_tokens - tokens_freed)

            self._save_state()
            return tokens_freed

    # ========================================================================
    # Main Compaction Logic
    # ========================================================================

    def add_message(
        self,
        content: str,
        role: str,
        token_count: int,
        metadata: dict[str, Any] | None = None,
    ) -> SessionMessage:
        """Add a message to the session history and auto-compact if needed."""
        with self._lock:
            message = SessionMessage(
                role=role,
                content=content,
                token_count=token_count,
                metadata=metadata or {},
            )

            # Score importance
            importance = self.score_importance(message)
            message.importance = importance.level
            message.importance_score = importance.final_score

            self._messages.append(message)
            self._total_tokens += token_count

            # Check if compaction needed
            self._check_and_compact()

            self._save_state()
            return message

    def _check_and_compact(self) -> CompactionResult | None:
        """Check thresholds and trigger compaction if needed."""
        if self.usage_percentage < self._compaction_threshold:
            return None
        return self.compact(strategy=CompactionStrategy.COMBINE)

    def compact(
        self,
        strategy: CompactionStrategy = CompactionStrategy.COMBINE,
    ) -> CompactionResult:
        """Perform compaction on session history with full execution tracking."""
        with self._lock:
            start_time = time.time()
            messages_before = len(self._messages)
            tokens_before = self._total_tokens

            result = CompactionResult(
                strategy=strategy,
                messages_before=messages_before,
                tokens_before=tokens_before,
            )

            try:
                if strategy == CompactionStrategy.SUMMARIZE:
                    self._compact_by_summarization(result)
                elif strategy == CompactionStrategy.PRUNE:
                    self._compact_by_pruning(result)
                elif strategy == CompactionStrategy.COMBINE:
                    self._compact_combined(result)

                result.messages_after = len(self._messages)
                result.tokens_after = self._total_tokens
                result.success = True
            except Exception as exc:
                result.success = False
                result.error_message = str(exc)
                result.messages_after = len(self._messages)
                result.tokens_after = self._total_tokens

            result.duration_ms = (time.time() - start_time) * 1000
            self._compaction_log.append(result)

            self._save_state()
            return result

    def _compact_by_summarization(self, result: CompactionResult) -> None:
        """Compact by summarizing low-importance messages."""
        messages_to_summarize = self.get_messages_to_summarize()
        if not messages_to_summarize:
            return

        summary = self.summarize_messages(messages_to_summarize)
        tokens_in_summary = max(1, int(len(summary.split()) * 1.3))

        # Remove summarized messages
        tokens_freed = self.prune_history(messages_to_summarize)

        # Add summary as a new system message
        summary_msg = SessionMessage(
            role="system",
            content=summary,
            token_count=tokens_in_summary,
            is_summarized=True,
            metadata={"is_summary": True, "original_count": len(messages_to_summarize)},
        )
        self._messages.append(summary_msg)
        self._total_tokens += tokens_in_summary

        result.summary_generated = True
        result.entries_removed += len(messages_to_summarize)
        result.tokens_freed += tokens_freed - tokens_in_summary

    def _compact_by_pruning(self, result: CompactionResult) -> None:
        """Compact by pruning low-importance messages."""
        messages_to_prune = self.get_messages_to_prune()
        if not messages_to_prune:
            return

        tokens_freed = self.prune_history(messages_to_prune)
        result.entries_removed += len(messages_to_prune)
        result.tokens_freed += tokens_freed

    def _compact_combined(self, result: CompactionResult) -> None:
        """Compact using combined pruning and summarization strategy."""
        # 1. First prune low-importance messages
        messages_to_prune = self.get_messages_to_prune()
        if messages_to_prune:
            tokens_freed = self.prune_history(messages_to_prune)
            result.entries_removed += len(messages_to_prune)
            result.tokens_freed += tokens_freed

        # 2. If still over threshold or if no pruning occurred, summarize
        if self.usage_percentage >= self._summarization_threshold or result.entries_removed == 0:
            self._compact_by_summarization(result)

    # ========================================================================
    # Query & Utility Methods
    # ========================================================================

    def get_messages(
        self,
        min_importance: ImportanceLevel | None = None,
        limit: int = 100,
    ) -> list[SessionMessage]:
        """Get messages from history matching minimum importance."""
        with self._lock:
            messages = list(self._messages)

            if min_importance:
                importance_order = {
                    ImportanceLevel.CRITICAL: 0,
                    ImportanceLevel.HIGH: 1,
                    ImportanceLevel.MEDIUM: 2,
                    ImportanceLevel.LOW: 3,
                }
                min_order = importance_order.get(min_importance, 0)
                messages = [
                    m for m in messages
                    if importance_order.get(m.importance, 99) <= min_order
                ]

            return messages[-limit:]

    def get_compaction_log(self, limit: int = 50) -> list[CompactionResult]:
        """Get compaction execution history."""
        with self._lock:
            return self._compaction_log[-limit:]

    def get_stats(self) -> dict[str, Any]:
        """Get comprehensive statistics for telemetry and dashboards."""
        with self._lock:
            importance_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }

            for msg in self._messages:
                importance_counts[msg.importance.value] += 1

            return {
                "session_id": self._session_id,
                "model_name": self._model_name,
                "message_count": len(self._messages),
                "token_count": self._total_tokens,
                "max_tokens": self._max_tokens,
                "max_messages": self._max_messages,
                "usage_percentage": f"{self.usage_percentage:.1%}",
                "importance_distribution": importance_counts,
                "thresholds": {
                    "summarization": f"{self._summarization_threshold:.0%}",
                    "compaction": f"{self._compaction_threshold:.0%}",
                },
                "total_compactions": len(self._compaction_log),
            }

    def reset(self) -> None:
        """Reset the compactor state completely."""
        with self._lock:
            self._messages.clear()
            self._total_tokens = 0
            self._compaction_log.clear()
            self._save_state()


# Multi-Agent Session Registry (Thread-Safe Isolation)
_SESSION_REGISTRY: dict[str, SessionCompactor] = {}
_REGISTRY_LOCK = threading.Lock()
_global_compactor: SessionCompactor | None = None


def get_session_compactor(
    max_tokens: int = SessionCompactor.DEFAULT_MAX_TOKENS,
    storage_path: str | Path | None = None,
    session_id: str | None = None,
    model_name: str | None = None,
) -> SessionCompactor:
    """Get or create a thread-safe SessionCompactor instance isolated per session."""
    global _global_compactor
    resolved_id = session_id or os.environ.get("CONVERSATION_ID") or "default"

    with _REGISTRY_LOCK:
        if resolved_id not in _SESSION_REGISTRY:
            compactor = SessionCompactor(
                max_tokens=max_tokens,
                storage_path=storage_path,
                session_id=resolved_id,
                model_name=model_name,
            )
            _SESSION_REGISTRY[resolved_id] = compactor
            if resolved_id == "default":
                _global_compactor = compactor

        return _SESSION_REGISTRY[resolved_id]


def reset_session_compactors() -> None:
    """Reset all cached compactors (primarily for tests)."""
    global _global_compactor
    with _REGISTRY_LOCK:
        for c in _SESSION_REGISTRY.values():
            c.reset()
        _SESSION_REGISTRY.clear()
        _global_compactor = None


# ============================================================================
# Self-Test Suite & CLI Interface
# ============================================================================

def run_self_test() -> bool:
    """Execute comprehensive self-test suite and return boolean status."""
    sys.stdout.write("====================================================\n")
    sys.stdout.write("  Session Compactor Self-Test & Diagnostic Suite   \n")
    sys.stdout.write("====================================================\n")

    tests_passed = 0
    total_tests = 6

    # Test 1: Word-Boundary Regex (No false positive on token, node, normal)
    try:
        c = SessionCompactor(max_tokens=10000)
        technical_text = "The node sends a token to normalize synchronization"
        score_tech = c.score_message_content(technical_text, "assistant")
        low_text = "No, ok, sure, thanks"
        score_low = c.score_message_content(low_text, "assistant")
        assert score_tech >= 0.5, f"Technical text should not be penalized, got {score_tech}"
        assert score_low < 0.5, f"Low text should be penalized, got {score_low}"
        sys.stdout.write("  [PASS] 1. Word-boundary regex eliminates false positives on technical terms\n")
        tests_passed += 1
    except Exception as exc:
        sys.stdout.write(f"  [FAIL] 1. Word-boundary regex test failed: {exc}\n")

    # Test 2: Dynamic Context Window Model Sensing
    try:
        flash_window = resolve_model_context_window("gemini-3.8-flash")
        pro_window = resolve_model_context_window("gemini-3.1-pro")
        assert flash_window >= 1000000, f"Flash window should be >= 1M, got {flash_window}"
        assert pro_window >= 2000000, f"Pro window should be >= 2M, got {pro_window}"
        sys.stdout.write("  [PASS] 2. Model Context Window dynamic resolution (Flash=1M, Pro=2M)\n")
        tests_passed += 1
    except Exception as exc:
        sys.stdout.write(f"  [FAIL] 2. Dynamic context window test failed: {exc}\n")

    # Test 3: Threshold Compaction Lifecycle
    try:
        compactor = SessionCompactor(
            max_tokens=1000, max_messages=20, compaction_threshold=0.80, session_id="self_test_compaction"
        )
        for i in range(7):
            compactor.add_message(f"Message {i}: regular interaction", "assistant", 150)
        assert compactor.usage_percentage < 0.80, f"Compaction should reduce usage, got {compactor.usage_percentage}"
        assert len(compactor.get_compaction_log()) >= 1, "Compaction log should record operation"
        sys.stdout.write("  [PASS] 3. Automatic 80% compaction triggers and frees capacity\n")
        tests_passed += 1
    except Exception as exc:
        sys.stdout.write(f"  [FAIL] 3. Compaction threshold test failed: {exc}\n")

    # Test 4: Multi-Agent Session Isolation
    try:
        c1 = get_session_compactor(session_id="agent_alpha_123")
        c2 = get_session_compactor(session_id="agent_beta_456")
        c1.add_message("Agent Alpha private message", "user", 200)
        assert c1.token_count == 200
        assert c2.token_count == 0
        sys.stdout.write("  [PASS] 4. Multi-agent per-session isolation verified\n")
        tests_passed += 1
    except Exception as exc:
        sys.stdout.write(f"  [FAIL] 4. Multi-agent isolation test failed: {exc}\n")

    # Test 5: Thread Safety & Concurrent Ingestion
    try:
        threaded_compactor = SessionCompactor(
            max_tokens=100000, max_messages=500, session_id="self_test_thread"
        )
        errors: list[Exception] = []

        def worker(thread_idx: int) -> None:
            try:
                for j in range(20):
                    threaded_compactor.add_message(f"Thread {thread_idx} msg {j}", "assistant", 50)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Threading errors encountered: {errors}"
        assert threaded_compactor.message_count == 100, f"Expected 100 messages, got {threaded_compactor.message_count}"
        sys.stdout.write("  [PASS] 5. Thread safety and concurrent message ingestion verified\n")
        tests_passed += 1
    except Exception as exc:
        sys.stdout.write(f"  [FAIL] 5. Thread safety test failed: {exc}\n")

    # Test 6: PreInvocation Hook Ingestion & Response Generation
    try:
        test_payload = {
            "conversationId": "test_session_hook",
            "invocationNum": 1,
            "model": "gemini-3.8-flash",
            "messages": [
                {"role": "user", "content": "Please implement feature X", "token_count": 100},
                {"role": "assistant", "content": "Sure, here is the implementation", "token_count": 200},
            ],
        }
        res = handle_pre_invocation(test_payload)
        assert "injectSteps" in res, f"Expected injectSteps in response, got {res}"
        sys.stdout.write("  [PASS] 6. PreInvocation stdin payload parsing and response generation\n")
        tests_passed += 1
    except Exception as exc:
        sys.stdout.write(f"  [FAIL] 6. PreInvocation hook test failed: {exc}\n")

    sys.stdout.write("----------------------------------------------------\n")
    sys.stdout.write(f"  Result: {tests_passed}/{total_tests} tests passed.\n")
    sys.stdout.write("====================================================\n")
    return tests_passed == total_tests


def handle_pre_invocation(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute real PreInvocation session compaction check."""
    if not isinstance(payload, dict):
        payload = {}

    session_id = (
        payload.get("conversationId")
        or payload.get("sessionId")
        or payload.get("conversation_id")
        or os.environ.get("CONVERSATION_ID")
        or "default"
    )
    model_name = (
        payload.get("model")
        or payload.get("modelName")
        or os.environ.get("GEMINI_MODEL")
        or os.environ.get("MODEL")
        or "default"
    )
    inv_num = payload.get("invocationNum", 0)

    # Dynamic limits integration
    max_tokens = resolve_model_context_window(model_name)
    compactor = get_session_compactor(max_tokens=max_tokens, session_id=session_id, model_name=model_name)

    # Ingest new messages from payload if present
    messages_data = payload.get("messages") or payload.get("history") or payload.get("trajectory") or []
    initial_log_count = len(compactor.get_compaction_log())
    if isinstance(messages_data, list):
        for raw_msg in messages_data:
            if isinstance(raw_msg, dict):
                content = str(raw_msg.get("content", ""))
                role = str(raw_msg.get("role", "assistant"))
                t_count = int(raw_msg.get("token_count", len(content.split()) * 1.3))
                compactor.add_message(content=content, role=role, token_count=t_count)

    # Evaluate compaction triggers or check if compaction occurred during message ingestion
    inject_steps: list[dict[str, Any]] = []
    should_comp, reason = compactor.should_prune()
    should_sum, sum_reason = compactor.should_summarize()

    current_log = compactor.get_compaction_log()
    if should_comp or should_sum:
        result = compactor.compact(strategy=CompactionStrategy.COMBINE)
        if result.success and (result.tokens_freed > 0 or result.summary_generated):
            inject_steps.append({
                "ephemeralMessage": (
                    f"⚡ [SESSION COMPACTOR] Session context compacted: freed {result.tokens_freed} tokens "
                    f"({result.entries_removed} entries compacted via {result.strategy.value}). "
                    f"Current usage: {compactor.usage_percentage:.1%} ({compactor.token_count}/{compactor.max_tokens} tokens)."
                )
            })
            log_diagnostic(
                f"Session compactor triggered for #{inv_num} [{session_id}]: freed {result.tokens_freed} tokens."
            )
    elif len(current_log) > initial_log_count:
        latest_result = current_log[-1]
        if latest_result.success and (latest_result.tokens_freed > 0 or latest_result.summary_generated):
            inject_steps.append({
                "ephemeralMessage": (
                    f"⚡ [SESSION COMPACTOR] Session context auto-compacted: freed {latest_result.tokens_freed} tokens "
                    f"({latest_result.entries_removed} entries compacted via {latest_result.strategy.value}). "
                    f"Current usage: {compactor.usage_percentage:.1%} ({compactor.token_count}/{compactor.max_tokens} tokens)."
                )
            })
            log_diagnostic(
                f"Session compactor auto-triggered during ingestion for #{inv_num} [{session_id}]: freed {latest_result.tokens_freed} tokens."
            )

    return pre_invocation_response(inject_steps=inject_steps)


def main() -> None:
    """CLI hook entrypoint for session context compaction."""
    if "--self-test" in sys.argv:
        success = run_self_test()
        sys.exit(0 if success else 1)

    if "--demo" in sys.argv:
        compactor = SessionCompactor(max_tokens=10000, max_messages=50)
        sys.stdout.write("Session Compactor Demo Initialized Successfully\n")
        stats = compactor.get_stats()
        sys.stdout.write(json.dumps(stats, indent=2) + "\n")
        return

    if "--status" in sys.argv:
        session_id = os.environ.get("CONVERSATION_ID", "default")
        compactor = get_session_compactor(session_id=session_id)
        sys.stdout.write(json.dumps(compactor.get_stats(), indent=2) + "\n")
        return

    # Real hook execution from stdin payload
    payload = read_stdin_payload(default={})
    try:
        response = handle_pre_invocation(payload)
    except Exception as exc:
        log_diagnostic(f"Session compactor error: {exc}")
        response = pre_invocation_response(inject_steps=[])

    emit_stdout_json(response)


if __name__ == "__main__":
    main()
