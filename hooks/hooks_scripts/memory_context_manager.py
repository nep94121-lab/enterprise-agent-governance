"""
Memory Context Manager
A TTL-based memory context system with priority eviction, JSON persistence,
cross-process file locking, and multi-agent context sharing for MCP integration.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any


class Priority(IntEnum):
    """Context priority levels. Higher values = higher priority."""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


def _normalize_priority(p: Any) -> int:
    """Normalize priority value to integer."""
    if isinstance(p, Priority):
        return int(p.value)
    if isinstance(p, int):
        return p
    if isinstance(p, str):
        mapping = {
            "low": Priority.LOW,
            "normal": Priority.NORMAL,
            "high": Priority.HIGH,
            "critical": Priority.CRITICAL,
        }
        return mapping.get(p.lower().strip(), Priority.NORMAL)
    try:
        return int(p)
    except (ValueError, TypeError):
        return Priority.NORMAL


@contextlib.contextmanager
def file_lock(lock_path: Path, timeout: float = 5.0, poll_interval: float = 0.02):
    """
    Cross-platform inter-process file lock.
    Uses msvcrt on Windows and fcntl on Unix/Linux.
    """
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    lock_file = None
    locked = False
    start_time = time.time()

    try:
        lock_file = open(lock_path, "a+b")
        while True:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except (BlockingIOError, OSError, PermissionError):
                if time.time() - start_time >= timeout:
                    # Timeout reached: break gracefully to prevent deadlocks
                    break
                time.sleep(poll_interval)
        yield
    finally:
        if locked and lock_file is not None:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
        if lock_file is not None:
            try:
                lock_file.close()
            except Exception:
                pass


@dataclass
class MemoryContext:
    """
    Represents a single memory context entry.
    """
    id: str
    key: str
    value: Any
    priority: int = Priority.NORMAL
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_accessed: float = field(default_factory=time.time)
    expires_at: float = 0.0
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    agent_id: str = ""
    agent_name: str = ""
    context_type: str = "general"
    content: Any = None

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if self.content is None and self.value is not None:
            self.content = self.value
        elif self.value is None and self.content is not None:
            self.value = self.content
        if isinstance(self.created_at, (int, float)):
            dt = datetime.fromtimestamp(self.created_at, timezone.utc)
            self.created_at = dt.isoformat()

    @property
    def context_id(self) -> str:
        """Alias for MCP compatibility."""
        return self.id

    def is_expired(self, current_time: float | None = None) -> bool:
        """Check if this context has expired."""
        if self.expires_at <= 0:
            return False
        if current_time is None:
            current_time = time.time()
        return current_time >= self.expires_at

    def touch(self) -> None:
        """Update last_accessed to current time."""
        self.last_accessed = time.time()

    def time_to_live(self) -> float:
        """Return remaining TTL in seconds, or -1 if no expiration."""
        if self.expires_at <= 0:
            return -1.0
        remaining = self.expires_at - time.time()
        return max(0.0, remaining)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> MemoryContext:
        """Create instance from dictionary with backward compatibility."""
        valid_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        if "context_id" in data and "id" not in filtered:
            filtered["id"] = data["context_id"]
        if "content" in data and "value" not in filtered:
            filtered["value"] = data["content"]
        return cls(**filtered)


@dataclass
class ContextHandoff:
    """
    Represents a handoff of memory context between systems/agents.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_context_id: str = ""
    target_agent: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    priority: int = Priority.NORMAL
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    status: str = "pending"
    metadata: dict[str, Any] = field(default_factory=dict)
    from_agent: str = ""
    to_agent: str = ""
    task_summary: str = ""
    pending_tasks: list[dict[str, Any]] = field(default_factory=list)
    decisions_made: list[str] = field(default_factory=list)
    context_snapshot: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.to_agent and self.target_agent:
            self.to_agent = self.target_agent
        elif not self.target_agent and self.to_agent:
            self.target_agent = self.to_agent
        self.priority = _normalize_priority(self.priority)

    @property
    def handoff_id(self) -> str:
        """Alias for MCP compatibility."""
        return self.id

    def complete(self) -> None:
        """Mark handoff as completed."""
        self.completed_at = time.time()
        self.status = "completed"

    def fail(self, reason: str = "") -> None:
        """Mark handoff as failed."""
        self.completed_at = time.time()
        self.status = "failed"
        if reason:
            self.metadata["failure_reason"] = reason

    def is_pending(self) -> bool:
        """Check if handoff is still pending."""
        return self.status == "pending"

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> ContextHandoff:
        """Create instance from dictionary with backward compatibility."""
        valid_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        if "handoff_id" in data and "id" not in filtered:
            filtered["id"] = data["handoff_id"]
        if "to_agent" in data and "target_agent" not in filtered:
            filtered["target_agent"] = data["to_agent"]
        return cls(**filtered)


class MemoryContextManager:
    """
    Main memory context manager with TTL, priority-based eviction,
    cross-process JSON persistence, and multi-agent MCP support.
    """

    def __init__(
        self,
        storage_path: str = "memory_contexts.json",
        default_ttl: float = 3600.0,
        max_entries: int = 1000,
        auto_persist: bool = True,
        persist_interval: float = 60.0
    ):
        self._storage_path = Path(storage_path)
        self._default_ttl = default_ttl
        self._max_entries = max_entries
        self._auto_persist = auto_persist
        self._persist_interval = persist_interval

        self._contexts: dict[str, MemoryContext] = {}
        self._handoffs: dict[str, ContextHandoff] = {}
        self._lock = threading.RLock()

        self._last_persist_time = time.time()
        self._load()

    def _load(self) -> None:
        """Load contexts and handoffs from JSON file with inter-process locking."""
        with self._lock:
            if not self._storage_path.exists():
                return

            lock_path = self._storage_path.with_suffix(".lock")
            with file_lock(lock_path):
                try:
                    with open(self._storage_path, encoding="utf-8") as f:
                        data = json.load(f)

                    contexts_data = data.get("contexts", [])
                    for ctx_data in contexts_data:
                        ctx = MemoryContext.from_dict(ctx_data)
                        if not ctx.is_expired():
                            self._contexts[ctx.id] = ctx

                    handoffs_data = data.get("handoffs", [])
                    for hand_data in handoffs_data:
                        hand = ContextHandoff.from_dict(hand_data)
                        if hand.is_pending():
                            self._handoffs[hand.id] = hand

                except (json.JSONDecodeError, KeyError, TypeError, OSError):
                    pass

    def persist(self) -> None:
        """Persist contexts and handoffs to JSON file with inter-process locking."""
        with self._lock:
            lock_path = self._storage_path.with_suffix(".lock")
            with file_lock(lock_path):
                data = {
                    "contexts": [ctx.to_dict() for ctx in self._contexts.values()],
                    "handoffs": [hand.to_dict() for hand in self._handoffs.values()],
                    "saved_at": time.time()
                }

                self._storage_path.parent.mkdir(parents=True, exist_ok=True)

                temp_path = self._storage_path.with_name(
                    f"{self._storage_path.stem}_{uuid.uuid4().hex[:8]}.tmp"
                )
                try:
                    with open(temp_path, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)

                    for attempt in range(5):
                        try:
                            temp_path.replace(self._storage_path)
                            break
                        except (PermissionError, OSError):
                            if attempt == 4:
                                raise
                            time.sleep(0.02)
                finally:
                    if temp_path.exists():
                        try:
                            temp_path.unlink()
                        except Exception:
                            pass

                self._last_persist_time = time.time()

    def _maybe_persist(self) -> None:
        """Auto-persist if interval elapsed and enabled."""
        if self._auto_persist:
            if time.time() - self._last_persist_time >= self._persist_interval:
                self.persist()

    def set(
        self,
        key: str,
        value: Any,
        priority: int = Priority.NORMAL,
        ttl: float | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None
    ) -> MemoryContext:
        """
        Store a memory context.

        Args:
            key: Context key/name.
            value: Data to store.
            priority: Priority level (0-3).
            ttl: Time-to-live in seconds (None = use default_ttl, 0 = never expire).
            tags: Optional tags for grouping.
            metadata: Optional metadata dict.
        """
        with self._lock:
            self._evict_if_needed()

            norm_priority = _normalize_priority(priority)
            effective_ttl = self._default_ttl if ttl is None else ttl
            expires_at = time.time() + effective_ttl if effective_ttl > 0 else 0.0

            context = MemoryContext(
                id=str(uuid.uuid4()),
                key=key,
                value=value,
                priority=norm_priority,
                expires_at=expires_at,
            )

            if tags:
                context.tags = tags
            if metadata:
                context.metadata = metadata

            self._contexts[context.id] = context
            self._maybe_persist()
            return context

    def store_context(
        self,
        agent_id: str,
        agent_name: str,
        context_type: str,
        content: Any,
        priority: int | str = 5,
        tags: list[str] | None = None,
        ttl: float | None = None,
    ) -> MemoryContext:
        """
        Store a memory context from an agent (MCP Integration contract).
        """
        with self._lock:
            self._evict_if_needed()

            norm_priority = _normalize_priority(priority)
            effective_ttl = self._default_ttl if ttl is None else ttl
            expires_at = time.time() + effective_ttl if effective_ttl > 0 else 0.0

            ctx_id = str(uuid.uuid4())
            context = MemoryContext(
                id=ctx_id,
                key=f"{context_type}:{agent_id}:{ctx_id[:8]}",
                value=content,
                priority=norm_priority,
                expires_at=expires_at,
                tags=tags or [],
                metadata={
                    "agent_id": agent_id,
                    "agent_name": agent_name,
                    "context_type": context_type,
                },
                agent_id=agent_id,
                agent_name=agent_name,
                context_type=context_type,
                content=content,
            )

            self._contexts[context.id] = context
            self._maybe_persist()
            return context

    def get(self, context_id: str) -> MemoryContext | None:
        """Retrieve a context by ID, updating last_accessed time."""
        with self._lock:
            context = self._contexts.get(context_id)
            if context is None:
                return None

            if context.is_expired():
                del self._contexts[context_id]
                self._maybe_persist()
                return None

            context.touch()
            return context

    def get_by_key(self, key: str) -> MemoryContext | None:
        """Retrieve the most recent non-expired context by key."""
        with self._lock:
            candidates = [
                ctx for ctx in self._contexts.values()
                if ctx.key == key and not ctx.is_expired()
            ]
            if not candidates:
                return None
            return max(candidates, key=lambda c: c.last_accessed)

    def get_all_by_key(self, key: str) -> list[MemoryContext]:
        """Retrieve all non-expired contexts matching a key."""
        with self._lock:
            return [
                ctx for ctx in self._contexts.values()
                if ctx.key == key and not ctx.is_expired()
            ]

    def get_by_tag(self, tag: str) -> list[MemoryContext]:
        """Retrieve all contexts with a specific tag."""
        with self._lock:
            return [
                ctx for ctx in self._contexts.values()
                if tag in ctx.tags and not ctx.is_expired()
            ]

    def query_contexts(
        self,
        agent_id: str | None = None,
        context_type: str | None = None,
        tags: list[str] | None = None,
        min_priority: int = 0,
    ) -> list[MemoryContext]:
        """Query contexts with multi-agent filtering (MCP Integration contract)."""
        with self._lock:
            current_time = time.time()
            results = []

            for ctx in self._contexts.values():
                if ctx.is_expired(current_time):
                    continue
                if _normalize_priority(ctx.priority) < min_priority:
                    continue
                if agent_id is not None and agent_id != "":
                    if ctx.agent_id != agent_id and ctx.agent_name != agent_id:
                        continue
                if context_type is not None and context_type != "all":
                    if ctx.context_type != context_type:
                        continue
                if tags and not all(t in ctx.tags for t in tags):
                    continue

                results.append(ctx)

            return sorted(results, key=lambda c: c.last_accessed, reverse=True)

    def get_shared_context(
        self,
        max_age_seconds: int | float | None = None,
    ) -> dict[str, Any]:
        """Get shared context for agent injection (MCP Integration contract)."""
        with self._lock:
            current_time = time.time()
            matching = []

            for ctx in self._contexts.values():
                if ctx.is_expired(current_time):
                    continue

                if max_age_seconds is not None:
                    try:
                        if isinstance(ctx.created_at, str):
                            ctx_time = datetime.fromisoformat(
                                ctx.created_at.replace("Z", "+00:00")
                            ).timestamp()
                        else:
                            ctx_time = float(ctx.created_at)
                        if (current_time - ctx_time) > max_age_seconds:
                            continue
                    except Exception:
                        pass

                matching.append(ctx)

            sorted_ctxs = sorted(
                matching,
                key=lambda c: (_normalize_priority(c.priority), c.last_accessed),
                reverse=True
            )

            return {
                "context_count": len(sorted_ctxs),
                "shared_contexts": [
                    serialize_context_for_mcp(c) for c in sorted_ctxs
                ],
            }

    def delete(self, context_id: str) -> bool:
        """Delete a context by ID."""
        with self._lock:
            if context_id in self._contexts:
                del self._contexts[context_id]
                self._maybe_persist()
                return True
            return False

    def clear_expired(self) -> int:
        """Remove all expired contexts."""
        with self._lock:
            current_time = time.time()
            expired_ids = [
                ctx_id for ctx_id, ctx in self._contexts.items()
                if ctx.expires_at > 0 and current_time >= ctx.expires_at
            ]
            for ctx_id in expired_ids:
                del self._contexts[ctx_id]

            if expired_ids:
                self._maybe_persist()
            return len(expired_ids)

    def _evict_if_needed(self) -> None:
        """Evict lowest priority/oldest contexts if over limit."""
        if self._max_entries <= 0:
            return

        # First clean up expired contexts
        self.clear_expired()

        if len(self._contexts) < self._max_entries:
            return

        sorted_contexts = sorted(
            self._contexts.values(),
            key=lambda c: (_normalize_priority(c.priority), c.last_accessed)
        )

        evict_count = len(self._contexts) - self._max_entries + 1
        for ctx in sorted_contexts[:evict_count]:
            self._contexts.pop(ctx.id, None)

    def create_handoff(
        self,
        source_context_id: str = "",
        target_agent: str = "",
        priority: int | str = Priority.NORMAL,
        metadata: dict[str, Any] | None = None,
        from_agent: str = "",
        to_agent: str = "",
        task_summary: str = "",
        context_snapshot: dict[str, Any] | None = None,
        pending_tasks: list[dict[str, Any]] | None = None,
        decisions_made: list[str] | None = None,
    ) -> ContextHandoff | None:
        """
        Create a handoff for a context to another agent/system.
        Supports both legacy signature and MCP multi-agent signature.
        """
        with self._lock:
            effective_target = to_agent or target_agent
            norm_priority = _normalize_priority(priority)
            meta = dict(metadata or {})
            payload: dict[str, Any] = {}

            if source_context_id:
                context = self._contexts.get(source_context_id)
                if context is None:
                    return None
                payload = {
                    "key": context.key,
                    "value": context.value,
                    "tags": context.tags,
                    "metadata": context.metadata,
                    "priority": context.priority,
                    "ttl": context.time_to_live(),
                }
            elif context_snapshot:
                payload = dict(context_snapshot)

            handoff = ContextHandoff(
                source_context_id=source_context_id,
                target_agent=effective_target,
                payload=payload,
                priority=norm_priority,
                from_agent=from_agent,
                to_agent=effective_target,
                task_summary=task_summary,
                pending_tasks=pending_tasks or [],
                decisions_made=decisions_made or [],
                context_snapshot=context_snapshot or {},
                metadata=meta,
            )

            self._handoffs[handoff.id] = handoff
            self._maybe_persist()
            return handoff

    def get_handoff(self, handoff_id: str) -> ContextHandoff | None:
        """Get a handoff by ID."""
        with self._lock:
            return self._handoffs.get(handoff_id)

    def complete_handoff(self, handoff_id: str) -> bool:
        """Mark a handoff as completed."""
        with self._lock:
            handoff = self._handoffs.get(handoff_id)
            if handoff is None:
                return False
            handoff.complete()
            self._maybe_persist()
            return True

    def update_handoff_status(
        self,
        handoff_id: str,
        status: str,
        additional_notes: str | None = None,
    ) -> ContextHandoff | None:
        """Update handoff status (MCP Integration contract)."""
        with self._lock:
            handoff = self._handoffs.get(handoff_id)
            if handoff is None:
                return None

            handoff.status = status
            if status in ("completed", "failed"):
                handoff.completed_at = time.time()
            if additional_notes:
                handoff.metadata["notes"] = additional_notes

            self._maybe_persist()
            return handoff

    def get_pending_handoffs(
        self,
        target_agent: str | None = None,
        min_priority: int | str = Priority.LOW,
        for_agent: str | None = None,
        status: str | None = "pending",
    ) -> list[ContextHandoff]:
        """Get pending handoffs with optional filters."""
        with self._lock:
            effective_agent = for_agent or target_agent
            norm_min_priority = _normalize_priority(min_priority)

            result = []
            for h in self._handoffs.values():
                if status and status != "all" and h.status != status:
                    continue
                if _normalize_priority(h.priority) < norm_min_priority:
                    continue
                if effective_agent is not None:
                    if h.target_agent != effective_agent and h.to_agent != effective_agent:
                        continue
                result.append(h)

            return sorted(
                result,
                key=lambda h: (_normalize_priority(h.priority), h.created_at),
                reverse=True
            )

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about the memory context manager."""
        with self._lock:
            current_time = time.time()
            expired_count = sum(
                1 for ctx in self._contexts.values()
                if ctx.is_expired(current_time)
            )

            by_priority = {}
            for p in Priority:
                by_priority[p.name] = sum(
                    1 for ctx in self._contexts.values()
                    if _normalize_priority(ctx.priority) == p.value
                )

            return {
                "total_contexts": len(self._contexts),
                "expired_contexts": expired_count,
                "pending_handoffs": sum(1 for h in self._handoffs.values() if h.is_pending()),
                "total_handoffs": len(self._handoffs),
                "by_priority": by_priority,
                "max_entries": self._max_entries,
                "utilization": len(self._contexts) / self._max_entries if self._max_entries > 0 else 0,
                "storage_path": str(self._storage_path)
            }

    def get_all(self) -> list[MemoryContext]:
        """Get all non-expired contexts."""
        with self._lock:
            current_time = time.time()
            return [
                ctx for ctx in self._contexts.values()
                if not ctx.is_expired(current_time)
            ]

    def clear(self) -> None:
        """Clear all contexts and handoffs."""
        with self._lock:
            self._contexts.clear()
            self._handoffs.clear()
            self.persist()

    def __len__(self) -> int:
        """Return count of non-expired contexts."""
        with self._lock:
            self.clear_expired()
            return len(self._contexts)

    def __contains__(self, context_id: str) -> bool:
        """Check if context ID exists and is not expired."""
        return self.get(context_id) is not None


def serialize_context_for_mcp(context: MemoryContext) -> dict[str, Any]:
    """Serialize a MemoryContext for MCP tool responses."""
    return {
        "context_id": getattr(context, "context_id", context.id),
        "agent_id": getattr(context, "agent_id", ""),
        "agent_name": getattr(context, "agent_name", "Claude"),
        "context_type": getattr(context, "context_type", "general"),
        "content": getattr(context, "content", context.value),
        "priority": _normalize_priority(getattr(context, "priority", 1)),
        "tags": getattr(context, "tags", []),
        "created_at": str(context.created_at),
        "expires_at": context.expires_at,
        "metadata": getattr(context, "metadata", {}),
    }


_manager_instances: dict[str, MemoryContextManager] = {}
_manager_lock = threading.Lock()


def get_memory_manager(
    storage_path: str | Path | None = None,
    default_ttl: float = 3600.0,
    max_entries: int = 1000,
) -> MemoryContextManager:
    """Get or create singleton MemoryContextManager instance for storage path."""
    path_key = str(Path(storage_path).resolve()) if storage_path else "default"
    with _manager_lock:
        if path_key not in _manager_instances:
            kwargs: dict[str, Any] = {
                "default_ttl": default_ttl,
                "max_entries": max_entries,
            }
            if storage_path is not None:
                kwargs["storage_path"] = str(storage_path)
            _manager_instances[path_key] = MemoryContextManager(**kwargs)
        return _manager_instances[path_key]
