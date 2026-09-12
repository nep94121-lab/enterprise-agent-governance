"""
Memory Context Manager
A TTL-based memory context system with priority eviction, JSON persistence,
cross-process file locking, and multi-agent context sharing for MCP integration.
"""

from __future__ import annotations

import atexit
import contextlib
import json
import os
import random
import shutil
import sys
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any


def validate_storage_path(path: str | Path | None) -> Path:
    """
    Validate and normalize memory storage path against path traversal,
    null bytes, and sensitive system root directories (Mục 14).
    """
    if path is None:
        return Path("memory_contexts.json").resolve()

    raw_str = str(path).strip()
    if not raw_str:
        return Path("memory_contexts.json").resolve()

    if "\0" in raw_str:
        raise ValueError(f"Storage path contains null bytes: {raw_str!r}")

    resolved_path = Path(raw_str).expanduser().resolve()

    # Disallow root drive directly (e.g. C:\ or /) or directly at root level
    if resolved_path == Path(resolved_path.anchor) or resolved_path.parent == Path(resolved_path.anchor):
        raise ValueError(f"Storage path cannot be in root directory: {resolved_path}")

    # Check restricted system directories
    restricted_dirs: list[Path] = [
        Path("/etc").resolve(),
        Path("/bin").resolve(),
        Path("/sbin").resolve(),
        Path("/usr").resolve(),
        Path("/root").resolve(),
        Path("/var").resolve(),
    ]
    if sys.platform == "win32":
        sys_root = os.environ.get("SystemRoot", "C:\\Windows")
        restricted_dirs.extend([
            Path(sys_root).resolve(),
            Path(sys_root, "System32").resolve(),
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")).resolve(),
            Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")).resolve(),
        ])

    for restricted in restricted_dirs:
        try:
            resolved_path.relative_to(restricted)
            raise ValueError(
                f"Storage path is inside restricted system directory ({restricted}): {resolved_path}"
            )
        except ValueError as e:
            if "restricted system directory" in str(e):
                raise

    if resolved_path.is_dir() or not resolved_path.suffix:
        resolved_path = resolved_path / "memory_contexts.json"
    elif resolved_path.suffix.lower() != ".json":
        raise ValueError(
            f"Storage path must have .json extension or be a directory: {resolved_path}"
        )

    return resolved_path


def _atomic_replace(
    temp_path: Path,
    target_path: Path,
    max_retries: int = 25,
    max_timeout: float = 5.0,
) -> None:
    """
    Atomically replace target_path with temp_path, with adaptive backoff
    specifically tailored for Windows NTFS file sharing violations and file locks (Mục 12).
    """
    start_time = time.time()
    delay = 0.025
    last_err: Exception | None = None

    for attempt in range(max_retries):
        try:
            temp_path.replace(target_path)
            return
        except (PermissionError, OSError) as e:
            last_err = e
            elapsed = time.time() - start_time
            if elapsed >= max_timeout or attempt == max_retries - 1:
                break
            time.sleep(delay + random.uniform(0.005, 0.025))
            delay = min(delay * 1.5, 0.5)

    raise OSError(
        f"Failed to atomically replace {target_path} after {max_retries} attempts "
        f"({time.time() - start_time:.2f}s): {last_err}"
    ) from last_err


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


class MemoryLockTimeoutError(TimeoutError, RuntimeError):
    """Exception raised when memory context manager fails to acquire lock."""
    pass


@contextlib.contextmanager
def file_lock(lock_path: Path, timeout: float = 5.0, poll_interval: float = 0.02):
    """
    Cross-platform inter-process file lock.
    Uses msvcrt on Windows and fcntl on Unix/Linux.
    Raises MemoryLockTimeoutError if the lock cannot be acquired within timeout seconds (Mục 9).
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
                    # Timeout reached: break to avoid hanging indefinitely
                    break
                time.sleep(poll_interval)

        if not locked:
            raise MemoryLockTimeoutError(
                f"Failed to acquire lock for memory context manager: Failed to acquire file lock within {timeout:.2f}s on {lock_path}"
            )
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
        storage_path: str | Path = "memory_contexts.json",
        default_ttl: float = 3600.0,
        max_entries: int = 1000,
        auto_persist: bool = True,
        persist_interval: float = 60.0
    ):
        self._storage_path = validate_storage_path(storage_path)
        self._backup_path = self._storage_path.with_name(self._storage_path.name + ".bak")
        self._default_ttl = default_ttl
        self._max_entries = max_entries
        self._auto_persist = auto_persist
        self._persist_interval = persist_interval

        self._contexts: dict[str, MemoryContext] = {}
        self._handoffs: dict[str, ContextHandoff] = {}
        self._lock = threading.RLock()

        self._dirty: bool = False
        self._load_failed: bool = False
        self._recovered_from_backup: bool = False
        self._last_loaded_mtime: float = 0.0
        self._deleted_context_ids: set[str] = set()

        self._last_persist_time = time.time()
        self._load()

        # Register atexit handler to ensure short-lived processes persist changes (Mục 13)
        atexit.register(self._atexit_flush)

    def _atexit_flush(self) -> None:
        """Ensure in-memory changes are persisted when process terminates (Mục 13)."""
        if not self._auto_persist:
            return
        try:
            self.flush()
        except Exception as e:
            print(f"[WARN] MemoryContextManager: atexit flush failed: {e}", file=sys.stderr)

    def flush(self) -> None:
        """Explicitly flush all pending in-memory changes to disk immediately (Mục 13)."""
        with self._lock:
            if self._dirty:
                self.persist()

    def _read_from_disk_locked(self) -> None:
        """Read data from storage path with backup fallback and corruption preservation (Mục 10)."""
        if not self._storage_path.exists():
            return

        data = None
        read_error = None
        try:
            with open(self._storage_path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, KeyError, TypeError, OSError) as e:
            read_error = e
            print(
                f"[ERROR] MemoryContextManager: Failed to load {self._storage_path}: {e}",
                file=sys.stderr,
            )

        if read_error is not None:
            # Preserve corrupted file for forensics instead of silent wipe (Mục 10)
            try:
                corrupt_path = self._storage_path.with_name(
                    f"{self._storage_path.stem}.corrupt.{int(time.time())}.json"
                )
                shutil.copy2(self._storage_path, corrupt_path)
                print(
                    f"[WARN] MemoryContextManager: Preserved corrupted file at {corrupt_path}",
                    file=sys.stderr,
                )
            except Exception:
                pass

            # Try loading from backup file
            if self._backup_path.exists():
                try:
                    with open(self._backup_path, encoding="utf-8") as f:
                        data = json.load(f)
                    print(
                        f"[INFO] MemoryContextManager: Successfully recovered from backup {self._backup_path}",
                        file=sys.stderr,
                    )
                    self._recovered_from_backup = True
                except Exception as bak_err:
                    print(
                        f"[ERROR] MemoryContextManager: Failed to load backup {self._backup_path}: {bak_err}",
                        file=sys.stderr,
                    )
                    self._load_failed = True
            else:
                self._load_failed = True

        if data and isinstance(data, dict):
            current_time = time.time()
            contexts_data = data.get("contexts", [])
            for ctx_data in contexts_data:
                try:
                    ctx = MemoryContext.from_dict(ctx_data)
                    if not ctx.is_expired(current_time):
                        self._contexts[ctx.id] = ctx
                except Exception:
                    pass

            handoffs_data = data.get("handoffs", [])
            for hand_data in handoffs_data:
                try:
                    hand = ContextHandoff.from_dict(hand_data)
                    if hand.is_pending():
                        self._handoffs[hand.id] = hand
                except Exception:
                    pass

            try:
                self._last_loaded_mtime = self._storage_path.stat().st_mtime
            except Exception:
                self._last_loaded_mtime = time.time()

    def _load(self) -> None:
        """Load contexts and handoffs from JSON file with inter-process locking (Mục 9, 10)."""
        with self._lock:
            if not self._storage_path.exists():
                return

            lock_path = self._storage_path.with_suffix(".lock")
            try:
                with file_lock(lock_path, timeout=5.0):
                    self._read_from_disk_locked()
            except TimeoutError as te:
                print(
                    f"[WARN] MemoryContextManager: lock timeout acquiring {lock_path} during _load(): {te}. "
                    "Attempting optimistic read from disk.",
                    file=sys.stderr,
                )
                try:
                    self._read_from_disk_locked()
                except Exception as e:
                    print(
                        f"[ERROR] MemoryContextManager: Optimistic read failed: {e}",
                        file=sys.stderr,
                    )

    def _merge_from_disk_locked(self) -> None:
        """
        Merge latest changes from disk into local memory state while holding lock.
        Prevents multi-process race conditions from overwriting concurrent updates (Mục 11).
        """
        if not self._storage_path.exists():
            return

        try:
            with open(self._storage_path, "r", encoding="utf-8") as f:
                disk_data = json.load(f)
        except Exception:
            return

        if not isinstance(disk_data, dict):
            return

        current_time = time.time()

        # 1. Merge contexts
        disk_contexts: dict[str, MemoryContext] = {}
        for c_dict in disk_data.get("contexts", []):
            try:
                c = MemoryContext.from_dict(c_dict)
                disk_contexts[c.id] = c
            except Exception:
                pass

        for c_id, disk_c in disk_contexts.items():
            if c_id in self._deleted_context_ids:
                # Explicitly deleted by this instance
                continue

            if c_id not in self._contexts:
                # Context created by another process
                if not disk_c.is_expired(current_time):
                    self._contexts[c_id] = disk_c
            else:
                # Exists in both; adopt newer last_accessed
                local_c = self._contexts[c_id]
                if disk_c.last_accessed > local_c.last_accessed:
                    self._contexts[c_id] = disk_c

        # 2. Merge handoffs
        disk_handoffs: dict[str, ContextHandoff] = {}
        for h_dict in disk_data.get("handoffs", []):
            try:
                h = ContextHandoff.from_dict(h_dict)
                disk_handoffs[h.id] = h
            except Exception:
                pass

        for h_id, disk_h in disk_handoffs.items():
            if h_id not in self._handoffs:
                self._handoffs[h_id] = disk_h
            else:
                local_h = self._handoffs[h_id]
                if local_h.is_pending() and not disk_h.is_pending():
                    self._handoffs[h_id] = disk_h
                elif not local_h.is_pending() and not disk_h.is_pending():
                    if disk_h.completed_at > local_h.completed_at:
                        self._handoffs[h_id] = disk_h

    def _maybe_reload_from_disk(self) -> None:
        """Check if file on disk was updated by another process and merge if needed (Mục 11)."""
        if not self._storage_path.exists():
            return
        try:
            mtime = self._storage_path.stat().st_mtime
            if mtime > self._last_loaded_mtime:
                lock_path = self._storage_path.with_suffix(".lock")
                with file_lock(lock_path, timeout=2.0):
                    self._merge_from_disk_locked()
                    self._last_loaded_mtime = self._storage_path.stat().st_mtime
        except Exception:
            pass

    def persist(self) -> None:
        """Persist contexts and handoffs to JSON file with inter-process locking and multi-process merge (Mục 10, 11, 12)."""
        with self._lock:
            # Guard against erasing data if load previously failed and local in-memory state is empty (Mục 10)
            if self._load_failed and len(self._contexts) == 0 and len(self._handoffs) == 0:
                if self._storage_path.exists() and self._storage_path.stat().st_size > 0:
                    raise RuntimeError(
                        f"Refusing to overwrite existing non-empty storage file {self._storage_path} "
                        "with empty state after load failure. Preserving disk data."
                    )

            lock_path = self._storage_path.with_suffix(".lock")
            with file_lock(lock_path, timeout=10.0):
                # Reload and merge latest changes from disk before persisting (Mục 11)
                self._merge_from_disk_locked()

                data = {
                    "contexts": [ctx.to_dict() for ctx in self._contexts.values()],
                    "handoffs": [hand.to_dict() for hand in self._handoffs.values()],
                    "saved_at": time.time(),
                }

                self._storage_path.parent.mkdir(parents=True, exist_ok=True)

                temp_path = self._storage_path.with_name(
                    f"{self._storage_path.stem}_{uuid.uuid4().hex[:8]}.tmp"
                )
                try:
                    with open(temp_path, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)

                    # Atomic replacement with adaptive backoff for Windows NTFS (Mục 12)
                    _atomic_replace(temp_path, self._storage_path)

                    # Update backup copy for fault tolerance
                    try:
                        shutil.copy2(self._storage_path, self._backup_path)
                    except Exception:
                        pass

                    try:
                        self._last_loaded_mtime = self._storage_path.stat().st_mtime
                    except Exception:
                        self._last_loaded_mtime = time.time()
                    self._dirty = False
                    self._load_failed = False
                finally:
                    if temp_path.exists():
                        try:
                            temp_path.unlink()
                        except Exception:
                            pass

                self._last_persist_time = time.time()

    def _persist_cleared_locked(self) -> None:
        """Directly persist empty state when explicitly cleared by user."""
        lock_path = self._storage_path.with_suffix(".lock")
        with file_lock(lock_path, timeout=10.0):
            data = {
                "contexts": [],
                "handoffs": [],
                "saved_at": time.time(),
            }
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = self._storage_path.with_name(
                f"{self._storage_path.stem}_{uuid.uuid4().hex[:8]}.tmp"
            )
            try:
                with open(temp_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                _atomic_replace(temp_path, self._storage_path)
                try:
                    shutil.copy2(self._storage_path, self._backup_path)
                except Exception:
                    pass
                try:
                    self._last_loaded_mtime = self._storage_path.stat().st_mtime
                except Exception:
                    self._last_loaded_mtime = time.time()
                self._dirty = False
                self._load_failed = False
            finally:
                if temp_path.exists():
                    try:
                        temp_path.unlink()
                    except Exception:
                        pass
            self._last_persist_time = time.time()

    def _maybe_persist(self) -> None:
        """Auto-persist if interval elapsed or zero-interval and enabled (Mục 13)."""
        if self._auto_persist:
            if self._persist_interval <= 0:
                self.persist()
            elif time.time() - self._last_persist_time >= self._persist_interval:
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

            self._deleted_context_ids.discard(context.id)
            self._contexts[context.id] = context
            self._dirty = True
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

            self._deleted_context_ids.discard(context.id)
            self._contexts[context.id] = context
            self._dirty = True
            self._maybe_persist()
            return context

    def get(self, context_id: str) -> MemoryContext | None:
        """Retrieve a context by ID, updating last_accessed time."""
        with self._lock:
            if context_id not in self._contexts:
                self._maybe_reload_from_disk()

            context = self._contexts.get(context_id)
            if context is None:
                return None

            if context.is_expired():
                del self._contexts[context_id]
                self._deleted_context_ids.add(context_id)
                self._dirty = True
                self._maybe_persist()
                return None

            context.touch()
            return context

    def get_by_key(self, key: str) -> MemoryContext | None:
        """Retrieve the most recent non-expired context by key."""
        with self._lock:
            self._maybe_reload_from_disk()
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
            self._maybe_reload_from_disk()
            return [
                ctx for ctx in self._contexts.values()
                if ctx.key == key and not ctx.is_expired()
            ]

    def get_by_tag(self, tag: str) -> list[MemoryContext]:
        """Retrieve all contexts with a specific tag."""
        with self._lock:
            self._maybe_reload_from_disk()
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
            self._maybe_reload_from_disk()
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
            self._maybe_reload_from_disk()
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
            self._deleted_context_ids.add(context_id)
            if context_id in self._contexts:
                del self._contexts[context_id]
                self._dirty = True
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
                self._deleted_context_ids.add(ctx_id)
                del self._contexts[ctx_id]

            if expired_ids:
                self._dirty = True
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
            self._deleted_context_ids.add(ctx.id)
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
            self._dirty = True
            self._maybe_persist()
            return handoff

    def get_handoff(self, handoff_id: str) -> ContextHandoff | None:
        """Get a handoff by ID."""
        with self._lock:
            if handoff_id not in self._handoffs:
                self._maybe_reload_from_disk()
            return self._handoffs.get(handoff_id)

    def complete_handoff(self, handoff_id: str) -> bool:
        """Mark a handoff as completed."""
        with self._lock:
            handoff = self._handoffs.get(handoff_id)
            if handoff is None:
                return False
            handoff.complete()
            self._dirty = True
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

            self._dirty = True
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
            self._maybe_reload_from_disk()
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
            self._maybe_reload_from_disk()
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
            self._deleted_context_ids.clear()
            self._dirty = True
            self._persist_cleared_locked()

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
    validated_path = validate_storage_path(storage_path) if storage_path else None
    path_key = str(validated_path) if validated_path else "default"
    with _manager_lock:
        if path_key not in _manager_instances:
            kwargs: dict[str, Any] = {
                "default_ttl": default_ttl,
                "max_entries": max_entries,
            }
            if validated_path is not None:
                kwargs["storage_path"] = validated_path
            _manager_instances[path_key] = MemoryContextManager(**kwargs)
        return _manager_instances[path_key]
