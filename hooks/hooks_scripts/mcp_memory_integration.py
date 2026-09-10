#!/usr/bin/env python3
"""
MCP Memory Integration Hook for Claude Code Multi-Agent Context Sharing.

This module provides:
1. Adapter Layer (MemoryContextAdapter) bridging MCP Memory interface with MemoryContextManager
2. MCP tool definitions for memory operations (mcp__memory__share_context, etc.)
3. PreInvocation hook to inject shared context into agent prompts
4. PostInvocation hook to capture and store agent context
5. Context & Handoff serialization/deserialization utilities

Usage:
    python hooks_scripts/mcp_memory_integration.py --action=pre-invocation
    python hooks_scripts/mcp_memory_integration.py --action=post-invocation
    python hooks_scripts/mcp_memory_integration.py --action=store-context
    python hooks_scripts/mcp_memory_integration.py --action=get-shared
    python hooks_scripts/mcp_memory_integration.py --action=create-handoff
    python hooks_scripts/mcp_memory_integration.py --action=get-handoffs
    python hooks_scripts/mcp_memory_integration.py --action=update-handoff
    python hooks_scripts/mcp_memory_integration.py --action=list-tools
    python hooks_scripts/mcp_memory_integration.py --action=stats
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Ensure UTF-8 I/O encoding across platforms (Windows PowerShell safe)
try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

# Add hooks_scripts directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from memory_context_manager import (
    ContextHandoff,
    MemoryContext,
    MemoryContextManager,
    Priority,
)

# ============================================================================
# Safe Default Storage Configuration (Avoid Workspace Pollution)
# ============================================================================

DEFAULT_STORAGE_DIR = (
    Path.home() / ".gemini" / "config" / "enterprise-hooks" / ".memory_context"
)
DEFAULT_STORAGE_FILE = DEFAULT_STORAGE_DIR / "memory_contexts.json"


def get_default_storage_path() -> Path:
    """
    Get the default storage path for memory contexts.

    Avoids polluting the workspace directory by defaulting to:
    ~/.gemini/config/enterprise-hooks/.memory_context/memory_contexts.json
    or via MEMORY_STORAGE_PATH environment variable if explicitly configured.
    """
    env_path = os.environ.get("MEMORY_STORAGE_PATH")
    if env_path:
        p = Path(env_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    DEFAULT_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_STORAGE_FILE


# ============================================================================
# Secret & PII Redaction Engine (§1, §2)
# ============================================================================

SECRET_PATTERNS: list[tuple[re.Pattern, Any]] = [
    # Specific API Keys first: OpenAI, Anthropic, Gemini, GitHub, AWS
    (re.compile(r"sk-[a-zA-Z0-9_-]{20,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{30,45}"), "[REDACTED_GEMINI_KEY]"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"), "[REDACTED_GITHUB_TOKEN]"),
    (
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        "[REDACTED_AWS_KEY]",
    ),
    # Private Keys
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # JWT Tokens
    (
        re.compile(
            r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+"
        ),
        "[REDACTED_JWT]",
    ),
    # Authorization header / Bearer token
    (
        re.compile(r"(?i)(?:bearer|token)\s+[a-zA-Z0-9_\-\.]{15,}"),
        "Bearer [REDACTED_TOKEN]",
    ),
    # Generic API Key / Secret assignments
    (
        re.compile(
            r"""(?i)(api[_-]?key|client[_-]?secret|auth[_-]?token|secret[_-]?key)\s*([:=])\s*(['"][a-zA-Z0-9_\-\.]{10,}['"]|[a-zA-Z0-9_\-\.]{10,})"""
        ),
        r'\1\2"[REDACTED_SECRET]"',
    ),
    # Database connection strings with passwords
    (
        re.compile(
            r"(?i)((?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^:]+:)([^@]+)(@)"
        ),
        r"\1[REDACTED_PASSWORD]\3",
    ),
    # §1 Base64 Raw Data (> 128 characters)
    (
        re.compile(
            r"(?:[A-Za-z0-9+/]{4}){32,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
        ),
        lambda m: f"[REDACTED_BASE64 len={len(m.group(0))}]",
    ),
]

SENSITIVE_KEY_NAMES: set[str] = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "private_key",
    "jwt",
    "token",
    "signature",
    "id_card",
    "passport",
    "biometric",
}


def redact_string(text: str) -> str:
    """Scrub secrets, tokens, API keys, and sensitive PII from a single string."""
    if not isinstance(text, str):
        return text
    scrubbed = text
    for pattern, replacement in SECRET_PATTERNS:
        if callable(replacement):
            scrubbed = pattern.sub(replacement, scrubbed)
        else:
            scrubbed = pattern.sub(replacement, scrubbed)
    return scrubbed


def redact_secrets(value: Any) -> Any:
    """Recursively scrub secrets, API keys, and PII from dicts, lists, sets, and strings."""
    if isinstance(value, dict):
        sanitized_dict: dict[str, Any] = {}
        for k, v in value.items():
            key_str = str(k).lower()
            if any(
                sens in key_str
                for sens in ("signature", "id_card", "passport", "biometric")
            ):
                sanitized_dict[k] = f"[REDACTED_PII len={len(str(v))}]"
            elif any(
                sens in key_str
                for sens in (
                    "password",
                    "passwd",
                    "pwd",
                    "client_secret",
                    "private_key",
                    "api_key",
                    "apikey",
                    "secret",
                )
            ):
                sanitized_dict[k] = "[REDACTED_SECRET]"
            elif (
                any(
                    sens in key_str
                    for sens in ("access_token", "auth_token", "jwt", "token")
                )
                and isinstance(v, str)
                and len(v) > 10
            ):
                sanitized_dict[k] = "[REDACTED_SECRET]"
            else:
                sanitized_dict[k] = redact_secrets(v)
        return sanitized_dict
    elif isinstance(value, list):
        return [redact_secrets(item) for item in value]
    elif isinstance(value, tuple):
        return tuple(redact_secrets(item) for item in value)
    elif isinstance(value, set):
        return {redact_secrets(item) for item in value}
    elif isinstance(value, str):
        return redact_string(value)
    return value


# ============================================================================
# Priority & Type Helpers
# ============================================================================

def map_priority(priority: int | str | Priority | None) -> int:
    """Map various priority representations to Priority int enum value (0-3)."""
    if priority is None:
        return Priority.NORMAL.value
    if isinstance(priority, Priority):
        return priority.value
    if isinstance(priority, str):
        p_lower = priority.strip().lower()
        if p_lower == "critical":
            return Priority.CRITICAL.value
        elif p_lower == "high":
            return Priority.HIGH.value
        elif p_lower == "low":
            return Priority.LOW.value
        elif p_lower == "normal":
            return Priority.NORMAL.value
        elif p_lower.isdigit():
            val = int(p_lower)
            return map_priority(val)
        return Priority.NORMAL.value
    if isinstance(priority, (int, float)):
        val = int(priority)
        if val <= 1:
            return Priority.LOW.value
        elif val <= 5:
            return Priority.NORMAL.value
        elif val <= 8:
            return Priority.HIGH.value
        else:
            return Priority.CRITICAL.value
    return Priority.NORMAL.value


def _to_timestamp(val: Any) -> float:
    """Convert epoch timestamp float/int or ISO 8601 string to epoch float."""
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0
    return 0.0


def serialize_context_for_mcp(
    ctx: MemoryContext, redact: bool = True
) -> dict[str, Any]:
    """Serialize MemoryContext into MCP-compliant dictionary with secret redaction."""
    created_at_iso = (
        datetime.fromtimestamp(ctx.created_at, tz=UTC).isoformat()
        if isinstance(ctx.created_at, (int, float))
        else str(ctx.created_at)
    )
    expires_at_iso = (
        datetime.fromtimestamp(ctx.expires_at, tz=UTC).isoformat()
        if ctx.expires_at and ctx.expires_at > 0
        else None
    )
    data = {
        "context_id": ctx.id,
        "id": ctx.id,
        "key": ctx.key,
        "agent_id": ctx.metadata.get("agent_id", ""),
        "agent_name": ctx.metadata.get("agent_name", ""),
        "context_type": ctx.metadata.get("context_type", "general"),
        "content": ctx.value,
        "value": ctx.value,
        "priority": ctx.priority,
        "tags": ctx.tags,
        "created_at": created_at_iso,
        "expires_at": expires_at_iso,
        "ttl_remaining": ctx.time_to_live(),
        "metadata": ctx.metadata,
    }
    if redact:
        return redact_secrets(data)
    return data


def serialize_handoff_for_mcp(
    handoff: ContextHandoff, redact: bool = True
) -> dict[str, Any]:
    """Serialize ContextHandoff into MCP-compliant dictionary with secret redaction."""
    created_at_iso = (
        datetime.fromtimestamp(handoff.created_at, tz=UTC).isoformat()
        if isinstance(handoff.created_at, (int, float))
        else str(handoff.created_at)
    )
    completed_at_iso = (
        datetime.fromtimestamp(handoff.completed_at, tz=UTC).isoformat()
        if handoff.completed_at and handoff.completed_at > 0
        else None
    )
    data = {
        "handoff_id": handoff.id,
        "id": handoff.id,
        "source_context_id": handoff.source_context_id,
        "from_agent": handoff.metadata.get("from_agent", ""),
        "to_agent": handoff.target_agent,
        "target_agent": handoff.target_agent,
        "task_summary": handoff.metadata.get(
            "task_summary", handoff.payload.get("task_summary", "")
        ),
        "pending_tasks": handoff.metadata.get(
            "pending_tasks", handoff.payload.get("pending_tasks", [])
        ),
        "decisions_made": handoff.metadata.get(
            "decisions_made", handoff.payload.get("decisions_made", [])
        ),
        "priority": handoff.priority,
        "status": handoff.status,
        "created_at": created_at_iso,
        "completed_at": completed_at_iso,
        "metadata": handoff.metadata,
        "payload": handoff.payload,
    }
    if redact:
        return redact_secrets(data)
    return data


# ============================================================================
# Memory Context Adapter
# ============================================================================


class MemoryContextAdapter:
    """Adapter bridging MCP Memory operations with MemoryContextManager."""

    def __init__(self, storage_path: str | Path | None = None):
        if storage_path:
            path = Path(storage_path)
            path.parent.mkdir(parents=True, exist_ok=True)
        else:
            path = get_default_storage_path()
        self._storage_path = path
        self._manager = MemoryContextManager(storage_path=str(path))

    @property
    def storage_path(self) -> Path:
        """Return the resolved storage path for context database."""
        return self._storage_path

    @property
    def manager(self) -> MemoryContextManager:
        return self._manager

    def store_context(
        self,
        agent_id: str,
        agent_name: str,
        context_type: str,
        content: dict[str, Any] | Any,
        priority: int | str = 5,
        tags: list[str] | None = None,
        ttl: int | float | None = 3600,
        redact: bool = True,
    ) -> MemoryContext:
        """Store a context via MemoryContextManager with secret redaction."""
        sanitized_content = redact_secrets(content) if redact else content
        p_val = map_priority(priority)
        all_tags = list(tags) if tags else []
        if context_type not in all_tags:
            all_tags.append(context_type)
        agent_tag = f"agent:{agent_id}"
        if agent_tag not in all_tags:
            all_tags.append(agent_tag)

        metadata = {
            "agent_id": agent_id,
            "agent_name": agent_name,
            "context_type": context_type,
        }

        key = f"{context_type}:{uuid.uuid4().hex[:8]}"
        ttl_val = float(ttl) if ttl is not None and ttl > 0 else 0.0

        ctx = self._manager.set(
            key=key,
            value=sanitized_content,
            priority=p_val,
            ttl=ttl_val,
            tags=all_tags,
            metadata=metadata,
        )
        self._manager.persist()
        return ctx

    def query_contexts(
        self,
        agent_id: str | None = None,
        context_type: str | None = None,
        tags: list[str] | None = None,
        min_priority: int = 0,
    ) -> list[MemoryContext]:
        """Query contexts with multiple filter criteria."""
        contexts = self._manager.get_all()

        filtered: list[MemoryContext] = []
        for ctx in contexts:
            if ctx.priority < min_priority:
                continue

            if agent_id:
                ctx_agent_id = ctx.metadata.get("agent_id")
                ctx_agent_name = ctx.metadata.get("agent_name")
                if (
                    ctx_agent_id != agent_id
                    and ctx_agent_name != agent_id
                    and f"agent:{agent_id}" not in ctx.tags
                ):
                    continue

            if context_type and context_type != "all":
                ctx_type = ctx.metadata.get("context_type")
                if (
                    ctx_type != context_type
                    and context_type not in ctx.tags
                    and not ctx.key.startswith(f"{context_type}:")
                ):
                    continue

            if tags:
                if not all(t in ctx.tags for t in tags):
                    continue

            filtered.append(ctx)

        filtered.sort(key=lambda c: (c.priority, c.last_accessed), reverse=True)
        return filtered

    def get_shared_context(
        self,
        max_age_seconds: int | float | None = None,
        limit: int = 10,
        exclude_agent_id: str | None = None,
        redact: bool = True,
    ) -> dict[str, Any]:
        """Retrieve shared contexts for other agents with secrets redacted."""
        contexts = self.query_contexts()

        if max_age_seconds is not None:
            now = time.time()
            contexts = [
                c
                for c in contexts
                if (now - _to_timestamp(c.created_at)) <= max_age_seconds
            ]

        if exclude_agent_id:
            contexts = [
                c for c in contexts if c.metadata.get("agent_id") != exclude_agent_id
            ]

        contexts = contexts[:limit]

        return {
            "context_count": len(contexts),
            "shared_contexts": [
                serialize_context_for_mcp(c, redact=redact) for c in contexts
            ],
            "retrieved_at": datetime.now(UTC).isoformat(),
        }

    def create_handoff(
        self,
        from_agent: str,
        to_agent: str,
        task_summary: str,
        context_snapshot: dict[str, Any] | None = None,
        pending_tasks: list[dict[str, Any]] | None = None,
        decisions_made: list[str] | None = None,
        priority: str | int = "normal",
        redact: bool = True,
    ) -> ContextHandoff:
        """Create a handoff with source context and metadata, sanitizing secrets."""
        p_val = map_priority(priority)
        s_summary = redact_string(task_summary) if redact else task_summary
        s_context_snapshot = (
            redact_secrets(context_snapshot or {})
            if redact
            else (context_snapshot or {})
        )
        s_pending_tasks = (
            redact_secrets(pending_tasks or []) if redact else (pending_tasks or [])
        )
        s_decisions_made = (
            [redact_string(d) for d in (decisions_made or [])]
            if redact
            else (decisions_made or [])
        )

        payload = {
            "task_summary": s_summary,
            "pending_tasks": s_pending_tasks,
            "decisions_made": s_decisions_made,
            "context_snapshot": s_context_snapshot,
        }

        source_ctx = self._manager.set(
            key=f"handoff_payload:{to_agent}:{uuid.uuid4().hex[:8]}",
            value=payload,
            priority=p_val,
            ttl=86400,
            tags=["handoff", f"to:{to_agent}", f"from:{from_agent}"],
            metadata={
                "from_agent": from_agent,
                "to_agent": to_agent,
                "context_type": "handoff",
            },
        )

        metadata = {
            "from_agent": from_agent,
            "task_summary": s_summary,
            "pending_tasks": s_pending_tasks,
            "decisions_made": s_decisions_made,
        }

        handoff = self._manager.create_handoff(
            source_context_id=source_ctx.id,
            target_agent=to_agent,
            priority=p_val,
            metadata=metadata,
        )

        if handoff is None:
            handoff = ContextHandoff(
                source_context_id=source_ctx.id,
                target_agent=to_agent,
                payload=payload,
                priority=p_val,
                metadata=metadata,
            )
            with self._manager._lock:
                self._manager._handoffs[handoff.id] = handoff

        self._manager.persist()
        return handoff

    def get_pending_handoffs(
        self,
        for_agent: str | None = None,
        status: str | None = "pending",
    ) -> list[ContextHandoff]:
        """Get handoffs filtered by agent and status."""
        with self._manager._lock:
            all_handoffs = list(self._manager._handoffs.values())

        filtered: list[ContextHandoff] = []
        for h in all_handoffs:
            if status and status != "all":
                if status == "pending" and not h.is_pending():
                    continue
                elif status != "pending" and h.status != status:
                    continue

            if for_agent and h.target_agent != for_agent:
                continue

            filtered.append(h)

        filtered.sort(key=lambda h: (h.priority, h.created_at), reverse=True)
        return filtered

    def update_handoff_status(
        self,
        handoff_id: str,
        status: str,
        additional_notes: str | None = None,
    ) -> ContextHandoff | None:
        """Update handoff status and notes."""
        with self._manager._lock:
            handoff = self._manager.get_handoff(handoff_id)
            if handoff is None:
                return None

            if status == "completed":
                handoff.complete()
            elif status == "failed":
                handoff.fail(additional_notes or "")
            else:
                handoff.status = status

            if additional_notes:
                handoff.metadata["notes"] = redact_string(additional_notes)

            self._manager.persist()
            return handoff

    def get_stats(self) -> dict[str, Any]:
        """Get statistics from underlying manager."""
        return self._manager.get_stats()


_adapter_singleton: MemoryContextAdapter | None = None


def get_memory_manager(
    storage_path: str | Path | None = None,
) -> MemoryContextAdapter:
    """Get or create singleton MemoryContextAdapter."""
    global _adapter_singleton
    if _adapter_singleton is None:
        _adapter_singleton = MemoryContextAdapter(storage_path=storage_path)
    elif storage_path is not None:
        target_path = Path(storage_path).resolve()
        if _adapter_singleton.storage_path.resolve() != target_path:
            _adapter_singleton = MemoryContextAdapter(storage_path=target_path)
    return _adapter_singleton


def reset_memory_manager() -> None:
    """Reset the singleton adapter for testing purposes."""
    global _adapter_singleton
    _adapter_singleton = None


# ============================================================================
# MCP Tool Definitions
# ============================================================================

MCP_TOOL_DEFINITIONS = {
    "mcp__memory__share_context": {
        "name": "mcp__memory__share_context",
        "description": "Share context with other agents in the multi-agent system. Stores current context for retrieval by other agents.",
        "input_schema": {
            "type": "object",
            "properties": {
                "context_type": {
                    "type": "string",
                    "enum": ["general", "task", "state", "handoff", "decision"],
                    "description": "Type of context being shared",
                },
                "content": {
                    "type": "object",
                    "description": "The context content to share",
                },
                "priority": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 10,
                    "default": 5,
                    "description": "Priority level (0-10, higher is more important)",
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Tags for categorization and filtering",
                },
                "ttl_seconds": {
                    "type": "integer",
                    "minimum": 60,
                    "maximum": 86400,
                    "description": "Time-to-live in seconds (default: 3600)",
                },
            },
            "required": ["context_type", "content"],
        },
    },
    "mcp__memory__get_shared": {
        "name": "mcp__memory__get_shared",
        "description": "Retrieve shared context from other agents. Use this to get context that other agents have shared.",
        "input_schema": {
            "type": "object",
            "properties": {
                "context_type": {
                    "type": "string",
                    "enum": ["general", "task", "state", "handoff", "decision", "all"],
                    "description": "Filter by context type",
                },
                "agent_name": {
                    "type": "string",
                    "description": "Filter by source agent name",
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by tags (all must match)",
                },
                "max_age_seconds": {
                    "type": "integer",
                    "description": "Only return contexts newer than this",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                    "default": 10,
                    "description": "Maximum number of contexts to return",
                },
            },
        },
    },
    "mcp__memory__create_handoff": {
        "name": "mcp__memory__create_handoff",
        "description": "Create a handoff to another agent with full context transfer.",
        "input_schema": {
            "type": "object",
            "properties": {
                "to_agent": {
                    "type": "string",
                    "description": "Target agent identifier",
                },
                "task_summary": {
                    "type": "string",
                    "description": "Brief summary of what the receiving agent should do",
                },
                "pending_tasks": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Tasks waiting for the next agent",
                },
                "decisions_made": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Key decisions made by this agent",
                },
                "priority": {
                    "type": "string",
                    "enum": ["low", "normal", "high", "critical"],
                    "default": "normal",
                },
            },
            "required": ["to_agent", "task_summary"],
        },
    },
    "mcp__memory__get_handoffs": {
        "name": "mcp__memory__get_handoffs",
        "description": "Get pending handoffs for this agent.",
        "input_schema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["pending", "in_progress", "completed", "all"],
                    "default": "pending",
                },
            },
        },
    },
    "mcp__memory__update_handoff": {
        "name": "mcp__memory__update_handoff",
        "description": "Update handoff status.",
        "input_schema": {
            "type": "object",
            "properties": {
                "handoff_id": {
                    "type": "string",
                    "description": "ID of the handoff to update",
                },
                "status": {
                    "type": "string",
                    "enum": ["in_progress", "completed", "failed"],
                    "description": "New status",
                },
                "notes": {
                    "type": "string",
                    "description": "Optional notes about the status change",
                },
            },
            "required": ["handoff_id", "status"],
        },
    },
}


# ============================================================================
# MCP Tool Handlers
# ============================================================================

class MCPMemoryToolHandler:
    """Handles MCP memory tool invocations."""

    def __init__(self, storage_path: str | Path | None = None):
        """Initialize the tool handler."""
        self.adapter = get_memory_manager(storage_path=storage_path)
        self.manager = self.adapter
        self._agent_id = self._detect_agent_id()
        self._agent_name = self._detect_agent_name()

    def _detect_agent_id(self) -> str:
        """Detect agent ID from environment or generate one."""
        return os.environ.get("AGENT_ID", f"agent-{uuid.uuid4().hex[:8]}")

    def _detect_agent_name(self) -> str:
        """Detect agent name from environment or use default."""
        return os.environ.get("AGENT_NAME", "Claude")

    def handle_share_context(
        self,
        context_type: str,
        content: dict[str, Any],
        priority: int = 5,
        tags: list[str] | None = None,
        ttl_seconds: int = 3600,
    ) -> dict[str, Any]:
        """Handle mcp__memory__share_context tool call."""
        ctx = self.adapter.store_context(
            agent_id=self._agent_id,
            agent_name=self._agent_name,
            context_type=context_type,
            content=content,
            priority=priority,
            tags=tags,
            ttl=ttl_seconds,
        )

        expires_at_iso = (
            datetime.fromtimestamp(ctx.expires_at, tz=UTC).isoformat()
            if ctx.expires_at > 0
            else None
        )

        return {
            "success": True,
            "context_id": ctx.id,
            "message": f"Context shared successfully with priority {priority}",
            "expires_at": expires_at_iso,
        }

    def handle_get_shared(
        self,
        context_type: str | None = None,
        agent_name: str | None = None,
        tags: list[str] | None = None,
        max_age_seconds: int | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        """Handle mcp__memory__get_shared tool call."""
        contexts = self.adapter.query_contexts(
            agent_id=agent_name,
            context_type=context_type
            if context_type and context_type != "all"
            else None,
            tags=tags,
            min_priority=0,
        )

        if max_age_seconds is not None:
            now = time.time()
            contexts = [
                c
                for c in contexts
                if (now - _to_timestamp(c.created_at)) <= max_age_seconds
            ]

        # Apply limit and exclude own context
        contexts = [
            c for c in contexts if c.metadata.get("agent_id") != self._agent_id
        ][:limit]

        return {
            "success": True,
            "context_count": len(contexts),
            "contexts": [serialize_context_for_mcp(c, redact=True) for c in contexts],
            "retrieved_at": datetime.now(UTC).isoformat(),
        }

    def handle_create_handoff(
        self,
        to_agent: str,
        task_summary: str,
        pending_tasks: list[dict[str, Any]] | None = None,
        decisions_made: list[str] | None = None,
        priority: str = "normal",
    ) -> dict[str, Any]:
        """Handle mcp__memory__create_handoff tool call."""
        handoff = self.adapter.create_handoff(
            from_agent=self._agent_name,
            to_agent=to_agent,
            task_summary=task_summary,
            context_snapshot={
                "last_agent": self._agent_name,
                "timestamp": datetime.now(UTC).isoformat(),
            },
            pending_tasks=pending_tasks,
            decisions_made=decisions_made,
            priority=priority,
            redact=True,
        )

        return {
            "success": True,
            "handoff_id": handoff.id,
            "message": f"Handoff created to {to_agent} with priority {priority}",
        }

    def handle_get_handoffs(
        self,
        status: str = "pending",
    ) -> dict[str, Any]:
        """Handle mcp__memory__get_handoffs tool call."""
        handoffs = self.adapter.get_pending_handoffs(
            for_agent=self._agent_name,
            status=status,
        )

        return {
            "success": True,
            "handoff_count": len(handoffs),
            "handoffs": [serialize_handoff_for_mcp(h, redact=True) for h in handoffs],
        }

    def handle_update_handoff(
        self,
        handoff_id: str,
        status: str,
        notes: str | None = None,
    ) -> dict[str, Any]:
        """Handle mcp__memory__update_handoff tool call."""
        handoff = self.adapter.update_handoff_status(
            handoff_id=handoff_id,
            status=status,
            additional_notes=notes,
        )

        if handoff:
            return {
                "success": True,
                "handoff_id": handoff.id,
                "new_status": status,
            }
        else:
            return {
                "success": False,
                "error": f"Handoff {handoff_id} not found",
            }


# ============================================================================
# PreInvocation Hook Integration
# ============================================================================


def generate_shared_context_injection(
    payload: dict[str, Any],
    storage_path: str | Path | None = None,
) -> dict[str, Any]:
    """Generate PreInvocation response with shared context injection and secret redaction."""
    adapter = get_memory_manager(storage_path=storage_path)

    invocation_num = payload.get("invocationNum", 0)
    tool_call = payload.get("toolCall", {})
    tool_name = ""
    if isinstance(tool_call, dict):
        tool_name = tool_call.get("name", "")

    inject_steps = []

    # Always include critical shared context on first invocation
    if invocation_num == 0:
        shared = adapter.get_shared_context(max_age_seconds=7200, redact=True)
        if shared.get("context_count", 0) > 0:
            context_text = _format_shared_context_for_injection(shared)
            inject_steps.append(
                {
                    "ephemeralMessage": f"🔄 [SHARED CONTEXT FROM OTHER AGENTS]\n{redact_string(context_text)}"
                }
            )

    # Include pending handoffs for this agent on every invocation
    agent_name = os.environ.get("AGENT_NAME", "Claude")
    handoffs = adapter.get_pending_handoffs(for_agent=agent_name, status="pending")
    if handoffs:
        handoff_text = _format_handoffs_for_injection(handoffs)
        inject_steps.append(
            {
                "ephemeralMessage": f"📋 [PENDING HANDOFFS FOR YOU]\n{redact_string(handoff_text)}"
            }
        )

    # Include recent task context for complex operations
    if tool_name in ("Bash", "Read", "Write", "Edit", "Glob", "Grep"):
        task_contexts = adapter.query_contexts(
            context_type="task",
            min_priority=3,
        )[:5]
        if task_contexts:
            task_text = _format_task_context_for_injection(task_contexts)
            inject_steps.append(
                {
                    "ephemeralMessage": f"📝 [RECENT TASK CONTEXT]\n{redact_string(task_text)}"
                }
            )

    return {"injectSteps": inject_steps} if inject_steps else {"injectSteps": []}


def _format_shared_context_for_injection(shared: dict[str, Any]) -> str:
    """Format shared context for injection into prompt with secrets scrubbed."""
    lines = []
    for ctx in shared.get("shared_contexts", [])[:5]:
        agent = ctx.get("agent_name", "Unknown Agent")
        ctx_type = ctx.get("context_type", "general")
        content = ctx.get("content", {})

        lines.append(f"\n[{agent}] ({ctx_type}):")
        if isinstance(content, dict):
            summary = _summarize_content(content)
            lines.append(f"  {redact_string(summary)}")
        elif isinstance(content, str):
            lines.append(f"  {redact_string(content[:200])}")

    return "\n".join(lines) if lines else "No shared context available."


def _summarize_content(content: dict[str, Any] | Any, max_length: int = 150) -> str:
    """Summarize content for injection."""
    if isinstance(content, dict):
        summary_parts = []
        for key in ["summary", "title", "task", "status", "result"]:
            if key in content:
                value = content[key]
                if isinstance(value, str):
                    summary_parts.append(f"{key}: {value[:80]}")
                elif isinstance(value, (int, float, bool)):
                    summary_parts.append(f"{key}: {value}")

        if summary_parts:
            return "; ".join(summary_parts[:3])

        keys = list(content.keys())[:3]
        return f"Fields: {', '.join(keys)}"

    return str(content)[:max_length]


def _format_handoffs_for_injection(
    handoffs: list[ContextHandoff] | list[dict[str, Any]],
) -> str:
    """Format handoffs for injection with secrets scrubbed."""
    lines = []
    for h in handoffs[:3]:
        if isinstance(h, ContextHandoff):
            priority_val = h.priority
            from_agent = h.metadata.get("from_agent", "Unknown")
            task_summary = h.metadata.get(
                "task_summary", h.payload.get("task_summary", "")
            )
            pending_tasks = h.metadata.get(
                "pending_tasks", h.payload.get("pending_tasks", [])
            )
            decisions_made = h.metadata.get(
                "decisions_made", h.payload.get("decisions_made", [])
            )
        else:
            priority_val = h.get("priority", Priority.NORMAL.value)
            from_agent = h.get("from_agent", "Unknown")
            task_summary = h.get("task_summary", "")
            pending_tasks = h.get("pending_tasks", [])
            decisions_made = h.get("decisions_made", [])

        priority_str = "normal"
        if priority_val >= Priority.CRITICAL.value:
            priority_str = "critical"
        elif priority_val >= Priority.HIGH.value:
            priority_str = "high"
        elif priority_val <= Priority.LOW.value:
            priority_str = "low"

        priority_indicator = {
            "critical": "🔴",
            "high": "🟠",
            "normal": "🟡",
            "low": "🟢",
        }.get(priority_str, "⚪")

        clean_summary = redact_string(task_summary)
        lines.append(f"{priority_indicator} From {from_agent}: {clean_summary[:100]}")
        if pending_tasks:
            lines.append(f"   Tasks: {len(pending_tasks)} pending")
        if decisions_made:
            clean_decisions = [redact_string(str(d)) for d in decisions_made[:2]]
            lines.append(f"   Decisions: {', '.join(clean_decisions)}")

    return "\n".join(lines) if lines else "No pending handoffs."


def _format_task_context_for_injection(contexts: list[MemoryContext]) -> str:
    """Format task contexts for injection with secrets scrubbed."""
    lines = []
    for ctx in contexts[:3]:
        content = ctx.value
        agent_name = ctx.metadata.get("agent_name", "Unknown Agent")
        summary = _summarize_content(content)
        lines.append(f"[{agent_name}] {redact_string(summary)}")

    return "\n".join(lines) if lines else "No recent task context."


# ============================================================================
# PostInvocation Hook Integration
# ============================================================================


def capture_and_store_context(
    payload: dict[str, Any],
    storage_path: str | Path | None = None,
) -> dict[str, Any]:
    """Capture context from PostInvocation and store for sharing with secret redaction."""
    adapter = get_memory_manager(storage_path=storage_path)
    agent_name = os.environ.get("AGENT_NAME", "Claude")
    agent_id = os.environ.get("AGENT_ID", f"agent-{uuid.uuid4().hex[:8]}")

    tool_call = payload.get("toolCall", {})
    if isinstance(tool_call, dict):
        tool_name = tool_call.get("name", "")
        tool_args = tool_call.get("args", {})
        tool_result = payload.get("toolResult", {})

        if tool_name in ("Bash", "Read", "Write", "Edit", "Glob", "Grep"):
            content = {
                "tool": tool_name,
                "operation": redact_string(_describe_operation(tool_name, tool_args)),
                "target": redact_string(_extract_target(tool_args)),
                "result_summary": redact_string(_summarize_result(tool_result)),
            }

            priority = 5
            if tool_name in ("Write", "Edit"):
                priority = 7
            elif tool_name == "Bash":
                priority = 6

            adapter.store_context(
                agent_id=agent_id,
                agent_name=agent_name,
                context_type="task",
                content=content,
                priority=priority,
                tags=[tool_name.lower()],
                ttl=1800,
                redact=True,
            )

        handoff_data = tool_args.get("handoff_context")
        if handoff_data and tool_name == "mcp__memory__share_context":
            adapter.store_context(
                agent_id=agent_id,
                agent_name=agent_name,
                context_type="handoff",
                content=handoff_data,
                priority=8,
                tags=["handoff", f"to:{handoff_data.get('target_agent', 'unknown')}"],
                ttl=3600,
                redact=True,
            )

    handoff_id = payload.get("handoff_id")
    if handoff_id:
        adapter.update_handoff_status(
            handoff_id=handoff_id,
            status="completed",
            additional_notes="PostInvocation captured completion",
        )

    return {}


def _describe_operation(tool_name: str, tool_args: dict[str, Any]) -> str:
    """Describe the operation performed."""
    if tool_name == "Bash":
        cmd = tool_args.get("command", "")
        return f"Executed: {cmd[:50]}..."
    elif tool_name == "Read":
        return f"Read: {tool_args.get('file_path', 'unknown')}"
    elif tool_name == "Write":
        return f"Written: {tool_args.get('file_path', 'unknown')}"
    elif tool_name == "Edit":
        return f"Edited: {tool_args.get('file_path', 'unknown')}"
    elif tool_name == "Glob":
        return f"Glob: {tool_args.get('pattern', 'unknown')}"
    elif tool_name == "Grep":
        return f"Grep: {tool_args.get('pattern', 'unknown')}"
    return f"Used {tool_name}"


def _extract_target(tool_args: dict[str, Any]) -> str:
    """Extract target file/path from tool args."""
    for key in ["file_path", "path", "command"]:
        if key in tool_args:
            return str(tool_args[key])[:100]
    return "unknown"


def _summarize_result(tool_result: Any) -> str:
    """Summarize tool result."""
    if tool_result is None:
        return "Success (no output)"

    if isinstance(tool_result, dict):
        if "error" in tool_result:
            return f"Error: {tool_result['error'][:100]}"
        if "stdout" in tool_result:
            return f"Output: {str(tool_result['stdout'])[:100]}"
        return "Completed"

    return str(tool_result)[:100]


# ============================================================================
# CLI Entry Point
# ============================================================================


def main() -> None:
    """Main entry point for the hook script."""
    parser = argparse.ArgumentParser(
        description="MCP Memory Integration for Claude Code"
    )
    parser.add_argument(
        "--action",
        choices=[
            "pre-invocation",
            "post-invocation",
            "store-context",
            "get-shared",
            "create-handoff",
            "get-handoffs",
            "update-handoff",
            "list-tools",
            "stats",
        ],
        default="pre-invocation",
        help="Action to perform",
    )
    parser.add_argument(
        "--context-type",
        help="Context type for store-context action",
    )
    parser.add_argument(
        "--content",
        help="JSON content for store-context action",
    )
    parser.add_argument(
        "--priority",
        type=int,
        default=5,
        help="Priority level (0-10)",
    )
    parser.add_argument(
        "--tags",
        help="Comma-separated tags",
    )
    parser.add_argument(
        "--to-agent",
        help="Target agent for handoff",
    )
    parser.add_argument(
        "--task-summary",
        help="Task summary for handoff",
    )
    parser.add_argument(
        "--handoff-id",
        help="Handoff ID for update",
    )
    parser.add_argument(
        "--status",
        help="Status for update-handoff",
    )
    parser.add_argument(
        "--storage-path",
        default=None,
        help="Path to memory storage json file (defaults to safe ~/.gemini/config/enterprise-hooks/.memory_context/)",
    )
    parser.add_argument(
        "--agent-name",
        default="Claude",
        help="Name of this agent",
    )
    parser.add_argument(
        "--agent-id",
        help="ID of this agent",
    )

    args = parser.parse_args()

    if args.agent_name:
        os.environ["AGENT_NAME"] = args.agent_name
    if args.agent_id:
        os.environ["AGENT_ID"] = args.agent_id

    handler = MCPMemoryToolHandler(storage_path=args.storage_path)

    stdin_data = {}
    if not sys.stdin.isatty():
        try:
            stdin_raw = sys.stdin.read()
            if stdin_raw.strip():
                stdin_data = json.loads(stdin_raw)
        except (json.JSONDecodeError, OSError):
            pass

    if args.action == "list-tools":
        output = {"tools": list(MCP_TOOL_DEFINITIONS.values())}
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    elif args.action == "pre-invocation":
        response = generate_shared_context_injection(
            stdin_data,
            storage_path=args.storage_path,
        )
        print(json.dumps(response, ensure_ascii=False))

    elif args.action == "post-invocation":
        response = capture_and_store_context(
            stdin_data,
            storage_path=args.storage_path,
        )
        print(json.dumps(response, ensure_ascii=False))

    elif args.action == "store-context":
        if not args.context_type or not args.content:
            print(json.dumps({"error": "--context-type and --content required"}))
            return
        try:
            content = json.loads(args.content)
        except json.JSONDecodeError:
            content = {"raw": args.content}

        tags = [t.strip() for t in args.tags.split(",") if t.strip()] if args.tags else None
        result = handler.handle_share_context(
            context_type=args.context_type,
            content=content,
            priority=args.priority,
            tags=tags,
        )
        print(json.dumps(result, ensure_ascii=False))

    elif args.action == "get-shared":
        tags = [t.strip() for t in args.tags.split(",") if t.strip()] if args.tags else None
        result = handler.handle_get_shared(
            context_type=args.context_type,
            tags=tags,
        )
        print(json.dumps(result, ensure_ascii=False))

    elif args.action == "create-handoff":
        if not args.to_agent or not args.task_summary:
            print(json.dumps({"error": "--to-agent and --task-summary required"}))
            return
        result = handler.handle_create_handoff(
            to_agent=args.to_agent,
            task_summary=args.task_summary,
        )
        print(json.dumps(result, ensure_ascii=False))

    elif args.action == "get-handoffs":
        result = handler.handle_get_handoffs(status=args.status or "pending")
        print(json.dumps(result, ensure_ascii=False))

    elif args.action == "update-handoff":
        if not args.handoff_id or not args.status:
            print(json.dumps({"error": "--handoff-id and --status required"}))
            return
        result = handler.handle_update_handoff(
            handoff_id=args.handoff_id,
            status=args.status,
        )
        print(json.dumps(result, ensure_ascii=False))

    elif args.action == "stats":
        stats = handler.adapter.get_stats()
        print(json.dumps(stats, indent=2, default=str, ensure_ascii=False))


if __name__ == "__main__":
    main()
