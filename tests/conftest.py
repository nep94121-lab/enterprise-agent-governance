"""Self-contained conftest.py for Universal Multi-Agent Governance Kit test suite.

Provides mock fixtures, generic execution contexts, token budgets, and schema rules
eliminating 100% of external src.* dependencies.
"""

from __future__ import annotations

import math
import os
import sys
import time
import pathlib
from collections import deque
from dataclasses import dataclass

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
for p in [str(ROOT_DIR / "hooks" / "hooks_scripts"), str(ROOT_DIR / "hooks"), str(ROOT_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)
from enum import StrEnum
from typing import Any, TypedDict
from uuid import uuid4

import pytest
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# 1. Environment Safety Autouse Fixture
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_test_env():
    """Ensure safe testing environment for all tests."""
    old_skip = os.environ.get("SKIP_PRE_PUSH_TEST")
    old_dry = os.environ.get("DRY_RUN")
    os.environ["SKIP_PRE_PUSH_TEST"] = "1"
    os.environ["DRY_RUN"] = "1"
    yield
    if old_skip is not None:
        os.environ["SKIP_PRE_PUSH_TEST"] = old_skip
    else:
        os.environ.pop("SKIP_PRE_PUSH_TEST", None)
    if old_dry is not None:
        os.environ["DRY_RUN"] = old_dry
    else:
        os.environ.pop("DRY_RUN", None)


# ---------------------------------------------------------------------------
# 2. ExecutionContext & Fixture
# ---------------------------------------------------------------------------

@dataclass
class ExecutionContext:
    """Generic ExecutionContext for multi-agent workflows."""
    authenticated_user_id: str = "test-user-id"
    active_membership_id: str = "test-membership-id"
    property_id: str = "test-property-id"
    trace_id: str = "test-trace-id"
    conversation_id: str | None = None
    household_id: str | None = None
    residential_asset_id: str | None = None
    household_role: str | None = None
    resident_name: str | None = "Test Resident"
    onboarding_summary: Any = None
    user_id: str = "test-user-id"
    role: str = "developer"
    tenant_id: str = "test-tenant-id"
    session_id: str = "test-session-id"


@pytest.fixture
def mock_execution_context() -> ExecutionContext:
    """Fixture providing a mock execution context."""
    return ExecutionContext(
        user_id="user-123",
        role="developer",
        tenant_id="tenant-456",
        session_id=str(uuid4()),
        authenticated_user_id="user-123",
        active_membership_id="membership-456",
        property_id="property-789",
        trace_id=str(uuid4()),
        conversation_id=str(uuid4()),
        resident_name="Test User",
    )


@pytest.fixture
def execution_context() -> ExecutionContext:
    """Compatible alias fixture for execution_context."""
    return ExecutionContext(
        authenticated_user_id="user-123",
        active_membership_id="membership-456",
        property_id="property-789",
        trace_id=str(uuid4()),
        conversation_id=str(uuid4()),
        resident_name="Test User",
    )


# ---------------------------------------------------------------------------
# 3. Token Budget Limiter & Fixtures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TokenBudgetDecision:
    """Read-only decision made before an outbound provider call."""
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int
    provider: str
    model: str


class TokenBudgetLimiter:
    """Generic sliding-window token budget limiter for multi-agent workflows."""

    def __init__(
        self,
        *,
        cache: Any = None,
        namespace: str = "token_budget",
        window_seconds: int = 60,
    ) -> None:
        self._cache = cache
        self._namespace = namespace
        self.window_seconds = window_seconds
        self._local: dict[str, deque[tuple[float, int]]] = {}
        self._errors = 0
        self._records = 0
        self._rejections = 0

    async def remaining(
        self,
        *,
        provider: str,
        model: str,
        budget: int,
        headroom_pct: int = 0,
    ) -> TokenBudgetDecision:
        if budget <= 0:
            return TokenBudgetDecision(True, budget, -1, 0, provider, model)

        effective_budget = max(1, math.floor(budget * (100 - headroom_pct) / 100))
        now = time.time()
        key = self._key(provider, model)
        total, oldest = self._usage_local(key, now)

        remaining = max(0, effective_budget - total)
        if remaining > 0:
            return TokenBudgetDecision(True, effective_budget, remaining, 0, provider, model)

        self._rejections += 1
        retry_after = self._retry_after(oldest, now)
        return TokenBudgetDecision(False, effective_budget, 0, retry_after, provider, model)

    async def record_usage(self, *, provider: str, model: str, tokens: int) -> None:
        if tokens <= 0:
            return
        now = time.time()
        key = self._key(provider, model)
        self._record_local(key, now, tokens)
        self._records += 1

    def stats(self) -> dict[str, Any]:
        return {
            "distributed": False,
            "window_seconds": self.window_seconds,
            "errors": self._errors,
            "records": self._records,
            "rejections": self._rejections,
            "tracked_keys_local": len(self._local),
        }

    def _key(self, provider: str, model: str) -> str:
        return f"{self._namespace}:{provider}:{model}"

    def _usage_local(self, key: str, now: float) -> tuple[int, float | None]:
        cutoff = now - self.window_seconds
        window = self._local.setdefault(key, deque())
        while window and window[0][0] <= cutoff:
            window.popleft()
        return sum(tokens for _, tokens in window), window[0][0] if window else None

    def _record_local(self, key: str, now: float, tokens: int) -> None:
        self._usage_local(key, now)
        self._local[key].append((now, tokens))

    def _retry_after(self, oldest: float | None, now: float) -> int:
        if oldest is None:
            return self.window_seconds
        return max(1, math.ceil(oldest + self.window_seconds - now))


@pytest.fixture
def mock_token_budget() -> TokenBudgetLimiter:
    """Fixture providing a mock TokenBudgetLimiter."""
    return TokenBudgetLimiter()


# ---------------------------------------------------------------------------
# 4. Generic Catalogue Rules for Schema Validation
# ---------------------------------------------------------------------------

CHECKLIST_TEMPLATES_V1: dict[str, dict[str, Any]] = {
    "PROFILE_SETUP": {
        "code": "PROFILE_SETUP",
        "scope_type": "HOUSEHOLD",
        "requirement_type": "REQUIRED",
        "blocking": True,
        "sequence_order": 10,
        "requires_evidence": False,
        "protected_completion": False,
        "completion_source": "RESIDENT_SUBMISSION",
        "title": {
            "vi": "Thiết lập hồ sơ người dùng",
            "en": "Setup user profile",
        },
        "description": {
            "vi": "Cập nhật thông tin định danh và hồ sơ ban đầu.",
            "en": "Update identity and initial profile information.",
        },
    },
    "DOCUMENT_VERIFICATION": {
        "code": "DOCUMENT_VERIFICATION",
        "scope_type": "INDIVIDUAL_RESIDENT",
        "requirement_type": "REQUIRED",
        "blocking": True,
        "sequence_order": 20,
        "requires_evidence": True,
        "protected_completion": True,
        "completion_source": "ADMIN_APPROVAL",
        "title": {
            "vi": "Xác minh tài liệu",
            "en": "Document verification",
        },
        "description": {
            "vi": "Ban quản trị xác minh tính hợp lệ của tài liệu gửi lên.",
            "en": "Administration verifies validity of submitted documents.",
        },
    },
    "ACCESS_PASS_ISSUANCE": {
        "code": "ACCESS_PASS_ISSUANCE",
        "scope_type": "INDIVIDUAL_RESIDENT",
        "requirement_type": "OPTIONAL",
        "blocking": False,
        "sequence_order": 30,
        "requires_evidence": False,
        "protected_completion": True,
        "completion_source": "SYSTEM_EVENT",
        "title": {
            "vi": "Cấp thẻ ra vào",
            "en": "Issue access pass",
        },
        "description": {
            "vi": "Cấp phát thẻ ra vào tự động sau khi hoàn tất xác minh.",
            "en": "Issue access pass automatically upon verification completion.",
        },
    },
}

LOCK_CONDITIONS_V1: dict[str, dict[str, Any]] = {
    "ACCESS_PASS_ISSUANCE": {
        "prerequisites": ["PROFILE_SETUP", "DOCUMENT_VERIFICATION"],
        "prerequisite_mode": "ALL",
        "reason_vi": "Cần hoàn tất thiết lập hồ sơ và xác minh tài liệu trước khi cấp thẻ.",
        "reason_en": "Must complete profile setup and document verification before pass issuance.",
    },
}

CHECKLIST_RULES_V1: list[dict[str, Any]] = [
    {
        "rule_id": "rule_initial_profile_setup_v1",
        "rule_version": 1,
        "status": "APPROVED",
        "effective_from": "2026-01-01",
        "when": {
            "journey_type": "INITIAL_ONBOARDING",
            "asset_type": "WORKSPACE",
        },
        "then": "PROFILE_SETUP",
        "reason": {
            "vi": "Người dùng mới bắt buộc phải hoàn thành thiết lập hồ sơ.",
            "en": "New user must complete initial profile setup.",
        },
    },
    {
        "rule_id": "rule_document_verification_v1",
        "rule_version": 1,
        "status": "APPROVED",
        "effective_from": "2026-01-01",
        "when": {
            "journey_type": "INITIAL_ONBOARDING",
            "primary_relationship": "OWNER",
        },
        "then": "DOCUMENT_VERIFICATION",
        "reason": {
            "vi": "Chủ sở hữu cần được ban quản trị xác minh tài liệu.",
            "en": "Owner requires document verification by administration.",
        },
    },
    {
        "rule_id": "rule_access_pass_issuance_v1",
        "rule_version": 1,
        "status": "APPROVED",
        "effective_from": "2026-01-01",
        "when": {
            "journey_type": "INITIAL_ONBOARDING",
            "declared_needs": {"needs_access_pass": True},
        },
        "then": "ACCESS_PASS_ISSUANCE",
        "reason": {
            "vi": "Cấp quyền truy cập nếu có nhu cầu thẻ ra vào.",
            "en": "Issue access permissions if access pass is requested.",
        },
    },
]


@pytest.fixture
def mock_catalogue_rules():
    """Fixture providing generic catalogue rules for schema validation."""
    return {
        "CHECKLIST_RULES_V1": CHECKLIST_RULES_V1,
        "CHECKLIST_TEMPLATES_V1": CHECKLIST_TEMPLATES_V1,
        "LOCK_CONDITIONS_V1": LOCK_CONDITIONS_V1,
    }


# ---------------------------------------------------------------------------
# 5. Knowledge & AI Generic Stubs
# ---------------------------------------------------------------------------

class RetrievalMode(StrEnum):
    VECTOR = "VECTOR"
    KEYWORD = "KEYWORD"
    HYBRID = "HYBRID"
    HYBRID_RERANKED = "HYBRID_RERANKED"


@dataclass
class RetrievalResult:
    rank: int
    knowledge_chunk_id: Any
    knowledge_document_id: Any
    knowledge_version_id: Any
    title: str
    section_heading: str
    content: str
    score: float
    citation_label: str
    effective_from: Any

    def model_dump(self, mode: str = "json") -> dict[str, Any]:
        return {
            "rank": self.rank,
            "knowledge_chunk_id": str(self.knowledge_chunk_id),
            "knowledge_document_id": str(self.knowledge_document_id),
            "knowledge_version_id": str(self.knowledge_version_id),
            "title": self.title,
            "section_heading": self.section_heading,
            "content": self.content,
            "score": self.score,
            "citation_label": self.citation_label,
            "effective_from": str(self.effective_from),
        }


@dataclass
class RetrievalResponse:
    query_id: Any
    retrieval_mode: RetrievalMode
    results: list[RetrievalResult]
    latency_ms: int = 10
    trace_id: Any | None = None


class ChatRequest(BaseModel):
    message: str = Field(..., max_length=1000000)
    conversation_id: Any | None = None
    language: str = "vi"
    client_message_id: Any | None = None
    image_data: str | None = None
    signature_data: str | None = None


class ChatResponse(BaseModel):
    response: str = "Mock response"
    conversation_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class FixtureRetrievalAdapter:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    async def search(self, *args: Any, **kwargs: Any) -> RetrievalResponse:
        return RetrievalResponse(
            query_id=uuid4(),
            retrieval_mode=RetrievalMode.VECTOR,
            results=[],
            latency_ms=5,
        )


class StubAnswerAdapter:
    def __init__(self, *completions: Any, raises: Exception | None = None) -> None:
        self._completions = list(completions)
        self._raises = raises
        self.calls: list[dict] = []

    async def generate_completion(self, *, messages: Any = None, tools: Any = None) -> dict[str, Any]:
        self.calls.append({"messages": messages, "tools": tools})
        if self._raises:
            raise self._raises
        if self._completions:
            item = self._completions.pop(0)
            if isinstance(item, str):
                return {"content": item}
            return item
        return {"content": "Mock completion response."}


class ChatService:
    def __init__(
        self,
        retrieval: Any = None,
        answer: Any = None,
        settings: Any = None,
        validator: Any = None,
    ) -> None:
        self.retrieval = retrieval
        self.answer = answer
        self.settings = settings
        self.validator = validator or self._default_sanitizer

    def _default_sanitizer(self, msg: str) -> None:
        prefix = "validate_identifier:"
        if prefix in msg:
            token = msg.split(prefix, 1)[1].strip()
            if not token:
                raise ValueError("Identifier token is required")
            if len(token) > 50:
                raise ValueError("Identifier length exceeds maximum allowed limit")
            if any(
                ch in token
                for ch in ["\x00", "\x01", "\x7f", "\u200b", "\u200c", "\u200d", "<", ">", "'", ";", "{", "}"]
            ):
                raise ValueError("Invalid identifier format detected")

    async def handle_chat(self, request: ChatRequest, ctx: ExecutionContext) -> ChatResponse:
        if self.validator:
            self.validator(request.message)
        return ChatResponse(response="Mock processed chat response", conversation_id=str(request.conversation_id or uuid4()))


def get_settings() -> Any:
    class MockSettings:
        app_env = "test"
        ai_adapter = "fixture"
        supabase_url = ""
        supabase_key = ""
        ai_token_budget_window_seconds = 60
    return MockSettings()


class AgentState(TypedDict, total=False):
    query: str
    context: str
    analysis: str
    response: str
    error: str
    metadata: dict[str, Any]


class MockAgent:
    async def ainvoke(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"response": f"Mock agent answer for {input_data.get('query', '')}"}


agent = MockAgent()
