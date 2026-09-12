#!/usr/bin/env python3
"""Grill-Me Research Enforcer Hook (PreToolUse) for Enterprise Multi-Agent Governance System.

Enforces Industry-Grounded Grill-Me Protocol (§INDUSTRY-GROUNDED-GRILL-ME):
1. When in /grill-me context, the agent is STRICTLY PROHIBITED from hallucinating options.
2. The agent MUST call 'search_web' (or approved research tools) to research industry standards
   and proven architectures from Big Tech (Google, Meta, Netflix, Uber, AWS, CNCF...) before
   presenting interview questions and options to the User.
3. The agent MUST create or update a research markdown file (research-*.md or summary .md)
   in the workspace (BOSS RULE #3 & INDUSTRY-GROUNDED GRILL-ME).
4. Anti-Bypass Guard: Rejects fraudulent flags (e.g. `is_grill_me: false` or `searched_web: true`)
   when transcript or session evidence confirms active /grill-me session.
5. Multi-Turn Context Awareness: Maintains active grill-me session across multiple interactive turns
   until user explicitly exits or terminates the interview.
6. If ask_question is called in /grill-me context without prior search_web or without research .md file:
   -> HARD DENY (chặn ngay lập tức, 0 ngoại lệ theo lệnh của Sếp).
7. Normal / non-grill-me questions bypass this hook safely.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import io
import json
import os
import pathlib
import random
import re
import subprocess
import sys
import threading
import time
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

HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).parent.resolve()
ENTERPRISE_HOOKS_ROOT = HOOKS_SCRIPTS_DIR.parent.resolve()

if str(HOOKS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_SCRIPTS_DIR))
if str(ENTERPRISE_HOOKS_ROOT) not in sys.path:
    sys.path.insert(0, str(ENTERPRISE_HOOKS_ROOT))

from common_hook_lib import (  # noqa: E402
    emit_stdout_json,
    get_tool_args,
    get_tool_call,
    get_workspace_roots,
    log_diagnostic,
    pre_tool_response,
    read_stdin_payload,
)

GRILL_ME_KEYWORDS: tuple[str, ...] = (
    "/grill-me",
    "grill-me",
    "grill_me",
    "/grill_me",
    "phỏng vấn làm rõ",
    "industry-grounded",
    "grill me",
)

GRILL_ME_EXIT_KEYWORDS: tuple[str, ...] = (
    "/exit",
    "/stop",
    "/cancel",
    "tiến hành code",
    "bắt đầu code",
    "làm luôn đi",
    "chốt phương án",
    "/build",
    "/leadpm",
    "/deploy",
    "/pm",
    "kết thúc phỏng vấn",
    "chốt kế hoạch",
    "bắt đầu triển khai",
    "triển khai ngay",
)

WEB_SEARCH_TOOLS: frozenset[str] = frozenset({
    "search_web",
    "firecrawl_search",
    "firecrawl_crawl",
    "gemini_search_docs",
    "read_url_content",
})

RESEARCH_FILE_PATTERNS: tuple[str, ...] = (
    "*research*.md",
    "*benchmark*.md",
    "*so-sanh*.md",
    "*so_sanh*.md",
    "*khao-sat*.md",
    "*khao_sat*.md",
    "*architecture*.md",
    "*pattern*.md",
    "*grill-me*.md",
    "*grill_me*.md",
)

SYSTEM_OR_ADMIN_FILES: frozenset[str] = frozenset({
    "progress.md",
    "request_artifact.md",
    "dispatch.md",
    "project_memory.md",
    "continuity.md",
    "implementation_plan.md",
    "walkthrough.md",
    "task_contract.md",
    "readme.md",
    "rules.md",
    "agents.md",
})

RESEARCH_CONTENT_KEYWORDS: tuple[str, ...] = (
    "kiến trúc",
    "architecture",
    "pattern",
    "benchmark",
    "so sánh",
    "nghiên cứu",
    "tiêu chuẩn",
    "chuẩn",
    "google",
    "meta",
    "netflix",
    "uber",
    "aws",
    "cncf",
    "trade-off",
    "ưu điểm",
    "nhược điểm",
    "giải pháp",
    "khảo sát",
    "option",
    "thiết kế",
    "hệ thống",
    "lựa chọn",
    "so-sanh",
    "đối chiếu",
    "phân tích",
)


# ============================================================================
# Inter-Process Locking & Atomic File Operations (Mục 29, 30)
# ============================================================================
class CrossProcessLock:
    """Robust cross-process & cross-thread file lock supporting Windows (msvcrt) and POSIX (fcntl).

    Combines in-process threading.RLock with kernel-level file locking (msvcrt/fcntl).
    Supports reentrancy and prevents WinError 32 / WinError 5 file contention locks on Windows NTFS.
    """

    _process_locks: dict[str, threading.RLock] = {}
    _lock_depths: dict[tuple[int, str], int] = {}
    _lock_fds: dict[str, int] = {}
    _meta_lock = threading.Lock()

    def __init__(self, lock_file: pathlib.Path, timeout: float = 10.0):
        self.lock_file = pathlib.Path(lock_file).resolve()
        self.timeout = timeout
        self.path_key = str(self.lock_file).lower() if sys.platform == "win32" else str(self.lock_file)
        self._thread_key = (threading.get_ident(), self.path_key)

    @classmethod
    def _get_thread_lock(cls, key: str) -> threading.RLock:
        with cls._meta_lock:
            if key not in cls._process_locks:
                cls._process_locks[key] = threading.RLock()
            return cls._process_locks[key]

    def __enter__(self) -> CrossProcessLock:
        thread_lock = self._get_thread_lock(self.path_key)
        start_time = time.monotonic()
        acquired = thread_lock.acquire(timeout=self.timeout)
        if not acquired:
            raise TimeoutError(f"Timed out waiting for thread lock on: {self.lock_file}")

        with CrossProcessLock._meta_lock:
            depth = CrossProcessLock._lock_depths.get(self._thread_key, 0)
            if depth > 0:
                CrossProcessLock._lock_depths[self._thread_key] = depth + 1
                return self

        try:
            self.lock_file.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.lock_file), os.O_RDWR | os.O_CREAT)
            os_start = time.monotonic()
            while True:
                try:
                    if sys.platform == "win32":
                        import msvcrt

                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with CrossProcessLock._meta_lock:
                        CrossProcessLock._lock_depths[self._thread_key] = 1
                        CrossProcessLock._lock_fds[self.path_key] = fd
                    return self
                except OSError:
                    if time.monotonic() - os_start > self.timeout:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                        raise TimeoutError(f"Timed out waiting for cross-process file lock: {self.lock_file}")
                    time.sleep(0.005 + random.uniform(0.002, 0.008))
        except Exception:
            thread_lock.release()
            raise

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        thread_lock = self._get_thread_lock(self.path_key)
        release_os = False
        fd = None
        with CrossProcessLock._meta_lock:
            depth = CrossProcessLock._lock_depths.get(self._thread_key, 0)
            if depth > 1:
                CrossProcessLock._lock_depths[self._thread_key] = depth - 1
            else:
                CrossProcessLock._lock_depths.pop(self._thread_key, None)
                fd = CrossProcessLock._lock_fds.pop(self.path_key, None)
                release_os = True

        if release_os and fd is not None:
            try:
                if sys.platform == "win32":
                    import msvcrt

                    try:
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
                else:
                    import fcntl

                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass

        thread_lock.release()


def atomic_replace_file(src: pathlib.Path, dst: pathlib.Path, max_retries: int = 10) -> None:
    """Safely replace dst with src using atomic rename and Windows retry backoff."""
    for attempt in range(max_retries):
        try:
            src.replace(dst)
            return
        except (PermissionError, OSError):
            if attempt == max_retries - 1:
                raise
            time.sleep(0.01 * (1.5**attempt) + random.uniform(0.005, 0.015))


# ============================================================================
# Session State Management (.grill_me_state)
# ============================================================================
def get_state_dir() -> pathlib.Path:
    """Resolve state directory for grill-me multi-turn sessions."""
    custom_dir = os.environ.get("GRILL_ME_STATE_DIR")
    if custom_dir:
        d = pathlib.Path(custom_dir).resolve()
    else:
        d = pathlib.Path.home() / ".gemini" / "config" / "enterprise-hooks" / ".grill_me_state"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        log_diagnostic(f"Could not create state dir {d}: {exc}")
    return d


def resolve_safe_session_id(conv_id: str) -> str:
    """Resolve conversation identifier avoiding cross-session pollution (Mục 30)."""
    if conv_id and str(conv_id).strip():
        clean = re.sub(r"[^\w\-]", "_", str(conv_id).strip())
        if clean:
            return clean[:64]

    # Check environment variables
    env_id = (
        os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
        or os.environ.get("CONVERSATION_ID")
        or os.environ.get("GEMINI_SESSION_ID")
        or os.environ.get("GRILL_ME_SESSION_ID")
    )
    if env_id and env_id.strip():
        clean = re.sub(r"[^\w\-]", "_", env_id.strip())
        if clean:
            return clean[:64]

    # Partition by workspace root path hash instead of global static "default_session"
    ws_hash = hashlib.sha256(str(pathlib.Path.cwd().resolve()).encode("utf-8")).hexdigest()[:16]
    return f"ws_{ws_hash}"


def get_session_file(conv_id: str) -> pathlib.Path:
    """Get path to session state file for a conversation (Mục 30)."""
    safe_id = resolve_safe_session_id(conv_id)
    return get_state_dir() / f"session_{safe_id}.json"


def get_session_lock_file(conv_id: str) -> pathlib.Path:
    """Get path to session lock file for a conversation (Mục 29)."""
    safe_id = resolve_safe_session_id(conv_id)
    return get_state_dir() / f"session_{safe_id}.lock"


def load_session_state(conv_id: str) -> dict[str, Any]:
    """Load persistent session state from disk under cross-process lock (Mục 29)."""
    sf = get_session_file(conv_id)
    lf = get_session_lock_file(conv_id)
    with CrossProcessLock(lf, timeout=10.0):
        if sf.is_file():
            try:
                with open(sf, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
            except Exception as exc:
                log_diagnostic(f"Error loading session state from {sf}: {exc}")
    return {}


def save_session_state(conv_id: str, state: dict[str, Any]) -> None:
    """Save persistent session state atomically to disk under cross-process lock with unique temp file (Mục 29, 30)."""
    sf = get_session_file(conv_id)
    lf = get_session_lock_file(conv_id)
    with CrossProcessLock(lf, timeout=10.0):
        try:
            sf.parent.mkdir(parents=True, exist_ok=True)
            # Unique temp file with PID + time_ns + entropy to prevent collisions
            tmp = (
                sf.parent
                / f"{sf.name}.tmp.{os.getpid()}.{time.time_ns()}.{random.randint(1000, 9999)}"
            )
            try:
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(state, f, ensure_ascii=False, indent=2)
                atomic_replace_file(tmp, sf)
            finally:
                if tmp.exists():
                    try:
                        tmp.unlink(missing_ok=True)
                    except OSError:
                        pass
        except Exception as exc:
            log_diagnostic(f"Error saving session state to {sf}: {exc}")


# ============================================================================
# Transcript Discovery & Multi-Turn Lifecycle Parsing
# ============================================================================
def parse_iso_timestamp(ts_str: Any) -> float | None:
    """Safely parse ISO 8601 timestamp string to epoch seconds."""
    if not ts_str or not isinstance(ts_str, str):
        return None
    try:
        clean = ts_str.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(clean).timestamp()
    except Exception:
        return None


def find_transcript_file(payload: dict[str, Any]) -> pathlib.Path | None:
    """Locate transcript.jsonl for current conversation."""
    raw_path = payload.get("transcriptPath")
    if raw_path and isinstance(raw_path, str):
        p = pathlib.Path(raw_path).resolve()
        if p.is_file():
            return p

    conv_id = payload.get("conversationId") or payload.get("conversation_id")
    if conv_id and isinstance(conv_id, str):
        candidate = (
            pathlib.Path.home()
            / ".gemini"
            / "antigravity"
            / "brain"
            / conv_id
            / ".system_generated"
            / "logs"
            / "transcript.jsonl"
        )
        if candidate.is_file():
            return candidate.resolve()

    return None


def inspect_transcript_for_grill_me(transcript_path: pathlib.Path) -> dict[str, Any]:
    """Parse transcript.jsonl and track the lifecycle of grill-me sessions."""
    result: dict[str, Any] = {
        "has_transcript": True,
        "is_grill_me": False,
        "session_start_epoch": None,
        "session_start_step": -1,
        "searched_web": False,
        "search_tools_called": [],
        "files_written": [],
        "turn_count": 0,
        "last_user_content": "",
    }
    if not transcript_path.is_file():
        result["has_transcript"] = False
        return result

    try:
        with open(transcript_path, "r", encoding="utf-8", errors="replace") as f:
            lines = [line.strip() for line in f if line.strip()]
    except Exception as exc:
        log_diagnostic(f"Failed to read transcript {transcript_path}: {exc}")
        result["has_transcript"] = False
        return result

    in_grill_me = False
    start_epoch = None
    start_step = -1
    search_tools: list[str] = []
    files_written: list[str] = []
    turns = 0
    last_user_msg = ""

    for line in lines:
        try:
            step = json.loads(line)
        except Exception:
            continue
        if not isinstance(step, dict):
            continue

        stype = step.get("type")
        if stype == "USER_INPUT":
            content = str(step.get("content", ""))
            last_user_msg = content
            clean = content.lower().strip()

            is_start = any(k in clean for k in GRILL_ME_KEYWORDS)
            is_exit = any(k in clean for k in GRILL_ME_EXIT_KEYWORDS)

            if is_start:
                in_grill_me = True
                start_step = step.get("step_index", 0)
                start_epoch = parse_iso_timestamp(step.get("created_at")) or time.time()
                search_tools.clear()
                files_written.clear()
                turns = 1
            elif in_grill_me:
                if is_exit:
                    in_grill_me = False
                else:
                    turns += 1

        elif in_grill_me:
            tcs = step.get("tool_calls") or []
            for tc in tcs:
                if not isinstance(tc, dict):
                    continue
                name = tc.get("name") or (
                    tc.get("function", {}).get("name") if isinstance(tc.get("function"), dict) else ""
                )
                args = tc.get("args") or (
                    tc.get("function", {}).get("arguments") if isinstance(tc.get("function"), dict) else {}
                )
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}
                if not isinstance(args, dict):
                    args = {}

                if name in WEB_SEARCH_TOOLS:
                    search_tools.append(name)
                if name in ("write_to_file", "replace_file_content"):
                    tf = args.get("TargetFile") or args.get("target_file") or args.get("path") or ""
                    if tf:
                        files_written.append(str(tf))

    result["is_grill_me"] = in_grill_me
    result["session_start_epoch"] = start_epoch
    result["session_start_step"] = start_step
    result["searched_web"] = len(search_tools) > 0
    result["search_tools_called"] = search_tools
    result["files_written"] = files_written
    result["turn_count"] = turns
    result["last_user_content"] = last_user_msg
    return result


def is_grill_me_context(
    payload: dict[str, Any],
    args: dict[str, Any],
    transcript_info: dict[str, Any] | None = None,
) -> bool:
    """Determine if current execution context is /grill-me.

    Anti-Bypass Guard:
    - If transcript_info confirms an active /grill-me session, ANY attempt by payload to claim
      `is_grill_me: false` is OVERRIDDEN and IGNORED.
    """
    # 1. Transcript-based determination (Highest authority / Source of Truth)
    if transcript_info and transcript_info.get("has_transcript"):
        if transcript_info.get("is_grill_me") is True:
            if payload.get("is_grill_me") is False:
                log_diagnostic(
                    "[ANTI-BYPASS] Payload specified 'is_grill_me: false', but transcript confirms "
                    "an active /grill-me session! Overridden to True."
                )
            return True
        elif transcript_info.get("is_grill_me") is False:
            pass

    # 2. Session state cache
    conv_id = payload.get("conversationId") or payload.get("conversation_id")
    if conv_id and isinstance(conv_id, str):
        s_state = load_session_state(conv_id)
        if s_state.get("active") is True:
            last_epoch = s_state.get("last_epoch", 0)
            if time.time() - last_epoch < 7200:
                if payload.get("is_grill_me") is False and (not transcript_info or not transcript_info.get("has_transcript")):
                    log_diagnostic(
                        f"[ANTI-BYPASS] Payload claimed is_grill_me: false, but session state for {conv_id} is ACTIVE."
                    )
                    return True
                elif payload.get("is_grill_me") is not False:
                    return True

    # 3. Environment variable
    if os.environ.get("GRILL_ME_ACTIVE") == "1":
        return True

    # 4. Question content analysis
    questions = args.get("questions", [])
    if isinstance(questions, list):
        for q in questions:
            if not isinstance(q, dict):
                continue
            q_text = str(q.get("question", "")).lower()
            if any(k in q_text for k in GRILL_ME_KEYWORDS):
                return True
            for opt in q.get("options", []):
                if any(k in str(opt).lower() for k in GRILL_ME_KEYWORDS):
                    return True

    # 5. Payload direct flags (when no contradicting transcript exists)
    if payload.get("is_grill_me") is True:
        return True
    if payload.get("slash_command") == "/grill-me":
        return True
    ctx = payload.get("context", {})
    if isinstance(ctx, dict):
        if ctx.get("is_grill_me") is True or ctx.get("slash_command") == "/grill-me":
            return True

    # If payload explicitly claimed False and no evidence proved otherwise:
    if payload.get("is_grill_me") is False:
        return False
    if isinstance(ctx, dict) and ctx.get("is_grill_me") is False:
        return False

    return False



def has_called_search_web(
    payload: dict[str, Any],
    transcript_info: dict[str, Any] | None = None,
) -> bool:
    """Check if search_web (or valid web search tool) has been executed in the current session.

    Anti-Bypass Guard:
    - If transcript is available and has tool calls in the active session, a fake flag
      `searched_web: true` with 0 actual search tool calls in transcript is REJECTED.
    """
    # 1. Transcript verification (Highest authority)
    if transcript_info and transcript_info.get("has_transcript"):
        if transcript_info.get("searched_web") is True:
            return True
        if transcript_info.get("is_grill_me") is True:
            if payload.get("searched_web") is True or payload.get("has_search_web") is True:
                # Double check history in payload
                history = payload.get("history") or payload.get("steps") or payload.get("toolCallsHistory")
                history_searched = False
                if isinstance(history, list):
                    for item in history:
                        if isinstance(item, dict):
                            name = item.get("name") or (
                                item.get("toolCall", {}).get("name")
                                if isinstance(item.get("toolCall"), dict)
                                else ""
                            )
                            if name in WEB_SEARCH_TOOLS:
                                history_searched = True
                                break
                if not history_searched:
                    log_diagnostic(
                        "[ANTI-BYPASS] Rejected fake 'searched_web: true' flag. "
                        "Transcript shows 0 search tool invocations in this /grill-me session!"
                    )
                    return False
                return True
            return False

    # 2. History in payload
    history = payload.get("history") or payload.get("steps") or payload.get("toolCallsHistory")
    if isinstance(history, list):
        for item in history:
            if isinstance(item, dict):
                name = item.get("name") or (
                    item.get("toolCall", {}).get("name") if isinstance(item.get("toolCall"), dict) else ""
                )
                if name in WEB_SEARCH_TOOLS:
                    return True

    # 3. Session state file
    conv_id = payload.get("conversationId") or payload.get("conversation_id")
    if conv_id and isinstance(conv_id, str):
        s_state = load_session_state(conv_id)
        if s_state.get("searched_web") is True:
            return True

    # 4. Payload flags (for test fixtures / direct injection without contradicting transcript)
    if payload.get("searched_web") is True or payload.get("has_search_web") is True:
        return True

    return False


def check_research_markdown_on_disk(
    payload: dict[str, Any],
    transcript_info: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Verify that at least one valid research markdown file exists on disk in workspace.

    Rules:
    1. Must exist on disk in workspace roots.
    2. Suffix must be .md or .markdown.
    3. Excludes system/admin files (progress.md, request_artifact.md, DISPATCH.md, project_memory.md...).
    4. Must be non-empty (size >= 50 bytes).
    5. Must be created or modified within the current grill-me session timeframe.
    6. Content sanity check: must contain markdown headings and research-related keywords.
    7. Supports payload fixtures (has_research_file / created_research_file / research_file)
       when running in isolated unit tests without disk access.
    """
    # 1. Check explicit research_file path in payload
    explicit_file = payload.get("research_file")
    if explicit_file and isinstance(explicit_file, str):
        ep = pathlib.Path(explicit_file)
        if ep.is_file() and ep.stat().st_size >= 50:
            return True, f"Verified explicit research file on disk: {ep.name}"

    # 2. Check files written during this session from transcript
    if transcript_info and transcript_info.get("files_written"):
        for fw in transcript_info["files_written"]:
            fwp = pathlib.Path(fw)
            if fwp.is_file() and fwp.suffix.lower() in (".md", ".markdown"):
                if fwp.name.lower() not in SYSTEM_OR_ADMIN_FILES and fwp.stat().st_size >= 50:
                    return True, f"Verified session-written research markdown file: {fwp.name} ({fwp.stat().st_size} bytes)"

    # 3. Check history in payload for write_to_file calls
    history = payload.get("history") or payload.get("steps") or payload.get("toolCallsHistory")
    if isinstance(history, list):
        for item in history:
            if isinstance(item, dict):
                t_name = item.get("name") or (
                    item.get("toolCall", {}).get("name") if isinstance(item.get("toolCall"), dict) else ""
                )
                if t_name in ("write_to_file", "replace_file_content"):
                    t_args = item.get("args") or (
                        item.get("toolCall", {}).get("args") if isinstance(item.get("toolCall"), dict) else {}
                    )
                    if isinstance(t_args, dict):
                        tf = t_args.get("TargetFile") or t_args.get("target_file") or t_args.get("path") or ""
                        if tf:
                            tf_p = pathlib.Path(tf)
                            if tf_p.is_file() and tf_p.suffix.lower() in (".md", ".markdown"):
                                if tf_p.name.lower() not in SYSTEM_OR_ADMIN_FILES and tf_p.stat().st_size >= 50:
                                    return True, f"Verified history-written research markdown file: {tf_p.name}"

    # 4. Scan workspace roots on disk
    workspace_roots = get_workspace_roots(payload)
    if not workspace_roots:
        known_roots = [
            pathlib.Path.cwd().resolve(),
            pathlib.Path.home().resolve(),
        ]
        for kr in known_roots:
            if kr.is_dir() and kr not in workspace_roots:
                workspace_roots.append(kr)

    session_start_epoch = transcript_info.get("session_start_epoch") if transcript_info else None

    found_candidates: list[pathlib.Path] = []

    for root in workspace_roots:
        if not root.is_dir():
            continue
        try:
            for item in root.rglob("*.md"):
                # Exclude hidden or build directories
                parts = item.parts
                if any(p.startswith(".") for p in parts[:-1]):
                    continue
                if any(p in ("node_modules", "__pycache__", "venv", ".venv", ".system_generated", ".gemini") for p in parts):
                    continue
                if "activity_logs" in parts:
                    # Skip normal daily logs like 2026-09-12.md unless explicitly research log
                    if not any(pat in item.name.lower() for pat in ("research", "benchmark", "so-sanh", "so_sanh", "khao-sat", "grill")):
                        continue

                fname = item.name.lower()
                if fname in SYSTEM_OR_ADMIN_FILES:
                    continue

                if not item.is_file():
                    continue

                st = item.stat()
                if st.st_size < 50:
                    continue

                # Check modification time if session start is known
                if session_start_epoch is not None:
                    # Allow 120 seconds tolerance before session start
                    if st.st_mtime < (session_start_epoch - 120):
                        is_pattern_name = any(
                            p in fname for p in ("research", "benchmark", "so-sanh", "so_sanh", "khao-sat", "architecture", "grill")
                        )
                        if not is_pattern_name or (time.time() - st.st_mtime > 86400):
                            continue

                # Content sanity check
                try:
                    with open(item, "r", encoding="utf-8", errors="replace") as mf:
                        preview = mf.read(4096).lower()
                        has_md_heading = "#" in preview or "- " in preview
                        has_research_kw = any(kw in preview for kw in RESEARCH_CONTENT_KEYWORDS)
                        is_named_research = any(
                            p in fname for p in ("research", "benchmark", "so-sanh", "so_sanh", "khao-sat", "architecture", "grill")
                        )
                        if has_md_heading and (has_research_kw or is_named_research):
                            found_candidates.append(item)
                except Exception:
                    continue
        except Exception as exc:
            log_diagnostic(f"Error scanning workspace {root}: {exc}")

    if found_candidates:
        found_candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        best = found_candidates[0]
        return True, f"Verified research markdown file on disk: {best.name} ({best.stat().st_size} bytes)"

    # 5. Check mock/fixture flag in payload (for isolated unit tests without disk access)
    if payload.get("has_research_file") is True or payload.get("created_research_file") is True:
        return True, "Verified via payload research file flag (test fixture)."

    return False, "Không tìm thấy file markdown nghiên cứu (.md) hợp lệ nào trong workspace."


def evaluate_grill_me_research(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate whether ask_question complies with grill-me research rules."""
    if not isinstance(payload, dict):
        return pre_tool_response("allow", "Payload is not a dictionary.")

    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""

    # Only gate ask_question tool
    if tool_name != "ask_question":
        return pre_tool_response("allow", f"Tool '{tool_name}' is not ask_question.")

    args = get_tool_args(tool_call)

    # Resolve transcript if available
    transcript_path = find_transcript_file(payload)
    transcript_info = inspect_transcript_for_grill_me(transcript_path) if transcript_path else None

    # Context check (with Anti-Bypass Guard)
    is_grill = is_grill_me_context(payload, args, transcript_info)

    # Sync session state under cross-process lock (Mục 29)
    conv_id = payload.get("conversationId") or payload.get("conversation_id")
    if conv_id and isinstance(conv_id, str):
        session_lock = get_session_lock_file(conv_id)
        with CrossProcessLock(session_lock, timeout=10.0):
            if is_grill:
                s_state = load_session_state(conv_id)
                s_state["conversation_id"] = conv_id
                s_state["active"] = True
                s_state["last_epoch"] = time.time()
                if transcript_info and transcript_info.get("session_start_epoch"):
                    s_state["session_start_epoch"] = transcript_info["session_start_epoch"]
                save_session_state(conv_id, s_state)
            elif transcript_info and not transcript_info.get("is_grill_me"):
                s_state = load_session_state(conv_id)
                if s_state.get("active"):
                    s_state["active"] = False
                    save_session_state(conv_id, s_state)

    # If NOT in grill-me context -> fast-path allow (bypass)
    if not is_grill:
        return pre_tool_response("allow", "Non-grill-me question approved.")

    # In grill-me context:
    # 1. MUST have called search_web (or approved research tool)
    searched = has_called_search_web(payload, transcript_info)
    if not searched:
        reason = (
            "LỆNH CƯỠNG CHẾ TỪ SẾP (HARD DENY - §INDUSTRY-GROUNDED-GRILL-ME): BẮT BUỘC TRA CỨU WEB TRƯỚC KHI HỎI GRILL-ME!\n"
            "Bạn đang trong quy trình /grill-me nhưng CHƯA thực hiện tra cứu web để xác thực tiêu chuẩn công nghiệp.\n"
            "TUYỆT ĐỐI CẤM tự nghĩ ra các phương án lý thuyết suông! BẮT BUỘC phải gọi công cụ 'search_web' tra cứu các "
            "giải pháp, mô hình kiến trúc thực tế của Big Tech (Google, Meta, Netflix, Uber, AWS, CNCF...) trước khi đưa "
            "ra câu hỏi và các phương án lựa chọn cho Sếp!"
        )
        log_diagnostic("HARD DENIED ask_question: Missing search_web in /grill-me context.")
        return pre_tool_response("deny", reason)

    # 2. MUST have created a research markdown file on disk in workspace (§RULE-3)
    has_md_file, md_detail = check_research_markdown_on_disk(payload, transcript_info)
    if not has_md_file:
        reason = (
            "LỆNH CƯỠNG CHẾ TỪ SẾP (HARD DENY - §INDUSTRY-GROUNDED-GRILL-ME): BẮT BUỘC TẠO FILE MARKDOWN NGHIÊN CỨU TRÊN ĐĨA!\n"
            "Bạn đang trong quy trình /grill-me và đã thực hiện tra cứu web, nhưng CHƯA tạo file .md tổng hợp kết quả nghiên cứu "
            "vào workspace (vi phạm Quy tắc cốt lõi số 3 của Sếp).\n"
            "TUYỆT ĐỐI CẤM phỏng vấn bằng lý thuyết suông hoặc chỉ tra cứu mà không lưu lại kết quả! BẮT BUỘC phải gọi 'write_to_file' "
            "tạo file .md tổng hợp kết quả nghiên cứu (VD: research-architecture.md, so-sanh-giai-phap.md) vào workspace trước khi gọi 'ask_question'!"
        )
        log_diagnostic(f"HARD DENIED ask_question: Missing research markdown file on disk. Detail: {md_detail}")
        return pre_tool_response("deny", reason)

    # If both verified -> ALLOW
    log_diagnostic(f"Both search_web and research markdown file verified ({md_detail}). ask_question approved.")
    return pre_tool_response(
        "allow",
        f"Industry research verified via search tools and research markdown file on disk. {md_detail}. ask_question approved.",
    )



def run_self_tests() -> bool:
    """Comprehensive Self-Test Suite covering all hardened security guarantees."""
    import tempfile

    print("======================================================================")
    print("Running Hardened Grill-Me Research Enforcer Self-Test Suite")
    print("======================================================================\n")

    test_results: list[tuple[str, bool, str]] = []

    def record(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        test_results.append((name, passed, detail))
        print(f"[{status}] {name}{f' - {detail}' if detail and not passed else ''}")

    with tempfile.TemporaryDirectory() as temp_root:
        temp_path = pathlib.Path(temp_root)
        ws_dir = temp_path / "workspace"
        ws_dir.mkdir(parents=True, exist_ok=True)
        state_dir = temp_path / "state"
        state_dir.mkdir(parents=True, exist_ok=True)

        os.environ["GRILL_ME_STATE_DIR"] = str(state_dir)
        os.environ.pop("GRILL_ME_ACTIVE", None)
        os.environ.pop("ANTIGRAVITY_CONVERSATION_ID", None)

        # TC1: Hard DENY ask_question without search_web in grill-me
        r1 = evaluate_grill_me_research({
            "is_grill_me": True,
            "searched_web": False,
            "workspacePaths": [str(ws_dir)],
            "toolCall": {
                "name": "ask_question",
                "args": {"questions": [{"question": "Chọn kiến trúc nào?", "options": ["A", "B"]}]},
            },
        })
        record(
            "TC1: Hard DENY ask_question without search_web in grill-me",
            r1.get("decision") == "deny" and "TRA CỨU WEB" in r1.get("reason", ""),
        )

        # TC2: Hard DENY ask_question when search_web called but NO research .md on disk
        r2 = evaluate_grill_me_research({
            "is_grill_me": True,
            "searched_web": True,
            "workspacePaths": [str(ws_dir)],
            "toolCall": {
                "name": "ask_question",
                "args": {"questions": [{"question": "Chọn pattern?", "options": ["A", "B"]}]},
            },
        })
        record(
            "TC2: Hard DENY ask_question when search_web called but NO research .md on disk",
            r2.get("decision") == "deny" and "BẮT BUỘC TẠO FILE MARKDOWN" in r2.get("reason", ""),
        )

        # TC3: Allow ask_question in grill-me when search_web called AND research .md exists on disk
        res_file = ws_dir / "research-architecture.md"
        with open(res_file, "w", encoding="utf-8") as f:
            f.write("# Nghiên cứu kiến trúc Microservices theo chuẩn Netflix & Google SRE\n\n- Ưu điểm: Phân tán tải tốt\n- Trade-off: Phức tạp\n")

        r3 = evaluate_grill_me_research({
            "is_grill_me": True,
            "searched_web": True,
            "workspacePaths": [str(ws_dir)],
            "toolCall": {
                "name": "ask_question",
                "args": {"questions": [{"question": "Chọn pattern?", "options": ["Netflix", "Google"]}]},
            },
        })
        record(
            "TC3: Allow ask_question in grill-me after search_web AND research .md on disk",
            r3.get("decision") == "allow" and "research markdown file" in r3.get("reason", "").lower(),
        )

        # TC4: Bypass ask_question outside grill-me context
        r4 = evaluate_grill_me_research({
            "is_grill_me": False,
            "workspacePaths": [str(ws_dir)],
            "toolCall": {
                "name": "ask_question",
                "args": {"questions": [{"question": "Bạn có muốn tiếp tục?", "options": ["Có", "Không"]}]},
            },
        })
        record("TC4: Bypass ask_question outside grill-me context", r4.get("decision") == "allow")

        # TC5: Allow other tools during grill-me (run_command, view_file, write_to_file)
        r5 = evaluate_grill_me_research({
            "is_grill_me": True,
            "toolCall": {"name": "run_command", "args": {"CommandLine": "dir"}},
        })
        record("TC5: Allow other tools (run_command)", r5.get("decision") == "allow")

        # TC6: Detect grill-me via question text containing keyword without search -> DENY
        r6 = evaluate_grill_me_research({
            "workspacePaths": [str(ws_dir)],
            "toolCall": {
                "name": "ask_question",
                "args": {
                    "questions": [
                        {"question": "[/grill-me] Chọn giải pháp concurrency cho hệ thống", "options": ["A", "B"]}
                    ]
                },
            },
        })
        record("TC6: Detect grill-me in question text -> DENY unsearched", r6.get("decision") == "deny")

        # TC7: Allow when toolCallsHistory contains search_web and research .md on disk
        r7 = evaluate_grill_me_research({
            "is_grill_me": True,
            "workspacePaths": [str(ws_dir)],
            "toolCallsHistory": [{"name": "search_web", "args": {"query": "concurrency models"}}],
            "toolCall": {
                "name": "ask_question",
                "args": {"questions": [{"question": "Pattern?", "options": ["A", "B"]}]},
            },
        })
        record("TC7: Allow when history contains search_web and disk has research .md", r7.get("decision") == "allow")

        # TC8: Anti-bypass: Reject payload `is_grill_me: false` when transcript confirms active grill-me
        transcript_file = temp_path / "transcript.jsonl"
        with open(transcript_file, "w", encoding="utf-8") as f:
            f.write(json.dumps({"type": "USER_INPUT", "content": "/grill-me: Tư vấn kiến trúc Cloud", "created_at": "2026-09-12T00:00:00Z"}) + "\n")
            f.write(json.dumps({"type": "PLANNER_RESPONSE", "tool_calls": [{"name": "search_web", "args": {}}]}) + "\n")

        # Note: res_file already exists on disk in ws_dir
        r8 = evaluate_grill_me_research({
            "is_grill_me": False,  # Attempting bypass!
            "transcriptPath": str(transcript_file),
            "workspacePaths": [str(ws_dir)],
            "toolCall": {
                "name": "ask_question",
                "args": {"questions": [{"question": "Chọn gì?", "options": ["AWS", "GCP"]}]},
            },
        })
        record(
            "TC8: Anti-bypass: is_grill_me: false overridden by active transcript",
            r8.get("decision") == "allow" and "Industry research verified" in r8.get("reason", ""),
        )

        # TC9: Anti-bypass: Reject payload `searched_web: true` when transcript has 0 search calls
        transcript_unsearched = temp_path / "transcript_unsearched.jsonl"
        with open(transcript_unsearched, "w", encoding="utf-8") as f:
            f.write(json.dumps({"type": "USER_INPUT", "content": "/grill-me: Thiết kế database", "created_at": "2026-09-12T00:00:00Z"}) + "\n")
            f.write(json.dumps({"type": "PLANNER_RESPONSE", "tool_calls": [{"name": "view_file", "args": {}}]}) + "\n")

        r9 = evaluate_grill_me_research({
            "is_grill_me": True,
            "searched_web": True,  # Fake flag!
            "transcriptPath": str(transcript_unsearched),
            "workspacePaths": [str(ws_dir)],
            "toolCall": {
                "name": "ask_question",
                "args": {"questions": [{"question": "DB nào?", "options": ["PG", "MySQL"]}]},
            },
        })
        record(
            "TC9: Anti-bypass: Fake searched_web: true rejected by transcript",
            r9.get("decision") == "deny" and "TRA CỨU WEB" in r9.get("reason", ""),
        )

        # TC10: Multi-turn context awareness: Turn 2 user response maintains grill-me session and research
        transcript_multiturn = temp_path / "transcript_multiturn.jsonl"
        with open(transcript_multiturn, "w", encoding="utf-8") as f:
            # Turn 1
            f.write(json.dumps({"type": "USER_INPUT", "content": "/grill-me: Tư vấn Event-driven", "created_at": "2026-09-12T00:00:00Z"}) + "\n")
            f.write(json.dumps({"type": "PLANNER_RESPONSE", "tool_calls": [{"name": "search_web", "args": {}}]}) + "\n")
            f.write(json.dumps({"type": "PLANNER_RESPONSE", "tool_calls": [{"name": "write_to_file", "args": {"TargetFile": str(res_file)}}]}) + "\n")
            f.write(json.dumps({"type": "PLANNER_RESPONSE", "tool_calls": [{"name": "ask_question", "args": {}}]}) + "\n")
            # Turn 2: User responds with selection (does NOT contain '/grill-me')
            f.write(json.dumps({"type": "USER_INPUT", "content": "Tôi chọn phương án Kafka thay vì RabbitMQ", "created_at": "2026-09-12T00:01:00Z"}) + "\n")

        r10 = evaluate_grill_me_research({
            "transcriptPath": str(transcript_multiturn),
            "workspacePaths": [str(ws_dir)],
            "toolCall": {
                "name": "ask_question",
                "args": {"questions": [{"question": "Kafka broker config?", "options": ["3 brokers", "5 brokers"]}]},
            },
        })
        record(
            "TC10: Multi-turn context: Turn 2 inherits grill-me session and research validation",
            r10.get("decision") == "allow" and "Industry research verified" in r10.get("reason", ""),
        )

        # TC11: Multi-turn session termination: /stop or 'chốt phương án' closes grill-me session
        transcript_exit = temp_path / "transcript_exit.jsonl"
        with open(transcript_exit, "w", encoding="utf-8") as f:
            f.write(json.dumps({"type": "USER_INPUT", "content": "/grill-me: Tư vấn hệ thống", "created_at": "2026-09-12T00:00:00Z"}) + "\n")
            f.write(json.dumps({"type": "PLANNER_RESPONSE", "tool_calls": [{"name": "search_web", "args": {}}]}) + "\n")
            # User explicitly concludes interview
            f.write(json.dumps({"type": "USER_INPUT", "content": "Chốt phương án, tiến hành code", "created_at": "2026-09-12T00:02:00Z"}) + "\n")

        r11 = evaluate_grill_me_research({
            "transcriptPath": str(transcript_exit),
            "workspacePaths": [str(ws_dir)],
            "toolCall": {
                "name": "ask_question",
                "args": {"questions": [{"question": "Bạn có chắc không?", "options": ["Có", "Không"]}]},
            },
        })
        record("TC11: Multi-turn exit: Session closed via exit signal, bypass allowed", r11.get("decision") == "allow")

        # TC12: Disk markdown validator rejects empty (< 50 bytes) or system files (progress.md)
        empty_dir = temp_path / "empty_ws"
        empty_dir.mkdir(parents=True, exist_ok=True)
        with open(empty_dir / "progress.md", "w", encoding="utf-8") as f:
            f.write("# System Progress Log\n" * 5)
        with open(empty_dir / "research-empty.md", "w", encoding="utf-8") as f:
            f.write("# Empty\n")  # < 50 bytes

        r12 = evaluate_grill_me_research({
            "is_grill_me": True,
            "searched_web": True,
            "workspacePaths": [str(empty_dir)],
            "toolCall": {
                "name": "ask_question",
                "args": {"questions": [{"question": "A hay B?", "options": ["A", "B"]}]},
            },
        })
        record(
            "TC12: Rejects empty research .md or system files (progress.md)",
            r12.get("decision") == "deny" and "BẮT BUỘC TẠO FILE MARKDOWN" in r12.get("reason", ""),
        )

        # TC13: Malformed payload safety fallback
        r13 = evaluate_grill_me_research({})
        record("TC13: Malformed payload safety fallback", r13.get("decision") == "allow")

        # TC14: Subprocess streaming verification with exit code 0
        proc = subprocess.run(
            [sys.executable, str(pathlib.Path(__file__).resolve())],
            input=json.dumps({
                "is_grill_me": True,
                "searched_web": False,
                "workspacePaths": [str(ws_dir)],
                "toolCall": {
                    "name": "ask_question",
                    "args": {"questions": [{"question": "Q?", "options": ["1", "2"]}]},
                },
            }),
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        sub_out = json.loads(proc.stdout) if proc.stdout.strip() else {}
        record(
            "TC14: Subprocess stdio streaming verification",
            proc.returncode == 0 and sub_out.get("decision") == "deny",
        )

    all_passed = all(p for _, p, _ in test_results)
    total_cases = len(test_results)
    total_passed = sum(1 for _, p, _ in test_results)
    print("\n----------------------------------------------------------------------")
    print(f"Self-Test Summary: {total_passed}/{total_cases} scenarios passed ({'100%' if all_passed else 'FAILED'}).")
    print("----------------------------------------------------------------------\n")
    return all_passed


def main() -> None:
    """Main CLI entrypoint."""
    if "--self-test" in sys.argv:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    payload = read_stdin_payload(default={})
    response = evaluate_grill_me_research(payload)
    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()

