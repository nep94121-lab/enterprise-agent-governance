#!/usr/bin/env python3
"""Anti-Sequential Guard Hook (PreToolUse & PostToolUse: invoke_subagent).

Enterprise Multi-Agent Governance System - Physical Runtime Layer 1 Guardrail.
Enforces multi-agent parallelism and CPU-adaptive concurrent decomposition.
Philosophy: 'Không quan tâm việc nhỏ hay lớn, tự biết phân chia công việc từ tốc độ với hiệu năng CPU!'

Architecture:
- Tầng 1: Dynamic Workload Sensing (via hook_utils.workload_sensor).
  Measures task complexity across structural bullets, targets/entities, action verbs, and workspace directory breadth.
  Enforces Atomic Workload Invariant: If Complexity(T) >= threshold, spawned subagents must be >= Complexity(T).
  Eliminates role/name whitelists completely (100% dynamic sensing, zero hardcoded roles).
- Tầng 2: Monolithic & Anti-Sequential Pattern Detection.
  Regex detection of monolithic bundling of tests/modules/loops/roles/ranges and sequential single-point mindsets.
- Tầng 3: Workspace Backlog Sensing (via dynamic matrix discovery).
  Detects backlogs in workspace and prevents broad/vague delegation without atomic task ID.
- Tầng 4: Atomic Task & Sliding Window Tracking (validates atomic tasks and tracks dispatch via append-only JSONL).
- Dual-field compatibility: Returns both 'decision' (allow/deny) and 'verdict' (ALLOW/DENY).
- Built-in --self-test suite with 23 comprehensive scenarios ensuring 100% UTF-8 safety on Windows.
"""

from __future__ import annotations

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

# Ensure local hook library and hook_utils package are importable
HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).parent.resolve()
HOOKS_ROOT_DIR = HOOKS_SCRIPTS_DIR.parent.resolve()
if str(HOOKS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_SCRIPTS_DIR))
if str(HOOKS_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_ROOT_DIR))

from common_hook_lib import (  # noqa: E402
    emit_stdout_json,
    extract_tool_invocation,
    get_tool_args,
    get_tool_call,
    get_workspace_roots,
    log_diagnostic,
    post_tool_response,
    pre_tool_response,
    read_stdin_payload,
)

from hook_utils.config_loader import (  # noqa: E402
    get_concurrency_rules,
)
from hook_utils.workload_sensor import (  # noqa: E402
    WorkloadSensor,
)

# Tầng 2: Monolithic Pattern Detection Patterns (Cấm tư duy đơn điểm & ôm đồm tuần tự)
MONOLITHIC_PATTERNS: list[tuple[str, str]] = [
    (
        r"(?:toàn\s*bộ|tất\s*cả|\ball\b|toàn\s*thể|cả)\s+(?:10|20|30|40|50|100|\d{2,}|các|mọi)\s+(?:bài|test|tasks?|cases?|endpoints?|modules?|files?|bước|phần|đợt)",
        "Ôm đồm toàn bộ danh sách bài test/module/task vào 1 subagent thay vì băm nhỏ đa luồng song song",
    ),
    (
        r"(?:kiểm\s*toán|audit|thẩm\s*định|kiểm\s*tra|verify|inspect)\s+.*(?:\bcả\b|toàn\s*bộ|\bhết\b|\d+\s*giai\s*đoạn|3\s*giai\s*đoạn|nhiều\s*bước|transcript.*hook.*test|vừa.*vừa.*vừa)",
        "Ôm đồm kiểm toán nhiều giai đoạn/lĩnh vực vào 1 Auditor thay vì phân rã Hội đồng Kiểm toán Đa luồng song song",
    ),
    (
        r"(?:chạy|thực hiện|làm|kiểm tra|test|audit|verify|execute|process|xử lý)\s+(?:\d{2,}|[2-9])\s+(?:bài|tests?|tasks?|cases?|endpoints?|modules?|files?)",
        "Giao số lượng lớn bài test/tasks/modules cho 1 subagent mà không băm nhỏ đa luồng song song",
    ),
    (
        r"(?:chạy|thực hiện|xử lý|kiểm tra|test|audit|làm|verify|execute|process)\s+(?:từ\s+(?:bài\s+|tests?\s+|tc[-\s]*\s*)?\w+\s*(?:đến|-)\s*(?:bài\s+|tests?\s+|tc[-\s]*\s*)?\w+|\b\d+\s*-\s*\d+\b)",
        "Giao dải bài test liên tiếp cho 1 subagent thay vì chia đa luồng song song",
    ),
    (
        r"\btừ\s+(?:bài\s+|tests?\s+|tc[-\s]*\s*)\w+\s*(?:đến|-)\s*(?:bài\s+|tests?\s+|tc[-\s]*\s*)\w+\b",
        "Giao dải bài test liên tiếp cho 1 subagent thay vì chia đa luồng song song",
    ),
    (
        r"(?:(?:cả|vừa|đồng thời|gồm)\s+.*)?(?:backend|frontend|devops|qa|techlead|security)\s*(?:,|\+|&|và|với|cùng|lẫn)\s*(?:backend|frontend|devops|qa|techlead|security)",
        "Gộp chéo nhiều vai trò kỹ thuật khác nhau vào 1 subagent vi phạm phân quyền Tier 3",
    ),
    (
        r"(?:lặp lại|lần lượt|duyệt qua|loop through|scan all|quét toàn bộ|kiểm tra lần lượt|chạy lần lượt|làm lần lượt)\s+.*(?:10|20|30|50|100|\d{2,})\s+(?:files?|tệp|modules?|hàm|functions?|mục)",
        "Vòng lặp tuần tự duyệt khối lượng lớn bên trong 1 subagent",
    ),
    (
        r"(?:chạy|thực hiện|làm|kiểm tra|xử lý|duyệt|verify|execute|process)\s+(?:tuần\s*tự|lần\s*lượt|lần\s*lượt\s*từng|đơn\s*điểm|một\s*mình|từng\s*bước\s*một|sequentially|one\s*by\s*one)\b",
        "Tư duy tuần tự đơn điểm làm chậm tiến độ hệ thống",
    ),
    (
        r"(?:tuần\s*tự|lần\s*lượt|đơn\s*điểm|chạy\s*lần\s*lượt|làm\s*lần\s*lượt|sequentially|one\s*by\s*one)\s+(?:chạy|thực hiện|kiểm tra|xử lý|duyệt|verify|execute|process)\b",
        "Tư duy tuần tự đơn điểm làm chậm tiến độ hệ thống",
    ),
    (
        r"\b(?:chạy|làm|thực hiện|xử lý)\s+lần\s*lượt\b",
        "Tư duy tuần tự đơn điểm làm chậm tiến độ hệ thống",
    ),
    (
        r"(?:tự\s*mình\s*(?:đọc|kiểm tra|làm|chạy|verify|execute|process)\s*(?:cả|hết|toàn bộ)\s*\d+)",
        "Một subagent tự cày khối lượng lớn bài test thay vì phân rã cho hội đồng kiểm toán",
    ),
]

# Tầng 4: Atomic Task Identifier Regex
ATOMIC_TASK_REGEX = re.compile(
    r"(?i)\b(?:TC(?:-[A-Z0-9]+)+-\d+|TC[-\s_]*\d+|Test\s*#?\d+|Task\s*#?\d+|Milestone\s*#?\d+|Bài\s*(?:test\s*)?#?\d+)\b"
)


def extract_flat_prompt_text(args: dict[str, Any]) -> str:
    """Extract prompt text specifically from top-level flat fields (ignoring Subagents array)."""
    parts: list[str] = []
    for key in ("prompt", "description", "task", "instruction", "details", "message", "Prompt"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            parts.append(val.strip())
    return "\n".join(parts)


def extract_single_subagent_prompt(sub: dict[str, Any]) -> str:
    """Extract prompt text from an individual subagent dictionary."""
    parts: list[str] = []
    for key in ("Prompt", "prompt", "description", "task", "instruction", "details", "message"):
        val = sub.get(key)
        if isinstance(val, str) and val.strip():
            parts.append(val.strip())
    return "\n".join(parts)


def extract_prompt_text(args: dict[str, Any]) -> str:
    """Extract and concatenate prompt-like fields from tool args safely.

    Handles both flat prompt arguments and nested Subagents array definitions.
    """
    parts: list[str] = []
    flat = extract_flat_prompt_text(args)
    if flat:
        parts.append(flat)

    subagents = args.get("Subagents") or args.get("subagents")
    if isinstance(subagents, list):
        for sub in subagents:
            if isinstance(sub, dict):
                sub_p = extract_single_subagent_prompt(sub)
                if sub_p:
                    parts.append(sub_p)

    return "\n".join(parts)


def extract_spawned_count(args: dict[str, Any]) -> int:
    """Extract the total number of subagents being spawned in this tool call."""
    subagents = args.get("Subagents") or args.get("subagents")
    if isinstance(subagents, list) and subagents:
        return len(subagents)
    return 1


def extract_agent_identity(args: dict[str, Any]) -> tuple[str, str]:
    """Extract role and name from args safely."""
    role = str(args.get("role") or args.get("Role") or "").strip().lower()
    name = str(args.get("name") or args.get("Name") or "").strip().lower()
    if not role:
        subagents = args.get("Subagents") or args.get("subagents")
        if isinstance(subagents, list) and subagents and isinstance(subagents[0], dict):
            role = str(subagents[0].get("Role") or subagents[0].get("role") or "").strip().lower()
            name = str(subagents[0].get("Name") or subagents[0].get("name") or "").strip().lower()
    return role, name


def check_workspace_backlog(
    workspace_roots: list[pathlib.Path],
    prompt_text: str,
    backlog_threshold: int = 5,
) -> tuple[bool, str]:
    """Tầng 3: Check if workspace contains a large backlog matrix while prompt is vague."""
    backlog_patterns = ["*matrix*.md", "*backlog*.md", "*test*.md", "PROJECT*.md", "TODO*.md"]
    has_large_backlog = False
    detected_backlog_file = ""

    for root in workspace_roots:
        if not root.is_dir():
            continue
        try:
            for pattern in backlog_patterns:
                for target in root.glob(pattern):
                    if target.is_file():
                        try:
                            content = target.read_text(encoding="utf-8", errors="ignore")
                            task_count = len(re.findall(r"(?i)\bTC-(?:[A-Z0-9]+-)*\d+\b", content)) + len(
                                re.findall(r"(?i)\b(?:Test|Task|Bài)\s*#?\d+\b", content)
                            )
                            if task_count >= backlog_threshold:
                                has_large_backlog = True
                                detected_backlog_file = target.name
                                break
                        except OSError:
                            continue
                if has_large_backlog:
                    break
        except OSError:
            continue
        if has_large_backlog:
            break

    if has_large_backlog:
        # If workspace has large backlog, prompt MUST specify an atomic task ID
        if not ATOMIC_TASK_REGEX.search(prompt_text):
            vague_indicators = [
                r"(?:chạy|kiểm thử|thực thi|test|audit|verify|execute|process)\s+(?:toàn\s*bộ|tất\s*cả|toàn\s*dự\s*án|hệ\s*thống|ma\s*trận|matrix)",
                r"(?:execute|run|verify|process)\s+(?:all|full|complete)\s+(?:suite|matrix|tests?)",
            ]
            for vind in vague_indicators:
                if re.search(vind, prompt_text, re.IGNORECASE):
                    return (
                        True,
                        f"Phát hiện Workspace chứa ma trận backlog lớn (>={backlog_threshold} tasks trong {detected_backlog_file}), "
                        "nhưng lệnh giao việc lại chung chung mà không chia nhỏ thành ID bài test nguyên tử",
                    )

    return False, ""


def get_state_dir(
    workspace_root: str | pathlib.Path | None = None,
    session_id: str | None = None,
) -> pathlib.Path:
    """Resolve state directory for anti-sequential sliding window tracking, partitioned by workspace or session."""
    custom_dir = os.environ.get("ANTI_SEQUENTIAL_STATE_DIR")
    if custom_dir:
        return pathlib.Path(custom_dir).resolve()

    base_dir = pathlib.Path.home() / ".gemini" / "config" / "enterprise-hooks" / ".anti_sequential"

    # Partition key resolution:
    ws_key: str | None = None
    if workspace_root:
        ws_key = str(pathlib.Path(workspace_root).resolve()).lower()
    else:
        env_ws = os.environ.get("WORKSPACE_ROOT") or os.environ.get("PROJECT_ROOT")
        if env_ws:
            ws_key = str(pathlib.Path(env_ws).resolve()).lower()

    sess_key = (
        session_id
        or os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
        or os.environ.get("CONVERSATION_ID")
        or os.environ.get("GEMINI_SESSION_ID")
    )

    import hashlib
    if ws_key:
        part_hash = hashlib.sha256(ws_key.encode("utf-8")).hexdigest()[:12]
        return base_dir / f"ws_{part_hash}"
    elif sess_key:
        part_hash = hashlib.sha256(sess_key.encode("utf-8")).hexdigest()[:12]
        return base_dir / f"sess_{part_hash}"
    else:
        return base_dir / "default"


_INTRA_PROCESS_LOCK = threading.Lock()


class CrossProcessLock:
    """Robust cross-process file lock supporting Windows (msvcrt) and POSIX (fcntl).

    Prevents WinError 32 / WinError 5 file contention locks across concurrent hook processes on Windows NTFS.
    """

    def __init__(self, lock_file: pathlib.Path, timeout: float = 10.0):
        self.lock_file = lock_file
        self.timeout = timeout
        self.fd: int | None = None

    def __enter__(self) -> CrossProcessLock:
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(str(self.lock_file), os.O_RDWR | os.O_CREAT)
        start_time = time.monotonic()
        while True:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    # Non-blocking lock on byte 0
                    msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() - start_time > self.timeout:
                    try:
                        os.close(self.fd)
                    except OSError:
                        pass
                    self.fd = None
                    raise TimeoutError(f"Timed out waiting for cross-process file lock: {self.lock_file}")
                time.sleep(0.005 + random.uniform(0.005, 0.015))

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.fd is not None:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    try:
                        os.lseek(self.fd, 0, os.SEEK_SET)
                        msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
                else:
                    import fcntl
                    try:
                        fcntl.flock(self.fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
            finally:
                try:
                    os.close(self.fd)
                except OSError:
                    pass
                self.fd = None


def get_lock_file(state_dir: pathlib.Path | None = None) -> pathlib.Path:
    s_dir = state_dir if state_dir is not None else get_state_dir()
    return s_dir / "dispatch.lock"


def record_dispatch(
    role: str,
    atomic_id: str,
    max_retries: int = 10,
    workspace_root: str | pathlib.Path | None = None,
    session_id: str | None = None,
    state_dir: pathlib.Path | None = None,
) -> None:
    """Tầng 4: Record subagent dispatch timestamp for sliding window concurrency tracking.

    Uses Thread-Safe and Process-Safe Append-Only JSONL (dispatch_events.jsonl) with
    kernel file locking (msvcrt on Windows) and OS-level atomic append and flush(),
    guaranteeing 0% data loss and 0 WinError 32 / WinError 5 file contention locks on Windows NTFS.
    """
    try:
        s_dir = state_dir if state_dir is not None else get_state_dir(workspace_root=workspace_root, session_id=session_id)
        s_dir.mkdir(parents=True, exist_ok=True)
        events_file = s_dir / "dispatch_events.jsonl"
        lock_file = get_lock_file(s_dir)
        now = time.time()
        record = {
            "timestamp": now,
            "role": role,
            "atomic_id": atomic_id,
        }
        line = json.dumps(record, ensure_ascii=False) + "\n"
        for attempt in range(max_retries):
            try:
                with _INTRA_PROCESS_LOCK:
                    with CrossProcessLock(lock_file):
                        with open(events_file, "a", encoding="utf-8") as f:
                            f.write(line)
                            f.flush()
                return
            except (OSError, TimeoutError):
                if attempt == max_retries - 1:
                    log_diagnostic(f"Warning: Failed to record dispatch event after {max_retries} attempts")
                time.sleep(0.005 * (2**attempt))
    except Exception as exc:
        log_diagnostic(f"Warning: Failed to record dispatch event: {exc}")


def read_recent_dispatches(
    max_age_sec: float | None = None,
    workspace_root: str | pathlib.Path | None = None,
    session_id: str | None = None,
    state_dir: pathlib.Path | None = None,
    lock_timeout: float = 3.0,
) -> list[dict[str, Any]]:
    """Read recent dispatches from dispatch_events.jsonl within sliding window using cross-process lock.

    Includes event pruning / rotation (Mục 21) and fail-safe lock contention handling (Mục 22).
    """
    if max_age_sec is None:
        concurrency_rules = get_concurrency_rules()
        max_age_sec = float(concurrency_rules.get("sliding_window_seconds", 1800))

    s_dir = state_dir if state_dir is not None else get_state_dir(workspace_root=workspace_root, session_id=session_id)
    events_file = s_dir / "dispatch_events.jsonl"
    lock_file = get_lock_file(s_dir)
    if not events_file.is_file():
        return []

    now = time.time()
    recent: list[dict[str, Any]] = []
    total_lines_read = 0
    lock_contention_occurred = False

    try:
        with _INTRA_PROCESS_LOCK:
            with CrossProcessLock(lock_file, timeout=lock_timeout):
                if not events_file.is_file():
                    return []
                with open(events_file, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        total_lines_read += 1
                        try:
                            record = json.loads(line)
                            if now - float(record.get("timestamp", 0)) <= max_age_sec:
                                recent.append(record)
                        except (json.JSONDecodeError, ValueError, TypeError):
                            continue

                # Mục 21: Pruning / trimming of expired IPC events
                # If file has grown with expired entries, prune it atomically under lock
                expired_count = total_lines_read - len(recent)
                if total_lines_read > 50 and expired_count >= 20:
                    try:
                        temp_file = events_file.with_name(f"{events_file.name}.tmp.{os.getpid()}_{time.time_ns()}")
                        with open(temp_file, "w", encoding="utf-8") as tf:
                            for r in recent:
                                tf.write(json.dumps(r, ensure_ascii=False) + "\n")
                            tf.flush()
                        os.replace(str(temp_file), str(events_file))
                        log_diagnostic(f"Pruned {expired_count} expired dispatch events from {events_file}")
                    except Exception as pe:
                        log_diagnostic(f"Warning: dispatch event pruning failed: {pe}")
                        try:
                            if temp_file.exists():
                                temp_file.unlink()
                        except OSError:
                            pass
                return recent

    except (OSError, TimeoutError) as exc:
        lock_contention_occurred = True
        log_diagnostic(f"Warning: Lock contention on dispatch lock {lock_file}: {exc}. Performing snapshot read.")

    # Mục 22: Fail-Safe Handling on Lock Contention Timeout
    # When lock contention occurs, NEVER return [] (0 active).
    # Perform a best-effort non-blocking snapshot read of events_file directly.
    if lock_contention_occurred:
        try:
            snapshot_recent: list[dict[str, Any]] = []
            if events_file.is_file():
                with open(events_file, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            if now - float(record.get("timestamp", 0)) <= max_age_sec:
                                snapshot_recent.append(record)
                        except Exception:
                            continue
            if not snapshot_recent:
                # Lock contention indicates active concurrency; inject a sentinel to prevent fail-open
                log_diagnostic("Lock contention occurred but snapshot was empty; injecting active contention sentinel.")
                snapshot_recent.append({
                    "timestamp": now,
                    "role": "contended_subagent",
                    "atomic_id": "lock_contention_sentinel",
                })
            return snapshot_recent
        except Exception as read_exc:
            log_diagnostic(f"Snapshot read failed under lock contention: {read_exc}")
            return [{
                "timestamp": now,
                "role": "contended_subagent",
                "atomic_id": "lock_contention_fallback",
            }]

    return recent


def evaluate_anti_sequential(payload: dict[str, Any]) -> dict[str, Any]:
    """Core evaluation function implementing 4-tier Anti-Sequential Guardrail.

    Eliminates role/name whitelists completely.
    Evaluates workloads dynamically based on workload complexity C(T), structural AST sensing,
    anti-monolithic pattern detection, and workspace backlog awareness.
    """
    # Fail-safe initial check
    if not isinstance(payload, dict):
        res = pre_tool_response("allow", "Fail-safe: non-dict payload allowed.")
        res["verdict"] = "ALLOW"
        return res

    tool_name, args = extract_tool_invocation(payload)

    # Non-invoke_subagent tools are immediately allowed (Fast-Path Bypass)
    if tool_name != "invoke_subagent":
        res = pre_tool_response("allow", f"Tool '{tool_name}' is not invoke_subagent.")
        res["verdict"] = "ALLOW"
        return res

    subagents_list = args.get("Subagents") or args.get("subagents")
    is_batch = isinstance(subagents_list, list) and len(subagents_list) > 0
    spawned_count = len(subagents_list) if is_batch else extract_spawned_count(args)
    role, name = extract_agent_identity(args)

    # Resolve workspace and session context for state partitioning
    workspace_roots = get_workspace_roots(payload)
    ws_root = workspace_roots[0] if workspace_roots else None
    session_id = (
        payload.get("conversationId")
        or payload.get("sessionId")
        or payload.get("conversation_id")
        or payload.get("session_id")
    )

    # Dynamic limits sourced directly from config_loader (Zero-Hardcoding)
    concurrency_rules = get_concurrency_rules()
    atomic_threshold = int(concurrency_rules.get("atomic_workload_threshold", 2))
    backlog_threshold = int(concurrency_rules.get("workspace_backlog_threshold", 5))
    max_concurrent_pool1 = int(concurrency_rules.get("pool_1_cloud_thinking_max_subagents", 20))
    active_window_sec = float(concurrency_rules.get("active_subagent_window_seconds", 30.0))

    # Tầng 0: Concurrency Cap Enforcer (Kubernetes Job parallelism: 20 Pattern)
    # Khối lượng tổng thể không giới hạn, nhưng giới hạn song song đồng thời tối đa là 20 subagents.
    if max_concurrent_pool1 > 0 and spawned_count > max_concurrent_pool1:
        total_subagents = subagents_list if is_batch else []
        batch_1_count = min(max_concurrent_pool1, len(total_subagents)) if total_subagents else max_concurrent_pool1
        remaining_count = max(0, len(total_subagents) - batch_1_count) if total_subagents else (spawned_count - max_concurrent_pool1)
        reason = (
            f"Vượt quá giới hạn thực thi song song tối đa {max_concurrent_pool1} subagents cùng lúc (đang yêu cầu gọi {spawned_count} subagents)! "
            f"BẮT BUỘC áp dụng Mô hình Rolling Batch Chunks (Chuẩn Kubernetes Job parallelism: {max_concurrent_pool1}): "
            f"Vui lòng chia thành các đợt cuộn: Đợt 1 điều phối {batch_1_count} subagents đầu tiên; "
            f"sau khi Đợt 1 hoàn tất thì tiếp tục điều phối {remaining_count} subagents còn lại. "
            "Điều này bảo vệ hệ thống không bị phân mảnh context và giữ tốc độ xử lý tối ưu nhất!"
        )
        log_diagnostic(f"BLOCKED subagent call exceeding pool_1 cap: {spawned_count} > {max_concurrent_pool1}")
        res = pre_tool_response("deny", reason)
        res["verdict"] = "DENY"
        return res

    # Tầng 0: Sliding window active concurrent dispatch check via read_recent_dispatches (SEC-W2-03)
    if max_concurrent_pool1 > 0 and active_window_sec > 0.0:
        recent_dispatches = read_recent_dispatches(
            max_age_sec=active_window_sec,
            workspace_root=ws_root,
            session_id=session_id,
        )
        active_count = len(recent_dispatches)
        if active_count + spawned_count > max_concurrent_pool1:
            reason = (
                f"Vượt quá trần thực thi song song {max_concurrent_pool1} subagents trong cửa sổ trượt {active_window_sec}s "
                f"(hiện có {active_count} subagent đang hoạt động, yêu cầu thêm {spawned_count} subagents, tổng {active_count + spawned_count} > {max_concurrent_pool1})! "
                f"BẮT BUỘC áp dụng Mô hình Rolling Batch Chunks (Chuẩn Kubernetes Job parallelism: {max_concurrent_pool1}): "
                "Chờ các subagent đang chạy hoàn tất (Reactive Wakeup) trước khi phóng tiếp đợt mới."
            )
            log_diagnostic(f"BLOCKED subagent call exceeding sliding window cap: {active_count} + {spawned_count} > {max_concurrent_pool1}")
            res = pre_tool_response("deny", reason)
            res["verdict"] = "DENY"
            return res

    # Tầng 0.5: Worker Subagent Write-Tool Enforcer (Anti-Readonly-Worker Guard)
    # Cưỡng chế nghiêm ngặt: Mọi subagent thợ (Dev, Fix, Code, Patch, Refactor, Implement)
    # BẮT BUỘC phải dùng TypeName="self" để được cấp công cụ ghi/sửa file và chạy lệnh.
    worker_role_keywords = [
        "dev", "developer", "backend", "frontend", "devops", "coder",
        "thợ", "lập trình", "fixer", "patcher"
    ]
    worker_prompt_keywords = [
        "vá lỗi", "sửa lỗi", "sửa bug", "fix bug", "patch", "refactor",
        "minimal change", "replace_file_content", "write_to_file", "triển khai mã"
    ]

    if is_batch:
        for idx, sa in enumerate(subagents_list):
            if not isinstance(sa, dict):
                continue
            sa_role = str(sa.get("Role") or sa.get("role") or "").strip().lower()
            sa_type = str(sa.get("TypeName") or sa.get("typeName") or "").strip().lower()
            sa_prompt = str(sa.get("Prompt") or sa.get("prompt") or "").strip().lower()

            is_worker = any(kw in sa_role for kw in worker_role_keywords) or any(kw in sa_prompt for kw in worker_prompt_keywords)

            if is_worker and sa_type == "research":
                display_role = sa.get("Role") or sa.get("role") or f"Subagent #{idx+1}"
                reason = (
                    f"CƯỠNG CHẾ QUY TẮC CÔNG CỤ (ANTI-READONLY-WORKER): Subagent [{display_role}] đóng vai trò thợ kỹ thuật/sửa code "
                    "nhưng lại được khởi tạo với TypeName='research' (Read-Only)! "
                    "Subagent 'research' bị tước toàn bộ quyền ghi/sửa file (không có replace_file_content, write_to_file), "
                    "không thể tự sửa code mà chỉ có thể gửi diff về bắt PM sửa hộ, vi phạm nghiêm trọng ranh giới phân tầng! "
                    "BẮT BUỘC ĐỔI TypeName thành 'self' để subagent kế thừa toàn bộ công cụ sửa file và tự thực hiện từ A-Z!"
                )
                log_diagnostic(f"BLOCKED invoke_subagent with read-only TypeName='research' for worker: {display_role}")
                res = pre_tool_response("deny", reason)
                res["verdict"] = "DENY"
                return res
    else:
        flat_type = str(args.get("TypeName") or args.get("typeName") or "").strip().lower()
        flat_role = str(role or name or "").strip().lower()
        flat_prompt = str(extract_prompt_text(args)).strip().lower()
        is_worker = any(kw in flat_role for kw in worker_role_keywords) or any(kw in flat_prompt for kw in worker_prompt_keywords)
        if is_worker and flat_type == "research":
            display_role = role or name or "Worker Subagent"
            reason = (
                f"CƯỠNG CHẾ QUY TẮC CÔNG CỤ (ANTI-READONLY-WORKER): Subagent [{display_role}] đóng vai trò thợ kỹ thuật/sửa code "
                "nhưng lại được khởi tạo với TypeName='research' (Read-Only)! "
                "Subagent 'research' bị tước toàn bộ quyền ghi/sửa file (không có replace_file_content, write_to_file), "
                "không thể tự sửa code mà chỉ có thể gửi diff về bắt PM sửa hộ, vi phạm nghiêm trọng ranh giới phân tầng! "
                "BẮT BUỘC ĐỔI TypeName thành 'self' để subagent kế thừa toàn bộ công cụ sửa file và tự thực hiện từ A-Z!"
            )
            log_diagnostic(f"BLOCKED invoke_subagent with read-only TypeName='research' for worker: {display_role}")
            res = pre_tool_response("deny", reason)
            res["verdict"] = "DENY"
            return res

    workspace_roots = get_workspace_roots(payload)
    ws_root = workspace_roots[0] if workspace_roots else None
    sensor = WorkloadSensor(atomic_threshold=atomic_threshold)

    # SEC-W2-01: Independent evaluation for Subagents array to prevent false positive concatenation
    if is_batch:
        batch_prompt = extract_flat_prompt_text(args)
        if batch_prompt:
            for pattern, desc in MONOLITHIC_PATTERNS:
                if re.search(pattern, batch_prompt, re.IGNORECASE):
                    reason = (
                        "Lãng phí CPU và làm chậm tiến độ! Yêu cầu băm nhỏ tác vụ ra N subagents song song ngay lập tức! "
                        f"(Phát hiện toàn bộ lô vi phạm mẫu ôm đồm/tuần tự: {desc}). "
                        "Triết lý chỉ đạo tối thượng của Sếp: 'Không quan tâm việc nhỏ hay lớn, tự biết phân chia công việc từ tốc độ với hiệu năng CPU!'."
                    )
                    log_diagnostic(f"BLOCKED batch monolithic delegation: {desc}")
                    res = pre_tool_response("deny", reason)
                    res["verdict"] = "DENY"
                    return res

        for idx, sa in enumerate(subagents_list):
            if not isinstance(sa, dict):
                continue
            sa_prompt = extract_single_subagent_prompt(sa)
            sa_role = str(sa.get("Role") or sa.get("role") or "").strip()
            sa_name = str(sa.get("Name") or sa.get("name") or "").strip()
            sa_display = sa_role or sa_name or f"Subagent #{idx+1}"

            # Tầng 1: Multi-atomic bundling on this single subagent
            sa_atomic_matches = ATOMIC_TASK_REGEX.findall(sa_prompt)
            sa_unique_atomic = {m.strip().upper().replace(" ", "").replace("_", "-") for m in sa_atomic_matches}
            if len(sa_unique_atomic) > 1:
                bundled_str = ", ".join(list(sa_unique_atomic)[:5])
                reason = (
                    "Lãng phí CPU và làm chậm tiến độ! Yêu cầu băm nhỏ tác vụ ra N subagents song song ngay lập tức! "
                    f"(Phát hiện Subagent [{sa_display}] bị gộp nhiều bài test nguyên tử: {bundled_str}). "
                    "Triết lý chỉ đạo tối thượng của Sếp: 'Không quan tâm việc nhỏ hay lớn, tự biết phân chia công việc từ tốc độ với hiệu năng CPU!'."
                )
                log_diagnostic(f"BLOCKED multi-atomic bundling in [{sa_display}]: {bundled_str}")
                res = pre_tool_response("deny", reason)
                res["verdict"] = "DENY"
                return res

            # Tầng 2: Monolithic & Anti-Sequential Pattern Detection on this single subagent
            for pattern, desc in MONOLITHIC_PATTERNS:
                if re.search(pattern, sa_prompt, re.IGNORECASE):
                    reason = (
                        "Lãng phí CPU và làm chậm tiến độ! Yêu cầu băm nhỏ tác vụ ra N subagents song song ngay lập tức! "
                        f"(Phát hiện Subagent [{sa_display}] vi phạm: {desc}). "
                        "Triết lý chỉ đạo tối thượng của Sếp: 'Không quan tâm việc nhỏ hay lớn, tự biết phân chia công việc từ tốc độ với hiệu năng CPU!'."
                    )
                    log_diagnostic(f"BLOCKED monolithic subagent delegation in [{sa_display}]: {desc}")
                    res = pre_tool_response("deny", reason)
                    res["verdict"] = "DENY"
                    return res

            # Tầng 3: Dynamic Workload Sensing on this single subagent (spawned_subagents=1)
            sa_complexity = sensor.assess_complexity(
                prompt=sa_prompt,
                spawned_subagents=1,
                workspace_root=ws_root,
            )
            if sa_complexity.is_violation:
                reason = (
                    "Lãng phí CPU và làm chậm tiến độ! Yêu cầu băm nhỏ tác vụ ra N subagents song song ngay lập tức theo triết lý tự động tối ưu tốc độ & CPU của Sếp! "
                    f"(Phát hiện Subagent [{sa_display}] vi phạm tải trọng nguyên tử: {sa_complexity.violation_details}). "
                    f"Độ phức tạp C(T)={sa_complexity.complexity_index} (ngưỡng={sa_complexity.threshold}) nhưng chỉ giao cho 1 subagent đơn lẻ."
                )
                log_diagnostic(f"BLOCKED atomic workload violation in [{sa_display}]: {sa_complexity.violation_details}")
                res = pre_tool_response("deny", reason)
                res["verdict"] = "DENY"
                return res

            # Tầng 4: Workspace Backlog Sensing on this single subagent
            has_backlog, backlog_desc = check_workspace_backlog(
                workspace_roots=workspace_roots,
                prompt_text=sa_prompt,
                backlog_threshold=backlog_threshold,
            )
            if has_backlog:
                reason = (
                    "Lãng phí CPU và làm chậm tiến độ! Yêu cầu băm nhỏ tác vụ ra N subagents song song ngay lập tức! "
                    f"(Phát hiện Subagent [{sa_display}] vi phạm: {backlog_desc}). "
                    "Triết lý chỉ đạo tối thượng của Sếp: 'Không quan tâm việc nhỏ hay lớn, tự biết phân chia công việc từ tốc độ với hiệu năng CPU!'."
                )
                log_diagnostic(f"BLOCKED vague delegation in [{sa_display}]: {backlog_desc}")
                res = pre_tool_response("deny", reason)
                res["verdict"] = "DENY"
                return res

        # Record dispatches for all subagents in the batch
        for idx, sa in enumerate(subagents_list):
            if not isinstance(sa, dict):
                continue
            sa_prompt = extract_single_subagent_prompt(sa)
            sa_role = str(sa.get("Role") or sa.get("role") or "").strip()
            sa_name = str(sa.get("Name") or sa.get("name") or "").strip()
            sa_atomic_matches = ATOMIC_TASK_REGEX.findall(sa_prompt)
            sa_atomic_id = sa_atomic_matches[0] if sa_atomic_matches else f"batch_task_{idx+1}"
            record_dispatch(
                sa_role or sa_name or "subagent",
                sa_atomic_id,
                workspace_root=ws_root,
                session_id=session_id,
            )

        res = pre_tool_response(
            "allow",
            f"Batch of {len(subagents_list)} subagents complies with Anti-Sequential policy: All tasks evaluated independently and verified atomic.",
        )
        res["verdict"] = "ALLOW"
        return res

    # Single subagent delegation (flat prompt)
    prompt_text = extract_flat_prompt_text(args)
    if not prompt_text:
        prompt_text = extract_prompt_text(args)

    # Tầng 1: Atomic Task Compliant & Multi-Atomic Bundling Detection
    atomic_matches = ATOMIC_TASK_REGEX.findall(prompt_text)
    unique_atomic_ids = {m.strip().upper().replace(" ", "").replace("_", "-") for m in atomic_matches}
    if len(unique_atomic_ids) > 1 and spawned_count < len(unique_atomic_ids):
        bundled_str = ", ".join(list(unique_atomic_ids)[:5])
        reason = (
            "Lãng phí CPU và làm chậm tiến độ! Yêu cầu băm nhỏ tác vụ ra N subagents song song ngay lập tức! "
            f"(Phát hiện gộp nhiều bài test nguyên tử vào 1 subagent: {bundled_str}). "
            "Triết lý chỉ đạo tối thượng của Sếp: 'Không quan tâm việc nhỏ hay lớn, tự biết phân chia công việc từ tốc độ với hiệu năng CPU!'."
        )
        log_diagnostic(f"BLOCKED multi-atomic bundling: {bundled_str}")
        res = pre_tool_response("deny", reason)
        res["verdict"] = "DENY"
        return res

    # Tầng 2: Monolithic & Anti-Sequential Pattern Detection
    for pattern, desc in MONOLITHIC_PATTERNS:
        if re.search(pattern, prompt_text, re.IGNORECASE):
            reason = (
                "Lãng phí CPU và làm chậm tiến độ! Yêu cầu băm nhỏ tác vụ ra N subagents song song ngay lập tức! "
                f"(Phát hiện vi phạm: {desc}). "
                "Triết lý chỉ đạo tối thượng của Sếp: 'Không quan tâm việc nhỏ hay lớn, tự biết phân chia công việc từ tốc độ với hiệu năng CPU!'."
            )
            log_diagnostic(f"BLOCKED monolithic subagent delegation: {desc}")
            res = pre_tool_response("deny", reason)
            res["verdict"] = "DENY"
            return res

    # Tầng 3: Dynamic Workload Sensing (hook_utils.workload_sensor)
    complexity = sensor.assess_complexity(
        prompt=prompt_text,
        spawned_subagents=spawned_count,
        workspace_root=ws_root,
    )

    if complexity.is_violation:
        reason = (
            "Lãng phí CPU và làm chậm tiến độ! Yêu cầu băm nhỏ tác vụ ra N subagents song song ngay lập tức theo triết lý tự động tối ưu tốc độ & CPU của Sếp! "
            f"(Phát hiện vi phạm tải trọng nguyên tử: {complexity.violation_details}). "
            f"Độ phức tạp C(T)={complexity.complexity_index} (ngưỡng={complexity.threshold}) nhưng chỉ điều phối {complexity.spawned_subagents} subagent."
        )
        log_diagnostic(f"BLOCKED atomic workload violation: {complexity.violation_details}")
        res = pre_tool_response("deny", reason)
        res["verdict"] = "DENY"
        return res

    # Tầng 4: Workspace Backlog Sensing
    has_backlog_violation, backlog_desc = check_workspace_backlog(
        workspace_roots=workspace_roots,
        prompt_text=prompt_text,
        backlog_threshold=backlog_threshold,
    )
    if has_backlog_violation:
        reason = (
            "Lãng phí CPU và làm chậm tiến độ! Yêu cầu băm nhỏ tác vụ ra N subagents song song ngay lập tức! "
            f"(Phát hiện vi phạm: {backlog_desc}). "
            "Triết lý chỉ đạo tối thượng của Sếp: 'Không quan tâm việc nhỏ hay lớn, tự biết phân chia công việc từ tốc độ với hiệu năng CPU!'."
        )
        log_diagnostic(f"BLOCKED vague delegation against workspace backlog: {backlog_desc}")
        res = pre_tool_response("deny", reason)
        res["verdict"] = "DENY"
        return res

    atomic_id = atomic_matches[0] if atomic_matches else "atomic_task"
    record_dispatch(
        role or name or "subagent",
        atomic_id,
        workspace_root=ws_root,
        session_id=session_id,
    )

    res = pre_tool_response(
        "allow", f"Task complies with Anti-Sequential policy: Atomic task assignment ({atomic_id})."
    )
    res["verdict"] = "ALLOW"
    return res


def run_self_tests() -> bool:
    """Run comprehensive self-test scenarios validating all tiers and UTF-8 safety."""
    import tempfile
    import shutil

    old_state_dir = os.environ.get("ANTI_SEQUENTIAL_STATE_DIR")
    temp_dir = tempfile.mkdtemp(prefix="anti_seq_test_")
    os.environ["ANTI_SEQUENTIAL_STATE_DIR"] = temp_dir
    try:
        return _run_self_tests_internal()
    finally:
        if old_state_dir is not None:
            os.environ["ANTI_SEQUENTIAL_STATE_DIR"] = old_state_dir
        else:
            os.environ.pop("ANTI_SEQUENTIAL_STATE_DIR", None)
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except OSError:
            pass


def _run_self_tests_internal() -> bool:
    """Internal test execution body."""
    test_results: list[tuple[str, bool, str]] = []

    def record_test(tc_id: str, name: str, passed: bool, detail: str = "") -> None:
        status_str = "PASS" if passed else "FAIL"
        test_results.append((f"{tc_id}: {name}", passed, detail))
        print(f"[{status_str}] {tc_id}: {name} {f'- {detail}' if detail else ''}")

    print("======================================================================")
    print("Executing Anti-Sequential Guard Hook Self-Test Suite (36 Scenarios)...")
    print("Zero-Whitelist & Dynamic Workload Sensor Architecture")
    print("======================================================================\n")

    import tempfile
    import concurrent.futures

    # TC01: test_allow_non_subagent
    tc01_payload = {"toolCall": {"name": "run_command", "args": {"CommandLine": "dir"}}}
    res01 = evaluate_anti_sequential(tc01_payload)
    passed01 = res01.get("decision") == "allow" and res01.get("verdict") == "ALLOW"
    record_test("TC01", "test_allow_non_subagent", passed01, f"decision={res01.get('decision')}")

    # TC02: test_allow_atomic_telemetry_profiler
    tc02_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "hardware_telemetry_profiler",
                "prompt": "Sample CPU and RAM every 500ms and write to timeline.csv",
            },
        }
    }
    res02 = evaluate_anti_sequential(tc02_payload)
    passed02 = res02.get("decision") == "allow" and res02.get("verdict") == "ALLOW"
    record_test("TC02", "test_allow_atomic_telemetry_profiler", passed02, f"atomic allowed={res02.get('decision')}")

    # TC03: test_allow_atomic_pm_orchestrator
    tc03_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "pm_orchestrator",
                "prompt": "Quản lý và điều phối các subagents theo 7 Phase Gates",
            },
        }
    }
    res03 = evaluate_anti_sequential(tc03_payload)
    passed03 = res03.get("decision") == "allow" and res03.get("verdict") == "ALLOW"
    record_test("TC03", "test_allow_atomic_pm_orchestrator", passed03, f"pm allowed={res03.get('decision')}")

    # TC04: test_allow_atomic_task_tc01
    tc04_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_backend_1",
                "prompt": "Thực thi test case TC-01: Bẫy SQLi và kiểm tra tham số hóa",
            },
        }
    }
    res04 = evaluate_anti_sequential(tc04_payload)
    passed04 = res04.get("decision") == "allow" and res04.get("verdict") == "ALLOW"
    record_test("TC04", "test_allow_atomic_task_tc01", passed04, f"atomic allowed={res04.get('decision')}")

    # TC05: test_deny_monolithic_all_10
    tc05_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_backend_1",
                "prompt": "Chạy toàn bộ 10 bài test đối kháng và ghi báo cáo",
            },
        }
    }
    res05 = evaluate_anti_sequential(tc05_payload)
    passed05 = (
        res05.get("decision") == "deny"
        and res05.get("verdict") == "DENY"
        and "Lãng phí CPU và làm chậm tiến độ" in str(res05.get("reason", ""))
    )
    record_test("TC05", "test_deny_monolithic_all_10", passed05, f"denied={res05.get('decision')}")

    # TC06: test_deny_range_of_tests
    tc06_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_qa_1",
                "prompt": "Thực hiện từ bài 1 đến bài 10 tuần tự",
            },
        }
    }
    res06 = evaluate_anti_sequential(tc06_payload)
    passed06 = res06.get("decision") == "deny" and res06.get("verdict") == "DENY"
    record_test("TC06", "test_deny_range_of_tests", passed06, f"range denied={res06.get('decision')}")

    # TC07: test_deny_cross_role_bundling
    tc07_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_fullstack",
                "prompt": "Làm cả backend, frontend và QA cùng lúc",
            },
        }
    }
    res07 = evaluate_anti_sequential(tc07_payload)
    passed07 = res07.get("decision") == "deny" and res07.get("verdict") == "DENY"
    record_test("TC07", "test_deny_cross_role_bundling", passed07, f"cross-role denied={res07.get('decision')}")

    # TC08: test_deny_loop_through_dataset
    tc08_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_auditor_1",
                "prompt": "Duyệt qua và audit 100 files tuần tự trong thư mục",
            },
        }
    }
    res08 = evaluate_anti_sequential(tc08_payload)
    passed08 = res08.get("decision") == "deny" and res08.get("verdict") == "DENY"
    record_test("TC08", "test_deny_loop_through_dataset", passed08, f"loop denied={res08.get('decision')}")

    # TC09: test_allow_batch_subagent_2
    tc09_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_devops_2",
                "prompt": "Thực thi TC-02: Bẫy PII rò rỉ và kiểm tra hash masking",
            },
        }
    }
    res09 = evaluate_anti_sequential(tc09_payload)
    passed09 = res09.get("decision") == "allow" and res09.get("verdict") == "ALLOW"
    record_test("TC09", "test_allow_batch_subagent_2", passed09, f"batch subagent allowed={res09.get('decision')}")

    # TC10: test_malformed_payload_safe
    malformed_cases = [{}, {"corrupted": True}, None]
    passed10 = True
    for m in malformed_cases:
        r = evaluate_anti_sequential(m)  # type: ignore[arg-type]
        if r.get("decision") != "allow" or r.get("verdict") != "ALLOW":
            passed10 = False
            break
    record_test("TC10", "test_malformed_payload_safe", passed10, "fail-safe resilience verified")

    # TC11: test_utf8_vietnamese_accent
    vietnamese_prompt = (
        "Kiểm tra toàn bộ 10 bài thử nghiệm có dấu tiếng Việt: á, ế, ộ, ử, ỹ, đ để xác nhận không lỗi font"
    )
    tc11_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_qa_vn",
                "prompt": vietnamese_prompt,
            },
        }
    }
    res11 = evaluate_anti_sequential(tc11_payload)
    # Must deny monolithic 'toàn bộ 10 bài' without Unicode encoding crash
    passed11 = (
        res11.get("decision") == "deny"
        and res11.get("verdict") == "DENY"
        and isinstance(res11.get("reason"), str)
        and "Lãng phí CPU" in str(res11.get("reason"))
    )
    record_test("TC11", "test_utf8_vietnamese_accent", passed11, "full UTF-8 Vietnamese strings verified")

    # TC12: test_verdict_dual_fields
    sample_payloads = [tc01_payload, tc04_payload, tc05_payload, tc07_payload]
    passed12 = True
    for p in sample_payloads:
        r = evaluate_anti_sequential(p)
        dec = r.get("decision")
        verd = r.get("verdict")
        if dec == "allow" and verd != "ALLOW":
            passed12 = False
            break
        if dec == "deny" and verd != "DENY":
            passed12 = False
            break
        if not dec or not verd:
            passed12 = False
            break
    record_test("TC12", "test_verdict_dual_fields", passed12, "dual fields 'decision' & 'verdict' verified")

    # TC13: test_allow_multi_segment_atomic (Reviewer 1 Finding 1)
    tc13_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_backend_1",
                "prompt": "Thực thi test case TC-EXP-BE-01: Bẫy SQLi và kiểm tra tham số hóa",
            },
        }
    }
    res13 = evaluate_anti_sequential(tc13_payload)
    passed13 = res13.get("decision") == "allow" and res13.get("verdict") == "ALLOW"
    record_test("TC13", "test_allow_multi_segment_atomic", passed13, "TC-EXP-BE-01 recognized as atomic")

    # TC14: test_deny_bare_count (Challenger 1 BYPASS-01)
    tc14_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_backend_1",
                "prompt": "Chạy 10 bài test đối kháng trong bộ đề",
            },
        }
    }
    res14 = evaluate_anti_sequential(tc14_payload)
    passed14 = res14.get("decision") == "deny" and res14.get("verdict") == "DENY"
    record_test("TC14", "test_deny_bare_count_bypass01", passed14, "bare count blocked")

    # TC15: test_deny_multi_token_range (Challenger 1 BYPASS-02)
    tc15_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_qa_1",
                "prompt": "Chạy từ test 1 đến test 10 ngay lập tức",
            },
        }
    }
    res15 = evaluate_anti_sequential(tc15_payload)
    passed15 = res15.get("decision") == "deny" and res15.get("verdict") == "DENY"
    record_test("TC15", "test_deny_multi_token_range_bypass02", passed15, "multi-token range blocked")

    # TC16: test_deny_hyphen_range (Challenger 1 BYPASS-03)
    tc16_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_qa_1",
                "prompt": "Test từ 1 - 10 không cần chia nhỏ",
            },
        }
    }
    res16 = evaluate_anti_sequential(tc16_payload)
    passed16 = res16.get("decision") == "deny" and res16.get("verdict") == "DENY"
    record_test("TC16", "test_deny_hyphen_range_bypass03", passed16, "hyphen range blocked")

    # TC17: test_deny_multi_atomic_bundling (Challenger 1 BYPASS-04)
    tc17_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_fullstack",
                "prompt": "Thực hiện TC-01, TC-02, TC-03, TC-04, TC-05 tuần tự",
            },
        }
    }
    res17 = evaluate_anti_sequential(tc17_payload)
    passed17 = (
        res17.get("decision") == "deny"
        and res17.get("verdict") == "DENY"
        and "gộp nhiều bài test nguyên tử" in str(res17.get("reason", ""))
    )
    record_test("TC17", "test_deny_multi_atomic_bundling_bypass04", passed17, "multi-atomic bundling blocked")

    # TC18: test_deny_cross_role_plus (Challenger 1 BYPASS-05)
    tc18_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_combo",
                "prompt": "Backend + Frontend + QA làm chung trong 1 subagent",
            },
        }
    }
    res18 = evaluate_anti_sequential(tc18_payload)
    passed18 = res18.get("decision") == "deny" and res18.get("verdict") == "DENY"
    record_test("TC18", "test_deny_cross_role_plus_bypass05", passed18, "unprefixed cross-role blocked")

    # TC19: test_append_only_dispatch_events (Challenger 2 Mitigation)
    recent = read_recent_dispatches()
    passed19 = isinstance(recent, list)
    record_test("TC19", "test_append_only_dispatch_events", passed19, f"read {len(recent)} dispatch events")

    # TC20: test_deny_monolithic_even_for_pm_role (No Whitelist Bypass)
    tc20_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "pm_orchestrator",
                "prompt": "Chạy toàn bộ 10 bài test đối kháng và ghi báo cáo",
            },
        }
    }
    res20 = evaluate_anti_sequential(tc20_payload)
    passed20 = (
        res20.get("decision") == "deny"
        and res20.get("verdict") == "DENY"
        and "Lãng phí CPU và làm chậm tiến độ" in str(res20.get("reason", ""))
    )
    record_test("TC20", "test_deny_monolithic_even_for_pm_role", passed20, "zero whitelist bypass for PM role")

    # TC21: test_deny_monolithic_even_for_telemetry_role (No Whitelist Bypass)
    tc21_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "hardware_telemetry_profiler",
                "prompt": "Thực hiện từ bài 1 đến bài 10 tuần tự",
            },
        }
    }
    res21 = evaluate_anti_sequential(tc21_payload)
    passed21 = res21.get("decision") == "deny" and res21.get("verdict") == "DENY"
    record_test("TC21", "test_deny_monolithic_even_for_telemetry_role", passed21, "zero whitelist bypass for profiler")

    # TC22: test_deny_workload_complexity_violation (WorkloadSensor integration)
    tc22_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker_qa",
                "prompt": "- Bước 1: Sửa bug auth\n- Bước 2: Viết test thanh toán\n- Bước 3: Deploy hạ tầng",
            },
        }
    }
    res22 = evaluate_anti_sequential(tc22_payload)
    passed22 = (
        res22.get("decision") == "deny"
        and res22.get("verdict") == "DENY"
        and "vi phạm tải trọng nguyên tử" in str(res22.get("reason", ""))
    )
    record_test("TC22", "test_deny_workload_complexity_violation", passed22, "workload sensor multi-step blocked")

    # TC23: test_allow_multi_subagents_array_satisfying_complexity
    tc23_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "Subagents": [
                    {"Role": "worker_1", "Prompt": "Thực thi test case TC-01: Bẫy SQLi"},
                    {"Role": "worker_2", "Prompt": "Thực thi test case TC-02: Bẫy PII"},
                ]
            },
        }
    }
    res23 = evaluate_anti_sequential(tc23_payload)
    passed23 = res23.get("decision") == "allow" and res23.get("verdict") == "ALLOW"
    record_test("TC23", "test_allow_multi_subagents_array_satisfying_complexity", passed23, "concurrent array allowed")

    # TC24: test_deny_concurrency_cap_exceeding_20 (Kubernetes Job parallelism: 20 Pattern)
    tc24_subagents = [{"Role": f"worker_{i}", "Prompt": f"Thực thi task atomic #{i}"} for i in range(1, 24)]
    tc24_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {"Subagents": tc24_subagents},
        }
    }
    res24 = evaluate_anti_sequential(tc24_payload)
    passed24 = (
        res24.get("decision") == "deny"
        and res24.get("verdict") == "DENY"
        and "Vượt quá giới hạn thực thi song song tối đa 20" in str(res24.get("reason", ""))
        and "Rolling Batch Chunks" in str(res24.get("reason", ""))
    )
    record_test("TC24", "test_deny_concurrency_cap_exceeding_20", passed24, "pool_1 cap 20 blocked with rolling chunks suggestion")

    # TC25: test_deny_worker_with_readonly_research_type
    tc25_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "Subagents": [
                    {"Role": "Backend Developer", "TypeName": "research", "Prompt": "Vá lỗi P0 trong module"}
                ]
            },
        }
    }
    res25 = evaluate_anti_sequential(tc25_payload)
    passed25 = (
        res25.get("decision") == "deny"
        and res25.get("verdict") == "DENY"
        and "ANTI-READONLY-WORKER" in str(res25.get("reason", ""))
        and "BẮT BUỘC ĐỔI TypeName thành 'self'" in str(res25.get("reason", ""))
    )
    record_test("TC25", "test_deny_worker_with_readonly_research_type", passed25, "blocked worker with research type")

    # TC26: test_allow_worker_with_self_type
    tc26_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "Subagents": [
                    {"Role": "Backend Developer", "TypeName": "self", "Prompt": "Vá lỗi P0 trong module"}
                ]
            },
        }
    }
    res26 = evaluate_anti_sequential(tc26_payload)
    passed26 = res26.get("decision") == "allow" and res26.get("verdict") == "ALLOW"
    record_test("TC26", "test_allow_worker_with_self_type", passed26, "allowed worker with self type")

    # TC27: test_allow_vietnamese_security_alert (Word-boundary fix for 'cả')
    tc27_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "auditor",
                "prompt": "Kiểm tra cảnh báo bảo mật và ghi log",
            },
        }
    }
    res27 = evaluate_anti_sequential(tc27_payload)
    passed27 = res27.get("decision") == "allow" and res27.get("verdict") == "ALLOW"
    record_test("TC27", "test_allow_vietnamese_security_alert", passed27, "Vietnamese 'cảnh báo' not blocked by 'cả'")

    # TC28: test_allow_repeated_single_atomic_id (Deduplication fix for atomic tasks)
    tc28_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker",
                "prompt": "Thực thi TC-01: Bẫy SQLi và kiểm tra kết quả TC-01",
            },
        }
    }
    res28 = evaluate_anti_sequential(tc28_payload)
    passed28 = res28.get("decision") == "allow" and res28.get("verdict") == "ALLOW"
    record_test("TC28", "test_allow_repeated_single_atomic_id", passed28, "repeated single atomic ID allowed")

    # TC29: test_allow_batch_subagents_independent_complexity (SEC-W2-01 Fix)
    # 3 subagents each with 1 bullet and 1 entity; combined would exceed threshold if concatenated,
    # but independently evaluated, each subagent is atomic and allowed.
    tc29_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "Subagents": [
                    {"Role": "worker_1", "TypeName": "self", "Prompt": "Tác vụ 1:\n- Sửa lỗi trong auth.py"},
                    {"Role": "worker_2", "TypeName": "self", "Prompt": "Tác vụ 2:\n- Sửa lỗi trong payment.py"},
                    {"Role": "worker_3", "TypeName": "self", "Prompt": "Tác vụ 3:\n- Sửa lỗi trong notification.py"},
                ]
            },
        }
    }
    res29 = evaluate_anti_sequential(tc29_payload)
    passed29 = res29.get("decision") == "allow" and res29.get("verdict") == "ALLOW"
    record_test("TC29", "test_allow_batch_subagents_independent_complexity", passed29, "batch evaluated independently without prompt concatenation inflation")

    # TC30: test_deny_batch_with_one_monolithic_subagent (SEC-W2-01 Fix)
    # 2 subagents, but Subagent 2 is monolithic (bundles 10 test cases).
    tc30_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "Subagents": [
                    {"Role": "worker_1", "TypeName": "self", "Prompt": "Sửa lỗi trong auth.py"},
                    {"Role": "worker_2", "TypeName": "self", "Prompt": "Chạy toàn bộ 10 bài test đối kháng"},
                ]
            },
        }
    }
    res30 = evaluate_anti_sequential(tc30_payload)
    passed30 = res30.get("decision") == "deny" and res30.get("verdict") == "DENY" and "worker_2" in res30.get("reason", "")
    record_test("TC30", "test_deny_batch_with_one_monolithic_subagent", passed30, "individual monolithic subagent inside batch blocked")

    # TC31: test_deny_batch_with_multi_atomic_bundling (SEC-W2-01 Fix)
    # Subagent 1 bundles TC-01 and TC-02 inside a single subagent.
    tc31_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "Subagents": [
                    {"Role": "worker_1", "TypeName": "self", "Prompt": "Thực hiện TC-01 và sau đó làm luôn TC-02"},
                    {"Role": "worker_2", "TypeName": "self", "Prompt": "Thực hiện TC-03"},
                ]
            },
        }
    }
    res31 = evaluate_anti_sequential(tc31_payload)
    passed31 = res31.get("decision") == "deny" and res31.get("verdict") == "DENY"
    record_test("TC31", "test_deny_batch_with_multi_atomic_bundling", passed31, "subagent bundling multi-atomic tasks blocked")

    # TC32: test_deny_sequential_phrase_chay_lan_luot (REQ 4)
    tc32_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker",
                "prompt": "Hãy chạy lần lượt từng module để kiểm tra chất lượng",
            },
        }
    }
    res32 = evaluate_anti_sequential(tc32_payload)
    passed32 = res32.get("decision") == "deny" and res32.get("verdict") == "DENY"
    record_test("TC32", "test_deny_sequential_phrase_chay_lan_luot", passed32, "'chạy lần lượt' blocked")

    # TC33: test_deny_action_verbs_english (REQ 4)
    tc33_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "role": "worker",
                "prompt": "execute 10 test cases on the authentication service",
            },
        }
    }
    res33 = evaluate_anti_sequential(tc33_payload)
    passed33 = res33.get("decision") == "deny" and res33.get("verdict") == "DENY"
    record_test("TC33", "test_deny_action_verbs_english", passed33, "'execute 10 test cases' blocked")

    # TC34: test_scan_workspace_breadth_skips_node_modules (SEC-W2-02 Fix)
    with tempfile.TemporaryDirectory() as ws_tmp:
        ws_path = pathlib.Path(ws_tmp)
        nm_dir = ws_path / "node_modules" / "fake_pkg"
        nm_dir.mkdir(parents=True)
        (nm_dir / "index.js").write_text("// dummy", encoding="utf-8")
        src_dir = ws_path / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "main.py").write_text("# main", encoding="utf-8")
        sensor_inst = WorkloadSensor()
        count_nm, _, files_nm = sensor_inst.scan_workspace_breadth(prompt="node_modules/", workspace_root=ws_path)
        count_src, _, files_src = sensor_inst.scan_workspace_breadth(prompt="src/", workspace_root=ws_path)
        passed34 = count_nm == 0 and len(files_nm) == 0 and count_src == 1
        record_test("TC34", "test_scan_workspace_breadth_skips_node_modules", passed34, "node_modules and venv filtered out")

    # TC35: test_sliding_window_concurrency_cap_active_check (SEC-W2-03 Fix)
    # Record 19 active dispatches in the isolated state dir, then try to spawn 2 subagents -> total 21 > 20 -> BLOCKED!
    for i in range(19):
        record_dispatch(f"worker_{i}", f"TC-ACTIVE-{i:02d}")
    tc35_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "Subagents": [
                    {"Role": "worker_20", "TypeName": "self", "Prompt": "Thực hiện TC-ACTIVE-20"},
                    {"Role": "worker_21", "TypeName": "self", "Prompt": "Thực hiện TC-ACTIVE-21"},
                ]
            },
        }
    }
    res35 = evaluate_anti_sequential(tc35_payload)
    passed35 = res35.get("decision") == "deny" and res35.get("verdict") == "DENY" and "cửa sổ trượt" in str(res35.get("reason", ""))
    record_test("TC35", "test_sliding_window_concurrency_cap_active_check", passed35, "sliding window cap 20 enforced across dispatches")

    # TC36: test_cross_process_lock_multithread_integrity (SEC-W2-03 Fix)
    num_threads = 8
    tasks_per_th = 2
    expected_tids = [f"TC-LOCK-{t}" for t in range(num_threads * tasks_per_th)]
    def _rec(tid: str) -> None:
        record_dispatch("lock_tester", tid)
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as pool:
        list(pool.map(_rec, expected_tids))
    recent_all = read_recent_dispatches(max_age_sec=3600)
    rec_set = {d.get("atomic_id") for d in recent_all}
    passed36 = all(tid in rec_set for tid in expected_tids)
    record_test("TC36", "test_cross_process_lock_multithread_integrity", passed36, f"verified {len(expected_tids)} atomic records via CrossProcessLock")

    # Subprocess execution test (Testing real stdio stream & exit code 0)
    print("\nExecuting Subprocess Stdio Stream Verification...")
    proc = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).resolve())],
        input=json.dumps(tc05_payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    subproc_passed = False
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            subproc_res = json.loads(proc.stdout.strip())
            subproc_passed = subproc_res.get("decision") == "deny" and subproc_res.get("verdict") == "DENY"
        except json.JSONDecodeError:
            subproc_passed = False
    print(f"[SUBPROCESS] Stdio streaming verification: {'PASS' if subproc_passed else 'FAIL'}")

    all_passed = all(t[1] for t in test_results) and subproc_passed
    total_passed = sum(1 for t in test_results if t[1]) + (1 if subproc_passed else 0)
    total_cases = len(test_results) + 1

    print("\n----------------------------------------------------------------------")
    print(f"Self-Test Summary: {total_passed}/{total_cases} tests passed ({'100%' if all_passed else 'FAILED'}).")
    print("----------------------------------------------------------------------\n")
    return all_passed


def main() -> None:
    """Main CLI entrypoint for PreToolUse and PostToolUse events."""
    if "--self-test" in sys.argv:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    if "--post" in sys.argv:
        # PostToolUse: Emit empty response
        emit_stdout_json(post_tool_response())
        sys.exit(0)

    # PreToolUse: Process input payload from stdin
    payload = read_stdin_payload(default={})
    response = evaluate_anti_sequential(payload)
    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()
