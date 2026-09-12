#!/usr/bin/env python3
"""Post-Invocation Trajectory Guard Hook (PostInvocation) for Enterprise Multi-Agent Governance System.

Audits invocation trajectory and tool execution progression to prevent runaway executions,
infinite retry loops, goal drift, and redundant operations. Dynamically sources thresholds
from hook_utils.config_loader (Zero-Config Resilience) and injects targeted intervention
steps (injectSteps) when repetitive tool loops or critical budget exhaustion are detected.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import io
import json
import os
import pathlib
import random
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

# Ensure local hook library and hook_utils are importable
HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).parent.resolve()
REPO_ROOT = HOOKS_SCRIPTS_DIR.parent.resolve()
for path_dir in (str(HOOKS_SCRIPTS_DIR), str(REPO_ROOT)):
    if path_dir not in sys.path:
        sys.path.insert(0, path_dir)

from common_hook_lib import (  # noqa: E402
    emit_stdout_json,
    log_diagnostic,
    post_invocation_response,
    read_stdin_payload,
)

# Dynamic Configuration Loader Integration
try:
    from hook_utils.config_loader import (  # noqa: E402
        get_dynamic_limits,
        get_trajectory_guard_config,
    )
except ImportError:
    try:
        from config_loader import get_dynamic_limits, get_trajectory_guard_config  # type: ignore # noqa: E402
    except ImportError:
        get_dynamic_limits = None
        get_trajectory_guard_config = None

# Default Fallback Parameters (Zero-Config Resilience - No Hardcoded Magic Numbers)
DEFAULT_TRAJECTORY_CONFIG: dict[str, Any] = {
    "enabled": True,
    "high_step_warning_threshold": 35,
    "critical_step_threshold": 50,
    "consecutive_tool_loop_threshold": 3,
    "ping_pong_loop_threshold": 3,
    "repeated_call_alert_enabled": True,
    "inject_warning_on_loop": True,
    "inject_warning_on_critical_steps": True,
    "max_history_window": 20,
    "state_storage_dir": ".trajectory_guard",
    "state_file_name": "trajectory_state.json",
}


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


IGNORED_ARG_KEYS: set[str] = {
    "timestamp",
    "call_id",
    "callid",
    "request_id",
    "requestid",
    "_nonce",
    "toolaction",
    "toolsummary",
    "tool_action",
    "tool_summary",
}


def resolve_trajectory_config() -> dict[str, Any]:
    """Resolve dynamic configuration merging hook_utils config_loader, dynamic_limits.json and env overrides."""
    config: dict[str, Any] = copy.deepcopy(DEFAULT_TRAJECTORY_CONFIG)

    if callable(get_trajectory_guard_config):
        try:
            loaded = get_trajectory_guard_config()
            if isinstance(loaded, dict):
                config.update(loaded)
        except Exception as exc:
            log_diagnostic(f"Warning: Failed to load trajectory_guard config via hook_utils: {exc}")
    elif callable(get_dynamic_limits):
        try:
            limits = get_dynamic_limits()
            if isinstance(limits, dict) and "trajectory_guard" in limits:
                config.update(limits["trajectory_guard"])
        except Exception as exc:
            log_diagnostic(f"Warning: Failed to load dynamic_limits: {exc}")

    # Environment variable overrides (Prioritized runtime control)
    env_enabled = os.environ.get("TRAJECTORY_GUARD_ENABLED")
    if env_enabled is not None:
        config["enabled"] = env_enabled.strip().lower() in ("true", "1", "yes", "on")

    env_warn = os.environ.get("TRAJECTORY_HIGH_STEP_WARNING_THRESHOLD")
    if env_warn is not None:
        try:
            config["high_step_warning_threshold"] = int(env_warn)
        except ValueError:
            pass

    env_crit = os.environ.get("TRAJECTORY_CRITICAL_STEP_THRESHOLD")
    if env_crit is not None:
        try:
            config["critical_step_threshold"] = int(env_crit)
        except ValueError:
            pass

    env_loop = os.environ.get("TRAJECTORY_CONSECUTIVE_LOOP_THRESHOLD")
    if env_loop is not None:
        try:
            config["consecutive_tool_loop_threshold"] = int(env_loop)
        except ValueError:
            pass

    env_pingpong = os.environ.get("TRAJECTORY_PING_PONG_LOOP_THRESHOLD")
    if env_pingpong is not None:
        try:
            config["ping_pong_loop_threshold"] = int(env_pingpong)
        except ValueError:
            pass

    return config


def get_state_dir(config: dict[str, Any]) -> pathlib.Path:
    """Resolve state directory for conversation trajectory tracking."""
    env_dir = os.environ.get("TRAJECTORY_GUARD_STATE_DIR")
    if env_dir:
        state_dir = pathlib.Path(env_dir).resolve()
    else:
        rel_dir = config.get("state_storage_dir", ".trajectory_guard")
        state_dir = (REPO_ROOT / rel_dir).resolve()

    try:
        state_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log_diagnostic(f"Failed to create trajectory state dir {state_dir}: {exc}")
    return state_dir


def _parse_tool_calls_from_transcript(transcript_path: pathlib.Path, max_lines: int = 30) -> list[dict[str, Any]]:
    """Parse last N lines of transcript.jsonl for tool calls."""
    extracted: list[dict[str, Any]] = []
    try:
        with open(transcript_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        for line in lines[-max_lines:]:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                if isinstance(data, dict):
                    t_calls = data.get("tool_calls") or data.get("toolCalls")
                    if isinstance(t_calls, list):
                        for tc in t_calls:
                            if isinstance(tc, dict):
                                extracted.append(tc)
            except json.JSONDecodeError:
                continue
    except OSError:
        pass
    return extracted


def extract_tool_calls_from_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract ordered tool calls from payload, steps, or trajectory objects."""
    tool_calls: list[dict[str, Any]] = []

    # 1. Direct toolCalls list in payload
    raw_tc = payload.get("toolCalls") or payload.get("tool_calls")
    if isinstance(raw_tc, list):
        for item in raw_tc:
            if isinstance(item, dict):
                tool_calls.append(item)

    # 2. Single toolCall in payload
    single_tc = payload.get("toolCall")
    if isinstance(single_tc, dict) and single_tc:
        tool_calls.append(single_tc)

    # 3. Steps list in payload
    steps = payload.get("steps") or payload.get("trajectory") or payload.get("history")
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, dict):
                continue
            step_tc = step.get("tool_calls") or step.get("toolCalls")
            if isinstance(step_tc, list):
                for item in step_tc:
                    if isinstance(item, dict):
                        tool_calls.append(item)
            elif isinstance(step.get("toolCall"), dict):
                tool_calls.append(step["toolCall"])
            elif step.get("type") in ("TOOL_USE", "tool_call", "action"):
                tool_calls.append(step)

    # 4. Optional transcript.jsonl lookup if conversationId is available
    if not tool_calls:
        conv_id = (
            payload.get("conversationId")
            or payload.get("conversation_id")
            or os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
        )
        if conv_id and isinstance(conv_id, str):
            transcript_path = payload.get("transcriptPath")
            if not transcript_path:
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
                if candidate.exists():
                    transcript_path = candidate
            if transcript_path:
                try:
                    t_path = pathlib.Path(transcript_path).resolve()
                    if t_path.is_file():
                        tool_calls = _parse_tool_calls_from_transcript(t_path, max_lines=30)
                except Exception as exc:
                    log_diagnostic(f"Could not read transcript {transcript_path}: {exc}")

    return tool_calls


def compute_tool_signature(tc: dict[str, Any]) -> tuple[str, str, str]:
    """Compute normalized (tool_name, args_hash, args_preview) for repetition detection.

    Adheres to §1 PII & Secrets rules: avoids dumping full raw content, masks secrets.
    """
    name = (
        tc.get("name")
        or tc.get("toolName")
        or tc.get("function", {}).get("name")
        or tc.get("tool")
        or "unknown_tool"
    )
    name = str(name).strip()

    args = tc.get("args") or tc.get("arguments") or tc.get("parameters") or {}
    if isinstance(args, str):
        try:
            parsed_args = json.loads(args)
            if isinstance(parsed_args, dict):
                args = parsed_args
            else:
                args = {"_raw_args": args}
        except (json.JSONDecodeError, ValueError):
            args = {"_raw_args": args}
    elif not isinstance(args, dict):
        args = {"_raw_args": str(args)}

    filtered_args = {}
    for k, v in args.items():
        if str(k).strip().lower() in IGNORED_ARG_KEYS:
            continue
        if isinstance(v, str) and len(v) > 200:
            filtered_args[k] = v[:200] + "...[TRUNCATED]"
        else:
            filtered_args[k] = v

    try:
        canonical_args = json.dumps(filtered_args, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        canonical_args = str(filtered_args)

    args_hash = hashlib.sha256(canonical_args.encode("utf-8")).hexdigest()[:16]
    preview = canonical_args[:80] + ("..." if len(canonical_args) > 80 else "")
    return name, args_hash, preview


@dataclasses.dataclass
class LoopDetectionResult:
    is_loop: bool = False
    loop_type: str = ""
    tool_name: str = ""
    loop_count: int = 0
    args_preview: str = ""
    message: str = ""


def detect_tool_execution_loop(
    tool_calls: list[dict[str, Any]],
    consecutive_threshold: int = 3,
    ping_pong_threshold: int = 3,
) -> LoopDetectionResult:
    """Analyze a sequence of tool calls for loops and repetitive patterns."""
    if not tool_calls or len(tool_calls) < consecutive_threshold:
        return LoopDetectionResult(is_loop=False)

    signatures = [compute_tool_signature(tc) for tc in tool_calls]

    # Check 1: Consecutive identical tool calls (Stalling Loop)
    last_name, last_hash, last_preview = signatures[-1]
    consecutive_count = 0
    for name, a_hash, _ in reversed(signatures):
        if name == last_name and a_hash == last_hash:
            consecutive_count += 1
        else:
            break

    if consecutive_count >= consecutive_threshold:
        return LoopDetectionResult(
            is_loop=True,
            loop_type="consecutive_identical",
            tool_name=last_name,
            loop_count=consecutive_count,
            args_preview=last_preview,
            message=(
                f"Phát hiện chuỗi gọi công cụ '{last_name}' lặp lại {consecutive_count} lần liên tiếp "
                f"với cùng tham số ({last_preview})."
            ),
        )

    # Check 2: Ping-pong alternating loop (A -> B -> A -> B -> A -> B)
    min_ping_pong_len = ping_pong_threshold * 2
    if len(signatures) >= min_ping_pong_len:
        recent = signatures[-min_ping_pong_len:]
        sig_a = recent[0][:2]  # (name, hash)
        sig_b = recent[1][:2]
        if sig_a != sig_b:
            is_alternating = True
            for i in range(len(recent)):
                expected = sig_a if i % 2 == 0 else sig_b
                if recent[i][:2] != expected:
                    is_alternating = False
                    break
            if is_alternating:
                return LoopDetectionResult(
                    is_loop=True,
                    loop_type="ping_pong_alternation",
                    tool_name=f"{sig_a[0]} <-> {sig_b[0]}",
                    loop_count=ping_pong_threshold,
                    args_preview="Mô hình con lắc luân phiên 2 công cụ",
                    message=(
                        f"Phát hiện mẫu lặp luân phiên con lắc giữa '{sig_a[0]}' và '{sig_b[0]}' "
                        f"{ping_pong_threshold} chu kỳ liên tiếp không tạo tiến triển."
                    ),
                )

    return LoopDetectionResult(is_loop=False)


def update_conversation_history(
    state_dir: pathlib.Path,
    conv_id: str,
    current_calls: list[dict[str, Any]],
    max_window: int = 20,
) -> list[dict[str, Any]]:
    """Persist and accumulate tool calls across invocations for the conversation under IPC lock (Mục 27, 28)."""
    safe_id = "".join(c for c in conv_id if c.isalnum() or c in ("-", "_")) or "default"
    state_file = state_dir / f"{safe_id}.json"
    lock_file = state_dir / f"{safe_id}.lock"

    # Cross-process lock prevents concurrent subagent race conditions (Mục 27)
    with CrossProcessLock(lock_file, timeout=10.0):
        history: list[dict[str, Any]] = []
        if state_file.exists():
            try:
                with open(state_file, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    history = data
            except (json.JSONDecodeError, OSError) as exc:
                log_diagnostic(f"Error reading trajectory state {state_file}: {exc}")
                history = []

        history.extend(current_calls)
        if len(history) > max_window:
            history = history[-max_window:]

        # Unique temporary filename with PID + time_ns + entropy to prevent collisions (Mục 28)
        state_dir.mkdir(parents=True, exist_ok=True)
        tmp_file = (
            state_dir
            / f"{safe_id}.tmp.{os.getpid()}.{time.time_ns()}.{random.randint(1000, 9999)}"
        )
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(history, f, ensure_ascii=False)
            atomic_replace_file(tmp_file, state_file)
        except OSError as exc:
            log_diagnostic(f"Failed to persist trajectory state for {conv_id}: {exc}")
        finally:
            if tmp_file.exists():
                try:
                    tmp_file.unlink(missing_ok=True)
                except OSError:
                    pass

    return history


def audit_trajectory(payload: dict) -> dict:
    """Audit invocation trajectory, step progression, and tool repetition loops."""
    if not isinstance(payload, dict):
        log_diagnostic(f"Warning: Payload is not a dict (type={type(payload).__name__}). Defaulting to empty.")
        payload = {}

    config = resolve_trajectory_config()
    if not config.get("enabled", True):
        log_diagnostic("Trajectory guard hook is disabled via configuration.")
        return post_invocation_response(inject_steps=[], termination_behavior="")

    high_step_warning_threshold = int(config.get("high_step_warning_threshold", 35))
    critical_step_threshold = int(config.get("critical_step_threshold", 50))
    consecutive_threshold = int(config.get("consecutive_tool_loop_threshold", 3))
    ping_pong_threshold = int(config.get("ping_pong_loop_threshold", 3))
    inject_warning_on_loop = bool(config.get("inject_warning_on_loop", True))
    inject_warning_on_critical = bool(config.get("inject_warning_on_critical_steps", True))

    raw_inv = payload.get("invocationNum", 0)
    try:
        invocation_num = int(raw_inv) if raw_inv is not None else 0
    except (ValueError, TypeError):
        log_diagnostic(f"Warning: Malformed 'invocationNum' ({raw_inv!r}). Defaulting to 0.")
        invocation_num = 0

    raw_steps = payload.get("initialNumSteps", 0)
    try:
        num_steps = int(raw_steps) if raw_steps is not None else 0
    except (ValueError, TypeError):
        log_diagnostic(f"Warning: Malformed 'initialNumSteps' ({raw_steps!r}). Defaulting to 0.")
        num_steps = 0

    # Diagnostic logging to stderr
    log_diagnostic(f"Post-invocation #{invocation_num} completed. Current step count: {num_steps}.")

    # Step threshold diagnostics
    if num_steps >= high_step_warning_threshold:
        log_diagnostic(
            f"⚠️ HIGH TRAJECTORY STEP WARNING: Step count reached {num_steps} (threshold: {high_step_warning_threshold}). "
            f"Review agent loop for potential redundant operations or stalled progress."
        )

    # Tool call extraction & loop analysis
    current_calls = extract_tool_calls_from_payload(payload)
    conv_id = (
        payload.get("conversationId")
        or payload.get("conversation_id")
        or os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
    )
    if conv_id and current_calls:
        state_dir = get_state_dir(config)
        all_calls = update_conversation_history(
            state_dir,
            str(conv_id),
            current_calls,
            max_window=config.get("max_history_window", 20),
        )
    else:
        all_calls = current_calls

    loop_result = detect_tool_execution_loop(
        all_calls,
        consecutive_threshold=consecutive_threshold,
        ping_pong_threshold=ping_pong_threshold,
    )

    inject_steps: list[dict[str, Any]] = []
    termination_behavior = ""

    # Mitigate detected loops (P0 Facade Fix)
    if loop_result.is_loop:
        log_diagnostic(
            f"🚨 TRAJECTORY LOOP DETECTED: {loop_result.message} (loop_count={loop_result.loop_count})"
        )
        if inject_warning_on_loop:
            intervention = {
                "ephemeralMessage": (
                    f"🚨 [TRAJECTORY GUARD INTERVENTION — LOOP DETECTED]\n"
                    f"{loop_result.message}\n"
                    f"Cảnh báo nguy cơ vòng lặp vô tận (Infinite Loop / Goal Drift).\n"
                    f"👉 YÊU CẦU BẮT BUỘC: Ngừng ngay việc gọi lặp lại công cụ này! Thay đổi chiến lược tiếp cận, "
                    f"kiểm tra nguyên nhân gốc rễ, hoặc báo cáo bế tắc kỹ thuật theo quy trình phân tầng."
                )
            }
            inject_steps.append(intervention)
        if loop_result.loop_count >= consecutive_threshold + 2:
            # Severe runaway loop: pause execution to prevent unbounded resource drain
            termination_behavior = "pause"

    # Step budget exhaustion mitigation
    elif num_steps >= critical_step_threshold and inject_warning_on_critical:
        log_diagnostic(
            f"⚠️ CRITICAL STEP BUDGET ALERT: Current step {num_steps} exceeded critical threshold {critical_step_threshold}."
        )
        intervention = {
            "ephemeralMessage": (
                f"⚠️ [TRAJECTORY GUARD BUDGET EXHAUSTION ALERT]\n"
                f"Số bước thực thi của tác vụ đã đạt mức tới hạn ({num_steps}/{critical_step_threshold}).\n"
                f"👉 YÊU CẦU: Khẩn trương tổng kết công việc, chạy kiểm thử xác nhận và hoàn tất nhiệm vụ "
                f"để tránh làm cạn kiệt ngân sách thực thi của hệ thống."
            )
        }
        inject_steps.append(intervention)

    return post_invocation_response(inject_steps=inject_steps, termination_behavior=termination_behavior)


def main() -> None:
    try:
        payload = read_stdin_payload(default={})
        response = audit_trajectory(payload)
        emit_stdout_json(response)
    except Exception as exc:
        import traceback

        error_detail = traceback.format_exc()
        sys.stderr.write(
            f"[HOOK_FATAL_ERROR] post_invocation_trajectory_guard.py gặp lỗi: {exc}\n{error_detail}\n"
        )
        sys.stderr.flush()
        # Fail-closed with safe recovery payload
        emit_stdout_json(post_invocation_response(inject_steps=[], termination_behavior=""))
        sys.exit(0)


if __name__ == "__main__":
    main()
