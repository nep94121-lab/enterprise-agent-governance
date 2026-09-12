#!/usr/bin/env python3
"""Action Loop Detector Hook (PreToolUse) for Enterprise Multi-Agent Governance System.

Detects and breaks infinite action loops in autonomous subagents:
1. Intercepts PreToolUse for all monitored tools.
2. Computes a deterministic SHA256 hash of (tool_name + normalized tool_args).
3. Maintains a sliding window of the last 10 actions in a persistent cache.
4. If an identical action is repeated >= 3 times consecutively (or configurable threshold):
   -> HARD DENY with "Infinite Action Loop Detected" to prevent token and compute exhaustion.
5. Thread-safe & process-safe atomic state persistence.
6. Comprehensive `--self-test` suite exiting with code 0 on 100% pass.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import random
import re
import sys
import tempfile
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

# Ensure local hook libraries are importable
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
    log_diagnostic,
    pre_tool_response,
    read_stdin_payload,
)

DEFAULT_MAX_HISTORY = 10
DEFAULT_LOOP_THRESHOLD = 3


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


def get_cache_dir() -> pathlib.Path:
    """Resolve directory for action loop history cache."""
    override = os.environ.get("ACTION_LOOP_CACHE_DIR")
    if override:
        path = pathlib.Path(override)
    else:
        path = pathlib.Path.home() / ".gemini" / "config" / "enterprise-hooks" / ".action_loop_cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_partition_key(session_id: str = "", workspace_id: str = "") -> str:
    """Generate sanitized partition key to avoid cross-session contamination (Mục 26)."""
    sid = (
        session_id
        or os.environ.get("ACTION_LOOP_SESSION_ID")
        or os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
        or os.environ.get("CONVERSATION_ID")
        or os.environ.get("GEMINI_SESSION_ID")
        or ""
    )
    if sid and str(sid).strip():
        return re.sub(r"[^\w\-]", "_", str(sid).strip())[:64]

    # Fallback: partition by workspace root path hash
    ws = workspace_id or str(pathlib.Path.cwd().resolve())
    ws_hash = hashlib.sha256(ws.encode("utf-8")).hexdigest()[:16]
    return f"ws_{ws_hash}"


def get_cache_file(
    cache_dir: pathlib.Path | None = None,
    session_id: str = "",
    workspace_id: str = "",
) -> pathlib.Path:
    """Resolve partitioned cache file path (Mục 26)."""
    override_file = os.environ.get("ACTION_LOOP_CACHE_FILE")
    if override_file:
        return pathlib.Path(override_file)
    cd = cache_dir or get_cache_dir()
    part = get_partition_key(session_id=session_id, workspace_id=workspace_id)
    return cd / f"action_history_{part}.json"


def normalize_value(val: Any) -> Any:
    """Recursively normalize data structure for deterministic JSON serialization."""
    if isinstance(val, dict):
        return {str(k): normalize_value(v) for k, v in sorted(val.items())}
    if isinstance(val, (list, tuple)):
        return [normalize_value(x) for x in val]
    if isinstance(val, (int, float, bool)) or val is None:
        return val
    return str(val).strip()


VOLATILE_ACTION_KEYS: frozenset[str] = frozenset({
    "toolaction",
    "toolsummary",
    "timestamp",
    "time",
    "request_id",
    "requestid",
    "nonce",
    "step_index",
    "stepindex",
})


def compute_action_hash(tool_name: str, tool_args: Any) -> tuple[str, str]:
    """Compute deterministic SHA256 digest of tool invocation.

    Returns (sha256_hex, compact_args_summary).
    """
    normalized_name = (tool_name or "").strip().lower()
    if isinstance(tool_args, dict):
        filtered_args = {
            k: v for k, v in tool_args.items()
            if str(k).lower().strip() not in VOLATILE_ACTION_KEYS
        }
    else:
        filtered_args = tool_args
    normalized_args = normalize_value(filtered_args)
    try:
        serialized_args = json.dumps(
            normalized_args,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        )
    except Exception:
        serialized_args = str(normalized_args)

    raw_signature = f"{normalized_name}::{serialized_args}".encode("utf-8")
    digest = hashlib.sha256(raw_signature).hexdigest()
    summary = serialized_args[:120]
    return digest, summary


class ActionLoopDetector:
    """Tracks action history and intercepts consecutive identical actions with IPC locking."""

    def __init__(
        self,
        cache_file: pathlib.Path | None = None,
        max_history: int = DEFAULT_MAX_HISTORY,
        threshold: int = DEFAULT_LOOP_THRESHOLD,
        session_id: str = "",
        workspace_id: str = "",
    ) -> None:
        self.cache_file = cache_file or get_cache_file(session_id=session_id, workspace_id=workspace_id)
        self.lock_file = self.cache_file.with_suffix(".lock")
        self.max_history = max_history
        self.threshold = threshold

    def _load_cache_unlocked(self) -> dict[str, Any]:
        """Load history state from disk without acquiring lock (assumes lock held)."""
        if self.cache_file.is_file():
            try:
                data = json.loads(self.cache_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
            except Exception as exc:
                log_diagnostic(f"Error loading action history cache: {exc}")
        return {
            "version": "1.0",
            "consecutive_count": 0,
            "current_hash": "",
            "history": [],
            "partitions": {},
        }

    def load_cache(self) -> dict[str, Any]:
        """Load history state from disk under cross-process lock (Mục 25)."""
        with CrossProcessLock(self.lock_file, timeout=10.0):
            return self._load_cache_unlocked()

    def _save_cache_unlocked(self, state: dict[str, Any]) -> None:
        """Persist state atomically to disk with unique temp file without acquiring lock."""
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        # Unique temp file name with PID, time_ns, and random entropy (Mục 24)
        temp_file = (
            self.cache_file.parent
            / f"{self.cache_file.name}.tmp.{os.getpid()}.{time.time_ns()}.{random.randint(1000, 9999)}"
        )
        try:
            content = json.dumps(state, indent=2)
            temp_file.write_text(content, encoding="utf-8")
            atomic_replace_file(temp_file, self.cache_file)
        except Exception as exc:
            log_diagnostic(f"Failed to persist action history cache: {exc}")
        finally:
            if temp_file.exists():
                try:
                    temp_file.unlink(missing_ok=True)
                except OSError:
                    pass

    def save_cache(self, state: dict[str, Any]) -> None:
        """Persist state atomically to disk under cross-process lock with unique temp file (Mục 24, 25)."""
        with CrossProcessLock(self.lock_file, timeout=10.0):
            self._save_cache_unlocked(state)

    def evaluate_action(
        self,
        tool_name: str,
        tool_args: Any,
        caller_id: str = "",
    ) -> tuple[str, str, int]:
        """Evaluate action for infinite repetition loop with atomic read-modify-write (Mục 25, 26).

        Returns (decision, reason, consecutive_count).
        """
        if not tool_name:
            return "allow", "Empty tool name.", 0

        action_hash, args_summary = compute_action_hash(tool_name, tool_args)
        caller_key = str(caller_id or "default").strip()

        # Atomic critical section across processes
        with CrossProcessLock(self.lock_file, timeout=10.0):
            state = self._load_cache_unlocked()

            # Partition tracking per caller_id to prevent multi-agent interleaving contamination (Mục 26)
            partitions = state.setdefault("partitions", {})
            if not isinstance(partitions, dict):
                partitions = {}
                state["partitions"] = partitions

            caller_state = partitions.setdefault(
                caller_key,
                {
                    "current_hash": "",
                    "consecutive_count": 0,
                },
            )

            last_hash = caller_state.get("current_hash", "")
            consecutive_count = caller_state.get("consecutive_count", 0)

            if action_hash == last_hash and action_hash != "":
                consecutive_count += 1
            else:
                consecutive_count = 1
                last_hash = action_hash

            caller_state["consecutive_count"] = consecutive_count
            caller_state["current_hash"] = action_hash

            # Maintain global / primary fields for backwards compatibility
            state["consecutive_count"] = consecutive_count
            state["current_hash"] = action_hash

            history = state.get("history", [])
            if not isinstance(history, list):
                history = []

            history.append({
                "timestamp": time.time(),
                "tool_name": tool_name,
                "hash": action_hash,
                "summary": args_summary,
                "caller": caller_id,
                "repetition": consecutive_count,
            })

            # Trim to sliding window
            if len(history) > self.max_history:
                history = history[-self.max_history:]

            state["history"] = history
            self._save_cache_unlocked(state)

            if consecutive_count >= self.threshold:
                msg = (
                    f"Infinite Action Loop Detected: Tool '{tool_name}' with identical arguments "
                    f"was executed {consecutive_count} consecutive times (threshold={self.threshold}). "
                    f"Action blocked by action_loop_detector hook to prevent autonomous agent resource exhaustion."
                )
                log_diagnostic(f"LOOP INTERVENTION: {msg}")
                return "deny", msg, consecutive_count

            return "allow", f"Action verified (repetition {consecutive_count}/{self.threshold}).", consecutive_count


def evaluate_action_loop(payload: dict[str, Any]) -> dict[str, Any]:
    """Hook entry point for PreToolUse."""
    tool_call = get_tool_call(payload)
    if not isinstance(tool_call, dict):
        return pre_tool_response("allow", "No valid tool call in payload.")

    tool_name = tool_call.get("name", "")
    args = get_tool_args(tool_call)

    # Detect session and workspace identity (Mục 26)
    session_id = (
        payload.get("conversationId")
        or payload.get("conversation_id")
        or payload.get("session_id")
        or payload.get("sessionId")
        or os.environ.get("ACTION_LOOP_SESSION_ID")
        or os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
        or os.environ.get("CONVERSATION_ID")
        or ""
    )
    workspace_paths = payload.get("workspacePaths") or payload.get("workspaces") or []
    workspace_id = workspace_paths[0] if isinstance(workspace_paths, list) and workspace_paths else ""

    caller_id = payload.get("caller_role") or payload.get("worker_id") or payload.get("caller_id") or ""

    threshold = int(os.environ.get("ACTION_LOOP_THRESHOLD", DEFAULT_LOOP_THRESHOLD))
    detector = ActionLoopDetector(
        threshold=threshold,
        session_id=str(session_id),
        workspace_id=str(workspace_id),
    )
    decision, reason, _ = detector.evaluate_action(tool_name, args, caller_id=str(caller_id))

    return pre_tool_response(decision, reason)


def run_self_test() -> bool:
    """Comprehensive self-test suite for Action Loop Detector."""
    print("=== [SELF-TEST] Action Loop Detector ===")
    all_passed = True

    with tempfile.TemporaryDirectory() as tmpdir:
        test_cache = pathlib.Path(tmpdir) / "test_history.json"
        detector = ActionLoopDetector(cache_file=test_cache, max_history=10, threshold=3)

        tool_a = "view_file"
        args_a = {"AbsolutePath": "C:/project/test.py"}

        # Iteration 1: First call -> allow
        dec1, reason1, count1 = detector.evaluate_action(tool_a, args_a)
        if dec1 == "allow" and count1 == 1:
            print("PASS: Test 1 - First invocation allowed (repetition=1).")
        else:
            print(f"FAIL: Test 1 - Expected allow/1, got {dec1}/{count1}")
            all_passed = False

        # Iteration 2: Second identical call -> allow (repetition=2)
        dec2, reason2, count2 = detector.evaluate_action(tool_a, args_a)
        if dec2 == "allow" and count2 == 2:
            print("PASS: Test 2 - Second identical invocation allowed (repetition=2).")
        else:
            print(f"FAIL: Test 2 - Expected allow/2, got {dec2}/{count2}")
            all_passed = False

        # Iteration 3: Third identical call -> DENY (repetition=3 >= threshold=3)
        dec3, reason3, count3 = detector.evaluate_action(tool_a, args_a)
        if dec3 == "deny" and count3 == 3 and "Infinite Action Loop Detected" in reason3:
            print("PASS: Test 3 - Third identical invocation blocked with HARD DENY.")
        else:
            print(f"FAIL: Test 3 - Expected deny/3, got {dec3}/{count3}, reason: {reason3}")
            all_passed = False

        # Iteration 4: Different action Tool B -> reset consecutive count, allow
        tool_b = "run_command"
        args_b = {"CommandLine": "pytest"}
        dec4, reason4, count4 = detector.evaluate_action(tool_b, args_b)
        if dec4 == "allow" and count4 == 1:
            print("PASS: Test 4 - Different tool invocation reset repetition to 1 and allowed.")
        else:
            print(f"FAIL: Test 4 - Expected allow/1, got {dec4}/{count4}")
            all_passed = False

        # Iteration 5: Sliding window max history trimming
        for i in range(15):
            detector.evaluate_action(f"tool_{i}", {"index": i})
        state = detector.load_cache()
        history_len = len(state.get("history", []))
        if history_len == 10:
            print(f"PASS: Test 5 - Sliding window correctly capped at 10 items (got {history_len}).")
        else:
            print(f"FAIL: Test 5 - History length expected 10, got {history_len}")
            all_passed = False

        # Iteration 6: Custom threshold verification
        custom_cache = pathlib.Path(tmpdir) / "custom_threshold.json"
        custom_det = ActionLoopDetector(cache_file=custom_cache, threshold=2)
        custom_det.evaluate_action("test_tool", {"a": 1})
        c_dec2, _, c_count2 = custom_det.evaluate_action("test_tool", {"a": 1})
        if c_dec2 == "deny" and c_count2 == 2:
            print("PASS: Test 6 - Custom threshold (2) correctly triggered denial on 2nd repeat.")
        else:
            print(f"FAIL: Test 6 - Expected deny at count 2, got {c_dec2}/{c_count2}")
            all_passed = False

        # Test 7: Full payload integration via evaluate_action_loop
        os.environ["ACTION_LOOP_CACHE_FILE"] = str(pathlib.Path(tmpdir) / "integration.json")
        try:
            payload = {
                "toolCall": {
                    "name": "read_url_content",
                    "args": {"Url": "https://example.com"},
                }
            }
            res = evaluate_action_loop(payload)
            if res.get("decision") == "allow":
                print("PASS: Test 7 - Full PreToolUse integration payload evaluated successfully.")
            else:
                print(f"FAIL: Test 7 - Unexpected PreToolUse integration response: {res}")
                all_passed = False
        finally:
            os.environ.pop("ACTION_LOOP_CACHE_FILE", None)

        # Test 8: Unique temp file & 0 leftover .tmp files (Mục 24)
        tmp_check_cache = pathlib.Path(tmpdir) / "tmp_check" / "history.json"
        tmp_det = ActionLoopDetector(cache_file=tmp_check_cache)
        for idx in range(5):
            tmp_det.evaluate_action("test_tool", {"step": idx})
        leftover_tmps = list(tmp_check_cache.parent.glob("*.tmp*"))
        if len(leftover_tmps) == 0 and tmp_check_cache.is_file():
            print("PASS: Test 8 - Unique temp file atomic replace succeeded with 0 leftover .tmp files.")
        else:
            print(f"FAIL: Test 8 - Leftover tmp files found: {leftover_tmps}")
            all_passed = False

        # Test 9: Concurrent multithreaded atomic read-modify-write under CrossProcessLock (Mục 25)
        import concurrent.futures

        concurrent_cache = pathlib.Path(tmpdir) / "concurrent" / "history.json"
        conc_det = ActionLoopDetector(cache_file=concurrent_cache, max_history=100)

        def worker_task(worker_id: int):
            for i in range(10):
                conc_det.evaluate_action(f"tool_worker_{worker_id}", {"i": i}, caller_id=f"worker_{worker_id}")
                time.sleep(0.001)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(worker_task, wid) for wid in range(5)]
            for f in futures:
                f.result()

        conc_state = conc_det.load_cache()
        total_history = len(conc_state.get("history", []))
        if total_history == 50:
            print("PASS: Test 9 - CrossProcessLock preserved all 50 concurrent records without lost updates.")
        else:
            print(f"FAIL: Test 9 - Expected 50 records under lock, got {total_history}")
            all_passed = False

        # Test 10: Session and Worker partitioning isolation (Mục 26)
        session_a_file = get_cache_file(cache_dir=pathlib.Path(tmpdir), session_id="session_alpha")
        session_b_file = get_cache_file(cache_dir=pathlib.Path(tmpdir), session_id="session_beta")
        if session_a_file != session_b_file and "session_alpha" in str(session_a_file):
            print("PASS: Test 10a - Cache files partitioned by session ID correctly.")
        else:
            print(f"FAIL: Test 10a - Session cache files not partitioned: {session_a_file} vs {session_b_file}")
            all_passed = False

        # Test 10b: Multiple workers in same session do not corrupt each other's consecutive repetition
        multi_worker_cache = pathlib.Path(tmpdir) / "multi_worker.json"
        mw_det = ActionLoopDetector(cache_file=multi_worker_cache, threshold=3)
        # Worker 1: 2 identical calls
        mw_det.evaluate_action("cmd_a", {"x": 1}, caller_id="worker_1")
        _, _, c1 = mw_det.evaluate_action("cmd_a", {"x": 1}, caller_id="worker_1")
        # Worker 2: calls a different tool (should NOT reset worker 1)
        mw_det.evaluate_action("cmd_b", {"y": 2}, caller_id="worker_2")
        # Worker 1: 3rd identical call (should reach 3 and DENY)
        dec_w1, _, c1_3 = mw_det.evaluate_action("cmd_a", {"x": 1}, caller_id="worker_1")
        if c1 == 2 and c1_3 == 3 and dec_w1 == "deny":
            print("PASS: Test 10b - Worker partitioning isolated repetition counters between interleaved workers.")
        else:
            print(f"FAIL: Test 10b - Expected deny/3 for worker_1, got {dec_w1}/{c1_3}")
            all_passed = False

    print(f"=== [RESULT] Action Loop Detector: {'ALL PASS' if all_passed else 'FAIL'} ===")
    return all_passed


def main() -> None:
    if "--self-test" in sys.argv:
        success = run_self_test()
        sys.exit(0 if success else 1)

    payload = read_stdin_payload(default={})
    response = evaluate_action_loop(payload)
    emit_stdout_json(response)


if __name__ == "__main__":
    main()
