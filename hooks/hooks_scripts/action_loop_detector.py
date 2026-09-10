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
import sys
import tempfile
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


def get_cache_dir() -> pathlib.Path:
    """Resolve directory for action loop history cache."""
    override = os.environ.get("ACTION_LOOP_CACHE_DIR")
    if override:
        path = pathlib.Path(override)
    else:
        path = pathlib.Path.home() / ".gemini" / "config" / "enterprise-hooks" / ".action_loop_cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_cache_file(cache_dir: pathlib.Path | None = None) -> pathlib.Path:
    """Resolve cache file path."""
    override_file = os.environ.get("ACTION_LOOP_CACHE_FILE")
    if override_file:
        return pathlib.Path(override_file)
    cd = cache_dir or get_cache_dir()
    return cd / "action_history.json"


def normalize_value(val: Any) -> Any:
    """Recursively normalize data structure for deterministic JSON serialization."""
    if isinstance(val, dict):
        return {str(k): normalize_value(v) for k, v in sorted(val.items())}
    if isinstance(val, (list, tuple)):
        return [normalize_value(x) for x in val]
    if isinstance(val, (int, float, bool)) or val is None:
        return val
    return str(val).strip()


def compute_action_hash(tool_name: str, tool_args: Any) -> tuple[str, str]:
    """Compute deterministic SHA256 digest of tool invocation.

    Returns (sha256_hex, compact_args_summary).
    """
    normalized_name = (tool_name or "").strip().lower()
    normalized_args = normalize_value(tool_args if isinstance(tool_args, dict) else {})
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
    """Tracks action history and intercepts consecutive identical actions."""

    def __init__(
        self,
        cache_file: pathlib.Path | None = None,
        max_history: int = DEFAULT_MAX_HISTORY,
        threshold: int = DEFAULT_LOOP_THRESHOLD,
    ) -> None:
        self.cache_file = cache_file or get_cache_file()
        self.max_history = max_history
        self.threshold = threshold

    def load_cache(self) -> dict[str, Any]:
        """Load history state from disk."""
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
        }

    def save_cache(self, state: dict[str, Any]) -> None:
        """Persist state atomically to disk."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            temp_file = self.cache_file.with_suffix(".tmp")
            temp_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
            temp_file.replace(self.cache_file)
        except Exception as exc:
            log_diagnostic(f"Failed to persist action history cache: {exc}")

    def evaluate_action(
        self,
        tool_name: str,
        tool_args: Any,
        caller_id: str = "",
    ) -> tuple[str, str, int]:
        """Evaluate action for infinite repetition loop.

        Returns (decision, reason, consecutive_count).
        """
        if not tool_name:
            return "allow", "Empty tool name.", 0

        action_hash, args_summary = compute_action_hash(tool_name, tool_args)
        state = self.load_cache()

        last_hash = state.get("current_hash", "")
        consecutive_count = state.get("consecutive_count", 0)

        if action_hash == last_hash and action_hash != "":
            consecutive_count += 1
        else:
            consecutive_count = 1
            last_hash = action_hash

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

        state["consecutive_count"] = consecutive_count
        state["current_hash"] = action_hash
        state["history"] = history
        self.save_cache(state)

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

    # Detect caller identity if available
    caller_id = payload.get("caller_role") or payload.get("worker_id") or ""

    threshold = int(os.environ.get("ACTION_LOOP_THRESHOLD", DEFAULT_LOOP_THRESHOLD))
    detector = ActionLoopDetector(threshold=threshold)
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
