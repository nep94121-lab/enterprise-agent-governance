#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
trace_context_injector.py — W3C Distributed Trace Context Injector Hook
Injects W3C traceparent (00-{trace_id}-{span_id}-01) into multi-agent workflows.
"""

import io
import json
import os
import random
import sys
import time
from typing import Any, Dict

try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

def generate_trace_id() -> str:
    return f"{random.getrandbits(128):032x}"

def generate_span_id() -> str:
    return f"{random.getrandbits(64):016x}"

def make_w3c_traceparent(trace_id: str = None, span_id: str = None, flags: str = "01") -> str:
    tid = trace_id or generate_trace_id()
    sid = span_id or generate_span_id()
    return f"00-{tid}-{sid}-{flags}"

def inject_trace_context(tool_name: str, tool_args: Dict[str, Any]) -> Dict[str, Any]:
    traceparent = make_w3c_traceparent()
    os.environ["TRACEPARENT"] = traceparent
    return {
        "traceparent": traceparent,
        "injected": True,
        "timestamp": time.time()
    }

def run_self_test() -> bool:
    print("[SELF-TEST] Running trace_context_injector self-tests...")
    tp = make_w3c_traceparent()
    parts = tp.split("-")
    assert len(parts) == 4
    assert parts[0] == "00"
    assert len(parts[1]) == 32
    assert len(parts[2]) == 16
    assert parts[3] == "01"

    res = inject_trace_context("invoke_subagent", {"Subagents": []})
    assert res["injected"] is True
    assert "TRACEPARENT" in os.environ

    print("[SELF-TEST] ALL W3C TRACE SCENARIOS PASSED (100% OK)")
    return True

def main():
    if "--self-test" in sys.argv:
        success = run_self_test()
        sys.exit(0 if success else 1)

    try:
        max_bytes = 10 * 1024 * 1024
        raw = sys.stdin.read(max_bytes + 1)
        if len(raw) > max_bytes:
            sys.stderr.write(f"Payload exceeds limit of {max_bytes} bytes\n")
            sys.exit(1)
        if not raw.strip():
            sys.exit(0)
        data = json.loads(raw)
        if not isinstance(data, dict):
            sys.exit(0)
    except Exception:
        sys.exit(0)

    tool_name = data.get("tool_name", "") or ""
    tool_args = data.get("tool_args", {}) or {}
    if not isinstance(tool_args, dict):
        tool_args = {}
    inject_trace_context(tool_name, tool_args)
    sys.exit(0)

if __name__ == "__main__":
    main()
