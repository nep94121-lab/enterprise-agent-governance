#!/usr/bin/env python3
"""Grill-Me Research Enforcer Hook (PreToolUse) for Enterprise Multi-Agent Governance System.

Enforces Industry-Grounded Grill-Me Protocol (§INDUSTRY-GROUNDED-GRILL-ME):
1. When in /grill-me context, the agent is STRICTLY PROHIBITED from hallucinating options.
2. The agent MUST call 'search_web' to research industry standards and proven architectures
   from Big Tech before presenting interview questions and options to the User.
3. If ask_question is called in /grill-me context without prior search_web call:
   -> HARD DENY (chặn ngay lập tức, 0 ngoại lệ theo lệnh của Sếp).
4. Normal / non-grill-me questions bypass this hook safely.
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import subprocess
import sys
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

WEB_SEARCH_TOOLS: frozenset[str] = frozenset({
    "search_web",
    "firecrawl_search",
    "firecrawl_crawl",
    "gemini_search_docs",
    "read_url_content",
})


def is_grill_me_context(payload: dict[str, Any], args: dict[str, Any]) -> bool:
    """Determine if current execution context is /grill-me."""
    # 1. Payload direct flags (explicit True or False)
    if "is_grill_me" in payload:
        return bool(payload["is_grill_me"])
    if payload.get("slash_command") == "/grill-me":
        return True
    ctx = payload.get("context", {})
    if isinstance(ctx, dict):
        if "is_grill_me" in ctx:
            return bool(ctx["is_grill_me"])
        if ctx.get("slash_command") == "/grill-me":
            return True

    # 2. Environment variable
    if os.environ.get("GRILL_ME_ACTIVE") == "1":
        return True

    # 3. Question content analysis
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

    # 4. Transcript analysis (only if conversationId is in payload)
    conv_id = payload.get("conversationId")
    if conv_id and isinstance(conv_id, str):
        brain_dir = pathlib.Path.home() / ".gemini" / "antigravity" / "brain" / conv_id / ".system_generated" / "logs"
        transcript = brain_dir / "transcript.jsonl"
        if transcript.is_file():
            try:
                with open(transcript, "r", encoding="utf-8", errors="replace") as f:
                    last_user_content = ""
                    for line in f:
                        if not line.strip():
                            continue
                        step = json.loads(line)
                        if step.get("type") == "USER_INPUT":
                            last_user_content = str(step.get("content", ""))
                    clean_content = last_user_content.lower().strip()
                    if "/grill-me" in clean_content or "grill me" in clean_content or clean_content.startswith("/grill_me"):
                        return True
            except Exception as exc:
                log_diagnostic(f"Transcript inspection error in grill-me check: {exc}")

    return False


def has_called_search_web(payload: dict[str, Any]) -> bool:
    """Check if search_web tool has been executed in the current turn/context."""
    # 1. Payload flags (for test fixtures / direct injection)
    if payload.get("searched_web") is True or payload.get("has_search_web") is True:
        return True

    # 2. History in payload
    history = payload.get("history") or payload.get("steps") or payload.get("toolCallsHistory")
    if isinstance(history, list):
        for item in history:
            if isinstance(item, dict):
                name = item.get("name") or (item.get("toolCall", {}).get("name") if isinstance(item.get("toolCall"), dict) else "")
                if name in WEB_SEARCH_TOOLS:
                    return True

    # 3. Transcript inspection (since last USER_INPUT)
    conv_id = payload.get("conversationId") or os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
    if conv_id and isinstance(conv_id, str):
        brain_dir = pathlib.Path.home() / ".gemini" / "antigravity" / "brain" / conv_id / ".system_generated" / "logs"
        transcript = brain_dir / "transcript.jsonl"
        if transcript.is_file():
            try:
                with open(transcript, "r", encoding="utf-8", errors="replace") as f:
                    tool_calls_since_user_input: list[str] = []
                    for line in f:
                        if not line.strip():
                            continue
                        step = json.loads(line)
                        if step.get("type") == "USER_INPUT":
                            tool_calls_since_user_input.clear()
                            continue
                        tcs = step.get("tool_calls") or []
                        for tc in tcs:
                            if isinstance(tc, dict):
                                tc_name = tc.get("name", "")
                                tool_calls_since_user_input.append(tc_name)
                                if tc_name in WEB_SEARCH_TOOLS:
                                    return True
            except Exception as exc:
                log_diagnostic(f"Transcript inspection error in search_web check: {exc}")

    return False


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

    # If NOT in grill-me context -> allow freely (bypass)
    if not is_grill_me_context(payload, args):
        return pre_tool_response("allow", "Non-grill-me question approved.")

    # In grill-me context: MUST have called search_web
    if has_called_search_web(payload):
        log_diagnostic("search_web verified in grill-me context. ask_question approved.")
        return pre_tool_response("allow", "Industry research verified via search_web. ask_question approved.")

    # HARD DENY per boss's strict order
    reason = (
        "LỆNH CƯỠNG CHẾ TỪ SẾP (HARD DENY - §INDUSTRY-GROUNDED-GRILL-ME): BẮT BUỘC TRA CỨU WEB TRƯỚC KHI HỎI GRILL-ME!\n"
        "Bạn đang trong quy trình /grill-me nhưng CHƯA thực hiện tra cứu web để xác thực tiêu chuẩn công nghiệp.\n"
        "TUYỆT ĐỐI CẤM tự nghĩ ra các phương án lý thuyết suông! BẮT BUỘC phải gọi công cụ 'search_web' tra cứu các "
        "giải pháp, mô hình kiến trúc thực tế của Big Tech (Google, Meta, Netflix, Uber, AWS, CNCF...) trước khi đưa "
        "ra câu hỏi và các phương án lựa chọn cho Sếp!"
    )
    log_diagnostic("HARD DENIED ask_question: Missing search_web in /grill-me context.")
    return pre_tool_response("deny", reason)


def run_self_tests() -> bool:
    """Self-test runner covering grill-me scenarios."""
    print("======================================================================")
    print("Running Grill-Me Research Enforcer Self-Test Suite")
    print("======================================================================\n")

    test_results: list[tuple[str, bool, str]] = []

    def record(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        test_results.append((name, passed, detail))
        print(f"[{status}] {name}{f' - {detail}' if detail and not passed else ''}")

    # TC1: Deny ask_question in grill-me context without prior search_web
    r1 = evaluate_grill_me_research({
        "is_grill_me": True,
        "searched_web": False,
        "toolCall": {
            "name": "ask_question",
            "args": {
                "questions": [
                    {
                        "question": "Sếp muốn chọn kiến trúc nào?",
                        "options": ["A", "B"],
                    },
                ],
            },
        },
    })
    record("TC1: Hard DENY ask_question without search_web in grill-me", r1.get("decision") == "deny" and "HARD DENY" in r1.get("reason", ""))

    # TC2: Allow ask_question in grill-me context after search_web
    r2 = evaluate_grill_me_research({
        "is_grill_me": True,
        "searched_web": True,
        "toolCall": {
            "name": "ask_question",
            "args": {
                "questions": [
                    {
                        "question": "Sếp muốn chọn kiến trúc nào?",
                        "options": ["Option A (Netflix Hystrix)", "Option B (Google SRE Circuit Breaker)"],
                    },
                ],
            },
        },
    })
    record("TC2: Allow ask_question in grill-me after search_web", r2.get("decision") == "allow")

    # TC3: Allow ask_question when NOT in grill-me context (bypass)
    r3 = evaluate_grill_me_research({
        "is_grill_me": False,
        "toolCall": {
            "name": "ask_question",
            "args": {
                "questions": [
                    {
                        "question": "Sếp có muốn tiếp tục không?",
                        "options": ["Có", "Không"],
                    },
                ],
            },
        },
    })
    record("TC3: Bypass ask_question when not grill-me context", r3.get("decision") == "allow")

    # TC4: Allow other tools (run_command, view_file)
    r4 = evaluate_grill_me_research({
        "is_grill_me": True,
        "toolCall": {"name": "run_command", "args": {"CommandLine": "dir"}},
    })
    record("TC4: Allow other tools (run_command)", r4.get("decision") == "allow")

    # TC5: Detect grill-me via question text containing keyword
    r5 = evaluate_grill_me_research({
        "toolCall": {
            "name": "ask_question",
            "args": {
                "questions": [
                    {
                        "question": "[/grill-me] Chọn giải pháp concurrency cho hệ thống",
                        "options": ["Actor Model", "Thread Pool"],
                    },
                ],
            },
        },
    })
    record("TC5: Deny when grill-me keyword is in question text without search", r5.get("decision") == "deny")

    # TC6: Allow when toolCallsHistory contains search_web
    r6 = evaluate_grill_me_research({
        "is_grill_me": True,
        "toolCallsHistory": [{"name": "search_web", "args": {"query": "circuit breaker patterns"}}],
        "toolCall": {
            "name": "ask_question",
            "args": {"questions": [{"question": "Pattern nào?", "options": ["A", "B"]}]},
        },
    })
    record("TC6: Allow when history contains search_web", r6.get("decision") == "allow")

    # TC7: Malformed payload safety fallback
    r7 = evaluate_grill_me_research({})
    record("TC7: Malformed payload safety fallback", r7.get("decision") == "allow")

    # TC8: Subprocess execution verification
    proc = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).resolve())],
        input=json.dumps({
            "is_grill_me": True,
            "searched_web": False,
            "toolCall": {"name": "ask_question", "args": {"questions": [{"question": "Q?", "options": ["1", "2"]}]}},
        }),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    sub_out = json.loads(proc.stdout) if proc.stdout.strip() else {}
    record("TC8: Subprocess streaming verification", proc.returncode == 0 and sub_out.get("decision") == "deny")

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
