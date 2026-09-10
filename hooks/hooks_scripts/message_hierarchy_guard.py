#!/usr/bin/env python3
"""Message Hierarchy Guard Hook (PreToolUse) for Enterprise Multi-Agent Governance System.

Enforces strict communication hierarchy:
1. Dev Sub-agents (Tier 3) MUST ONLY message their PM Sub-agent (parent).
   Strictly prohibits jumping hierarchy (ny cóc vượt cấp) to Agent Chính or User.
2. PM Sub-agents (Tier 2) message upward to Agent Chính (parent) or downward to Worker Subagents.
   PM Sub-agents are STRICTLY PROHIBITED from messaging User directly via send_message.
3. [ESCALATION_TO_TOP] Protocol: Detects escalation tags. PM can escalate to Agent Chính,
   triggering the non-blocking 60-second countdown protocol for User decisions.
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

TOP_LEVEL_RECIPIENT_IDENTIFIERS: frozenset[str] = frozenset({
    "agent_chinh",
    "agent-chinh",
    "agentchinh",
    "agent chính",
    "top",
    "top_level",
    "top-level",
    "top_level_agent",
    "main_agent",
})

USER_RECIPIENT_IDENTIFIERS: frozenset[str] = frozenset({
    "user",
    "sếp",
    "sep",
    "boss",
    "human",
})


def detect_sender_role(payload: dict[str, Any]) -> str:
    """Detect sender role: 'DEV', 'PM', or 'TOP_LEVEL'.

    Checks payload metadata, environment variables, or transcript first line.
    """
    # 1. Payload direct specification
    for key in ("caller_role", "sender_role", "role"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            clean = val.lower().strip()
            if any(k in clean for k in ("pm", "orchestrator", "project_manager")):
                return "PM"
            if any(k in clean for k in ("top", "agent_chinh", "agent chính")):
                return "TOP_LEVEL"
            if any(k in clean for k in ("dev", "backend", "frontend", "qa", "tech_lead", "worker", "subagent")):
                return "DEV"

    # 2. Environment variable override
    env_role = os.environ.get("AGENT_ROLE", "").lower()
    if "pm" in env_role:
        return "PM"
    if "top" in env_role:
        return "TOP_LEVEL"
    if any(k in env_role for k in ("dev", "backend", "frontend", "qa", "tech_lead", "worker")):
        return "DEV"

    # 3. Transcript first-line check
    conv_id = payload.get("conversationId") or os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
    if conv_id and isinstance(conv_id, str):
        brain_dir = pathlib.Path.home() / ".gemini" / "antigravity" / "brain" / conv_id / ".system_generated" / "logs"
        transcript = brain_dir / "transcript.jsonl"
        if transcript.is_file():
            try:
                with open(transcript, "r", encoding="utf-8", errors="replace") as f:
                    first_line = f.readline()
                    if first_line:
                        data = json.loads(first_line)
                        content = str(data.get("content", "")).lower()
                        if any(k in content for k in ("pm orchestrator", "pm sub-agent", "bạn là pm", "vai trò: pm")):
                            return "PM"
                        if any(k in content for k in ("agent chính", "top-level", "bạn là agent chính")):
                            return "TOP_LEVEL"
                        if any(k in content for k in ("backend", "frontend", "tech lead", "qa", "devops", "vai trò: backend", "vai trò: frontend")):
                            return "DEV"
            except Exception as exc:
                log_diagnostic(f"Transcript inspection error in hierarchy guard: {exc}")

    # Fallback heuristic: subagents default to DEV if not identified as PM
    return "DEV"


def evaluate_message_hierarchy(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate whether send_message satisfies hierarchy constraints."""
    if not isinstance(payload, dict):
        return pre_tool_response("allow", "Payload is not a dictionary.")

    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""
    if tool_name != "send_message":
        return pre_tool_response("allow", f"Tool '{tool_name}' is not send_message.")

    args = get_tool_args(tool_call)
    recipient = str(args.get("Recipient", "")).strip().lower()
    recipient_name = str(args.get("RecipientName", "")).strip().lower()
    message = str(args.get("Message", ""))
    has_escalation_tag = "[ESCALATION_TO_TOP]" in message

    sender_role = detect_sender_role(payload)

    # 1. Dev Sub-agent (Tier 3) Hierarchy Enforcement
    if sender_role == "DEV":
        # Dev MUST NOT send to User
        if recipient in USER_RECIPIENT_IDENTIFIERS or recipient_name in USER_RECIPIENT_IDENTIFIERS:
            reason = (
                "VI PHẠM THỨ BẬC GIAO TIẾP (§STRICT-HIERARCHY): Dev Sub-agent TUYỆT ĐỐI CẤM gửi thông điệp "
                "trực tiếp cho User/Sếp! Mọi giao tiếp với Sếp thuộc thẩm quyền duy nhất của Agent Chính. "
                "Dev chỉ được phép trao đổi với PM Sub-agent (parent)."
            )
            log_diagnostic("BLOCKED Dev Sub-agent from sending message directly to User.")
            return pre_tool_response("deny", reason)

        # Dev MUST NOT send to Top-Level Agent (bypass PM)
        if (
            recipient in TOP_LEVEL_RECIPIENT_IDENTIFIERS
            or recipient_name in TOP_LEVEL_RECIPIENT_IDENTIFIERS
            or has_escalation_tag
        ):
            reason = (
                "VI PHẠM THỨ BẬC GIAO TIẾP (§STRICT-HIERARCHY): Dev Sub-agent chỉ được phép gửi thông điệp "
                "duy nhất cho PM Sub-agent (parent)! Tuyệt đối cấm nhảy cóc vượt cấp gửi trực tiếp cho Agent Chính. "
                "Khi gặp bế tắc kỹ thuật, hãy gửi thông điệp [BLOCKER/TECHNICAL_DECISION] cho PM để PM điều phối."
            )
            log_diagnostic(f"BLOCKED Dev Sub-agent from jumping hierarchy to Agent Chính (Recipient={recipient}).")
            return pre_tool_response("deny", reason)

        # Dev sending to PM (parent) is allowed
        return pre_tool_response("allow", "Dev Sub-agent communicating with PM Sub-agent (parent) approved.")

    # 2. PM Sub-agent (Tier 2) Hierarchy Enforcement
    if sender_role == "PM":
        # PM MUST NOT send to User directly via send_message
        if recipient in USER_RECIPIENT_IDENTIFIERS or recipient_name in USER_RECIPIENT_IDENTIFIERS:
            reason = (
                "VI PHẠM THỨ BẬC GIAO TIẾP (§STRICT-HIERARCHY): PM Sub-agent TUYỆT ĐỐI CẤM gửi tin nhắn "
                "trực tiếp cho User/Sếp qua send_message! Đầu mối duy nhất giao tiếp với Sếp là Agent Chính. "
                "Nếu cần xin ý kiến chỉ đạo khẩn cấp từ Sếp, hãy gửi thông điệp gắn thẻ [ESCALATION_TO_TOP] "
                "lên Agent Chính (parent) để kích hoạt giao thức bộ đếm ngược 60 giây!"
            )
            log_diagnostic("BLOCKED PM Sub-agent from messaging User directly.")
            return pre_tool_response("deny", reason)

        # PM escalating to Agent Chính (parent) with [ESCALATION_TO_TOP]
        if has_escalation_tag:
            log_diagnostic("[ESCALATION_TO_TOP] tag detected from PM Sub-agent to Agent Chính. Escalation pipeline active.")
            return pre_tool_response("allow", "PM Sub-agent escalation to Agent Chính approved.")

        # PM sending to parent (Agent Chính) or worker subagents is allowed
        return pre_tool_response("allow", "PM Sub-agent communication approved.")

    # 3. Top-Level Agent
    return pre_tool_response("allow", "Top-level communication approved.")


def run_self_tests() -> bool:
    """Self-test runner covering hierarchy scenarios."""
    print("======================================================================")
    print("Running Message Hierarchy Guard Self-Test Suite")
    print("======================================================================\n")

    test_results: list[tuple[str, bool, str]] = []

    def record(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        test_results.append((name, passed, detail))
        print(f"[{status}] {name}{f' - {detail}' if detail and not passed else ''}")

    # TC1: Deny Dev sending to Agent Chính
    r1 = evaluate_message_hierarchy({
        "caller_role": "backend_developer",
        "toolCall": {
            "name": "send_message",
            "args": {"Recipient": "agent_chinh", "Message": "Báo cáo tiến độ"},
        },
    })
    record("TC1: Deny Dev sending to Agent Chính", r1.get("decision") == "deny")

    # TC2: Allow Dev sending to PM (parent)
    r2 = evaluate_message_hierarchy({
        "caller_role": "backend_developer",
        "toolCall": {
            "name": "send_message",
            "args": {"Recipient": "parent", "Message": "Báo cáo PM hoàn thành task"},
        },
    })
    record("TC2: Allow Dev sending to PM (parent)", r2.get("decision") == "allow")

    # TC3: Detect [ESCALATION_TO_TOP] and allow PM sending to parent
    r3 = evaluate_message_hierarchy({
        "caller_role": "pm_orchestrator",
        "toolCall": {
            "name": "send_message",
            "args": {"Recipient": "parent", "Message": "[ESCALATION_TO_TOP] Bế tắc kiến trúc cần Sếp duyệt"},
        },
    })
    record("TC3: Allow PM escalating to Agent Chính with [ESCALATION_TO_TOP]", r3.get("decision") == "allow")

    # TC4: Deny PM sending directly to User
    r4 = evaluate_message_hierarchy({
        "caller_role": "pm_orchestrator",
        "toolCall": {
            "name": "send_message",
            "args": {"Recipient": "user", "Message": "Chào Sếp em làm xong rồi"},
        },
    })
    record("TC4: Deny PM sending directly to User", r4.get("decision") == "deny")

    # TC5: Allow PM sending to worker subagent
    r5 = evaluate_message_hierarchy({
        "caller_role": "pm_orchestrator",
        "toolCall": {
            "name": "send_message",
            "args": {"Recipient": "subagent-conv-12345", "Message": "Hãy sửa file bug.py"},
        },
    })
    record("TC5: Allow PM sending to worker subagent", r5.get("decision") == "allow")

    # TC6: Deny Dev sending directly to User
    r6 = evaluate_message_hierarchy({
        "caller_role": "frontend_developer",
        "toolCall": {
            "name": "send_message",
            "args": {"Recipient": "sếp", "Message": "Sếp ơi em làm xong"},
        },
    })
    record("TC6: Deny Dev sending directly to User", r6.get("decision") == "deny")

    # TC7: Deny Dev using [ESCALATION_TO_TOP] to bypass PM to Top
    r7 = evaluate_message_hierarchy({
        "caller_role": "qa_challenger",
        "toolCall": {
            "name": "send_message",
            "args": {"Recipient": "agent_chinh", "Message": "[ESCALATION_TO_TOP] Dev tự escalate"},
        },
    })
    record("TC7: Deny Dev bypassing PM with ESCALATION tag", r7.get("decision") == "deny")

    # TC8: Allow Top-Level agent messaging PM
    r8 = evaluate_message_hierarchy({
        "caller_role": "top_level",
        "toolCall": {
            "name": "send_message",
            "args": {"Recipient": "pm-conv-id", "Message": "Bắt đầu Phase 1"},
        },
    })
    record("TC8: Allow Top-Level messaging PM", r8.get("decision") == "allow")

    # TC9: Malformed payload safety fallback
    r9 = evaluate_message_hierarchy({})
    record("TC9: Malformed payload safety fallback", r9.get("decision") == "allow")

    # TC10: Subprocess streaming verification
    proc = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).resolve())],
        input=json.dumps({
            "caller_role": "backend",
            "toolCall": {"name": "send_message", "args": {"Recipient": "user", "Message": "hi"}},
        }),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    sub_out = json.loads(proc.stdout) if proc.stdout.strip() else {}
    record("TC10: Subprocess streaming verification", proc.returncode == 0 and sub_out.get("decision") == "deny")

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
    response = evaluate_message_hierarchy(payload)
    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()
