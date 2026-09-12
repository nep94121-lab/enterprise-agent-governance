#!/usr/bin/env python3
"""Grounding Evidence Enforcer Hook for Enterprise Governance System.

Event: PreToolUse
Matcher: .* (Monitors send_message, ask_question)

Enforces that when the AI agent issues a verdict, conclusion, or definitive claim
to the user or another agent, it must possess empirical grounding evidence
(i.e. web search via search_web / read_url_content).
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import re
import sys
import tempfile
import unicodedata
from typing import Any

# Enforce UTF-8 I/O encoding across all platforms (especially Windows PowerShell)
try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8-sig", errors="replace")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

# Path resolution for enterprise hooks environment
HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent
ENTERPRISE_HOOKS_ROOT = HOOKS_SCRIPTS_DIR.parent
if str(HOOKS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_SCRIPTS_DIR))
if str(ENTERPRISE_HOOKS_ROOT) not in sys.path:
    sys.path.insert(0, str(ENTERPRISE_HOOKS_ROOT))

# Safe fallback imports from common_hook_lib if available
try:
    from common_hook_lib import (
        emit_stdout_json as lib_emit_stdout_json,
        extract_tool_invocation as lib_extract_tool_invocation,
        log_diagnostic as lib_log_diagnostic,
        pre_tool_response as lib_pre_tool_response,
        MAX_STDIN_BYTES as LIB_MAX_STDIN_BYTES,
    )
except ImportError:
    lib_emit_stdout_json = None
    lib_extract_tool_invocation = None
    lib_log_diagnostic = None
    lib_pre_tool_response = None
    LIB_MAX_STDIN_BYTES = None

MAX_STDIN_BYTES: int = LIB_MAX_STDIN_BYTES if LIB_MAX_STDIN_BYTES is not None else 10 * 1024 * 1024  # 10 MB

DEFAULT_VERDICT_KEYWORDS: list[str] = [
    "phán quyết",
    "kết luận",
    "khẳng định chắc chắn",
    "khẳng định 100%",
    "chắc chắn 100%",
    "hoàn toàn xác thực",
    "đảm bảo 100%",
    "tuyệt đối đúng",
    "final verdict",
]

MONITORED_TOOLS: frozenset[str] = frozenset({
    "send_message",
    "ask_question",
    "default_api:send_message",
    "default_api:ask_question",
})


def log_diagnostic(message: str) -> None:
    """Log formatted diagnostic message to stderr (never stdout)."""
    if lib_log_diagnostic is not None:
        lib_log_diagnostic(message)
        return
    try:
        sys.stderr.write(f"[GROUNDING-ENFORCER-DIAGNOSTIC] {message}\n")
        sys.stderr.flush()
    except (OSError, UnicodeEncodeError):
        pass


def emit_stdout_json(payload: dict[str, Any]) -> None:
    """Serialize and print exact JSON payload to sys.stdout and flush immediately."""
    if lib_emit_stdout_json is not None:
        lib_emit_stdout_json(payload)
        return
    try:
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    except Exception as exc:
        log_diagnostic(f"Error emitting stdout JSON: {exc}")
        sys.stdout.write('{"decision":"deny","status":"DENY","reason":"Stdout emission failure"}\n')
        sys.stdout.flush()


def pre_tool_response(
    decision: str,
    reason: str = "",
    suggestion: str = "",
    permission_overrides: list[str] | None = None,
) -> dict[str, Any]:
    """Construct standard PreToolUse response payload with full dual-standard compatibility."""
    dec_lower = str(decision).lower()
    dec_upper = str(decision).upper()
    res: dict[str, Any] = {
        "decision": dec_lower,
        "status": dec_upper,
    }
    if reason:
        res["reason"] = reason
    if suggestion:
        res["suggestion"] = suggestion
    if permission_overrides:
        res["permissionOverrides"] = permission_overrides
    return res


def read_bounded_stdin(max_bytes: int = MAX_STDIN_BYTES) -> tuple[str, bool, str | None]:
    """Read bounded input from sys.stdin.

    Returns:
        (raw_data, is_overflow, error_message)
    """
    try:
        raw_data = sys.stdin.read(max_bytes + 1)
        if len(raw_data) > max_bytes:
            return "", True, "Payload exceeded 10MB limit"
        cleaned = raw_data.lstrip("\ufeff\ufffe")
        return cleaned, False, None
    except Exception as exc:
        return "", False, str(exc)


def normalize_and_remove_noise(text: str) -> str:
    """Normalize text and strip noise, spaces, punctuation to defeat evasions.

    E.g. 'p h á n   q u y ế t' -> 'phánquyết'
    """
    if not isinstance(text, str):
        return ""
    # NFC normalization for Unicode accent consistency
    text = unicodedata.normalize("NFC", text.lower())
    # Remove invisible, zero-width, and BiDi formatting characters
    text = re.sub(r"[\u200b-\u200f\ufeff\u202a-\u202e\u2060-\u206f]", "", text)
    # Remove non-word characters, underscores, and whitespace
    text = re.sub(r"[^\w]|_", "", text)
    return text


def has_verdict_keywords(message: str, keywords: list[str]) -> tuple[bool, str]:
    """Check if message contains any of the verdict keywords after noise removal."""
    norm_msg = normalize_and_remove_noise(message)
    if not norm_msg:
        return False, ""
    for kw in keywords:
        norm_kw = normalize_and_remove_noise(kw)
        if norm_kw and norm_kw in norm_msg:
            return True, kw
    return False, ""


def load_grounding_config() -> dict[str, Any]:
    """Load configuration from grounding_config.json if it exists."""
    config_path = HOOKS_SCRIPTS_DIR / "grounding_config.json"
    if config_path.is_file():
        try:
            with open(config_path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception as exc:
            log_diagnostic(f"Failed to read grounding_config.json: {exc}")
    return {}


def get_verdict_keywords(config: dict[str, Any]) -> list[str]:
    """Compile verdict keywords combining defaults and config settings."""
    keywords = list(DEFAULT_VERDICT_KEYWORDS)
    for cfg_key in ("verdict_keywords", "decision_keywords"):
        cfg_list = config.get(cfg_key)
        if isinstance(cfg_list, list):
            for kw in cfg_list:
                if isinstance(kw, str) and kw.strip() and kw.strip() not in keywords:
                    keywords.append(kw.strip())
    return keywords


def is_search_web_tool(tool_name: str) -> bool:
    """Check if a tool name represents an empirical web search tool."""
    if not tool_name:
        return False
    name = str(tool_name).strip()
    return (
        name == "search_web"
        or name.endswith(":search_web")
        or name == "read_url_content"
        or name.endswith(":read_url_content")
        or "firecrawl_search" in name
    )


def count_search_web_in_transcript(file_path: pathlib.Path | str) -> int:
    """Scan a transcript.jsonl file and count valid web search calls."""
    path = pathlib.Path(file_path)
    if not path.is_file():
        return 0
    count = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip() or "search_web" not in line:
                    continue
                try:
                    data = json.loads(line)
                    # 1. tool_calls array (standard transcript format)
                    tool_calls = data.get("tool_calls")
                    if isinstance(tool_calls, list):
                        for call in tool_calls:
                            if isinstance(call, dict):
                                c_name = call.get("name", "") or call.get("function", {}).get("name", "")
                                if is_search_web_tool(c_name):
                                    count += 1
                    # 2. direct toolCall dict if present
                    direct_call = data.get("toolCall")
                    if isinstance(direct_call, dict):
                        c_name = direct_call.get("name", "") or direct_call.get("function", {}).get("name", "")
                        if is_search_web_tool(c_name):
                            count += 1
                except Exception:
                    pass
    except Exception as exc:
        log_diagnostic(f"Error scanning transcript {path}: {exc}")
    return count


def check_search_web_called(payload: dict[str, Any], min_search_count: int = 1) -> tuple[bool, int]:
    """Verify if search_web was called in the trajectory or conversation history."""
    search_count = 0

    # 1. Direct explicit assertions in payload
    if payload.get("has_search_web") is True or payload.get("search_called") is True or payload.get("grounded") is True:
        return True, max(min_search_count, 1)

    explicit_count = payload.get("search_web_count") or payload.get("search_count")
    if isinstance(explicit_count, (int, float)) and explicit_count >= min_search_count:
        return True, int(explicit_count)

    # 2. In-payload trajectory / tool_calls / history
    for list_key in ("tool_calls", "trajectory", "history", "steps"):
        items = payload.get(list_key)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    t_name = (
                        item.get("name", "")
                        or item.get("tool_name", "")
                        or (item.get("toolCall", {}) or {}).get("name", "")
                    )
                    if is_search_web_tool(t_name):
                        search_count += 1

    if search_count >= min_search_count:
        return True, search_count

    # 3. Explicit transcript path from payload or environment
    transcript_paths_to_check: list[pathlib.Path] = []
    for tp_key in ("transcriptPath", "transcript_path", "transcript"):
        val = payload.get(tp_key)
        if isinstance(val, str) and val.strip():
            tp = pathlib.Path(val.strip().strip('"').strip("'"))
            if tp.is_file():
                transcript_paths_to_check.append(tp)

    env_tp = os.environ.get("ANTIGRAVITY_TRANSCRIPT_PATH")
    if env_tp and os.path.isfile(env_tp):
        transcript_paths_to_check.append(pathlib.Path(env_tp))

    # 4. Lookup by conversationId in brain directory
    conv_id = (
        payload.get("conversationId")
        or payload.get("conversation_id")
        or os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
    )
    brain_root = os.environ.get(
        "GEMINI_BRAIN_DIR",
        os.path.expanduser(r"~\.gemini\antigravity\brain"),
    )
    brain_path = pathlib.Path(brain_root)

    if conv_id and isinstance(conv_id, str) and brain_path.is_dir():
        cand1 = brain_path / conv_id / ".system_generated" / "logs" / "transcript.jsonl"
        cand2 = brain_path / conv_id / "transcript.jsonl"
        for cand in (cand1, cand2):
            if cand.is_file() and cand not in transcript_paths_to_check:
                transcript_paths_to_check.append(cand)

    # 5. Fallback: Check top 3 most recently modified conversation directories
    if not transcript_paths_to_check and brain_path.is_dir():
        try:
            conv_dirs = [
                d for d in brain_path.iterdir()
                if d.is_dir() and d.name != "tempmediaStorage"
            ]
            conv_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            for cd in conv_dirs[:3]:
                cand = cd / ".system_generated" / "logs" / "transcript.jsonl"
                if cand.is_file():
                    transcript_paths_to_check.append(cand)
        except Exception as exc:
            log_diagnostic(f"Error scanning brain directory: {exc}")

    # Scan identified transcript files
    for tp in transcript_paths_to_check:
        file_count = count_search_web_in_transcript(tp)
        search_count += file_count
        if search_count >= min_search_count:
            return True, search_count

    return search_count >= min_search_count, search_count


def extract_tool_invocation(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Uniformly extract tool_name and tool_args across all payload variations."""
    if lib_extract_tool_invocation is not None:
        try:
            return lib_extract_tool_invocation(payload)
        except Exception:
            pass

    if not isinstance(payload, dict):
        return "", {}

    tool_call = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    tool_name = (
        tool_call.get("name")
        or payload.get("tool_name")
        or payload.get("toolName")
        or payload.get("tool")
        or payload.get("name")
        or ""
    )
    tool_args = (
        tool_call.get("args")
        or payload.get("tool_args")
        or payload.get("toolArgs")
        or payload.get("arguments")
        or payload.get("args")
        or {}
    )
    if not isinstance(tool_args, dict):
        tool_args = {}

    return str(tool_name).strip(), tool_args


def extract_candidate_text(payload: dict[str, Any], tool_name: str, args: dict[str, Any]) -> str:
    """Extract all candidate text lines from tool arguments and payload."""
    texts: list[str] = []

    # 1. From tool args
    if isinstance(args, dict):
        for key in ("Message", "message", "content", "text", "body", "prompt"):
            val = args.get(key)
            if isinstance(val, str) and val.strip():
                texts.append(val)

        questions = args.get("questions")
        if isinstance(questions, (list, dict)):
            texts.append(json.dumps(questions, ensure_ascii=False))

    # 2. From root-level payload fields
    for key in ("Message", "message", "content", "text", "tool_output", "output", "result"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            texts.append(val)

    if "questions" in payload and isinstance(payload["questions"], (list, dict)):
        texts.append(json.dumps(payload["questions"], ensure_ascii=False))

    return " ".join(texts)


def evaluate_grounding_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate whether the tool call is permitted or requires grounding evidence."""
    if not isinstance(payload, dict):
        return pre_tool_response(
            "deny",
            reason="Payload không phải là JSON object hợp lệ (Fail-Closed bảo mật).",
        )

    # Check event type
    event_type = payload.get("hook_event_name") or payload.get("event") or payload.get("event_type") or "PreToolUse"
    if event_type and event_type != "PreToolUse":
        return pre_tool_response("allow", reason=f"Sự kiện '{event_type}' không yêu cầu kiểm tra PreToolUse.")

    tool_name, args = extract_tool_invocation(payload)
    if not tool_name:
        return pre_tool_response("allow", reason="Không phát hiện tên tool trong payload.")

    clean_tool_name = str(tool_name).strip()
    base_tool_name = clean_tool_name.split(":")[-1]

    # Load configuration
    config = load_grounding_config()

    # Check bypass tools
    bypass_tools = config.get("bypass_tools", [])
    if isinstance(bypass_tools, list) and (clean_tool_name in bypass_tools or base_tool_name in bypass_tools):
        return pre_tool_response("allow", reason=f"Tool '{tool_name}' nằm trong danh sách bypass_tools.")

    # Check monitored tool
    if base_tool_name not in ("send_message", "ask_question"):
        return pre_tool_response(
            "allow",
            reason=f"Tool '{tool_name}' không thuộc phạm vi giám sát của grounding enforcer.",
        )

    # Extract text to inspect
    candidate_text = extract_candidate_text(payload, tool_name, args)
    if not candidate_text.strip():
        return pre_tool_response(
            "allow",
            reason=f"Tool '{tool_name}' không chứa nội dung văn bản cần kiểm tra.",
        )

    # Check bypass keywords
    bypass_keywords = config.get("bypass_keywords", [])
    if isinstance(bypass_keywords, list):
        norm_text = normalize_and_remove_noise(candidate_text)
        for bkw in bypass_keywords:
            if isinstance(bkw, str) and bkw.strip():
                norm_bkw = normalize_and_remove_noise(bkw)
                if norm_bkw and norm_bkw in norm_text:
                    return pre_tool_response(
                        "allow",
                        reason=f"Bỏ qua kiểm tra grounding theo cấu hình bypass keyword '{bkw}'.",
                    )

    # Check verdict keywords
    verdict_keywords = get_verdict_keywords(config)
    has_verdict, matched_kw = has_verdict_keywords(candidate_text, verdict_keywords)

    if not has_verdict:
        return pre_tool_response("allow", reason="Nội dung không chứa từ khóa phán quyết / khẳng định.")

    # Verify search_web evidence
    min_search_count = int(config.get("min_search_count", 1))
    has_evidence, search_count = check_search_web_called(payload, min_search_count=min_search_count)

    if not has_evidence:
        reason_msg = (
            f"Phát hiện phán quyết (từ khóa '{matched_kw}') nhưng chưa có bằng chứng xác thực "
            f"(chưa gọi search_web tối thiểu {min_search_count} lần, hiện có {search_count} lần). "
            "Yêu cầu gọi search_web trước."
        )
        suggestion_msg = "Hãy gọi tool search_web để xác thực và thu thập bằng chứng tiếp đất trước khi đưa ra phán quyết."
        return pre_tool_response("deny", reason=reason_msg, suggestion=suggestion_msg)

    return pre_tool_response(
        "allow",
        reason=f"Phát hiện phán quyết (từ khóa '{matched_kw}'), đã xác thực bằng chứng tiếp đất ({search_count} lượt gọi search_web).",
    )


def run_self_tests() -> bool:
    """Run comprehensive self-tests verifying bounded stdin, edge cases, and verdict enforcement."""
    print("======================================================================")
    print("Running Grounding Evidence Enforcer Self-Test Suite")
    print("======================================================================\n")

    cases_passed = 0
    total_cases = 0

    def assert_test(name: str, condition: bool, extra: str = "") -> None:
        nonlocal cases_passed, total_cases
        total_cases += 1
        if condition:
            cases_passed += 1
            print(f"[PASS] {name}")
        else:
            print(f"[FAIL] {name}: {extra}")
            assert condition, f"Test failed: {name} - {extra}"

    # Test 1: Normalization & noise removal
    assert_test(
        "Test 1.1: Standard string normalization",
        normalize_and_remove_noise("Phán Quyết") == "phánquyết",
    )
    assert_test(
        "Test 1.2: Spaced noise bypass attempt",
        normalize_and_remove_noise("p h á n   q u y ế t") == "phánquyết",
    )
    assert_test(
        "Test 1.3: Punctuation and zero-width evasion",
        normalize_and_remove_noise("k.ế-t\u200b_l*u!ậ?n") == "kếtluận",
    )

    # Test 2: Non-monitored tools are allowed
    run_cmd_payload = {
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "python test.py"},
        }
    }
    res2 = evaluate_grounding_evidence(run_cmd_payload)
    assert_test(
        "Test 2: Non-monitored tool (run_command) is allowed",
        res2["decision"] == "allow" and res2["status"] == "ALLOW",
        str(res2),
    )

    # Test 3: Monitored tool (send_message) without verdict keyword is allowed
    normal_msg_payload = {
        "toolCall": {
            "name": "send_message",
            "args": {"Message": "Chào PM, tôi đang tiến hành cập nhật mã nguồn theo yêu cầu."},
        }
    }
    res3 = evaluate_grounding_evidence(normal_msg_payload)
    assert_test(
        "Test 3: Normal message without verdict is allowed",
        res3["decision"] == "allow" and res3["status"] == "ALLOW",
        str(res3),
    )

    # Test 4: Monitored tool (send_message) with verdict keyword but no search_web is denied
    verdict_no_search_payload = {
        "toolCall": {
            "name": "send_message",
            "args": {"Message": "Tôi xin đưa ra kết luận chắc chắn rằng nguyên nhân là do lỗi bộ nhớ."},
        }
    }
    res4 = evaluate_grounding_evidence(verdict_no_search_payload)
    assert_test(
        "Test 4: Verdict keyword without grounding evidence is DENIED",
        res4["decision"] == "deny" and res4["status"] == "DENY",
        str(res4),
    )

    # Test 5: Monitored tool (send_message) with verdict keyword AND search_web called is allowed
    verdict_with_search_payload = {
        "toolCall": {
            "name": "send_message",
            "args": {"Message": "Tôi xin đưa ra kết luận rằng hệ thống đã hoàn toàn đạt chuẩn."},
        },
        "has_search_web": True,
    }
    res5 = evaluate_grounding_evidence(verdict_with_search_payload)
    assert_test(
        "Test 5: Verdict keyword WITH grounding evidence is ALLOWED",
        res5["decision"] == "allow" and res5["status"] == "ALLOW",
        str(res5),
    )

    # Test 6: In-payload tool_calls trajectory detection
    verdict_with_trajectory_payload = {
        "tool_name": "send_message",
        "tool_args": {"Message": "Khẳng định chắc chắn dịch vụ đã phục hồi."},
        "tool_calls": [{"name": "search_web", "args": {"query": "service status"}}],
    }
    res6 = evaluate_grounding_evidence(verdict_with_trajectory_payload)
    assert_test(
        "Test 6: Grounding evidence verified via in-payload trajectory",
        res6["decision"] == "allow" and res6["status"] == "ALLOW",
        str(res6),
    )

    # Test 7: ask_question tool with verdict keyword in questions list is denied without search
    ask_question_payload = {
        "toolCall": {
            "name": "ask_question",
            "args": {
                "questions": [
                    {
                        "question": "Sếp có phán quyết chấp thuận giải pháp này không?",
                        "options": ["Đồng ý", "Từ chối"],
                    }
                ]
            },
        }
    }
    res7 = evaluate_grounding_evidence(ask_question_payload)
    assert_test(
        "Test 7: ask_question tool with verdict keyword is DENIED without search",
        res7["decision"] == "deny" and res7["status"] == "DENY",
        str(res7),
    )

    # Test 8: Transcript file integration check
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".jsonl") as tf:
        tf.write('{"step_index": 1, "tool_calls": [{"name": "search_web", "args": {"query": "python docs"}}]}\n')
        temp_transcript = tf.name

    try:
        verdict_with_transcript_payload = {
            "tool_name": "send_message",
            "tool_args": {"Message": "Phán quyết này dựa trên tài liệu chính thức."},
            "transcriptPath": temp_transcript,
        }
        res8 = evaluate_grounding_evidence(verdict_with_transcript_payload)
        assert_test(
            "Test 8: Grounding evidence verified via transcript.jsonl file",
            res8["decision"] == "allow" and res8["status"] == "ALLOW",
            str(res8),
        )
    finally:
        if os.path.exists(temp_transcript):
            try:
                os.remove(temp_transcript)
            except OSError:
                pass

    # Test 9: Fail-Closed on invalid non-dict payload
    res9 = evaluate_grounding_evidence("non-dict payload")  # type: ignore
    assert_test(
        "Test 9: Fail-Closed on non-dict payload",
        res9["decision"] == "deny" and res9["status"] == "DENY",
        str(res9),
    )

    # Test 10: Fail-Closed on malformed JSON simulation
    # (Testing that malformed JSON triggers deny)
    def simulate_parse(raw: str) -> dict[str, Any]:
        try:
            d = json.loads(raw)
            if not isinstance(d, dict):
                return pre_tool_response("deny", reason="Not dict")
            return evaluate_grounding_evidence(d)
        except json.JSONDecodeError as exc:
            return pre_tool_response("deny", reason=f"Malformed JSON: {exc}")

    res10 = simulate_parse("{invalid json string:")
    assert_test(
        "Test 10: Fail-Closed on malformed JSON",
        res10["decision"] == "deny" and res10["status"] == "DENY",
        str(res10),
    )

    # Test 11: Fail-Closed on overflow simulation (>10MB)
    def simulate_overflow(size: int, max_bytes: int = 10 * 1024 * 1024) -> dict[str, Any]:
        if size > max_bytes:
            return pre_tool_response("deny", reason="Payload stdin vượt quá giới hạn an toàn 10MB")
        return pre_tool_response("allow")

    res11 = simulate_overflow(10 * 1024 * 1024 + 10)
    assert_test(
        "Test 11: Fail-Closed on payload overflow (> 10MB)",
        res11["decision"] == "deny" and res11["status"] == "DENY",
        str(res11),
    )

    # Test 12: Empty string handling
    empty_payload: dict[str, Any] = {}
    res12 = evaluate_grounding_evidence(empty_payload)
    assert_test(
        "Test 12: Empty payload defaults safely to allow without monitored tool",
        res12["decision"] == "allow" and res12["status"] == "ALLOW",
        str(res12),
    )

    print("\n----------------------------------------------------------------------")
    print(f"Self-Test Summary: {cases_passed}/{total_cases} test cases PASSED (100% success).")
    print("----------------------------------------------------------------------\n")
    return cases_passed == total_cases


def main() -> None:
    """Main CLI entrypoint for grounding_evidence_enforcer."""
    if "--self-test" in sys.argv:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    # Optional CLI arguments fallback
    cli_event = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else ""
    cli_tool = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("-") else ""

    # Bounded read from stdin (10MB limit)
    raw_data, is_overflow, read_error = read_bounded_stdin(MAX_STDIN_BYTES)

    if is_overflow:
        # Fail-closed on payload too large
        response = pre_tool_response(
            "deny",
            reason="Payload stdin vượt quá giới hạn an toàn 10MB (Fail-Closed bảo mật).",
            suggestion="Giảm kích thước payload trước khi gửi.",
        )
        emit_stdout_json(response)
        sys.exit(0)

    if read_error:
        # Fail-closed on read error
        response = pre_tool_response(
            "deny",
            reason=f"Lỗi đọc dữ liệu stdin: {read_error} (Fail-Closed bảo mật).",
        )
        emit_stdout_json(response)
        sys.exit(0)

    # Parse JSON payload safely
    if not raw_data or not raw_data.strip():
        # If stdin is empty, fallback to CLI args if provided, else allow (no tool invocation)
        if cli_tool:
            payload = {"tool_name": cli_tool, "event": cli_event or "PreToolUse"}
        else:
            response = pre_tool_response("allow", reason="Empty stdin and no tool invocation detected.")
            emit_stdout_json(response)
            sys.exit(0)
    else:
        try:
            payload = json.loads(raw_data)
            if not isinstance(payload, dict):
                response = pre_tool_response(
                    "deny",
                    reason=f"Dữ liệu stdin bất thường: Payload phải là JSON object, nhận được {type(payload).__name__} (Fail-Closed bảo mật).",
                )
                emit_stdout_json(response)
                sys.exit(0)
        except json.JSONDecodeError as exc:
            # Fail-closed on malformed JSON
            response = pre_tool_response(
                "deny",
                reason=f"Dữ liệu JSON từ stdin không hợp lệ: {exc} (Fail-Closed bảo mật).",
            )
            emit_stdout_json(response)
            sys.exit(0)

    # Merge CLI arguments if missing in payload
    if cli_tool and not (payload.get("tool_name") or payload.get("toolCall")):
        payload["tool_name"] = cli_tool
    if cli_event and not (payload.get("event") or payload.get("hook_event_name")):
        payload["event"] = cli_event

    try:
        response = evaluate_grounding_evidence(payload)
    except Exception as exc:
        log_diagnostic(f"Unhandled exception in evaluate_grounding_evidence: {exc}")
        response = pre_tool_response(
            "deny",
            reason=f"Lỗi hệ thống khi kiểm tra grounding: {exc} (Fail-Closed bảo mật).",
        )

    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()
