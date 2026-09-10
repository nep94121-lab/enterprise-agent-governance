#!/usr/bin/env python3
"""dockerfile_security_guard.py — PreToolUse Hook to Enforce Non-Root Container Execution.

Enforces §DOCKERFILE-SECURITY & Least Privilege:
1. Intercepts write_to_file, replace_file_content, multi_replace_file_content on Dockerfile targets.
2. Inspects Dockerfile instructions for active `USER` directives.
3. Denies Dockerfiles that lack `USER` (running as root by default).
4. Denies Dockerfiles that explicitly specify `USER root` or `USER 0`.
5. Allows Dockerfiles with explicit non-root users (e.g., `USER appuser`, `USER node`, `USER 10001`).
6. Supports `--self-test` mode returning exit code 0.
"""

from __future__ import annotations

import io
import json
import pathlib
import re
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

MONITORED_TOOLS: frozenset[str] = frozenset({
    "write_to_file",
    "replace_file_content",
    "multi_replace_file_content",
})

TARGET_PATH_KEYS: tuple[str, ...] = (
    "TargetFile",
    "target_file",
    "filePath",
    "file_path",
    "path",
)

USER_DIRECTIVE_REGEX = re.compile(r"^\s*USER\s+([^\s#]+)", re.IGNORECASE)
FROM_DIRECTIVE_REGEX = re.compile(r"^\s*FROM\s+", re.IGNORECASE)
ROOT_USERS: frozenset[str] = frozenset({"root", "0"})


def extract_target_path(args: dict[str, Any]) -> str | None:
    """Extract raw target file path from tool arguments."""
    for k in TARGET_PATH_KEYS:
        val = args.get(k)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def is_dockerfile_target(target_path: str) -> bool:
    """Determine whether the target file is a Dockerfile."""
    basename = pathlib.Path(target_path).name.lower()
    return "dockerfile" in basename or basename.endswith(".dockerfile")


def extract_full_content(tool_name: str, args: dict[str, Any], raw_target: str) -> str:
    """Extract or simulate full file content for inspection."""
    if tool_name == "write_to_file":
        for k in ("CodeContent", "code_content", "content"):
            val = args.get(k)
            if isinstance(val, str):
                return val

    # For replace operations, attempt to simulate resulting file if original exists
    if tool_name in ("replace_file_content", "multi_replace_file_content"):
        target_path = pathlib.Path(raw_target)
        if target_path.is_file():
            try:
                original = target_path.read_text(encoding="utf-8", errors="replace")
                if tool_name == "replace_file_content":
                    target_content = args.get("TargetContent", "")
                    replacement = args.get("ReplacementContent", "")
                    if target_content in original:
                        return original.replace(target_content, replacement, 1)
            except Exception as exc:
                log_diagnostic(f"Could not simulate file modification: {exc}")

        # Fallback to replacement content
        for k in ("ReplacementContent", "replacement_content", "CodeContent", "content"):
            val = args.get(k)
            if isinstance(val, str):
                return val

    return ""


def check_dockerfile_user(content: str) -> tuple[bool, str]:
    """Inspect Dockerfile content for Least Privilege non-root USER directive.

    Returns (is_allowed, reason_or_detail).
    """
    lines = content.splitlines()

    # Split into stages by FROM directives
    stages: list[list[str]] = [[]]
    for line in lines:
        clean = line.strip()
        if clean.startswith("#"):
            continue
        if FROM_DIRECTIVE_REGEX.match(clean):
            stages.append([])
        stages[-1].append(clean)

    # Use the final stage (the runtime image stage), or all lines if no FROM
    target_stage = stages[-1] if len(stages) > 1 else lines

    # Find all USER directives in the target stage
    active_users: list[tuple[int, str]] = []
    for line_idx, line in enumerate(target_stage, start=1):
        clean = line.strip()
        if clean.startswith("#"):
            continue
        match = USER_DIRECTIVE_REGEX.match(clean)
        if match:
            active_users.append((line_idx, match.group(1).strip()))

    if not active_users:
        return (
            False,
            "Dockerfile không khai báo chỉ thị `USER`. Container sẽ chạy với quyền `root` (UID 0) mặc định."
        )

    # Evaluate the last active USER directive in the runtime stage
    last_line_idx, last_user = active_users[-1]
    # Handle user:group syntax (e.g., 'root:root', 'appuser:appgroup', '1000:1000')
    user_name = last_user.split(":")[0].strip().lower()

    if user_name in ROOT_USERS:
        return (
            False,
            f"Chỉ thị `USER {last_user}` (dòng {last_line_idx}) chỉ định chạy với quyền Root / UID 0."
        )

    return (True, f"Chỉ thị `USER {last_user}` hợp lệ (non-root).")


def evaluate_dockerfile_security(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate whether Dockerfile conforms to Least Privilege security requirements."""
    if not isinstance(payload, dict):
        return pre_tool_response("allow", "Payload is not a dictionary.")

    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""

    if tool_name not in MONITORED_TOOLS:
        return pre_tool_response("allow", f"Tool '{tool_name}' is not monitored for Dockerfile security.")

    args = get_tool_args(tool_call)
    raw_target = extract_target_path(args)
    if not raw_target:
        return pre_tool_response("allow", "No target file found in tool args.")

    if not is_dockerfile_target(raw_target):
        return pre_tool_response("allow", f"File '{raw_target}' is not a Dockerfile.")

    content = extract_full_content(tool_name, args, raw_target)
    if not content:
        return pre_tool_response("allow", "No inspectable Dockerfile content provided in tool args.")

    is_allowed, detail = check_dockerfile_user(content)
    if is_allowed:
        return pre_tool_response("allow", f"Dockerfile security check passed for '{raw_target}': {detail}")

    reason = (
        f"❌ CHẶN BẢO MẬT CONTAINER (§DOCKERFILE-SECURITY / LEAST PRIVILEGE):\n"
        f"Phát hiện cấu hình container vi phạm an ninh trong '{raw_target}':\n"
        f"  - Chi tiết: {detail}\n\n"
        "Nguy cơ an ninh:\n"
        "Chạy tiến trình trong container dưới quyền root (UID 0) cho phép kẻ tấn công dễ dàng "
        "thực hiện Container Breakout (thoát khỏi sandbox container) và chiếm quyền điều khiển "
        "máy chủ Host (Host Takeover) khi có lỗ hổng bảo mật trong ứng dụng.\n\n"
        "Hướng dẫn khắc phục bắt buộc:\n"
        "1. Tạo tài khoản người dùng thông thường và khai báo chỉ thị `USER [tên_user]`:\n"
        "   ```dockerfile\n"
        "   # Ví dụ cho Debian/Ubuntu:\n"
        "   RUN groupadd -r appgroup && useradd -r -g appgroup -s /bin/false appuser\n"
        "   USER appuser\n"
        "   ```\n"
        "   ```dockerfile\n"
        "   # Ví dụ cho Alpine Linux:\n"
        "   RUN addgroup -S appgroup && adduser -S appuser -G appgroup\n"
        "   USER appuser\n"
        "   ```\n"
        "2. Đảm bảo chỉ thị `USER [non-root]` nằm ở stage cuối cùng trước lệnh `ENTRYPOINT` hoặc `CMD`."
    )
    log_diagnostic(f"DENIED root Dockerfile in {raw_target}: {detail}")
    return pre_tool_response("deny", reason)


def run_self_tests() -> bool:
    """Self-test runner for dockerfile_security_guard."""
    print("======================================================================")
    print("Running Dockerfile Security Guard Self-Test Suite")
    print("======================================================================\n")

    test_results: list[tuple[str, bool, str]] = []

    def record(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        test_results.append((name, passed, detail))
        print(f"[{status}] {name}{f' - {detail}' if detail and not passed else ''}")

    # TC1: Deny Dockerfile without USER directive
    r1 = evaluate_dockerfile_security({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "Dockerfile",
                "CodeContent": "FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\nCMD [\"python\", \"app.py\"]",
            },
        },
    })
    record("TC1: Deny Dockerfile without USER directive", r1.get("decision") == "deny" and "không khai báo" in r1.get("reason", ""))

    # TC2: Deny Dockerfile with explicit USER root
    r2 = evaluate_dockerfile_security({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "deploy/Dockerfile.prod",
                "CodeContent": "FROM node:20-alpine\nWORKDIR /app\nUSER root\nCMD [\"node\", \"server.js\"]",
            },
        },
    })
    record("TC2: Deny Dockerfile with USER root", r2.get("decision") == "deny" and "Root" in r2.get("reason", ""))

    # TC3: Deny Dockerfile with USER 0
    r3 = evaluate_dockerfile_security({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "app.dockerfile",
                "CodeContent": "FROM alpine:3.19\nUSER 0:0\nCMD [\"sh\"]",
            },
        },
    })
    record("TC3: Deny Dockerfile with USER 0", r3.get("decision") == "deny")

    # TC4: Allow Dockerfile with valid non-root user
    r4 = evaluate_dockerfile_security({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "Dockerfile",
                "CodeContent": (
                    "FROM python:3.11-slim\n"
                    "RUN useradd -m appuser\n"
                    "WORKDIR /home/appuser\n"
                    "USER appuser\n"
                    "CMD [\"python\", \"app.py\"]"
                ),
            },
        },
    })
    record("TC4: Allow Dockerfile with USER appuser", r4.get("decision") == "allow")

    # TC5: Allow multi-stage Dockerfile where runtime stage has non-root USER
    r5 = evaluate_dockerfile_security({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "Dockerfile",
                "CodeContent": (
                    "FROM golang:1.22 AS builder\n"
                    "WORKDIR /build\n"
                    "COPY . .\n"
                    "RUN go build -o app .\n"
                    "FROM alpine:3.19\n"
                    "COPY --from=builder /build/app /app\n"
                    "USER 10001:10001\n"
                    "ENTRYPOINT [\"/app\"]"
                ),
            },
        },
    })
    record("TC5: Allow multi-stage with USER in runtime stage", r5.get("decision") == "allow")

    # TC6: Deny multi-stage Dockerfile where builder has USER but runtime forgot USER
    r6 = evaluate_dockerfile_security({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "Dockerfile",
                "CodeContent": (
                    "FROM golang:1.22 AS builder\n"
                    "USER builduser\n"
                    "RUN go build\n"
                    "FROM alpine:3.19\n"
                    "COPY --from=builder /app /app\n"
                    "CMD [\"./app\"]"
                ),
            },
        },
    })
    record("TC6: Deny multi-stage when runtime stage lacks USER", r6.get("decision") == "deny")

    # TC7: Deny commented out USER
    r7 = evaluate_dockerfile_security({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "Dockerfile",
                "CodeContent": "FROM alpine:3.19\n# USER appuser\nCMD [\"sh\"]",
            },
        },
    })
    record("TC7: Deny commented out # USER", r7.get("decision") == "deny")

    # TC8: Allow non-Dockerfile targets (e.g. docker-compose.yml)
    r8 = evaluate_dockerfile_security({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "docker-compose.yml",
                "CodeContent": "version: '3.8'\nservices:\n  web:\n    image: nginx",
            },
        },
    })
    record("TC8: Allow non-Dockerfile targets", r8.get("decision") == "allow")

    # TC9: Allow non-monitored tool (run_command)
    r9 = evaluate_dockerfile_security({
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "docker build -t app ."},
        },
    })
    record("TC9: Allow non-monitored tool (run_command)", r9.get("decision") == "allow")

    # TC10: Subprocess streaming execution
    proc = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).resolve())],
        input=json.dumps({
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": "Dockerfile",
                    "CodeContent": "FROM alpine\nCMD [\"sh\"]",
                },
            },
        }),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    sub_out = json.loads(proc.stdout) if proc.stdout.strip() else {}
    record("TC10: Subprocess streaming execution returns deny", proc.returncode == 0 and sub_out.get("decision") == "deny")

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
    response = evaluate_dockerfile_security(payload)
    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()
