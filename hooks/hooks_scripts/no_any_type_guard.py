#!/usr/bin/env python3
r"""no_any_type_guard.py — PreToolUse Hook to Enforce Strict Typing in TypeScript/TSX.

Enforces §STRICT-TYPES:
1. Intercepts write_to_file, replace_file_content, multi_replace_file_content.
2. Checks .ts and .tsx files for insecure 'any' types:
   - `:\s*any\b`
   - `\bas\s+any\b`
   - `\bas\s+unknown\s+as\b`
3. Allows exception if commented with `// @allowed-any` or `/* @allowed-any */`
   on the same line or immediate preceding line.
4. Returns HARD DENY with actionable remediation advice.
5. Supports `--self-test` mode returning exit code 0.
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

TS_EXTENSIONS: tuple[str, ...] = (".ts", ".tsx")

VIOLATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("colon_any", re.compile(r":\s*any\b")),
    ("as_any", re.compile(r"\bas\s+any\b")),
    ("as_unknown_as", re.compile(r"\bas\s+unknown\s+as\b")),
]

ALLOW_COMMENT_PATTERN = re.compile(r"(?://|/\*)\s*@allowed-any")


def extract_target_path(args: dict[str, Any]) -> str | None:
    """Extract raw target file path from tool arguments."""
    for k in TARGET_PATH_KEYS:
        val = args.get(k)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def extract_new_content(tool_name: str, args: dict[str, Any]) -> str:
    """Extract proposed new content from tool arguments."""
    if tool_name == "write_to_file":
        for k in ("CodeContent", "code_content", "content"):
            val = args.get(k)
            if isinstance(val, str):
                return val
    elif tool_name == "replace_file_content":
        for k in ("ReplacementContent", "replacement_content", "content"):
            val = args.get(k)
            if isinstance(val, str):
                return val
    elif tool_name == "multi_replace_file_content":
        chunks: list[str] = []
        for k in ("Replacements", "replacements", "chunks"):
            val = args.get(k)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        c = item.get("ReplacementContent") or item.get("replacement_content") or item.get("content")
                        if isinstance(c, str):
                            chunks.append(c)
                    elif isinstance(item, str):
                        chunks.append(item)
        if chunks:
            return "\n".join(chunks)
        val = args.get("ReplacementContent") or args.get("CodeContent")
        if isinstance(val, str):
            return val
    return ""


def check_ts_content_for_any(content: str) -> list[dict[str, Any]]:
    """Scan TypeScript content line by line for illegal 'any' usage."""
    violations: list[dict[str, Any]] = []
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        # Check if line matches any violation pattern
        matching_patterns: list[str] = []
        for pattern_name, regex in VIOLATION_PATTERNS:
            if regex.search(line):
                matching_patterns.append(pattern_name)

        if not matching_patterns:
            continue

        # Check if line or previous line has @allowed-any exception
        has_exception_same_line = bool(ALLOW_COMMENT_PATTERN.search(line))
        has_exception_prev_line = False
        if i > 1 and i - 2 < len(lines):
            prev_line = lines[i - 2]
            has_exception_prev_line = bool(ALLOW_COMMENT_PATTERN.search(prev_line))

        if has_exception_same_line or has_exception_prev_line:
            continue

        violations.append({
            "line_number": i,
            "line_content": line.strip(),
            "patterns": matching_patterns,
        })

    return violations


def evaluate_no_any(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate whether TypeScript modification introduces unsafe 'any'."""
    if not isinstance(payload, dict):
        return pre_tool_response("allow", "Payload is not a dictionary.")

    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""

    if tool_name not in MONITORED_TOOLS:
        return pre_tool_response("allow", f"Tool '{tool_name}' is not monitored for strict typing.")

    args = get_tool_args(tool_call)
    raw_target = extract_target_path(args)
    if not raw_target:
        return pre_tool_response("allow", "No target file found in tool args.")

    # Check if target is a TypeScript file (.ts or .tsx)
    norm_path = raw_target.lower().replace("\\", "/")
    is_ts = any(norm_path.endswith(ext) for ext in TS_EXTENSIONS)
    if not is_ts:
        return pre_tool_response("allow", f"File '{raw_target}' is not a TypeScript (.ts/.tsx) file.")

    content = extract_new_content(tool_name, args)
    if not content:
        return pre_tool_response("allow", "No inspectable content provided in tool args.")

    violations = check_ts_content_for_any(content)
    if not violations:
        return pre_tool_response("allow", f"TypeScript strict typing check passed for '{raw_target}'.")

    # Construct actionable failure reason
    details = "\n".join(
        f"  - Dòng {v['line_number']}: `{v['line_content']}` (Mẫu: {', '.join(v['patterns'])})"
        for v in violations[:5]
    )
    if len(violations) > 5:
        details += f"\n  ... và {len(violations) - 5} vị trí vi phạm khác."

    reason = (
        f"❌ CHẶN BẢO MẬT TYPE (§STRICT-TYPES): Phát hiện sử dụng kiểu 'any' không an toàn trong '{raw_target}':\n"
        f"{details}\n\n"
        "Quy chuẩn TypeScript Strict Typing nghiêm cấm 'any', 'as any' và 'as unknown as'.\n"
        "Hướng xử lý bắt buộc:\n"
        "1. Định nghĩa interface / type cụ thể hoặc dùng generic type.\n"
        "2. Sử dụng 'unknown' kết hợp type narrowing (typeof, instanceof, Zod schema validation).\n"
        "3. Nếu bắt buộc phải dùng cho thư viện bên thứ 3 thiếu type definition, thêm comment:\n"
        "   `// @allowed-any: [lý do kỹ thuật rõ ràng]` trên cùng dòng hoặc dòng ngay phía trên."
    )
    log_diagnostic(f"DENIED unsafe 'any' in {raw_target} ({len(violations)} violations).")
    return pre_tool_response("deny", reason)


def run_self_tests() -> bool:
    """Self-test runner for no_any_type_guard."""
    print("======================================================================")
    print("Running No Any Type Guard Self-Test Suite")
    print("======================================================================\n")

    test_results: list[tuple[str, bool, str]] = []

    def record(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        test_results.append((name, passed, detail))
        print(f"[{status}] {name}{f' - {detail}' if detail and not passed else ''}")

    # TC1: Deny : any in .ts
    r1 = evaluate_no_any({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/services/api.ts",
                "CodeContent": "const processData = (data: any): void => {\n  console.log(data);\n};",
            },
        },
    })
    record("TC1: Deny ': any' parameter type", r1.get("decision") == "deny" and "colon_any" in r1.get("reason", ""))

    # TC2: Deny 'as any' type assertion
    r2 = evaluate_no_any({
        "toolCall": {
            "name": "replace_file_content",
            "args": {
                "TargetFile": "src/components/UserCard.tsx",
                "ReplacementContent": "const user = rawResponse as any;\nreturn <div>{user.name}</div>;",
            },
        },
    })
    record("TC2: Deny 'as any' cast", r2.get("decision") == "deny" and "as_any" in r2.get("reason", ""))

    # TC3: Deny 'as unknown as' double casting
    r3 = evaluate_no_any({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/utils/parser.ts",
                "CodeContent": "const result = payload as unknown as TargetType;",
            },
        },
    })
    record("TC3: Deny 'as unknown as' escape hatch", r3.get("decision") == "deny" and "as_unknown_as" in r3.get("reason", ""))

    # TC4: Allow with comment on same line
    r4 = evaluate_no_any({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/legacy/bridge.ts",
                "CodeContent": "const legacyObj: any = window.legacySdk; // @allowed-any: untyped legacy SDK",
            },
        },
    })
    record("TC4: Allow with '// @allowed-any' on same line", r4.get("decision") == "allow")

    # TC5: Allow with comment on preceding line
    r5 = evaluate_no_any({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/legacy/bridge.ts",
                "CodeContent": "// @allowed-any: 3rd-party webhook\nconst raw = req.body as any;",
            },
        },
    })
    record("TC5: Allow with comment on preceding line", r5.get("decision") == "allow")

    # TC6: Allow with block comment
    r6 = evaluate_no_any({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/test.tsx",
                "CodeContent": "/* @allowed-any */ const mock: any = {};",
            },
        },
    })
    record("TC6: Allow with block comment /* @allowed-any */", r6.get("decision") == "allow")

    # TC7: Allow valid strict TypeScript
    r7 = evaluate_no_any({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/models/user.ts",
                "CodeContent": "interface User {\n  id: string;\n  age: number;\n  metadata: Record<string, unknown>;\n}",
            },
        },
    })
    record("TC7: Allow valid strict TypeScript code", r7.get("decision") == "allow")

    # TC8: Allow non-TS file even with any
    r8 = evaluate_no_any({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/python_service.py",
                "CodeContent": "def test(val: Any) -> None:\n    pass",
            },
        },
    })
    record("TC8: Allow non-TypeScript file (.py)", r8.get("decision") == "allow")

    # TC9: Allow non-monitored tools
    r9 = evaluate_no_any({
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "npm run build"},
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
                    "TargetFile": "src/app.ts",
                    "CodeContent": "let val: any = 123;",
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
    response = evaluate_no_any(payload)
    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()
