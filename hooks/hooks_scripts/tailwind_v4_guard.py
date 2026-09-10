#!/usr/bin/env python3
"""tailwind_v4_guard.py — PreToolUse Hook to Enforce Tailwind CSS v4 CSS-First Architecture.

Enforces §TAILWIND-V4:
1. Intercepts write_to_file, replace_file_content, multi_replace_file_content.
2. Hard blocks creating or modifying legacy JavaScript/TypeScript configuration files:
   - tailwind.config.js
   - tailwind.config.ts
   - tailwind.config.mjs
   - tailwind.config.cjs
3. Guides developer toward Tailwind CSS v4 CSS-First architecture using `@theme`.
4. Supports `--self-test` mode returning exit code 0.
"""

from __future__ import annotations

import io
import json
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

BANNED_CONFIG_FILES: frozenset[str] = frozenset({
    "tailwind.config.js",
    "tailwind.config.ts",
    "tailwind.config.mjs",
    "tailwind.config.cjs",
})


def extract_target_path(args: dict[str, Any]) -> str | None:
    """Extract raw target file path from tool arguments."""
    for k in TARGET_PATH_KEYS:
        val = args.get(k)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def evaluate_tailwind_v4(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate whether action attempts to use legacy Tailwind config files."""
    if not isinstance(payload, dict):
        return pre_tool_response("allow", "Payload is not a dictionary.")

    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""

    if tool_name not in MONITORED_TOOLS:
        return pre_tool_response("allow", f"Tool '{tool_name}' is not monitored for Tailwind v4.")

    args = get_tool_args(tool_call)
    raw_target = extract_target_path(args)
    if not raw_target:
        return pre_tool_response("allow", "No target file found in tool args.")

    target_name = pathlib.Path(raw_target).name.lower()

    if target_name in BANNED_CONFIG_FILES:
        reason = (
            f"❌ CHẶN CẤU HÌNH LỖI THỜI (§TAILWIND-V4): Phát hiện hành vi tạo/sửa file '{target_name}'.\n\n"
            "Tailwind CSS v4 đã loại bỏ hoàn toàn mô hình JavaScript/TypeScript configuration file "
            "(`tailwind.config.js/ts/mjs/cjs`).\n\n"
            "Kiến trúc v4 chuyển sang chuẩn **CSS-First Configuration**:\n"
            "1. Nhập Tailwind CSS trong file CSS chính (vd: `src/index.css` hoặc `src/app.css`):\n"
            "   ```css\n"
            "   @import \"tailwindcss\";\n\n"
            "   @theme {\n"
            "     --color-primary: #2563eb;\n"
            "     --color-secondary: #475569;\n"
            "     --font-sans: 'Inter', system-ui, sans-serif;\n"
            "   }\n"
            "   ```\n"
            "2. Khai báo các utility tùy biến bằng `@utility` hoặc `@variant` trực tiếp trong file CSS.\n"
            "3. Tích hợp bundler hiện đại qua `@tailwindcss/vite` (trong `vite.config.ts`) "
            "hoặc `@tailwindcss/postcss`.\n\n"
            f"Hành động bắt buộc: Không tạo file `{target_name}`, xóa nếu đã tạo và chuyển toàn bộ "
            "cấu hình sang cú pháp `@theme` trong file CSS."
        )
        log_diagnostic(f"DENIED legacy Tailwind config creation: {raw_target}")
        return pre_tool_response("deny", reason)

    return pre_tool_response("allow", f"File '{raw_target}' conforms to modern architecture.")


def run_self_tests() -> bool:
    """Self-test runner for tailwind_v4_guard."""
    print("======================================================================")
    print("Running Tailwind CSS v4 Guard Self-Test Suite")
    print("======================================================================\n")

    test_results: list[tuple[str, bool, str]] = []

    def record(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        test_results.append((name, passed, detail))
        print(f"[{status}] {name}{f' - {detail}' if detail and not passed else ''}")

    # TC1: Deny tailwind.config.js
    r1 = evaluate_tailwind_v4({
        "toolCall": {
            "name": "write_to_file",
            "args": {"TargetFile": "frontend/tailwind.config.js", "CodeContent": "module.exports = {}"},
        },
    })
    record("TC1: Deny tailwind.config.js", r1.get("decision") == "deny" and "TAILWIND-V4" in r1.get("reason", ""))

    # TC2: Deny tailwind.config.ts
    r2 = evaluate_tailwind_v4({
        "toolCall": {
            "name": "write_to_file",
            "args": {"TargetFile": "src/tailwind.config.ts", "CodeContent": "export default {}"},
        },
    })
    record("TC2: Deny tailwind.config.ts", r2.get("decision") == "deny")

    # TC3: Deny tailwind.config.mjs
    r3 = evaluate_tailwind_v4({
        "toolCall": {
            "name": "replace_file_content",
            "args": {"TargetFile": "tailwind.config.mjs", "ReplacementContent": "export default {}"},
        },
    })
    record("TC3: Deny tailwind.config.mjs", r3.get("decision") == "deny")

    # TC4: Deny tailwind.config.cjs
    r4 = evaluate_tailwind_v4({
        "toolCall": {
            "name": "multi_replace_file_content",
            "args": {"TargetFile": "tailwind.config.cjs", "Replacements": []},
        },
    })
    record("TC4: Deny tailwind.config.cjs", r4.get("decision") == "deny")

    # TC5: Allow modern app.css with @theme
    r5 = evaluate_tailwind_v4({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/app.css",
                "CodeContent": '@import "tailwindcss";\n@theme {\n  --color-brand: #ff0000;\n}',
            },
        },
    })
    record("TC5: Allow modern app.css with @theme", r5.get("decision") == "allow")

    # TC6: Allow vite.config.ts
    r6 = evaluate_tailwind_v4({
        "toolCall": {
            "name": "write_to_file",
            "args": {"TargetFile": "vite.config.ts", "CodeContent": "import tailwindcss from '@tailwindcss/vite'"},
        },
    })
    record("TC6: Allow vite.config.ts", r6.get("decision") == "allow")

    # TC7: Allow non-monitored tool (run_command)
    r7 = evaluate_tailwind_v4({
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "npm install tailwindcss @tailwindcss/vite"},
        },
    })
    record("TC7: Allow non-monitored tool (run_command)", r7.get("decision") == "allow")

    # TC8: Malformed payload safety fallback
    r8 = evaluate_tailwind_v4({})
    record("TC8: Malformed payload safety fallback", r8.get("decision") == "allow")

    # TC9: Subprocess streaming execution
    proc = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).resolve())],
        input=json.dumps({
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "frontend/tailwind.config.js"},
            },
        }),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    sub_out = json.loads(proc.stdout) if proc.stdout.strip() else {}
    record("TC9: Subprocess streaming execution returns deny", proc.returncode == 0 and sub_out.get("decision") == "deny")

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
    response = evaluate_tailwind_v4(payload)
    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()
