#!/usr/bin/env python3
"""ml_deserialization_guard.py — PreToolUse Hook to Prevent Insecure ML Deserialization (RCE).

Enforces §ML-SECURITY & §CVE-DESERIALIZATION:
1. Intercepts write_to_file, replace_file_content, multi_replace_file_content on .py files.
2. Detects insecure `torch.load` calls:
   - Missing `weights_only=True` parameter.
   - Explicit `weights_only=False`.
3. Detects arbitrary code execution risks from `pickle.load` / `pickle.loads`.
4. Recommends safe loading via `weights_only=True` or SafeTensors (`safetensors.torch.load_file`).
5. Supports `--self-test` mode returning exit code 0.
"""

from __future__ import annotations

import ast
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

PICKLE_CALL_REGEX = re.compile(r"\b(?:pickle|_pickle|cPickle)\.loads?\s*\(", re.IGNORECASE)
TORCH_LOAD_REGEX = re.compile(r"\btorch(?:\.serialization)?\.load\s*\((.*?)\)", re.DOTALL)


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


def check_python_ast(content: str) -> list[str]:
    """Parse Python code with AST and check for deserialization risks."""
    violations: list[str] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        # Partial snippet or syntax error, caller should fallback to regex
        return []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Check for pickle.load or pickle.loads
        if isinstance(node.func, ast.Attribute):
            mod = ""
            if isinstance(node.func.value, ast.Name):
                mod = node.func.value.id
            if mod in ("pickle", "_pickle", "cPickle") and node.func.attr in ("load", "loads"):
                violations.append(
                    f"Dòng {node.lineno}: Sử dụng `{mod}.{node.func.attr}()` không an toàn cho mô hình ML (Nguy cơ RCE)."
                )

        # Check for torch.load(...)
        is_torch_load = False
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "load":
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "torch":
                    is_torch_load = True
                elif isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "serialization":
                    is_torch_load = True
        elif isinstance(node.func, ast.Name) and node.func.id == "load":
            # Potentially from torch import load
            pass

        if is_torch_load:
            has_weights_only_true = False
            has_weights_only_false = False
            for kw in node.keywords:
                if kw.arg == "weights_only":
                    if isinstance(kw.value, ast.Constant):
                        if kw.value.value is True:
                            has_weights_only_true = True
                        elif kw.value.value is False:
                            has_weights_only_false = True
                    else:
                        # Non-constant or variable, not strictly True
                        has_weights_only_false = True

            if has_weights_only_false:
                violations.append(
                    f"Dòng {node.lineno}: `torch.load()` có `weights_only=False` (Lỗ hổng Deserialization RCE nghiêm trọng)."
                )
            elif not has_weights_only_true:
                violations.append(
                    f"Dòng {node.lineno}: `torch.load()` thiếu tham số bắt buộc `weights_only=True`."
                )

    return violations


def check_python_regex(content: str) -> list[str]:
    """Fallback regex scanner for Python snippets or unparseable blocks."""
    violations: list[str] = []

    # 1. Check pickle
    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        if PICKLE_CALL_REGEX.search(line):
            violations.append(f"Dòng {i}: Phát hiện gọi hàm `{line.strip()}` tiềm ẩn nguy cơ Arbitrary Code Execution.")

    # 2. Check torch.load
    # Find occurrences of torch.load(...)
    for match in TORCH_LOAD_REGEX.finditer(content):
        args_str = match.group(1)
        # Check if weights_only=True is in args
        if re.search(r"\bweights_only\s*=\s*False\b", args_str):
            violations.append("Phát hiện `torch.load(...)` với `weights_only=False` (Nguy cơ RCE).")
        elif not re.search(r"\bweights_only\s*=\s*True\b", args_str):
            violations.append("Phát hiện `torch.load(...)` thiếu tham số bảo mật `weights_only=True`.")

    return violations


def scan_deserialization_violations(content: str) -> list[str]:
    """Scan Python content using AST first, fallback to regex if needed."""
    ast_violations = check_python_ast(content)
    if ast_violations:
        return ast_violations

    # If AST produced nothing, test if regex catches anything (handles snippets)
    return check_python_regex(content)


def evaluate_ml_deserialization(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate whether action introduces insecure ML deserialization."""
    if not isinstance(payload, dict):
        return pre_tool_response("allow", "Payload is not a dictionary.")

    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""

    if tool_name not in MONITORED_TOOLS:
        return pre_tool_response("allow", f"Tool '{tool_name}' is not monitored for ML deserialization.")

    args = get_tool_args(tool_call)
    raw_target = extract_target_path(args)
    if not raw_target:
        return pre_tool_response("allow", "No target file found in tool args.")

    # Only inspect Python files
    norm_path = raw_target.lower().replace("\\", "/")
    if not norm_path.endswith(".py"):
        return pre_tool_response("allow", f"File '{raw_target}' is not a Python script.")

    content = extract_new_content(tool_name, args)
    if not content:
        return pre_tool_response("allow", "No inspectable content provided in tool args.")

    violations = scan_deserialization_violations(content)
    if not violations:
        return pre_tool_response("allow", f"ML deserialization security check passed for '{raw_target}'.")

    details = "\n".join(f"  - {v}" for v in violations[:5])
    reason = (
        f"❌ CHẶN LỖ HỔNG AN NINH ML (§ML-SECURITY / CVE-DESERIALIZATION):\n"
        f"Phát hiện phương thức nạp mô hình không an toàn trong '{raw_target}':\n"
        f"{details}\n\n"
        "Nguy cơ an ninh:\n"
        "- `torch.load` mặc định sử dụng module `pickle` của Python, cho phép kẻ tấn công thực thi "
        "mã tùy ý (Arbitrary Code Execution / Remote Code Execution - RCE) qua các tệp checkpoint độc hại.\n"
        "- `pickle.load` / `pickle.loads` hoàn toàn không an toàn đối với dữ liệu không tin cậy.\n\n"
        "Hướng khắc phục bắt buộc:\n"
        "1. Đối với PyTorch weights (.pt / .pth / .bin): Bắt buộc truyền tham số `weights_only=True`:\n"
        "   ```python\n"
        "   checkpoint = torch.load('model.pt', map_location='cpu', weights_only=True)\n"
        "   ```\n"
        "2. Hoặc sử dụng định dạng hiện đại, an toàn tuyệt đối **SafeTensors** (Hugging Face / PyTorch standard):\n"
        "   ```python\n"
        "   from safetensors.torch import load_file\n"
        "   state_dict = load_file('model.safetensors')\n"
        "   ```"
    )
    log_diagnostic(f"DENIED insecure deserialization in {raw_target} ({len(violations)} violations).")
    return pre_tool_response("deny", reason)


def run_self_tests() -> bool:
    """Self-test runner for ml_deserialization_guard."""
    print("======================================================================")
    print("Running ML Deserialization Guard Self-Test Suite")
    print("======================================================================\n")

    test_results: list[tuple[str, bool, str]] = []

    def record(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        test_results.append((name, passed, detail))
        print(f"[{status}] {name}{f' - {detail}' if detail and not passed else ''}")

    # TC1: Deny torch.load without weights_only
    r1 = evaluate_ml_deserialization({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/models/loader.py",
                "CodeContent": "import torch\nmodel = torch.load('model.pt')",
            },
        },
    })
    record("TC1: Deny torch.load without weights_only", r1.get("decision") == "deny" and "weights_only=True" in r1.get("reason", ""))

    # TC2: Deny torch.load with weights_only=False
    r2 = evaluate_ml_deserialization({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/models/loader.py",
                "CodeContent": "import torch\nmodel = torch.load('model.pt', weights_only=False)",
            },
        },
    })
    record("TC2: Deny torch.load with weights_only=False", r2.get("decision") == "deny")

    # TC3: Allow torch.load with weights_only=True
    r3 = evaluate_ml_deserialization({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/models/loader.py",
                "CodeContent": "import torch\nmodel = torch.load('model.pt', map_location='cpu', weights_only=True)",
            },
        },
    })
    record("TC3: Allow torch.load with weights_only=True", r3.get("decision") == "allow")

    # TC4: Deny pickle.load
    r4 = evaluate_ml_deserialization({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/utils/serialization.py",
                "CodeContent": "import pickle\nwith open('model.pkl', 'rb') as f:\n    obj = pickle.load(f)",
            },
        },
    })
    record("TC4: Deny pickle.load", r4.get("decision") == "deny" and "pickle" in r4.get("reason", ""))

    # TC5: Deny pickle.loads
    r5 = evaluate_ml_deserialization({
        "toolCall": {
            "name": "replace_file_content",
            "args": {
                "TargetFile": "src/utils/serialization.py",
                "ReplacementContent": "data = pickle.loads(raw_bytes)",
            },
        },
    })
    record("TC5: Deny pickle.loads", r5.get("decision") == "deny")

    # TC6: Allow SafeTensors
    r6 = evaluate_ml_deserialization({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/models/safe_loader.py",
                "CodeContent": "from safetensors.torch import load_file\nweights = load_file('model.safetensors')",
            },
        },
    })
    record("TC6: Allow SafeTensors load_file", r6.get("decision") == "allow")

    # TC7: Allow non-Python file
    r7 = evaluate_ml_deserialization({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/inference.ts",
                "CodeContent": "const res = torch.load('model.pt');",
            },
        },
    })
    record("TC7: Allow non-Python file (.ts)", r7.get("decision") == "allow")

    # TC8: Allow non-monitored tool (run_command)
    r8 = evaluate_ml_deserialization({
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "python -m pytest tests/"},
        },
    })
    record("TC8: Allow non-monitored tool (run_command)", r8.get("decision") == "allow")

    # TC9: Subprocess streaming execution
    proc = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).resolve())],
        input=json.dumps({
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": "src/test_ml.py",
                    "CodeContent": "import torch\nx = torch.load('data.bin')",
                },
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
    response = evaluate_ml_deserialization(payload)
    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()
