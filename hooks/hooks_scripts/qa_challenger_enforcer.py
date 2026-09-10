#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qa_challenger_enforcer.py — Physical Hook & Guard for QA Adversarial Testing
Enforces high-integrity testing standards across all microservices and worker domains.
Operates under the authority of pm_qa_challenger / QA Challenger.
"""

import os
import sys
import ast
import json
import argparse
import re

DUMMY_PATTERNS = [
    r'assert\s+True\b',
    r'assert\s+1\s*==\s*1',
    r'assert\s+not\s+False\b',
    r'assert\s+"test"\s*==\s*"test"'
]

MOCK_PATTERNS = [
    r'unittest\.mock',
    r'mocker\.patch',
    r'@patch'
]

def audit_test_source(code_content: str, filename: str = "test.py") -> tuple[bool, list[str]]:
    """
    Audits Python test code AST to ensure authentic assertions and zero dummy testing.
    """
    issues = []

    # Enforce minimum 120 lines
    lines = code_content.splitlines()
    if len(lines) < 120:
        issues.append(f"Test file {filename} is < 120 lines ({len(lines)} lines). Requires comprehensive testing >= 120 lines.")

    # Check regex dummy patterns
    for pattern in DUMMY_PATTERNS:
        if re.search(pattern, code_content):
            issues.append(f"Dummy assertion detected matching pattern '{pattern}' in {filename}.")

    # Check regex mock patterns (giả lập ảo)
    for pattern in MOCK_PATTERNS:
        if re.search(pattern, code_content):
            issues.append(f"Virtual mocking (giả lập ảo) detected matching '{pattern}' in {filename}. Real adversarial tests must not mock.")

    try:
        tree = ast.parse(code_content, filename=filename)
    except SyntaxError as e:
        return False, [f"Syntax error in test code: {str(e)}"]

    test_funcs = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")]
    if not test_funcs:
        if "test" in filename.lower():
            issues.append(f"No test functions starting with 'test_' found in {filename}.")
        return len(issues) == 0, issues

    for fn in test_funcs:
        body_stmts = [s for s in fn.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str))]
        if not body_stmts or (len(body_stmts) == 1 and isinstance(body_stmts[0], ast.Pass)):
            issues.append(f"Empty test function '{fn.name}' in {filename} (contains only pass or docstring).")
            continue

        has_assert = False
        for subnode in ast.walk(fn):
            if isinstance(subnode, ast.Assert):
                has_assert = True
                break
            if isinstance(subnode, ast.With):
                for item in subnode.items:
                    if isinstance(item.context_expr, ast.Call):
                        func = item.context_expr.func
                        if (isinstance(func, ast.Attribute) and func.attr == "raises") or \
                           (isinstance(func, ast.Name) and func.id == "raises"):
                            has_assert = True
                            break
            if has_assert:
                break

        if not has_assert:
            issues.append(f"Test function '{fn.name}' in {filename} contains no assertions or exception checks.")

    return len(issues) == 0, issues

def run_hook():
    """Hook entry point"""
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            sys.exit(0)

        payload = json.loads(raw_input)

        args = payload.get('tool_args') or payload.get('toolCall', {}).get('args') or payload.get('arguments', payload.get('kwargs', {}))

        target_file = args.get("TargetFile") or args.get("path") or ""
        code_content = args.get("CodeContent", args.get("ReplacementContent", ""))

        if not code_content or not target_file:
            sys.exit(0)

        if "test" in target_file.lower() and target_file.endswith(".py"):
            ok, issues = audit_test_source(code_content, target_file)
            if not ok:
                print(f"DENY: " + " | ".join(issues))
                sys.exit(1)

    except Exception:
        sys.exit(0)
    sys.exit(0)

def self_test():
    print("=== RUNNING SELF-TEST: qa_challenger_enforcer.py ===")

    # Test 1: Dummy assertion 'assert True' -> FAIL
    dummy_code = "\n" * 125 + """
def test_foo():
    assert True
"""
    ok, issues = audit_test_source(dummy_code, "test_dummy.py")
    assert not ok and any("Dummy assertion detected" in iss for iss in issues), f"Test 1 Failed: {issues}"
    print("Test 1 Passed: 'assert True' dummy assertion successfully intercepted.")

    # Test 2: Empty test function with only pass -> FAIL
    empty_code = "\n" * 125 + """
def test_bar():
    '''This is a placeholder'''
    pass
"""
    ok, issues = audit_test_source(empty_code, "test_empty.py")
    assert not ok and any("Empty test function" in iss for iss in issues), f"Test 2 Failed: {issues}"
    print("Test 2 Passed: Empty test function successfully intercepted.")

    # Test 3: Line length < 120 -> FAIL
    short_code = """
def test_auth_login():
    response = {"status": 200, "token": "jwt_token_valid"}
    assert response["status"] == 200
"""
    ok, issues = audit_test_source(short_code, "test_short.py")
    assert not ok and any("< 120 lines" in iss for iss in issues), f"Test 3 Failed: {issues}"
    print("Test 3 Passed: Test file < 120 lines successfully intercepted.")

    # Test 4: Mocking -> FAIL
    mock_code = "\n" * 125 + """
from unittest.mock import patch

def test_mocking():
    with patch('os.path.exists', return_value=True):
        assert True
"""
    ok, issues = audit_test_source(mock_code, "test_mock.py")
    assert not ok and any("Virtual mocking" in iss for iss in issues), f"Test 4 Failed: {issues}"
    print("Test 4 Passed: Mocking detected and intercepted.")

    # Test 5: Authentic test -> PASS
    valid_code = "\n" * 125 + """
def test_auth_login():
    response = {"status": 200, "token": "jwt_token_valid"}
    assert response["status"] == 200
    assert len(response["token"]) > 0
"""
    ok, issues = audit_test_source(valid_code, "test_valid.py")
    assert ok and len(issues) == 0, f"Test 5 Failed: {issues}"
    print("Test 5 Passed: Authentic test suite passed with 0 issues.")

    print("\nALL 5 TESTS PASSED WITH 100% SUCCESS!")
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true", help="Run automated self-tests")
    args, _ = parser.parse_known_args()

    if args.self_test:
        sys.exit(self_test())
    else:
        run_hook()
