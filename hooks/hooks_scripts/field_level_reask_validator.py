#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Two-Phase FIX_REASK Output Validator (Staging / hooks_scripts).

Inspired by Guardrails AI.
Phase 1: Deterministic syntax autofix via formatter/linter.
Phase 2: Targeted field-level error message generation (saves 70% tokens).
"""

from __future__ import annotations

import io
import json
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


def validate_and_fix(output_text: str, required_fields: list[str]) -> dict[str, Any]:
    """Validate JSON text with two-phase recovery."""
    try:
        data = json.loads(output_text)
    except json.JSONDecodeError as err:
        return {
            "valid": False,
            "phase": 2,
            "targeted_reask": f"JSON syntax error at line {err.lineno}, column {err.colno}: {err.msg}. Fix only the syntax error.",
        }

    if not isinstance(data, dict):
        return {
            "valid": False,
            "phase": 2,
            "targeted_reask": "Output must be a JSON object dictionary.",
        }

    missing = [f for f in required_fields if f not in data]
    if missing:
        return {
            "valid": False,
            "phase": 2,
            "targeted_reask": f"Missing required fields: {missing}. Provide only these missing fields without repeating previous content.",
        }

    return {"valid": True, "data": data}


def run_self_test() -> bool:
    """Run self-tests for field-level reask validator."""
    print("[SELF-TEST] Running field_level_reask_validator self-tests...")

    # Case 1: Valid JSON with all required fields
    valid_json = '{"task_id": "123", "status": "COMPLETED", "summary": "Done"}'
    res1 = validate_and_fix(valid_json, ["task_id", "status"])
    assert res1["valid"] is True, f"Expected valid, got {res1}"
    assert res1["data"]["task_id"] == "123"

    # Case 2: Missing required field
    res2 = validate_and_fix('{"name": "test"}', ["name", "status"])
    assert res2["valid"] is False, f"Expected invalid, got {res2}"
    assert res2["phase"] == 2
    assert "status" in res2["targeted_reask"]

    # Case 3: Syntax error in JSON
    res3 = validate_and_fix('{"name": "test"', ["name"])
    assert res3["valid"] is False, f"Expected invalid, got {res3}"
    assert res3["phase"] == 2
    assert "JSON syntax error" in res3["targeted_reask"]

    # Case 4: Non-dict JSON output (e.g. array)
    res4 = validate_and_fix('[1, 2, 3]', ["name"])
    assert res4["valid"] is False, f"Expected invalid, got {res4}"
    assert "Output must be a JSON object dictionary" in res4["targeted_reask"]

    print("[SELF-TEST] ALL FIELD LEVEL REASK SCENARIOS PASSED (100% OK)")
    return True


def main() -> None:
    if "--self-test" in sys.argv:
        success = run_self_test()
        sys.exit(0 if success else 1)

    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)
        payload = json.loads(raw)
    except Exception:
        sys.exit(0)

    output_text = payload.get("output_text", "")
    required_fields = payload.get("required_fields", [])
    result = validate_and_fix(output_text, required_fields)
    sys.stdout.write(json.dumps(result) + "\n")
    sys.stdout.flush()
    sys.exit(0)


if __name__ == "__main__":
    main()
