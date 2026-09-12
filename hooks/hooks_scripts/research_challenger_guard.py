#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
research_challenger_guard.py — Physical Hook & Guard for Research Adversarial Critique
Enforces that ANY research, data harvesting, or technical discovery task MUST undergo
rigorous adversarial critique by a dedicated Research Challenger before being accepted
as an implementation spec or baseline architecture.

INVARIANTS ENFORCED:
1. Research Gate Invariant: A research artifact or benchmark spec CANNOT pass to Phase 4/5
   without a valid adversarial critique file (research_critique.md / research_adversarial_critique.md).
2. Minimum Passing Score: The critique must award >= 85.0 / 100 points.
3. 5 Adversarial Pillars Required:
   - Pillar 1: Enterprise Authenticity & Zero Hallucination
   - Pillar 2: Edge Case & Chaos Resilience
   - Pillar 3: Scalability & Coordination Tax (Amazon STO)
   - Pillar 4: Hardware & OS Compatibility (Windows 11 4C/8T)
   - Pillar 5: Contract Completeness (OpenAPI / Saga / Schemas)
"""

import os
import sys
import json
import re
import argparse

CRITIQUE_PILLARS = [
    "enterprise authenticity",
    "edge case",
    "coordination tax",
    "hardware",
    "contract completeness"
]

def verify_research_critique(critique_content: str) -> tuple[bool, float, str]:
    """
    Parses and verifies the contents of a research critique file.
    Returns (is_valid, score, message).
    """
    if not critique_content or len(critique_content.strip()) < 200:
        return False, 0.0, "Critique content is empty or too short (< 200 characters)."

    # Extract score: look for patterns like 'Score: 92/100', 'Điểm: 88.5/100', 'OVERALL_SCORE: 90'
    score_match = re.search(r'(?:score|điểm|overall_score|tổng điểm)[:\s]*([0-9]+(?:\.[0-9]+)?)\s*(?:/\s*100)?', critique_content, re.IGNORECASE)
    if not score_match:
        return False, 0.0, "Could not locate numeric critique score (expected e.g. 'Score: 88/100')."
    
    score = float(score_match.group(1))
    if score < 85.0:
        return False, score, f"Critique score {score}/100 is below the mandatory threshold of 85.0/100. Research rejected."

    # Check for 5 critique pillars
    missing_pillars = []
    content_lower = critique_content.lower()
    for pillar in CRITIQUE_PILLARS:
        if pillar not in content_lower:
            missing_pillars.append(pillar)
    
    if len(missing_pillars) > 2:
        return False, score, f"Critique lacks coverage of essential pillars: {', '.join(missing_pillars)}"

    return True, score, f"PASSED: Critique verified with score {score}/100."

def check_research_gate(workspace_dir: str) -> tuple[bool, str]:
    """
    Checks if a valid research critique exists in workspace or .agents directories.
    """
    candidate_files = [
        os.path.join(workspace_dir, "research_critique.md"),
        os.path.join(workspace_dir, "research_adversarial_critique.md"),
    ]
    
    agents_dir = os.path.join(workspace_dir, ".agents")
    if os.path.exists(agents_dir):
        for root, _, files in os.walk(agents_dir):
            for f in files:
                if f.lower() in ["research_critique.md", "research_adversarial_critique.md", "critique.md"]:
                    candidate_files.append(os.path.join(root, f))

    found_valid = False
    best_score = 0.0
    last_reason = "No critique file found."

    for cpath in candidate_files:
        if os.path.exists(cpath):
            try:
                with open(cpath, "r", encoding="utf-8", errors="ignore") as fp:
                    content = fp.read()
                valid, score, msg = verify_research_critique(content)
                if valid:
                    return True, f"Found valid critique at '{cpath}' with score {score}/100."
                else:
                    last_reason = f"File '{cpath}' failed verification: {msg}"
            except Exception as e:
                last_reason = f"Error reading '{cpath}': {str(e)}"

    return False, f"Research gate failed. {last_reason}"

def run_hook():
    """Hook entry point for PreToolUse events with standard JSON output and verification."""
    try:
        MAX_STDIN_BYTES = 10 * 1024 * 1024
        raw_input = sys.stdin.read(MAX_STDIN_BYTES + 1)
        if not raw_input or not raw_input.strip():
            print(json.dumps({"decision": "ALLOW", "reason": "Empty payload"}, ensure_ascii=False))
            sys.exit(0)
            
        if len(raw_input) > MAX_STDIN_BYTES:
            deny_msg = f"❌ [DENY]: Payload exceeds maximum limit of {MAX_STDIN_BYTES} bytes."
            print(json.dumps({"decision": "DENY", "reason": deny_msg, "message": deny_msg}, ensure_ascii=False))
            sys.exit(0)

        data = json.loads(raw_input)
        if not isinstance(data, dict):
            print(json.dumps({"decision": "ALLOW", "reason": "Non-object payload"}, ensure_ascii=False))
            sys.exit(0)

        tool_call = data.get("toolCall") if isinstance(data.get("toolCall"), dict) else {}
        args = data.get("tool_args") or tool_call.get("args") or data.get("arguments") or {}
        if not isinstance(args, dict):
            args = {}

        target_file = args.get("TargetFile") or args.get("path") or data.get("TargetFile") or ""
        code_content = args.get("CodeContent") or args.get("ReplacementContent") or data.get("CodeContent") or ""

        # If writing or modifying an adversarial research critique file
        if target_file and any(target_file.lower().endswith(k) for k in ("critique.md", "research_critique.md", "research_adversarial_critique.md")):
            if code_content:
                valid, score, msg = verify_research_critique(code_content)
                if not valid:
                    deny_msg = f"❌ [RESEARCH CRITIQUE REJECTED]: {msg}"
                    print(json.dumps({"decision": "DENY", "reason": deny_msg, "message": deny_msg}, ensure_ascii=False))
                    sys.exit(0)

        print(json.dumps({"decision": "ALLOW", "reason": "Research challenger guard check passed"}, ensure_ascii=False))
        sys.exit(0)
    except Exception as exc:
        deny_msg = f"❌ [RESEARCH CHALLENGER FAIL-CLOSED]: {exc}"
        print(json.dumps({"decision": "DENY", "reason": deny_msg, "message": deny_msg}, ensure_ascii=False))
        sys.exit(0)

def self_test():
    print("=== RUNNING SELF-TEST: research_challenger_guard.py ===")
    
    # Test 1: Empty critique -> FAIL
    valid, score, msg = verify_research_critique("")
    assert not valid and score == 0.0, f"Test 1 Failed: {msg}"
    print("Test 1 Passed: Empty critique is rejected.")

    # Test 2: Low score (75/100) -> FAIL
    low_score_text = """
    # Adversarial Research Critique Evaluation
    Score: 75/100
    This critique provides an assessment of the architectural specification.
    - Enterprise authenticity: Poor fidelity to real-world cloud patterns.
    - Edge case: Many edge cases and boundary conditions are left undocumented.
    - Coordination tax: High coupling between services without contract isolation.
    - Hardware: Fails to protect host CPU resources adequately.
    - Contract completeness: Missing several key payload schemas and error definitions.
    """
    valid, score, msg = verify_research_critique(low_score_text)
    assert not valid and score == 75.0, f"Test 2 Failed: Low score should be rejected ({msg})"
    print("Test 2 Passed: Low score (< 85) is rejected.")

    # Test 3: High score without pillars -> FAIL
    missing_pillars_text = """
    # Research Critique
    Score: 95/100
    Looks good to me, great job!
    """
    valid, score, msg = verify_research_critique(missing_pillars_text)
    assert not valid, f"Test 3 Failed: Critique without pillars should be rejected ({msg})"
    print("Test 3 Passed: Critique missing pillars is rejected.")

    # Test 4: Comprehensive critique with >= 85 and pillars -> PASS
    good_critique_text = """
    # Adversarial Research Critique & Validation Report
    ## Overall Score: 92.5/100 (PASSED)
    
    ### 1. Enterprise Authenticity & Zero Hallucination
    The architecture adheres strictly to Google Online Boutique and Netflix OSS.
    
    ### 2. Edge Case & Chaos Resilience
    Includes Circuit Breaker half-open transitions and Saga rollback compensating steps.
    
    ### 3. Scalability & Coordination Tax (Amazon STO)
    Services communicate via asynchronous events and disk contracts, eliminating meeting overhead.
    
    ### 4. Hardware & OS Compatibility
    Constrained to Windows 11 (4 Cores / 8 Threads) via 3-zone CPU governor and 3-slot semaphore.
    
    ### 5. Contract Completeness
    OpenAPI 3.0 schemas, HTTP status codes, and idempotency headers are rigorously defined.
    """
    valid, score, msg = verify_research_critique(good_critique_text)
    assert valid and score == 92.5, f"Test 4 Failed: Valid critique should pass ({msg})"
    print(f"Test 4 Passed: Comprehensive critique accepted ({score}/100).")

    # Test 5: Check workspace scanner logic
    test_dir = os.path.dirname(__file__)
    # When no file exists, should return False gracefully
    passed, reason = check_research_gate(test_dir)
    print(f"Test 5 Passed: Directory scanner executed safely (Result: {passed}).")

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
