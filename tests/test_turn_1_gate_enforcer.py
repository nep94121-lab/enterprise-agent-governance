#!/usr/bin/env python3
"""Automated Test Suite for turn_1_gate_enforcer Hook.

Validates the Zero-Tolerance Turn-1 Action Gate:
1. Blocks any modifying or technical tool calls before Turn-1 verification.
2. Permits viewing designated rules files (AGENTS.md, PM_RULES.md, *_RULES.md).
3. Permits bootstrap writing of CANARY_VERIFIED to progress.md / progress_*.md.
4. Allows all tool calls once CANARY_VERIFIED is active in progress.md.
5. Strict denial when progress.md is missing, empty, or missing CANARY token.
6. Cross-platform path matching (Windows backslashes vs POSIX slashes).
7. Adversarial defenses: fake rules extensions, path traversal, corrupt payloads.
8. Subprocess stdio streaming with exit code 0 and valid JSON serialization.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from typing import Any

import pytest

# Enterprise hooks root & scripts paths
REPO_ROOT = pathlib.Path(__file__).parent.parent.resolve()
HOOKS_DIR = REPO_ROOT / "hooks_scripts"
PYTHON_EXE = sys.executable
ENFORCER_SCRIPT = HOOKS_DIR / "turn_1_gate_enforcer.py"

# Add hooks directory to module search path
if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

from turn_1_gate_enforcer import (  # noqa: E402
    check_canary_in_file,
    evaluate_turn_1_gate,
    extract_target_path,
    has_turn_1_verified,
    is_rules_file,
    run_self_tests,
)


def run_enforcer_subproc(
    payload: dict[str, Any],
    flag: str = "",
    extra_env: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any], str]:
    """Execute turn_1_gate_enforcer.py via subprocess simulating Antigravity stdin/stdout."""
    args = [PYTHON_EXE, str(ENFORCER_SCRIPT)]
    if flag:
        args.append(flag)
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        args,
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        cwd=str(REPO_ROOT),
        env=env,
        check=False,
    )
    stdout_raw = proc.stdout.strip()
    try:
        data = json.loads(stdout_raw) if stdout_raw else {}
    except json.JSONDecodeError:
        data = {"__raw_stdout__": stdout_raw}
    return proc.returncode, data, proc.stderr


# ============================================================================
# 1. Direct Evaluation Tests: Tool Blocking Before Verification
# ============================================================================
class TestTurn1GateToolBlocking:
    """Tests that technical and modifying tools are blocked before verification."""

    def test_deny_write_to_file_before_canary(self, tmp_path: pathlib.Path) -> None:
        """write_to_file targeting normal source code must be DENIED before canary."""
        payload = {
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(tmp_path / "src" / "app.py"),
                    "CodeContent": "print('hello')",
                },
            },
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "deny"
        reason_upper = res.get("reason", "").upper()
        assert "TURN 1" in reason_upper or "TURN-1" in reason_upper
        assert "CANARY_VERIFIED" in res.get("reason", "")

    def test_deny_run_command_before_canary(self, tmp_path: pathlib.Path) -> None:
        """run_command must be DENIED before Turn-1 verification."""
        payload = {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "python test.py"},
            },
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "deny"
        reason_upper = res.get("reason", "").upper()
        assert "TURN 1" in reason_upper or "TURN-1" in reason_upper

    def test_deny_replace_file_content_before_canary(self, tmp_path: pathlib.Path) -> None:
        """replace_file_content must be DENIED before Turn-1 verification."""
        payload = {
            "toolCall": {
                "name": "replace_file_content",
                "args": {
                    "TargetFile": str(tmp_path / "service.py"),
                    "TargetContent": "old",
                    "ReplacementContent": "new",
                },
            },
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "deny"

    def test_deny_invoke_subagent_before_canary(self, tmp_path: pathlib.Path) -> None:
        """invoke_subagent must be DENIED before Turn-1 verification."""
        payload = {
            "toolCall": {
                "name": "invoke_subagent",
                "args": {"Role": "Worker", "Prompt": "Do work"},
            },
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "deny"

    def test_deny_send_message_before_canary(self, tmp_path: pathlib.Path) -> None:
        """send_message must be DENIED before Turn-1 verification."""
        payload = {
            "toolCall": {
                "name": "send_message",
                "args": {"Recipient": "parent", "Message": "Hello"},
            },
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "deny"

    def test_deny_view_file_on_regular_code_before_canary(self, tmp_path: pathlib.Path) -> None:
        """view_file on regular source code (not rules) must be DENIED before canary."""
        payload = {
            "toolCall": {
                "name": "view_file",
                "args": {"AbsolutePath": str(tmp_path / "main.py")},
            },
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "deny"
        assert "view_file" in res.get("reason", "")


# ============================================================================
# 2. Exceptions: Allowed Actions at Turn 1
# ============================================================================
class TestTurn1GateAllowedExceptions:
    """Tests that reading designated rules files and bootstrap canary writing are allowed."""

    @pytest.mark.parametrize(
        "rules_rel_path",
        [
            "AGENTS.md",
            "agents.md",
            "PM_RULES.md",
            "pm_rules.md",
            "BACKEND_RULES.md",
            "FRONTEND_RULES.md",
            "QA_RULES.md",
            "TECH_LEAD_RULES.md",
            "DEVOPS_RULES.md",
            "rules_by_role/pm_orchestrator/PM_RULES.md",
            "rules_by_role/qa_challenger/QA_RULES.md",
            "rules_by_role/backend_developer/BACKEND_RULES.md",
            "config/rules/AGENTS.md",
            "enterprise-hooks/rules/coding-standards.md",
        ],
    )
    def test_allow_view_file_on_rules_files(self, tmp_path: pathlib.Path, rules_rel_path: str) -> None:
        """view_file on any valid rules file is ALWAYS allowed at Turn 1."""
        full_path = str(tmp_path / rules_rel_path)
        payload = {
            "toolCall": {
                "name": "view_file",
                "args": {"AbsolutePath": full_path},
            },
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "allow"
        assert "rules file" in res.get("reason", "").lower()

    def test_allow_bootstrap_write_canary_to_progress_md(self, tmp_path: pathlib.Path) -> None:
        """write_to_file to progress.md with CANARY_VERIFIED is allowed to bootstrap state."""
        target_file = str(tmp_path / "progress.md")
        payload = {
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": target_file,
                    "CodeContent": "CANARY_VERIFIED: QA_TEST_TOKEN\n# Progress Log\n",
                },
            },
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "allow"
        assert "Recording CANARY_VERIFIED" in res.get("reason", "")

    def test_allow_bootstrap_write_canary_to_role_progress_file(self, tmp_path: pathlib.Path) -> None:
        """write_to_file to progress_backend_ws2.md with CANARY_VERIFIED is allowed."""
        target_file = str(tmp_path / "progress_backend_ws2.md")
        payload = {
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": target_file,
                    "CodeContent": "CANARY_VERIFIED: BACKEND_SEC_01\n",
                },
            },
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "allow"

    def test_deny_write_to_progress_md_without_canary(self, tmp_path: pathlib.Path) -> None:
        """write_to_file to progress.md WITHOUT CANARY_VERIFIED must be DENIED."""
        target_file = str(tmp_path / "progress.md")
        payload = {
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": target_file,
                    "CodeContent": "# Just a regular note without canary token\n",
                },
            },
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "deny"


# ============================================================================
# 3. Post-Verification: All Tools Permitted Once Verified
# ============================================================================
class TestTurn1GateAfterVerification:
    """Tests that all tools proceed unimpeded once Turn-1 verification is confirmed."""

    def test_allow_all_tools_when_progress_has_canary(self, tmp_path: pathlib.Path) -> None:
        """All tools are ALLOWED once progress.md contains CANARY_VERIFIED on line 1."""
        progress_file = tmp_path / "progress.md"
        progress_file.write_text("CANARY_VERIFIED: §PM-ROLE-BOUNDARY\n# Progress log", encoding="utf-8")

        for tool_name, args in [
            ("write_to_file", {"TargetFile": str(tmp_path / "new.py"), "CodeContent": "x = 1"}),
            ("replace_file_content", {"TargetFile": str(tmp_path / "new.py"), "TargetContent": "1", "ReplacementContent": "2"}),
            ("run_command", {"CommandLine": "pytest"}),
            ("invoke_subagent", {"Role": "Worker", "Prompt": "Run tests"}),
            ("view_file", {"AbsolutePath": str(tmp_path / "new.py")}),
        ]:
            payload = {
                "toolCall": {"name": tool_name, "args": args},
                "workspacePaths": [str(tmp_path)],
            }
            res = evaluate_turn_1_gate(payload)
            assert res.get("decision") == "allow", f"Tool {tool_name} should be allowed after verification"

    def test_allow_when_role_specific_progress_has_canary(self, tmp_path: pathlib.Path) -> None:
        """Tools are allowed if any progress_*.md in workspace root contains CANARY_VERIFIED."""
        role_progress = tmp_path / "progress_qa_ws4.md"
        role_progress.write_text("CANARY_VERIFIED: QA_TOKEN_999\n", encoding="utf-8")

        payload = {
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(tmp_path / "test.py"), "CodeContent": "pass"},
            },
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "allow"

    def test_allow_when_payload_has_canary_verified_override(self, tmp_path: pathlib.Path) -> None:
        """Test payload direct override flag 'canary_verified': True allows execution."""
        payload = {
            "canary_verified": True,
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "dir"},
            },
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "allow"


# ============================================================================
# 4. Progress File Edge Cases & Boundary Conditions
# ============================================================================
class TestTurn1GateProgressFileEdgeCases:
    """Tests boundary conditions around progress.md file content and state."""

    def test_deny_when_progress_file_is_empty(self, tmp_path: pathlib.Path) -> None:
        """An empty progress.md (0 bytes) must result in DENY."""
        progress_file = tmp_path / "progress.md"
        progress_file.write_text("", encoding="utf-8")

        payload = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": "python"}},
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "deny"

    def test_deny_when_canary_beyond_first_five_lines(self, tmp_path: pathlib.Path) -> None:
        """CANARY_VERIFIED buried deep in the file (e.g. line 10) must result in DENY."""
        progress_file = tmp_path / "progress.md"
        padding = "\n".join([f"# Note line {i}" for i in range(1, 10)])
        progress_file.write_text(f"{padding}\nCANARY_VERIFIED: LATE_TOKEN\n", encoding="utf-8")

        payload = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": "python"}},
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "deny"

    def test_check_canary_in_file_non_existent(self, tmp_path: pathlib.Path) -> None:
        """check_canary_in_file returns False for non-existent files."""
        assert check_canary_in_file(tmp_path / "non_existent.md") is False


# ============================================================================
# 5. Adversarial & Security Tests
# ============================================================================
class TestTurn1GateAdversarial:
    """Adversarial attack tests attempting to bypass Turn-1 Gate."""

    def test_adversarial_fake_rules_extension(self, tmp_path: pathlib.Path) -> None:
        """view_file on executable or script disguising as rules must be DENIED."""
        for fake_name in ["pm_rules.md.exe", "AGENTS.md.py", "rules_by_role.sh"]:
            payload = {
                "toolCall": {
                    "name": "view_file",
                    "args": {"AbsolutePath": str(tmp_path / fake_name)},
                },
                "workspacePaths": [str(tmp_path)],
            }
            res = evaluate_turn_1_gate(payload)
            assert res.get("decision") == "deny", f"Should deny fake rules target: {fake_name}"

    def test_adversarial_path_traversal_to_rules(self, tmp_path: pathlib.Path) -> None:
        """Path traversal pretending to access rules must not bypass if not targeting real rules."""
        payload = {
            "toolCall": {
                "name": "view_file",
                "args": {"AbsolutePath": str(tmp_path / ".." / ".." / "etc" / "passwd")},
            },
            "workspacePaths": [str(tmp_path)],
        }
        res = evaluate_turn_1_gate(payload)
        assert res.get("decision") == "deny"

    def test_fail_safe_empty_or_corrupt_payload(self) -> None:
        """Empty dictionary or corrupt payload returns safe response without unhandled exception."""
        assert evaluate_turn_1_gate({}).get("decision") == "allow"
        assert evaluate_turn_1_gate({"toolCall": None}).get("decision") == "allow"
        assert evaluate_turn_1_gate({"toolCall": {"name": ""}}).get("decision") == "allow"

    def test_extract_target_path_variants(self) -> None:
        """extract_target_path extracts path from all supported argument keys."""
        assert extract_target_path({"TargetFile": "foo.py"}) == "foo.py"
        assert extract_target_path({"AbsolutePath": "bar.py"}) == "bar.py"
        assert extract_target_path({"filePath": "baz.py"}) == "baz.py"
        assert extract_target_path({"path": "qux.py"}) == "qux.py"
        assert extract_target_path({}) is None


# ============================================================================
# 6. Subprocess CLI & Self-Test Verification
# ============================================================================
class TestTurn1GateSubprocessExecution:
    """Subprocess execution tests validating stdio streaming and JSON serialization."""

    def test_subprocess_denial_streaming(self, tmp_path: pathlib.Path) -> None:
        """Subprocess streams JSON deny response with exit code 0 when unverified."""
        payload = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": "dir"}},
            "workspacePaths": [str(tmp_path)],
        }
        rc, out, stderr = run_enforcer_subproc(payload)
        assert rc == 0, f"Hook should exit 0, stderr: {stderr}"
        assert out.get("decision") == "deny"
        reason_upper = out.get("reason", "").upper()
        assert "TURN 1" in reason_upper or "TURN-1" in reason_upper

    def test_subprocess_allow_rules_view(self, tmp_path: pathlib.Path) -> None:
        """Subprocess streams JSON allow response for viewing rules."""
        payload = {
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": "C:/config/rules/AGENTS.md"}},
            "workspacePaths": [str(tmp_path)],
        }
        rc, out, stderr = run_enforcer_subproc(payload)
        assert rc == 0
        assert out.get("decision") == "allow"

    def test_hook_built_in_self_test(self) -> None:
        """Run hook with --self-test flag and verify it passes 100%."""
        rc, out, stderr = run_enforcer_subproc({}, flag="--self-test")
        assert rc == 0, f"Self-test failed: stderr={stderr}, out={out}"

    def test_direct_run_self_tests(self) -> None:
        """Direct in-process execution of run_self_tests()."""
        assert run_self_tests() is True
