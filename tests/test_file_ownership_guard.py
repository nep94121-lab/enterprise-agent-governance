#!/usr/bin/env python3
"""Automated Test Suite for file_ownership_guard Hook.

Validates Exclusive File Ownership (§EXCLUSIVE-FILE-OWNERSHIP):
1. Reads Exclusive File Ownership table from progress.md in workspace.
2. HARD DENY (chặn ngay, 0 ngoại lệ) khi Worker B cố tình ghi/sửa file của Worker A.
3. ALLOW khi Worker ghi/sửa file do chính mình sở hữu.
4. ALLOW PM Orchestrator ghi/sửa các file quản lý tiến độ (progress.md, gate_status.md, activity_logs).
5. Fast-path bypass cho các tool đọc (view_file, list_dir, grep_search).
6. Cho phép chỉnh sửa file trong thư mục scratch/ và file nhật ký vai trò (progress_<role>.md).
7. Xử lý đường dẫn chuẩn hóa cross-platform (Windows backslash vs POSIX slash, case-insensitivity).
8. Subprocess stdio streaming với exit code 0 và định dạng JSON hợp lệ.
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
GUARD_SCRIPT = HOOKS_DIR / "file_ownership_guard.py"

# Add hooks directory to module search path
if str(HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_DIR))

from file_ownership_guard import (  # noqa: E402
    detect_caller_identity,
    evaluate_file_ownership,
    extract_target_path,
    find_file_owner,
    is_caller_owner,
    normalize_identifier,
    parse_ownership_table,
    run_self_tests,
)


def run_ownership_subproc(
    payload: dict[str, Any],
    flag: str = "",
    extra_env: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any], str]:
    """Execute file_ownership_guard.py via subprocess simulating Antigravity stdin/stdout."""
    args = [PYTHON_EXE, str(GUARD_SCRIPT)]
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


@pytest.fixture
def workspace_with_ownership(tmp_path: pathlib.Path) -> pathlib.Path:
    """Fixture creating a temporary workspace with progress.md containing ownership table."""
    progress_md = tmp_path / "progress.md"
    progress_content = """CANARY_VERIFIED: TEST_SUITE_FIXTURE

# Bảng Exclusive File Ownership
| Subagent | File(s) Owned | Trạng Thái |
|---|---|---|
| DevOps_WS1 | `PM_RULES.md`, `AGENTS.md` | Đang chạy |
| Backend_WS2 | `turn_1_gate_enforcer.py`, `hooks.json`, `service.py` | Đang chạy |
| TechLead_WS3 | `task_contract_spec.md`, `BACKEND_RULES.md` | Đang chạy |
| QA_WS4 | `test_turn_1.py`, `test_hierarchy.py` | Đang chạy |
"""
    progress_md.write_text(progress_content, encoding="utf-8")
    return tmp_path


# ============================================================================
# 1. Hard DENY Tests: Cross-Worker File Tampering
# ============================================================================
class TestCrossWorkerHardDenial:
    """Tests that a worker modifying files owned by another worker receives HARD DENY."""

    def test_hard_deny_worker_b_modifying_worker_a_file_via_write(self, workspace_with_ownership: pathlib.Path) -> None:
        """QA_WS4 attempting to overwrite turn_1_gate_enforcer.py (Backend_WS2) must receive HARD DENY."""
        payload = {
            "caller_role": "QA_WS4",
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(workspace_with_ownership / "turn_1_gate_enforcer.py"),
                    "CodeContent": "corrupt_code = True",
                },
            },
            "workspacePaths": [str(workspace_with_ownership)],
        }
        res = evaluate_file_ownership(payload)
        assert res.get("decision") == "deny"
        reason_upper = res.get("reason", "").upper()
        assert "HARD DENY" in reason_upper
        assert "EXCLUSIVE-FILE-OWNERSHIP" in reason_upper

    def test_hard_deny_worker_b_modifying_worker_a_file_via_replace(self, workspace_with_ownership: pathlib.Path) -> None:
        """Backend_WS2 attempting to replace content in PM_RULES.md (DevOps_WS1) must receive HARD DENY."""
        payload = {
            "caller_role": "Backend_WS2",
            "toolCall": {
                "name": "replace_file_content",
                "args": {
                    "TargetFile": str(workspace_with_ownership / "PM_RULES.md"),
                    "TargetContent": "old",
                    "ReplacementContent": "new",
                },
            },
            "workspacePaths": [str(workspace_with_ownership)],
        }
        res = evaluate_file_ownership(payload)
        assert res.get("decision") == "deny"
        assert "HARD DENY" in res.get("reason", "").upper()

    def test_hard_deny_tech_lead_modifying_qa_test_file(self, workspace_with_ownership: pathlib.Path) -> None:
        """TechLead_WS3 attempting to modify test_turn_1.py (QA_WS4) must be DENIED."""
        payload = {
            "caller_role": "TechLead_WS3",
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(workspace_with_ownership / "test_turn_1.py"),
                    "CodeContent": "def test(): pass",
                },
            },
            "workspacePaths": [str(workspace_with_ownership)],
        }
        res = evaluate_file_ownership(payload)
        assert res.get("decision") == "deny"


# ============================================================================
# 2. ALLOW Tests: Owner Modifying Its Own Files
# ============================================================================
class TestOwnerAuthorizedModifications:
    """Tests that each worker is ALLOWED to write/modify its own designated files."""

    def test_allow_backend_ws2_modifying_turn_1_enforcer(self, workspace_with_ownership: pathlib.Path) -> None:
        """Backend_WS2 modifying turn_1_gate_enforcer.py is ALLOWED."""
        payload = {
            "caller_role": "Backend_WS2",
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(workspace_with_ownership / "turn_1_gate_enforcer.py"),
                    "CodeContent": "# valid code",
                },
            },
            "workspacePaths": [str(workspace_with_ownership)],
        }
        res = evaluate_file_ownership(payload)
        assert res.get("decision") == "allow"
        assert "verified owner" in res.get("reason", "").lower()

    def test_allow_backend_ws2_modifying_hooks_json(self, workspace_with_ownership: pathlib.Path) -> None:
        """Backend_WS2 modifying hooks.json via replace_file_content is ALLOWED."""
        payload = {
            "caller_role": "backend",
            "toolCall": {
                "name": "replace_file_content",
                "args": {
                    "TargetFile": str(workspace_with_ownership / "hooks.json"),
                    "TargetContent": "{}",
                    "ReplacementContent": "{\"key\": 1}",
                },
            },
            "workspacePaths": [str(workspace_with_ownership)],
        }
        res = evaluate_file_ownership(payload)
        assert res.get("decision") == "allow"

    def test_allow_qa_ws4_modifying_test_turn_1(self, workspace_with_ownership: pathlib.Path) -> None:
        """QA_WS4 modifying test_turn_1.py is ALLOWED."""
        payload = {
            "caller_role": "qa_challenger",
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(workspace_with_ownership / "test_turn_1.py"),
                    "CodeContent": "def test_ok(): pass",
                },
            },
            "workspacePaths": [str(workspace_with_ownership)],
        }
        res = evaluate_file_ownership(payload)
        assert res.get("decision") == "allow"


# ============================================================================
# 3. PM Orchestrator Management Files Permissions
# ============================================================================
class TestPMManagementFilePermissions:
    """Tests that PM Orchestrator has authority to update tracking and log files."""

    @pytest.mark.parametrize(
        "mgmt_file",
        ["progress.md", "gate_status.md", "dead_ends.md", "handoff.md", "implementation_plan.md"],
    )
    def test_allow_pm_modifying_tracking_files(self, workspace_with_ownership: pathlib.Path, mgmt_file: str) -> None:
        """PM Orchestrator is authorized to update all tracking files."""
        payload = {
            "caller_role": "PM_Orchestrator",
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(workspace_with_ownership / mgmt_file),
                    "CodeContent": "# updated",
                },
            },
            "workspacePaths": [str(workspace_with_ownership)],
        }
        res = evaluate_file_ownership(payload)
        assert res.get("decision") == "allow"
        assert "PM Orchestrator authorized" in res.get("reason", "")

    def test_allow_pm_updating_activity_logs(self, workspace_with_ownership: pathlib.Path) -> None:
        """PM Orchestrator updating daily activity log is ALLOWED."""
        payload = {
            "caller_role": "pm",
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(workspace_with_ownership / "activity_logs" / "2026-09-09.md"),
                    "CodeContent": "10:30 - WS4 test suite created",
                },
            },
            "workspacePaths": [str(workspace_with_ownership)],
        }
        res = evaluate_file_ownership(payload)
        assert res.get("decision") == "allow"


# ============================================================================
# 4. Special Paths: Scratch Files & Unrestricted Files
# ============================================================================
class TestSpecialPathsAndUnrestricted:
    """Tests scratch files, role progress logs, and unrestricted files."""

    def test_allow_worker_modifying_own_role_progress(self, workspace_with_ownership: pathlib.Path) -> None:
        """Worker modifying its private progress log progress_backend_ws2.md is ALLOWED."""
        payload = {
            "caller_role": "backend_ws2",
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(workspace_with_ownership / "progress_backend_ws2.md"),
                    "CodeContent": "# Role Log",
                },
            },
            "workspacePaths": [str(workspace_with_ownership)],
        }
        res = evaluate_file_ownership(payload)
        assert res.get("decision") == "allow"
        assert "progress log" in res.get("reason", "").lower()

    def test_allow_worker_writing_scratch_file(self, workspace_with_ownership: pathlib.Path) -> None:
        """Writing temporary scripts in scratch directory is ALLOWED for any caller."""
        payload = {
            "caller_role": "qa_ws4",
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(workspace_with_ownership / "scratch" / "temp_check.py"),
                    "CodeContent": "print('check')",
                },
            },
            "workspacePaths": [str(workspace_with_ownership)],
        }
        res = evaluate_file_ownership(payload)
        assert res.get("decision") == "allow"

    def test_allow_unrestricted_file(self, workspace_with_ownership: pathlib.Path) -> None:
        """Modifying a file not listed in the ownership table is ALLOWED (unrestricted)."""
        payload = {
            "caller_role": "qa_ws4",
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(workspace_with_ownership / "readme.txt"),
                    "CodeContent": "unrestricted",
                },
            },
            "workspacePaths": [str(workspace_with_ownership)],
        }
        res = evaluate_file_ownership(payload)
        assert res.get("decision") == "allow"
        assert "not restricted" in res.get("reason", "").lower()

    @pytest.mark.parametrize("read_tool", ["view_file", "list_dir", "grep_search", "find_by_name"])
    def test_allow_read_only_tools(self, workspace_with_ownership: pathlib.Path, read_tool: str) -> None:
        """Read-only tools are never restricted by file ownership."""
        payload = {
            "caller_role": "qa_ws4",
            "toolCall": {
                "name": read_tool,
                "args": {"AbsolutePath": str(workspace_with_ownership / "turn_1_gate_enforcer.py")},
            },
            "workspacePaths": [str(workspace_with_ownership)],
        }
        res = evaluate_file_ownership(payload)
        assert res.get("decision") == "allow"
        assert "not monitored" in res.get("reason", "").lower()


# ============================================================================
# 5. Parsing & Helper Functions
# ============================================================================
class TestOwnershipParsingAndHelpers:
    """Tests parsing of markdown table / list syntax and helper functions."""

    def test_parse_ownership_table_from_markdown(self, tmp_path: pathlib.Path) -> None:
        """parse_ownership_table correctly parses standard markdown table."""
        doc = tmp_path / "progress.md"
        doc.write_text(
            """# File Ownership
| Subagent | File(s) Owned | Trạng Thái |
|---|---|---|
| Alice_WS1 | `alpha.py`, `alpha_test.py` | OK |
| Bob_WS2 | `beta.py` | OK |
""",
            encoding="utf-8",
        )
        tbl = parse_ownership_table(doc)
        assert "alice_ws1" in tbl
        assert "alpha.py" in tbl["alice_ws1"]
        assert "alpha_test.py" in tbl["alice_ws1"]
        assert "bob_ws2" in tbl
        assert "beta.py" in tbl["bob_ws2"]

    def test_parse_ownership_table_from_list_syntax(self, tmp_path: pathlib.Path) -> None:
        """parse_ownership_table correctly parses bullet list syntax."""
        doc = tmp_path / "progress.md"
        doc.write_text(
            """# Ownership
- dev1 -> module_a.py, helper_a.py
- dev2 -> module_b.py
""",
            encoding="utf-8",
        )
        tbl = parse_ownership_table(doc)
        assert "dev1" in tbl
        assert "module_a.py" in tbl["dev1"]
        assert "helper_a.py" in tbl["dev1"]
        assert "dev2" in tbl
        assert "module_b.py" in tbl["dev2"]

    def test_find_file_owner_helper(self) -> None:
        """find_file_owner returns designated owner or None."""
        m = {"worker_a": ["file_a.py", "app.py"], "worker_b": ["file_b.py"]}
        assert find_file_owner("file_a.py", m) == "worker_a"
        assert find_file_owner("file_b.py", m) == "worker_b"
        assert find_file_owner("unowned.py", m) is None

    def test_is_caller_owner_helper(self) -> None:
        """is_caller_owner supports fuzzy matches and alias mappings."""
        assert is_caller_owner("backend_developer", "backend_ws2") is True
        assert is_caller_owner("qa_challenger", "qa_ws4") is True
        assert is_caller_owner("techlead", "techlead_ws3") is True
        assert is_caller_owner("devops", "devops_ws1") is True
        assert is_caller_owner("qa_ws4", "backend_ws2") is False

    def test_extract_target_path_keys(self) -> None:
        """extract_target_path extracts target path across various supported keys."""
        assert extract_target_path({"TargetFile": "a.py"}) == "a.py"
        assert extract_target_path({"target_file": "b.py"}) == "b.py"
        assert extract_target_path({"filePath": "c.py"}) == "c.py"
        assert extract_target_path({}) is None


# ============================================================================
# 6. Subprocess CLI & Self-Test Verification
# ============================================================================
class TestOwnershipSubprocessExecution:
    """Subprocess execution tests validating stdio streaming and JSON serialization."""

    def test_subprocess_hard_deny_streaming(self, workspace_with_ownership: pathlib.Path) -> None:
        """Subprocess streams JSON HARD DENY response with exit code 0 on ownership violation."""
        payload = {
            "caller_role": "QA_WS4",
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(workspace_with_ownership / "turn_1_gate_enforcer.py"),
                    "CodeContent": "violation",
                },
            },
            "workspacePaths": [str(workspace_with_ownership)],
        }
        rc, out, stderr = run_ownership_subproc(payload)
        assert rc == 0, f"Hook should exit 0, stderr: {stderr}"
        assert out.get("decision") == "deny"
        reason_upper = out.get("reason", "").upper()
        assert "HARD DENY" in reason_upper
        assert "EXCLUSIVE-FILE-OWNERSHIP" in reason_upper

    def test_subprocess_allow_streaming(self, workspace_with_ownership: pathlib.Path) -> None:
        """Subprocess streams JSON ALLOW response when owner modifies its file."""
        payload = {
            "caller_role": "Backend_WS2",
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(workspace_with_ownership / "turn_1_gate_enforcer.py"),
                    "CodeContent": "authorized code",
                },
            },
            "workspacePaths": [str(workspace_with_ownership)],
        }
        rc, out, stderr = run_ownership_subproc(payload)
        assert rc == 0
        assert out.get("decision") == "allow"

    def test_hook_built_in_self_test(self) -> None:
        """Run hook with --self-test flag and verify it passes 100%."""
        rc, out, stderr = run_ownership_subproc({}, flag="--self-test")
        assert rc == 0, f"Self-test failed: stderr={stderr}, out={out}"

    def test_direct_run_self_tests(self) -> None:
        """Direct in-process execution of run_self_tests()."""
        assert run_self_tests() is True
