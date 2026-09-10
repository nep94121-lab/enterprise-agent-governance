#!/usr/bin/env python3
"""Enterprise Test Suite for Regression Detector Hook & Engine.

Validates:
- Cryptographic SHA-256 snapshot manifest creation and Merkle root calculation
- Real unified git diff parsing into structured FileDiff and DiffHunk
- Cross-matching correlation between hash snapshots and git diff
- Phantom diff detection
- Untracked drift detection
- Python AST syntax regression detection
- Protected path violation blocking
- Dynamic configuration loading from hook_utils.config_loader
- Antigravity hook protocol lifecycle events (PreToolUse, PostToolUse, Stop)
- Windows cross-platform path normalization and UTF-8 handling
"""

from __future__ import annotations

import hashlib
import pathlib
import sys

import pytest

# Ensure hook scripts are in sys.path
HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).parent.parent / "hooks_scripts"
if str(HOOKS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_SCRIPTS_DIR))

from hooks_scripts.regression_detector import (
    RegressionDetector,
    RegressionIssue,
    RegressionType,
    handle_hook_event,
)


@pytest.fixture
def temp_workspace(tmp_path: pathlib.Path) -> pathlib.Path:
    """Create a temporary workspace directory for hermetic testing."""
    ws = tmp_path / "test_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    return ws


class TestRegressionDetectorCore:
    """Core cryptographic hashing and snapshot tests."""

    def test_dynamic_config_loading(self, temp_workspace: pathlib.Path):
        """Verify dynamic config loads properly with defaults."""
        detector = RegressionDetector(workspace_root=temp_workspace)
        assert detector.config.get("hash_algorithm") == "sha256"
        assert "max_diff_lines" in detector.config
        assert "protected_paths" in detector.config

    def test_compute_file_hash_text_and_binary(self, temp_workspace: pathlib.Path):
        """Verify hash computation for both text and binary files."""
        detector = RegressionDetector(workspace_root=temp_workspace)

        # Text file
        text_file = temp_workspace / "text.txt"
        text_content = b"Hello Enterprise Governance!\n"
        text_file.write_bytes(text_content)
        hash_val, size_b, _, is_bin = detector.compute_file_hash(text_file)

        assert hash_val == hashlib.sha256(text_content).hexdigest()
        assert size_b == len(text_content)
        assert not is_bin

        # Binary file
        bin_file = temp_workspace / "bin.dat"
        bin_content = b"\x00\x01\x02\xff\xfe\x00"
        bin_file.write_bytes(bin_content)
        hash_val_b, size_b_b, _, is_bin_b = detector.compute_file_hash(bin_file)

        assert hash_val_b == hashlib.sha256(bin_content).hexdigest()
        assert size_b_b == len(bin_content)
        assert is_bin_b

    def test_snapshot_lifecycle(self, temp_workspace: pathlib.Path):
        """Verify snapshot creation, persistence, and reloading."""
        detector = RegressionDetector(workspace_root=temp_workspace)

        f1 = temp_workspace / "file1.py"
        f1.write_bytes(b"x = 1\n")
        f2 = temp_workspace / "file2.json"
        f2.write_bytes(b'{"status": "ok"}\n')

        manifest = detector.create_snapshot(label="test_snap", save=True)
        assert manifest.file_count == 2
        assert "file1.py" in manifest.files
        assert "file2.json" in manifest.files
        assert len(manifest.manifest_hash) == 64

        # Reload snapshot
        loaded = detector.load_snapshot(manifest.snapshot_id)
        assert loaded is not None
        assert loaded.snapshot_id == manifest.snapshot_id
        assert loaded.manifest_hash == manifest.manifest_hash
        assert loaded.file_count == 2

    def test_compare_snapshots_delta(self, temp_workspace: pathlib.Path):
        """Verify comparison identifies added, modified, and deleted files."""
        detector = RegressionDetector(workspace_root=temp_workspace)

        f1 = temp_workspace / "f1.py"
        f1.write_bytes(b"v1\n")
        f2 = temp_workspace / "f2.py"
        f2.write_bytes(b"v1\n")

        snap1 = detector.create_snapshot(label="s1", save=False)

        # Modify f1, delete f2, add f3
        f1.write_bytes(b"v2\n")
        f2.unlink()
        f3 = temp_workspace / "f3.py"
        f3.write_bytes(b"v1\n")

        snap2 = detector.create_snapshot(label="s2", save=False)

        added, modified, deleted = detector.compare_snapshots(snap1, snap2)
        assert added == ["f3.py"]
        assert modified == ["f1.py"]
        assert deleted == ["f2.py"]


class TestGitDiffParsingAndCorrelation:
    """Git diff parsing and cross-verification tests."""

    def test_parse_unified_git_diff(self, temp_workspace: pathlib.Path):
        """Verify unified git diff output parsing into structured objects."""
        detector = RegressionDetector(workspace_root=temp_workspace)

        raw_diff = (
            "diff --git a/src/main.py b/src/main.py\n"
            "index 0000000..1111111 100644\n"
            "--- a/src/main.py\n"
            "+++ b/src/main.py\n"
            "@@ -1,3 +1,4 @@\n"
            " line 1\n"
            "-line 2\n"
            "+line 2 modified\n"
            "+line 3 added\n"
            " line 4\n"
        )

        report = detector.parse_git_diff(raw_diff)
        assert len(report.files_changed) == 1
        file_diff = report.files_changed[0]
        assert file_diff.file_path == "src/main.py"
        assert file_diff.added_lines_count == 2
        assert file_diff.deleted_lines_count == 1
        assert len(file_diff.hunks) == 1
        assert not report.is_clean

    def test_detect_phantom_diff(self, temp_workspace: pathlib.Path):
        """Verify detection of git diff modifications where file hash is unchanged."""
        detector = RegressionDetector(workspace_root=temp_workspace)

        f = temp_workspace / "script.py"
        f.write_bytes(b"print('test')\n")
        baseline = detector.create_snapshot(label="base", save=True)

        # Simulated phantom diff claiming changes in script.py
        phantom_diff = (
            "diff --git a/script.py b/script.py\n"
            "--- a/script.py\n"
            "+++ b/script.py\n"
            "@@ -1,1 +1,1 @@\n"
            "+# no real change\n"
        )

        # Inject parsed diff into detection logic
        parsed = detector.parse_git_diff(phantom_diff)
        curr_snap = detector.create_snapshot(label="curr", save=False)

        issues = []
        for fd in parsed.files_changed:
            c = curr_snap.files.get(fd.file_path)
            b = baseline.files.get(fd.file_path)
            if c and b and c.sha256 == b.sha256:
                issues.append(
                    RegressionIssue(
                        issue_id="test_phan",
                        issue_type=RegressionType.PHANTOM_DIFF,
                        severity="low",
                        file_path=fd.file_path,
                        description="Phantom diff detected",
                        is_blocking=False,
                    )
                )

        assert len(issues) == 1
        assert issues[0].issue_type == RegressionType.PHANTOM_DIFF

    def test_detect_untracked_drift(self, temp_workspace: pathlib.Path):
        """Verify modification on disk without git diff triggers Untracked Drift."""
        detector = RegressionDetector(workspace_root=temp_workspace)

        f = temp_workspace / "app.py"
        f.write_bytes(b"version = 1.0\n")
        baseline = detector.create_snapshot(label="base", save=True)

        # Alter file directly on disk
        f.write_bytes(b"version = 2.0\n")

        # Compare without git diff tracking
        report = detector.detect_regressions(baseline=baseline, compare_git=False)
        assert report.has_regressions
        untracked = [i for i in report.issues if i.issue_type == RegressionType.UNTRACKED_DRIFT]
        assert len(untracked) == 1
        assert untracked[0].file_path == "app.py"
        assert untracked[0].is_blocking is True


class TestProtectedPathsAndSyntaxRegressions:
    """Security rules, protected paths, and AST syntax tests."""

    def test_protected_path_blocking(self, temp_workspace: pathlib.Path):
        """Verify modifying protected paths generates blocking critical regression."""
        detector = RegressionDetector(workspace_root=temp_workspace)

        rule_file = temp_workspace / "rules_by_role" / "BACKEND_RULES.md"
        rule_file.parent.mkdir(parents=True, exist_ok=True)
        rule_file.write_bytes(b"Original rules\n")

        baseline = detector.create_snapshot(label="base", save=True)

        # Tamper with protected rule
        rule_file.write_bytes(b"Tampered rules\n")

        report = detector.detect_regressions(baseline=baseline, compare_git=False)
        prot_issues = [
            i for i in report.issues if i.issue_type == RegressionType.PROTECTED_PATH_VIOLATION
        ]
        assert len(prot_issues) == 1
        assert prot_issues[0].is_blocking is True
        assert prot_issues[0].severity == "critical"

    def test_syntax_regression_detection(self, temp_workspace: pathlib.Path):
        """Verify introducing invalid Python syntax triggers blocking regression."""
        detector = RegressionDetector(workspace_root=temp_workspace)

        code_file = temp_workspace / "handler.py"
        code_file.write_bytes(b"def handle():\n    return True\n")
        baseline = detector.create_snapshot(label="base", save=True)

        # Introduce syntax error
        code_file.write_bytes(b"def handle(:\n    return True\n")

        report = detector.detect_regressions(baseline=baseline, compare_git=False)
        syntax_issues = [
            i for i in report.issues if i.issue_type == RegressionType.SYNTAX_REGRESSION
        ]
        assert len(syntax_issues) == 1
        assert syntax_issues[0].is_blocking is True
        assert "SyntaxError" in syntax_issues[0].description


class TestHookProtocolIntegration:
    """Antigravity hook lifecycle protocol tests."""

    def test_pre_tool_use_denies_protected_path(self, temp_workspace: pathlib.Path):
        """PreToolUse denies write_to_file on protected path."""
        prot_path = temp_workspace / "rules_by_role" / "SECURITY.md"
        payload = {
            "toolCall": {
                "name": "write_to_file",
                "args": {"target_file": str(prot_path)},
            },
            "workspacePaths": [str(temp_workspace)],
        }
        res = handle_hook_event(payload)
        assert res.get("decision") == "deny"
        assert "protected path" in res.get("reason", "")

    def test_pre_tool_use_allows_safe_path(self, temp_workspace: pathlib.Path):
        """PreToolUse allows write_to_file on normal workspace files."""
        safe_path = temp_workspace / "src" / "worker.py"
        payload = {
            "toolCall": {
                "name": "write_to_file",
                "args": {"target_file": str(safe_path)},
            },
            "workspacePaths": [str(temp_workspace)],
        }
        res = handle_hook_event(payload)
        assert res.get("decision") == "allow"

    def test_stop_hook_blocks_on_regression(self, temp_workspace: pathlib.Path):
        """Stop hook blocks if workspace has blocking regressions."""
        detector = RegressionDetector(workspace_root=temp_workspace)
        broken = temp_workspace / "broken.py"
        broken.write_bytes(b"valid = True\n")
        _baseline = detector.create_snapshot(save=True)

        # Break syntax
        broken.write_bytes(b"invalid syntax ))))\n")

        payload = {
            "event": "Stop",
            "workspacePaths": [str(temp_workspace)],
        }
        res = handle_hook_event(payload)
        assert res.get("decision") == "deny"
        assert "Regression detected" in res.get("reason", "")


class TestP1FixesRegressionAndFallback:
    """Validate P1 fixes: read_stdin_payload fallback interface and detect_regressions path normalization."""

    def test_read_stdin_payload_fallback_interface(self, monkeypatch: pytest.MonkeyPatch):
        """Verify read_stdin_payload accepts 'default' keyword argument and parses correctly."""
        import io
        from hooks_scripts.regression_detector import read_stdin_payload

        # 1. Empty stdin with keyword arg default
        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        res = read_stdin_payload(default={"fallback_key": "ok"})
        assert res == {"fallback_key": "ok"}

        # 2. None default with empty stdin
        monkeypatch.setattr("sys.stdin", io.StringIO("   \n"))
        res = read_stdin_payload()
        assert res == {}

        # 3. Valid JSON with keyword arg default
        monkeypatch.setattr("sys.stdin", io.StringIO('{"toolCall": {"name": "test"}}'))
        res = read_stdin_payload(default={"fallback": True})
        assert res == {"toolCall": {"name": "test"}}

        # 4. Malformed JSON with keyword arg default
        monkeypatch.setattr("sys.stdin", io.StringIO("invalid {json"))
        res = read_stdin_payload(default={"recovered": True})
        assert res == {"recovered": True}

    def test_detect_regressions_scope_grep_path_normalization(self, temp_workspace: pathlib.Path):
        """Verify detect_regressions properly normalizes paths across snapshots and git diff."""
        import time
        from hooks_scripts.regression_detector import (
            FileDiff,
            FileSnapshot,
            GitDiffReport,
            SnapshotManifest,
        )

        detector = RegressionDetector(workspace_root=temp_workspace)

        # Baseline with unnormalized Windows backslashes
        base_manifest = SnapshotManifest(
            snapshot_id="base_test_norm",
            label="baseline",
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            workspace_root=str(temp_workspace),
            file_count=2,
            total_bytes=100,
            manifest_hash="abc",
            files={
                "core\\module.py": FileSnapshot("core\\module.py", "hash_orig", 50, 0.0),
                "rules_by_role\\BACKEND_RULES.md": FileSnapshot("rules_by_role\\BACKEND_RULES.md", "hash_prot", 50, 0.0),
            },
        )

        # Write actual files in workspace
        mod_file = temp_workspace / "core" / "module.py"
        mod_file.parent.mkdir(parents=True, exist_ok=True)
        mod_file.write_text("print('updated')\n", encoding="utf-8")

        prot_file = temp_workspace / "rules_by_role" / "BACKEND_RULES.md"
        prot_file.parent.mkdir(parents=True, exist_ok=True)
        prot_file.write_text("print('tampered')\n", encoding="utf-8")

        # Mock git diff returning forward-slash path for core/module.py
        mock_diff = GitDiffReport(
            files_changed=[FileDiff(file_path="core/module.py", added_lines_count=1)],
            total_added_lines=1,
            total_deleted_lines=0,
            is_clean=False,
        )
        detector.get_git_diff = lambda: mock_diff  # type: ignore[assignment]

        report = detector.detect_regressions(baseline=base_manifest, compare_git=True)

        # core/module.py was tracked in git diff, so it must NOT be flagged as untracked drift
        untracked = [i for i in report.issues if i.issue_type == RegressionType.UNTRACKED_DRIFT]
        untracked_paths = [i.file_path for i in untracked]
        assert "core/module.py" not in untracked_paths
        assert "core\\module.py" not in untracked_paths

        # rules_by_role/BACKEND_RULES.md is protected, must be flagged as protected violation
        prot_issues = [i for i in report.issues if i.issue_type == RegressionType.PROTECTED_PATH_VIOLATION]
        assert len(prot_issues) == 1
        assert prot_issues[0].file_path == "rules_by_role/BACKEND_RULES.md"

        # Report files should all be normalized
        assert all("\\" not in p for p in report.modified_files)
        assert all("\\" not in p for p in report.added_files)
        assert all("\\" not in p for p in report.deleted_files)
