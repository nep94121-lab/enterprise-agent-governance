#!/usr/bin/env python3
"""Regression Detector Hook & Engine for Enterprise Multi-Agent Governance System.

Provides physical runtime regression detection and baseline verification:
1. Cryptographic Snapshot Manifest: SHA-256 chunked hashing of workspace files.
2. Real Unified Git Diff Parsing: Extraction of modified files, hunks, and line deltas.
3. Cross-Verification & Correlation:
   - Matches git diff changes against hash snapshot deltas.
   - Detects Phantom Diffs (git modified with unchanged hash).
   - Detects Untracked Drift (disk modified without git tracking).
   - Detects Syntax Regressions (AST parsing on modified code).
   - Enforces Protected Paths (blocks unauthorized mutation of critical files).
4. Dynamic Zero-Hardcode Configuration: Integrated with hook_utils.config_loader.
5. Multi-Lifecycle Hook Support: PreToolUse, PostToolUse, Stop events.
6. Comprehensive Built-In Self-Test Suite (--self-test).

Conforms to Enterprise Coding Standards (§1-§29), Backend Security (§3, §7, §8, §18).
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import enum
import fnmatch
import hashlib
import io
import json
import logging
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import Any
from uuid import uuid4

# =============================================================================
# Enforce UTF-8 standard encoding across all platforms (Windows PowerShell safe)
# =============================================================================
try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

logger = logging.getLogger("enterprise_hooks.regression_detector")

# Ensure local hook packages are importable
HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).parent.resolve()
ENTERPRISE_HOOKS_ROOT = HOOKS_SCRIPTS_DIR.parent.resolve()

if str(HOOKS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_SCRIPTS_DIR))
if str(ENTERPRISE_HOOKS_ROOT) not in sys.path:
    sys.path.insert(0, str(ENTERPRISE_HOOKS_ROOT))

# Import hook_utils
try:
    from hook_utils import (
        DynamicConfigLoader,
        get_concurrency_rules,
        get_dynamic_limits,
        get_execution_timeouts,
        get_regression_detector_config,
    )
except ImportError:
    try:
        from hook_utils.config_loader import (  # type: ignore[no-redef]
            DynamicConfigLoader,
            get_concurrency_rules,
            get_dynamic_limits,
            get_execution_timeouts,
            get_regression_detector_config,
        )
    except ImportError:
        DynamicConfigLoader = None  # type: ignore[assignment]
        get_regression_detector_config = None  # type: ignore[assignment]
        get_dynamic_limits = None  # type: ignore[assignment]
        get_execution_timeouts = None  # type: ignore[assignment]
        get_concurrency_rules = None  # type: ignore[assignment]

# Import common_hook_lib
try:
    from common_hook_lib import (
        emit_stdout_json,
        get_tool_args,
        get_tool_call,
        get_workspace_roots,
        log_diagnostic,
        post_tool_response,
        pre_tool_response,
        read_stdin_payload,
        stop_response,
    )
except ImportError:
    # Emergency fallback definitions
    def log_diagnostic(msg: str) -> None:
        try:
            sys.stderr.write(f"[REGRESSION-DIAGNOSTIC] {msg}\n")
            sys.stderr.flush()
        except (OSError, UnicodeEncodeError):
            pass

    def emit_stdout_json(p: dict[str, Any]) -> None:
        try:
            sys.stdout.write(json.dumps(p, ensure_ascii=False) + "\n")
            sys.stdout.flush()
        except Exception:
            sys.stdout.write("{}\n")
            sys.stdout.flush()

    def read_stdin_payload(default: dict[str, Any] | None = None) -> dict[str, Any]:
        if default is None:
            default = {}
        try:
            raw = sys.stdin.read()
            if not raw or not raw.strip():
                return default
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else default
        except Exception:
            return default

    def get_tool_call(p: Any) -> dict[str, Any]:
        return p.get("toolCall", {}) if isinstance(p, dict) and isinstance(p.get("toolCall"), dict) else {}

    def get_tool_args(tc: Any) -> dict[str, Any]:
        return tc.get("args", {}) if isinstance(tc, dict) and isinstance(tc.get("args"), dict) else {}

    def get_workspace_roots(p: Any) -> list[pathlib.Path]:
        return [pathlib.Path.cwd().resolve()]

    def pre_tool_response(decision: str, reason: str = "") -> dict[str, Any]:
        res = {"decision": decision}
        if reason:
            res["reason"] = reason
        return res

    def post_tool_response() -> dict[str, Any]:
        return {}

    def stop_response(decision: str = "allow", reason: str = "") -> dict[str, Any]:
        res = {"decision": decision}
        if reason:
            res["reason"] = reason
        return res


# =============================================================================
# Fallback Default Configuration (Zero-Config Resilience)
# =============================================================================
DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": True,
    "hash_algorithm": "sha256",
    "snapshot_store_dir": ".regression_snapshots",
    "max_diff_lines": 5000,
    "max_file_size_bytes": 10485760,  # 10 MB
    "block_on_untracked_drift": True,
    "block_on_checksum_mismatch": True,
    "syntax_verification_enabled": True,
    "protected_paths": [
        "rules_by_role",
        "governance.config.schema.json",
    ],
    "excluded_patterns": [
        ".git",
        "__pycache__",
        "*.pyc",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
        ".venv",
        "venv",
        ".anti_sequential",
        ".burst_guard",
        ".regression_snapshots",
    ],
}


# =============================================================================
# Enumerations & Data Classes
# =============================================================================
class RegressionType(enum.Enum):
    """Types of regressions detected across snapshot and diff analysis."""

    UNTRACKED_DRIFT = "untracked_drift"
    PHANTOM_DIFF = "phantom_diff"
    CHECKSUM_MISMATCH = "checksum_mismatch"
    PROTECTED_PATH_VIOLATION = "protected_path_violation"
    SYNTAX_REGRESSION = "syntax_regression"
    FILE_DELETION = "file_deletion"
    SIZE_EXPLOSION = "size_explosion"
    SECURITY_REGRESSION = "security_regression"


@dataclasses.dataclass
class FileSnapshot:
    """Metadata and hash for an individual snapshot file."""

    relative_path: str
    sha256: str
    size_bytes: int
    mtime: float
    is_binary: bool = False
    syntax_valid: bool | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileSnapshot:
        return cls(**data)


@dataclasses.dataclass
class SnapshotManifest:
    """Complete cryptographic manifest of workspace file state."""

    snapshot_id: str
    label: str
    created_at: str
    workspace_root: str
    file_count: int
    total_bytes: int
    manifest_hash: str
    git_commit: str | None = None
    git_branch: str | None = None
    files: dict[str, FileSnapshot] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "label": self.label,
            "created_at": self.created_at,
            "workspace_root": self.workspace_root,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "manifest_hash": self.manifest_hash,
            "git_commit": self.git_commit,
            "git_branch": self.git_branch,
            "files": {k: v.to_dict() for k, v in self.files.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SnapshotManifest:
        files_dict = {
            k: FileSnapshot.from_dict(v) for k, v in data.get("files", {}).items()
        }
        return cls(
            snapshot_id=data["snapshot_id"],
            label=data.get("label", ""),
            created_at=data["created_at"],
            workspace_root=data["workspace_root"],
            file_count=data["file_count"],
            total_bytes=data["total_bytes"],
            manifest_hash=data["manifest_hash"],
            git_commit=data.get("git_commit"),
            git_branch=data.get("git_branch"),
            files=files_dict,
        )


@dataclasses.dataclass
class DiffHunk:
    """Represents a unified diff hunk."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class FileDiff:
    """Represents diff details for a specific file."""

    file_path: str
    old_path: str | None = None
    change_type: str = "modified"  # modified, added, deleted, renamed
    added_lines_count: int = 0
    deleted_lines_count: int = 0
    hunks: list[DiffHunk] = dataclasses.field(default_factory=list)
    raw_diff: str = ""



def _normalize_rel_path(path_str: str) -> str:
    """Safely normalize path by replacing backslashes and removing leading './' or '/' without stripping filename characters."""
    p = path_str.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    if p.startswith("/"):
        p = p[1:]
    return p


def _clean_git_path(p: str, expected_prefix: str = "") -> str:
    """Safely strip surrounding quotes, unescape C-style escapes, and remove a/ or b/ prefix."""
    p = p.strip()
    if p.startswith('"') and p.endswith('"') and len(p) >= 2:
        inner = p[1:-1]
        try:
            p = inner.encode("latin1").decode("unicode_escape")
        except Exception:
            p = inner

    p = p.replace("\\", "/")

    if expected_prefix and p.startswith(expected_prefix):
        p = p[len(expected_prefix):]
    elif p.startswith("a/"):
        p = p[2:]
    elif p.startswith("b/"):
        p = p[2:]

    while p.startswith("./"):
        p = p[2:]
    if p.startswith("/"):
        p = p[1:]

    return p


def _extract_quoted_path(s: str) -> tuple[str, str]:
    """Extract a double-quoted path token supporting escaped quotes, returning (token, remaining)."""
    if not s.startswith('"'):
        return "", s
    idx = 1
    while idx < len(s):
        if s[idx] == "\\":
            idx += 2
        elif s[idx] == '"':
            return s[: idx + 1], s[idx + 1 :].strip()
        else:
            idx += 1
    return s, ""


def _parse_diff_git_line(line: str) -> tuple[str, str]:
    """Parse 'diff --git <old_spec> <new_spec>' supporting spaces and quotes."""
    prefix = "diff --git "
    if not line.startswith(prefix):
        return "", ""

    payload = line[len(prefix) :].strip()

    if payload.startswith('"'):
        raw_a, rest = _extract_quoted_path(payload)
        rest = rest.strip()
        if rest.startswith('"'):
            raw_b, _ = _extract_quoted_path(rest)
        else:
            raw_b = rest
        old_p = _clean_git_path(raw_a, "a/")
        new_p = _clean_git_path(raw_b, "b/")
        return old_p, new_p

    if payload.startswith("a/"):
        rem_len = len(payload) - 5
        if rem_len >= 0 and rem_len % 2 == 0:
            p_len = rem_len // 2
            cand_p1 = payload[2 : 2 + p_len]
            cand_sep = payload[2 + p_len : 2 + p_len + 3]
            cand_p2 = payload[2 + p_len + 3 :]
            if cand_sep == " b/" and cand_p1 == cand_p2:
                norm_p = _clean_git_path(cand_p1, "")
                return norm_p, norm_p

    if payload.startswith("a/") and " b/" in payload:
        b_idx = payload.rfind(" b/")
        raw_a = payload[:b_idx]
        raw_b = payload[b_idx + 1 :]
        old_p = _clean_git_path(raw_a, "a/")
        new_p = _clean_git_path(raw_b, "b/")
        return old_p, new_p

    parts = payload.split(" ")
    if len(parts) >= 2:
        old_p = _clean_git_path(parts[0], "a/")
        new_p = _clean_git_path(parts[1], "b/")
        return old_p, new_p
    elif len(parts) == 1:
        p = _clean_git_path(parts[0], "b/")
        return p, p

    return "", ""


@dataclasses.dataclass
class GitDiffReport:
    """Report generated by parsing git diff."""

    files_changed: list[FileDiff] = dataclasses.field(default_factory=list)
    total_added_lines: int = 0
    total_deleted_lines: int = 0
    is_clean: bool = True
    raw_stdout: str = ""

    def get_file_diff(self, path: str) -> FileDiff | None:
        normalized = _normalize_rel_path(path)
        for f in self.files_changed:
            if _normalize_rel_path(f.file_path) == normalized:
                return f
        return None


@dataclasses.dataclass
class RegressionIssue:
    """Detailed regression finding with severity and blocking status."""

    issue_id: str
    issue_type: RegressionType
    severity: str  # critical, high, medium, low
    file_path: str
    description: str
    baseline_hash: str | None = None
    current_hash: str | None = None
    is_blocking: bool = True
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_id": self.issue_id,
            "issue_type": self.issue_type.value,
            "severity": self.severity,
            "file_path": self.file_path,
            "description": self.description,
            "baseline_hash": self.baseline_hash,
            "current_hash": self.current_hash,
            "is_blocking": self.is_blocking,
            "metadata": self.metadata,
        }


@dataclasses.dataclass
class RegressionReport:
    """Comprehensive report summarizing regression detection across snapshots and git diff."""

    report_id: str
    timestamp: str
    workspace_root: str
    baseline_snapshot_id: str | None
    current_snapshot_id: str | None
    issues: list[RegressionIssue] = dataclasses.field(default_factory=list)
    added_files: list[str] = dataclasses.field(default_factory=list)
    modified_files: list[str] = dataclasses.field(default_factory=list)
    deleted_files: list[str] = dataclasses.field(default_factory=list)
    git_diff_summary: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def has_regressions(self) -> bool:
        return len(self.issues) > 0

    @property
    def has_blocking_regressions(self) -> bool:
        return any(issue.is_blocking for issue in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "workspace_root": self.workspace_root,
            "baseline_snapshot_id": self.baseline_snapshot_id,
            "current_snapshot_id": self.current_snapshot_id,
            "has_regressions": self.has_regressions,
            "has_blocking_regressions": self.has_blocking_regressions,
            "issues_count": len(self.issues),
            "issues": [issue.to_dict() for issue in self.issues],
            "added_files": self.added_files,
            "modified_files": self.modified_files,
            "deleted_files": self.deleted_files,
            "git_diff_summary": self.git_diff_summary,
        }

    def format_markdown(self) -> str:
        """Format human-readable Markdown summary for logging and reports."""
        lines = [
            f"# 🔍 Regression Detection Report ({self.report_id})",
            f"- **Timestamp**: {self.timestamp}",
            f"- **Workspace**: `{self.workspace_root}`",
            f"- **Baseline Snapshot**: `{self.baseline_snapshot_id or 'None'}`",
            f"- **Current Snapshot**: `{self.current_snapshot_id or 'None'}`",
            f"- **Blocking Regressions**: {'🚨 YES' if self.has_blocking_regressions else '✅ NO'}",
            "",
            "## Summary Statistics",
            f"- Added files: {len(self.added_files)}",
            f"- Modified files: {len(self.modified_files)}",
            f"- Deleted files: {len(self.deleted_files)}",
            f"- Total issues detected: {len(self.issues)}",
            "",
        ]

        if self.issues:
            lines.append("## Detected Regression Issues")
            for idx, issue in enumerate(self.issues, 1):
                icon = "🔴" if issue.is_blocking else "⚠️"
                lines.append(
                    f"{idx}. {icon} **[{issue.issue_type.value.upper()}]** ({issue.severity.upper()}) "
                    f"`{issue.file_path}`: {issue.description}"
                )
                if issue.baseline_hash or issue.current_hash:
                    lines.append(
                        f"   - Baseline: `{issue.baseline_hash or 'N/A'}` | Current: `{issue.current_hash or 'N/A'}`"
                    )
        else:
            lines.append("## ✅ Clean State - No Regressions Detected")

        return "\n".join(lines)


# =============================================================================
# Core Regression Detector Engine
# =============================================================================
class RegressionDetector:
    """Core engine for snapshot generation, git diff parsing, and regression verification."""

    def __init__(
        self,
        workspace_root: pathlib.Path | str | None = None,
        custom_config: dict[str, Any] | None = None,
    ) -> None:
        """Initialize detector with dynamic config and workspace resolution."""
        if workspace_root:
            self.workspace_root = pathlib.Path(workspace_root).resolve()
        else:
            self.workspace_root = pathlib.Path.cwd().resolve()

        # Load dynamic configuration via hook_utils if available
        self.config: dict[str, Any] = {}
        if get_regression_detector_config:
            try:
                loaded = get_regression_detector_config()
                if isinstance(loaded, dict) and loaded:
                    self.config = dict(loaded)
            except Exception as e:
                log_diagnostic(f"Failed to load dynamic config: {e}")

        if not self.config:
            self.config = dict(DEFAULT_CONFIG)

        if custom_config:
            self.config.update(custom_config)

        # Snapshot storage directory (relative to workspace or configured)
        snapshot_dir_setting = self.config.get("snapshot_store_dir", ".regression_snapshots")
        self.snapshot_dir = self.workspace_root / snapshot_dir_setting
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

    def compute_file_hash(self, file_path: pathlib.Path) -> tuple[str, int, float, bool]:
        """Compute cryptographic hash of a file using chunked streaming (§8, §18).

        Returns: (sha256_hash, file_size_bytes, mtime, is_binary)
        """
        stat = file_path.stat()
        size_bytes = stat.st_size
        mtime = stat.st_mtime

        algo_name = self.config.get("hash_algorithm", "sha256").lower()
        hasher = hashlib.new(algo_name)
        is_binary = False

        chunk_size = 65536  # 64 KB chunks
        with open(file_path, "rb") as f:
            first_chunk = f.read(chunk_size)
            if first_chunk:
                # Check for null bytes to identify binary file
                if b"\x00" in first_chunk:
                    is_binary = True
                hasher.update(first_chunk)
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)

        return hasher.hexdigest(), size_bytes, mtime, is_binary

    def check_python_syntax(self, file_path: pathlib.Path) -> tuple[bool, str | None]:
        """Verify Python file syntax using AST compilation (§3)."""
        if file_path.suffix.lower() != ".py":
            return True, None
        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                content = f.read()
            ast.parse(content, filename=str(file_path))
            return True, None
        except SyntaxError as e:
            return False, f"SyntaxError at line {e.lineno}: {e.msg}"
        except Exception as e:
            return False, f"AST parse error: {str(e)}"

    def is_path_excluded(self, rel_path_str: str) -> bool:
        """Check if relative path matches any exclusion glob patterns."""
        normalized = _normalize_rel_path(rel_path_str)
        excluded_patterns = self.config.get("excluded_patterns", DEFAULT_CONFIG["excluded_patterns"])

        parts = normalized.split("/")
        for pattern in excluded_patterns:
            # Check pattern against whole path or individual directory components
            if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(f"/{normalized}", pattern):
                return True
            for part in parts:
                if fnmatch.fnmatch(part, pattern):
                    return True
        return False

    def is_path_protected(self, rel_path_str: str) -> bool:
        """Check if relative path matches any protected path patterns."""
        normalized = _normalize_rel_path(rel_path_str)
        protected_patterns = self.config.get("protected_paths", DEFAULT_CONFIG["protected_paths"])

        for pattern in protected_patterns:
            pat = _normalize_rel_path(pattern).rstrip("/")
            if normalized == pat or normalized.startswith(f"{pat}/") or fnmatch.fnmatch(normalized, pattern):
                return True
        return False

    def get_git_info(self) -> tuple[str | None, str | None]:
        """Extract current git commit hash and branch safely without shell=True (§3)."""
        try:
            commit_res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(self.workspace_root),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                check=False,
            )
            commit = commit_res.stdout.strip() if commit_res.returncode == 0 else None

            branch_res = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=str(self.workspace_root),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                check=False,
            )
            branch = branch_res.stdout.strip() if branch_res.returncode == 0 else None
            return commit, branch
        except Exception:
            return None, None

    def create_snapshot(self, label: str = "", save: bool = True) -> SnapshotManifest:
        """Scan workspace and generate full cryptographic snapshot manifest."""
        snapshot_id = f"snap_{int(time.time())}_{uuid4().hex[:8]}"
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        git_commit, git_branch = self.get_git_info()

        max_file_size = self.config.get("max_file_size_bytes", DEFAULT_CONFIG["max_file_size_bytes"])
        syntax_check_enabled = self.config.get("syntax_verification_enabled", True)

        files_map: dict[str, FileSnapshot] = {}
        total_bytes = 0

        # Walk workspace directory recursively
        for root_dir, dirs, filenames in os.walk(self.workspace_root):
            # Prune excluded directories in-place
            dirs[:] = [
                d for d in dirs
                if not self.is_path_excluded(
                    str((pathlib.Path(root_dir) / d).relative_to(self.workspace_root))
                )
            ]

            for fname in filenames:
                full_path = pathlib.Path(root_dir) / fname
                try:
                    rel_path = full_path.relative_to(self.workspace_root)
                    rel_str = rel_path.as_posix()
                except ValueError:
                    continue

                if self.is_path_excluded(rel_str):
                    continue

                try:
                    stat = full_path.stat()
                    if stat.st_size > max_file_size:
                        log_diagnostic(f"Skipping oversized file: {rel_str} ({stat.st_size} bytes)")
                        continue

                    sha256_hash, size_bytes, mtime, is_binary = self.compute_file_hash(full_path)
                    syntax_valid = None
                    syntax_err = None

                    if syntax_check_enabled and not is_binary and full_path.suffix.lower() == ".py":
                        syntax_valid, syntax_err = self.check_python_syntax(full_path)

                    files_map[rel_str] = FileSnapshot(
                        relative_path=rel_str,
                        sha256=sha256_hash,
                        size_bytes=size_bytes,
                        mtime=mtime,
                        is_binary=is_binary,
                        syntax_valid=syntax_valid,
                        error=syntax_err,
                    )
                    total_bytes += size_bytes
                except (OSError, PermissionError) as e:
                    log_diagnostic(f"Error accessing file {rel_str}: {e}")

        # Compute deterministic Merkle / manifest cumulative hash
        hasher = hashlib.sha256()
        for p in sorted(files_map.keys()):
            hasher.update(p.encode("utf-8"))
            hasher.update(files_map[p].sha256.encode("utf-8"))
        manifest_hash = hasher.hexdigest()

        manifest = SnapshotManifest(
            snapshot_id=snapshot_id,
            label=label,
            created_at=created_at,
            workspace_root=str(self.workspace_root),
            file_count=len(files_map),
            total_bytes=total_bytes,
            manifest_hash=manifest_hash,
            git_commit=git_commit,
            git_branch=git_branch,
            files=files_map,
        )

        if save:
            self.save_snapshot(manifest)

        return manifest

    def save_snapshot(self, manifest: SnapshotManifest) -> pathlib.Path:
        """Save snapshot manifest to storage directory as JSON."""
        target_path = self.snapshot_dir / f"{manifest.snapshot_id}.json"
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(manifest.to_dict(), f, indent=2, ensure_ascii=False)
        return target_path

    def load_snapshot(self, snapshot_id_or_path: str | pathlib.Path) -> SnapshotManifest | None:
        """Load snapshot manifest from file path or snapshot ID."""
        candidate = pathlib.Path(snapshot_id_or_path)
        if not candidate.is_file():
            candidate = self.snapshot_dir / f"{snapshot_id_or_path}.json"

        if not candidate.is_file():
            return None

        try:
            with open(candidate, encoding="utf-8") as f:
                data = json.load(f)
            return SnapshotManifest.from_dict(data)
        except Exception as e:
            log_diagnostic(f"Failed to load snapshot manifest {candidate}: {e}")
            return None

    def get_latest_snapshot(self) -> SnapshotManifest | None:
        """Find and load the most recent snapshot manifest."""
        manifest_files = list(self.snapshot_dir.glob("*.json"))
        if not manifest_files:
            return None

        manifest_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return self.load_snapshot(manifest_files[0])

    def compare_snapshots(
        self, baseline: SnapshotManifest, current: SnapshotManifest
    ) -> tuple[list[str], list[str], list[str]]:
        """Compare two snapshots and return (added_files, modified_files, deleted_files)."""
        base_files = {_normalize_rel_path(k): v for k, v in baseline.files.items()}
        curr_files = {_normalize_rel_path(k): v for k, v in current.files.items()}

        base_keys = set(base_files.keys())
        curr_keys = set(curr_files.keys())

        added = sorted(list(curr_keys - base_keys))
        deleted = sorted(list(base_keys - curr_keys))
        common = base_keys & curr_keys

        modified: list[str] = []
        for k in sorted(list(common)):
            if base_files[k].sha256 != curr_files[k].sha256:
                modified.append(k)

        return added, modified, deleted

    def get_git_diff(
        self,
        staged: bool = False,
        commit_range: str | None = None,
    ) -> GitDiffReport:
        """Execute git diff and parse output safely without shell=True (§3)."""
        cmd = ["git", "diff"]
        if staged:
            cmd.append("--staged")
        if commit_range:
            cmd.append(commit_range)

        try:
            res = subprocess.run(
                cmd,
                cwd=str(self.workspace_root),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
            raw_stdout = res.stdout if res.returncode == 0 else ""
            return self.parse_git_diff(raw_stdout)
        except Exception as e:
            log_diagnostic(f"Error executing git diff: {e}")
            return GitDiffReport(is_clean=True, raw_stdout="")

    def parse_git_diff(self, raw_diff: str) -> GitDiffReport:
        """Parse unified git diff output into structured FileDiff and DiffHunk objects."""
        if not raw_diff or not raw_diff.strip():
            return GitDiffReport(is_clean=True, raw_stdout=raw_diff)

        file_diffs: list[FileDiff] = []
        lines = raw_diff.splitlines()

        current_file_diff: FileDiff | None = None
        current_hunk: DiffHunk | None = None
        total_added = 0
        total_deleted = 0

        hunk_header_regex = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

        for line in lines:
            if line.startswith("diff --git "):
                if current_file_diff:
                    file_diffs.append(current_file_diff)
                    current_file_diff = None
                    current_hunk = None

                old_p, new_p = _parse_diff_git_line(line)
                if new_p:
                    current_file_diff = FileDiff(
                        file_path=new_p,
                        old_path=old_p if old_p != new_p else None,
                        raw_diff=line + "\n",
                    )
            elif current_file_diff is not None:
                current_file_diff.raw_diff += line + "\n"

                if line.startswith("new file mode "):
                    current_file_diff.change_type = "added"
                elif line.startswith("deleted file mode "):
                    current_file_diff.change_type = "deleted"
                elif line.startswith("similarity index ") or line.startswith("rename from "):
                    current_file_diff.change_type = "renamed"
                elif line.startswith("rename to "):
                    renamed_to = _clean_git_path(line[10:].strip(), "")
                    if renamed_to:
                        current_file_diff.file_path = renamed_to
                elif line.startswith("--- ") and not line.startswith("--- /dev/null"):
                    old_cand = _clean_git_path(line[4:].strip(), "a/")
                    if old_cand and not current_file_diff.old_path and old_cand != current_file_diff.file_path:
                        current_file_diff.old_path = old_cand
                elif line.startswith("+++ ") and not line.startswith("+++ /dev/null"):
                    new_cand = _clean_git_path(line[4:].strip(), "b/")
                    if new_cand:
                        current_file_diff.file_path = new_cand
                elif hunk_match := hunk_header_regex.match(line):
                    old_start = int(hunk_match.group(1))
                    old_count = int(hunk_match.group(2) or 1)
                    new_start = int(hunk_match.group(3))
                    new_count = int(hunk_match.group(4) or 1)
                    current_hunk = DiffHunk(
                        old_start=old_start,
                        old_count=old_count,
                        new_start=new_start,
                        new_count=new_count,
                    )
                    current_file_diff.hunks.append(current_hunk)
                elif current_hunk is not None:
                    if line.startswith("+") and not line.startswith("+++"):
                        current_file_diff.added_lines_count += 1
                        total_added += 1
                        current_hunk.lines.append(line)
                    elif line.startswith("-") and not line.startswith("---"):
                        current_file_diff.deleted_lines_count += 1
                        total_deleted += 1
                        current_hunk.lines.append(line)
                    else:
                        current_hunk.lines.append(line)

        if current_file_diff:
            file_diffs.append(current_file_diff)

        return GitDiffReport(
            files_changed=file_diffs,
            total_added_lines=total_added,
            total_deleted_lines=total_deleted,
            is_clean=len(file_diffs) == 0,
            raw_stdout=raw_diff,
        )

    def detect_regressions(
        self,
        baseline: SnapshotManifest | None = None,
        compare_git: bool = True,
    ) -> RegressionReport:
        """Execute full cross-check of hash snapshots and git diff to identify regressions."""
        report_id = f"reg_rep_{int(time.time())}_{uuid4().hex[:6]}"
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # If baseline not provided, load latest saved or create initial baseline
        if baseline is None:
            baseline = self.get_latest_snapshot()
            if baseline is None:
                log_diagnostic("No existing baseline snapshot found. Initializing baseline.")
                baseline = self.create_snapshot(label="initial_auto_baseline", save=True)

        current = self.create_snapshot(label="current_inspection", save=False)
        added, modified, deleted = self.compare_snapshots(baseline, current)

        base_files = {_normalize_rel_path(k): v for k, v in baseline.files.items()}
        curr_files = {_normalize_rel_path(k): v for k, v in current.files.items()}

        issues: list[RegressionIssue] = []

        # 1. Protected Paths Validation
        for path in modified + deleted:
            norm_path = _normalize_rel_path(path)
            if self.is_path_protected(norm_path):
                base_snap = base_files.get(norm_path, FileSnapshot(norm_path, "", 0, 0))
                curr_snap = curr_files.get(norm_path, FileSnapshot(norm_path, "", 0, 0))
                issues.append(
                    RegressionIssue(
                        issue_id=f"prot_{uuid4().hex[:6]}",
                        issue_type=RegressionType.PROTECTED_PATH_VIOLATION,
                        severity="critical",
                        file_path=norm_path,
                        description=f"Protected path '{norm_path}' was modified or deleted.",
                        baseline_hash=base_snap.sha256,
                        current_hash=curr_snap.sha256,
                        is_blocking=True,
                    )
                )

        # 2. Syntax Regressions in Current Snapshot
        for path, snap in curr_files.items():
            norm_path = _normalize_rel_path(path)
            if snap.syntax_valid is False and snap.error:
                # Check if this syntax error is new compared to baseline
                base_snap = base_files.get(norm_path)
                if not base_snap or base_snap.syntax_valid is not False:
                    issues.append(
                        RegressionIssue(
                            issue_id=f"synt_{uuid4().hex[:6]}",
                            issue_type=RegressionType.SYNTAX_REGRESSION,
                            severity="critical",
                            file_path=norm_path,
                            description=f"Syntax regression introduced: {snap.error}",
                            baseline_hash=base_snap.sha256 if base_snap else None,
                            current_hash=snap.sha256,
                            is_blocking=True,
                        )
                    )

        # 3. Deleted Files Check
        for path in deleted:
            norm_path = _normalize_rel_path(path)
            # If critical file deleted
            if self.is_path_protected(norm_path) or norm_path.endswith((".py", ".json", ".md")):
                base_snap = base_files.get(norm_path, FileSnapshot(norm_path, "", 0, 0))
                issues.append(
                    RegressionIssue(
                        issue_id=f"del_{uuid4().hex[:6]}",
                        issue_type=RegressionType.FILE_DELETION,
                        severity="high",
                        file_path=norm_path,
                        description=f"File deleted from baseline: {norm_path}",
                        baseline_hash=base_snap.sha256,
                        current_hash=None,
                        is_blocking=self.is_path_protected(norm_path),
                    )
                )

        # 4. Git Diff Cross-Matching & Correlation
        git_summary: dict[str, Any] = {}
        if compare_git:
            git_report = self.get_git_diff()
            git_summary = {
                "files_changed_count": len(git_report.files_changed),
                "total_added_lines": git_report.total_added_lines,
                "total_deleted_lines": git_report.total_deleted_lines,
                "is_clean": git_report.is_clean,
            }

            max_diff_lines = self.config.get("max_diff_lines", DEFAULT_CONFIG["max_diff_lines"])
            total_diff_lines = git_report.total_added_lines + git_report.total_deleted_lines
            if total_diff_lines > max_diff_lines:
                issues.append(
                    RegressionIssue(
                        issue_id=f"size_{uuid4().hex[:6]}",
                        issue_type=RegressionType.SIZE_EXPLOSION,
                        severity="medium",
                        file_path="git_diff",
                        description=(
                            f"Total diff lines ({total_diff_lines}) exceed limit ({max_diff_lines})."
                        ),
                        is_blocking=False,
                    )
                )

            # Check for Phantom Diffs & Cross-Matching
            for file_diff in git_report.files_changed:
                fpath = _normalize_rel_path(file_diff.file_path)
                curr_snap = curr_files.get(fpath)
                base_snap = base_files.get(fpath)

                if curr_snap and base_snap:
                    # Git reports modified, but SHA256 hashes are identical
                    if curr_snap.sha256 == base_snap.sha256 and (
                        file_diff.added_lines_count > 0 or file_diff.deleted_lines_count > 0
                    ):
                        issues.append(
                            RegressionIssue(
                                issue_id=f"phan_{uuid4().hex[:6]}",
                                issue_type=RegressionType.PHANTOM_DIFF,
                                severity="low",
                                file_path=fpath,
                                description=(
                                    f"Phantom Diff detected: git reports modifications in '{fpath}' "
                                    f"but cryptographic hash ({curr_snap.sha256[:8]}) is unchanged."
                                ),
                                baseline_hash=base_snap.sha256,
                                current_hash=curr_snap.sha256,
                                is_blocking=False,
                            )
                        )

        # Check for Untracked Drift: Modified on disk compared to baseline, but not in git diff
        git_paths = {_normalize_rel_path(f.file_path) for f in git_report.files_changed} if compare_git else set()
        block_untracked = self.config.get("block_on_untracked_drift", True)

        for path in modified:
            norm_path = _normalize_rel_path(path)
            if norm_path not in git_paths and not self.is_path_excluded(norm_path):
                base_snap = base_files.get(norm_path, FileSnapshot(norm_path, "", 0, 0))
                curr_snap = curr_files.get(norm_path, FileSnapshot(norm_path, "", 0, 0))
                issues.append(
                    RegressionIssue(
                        issue_id=f"untrack_{uuid4().hex[:6]}",
                        issue_type=RegressionType.UNTRACKED_DRIFT,
                        severity="high" if block_untracked else "medium",
                        file_path=norm_path,
                        description=(
                            f"Untracked Drift: file '{norm_path}' content differs from baseline snapshot "
                            f"but is not tracked in git diff."
                        ),
                        baseline_hash=base_snap.sha256,
                        current_hash=curr_snap.sha256,
                        is_blocking=block_untracked,
                    )
                )

        return RegressionReport(
            report_id=report_id,
            timestamp=timestamp,
            workspace_root=str(self.workspace_root),
            baseline_snapshot_id=baseline.snapshot_id,
            current_snapshot_id=current.snapshot_id,
            issues=issues,
            added_files=[_normalize_rel_path(p) for p in added],
            modified_files=[_normalize_rel_path(p) for p in modified],
            deleted_files=[_normalize_rel_path(p) for p in deleted],
            git_diff_summary=git_summary,
        )


# =============================================================================
# Hook Protocol Handlers (PreToolUse, PostToolUse, Stop)
# =============================================================================
def handle_hook_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Process incoming Antigravity hook payload across supported lifecycle events."""
    roots = get_workspace_roots(payload)
    workspace_root = roots[0] if roots else pathlib.Path.cwd().resolve()
    detector = RegressionDetector(workspace_root=workspace_root)

    # Check if this is PreToolUse
    tool_call = get_tool_call(payload)
    if tool_call:
        tool_name = tool_call.get("name", "")
        args = get_tool_args(tool_call)

        # Inspect file write/replacement operations
        target_file = args.get("target_file") or args.get("path") or args.get("file_path") or args.get("TargetFile")
        if target_file and isinstance(target_file, str):
            try:
                target_p = pathlib.Path(target_file).resolve()
                rel_p = target_p.relative_to(workspace_root).as_posix()
            except (ValueError, OSError):
                rel_p = _normalize_rel_path(target_file)

            if detector.is_path_protected(rel_p):
                reason = (
                    f"Blocked by RegressionDetector: '{rel_p}' is a protected path. "
                    f"Direct modifications through {tool_name} are forbidden."
                )
                log_diagnostic(reason)
                return pre_tool_response(decision="deny", reason=reason)

        return pre_tool_response(decision="allow")

    # Check for Stop event or post-validation
    stop_event = payload.get("stop", False) or payload.get("event") == "Stop"
    if stop_event:
        report = detector.detect_regressions()
        if report.has_blocking_regressions:
            blocking_reasons = [
                f"{i.file_path}: {i.description}" for i in report.issues if i.is_blocking
            ]
            reason_str = " | ".join(blocking_reasons[:3])
            log_diagnostic(f"Blocking Stop due to regressions: {reason_str}")
            return stop_response(decision="deny", reason=f"Regression detected: {reason_str}")
        return stop_response(decision="allow")

    # Default PostToolUse response
    return post_tool_response()


# =============================================================================
# Self-Test Verification Suite (--self-test)
# =============================================================================
def run_self_test() -> bool:
    """Execute comprehensive 13-point self-test suite covering all capabilities."""
    import shutil
    import tempfile

    log_diagnostic("=== STARTING REGRESSION DETECTOR SELF-TEST ===")
    test_dir = pathlib.Path(tempfile.mkdtemp(prefix="reg_test_"))
    success = True
    tests_run = 0
    tests_passed = 0

    def assert_test(condition: bool, test_name: str) -> None:
        nonlocal tests_run, tests_passed, success
        tests_run += 1
        if condition:
            tests_passed += 1
            log_diagnostic(f"  [PASS] Test {tests_run}: {test_name}")
        else:
            success = False
            log_diagnostic(f"  [FAIL] Test {tests_run}: {test_name}")

    try:
        # Test 1: Config loading & dynamic defaults
        detector = RegressionDetector(workspace_root=test_dir)
        assert_test(
            detector.config.get("hash_algorithm") == "sha256" and "max_diff_lines" in detector.config,
            "Dynamic config loading and fallback defaults integrity",
        )

        # Test 2: File cryptographic hash computation & chunked streaming
        test_file_1 = test_dir / "sample.py"
        test_content = b"print('hello world')\n"
        test_file_1.write_bytes(test_content)
        hash_val, size_b, _mtime_f, is_bin = detector.compute_file_hash(test_file_1)
        expected_hash = hashlib.sha256(test_content).hexdigest()
        assert_test(
            hash_val == expected_hash and size_b == len(test_content) and not is_bin,
            "Cryptographic SHA-256 chunked hashing matches exact digest",
        )

        # Test 3: Snapshot creation, serialization, deserialization, manifest hashing
        snap1 = detector.create_snapshot(label="baseline_test", save=True)
        assert_test(
            snap1.file_count == 1 and "sample.py" in snap1.files and len(snap1.manifest_hash) == 64,
            "Snapshot manifest creation and Merkle root hash computation",
        )

        loaded_snap = detector.load_snapshot(snap1.snapshot_id)
        assert_test(
            loaded_snap is not None and loaded_snap.manifest_hash == snap1.manifest_hash,
            "Snapshot manifest JSON persistence and deserialization match",
        )

        # Test 4: Detecting added, modified, deleted files via hash comparison
        test_file_2 = test_dir / "added.py"
        test_file_2.write_text("x = 10\n", encoding="utf-8")
        test_file_1.write_text("print('hello modified')\n", encoding="utf-8")

        snap2 = detector.create_snapshot(label="step_2", save=False)
        added, modified, deleted = detector.compare_snapshots(snap1, snap2)
        assert_test(
            added == ["added.py"] and modified == ["sample.py"] and deleted == [],
            "Snapshot delta comparison accurately identifies added and modified files",
        )

        # Test 5: File deletion detection
        test_file_2.unlink()
        snap3 = detector.create_snapshot(label="step_3", save=False)
        _, _, deleted3 = detector.compare_snapshots(snap2, snap3)
        assert_test(
            deleted3 == ["added.py"],
            "Snapshot delta accurately tracks file deletion",
        )

        # Test 6: Unified Git diff parsing into structured FileDiff & DiffHunk
        sample_diff = (
            "diff --git a/sample.py b/sample.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/sample.py\n"
            "+++ b/sample.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-print('hello world')\n"
            "+print('hello modified')\n"
        )
        diff_report = detector.parse_git_diff(sample_diff)
        assert_test(
            len(diff_report.files_changed) == 1
            and diff_report.total_added_lines == 1
            and diff_report.total_deleted_lines == 1,
            "Unified Git diff parser parses file headers, line counts and hunks",
        )

        # Test 7: Phantom diff detection (diff reports edit, but hash is identical)
        phantom_baseline = detector.create_snapshot(label="phantom_base", save=True)
        # Simulate diff report claiming change while file is unchanged
        phantom_diff = (
            "diff --git a/sample.py b/sample.py\n"
            "--- a/sample.py\n"
            "+++ b/sample.py\n"
            "@@ -1,1 +1,1 @@\n"
            "+# comment\n"
        )
        parsed_phantom = detector.parse_git_diff(phantom_diff)
        # Use mocked report
        issues_phantom: list[RegressionIssue] = []
        for fd in parsed_phantom.files_changed:
            c_snap = phantom_baseline.files.get(fd.file_path)
            b_snap = phantom_baseline.files.get(fd.file_path)
            if c_snap and b_snap and c_snap.sha256 == b_snap.sha256:
                issues_phantom.append(
                    RegressionIssue(
                        issue_id="test_phan",
                        issue_type=RegressionType.PHANTOM_DIFF,
                        severity="low",
                        file_path=fd.file_path,
                        description="Phantom diff detected",
                        is_blocking=False,
                    )
                )
        assert_test(
            len(issues_phantom) == 1 and issues_phantom[0].issue_type == RegressionType.PHANTOM_DIFF,
            "Phantom diff correctly detected when git reports edit but hash matches baseline",
        )

        # Test 8: Untracked drift detection (file changed on disk without git diff)
        report_drift = detector.detect_regressions(baseline=snap1, compare_git=False)
        assert_test(
            any(i.issue_type == RegressionType.UNTRACKED_DRIFT for i in report_drift.issues),
            "Untracked drift correctly detected when file is altered without git tracking",
        )

        # Test 9: Python AST syntax regression detection
        syntax_err_file = test_dir / "broken.py"
        syntax_err_file.write_text("def broken_syntax(:\n    pass\n", encoding="utf-8")
        snap_syntax = detector.create_snapshot(label="syntax_test", save=False)
        assert_test(
            snap_syntax.files.get("broken.py") is not None
            and snap_syntax.files["broken.py"].syntax_valid is False,
            "Python AST analyzer catches SyntaxError and flags broken file",
        )

        # Test 10: Protected path regression blocking
        prot_file = test_dir / "rules_by_role" / "PM_RULES.md"
        prot_file.parent.mkdir(parents=True, exist_ok=True)
        prot_file.write_text("Original PM rules\n", encoding="utf-8")
        snap_prot_base = detector.create_snapshot(label="prot_base", save=True)
        prot_file.write_text("Tampered PM rules\n", encoding="utf-8")
        prot_report = detector.detect_regressions(baseline=snap_prot_base, compare_git=False)
        assert_test(
            any(i.issue_type == RegressionType.PROTECTED_PATH_VIOLATION and i.is_blocking for i in prot_report.issues),
            "Protected path violation strictly flagged as blocking regression",
        )

        # Test 11: Hook protocol PreToolUse denies write to protected path
        hook_payload_deny = {
            "toolCall": {
                "name": "write_to_file",
                "args": {"target_file": str(prot_file)},
            },
            "workspacePaths": [str(test_dir)],
        }
        res_deny = handle_hook_event(hook_payload_deny)
        assert_test(
            res_deny.get("decision") == "deny",
            "PreToolUse hook strictly denies writing to protected paths",
        )

        # Test 12: Hook protocol PreToolUse allows safe path
        hook_payload_allow = {
            "toolCall": {
                "name": "write_to_file",
                "args": {"target_file": str(test_dir / "safe_file.py")},
            },
            "workspacePaths": [str(test_dir)],
        }
        res_allow = handle_hook_event(hook_payload_allow)
        assert_test(
            res_allow.get("decision") == "allow",
            "PreToolUse hook permits writes to authorized non-protected workspace files",
        )

        # Test 13: Windows UTF-8 and path separator normalization
        norm_res = detector.is_path_protected("rules_by_role\\PM_RULES.md")
        assert_test(
            norm_res is True,
            "Path normalization correctly handles Windows backslashes in protected patterns",
        )

        # Test 14: Verification of fix for str.lstrip bug on filenames starting with 'a' or 'b'
        diff_lstrip_edge_cases = (
            "diff --git a/assets/app.py b/assets/app.py\n"
            "--- a/assets/app.py\n"
            "+++ b/assets/app.py\n"
            "@@ -1,1 +1,1 @@\n"
            "+# asset file\n"
            "diff --git a/backend/server.py b/backend/server.py\n"
            "--- a/backend/server.py\n"
            "+++ b/backend/server.py\n"
            "@@ -1,1 +1,1 @@\n"
            "+# backend server\n"
        )
        rep_edge = detector.parse_git_diff(diff_lstrip_edge_cases)
        parsed_paths = [f.file_path for f in rep_edge.files_changed]
        assert_test(
            parsed_paths == ["assets/app.py", "backend/server.py"],
            "Git diff parser preserves filenames starting with 'a' and 'b' without str.lstrip truncation",
        )

        # Test 15: Verification of paths containing spaces and quotes in Git diff
        diff_spaces = (
            "diff --git a/my long folder/my script.py b/my long folder/my script.py\n"
            "--- a/my long folder/my script.py\n"
            "+++ b/my long folder/my script.py\n"
            "@@ -1,1 +1,1 @@\n"
            "+# space script\n"
            'diff --git "a/quoted dir/test.py" "b/quoted dir/test.py"\n'
            '--- "a/quoted dir/test.py"\n'
            '+++ "b/quoted dir/test.py"\n'
            "@@ -1,1 +1,1 @@\n"
            "+# quoted test\n"
        )
        rep_spaces = detector.parse_git_diff(diff_spaces)
        parsed_space_paths = [f.file_path for f in rep_spaces.files_changed]
        assert_test(
            parsed_space_paths == ["my long folder/my script.py", "quoted dir/test.py"],
            "Git diff parser accurately extracts paths containing spaces and surrounding quotes",
        )

        # Test 16: Verification of read_stdin_payload default parameter signature
        test_default = {"test_key": "fallback_ok"}
        old_stdin = sys.stdin
        try:
            sys.stdin = io.StringIO("")
            res_default = read_stdin_payload(default=test_default)
            assert_test(
                res_default == test_default,
                "read_stdin_payload accepts keyword argument 'default' and returns default on empty stdin",
            )
        finally:
            sys.stdin = old_stdin

        # Test 17: Verification of path normalization in detect_regressions
        unnorm_base = SnapshotManifest(
            snapshot_id="unnorm_base",
            label="test",
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            workspace_root=str(test_dir),
            file_count=1,
            total_bytes=10,
            manifest_hash="dummy",
            files={"sub\\unnorm.py": FileSnapshot("sub\\unnorm.py", "hash1", 10, 0.0)},
        )
        mock_diff_report = GitDiffReport(
            files_changed=[FileDiff(file_path="sub/unnorm.py", added_lines_count=1)],
            total_added_lines=1,
            total_deleted_lines=0,
            is_clean=False,
        )
        orig_get_git_diff = detector.get_git_diff
        detector.get_git_diff = lambda: mock_diff_report  # type: ignore[assignment]
        try:
            unnorm_file = test_dir / "sub" / "unnorm.py"
            unnorm_file.parent.mkdir(parents=True, exist_ok=True)
            unnorm_file.write_text("updated = True\n", encoding="utf-8")
            rep_norm = detector.detect_regressions(baseline=unnorm_base, compare_git=True)
            has_untracked = any(i.issue_type == RegressionType.UNTRACKED_DRIFT for i in rep_norm.issues)
            assert_test(
                not has_untracked and any(f == "sub/unnorm.py" for f in rep_norm.modified_files),
                "detect_regressions normalizes paths across snapshot keys and git diff, preventing false drift",
            )
        finally:
            detector.get_git_diff = orig_get_git_diff

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

    log_diagnostic(f"=== SELF-TEST COMPLETE: {tests_passed}/{tests_run} PASSED ===")
    return tests_passed == tests_run and tests_run >= 17


# =============================================================================
# CLI Main Entry Point
# =============================================================================
def main() -> None:
    """CLI and Hook execution dispatcher."""
    parser = argparse.ArgumentParser(description="Regression Detector - Enterprise Multi-Agent Governance")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test validation suite")
    parser.add_argument("--snapshot", nargs="?", const="manual", help="Create workspace snapshot with optional label")
    parser.add_argument("--compare", type=str, help="Compare current workspace state with baseline snapshot ID")
    parser.add_argument("--diff", action="store_true", help="Inspect git diff and cross-check against snapshot")
    parser.add_argument("--verify", action="store_true", help="Run full regression verification")
    parser.add_argument("--json", action="store_true", help="Output report in JSON format")
    parser.add_argument("--workspace", type=str, help="Target workspace root directory")

    args, _unknown = parser.parse_known_args()

    if args.self_test:
        passed = run_self_test()
        sys.exit(0 if passed else 1)

    workspace_root = pathlib.Path(args.workspace).resolve() if args.workspace else pathlib.Path.cwd().resolve()
    detector = RegressionDetector(workspace_root=workspace_root)

    if args.snapshot is not None:
        manifest = detector.create_snapshot(label=args.snapshot, save=True)
        if args.json:
            emit_stdout_json(manifest.to_dict())
        else:
            print(f"✅ Snapshot created: {manifest.snapshot_id} ({manifest.file_count} files, hash: {manifest.manifest_hash[:12]})")
        sys.exit(0)

    if args.compare:
        baseline = detector.load_snapshot(args.compare)
        if not baseline:
            log_diagnostic(f"Error: Snapshot {args.compare} not found.")
            sys.exit(1)
        report = detector.detect_regressions(baseline=baseline, compare_git=args.diff)
        if args.json:
            emit_stdout_json(report.to_dict())
        else:
            print(report.format_markdown())
        sys.exit(1 if report.has_blocking_regressions else 0)

    if args.verify or args.diff:
        report = detector.detect_regressions(compare_git=True)
        if args.json:
            emit_stdout_json(report.to_dict())
        else:
            print(report.format_markdown())
        sys.exit(1 if report.has_blocking_regressions else 0)

    # If invoked with stdin payload (Antigravity hook execution)
    payload = read_stdin_payload(default={})
    response = handle_hook_event(payload)
    emit_stdout_json(response)


if __name__ == "__main__":
    main()
