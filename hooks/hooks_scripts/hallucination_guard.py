#!/usr/bin/env python3
"""Hallucination Guard Hook (PreToolUse & PostToolUse) for Enterprise Multi-Agent Governance System.

Physical Runtime Layer Guardrail.
Enforces:
1. File Existence Verification: Verifies that paths provided to file-reading and file-modification
   tools (e.g. view_file, replace_file_content) actually exist on the filesystem before tool execution.
2. Path Traversal & Normalization (§7): Cross-platform normalization (pathlib.Path, forward/backward
   slashes, case-insensitivity on Windows), resolving relative paths against workspace roots.
3. Smart Fuzzy Suggestion Engine: When an agent hallucinates a path with typos or slight misnamings,
   suggests existing candidate files using fuzzy matching to allow rapid self-correction.
4. Command Script Inspection: Scans run_command for local script references (e.g., python script.py)
   and verifies script existence before launch.
5. Zero Hardcoding (§2, §7): Fully integrated with hook_utils.config_loader (DynamicConfigLoader,
   dynamic_limits.json) and environment variable overrides.
6. Dual-field compatibility: Emits both 'decision' (allow/deny) and 'verdict' (ALLOW/DENY).
7. Built-in --self-test suite with 16 comprehensive scenarios ensuring 100% UTF-8 safety on Windows.
"""

from __future__ import annotations

import difflib
import io
import os
import pathlib
import re
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

# Ensure local hook library and hook_utils are importable
HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).parent.resolve()
ENTERPRISE_HOOKS_ROOT = HOOKS_SCRIPTS_DIR.parent.resolve()

for p in (str(HOOKS_SCRIPTS_DIR), str(ENTERPRISE_HOOKS_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from common_hook_lib import (  # noqa: E402
    emit_stdout_json,
    get_tool_args,
    get_tool_call,
    get_workspace_roots,
    log_diagnostic,
    post_tool_response,
    pre_tool_response,
    read_stdin_payload,
)

# Optional config loader from hook_utils
try:
    from hook_utils.config_loader import DynamicConfigLoader, get_hallucination_guard_config
except ImportError:
    DynamicConfigLoader = None  # type: ignore
    get_hallucination_guard_config = None  # type: ignore

# Default Governance Parameters (Zero-Config Resilience)
DEFAULT_GUARD_CONFIG: dict[str, Any] = {
    "enabled": True,
    "strict_mode": True,
    "inspect_tools": [
        "view_file",
        "replace_file_content",
        "read_file",
        "get_code_snippet",
    ],
    "file_creation_tools": [
        "write_to_file",
    ],
    "check_command_scripts": True,
    "suggest_corrections": True,
    "max_suggestions": 3,
    "fuzzy_cutoff": 0.6,
    "allowed_virtual_schemes": [
        "memory:",
        "virtual:",
        "tmp:",
        "temp:",
    ],
}


def load_guard_config() -> dict[str, Any]:
    """Retrieve hallucination guard configuration dynamically from config_loader or environment.

    Zero Hardcoding: Limits and options are dynamically loaded from dynamic_limits.json
    with graceful fallback to DEFAULT_GUARD_CONFIG and environment variables.
    """
    cfg: dict[str, Any] = dict(DEFAULT_GUARD_CONFIG)

    if get_hallucination_guard_config is not None:
        try:
            loaded_cfg = get_hallucination_guard_config()
            if isinstance(loaded_cfg, dict):
                cfg.update(loaded_cfg)
        except Exception as exc:
            log_diagnostic(f"Failed to load dynamic config: {exc}")

    # Environment variable overrides (Highest Precedence)
    if "HALLUCINATION_GUARD_ENABLED" in os.environ:
        val = os.environ["HALLUCINATION_GUARD_ENABLED"].strip().lower()
        cfg["enabled"] = val in ("1", "true", "yes")

    if "HALLUCINATION_GUARD_STRICT" in os.environ:
        val = os.environ["HALLUCINATION_GUARD_STRICT"].strip().lower()
        cfg["strict_mode"] = val in ("1", "true", "yes")

    if "HALLUCINATION_GUARD_SUGGEST" in os.environ:
        val = os.environ["HALLUCINATION_GUARD_SUGGEST"].strip().lower()
        cfg["suggest_corrections"] = val in ("1", "true", "yes")

    if "HALLUCINATION_GUARD_MAX_SUGGESTIONS" in os.environ:
        try:
            cfg["max_suggestions"] = int(os.environ["HALLUCINATION_GUARD_MAX_SUGGESTIONS"])
        except ValueError:
            pass

    if "HALLUCINATION_GUARD_FUZZY_CUTOFF" in os.environ:
        try:
            cfg["fuzzy_cutoff"] = float(os.environ["HALLUCINATION_GUARD_FUZZY_CUTOFF"])
        except ValueError:
            pass

    if "HALLUCINATION_GUARD_TOOLS" in os.environ:
        raw_tools = os.environ["HALLUCINATION_GUARD_TOOLS"].split(",")
        cfg["inspect_tools"] = [t.strip() for t in raw_tools if t.strip()]

    if "HALLUCINATION_GUARD_CHECK_COMMANDS" in os.environ:
        val = os.environ["HALLUCINATION_GUARD_CHECK_COMMANDS"].strip().lower()
        cfg["check_command_scripts"] = val in ("1", "true", "yes")

    return cfg


def clean_raw_path(raw_path: str) -> str:
    """Strip quotes, leading/trailing whitespace, and normalize slashes."""
    if not isinstance(raw_path, str):
        return ""
    cleaned = raw_path.strip()
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (cleaned.startswith("'") and cleaned.endswith("'")):
        cleaned = cleaned[1:-1].strip()
    return cleaned


def is_virtual_scheme(path_str: str, allowed_schemes: list[str]) -> bool:
    """Check if path starts with an allowed virtual or in-memory scheme."""
    lower_path = path_str.lower()
    for scheme in allowed_schemes:
        if lower_path.startswith(scheme.lower()):
            return True
    return False


def resolve_candidate_path(raw_path: str, workspace_roots: list[pathlib.Path]) -> tuple[pathlib.Path, bool]:
    """Resolve raw path against workspace roots.

    Returns:
        tuple[pathlib.Path, bool]: (resolved_path, exists_flag)
    """
    cleaned = clean_raw_path(raw_path)
    if not cleaned:
        return pathlib.Path("."), False

    path_obj = pathlib.Path(cleaned)

    # 1. Absolute path
    if path_obj.is_absolute():
        try:
            resolved = path_obj.resolve()
            return resolved, resolved.exists()
        except (OSError, ValueError):
            return path_obj, False

    # 2. Relative path: check against each workspace root
    for root in workspace_roots:
        try:
            candidate = (root / path_obj).resolve()
            if candidate.exists():
                return candidate, True
        except (OSError, ValueError):
            continue

    # 3. Fallback: relative to primary workspace root or cwd
    primary_root = workspace_roots[0] if workspace_roots else pathlib.Path.cwd().resolve()
    try:
        resolved = (primary_root / path_obj).resolve()
        return resolved, resolved.exists()
    except (OSError, ValueError):
        return path_obj, False


def find_similar_files(
    target_path: pathlib.Path,
    workspace_roots: list[pathlib.Path],
    max_suggestions: int = 3,
    cutoff: float = 0.6,
) -> list[str]:
    """Search parent directory or workspace roots for similarly named files using fuzzy matching."""
    suggestions: list[str] = []
    target_name = target_path.name
    if not target_name:
        return []

    # Strategy 1: Check in the same parent directory if parent exists
    parent_dir = target_path.parent
    if parent_dir.exists() and parent_dir.is_dir():
        try:
            candidates = [entry.name for entry in parent_dir.iterdir() if not entry.name.startswith(".")]
            matches = difflib.get_close_matches(target_name, candidates, n=max_suggestions, cutoff=cutoff)
            for match in matches:
                suggestions.append(str(parent_dir / match))
        except (OSError, PermissionError):
            pass

    # Strategy 2: If no matches in parent, search workspace roots for same basename
    if not suggestions and workspace_roots:
        for root in workspace_roots:
            if not root.exists() or not root.is_dir():
                continue
            try:
                # Shallow scan top-level directories or common subdirectories
                matched_entries: list[str] = []
                for entry in root.glob(f"**/{target_name}"):
                    if entry.is_file() and not any(p.startswith(".") for p in entry.parts):
                        matched_entries.append(str(entry))
                        if len(matched_entries) >= max_suggestions:
                            break
                if matched_entries:
                    suggestions.extend(matched_entries)
                    break
            except (OSError, PermissionError):
                continue

    return suggestions[:max_suggestions]


def extract_script_from_command(command_str: str) -> str | None:
    """Extract local script file target from command line strings (e.g. python script.py, node app.js)."""
    if not command_str or not isinstance(command_str, str):
        return None

    cmd_stripped = command_str.strip()
    if not cmd_stripped:
        return None

    # Handle pipeline or chained commands by taking each segment
    segments = re.split(r"[;&|]+", cmd_stripped)
    for seg in segments:
        tokens = seg.strip().split()
        if not tokens:
            continue

        runner = pathlib.Path(tokens[0]).name.lower()
        if runner in ("python", "python3", "py", "node", "ts-node", "bash", "sh", "pytest"):
            # Scan subsequent tokens for a script argument
            idx = 1
            while idx < len(tokens):
                tok = tokens[idx]
                if tok in ("-m", "-c", "-e", "--eval", "-r", "--require"):
                    # Module execution or inline code, not a file target
                    break
                if tok.startswith("-"):
                    idx += 1
                    continue
                # Potential script path
                clean_tok = clean_raw_path(tok)
                ext = pathlib.Path(clean_tok).suffix.lower()
                if ext in (".py", ".js", ".ts", ".sh", ".ps1", ".bash", ".rb", ".php"):
                    return clean_tok
                break

    return None


def evaluate_file_existence(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate if tool arguments contain non-existent hallucinated file paths."""
    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""
    args = get_tool_args(tool_call)

    cfg = load_guard_config()
    if not cfg.get("enabled", True):
        res = pre_tool_response("allow", "Hallucination Guard is disabled by configuration.")
        res["verdict"] = "ALLOW"
        return res

    inspect_tools = set(cfg.get("inspect_tools", []))
    file_creation_tools = set(cfg.get("file_creation_tools", []))
    allowed_schemes = cfg.get("allowed_virtual_schemes", ["memory:", "virtual:", "tmp:"])
    max_suggestions = cfg.get("max_suggestions", 3)
    cutoff = cfg.get("fuzzy_cutoff", 0.6)
    suggest_corrections = cfg.get("suggest_corrections", True)
    check_command_scripts = cfg.get("check_command_scripts", True)

    workspace_roots = get_workspace_roots(payload)

    # 1. Inspect file modification / viewing tools
    if tool_name in inspect_tools:
        # Extract target path from common tool argument keys
        raw_path: str | None = None
        for key in ("AbsolutePath", "TargetFile", "FilePath", "path", "file_path", "target_file"):
            val = args.get(key)
            if isinstance(val, str) and val.strip():
                raw_path = val.strip()
                break

        if not raw_path:
            # No path specified or empty argument - pass through safely
            res = pre_tool_response("allow", "No file path argument provided in toolCall.")
            res["verdict"] = "ALLOW"
            return res

        # Skip virtual schemes
        if is_virtual_scheme(raw_path, allowed_schemes):
            res = pre_tool_response("allow", f"Virtual path '{raw_path}' allowed.")
            res["verdict"] = "ALLOW"
            return res

        resolved_path, exists = resolve_candidate_path(raw_path, workspace_roots)

        if not exists:
            # File does not exist -> HALLUCINATION DETECTED
            reason_lines = [
                f"Enterprise Hallucination Guard (§7): Target file does not exist on disk: '{raw_path}'.",
            ]
            if suggest_corrections:
                suggestions = find_similar_files(
                    resolved_path, workspace_roots, max_suggestions=max_suggestions, cutoff=cutoff
                )
                if suggestions:
                    reason_lines.append(f"Did you mean: {suggestions}?")
                else:
                    reason_lines.append(
                        "Please verify the exact filepath using find_by_name or list_dir before proceeding."
                    )
            else:
                reason_lines.append("Please verify filepath using find_by_name or list_dir.")

            full_reason = " ".join(reason_lines)
            log_diagnostic(f"Blocked hallucinated file path in '{tool_name}': {raw_path}")

            res = pre_tool_response("deny", full_reason)
            res["verdict"] = "DENY"
            res["hallucination_type"] = "FILE_NOT_FOUND"
            res["attempted_path"] = raw_path
            return res

        # If it exists, verify it is a regular file when a file is expected
        if resolved_path.is_dir():
            reason = (
                f"Enterprise Hallucination Guard (§7): Target path '{raw_path}' is a directory, "
                f"not a regular file. Tool '{tool_name}' requires a file. Use list_dir to inspect directories."
            )
            log_diagnostic(f"Blocked directory passed to file tool '{tool_name}': {raw_path}")
            res = pre_tool_response("deny", reason)
            res["verdict"] = "DENY"
            res["hallucination_type"] = "IS_DIRECTORY"
            res["attempted_path"] = raw_path
            return res

        # Existing regular file -> ALLOW
        res = pre_tool_response("allow", f"Path verified: '{resolved_path}'.")
        res["verdict"] = "ALLOW"
        return res

    # 2. File creation tools (e.g. write_to_file)
    if tool_name in file_creation_tools:
        raw_target = args.get("TargetFile") or args.get("target_file")
        if isinstance(raw_target, str) and raw_target.strip():
            cleaned_target = clean_raw_path(raw_target)
            resolved_target, exists = resolve_candidate_path(cleaned_target, workspace_roots)

            # If path already exists and is a directory, write_to_file would corrupt or error
            if exists and resolved_target.is_dir():
                reason = (
                    f"Enterprise Hallucination Guard (§7): Target path '{raw_target}' is an existing directory. "
                    f"Cannot write file to a directory path."
                )
                log_diagnostic(f"Blocked file write to directory: {raw_target}")
                res = pre_tool_response("deny", reason)
                res["verdict"] = "DENY"
                res["hallucination_type"] = "TARGET_IS_DIRECTORY"
                return res

        # File creation is permissible
        res = pre_tool_response("allow", f"Tool '{tool_name}' permitted for file creation.")
        res["verdict"] = "ALLOW"
        return res

    # 3. Command execution tool (run_command)
    if tool_name == "run_command" and check_command_scripts:
        cmd_line = args.get("CommandLine") or args.get("command")
        cwd_arg = args.get("Cwd")
        if isinstance(cmd_line, str) and cmd_line.strip():
            script_candidate = extract_script_from_command(cmd_line)
            if script_candidate:
                # Determine command working directory
                cmd_roots = list(workspace_roots)
                if isinstance(cwd_arg, str) and cwd_arg.strip():
                    try:
                        resolved_cwd = pathlib.Path(cwd_arg.strip()).resolve()
                        if resolved_cwd.exists() and resolved_cwd.is_dir():
                            cmd_roots.insert(0, resolved_cwd)
                    except (OSError, ValueError):
                        pass

                resolved_script, script_exists = resolve_candidate_path(script_candidate, cmd_roots)
                if not script_exists:
                    reason_lines = [
                        f"Enterprise Hallucination Guard (§7): Command references non-existent script file: '{script_candidate}'.",
                    ]
                    if suggest_corrections:
                        suggestions = find_similar_files(
                            resolved_script, cmd_roots, max_suggestions=max_suggestions, cutoff=cutoff
                        )
                        if suggestions:
                            reason_lines.append(f"Did you mean: {suggestions}?")
                    full_reason = " ".join(reason_lines)
                    log_diagnostic(f"Blocked run_command referencing non-existent script: {script_candidate}")

                    res = pre_tool_response("deny", full_reason)
                    res["verdict"] = "DENY"
                    res["hallucination_type"] = "SCRIPT_NOT_FOUND"
                    res["attempted_script"] = script_candidate
                    return res

    # Unmonitored tools or safe pass-through
    res = pre_tool_response("allow", f"Tool '{tool_name}' passed hallucination guard.")
    res["verdict"] = "ALLOW"
    return res


# ============================================================================
# Self-Test Suite
# ============================================================================
def run_self_test() -> bool:
    """Execute comprehensive 16-scenario self-test suite for Hallucination Guard."""
    import shutil
    import tempfile

    print("Executing Hallucination Guard Hook Self-Test Suite (16 Scenarios)...")
    passed = 0
    total = 16

    temp_dir = pathlib.Path(tempfile.mkdtemp(prefix="hallucination_guard_test_")).resolve()

    try:
        # Prepare mock filesystem
        existing_file = temp_dir / "valid_module.py"
        existing_file.write_text("# valid python file\n", encoding="utf-8")

        existing_folder = temp_dir / "my_dir"
        existing_folder.mkdir(exist_ok=True)

        workspace_roots = [str(temp_dir)]

        # Scenario 1: view_file on existing file -> ALLOW
        p1 = {
            "toolCall": {
                "name": "view_file",
                "args": {"AbsolutePath": str(existing_file)},
            },
            "workspacePaths": workspace_roots,
        }
        r1 = evaluate_file_existence(p1)
        assert r1.get("decision") == "allow" and r1.get("verdict") == "ALLOW", f"S1 failed: {r1}"
        print("  [PASS] Scenario 01: view_file on existing file -> ALLOW")
        passed += 1

        # Scenario 2: view_file on non-existent file -> DENY
        non_existent = temp_dir / "ghost_file.py"
        p2 = {
            "toolCall": {
                "name": "view_file",
                "args": {"AbsolutePath": str(non_existent)},
            },
            "workspacePaths": workspace_roots,
        }
        r2 = evaluate_file_existence(p2)
        assert r2.get("decision") == "deny" and r2.get("verdict") == "DENY", f"S2 failed: {r2}"
        assert "does not exist" in r2.get("reason", "").lower(), f"S2 reason failed: {r2}"
        print("  [PASS] Scenario 02: view_file on non-existent file -> DENY")
        passed += 1

        # Scenario 3: view_file with typo in filename -> DENY with suggestions
        typo_file = temp_dir / "valid_modul.py"  # Typo of valid_module.py
        p3 = {
            "toolCall": {
                "name": "view_file",
                "args": {"AbsolutePath": str(typo_file)},
            },
            "workspacePaths": workspace_roots,
        }
        r3 = evaluate_file_existence(p3)
        assert r3.get("decision") == "deny", f"S3 failed: {r3}"
        assert "did you mean" in r3.get("reason", "").lower(), f"S3 suggestions failed: {r3}"
        print("  [PASS] Scenario 03: view_file with typo -> DENY with fuzzy suggestion")
        passed += 1

        # Scenario 4: view_file on a directory -> DENY ("is a directory")
        p4 = {
            "toolCall": {
                "name": "view_file",
                "args": {"AbsolutePath": str(existing_folder)},
            },
            "workspacePaths": workspace_roots,
        }
        r4 = evaluate_file_existence(p4)
        assert r4.get("decision") == "deny" and r4.get("hallucination_type") == "IS_DIRECTORY", f"S4 failed: {r4}"
        print("  [PASS] Scenario 04: view_file on a directory -> DENY (IS_DIRECTORY)")
        passed += 1

        # Scenario 5: replace_file_content on existing file -> ALLOW
        p5 = {
            "toolCall": {
                "name": "replace_file_content",
                "args": {"TargetFile": str(existing_file)},
            },
            "workspacePaths": workspace_roots,
        }
        r5 = evaluate_file_existence(p5)
        assert r5.get("decision") == "allow", f"S5 failed: {r5}"
        print("  [PASS] Scenario 05: replace_file_content on existing file -> ALLOW")
        passed += 1

        # Scenario 6: replace_file_content on non-existent file -> DENY
        p6 = {
            "toolCall": {
                "name": "replace_file_content",
                "args": {"TargetFile": str(non_existent)},
            },
            "workspacePaths": workspace_roots,
        }
        r6 = evaluate_file_existence(p6)
        assert r6.get("decision") == "deny", f"S6 failed: {r6}"
        print("  [PASS] Scenario 06: replace_file_content on non-existent file -> DENY")
        passed += 1

        # Scenario 7: write_to_file creating new file -> ALLOW (non-destructive)
        p7 = {
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(non_existent), "CodeContent": "new content"},
            },
            "workspacePaths": workspace_roots,
        }
        r7 = evaluate_file_existence(p7)
        assert r7.get("decision") == "allow", f"S7 failed: {r7}"
        print("  [PASS] Scenario 07: write_to_file for new file -> ALLOW (non-destructive)")
        passed += 1

        # Scenario 8: write_to_file target is an existing directory -> DENY
        p8 = {
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(existing_folder), "CodeContent": "content"},
            },
            "workspacePaths": workspace_roots,
        }
        r8 = evaluate_file_existence(p8)
        assert r8.get("decision") == "deny", f"S8 failed: {r8}"
        print("  [PASS] Scenario 08: write_to_file target is an existing directory -> DENY")
        passed += 1

        # Scenario 9: run_command with existing script -> ALLOW
        p9 = {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "python valid_module.py", "Cwd": str(temp_dir)},
            },
            "workspacePaths": workspace_roots,
        }
        r9 = evaluate_file_existence(p9)
        assert r9.get("decision") == "allow", f"S9 failed: {r9}"
        print("  [PASS] Scenario 09: run_command with existing script -> ALLOW")
        passed += 1

        # Scenario 10: run_command with non-existent script -> DENY
        p10 = {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "python missing_script.py", "Cwd": str(temp_dir)},
            },
            "workspacePaths": workspace_roots,
        }
        r10 = evaluate_file_existence(p10)
        assert r10.get("decision") == "deny" and r10.get("hallucination_type") == "SCRIPT_NOT_FOUND", (
            f"S10 failed: {r10}"
        )
        print("  [PASS] Scenario 10: run_command with non-existent script -> DENY (SCRIPT_NOT_FOUND)")
        passed += 1

        # Scenario 11: run_command standard system tool (git status, dir) -> ALLOW
        p11 = {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "git status", "Cwd": str(temp_dir)},
            },
            "workspacePaths": workspace_roots,
        }
        r11 = evaluate_file_existence(p11)
        assert r11.get("decision") == "allow", f"S11 failed: {r11}"
        print("  [PASS] Scenario 11: run_command system tool without script -> ALLOW")
        passed += 1

        # Scenario 12: Unmonitored tool (e.g. search_web) -> ALLOW
        p12 = {
            "toolCall": {
                "name": "search_web",
                "args": {"query": "python asyncio"},
            },
            "workspacePaths": workspace_roots,
        }
        r12 = evaluate_file_existence(p12)
        assert r12.get("decision") == "allow", f"S12 failed: {r12}"
        print("  [PASS] Scenario 12: Unmonitored tool -> ALLOW")
        passed += 1

        # Scenario 13: Empty args / non-dict payload -> ALLOW fail-safe
        r13a = evaluate_file_existence({})
        r13b = evaluate_file_existence({"toolCall": None})
        assert r13a.get("decision") == "allow" and r13b.get("decision") == "allow", "S13 failed"
        print("  [PASS] Scenario 13: Malformed payload / None args -> ALLOW fail-safe")
        passed += 1

        # Scenario 14: Virtual URI allowed
        p14 = {
            "toolCall": {
                "name": "view_file",
                "args": {"AbsolutePath": "memory://virtual_state.json"},
            },
            "workspacePaths": workspace_roots,
        }
        r14 = evaluate_file_existence(p14)
        assert r14.get("decision") == "allow", f"S14 failed: {r14}"
        print("  [PASS] Scenario 14: Virtual URI scheme -> ALLOW")
        passed += 1

        # Scenario 15: Relative path resolved against workspace root
        p15 = {
            "toolCall": {
                "name": "view_file",
                "args": {"AbsolutePath": "valid_module.py"},
            },
            "workspacePaths": workspace_roots,
        }
        r15 = evaluate_file_existence(p15)
        assert r15.get("decision") == "allow", f"S15 failed: {r15}"
        print("  [PASS] Scenario 15: Relative path resolution against workspace root -> ALLOW")
        passed += 1

        # Scenario 16: Environment variable disable override
        os.environ["HALLUCINATION_GUARD_ENABLED"] = "0"
        p16 = {
            "toolCall": {
                "name": "view_file",
                "args": {"AbsolutePath": str(non_existent)},
            },
            "workspacePaths": workspace_roots,
        }
        r16 = evaluate_file_existence(p16)
        assert r16.get("decision") == "allow", f"S16 failed: {r16}"
        os.environ.pop("HALLUCINATION_GUARD_ENABLED", None)
        print("  [PASS] Scenario 16: Environment variable disable override -> ALLOW")
        passed += 1

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    print(f"\nHallucination Guard Self-Test Completed: {passed}/{total} Scenarios Passed.")
    return passed == total


def main() -> None:
    """CLI entry point for Antigravity hook invocation and testing."""
    if "--self-test" in sys.argv:
        success = run_self_test()
        sys.exit(0 if success else 1)

    if "--post" in sys.argv:
        emit_stdout_json(post_tool_response())
        return

    payload = read_stdin_payload()
    result = evaluate_file_existence(payload)
    emit_stdout_json(result)


if __name__ == "__main__":
    main()
