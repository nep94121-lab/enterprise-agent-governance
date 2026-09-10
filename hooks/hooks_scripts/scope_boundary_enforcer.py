#!/usr/bin/env python3
"""Scope Boundary Enforcer Hook (PreToolUse) for Enterprise Multi-Agent Governance System.

Enforces:
1. Workspace boundary security & path traversal defense (§7).
2. Layout compliance (§15, §29): Prohibits creating/modifying source code or non-metadata files
   inside .agents/ or configured metadata directories.
3. Zero-hardcoding architecture: Dynamically loads configuration and thresholds from
   hook_utils.config_loader (and GovernanceConfig) with robust Zero-Config Resilience fallbacks.
4. Cross-platform robustness: Handles Windows case-insensitivity, 8.3 short names,
   Alternate Data Streams (ADS), relative path anchoring, and Unicode/UTF-8 safety.
5. Built-in --self-test suite with 16 comprehensive security & resilience scenarios.
"""

from __future__ import annotations

import io
import json
import os
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

# Ensure local hook library and enterprise root are importable
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
    get_workspace_roots,
    log_diagnostic,
    pre_tool_response,
    read_stdin_payload,
)

# Dynamic Configuration Loader Integration
try:
    from hook_utils.config_loader import (  # noqa: E402
        get_config_loader,
        get_scope_boundary_rules,
    )
    HAS_HOOK_UTILS = True
except ImportError:
    HAS_HOOK_UTILS = False
    get_scope_boundary_rules = None  # type: ignore[assignment]
    get_config_loader = None  # type: ignore[assignment]

# Governance Config integration
try:
    from config_loader import get_governance_config  # noqa: E402
    HAS_GOVERNANCE_CONFIG = True
except ImportError:
    HAS_GOVERNANCE_CONFIG = False
    get_governance_config = None  # type: ignore[assignment]


# Default Fallback Rules (Zero-Config Resilience) - Used only when config is unavailable
DEFAULT_MONITORED_TOOLS: tuple[str, ...] = (
    "write_to_file",
    "replace_file_content",
    "multi_replace_file_content",
)

DEFAULT_TARGET_ARGUMENT_KEYS: tuple[str, ...] = (
    "TargetFile",
    "target_file",
    "filePath",
    "file_path",
    "path",
    "destination",
)

DEFAULT_METADATA_DIRECTORIES: tuple[str, ...] = (
    ".agents",
)

DEFAULT_ALLOWED_METADATA_EXTENSIONS: frozenset[str] = frozenset({
    ".md",
    ".json",
    ".jsonl",
    ".ndjson",
    ".yaml",
    ".yml",
    ".txt",
    ".log",
    ".csv",
    ".toml",
    ".xml",
    ".dot",
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".gitkeep",
    ".gitignore",
})

DEFAULT_PROHIBITED_SOURCE_EXTENSIONS: frozenset[str] = frozenset({
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
    ".c",
    ".cpp",
    ".rs",
    ".go",
    ".java",
    ".sql",
    ".php",
    ".rb",
    ".cs",
    ".kt",
    ".kts",
    ".swift",
    ".dart",
    ".lua",
    ".r",
    ".m",
    ".zig",
    ".nim",
    ".scala",
    ".ex",
    ".exs",
    ".erl",
    ".clj",
})


def load_active_scope_rules() -> dict[str, Any]:
    """Dynamically load active scope boundary rules from config_loader.

    Adheres to precedence:
    1. hook_utils.config_loader (get_scope_boundary_rules)
    2. GovernanceConfig (if configured in governance.config.json or project-hooks.yaml)
    3. Zero-Config Resilience defaults
    """
    rules: dict[str, Any] = {}

    # 1. Try hook_utils dynamic config loader
    if HAS_HOOK_UTILS and get_scope_boundary_rules is not None:
        try:
            dynamic_rules = get_scope_boundary_rules()
            if isinstance(dynamic_rules, dict) and dynamic_rules:
                rules.update(dynamic_rules)
        except Exception as exc:
            log_diagnostic(f"Notice: Failed to load from hook_utils config loader: {exc}")

    # 2. Try GovernanceConfig if available and missing fields
    if HAS_GOVERNANCE_CONFIG and get_governance_config is not None:
        try:
            gov_cfg = get_governance_config()
            sec = getattr(gov_cfg, "security", None)
            sb = getattr(sec, "scope_boundary", None) if sec else None
            if sb and hasattr(sb, "to_dict"):
                for k, v in sb.to_dict().items():
                    if k not in rules or not rules[k]:
                        rules[k] = v
        except Exception as exc:
            log_diagnostic(f"Notice: Failed to load from governance config: {exc}")

    # 3. Assemble final normalized configuration with zero-hardcoded defaults
    monitored_tools = set(rules.get("monitored_tools", DEFAULT_MONITORED_TOOLS))
    target_keys = list(rules.get("target_argument_keys", DEFAULT_TARGET_ARGUMENT_KEYS))
    metadata_dirs = set(rules.get("metadata_directories", DEFAULT_METADATA_DIRECTORIES))
    allowed_meta = {
        ext.lower() if ext.startswith(".") else f".{ext.lower()}"
        for ext in rules.get("allowed_metadata_extensions", DEFAULT_ALLOWED_METADATA_EXTENSIONS)
    }
    prohibited_src = {
        ext.lower() if ext.startswith(".") else f".{ext.lower()}"
        for ext in rules.get("prohibited_source_extensions", DEFAULT_PROHIBITED_SOURCE_EXTENSIONS)
    }

    return {
        "enabled": bool(rules.get("enabled", True)),
        "monitored_tools": monitored_tools,
        "target_argument_keys": target_keys,
        "metadata_directories": metadata_dirs,
        "allowed_metadata_extensions": allowed_meta,
        "prohibited_source_extensions": prohibited_src,
    }


def extract_target_path_from_args(args: dict[str, Any], target_keys: list[str]) -> str | None:
    """Extract raw target file path from tool arguments dictionary across known parameter keys."""
    if not isinstance(args, dict):
        return None

    # Check designated keys first
    for key in target_keys:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()

    # Fallback search over any arg containing 'file' or 'path' in key name
    for k, v in args.items():
        if isinstance(k, str) and ("target" in k.lower() or "file" in k.lower() or "path" in k.lower()):
            if isinstance(v, str) and v.strip():
                return v.strip()

    return None


def resolve_target_path(raw_target: str, workspace_roots: list[pathlib.Path]) -> pathlib.Path | None:
    """Safely resolve target file path against workspace root, defeating traversal and CWD drift.

    Returns None if the path contains null bytes, invalid control characters, or malicious syntax.
    """
    # Null byte defense
    if "\0" in raw_target:
        log_diagnostic("Detected embedded null byte in target path.")
        return None

    try:
        p = pathlib.Path(raw_target)
        if p.is_absolute():
            return p.resolve()

        # Relative path: Anchor to primary workspace root to guarantee deterministic resolution
        primary_root = workspace_roots[0] if workspace_roots else pathlib.Path.cwd().resolve()
        return (primary_root / p).resolve()
    except (OSError, ValueError) as exc:
        log_diagnostic(f"Path resolution error for '{raw_target}': {exc}")
        return None


def is_path_within_workspace(target_path: pathlib.Path, workspace_roots: list[pathlib.Path]) -> bool:
    """Verify target path is strictly located within any of authorized workspace roots.

    Fully immune to Windows case discrepancies (e.g., C:\\ vs c:\\), symlinks, and trailing dots/slashes.
    """
    try:
        resolved_target = target_path.resolve()
        # 1. Standard relative_to check
        for root in workspace_roots:
            try:
                resolved_target.relative_to(root.resolve())
                return True
            except ValueError:
                pass

        # 2. Windows NTFS case-insensitive check
        if os.name == "nt" or sys.platform == "win32":
            target_norm = os.path.normcase(os.path.normpath(str(resolved_target)))
            for root in workspace_roots:
                root_norm = os.path.normcase(os.path.normpath(str(root.resolve())))
                if not root_norm.endswith(os.sep):
                    root_norm_sep = root_norm + os.sep
                else:
                    root_norm_sep = root_norm
                if target_norm == root_norm or target_norm.startswith(root_norm_sep):
                    return True

        return False
    except (OSError, ValueError):
        return False


def is_metadata_directory_target(
    target_path: pathlib.Path,
    metadata_dirs: set[str],
) -> tuple[bool, str]:
    """Check if target path is situated inside an agent metadata directory (e.g. .agents/).

    Detects standard directory names, case variations (.AGENTS), relative hops,
    and Windows 8.3 short name variations (AGENT~1).
    """
    normalized_parts = [part.lower() for part in target_path.parts]
    for m_dir in metadata_dirs:
        m_lower = m_dir.lower().lstrip("/\\")
        if m_lower in normalized_parts:
            return True, m_dir

        # Windows 8.3 short name defense (e.g. AGENTS~1 or AGENT~1)
        clean_name = m_lower.lstrip(".")
        short_pattern = re.compile(rf"^\.?{re.escape(clean_name[:5])}.*~\d+$", re.IGNORECASE)
        for part in normalized_parts:
            if short_pattern.match(part):
                return True, m_dir

    return False, ""


def is_caller_pm_orchestrator(payload: dict[str, Any] | None = None) -> bool:
    """Check if the current calling agent is the PM Orchestrator.

    Inspects payload metadata or ANTIGRAVITY_CONVERSATION_ID transcript first line.
    Fast-path: reads only 1 line, completes in < 1ms, fail-safe.
    """
    if payload:
        caller = str(payload.get("caller_role") or payload.get("role") or "").lower().strip()
        if any(k in caller for k in ("pm", "orchestrator", "project_manager")):
            return True
        if any(k in caller for k in ("top_level", "top-level", "agent_chinh", "backend", "frontend", "qa", "devops", "tech_lead", "worker")):
            return False

    conv_id = (payload.get("conversationId") if payload else None) or os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
    if not conv_id:
        src_meta = os.environ.get("ANTIGRAVITY_SOURCE_METADATA")
        if src_meta:
            try:
                meta_json = json.loads(src_meta)
                conv_id = meta_json.get("tool", {}).get("conversationId")
            except Exception:
                pass
    if not conv_id:
        return False

    brain_dir = pathlib.Path.home() / ".gemini" / "antigravity" / "brain" / conv_id / ".system_generated" / "logs"
    transcript = brain_dir / "transcript.jsonl"
    if not transcript.exists():
        return False

    try:
        with open(transcript, "r", encoding="utf-8") as f:
            first_line = f.readline()
            if not first_line:
                return False
            data = json.loads(first_line)
            content = str(data.get("content", "")).lower()
            if "vai trò:" in content:
                m = re.search(r"vai trò:\s*([^\n\r]+)", content)
                if m:
                    role_str = m.group(1).lower()
                    if any(k in role_str for k in ("backend", "frontend", "qa", "devops", "tech_lead", "top")):
                        return False
            pm_keywords = ["pm orchestrator", "pm sub-agent", "bạn là pm", "vai trò: pm"]
            return any(kw in content for kw in pm_keywords)
    except Exception:
        return False


def is_caller_top_level_agent(payload: dict[str, Any] | None = None) -> bool:
    """Check if the current calling agent is the Top-Level Agent (Agent Chính).

    Inspects payload metadata or transcript first line.
    """
    if payload:
        caller = str(payload.get("caller_role") or payload.get("role") or "").lower().strip()
        if any(k in caller for k in ("top_level", "top-level", "agent_chinh", "agent chính")):
            return True
        if any(k in caller for k in ("pm", "backend", "frontend", "qa", "devops", "tech_lead", "worker", "subagent")):
            return False

    conv_id = payload.get("conversationId") if payload else None
    if not conv_id:
        return False

    brain_dir = pathlib.Path.home() / ".gemini" / "antigravity" / "brain" / conv_id / ".system_generated" / "logs"
    transcript = brain_dir / "transcript.jsonl"
    if not transcript.exists():
        return False

    try:
        with open(transcript, "r", encoding="utf-8") as f:
            first_line = f.readline()
            if not first_line:
                return False
            data = json.loads(first_line)
            content = str(data.get("content", "")).lower()
            if "vai trò:" in content:
                m = re.search(r"vai trò:\s*([^\n\r]+)", content)
                if m:
                    role_str = m.group(1).lower()
                    if any(k in role_str for k in ("backend", "frontend", "qa", "devops", "tech_lead", "pm")):
                        return False
            top_declarations = ["bạn là agent chính", "vai trò: agent chính", "vai trò: top-level"]
            return any(kw in content for kw in top_declarations)
    except Exception:
        return False


def is_terminal_code_write_command(cmd: str) -> bool:
    """Detect if a terminal command writes or creates source code files."""
    if not cmd or not isinstance(cmd, str):
        return False
    code_ext_pattern = r"\.(?:py|js|ts|jsx|tsx|java|go|rs|c|cpp|sh|bat|ps1)\b"
    # Shell redirection: > or >> into code file
    if re.search(r">{1,2}\s*[^\s|&;]+?" + code_ext_pattern, cmd, re.IGNORECASE):
        return True
    # PowerShell file writing cmdlets
    if re.search(r"(?:set-content|out-file|add-content|new-item)\s+.*?" + code_ext_pattern, cmd, re.IGNORECASE):
        return True
    # Inline python file writing script
    if re.search(r"python\s+-c\s+.*open\(.*?['\"]w['\"]", cmd, re.IGNORECASE):
        return True
    return False


def evaluate_scope_boundary(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate if the target file path complies with scope boundary and layout rules."""
    if not isinstance(payload, dict):
        return pre_tool_response("allow", "Payload is not a dictionary.")

    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""
    if not isinstance(tool_name, str):
        return pre_tool_response("allow", "Invalid tool call name.")

    # Dynamically load active rules from config_loader
    rules = load_active_scope_rules()
    if not rules.get("enabled", True):
        return pre_tool_response("allow", "Scope boundary enforcer is disabled via configuration.")

    monitored_tools = rules["monitored_tools"]
    target_keys = rules["target_argument_keys"]
    metadata_dirs = rules["metadata_directories"]
    allowed_meta_exts = rules["allowed_metadata_extensions"]
    prohibited_src_exts = rules["prohibited_source_extensions"]

    # Check terminal command code write bypass if tool is run_command
    if tool_name == "run_command":
        if is_caller_pm_orchestrator(payload):
            args = get_tool_args(tool_call)
            cmd = str(args.get("CommandLine", "")).strip()
            if is_terminal_code_write_command(cmd):
                reason = (
                    "CƯỠNG CHẾ RANH GIỚI VAI TRÒ (§PM-ROLE-BOUNDARY): PM Orchestrator CẤM bypass bằng "
                    f"terminal command để tạo/sửa file mã nguồn qua run_command ('{cmd}')! "
                    "Mọi hành động lập trình/sửa code BẮT BUỘC phải ủy quyền cho Developer Sub-agent!"
                )
                log_diagnostic(f"BLOCKED PM Orchestrator terminal code bypass: {cmd}")
                return pre_tool_response("deny", reason)
        return pre_tool_response("allow", f"Tool '{tool_name}' is not a monitored file modification tool.")

    # Only inspect file modification tools
    if tool_name not in monitored_tools:
        return pre_tool_response("allow", f"Tool '{tool_name}' is not a monitored file modification tool.")

    args = get_tool_args(tool_call)
    if not isinstance(args, dict):
        return pre_tool_response("allow", "Tool args is not a dictionary.")

    raw_target = extract_target_path_from_args(args, target_keys)
    if not raw_target:
        # If no target file is specified or empty args, pass through safely
        return pre_tool_response("allow", "No TargetFile argument found.")

    # Check -1: Top-Level Agent Role Boundary Enforcement (§TOP-LEVEL-ROLE-BOUNDARY)
    # Agent Chính tuyệt đối cấm tự viết mã nguồn (.py, .js, .ts, etc.).
    if is_caller_top_level_agent(payload):
        target_ext = pathlib.Path(raw_target).suffix.lower()
        code_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".c", ".cpp", ".sh", ".bat", ".ps1"}
        if target_ext in prohibited_src_exts or target_ext in code_exts:
            reason = (
                f"CƯỠNG CHẾ PHÂN TẦNG AGENT CHÍNH (§TOP-LEVEL-ROLE-BOUNDARY): Agent Chính (Top-Level Agent) "
                f"TUYỆT ĐỐI CẤM tự sửa/tạo file mã nguồn '{raw_target}'! "
                "Agent Chính chỉ tương tác trực tiếp với Sếp và điều phối cấp cao. "
                "Mọi hành động viết code, sửa bug kỹ thuật BẮT BUỘC phải ủy quyền cho PM Sub-agent điều phối!"
            )
            log_diagnostic(f"BLOCKED Top-Level Agent from modifying source code file: {raw_target}")
            return pre_tool_response("deny", reason)

    # Check 0: PM Orchestrator Role Boundary Enforcement (§PM-ROLE-BOUNDARY)
    # PM Orchestrator tuyệt đối không được tự ý sửa hoặc tạo mã nguồn (.py, .js, .ts, etc.).
    # PM chỉ được phép tạo/sửa file markdown tiến độ (.md), config, hoặc log.
    if is_caller_pm_orchestrator(payload):
        target_ext = pathlib.Path(raw_target).suffix.lower()
        code_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".c", ".cpp", ".sh", ".bat", ".ps1"}
        if target_ext in prohibited_src_exts or target_ext in code_exts:
            reason = (
                f"CƯỠNG CHẾ RANH GIỚI VAI TRÒ (§PM-ROLE-BOUNDARY): PM Orchestrator TUYỆT ĐỐI CẤM tự sửa/tạo file mã nguồn '{raw_target}'! "
                "PM chỉ đóng vai trò lập kế hoạch, điều phối 7 Phase Gates và ghi chép tiến độ (progress.md, GATE_STATUS.md, handoff.md). "
                "Mọi hành động sửa code/vá lỗi BẮT BUỘC phải ủy quyền cho Developer Sub-agent (TypeName='self') để thợ tự tay sửa và kiểm thử!"
            )
            log_diagnostic(f"BLOCKED PM Orchestrator from directly modifying source code file: {raw_target}")
            return pre_tool_response("deny", reason)

    # Windows Alternate Data Stream (ADS) injection defense
    # E.g. filename.py:hidden_stream or drive:\path\file.py:$DATA
    clean_target = raw_target[2:] if (len(raw_target) > 2 and raw_target[1] == ":") else raw_target
    if ":" in clean_target:
        reason = (
            f"Enterprise Security Violation (§7): Target path '{raw_target}' contains illegal "
            f"Alternate Data Stream (ADS) separator. Writes to NTFS streams are strictly prohibited."
        )
        log_diagnostic(f"Blocked NTFS Alternate Data Stream attack: {raw_target}")
        return pre_tool_response("deny", reason)

    workspace_roots = get_workspace_roots(payload)
    target_path = resolve_target_path(raw_target, workspace_roots)

    # If path resolution failed (e.g. embedded null byte or malformed path), deny safely
    if target_path is None:
        reason = (
            f"Enterprise Security Violation (§7): Target path '{raw_target}' is malformed "
            f"or contains prohibited control characters. Writes rejected."
        )
        log_diagnostic(f"Blocked invalid path: {raw_target}")
        return pre_tool_response("deny", reason)

    # Check 1: Workspace Boundary & Path Traversal Guard (§7)
    # Always verify target is inside one of the workspace roots (defaults to cwd if workspacePaths omitted)
    if not is_path_within_workspace(target_path, workspace_roots):
        reason = (
            f"Enterprise Security Violation (§7): Target path '{raw_target}' is outside "
            f"authorized workspace roots. Writes outside workspace boundaries are prohibited."
        )
        log_diagnostic(f"Blocked out-of-scope write: {raw_target}")
        return pre_tool_response("deny", reason)

    # Check 2: .agents/ Layout Compliance (§15, §29)
    # Check if target is inside an .agents directory (or configured metadata directories)
    is_meta_dir, matched_dir = is_metadata_directory_target(target_path, metadata_dirs)
    if is_meta_dir:
        ext = target_path.suffix.lower()
        all_suffixes = [s.lower() for s in target_path.suffixes]

        # 2a. Check if any suffix matches prohibited source code extensions
        is_prohibited_src = (ext in prohibited_src_exts) or any(s in prohibited_src_exts for s in all_suffixes)
        if is_prohibited_src:
            matched_ext = ext if ext in prohibited_src_exts else next(s for s in all_suffixes if s in prohibited_src_exts)
            reason = (
                f"Enterprise Rule Layout Compliance (§15, §29): Prohibited writing source code "
                f"('{matched_ext}') into '{matched_dir}/' directory. '{matched_dir}/' is reserved exclusively for agent "
                f"metadata (plans, progress, handoffs, briefings, reports). Place source code in designated source directories."
            )
            log_diagnostic(f"Blocked code placement in {matched_dir}/: {raw_target}")
            return pre_tool_response("deny", reason)

        # 2b. Check whitelist: file must have an allowed metadata extension
        if ext not in allowed_meta_exts:
            reason = (
                f"Enterprise Rule Layout Compliance (§15, §29): Prohibited writing non-metadata file "
                f"('{ext or 'no extension'}') into '{matched_dir}/' directory. '{matched_dir}/' is reserved exclusively for agent "
                f"metadata (plans, progress, handoffs, briefings, reports)."
            )
            log_diagnostic(f"Blocked non-metadata placement in {matched_dir}/: {raw_target}")
            return pre_tool_response("deny", reason)

    return pre_tool_response("allow", "Target file path is within authorized workspace scope and complies with layout rules.")


# ==============================================================================
# Self-Test Suite (--self-test CLI runner)
# ==============================================================================
def run_self_tests() -> bool:
    """Run comprehensive in-process self-test suite covering 16 security and resilience scenarios."""
    print("======================================================================")
    print("Running Scope Boundary Enforcer Self-Test Suite (Enterprise Mode)")
    print("======================================================================\n")

    test_workspace = ENTERPRISE_HOOKS_ROOT.resolve()
    test_results: list[tuple[str, bool, str]] = []

    def record_test(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        test_results.append((name, passed, detail))
        print(f"[{status}] {name}{f' - {detail}' if detail and not passed else ''}")

    # 1. Valid workspace write -> allow
    res1 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "valid.txt")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("1. Valid Workspace Write (allow)", res1.get("decision") == "allow")

    # 2. Outside workspace write (C:\Windows) -> deny
    outside_target = "C:\\Windows\\System32\\drivers\\etc\\hosts"
    res2 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": outside_target}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test(
        "2. Deny Outside Workspace Path",
        res2.get("decision") == "deny" and "outside authorized workspace" in res2.get("reason", "").lower(),
    )

    # 3. Missing workspacePaths key fallback -> deny
    res3 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": "C:/Windows/temp/evil.py"}},
    })
    record_test(
        "3. Deny Outside Workspace when workspacePaths omitted",
        res3.get("decision") == "deny" and "outside authorized workspace" in res3.get("reason", "").lower(),
    )

    # 4. Relative path traversal (../outside.txt) -> deny
    res4 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": "../outside.txt"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("4. Deny Relative Path Traversal (../outside.txt)", res4.get("decision") == "deny")

    # 5. Prohibited source code in .agents/ -> deny
    prohibited_samples = [".py", ".ts", ".js", ".sh", ".ps1", ".bat", ".cmd", ".sql"]
    p5_passed = True
    for ext in prohibited_samples:
        r = evaluate_scope_boundary({
            "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / ".agents" / "w" / f"app{ext}")}},
            "workspacePaths": [str(test_workspace)],
        })
        if r.get("decision") != "deny" or "prohibited writing source code" not in r.get("reason", "").lower():
            p5_passed = False
            break
    record_test("5. Deny Prohibited Source Code in .agents/", p5_passed)

    # 6. Allowed metadata in .agents/ -> allow
    allowed_samples = [".md", ".json", ".yaml", ".txt", ".log", ".csv", ".toml"]
    p6_passed = True
    for ext in allowed_samples:
        r = evaluate_scope_boundary({
            "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / ".agents" / "w" / f"doc{ext}")}},
            "workspacePaths": [str(test_workspace)],
        })
        if r.get("decision") != "allow":
            p6_passed = False
            break
    record_test("6. Allow Valid Metadata in .agents/", p6_passed)

    # 7. Double extension evasion in .agents/ (notes.md.py) -> deny
    res7 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / ".agents" / "w" / "notes.md.py")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("7. Deny Double Extension Evasion (notes.md.py)", res7.get("decision") == "deny")

    # 8. Case variation evasion (.AGENTS/code.py, malicious.PY) -> deny
    res8a = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / ".AGENTS" / "code.py")}},
        "workspacePaths": [str(test_workspace)],
    })
    res8b = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / ".agents" / "malicious.PY")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("8. Deny Case Variations in .AGENTS and uppercase extensions", res8a.get("decision") == "deny" and res8b.get("decision") == "deny")

    # 9. Non-metadata file in .agents/ (binary.exe, payload.bin) -> deny
    res9 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / ".agents" / "w" / "binary.exe")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("9. Deny Non-Metadata Executable in .agents/ (binary.exe)", res9.get("decision") == "deny")

    # 10. Alternate file modification tools (replace_file_content, multi_replace_file_content) -> deny on violation
    res10a = evaluate_scope_boundary({
        "toolCall": {"name": "replace_file_content", "args": {"TargetFile": str(test_workspace / ".agents" / "w" / "app.py")}},
        "workspacePaths": [str(test_workspace)],
    })
    res10b = evaluate_scope_boundary({
        "toolCall": {"name": "multi_replace_file_content", "args": {"TargetFile": str(test_workspace / ".agents" / "w" / "app.py")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("10. Gate replace_file_content and multi_replace_file_content", res10a.get("decision") == "deny" and res10b.get("decision") == "deny")

    # 11. Unmonitored tools (run_command, view_file) -> allow
    res11 = evaluate_scope_boundary({
        "toolCall": {"name": "run_command", "args": {"CommandLine": "dir"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("11. Allow Unmonitored Tools (run_command, view_file)", res11.get("decision") == "allow")

    # 12. Malformed payloads and schema mutations -> safe fallback allow
    malformed_samples = [
        {},
        {"toolCall": None},
        {"toolCall": "not_a_dict"},
        {"toolCall": {"name": None, "args": None}},
        {"toolCall": {"name": "write_to_file", "args": None}},
        {"toolCall": {"name": "write_to_file", "args": {"TargetFile": None}}},
        {"toolCall": {"name": "write_to_file", "args": {"TargetFile": ""}}},
    ]
    p12_passed = all(evaluate_scope_boundary(p).get("decision") == "allow" for p in malformed_samples)
    record_test("12. Malformed Payloads & Null Safety Fallback", p12_passed)

    # 13. Alternate parameter keys (target_file, filePath, file_path, path) -> properly inspected
    alt_keys = ["target_file", "filePath", "file_path", "path", "destination"]
    p13_passed = True
    for key in alt_keys:
        r = evaluate_scope_boundary({
            "toolCall": {"name": "write_to_file", "args": {key: outside_target}},
            "workspacePaths": [str(test_workspace)],
        })
        if r.get("decision") != "deny":
            p13_passed = False
            break
    record_test("13. Alternate Parameter Keys Inspection (target_file, filePath, etc.)", p13_passed)

    # 14. Windows Alternate Data Streams (ADS) defense -> deny
    ads_target = str(test_workspace / "script.py:hidden_stream")
    res14 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": ads_target}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("14. Deny NTFS Alternate Data Streams (ADS)", res14.get("decision") == "deny")

    # 15. Dynamic Config Loader Integration
    rules = load_active_scope_rules()
    config_valid = (
        isinstance(rules, dict)
        and "monitored_tools" in rules
        and "allowed_metadata_extensions" in rules
        and "prohibited_source_extensions" in rules
        and ".md" in rules["allowed_metadata_extensions"]
        and ".py" in rules["prohibited_source_extensions"]
    )
    record_test("15. Dynamic Config Loader Integration (hook_utils/config_loader)", config_valid)

    # 16. Subprocess STDIO Pipe Streaming Verification
    subproc_passed = False
    try:
        sample_payload = {
            "toolCall": {"name": "write_to_file", "args": {"TargetFile": outside_target}},
            "workspacePaths": [str(test_workspace)],
        }
        proc = subprocess.Popen(
            [sys.executable, str(pathlib.Path(__file__).resolve())],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout_bytes, _ = proc.communicate(json.dumps(sample_payload).encode("utf-8"), timeout=10)
        parsed_out = json.loads(stdout_bytes.decode("utf-8"))
        if proc.returncode == 0 and parsed_out.get("decision") == "deny":
            subproc_passed = True
    except Exception as exc:
        log_diagnostic(f"Subprocess test exception: {exc}")
        subproc_passed = False
    record_test("16. Subprocess STDIO Pipeline Streaming Verification", subproc_passed)

    # 17. Deny Top-Level Agent modifying source code files (.py)
    res17 = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "main.py")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("17. Deny Top-Level Agent modifying source code (.py)", res17.get("decision") == "deny" and "TOP-LEVEL-ROLE-BOUNDARY" in res17.get("reason", ""))

    # 18. Allow Top-Level Agent modifying non-code tracking files (.md)
    res18 = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "plan.md")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("18. Allow Top-Level Agent modifying documentation (.md)", res18.get("decision") == "allow")

    # 19. Deny PM Orchestrator terminal command bypass writing code files
    res19 = evaluate_scope_boundary({
        "caller_role": "pm_orchestrator",
        "toolCall": {"name": "run_command", "args": {"CommandLine": "echo 'x = 1' > app.py"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("19. Deny PM Orchestrator terminal code write bypass (echo > app.py)", res19.get("decision") == "deny" and "PM-ROLE-BOUNDARY" in res19.get("reason", ""))

    # 20. Allow PM Orchestrator normal terminal commands
    res20 = evaluate_scope_boundary({
        "caller_role": "pm_orchestrator",
        "toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("20. Allow PM Orchestrator normal terminal command (git status)", res20.get("decision") == "allow")

    total_passed = sum(1 for _, passed, _ in test_results)
    total_cases = len(test_results)
    all_passed = (total_passed == total_cases)

    print("\n----------------------------------------------------------------------")
    print(f"Self-Test Summary: {total_passed}/{total_cases} scenarios passed ({'100%' if all_passed else 'FAILED'}).")
    print("----------------------------------------------------------------------\n")
    return all_passed


def main() -> None:
    """Main CLI entrypoint for scope boundary enforcer."""
    if "--self-test" in sys.argv:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    payload = read_stdin_payload(default={})
    response = evaluate_scope_boundary(payload)
    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()
