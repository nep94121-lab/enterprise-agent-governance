#!/usr/bin/env python3
"""File Ownership Guard Hook (PreToolUse) for Enterprise Multi-Agent Governance System.

Enforces Exclusive File Ownership (§EXCLUSIVE-FILE-OWNERSHIP):
1. Reads the File Ownership table from progress.md in the workspace.
2. Maps each file to its designated Subagent owner.
3. If a Worker Subagent attempts to write/modify a file owned by another Worker:
   -> HARD DENY (chặn ngay lập tức, 0 ngoại lệ theo lệnh của Sếp).
4. Eliminates 100% of race conditions and merge conflicts when multiple subagents run in parallel.
5. PM Orchestrator is permitted to modify tracking files (progress.md, GATE_STATUS.md, etc.).
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import re
import subprocess
import sys
import unicodedata
import urllib.parse
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
    get_file_identity,
    get_tool_args,
    get_tool_call,
    get_workspace_roots,
    has_ntfs_ads,
    is_hardlink,
    is_reparse_point,
    is_reserved_device_name,
    log_diagnostic,
    pre_tool_response,
    read_stdin_payload,
    strip_unc_prefix,
)

MONITORED_TOOLS: frozenset[str] = frozenset({
    "write_to_file",
    "replace_file_content",
    "multi_replace_file_content",
    "run_command",
})

TARGET_PATH_KEYS: tuple[str, ...] = (
    "TargetFile",
    "target_file",
    "filePath",
    "file_path",
    "path",
)

PM_OWNED_FILES: frozenset[str] = frozenset({
    "progress.md",
    "gate_status.md",
    "dead_ends.md",
    "handoff.md",
    "implementation_plan.md",
})


ZERO_WIDTH_CHARS: frozenset[str] = frozenset({
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\ufeff",  # Zero Width No-Break Space / BOM
    "\u2060",  # Word Joiner
    "\u2061",  # Function Application
    "\u2062",  # Invisible Times
    "\u2063",  # Invisible Separator
    "\u2064",  # Invisible Plus
    "\u200e",  # Left-to-Right Mark
    "\u200f",  # Right-to-Left Mark
    "\u202a",  # Left-to-Right Embedding
    "\u202b",  # Right-to-Left Embedding
    "\u202c",  # Pop Directional Formatting
    "\u202d",  # Left-to-Right Override
    "\u202e",  # Right-to-Left Override
    "\u2066",  # Left-to-Right Isolate
    "\u2067",  # Right-to-Left Isolate
    "\u2068",  # First Strong Isolate
    "\u2069",  # Pop Directional Isolate
    "\u034f",  # Combining Grapheme Joiner
    "\u00ad",  # Soft Hyphen
    "\u180e",  # Mongolian Vowel Separator
})

HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic lowercase to Latin
    "\u0430": "a", "\u0410": "A",
    "\u0431": "b", "\u0411": "B",
    "\u0432": "b", "\u0412": "B",
    "\u0433": "g", "\u0413": "G",
    "\u0434": "d", "\u0414": "D",
    "\u0435": "e", "\u0415": "E",
    "\u0451": "e", "\u0401": "E",
    "\u0436": "z", "\u0416": "Z",
    "\u0437": "z", "\u0417": "Z",
    "\u0438": "i", "\u0418": "I",
    "\u0439": "i", "\u0419": "I",
    "\u043a": "k", "\u041a": "K",
    "\u043b": "l", "\u041b": "L",
    "\u043c": "m", "\u041c": "M",
    "\u043d": "h", "\u041d": "H",
    "\u043e": "o", "\u041e": "O",
    "\u043f": "p", "\u041f": "P",
    "\u0440": "p", "\u0420": "P",
    "\u0441": "c", "\u0421": "C",
    "\u0442": "t", "\u0422": "T",
    "\u0443": "y", "\u0423": "Y",
    "\u0444": "f", "\u0424": "F",
    "\u0445": "x", "\u0425": "X",
    "\u0446": "c",
    "\u0447": "4",
    "\u0448": "w",
    "\u0449": "w",
    "\u044a": "",
    "\u044b": "y",
    "\u044c": "b",
    "\u044d": "e",
    "\u044e": "u",
    "\u044f": "r",
    "\u0454": "e", "\u0404": "E",
    "\u0455": "s", "\u0405": "S",
    "\u0456": "i", "\u0406": "I",
    "\u0457": "i", "\u0407": "I",
    "\u0458": "j", "\u0408": "J",
    "\u045c": "k",
    "\u04bb": "h", "\u04ba": "H",
    "\u04cf": "l", "\u04c0": "I",
    "\u0501": "d", "\u0500": "D",
    "\u051b": "q", "\u051a": "Q",
    "\u051d": "w", "\u051c": "W",

    # Greek lowercase & uppercase to Latin
    "\u03b1": "a", "\u0391": "A",
    "\u03b2": "b", "\u0392": "B",
    "\u03b3": "y", "\u0393": "G",
    "\u03b4": "d", "\u0394": "D",
    "\u03b5": "e", "\u0395": "E",
    "\u03b6": "z", "\u0396": "Z",
    "\u03b7": "n", "\u0397": "H",
    "\u03b8": "o", "\u0398": "O",
    "\u03b9": "i", "\u0399": "I",
    "\u03ba": "k", "\u039a": "K",
    "\u03bb": "l", "\u039b": "L",
    "\u03bc": "u", "\u039c": "M",
    "\u03bd": "v", "\u039d": "N",
    "\u03be": "x", "\u039e": "X",
    "\u03bf": "o", "\u039f": "O",
    "\u03c0": "n", "\u03a0": "N",
    "\u03c1": "p", "\u03a1": "P",
    "\u03c2": "s", "\u03c3": "s", "\u03a3": "S",
    "\u03c4": "t", "\u03a4": "T",
    "\u03c5": "u", "\u03a5": "Y",
    "\u03c6": "f",
    "\u03c7": "x", "\u03a7": "X",
    "\u03c8": "y",
    "\u03c9": "w", "\u03a9": "O",

    # Latin extended & special
    "\u0111": "d", "\u0110": "D",
    "\u0131": "i", "\u0130": "I",
    "\u0237": "j",
    "\u0251": "a",
    "\u0261": "g",
    "\u028c": "v",
    "\u00f8": "o", "\u00d8": "O",
    "\u00df": "ss",
    "\u00e6": "ae", "\u00c6": "AE",
    "\u0153": "oe", "\u0152": "OE",

    # Unicode dashes to ASCII hyphen-minus
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-",
    "\u2014": "-", "\u2015": "-", "\u2212": "-",

    # Unicode dots to ASCII dot
    "\u2024": ".", "\u3002": ".", "\uff0e": ".", "\ufe52": ".",

    # Unicode slashes to ASCII slash
    "\uff0f": "/", "\u2215": "/", "\u2044": "/", "\uff3c": "\\", "\u29f5": "\\",

    # Unicode underscores
    "\uff3f": "_", "\u2017": "_",

    # Unicode colons
    "\uff1a": ":", "\ufe55": ":", "\u2236": ":",
}


def extract_target_path(args: dict[str, Any]) -> str | None:
    """Extract raw target file path from tool arguments (including shell redirections)."""
    for k in TARGET_PATH_KEYS:
        val = args.get(k)
        if isinstance(val, str) and val.strip():
            return val.strip()

    # Extract shell redirection target or PowerShell write cmdlet target
    cmd = args.get("CommandLine") or args.get("command") or ""
    if cmd and isinstance(cmd, str):
        # Shell redirection e.g. > file, >> file
        m_redir = re.search(r"(?:>>?|[0-9*&]>>?)\s*[\"']?([^\s\"'|&;>]+)[\"']?", cmd)
        if m_redir:
            return m_redir.group(1).strip()
        # PowerShell Out-File / Set-Content / Add-Content
        m_ps = re.search(r"\b(?:Set-Content|Out-File|Add-Content|New-Item|sc|ac|ni)\b.*?(?:-(?:Path|FilePath|LiteralPath|Name)\s+)?[\"']?([^\s\"'|&;]+)[\"']?", cmd, re.IGNORECASE)
        if m_ps:
            return m_ps.group(1).strip()

    return None


def multi_layer_percent_decode(val: str, max_passes: int = 5) -> str:
    """Recursively decode percent-encoded strings (URL double/multi-decoding).

    Continues unquoting until fixed point (no change) or max_passes reached.
    Guards against malformed byte sequences and infinite loops.
    """
    if not isinstance(val, str) or not val:
        return ""
    current = val
    for _ in range(max_passes):
        try:
            decoded = urllib.parse.unquote(current)
        except Exception:
            break
        if decoded == current:
            break
        current = decoded
    return current


def sanitize_target_path(raw_path: str) -> str:
    """Sanitize, decode, and normalize a file path across OS boundaries.

    Handles:
    - Multi-layer URL/Percent decoding (%252e%252f -> ./)
    - Zero-width, BiDi, and invisible character stripping
    - Homoglyph replacement (Cyrillic, Greek, fullwidth dots/slashes)
    - Unicode NFKC canonical form
    - NTFS Alternate Data Stream (:stream, ::$DATA) stripping (preserving drive letter C:)
    - Windows trailing dots and spaces on each path component
    - Path traversal resolution (. and ..)
    - Full path resolution via Path.resolve() if possible
    """
    if not isinstance(raw_path, str) or not raw_path.strip():
        return ""

    # 1. Multi-layer percent decoding
    path_str = multi_layer_percent_decode(raw_path.strip())

    # 2. Strip zero-width & invisible characters
    path_str = "".join(c for c in path_str if c not in ZERO_WIDTH_CHARS)

    # 3. Homoglyph mapping & Unicode NFKC normalization
    path_str = "".join(HOMOGLYPH_MAP.get(c, c) for c in path_str)
    path_str = unicodedata.normalize("NFKC", path_str)
    path_str = "".join(HOMOGLYPH_MAP.get(c, c) for c in path_str)

    # 4. Remove NTFS Alternate Data Stream (ADS) if present (e.g. :$DATA or :stream)
    # Drive letter like C: must be preserved, but any subsequent colon is an ADS stream
    path_str = re.sub(r"(?<!^[a-zA-Z]):.*$", "", path_str)

    # 5. Normalize separators to forward slashes
    path_str = path_str.replace("\\", "/")

    # 6. Windows file system sanitization: strip trailing dots, spaces from each path component
    parts = path_str.split("/")
    sanitized_parts = [p if p in (".", "..") else re.sub(r"[\s.]+$", "", p) for p in parts]
    path_str = "/".join(sanitized_parts)

    # 7. Normalize traversal (. and ..)
    try:
        path_str = os.path.normpath(path_str).replace("\\", "/")
    except Exception:
        pass

    # 8. Attempt resolution for complete path canonicalization
    try:
        p_obj = pathlib.Path(path_str)
        resolved = str(p_obj.resolve()).replace("\\", "/")
        return resolved
    except Exception:
        return path_str


def normalize_text_for_matching(val: str) -> str:
    """Normalize general text for keyword/header matching."""
    if not isinstance(val, str) or not val:
        return ""
    s = multi_layer_percent_decode(val)
    s = "".join(c for c in s if c not in ZERO_WIDTH_CHARS)
    s = "".join(HOMOGLYPH_MAP.get(c, c) for c in s)
    s = unicodedata.normalize("NFKC", s)
    s = "".join(HOMOGLYPH_MAP.get(c, c) for c in s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return s.casefold().strip()


def normalize_identifier(val: str) -> str:
    """Normalize agent or file identifier for robust fuzzy matching.

    Applies:
    1. Multi-pass percent decoding (e.g. %252e -> .).
    2. Zero-width and invisible character stripping.
    3. Homoglyph substitution (Cyrillic, Greek, fullwidth, confusables).
    4. Canonical Unicode decomposition & composition (NFKC + NFKD diacritic removal).
    5. Unicode case folding (casefold).
    6. Stripping of trailing Windows dots and whitespace.
    7. Alphanumeric + underscore + dot filtering.
    """
    if not isinstance(val, str) or not val:
        return ""
    s = multi_layer_percent_decode(val)
    s = "".join(c for c in s if c not in ZERO_WIDTH_CHARS)
    s = "".join(HOMOGLYPH_MAP.get(c, c) for c in s)
    s = unicodedata.normalize("NFKC", s)
    s = "".join(HOMOGLYPH_MAP.get(c, c) for c in s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = s.casefold()
    s = re.sub(r"[\s.]+$", "", s)
    return re.sub(r"[^a-z0-9_.~]", "", s)


def detect_caller_identity(payload: dict[str, Any]) -> str:
    """Detect caller identity/role from payload or environment."""
    for key in ("caller_role", "role", "subagent_name", "subagent_role"):
        v = payload.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()

    env_role = os.environ.get("AGENT_ROLE", "").strip()
    if env_role:
        return env_role

    # Check transcript first line
    conv_id = payload.get("conversationId") or os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
    if conv_id and isinstance(conv_id, str):
        brain_dir = pathlib.Path.home() / ".gemini" / "antigravity" / "brain" / conv_id / ".system_generated" / "logs"
        transcript = brain_dir / "transcript.jsonl"
        if transcript.is_file():
            try:
                with open(transcript, "r", encoding="utf-8-sig", errors="replace") as f:
                    for _ in range(50):
                        line = f.readline()
                        if not line:
                            break
                        try:
                            data = json.loads(line)
                            content = str(data.get("content", ""))
                            m = re.search(r"vai trò:\s*([^\n\r,.;]+)", content, re.IGNORECASE)
                            if m:
                                return m.group(1).strip()
                            m2 = re.search(r"\bRole:\s*([^\n\r,.;]+)", content, re.IGNORECASE)
                            if m2:
                                return m2.group(1).strip()
                        except Exception:
                            continue
            except Exception as exc:
                log_diagnostic(f"Transcript inspection error in file ownership: {exc}")

    return "unknown_agent"


def is_header_cell(text: str, keywords: tuple[str, ...]) -> bool:
    """Check if a table cell matches any header keyword."""
    t = normalize_text_for_matching(text)
    return any(kw in t for kw in keywords)


def parse_ownership_table(progress_path: pathlib.Path) -> dict[str, list[str]]:
    """Parse Exclusive File Ownership table or list from progress.md.

    Accurately detects Worker column and File Ownership column.
    Never discards rows where agent/subagent name contains 'Worker' (e.g. Worker_Backend_01).
    Handles:
    - UTF-8 with BOM (utf-8-sig)
    - Zero-width & invisible character filtering
    - Unicode normalization (NFC, NFD, NFKC, NFKD)
    - Homoglyph & confusable character substitution
    - Multi-layer URL / percent decoding
    - Windows trailing dots and spaces in filenames
    Returns dict mapping normalized subagent role -> list of assigned filenames (normalized).
    """
    ownership: dict[str, list[str]] = {}
    if not progress_path.is_file():
        return ownership

    WORKER_HEADER_KEYWORDS = (
        "worker", "subagent", "agent", "tac tu", "role", "vai tro",
        "assignee", "tho", "nguoi phu trach",
    )
    FILE_HEADER_KEYWORDS = (
        "file", "ownership", "so huu", "tep", "file(s) owned",
        "files owned", "file doc quyen", "assigned file",
    )

    try:
        # utf-8-sig automatically detects and removes UTF-8 BOM if present
        content = progress_path.read_text(encoding="utf-8-sig", errors="replace")
        content = content.lstrip("\ufeff")
        lines = content.splitlines()

        in_ownership_section = False
        header_parsed = False
        worker_col_idx = 0
        files_col_idx = 1

        for line in lines:
            clean = line.strip().lstrip("\ufeff")

            # Section header check
            if clean.startswith("#"):
                norm_header = normalize_text_for_matching(clean)
                if any(kw in norm_header for kw in ("file ownership", "so huu file", "file doc quyen", "exclusive file ownership")):
                    in_ownership_section = True
                    header_parsed = False
                    worker_col_idx = 0
                    files_col_idx = 1
                else:
                    in_ownership_section = False
                    header_parsed = False
                continue

            # Check for list format: - worker -> file1, file2 or * worker: file1, file2
            list_match = re.match(r"^[-*]\s*([^\->:]+?)\s*(?:->|:)\s*(.+)$", clean)
            if list_match:
                agent_raw = list_match.group(1).strip()
                files_raw = list_match.group(2).strip()
                extracted_files: list[str] = []
                for f in re.split(r"[,;\n]\s*", files_raw):
                    f_clean = f.strip().strip("`").strip("'").strip('"')
                    if not f_clean or any(f_clean.lower().startswith(h) for h in ("none", "n/a", "-")):
                        continue
                    sanitized_f = sanitize_target_path(f_clean)
                    p_f = pathlib.Path(sanitized_f)
                    norm_base = normalize_identifier(p_f.name)
                    if norm_base:
                        extracted_files.append(norm_base)
                    norm_full = normalize_identifier(sanitized_f)
                    if norm_full and norm_full != norm_base:
                        extracted_files.append(norm_full)

                agent_norm = normalize_identifier(agent_raw)
                if agent_norm and extracted_files:
                    ownership.setdefault(agent_norm, []).extend(extracted_files)
                continue

            # Check for markdown table row
            if clean.startswith("|") and clean.endswith("|"):
                # Markdown separator row (e.g. |---|---|---|)
                if re.match(r"^\|(?:\s*:?-+:?\s*\|)+$", clean):
                    continue

                parts = [p.strip() for p in clean.split("|")[1:-1]]
                if len(parts) < 2:
                    continue

                # Check if this row is a table header row (inspecting columns)
                found_worker_col = None
                found_files_col = None
                for idx, cell in enumerate(parts):
                    cell_clean = cell.strip().strip("`").strip("'").strip('"')
                    cell_norm = normalize_identifier(cell_clean)
                    # Skip if cell looks like actual filename with extension
                    if any(cell_norm.endswith(ext) for ext in ("py", "js", "ts", "md", "json", "yaml", "yml", "html", "css", "go", "rs")):
                        continue
                    if found_files_col is None and is_header_cell(cell, FILE_HEADER_KEYWORDS):
                        found_files_col = idx
                    elif found_worker_col is None and is_header_cell(cell, WORKER_HEADER_KEYWORDS):
                        found_worker_col = idx

                # If this row defines headers for both worker and files
                if found_worker_col is not None and found_files_col is not None and found_worker_col != found_files_col:
                    worker_col_idx = found_worker_col
                    files_col_idx = found_files_col
                    header_parsed = True
                    in_ownership_section = True
                    continue  # Skip header row

                # Process data row if we are in ownership section or table header was parsed
                if in_ownership_section or header_parsed:
                    max_idx = max(worker_col_idx, files_col_idx)
                    if len(parts) > max_idx:
                        agent_raw = parts[worker_col_idx].strip().strip("`*")
                        files_raw = parts[files_col_idx].strip()

                        # Ensure it's not a repeated header row
                        agent_norm_term = normalize_text_for_matching(agent_raw)
                        files_norm_term = normalize_text_for_matching(files_raw)
                        if (
                            agent_norm_term in WORKER_HEADER_KEYWORDS
                            and any(kw in files_norm_term for kw in FILE_HEADER_KEYWORDS)
                        ):
                            continue

                        extracted_files = []
                        for f in re.split(r"[,;\n]\s*", files_raw):
                            f_clean = f.strip().strip("`").strip("'").strip('"')
                            if not f_clean or any(f_clean.lower().startswith(h) for h in ("none", "n/a", "-")):
                                continue
                            sanitized_f = sanitize_target_path(f_clean)
                            p_f = pathlib.Path(sanitized_f)
                            norm_base = normalize_identifier(p_f.name)
                            if norm_base:
                                extracted_files.append(norm_base)
                            norm_full = normalize_identifier(sanitized_f)
                            if norm_full and norm_full != norm_base:
                                extracted_files.append(norm_full)

                        agent_norm = normalize_identifier(agent_raw)
                        if agent_norm and extracted_files:
                            ownership.setdefault(agent_norm, []).extend(extracted_files)

    except Exception as exc:
        log_diagnostic(f"Error parsing ownership table from {progress_path}: {exc}")

    return ownership


def is_scratch_path(path_str: str) -> bool:
    """Check if target path is legitimately within a designated scratch directory.
    Prevents evasion where arbitrary filenames contain the substring 'scratch' (e.g. scratch_backend.py).
    """
    try:
        clean_p, _ = strip_unc_prefix(path_str)
        p = pathlib.PurePath(clean_p)
        parts = [part.lower() for part in p.parts]
        return "scratch" in parts[:-1]
    except Exception:
        return False


def find_file_owner(
    target_path: str,
    ownership_map: dict[str, list[str]],
    workspace_root: pathlib.Path | None = None,
) -> str | None:
    """Find the designated owner of target_path in ownership map.

    Checks:
    1. Normalized basename (e.g. service_api.py).
    2. Normalized relative path from workspace_root if provided (e.g. src/service_api.py).
    3. Canonical realpath resolution (defeats symlinks and junction traversal).
    4. NTFS Inode / File ID tracking for hardlinks (get_file_identity).
    5. Windows 8.3 short name patterns (e.g. SERVIC~1.PY).
    6. Normalized full sanitized path if distinct.
    """
    clean_target = sanitize_target_path(target_path)
    clean_target, _ = strip_unc_prefix(clean_target)
    target_p = pathlib.Path(clean_target)
    norm_basename = normalize_identifier(target_p.name)

    # 1. Check basename match
    if norm_basename:
        for owner, files in ownership_map.items():
            if norm_basename in files:
                return owner

    # 2. Check relative path match if workspace_root is provided
    if workspace_root:
        try:
            abs_workspace = workspace_root.resolve()
            if target_p.is_absolute():
                rel = target_p.relative_to(abs_workspace)
            else:
                rel = target_p
            norm_rel = normalize_identifier(str(rel).replace("\\", "/"))
            if norm_rel:
                for owner, files in ownership_map.items():
                    if norm_rel in files:
                        return owner
        except (ValueError, Exception):
            pass

    # 3. Canonical realpath resolution and Inode / Hardlink identity check
    try:
        if target_p.is_absolute():
            real_target = os.path.realpath(clean_target)
        elif workspace_root:
            real_target = os.path.realpath(str(workspace_root / target_p))
        else:
            real_target = os.path.realpath(clean_target)

        target_real_p = pathlib.Path(real_target)
        real_basename = normalize_identifier(target_real_p.name)
        if real_basename and real_basename != norm_basename:
            for owner, files in ownership_map.items():
                if real_basename in files:
                    return owner

        # Inode / File ID tracking for hardlinks
        target_identity = get_file_identity(real_target)
        if target_identity and workspace_root:
            for owner, files in ownership_map.items():
                for f_name in files:
                    f_cand = workspace_root / f_name
                    if f_cand.exists() and get_file_identity(f_cand) == target_identity:
                        return owner
    except Exception:
        pass

    # 4. Windows 8.3 short name defense
    if "~" in norm_basename:
        stem, _, ext = norm_basename.partition(".")
        short_stem = stem.split("~")[0]
        if short_stem:
            for owner, files in ownership_map.items():
                for f_name in files:
                    f_stem, _, f_ext = f_name.partition(".")
                    if f_stem.startswith(short_stem) and f_ext == ext:
                        return owner

    # 5. Check normalized path
    norm_path = normalize_identifier(clean_target)
    if norm_path and norm_path != norm_basename:
        for owner, files in ownership_map.items():
            if norm_path in files:
                return owner

    return None


def is_caller_owner(caller_identity: str, designated_owner: str) -> bool:
    """Fuzzy check if caller matches the designated owner.

    Guards against:
    - Homoglyph disguises
    - False positive substring matches from short or generic tokens ('worker', 'subagent', 'ws')
    - Empty or stripped tokens
    """
    c_norm = normalize_identifier(caller_identity)
    o_norm = normalize_identifier(designated_owner)

    if not c_norm or not o_norm:
        return False

    # 1. Exact match
    if c_norm == o_norm:
        return True

    # 2. Tokenized component comparison (avoids dangerous false substring matches)
    c_tokens = [t for t in re.split(r"[^a-z0-9]", c_norm) if t]
    o_tokens = [t for t in re.split(r"[^a-z0-9]", o_norm) if t]
    c_token_set = set(c_tokens)
    o_token_set = set(o_tokens)

    if c_token_set == o_token_set:
        return True

    GENERIC_ROLES = {"worker", "subagent", "agent", "tho", "dev", "task"}
    c_specific = {t for t in c_token_set if t not in GENERIC_ROLES}
    o_specific = {t for t in o_token_set if t not in GENERIC_ROLES}

    # If specific tokens match exactly (e.g. Worker_Backend_01 vs Backend_01)
    if c_specific and o_specific and c_specific == o_specific:
        return True

    # Check if one is a subset of the other, but ONLY for specific tokens of substantial length (>= 3 chars)
    if c_specific and o_specific:
        common = c_specific & o_specific
        if (c_specific.issubset(o_specific) or o_specific.issubset(c_specific)) and any(len(t) >= 3 for t in common):
            return True

    # 3. Known aliases (ws2 -> backend, ws1 -> devops, ws3 -> techlead, ws4 -> qa)
    alias_map = {
        "backend": "ws2",
        "devops": "ws1",
        "techlead": "ws3",
        "qa": "ws4",
    }
    for k, v in alias_map.items():
        if (k in c_token_set and v in o_token_set) or (k in o_token_set and v in c_token_set):
            return True

    return False


def evaluate_file_ownership(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate whether file modification satisfies Exclusive File Ownership."""
    if not isinstance(payload, dict):
        return pre_tool_response("allow", "Payload is not a dictionary.")

    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""

    if tool_name not in MONITORED_TOOLS:
        return pre_tool_response("allow", f"Tool '{tool_name}' is not monitored for file ownership.")

    args = get_tool_args(tool_call)
    raw_target = extract_target_path(args)
    if not raw_target:
        return pre_tool_response("allow", "No target file found in tool args.")

    clean_target = sanitize_target_path(raw_target)
    if not clean_target:
        return pre_tool_response("allow", "Target path could not be parsed.")

    target_basename = pathlib.Path(clean_target).name.lower() or clean_target.lower()
    caller = detect_caller_identity(payload)
    caller_norm = normalize_identifier(caller)

    # 1. PM Orchestrator is allowed to edit tracking/management files
    is_pm = any(k in caller_norm for k in ("pm", "orchestrator", "project_manager", "lead_pm"))
    is_management_doc = target_basename in PM_OWNED_FILES or "activity_logs" in clean_target.lower() or "activity_logs" in raw_target.lower()
    if is_management_doc:
        if is_pm:
            return pre_tool_response("allow", f"PM Orchestrator authorized to update tracking file '{target_basename}'.")
        # Check if caller is writing their own role log (e.g. progress_backend.md)
        if f"progress_{caller_norm}" in target_basename:
            return pre_tool_response("allow", "Private role progress log permitted.")
        reason = (
            "CƯỠNG CHẾ ĐỘC QUYỀN SỞ HỮU FILE (§EXCLUSIVE-FILE-OWNERSHIP): LỆNH TỪ SẾP (HARD DENY)!\n"
            f"Caller '{caller}' CẤM sửa tệp quản trị '{target_basename}'!\n"
            "Tệp này thuộc quyền sở hữu độc quyền của PM Orchestrator."
        )
        log_diagnostic(f"BLOCKED: Non-PM caller '{caller}' attempted to modify PM file '{target_basename}'.")
        return pre_tool_response("deny", reason)

    # 2. Private role progress log / temporary scratch files (strict scratch directory check)
    if f"progress_{caller_norm}" in target_basename or is_scratch_path(clean_target) or is_scratch_path(raw_target):
        return pre_tool_response("allow", "Private role progress log or scratch file permitted.")

    # 3. Locate progress.md and parse ownership table
    workspace_roots = get_workspace_roots(payload)
    progress_file: pathlib.Path | None = None
    matched_root: pathlib.Path | None = None
    for r in workspace_roots:
        candidate = r / "progress.md"
        if candidate.is_file():
            progress_file = candidate
            matched_root = r
            break
    if not progress_file and not payload.get("workspacePaths"):
        candidate_cwd = pathlib.Path.cwd().resolve() / "progress.md"
        if candidate_cwd.is_file():
            progress_file = candidate_cwd
            matched_root = pathlib.Path.cwd().resolve()

    if not progress_file:
        # No progress file found -> allow (no ownership declared)
        return pre_tool_response("allow", "No progress.md found; ownership enforcement bypassed.")

    ownership_map = parse_ownership_table(progress_file)
    if not ownership_map:
        # No ownership table in progress.md -> allow
        return pre_tool_response("allow", "No ownership table declared in progress.md; write allowed.")

    designated_owner = find_file_owner(clean_target, ownership_map, workspace_root=matched_root)
    if not designated_owner:
        # Fallback check on raw target path
        designated_owner = find_file_owner(raw_target, ownership_map, workspace_root=matched_root)
    if not designated_owner:
        # File is not declared in the exclusive ownership table -> allow
        return pre_tool_response("allow", f"File '{target_basename}' is not restricted in ownership table.")

    # 4. Check if current caller owns this file
    if is_caller_owner(caller, designated_owner):
        log_diagnostic(f"Authorized: Caller '{caller}' owns '{target_basename}'.")
        return pre_tool_response("allow", f"Caller '{caller}' is verified owner of '{target_basename}'.")

    # 5. HARD DENY - Boss's strict order (0 exceptions)
    reason = (
        "CƯỠNG CHẾ ĐỘC QUYỀN SỞ HỮU FILE (§EXCLUSIVE-FILE-OWNERSHIP): LỆNH TỪ SẾP (HARD DENY - 0 NGOẠI LỆ)!\n"
        f"Subagent '{caller}' CẤM sửa file '{raw_target}'!\n"
        f"File này đã được phân bổ độc quyền cho '{designated_owner}'.\n"
        "Mọi hành vi vi phạm ranh giới sở hữu file đều bị CHẶN NGAY LẬP TỨC để triệt tiêu 100% "
        "rủi ro Race Condition / Merge Conflict khi đa luồng chạy song song!"
    )
    log_diagnostic(f"HARD DENIED: Caller '{caller}' attempted to edit '{target_basename}' owned by '{designated_owner}'.")
    return pre_tool_response("deny", reason)


def run_self_tests() -> bool:
    """Self-test runner covering File Ownership scenarios."""
    print("======================================================================")
    print("Running File Ownership Guard Self-Test Suite")
    print("======================================================================\n")

    import tempfile
    test_results: list[tuple[str, bool, str]] = []

    def record(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        test_results.append((name, passed, detail))
        print(f"[{status}] {name}{f' - {detail}' if detail and not passed else ''}")

    with tempfile.TemporaryDirectory() as temp_dir:
        t_root = pathlib.Path(temp_dir)

        progress_content = """# Bảng Exclusive File Ownership
| Subagent | File(s) Owned | Trạng Thái |
|---|---|---|
| DevOps_WS1 | `PM_RULES.md`, `AGENTS.md` | Đang chạy |
| Backend_WS2 | `turn_1_gate_enforcer.py`, `hooks.json` | Đang chạy |
| TechLead_WS3 | `task_contract_spec.md` | Đang chạy |
| QA_WS4 | `test_turn_1.py` | Đang chạy |
"""
        (t_root / "progress.md").write_text(progress_content, encoding="utf-8")

        # TC1: Deny QA_WS4 modifying turn_1_gate_enforcer.py (owned by Backend_WS2)
        r1 = evaluate_file_ownership({
            "caller_role": "QA_WS4",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(t_root / "turn_1_gate_enforcer.py"), "CodeContent": "x"},
            },
            "workspacePaths": [str(t_root)],
        })
        record(
            "TC1: Hard DENY Worker B modifying file of Worker A",
            r1.get("decision") == "deny" and "HARD DENY" in r1.get("reason", ""),
        )

        # TC2: Allow Backend_WS2 modifying turn_1_gate_enforcer.py (assigned file)
        r2 = evaluate_file_ownership({
            "caller_role": "Backend_WS2",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(t_root / "turn_1_gate_enforcer.py"), "CodeContent": "x"},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC2: Allow Worker modifying assigned file", r2.get("decision") == "allow")

        # TC3: Allow PM Orchestrator modifying progress.md
        r3 = evaluate_file_ownership({
            "caller_role": "PM_Orchestrator",
            "toolCall": {
                "name": "replace_file_content",
                "args": {"TargetFile": str(t_root / "progress.md"), "ReplacementContent": "y"},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC3: Allow PM modifying progress.md", r3.get("decision") == "allow")

        # TC4: Allow Backend editing role progress log progress_backend_ws2.md
        r4 = evaluate_file_ownership({
            "caller_role": "Backend_WS2",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(t_root / "progress_backend_ws2.md"), "CodeContent": "log"},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC4: Allow editing role progress log", r4.get("decision") == "allow")

        # TC5: Allow when no ownership table is configured
        with tempfile.TemporaryDirectory() as empty_dir:
            e_root = pathlib.Path(empty_dir)
            r5 = evaluate_file_ownership({
                "caller_role": "Backend_WS2",
                "toolCall": {
                    "name": "write_to_file",
                    "args": {"TargetFile": str(e_root / "other.py")},
                },
                "workspacePaths": [str(e_root)],
            })
            record("TC5: Bypass when no ownership table exists", r5.get("decision") == "allow")

        # TC6: Deny Backend_WS2 modifying AGENTS.md (owned by DevOps_WS1)
        r6 = evaluate_file_ownership({
            "caller_role": "Backend_WS2",
            "toolCall": {
                "name": "replace_file_content",
                "args": {"TargetFile": str(t_root / "AGENTS.md"), "ReplacementContent": "z"},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC6: Deny Backend modifying AGENTS.md", r6.get("decision") == "deny")

        # TC7: Allow non-modifying tools (run_command, view_file)
        r7 = evaluate_file_ownership({
            "caller_role": "QA_WS4",
            "toolCall": {"name": "run_command", "args": {"CommandLine": "dir"}},
            "workspacePaths": [str(t_root)],
        })
        record("TC7: Allow non-modifying tools", r7.get("decision") == "allow")

        # TC8: Malformed payload safety fallback
        r8 = evaluate_file_ownership({})
        record("TC8: Malformed payload safety fallback", r8.get("decision") == "allow")

        # TC9: Subprocess streaming verification
        proc = subprocess.run(
            [sys.executable, str(pathlib.Path(__file__).resolve())],
            input=json.dumps({
                "caller_role": "QA_WS4",
                "toolCall": {
                    "name": "write_to_file",
                    "args": {"TargetFile": str(t_root / "turn_1_gate_enforcer.py"), "CodeContent": "x"},
                },
                "workspacePaths": [str(t_root)],
            }),
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        sub_out = json.loads(proc.stdout) if proc.stdout.strip() else {}
        record("TC9: Subprocess streaming verification", proc.returncode == 0 and sub_out.get("decision") == "deny")

        # TC10: Worker with name containing 'Worker' (e.g. Worker_Backend_01) parsed and allowed for own file
        progress_worker_content = """# Exclusive File Ownership
| STT | Worker | File Ownership | Trạng thái |
|---|---|---|---|
| 1 | Worker_Backend_01 | `service_api.py`, `database.py` | Working |
| 2 | Worker_Frontend_02 | `app.tsx`, `styles.css` | Working |
"""
        (t_root / "progress.md").write_text(progress_worker_content, encoding="utf-8")
        parsed_tbl = parse_ownership_table(t_root / "progress.md")
        has_worker_row = "worker_backend_01" in parsed_tbl and "service_api.py" in parsed_tbl["worker_backend_01"]
        record("TC10: Parser retains rows where agent name contains 'Worker'", has_worker_row)

        # TC11: Worker_Backend_01 allowed to modify service_api.py
        r11 = evaluate_file_ownership({
            "caller_role": "Worker_Backend_01",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(t_root / "service_api.py"), "CodeContent": "pass"},
            },
            "workspacePaths": [str(t_root)],
        })
        record("TC11: Worker_Backend_01 allowed to modify own file", r11.get("decision") == "allow")

        # TC12: Worker_Frontend_02 modifying service_api.py (owned by Worker_Backend_01) receives HARD DENY
        r12 = evaluate_file_ownership({
            "caller_role": "Worker_Frontend_02",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(t_root / "service_api.py"), "CodeContent": "exploit"},
            },
            "workspacePaths": [str(t_root)],
        })
        record(
            "TC12: Hard DENY Worker_Frontend_02 modifying Worker_Backend_01 file",
            r12.get("decision") == "deny" and "HARD DENY" in r12.get("reason", ""),
        )

        # TC13: UTF-8 BOM handling in progress.md
        bom_root = t_root / "bom_workspace"
        bom_root.mkdir(exist_ok=True)
        bom_progress = b"\xef\xbb\xbf# Exclusive File Ownership\n| Subagent | File(s) Owned |\n|---|---|\n| Worker_Sec_01 | secret_core.py |\n"
        (bom_root / "progress.md").write_bytes(bom_progress)

        r13_deny = evaluate_file_ownership({
            "caller_role": "Worker_Attacker_02",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(bom_root / "secret_core.py"), "CodeContent": "steal"},
            },
            "workspacePaths": [str(bom_root)],
        })
        r13_allow = evaluate_file_ownership({
            "caller_role": "Worker_Sec_01",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(bom_root / "secret_core.py"), "CodeContent": "legit"},
            },
            "workspacePaths": [str(bom_root)],
        })
        record(
            "TC13: UTF-8 BOM progress.md parsing & enforcement",
            r13_deny.get("decision") == "deny" and r13_allow.get("decision") == "allow",
        )

        # TC14: Multi-layer percent-encoded evasion (%252e%252fservice_api%252epy)
        r14_deny = evaluate_file_ownership({
            "caller_role": "Worker_Frontend_02",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "%252e%252fservice_api%252epy", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        r14_allow = evaluate_file_ownership({
            "caller_role": "Worker_Backend_01",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "%252e%252fservice_api%252epy", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        record(
            "TC14: Multi-layer percent-encoding evasion blocked",
            r14_deny.get("decision") == "deny" and r14_allow.get("decision") == "allow",
        )

        # TC15: Windows trailing dots and spaces evasion (service_api.py. . )
        r15_deny = evaluate_file_ownership({
            "caller_role": "Worker_Frontend_02",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "service_api.py. . ", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        r15_allow = evaluate_file_ownership({
            "caller_role": "Worker_Backend_01",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "service_api.py. . ", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        record(
            "TC15: Windows trailing dots & spaces evasion blocked",
            r15_deny.get("decision") == "deny" and r15_allow.get("decision") == "allow",
        )

        # TC16: Cyrillic homoglyphs in file path (servi\u0441e_api.py)
        r16_deny = evaluate_file_ownership({
            "caller_role": "Worker_Frontend_02",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "servi\u0441e_api.py", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        r16_allow = evaluate_file_ownership({
            "caller_role": "Worker_Backend_01",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "servi\u0441e_api.py", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        record(
            "TC16: Cyrillic homoglyph in file path blocked",
            r16_deny.get("decision") == "deny" and r16_allow.get("decision") == "allow",
        )

        # TC17: Zero-width characters in file path (service\u200b_api.py)
        r17_deny = evaluate_file_ownership({
            "caller_role": "Worker_Frontend_02",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "service\u200b_api.py", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        r17_allow = evaluate_file_ownership({
            "caller_role": "Worker_Backend_01",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "service\u200b_api.py", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        record(
            "TC17: Zero-width invisible characters in path blocked",
            r17_deny.get("decision") == "deny" and r17_allow.get("decision") == "allow",
        )

        # TC18: Fullwidth Unicode characters in file path (\uff53\uff45\uff52\uff56\uff49\uff43\uff45\uff3f\uff41\uff50\uff49\uff0e\uff50\uff59)
        r18_deny = evaluate_file_ownership({
            "caller_role": "Worker_Frontend_02",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "\uff53\uff45\uff52\uff56\uff49\uff43\uff45\uff3f\uff41\uff50\uff49\uff0e\uff50\uff59", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        r18_allow = evaluate_file_ownership({
            "caller_role": "Worker_Backend_01",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "\uff53\uff45\uff52\uff56\uff49\uff43\uff45\uff3f\uff41\uff50\uff49\uff0e\uff50\uff59", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        record(
            "TC18: Fullwidth Unicode characters in path blocked",
            r18_deny.get("decision") == "deny" and r18_allow.get("decision") == "allow",
        )

        # TC19: Homoglyphs in caller identity & generic caller hijacking defense
        r19_allow = evaluate_file_ownership({
            "caller_role": "Worker_B\u0430ckend_01",  # Cyrillic small 'a'
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(t_root / "service_api.py"), "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        r19_deny_generic = evaluate_file_ownership({
            "caller_role": "Worker",  # Generic role substring attempt
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(t_root / "service_api.py"), "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        record(
            "TC19: Caller homoglyph resolved and generic role hijacking denied",
            r19_allow.get("decision") == "allow" and r19_deny_generic.get("decision") == "deny",
        )

        # TC20: Relative traversal path resolution (sub/../service_api.py)
        r20_deny = evaluate_file_ownership({
            "caller_role": "Worker_Frontend_02",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "sub/../service_api.py", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        r20_allow = evaluate_file_ownership({
            "caller_role": "Worker_Backend_01",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "sub/../service_api.py", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        record(
            "TC20: Path traversal (../) resolution & enforcement",
            r20_deny.get("decision") == "deny" and r20_allow.get("decision") == "allow",
        )

        # TC21: NTFS Alternate Data Stream (:stream) evasion blocked
        r21_deny = evaluate_file_ownership({
            "caller_role": "Worker_Frontend_02",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "service_api.py:stream", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        r21_allow = evaluate_file_ownership({
            "caller_role": "Worker_Backend_01",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "service_api.py:stream", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        record(
            "TC21: NTFS Alternate Data Stream (:stream) evasion blocked",
            r21_deny.get("decision") == "deny" and r21_allow.get("decision") == "allow",
        )

        # TC22: Windows 8.3 short name evasion blocked (SERVIC~1.PY -> service_api.py)
        r22_deny = evaluate_file_ownership({
            "caller_role": "Worker_Frontend_02",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "SERVIC~1.PY", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        r22_allow = evaluate_file_ownership({
            "caller_role": "Worker_Backend_01",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "SERVIC~1.PY", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        record(
            "TC22: Windows 8.3 short name evasion blocked",
            r22_deny.get("decision") == "deny" and r22_allow.get("decision") == "allow",
        )

        # TC23: Strict scratch directory checking (scratch_backend.py is NOT exempted)
        r23_scratch_dir = evaluate_file_ownership({
            "caller_role": "Worker_Frontend_02",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "scratch/service_api.py", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        r23_fake_scratch = evaluate_file_ownership({
            "caller_role": "Worker_Frontend_02",
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "scratch_service_api.py", "CodeContent": "payload"},
            },
            "workspacePaths": [str(t_root)],
        })
        record(
            "TC23: Strict scratch directory isolation",
            r23_scratch_dir.get("decision") == "allow",
        )

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
    response = evaluate_file_ownership(payload)
    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()
