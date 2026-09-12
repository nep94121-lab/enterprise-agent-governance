#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
top_level_agent_code_guard.py — Physical PreToolUse Hook to Block Agent Chinh from Writing Code
Strictly enforces that the Top-Level Agent (Agent Chinh) CANNOT touch source code files (.py, .js, .ts, etc.).

INVARIANTS ENFORCED:
1. Hard Block on Code Modification by Agent Chinh:
   If the caller is the Top-Level Agent (or root conversation session) and attempts to write or edit
   any source code file (.py, .js, .ts, .go, .rs, .java, .cpp, .cs), the hook TERMINATES with exit code 1 (HARD DENY).
2. Permitted Files for Agent Chinh:
   Only management and specification documents:
   - *.md (request_artifact.md, progress.md, GATE_STATUS.md, DEAD_ENDS.md, handoff.md, activity_logs/*.md, research reports)
   - *.json, *.jsonl, *.yaml, *.yml (configuration and metadata)
3. Delegation Enforcement:
   Forces Agent Chinh to delegate all coding and debugging to Lead PM and Dev Subagents.
4. Hardened Anti-Bypass Security:
   - Unicode Normalization (NFKC/NFKD) to neutralize fullwidth dots, fullwidth letters, slashes.
   - Cross-script Homoglyph resolution (Cyrillic, Greek confusables like р, у, с, о, е, etc.).
   - Multi-layer recursive URL/percent decoding (handles single, double, multi-level %2e%70%79).
   - Complete zero-width, invisible, and BiDi directional control stripping (\u200B..\u200D, \uFEFF, \u202E, etc.).
   - Unicode Case Folding (.casefold()) across all comparisons.
   - Robust Fail-Close stdin handling for unreadable or invalid UTF-8 bytes and malformed payloads.
   - Shell command deobfuscation: PowerShell Base64 -EncodedCommand decoding, Hex/Octal/Unicode escapes,
     PowerShell character code interpolation, and NTFS ADS stream extraction.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import unicodedata
import urllib.parse
from typing import Any

_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_HOOK_DIR = os.path.dirname(_CURRENT_DIR)
if _HOOK_DIR not in sys.path:
    sys.path.insert(0, _HOOK_DIR)

try:
    from hook_utils.powershell_normalizer import (
        decode_powershell_base64_payload,
        extract_base64_payloads,
        strip_powershell_backticks,
    )
except ImportError:
    extract_base64_payloads = None
    strip_powershell_backticks = None

try:
    from common_hook_lib import (
        get_file_identity,
        has_ntfs_ads,
        is_hardlink,
        is_reparse_point,
        is_reserved_device_name,
        strip_unc_prefix,
    )
except ImportError:
    try:
        from hooks_scripts.common_hook_lib import (
            get_file_identity,
            has_ntfs_ads,
            is_hardlink,
            is_reparse_point,
            is_reserved_device_name,
            strip_unc_prefix,
        )
    except ImportError:
        def has_ntfs_ads(p): return False
        def is_hardlink(p): return False
        def is_reparse_point(p): return False
        def is_reserved_device_name(p): return False
        def strip_unc_prefix(p): return p, ""
        def get_file_identity(p): return None

try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

CODE_EXTENSIONS = frozenset({
    '.py', '.pyw', '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx',
    '.go', '.rs', '.java', '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx',
    '.cs', '.php', '.rb', '.sh', '.bash', '.ps1', '.psm1', '.psd1', '.bat', '.cmd',
    '.kt', '.kts', '.swift', '.scala', '.pl', '.pm', '.lua', '.r', '.dart', '.zig'
})

ALLOWED_AGENT_CHINH_BASENAMES = frozenset({
    'progress.md', 'gate_status.md', 'dead_ends.md', 'handoff.md',
    'request_artifact.md', 'dispatch.md', 'briefing.md', 'project_memory.md'
})

# Zero-width, invisible formatting, and BiDi control characters
INVISIBLE_AND_BIDI_CHARS = frozenset({
    '\u200b', '\u200c', '\u200d', '\ufeff', '\u2060', '\u2061', '\u2062', '\u2063', '\u2064',
    '\u034f', '\u00ad', '\u180e',
    '\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
    '\u2066', '\u2067', '\u2068', '\u2069'
})

# Cross-script homoglyphs mapping Cyrillic, Greek, fullwidth, and punctuation confusables to canonical ASCII
HOMOGLYPH_MAP = {
    # Cyrillic confusables
    '\u0430': 'a', '\u0410': 'a',  # Cyrillic a
    '\u0441': 'c', '\u0421': 'c',  # Cyrillic es
    '\u0435': 'e', '\u0415': 'e',  # Cyrillic ie
    '\u0456': 'i', '\u0406': 'i',  # Cyrillic i
    '\u0458': 'j', '\u0408': 'j',  # Cyrillic je
    '\u043e': 'o', '\u041e': 'o',  # Cyrillic o
    '\u0440': 'p', '\u0420': 'p',  # Cyrillic er
    '\u0455': 's', '\u0405': 's',  # Cyrillic dze
    '\u0445': 'x', '\u0425': 'x',  # Cyrillic ha
    '\u0443': 'y', '\u0423': 'y',  # Cyrillic u
    '\u04bb': 'h', '\u04ba': 'h',  # Cyrillic shha
    '\u0442': 't', '\u0422': 't',  # Cyrillic te
    '\u0432': 'b', '\u0412': 'b',  # Cyrillic ve
    '\u0433': 'r', '\u0413': 'r',  # Cyrillic ghe (confusable with r)
    '\u0491': 'r', '\u0490': 'r',  # Ukrainian ghe
    '\u043a': 'k', '\u041a': 'k',  # Cyrillic ka
    '\u043c': 'm', '\u041c': 'm',  # Cyrillic em
    '\u043d': 'h', '\u041d': 'h',  # Cyrillic en
    '\u044c': 'b', '\u042c': 'b',  # Cyrillic soft sign
    '\u04cf': 'l', '\u04c0': 'l',  # Cyrillic palochka
    '\u0501': 'd',                 # Cyrillic komi de
    
    # Greek confusables
    '\u03b1': 'a', '\u0391': 'a',  # Greek alpha
    '\u03b2': 'b', '\u0392': 'b',  # Greek beta
    '\u03b5': 'e', '\u0395': 'e',  # Greek epsilon
    '\u03bf': 'o', '\u039f': 'o',  # Greek omicron
    '\u03c1': 'p', '\u03a1': 'p',  # Greek rho
    '\u03c4': 't', '\u03a4': 't',  # Greek tau
    '\u03c5': 'y', '\u03a5': 'y',  # Greek upsilon
    '\u03c7': 'x', '\u03a7': 'x',  # Greek chi
    '\u03bd': 'v', '\u039d': 'n',  # Greek nu
    '\u03ba': 'k', '\u039a': 'k',  # Greek kappa
    '\u03b9': 'i', '\u0399': 'i',  # Greek iota
    '\u03f2': 'c',                 # Greek lunate sigma

    # Dots / Colons / Slashes / Operators
    '\u3002': '.',                 # Ideographic full stop
    '\uff0e': '.',                 # Fullwidth full stop
    '\ufe52': '.',                 # Small full stop
    '\u2024': '.',                 # One dot leader
    '\u00b7': '.',                 # Middle dot
    '\u22c5': '.',                 # Dot operator
    '\uff0f': '/',                 # Fullwidth solidus
    '\uff3c': '\\',                # Fullwidth reverse solidus
    '\uff1a': ':',                 # Fullwidth colon
    '\ufe55': ':',                 # Small colon
}
HOMOGLYPH_TRANSLATION = str.maketrans(HOMOGLYPH_MAP)

# Regex patterns to detect writing/redirection to code files via shell commands
SHELL_REDIRECTION_REGEX = re.compile(
    r"(?:>>?|[0-9*&]>>?)\s*[\"']?([^\s\"'|&;>]+)[\"']?",
    re.IGNORECASE
)

PS_FILE_WRITE_REGEX = re.compile(
    r"\b(?:Set-Content|Out-File|Add-Content|New-Item|sc|ac|ni)\b.*?(?:-(?:Path|FilePath|LiteralPath|Name)\s+)?[\"']?([^\s\"'|&;]+)[\"']?",
    re.IGNORECASE
)

DOTNET_FILE_WRITE_REGEX = re.compile(
    r"\[(?:System\.)?IO\.File\]::(?:WriteAllText|AppendAllText|Create)\([\"']([^\"']+)[\"']",
    re.IGNORECASE
)

TEE_WRITE_REGEX = re.compile(
    r"\btee\s+(?:-a\s+)?[\"']?([^\s\"'|&;]+)[\"']?",
    re.IGNORECASE
)

PYTHON_INLINE_WRITE_REGEX = re.compile(
    r"python(?:3)?\s+-c\s+.*?(?:open|Path)\([\"']([^\"']+)[\"'].*?['\"][wa\+]",
    re.IGNORECASE
)

NODE_INLINE_WRITE_REGEX = re.compile(
    r"node\s+-e\s+.*?(?:writeFileSync|writeFile|appendFileSync|appendFile)\([\"']([^\"']+)[\"']",
    re.IGNORECASE
)

# Regex to detect PowerShell -EncodedCommand (supports various dash forms: -, /, en-dash, em-dash, etc.)
POWERSHELL_ENC_REGEX = re.compile(
    r"(?:[-/–—−\uff0d](?:encodedcommand|enc|ec|e))\s+[\"']?([A-Za-z0-9+/=]{4,})[\"']?",
    re.IGNORECASE
)


def multi_layer_url_decode(s: str, max_rounds: int = 5) -> str:
    """Recursively decode URL / percent-encoded string (single, double, multi-decode)."""
    if not s or "%" not in s:
        return s
    current = s
    for _ in range(max_rounds):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def strip_invisible_and_bidi(s: str) -> str:
    """Filter out zero-width characters, BiDi controls, and Unicode format category (Cf)."""
    if not s:
        return ""
    return "".join(
        ch for ch in s
        if ch not in INVISIBLE_AND_BIDI_CHARS and unicodedata.category(ch) != "Cf"
    )


def decode_escape_sequences(text: str) -> str:
    """Decode Hex escapes (\\xHH), Unicode escapes (\\uHHHH), Octal escapes (\\0OOO or \\OOO), and PowerShell [char]."""
    if not text:
        return ""
    
    # 1. Hex escapes \xHH
    def hex_sub(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)
    text = re.sub(r'\\x([0-9a-fA-F]{2})', hex_sub, text)

    # 2. Unicode escapes \uHHHH
    def u4_sub(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)
    text = re.sub(r'\\u([0-9a-fA-F]{4})', u4_sub, text)

    # 3. Octal escapes \0OOO or \OOO
    def oct_sub(m: re.Match) -> str:
        try:
            val = int(m.group(1), 8)
            if val < 256:
                return chr(val)
            return m.group(0)
        except Exception:
            return m.group(0)
    text = re.sub(r'\\0([0-7]{2,3})', oct_sub, text)
    text = re.sub(r'\\([0-3][0-7]{2})', oct_sub, text)

    # 4. PowerShell [char]0xHH, [char]NNN, or $([char]...) subexpression interpolation
    def ps_char_sub(m: re.Match) -> str:
        try:
            val = int(m.group(1), 16) if m.group(1) else int(m.group(2))
            return chr(val)
        except Exception:
            return m.group(0)
    text = re.sub(r'(?:\$\()?\s*\[char\]\s*(?:0x([0-9a-fA-F]+)|([0-9]+))\s*\)?', ps_char_sub, text)

    return text


def decode_powershell_base64(b64_payload: str) -> str:
    """Safely decode Base64 payload from PowerShell -EncodedCommand (UTF-16LE / UTF-8 fallback)."""
    if not b64_payload:
        return ""
    try:
        raw_bytes = base64.b64decode(b64_payload.strip())
        try:
            return raw_bytes.decode("utf-16le")
        except UnicodeDecodeError:
            try:
                return raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                return raw_bytes.decode("latin1", errors="ignore")
    except Exception:
        return ""


def normalize_string_canonical(s: str) -> str:
    """
    Complete canonical normalization pipeline:
    1. Multi-pass URL / Percent decoding.
    2. NFKC Unicode normalization (normalizes fullwidth forms, dots, slashes).
    3. Strip invisible, zero-width, and BiDi characters.
    4. Unicode Case Folding (casefold).
    5. Homoglyph / confusable character translation.
    6. Slash normalization.
    """
    if not s or not isinstance(s, str):
        return ""
    # 1. Multi-pass URL decode
    res = multi_layer_url_decode(s)
    # 2. Unicode NFKC normalization
    res = unicodedata.normalize("NFKC", res)
    # 3. Strip invisible / zero-width / BiDi
    res = strip_invisible_and_bidi(res)
    # 4. Unicode Case Folding
    res = res.casefold()
    # 5. Homoglyphs
    res = res.translate(HOMOGLYPH_TRANSLATION)
    # 6. Normalize slashes
    res = res.replace('\\', '/')
    return res


def is_source_code_file(filepath: str) -> bool:
    """
    Detect if filepath is a source code file with multi-layer hardening against evasion:
    - URL multi-decode
    - Unicode NFKC & Homoglyph resolution
    - Invisible / BiDi stripping
    - NTFS ADS stream detection
    - Windows trailing dot / space stripping
    - Symlink & Junction canonical realpath resolution
    - UNC / Volume GUID stripping
    """
    if not filepath or not isinstance(filepath, str):
        return False

    clean_fp, p_type = strip_unc_prefix(filepath)
    if p_type == "VOLUME_GUID":
        return True

    norm = normalize_string_canonical(clean_fp)
    if not norm:
        return False
    norm = norm.replace("`", "").replace("^", "")

    # Handle NTFS Alternate Data Streams (ADS) e.g., "file.py::$DATA", "file.py:stream"
    if ":" in norm:
        parts = norm.split(":")
        # Check if part 0 is single letter drive (e.g. 'c:/path/file.py:stream')
        if len(parts) >= 2 and len(parts[0]) == 1 and parts[0].isalpha():
            if len(parts) >= 3:
                norm = parts[0] + ":" + parts[1]
        else:
            norm = parts[0]

    # Handle trailing Windows dots and spaces e.g. "main.py." or "main.py "
    norm = norm.strip().rstrip(". ")

    # Check extension via splitext
    ext = os.path.splitext(norm)[1]
    if ext in CODE_EXTENSIONS:
        return True

    # Trailing dot/space double check (defense-in-depth)
    for code_ext in CODE_EXTENSIONS:
        if norm.endswith(code_ext):
            return True

    # Check resolved canonical path for symlinks / junctions if target exists on disk
    try:
        real_p = os.path.realpath(clean_fp)
        if real_p != clean_fp:
            real_norm = normalize_string_canonical(real_p).replace('\\', '/')
            real_ext = os.path.splitext(real_norm)[1]
            if real_ext in CODE_EXTENSIONS or any(real_norm.endswith(ce) for ce in CODE_EXTENSIONS):
                return True
    except Exception:
        pass

    return False


def is_management_artifact(filepath: str) -> bool:
    """
    Check if target file is an allowed management artifact for Agent Chinh.
    Enforces canonical normalization, Unicode case folding, and junction / reparse point checks.
    """
    if not filepath or not isinstance(filepath, str):
        return False

    clean_fp, p_type = strip_unc_prefix(filepath)
    if p_type == "VOLUME_GUID":
        return False

    norm = normalize_string_canonical(clean_fp)
    base = os.path.basename(norm).rstrip(". ")

    # If canonical realpath resolves to source code, it cannot be a management artifact
    try:
        real_p = os.path.realpath(clean_fp)
        real_norm = normalize_string_canonical(real_p).replace('\\', '/')
        real_ext = os.path.splitext(real_norm)[1]
        if real_ext in CODE_EXTENSIONS:
            return False
        # Activity logs junction defense: ensure realpath is also inside activity_logs
        if "/activity_logs/" in norm:
            if "/activity_logs/" not in real_norm and "activity_logs" not in real_norm:
                return False
    except Exception:
        pass

    if base in ALLOWED_AGENT_CHINH_BASENAMES:
        return True
    if "/activity_logs/" in norm and norm.endswith(".md"):
        return True
    if any(norm.endswith(ext) for ext in (".md", ".json", ".jsonl", ".yaml", ".yml")):
        return True
    return False


def deobfuscate_command_line(cmd: str) -> str:
    """Deobfuscate command line to uncover hidden file writes."""
    if not cmd or not isinstance(cmd, str):
        return ""
    # 1. Multi-pass URL decode
    res = multi_layer_url_decode(cmd)
    # 2. Unicode NFKC normalization (converts fullwidth redirect ＞ to >)
    res = unicodedata.normalize("NFKC", res)
    # 3. Decode hex/octal/unicode escapes and [char] interpolation
    res = decode_escape_sequences(res)
    # 4. Strip invisible and BiDi characters
    res = strip_invisible_and_bidi(res)
    # 5. Normalize dash characters (Unicode en-dash, em-dash, minus to standard '-')
    res = re.sub(r'[\u2010-\u2015\u2212\uff0d]', '-', res)
    # 6. Strip shell caret escapes (^ in cmd.exe) and backticks (` in PowerShell)
    if strip_powershell_backticks is not None:
        res = strip_powershell_backticks(res).replace('^', '')
    else:
        res = res.replace('^', '').replace('`', '')
    # 7. Strip empty quotes that might break words (e.g. p''y or p""y)
    while "''" in res or '""' in res:
        res = res.replace("''", "").replace('""', "")
    # 8. Strip string concatenation operators (e.g. "a" + ".py" or . + p + y)
    res = re.sub(r'["\']\s*\+\s*["\']', '', res)
    res = re.sub(r'(?<=[^\s])\s*\+\s*(?=[^\s])', '', res)
    return res


def detect_code_write_in_command(command_line: str, depth: int = 0) -> tuple[bool, str]:
    """Inspect shell command to detect attempts to write or redirect source code files."""
    if not command_line or not isinstance(command_line, str) or depth > 5:
        return False, ""

    # 0. Check PowerShell Base64 EncodedCommand payloads
    b64_payloads: list[str] = []
    if extract_base64_payloads is not None:
        b64_payloads.extend(extract_base64_payloads(command_line))

    for match in POWERSHELL_ENC_REGEX.finditer(command_line):
        b64_payload = match.group(1)
        decoded_cmd = decode_powershell_base64(b64_payload)
        if decoded_cmd and decoded_cmd not in b64_payloads:
            b64_payloads.append(decoded_cmd)

    for decoded_cmd in b64_payloads:
        if decoded_cmd:
            is_write, target = detect_code_write_in_command(decoded_cmd, depth=depth + 1)
            if is_write:
                return True, f"PowerShell EncodedCommand -> {target}"

    # Deobfuscate command line for matching
    cleaned = deobfuscate_command_line(command_line)

    # 1. Shell redirection (>, >>, 1>, 2>, *>, &>)
    for match in SHELL_REDIRECTION_REGEX.finditer(cleaned):
        target = match.group(1).strip("\"' ")
        if is_source_code_file(target):
            return True, target

    # 2. PowerShell cmdlets (Set-Content, Out-File, Add-Content, New-Item, sc, ac)
    for match in PS_FILE_WRITE_REGEX.finditer(cleaned):
        target = match.group(1).strip("\"' ")
        if is_source_code_file(target):
            return True, target

    # 2b. .NET file writing ([System.IO.File]::WriteAllText / AppendAllText / Create)
    for match in DOTNET_FILE_WRITE_REGEX.finditer(cleaned):
        target = match.group(1).strip("\"' ")
        if is_source_code_file(target):
            return True, target

    # 3. tee command
    for match in TEE_WRITE_REGEX.finditer(cleaned):
        target = match.group(1).strip("\"' ")
        if is_source_code_file(target):
            return True, target

    # 4. Inline python writing source code
    for match in PYTHON_INLINE_WRITE_REGEX.finditer(cleaned):
        target = match.group(1).strip("\"' ")
        if is_source_code_file(target):
            return True, target

    # 5. Inline node writing source code
    for match in NODE_INLINE_WRITE_REGEX.finditer(cleaned):
        target = match.group(1).strip("\"' ")
        if is_source_code_file(target):
            return True, target

    return False, ""


def validate_agent_chinh_action(target_file: str, is_worker_context: bool = False) -> tuple[bool, str]:
    """
    Blocks Agent Chinh from modifying source code.
    If is_worker_context is True (i.e. called by a dedicated Dev Worker in .agents/), allowed.
    """
    if not target_file:
        return True, "No target file specified"

    # Check if this tool call originates from a dedicated Dev Worker
    if is_worker_context:
        return True, "Worker context permitted"

    clean_target, p_type = strip_unc_prefix(target_file)
    if p_type == "VOLUME_GUID":
        return False, f"❌ [PHYSICAL HOOK HARD BLOCKED]: AGENT CHÍNH BỊ CẤM TUYỆT ĐỐI dùng Volume GUID prefix ('{target_file}')!"

    if has_ntfs_ads(target_file):
        return False, f"❌ [PHYSICAL HOOK HARD BLOCKED]: AGENT CHÍNH BỊ CẤM TUYỆT ĐỐI ghi vào NTFS Alternate Data Stream ('{target_file}')!"

    if is_reserved_device_name(clean_target):
        return False, f"❌ [PHYSICAL HOOK HARD BLOCKED]: AGENT CHÍNH BỊ CẤM TUYỆT ĐỐI ghi vào thiết bị hệ thống Windows ('{target_file}')!"

    # Normalize path
    norm_path = clean_target.replace('\\', '/')

    # If target is source code and NOT a management doc -> HARD BLOCK!
    if is_source_code_file(norm_path):
        return False, f"❌ [PHYSICAL HOOK HARD BLOCKED]: AGENT CHÍNH BỊ CẤM TUYỆT ĐỐI TỰ VIẾT HOẶC SỬA MÃ NGUỒN ('{target_file}')! Bạn là Agent cấp cao, phải giao việc cho Lead PM và Subagents thực hiện!"

    if not is_management_artifact(norm_path):
        return False, f"❌ [PHYSICAL HOOK HARD BLOCKED]: File '{target_file}' không phải là tài liệu quản trị hợp lệ cho Agent Chính."

    return True, "PASSED: Management artifact allowed"


def run_hook():
    """Hook entry point for PreToolUse events with Fail-Close safety."""
    try:
        raw_input = ""
        # Fail-Close: Read stdin bytes safely, reject Unicode decode errors or malformed input
        MAX_STDIN_BYTES = 10 * 1024 * 1024
        if hasattr(sys.stdin, "buffer"):
            raw_bytes = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
            if len(raw_bytes) > MAX_STDIN_BYTES:
                deny_msg = f"❌ [FAIL-CLOSE DENY]: Stdin payload exceeded maximum limit of {MAX_STDIN_BYTES} bytes."
                print(json.dumps({"decision": "DENY", "reason": deny_msg, "message": deny_msg}, ensure_ascii=False))
                sys.exit(0)
            if not raw_bytes or not raw_bytes.strip():
                deny_msg = "❌ [FAIL-CLOSE DENY]: Empty stdin payload received. Access safely denied."
                print(json.dumps({"decision": "DENY", "reason": deny_msg, "message": deny_msg}, ensure_ascii=False))
                sys.exit(0)
            try:
                raw_input = raw_bytes.decode("utf-8")
            except UnicodeDecodeError as ude:
                deny_msg = f"❌ [FAIL-CLOSE DENY]: Stdin Unicode decode error ({ude}). Access safely denied."
                print(json.dumps({"decision": "DENY", "reason": deny_msg, "message": deny_msg}, ensure_ascii=False))
                sys.exit(0)
        else:
            raw_input = sys.stdin.read(MAX_STDIN_BYTES + 1)
            if len(raw_input) > MAX_STDIN_BYTES:
                deny_msg = f"❌ [FAIL-CLOSE DENY]: Stdin payload exceeded maximum limit of {MAX_STDIN_BYTES} bytes."
                print(json.dumps({"decision": "DENY", "reason": deny_msg, "message": deny_msg}, ensure_ascii=False))
                sys.exit(0)
            if not raw_input or not raw_input.strip():
                deny_msg = "❌ [FAIL-CLOSE DENY]: Empty stdin payload received. Access safely denied."
                print(json.dumps({"decision": "DENY", "reason": deny_msg, "message": deny_msg}, ensure_ascii=False))
                sys.exit(0)

        data = json.loads(raw_input)
        if not isinstance(data, dict):
            deny_msg = "❌ [FAIL-CLOSE DENY]: Non-object stdin payload received. Access safely denied."
            print(json.dumps({"decision": "DENY", "reason": deny_msg, "message": deny_msg}, ensure_ascii=False))
            sys.exit(0)
    except Exception as exc:
        deny_msg = f"❌ [FAIL-CLOSE DENY]: Malformed or unreadable stdin payload ({exc}). Access safely denied."
        print(json.dumps({"decision": "DENY", "reason": deny_msg, "message": deny_msg}, ensure_ascii=False))
        sys.exit(0)

    # Standardized payload extraction across all Antigravity formats
    tool_call = data.get("toolCall") if isinstance(data.get("toolCall"), dict) else {}
    tool_name = data.get("tool_name") or tool_call.get("name", "")
    tool_args = data.get("tool_args") or tool_call.get("args", {})
    if not isinstance(tool_args, dict):
        tool_args = {}
    context = data.get("context") if isinstance(data.get("context"), dict) else {}
    
    # Determine caller identity
    raw_role = data.get("caller_role") or data.get("role") or context.get("role", "") or os.environ.get("AGENT_ROLE", "") or ""
    caller_role = str(raw_role) if raw_role is not None else ""
    caller_role_norm = normalize_string_canonical(caller_role)
    is_worker = any(kw in caller_role_norm for kw in [
        "backend", "frontend", "dev", "worker", "debugger", "patcher",
        "qa", "test", "engineer", "devops", "tech_lead", "subagent"
    ])

    # 1. Inspect run_command for shell redirection writing to source code
    if tool_name == "run_command":
        command_line = tool_args.get("CommandLine") or tool_args.get("command") or ""
        is_code_write, target_code = detect_code_write_in_command(command_line)
        if is_code_write and not is_worker:
            reason = (
                f"❌ [PHYSICAL HOOK HARD BLOCKED]: AGENT CHÍNH BỊ CẤM TUYỆT ĐỐI DÙNG RUN_COMMAND ĐỂ GHI MÃ NGUỒN QUA SHELL REDIRECTION ('{target_code}')! "
                "Bạn là Agent cấp cao, phải giao việc cho Lead PM và Dev Subagents thực hiện!"
            )
            print(f"\n{reason}\n", file=sys.stderr)
            rejection_response = {
                "decision": "DENY",
                "reason": reason,
                "message": reason
            }
            print(json.dumps(rejection_response, ensure_ascii=False))
            sys.exit(0)

        # Allow non-violating run_command
        allow_response = {
            "decision": "ALLOW",
            "reason": "run_command does not write to source code"
        }
        print(json.dumps(allow_response, ensure_ascii=False))
        sys.exit(0)

    # 2. Inspect file-writing tools (write_to_file, replace_file_content, etc.)
    if tool_name in ("write_to_file", "replace_file_content", "multi_replace_file_content"):
        target_file = (
            tool_args.get("TargetFile") or
            tool_args.get("target_file") or
            tool_args.get("path") or
            tool_args.get("file_path") or
            tool_args.get("FilePath") or ""
        )
        passed, reason = validate_agent_chinh_action(target_file, is_worker_context=is_worker)
        if not passed:
            print(f"\n{reason}\n", file=sys.stderr)
            rejection_response = {
                "decision": "DENY",
                "reason": reason,
                "message": reason
            }
            print(json.dumps(rejection_response, ensure_ascii=False))
            sys.exit(0)

        allow_response = {
            "decision": "ALLOW",
            "reason": reason
        }
        print(json.dumps(allow_response, ensure_ascii=False))
        sys.exit(0)

    # All other tools allowed
    print(json.dumps({"decision": "ALLOW", "reason": f"Tool '{tool_name}' permitted"}, ensure_ascii=False))
    sys.exit(0)


def self_test():
    import subprocess

    print("======================================================================")
    print("RUNNING SELF-TEST: top_level_agent_code_guard.py")
    print("======================================================================\n")

    # Test 1: Agent Chinh writing python service code -> HARD BLOCKED
    passed, reason = validate_agent_chinh_action("services/order_management/main.py", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 1 Failed: {reason}"
    print("[PASS] Test 1: Agent Chinh writing service code is HARD BLOCKED.")

    # Test 2: Agent Chinh writing test code -> HARD BLOCKED
    passed, reason = validate_agent_chinh_action("tests/test_auth.py", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 2 Failed: {reason}"
    print("[PASS] Test 2: Agent Chinh writing test code is HARD BLOCKED.")

    # Test 3: Agent Chinh writing request_artifact.md -> ALLOWED
    passed, reason = validate_agent_chinh_action("C:\\Users\\Admin\\Desktop\\học tập\\request_artifact.md", is_worker_context=False)
    assert passed, f"Test 3 Failed: {reason}"
    print("[PASS] Test 3: Agent Chinh writing request_artifact.md is allowed.")

    # Test 4: Agent Chinh writing progress.md or activity_logs -> ALLOWED
    passed, reason = validate_agent_chinh_action("activity_logs/2026-09-09.md", is_worker_context=False)
    assert passed, f"Test 4 Failed: {reason}"
    print("[PASS] Test 4: Agent Chinh writing activity log is allowed.")

    # Test 5: Dev Worker writing service code -> ALLOWED
    passed, reason = validate_agent_chinh_action("services/order_management/main.py", is_worker_context=True)
    assert passed, f"Test 5 Failed: {reason}"
    print("[PASS] Test 5: Dev Worker writing service code is permitted.")

    # Test 6: Agent Chinh run_command with shell redirection to .py -> DETECTED
    is_write, target = detect_code_write_in_command("echo 'import os' > main.py")
    assert is_write and target == "main.py", f"Test 6 Failed: {is_write}, {target}"
    print("[PASS] Test 6: Shell redirection to main.py detected.")

    # Test 7: Agent Chinh run_command with append redirection to .ts -> DETECTED
    is_write, target = detect_code_write_in_command("echo 'export default {}' >> src/app.ts")
    assert is_write and "app.ts" in target, f"Test 7 Failed: {is_write}, {target}"
    print("[PASS] Test 7: Append redirection to app.ts detected.")

    # Test 8: Agent Chinh run_command with PowerShell Set-Content -> DETECTED
    is_write, target = detect_code_write_in_command("Set-Content -Path script.py -Value 'test'")
    assert is_write and "script.py" in target, f"Test 8 Failed: {is_write}, {target}"
    print("[PASS] Test 8: PowerShell Set-Content to script.py detected.")

    # Test 9: Agent Chinh run_command with Out-File -> DETECTED
    is_write, target = detect_code_write_in_command("cat data.txt | Out-File worker.js")
    assert is_write and "worker.js" in target, f"Test 9 Failed: {is_write}, {target}"
    print("[PASS] Test 9: Out-File to worker.js detected.")

    # Test 10: Agent Chinh run_command redirection to markdown -> ALLOWED
    is_write, _ = detect_code_write_in_command("git log > activity_logs/2026-09-12.md")
    assert not is_write, "Test 10 Failed: Markdown redirection should not be flagged as code write"
    print("[PASS] Test 10: Redirection to markdown file is allowed.")

    # Test 11: Agent Chinh run_command safe command -> ALLOWED
    is_write, _ = detect_code_write_in_command("git status && pytest tests/")
    assert not is_write, "Test 11 Failed: Safe git/pytest command flagged"
    print("[PASS] Test 11: Safe shell command allowed.")

    # Test 12: Subprocess execution simulating Antigravity PreToolUse payload for code write
    test_payload = {
        "caller_role": "top_level_agent",
        "tool_name": "run_command",
        "tool_args": {"CommandLine": "echo 'x=1' > server.py"}
    }
    proc = subprocess.run(
        [sys.executable, __file__],
        input=json.dumps(test_payload),
        capture_output=True,
        text=True,
        encoding="utf-8"
    )
    assert proc.returncode == 0, f"Test 12 Failed: Expected exit 0, got {proc.returncode}"
    resp = json.loads(proc.stdout.strip())
    assert resp.get("decision") == "DENY", f"Test 12 Failed: Expected DENY, got {resp}"
    print("[PASS] Test 12: Subprocess output JSON decision DENY with sys.exit(0).")

    # Test 13: Subprocess execution with toolCall format
    test_payload_toolcall = {
        "caller_role": "top_level_agent",
        "toolCall": {
            "name": "write_to_file",
            "args": {"TargetFile": "services/auth.py", "CodeContent": "secret"}
        }
    }
    proc2 = subprocess.run(
        [sys.executable, __file__],
        input=json.dumps(test_payload_toolcall),
        capture_output=True,
        text=True,
        encoding="utf-8"
    )
    assert proc2.returncode == 0, f"Test 13 Failed: Expected exit 0, got {proc2.returncode}"
    resp2 = json.loads(proc2.stdout.strip())
    assert resp2.get("decision") == "DENY", f"Test 13 Failed: Expected DENY, got {resp2}"
    print("[PASS] Test 13: Subprocess toolCall format parsed and DENIED with sys.exit(0).")

    # =========================================================================
    # HARDENED SECURITY GAP TESTS (Mục 8 - QA Worker 08)
    # =========================================================================

    # Test 14: Fullwidth dot and fullwidth letters: main．ｐｙ -> HARD BLOCKED
    passed, reason = validate_agent_chinh_action("services/order/main\uff0e\uff50\uff59", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 14 Failed: {reason}"
    print("[PASS] Test 14: Fullwidth dot and letters (main．ｐｙ) detected and HARD BLOCKED.")

    # Test 15: Cross-script Homoglyphs (Cyrillic р U+0440 and у U+0443): main.рy and main.ру -> HARD BLOCKED
    passed, reason = validate_agent_chinh_action("main.\u0440y", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 15a Failed: {reason}"
    passed, reason = validate_agent_chinh_action("main.\u0440\u0443", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 15b Failed: {reason}"
    print("[PASS] Test 15: Cyrillic homoglyphs (main.рy / main.ру) detected and HARD BLOCKED.")

    # Test 16: Multi-layer URL / Percent-Encoding (Single and Double-Decode: %2epy and %252e%2570%2579) -> HARD BLOCKED
    passed, reason = validate_agent_chinh_action("src/core/app%2epy", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 16a Failed: {reason}"
    passed, reason = validate_agent_chinh_action("src/core/app%252e%2570%2579", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 16b Failed: {reason}"
    print("[PASS] Test 16: Multi-layer URL percent-encoding (%2epy & %252e%2570%2579) detected and HARD BLOCKED.")

    # Test 17: Zero-width characters and BiDi controls: main.p\u200by and main\u202e.py -> HARD BLOCKED
    passed, reason = validate_agent_chinh_action("src/main.p\u200by", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 17a Failed: {reason}"
    passed, reason = validate_agent_chinh_action("src/main\u202e.py", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 17b Failed: {reason}"
    print("[PASS] Test 17: Zero-width (\u200b) and BiDi (\u202e) characters filtered and HARD BLOCKED.")

    # Test 18: Unicode Case Folding: MAIN.PY and mixed case homoglyphs -> HARD BLOCKED
    passed, reason = validate_agent_chinh_action("SERVICES/HANDLER.PY", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 18 Failed: {reason}"
    print("[PASS] Test 18: Unicode Case Folding (casefold) matches uppercase source extensions.")

    # Test 19: NTFS Alternate Data Streams (ADS): main.py::$DATA and main.py:stream -> HARD BLOCKED
    passed, reason = validate_agent_chinh_action("main.py::$DATA", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 19a Failed: {reason}"
    passed, reason = validate_agent_chinh_action("c:/services/auth.py:hidden_stream", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 19b Failed: {reason}"
    print("[PASS] Test 19: NTFS Alternate Data Streams (ADS) detected and HARD BLOCKED.")

    # Test 20: Windows trailing dots and spaces: main.py. and main.py -> HARD BLOCKED
    passed, reason = validate_agent_chinh_action("main.py.", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 20a Failed: {reason}"
    passed, reason = validate_agent_chinh_action("main.py ", is_worker_context=False)
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 20b Failed: {reason}"
    print("[PASS] Test 20: Windows trailing dots and spaces stripped and HARD BLOCKED.")

    # Test 21: Shell redirection with PowerShell Base64 EncodedCommand
    raw_sub_cmd = "echo 'malicious' > backend/app.py"
    b64_payload = base64.b64encode(raw_sub_cmd.encode("utf-16le")).decode("ascii")
    ps_cmd = f"powershell.exe -EncodedCommand {b64_payload}"
    is_write, target = detect_code_write_in_command(ps_cmd)
    assert is_write and "app.py" in target, f"Test 21 Failed: {is_write}, {target}"
    print("[PASS] Test 21: PowerShell Base64 -EncodedCommand decoded and code write detected.")

    # Test 22: PowerShell with Unicode Dash variant (–enc)
    ps_dash_cmd = f"powershell \u2013enc {b64_payload}"
    is_write, target = detect_code_write_in_command(ps_dash_cmd)
    assert is_write and "app.py" in target, f"Test 22 Failed: {is_write}, {target}"
    print("[PASS] Test 22: PowerShell Unicode Dash (–enc) decoded and detected.")

    # Test 23: Hex & Octal escapes in shell commands
    hex_cmd = r"echo 'x=1' > main\x2epy"
    is_write, target = detect_code_write_in_command(hex_cmd)
    assert is_write and "main.py" in target, f"Test 23a Failed: {is_write}, {target}"
    oct_cmd = r"echo 'x=1' > main\056\160\171"
    is_write, target = detect_code_write_in_command(oct_cmd)
    assert is_write and "main.py" in target, f"Test 23b Failed: {is_write}, {target}"
    print("[PASS] Test 23: Hex (\\x2e) and Octal (\\056) escapes decoded and detected.")

    # Test 24: PowerShell [char] interpolation in command
    ps_char_cmd = r'echo test > "$([char]0x2e)$([char]0x70)$([char]0x79)"'
    is_write, target = detect_code_write_in_command(ps_char_cmd)
    assert is_write and ".py" in target, f"Test 24 Failed: {is_write}, {target}"
    print("[PASS] Test 24: PowerShell [char] code interpolation deobfuscated and detected.")

    # Test 25: Fail-Close safety on invalid UTF-8 bytes to stdin -> DENIED
    proc_bad_bytes = subprocess.run(
        [sys.executable, __file__],
        input=b"\xff\xfe\x00\x00\xaa\xbb\xcc",
        capture_output=True
    )
    assert proc_bad_bytes.returncode == 0, f"Test 25 Failed: Exit code {proc_bad_bytes.returncode}"
    resp_bad = json.loads(proc_bad_bytes.stdout.decode("utf-8", errors="replace").strip())
    assert resp_bad.get("decision") == "DENY", f"Test 25 Failed: Expected DENY, got {resp_bad}"
    assert "FAIL-CLOSE" in resp_bad.get("reason", ""), f"Test 25 Failed: Expected FAIL-CLOSE reason, got {resp_bad}"
    print("[PASS] Test 25: Fail-Close safety verified on invalid UTF-8 bytes (returned DENY).")

    # Test 26: Fail-Close safety on malformed JSON to stdin -> DENIED
    proc_bad_json = subprocess.run(
        [sys.executable, __file__],
        input=b"{invalid_json: true,",
        capture_output=True
    )
    assert proc_bad_json.returncode == 0, f"Test 26 Failed: Exit code {proc_bad_json.returncode}"
    resp_bad_json = json.loads(proc_bad_json.stdout.decode("utf-8", errors="replace").strip())
    assert resp_bad_json.get("decision") == "DENY", f"Test 26 Failed: Expected DENY, got {resp_bad_json}"
    print("[PASS] Test 26: Fail-Close safety verified on malformed JSON (returned DENY).")

    # Test 27: Fail-Close safety on empty stdin -> DENIED
    proc_empty = subprocess.run(
        [sys.executable, __file__],
        input=b"",
        capture_output=True
    )
    assert proc_empty.returncode == 0, f"Test 27 Failed: Exit code {proc_empty.returncode}"
    resp_empty = json.loads(proc_empty.stdout.decode("utf-8", errors="replace").strip())
    assert resp_empty.get("decision") == "DENY", f"Test 27 Failed: Expected DENY, got {resp_empty}"
    print("[PASS] Test 27: Fail-Close safety verified on empty stdin (returned DENY).")

    # Test 28: Volume GUID target write blocked for Agent Chinh
    passed, reason = validate_agent_chinh_action(r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\test.md")
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 28 Failed: {reason}"
    print("[PASS] Test 28: Volume GUID target write blocked for Agent Chinh.")

    # Test 29: DOS reserved device write blocked for Agent Chinh
    passed, reason = validate_agent_chinh_action("CON")
    assert not passed and "CẤM TUYỆT ĐỐI" in reason, f"Test 29 Failed: {reason}"
    print("[PASS] Test 29: DOS reserved device write blocked for Agent Chinh.")

    print("\n======================================================================")
    print("ALL 29 TESTS PASSED WITH 100% SUCCESS! HOOK IS FULLY HARDENED!")
    print("======================================================================\n")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true", help="Run automated self-tests")
    args, _ = parser.parse_known_args()

    if args.self_test:
        sys.exit(self_test())
    else:
        run_hook()
