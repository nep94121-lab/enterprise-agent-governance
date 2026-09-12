#!/usr/bin/env python3
"""Dual-Engine Lexical AST Shell Sanitizer (PreToolUse / Staging).

Inspired by Anthropic Claude Code Tool Execution Guard & Tree-sitter AST validation.
Implements a multi-layered defense-in-depth pipeline:
1. POSIX shlex Engine (posix=False for Windows safety): Tokenizes commands, handles
   safe quotes preservation, blocks unquoted chaining operators (&&, ||, ;, |, &, \\n)
   and command substitution ($(..), `..`).
2. PowerShell De-obfuscator: Automatically detects -enc, -encodedcommand, -e, -ec flags
   (and case-insensitive/colon variations), decodes Base64 UTF-16LE / UTF-8 payloads,
   and recursively evaluates the unwrapped inner payload.
3. Recursive Wrapper Unwrapping: Recursively peels off deceptive command wrappers
   (sudo, nice, nohup, timeout, builtin, command, cmd /c, cmd.exe /c, powershell -c,
   powershell.exe -c, exec, eval) to analyze the actual executed command.
4. Comprehensive Destructive Blacklist: Enforces zero-tolerance blocking for catastrophic
   commands across POSIX, Windows CMD, and PowerShell:
   - rm -rf
   - :(){ :|:& };: (fork bomb)
   - mkfs (and mkfs.*)
   - dd if=
   - > /dev/
   - chmod -R 777
   - del /f /s /q (and flag permutations)
   - Format-Volume
   - Remove-Item -Recurse -Force C:\\ (and flag/alias permutations)
5. I/O Redirection Guard: Detects and blocks unauthorized redirection operators (> and >>)
   attempting to overwrite system targets, device nodes, root directories, or critical
   operating system files on Windows and Linux.

Dual-field compatibility: Returns both 'decision' ('allow'/'deny') and 'verdict' ('ALLOW'/'DENY').
Self-test suite: 40+ rich scenarios validating 100% compliance.
"""

from __future__ import annotations

import base64
import io
import json
import pathlib
import re
import shlex
import sys
import unicodedata
import urllib.parse
import zlib
from typing import Any

_CURRENT_DIR = pathlib.Path(__file__).resolve().parent
_HOOK_DIR = _CURRENT_DIR.parent
if str(_HOOK_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOK_DIR))

from hook_utils.powershell_normalizer import (
    POWERSHELL_CMDLET_ALIASES,
    decode_powershell_base64_payload,
    expand_powershell_aliases,
    expand_powershell_concatenation,
    extract_base64_payloads,
    get_all_command_variants,
    is_powershell_cmd_flag,
    is_powershell_enc_flag,
    normalize_powershell_command,
    strip_powershell_backticks,
)

try:
    from common_hook_lib import (
        has_ntfs_ads,
        is_reserved_device_name,
        strip_unc_prefix,
    )
except ImportError:
    from hooks_scripts.common_hook_lib import (
        has_ntfs_ads,
        is_reserved_device_name,
        strip_unc_prefix,
    )

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

# ==============================================================================
# CANONICAL UNICODE CONSTANTS & HOMOGLYPH LOOKUPS
# ==============================================================================

# Zero-Width, Invisible, and BiDi Formatting Control Characters
ZERO_WIDTH_AND_INVISIBLE_CHARS = (
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space / Byte Order Mark
    "\u2060",  # Word joiner
    "\u2061",  # Function application
    "\u2062",  # Invisible times
    "\u2063",  # Invisible separator
    "\u2064",  # Invisible plus
    "\u200e",  # Left-to-right mark
    "\u200f",  # Right-to-left mark
    "\u202a",  # Left-to-right embedding
    "\u202b",  # Right-to-left embedding
    "\u202c",  # Pop directional formatting
    "\u202d",  # Left-to-right override
    "\u202e",  # Right-to-left override
    "\u2066",  # Left-to-right isolate
    "\u2067",  # Right-to-left isolate
    "\u2068",  # First strong isolate
    "\u2069",  # Pop directional isolate
    "\u00ad",  # Soft hyphen
    "\u034f",  # Combining grapheme joiner
    "\u180e",  # Mongolian vowel separator
)

# Unicode Newline Operators (Line-breaking characters)
UNICODE_NEWLINES = (
    "\n",      # \u000a Line Feed
    "\r",      # \u000d Carriage Return
    "\u0085",  # Next Line (NEL)
    "\u2028",  # Line Separator (LS)
    "\u2029",  # Paragraph Separator (PS)
    "\u000b",  # Line Tabulation / Vertical Tab
    "\u000c",  # Form Feed
)

# Unicode Dash Variants (PowerShell & Command switches)
UNICODE_DASHES = (
    "\u2010",  # Hyphen
    "\u2011",  # Non-breaking hyphen
    "\u2012",  # Figure dash
    "\u2013",  # En dash (–)
    "\u2014",  # Em dash (—)
    "\u2015",  # Horizontal bar (―)
    "\u2212",  # Minus sign (−)
    "\ufe58",  # Small em dash
    "\ufe63",  # Small hyphen-minus
    "\uff0d",  # Fullwidth hyphen-minus (－)
)

# Extended Unicode Whitespace Characters
UNICODE_WHITESPACES = (
    "\u00a0",  # No-break space
    "\u1680",  # Ogham space mark
    "\u2000",  # En quad
    "\u2001",  # Em quad
    "\u2002",  # En space
    "\u2003",  # Em space
    "\u2004",  # Three-per-em space
    "\u2005",  # Four-per-em space
    "\u2006",  # Six-per-em space
    "\u2007",  # Figure space
    "\u2008",  # Punctuation space
    "\u2009",  # Thin space
    "\u200a",  # Hair space
    "\u202f",  # Narrow no-break space
    "\u205f",  # Medium mathematical space
    "\u3000",  # Ideographic space (CJK fullwidth space)
    "\u180e",  # Mongolian vowel separator
)

# Fullwidth Operators and Special Characters Mapping
FULLWIDTH_OPERATOR_MAP = {
    "\uff06": "&",   # Fullwidth ampersand ＆
    "\uff5c": "|",   # Fullwidth vertical bar ｜
    "\uff1b": ";",   # Fullwidth semicolon ；
    "\uff1e": ">",   # Fullwidth greater-than ＞
    "\uff1c": "<",   # Fullwidth less-than ＜
    "\uff0f": "/",   # Fullwidth slash ／
    "\uff3c": "\\",  # Fullwidth backslash ＼
    "\uff1a": ":",   # Fullwidth colon ：
    "\ufe55": ":",   # Small colon ﹕
    "\ufe65": ">",   # Small greater-than ﹥
    "\ufe64": "<",   # Small less-than ﹤
    "\u2215": "/",   # Division slash ∕
    "\u2044": "/",   # Fraction slash ⁄
    "\u29f5": "\\",  # Reverse solidus operator ⧵
}
FULLWIDTH_OPERATOR_TABLE = str.maketrans(FULLWIDTH_OPERATOR_MAP)

# Cross-Script Homoglyphs Mapping (Cyrillic, Greek, Math lookalikes to Latin ASCII)
HOMOGLYPH_MAP = {
    # Cyrillic lowercase to Latin
    "\u0430": "a", "\u0431": "b", "\u0432": "v", "\u0433": "g", "\u0434": "d",
    "\u0435": "e", "\u0436": "zh", "\u0437": "z", "\u0438": "i", "\u0439": "j",
    "\u043a": "k", "\u043b": "l", "\u043c": "m", "\u043d": "n", "\u043e": "o",
    "\u043f": "n", "\u0440": "p", "\u0441": "c", "\u0442": "t", "\u0443": "y",
    "\u0444": "f", "\u0445": "x", "\u0446": "ts", "\u0447": "ch", "\u0448": "sh",
    "\u0449": "shch", "\u044b": "y", "\u044d": "e", "\u044e": "yu", "\u044f": "ya",
    "\u0455": "s", "\u0456": "i", "\u0458": "j", "\u0454": "e", "\u045c": "k",
    # Cyrillic uppercase to Latin
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0423": "Y", "\u0425": "X", "\u0406": "I", "\u0408": "J", "\u0405": "S",
    # Greek lowercase to Latin
    "\u03b1": "a", "\u03b2": "b", "\u03b3": "y", "\u03b5": "e", "\u03b9": "i",
    "\u03ba": "k", "\u03bd": "v", "\u03bf": "o", "\u03c1": "p", "\u03c2": "s",
    "\u03c3": "s", "\u03c4": "t", "\u03c5": "u", "\u03c7": "x", "\u03c9": "w",
    # Greek uppercase to Latin
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O",
    "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
    # Mathematical / typographic lookalikes
    "\u210e": "h", "\u2113": "l", "\u2115": "N", "\u2119": "P",
    "\u211a": "Q", "\u211d": "R", "\u2124": "Z",
}
HOMOGLYPH_TABLE = str.maketrans(HOMOGLYPH_MAP)

# ==============================================================================
# CANONICAL PRE-PROCESSING & NORMALIZATION UTILITIES
# ==============================================================================

def normalize_dash_variants(text: str) -> str:
    """Normalize all Unicode dash variants to standard ASCII hyphen-minus '-'."""
    res = text
    for d in UNICODE_DASHES:
        res = res.replace(d, "-")
    return res


def decode_percent_and_escapes(text: str, max_depth: int = 5) -> str:
    """Recursively decode percent-encoding, hex escapes, unicode escapes, and octal escapes."""
    current = text
    for _ in range(max_depth):
        prev = current

        # 1. Percent-encoding (e.g. %26, %20, %2526)
        if "%" in current:
            try:
                unquoted = urllib.parse.unquote(current)
                if unquoted != current:
                    current = unquoted
            except Exception:
                pass

        # 2. Hex escape sequences (e.g. \\x26, \\x7c, \\x3b, \\x20)
        if "\\x" in current or "\\X" in current:
            def replace_hex(m: re.Match) -> str:
                try:
                    val = int(m.group(1), 16)
                    return chr(val)
                except Exception:
                    return m.group(0)
            current = re.sub(r"(?i)\\x([0-9a-f]{2})", replace_hex, current)

        # 3. Unicode escape sequences (e.g. \\u0026, \\u007c)
        if "\\u" in current or "\\U" in current:
            def replace_uni(m: re.Match) -> str:
                try:
                    val = int(m.group(1), 16)
                    return chr(val)
                except Exception:
                    return m.group(0)
            current = re.sub(r"(?i)\\u([0-9a-f]{4})", replace_uni, current)

        # 4. Octal escape sequences (e.g. \\046 for &, \\174 for |, \\073 for ;)
        if "\\" in current:
            def replace_oct(m: re.Match) -> str:
                try:
                    val = int(m.group(1), 8)
                    if 0 <= val <= 255:
                        return chr(val)
                    return m.group(0)
                except Exception:
                    return m.group(0)
            current = re.sub(r"\\0?([0-7]{2,3})", replace_oct, current)

        if current == prev:
            break

    return current


def normalize_and_deobfuscate_text(text: str, max_passes: int = 3) -> str:
    """Multi-pass deobfuscation and canonical normalization pipeline.

    1. Multi-layer URL / percent-decoding & hex/unicode/octal escape decoding.
    2. Unicode normalization (NFKC) - decomposes fullwidth & compatibility characters.
    3. Strip zero-width, invisible, and BiDi formatting characters.
    4. Canonical homoglyphs substitution (Cyrillic, Greek, math lookalikes to Latin).
    5. Unicode Dash variants normalization to standard ASCII '-'.
    6. Unicode fullwidth operators & symbols normalization (&, |, ;, >, <, /, \\, :).
    7. Unicode extended whitespace normalization to ASCII space ' '.
    8. Fixed-point loop to ensure convergence against nested/iterated obfuscation.
    """
    if not text:
        return ""
    current = text
    for _ in range(max_passes):
        prev = current

        # 1. Multi-layer URL / percent-decoding & hex/unicode/octal escapes
        current = decode_percent_and_escapes(current)

        # 2. Unicode normalization (NFKC)
        current = unicodedata.normalize("NFKC", current)

        # 3. Strip zero-width and invisible characters
        for zw in ZERO_WIDTH_AND_INVISIBLE_CHARS:
            current = current.replace(zw, "")

        # 4. Homoglyphs mapping to ASCII Latin
        current = current.translate(HOMOGLYPH_TABLE)

        # 5. Unicode Dash variants to standard ASCII '-'
        for d in UNICODE_DASHES:
            current = current.replace(d, "-")

        # 6. Fullwidth operators and symbols to ASCII
        current = current.translate(FULLWIDTH_OPERATOR_TABLE)

        # 7. Extended Unicode whitespaces to standard space ' '
        for ws in UNICODE_WHITESPACES:
            current = current.replace(ws, " ")

        # 8. Strip PowerShell backtick escape characters
        current = current.replace("`", "")

        if current == prev:
            break

    return current


# 1. PowerShell Encoded Command Flags
POWERSHELL_ENC_FLAGS = frozenset({
    "-enc", "/enc",
    "-encodedcommand", "/encodedcommand",
    "-ec", "/ec",
    "-e", "/e",
})

# 2. PowerShell Command Execution Flags
POWERSHELL_CMD_FLAGS = frozenset({
    "-c", "/c",
    "-command", "/command",
})

# 3. CMD Shell Switch Flags
CMD_SHELL_FLAGS = frozenset({
    "/c", "-c",
    "/k", "-k",
    "/r", "-r",
})

# 4. Standard Wrapper Binaries
WRAPPER_BINARIES = frozenset({
    "sudo",
    "nice",
    "nohup",
    "timeout",
    "builtin",
    "command",
    "exec",
    "eval",
    "iex",
    "invoke-expression",
    "wsl",
    "bash",
    "sh",
    "zsh",
    "env",
    "start-process",
    "start",
})

# 5. Shell Command Chaining Tokens
FORBIDDEN_CHAINING_TOKENS = frozenset({"&&", "||", ";", "|", "&"})

# 6. Destructive Blacklist Substrings (Case-Insensitive Match)
DESTRUCTIVE_BLACKLIST_SUBSTRINGS = (
    "rm -rf",
    ":(){ :|:& };:",
    "mkfs",
    "dd if=",
    "> /dev/",
    "chmod -R 777",
    "del /f /s /q",
    "format-volume",
    "remove-item -recurse -force c:\\",
)

# 7. Destructive Blacklist Regex Patterns (Detects Structural Permutations)
DESTRUCTIVE_BLACKLIST_PATTERNS = [
    # rm -rf with various flag combinations
    (
        re.compile(
            r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|-r\s+-f|-f\s+-r|--recursive\s+--force|--force\s+--recursive)\b",
            re.IGNORECASE,
        ),
        "rm -rf",
    ),
    # Fork bomb :(){ :|:& };: variations
    (
        re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),
        ":(){ :|:& };:",
    ),
    # mkfs disk formatting
    (
        re.compile(r"\bmkfs(?:\.[a-zA-Z0-9_-]+)?\b", re.IGNORECASE),
        "mkfs",
    ),
    # dd if= raw disk write
    (
        re.compile(r"\bdd\s+.*?\bif=", re.IGNORECASE),
        "dd if=",
    ),
    # > /dev/ device overwriting
    (
        re.compile(r">\s*/dev/", re.IGNORECASE),
        "> /dev/",
    ),
    # chmod -R 777 permissions stripping
    (
        re.compile(r"\bchmod\s+(?:-R\s+0?777|0?777\s+-R)\b", re.IGNORECASE),
        "chmod -R 777",
    ),
    # del /f /s /q permutations (hardened against catastrophic backtracking)
    (
        re.compile(
            r"\b(?:del|erase)\b(?=[^;\n&|]*?[/-]f)(?=[^;\n&|]*?[/-]s)(?=[^;\n&|]*?[/-]q)",
            re.IGNORECASE,
        ),
        "del /f /s /q",
    ),
    # Format-Volume cmdlet
    (
        re.compile(r"\bformat-volume\b", re.IGNORECASE),
        "Format-Volume",
    ),
    # Remove-Item -Recurse -Force C:\ variations (supports aliases: ri, del, erase, rm, rd, rmdir, and namespace, positional ordering, and flag truncations)
    (
        re.compile(
            r"\b(?:(?:Microsoft\.PowerShell\.[a-zA-Z0-9_]+\\)?(?:remove-item|ri|rd|rmdir|del|erase|rm))\b"
            r"(?=.*?(?:-[a-zA-Z0-9]*r[a-zA-Z0-9]*|--recursive|-r\b))"
            r"(?=.*?(?:-[a-zA-Z0-9]*f[a-zA-Z0-9]*|--force|-fo\b|-f\b))"
            r".*?(?:c:\\|c:|\b[a-zA-Z]:\\|/|\b[a-zA-Z]:)",
            re.IGNORECASE,
        ),
        "Remove-Item -Recurse -Force C:\\",
    ),
    # Windows mklink link creation
    (
        re.compile(r"\bmklink\b(?:\s+(?:/[dDhHjJ]))?", re.IGNORECASE),
        "mklink",
    ),
    # PowerShell New-Item link creation (SymbolicLink, Junction, HardLink)
    (
        re.compile(r"\b(?:new-item|ni)\b.*?-itemtype\s+['\"]?(?:symboliclink|junction|hardlink)['\"]?", re.IGNORECASE),
        "New-Item SymbolicLink/Junction/HardLink",
    ),
    # Windows fsutil low-level manipulation
    (
        re.compile(r"\bfsutil(?:\.exe)?\s+(?:hardlink\s+create|reparsepoint\s+(?:delete|query)|volume\s+dismount)\b", re.IGNORECASE),
        "fsutil filesystem manipulation",
    ),
    # Sysinternals junction
    (
        re.compile(r"\bjunction(?:\.exe)?\b", re.IGNORECASE),
        "junction",
    ),
    # Windows ACL / ownership manipulation
    (
        re.compile(r"\b(?:icacls|cacls|takeown)(?:\.exe)?\b.*?(?:/grant|/deny|/remove|/reset|/f|/r)", re.IGNORECASE),
        "icacls/takeown",
    ),
    # .NET Reflection In-Memory Assembly Loading
    (
        re.compile(
            r"\[(?:System\.)?Reflection\.Assembly\]::Load|\[(?:System\.)?AppDomain\]::CurrentDomain\.Load",
            re.IGNORECASE,
        ),
        ".NET Reflection Assembly Load",
    ),
]

# 8. System Paths and Targets Monitored for Dangerous Redirection
SYSTEM_PATH_PATTERNS = (
    "/dev/",
    "/etc/",
    "/proc/",
    "/sys/",
    "/boot/",
    "/root/",
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "c:\\windows",
    "c:/windows",
    "\\windows\\",
    "/windows/",
    "system32",
    "syswow64",
    "c:\\program files",
    "c:/program files",
    "c:\\program files (x86)",
    "c:/program files (x86)",
    "drivers\\etc\\hosts",
    "drivers/etc/hosts",
    "/etc/hosts",
    "c:\\boot",
    "c:/boot",
)


def is_quoted(tok: str) -> bool:
    """Determine whether a token is wrapped in matching single or double quotes."""
    s = tok.strip()
    return (len(s) >= 2 and ((s.startswith('"') and s.endswith('"')) or
                             (s.startswith("'") and s.endswith("'"))))


def strip_outer_quotes(s: str) -> str:
    """Safely unwrap all matching enclosing single or double quotes."""
    clean = s.strip()
    while is_quoted(clean):
        clean = clean[1:-1].strip()
    return clean


def deobfuscate_powershell_payload(b64_str: str, max_depth: int = 10) -> tuple[bool, str]:
    """Recursively decode PowerShell Base64 payload, handling nested encodings,
    deflate/gzip compression, percent-encoding, hex escapes, and Unicode normalization.
    """
    clean_b64 = b64_str.strip().strip("\"'")
    if not clean_b64:
        return False, "Empty Base64 payload"

    current_payload = clean_b64
    final_decoded = ""

    for depth in range(max_depth):
        # 1. Unquote and clean candidate base64 string
        cand_str = decode_percent_and_escapes(current_payload).strip().strip("\"'")
        cand_str = "".join(cand_str.split())  # remove any internal whitespace/newlines

        # 2. Base64 padding normalization
        missing_padding = len(cand_str) % 4
        if missing_padding:
            cand_str += "=" * (4 - missing_padding)

        raw_bytes = b""
        try:
            raw_bytes = base64.b64decode(cand_str, validate=False)
        except Exception as exc:
            if depth == 0:
                return False, f"Invalid Base64 payload: {exc}"
            break

        if not raw_bytes:
            break

        # 3. Handle Gzip / Deflate compressed streams
        if raw_bytes.startswith(b"\x1f\x8b"):
            try:
                raw_bytes = zlib.decompress(raw_bytes, 16 + zlib.MAX_WBITS)
            except Exception:
                pass
        else:
            # Try raw deflate or zlib stream
            try:
                raw_bytes = zlib.decompress(raw_bytes)
            except Exception:
                try:
                    raw_bytes = zlib.decompress(raw_bytes, -zlib.MAX_WBITS)
                except Exception:
                    pass

        # 4. Decode bytes to string: Intelligent UTF-16LE vs UTF-8 selection
        # PowerShell standard uses UTF-16LE which has null bytes on ASCII characters.
        # Nested Base64 and Unix/Bash tools typically produce raw UTF-8 without nulls.
        has_utf16_nulls = len(raw_bytes) >= 2 and (
            raw_bytes[1::2].count(0) >= max(len(raw_bytes) // 4, 1) or
            raw_bytes[0::2].count(0) >= max(len(raw_bytes) // 4, 1)
        )

        decoded = ""
        # If null patterns indicate UTF-16LE, prioritize UTF-16LE
        if has_utf16_nulls:
            try:
                cand = raw_bytes.decode("utf-16le")
                if any(c.isprintable() for c in cand):
                    decoded = cand
            except UnicodeDecodeError:
                pass

        # If no null patterns or UTF-16LE failed, try UTF-8
        if not decoded:
            try:
                cand = raw_bytes.decode("utf-8")
                printable_ratio = sum(1 for c in cand if c.isprintable()) / max(len(cand), 1)
                ascii_ratio = sum(1 for c in cand if ord(c) < 128) / max(len(cand), 1)
                if printable_ratio > 0.8 and ascii_ratio > 0.5:
                    decoded = cand
            except UnicodeDecodeError:
                pass

        # Fallback to UTF-16LE if UTF-8 didn't match
        if not decoded:
            try:
                cand = raw_bytes.decode("utf-16le")
                if any(c.isprintable() for c in cand):
                    decoded = cand
            except UnicodeDecodeError:
                pass

        # Fallback to general UTF-8 or Latin-1
        if not decoded:
            try:
                decoded = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    decoded = raw_bytes.decode("latin-1")
                except UnicodeDecodeError as exc:
                    if depth == 0:
                        return False, f"Failed to decode payload as UTF-16LE or UTF-8: {exc}"
                    break

        if not decoded:
            break

        # 5. Normalize and decode escapes on current decoded payload
        decoded_norm = decode_percent_and_escapes(decoded)
        final_decoded = decoded_norm

        # 6. Check if payload is nested Base64
        # Case A: Contains powershell -enc <inner>
        nested_match = re.search(
            r"(?i)\b(?:powershell|pwsh)?\s*(?:-|/|[–—―−－])(?:enc|encodedcommand|ec|e)(?::|\s+)([A-Za-z0-9+/=]{4,})",
            decoded_norm,
        )
        if nested_match:
            current_payload = nested_match.group(1)
            continue

        # Case B: The entire decoded string is another Base64 blob
        stripped_cand = decoded_norm.strip().strip("\"'")
        if (
            len(stripped_cand) >= 8
            and re.match(r"^[A-Za-z0-9+/=]+$", stripped_cand)
            and len(stripped_cand) % 4 <= 2
        ):
            # Check if decoding it yields printable characters
            try:
                pad = len(stripped_cand) % 4
                padded = stripped_cand + ("=" * (4 - pad) if pad else "")
                test_bytes = base64.b64decode(padded, validate=False)
                test_txt = ""
                try:
                    test_txt = test_bytes.decode("utf-16le")
                except UnicodeDecodeError:
                    test_txt = test_bytes.decode("utf-8", errors="ignore")
                if test_txt and any(c.isprintable() for c in test_txt):
                    current_payload = stripped_cand
                    continue
            except Exception:
                pass

        # No more nested base64 layers
        break

    if not final_decoded:
        return False, "Failed to extract valid command payload from Base64"

    return True, final_decoded


def check_destructive_blacklist(cmd_str: str) -> str | None:
    """Scan command against destructive commands blacklist (both substrings & regex).
    Applies Unicode normalization (NFKC), homoglyphs resolution, zero-width removal,
    extended whitespace normalization, and escape decoding.
    """
    # 1. Canonical normalization
    normalized_cmd = normalize_and_deobfuscate_text(cmd_str)
    normalized_collapsed = " ".join(normalized_cmd.split())
    clean_lower_norm = normalized_collapsed.casefold()
    clean_lower_raw = cmd_str.lower()

    # Exact or substring match (prioritize normalized, then raw)
    for sub in DESTRUCTIVE_BLACKLIST_SUBSTRINGS:
        if sub in clean_lower_norm or sub in clean_lower_raw:
            return sub

    # Regex permutation match
    for regex_pat, name in DESTRUCTIVE_BLACKLIST_PATTERNS:
        if regex_pat.search(normalized_cmd) or regex_pat.search(normalized_collapsed) or regex_pat.search(cmd_str):
            return name

    # 2. Check PowerShell deobfuscated and alias-expanded variants
    ps_variants = get_all_command_variants(cmd_str)
    for variant in ps_variants:
        v_norm = normalize_and_deobfuscate_text(variant)
        v_collapsed = " ".join(v_norm.split())
        v_lower = v_collapsed.lower()
        for sub in DESTRUCTIVE_BLACKLIST_SUBSTRINGS:
            if sub in v_lower:
                return sub
        for regex_pat, name in DESTRUCTIVE_BLACKLIST_PATTERNS:
            if regex_pat.search(variant) or regex_pat.search(v_collapsed):
                return name

    return None


def unwrap_command_recursively(cmd_str: str) -> tuple[str, dict[str, Any] | None]:
    """Recursively peel off execution wrappers and de-obfuscate PowerShell commands.

    Unwraps:
    - sudo, nice, nohup, timeout, builtin, command, exec, eval
    - cmd /c, cmd.exe /c (and /k, /r)
    - powershell -c, powershell.exe -c, pwsh -c (and -command, /c, /command)
    - powershell -enc, powershell.exe -encodedcommand, pwsh -e, -ec (all Unicode Dash variants)
    """
    current = cmd_str.strip()
    max_depth = 20

    for _ in range(max_depth):
        current = strip_outer_quotes(current)
        if not current:
            break

        try:
            tokens = shlex.split(current, posix=False)
        except ValueError as exc:
            return current, {
                "decision": "deny",
                "verdict": "DENY",
                "reason": f"Unclosed quotation or syntax error during unwrapping: {exc}",
            }

        if not tokens:
            break

        # Check raw executable name (strip path, quotes, and .exe extension)
        first_token = strip_outer_quotes(tokens[0])
        first_token_norm = normalize_dash_variants(first_token)
        first_base = pathlib.PurePath(first_token).name.lower()
        first_stem = first_base[:-4] if first_base.endswith(".exe") else first_base

        # 1. PowerShell wrappers and de-obfuscator
        if first_stem in {"powershell", "pwsh"}:
            enc_idx = -1
            cmd_idx = -1
            found_inline_enc = False

            for i, t in enumerate(tokens[1:], start=1):
                t_clean = strip_outer_quotes(t)
                t_norm = normalize_dash_variants(t_clean).lower().replace("`", "")

                # Check for -enc:payload or -enc payload (with all prefix abbreviations)
                if ":" in t_norm:
                    flag_part, _, payload_part = t_norm.partition(":")
                    if is_powershell_enc_flag(flag_part):
                        payload = t_clean.partition(":")[2]
                        success, decoded = deobfuscate_powershell_payload(payload)
                        if not success:
                            return current, {
                                "decision": "deny",
                                "verdict": "DENY",
                                "reason": f"PowerShell de-obfuscation failed: {decoded}",
                            }
                        current = decoded.strip()
                        found_inline_enc = True
                        break
                    if is_powershell_cmd_flag(flag_part):
                        current = t_clean.partition(":")[2].strip()
                        found_inline_enc = True
                        break

                if is_powershell_enc_flag(t_norm):
                    enc_idx = i
                    break

                if is_powershell_cmd_flag(t_norm):
                    cmd_idx = i
                    break

            if found_inline_enc:
                continue

            if enc_idx != -1:
                if enc_idx + 1 < len(tokens):
                    payload = strip_outer_quotes(tokens[enc_idx + 1])
                    success, decoded = deobfuscate_powershell_payload(payload)
                    if not success:
                        return current, {
                            "decision": "deny",
                            "verdict": "DENY",
                            "reason": f"PowerShell de-obfuscation failed: {decoded}",
                        }
                    current = decoded.strip()
                    continue
                else:
                    return current, {
                        "decision": "deny",
                        "verdict": "DENY",
                        "reason": f"PowerShell encoded flag '{tokens[enc_idx]}' without payload",
                    }

            if cmd_idx != -1:
                if cmd_idx + 1 < len(tokens):
                    current = " ".join(tokens[cmd_idx + 1:]).strip()
                    continue
                else:
                    current = ""
                    continue

        # 2. CMD.EXE wrappers (cmd /c, cmd.exe /c, cmd /k, etc.) - checks any flag position
        if first_stem == "cmd":
            found_cmd = False
            for idx in range(1, len(tokens)):
                tok_norm = normalize_dash_variants(strip_outer_quotes(tokens[idx])).lower()
                if tok_norm in CMD_SHELL_FLAGS:
                    current = " ".join(tokens[idx + 1:]).strip()
                    found_cmd = True
                    break
                if any(tok_norm.startswith(f + ":") for f in CMD_SHELL_FLAGS):
                    current = tokens[idx].split(":", 1)[1] + " " + " ".join(tokens[idx + 1:])
                    current = current.strip()
                    found_cmd = True
                    break
            if found_cmd:
                continue

        # 3. Unix & WSL shell wrappers (bash -c, sh -c, zsh -c, wsl)
        if first_stem in {"bash", "sh", "zsh", "wsl"}:
            found_c = False
            for idx in range(1, len(tokens)):
                tok_norm = normalize_dash_variants(strip_outer_quotes(tokens[idx])).lower()
                if tok_norm == "-c":
                    current = " ".join(tokens[idx + 1:]).strip()
                    found_c = True
                    break
            if found_c:
                continue
            current = " ".join(tokens[1:]).strip()
            continue

        # 4. Start-Process / start
        if first_stem in {"start-process", "start"}:
            sub_tokens = tokens[1:]
            found_sp = False
            for idx, tok in enumerate(sub_tokens):
                t_norm = tok.lower()
                if t_norm in {"-filepath", "-file", "-command"}:
                    if idx + 1 < len(sub_tokens):
                        current = " ".join(sub_tokens[idx + 1:]).strip()
                        found_sp = True
                        break
            if found_sp:
                continue
            current = " ".join(sub_tokens).strip()
            continue

        # 5. Unix wrapper binaries (sudo, nice, nohup, timeout, builtin, command, exec, eval, iex, invoke-expression)
        if first_stem in WRAPPER_BINARIES:
            idx = 1
            if first_stem == "nice":
                if idx < len(tokens) and tokens[idx] == "-n":
                    idx += 2
                elif idx < len(tokens) and re.match(r"^-\d+$", tokens[idx]):
                    idx += 1
            elif first_stem == "timeout":
                if idx < len(tokens) and tokens[idx].lower() in {"/t", "-t", "-s"}:
                    idx += 1
                if idx < len(tokens) and (tokens[idx].isdigit() or re.match(r"^\d+[smhd]?$", tokens[idx])):
                    idx += 1
            current = " ".join(tokens[idx:]).strip()
            continue

        # 4. Standalone PowerShell encoded command without binary name (e.g. -enc <payload>, -enc:payload, /e, etc.)
        first_flag = first_token_norm.lower().replace("`", "")
        if ":" in first_flag:
            flag_part, _, _ = first_flag.partition(":")
            if is_powershell_enc_flag(flag_part):
                payload = first_token.partition(":")[2]
                success, decoded = deobfuscate_powershell_payload(payload)
                if not success:
                    return current, {
                        "decision": "deny",
                        "verdict": "DENY",
                        "reason": f"PowerShell de-obfuscation failed: {decoded}",
                    }
                current = decoded.strip()
                continue
        elif is_powershell_enc_flag(first_flag):
            if len(tokens) >= 2:
                payload = strip_outer_quotes(tokens[1])
                success, decoded = deobfuscate_powershell_payload(payload)
                if not success:
                    return current, {
                        "decision": "deny",
                        "verdict": "DENY",
                        "reason": f"PowerShell de-obfuscation failed: {decoded}",
                    }
                current = decoded.strip()
                continue

        # 5. Extract and inspect embedded .NET Base64 payloads (e.g. [Convert]::FromBase64String("..."))
        b64_extracted = extract_base64_payloads(current)
        if b64_extracted:
            for bp in b64_extracted:
                bl_hit = check_destructive_blacklist(bp)
                if bl_hit:
                    return current, {
                        "decision": "deny",
                        "verdict": "DENY",
                        "reason": f"Forbidden destructive shell command detected inside .NET Base64 payload: '{bl_hit}'",
                    }

        # No more unwrappable wrappers
        break

    return current, None


def strip_powershell_escapes_for_posix_backtick_check(cmd_text: str) -> str:
    """Strip legitimate PowerShell escape sequences before scanning for POSIX backticks.

    PowerShell uses backtick (`) as an escape character:
    - `" and `' (escaped double and single quotes)
    - `$ (escaped dollar variable)
    - `0 (null character)
    - `r`n (escaped carriage return + newline)
    - `a, `b, `e, `f, `n, `r, `t, `v (control character escapes)
    - `` (escaped literal backtick)
    - `u{hex} (unicode escape sequence)

    Distinguishes legitimate PowerShell escapes from POSIX backtick command substitutions
    (`whoami`, `id`, `rm -rf /`, `uname -a`).
    """
    if not cmd_text or "`" not in cmd_text:
        return cmd_text

    text = cmd_text

    # 1. Strip literal backtick escapes: `` -> empty
    text = re.sub(r"``", "", text)

    # 2. Strip escaped quotes and dollar sign anywhere: `", `', `$
    text = re.sub(r"`[\"\'$]", "", text)

    # 3. Strip null byte and unicode escapes: `0, `u{hex}
    text = re.sub(r"`(?:0|u\{[0-9a-fA-F]{1,6}\})", "", text, flags=re.IGNORECASE)

    # 4. Strip CRLF escape sequence: `r`n
    text = re.sub(r"`r`n", "", text, flags=re.IGNORECASE)

    # 5. Inside quoted strings ("..." or '...'), strip any `[0abefnrtv]
    def _strip_quotes_cb(m: re.Match) -> str:
        quote = m.group(1)
        body = m.group(2)
        body_clean = re.sub(r"`[0abefnrtv]", "", body, flags=re.IGNORECASE)
        return f"{quote}{body_clean}{quote}"

    text = re.sub(r'("|\')(.*?)\1', _strip_quotes_cb, text)

    # 6. Outside quoted strings: control escapes followed by non-word or end of string
    text = re.sub(r"`[0abefnrtv](?=[^\w]|$)", "", text, flags=re.IGNORECASE)

    return text


def check_chaining_operators(tokens: list[str], raw_cmd: str) -> str | None:
    """Detect and block forbidden command chaining operators and command substitutions.
    Detects Unicode newlines (\\n, \\r, \\u0085, \\u2028, \\u2029, \\v, \\f) and fullwidth
    chaining operators (＆＆, ｜｜, ；, ＆, ｜).
    """
    # 1. Unicode newline command chaining (\n, \r, \u0085, \u2028, \u2029, \v, \f)
    for nl in UNICODE_NEWLINES:
        if nl in raw_cmd:
            return f"Command chaining via newline operator ({repr(nl)}) detected"

    # Also check decoded escapes on raw_cmd for newlines (e.g. %0a, %0d, \x0a, \n)
    decoded_raw = decode_percent_and_escapes(raw_cmd)
    for nl in UNICODE_NEWLINES:
        if nl in decoded_raw and nl not in raw_cmd:
            return f"Command chaining via encoded newline operator ({repr(nl)}) detected"

    # 2. Command substitution: $(...) and POSIX `command args`
    if "$(" in raw_cmd or "$(" in decoded_raw:
        return "Command substitution operator detected: '$('"
    # Check for POSIX backtick command substitution (e.g. `rm -rf /` or `ls -la`)
    # Distinguish from legitimate PowerShell backtick escapes (`", `', `0, `n, `$, etc.)
    # and PowerShell backtick evasion (`i`e`x, `g`i`t, -`r`e`c)
    raw_cmd_for_bt = strip_powershell_escapes_for_posix_backtick_check(raw_cmd)
    decoded_raw_for_bt = strip_powershell_escapes_for_posix_backtick_check(decoded_raw)

    bt_match = re.search(r"`([^`\r\n]+)`", raw_cmd_for_bt) or re.search(r"`([^`\r\n]+)`", decoded_raw_for_bt)
    if bt_match:
        inner = bt_match.group(1)
        if len(inner) >= 2 or " " in inner:
            return "Command substitution operator detected: '`...`'"

    # 3. Direct inspection for Fullwidth chaining operators in unquoted tokens
    for idx, tok in enumerate(tokens):
        if is_quoted(tok):
            continue

        # Allow leading '&' Call Operator in PowerShell if invoking a command
        if idx == 0 and tok == "&" and len(tokens) > 1:
            continue

        # Direct check for fullwidth operators
        if "＆＆" in tok or "\uff06\uff06" in tok:
            return "Forbidden command chaining operator detected: '＆＆'"
        if "｜｜" in tok or "\uff5c\uff5c" in tok:
            return "Forbidden command chaining operator detected: '｜｜'"
        if "；" in tok or "\uff1b" in tok:
            return "Forbidden command chaining operator detected: '；'"

        # Normalize token: decode percent/hex, strip zero-width, fullwidth map, homoglyph map
        norm_tok = normalize_and_deobfuscate_text(tok)

        if idx == 0 and norm_tok == "&" and len(tokens) > 1:
            continue

        # Exact token match
        if tok in FORBIDDEN_CHAINING_TOKENS or norm_tok in FORBIDDEN_CHAINING_TOKENS:
            display_op = norm_tok if norm_tok in FORBIDDEN_CHAINING_TOKENS else tok
            return f"Forbidden command chaining operator detected: '{display_op}'"

        # Embedded operators in unquoted token
        if "&&" in tok or "&&" in norm_tok:
            return "Forbidden command chaining operator detected: '&&'"
        if "||" in tok or "||" in norm_tok:
            return "Forbidden command chaining operator detected: '||'"
        if ";" in tok or ";" in norm_tok:
            return "Forbidden command chaining operator detected: ';'"
        if "|" in tok or "|" in norm_tok:
            return "Forbidden command chaining operator detected: '|'"

        # Backgrounding (&) or chaining (&) operator
        if tok == "&" or norm_tok == "&" or tok.endswith("&") or norm_tok.endswith("&") or \
           ((tok.startswith("&") or norm_tok.startswith("&")) and not tok.startswith("&>") and not norm_tok.startswith("&>")):
            return "Forbidden command chaining or background operator detected: '&'"
        if ("&" in tok or "&" in norm_tok) and not re.match(r"^[0-9]?>(?:&[0-9]?)?$", norm_tok):
            return "Forbidden command chaining operator detected: '&'"

    return None


def check_io_redirection(tokens: list[str]) -> str | None:
    """Detect and block unauthorized I/O redirection overwriting system files or devices.
    Normalizes Fullwidth redirection operators (＞, ＞＞, ﹥, ﹥﹥), resolves drive letter
    homoglyphs (e.g. Cyrillic 'с' -> Latin 'c'), and canonicalizes path separators.
    """
    for i, tok in enumerate(tokens):
        if is_quoted(tok):
            continue

        # Normalize token operators for redirection matching
        tok_norm = normalize_dash_variants(tok)
        for fw_op, std_op in (("＞", ">"), ("﹥", ">"), ("＜", "<"), ("﹤", "<")):
            tok_norm = tok_norm.replace(fw_op, std_op)

        redir_op = None
        target = ""

        # Standalone redirection operator (>, >>, <, <<, 1>, 2>, 3>-6>, *>, *>>)
        if tok_norm in {
            ">", ">>", "1>", "2>", "1>>", "2>>", "&>", "&>>",
            "<", "<<", "0<", "0<<",
            "3>", "4>", "5>", "6>", "3>>", "4>>", "5>>", "6>>",
            "*>", "*>>",
        }:
            redir_op = tok
            if i + 1 < len(tokens):
                target = strip_outer_quotes(tokens[i + 1])
        # Attached redirection operator (e.g. >/etc/passwd, >>C:\Windows\calc.exe, 3>out.txt, *>>log)
        elif re.match(r"^(?:[0-9]|\*|&)?>{1,2}", tok_norm) or re.match(r"^<[<]?", tok_norm):
            m = re.match(r"^((?:[0-9]|\*|&)?>{1,2}|<[<]?)(.*)$", tok_norm)
            if m:
                redir_op = m.group(1)
                attached = m.group(2).strip()
                if attached:
                    target = strip_outer_quotes(attached)
                elif i + 1 < len(tokens):
                    target = strip_outer_quotes(tokens[i + 1])

        if redir_op and target:
            # File descriptor redirection like 2>&1 is safe
            if re.match(r"^&[0-9]$", target.strip()):
                continue

            # Check NTFS Alternate Data Streams (ADS)
            if has_ntfs_ads(target):
                return f"Forbidden I/O redirection to NTFS Alternate Data Stream: '{redir_op} {target}'"

            # Check Windows DOS reserved devices (CON, PRN, AUX, NUL, COM1-9, LPT1-9, CONIN$, CONOUT$)
            if is_reserved_device_name(target):
                return f"Forbidden I/O redirection to Windows reserved device: '{redir_op} {target}'"

            # Strip NT / UNC / Volume prefixes
            clean_tgt, p_type = strip_unc_prefix(target)
            if p_type == "VOLUME_GUID":
                return f"Forbidden I/O redirection to Volume GUID target: '{redir_op} {target}'"

            # Canonicalize target path: decode percent/hex, NFKC, homoglyphs, slashes, zero-width
            target_norm = normalize_and_deobfuscate_text(clean_tgt)
            target_norm = target_norm.lower().replace("\\", "/")

            # Root path overwrite check
            if target_norm in {"/", "c:", "c:/", "\\"} or clean_tgt.lower() in {"c:\\", "c:"}:
                return f"Forbidden I/O redirection overwriting system root: '{redir_op} {target}'"

            # System directories and sensitive file check
            for sys_pat in SYSTEM_PATH_PATTERNS:
                sys_norm = sys_pat.lower().replace("\\", "/")
                if sys_norm in target_norm:
                    return f"Forbidden I/O redirection overwriting system target: '{redir_op} {target}'"

            # Resolve symlinks and junction points to inspect actual filesystem destination
            try:
                real_tgt = os.path.realpath(clean_tgt).lower().replace("\\", "/")
                for sys_pat in SYSTEM_PATH_PATTERNS:
                    sys_norm = sys_pat.lower().replace("\\", "/")
                    if sys_norm in real_tgt:
                        return f"Forbidden I/O redirection to system target via resolved path: '{redir_op} {target}'"
            except Exception:
                pass

    return None


def sanitize_command(cmd_str: str) -> dict[str, Any]:
    """Sanitize shell command string using Dual-Engine Lexical AST architecture."""
    if not cmd_str or not isinstance(cmd_str, str):
        return {
            "decision": "allow",
            "verdict": "ALLOW",
            "sanitized_command": "",
        }

    raw_clean = cmd_str.strip()
    if not raw_clean:
        return {
            "decision": "allow",
            "verdict": "ALLOW",
            "sanitized_command": "",
        }

    # Large command limit: prevent regex DoS / CPU exhaustion (Gap 16)
    MAX_COMMAND_LEN = 32768
    if len(cmd_str) > MAX_COMMAND_LEN:
        return {
            "decision": "deny",
            "verdict": "DENY",
            "reason": f"Command exceeds maximum allowable length ({len(cmd_str)} > {MAX_COMMAND_LEN} bytes). Potential DoS vector.",
        }

    # Step 0: Check for unquoted Unicode newlines early on raw input
    for nl in UNICODE_NEWLINES:
        if nl in raw_clean:
            return {
                "decision": "deny",
                "verdict": "DENY",
                "reason": f"Command chaining via newline operator ({repr(nl)}) detected",
            }

    # Step 1: Pre-unwrapping check on raw input for destructive blacklist
    matched_destructive = check_destructive_blacklist(raw_clean)
    if matched_destructive:
        return {
            "decision": "deny",
            "verdict": "DENY",
            "reason": f"Forbidden destructive shell command detected: '{matched_destructive}'",
        }

    # Step 2: Recursive wrapper unwrapping & PowerShell de-obfuscation
    unwrapped_cmd, unwrap_error = unwrap_command_recursively(raw_clean)
    if unwrap_error:
        return unwrap_error

    if not unwrapped_cmd:
        return {
            "decision": "allow",
            "verdict": "ALLOW",
            "sanitized_command": "",
        }

    # Step 3: Post-unwrapping check on inner command for destructive blacklist
    matched_unwrapped_destructive = check_destructive_blacklist(unwrapped_cmd)
    if matched_unwrapped_destructive:
        return {
            "decision": "deny",
            "verdict": "DENY",
            "reason": f"Forbidden destructive shell command detected: '{matched_unwrapped_destructive}'",
        }

    # Step 4: Tokenization via POSIX shlex engine (posix=False for Windows safety)
    try:
        tokens = shlex.split(unwrapped_cmd, posix=False)
    except ValueError as exc:
        return {
            "decision": "deny",
            "verdict": "DENY",
            "reason": f"Unclosed quotation or malformed shell command syntax: {exc}",
        }

    # Step 5: Check for command chaining operators (&&, ||, ;, |, &, \n) and substitutions ($(..), `..`)
    chain_err = check_chaining_operators(tokens, unwrapped_cmd)
    if chain_err:
        return {
            "decision": "deny",
            "verdict": "DENY",
            "reason": chain_err,
        }

    # Step 6: I/O Redirection check (> and >> overwriting system targets)
    redir_err = check_io_redirection(tokens)
    if redir_err:
        return {
            "decision": "deny",
            "verdict": "DENY",
            "reason": redir_err,
        }

    # Safe command allowed
    return {
        "decision": "allow",
        "verdict": "ALLOW",
        "sanitized_command": unwrapped_cmd,
    }


def evaluate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate hook payload for run_command or direct command input."""
    if not isinstance(payload, dict):
        return {"decision": "allow", "verdict": "ALLOW"}

    cmd = ""
    tool_call = payload.get("toolCall")
    if isinstance(tool_call, dict):
        tool_name = tool_call.get("name", "")
        if tool_name and tool_name != "run_command":
            return {"decision": "allow", "verdict": "ALLOW"}
        args = tool_call.get("args")
        if isinstance(args, dict):
            cmd = args.get("CommandLine") or args.get("command") or args.get("cmd") or ""

    if not cmd:
        cmd = (
            payload.get("CommandLine")
            or payload.get("command")
            or payload.get("cmd")
            or ""
        )

    if not cmd or not isinstance(cmd, str) or not cmd.strip():
        return {"decision": "allow", "verdict": "ALLOW"}

    return sanitize_command(cmd)


def run_self_test() -> bool:
    """Run comprehensive 40+ self-test scenarios across all guard layers."""
    print("[SELF-TEST] Running Dual-Engine Lexical AST Shell Sanitizer self-tests...")

    # Helper for PowerShell Base64 encoding
    def ps_b64(command: str) -> str:
        return base64.b64encode(command.encode("utf-16le")).decode("ascii")

    # --- Group 1: Wrapper Stripping & Recursive Unwrapping ---
    # Scenario 1: Standard wrappers stripping
    r1 = sanitize_command("nice nohup python script.py")
    assert r1["decision"] == "allow", f"Failed S1: {r1}"
    assert r1["sanitized_command"] == "python script.py", f"Failed S1 sanitized: {r1}"

    # Scenario 2: Multi-level nested wrappers with arguments
    r2 = sanitize_command("sudo timeout 10 nice -n 5 python test.py")
    assert r2["decision"] == "allow", f"Failed S2: {r2}"
    assert r2["sanitized_command"] == "python test.py", f"Failed S2 sanitized: {r2}"

    # Scenario 3: CMD.EXE /c wrapper
    r3 = sanitize_command("cmd.exe /c dir")
    assert r3["decision"] == "allow", f"Failed S3: {r3}"
    assert r3["sanitized_command"] == "dir", f"Failed S3 sanitized: {r3}"

    # Scenario 4: PowerShell -c wrapper
    r4 = sanitize_command('powershell.exe -c "python script.py"')
    assert r4["decision"] == "allow", f"Failed S4: {r4}"
    assert r4["sanitized_command"] == "python script.py", f"Failed S4 sanitized: {r4}"

    # Scenario 5: Nested cmd /c and powershell -c
    r5 = sanitize_command('cmd /c powershell -c "python script.py"')
    assert r5["decision"] == "allow", f"Failed S5: {r5}"
    assert r5["sanitized_command"] == "python script.py", f"Failed S5 sanitized: {r5}"

    # Scenario 6: Builtin command wrapper
    r6 = sanitize_command("builtin command nohup python script.py")
    assert r6["decision"] == "allow", f"Failed S6: {r6}"
    assert r6["sanitized_command"] == "python script.py", f"Failed S6 sanitized: {r6}"

    # --- Group 2: Comprehensive Destructive Blacklist (All 9 items) ---
    # Scenario 7: rm -rf
    r7 = sanitize_command("rm -rf /")
    assert r7["decision"] == "deny" and "rm -rf" in r7["reason"], f"Failed S7: {r7}"

    # Scenario 8: Fork bomb :(){ :|:& };:
    r8 = sanitize_command(":(){ :|:& };:")
    assert r8["decision"] == "deny" and ":(){ :|:& };:" in r8["reason"], f"Failed S8: {r8}"

    # Scenario 9: mkfs disk formatting
    r9 = sanitize_command("mkfs.ext4 /dev/sdb1")
    assert r9["decision"] == "deny" and "mkfs" in r9["reason"], f"Failed S9: {r9}"

    # Scenario 10: dd if= raw disk write
    r10 = sanitize_command("dd if=/dev/zero of=/dev/sda")
    assert r10["decision"] == "deny" and "dd if=" in r10["reason"], f"Failed S10: {r10}"

    # Scenario 11: > /dev/ device overwrite
    r11 = sanitize_command("> /dev/sda")
    assert r11["decision"] == "deny" and "> /dev/" in r11["reason"], f"Failed S11: {r11}"

    # Scenario 12: chmod -R 777 permissions wipe
    r12 = sanitize_command("chmod -R 777 /var/www")
    assert r12["decision"] == "deny" and "chmod -R 777" in r12["reason"], f"Failed S12: {r12}"

    # Scenario 13: del /f /s /q CMD file wipe
    r13 = sanitize_command("del /f /s /q C:\\Windows")
    assert r13["decision"] == "deny" and "del /f /s /q" in r13["reason"], f"Failed S13: {r13}"

    # Scenario 14: del with permuted flags (del /s /q /f)
    r14 = sanitize_command("del /s /q /f C:\\Users\\Public")
    assert r14["decision"] == "deny" and "del /f /s /q" in r14["reason"], f"Failed S14: {r14}"

    # Scenario 15: Format-Volume cmdlet
    r15 = sanitize_command("Format-Volume -DriveLetter D")
    assert r15["decision"] == "deny" and "format-volume" in r15["reason"].lower(), f"Failed S15: {r15}"

    # Scenario 16: Remove-Item -Recurse -Force C:\
    r16 = sanitize_command("Remove-Item -Recurse -Force C:\\")
    assert r16["decision"] == "deny" and "remove-item -recurse -force c:\\" in r16["reason"].lower(), f"Failed S16: {r16}"

    # Scenario 17: Remove-Item with inverted flags
    r17 = sanitize_command("Remove-Item -Force -Recurse C:\\")
    assert r17["decision"] == "deny" and "remove-item -recurse -force c:\\" in r17["reason"].lower(), f"Failed S17: {r17}"

    # --- Group 3: POSIX shlex Engine Operators (&&, ||, ;, |, &, \n) ---
    # Scenario 18: Operator &&
    r18 = sanitize_command("echo hello && dir")
    assert r18["decision"] == "deny" and "&&" in r18["reason"], f"Failed S18: {r18}"

    # Scenario 19: Operator ||
    r19 = sanitize_command("echo hello || whoami")
    assert r19["decision"] == "deny" and "||" in r19["reason"], f"Failed S19: {r19}"

    # Scenario 20: Operator ;
    r20 = sanitize_command("echo hello; dir")
    assert r20["decision"] == "deny" and ";" in r20["reason"], f"Failed S20: {r20}"

    # Scenario 21: Operator |
    r21 = sanitize_command("echo hello | more")
    assert r21["decision"] == "deny" and "|" in r21["reason"], f"Failed S21: {r21}"

    # Scenario 22: Operator & (chained or background)
    r22 = sanitize_command("echo hello & calc")
    assert r22["decision"] == "deny" and "&" in r22["reason"], f"Failed S22: {r22}"

    r22b = sanitize_command("python script.py &")
    assert r22b["decision"] == "deny" and "&" in r22b["reason"], f"Failed S22b: {r22b}"

    # Scenario 23: Newline command chaining \n
    r23 = sanitize_command("echo hello\ndir")
    assert r23["decision"] == "deny" and "newline" in r23["reason"].lower(), f"Failed S23: {r23}"

    # --- Group 4: Command Substitution ($(..), `..`) ---
    # Scenario 24: Subshell $(...)
    r24 = sanitize_command("echo $(whoami)")
    assert r24["decision"] == "deny" and "$(" in r24["reason"], f"Failed S24: {r24}"

    # Scenario 25: Backticks `...`
    r25 = sanitize_command("echo `whoami`")
    assert r25["decision"] == "deny" and "`" in r25["reason"], f"Failed S25: {r25}"

    # --- Group 5: PowerShell De-obfuscator (-enc, -encodedcommand, -e, -ec) ---
    # Scenario 26: PowerShell -enc with safe command
    r26 = sanitize_command(f"powershell -enc {ps_b64('dir')}")
    assert r26["decision"] == "allow", f"Failed S26: {r26}"
    assert r26["sanitized_command"] == "dir", f"Failed S26 sanitized: {r26}"

    # Scenario 27: PowerShell.exe -encodedcommand with safe command
    r27 = sanitize_command(f"powershell.exe -encodedcommand {ps_b64('python test.py')}")
    assert r27["decision"] == "allow", f"Failed S27: {r27}"
    assert r27["sanitized_command"] == "python test.py", f"Failed S27 sanitized: {r27}"

    # Scenario 28: PowerShell -e flag
    r28 = sanitize_command(f"powershell -e {ps_b64('dir')}")
    assert r28["decision"] == "allow", f"Failed S28: {r28}"
    assert r28["sanitized_command"] == "dir", f"Failed S28 sanitized: {r28}"

    # Scenario 29: PowerShell -ec flag
    r29 = sanitize_command(f"powershell -ec {ps_b64('dir')}")
    assert r29["decision"] == "allow", f"Failed S29: {r29}"
    assert r29["sanitized_command"] == "dir", f"Failed S29 sanitized: {r29}"

    # Scenario 30: PowerShell -enc with destructive payload (rm -rf)
    r30 = sanitize_command(f"powershell -enc {ps_b64('rm -rf /')}")
    assert r30["decision"] == "deny" and "rm -rf" in r30["reason"], f"Failed S30: {r30}"

    # Scenario 31: PowerShell -ec with Format-Volume payload
    r31 = sanitize_command(f"powershell -ec {ps_b64('Format-Volume -DriveLetter C')}")
    assert r31["decision"] == "deny" and "format-volume" in r31["reason"].lower(), f"Failed S31: {r31}"

    # Scenario 32: PowerShell -encodedcommand with Remove-Item C:\
    b64_ri_target = ps_b64("Remove-Item -Recurse -Force C:\\")
    r32 = sanitize_command(f"powershell -encodedcommand {b64_ri_target}")
    assert r32["decision"] == "deny" and "remove-item -recurse -force c:\\" in r32["reason"].lower(), f"Failed S32: {r32}"

    # Scenario 33: PowerShell -enc with chained command payload (dir && whoami)
    r33 = sanitize_command(f"powershell -enc {ps_b64('dir && whoami')}")
    assert r33["decision"] == "deny" and "&&" in r33["reason"], f"Failed S33: {r33}"

    # Scenario 34: PowerShell -enc with corrupt/invalid Base64
    r34 = sanitize_command("powershell -enc Invalid!!Base64@@")
    assert r34["decision"] == "deny" and "base64" in r34["reason"].lower(), f"Failed S34: {r34}"

    # --- Group 6: I/O Redirection Guard (> and >> system files) ---
    # Scenario 35: Overwriting Linux /etc/passwd
    r35 = sanitize_command("echo bad > /etc/passwd")
    assert r35["decision"] == "deny" and "redirection" in r35["reason"].lower(), f"Failed S35: {r35}"

    # Scenario 36: Appending to Windows hosts file
    r36 = sanitize_command("echo evil >> C:\\Windows\\System32\\drivers\\etc\\hosts")
    assert r36["decision"] == "deny" and "redirection" in r36["reason"].lower(), f"Failed S36: {r36}"

    # Scenario 37: Overwriting raw disk device node
    r37 = sanitize_command("cat image.iso > /dev/sda")
    assert r37["decision"] == "deny", f"Failed S37: {r37}"

    # Scenario 38: Benign redirection to local project file (Allowed)
    r38 = sanitize_command("echo hello > build_output.log")
    assert r38["decision"] == "allow", f"Failed S38: {r38}"

    # --- Group 7: Safe Quoted Characters & Legitimate Development Commands ---
    # Scenario 39: Semicolon inside quotes (Python -c one-liner)
    r39 = sanitize_command('python -c "import sys; print(sys.version)"')
    assert r39["decision"] == "allow", f"Failed S39: {r39}"

    # Scenario 40: Ampersand inside quoted Git commit message
    r40 = sanitize_command('git commit -m "fix: login & signup logic"')
    assert r40["decision"] == "allow", f"Failed S40: {r40}"

    # Scenario 41: Greater-than operator inside Python quote
    r41 = sanitize_command('python -c "if 10 > 5: print(\'yes\')"')
    assert r41["decision"] == "allow", f"Failed S41: {r41}"

    # Scenario 42: Standard pytest test run
    r42 = sanitize_command("python -m pytest tests/")
    assert r42["decision"] == "allow", f"Failed S42: {r42}"

    # Scenario 43: Unclosed quote syntax error handling
    r43 = sanitize_command('echo "unclosed quote')
    assert r43["decision"] == "deny" and "unclosed" in r43["reason"].lower(), f"Failed S43: {r43}"

    # Scenario 44: Deeply wrapped destructive command
    r44 = sanitize_command('sudo cmd.exe /c "powershell -c \\"del /f /s /q C:\\\\\\""')
    assert r44["decision"] == "deny", f"Failed S44: {r44}"

    # --- Group 8: PreToolUse Payload Evaluation ---
    # Scenario 45: Payload allow
    p_allow = {"toolCall": {"name": "run_command", "args": {"CommandLine": "python -m pytest"}}}
    assert evaluate_payload(p_allow)["decision"] == "allow", "Failed S45"

    # Scenario 46: Payload deny
    p_deny = {"toolCall": {"name": "run_command", "args": {"CommandLine": "rm -rf /"}}}
    assert evaluate_payload(p_deny)["decision"] == "deny", "Failed S46"

    # Scenario 47: Non-run_command toolCall bypass
    p_bypass = {"toolCall": {"name": "view_file", "args": {"AbsolutePath": "foo.py"}}}
    assert evaluate_payload(p_bypass)["decision"] == "allow", "Failed S47"

    # --- Group 9: Hardening & Gap Analysis Fixes (Scenarios 48-78) ---
    # Vulnerability 1: Fullwidth and Extended Unicode Whitespace Blacklist Matching
    # Scenario 48: Fullwidth characters in blacklist (rm -rf)
    r48 = sanitize_command("ｒｍ　－ｒｆ　／")
    assert r48["decision"] == "deny" and "rm -rf" in r48["reason"], f"Failed S48: {r48}"

    # Scenario 49: Extended Unicode whitespace (Ideographic space \u3000 and NBSP \u00a0)
    r49 = sanitize_command("rm\u3000-rf\u00a0/")
    assert r49["decision"] == "deny" and "rm -rf" in r49["reason"], f"Failed S49: {r49}"

    # Scenario 50: Fullwidth Format-Volume
    r50 = sanitize_command("Ｆｏｒｍａｔ－Ｖｏｌｕｍｅ -DriveLetter C")
    assert r50["decision"] == "deny" and "format-volume" in r50["reason"].lower(), f"Failed S50: {r50}"

    # Vulnerability 2: Zero-Width & Homoglyph Obfuscation
    # Scenario 51: Zero-width space inserted in blacklist keyword
    r51 = sanitize_command("r\u200bm\u200c -rf /")
    assert r51["decision"] == "deny" and "rm -rf" in r51["reason"], f"Failed S51: {r51}"

    # Scenario 52: Cyrillic homoglyph in rm -rf (Cyrillic 'м' \u043c)
    r52 = sanitize_command("r\u043c -rf /")
    assert r52["decision"] == "deny" and "rm -rf" in r52["reason"], f"Failed S52: {r52}"

    # Scenario 53: Homoglyph in Remove-Item
    r53 = sanitize_command("Rеmovе-Itеm -Recurse -Force C:\\")
    assert r53["decision"] == "deny", f"Failed S53: {r53}"

    # Scenario 54: Zero-width characters inside chaining token
    r54 = sanitize_command("echo a &\u200b& echo b")
    assert r54["decision"] == "deny" and "&&" in r54["reason"], f"Failed S54: {r54}"

    # Vulnerability 3: Unicode Dash Variants in PowerShell & Command Switches
    # Scenario 55: En Dash (\u2013) in powershell –enc
    r55 = sanitize_command(f"powershell \u2013enc {ps_b64('rm -rf /')}")
    assert r55["decision"] == "deny" and "rm -rf" in r55["reason"], f"Failed S55: {r55}"

    # Scenario 56: Em Dash (\u2014) in powershell —encodedcommand
    r56 = sanitize_command(f"powershell.exe \u2014encodedcommand {ps_b64('dir')}")
    assert r56["decision"] == "allow" and r56["sanitized_command"] == "dir", f"Failed S56: {r56}"

    # Scenario 57: Horizontal Bar (\u2015) in powershell ―e
    r57 = sanitize_command(f"powershell \u2015e {ps_b64('whoami')}")
    assert r57["decision"] == "allow" and r57["sanitized_command"] == "whoami", f"Failed S57: {r57}"

    # Scenario 58: Minus Sign (\u2212) in powershell −ec
    r58 = sanitize_command(f"pwsh \u2212ec {ps_b64('rm -rf /')}")
    assert r58["decision"] == "deny" and "rm -rf" in r58["reason"], f"Failed S58: {r58}"

    # Scenario 59: Fullwidth Hyphen-Minus (\uff0d) in powershell －c
    r59 = sanitize_command("powershell.exe \uff0dc 'dir'")
    assert r59["decision"] == "allow" and r59["sanitized_command"] == "dir", f"Failed S59: {r59}"

    # Vulnerability 4: Multi-Layer Encoding & Nested Base64
    # Scenario 60: Nested Base64 in PowerShell payload
    inner_ps = f"powershell -enc {ps_b64('rm -rf /')}"
    outer_b64 = ps_b64(inner_ps)
    r60 = sanitize_command(f"powershell -enc {outer_b64}")
    assert r60["decision"] == "deny" and "rm -rf" in r60["reason"], f"Failed S60: {r60}"

    # Scenario 61: Double Base64 raw encoding
    raw_b64_1 = base64.b64encode(b"rm -rf /").decode("ascii")
    raw_b64_2 = base64.b64encode(raw_b64_1.encode("utf-16le")).decode("ascii")
    r61 = sanitize_command(f"powershell -enc {raw_b64_2}")
    assert r61["decision"] == "deny" and "rm -rf" in r61["reason"], f"Failed S61: {r61}"

    # Scenario 62: Percent-encoded Base64 string
    clean_b64_payload = ps_b64("Format-Volume -DriveLetter C")
    percent_b64 = urllib.parse.quote(clean_b64_payload)
    r62 = sanitize_command(f"powershell -enc {percent_b64}")
    assert r62["decision"] == "deny" and "format-volume" in r62["reason"].lower(), f"Failed S62: {r62}"

    # Vulnerability 5: Unicode Newlines and Fullwidth Chaining Operators
    # Scenario 63: Next Line (NEL \u0085) chaining
    r63 = sanitize_command("echo hello\u0085rm -rf /")
    assert r63["decision"] == "deny" and "newline" in r63["reason"].lower(), f"Failed S63: {r63}"

    # Scenario 64: Line Separator (LS \u2028) chaining
    r64 = sanitize_command("echo hello\u2028dir")
    assert r64["decision"] == "deny" and "newline" in r64["reason"].lower(), f"Failed S64: {r64}"

    # Scenario 65: Paragraph Separator (PS \u2029) chaining
    r65 = sanitize_command("echo hello\u2029whoami")
    assert r65["decision"] == "deny" and "newline" in r65["reason"].lower(), f"Failed S65: {r65}"

    # Scenario 66: Fullwidth Ampersands (＆＆ \uff06\uff06)
    r66 = sanitize_command("echo a ＆＆ rm -rf /")
    assert r66["decision"] == "deny", f"Failed S66: {r66}"

    # Scenario 67: Fullwidth Vertical Bars (｜｜ \uff5c\uff5c)
    r67 = sanitize_command("echo a ｜｜ dir")
    assert r67["decision"] == "deny", f"Failed S67: {r67}"

    # Scenario 68: Fullwidth Semicolon (； \uff1b)
    r68 = sanitize_command("echo a ； rm -rf /")
    assert r68["decision"] == "deny", f"Failed S68: {r68}"

    # Vulnerability 6: I/O Redirection Normalization (Fullwidth operators & Path Homoglyphs)
    # Scenario 69: Fullwidth Greater-Than (＞ \uff1e) overwriting /etc/passwd
    r69 = sanitize_command("echo evil ＞ /etc/passwd")
    assert r69["decision"] == "deny" and "redirection" in r69["reason"].lower(), f"Failed S69: {r69}"

    # Scenario 70: Fullwidth Append Operator (＞＞ \uff1e\uff1e) to Windows hosts
    r70 = sanitize_command("echo evil ＞＞ C:\\Windows\\System32\\drivers\\etc\\hosts")
    assert r70["decision"] == "deny" and "redirection" in r70["reason"].lower(), f"Failed S70: {r70}"

    # Scenario 71: Small Greater-Than (﹥ \ufe65) overwriting system target
    r71 = sanitize_command("echo bad ﹥ /dev/sda")
    assert r71["decision"] == "deny", f"Failed S71: {r71}"

    # Scenario 72: Drive letter homoglyph (Cyrillic 'с' \u0441 in C:\Windows)
    r72 = sanitize_command("echo bad > \u0441:\\windows\\system32\\calc.exe")
    assert r72["decision"] == "deny" and "redirection" in r72["reason"].lower(), f"Failed S72: {r72}"

    # Scenario 73: Safe redirection with legitimate fullwidth quote content inside single quotes
    r73 = sanitize_command("echo 'fullwidth content: ＞ test' > output.log")
    assert r73["decision"] == "allow", f"Failed S73: {r73}"

    # Vulnerability 7: Percent-Encoding and Hex Escape Sequences
    # Scenario 74: Percent-encoded destructive command
    r74 = sanitize_command("rm%20-rf%20/")
    assert r74["decision"] == "deny" and "rm -rf" in r74["reason"], f"Failed S74: {r74}"

    # Scenario 75: Double percent-encoded chaining operator (%2526%2526)
    r75 = sanitize_command("echo%20a%20%2526%2526%20dir")
    assert r75["decision"] == "deny", f"Failed S75: {r75}"

    # Scenario 76: Hex escape sequence (\\x26\\x26 for &&)
    r76 = sanitize_command("echo a \\x26\\x26 dir")
    assert r76["decision"] == "deny" and "&&" in r76["reason"], f"Failed S76: {r76}"

    # Scenario 77: Hex escaped newline (\\x0a)
    r77 = sanitize_command("echo a\\x0adir")
    assert r77["decision"] == "deny" and "newline" in r77["reason"].lower(), f"Failed S77: {r77}"

    # Scenario 78: Percent-encoded newline (%0A) chaining
    r78 = sanitize_command("echo a%0Adir")
    assert r78["decision"] == "deny" and "newline" in r78["reason"].lower(), f"Failed S78: {r78}"

    # --- Group 10: Vector 2 Windows Filesystem Protection (Scenarios 79-88) ---
    # Scenario 79: mklink /D symlink creation
    r79 = sanitize_command("mklink /D mylink target")
    assert r79["decision"] == "deny" and "mklink" in r79["reason"].lower(), f"Failed S79: {r79}"

    # Scenario 80: mklink /J junction creation
    r80 = sanitize_command("mklink /J C:\\junction C:\\target")
    assert r80["decision"] == "deny" and "mklink" in r80["reason"].lower(), f"Failed S80: {r80}"

    # Scenario 81: PowerShell New-Item SymbolicLink
    r81 = sanitize_command("New-Item -ItemType SymbolicLink -Path link -Target target")
    assert r81["decision"] == "deny", f"Failed S81: {r81}"

    # Scenario 82: fsutil hardlink create
    r82 = sanitize_command("fsutil hardlink create newfile existingfile")
    assert r82["decision"] == "deny" and "fsutil" in r82["reason"].lower(), f"Failed S82: {r82}"

    # Scenario 83: Sysinternals junction
    r83 = sanitize_command("junction C:\\junc C:\\target")
    assert r83["decision"] == "deny" and "junction" in r83["reason"].lower(), f"Failed S83: {r83}"

    # Scenario 84: Redirection to NTFS Alternate Data Stream (ADS)
    r84 = sanitize_command("echo payload > test.txt:hidden")
    assert r84["decision"] == "deny" and "alternate data stream" in r84["reason"].lower(), f"Failed S84: {r84}"

    # Scenario 85: Redirection to Windows DOS reserved device
    r85 = sanitize_command("echo payload > NUL")
    assert r85["decision"] == "deny" and "reserved device" in r85["reason"].lower(), f"Failed S85: {r85}"

    # Scenario 86: CMD flag permutation unwrapping (/q /d /c)
    r86 = sanitize_command('cmd.exe /q /d /c "del /f /s /q C:\\"')
    assert r86["decision"] == "deny", f"Failed S86: {r86}"

    # Scenario 87: PowerShell -c: command colon unwrapping
    r87 = sanitize_command('powershell -c:"del /f /s /q C:\\"')
    assert r87["decision"] == "deny", f"Failed S87: {r87}"

    # Scenario 88: Bash wrapper unwrapping (bash -c "rm -rf /")
    r88 = sanitize_command('bash -c "rm -rf /"')
    assert r88["decision"] == "deny", f"Failed S88: {r88}"

    # --- Group 11: Vector 1 PowerShell Escape False Positive & ScriptBlock Hotfix (Scenarios 89-93) ---
    # Scenario 89: PowerShell `" escaping quotes allowed
    r89 = sanitize_command('Write-Host "Hello `"World`""')
    assert r89["decision"] == "allow", f"Failed S89: {r89}"

    # Scenario 90: PowerShell `n / `r newline escapes allowed
    r90 = sanitize_command('Write-Host "Line1`nLine2"')
    assert r90["decision"] == "allow", f"Failed S90: {r90}"

    # Scenario 91: PowerShell `$ dollar escape allowed
    r91 = sanitize_command('Write-Host "Total: `$100 USD"')
    assert r91["decision"] == "allow", f"Failed S91: {r91}"

    # Scenario 92: Destructive ScriptBlock with alias expansion blocked
    r92 = sanitize_command("{icm { Remove-Item -Recurse -Force C:\\ }}")
    assert r92["decision"] == "deny", f"Failed S92: {r92}"

    # Scenario 93: Short 2-char POSIX backtick command substitution blocked
    r93 = sanitize_command("echo `id`")
    assert r93["decision"] == "deny" and "command substitution" in r93["reason"].lower(), f"Failed S93: {r93}"

    print("[SELF-TEST] ALL 93 AST SHELL SANITIZER SCENARIOS PASSED (100% OK)")
    return True


def main() -> None:
    if "--self-test" in sys.argv:
        success = run_self_test()
        sys.exit(0 if success else 1)

    try:
        MAX_STDIN_BYTES = 10 * 1024 * 1024
        raw = sys.stdin.read(MAX_STDIN_BYTES + 1)
        if not raw or not raw.strip():
            sys.stdout.write(json.dumps({"decision": "allow", "verdict": "ALLOW"}) + "\n")
            sys.exit(0)
        if len(raw) > MAX_STDIN_BYTES:
            sys.stdout.write(json.dumps({"decision": "deny", "verdict": "DENY", "reason": f"Payload exceeds maximum limit of {MAX_STDIN_BYTES} bytes."}) + "\n")
            sys.exit(0)
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            sys.stdout.write(json.dumps({"decision": "allow", "verdict": "ALLOW"}) + "\n")
            sys.exit(0)
    except Exception as exc:
        sys.stdout.write(json.dumps({"decision": "deny", "verdict": "DENY", "reason": f"Malformed JSON input: {exc}"}) + "\n")
        sys.exit(0)

    result = evaluate_payload(payload)
    sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    sys.exit(0)


if __name__ == "__main__":
    main()

