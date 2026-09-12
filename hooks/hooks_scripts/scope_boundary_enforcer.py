#!/usr/bin/env python3
"""Scope Boundary Enforcer Hook (PreToolUse) for Enterprise Multi-Agent Governance System.

Enforces:
1. Workspace boundary security & path traversal defense (§7) with os.path.realpath() resolution.
2. Layout compliance (§15, §29): Prohibits creating/modifying source code or non-metadata files
   inside .agents/ or configured metadata directories.
3. Zero-hardcoding architecture: Dynamically loads configuration and thresholds from
   hook_utils.config_loader (and GovernanceConfig) with robust Zero-Config Resilience fallbacks.
4. NTFS Trailing Dot/Space Evasion Defense: Strips trailing dots and spaces from path components
   before extension extraction and permission verification.
5. NTFS Alternate Data Streams (ADS) Defense: Blocks streams containing ':' outside valid drive letters.
6. Windows filesystem defense: Rejects forbidden characters (* ? " < > | and control chars) and
   normalizes UNC/device prefixes (\\\\?\\, \\\\.\\).
7. Agent Chính / Root Session Role Boundary Enforcement: Top-Level Agent is strictly forbidden
   from modifying or creating source code (.py, .js, .ts...), including via terminal command
   shell redirection (run_command).
8. Comprehensive in-process --self-test suite with 34 empirical security scenarios.
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
    has_ntfs_ads,
    is_hardlink,
    is_reparse_point,
    is_reserved_device_name,
    log_diagnostic,
    pre_tool_response,
    read_stdin_payload,
    strip_unc_prefix,
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

# Unicode invisible, zero-width, and directional control characters
ZERO_WIDTH_AND_BIDI_CHARS: frozenset[str] = frozenset({
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space (BOM)
    "\u2060",  # Word joiner
    "\u2061",  # Function application
    "\u2062",  # Invisible times
    "\u2063",  # Invisible separator
    "\u2064",  # Invisible plus
    "\u00ad",  # Soft hyphen
    "\u034f",  # Combining grapheme joiner
    "\u180e",  # Mongolian vowel separator
    "\u200e",  # Left-to-Right Mark (LRM)
    "\u200f",  # Right-to-Right Mark (RLM)
    "\u202a",  # Left-to-Right Embedding (LRE)
    "\u202b",  # Right-to-Right Embedding (RLE)
    "\u202c",  # Pop Directional Formatting (PDF)
    "\u202d",  # Left-to-Right Override (LRO)
    "\u202e",  # Right-to-Right Override (RLO)
    "\u2066",  # Left-to-Right Isolate (LRI)
    "\u2067",  # Right-to-Right Isolate (RLI)
    "\u2068",  # First Strong Isolate (FSI)
    "\u2069",  # Pop Directional Isolate (PDI)
})

# Cross-script homoglyphs mapping (Cyrillic, Greek, lookalikes -> lowercase ASCII Latin)
HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic lowercase & uppercase lookalikes
    "\u0430": "a", "\u0410": "a",  # а, А
    "\u0432": "b", "\u0412": "b",  # в, В
    "\u0441": "c", "\u0421": "c",  # с, С
    "\u0501": "d", "\u0500": "d",  # ԁ, Ԁ
    "\u0435": "e", "\u0415": "e",  # е, Е
    "\u04bb": "h", "\u04ba": "h",  # һ, Һ
    "\u0456": "i", "\u0406": "i",  # і, І
    "\u0458": "j", "\u0408": "j",  # ј, Ј
    "\u043a": "k", "\u041a": "k",  # к, К
    "\u0513": "l",                 # ԓ
    "\u043c": "m", "\u041c": "m",  # м, М
    "\u043d": "n", "\u041d": "n",  # н, Н
    "\u043e": "o", "\u041e": "o",  # о, О
    "\u0440": "p", "\u0420": "p",  # р, Р
    "\u051b": "q", "\u051a": "q",  # ԛ, Ԛ
    "\u0455": "s", "\u0405": "s",  # ѕ, Ѕ
    "\u0442": "t", "\u0422": "t",  # т, Т
    "\u0443": "y", "\u0423": "y",  # у, У
    "\u0445": "x", "\u0425": "x",  # х, Х
    "\u051d": "w", "\u051c": "w",  # ԝ, Ԝ
    "\u0433": "r",                 # г
    # Greek lowercase & uppercase lookalikes
    "\u03b1": "a", "\u0391": "a",  # α, Α
    "\u03b2": "b", "\u0392": "b",  # β, Β
    "\u03b3": "y",                 # γ
    "\u03b5": "e", "\u0395": "e",  # ε, Ε
    "\u03b6": "z", "\u0396": "z",  # ζ, Ζ
    "\u03b7": "n", "\u0397": "h",  # η, Η
    "\u03b9": "i", "\u0399": "i",  # ι, Ι
    "\u03ba": "k", "\u039a": "k",  # κ, Κ
    "\u03bd": "v", "\u039d": "n",  # ν, Ν
    "\u03bf": "o", "\u039f": "o",  # ο, Ο
    "\u03c1": "p", "\u03a1": "p",  # ρ, Ρ
    "\u03c2": "s", "\u03c3": "s", "\u03a3": "s",  # ς, σ, Σ
    "\u03c4": "t", "\u03a4": "t",  # τ, Τ
    "\u03c5": "u", "\u03a5": "y",  # υ, Υ
    "\u03c7": "x", "\u03a7": "x",  # χ, Χ
    # Latin lookalikes & IPA
    "\u0261": "g",  # ɡ
    "\u0131": "i",  # ı
    "\u0237": "j",  # ȷ
}
HOMOGLYPH_TRANSLATION_TABLE = str.maketrans(HOMOGLYPH_MAP)

# Unicode Colons (ADS separator homoglyphs)
UNICODE_COLON_CHARS: tuple[str, ...] = (
    ":",        # Standard ASCII colon U+003A
    "\uff1a",   # Fullwidth Colon U+FF1A
    "\ufe55",   # Small Colon U+FE55
    "\u0589",   # Armenian Full Stop U+0589
    "\ua789",   # Modifier Letter Colon U+A789
    "\u2236",   # Ratio U+2236
    "\u05c3",   # Hebrew Punctuation Sof Pasuq U+05C3
)

# NTFS trailing characters to sanitize (dots and whitespace in ASCII and Unicode)
NTFS_TRAILING_DOTS: str = ".\uFF0E\u2024\uFE52\u00B7\u2027\u3002\u06D4"
NTFS_TRAILING_SPACES: str = " \t\r\n\u00A0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u202F\u205F\u3000\u200B"
NTFS_TRAILING_TRIM_CHARS: str = NTFS_TRAILING_DOTS + NTFS_TRAILING_SPACES

# Prohibited Windows path characters (excluding directory separators and drive colon)
# In NTFS, filenames cannot contain * ? " < > | or ASCII control characters 0x00-0x1F,
# plus zero-width characters, BiDi control characters, and fullwidth dangerous characters (* ? " < > |)
PROHIBITED_WIN_CHARS_PATTERN = (
    r'[*?"<>|\x00-\x1f'
    r'\u200b-\u200d\ufeff\u2060-\u2064\u00ad\u034f\u180e'
    r'\u200e\u200f\u202a-\u202e\u2066-\u2069'
    r'\uff0a\uff1f\uff02\uff1c\uff1e\uff5c]'
)
PROHIBITED_WIN_CHARS_REGEX = re.compile(PROHIBITED_WIN_CHARS_PATTERN)

# Regex for source code file extensions in shell command analysis
CODE_EXT_REGEX = r"\.(?:py|js|ts|jsx|tsx|java|go|rs|c|cpp|cs|php|rb|sh|ps1|bat|cmd|sql|kt|kts|swift|dart|lua|r|m|zig|nim|scala|ex|exs|erl|clj)\b"


def decode_multi_layer(text: str, max_passes: int = 5) -> str:
    """Recursively decode URL / percent-encoded and multi-layer encoded strings until fixed point."""
    if not text or not isinstance(text, str):
        return text
    current = text
    for _ in range(max_passes):
        try:
            unquoted = urllib.parse.unquote(current)
        except Exception:
            break
        if unquoted == current:
            break
        current = unquoted
    return current


def canonicalize_extension(ext: str) -> str:
    """Normalize and convert homoglyphs in a file extension to standard ASCII lowercase.

    Applies NFKC normalization (Fullwidth -> ASCII, e.g. ． -> ., ｐｙ -> py),
    strips zero-width/BiDi characters, translates cross-script homoglyphs
    (e.g., Cyrillic 'р' -> 'p', Greek 'ο' -> 'o'), and normalizes dots.
    """
    if not ext:
        return ""
    # 1. NFKC normalization decomposes compatibility forms (fullwidth, math alphanumerics)
    norm = unicodedata.normalize("NFKC", ext)
    norm = norm.replace("`", "").replace("^", "")
    # 2. Strip zero-width and invisible chars
    for ch in ZERO_WIDTH_AND_BIDI_CHARS:
        norm = norm.replace(ch, "")
    # 3. Translate cross-script homoglyphs (Cyrillic, Greek -> Latin)
    norm = norm.translate(HOMOGLYPH_TRANSLATION_TABLE)
    # 4. Standardize Unicode dots to ASCII dot
    for dot in NTFS_TRAILING_DOTS:
        if dot != ".":
            norm = norm.replace(dot, ".")
    # 5. Casefold for strict Unicode case-insensitive matching
    return norm.casefold()


def canonicalize_path_component(comp: str) -> str:
    """Normalize and convert homoglyphs, fullwidth, and zero-width chars in a path component."""
    if not comp:
        return ""
    norm = unicodedata.normalize("NFKC", comp)
    norm = norm.replace("`", "").replace("^", "")
    for ch in ZERO_WIDTH_AND_BIDI_CHARS:
        norm = norm.replace(ch, "")
    norm = norm.translate(HOMOGLYPH_TRANSLATION_TABLE)
    return norm.casefold()


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
        canonicalize_extension(ext if ext.startswith(".") else f".{ext}")
        for ext in rules.get("allowed_metadata_extensions", DEFAULT_ALLOWED_METADATA_EXTENSIONS)
    }
    prohibited_src = {
        canonicalize_extension(ext if ext.startswith(".") else f".{ext}")
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


def strip_unc_prefix(path_str: str) -> tuple[str, str]:
    """Strip or normalize Windows UNC / device prefixes (\\\\?\\, \\\\.\\, etc.).

    Returns: (clean_path, prefix_type)
    - \\\\?\\C:\\path -> C:\\path, 'DEVICE'
    - \\\\.\\C:\\path -> C:\\path, 'DEVICE'
    - \\\\?\\UNC\\server\\share\\path -> \\\\server\\share\\path, 'UNC'
    - \\\\.\\UNC\\server\\share\\path -> \\\\server\\share\\path, 'UNC'
    - \\\\?\\Volume{...}\\path -> path, 'VOLUME_GUID'
    """
    s = path_str
    # Normalize forward slashes in UNC prefix
    if s.startswith(("//?/", "//./")):
        s = "\\\\" + s[2:4] + "\\" + s[4:]
    elif s.startswith(("\\\\?/", "\\\\./")):
        s = s[:4].replace("/", "\\") + s[4:]

    if s.startswith(("\\\\?\\Volume{", "\\\\.\\Volume{")):
        return s[4:], "VOLUME_GUID"
    if s.startswith(("//?/Volume{", "//./Volume{")):
        return s[4:], "VOLUME_GUID"

    if s.startswith(("\\\\?\\UNC\\", "\\\\.\\UNC\\")):
        return "\\\\" + s[8:], "UNC"
    if s.startswith(("//?/UNC/", "//./UNC/")):
        return "//" + s[8:], "UNC"

    if s.startswith(("\\\\?\\", "\\\\.\\")):
        return s[4:], "DEVICE"

    return s, ""


def has_ntfs_ads(path_str: str) -> bool:
    """Detect if path contains NTFS Alternate Data Stream (ADS) separator (:).

    In Windows, ':' is strictly forbidden in file and directory names.
    The only valid appearance is at index 1 for a drive letter (e.g., C:).
    Any other ':' indicates an ADS stream (e.g., file.txt:hidden, file.py:$DATA)
    or invalid NTFS syntax.

    Hardened against:
    - Multi-layer percent-encoded colons (%3a, %253a).
    - Unicode colon homoglyphs: Fullwidth Colon (： \uFF1A), Small Colon (﹕ \uFE55),
      Armenian Full Stop (\u0589), Modifier Letter Colon (\uA789), Ratio (\u2236).
    - NFKC normalized compatibility colons.
    """
    decoded = decode_multi_layer(path_str)
    clean_path, _ = strip_unc_prefix(decoded)

    # If starts with drive letter e.g. C: or C：
    if (
        len(clean_path) >= 2
        and clean_path[0].isalpha()
        and (clean_path[1] in UNICODE_COLON_CHARS or clean_path[1] == ":")
    ):
        remainder = clean_path[2:]
    else:
        remainder = clean_path

    # Check for direct presence of any colon homoglyph in remainder
    if any(c in remainder for c in UNICODE_COLON_CHARS):
        return True

    # Check NFKC-normalized remainder for standard ASCII colon
    norm_remainder = unicodedata.normalize("NFKC", remainder)
    return ":" in norm_remainder


def has_windows_forbidden_chars(path_str: str) -> tuple[bool, str]:
    """Check for forbidden Windows path characters (* ? \" < > | and control chars).

    UNC prefix is stripped first so valid \\\\?\\ device prefix is not flagged.

    Hardened against:
    - Zero-width characters (\u200B..\u200D, \uFEFF, \u2060..\u2064, \u00AD, \u034F, \u180E)
    - BiDi / directional override characters (\u202E, \u200E, \u200F, \u202A..\u202D, \u2066..\u2069)
    - Fullwidth forbidden characters (＊ ？ ＂ ＜ ＞ ｜)
    - Multi-layer percent-encoded representations (%2a, %252a, etc.)
    """
    decoded = decode_multi_layer(path_str)
    clean_path, _ = strip_unc_prefix(decoded)
    m = PROHIBITED_WIN_CHARS_REGEX.search(clean_path)
    if m:
        char = m.group(0)
        code = ord(char)
        char_repr = f"U+{code:04X}" if code > 127 else (f"0x{code:02x}" if code < 32 else repr(char))
        return True, char_repr
    return False, ""


def sanitize_ntfs_trailing_dots_and_spaces(path_str: str) -> tuple[str | None, bool]:
    """Strip trailing dots and whitespace from each component of a path.

    On Windows NTFS, filenames and directory names cannot end with dots or spaces;
    Win32 automatically truncates them (e.g. 'main.py.' or 'main.py ' becomes 'main.py').
    Attackers use this to evade extension and permission checks.

    Hardened against:
    - Multi-layer / percent-encoding (%20, %2e, %252e...).
    - Non-ASCII whitespace (\u00A0, \u2002, \u3000, etc.).
    - Unicode dots (Fullwidth Full Stop ． \uFF0E, One-Dot Leader ․ \u2024, etc.).
    - Fullwidth path separators (／ \uFF0F, ＼ \uFF3C).

    Returns: (sanitized_path, was_modified) or (None, False) if path becomes invalid.
    """
    decoded = decode_multi_layer(path_str)
    s = decoded.strip()
    if not s:
        return s, False

    clean_unc, unc_type = strip_unc_prefix(s)

    # Normalize fullwidth slashes in path body
    clean_unc = clean_unc.replace("\uff0f", "/").replace("\uff3c", "\\")

    # Preserve drive if present e.g. C: or C：
    drive = ""
    if (
        len(clean_unc) >= 2
        and clean_unc[0].isalpha()
        and (clean_unc[1] in UNICODE_COLON_CHARS or clean_unc[1] == ":")
    ):
        drive = clean_unc[0] + ":"
        rest = clean_unc[2:]
    else:
        rest = clean_unc

    # Preserve leading separator
    leading_sep = ""
    if rest.startswith(("\\\\", "//")):
        leading_sep = "\\\\"
        rest = rest[2:]
    elif rest.startswith(("\\", "/")):
        leading_sep = "\\"
        rest = rest[1:]

    # Split path components by / or \
    components = re.split(r"[\\/]+", rest)
    cleaned_components = []
    modified = (decoded != path_str)

    for comp in components:
        if comp in ("", ".", ".."):
            cleaned_components.append(comp)
        else:
            # Strip both ASCII and Unicode trailing dots & spaces
            cleaned = comp.rstrip(NTFS_TRAILING_TRIM_CHARS)
            if not cleaned:
                # Component consisted only of dots and spaces (e.g. "...", " . .", "\uff0e\uff0e\uff0e", "\u00a0\u2024"), which is illegal on Windows
                return None, False
            # Normalize fullwidth dots inside component (e.g. main．py -> main.py)
            for dot in NTFS_TRAILING_DOTS:
                if dot != ".":
                    cleaned = cleaned.replace(dot, ".")
            if cleaned != comp:
                modified = True
            cleaned_components.append(cleaned)

    sep = "\\" if "\\" in path_str or os.name == "nt" else "/"
    rebuilt = drive + leading_sep + sep.join(cleaned_components)

    if unc_type == "DEVICE":
        rebuilt = "\\\\?\\" + rebuilt
    elif unc_type == "UNC":
        rebuilt = "\\\\?\\UNC\\" + rebuilt.lstrip("\\/")

    return rebuilt, (modified or (rebuilt != path_str))


def extract_target_path_from_args(args: dict[str, Any], target_keys: list[str]) -> str | None:
    """Extract raw target file path from tool arguments dictionary across known parameter keys.

    Automatically handles multi-layer URL/percent-encoding (%252e -> .) and shell escape stripping.
    """
    if not isinstance(args, dict):
        return None

    # Check designated keys first
    for key in target_keys:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            clean = decode_multi_layer(val.strip())
            return clean.replace("`", "").replace("^", "")

    # Fallback search over any arg containing 'file' or 'path' in key name
    for k, v in args.items():
        if isinstance(k, str) and ("target" in k.lower() or "file" in k.lower() or "path" in k.lower()):
            if isinstance(v, str) and v.strip():
                clean = decode_multi_layer(v.strip())
                return clean.replace("`", "").replace("^", "")

    return None


def resolve_target_path(target_str: str, workspace_roots: list[pathlib.Path]) -> pathlib.Path | None:
    """Safely resolve target file path against workspace root, defeating traversal and CWD drift.

    Uses os.path.realpath() and strips UNC device prefixes for deterministic resolution.
    Returns None if the path contains null bytes, invalid control characters, or is malformed.
    """
    if "\0" in target_str:
        log_diagnostic("Detected embedded null byte in target path.")
        return None

    try:
        clean_path, p_type = strip_unc_prefix(target_str)
        if p_type == "VOLUME_GUID":
            log_diagnostic("Volume GUID paths are not permitted in workspace resolution.")
            return None

        if os.path.isabs(clean_path):
            real = os.path.realpath(clean_path)
            clean_real, _ = strip_unc_prefix(real)
            return pathlib.Path(clean_real)

        # Relative path: Check all workspace roots to handle Multi-Workspace Drift
        if workspace_roots:
            for root in workspace_roots:
                root_str, _ = strip_unc_prefix(str(root.resolve()))
                candidate = os.path.join(root_str, clean_path)
                if os.path.exists(candidate) or os.path.exists(os.path.dirname(candidate)):
                    real = os.path.realpath(candidate)
                    clean_real, _ = strip_unc_prefix(real)
                    return pathlib.Path(clean_real)

            # Fallback anchor to primary workspace root
            primary_root_str, _ = strip_unc_prefix(str(workspace_roots[0].resolve()))
            full_path = os.path.join(primary_root_str, clean_path)
            real = os.path.realpath(full_path)
            clean_real, _ = strip_unc_prefix(real)
            return pathlib.Path(clean_real)

        # Standalone fallback to cwd
        full_path = os.path.join(os.getcwd(), clean_path)
        real = os.path.realpath(full_path)
        clean_real, _ = strip_unc_prefix(real)
        return pathlib.Path(clean_real)
    except (OSError, ValueError) as exc:
        log_diagnostic(f"Path resolution error for '{target_str}': {exc}")
        return None


def is_path_within_workspace(target_path: pathlib.Path, workspace_roots: list[pathlib.Path]) -> bool:
    """Verify target path is strictly located within any of authorized workspace roots.

    Fully immune to Windows case discrepancies (e.g., C:\\ vs c:\\), symlinks,
    path traversal, UNC device prefixes, and prefix collision attacks.
    """
    try:
        target_real = os.path.realpath(str(target_path))
        target_clean, _ = strip_unc_prefix(target_real)
        target_norm = os.path.normcase(os.path.normpath(target_clean))

        for root in workspace_roots:
            root_real = os.path.realpath(str(root))
            root_clean, _ = strip_unc_prefix(root_real)
            root_norm = os.path.normcase(os.path.normpath(root_clean))

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
    Windows 8.3 short name variations (AGENT~1), Unicode homoglyphs/fullwidth (.аgents, ．ａｇｅｎｔｓ),
    and NTFS Reparse Points / Directory Junctions traversing into or out of metadata directories.
    """
    normalized_parts = [canonicalize_path_component(part) for part in target_path.parts]
    for m_dir in metadata_dirs:
        m_lower = canonicalize_path_component(m_dir.lstrip("/\\"))
        if m_lower in normalized_parts:
            return True, m_dir

        # Windows 8.3 short name defense (e.g. AGENTS~1 or AGENT~1)
        clean_name = m_lower.lstrip(".")
        short_pattern = re.compile(rf"^\.?{re.escape(clean_name[:5])}.*~\d+$", re.IGNORECASE)
        for part in normalized_parts:
            if short_pattern.match(part):
                return True, m_dir

    # Check canonical resolved path if target or parent exists (resolves NTFS symlinks & junctions)
    try:
        resolved_path = target_path.resolve()
        res_parts = [canonicalize_path_component(part) for part in resolved_path.parts]
        for m_dir in metadata_dirs:
            m_lower = canonicalize_path_component(m_dir.lstrip("/\\"))
            if m_lower in res_parts:
                return True, m_dir
            clean_name = m_lower.lstrip(".")
            short_pattern = re.compile(rf"^\.?{re.escape(clean_name[:5])}.*~\d+$", re.IGNORECASE)
            for part in res_parts:
                if short_pattern.match(part):
                    return True, m_dir
    except Exception:
        pass

    return False, ""


def is_caller_pm_orchestrator(payload: dict[str, Any] | None = None) -> bool:
    """Check if the current calling agent is the PM Orchestrator.

    Inspects payload metadata or ANTIGRAVITY_CONVERSATION_ID transcript first line.
    Fast-path: reads only 1 line, completes in < 1ms, fail-safe.
    """
    if payload:
        caller = str(payload.get("caller_role") or payload.get("role") or "").lower().strip()
        if any(k in caller for k in ("pm", "orchestrator", "project_manager", "lead_pm")):
            return True
        if any(k in caller for k in ("top_level", "top-level", "agent_chinh", "backend", "frontend", "qa", "devops", "tech_lead", "worker", "subagent")):
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
        with open(transcript, "r", encoding="utf-8", errors="replace") as f:
            for _ in range(50):
                line = f.readline()
                if not line:
                    break
                try:
                    data = json.loads(line)
                    content = str(data.get("content", "")).lower()
                    if "vai trò:" in content or "bạn là" in content:
                        m = re.search(r"(?:vai trò:|bạn là)\s*([^\n\r,.;]+)", content)
                        if m:
                            role_str = m.group(1).lower()
                            if any(k in role_str for k in ("backend", "frontend", "qa", "devops", "tech_lead", "worker", "dev", "debugger", "top")):
                                return False
                            if any(k in role_str for k in ("pm", "orchestrator", "lead pm")):
                                return True
                except Exception:
                    continue
    except Exception:
        return False

    return False


def is_caller_top_level_agent(payload: dict[str, Any] | None = None) -> bool:
    """Check if caller is Top-Level Agent (Agent Chính) or running in root session.

    Inspects payload metadata (caller_role, role, is_root_session) or transcript first lines.
    """
    if payload:
        caller = str(payload.get("caller_role") or payload.get("role") or "").lower().strip()
        if any(k in caller for k in ("top_level", "top-level", "agent_chinh", "agent chính", "root", "root_session", "main")):
            return True
        if any(k in caller for k in ("pm", "orchestrator", "backend", "frontend", "qa", "devops", "tech_lead", "worker", "subagent", "dev", "engineer", "debugger", "patcher", "tester")):
            return False
        if payload.get("is_root_session") is True:
            return True
        if payload.get("is_subagent") is False:
            return True

    conv_id = (payload.get("conversationId") if payload else None) or os.environ.get("ANTIGRAVITY_CONVERSATION_ID")
    if not conv_id:
        if os.environ.get("ANTIGRAVITY_SUBAGENT", "").lower() in ("false", "0"):
            return True
        return False

    brain_dir = pathlib.Path.home() / ".gemini" / "antigravity" / "brain" / conv_id / ".system_generated" / "logs"
    transcript = brain_dir / "transcript.jsonl"
    if not transcript.exists():
        return False

    try:
        with open(transcript, "r", encoding="utf-8", errors="replace") as f:
            for _ in range(50):
                line = f.readline()
                if not line:
                    break
                try:
                    data = json.loads(line)
                    content = str(data.get("content", "")).lower()
                    worker_keywords = ("backend", "frontend", "qa", "devops", "tech_lead", "pm", "worker", "subagent", "debugger", "tester")
                    if any(k in content for k in worker_keywords):
                        return False
                    top_declarations = ["bạn là agent chính", "vai trò: agent chính", "vai trò: top-level", "top-level agent"]
                    if any(kw in content for kw in top_declarations):
                        return True
                    if data.get("source") == "USER_EXPLICIT" and data.get("type") == "USER_INPUT":
                        if not any(k in content for k in ("vai trò:", "<metadata>", "subagent")):
                            return True
                except Exception:
                    continue
    except Exception:
        return False

    return False


def normalize_command_string(cmd: str) -> str:
    """Normalize, deobfuscate, and decode terminal command string for security inspection.

    Performs:
    1. Multi-layer URL / percent decoding (%252e -> .).
    2. Hex escape sequences decoding (\\x2e -> .).
    3. Unicode NFKC normalization (Fullwidth ＞ -> >, ． -> ., ｐｙ -> py).
    4. Strips zero-width and invisible characters (\\u200B..\\u200D, BiDi \\u202E).
    5. Homoglyph translation (Cyrillic 'р' -> 'p', Greek 'ο' -> 'o', etc.).
    6. Normalizes non-ASCII Unicode whitespace and dots.
    """
    if not cmd or not isinstance(cmd, str):
        return ""
    # 1. Multi-layer percent decoding
    current = decode_multi_layer(cmd)

    # 2. Hex escape decoding (\\x2e -> .)
    def _hex_sub(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    current = re.sub(r"(?i)\\x([0-9a-f]{2})", _hex_sub, current)

    # 3. Unicode NFKC normalization
    current = unicodedata.normalize("NFKC", current)

    # 4. Remove zero-width and BiDi characters
    for ch in ZERO_WIDTH_AND_BIDI_CHARS:
        current = current.replace(ch, "")

    # 5. Translate homoglyphs
    current = current.translate(HOMOGLYPH_TRANSLATION_TABLE)

    # 6. Normalize Unicode spaces and dots
    current = current.replace("\u00a0", " ").replace("\u3000", " ")
    for dot in NTFS_TRAILING_DOTS:
        if dot != ".":
            current = current.replace(dot, ".")

    return current


def is_terminal_code_write_command(cmd: str) -> bool:
    """Detect if a terminal command writes or creates source code files.

    Inspects both normalized/deobfuscated command and raw command against code writing patterns.
    """
    if not cmd or not isinstance(cmd, str):
        return False

    variants = [normalize_command_string(cmd), cmd.strip()]

    for c in variants:
        if not c:
            continue
        # 1. Shell redirection (> or >>) into code file (supports quotes and trailing dots/spaces)
        if re.search(r">{1,2}\s*[\"']?[^\s|&;'\"]+?" + CODE_EXT_REGEX, c, re.IGNORECASE):
            return True
        # 2. PowerShell file writing cmdlets (Set-Content, Out-File, Add-Content, New-Item)
        if re.search(r"(?:set-content|out-file|add-content|new-item)\b.*?[\"']?[^\s|&;'\"]+?" + CODE_EXT_REGEX, c, re.IGNORECASE):
            return True
        # 3. Unix file writing utilities (tee, cat >)
        if re.search(r"\btee(?:\s+-[a-zA-Z]+)*\s+[\"']?[^\s|&;'\"]+?" + CODE_EXT_REGEX, c, re.IGNORECASE):
            return True
        # 4. Inline python scripts writing files
        if re.search(r"python(?:\d+)?\s+-c\s+.*open\(.*?[\"'][wa\+]", c, re.IGNORECASE):
            return True
        # 5. Inline node scripts writing files
        if re.search(r"node\s+-e\s+.*(?:writefile|appendfile)", c, re.IGNORECASE):
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
        args = get_tool_args(tool_call)
        cmd = str(args.get("CommandLine", "")).strip()
        if is_caller_top_level_agent(payload):
            if is_terminal_code_write_command(cmd):
                reason = (
                    "CƯỠNG CHẾ PHÂN TẦNG AGENT CHÍNH (§TOP-LEVEL-ROLE-BOUNDARY): Agent Chính (Top-Level Agent) "
                    f"TUYỆT ĐỐI CẤM bypass bằng terminal command để tạo/sửa file mã nguồn qua run_command ('{cmd}')! "
                    "Mọi hành động lập trình/sửa code BẮT BUỘC phải ủy quyền cho PM Sub-agent và Developer Sub-agents!"
                )
                log_diagnostic(f"BLOCKED Top-Level Agent terminal code bypass: {cmd}")
                return pre_tool_response("deny", reason)
        elif is_caller_pm_orchestrator(payload):
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
        return pre_tool_response("allow", "No TargetFile argument found.")

    # Defense 1: Null byte injection
    if "\0" in raw_target:
        log_diagnostic("Detected embedded null byte in target path.")
        return pre_tool_response("deny", "Enterprise Security Violation (§7): Target path contains embedded null byte.")

    # Defense 2: Windows Alternate Data Stream (ADS) injection defense (: separator)
    if has_ntfs_ads(raw_target):
        reason = (
            f"Enterprise Security Violation (§7): Target path '{raw_target}' contains illegal "
            f"Alternate Data Stream (ADS) separator. Writes to NTFS streams are strictly prohibited."
        )
        log_diagnostic(f"Blocked NTFS Alternate Data Stream attack: {raw_target}")
        return pre_tool_response("deny", reason)

    # Defense 3: Windows prohibited characters (* ? " < > | and control chars)
    # Defense 3: Windows prohibited characters (* ? " < > | and control chars)
    has_forbidden, char_repr = has_windows_forbidden_chars(raw_target)
    if has_forbidden:
        reason = (
            f"Enterprise Security Violation (§7): Target path '{raw_target}' contains illegal "
            f"Windows character {char_repr}. Writes rejected."
        )
        log_diagnostic(f"Blocked forbidden Windows character {char_repr} in: {raw_target}")
        return pre_tool_response("deny", reason)

    # Defense 4: Windows DOS reserved device names and Volume GUID prefixes
    clean_raw, p_type = strip_unc_prefix(raw_target)
    if p_type == "VOLUME_GUID":
        reason = f"Enterprise Security Violation (§7): Target path '{raw_target}' uses prohibited Volume GUID prefix."
        log_diagnostic(f"Blocked Volume GUID write: {raw_target}")
        return pre_tool_response("deny", reason)
    if is_reserved_device_name(clean_raw):
        reason = f"Enterprise Security Violation (§7): Target path '{raw_target}' refers to a reserved Windows device name."
        log_diagnostic(f"Blocked reserved device write: {raw_target}")
        return pre_tool_response("deny", reason)

    # Defense 5: NTFS Trailing Dots and Whitespace Evasion Defense
    sanitized_target, _ = sanitize_ntfs_trailing_dots_and_spaces(raw_target)
    if sanitized_target is None:
        reason = (
            f"Enterprise Security Violation (§7): Target path '{raw_target}' contains invalid "
            f"component syntax (dots/spaces only). Writes rejected."
        )
        log_diagnostic(f"Blocked dots-only component path: {raw_target}")
        return pre_tool_response("deny", reason)

    # Defense 6: Path Resolution & Canonical Realpath (Defeats Symlink / Junction Traversal & Multi-Workspace Drift)
    workspace_roots = get_workspace_roots(payload)
    target_path = resolve_target_path(sanitized_target, workspace_roots)

    # If path resolution failed (e.g. malformed path), deny safely
    if target_path is None:
        reason = (
            f"Enterprise Security Violation (§7): Target path '{raw_target}' is malformed "
            f"or contains prohibited control characters. Writes rejected."
        )
        log_diagnostic(f"Blocked invalid path: {raw_target}")
        return pre_tool_response("deny", reason)

    # Defense 7: Hardlink tracking (st_nlink > 1)
    if is_hardlink(target_path):
        log_diagnostic(f"Target path '{target_path}' is an NTFS hardlink (st_nlink > 1).")

    # Defense 8: Workspace Boundary & Path Traversal Guard (§7)
    if not is_path_within_workspace(target_path, workspace_roots):
        reason = (
            f"Enterprise Security Violation (§7): Target path '{raw_target}' is outside "
            f"authorized workspace roots. Writes outside workspace boundaries are prohibited."
        )
        log_diagnostic(f"Blocked out-of-scope write: {raw_target}")
        return pre_tool_response("deny", reason)

    # Canonical extensions extraction from both input syntax and resolved realpath
    clean_target_path = pathlib.Path(sanitized_target)
    clean_target_ext = canonicalize_extension(clean_target_path.suffix)
    clean_all_exts = [canonicalize_extension(s) for s in clean_target_path.suffixes]
    resolved_ext = canonicalize_extension(target_path.suffix)
    resolved_all_exts = [canonicalize_extension(s) for s in target_path.suffixes]
    all_inspected_exts = set(clean_all_exts + resolved_all_exts + [clean_target_ext, resolved_ext])

    # Defense 9: Top-Level Agent Role Boundary Enforcement (§TOP-LEVEL-ROLE-BOUNDARY)
    # Agent Chính tuyệt đối cấm tự viết/sửa mã nguồn (.py, .js, .ts, etc.), including via resolved symlinks.
    if is_caller_top_level_agent(payload):
        is_code = any(s in prohibited_src_exts for s in all_inspected_exts)
        if is_code:
            reason = (
                f"CƯỠNG CHẾ PHÂN TẦNG AGENT CHÍNH (§TOP-LEVEL-ROLE-BOUNDARY): Agent Chính (Top-Level Agent) "
                f"TUYỆT ĐỐI CẤM tự sửa/tạo file mã nguồn '{raw_target}'! "
                "Agent Chính chỉ tương tác trực tiếp với Sếp và điều phối cấp cao. "
                "Mọi hành động viết code, sửa bug kỹ thuật BẮT BUỘC phải ủy quyền cho PM Sub-agent điều phối!"
            )
            log_diagnostic(f"BLOCKED Top-Level Agent from modifying source code file: {raw_target}")
            return pre_tool_response("deny", reason)

    # Defense 10: PM Orchestrator Role Boundary Enforcement (§PM-ROLE-BOUNDARY)
    # PM Orchestrator tuyệt đối không được tự ý sửa hoặc tạo mã nguồn (.py, .js, .ts, etc.).
    if is_caller_pm_orchestrator(payload):
        is_code = any(s in prohibited_src_exts for s in all_inspected_exts)
        if is_code:
            reason = (
                f"CƯỠNG CHẾ RANH GIỚI VAI TRÒ (§PM-ROLE-BOUNDARY): PM Orchestrator TUYỆT ĐỐI CẤM tự sửa/tạo file mã nguồn '{raw_target}'! "
                "PM chỉ đóng vai trò lập kế hoạch, điều phối 7 Phase Gates và ghi chép tiến độ (progress.md, GATE_STATUS.md, handoff.md). "
                "Mọi hành động sửa code/vá lỗi BẮT BUỘC phải ủy quyền cho Developer Sub-agent (TypeName='self') để thợ tự tay sửa và kiểm thử!"
            )
            log_diagnostic(f"BLOCKED PM Orchestrator from directly modifying source code file: {raw_target}")
            return pre_tool_response("deny", reason)

    # Defense 11: .agents/ Layout Compliance (§15, §29) & Double Extension Masking
    is_meta_dir, matched_dir = is_metadata_directory_target(target_path, metadata_dirs)
    if is_meta_dir:
        # Check double extension masking (e.g. app.exe.md or code.py.txt)
        if len(resolved_all_exts) > 1:
            for s in resolved_all_exts[:-1]:
                if s in prohibited_src_exts or s in {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".dll", ".so", ".sh"}:
                    reason = (
                        f"Enterprise Rule Layout Compliance (§15, §29): Prohibited double extension masked file "
                        f"('{s}') into '{matched_dir}/' directory: '{raw_target}'."
                    )
                    log_diagnostic(f"Blocked double extension masked file in {matched_dir}/: {raw_target}")
                    return pre_tool_response("deny", reason)

        is_prohibited_src = any(s in prohibited_src_exts for s in all_inspected_exts)
        if is_prohibited_src:
            matched_ext = next(s for s in all_inspected_exts if s in prohibited_src_exts)
            reason = (
                f"Enterprise Rule Layout Compliance (§15, §29): Prohibited writing source code "
                f"('{matched_ext}') into '{matched_dir}/' directory. '{matched_dir}/' is reserved exclusively for agent "
                f"metadata (plans, progress, handoffs, briefings, reports). Place source code in designated source directories."
            )
            log_diagnostic(f"Blocked code placement in {matched_dir}/: {raw_target}")
            return pre_tool_response("deny", reason)

        if resolved_ext not in allowed_meta_exts:
            reason = (
                f"Enterprise Rule Layout Compliance (§15, §29): Prohibited writing non-metadata file "
                f"('{resolved_ext or 'no extension'}') into '{matched_dir}/' directory. '{matched_dir}/' is reserved exclusively for agent "
                f"metadata (plans, progress, handoffs, briefings, reports)."
            )
            log_diagnostic(f"Blocked non-metadata placement in {matched_dir}/: {raw_target}")
            return pre_tool_response("deny", reason)

    return pre_tool_response("allow", "Target file path is within authorized workspace scope and complies with layout rules.")


# ==============================================================================
# Self-Test Suite (--self-test CLI runner)
# ==============================================================================
def run_self_tests() -> bool:
    """Run comprehensive in-process self-test suite covering 34 security and resilience scenarios."""
    print("======================================================================")
    print("Running Hardened Scope Boundary Enforcer Self-Test Suite (Enterprise Mode)")
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
            "caller_role": "worker",
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

    # 11. Unmonitored tools (dir, view_file) -> allow
    res11 = evaluate_scope_boundary({
        "toolCall": {"name": "run_command", "args": {"CommandLine": "dir"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("11. Allow Unmonitored Tools (dir, view_file)", res11.get("decision") == "allow")

    # 12. Malformed payloads and null safety fallback
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
    record_test("14. Deny NTFS Alternate Data Streams (ADS)", res14.get("decision") == "deny" and "ADS" in res14.get("reason", ""))

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

    # 21. Deny NTFS Trailing Dot Evasion on source code for Top-Level Agent (main.py.)
    res21 = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "main.py.")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("21. Deny Top-Level Agent NTFS Trailing Dot Evasion (main.py.)", res21.get("decision") == "deny" and "TOP-LEVEL-ROLE-BOUNDARY" in res21.get("reason", ""))

    # 22. Deny NTFS Trailing Space Evasion on source code for Top-Level Agent (main.py )
    res22 = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "main.py ")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("22. Deny Top-Level Agent NTFS Trailing Space Evasion ('main.py ')", res22.get("decision") == "deny" and "TOP-LEVEL-ROLE-BOUNDARY" in res22.get("reason", ""))

    # 23. Deny NTFS Trailing Dot/Space Evasion for PM Orchestrator (app.py. . .)
    res23 = evaluate_scope_boundary({
        "caller_role": "pm_orchestrator",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "app.py. . .")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("23. Deny PM Orchestrator NTFS Trailing Dot/Space Evasion ('app.py. . .')", res23.get("decision") == "deny" and "PM-ROLE-BOUNDARY" in res23.get("reason", ""))

    # 24. Deny NTFS Trailing Dot in .agents/ double extension (notes.md.py.)
    res24 = evaluate_scope_boundary({
        "caller_role": "worker",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / ".agents" / "w" / "notes.md.py.")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("24. Deny Trailing Dot Double Extension in .agents/ (notes.md.py.)", res24.get("decision") == "deny")

    # 25. Allow UNC Path within workspace (\\\\?\\C:\\...)
    res25 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": f"\\\\?\\{test_workspace}\\valid.txt"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("25. Allow UNC Device Path Within Workspace", res25.get("decision") == "allow")

    # 26. Deny UNC Path outside workspace (\\\\?\\C:\\Windows\\...)
    res26 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": "\\\\?\\C:\\Windows\\System32\\calc.exe"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("26. Deny UNC Device Path Outside Workspace", res26.get("decision") == "deny")

    # 27. Deny Windows Forbidden Characters (*, ?, \", <, >, |)
    forbidden_samples = ["file*name.txt", "file?name.txt", 'file"name.txt', "file<name>.txt", "file|name.txt"]
    p27_passed = True
    for f_name in forbidden_samples:
        r = evaluate_scope_boundary({
            "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / f_name)}},
            "workspacePaths": [str(test_workspace)],
        })
        if r.get("decision") != "deny" or "illegal windows character" not in r.get("reason", "").lower():
            p27_passed = False
            break
    record_test("27. Deny Windows Forbidden Characters (*, ?, \", <, >, |)", p27_passed)

    # 28. Deny Top-Level Agent terminal code write bypass (echo > main.py)
    res28 = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "run_command", "args": {"CommandLine": "echo 'print(1)' > main.py"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("28. Deny Top-Level Agent terminal code write (echo > main.py)", res28.get("decision") == "deny" and "TOP-LEVEL-ROLE-BOUNDARY" in res28.get("reason", ""))

    # 29. Deny Top-Level Agent terminal code write with trailing dot (echo > main.py.)
    res29 = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "run_command", "args": {"CommandLine": "echo 'print(1)' > main.py."}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("29. Deny Top-Level Agent terminal code write with trailing dot", res29.get("decision") == "deny" and "TOP-LEVEL-ROLE-BOUNDARY" in res29.get("reason", ""))

    # 30. Deny Top-Level Agent PowerShell Set-Content command
    res30 = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "run_command", "args": {"CommandLine": "Set-Content -Path app.py -Value 'x=1'"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("30. Deny Top-Level Agent PowerShell Set-Content code write", res30.get("decision") == "deny" and "TOP-LEVEL-ROLE-BOUNDARY" in res30.get("reason", ""))

    # 31. Deny Root Session modifying source code (.py)
    res31 = evaluate_scope_boundary({
        "is_root_session": True,
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "main.py")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("31. Deny Root Session Modifying Source Code (.py)", res31.get("decision") == "deny" and "TOP-LEVEL-ROLE-BOUNDARY" in res31.get("reason", ""))

    # 32. Allow Root Session modifying documentation (.md)
    res32 = evaluate_scope_boundary({
        "is_root_session": True,
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "progress.md")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("32. Allow Root Session Modifying Documentation (.md)", res32.get("decision") == "allow")

    # 33. Allow Worker modifying source code within workspace
    res33 = evaluate_scope_boundary({
        "caller_role": "backend",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "main.py")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("33. Allow Worker Modifying Source Code Within Workspace", res33.get("decision") == "allow")

    # 34. Deny Dots-Only Component Evasion (...)
    res34 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "...")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("34. Deny Dots-Only Component Evasion (...)", res34.get("decision") == "deny")

    # 35. Deny Fullwidth Full Stop in extension evasion (main．py / \uff0e) for Top-Level Agent
    res35 = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "main\uff0epy")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("35. Deny Fullwidth Full Stop in extension evasion (main\uff0epy)", res35.get("decision") == "deny" and "TOP-LEVEL-ROLE-BOUNDARY" in res35.get("reason", ""))

    # 36. Deny Fullwidth Solidus in path traversal (..\uff0foutside.txt)
    res36 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": f"..{chr(0xff0f)}outside.txt"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("36. Deny Fullwidth Solidus in path traversal (..\uff0foutside.txt)", res36.get("decision") == "deny")

    # 37. Deny Double-encoded percent path (%252e%2570%2579 -> .py) for Top-Level Agent
    res37 = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace) + "\\main%252e%2570%2579"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("37. Deny Double-encoded percent path (%252e%2570%2579)", res37.get("decision") == "deny" and "TOP-LEVEL-ROLE-BOUNDARY" in res37.get("reason", ""))

    # 38. Deny Cyrillic homoglyph in extension (main.рy / \u0440) for Top-Level Agent
    res38 = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "main.\u0440y")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("38. Deny Cyrillic homoglyph in extension (main.\u0440y)", res38.get("decision") == "deny" and "TOP-LEVEL-ROLE-BOUNDARY" in res38.get("reason", ""))

    # 39. Deny Cyrillic homoglyph in .agents directory (.\u0430gents/code.py)
    res39 = evaluate_scope_boundary({
        "caller_role": "worker",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / ".\u0430gents" / "code.py")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("39. Deny Cyrillic homoglyph in .agents directory (.\u0430gents)", res39.get("decision") == "deny" and ".agents" in res39.get("reason", ""))

    # 40. Deny Fullwidth Colon in Alternate Data Streams (script.py：hidden / \uff1a)
    res40 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "script.py\uff1ahidden")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("40. Deny Fullwidth Colon in Alternate Data Streams (script.py\uff1ahidden)", res40.get("decision") == "deny" and "Alternate Data Stream" in res40.get("reason", ""))

    # 41. Deny Small Colon in Alternate Data Streams (script.py﹕$DATA / \ufe55)
    res41 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "script.py\ufe55$DATA")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("41. Deny Small Colon in Alternate Data Streams (script.py\ufe55$DATA)", res41.get("decision") == "deny" and "Alternate Data Stream" in res41.get("reason", ""))

    # 42. Deny Percent-encoded colon in Alternate Data Streams (script.py%3ahidden and %253a)
    res42a = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace) + "\\script.py%3ahidden"}},
        "workspacePaths": [str(test_workspace)],
    })
    res42b = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace) + "\\script.py%253ahidden"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("42. Deny Percent-encoded colon in Alternate Data Streams (%3a / %253a)", res42a.get("decision") == "deny" and res42b.get("decision") == "deny")

    # 43. Deny Non-ASCII Unicode whitespace trailing evasion (main.py\u00a0 and main.py\u3000) for Top-Level Agent
    res43a = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "main.py\u00a0")}},
        "workspacePaths": [str(test_workspace)],
    })
    res43b = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "main.py\u3000")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("43. Deny Non-ASCII Unicode whitespace trailing evasion (\u00a0, \u3000)", res43a.get("decision") == "deny" and res43b.get("decision") == "deny")

    # 44. Deny Non-ASCII Unicode dot trailing evasion (main.py\uff0e and main.py\u2024) for Top-Level Agent
    res44a = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "main.py\uff0e")}},
        "workspacePaths": [str(test_workspace)],
    })
    res44b = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "main.py\u2024")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("44. Deny Non-ASCII Unicode dot trailing evasion (\uff0e, \u2024)", res44a.get("decision") == "deny" and res44b.get("decision") == "deny")

    # 45. Deny Dots/spaces-only component evasion with Unicode characters (\uff0e\uff0e\uff0e and \u00a0\u2024\u3000)
    res45a = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "\uff0e\uff0e\uff0e")}},
        "workspacePaths": [str(test_workspace)],
    })
    res45b = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "\u00a0\u2024\u3000")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("45. Deny Unicode Dots/Spaces-only component evasion", res45a.get("decision") == "deny" and res45b.get("decision") == "deny")

    # 46. Deny Prohibited Windows zero-width characters in filename (main\u200b.txt)
    res46 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "main\u200b.txt")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("46. Deny Prohibited Windows zero-width characters (main\u200b.txt)", res46.get("decision") == "deny" and "U+200B" in res46.get("reason", ""))

    # 47. Deny Prohibited Windows BiDi control character in filename (main\u202e.txt)
    res47 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "main\u202e.txt")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("47. Deny Prohibited Windows BiDi control character (main\u202e.txt)", res47.get("decision") == "deny" and "U+202E" in res47.get("reason", ""))

    # 48. Deny Terminal command with Fullwidth redirection (echo 'x=1' \uff1e app.py)
    res48 = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "run_command", "args": {"CommandLine": "echo 'x=1' \uff1e app.py"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("48. Deny Terminal command with Fullwidth redirection (\uff1e)", res48.get("decision") == "deny" and "TOP-LEVEL-ROLE-BOUNDARY" in res48.get("reason", ""))

    # 49. Deny Terminal command with Cyrillic homoglyph in redirect target (echo 'x=1' > app.\u0440y)
    res49 = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "run_command", "args": {"CommandLine": "echo 'x=1' > app.\u0440y"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("49. Deny Terminal command with Cyrillic homoglyph in redirect (app.\u0440y)", res49.get("decision") == "deny" and "TOP-LEVEL-ROLE-BOUNDARY" in res49.get("reason", ""))

    # 50. Deny Terminal command with percent-encoded extension (echo 'x=1' > app%252epy)
    res50 = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "run_command", "args": {"CommandLine": "echo 'x=1' > app%252epy"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("50. Deny Terminal command with percent-encoded extension (%252epy)", res50.get("decision") == "deny" and "TOP-LEVEL-ROLE-BOUNDARY" in res50.get("reason", ""))

    # 51. Deny Terminal command with zero-width character (echo 'x=1' > app.\u200bpy)
    res51 = evaluate_scope_boundary({
        "caller_role": "top_level",
        "toolCall": {"name": "run_command", "args": {"CommandLine": "echo 'x=1' > app.\u200bpy"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("51. Deny Terminal command with zero-width character in extension", res51.get("decision") == "deny" and "TOP-LEVEL-ROLE-BOUNDARY" in res51.get("reason", ""))

    # 52. Deny PM Orchestrator from modifying Cyrillic .рy source file
    res52 = evaluate_scope_boundary({
        "caller_role": "pm_orchestrator",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / "handler.\u0440y")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("52. Deny PM Orchestrator from modifying Cyrillic .рy source file", res52.get("decision") == "deny" and "PM-ROLE-BOUNDARY" in res52.get("reason", ""))

    # 53. Deny Volume GUID target
    res53 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\test.txt"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("53. Deny Volume GUID target write", res53.get("decision") == "deny" and "Volume GUID" in res53.get("reason", ""))

    # 54. Deny DOS reserved device write (CON, NUL, AUX)
    res54 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": "NUL"}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("54. Deny DOS reserved device write (NUL)", res54.get("decision") == "deny" and "reserved Windows device" in res54.get("reason", ""))

    # 55. Deny Double Extension Masking in .agents/ (app.exe.md)
    res55 = evaluate_scope_boundary({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": str(test_workspace / ".agents" / "app.exe.md")}},
        "workspacePaths": [str(test_workspace)],
    })
    record_test("55. Deny Double Extension Masking in .agents/ (app.exe.md)", res55.get("decision") == "deny" and "double extension" in res55.get("reason", "").lower())

    # 56. Multi-workspace root relative path resolution
    second_workspace = test_workspace.parent / "second_ws"
    second_workspace.mkdir(exist_ok=True)
    res56 = evaluate_scope_boundary({
        "caller_role": "worker",
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": "subfile.txt"}},
        "workspacePaths": [str(test_workspace), str(second_workspace)],
    })
    record_test("56. Multi-workspace root relative path resolution", res56.get("decision") == "allow")

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
