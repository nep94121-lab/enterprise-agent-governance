#!/usr/bin/env python3
"""Dangerous Command Guard Hook (PreToolUse) for Enterprise Multi-Agent Governance System.

Protects system infrastructure and data assets against accidental destruction
(accidental-data-loss-prevention rule, §3 injection and destruction defense).
Blocks destructive OS commands, unqualified database drops/truncations,
and blanket Git staging with advanced evasion/obfuscation defense.

Enhanced with:
- Multi-Layer / Double-Decode Handling (percent-encoding, URL double-encoding, hex/octal escapes, Base64 wrappers).
- Cross-Script Homoglyph Normalization (Cyrillic, Greek -> Latin/ASCII).
- Comprehensive Invisible, BiDi, Zero-Width, and Formatting Character Filtering.
- Unicode Case Folding Normalization (casefold()).
- Multi-Pass Fixed-Point Normalization (idempotent convergence).
- Raw Context Preservation and Multi-Candidate Cross-Referencing in Validation Invocation.
"""

from __future__ import annotations

import base64
import io
import pathlib
import re
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

# Ensure local hook libraries are importable
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
    log_diagnostic,
    pre_tool_response,
    read_stdin_payload,
)

from hook_utils import get_command_validator  # noqa: E402
from hook_utils.powershell_normalizer import (
    decode_powershell_base64_payload,
    expand_powershell_aliases,
    expand_powershell_concatenation,
    extract_base64_payloads as extract_ps_base64_payloads,
    get_all_command_variants,
    strip_powershell_backticks,
)

# Maximum iterations for multi-pass fixed-point convergence
MAX_NORMALIZATION_PASSES = 10

# Complete tuple of zero-width and invisible characters for backwards-compatibility
ZERO_WIDTH_CHARS = (
    "\u200b",  # Zero-Width Space (ZWSP)
    "\u200c",  # Zero-Width Non-Joiner (ZWNJ)
    "\u200d",  # Zero-Width Joiner (ZWJ)
    "\ufeff",  # Zero-Width No-Break Space / Byte Order Mark (BOM)
    "\u00ad",  # Soft Hyphen (SHY)
    "\u034f",  # Combining Grapheme Joiner (CGJ)
    "\u180e",  # Mongolian Vowel Separator (MVS)
    "\u200e",  # Left-to-Right Mark (LRM)
    "\u200f",  # Right-to-Left Mark (RLM)
    "\u202a",  # Left-to-Right Embedding (LRE)
    "\u202b",  # Right-to-Left Embedding (RLE)
    "\u202c",  # Pop Directional Formatting (PDF)
    "\u202d",  # Left-to-Right Override (LRO)
    "\u202e",  # Right-to-Left Override (RLO)
    "\u2060",  # Word Joiner (WJ)
    "\u2061",  # Function Application
    "\u2062",  # Invisible Times
    "\u2063",  # Invisible Separator
    "\u2064",  # Invisible Plus
    "\u2066",  # Left-to-Right Isolate (LRI)
    "\u2067",  # Right-to-Left Isolate (RLI)
    "\u2068",  # First Strong Isolate (FSI)
    "\u2069",  # Pop Directional Isolate (PDI)
)

# High-performance compiled regex stripping all invisible, BiDi, and zero-width code points
INVISIBLE_AND_ZERO_WIDTH_REGEX = re.compile(
    r"["
    r"\u00ad"        # Soft Hyphen
    r"\u034f"        # Combining Grapheme Joiner
    r"\u180e"        # Mongolian Vowel Separator
    r"\u200b-\u200f" # ZWSP, ZWNJ, ZWJ, LRM, RLM
    r"\u202a-\u202e" # BiDi: LRE, RLE, PDF, LRO, RLO
    r"\u2060-\u2064" # Word Joiner, Invisible Operators
    r"\u2066-\u2069" # Directional Isolates: LRI, RLI, FSI, PDI
    r"\ufeff"        # ZWNBSP / BOM
    r"]"
)

# Cross-script homoglyph mappings (Cyrillic and Greek visually confusable with Latin/ASCII)
HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic lowercase homoglyphs to Latin
    "\u0430": "a",   # Cyrillic small a
    "\u0431": "b",   # Cyrillic small be
    "\u0432": "v",   # Cyrillic small ve
    "\u0433": "r",   # Cyrillic small ghe
    "\u0434": "d",   # Cyrillic small de
    "\u0435": "e",   # Cyrillic small ie
    "\u043a": "k",   # Cyrillic small ka
    "\u043c": "m",   # Cyrillic small em
    "\u043d": "h",   # Cyrillic small en
    "\u043e": "o",   # Cyrillic small o
    "\u0440": "p",   # Cyrillic small er (visually looks identical to Latin p)
    "\u0441": "c",   # Cyrillic small es (visually looks identical to Latin c)
    "\u0442": "t",   # Cyrillic small te
    "\u0443": "y",   # Cyrillic small u (visually looks identical to Latin y)
    "\u0445": "x",   # Cyrillic small ha (visually looks identical to Latin x)
    "\u0455": "s",   # Cyrillic small dze (visually looks identical to Latin s)
    "\u0456": "i",   # Cyrillic small i
    "\u0458": "j",   # Cyrillic small je
    "\u04bb": "h",   # Cyrillic small shha
    "\u0501": "d",   # Cyrillic small komi de
    "\u051b": "q",   # Cyrillic small qa
    "\u051d": "w",   # Cyrillic small we

    # Cyrillic uppercase homoglyphs to Latin
    "\u0410": "A",   # Cyrillic capital A
    "\u0411": "B",   # Cyrillic capital Be
    "\u0412": "B",   # Cyrillic capital Ve (looks identical to Latin B)
    "\u0413": "G",   # Cyrillic capital Ghe
    "\u0415": "E",   # Cyrillic capital Ie (looks identical to Latin E)
    "\u041a": "K",   # Cyrillic capital Ka (looks identical to Latin K)
    "\u041c": "M",   # Cyrillic capital Em (looks identical to Latin M)
    "\u041d": "H",   # Cyrillic capital En (looks identical to Latin H)
    "\u041e": "O",   # Cyrillic capital O (looks identical to Latin O)
    "\u0420": "P",   # Cyrillic capital Er (looks identical to Latin P)
    "\u0421": "C",   # Cyrillic capital Es (looks identical to Latin C)
    "\u0422": "T",   # Cyrillic capital Te (looks identical to Latin T)
    "\u0423": "Y",   # Cyrillic capital U
    "\u0425": "X",   # Cyrillic capital Ha (looks identical to Latin X)
    "\u0405": "S",   # Cyrillic capital Dze (looks identical to Latin S)
    "\u0406": "I",   # Cyrillic capital I (looks identical to Latin I)
    "\u0408": "J",   # Cyrillic capital Je (looks identical to Latin J)
    "\u04ba": "H",   # Cyrillic capital Shha
    "\u04ae": "Y",   # Cyrillic capital Straight U
    "\u0500": "D",   # Cyrillic capital Komi De
    "\u051a": "Q",   # Cyrillic capital Qa
    "\u051c": "W",   # Cyrillic capital We

    # Greek lowercase homoglyphs to Latin
    "\u03b1": "a",   # Greek small alpha
    "\u03b2": "b",   # Greek small beta
    "\u03b5": "e",   # Greek small epsilon
    "\u03b7": "h",   # Greek small eta
    "\u03b9": "i",   # Greek small iota
    "\u03ba": "k",   # Greek small kappa
    "\u03bd": "v",   # Greek small nu (looks like Latin v)
    "\u03bf": "o",   # Greek small omicron (looks identical to Latin o)
    "\u03c1": "p",   # Greek small rho (looks like Latin p)
    "\u03c2": "s",   # Greek small final sigma
    "\u03c3": "s",   # Greek small sigma
    "\u03c4": "t",   # Greek small tau
    "\u03c5": "u",   # Greek small upsilon
    "\u03c7": "x",   # Greek small chi
    "\u03c9": "w",   # Greek small omega

    # Greek uppercase homoglyphs to Latin
    "\u0391": "A",   # Greek capital Alpha
    "\u0392": "B",   # Greek capital Beta
    "\u0395": "E",   # Greek capital Epsilon
    "\u0397": "H",   # Greek capital Eta
    "\u0399": "I",   # Greek capital Iota
    "\u039a": "K",   # Greek capital Kappa
    "\u039c": "M",   # Greek capital Mu
    "\u039d": "N",   # Greek capital Nu
    "\u039f": "O",   # Greek capital Omicron
    "\u03a1": "P",   # Greek capital Rho
    "\u03a4": "T",   # Greek capital Tau
    "\u03a7": "X",   # Greek capital Chi
    "\u03a5": "Y",   # Greek capital Upsilon
}

HOMOGLYPH_TRANSLATION_TABLE = str.maketrans(HOMOGLYPH_MAP)


def unescape_percent_encoding(text: str) -> str:
    """Decode percent-encoded sequences (%HH), handling nested/double-encoding."""
    if not isinstance(text, str) or "%" not in text:
        return text
    try:
        return urllib.parse.unquote(text)
    except Exception:
        return text


def unescape_hex_sequences(text: str) -> str:
    """Decode \\xHH hex escapes and \\uHHHH unicode escape sequences."""
    if not isinstance(text, str) or "\\" not in text:
        return text

    def _replace_hex(m: re.Match) -> str:
        try:
            val = int(m.group(1), 16)
            return chr(val)
        except (ValueError, OverflowError):
            return m.group(0)

    # Decode \xHH (2 hex digits)
    text = re.sub(r"\\x([0-9a-fA-F]{2})", _replace_hex, text)
    # Decode \uHHHH (4 hex digits)
    text = re.sub(r"\\u([0-9a-fA-F]{4})", _replace_hex, text)
    return text


def unescape_octal_sequences(text: str) -> str:
    """Decode \\0OOO octal escapes and \\OOO 3-digit octal escapes."""
    if not isinstance(text, str) or "\\" not in text:
        return text

    def _replace_octal(m: re.Match) -> str:
        try:
            val = int(m.group(1), 8)
            if 0 < val <= 255:
                return chr(val)
        except (ValueError, OverflowError):
            pass
        return m.group(0)

    # Decode \0[0-7]{2,3}
    text = re.sub(r"\\0([0-7]{2,3})", _replace_octal, text)
    # Decode \[0-3][0-7]{2}
    text = re.sub(r"\\([0-3][0-7]{2})", _replace_octal, text)
    return text


def _normalize_single_pass(text: str) -> str:
    """Execute one single pass of canonical normalization and deobfuscation."""
    if not text:
        return ""

    # 1. Unicode NFKC normalization
    norm = unicodedata.normalize("NFKC", text)

    # 2. Cross-script homoglyph normalization (Cyrillic & Greek -> Latin)
    norm = norm.translate(HOMOGLYPH_TRANSLATION_TABLE)

    # 3. Strip invisible and zero-width characters
    norm = INVISIBLE_AND_ZERO_WIDTH_REGEX.sub("", norm)

    # 4. Multi-layer percent-decoding
    norm = unescape_percent_encoding(norm)

    # 5. Hex escape unescaping (\xHH and \uHHHH)
    norm = unescape_hex_sequences(norm)

    # 6. Octal escape unescaping (\0OO and \OOO)
    norm = unescape_octal_sequences(norm)

    # 7. Strip caret escape character (CMD) and backtick (PowerShell)
    norm = strip_powershell_backticks(norm).replace("^", "")

    # 8. Strip redundant quotes repeatedly
    while "''" in norm or '""' in norm:
        norm = norm.replace("''", "").replace('""', "")

    # 9. Expand string concatenations and format operators
    norm = expand_powershell_concatenation(norm)

    return norm


def deobfuscate_command_string(command_line: str, apply_casefold: bool = False) -> str:
    """Preprocess command line to thoroughly defeat evasion and obfuscation techniques.

    Multi-Pass Fixed-Point Normalization:
    1. Unicode NFKC normalization.
    2. Cross-script homoglyph mapping (Cyrillic, Greek -> Latin).
    3. Strip invisible & zero-width characters: BiDi (\\u202a-\\u202e),
       Word Joiner (\\u2060), Invisible Math Operators (\\u2061-\\u2064),
       Directional Isolates (\\u2066-\\u2069), CGJ (\\u034f), Soft Hyphen (\\u00ad),
       MVS (\\u180e), and standard ZWSP/BOM.
    4. Multi-layer URL / percent-decoding (%252f -> %2f -> /).
    5. Hex (\\x..) and Octal (\\0..) escape unescaping.
    6. Strip caret escape character (^) and redundant empty quotes ('' / "").
    7. Multi-pass loop until fixed-point (idempotent state) is reached.
    8. Optional Unicode case folding (casefold()).
    """
    if not isinstance(command_line, str) or not command_line:
        return ""

    current = command_line
    for _ in range(MAX_NORMALIZATION_PASSES):
        previous = current
        current = _normalize_single_pass(current)
        if current == previous:
            break

    if apply_casefold:
        current = current.casefold()

    return current


def decode_base64_payload(b64_str: str) -> list[str]:
    """Safely decode Base64 string into UTF-16LE and UTF-8 command representations."""
    decoded_commands: list[str] = []
    try:
        raw = base64.b64decode(b64_str.strip())
        # Try UTF-16LE (PowerShell standard for -EncodedCommand)
        try:
            u16 = raw.decode("utf-16le").strip()
            if u16 and any(c.isalnum() for c in u16):
                decoded_commands.append(u16)
        except Exception:
            pass
        # Try UTF-8
        try:
            u8 = raw.decode("utf-8").strip()
            if u8 and any(c.isalnum() for c in u8):
                if u8 not in decoded_commands:
                    decoded_commands.append(u8)
        except Exception:
            pass
    except Exception:
        pass
    return decoded_commands


def extract_base64_payloads(command_line: str) -> list[str]:
    """Extract and decode potential hidden base64 command wrappers from shell commands."""
    if not isinstance(command_line, str) or not command_line:
        return []

    payloads: list[str] = list(extract_ps_base64_payloads(command_line))
    patterns = [
        # PowerShell -EncodedCommand / -enc / -ec / -e (with - or / prefix)
        re.compile(
            r"(?:^|\s)[-/](?:encodedcommand|encodedcomman|encodedcomma|encodedcomm|encodedcom|encodedco|encodedc|encode|encod|enco|enc|ec|e)\s+[\"']?([A-Za-z0-9+/=]{4,})[\"']?",
            re.IGNORECASE,
        ),
        # Shell echo pipe to base64 -d / --decode
        re.compile(
            r"echo\s+[\"']?([A-Za-z0-9+/=]{4,})[\"']?\s*\|\s*base64(?:\.exe)?\s+-(?:d|-decode)",
            re.IGNORECASE,
        ),
        # [System.Convert]::FromBase64String("...")
        re.compile(
            r"FromBase64String\s*\(\s*[\"']([A-Za-z0-9+/=]{4,})[\"']\s*\)",
            re.IGNORECASE,
        ),
    ]

    found_tokens: set[str] = set()
    for pat in patterns:
        for match in pat.finditer(command_line):
            b64_str = match.group(1).strip()
            if b64_str and b64_str not in found_tokens:
                found_tokens.add(b64_str)
                decoded_variants = decode_base64_payload(b64_str)
                payloads.extend(decoded_variants)

    return list(dict.fromkeys(payloads))


def evaluate_dangerous_command(payload: dict[str, Any]) -> dict[str, Any]:
    """Scan proposed run_command CommandLine for dangerous patterns via hook_utils.

    Preserves raw context alongside multi-layer deobfuscated and decoded variants,
    performing multi-candidate cross-referencing to eliminate Raw Context Loss.
    """
    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""
    args = get_tool_args(tool_call)

    if tool_name != "run_command":
        return pre_tool_response("allow", "Tool is not run_command.")

    if not isinstance(args, dict):
        return pre_tool_response("allow", "Arguments is not a valid dict.")

    command_line = args.get("CommandLine", "")
    if not isinstance(command_line, str) or not command_line.strip():
        return pre_tool_response("allow", "Empty CommandLine argument.")

    validator = get_command_validator()

    # 1. Multi-pass deobfuscation (case preserved)
    cleaned_command = deobfuscate_command_string(command_line, apply_casefold=False)

    # 2. Unicode Case Folding variant
    casefolded_cleaned = cleaned_command.casefold()

    # 3. Base64 command wrapper extraction and deobfuscation
    b64_extracted = extract_base64_payloads(command_line) + extract_base64_payloads(cleaned_command)
    b64_cleaned = [deobfuscate_command_string(p, apply_casefold=False) for p in b64_extracted]
    b64_casefolded = [p.casefold() for p in b64_cleaned]

    # 4. Multi-dimensional evaluation candidates preserving raw context
    all_ps_variants = get_all_command_variants(command_line)
    for p in b64_extracted:
        all_ps_variants.extend(get_all_command_variants(p))

    evaluation_candidates = list(dict.fromkeys(
        [cleaned_command, casefolded_cleaned]
        + b64_cleaned
        + b64_casefolded
        + b64_extracted
        + [command_line, command_line.casefold()]
        + all_ps_variants
    ))

    # Evaluate across all candidates, prioritizing most restrictive decision:
    # 'deny' > 'force_ask' > 'allow'
    worst_decision = "allow"
    worst_reason = "Command passed dangerous pattern security scan."
    triggering_candidate = ""

    for candidate in evaluation_candidates:
        if not candidate or not candidate.strip():
            continue
        decision, reason = validator.evaluate_command_string(candidate)
        if decision == "deny":
            worst_decision = "deny"
            worst_reason = reason
            triggering_candidate = candidate
            break  # 'deny' is highest severity, immediately break
        elif decision == "force_ask" and worst_decision != "force_ask":
            worst_decision = "force_ask"
            worst_reason = reason
            triggering_candidate = candidate

    if worst_decision != "allow":
        log_diagnostic(
            f"Command Guard intervention [{worst_decision}]: raw='{command_line}' "
            f"(cleaned='{cleaned_command}', triggered_by='{triggering_candidate}') -> {worst_reason}"
        )

    return pre_tool_response(worst_decision, worst_reason)


def run_self_tests() -> bool:
    """Self-test runner covering deobfuscation and evasion patterns."""
    print("======================================================================")
    print("Running Dangerous Command Guard Self-Test Suite")
    print("======================================================================\n")

    # 1. Unit tests for deobfuscate_command_string
    deob_cases = [
        # Carets & quotes
        ("r^m -^r^f /", "rm -rf /"),
        ('r""m -r""f /', "rm -rf /"),
        ("r''m -r''f /", "rm -rf /"),
        ("d^e^l /f /s /q C:\\*", "del /f /s /q C:\\*"),
        ('g""i""t a^d^d .', "git add ."),
        # Zero-width chars
        ("r\u200bm -rf /", "rm -rf /"),
        ("r\ufeffm -rf /", "rm -rf /"),
        ("r\u200cm\u200d -rf /", "rm -rf /"),
        # BiDi & Formatting & Invisible
        ("r\u202am\u202c -rf /", "rm -rf /"),
        ("r\u202em -rf /", "rm -rf /"),
        ("r\u2060m -rf /", "rm -rf /"),
        ("r\u2061\u2062\u2063\u2064m -rf /", "rm -rf /"),
        ("r\u2066m\u2069 -rf /", "rm -rf /"),
        ("r\u034fm -rf /", "rm -rf /"),
        ("r\u00adm -rf /", "rm -rf /"),
        ("r\u180em -rf /", "rm -rf /"),
        # Fullwidth Unicode
        ("\uff52\uff4d -rf /", "rm -rf /"),
        # Multi-layer percent-encoding
        ("%252f", "/"),
        ("rm -rf %252f", "rm -rf /"),
        ("git%20add%20.", "git add ."),
        ("%2572%256d -rf /", "rm -rf /"),
        # Hex & Octal escapes
        (r"r\x6d -rf /", "rm -rf /"),
        (r"\x72\x6d -rf /", "rm -rf /"),
        (r"\162\155 -rf \057", "rm -rf /"),
        # Cross-Script Cyrillic homoglyphs
        ("git \u0430dd .", "git add ."),
        ("\u0441at /etc/passwd", "cat /etc/passwd"),
        ("d\u0435l /f /s /q C:\\*", "del /f /s /q C:\\*"),
        ("DRO\u0420 TABLE users;", "DROP TABLE users;"),
        # Cross-Script Greek homoglyphs
        ("dr\u03bfp table users;", "drop table users;"),
        ("git \u03b1dd .", "git add ."),
        # PowerShell backtick deobfuscation
        ("New-`Item -ItemType Sym`bolicLink", "New-Item -ItemType SymbolicLink"),
        # Nested multi-pass fixed point
        (r"r^'""'\x6d -rf %252f", "rm -rf /"),
    ]
    for raw, expected in deob_cases:
        res = deobfuscate_command_string(raw)
        assert res == expected, f"Deobfuscation failed: '{raw}' -> '{res}', expected '{expected}'"
        print(f"[PASS] Deobfuscation test: '{raw}' -> '{res}'")

    # Casefold test
    cf_res = deobfuscate_command_string("D^R^O^P T^A^B^L^E users;", apply_casefold=True)
    assert cf_res == "drop table users;", f"Casefold failed: '{cf_res}'"
    print(f"[PASS] Unicode Casefold test: 'D^R^O^P T^A^B^L^E users;' -> '{cf_res}'")

    # 2. Integration tests for evaluate_dangerous_command with obfuscated payloads
    obfuscated_eval_cases = [
        ("r^m -^r^f /", "force_ask"),
        ('r""m -r""f /', "force_ask"),
        ("r''m -r''f /", "force_ask"),
        ("git add\u200b .", "deny"),
        ("g^i^t a^d^d .", "deny"),
        ("D^R^O^P T^A^B^L^E users;", "force_ask"),
        ("\uff52\uff4d -rf /", "force_ask"),
        # Hex / Octal / Percent evasion
        (r"\x72\x6d -rf /", "force_ask"),
        (r"\162\155 -rf \057", "force_ask"),
        ("rm -rf %252f", "force_ask"),
        ("git%2520add%2520.", "deny"),
        # Invisible / BiDi evasion
        ("r\u202em -rf /", "force_ask"),
        ("r\u034fm -rf /", "force_ask"),
        # Homoglyphs evasion
        ("git \u0430dd .", "deny"),
        ("DR\u039fP TABLE users;", "force_ask"),
        ("DRO\u0420 TABLE users;", "force_ask"),
        # Base64 wrappers (PowerShell UTF-8 and UTF-16LE, Pipe)
        ("powershell -enc cm0gLXJmIC8=", "force_ask"),
        ("powershell.exe -EncodedCommand cgBtACAALQByAGYAIAAvAA==", "force_ask"),
        ("echo cm0gLXJmIC8= | base64 -d | sh", "force_ask"),
        ("powershell -ec Z2l0IGFkZCAu", "deny"),
        ("Safe command", "allow"),
    ]
    for cmd, expected_decision in obfuscated_eval_cases:
        actual_cmd = "echo safe" if cmd == "Safe command" else cmd
        resp = evaluate_dangerous_command({
            "toolCall": {"name": "run_command", "args": {"CommandLine": actual_cmd}}
        })
        actual = resp.get("decision")
        assert actual == expected_decision, f"Eval failed for '{cmd}': expected {expected_decision}, got {actual}"
        print(f"[PASS] Eval obfuscated payload: '{cmd}' -> {actual}")

    # 3. Comprehensive validator test suite
    validator = get_command_validator()
    val_ok = validator.run_self_test()
    assert val_ok, "Validator self test failed"

    print("\n[SELF-TEST] dangerous_command_guard.py: All tests PASSED with 100% success!")
    return True


def main() -> None:
    if "--self-test" in sys.argv:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    payload = read_stdin_payload(default={})
    response = evaluate_dangerous_command(payload)
    emit_stdout_json(response)


if __name__ == "__main__":
    main()
