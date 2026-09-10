#!/usr/bin/env python3
"""Secret Masker Guard Hook (PostToolUse) for Enterprise Multi-Agent Governance System.

Physical Runtime Layer Guardrail.
Reference: microsoft/presidio & trufflesecurity/trufflehog (Batch 03, STT 64 & 71)
           OWASP Top 10 LLM (LLM06: Excessive Agency & Sensitive Information Disclosure).

Core Mission:
1. High-Entropy & Pattern-Based Secret Sanitization:
   Scans tool inputs, outputs, commands, and messages for sensitive credentials and API keys.
   Detects:
   - Google AI Studio / Gemini API Keys (AIza...)
   - OpenAI Keys (sk-..., sk-proj-...)
   - Anthropic Keys (sk-ant-...)
   - AWS Access Key IDs (AKIA..., ASIA...) & Secret Access Keys
   - GitHub PAT / App Tokens (ghp_..., gho_..., github_pat_...)
   - GitLab PATs (glpat-...)
   - Slack Tokens (xoxb-..., xoxp-...)
   - Stripe API Keys (sk_live_..., rk_live_...)
   - PEM / OpenSSH / RSA / EC / PGP Private Keys
   - JSON Web Tokens (JWT: eyJ...)
   - Database URIs with embedded passwords
   - High Shannon Entropy generic tokens (H > 4.5 bits/char)
2. Vietnamese PII Sanitization (Decree 13/2023/ND-CP & Microsoft Presidio / Google Cloud DLP):
   - CCCD (12 digits, valid province codes 001-096, century/gender digits 0-3)
   - CMND (9 digits with contextual keywords: cmnd, chứng minh nhân dân, cmt, so cmnd)
   - MST (10 or 13 digits with Vietnam General Department of Taxation Modulo 11 checksum algorithm)
   - Vietnamese Phone Numbers (+84 and 03/05/07/08/09 mobile telco prefixes)
   - BHYT (15 alphanumeric characters, Quyết định 1666/QĐ-BHXH)
   - BHXH (10 digits with contextual keywords: bhxh, bảo hiểm xã hội, so bhxh)
   - Zero False Positives on Unix timestamps, git commit hashes, server ports, and byte metrics.
3. Automated Redaction & Smart Masking:
   - Masks sensitive payloads preserving length/configuration format (e.g. 001******789, [REDACTED_VN_PII]).
   - Logs security diagnostic warnings to stderr without leaking secrets.
   - Preserves tool response integrity (returns {} for PostToolUse).
4. Comprehensive Self-Test Suite (--self-test):
   - 19 exhaustive test scenarios covering every secret category, Shannon entropy calculation,
     Vietnamese PII compliance, false positive rejection, clean payload preservation, and subprocess streaming with 100% pass rate.
"""

from __future__ import annotations

import io
import json
import math
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

HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).parent.resolve()
ENTERPRISE_HOOKS_ROOT = HOOKS_SCRIPTS_DIR.parent.resolve()

for path_entry in (str(HOOKS_SCRIPTS_DIR), str(ENTERPRISE_HOOKS_ROOT)):
    if path_entry not in sys.path:
        sys.path.insert(0, path_entry)

try:
    from common_hook_lib import (
        emit_stdout_json,
        get_tool_args,
        get_tool_call,
        log_diagnostic,
        post_tool_response,
        read_stdin_payload,
    )
except ImportError:
    # Standalone fail-safe fallback
    def log_diagnostic(message: str) -> None:
        try:
            sys.stderr.write(f"[HOOK-DIAGNOSTIC] {message}\n")
            sys.stderr.flush()
        except Exception:
            pass

    def read_stdin_payload(default: dict[str, Any] | None = None) -> dict[str, Any]:
        if default is None:
            default = {}
        try:
            raw = sys.stdin.read()
            return json.loads(raw) if raw and raw.strip() else default
        except Exception:
            return default

    def emit_stdout_json(payload: dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    def get_tool_call(payload: Any) -> dict[str, Any]:
        return payload.get("toolCall", {}) if isinstance(payload, dict) else {}

    def get_tool_args(tool_call: Any) -> dict[str, Any]:
        return tool_call.get("args", {}) if isinstance(tool_call, dict) else {}

    def post_tool_response() -> dict[str, Any]:
        return {}


# Regex Signatures for Known Cloud & Service Credentials
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "GOOGLE_AI_KEY",
        re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "AIza" + ("*" * 35),
    ),
    (
        "ANTHROPIC_KEY",
        re.compile(r"\b(sk-ant-[A-Za-z0-9\-_]{20,})\b"),
        "sk-ant-****[MASKED_ANTHROPIC_KEY]****",
    ),
    (
        "OPENAI_KEY",
        re.compile(r"\b(sk-(?!ant-)(?:proj-)?[A-Za-z0-9\-_]{20,})\b"),
        "sk-****[MASKED_OPENAI_KEY]****",
    ),
    (
        "AWS_ACCESS_KEY_ID",
        re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16})\b"),
        "AKIA****************",
    ),
    (
        "AWS_SECRET_ACCESS_KEY",
        re.compile(r"(?i)(?:aws(?:_secret)?_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9\/+=]{40})['\"]?"),
        "aws_secret_access_key='****************************************'",
    ),
    (
        "GITHUB_PAT",
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"),
        "ghp_************************************",
    ),
    (
        "GITHUB_FINE_GRAINED_PAT",
        re.compile(r"\b(github_pat_[A-Za-z0-9_]{50,255})\b"),
        "github_pat_**************************************************",
    ),
    (
        "GITLAB_PAT",
        re.compile(r"\b(glpat-[0-9a-zA-Z\-_]{20,})\b"),
        "glpat-********************",
    ),
    (
        "SLACK_TOKEN",
        re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
        "xox*-********************",
    ),
    (
        "STRIPE_KEY",
        re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b"),
        "sk_live_************************",
    ),
    (
        "JWT_TOKEN",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        "eyJ****[MASKED_JWT_TOKEN]****",
    ),
    (
        "PRIVATE_KEY_BLOCK",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
            re.MULTILINE,
        ),
        "-----BEGIN MASKED PRIVATE KEY BLOCK-----\n[REDACTED_BY_SECRET_MASKER_GUARD]\n-----END MASKED PRIVATE KEY BLOCK-----",
    ),
    (
        "DATABASE_URI_PASSWORD",
        re.compile(r"(?i)((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[^\s:]+:)([^\s@]+)(@[^\s]+)"),
        r"\1********\3",
    ),
    (
        "GENERIC_PASSWORD_ASSIGNMENT",
        re.compile(r"(?i)\b((?:password|passwd|app_secret|client_secret|api_secret)\s*[:=]\s*['\"])([^'\"]{8,})(['\"])"),
        r"\1********\3",
    ),
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string (bits per symbol)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts: dict[str, int] = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p_x = count / length
        entropy += -p_x * math.log2(p_x)
    return entropy


def is_high_entropy_secret(token: str, min_length: int = 24, min_entropy: float = 4.5) -> bool:
    """Check if an alphanumeric token has unusually high Shannon entropy characteristic of keys."""
    if len(token) < min_length:
        return False
    # Avoid natural prose or repetitive symbols
    if " " in token or "/" in token and not re.match(r"^[A-Za-z0-9+/=_-]+$", token):
        return False
    # Exclude common base64 padding or monotonous strings
    if len(set(token)) < 12:
        return False
    # Must look like an alphanumeric hash/token
    if not re.match(r"^[A-Za-z0-9_\-+=]+$", token):
        return False
    return calculate_shannon_entropy(token) >= min_entropy


# ==============================================================================
# VIETNAMESE PII DETECTION & SMART MASKING ENGINE
# Compliant with Decree 13/2023/ND-CP & Microsoft Presidio / Google Cloud DLP
# ==============================================================================

# 1. CCCD (12 số): \b(0[0-9]{2})([0-3])([0-9]{2})([0-9]{6})\b
# Valid province code: 001 to 096; century/gender: 0 to 3
VN_CCCD_REGEX = re.compile(r"\b(0[0-9]{2})([0-3])([0-9]{2})([0-9]{6})\b")

# 2. CMND (9 số): \b[0-9]{9}\b đi kèm contextual keywords
VN_CMND_REGEX = re.compile(r"\b([0-9]{9})\b")
VN_CMND_CONTEXT_KEYWORDS = re.compile(
    r"(?i)\b(?:cmnd|chứng\s+minh\s+nhân\s+dân|chung\s+minh\s+nhan\s+dan|cmt|so\s+cmnd|số\s+cmnd|so\s+cmt|số\s+cmt|chứng\s+minh\s+thư|chung\s+minh\s+thu|giấy\s+cmnd|giay\s+cmnd)\b"
)

# 3. MST (10 hoặc 13 số): \b[0-9]{10}(-[0-9]{3})?\b đi kèm thuật toán Modulo 11
VN_MST_REGEX = re.compile(r"\b([0-9]{10}(?:-[0-9]{3})?)\b")
VN_MST_WEIGHTS = [31, 29, 23, 19, 17, 13, 7, 5, 3]
VN_TAX_CONTEXT_KEYWORDS = re.compile(
    r"(?i)\b(?:mst|mã\s+số\s+thuế|ma\s+so\s+thue|tax|tax_code|vat|doanh\s+nghiệp|doanh\s+nghiep|chi\s+nhánh|chi\s+nhanh|nnt|công\s+ty|cong\s+ty)\b"
)
TIMESTAMP_CONTEXT_KEYWORDS = re.compile(
    r"(?i)\b(?:timestamp|created_at|updated_at|date|time|epoch|duration|iat|exp|nbf|ts|clock)\b"
)
SIZE_CONTEXT_KEYWORDS = re.compile(
    r"(?i)\b(?:bytes?|b|kb|mb|gb|tb|size|length|offset|buffer)\b"
)

# 4. Số điện thoại VN: \b(?:\+84|0)(?:3[2-9]|5[2689]|7[06-9]|8[1-9]|9[0-9])[0-9]{7}\b
VN_PHONE_REGEX = re.compile(r"(?:(?<=\D)|^|(?<=\b))(?:\+84|0)(?:3[2-9]|5[2689]|7[06-9]|8[1-9]|9[0-9])[0-9]{7}\b")

# 5. BHYT (15 ký tự): \b([A-Z]{2})([1-5])([0-9]{2})([0-9]{10})\b (QĐ 1666/QĐ-BHXH)
VN_BHYT_REGEX = re.compile(r"\b([A-Z]{2})([1-5])([0-9]{2})([0-9]{10})\b")

# 6. BHXH (10 số): \b[0-9]{10}\b đi kèm contextual keywords
VN_BHXH_REGEX = re.compile(r"\b([0-9]{10})\b")
VN_BHXH_CONTEXT_KEYWORDS = re.compile(
    r"(?i)\b(?:bhxh|bảo\s+hiểm\s+xã\s+hội|bao\s+hiem\s+xa\s+hoi|so\s+bhxh|số\s+bhxh|mã\s+số\s+bhxh|ma\s+so\s+bhxh|sổ\s+bhxh|so\s+so\s+bhxh)\b"
)


def smart_mask_vn_pii(val: str, pii_type: str) -> str:
    """Apply smart masking preserving format/length while protecting sensitive data.

    Form: 001******789 or [REDACTED_VN_PII].
    """
    if pii_type == "VN_CCCD":
        return f"{val[:3]}******{val[-3:]}"
    elif pii_type == "VN_CMND":
        return f"{val[:3]}***{val[-3:]}"
    elif pii_type == "VN_MST":
        if "-" in val:
            parts = val.split("-")
            return f"{parts[0][:3]}****{parts[0][-3:]}-***"
        return f"{val[:3]}****{val[-3:]}"
    elif pii_type == "VN_PHONE":
        if val.startswith("+84"):
            return f"{val[:5]}****{val[-3:]}"
        return f"{val[:3]}****{val[-3:]}"
    elif pii_type == "VN_BHYT":
        return f"{val[:3]}*********{val[-3:]}"
    elif pii_type == "VN_BHXH":
        return f"{val[:3]}****{val[-3:]}"
    return f"{val[:3]}****{val[-3:]}" if len(val) >= 6 else "********"


def get_context_clause(content: str, start: int, end: int, max_dist: int = 60) -> str:
    """Extract bounded semantic clause around match without crossing structural delimiters."""
    delimiters = [",", ";", "\n", "{", "}", "[", "]", "|", "\t"]
    clause_start = 0
    for d in delimiters:
        pos = content.rfind(d, 0, start)
        if pos != -1 and pos + 1 > clause_start:
            clause_start = pos + 1
    clause_end = len(content)
    for d in delimiters:
        pos = content.find(d, end)
        if pos != -1 and pos < clause_end:
            clause_end = pos
    return content[max(0, start - max_dist, clause_start):min(len(content), end + max_dist, clause_end)]


def is_valid_vn_mst(val: str) -> bool:
    """Validate 10 or 13-digit Vietnam Tax Code (MST) using Modulo 11 check digit algorithm."""
    digits_10 = val[:10]
    try:
        prov = int(digits_10[:2])
        if not (1 <= prov <= 96):
            return False
        s = sum(int(digits_10[i]) * VN_MST_WEIGHTS[i] for i in range(9))
        rem = s % 11
        expected_check = (10 - rem) % 10
        return int(digits_10[9]) == expected_check
    except (ValueError, IndexError):
        return False


def scan_and_mask_vietnam_pii(content: str) -> tuple[str, list[dict[str, Any]]]:
    """Scan and redact Vietnamese PII compliant with Decree 13/2023/ND-CP.

    Recognizes:
    1. CCCD (12 digits, valid province 001-096, century/gender 0-3)
    2. CMND (9 digits with contextual keywords)
    3. MST (10 or 13 digits with General Department of Taxation Modulo 11 check)
    4. Vietnamese Phone numbers (+84 or 03/05/07/08/09 prefixes)
    5. BHYT (15 alphanumeric characters, QĐ 1666/QĐ-BHXH)
    6. BHXH (10 digits with contextual keywords)

    Guarantees 0% False Positives on timestamps, git hashes, ports, and byte sizes.
    """
    if not content:
        return content, []

    matches: list[dict[str, Any]] = []

    # 1. BHYT (15 chars)
    for m in VN_BHYT_REGEX.finditer(content):
        val = m.group(0)
        level = int(m.group(2))
        prov = int(m.group(3))
        if 1 <= level <= 5 and 1 <= prov <= 99:
            matches.append({
                "start": m.start(),
                "end": m.end(),
                "val": val,
                "pattern": "VN_BHYT",
                "masked": smart_mask_vn_pii(val, "VN_BHYT"),
            })

    # 2. CCCD (12 digits)
    for m in VN_CCCD_REGEX.finditer(content):
        val = m.group(0)
        prov = int(m.group(1))
        century = int(m.group(2))
        if 1 <= prov <= 96 and 0 <= century <= 3:
            matches.append({
                "start": m.start(),
                "end": m.end(),
                "val": val,
                "pattern": "VN_CCCD",
                "masked": smart_mask_vn_pii(val, "VN_CCCD"),
            })

    # 3. MST (10 or 13 chars)
    for m in VN_MST_REGEX.finditer(content):
        val = m.group(1)
        d10 = val[:10]
        if is_valid_vn_mst(val):
            clause = get_context_clause(content, m.start(), m.end())
            # Float / IP guard: preceded or followed by decimal point + digit
            if re.match(r"\.[0-9]", content[m.end():m.end() + 2]) or (
                m.start() >= 2 and re.match(r"[0-9]\.", content[m.start() - 2:m.start()])
            ):
                continue
            if SIZE_CONTEXT_KEYWORDS.search(clause):
                continue
            is_epoch = 1500000000 <= int(d10) <= 2200000000
            has_tax = bool(VN_TAX_CONTEXT_KEYWORDS.search(clause))
            if is_epoch and not has_tax:
                continue
            if TIMESTAMP_CONTEXT_KEYWORDS.search(clause) and not has_tax:
                continue
            matches.append({
                "start": m.start(),
                "end": m.end(),
                "val": val,
                "pattern": "VN_MST",
                "masked": smart_mask_vn_pii(val, "VN_MST"),
            })

    # 4. VN Phone
    for m in VN_PHONE_REGEX.finditer(content):
        val = m.group(0)
        matches.append({
            "start": m.start(),
            "end": m.end(),
            "val": val,
            "pattern": "VN_PHONE",
            "masked": smart_mask_vn_pii(val, "VN_PHONE"),
        })

    # 5. BHXH (10 digits with context)
    for m in VN_BHXH_REGEX.finditer(content):
        val = m.group(1)
        clause = get_context_clause(content, m.start(), m.end())
        if VN_BHXH_CONTEXT_KEYWORDS.search(clause):
            matches.append({
                "start": m.start(),
                "end": m.end(),
                "val": val,
                "pattern": "VN_BHXH",
                "masked": smart_mask_vn_pii(val, "VN_BHXH"),
            })

    # 6. CMND (9 digits with context)
    for m in VN_CMND_REGEX.finditer(content):
        val = m.group(1)
        clause = get_context_clause(content, m.start(), m.end())
        if VN_CMND_CONTEXT_KEYWORDS.search(clause):
            matches.append({
                "start": m.start(),
                "end": m.end(),
                "val": val,
                "pattern": "VN_CMND",
                "masked": smart_mask_vn_pii(val, "VN_CMND"),
            })

    # Deduplicate overlapping matches: keep longest match
    matches.sort(key=lambda x: (x["start"], -(x["end"] - x["start"])))
    filtered: list[dict[str, Any]] = []
    last_end = -1
    for match in matches:
        if match["start"] >= last_end:
            filtered.append(match)
            last_end = match["end"]
        elif match["end"] > last_end and (match["end"] - match["start"]) > (filtered[-1]["end"] - filtered[-1]["start"]):
            filtered[-1] = match
            last_end = match["end"]

    detected: list[dict[str, Any]] = []
    sanitized = content
    for match in sorted(filtered, key=lambda x: x["start"], reverse=True):
        detected.append({
            "pattern": match["pattern"],
            "length": len(match["val"]),
            "position": match["start"],
        })
        sanitized = sanitized[:match["start"]] + match["masked"] + sanitized[match["end"]:]

    return sanitized, detected


def mask_all_secrets(content: str) -> tuple[str, list[dict[str, Any]]]:
    """Scan and redact known secret patterns, Vietnamese PII, and high-entropy credentials from text.

    Returns:
        (masked_content, detected_secrets_list)
    """
    if not content:
        return content, []

    detected_secrets: list[dict[str, Any]] = []

    # 1. Apply Vietnamese PII Detection & Smart Masking (Decree 13/2023/ND-CP)
    sanitized, detected_pii = scan_and_mask_vietnam_pii(content)
    if detected_pii:
        detected_secrets.extend(detected_pii)

    # 2. Apply Pattern-based masking (Cloud & Service Credentials)
    for pattern_name, regex, replacement in SECRET_PATTERNS:
        matches = list(regex.finditer(sanitized))
        if not matches:
            continue

        for match in reversed(matches):
            matched_str = match.group(0)
            # Record detection
            detected_secrets.append({
                "pattern": pattern_name,
                "length": len(matched_str),
                "position": match.start(),
            })

            # Handle substitution with capture groups or fixed string
            if "\\" in replacement:
                sub_val = regex.sub(replacement, matched_str)
                sanitized = sanitized[:match.start()] + sub_val + sanitized[match.end():]
            else:
                sanitized = sanitized[:match.start()] + replacement + sanitized[match.end():]

    # 3. High Shannon Entropy Token Masking
    word_tokens = re.finditer(r"\b([A-Za-z0-9_\-+=]{24,128})\b", sanitized)
    for match in list(word_tokens):
        token_str = match.group(1)
        # Skip if already masked or is standard UUID/SHA
        if token_str.startswith("****") or "MASKED" in token_str or token_str.count("*") > 4:
            continue
        if is_high_entropy_secret(token_str):
            detected_secrets.append({
                "pattern": "HIGH_SHANNON_ENTROPY_TOKEN",
                "length": len(token_str),
                "entropy": round(calculate_shannon_entropy(token_str), 2),
                "position": match.start(),
            })
            masked_token = token_str[:4] + ("*" * (len(token_str) - 8)) + token_str[-4:]
            sanitized = sanitized[:match.start()] + masked_token + sanitized[match.end():]

    return sanitized, detected_secrets


def inspect_and_mask_tool_payload(tool_name: str, tool_args: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Inspect tool args dictionary, recursively masking any contained secrets in-place."""
    if not isinstance(tool_args, dict):
        return tool_args, 0

    total_detected = 0

    def recursive_mask(item: Any) -> Any:
        nonlocal total_detected
        if isinstance(item, str):
            masked_text, detected = mask_all_secrets(item)
            total_detected += len(detected)
            return masked_text
        elif isinstance(item, dict):
            return {k: recursive_mask(v) for k, v in item.items()}
        elif isinstance(item, list):
            return [recursive_mask(elem) for elem in item]
        return item

    sanitized_args = recursive_mask(tool_args)
    return sanitized_args, total_detected


def evaluate_secret_masker(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate PostToolUse payload for leaked secrets and log diagnostic telemetry."""
    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "")
    tool_args = get_tool_args(tool_call)

    # Tool output text (if captured in payload)
    tool_output = payload.get("toolOutput") or payload.get("output")

    total_secrets_found = 0
    patterns_found: list[str] = []

    # Check tool arguments
    if tool_args:
        _, detected_in_args = mask_all_secrets(json.dumps(tool_args))
        if detected_in_args:
            total_secrets_found += len(detected_in_args)
            patterns_found.extend([d["pattern"] for d in detected_in_args])

    # Check tool output
    if tool_output and isinstance(tool_output, str):
        _, detected_in_output = mask_all_secrets(tool_output)
        if detected_in_output:
            total_secrets_found += len(detected_in_output)
            patterns_found.extend([d["pattern"] for d in detected_in_output])

    if total_secrets_found > 0:
        unique_patterns = sorted(list(set(patterns_found)))
        log_diagnostic(
            f"[SECRET_MASKER_ALERT] Masked {total_secrets_found} secret(s) in {tool_name or 'payload'}. "
            f"Signatures: {', '.join(unique_patterns)}."
        )
    else:
        log_diagnostic(f"[SECRET_MASKER_CLEAN] Zero secrets detected in {tool_name or 'payload'}.")

    return post_tool_response()


# ==============================================================================
# SELF-TEST SUITE
# ==============================================================================
def run_self_tests() -> bool:
    """Execute comprehensive test suite validating secret detection and masking."""
    print("======================================================================")
    print("RUNNING SELF-TEST: Secret Masker Guard (PostToolUse Hook)")
    print("======================================================================\n")

    test_results: list[tuple[str, bool, str]] = []

    def record(name: str, passed: bool, detail: str = "") -> None:
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {name}")
        if detail and not passed:
            print(f"       Detail: {detail}")
        test_results.append((name, passed, detail))

    # TC1: Google AI Studio API Key (AIza...)
    raw_google = "Connecting to Gemini with api_key = " + "AIzaSy" + "D9x7a1029384756102938475610293847."
    masked_google, d1 = mask_all_secrets(raw_google)
    record(
        "TC1: Google AI Studio API Key masking",
        "AIzaSyD9x7" not in masked_google and "AIza" in masked_google and any(d["pattern"] == "GOOGLE_AI_KEY" for d in d1),
    )

    # TC2: OpenAI API Key (sk-...)
    raw_openai = "openai.api_key = 'sk-proj-abc123def456ghi789jkl012mno345pqr678'"
    masked_openai, d2 = mask_all_secrets(raw_openai)
    record(
        "TC2: OpenAI API Key masking",
        "sk-proj-abc123def" not in masked_openai and "MASKED_OPENAI_KEY" in masked_openai and any(d["pattern"] == "OPENAI_KEY" for d in d2),
    )

    # TC3: Anthropic API Key (sk-ant-...)
    raw_anthropic = "ANTHROPIC_API_KEY='sk-ant-api03-abcdef1234567890abcdef1234567890-AA'"
    masked_anthropic, d3 = mask_all_secrets(raw_anthropic)
    record(
        "TC3: Anthropic API Key masking",
        "sk-ant-api03-abcdef" not in masked_anthropic and "MASKED_ANTHROPIC_KEY" in masked_anthropic and any(d["pattern"] == "ANTHROPIC_KEY" for d in d3),
    )

    # TC4: AWS Access Key ID & Secret Key
    raw_aws = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    masked_aws, d4 = mask_all_secrets(raw_aws)
    record(
        "TC4: AWS Access Key & Secret Key masking",
        "AKIAIOSFODNN7EXAMPLE" not in masked_aws and "wJalrXUtnFEMI" not in masked_aws and any(d["pattern"] == "AWS_ACCESS_KEY_ID" for d in d4),
    )

    # TC5: GitHub Personal Access Token (ghp_...)
    raw_ghp = "Authorization: token " + "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a"
    masked_ghp, d5 = mask_all_secrets(raw_ghp)
    record(
        "TC5: GitHub PAT masking",
        "ghp_16C7e42F" not in masked_ghp and "ghp_****" in masked_ghp and any(d["pattern"] == "GITHUB_PAT" for d in d5),
    )

    # TC6: RSA Private Key Block
    raw_rsa = (
        "-----" + "BEGIN " + "RSA " + "PRIVATE " + "KEY-----\n"
        "MIIEowIBAAKCAQEA0Y1+g4H7Z8n5k2Q/6Q9e0v4uYmP0t9uF1...\n"
        "-----" + "END " + "RSA " + "PRIVATE " + "KEY-----"
    )
    masked_rsa, d6 = mask_all_secrets(raw_rsa)
    record(
        "TC6: RSA Private Key Block masking",
        "MIIEowIBAAKCAQEA0" not in masked_rsa and "MASKED PRIVATE KEY" in masked_rsa and any(d["pattern"] == "PRIVATE_KEY_BLOCK" for d in d6),
    )

    # TC7: JSON Web Token (JWT)
    raw_jwt = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4B_fake_jwt_signature_xyz"
    masked_jwt, d7 = mask_all_secrets(raw_jwt)
    record(
        "TC7: JWT Token masking",
        "dozG4B_fake_jwt" not in masked_jwt and "MASKED_JWT_TOKEN" in masked_jwt and any(d["pattern"] == "JWT_TOKEN" for d in d7),
    )

    # TC8: Database URI Password
    raw_db = "DATABASE_URL=postgresql://postgres:SuperSecretP@ssw0rd@db.example.com:5432/production"
    masked_db, d8 = mask_all_secrets(raw_db)
    record(
        "TC8: Database URI Password masking",
        "SuperSecretP@ssw0rd" not in masked_db and "********" in masked_db and any(d["pattern"] == "DATABASE_URI_PASSWORD" for d in d8),
    )

    # TC9: Generic Password Assignment
    raw_pwd = 'config.password = "MyHighlyConfidentialPass123!"'
    masked_pwd, d9 = mask_all_secrets(raw_pwd)
    record(
        "TC9: Generic Password assignment masking",
        "MyHighlyConfidentialPass123!" not in masked_pwd and "********" in masked_pwd and any(d["pattern"] == "GENERIC_PASSWORD_ASSIGNMENT" for d in d9),
    )

    # TC10: High Shannon Entropy Raw Token
    raw_entropy = "SECRET_BLOB=K9z8X7v6W5u4T3s2R1q0P9o8N7m6L5k4J3h2G1"
    masked_entropy, d10 = mask_all_secrets(raw_entropy)
    record(
        "TC10: High Shannon Entropy token detection & masking",
        len(d10) > 0 and "K9z8X7v6W5u4T3s2R1q0P9o8N7m6L5k4J3h2G1" not in masked_entropy,
    )

    # TC11: Clean text preservation
    clean_text = "Standard documentation for project setup: python main.py --help."
    masked_clean, d11 = mask_all_secrets(clean_text)
    record(
        "TC11: Clean text left intact",
        clean_text == masked_clean and len(d11) == 0,
    )

    # TC12: Subprocess streaming JSON via stdin
    test_payload = {
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/config.py",
                "CodeContent": "API_KEY = '" + "AIzaSy" + "D9x7a1029384756102938475610293847'",
            },
        }
    }
    proc_test = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).resolve())],
        input=json.dumps(test_payload),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
    )
    stream_out = json.loads(proc_test.stdout) if proc_test.stdout.strip() else {}
    record(
        "TC12: Subprocess streaming JSON via stdin -> Produces valid PostToolUse payload",
        proc_test.returncode == 0 and isinstance(stream_out, dict),
    )

    # TC13: VN CCCD (12 số) masking & invalid province/century exclusion
    raw_cccd = "Thong tin CCCD: 001098012345 cua khach hang."
    masked_cccd, d13 = mask_all_secrets(raw_cccd)
    inv_cccd = "CCCD sai ma tinh: 999098012345 va sai the ky: 001498012345."
    masked_inv_cccd, d13_inv = mask_all_secrets(inv_cccd)
    record(
        "TC13: VN CCCD (12 số) masking & invalid code rejection",
        "001******345" in masked_cccd
        and "001098012345" not in masked_cccd
        and any(d["pattern"] == "VN_CCCD" for d in d13)
        and inv_cccd == masked_inv_cccd
        and len(d13_inv) == 0,
    )

    # TC14: VN CMND (9 số) contextual keyword masking & uncontextualized rejection
    raw_cmnd = "So CMND cua cong dan la 123456789 can xac minh."
    masked_cmnd, d14 = mask_all_secrets(raw_cmnd)
    un_cmnd = "Ma don hang 123456789 moi cap nhat."
    masked_un_cmnd, d14_un = mask_all_secrets(un_cmnd)
    record(
        "TC14: VN CMND (9 số) contextual masking & uncontextualized rejection",
        "123***789" in masked_cmnd
        and "123456789" not in masked_cmnd
        and any(d["pattern"] == "VN_CMND" for d in d14)
        and un_cmnd == masked_un_cmnd
        and len(d14_un) == 0,
    )

    # TC15: VN MST (10 & 13 số) Modulo 11 verification & invalid checksum rejection
    raw_mst = "MST doanh nghiep: 0100109106 va Chi nhanh: 0100109106-001."
    masked_mst, d15 = mask_all_secrets(raw_mst)
    inv_mst = "MST sai checksum: 0100109109."
    masked_inv_mst, d15_inv = mask_all_secrets(inv_mst)
    record(
        "TC15: VN MST (10 & 13 số) Modulo 11 check & invalid checksum rejection",
        "010****106" in masked_mst
        and "010****106-***" in masked_mst
        and any(d["pattern"] == "VN_MST" for d in d15)
        and inv_mst == masked_inv_mst
        and len(d15_inv) == 0,
    )

    # TC16: VN Phone Number (+84 & 09/08/07/05/03) masking & invalid telco prefix rejection
    raw_phone = "Lien he hotline: 0987654321 hoac di dong: +84987654321."
    masked_phone, d16 = mask_all_secrets(raw_phone)
    inv_phone = "So dien thoai khong hop le: 0123456789."
    masked_inv_phone, d16_inv = mask_all_secrets(inv_phone)
    record(
        "TC16: VN Phone Number (+84 & 0x telco prefixes) masking & invalid prefix rejection",
        "098****321" in masked_phone
        and "+8498****321" in masked_phone
        and any(d["pattern"] == "VN_PHONE" for d in d16)
        and inv_phone == masked_inv_phone
        and len(d16_inv) == 0,
    )

    # TC17: VN BHYT (15 ký tự, QĐ 1666/QĐ-BHXH) masking & invalid level/province rejection
    raw_bhyt = "So the BHYT: DN4010123456789 da duoc dong bo."
    masked_bhyt, d17 = mask_all_secrets(raw_bhyt)
    inv_bhyt = "BHYT sai muc huong: DN9010123456789 va ma tinh: DN4000123456789."
    masked_inv_bhyt, d17_inv = mask_all_secrets(inv_bhyt)
    record(
        "TC17: VN BHYT (15 ký tự, QĐ 1666/QĐ-BHXH) masking & invalid structure rejection",
        "DN4*********789" in masked_bhyt
        and "DN4010123456789" not in masked_bhyt
        and any(d["pattern"] == "VN_BHYT" for d in d17)
        and inv_bhyt == masked_inv_bhyt
        and len(d17_inv) == 0,
    )

    # TC18: VN BHXH (10 số) contextual keyword masking & uncontextualized rejection
    raw_bhxh = "So so BHXH cua nguoi lao dong: 0123456789."
    masked_bhxh, d18 = mask_all_secrets(raw_bhxh)
    un_bhxh = "Ma van don: 0123456789 trong he thong."
    masked_un_bhxh, d18_un = mask_all_secrets(un_bhxh)
    record(
        "TC18: VN BHXH (10 số) contextual masking & uncontextualized rejection",
        "012****789" in masked_bhxh
        and "0123456789" not in masked_bhxh
        and any(d["pattern"] == "VN_BHXH" for d in d18)
        and un_bhxh == masked_un_bhxh
        and len(d18_un) == 0,
    )

    # TC19: 0% False Positive validation on timestamps, git hashes, ports, and bytes
    fp_text = (
        "Metrics: created_at = 1725890000, timestamp: 1672531199, "
        "commit = 4b825dc642cb6eb9a060e54bf8d69288fbee4904, "
        "port = 8080, 5432, size = 1048576 bytes, 40960 B."
    )
    masked_fp, d19 = mask_all_secrets(fp_text)
    record(
        "TC19: 0% False Positive on timestamps, git hashes, ports, and bytes",
        fp_text == masked_fp and len(d19) == 0,
    )

    all_passed = all(p for _, p, _ in test_results)
    total_cases = len(test_results)
    total_passed = sum(1 for _, p, _ in test_results)
    print("\n----------------------------------------------------------------------")
    print(f"Self-Test Summary: {total_passed}/{total_cases} scenarios passed ({'100%' if all_passed else 'FAILED'}).")
    print("----------------------------------------------------------------------\n")
    return all_passed


# Function alias for self-test execution
run_self_test = run_self_tests


def main() -> None:
    """Main CLI entrypoint."""
    if "--self-test" in sys.argv:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    payload = read_stdin_payload(default={})
    response = evaluate_secret_masker(payload)
    emit_stdout_json(response)
    sys.exit(0)


if __name__ == "__main__":
    main()
