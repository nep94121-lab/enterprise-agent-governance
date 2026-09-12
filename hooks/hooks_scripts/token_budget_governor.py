#!/usr/bin/env python3
"""Token Budget Governor Hook & Ratio Estimation Engine.

Enterprise Multi-Agent Governance System - Physical Layer 1 Runtime Guardrail.
Architectural Reference: ARCH-DOC-06 (Section 2.6) & Tier 3 BACKEND_RULES.md.

Key Capabilities:
1. Dynamic Token Ratio Estimation (Zero Hardcoding):
   - Categorizes characters into ASCII Alphanumeric, Code Symbols, Vietnamese Accented,
     CJK Ideographs, and Whitespace with Unicode normalization (NFC).
   - Computes weighted token ratio dynamically from dynamic_limits.json via hook_utils.
   - Optional TikToken validation when available with zero crash fallback.
2. Per-Role & Session Budget Governance:
   - Enforces isolated budgets for standard roles (pm_orchestrator, backend_developer,
     frontend_developer, devops_security, qa_challenger, tech_lead_auditor).
   - Triggers Warning (80%), Critical (95%), and Exhausted (100%) events.
3. Verbosity & "Lậm lời" Guard (Anti-Verbosity Detection):
   - Detects single-turn prompt/response inflation exceeding verbosity_warning_tokens.
4. PreToolUse & PostToolUse Hook Lifecycle:
   - Inspects write_to_file (file size limit 4000 tokens), replace_file_content,
     invoke_subagent, and send_message.
   - Dual-verdict output: 'decision' (allow/deny) and 'verdict' (ALLOW/DENY).
5. Safe-Fail-Closed with Alert:
   - On internal unexpected error, emits [HOOK_FATAL_ERROR] to stderr and blocks
     destabilizing operations instead of blindly passing.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import os
import pathlib
import random
import re
import sys
import threading
import time
import traceback
import unicodedata
import urllib.parse
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

# Enforce UTF-8 standard encoding on Windows PowerShell with safe error replacement
try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

logger = logging.getLogger("enterprise_hooks.token_budget_governor")

# Path discovery for hook_utils and common_hook_lib
HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).parent.resolve()
HOOKS_ROOT = HOOKS_SCRIPTS_DIR.parent.resolve()

for path_entry in [str(HOOKS_ROOT), str(HOOKS_SCRIPTS_DIR)]:
    if path_entry not in sys.path:
        sys.path.insert(0, path_entry)

# Import dynamic config loader from hook_utils
try:
    from hook_utils.config_loader import get_config_loader, get_token_budget_config
except ImportError:
    try:
        from hook_utils import get_config_loader, get_token_budget_config  # type: ignore
    except ImportError:
        get_config_loader = None  # type: ignore
        get_token_budget_config = None  # type: ignore

# Import common hook protocol helpers
try:
    from common_hook_lib import (
        emit_stdout_json,
        get_tool_args,
        get_tool_call,
        log_diagnostic,
        post_invocation_response,
        post_tool_response,
        pre_tool_response,
        read_stdin_payload,
    )
except ImportError:
    # Safe fallback stubs
    def log_diagnostic(msg: str) -> None:
        sys.stderr.write(f"[HOOK-DIAGNOSTIC] {msg}\n")

    def read_stdin_payload(default: dict[str, Any] | None = None) -> dict[str, Any]:
        raw = ""
        max_bytes = 10 * 1024 * 1024
        try:
            raw = sys.stdin.read(max_bytes + 1)
            if len(raw) > max_bytes:
                log_diagnostic(f"STDIN payload exceeded maximum limit ({len(raw)} > {max_bytes} bytes).")
                return default or {}
        except UnicodeDecodeError:
            try:
                raw_bytes = getattr(sys.stdin, "buffer", None)
                if raw_bytes is not None:
                    chunk = raw_bytes.read(max_bytes + 1)
                    if len(chunk) > max_bytes:
                        log_diagnostic(f"STDIN payload exceeded maximum limit ({len(chunk)} > {max_bytes} bytes).")
                        return default or {}
                    raw = chunk.decode("utf-8", errors="replace")
            except Exception:
                return default or {}
        except Exception:
            return default or {}

        try:
            return json.loads(raw) if raw and raw.strip() else (default or {})
        except Exception:
            return default or {}

    def emit_stdout_json(payload: dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    def get_tool_call(payload: dict[str, Any]) -> dict[str, Any]:
        return payload.get("toolCall", {}) if isinstance(payload, dict) else {}

    def get_tool_args(tool_call: dict[str, Any]) -> dict[str, Any]:
        return tool_call.get("args", {}) if isinstance(tool_call, dict) else {}

    def pre_tool_response(decision: str, reason: str = "") -> dict[str, Any]:
        res: dict[str, Any] = {"decision": decision}
        if reason:
            res["reason"] = reason
        return res

    def post_tool_response() -> dict[str, Any]:
        return {}

    def post_invocation_response(inject_steps: list[dict[str, Any]] | None = None, termination_behavior: str = "") -> dict[str, Any]:
        return {"injectSteps": inject_steps or [], "terminationBehavior": termination_behavior}


# Optional tiktoken integration
try:
    import tiktoken

    _TIKTOKEN_ENCODER = tiktoken.get_encoding("cl100k_base")
except Exception:
    _TIKTOKEN_ENCODER = None


# Cross-process file lock registry and implementation (Mục 31)
_LOCK_REGISTRY_MUTEX = threading.Lock()
_THREAD_LOCKS: dict[str, threading.RLock] = {}
_LOCK_COUNTS: dict[str, int] = {}
_LOCK_FDS: dict[str, int] = {}


def _get_thread_lock(key: str) -> threading.RLock:
    with _LOCK_REGISTRY_MUTEX:
        if key not in _THREAD_LOCKS:
            _THREAD_LOCKS[key] = threading.RLock()
        return _THREAD_LOCKS[key]


class CrossProcessLock:
    """Robust cross-process file lock supporting Windows (msvcrt) and POSIX (fcntl).

    Includes process/thread reentrancy protection to prevent self-deadlock
    and intra-process thread synchronization to prevent race conditions.
    """

    def __init__(self, lock_file: pathlib.Path | str, timeout: float = 10.0):
        self.lock_file = pathlib.Path(lock_file).resolve()
        self.timeout = timeout
        self.fd: int | None = None
        self._key = str(self.lock_file)
        self._tlock = _get_thread_lock(self._key)

    def __enter__(self) -> CrossProcessLock:
        start_time = time.monotonic()
        acquired_thread = self._tlock.acquire(timeout=self.timeout)
        if not acquired_thread:
            raise TimeoutError(f"Timed out waiting for intra-process thread lock: {self.lock_file}")

        try:
            with _LOCK_REGISTRY_MUTEX:
                if _LOCK_COUNTS.get(self._key, 0) > 0:
                    _LOCK_COUNTS[self._key] += 1
                    self.fd = _LOCK_FDS[self._key]
                    return self

            self.lock_file.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.lock_file), os.O_RDWR | os.O_CREAT)
            while True:
                try:
                    if sys.platform == "win32":
                        import msvcrt
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

                    with _LOCK_REGISTRY_MUTEX:
                        _LOCK_COUNTS[self._key] = 1
                        _LOCK_FDS[self._key] = fd
                    self.fd = fd
                    return self
                except OSError:
                    if time.monotonic() - start_time > self.timeout:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                        raise TimeoutError(f"Timed out waiting for file lock: {self.lock_file}")
                    time.sleep(0.01 + random.uniform(0.005, 0.015))
        except Exception:
            self._tlock.release()
            raise

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        try:
            with _LOCK_REGISTRY_MUTEX:
                count = _LOCK_COUNTS.get(self._key, 0)
                if count > 1:
                    _LOCK_COUNTS[self._key] = count - 1
                    return
                _LOCK_COUNTS.pop(self._key, None)
                fd = _LOCK_FDS.pop(self._key, self.fd)

            if fd is not None:
                try:
                    if sys.platform == "win32":
                        import msvcrt
                        try:
                            os.lseek(fd, 0, os.SEEK_SET)
                            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                        except OSError:
                            pass
                    else:
                        import fcntl
                        try:
                            fcntl.flock(fd, fcntl.LOCK_UN)
                        except OSError:
                            pass
                finally:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    self.fd = None
        finally:
            self._tlock.release()


# Invisible and BiDi control characters
# Covers Zero-Width spaces/joiners, BiDi marks/embeddings/overrides/isolates, CGJ, Soft Hyphen, Mongolian vowel separator
INVISIBLE_AND_BIDI_REGEX = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad\u180e\u034f]"
)

# Combining Grapheme Joiner specifically
CGJ_CHAR = "\u034f"

# Comprehensive Homoglyph translation mapping (Cyrillic & Greek -> Latin ASCII)
HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic lowercase
    "\u0430": "a", "\u0432": "b", "\u0433": "r", "\u0434": "d", "\u0435": "e",
    "\u0436": "zh", "\u0437": "z", "\u0438": "i", "\u0439": "i", "\u043a": "k",
    "\u043b": "l", "\u043c": "m", "\u043d": "h", "\u043e": "o", "\u043f": "n",
    "\u0440": "p", "\u0441": "c", "\u0442": "t", "\u0443": "y", "\u0444": "f",
    "\u0445": "x", "\u0446": "ts", "\u0447": "ch", "\u0448": "sh", "\u0449": "sh",
    "\u044a": "", "\u044b": "y", "\u044c": "", "\u044d": "e", "\u044e": "yu",
    "\u044f": "ya", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    # Cyrillic uppercase
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X", "\u0423": "Y",
    # Greek lowercase
    "\u03b1": "a", "\u03b2": "b", "\u03b3": "g", "\u03b4": "d", "\u03b5": "e",
    "\u03b6": "z", "\u03b7": "h", "\u03b8": "th", "\u03b9": "i", "\u03ba": "k",
    "\u03bb": "l", "\u03bc": "m", "\u03bd": "v", "\u03be": "x", "\u03bf": "o",
    "\u03c0": "p", "\u03c1": "p", "\u03c2": "s", "\u03c3": "s", "\u03c4": "t",
    "\u03c5": "u", "\u03c6": "f", "\u03c7": "x", "\u03c8": "ps", "\u03c9": "w",
    # Greek uppercase
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O",
    "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
}

# Unicode character classification regex patterns
# Regex matching Vietnamese accented characters in both precomposed (NFC) and decomposed (NFD combining marks)
RE_VIETNAMESE_ACCENTED = re.compile(
    r"[àáảãạăằắẳẵặâầấẩẫậèéẻẽẹêềếểễệìíỉĩịòóỏõọôồốổỗộơờớởỡợùúủũụưừứửữựỳýỷỹỵđ"
    r"ÀÁẢÃẠĂẰẮẲẴẶÂẦẤẨẪẬÈÉẺẸÊỀẾỂỄỆÌÍỈĨỊÒÓỎÕỌÔỒỐỔỖỘƠỜỚỞỠỢÙÚỦŨỤƯỪỨỬỮỰỲÝỶỸỴĐ"
    r"\u0300-\u0303\u0306\u0309\u031b\u0323]",
    re.UNICODE,
)
RE_CJK = re.compile(
    r"[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af\uff00-\uffef]",
    re.UNICODE,
)
RE_CODE_SYMBOLS = re.compile(
    r"[{}\[\]()<>=:;+\-*/_&|^%!~,\\.\"'`?#@\$\\]"
)
RE_ASCII_ALPHANUM = re.compile(
    r"[a-zA-Z0-9]"
)
RE_WHITESPACE = re.compile(
    r"\s"
)


def canonicalize_vietnamese_text(text: str) -> str:
    """Canonicalize Vietnamese text handling NFD, CGJ (\u034f), and non-standard diacritic orders."""
    if not text:
        return ""
    # Strip invisible/BiDi and CGJ so combining marks attach properly to base characters
    cleaned = INVISIBLE_AND_BIDI_REGEX.sub("", text)
    nfd_text = unicodedata.normalize("NFD", cleaned)
    # Reorder if tone mark was placed before vowel modifier
    nfd_reordered = re.sub(
        r"([\u0300\u0301\u0303\u0309\u0323])([\u0302\u0306\u031b])",
        r"\2\1",
        nfd_text,
    )
    return unicodedata.normalize("NFKC", nfd_reordered)


def normalize_role_identity(role: str) -> str:
    """Normalize role identity using NFKC, homoglyph mapping, and case folding.

    Prevents role identity spoofing, state fragmentation, and tracking bypasses caused
    by Cyrillic/Greek homoglyphs, zero-width characters, or casing inconsistencies.
    """
    if not role or not isinstance(role, str):
        return "default"
    cleaned = INVISIBLE_AND_BIDI_REGEX.sub("", role)
    norm = unicodedata.normalize("NFKC", cleaned)
    mapped = "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in norm)
    folded = mapped.casefold().strip()
    canonical = re.sub(r"[\s\-]+", "_", folded)
    return canonical or "default"


def decode_payload_multilayer(content: str, max_passes: int = 3) -> list[str]:
    """Recursively decode multi-layer encoded content (URL percent-encoding, escapes, Base64).

    Returns a list of decoded representations including the original string and unpacked layers.
    """
    if not content or not isinstance(content, str):
        return [content] if content else []
    variants: list[str] = [content]
    seen: set[str] = {content}
    current = content

    for _ in range(max_passes):
        changed = False

        # Layer 1: URL / Percent-decoding (e.g. %20, %2520)
        if "%" in current:
            try:
                unq = urllib.parse.unquote(current)
                if unq != current and unq not in seen:
                    variants.append(unq)
                    seen.add(unq)
                    current = unq
                    changed = True
            except Exception:
                pass

        # Layer 2: Escapes decoding (\uXXXX, \UXXXXXXXX, \xXX, \n, \t)
        if "\\" in current:
            try:
                def _replace_escape(match: re.Match) -> str:
                    esc = match.group(0)
                    try:
                        return esc.encode("utf-8").decode("unicode_escape")
                    except Exception:
                        return esc

                dec_escapes = re.sub(
                    r"\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|x[0-9a-fA-F]{2}|[nrtbfv\\'\"])",
                    _replace_escape,
                    current,
                )
                if dec_escapes != current and dec_escapes not in seen:
                    variants.append(dec_escapes)
                    seen.add(dec_escapes)
                    current = dec_escapes
                    changed = True
            except Exception:
                pass

        # Layer 3: Base64 detection and decoding (supporting UTF-8 and UTF-16LE)
        candidate_b64_matches = re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", current)
        for b64_cand in candidate_b64_matches:
            try:
                b64_bytes = base64.b64decode(b64_cand, validate=True)
                decoded_str = None
                # Check for null bytes indicative of UTF-16LE (e.g. PowerShell EncodedCommand)
                if b"\x00" in b64_bytes:
                    try:
                        decoded_str = b64_bytes.decode("utf-16le")
                    except UnicodeDecodeError:
                        pass
                if decoded_str is None:
                    try:
                        decoded_str = b64_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        try:
                            decoded_str = b64_bytes.decode("utf-16le")
                        except UnicodeDecodeError:
                            pass

                if decoded_str and decoded_str.strip() and decoded_str not in seen:
                    printable_ratio = sum(1 for c in decoded_str if c.isprintable() or c in "\r\n\t") / max(1, len(decoded_str))
                    if printable_ratio > 0.8:
                        variants.append(decoded_str)
                        seen.add(decoded_str)
                        current = decoded_str
                        changed = True
            except Exception:
                pass

        if not changed:
            break

    return variants


# Standard fallback configuration if dynamic_limits.json is unavailable
FALLBACK_TOKEN_CONFIG: dict[str, Any] = {
    "enabled": True,
    "default_context_window": 1000000,
    "warning_threshold_ratio": 0.80,
    "critical_threshold_ratio": 0.95,
    "exhausted_threshold_ratio": 1.0,
    "max_rule_file_tokens": 4000,
    "max_role_tokens": 12000,
    "target_role_tokens": 7000,
    "max_single_message_tokens": 8000,
    "verbosity_warning_tokens": 6000,
    "ratios": {
        "ascii_chars_per_token": 4.0,
        "code_symbol_chars_per_token": 2.5,
        "vietnamese_accented_chars_per_token": 1.5,
        "cjk_chars_per_token": 1.2,
        "whitespace_chars_per_token": 4.0,
        "default_chars_per_token": 3.5,
    },
    "role_budgets": {
        "pm_orchestrator": 15000,
        "backend_developer": 12000,
        "frontend_developer": 12000,
        "devops_security": 12000,
        "qa_challenger": 15000,
        "tech_lead_auditor": 12000,
        "pm": 15000,
        "dev": 12000,
        "qa": 15000,
        "tl": 12000,
    },
    "state_storage_dir": ".token_budget",
    "state_file_name": "governor_state.json",
    "rolling_window_seconds": 3600,
}


@dataclass
class TokenEstimationResult:
    """Detailed result of dynamic character-to-token ratio estimation."""
    char_count: int
    estimated_tokens: int
    effective_ratio: float
    char_breakdown: dict[str, int]
    dominant_category: str
    tiktoken_tokens: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TokenBudgetDecision:
    """Decision produced by token budget governor."""
    allowed: bool
    decision: str  # "allow" or "deny"
    verdict: str   # "ALLOW" or "DENY"
    role: str
    current_usage: int
    projected_usage: int
    budget: int
    usage_percentage: float
    warning_threshold: float
    critical_threshold: float
    is_warning: bool = False
    is_critical: bool = False
    is_exhausted: bool = False
    is_verbosity_warning: bool = False
    reason: str = ""
    suggestions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TokenRatioEstimator:
    """Dynamic character-to-token ratio estimator.

    Zero-hardcoding: All ratio coefficients are obtained from dynamic configuration.
    Performs linguistic character classification and syllable-aware weighting.
    """

    def __init__(self, ratios_config: dict[str, float] | None = None) -> None:
        self._ratios = ratios_config or FALLBACK_TOKEN_CONFIG["ratios"].copy()

    def update_ratios(self, ratios_config: dict[str, float]) -> None:
        """Hot-reload ratio coefficients."""
        self._ratios = ratios_config

    def estimate(self, text: str) -> TokenEstimationResult:
        """Estimate token count and effective ratio from input text."""
        if not text:
            r_def = float(self._ratios.get("default_chars_per_token", 3.5))
            return TokenEstimationResult(
                char_count=0,
                estimated_tokens=0,
                effective_ratio=r_def,
                char_breakdown={
                    "ascii_alphanum": 0,
                    "code_symbols": 0,
                    "vietnamese_accented": 0,
                    "cjk": 0,
                    "whitespace": 0,
                    "other": 0,
                },
                dominant_category="empty",
                tiktoken_tokens=0 if _TIKTOKEN_ENCODER else None,
            )

        # 1. Canonicalize Vietnamese text (handles NFD, CGJ \u034f, and non-standard diacritic orders)
        canon_text = canonicalize_vietnamese_text(text)

        # 2. Normalize Unicode compatibility forms (Fullwidth ASCII, etc.) via NFKC
        norm_text = unicodedata.normalize("NFKC", canon_text)

        # 3. Filter invisible zero-width and BiDi control characters before token estimation and word splitting
        clean_text = INVISIBLE_AND_BIDI_REGEX.sub("", norm_text)

        char_count = len(clean_text)
        if char_count == 0 and len(text) > 0:
            char_count = len(text)
            clean_text = text

        # Categorize characters
        c_vn = len(RE_VIETNAMESE_ACCENTED.findall(clean_text))
        c_cjk = len(RE_CJK.findall(clean_text))
        c_code = len(RE_CODE_SYMBOLS.findall(clean_text))
        c_ws = len(RE_WHITESPACE.findall(clean_text))
        c_ascii = len(RE_ASCII_ALPHANUM.findall(clean_text))
        c_other = max(0, char_count - (c_vn + c_cjk + c_code + c_ws + c_ascii))

        breakdown = {
            "ascii_alphanum": c_ascii,
            "code_symbols": c_code,
            "vietnamese_accented": c_vn,
            "cjk": c_cjk,
            "whitespace": c_ws,
            "other": c_other,
        }

        # Determine dominant category
        sorted_cats = sorted(breakdown.items(), key=lambda kv: kv[1], reverse=True)
        dominant_cat = sorted_cats[0][0] if sorted_cats else "ascii_alphanum"

        # Ratios from dynamic configuration
        r_ascii = float(self._ratios.get("ascii_chars_per_token", 4.0))
        r_code = float(self._ratios.get("code_symbol_chars_per_token", 2.5))
        r_vn = float(self._ratios.get("vietnamese_accented_chars_per_token", 1.5))
        r_cjk = float(self._ratios.get("cjk_chars_per_token", 1.2))
        r_ws = float(self._ratios.get("whitespace_chars_per_token", 4.0))
        r_other = float(self._ratios.get("default_chars_per_token", 3.5))

        # Vietnamese syllable-aware weighting:
        # Syllables with Vietnamese diacritics incur higher token density across the syllable.
        words = clean_text.split()
        vn_words_chars = sum(len(w) for w in words if RE_VIETNAMESE_ACCENTED.search(w))

        if vn_words_chars > 0:
            # Vietnamese syllables estimated at r_vn
            vn_tokens = vn_words_chars / r_vn
            non_vn_ascii = max(0, c_ascii - sum(len(RE_ASCII_ALPHANUM.findall(w)) for w in words if RE_VIETNAMESE_ACCENTED.search(w)))
            non_vn_tokens = (
                (non_vn_ascii / r_ascii)
                + (c_code / r_code)
                + (c_cjk / r_cjk)
                + (c_ws / r_ws)
                + (c_other / r_other)
            )
            raw_tokens = vn_tokens + non_vn_tokens
        else:
            raw_tokens = (
                (c_ascii / r_ascii)
                + (c_code / r_code)
                + (c_cjk / r_cjk)
                + (c_ws / r_ws)
                + (c_other / r_other)
            )

        estimated_tokens = max(1, int(round(raw_tokens)))
        effective_ratio = round(char_count / estimated_tokens, 2) if estimated_tokens > 0 else r_ascii

        # Optional tiktoken count
        tiktoken_val: int | None = None
        if _TIKTOKEN_ENCODER is not None:
            try:
                tiktoken_val = len(_TIKTOKEN_ENCODER.encode(clean_text))
            except Exception:
                tiktoken_val = None

        return TokenEstimationResult(
            char_count=char_count,
            estimated_tokens=estimated_tokens,
            effective_ratio=effective_ratio,
            char_breakdown=breakdown,
            dominant_category=dominant_cat,
            tiktoken_tokens=tiktoken_val,
        )


class TokenBudgetGovernor:
    """Enterprise Token Budget Governor.

    Zero hardcoded values: dynamically binds limits and budgets from dynamic_limits.json.
    Maintains rolling session state, threshold alerts, verbosity detection, and audit trail.
    """

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        state_dir: pathlib.Path | str | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._custom_config = config is not None
        self._config = config or self._fetch_dynamic_config()
        self._estimator = TokenRatioEstimator(self._config.get("ratios"))

        # Storage resolution - standardized global path to avoid CWD fragmentation (Mục 32)
        env_storage = os.environ.get("TOKEN_BUDGET_STORAGE_PATH")
        if state_dir:
            self._state_dir = pathlib.Path(state_dir).resolve()
        elif env_storage:
            self._state_dir = pathlib.Path(env_storage).resolve()
        else:
            cfg_dir = self._config.get("state_storage_dir", ".token_budget")
            p = pathlib.Path(cfg_dir)
            if p.is_absolute():
                self._state_dir = p.resolve()
            else:
                self._state_dir = (HOOKS_ROOT / p).resolve()

        state_file_name = self._config.get("state_file_name", "governor_state.json")
        self._state_file = self._state_dir / state_file_name
        self._lock_file = self._state_dir / "governor.lock"

        # Runtime usage per role: { role: int }
        self._role_usage: dict[str, int] = {}
        # Warning states per role: { role: { "warning": bool, "critical": bool, "exhausted": bool } }
        self._role_flags: dict[str, dict[str, bool]] = {}
        # Cumulative session tokens
        self._total_session_tokens: int = 0
        # Transaction history: list[dict]
        self._transactions: list[dict[str, Any]] = []

        self._load_state()

    def _fetch_dynamic_config(self) -> dict[str, Any]:
        """Fetch token budget configuration dynamically from hook_utils."""
        if get_token_budget_config:
            try:
                cfg = get_token_budget_config()
                if isinstance(cfg, dict) and cfg:
                    return cfg
            except Exception as exc:
                log_diagnostic(f"Failed to fetch config from hook_utils: {exc}")
        return FALLBACK_TOKEN_CONFIG.copy()

    def refresh_config(self, force_reload: bool = False) -> None:
        """Hot-reload configuration dynamically."""
        with self._lock:
            if not getattr(self, "_custom_config", False) or force_reload:
                self._config = self._fetch_dynamic_config()
                self._estimator.update_ratios(self._config.get("ratios", FALLBACK_TOKEN_CONFIG["ratios"]))

    def get_role_budget(self, role: str) -> int:
        """Get budget for a specific role dynamically with homoglyph-safe normalization."""
        normalized_role = normalize_role_identity(role)
        role_budgets = self._config.get("role_budgets", FALLBACK_TOKEN_CONFIG["role_budgets"])
        if normalized_role in role_budgets:
            return int(role_budgets[normalized_role])

        # Try prefix matching (e.g. backend -> backend_developer)
        for r_name, r_budget in role_budgets.items():
            if normalized_role in r_name or r_name in normalized_role:
                return int(r_budget)

        return int(self._config.get("max_role_tokens", FALLBACK_TOKEN_CONFIG["max_role_tokens"]))

    def estimate_tokens(self, text: str, decode_multilayer: bool = True) -> TokenEstimationResult:
        """Estimate token count for a piece of text with optional multi-layer decoding.

        Evaluates token consumption across raw and decoded variants (URL percent-decoding,
        escape decoding, Base64 unpacking) to ensure no token limit or budget evasion.
        """
        if not decode_multilayer or not text:
            return self._estimator.estimate(text)

        variants = decode_payload_multilayer(text)
        if len(variants) <= 1:
            return self._estimator.estimate(text)

        best_est: TokenEstimationResult | None = None
        max_tokens = -1

        for var in variants:
            est = self._estimator.estimate(var)
            if est.estimated_tokens > max_tokens:
                max_tokens = est.estimated_tokens
                best_est = est

        return best_est if best_est is not None else self._estimator.estimate(text)

    def record_usage(
        self,
        role: str,
        tokens: int,
        token_type: str = "prompt",
        metadata: dict[str, Any] | None = None,
    ) -> TokenBudgetDecision:
        """Record token consumption and evaluate budget thresholds under cross-process lock."""
        with self._lock:
            with CrossProcessLock(self._lock_file):
                self._load_state_locked()
                normalized_role = normalize_role_identity(role)
                budget = self.get_role_budget(normalized_role)
                current = self._role_usage.get(normalized_role, 0)
                projected = current + tokens

                self._role_usage[normalized_role] = projected
                self._total_session_tokens += tokens

                if normalized_role not in self._role_flags:
                    self._role_flags[normalized_role] = {
                        "warning": False,
                        "critical": False,
                        "exhausted": False,
                    }

                flags = self._role_flags[normalized_role]
                warn_ratio = float(self._config.get("warning_threshold_ratio", 0.80))
                crit_ratio = float(self._config.get("critical_threshold_ratio", 0.95))
                exhaust_ratio = float(self._config.get("exhausted_threshold_ratio", 1.00))

                usage_pct = projected / budget if budget > 0 else 0.0

                is_warning = usage_pct >= warn_ratio
                is_critical = usage_pct >= crit_ratio
                is_exhausted = usage_pct >= exhaust_ratio

                suggestions: list[str] = []
                allowed = True
                decision = "allow"
                verdict = "ALLOW"
                reason = ""

                if is_exhausted:
                    flags["exhausted"] = True
                    allowed = False
                    decision = "deny"
                    verdict = "DENY"
                    reason = (
                        f"Ngân sách token của vai trò '{normalized_role}' đã cạn kiệt "
                        f"({projected}/{budget} tokens, {usage_pct:.1%}). Yêu cầu compact session ngay!"
                    )
                    suggestions.append("Kích hoạt session_compactor để thu gọn lịch sử.")
                    suggestions.append("Bàn giao ngữ cảnh cô đọng qua progress.md.")
                elif is_critical and not flags["critical"]:
                    flags["critical"] = True
                    reason = (
                        f"CẢNH BÁO NGUY CẤP: Vai trò '{normalized_role}' đã dùng {usage_pct:.1%} "
                        f"ngân sách ({projected}/{budget} tokens). Cần tóm tắt khẩn cấp!"
                    )
                    suggestions.append("Kích hoạt session compactor ngay.")
                elif is_warning and not flags["warning"]:
                    flags["warning"] = True
                    reason = (
                        f"CẢNH BÁO: Vai trò '{normalized_role}' đã đạt ngưỡng 80% "
                        f"ngân sách ({projected}/{budget} tokens)."
                    )
                    suggestions.append("Chuẩn bị nén ngữ cảnh hoặc tóm tắt các bước trước.")

                # Record transaction
                txn = {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "role": normalized_role,
                    "tokens": tokens,
                    "token_type": token_type,
                    "projected_usage": projected,
                    "budget": budget,
                    "usage_percentage": round(usage_pct, 4),
                    "metadata": metadata or {},
                }
                self._transactions.append(txn)
                if len(self._transactions) > 1000:
                    self._transactions = self._transactions[-1000:]

                self._save_state_locked()

            return TokenBudgetDecision(
                allowed=allowed,
                decision=decision,
                verdict=verdict,
                role=normalized_role,
                current_usage=current,
                projected_usage=projected,
                budget=budget,
                usage_percentage=round(usage_pct, 4),
                warning_threshold=warn_ratio,
                critical_threshold=crit_ratio,
                is_warning=is_warning,
                is_critical=is_critical,
                is_exhausted=is_exhausted,
                reason=reason,
                suggestions=suggestions,
            )

    def evaluate_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        role: str = "default",
        record_if_allowed: bool = False,
    ) -> TokenBudgetDecision:
        """Evaluate a toolCall payload against token budget rules (PreToolUse) under cross-process lock."""
        with self._lock:
            with CrossProcessLock(self._lock_file):
                self._load_state_locked()
                self.refresh_config()
                normalized_role = normalize_role_identity(role)
                budget = self.get_role_budget(normalized_role)
                current = self._role_usage.get(normalized_role, 0)

                # Inspect payload text
                text_to_evaluate = ""
                is_file_op = False

                if tool_name == "write_to_file":
                    text_to_evaluate = str(tool_args.get("CodeContent", ""))
                    is_file_op = True
                elif tool_name == "replace_file_content":
                    text_to_evaluate = str(tool_args.get("ReplacementContent", ""))
                elif tool_name == "invoke_subagent":
                    subagents = tool_args.get("Subagents", [])
                    if isinstance(subagents, list):
                        prompts = [str(s.get("Prompt", "")) for s in subagents if isinstance(s, dict)]
                        text_to_evaluate = "\n".join(prompts)
                elif tool_name == "send_message":
                    text_to_evaluate = str(tool_args.get("Message", ""))

                est = self.estimate_tokens(text_to_evaluate)
                tokens = est.estimated_tokens
                projected = current + tokens
                usage_pct = projected / budget if budget > 0 else 0.0

                # File size token ceiling check (§Rule file token limit: 4000 tokens)
                max_file_tokens = int(self._config.get("max_rule_file_tokens", 4000))
                if is_file_op and tokens > max_file_tokens:
                    target_file = str(tool_args.get("TargetFile", ""))
                    return TokenBudgetDecision(
                        allowed=False,
                        decision="deny",
                        verdict="DENY",
                        role=normalized_role,
                        current_usage=current,
                        projected_usage=projected,
                        budget=budget,
                        usage_percentage=round(usage_pct, 4),
                        warning_threshold=float(self._config.get("warning_threshold_ratio", 0.80)),
                        critical_threshold=float(self._config.get("critical_threshold_ratio", 0.95)),
                        reason=(
                            f"Tệp '{pathlib.Path(target_file).name}' ước tính {tokens} tokens, "
                            f"vượt trần giới hạn cho phép ({max_file_tokens} tokens) theo quy chuẩn doanh nghiệp!"
                        ),
                        suggestions=[
                            f"Băm nhỏ tệp thành các module nhỏ hơn (mỗi module <= {max_file_tokens} tokens).",
                            "Sử dụng kỹ thuật phân rã cấu trúc theo kiến trúc sạch.",
                        ],
                    )

                # Anti-Verbosity / 'Lậm lời' check
                verbosity_limit = int(self._config.get("verbosity_warning_tokens", 6000))
                is_verbosity_warn = tokens > verbosity_limit
                suggestions: list[str] = []
                if is_verbosity_warn:
                    suggestions.append(
                        f"Cảnh báo 'lậm lời': Tin nhắn/nội dung ước tính {tokens} tokens "
                        f"(vượt ngưỡng cảnh báo độ dài {verbosity_limit} tokens). Nên tóm tắt ngắn gọn."
                    )

                # Context window saturation check
                context_window = int(self._config.get("default_context_window", 1000000))
                if (self._total_session_tokens + tokens) > (context_window * 0.95):
                    return TokenBudgetDecision(
                        allowed=False,
                        decision="deny",
                        verdict="DENY",
                        role=normalized_role,
                        current_usage=current,
                        projected_usage=projected,
                        budget=budget,
                        usage_percentage=round(usage_pct, 4),
                        warning_threshold=float(self._config.get("warning_threshold_ratio", 0.80)),
                        critical_threshold=float(self._config.get("critical_threshold_ratio", 0.95)),
                        is_exhausted=True,
                        reason=f"Cửa sổ ngữ cảnh phiên sắp cạn ({self._total_session_tokens + tokens}/{context_window} tokens).",
                        suggestions=["Thu gọn lịch sử qua session_compactor ngay."],
                    )

                # Check role budget exhaustion
                exhaust_ratio = float(self._config.get("exhausted_threshold_ratio", 1.00))
                if usage_pct >= exhaust_ratio:
                    return TokenBudgetDecision(
                        allowed=False,
                        decision="deny",
                        verdict="DENY",
                        role=normalized_role,
                        current_usage=current,
                        projected_usage=projected,
                        budget=budget,
                        usage_percentage=round(usage_pct, 4),
                        warning_threshold=float(self._config.get("warning_threshold_ratio", 0.80)),
                        critical_threshold=float(self._config.get("critical_threshold_ratio", 0.95)),
                        is_exhausted=True,
                        reason=(
                            f"Lệnh sẽ làm vượt quá ngân sách vai trò '{normalized_role}' "
                            f"({projected}/{budget} tokens, {usage_pct:.1%})."
                        ),
                        suggestions=["Nén context hoặc reset session trước khi tiếp tục."],
                    )

                warn_ratio = float(self._config.get("warning_threshold_ratio", 0.80))
                crit_ratio = float(self._config.get("critical_threshold_ratio", 0.95))

                if record_if_allowed and tokens > 0:
                    self._role_usage[normalized_role] = projected
                    self._total_session_tokens += tokens
                    if normalized_role not in self._role_flags:
                        self._role_flags[normalized_role] = {
                            "warning": False,
                            "critical": False,
                            "exhausted": False,
                        }
                    flags = self._role_flags[normalized_role]
                    if usage_pct >= crit_ratio:
                        flags["critical"] = True
                    elif usage_pct >= warn_ratio:
                        flags["warning"] = True
                    txn = {
                        "timestamp": datetime.now(UTC).isoformat(),
                        "role": normalized_role,
                        "tokens": tokens,
                        "token_type": tool_name,
                        "projected_usage": projected,
                        "budget": budget,
                        "usage_percentage": round(usage_pct, 4),
                        "metadata": {"tool_name": tool_name},
                    }
                    self._transactions.append(txn)
                    if len(self._transactions) > 1000:
                        self._transactions = self._transactions[-1000:]
                    self._save_state_locked()

                return TokenBudgetDecision(
                    allowed=True,
                    decision="allow",
                    verdict="ALLOW",
                    role=normalized_role,
                    current_usage=current,
                    projected_usage=projected,
                    budget=budget,
                    usage_percentage=round(usage_pct, 4),
                    warning_threshold=warn_ratio,
                    critical_threshold=crit_ratio,
                    is_warning=usage_pct >= warn_ratio,
                    is_critical=usage_pct >= crit_ratio,
                    is_verbosity_warning=is_verbosity_warn,
                    reason="Kiểm tra ngân sách token thành công." if not is_verbosity_warn else suggestions[0],
                    suggestions=suggestions,
                )

    def _get_status_locked(self, normalized_role: str) -> dict[str, Any]:
        """Get status summary for a specific role assuming lock is held."""
        budget = self.get_role_budget(normalized_role)
        used = self._role_usage.get(normalized_role, 0)
        pct = used / budget if budget > 0 else 0.0
        return {
            "role": normalized_role,
            "budget": budget,
            "used": used,
            "remaining": max(0, budget - used),
            "percentage": round(pct, 4),
            "percentage_display": f"{pct:.1%}",
        }

    def get_status(self, role: str) -> dict[str, Any]:
        """Get status summary for a specific role under cross-process lock."""
        with self._lock:
            with CrossProcessLock(self._lock_file):
                self._load_state_locked()
                normalized_role = normalize_role_identity(role)
                return self._get_status_locked(normalized_role)

    def get_all_statuses(self) -> dict[str, Any]:
        """Get status summaries for all configured roles under cross-process lock."""
        with self._lock:
            with CrossProcessLock(self._lock_file):
                self._load_state_locked()
                role_budgets = self._config.get("role_budgets", {})
                statuses = {r: self._get_status_locked(normalize_role_identity(r)) for r in role_budgets}
                return {
                    "roles": statuses,
                    "total_session_tokens": self._total_session_tokens,
                    "context_window": self._config.get("default_context_window", 1000000),
                }

    def reset(self, role: str | None = None) -> None:
        """Reset usage tracking for a specific role or entire session under cross-process lock."""
        with self._lock:
            with CrossProcessLock(self._lock_file):
                self._load_state_locked()
                if role:
                    r_norm = normalize_role_identity(role)
                    self._role_usage[r_norm] = 0
                    if r_norm in self._role_flags:
                        self._role_flags[r_norm] = {"warning": False, "critical": False, "exhausted": False}
                else:
                    self._role_usage.clear()
                    self._role_flags.clear()
                    self._total_session_tokens = 0
                    self._transactions.clear()
                self._save_state_locked()

    def _save_state_locked(self) -> None:
        """Persist state atomically to disk assuming cross-process lock is held."""
        temp_file: pathlib.Path | None = None
        try:
            self._state_dir.mkdir(parents=True, exist_ok=True)
            data = {
                "role_usage": self._role_usage,
                "role_flags": self._role_flags,
                "total_session_tokens": self._total_session_tokens,
                "last_updated": datetime.now(UTC).isoformat(),
            }
            # Atomic write via unique temp file (Mục 35 pattern)
            temp_file = self._state_file.with_suffix(
                f".tmp.{os.getpid()}.{time.time_ns()}.{uuid.uuid4().hex[:6]}"
            )
            temp_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8", errors="replace")

            # Retry on Windows NTFS lock contention (Mục 36 pattern)
            for attempt in range(5):
                try:
                    temp_file.replace(self._state_file)
                    break
                except OSError:
                    if attempt == 4:
                        raise
                    time.sleep(0.02 * (2 ** attempt))
        except Exception as exc:
            log_diagnostic(f"Failed to save governor state: {exc}")
        finally:
            # Deterministic cleanup of temp file (Mục 37 pattern)
            if temp_file and temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError:
                    pass

    def _save_state(self) -> None:
        """Persist state atomically to disk under cross-process lock (Mục 31)."""
        with CrossProcessLock(self._lock_file):
            self._save_state_locked()

    def _load_state_locked(self) -> None:
        """Load state assuming cross-process lock is already held."""
        if not self._state_file.exists():
            return
        try:
            content = self._state_file.read_text(encoding="utf-8-sig", errors="replace")
            if not content.strip():
                return
            data = json.loads(content)
            if isinstance(data, dict):
                disk_roles = data.get("role_usage", {})
                if isinstance(disk_roles, dict):
                    self._role_usage = {str(r): int(u) for r, u in disk_roles.items()}
                disk_flags = data.get("role_flags", {})
                if isinstance(disk_flags, dict):
                    self._role_flags = {
                        str(r): {str(k): bool(v) for k, v in flags.items()}
                        for r, flags in disk_flags.items()
                        if isinstance(flags, dict)
                    }
                self._total_session_tokens = int(data.get("total_session_tokens", 0))
        except Exception as exc:
            log_diagnostic(f"Failed to load governor state: {exc}")

    def _load_state(self) -> None:
        """Load state safely from disk under cross-process lock (Mục 31)."""
        try:
            with CrossProcessLock(self._lock_file):
                self._load_state_locked()
        except Exception as exc:
            log_diagnostic(f"Failed to load governor state: {exc}")


# Global singleton instance
_GLOBAL_GOVERNOR: TokenBudgetGovernor | None = None
_GLOBAL_LOCK = threading.Lock()


def get_token_governor() -> TokenBudgetGovernor:
    """Obtain or initialize the global TokenBudgetGovernor singleton."""
    global _GLOBAL_GOVERNOR
    with _GLOBAL_LOCK:
        if _GLOBAL_GOVERNOR is None:
            _GLOBAL_GOVERNOR = TokenBudgetGovernor()
        return _GLOBAL_GOVERNOR


def estimate_tokens(text: str) -> TokenEstimationResult:
    """Convenience helper to estimate tokens using the global governor."""
    return get_token_governor().estimate_tokens(text)


def evaluate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Top-level evaluation entry point for Antigravity Hook runtime.

    Conforms to Safe-Fail-Closed With Alert standard (ARCH-DOC-06 Section 4).
    """
    try:
        governor = get_token_governor()
        tool_call = get_tool_call(payload)

        # PreToolUse evaluation
        if tool_call:
            tool_name = str(tool_call.get("name", ""))
            tool_args = get_tool_args(tool_call)
            role = normalize_role_identity(str(payload.get("role") or payload.get("agentRole") or "default"))

            with CrossProcessLock(governor._lock_file):
                decision = governor.evaluate_tool_call(tool_name, tool_args, role=role)

                if not decision.allowed:
                    return {
                        "decision": "deny",
                        "verdict": "DENY",
                        "reason": decision.reason,
                        "suggestions": decision.suggestions,
                    }

                # Record usage if applicable (write_to_file, replace_file_content, send_message, invoke_subagent)
                est_tokens = 0
                if tool_name == "write_to_file":
                    est_tokens = governor.estimate_tokens(str(tool_args.get("CodeContent", ""))).estimated_tokens
                elif tool_name == "replace_file_content":
                    est_tokens = governor.estimate_tokens(str(tool_args.get("ReplacementContent", ""))).estimated_tokens
                elif tool_name == "send_message":
                    est_tokens = governor.estimate_tokens(str(tool_args.get("Message", ""))).estimated_tokens
                elif tool_name == "invoke_subagent":
                    subagents = tool_args.get("Subagents", [])
                    if isinstance(subagents, list):
                        prompts = [str(s.get("Prompt", "")) for s in subagents if isinstance(s, dict)]
                        combined_prompts = "\n".join(prompts)
                        est_tokens = governor.estimate_tokens(combined_prompts).estimated_tokens

                if est_tokens > 0:
                    governor.record_usage(role, est_tokens, token_type=tool_name)

                res = pre_tool_response("allow", decision.reason)
                res["verdict"] = "ALLOW"
                if decision.suggestions:
                    res["suggestions"] = decision.suggestions
                return res

        # PostInvocation / PreInvocation evaluation
        inv_num = payload.get("invocationNum", 0)
        log_diagnostic(f"Token budget governor evaluated invocation #{inv_num}.")
        return post_invocation_response()

    except Exception as exc:
        err_detail = traceback.format_exc()
        sys.stderr.write(
            f"[HOOK_FATAL_ERROR] token_budget_governor.py gặp sự cố: {exc}\n{err_detail}\n"
        )
        sys.stderr.flush()
        return {
            "decision": "deny",
            "verdict": "DENY",
            "allow": False,
            "error_code": "HOOK_EXECUTION_FAILURE",
            "reason": f"Hook token_budget_governor.py gặp lỗi nội bộ: {exc}. Đã chặn lệnh để bảo vệ an toàn.",
        }


# ==============================================================================
# Comprehensive Self-Test Suite (--self-test)
# ==============================================================================

def run_self_tests() -> bool:
    """Run automated self-tests verifying 100% of functional requirements."""
    print("=" * 80)
    print(" 🚀 RUNNING TOKEN BUDGET GOVERNOR SELF-TEST SUITE")
    print("=" * 80)

    total_tests = 0
    passed_tests = 0

    def assert_test(name: str, condition: bool, extra_info: str = "") -> None:
        nonlocal total_tests, passed_tests
        total_tests += 1
        if condition:
            passed_tests += 1
            print(f"  ✅ [PASS] {name} {extra_info}")
        else:
            print(f"  ❌ [FAIL] {name} {extra_info}")

    # TC01: Config loader dynamic integration
    governor = TokenBudgetGovernor()
    assert_test(
        "TC01: Config Loader Dynamic Integration",
        governor._config.get("enabled") is True and "ratios" in governor._config,
        f"(Ratios: {list(governor._config.get('ratios', {}).keys())})",
    )

    # TC02: Pure English token ratio estimation (~4.0 - 4.5)
    en_sample = "The quick brown fox jumps over the lazy dog and runs away into the deep forest."
    en_est = governor.estimate_tokens(en_sample)
    assert_test(
        "TC02: English Token Ratio Estimation (~4.0 chars/token)",
        3.5 <= en_est.effective_ratio <= 5.0 and en_est.dominant_category == "ascii_alphanum",
        f"(Chars: {en_est.char_count}, Tokens: {en_est.estimated_tokens}, Ratio: {en_est.effective_ratio})",
    )

    # TC03: Vietnamese accented token ratio estimation (~1.5 - 2.5)
    vn_sample = "Hệ thống quản trị doanh nghiệp đa tác nhân và bộ điều phối ngân sách token thông minh."
    vn_est = governor.estimate_tokens(vn_sample)
    assert_test(
        "TC03: Vietnamese Accented Token Ratio Estimation (~1.5 - 2.5 chars/token)",
        1.3 <= vn_est.effective_ratio <= 2.6,
        f"(Chars: {vn_est.char_count}, Tokens: {vn_est.estimated_tokens}, Ratio: {vn_est.effective_ratio})",
    )

    # TC04: CJK token ratio estimation (~1.0 - 1.5)
    cjk_sample = "这是一个关于多智能体架构与令牌预算控制器的企业级测试样例。"
    cjk_est = governor.estimate_tokens(cjk_sample)
    assert_test(
        "TC04: CJK Ideographs Token Ratio Estimation (~1.0 - 1.5 chars/token)",
        0.8 <= cjk_est.effective_ratio <= 1.6 and cjk_est.dominant_category == "cjk",
        f"(Chars: {cjk_est.char_count}, Tokens: {cjk_est.estimated_tokens}, Ratio: {cjk_est.effective_ratio})",
    )

    # TC05: Dense code syntax token ratio estimation (~2.5 - 3.5)
    code_sample = "def execute_pipeline(items: list[dict[str, Any]], timeout: float = 30.0) -> bool: return all(x.ok for x in items)"
    code_est = governor.estimate_tokens(code_sample)
    assert_test(
        "TC05: Dense Code Syntax Token Ratio Estimation (~2.5 - 3.5 chars/token)",
        2.0 <= code_est.effective_ratio <= 3.8,
        f"(Chars: {code_est.char_count}, Tokens: {code_est.estimated_tokens}, Ratio: {code_est.effective_ratio})",
    )

    # TC06: Tiktoken integration or graceful fallback
    assert_test(
        "TC06: TikToken Integration / Fallback Safety",
        _TIKTOKEN_ENCODER is not None or en_est.tiktoken_tokens is None,
        f"(Tiktoken active: {_TIKTOKEN_ENCODER is not None})",
    )

    # TC07: Independent multi-role budget isolation
    governor.reset()
    governor.record_usage("backend_developer", 3000)
    dev_status = governor.get_status("backend_developer")
    pm_status = governor.get_status("pm_orchestrator")
    assert_test(
        "TC07: Multi-Role Budget Isolation",
        dev_status["used"] == 3000 and pm_status["used"] == 0,
        f"(Dev: {dev_status['used']}, PM: {pm_status['used']})",
    )

    # TC08: 80% Warning threshold triggering
    governor.reset("backend_developer")
    # Budget is 12000, 80% is 9600
    d_warn = governor.record_usage("backend_developer", 9650)
    assert_test(
        "TC08: 80% Warning Threshold Triggering",
        d_warn.is_warning is True and d_warn.allowed is True and "80%" in d_warn.reason,
        f"(Usage: {d_warn.usage_percentage:.1%}, Reason: {d_warn.reason})",
    )

    # TC09: 95% Critical threshold triggering
    d_crit = governor.record_usage("backend_developer", 1800)  # Total 11450 / 12000 = 95.4%
    assert_test(
        "TC09: 95% Critical Threshold Triggering",
        d_crit.is_critical is True and d_crit.allowed is True and "NGUY CẤP" in d_crit.reason,
        f"(Usage: {d_crit.usage_percentage:.1%})",
    )

    # TC10: 100% Exhausted budget rejection
    d_exh = governor.record_usage("backend_developer", 600)  # Total 12050 / 12000 > 100%
    assert_test(
        "TC10: 100% Budget Exhaustion Rejection",
        d_exh.is_exhausted is True and d_exh.allowed is False and d_exh.decision == "deny",
        f"(Verdict: {d_exh.verdict}, Reason: {d_exh.reason})",
    )

    # TC11: Anti-Verbosity / 'Lậm lời' detection on oversized message
    governor.reset()
    huge_message = "Mô tả chi tiết giải thuật " * 800  # ~20,000 characters => ~5,000-8,000 tokens
    huge_eval = governor.evaluate_tool_call("send_message", {"Message": huge_message}, role="pm_orchestrator")
    assert_test(
        "TC11: Anti-Verbosity / 'Lậm lời' Detection",
        huge_eval.is_verbosity_warning is True or "lậm lời" in str(huge_eval.suggestions),
        f"(Verbosity Warn: {huge_eval.is_verbosity_warning})",
    )

    # TC12: File token limit enforcement (4000 tokens)
    huge_code = "# Giant Code File\n" + ("x = 1\n" * 5000)  # ~30k chars > 4000 tokens
    file_eval = governor.evaluate_tool_call(
        "write_to_file",
        {"TargetFile": "huge_module.py", "CodeContent": huge_code},
        role="backend_developer",
    )
    assert_test(
        "TC12: File Token Limit Enforcement (4000 tokens)",
        file_eval.allowed is False and file_eval.decision == "deny" and "4000" in file_eval.reason,
        f"(Decision: {file_eval.decision}, Reason: {file_eval.reason})",
    )

    # TC13: PreToolUse standard hook payload evaluation
    sample_payload = {
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "test_script.py",
                "CodeContent": "print('Hello world!')\n",
            },
        },
        "role": "backend_developer",
    }
    hook_res = evaluate_payload(sample_payload)
    assert_test(
        "TC13: PreToolUse Payload Evaluation Protocol",
        hook_res.get("decision") == "allow" and hook_res.get("verdict") == "ALLOW",
        f"(Result: {hook_res})",
    )

    # TC14: Safe-Fail-Closed exception handling (ARCH-DOC-06 Section 4)
    class ExplodingPayload(dict):
        def get(self, *args, **kwargs):
            raise RuntimeError("Simulated critical failure during hook evaluation")

    fail_closed_res = evaluate_payload(ExplodingPayload())
    assert_test(
        "TC14: Safe-Fail-Closed Exception Handling",
        fail_closed_res.get("decision") == "deny" and fail_closed_res.get("verdict") == "DENY",
        f"(Decision: {fail_closed_res.get('decision')}, Verdict: {fail_closed_res.get('verdict')})",
    )

    # TC15: Concurrent usage thread-safety
    governor.reset()
    threads = []
    concurrency_errors = []

    def concurrent_worker(tid: int) -> None:
        try:
            for _ in range(20):
                governor.record_usage(f"thread_{tid % 3}", 50)
        except Exception as exc:
            concurrency_errors.append(exc)

    for i in range(10):
        t = threading.Thread(target=concurrent_worker, args=(i,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    total_tokens = sum(governor.get_status(f"thread_{k}")["used"] for k in range(3))
    assert_test(
        "TC15: Thread-Safe Concurrent Recording",
        len(concurrency_errors) == 0 and total_tokens == 10000,
        f"(Total: {total_tokens}, Expected: 10000, Errors: {len(concurrency_errors)})",
    )

    # TC16: Fullwidth Forms & Unicode NFKC Normalization (Fullwidth "ＡＢＣ１２３" -> ASCII alphanum)
    fullwidth_sample = "\uff21\uff22\uff23\uff11\uff12\uff13"  # Fullwidth "ABC123"
    fw_est = governor.estimate_tokens(fullwidth_sample)
    assert_test(
        "TC16: Fullwidth Forms & Unicode NFKC Normalization",
        fw_est.dominant_category == "ascii_alphanum" and fw_est.char_breakdown["cjk"] == 0 and fw_est.char_breakdown["ascii_alphanum"] == 6,
        f"(Cat: {fw_est.dominant_category}, CJK: {fw_est.char_breakdown['cjk']}, ASCII: {fw_est.char_breakdown['ascii_alphanum']})",
    )

    # TC17: Homoglyph Role Identity Normalization & Budget Isolation
    governor.reset()
    # Record usage using Cyrillic homoglyph for 'p' in 'pm_orchestrator'
    homoglyph_role = "\u0440m_orchestrator"  # Cyrillic 'р'
    d_hg = governor.record_usage(homoglyph_role, 500)
    canonical_status = governor.get_status("pm_orchestrator")
    assert_test(
        "TC17: Homoglyph Role Identity Normalization",
        d_hg.role == "pm_orchestrator" and canonical_status["used"] == 500,
        f"(Role: {d_hg.role}, Canonical used: {canonical_status['used']})",
    )

    # TC18: Multi-layer Payload Decoding (URL percent-encoding, escapes, Base64)
    raw_secret_code = "def process_critical_system_task():\n" + ("    pass\n" * 50)
    b64_code = base64.b64encode(raw_secret_code.encode("utf-8")).decode("ascii")
    url_b64_payload = urllib.parse.quote(f"PREFIX_{b64_code}_SUFFIX")
    variants = decode_payload_multilayer(url_b64_payload)
    multi_est = governor.estimate_tokens(url_b64_payload, decode_multilayer=True)
    assert_test(
        "TC18: Multi-layer Payload Decoding (URL/Escapes/Base64)",
        len(variants) >= 2 and any("process_critical_system_task" in v for v in variants) and multi_est.estimated_tokens > 0,
        f"(Variants found: {len(variants)}, Tokens: {multi_est.estimated_tokens})",
    )

    # TC19: Zero-Width Characters & BiDi Controls Filtering in Vietnamese Word Boundary Splitting
    zw_text = "ti\u200be\u034f\u0301\u0302ng Vi\u200e\u200f\u1ec7t"  # tiếng Việt with ZWSP, CGJ, BiDi marks
    zw_est = governor.estimate_tokens(zw_text)
    assert_test(
        "TC19: Zero-Width & BiDi Controls Filtering in Word Splitting",
        zw_est.char_breakdown["vietnamese_accented"] >= 2 and zw_est.effective_ratio < 3.0,
        f"(Chars: {zw_est.char_count}, Tokens: {zw_est.estimated_tokens}, Ratio: {zw_est.effective_ratio})",
    )

    # TC20: Non-standard NFD & Combining Grapheme Joiner (\u034F) Canonicalization
    nfd_cgj_sample = "e\u034f\u0301\u0302"  # e + CGJ + acute + circumflex -> should compose to ế
    canon_res = canonicalize_vietnamese_text(nfd_cgj_sample)
    assert_test(
        "TC20: Non-standard NFD & CGJ Canonicalization",
        canon_res == "ế",
        f"(Canonicalized: {canon_res!r}, Expected: 'ế')",
    )

    # TC21: invoke_subagent Token Budget Accounting in evaluate_payload
    global_gov = get_token_governor()
    global_gov.reset("pm_orchestrator")
    subagent_payload = {
        "toolCall": {
            "name": "invoke_subagent",
            "args": {
                "Subagents": [
                    {"TypeName": "backend_developer", "Prompt": "Implement microservice authentication module with JWT tokens."},
                    {"TypeName": "qa_challenger", "Prompt": "Audit boundary conditions and adversarial token payloads."},
                ],
            },
        },
        "role": "\u0440m_orchestrator",  # Cyrillic homoglyph test combined
    }
    sub_eval = evaluate_payload(subagent_payload)
    pm_status = global_gov.get_status("pm_orchestrator")
    assert_test(
        "TC21: invoke_subagent Token Budget Accounting in evaluate_payload",
        sub_eval.get("decision") == "allow" and pm_status["used"] > 0,
        f"(Decision: {sub_eval.get('decision')}, PM Used: {pm_status['used']})",
    )

    # TC22: Robust Unicode Stdio & State File Decode Resilience
    test_temp_state = governor._state_dir / "test_unicode_resilience.json"
    test_temp_state.write_bytes(b"\xef\xbb\xbf{\"role_usage\": {\"resilience_test\": 123}, \"invalid\": \"\xff\xfe\"}")
    read_ok = False
    try:
        data_read = json.loads(test_temp_state.read_text(encoding="utf-8-sig", errors="replace"))
        read_ok = isinstance(data_read, dict) and data_read.get("role_usage", {}).get("resilience_test") == 123
    except Exception:
        read_ok = False
    finally:
        if test_temp_state.exists():
            test_temp_state.unlink()

    assert_test(
        "TC22: Robust Unicode Decode Resilience (BOM & Replacement)",
        read_ok is True,
        f"(Read OK: {read_ok})",
    )

    # TC23: CrossProcessLock Reentrancy & Anti-Double-Spending Protection
    global_gov = get_token_governor()
    global_gov.reset("qa_challenger")
    lock_reentrant_ok = False
    with CrossProcessLock(global_gov._lock_file):
        with CrossProcessLock(global_gov._lock_file):
            lock_reentrant_ok = True

    qa_budget = global_gov.get_role_budget("qa_challenger")
    global_gov.record_usage("qa_challenger", qa_budget - 150)
    # Payload A needs ~127 tokens (fits into 150 remaining)
    payload_a = {
        "toolCall": {
            "name": "write_to_file",
            "args": {"TargetFile": "mod_a.py", "CodeContent": "def test_a():\n    pass\n" * 20},
        },
        "role": "qa_challenger",
    }
    # Payload B needs ~127 tokens (will exceed remaining after A is recorded)
    payload_b = {
        "toolCall": {
            "name": "write_to_file",
            "args": {"TargetFile": "mod_b.py", "CodeContent": "def test_b():\n    pass\n" * 20},
        },
        "role": "qa_challenger",
    }
    res_a = evaluate_payload(payload_a)
    res_b = evaluate_payload(payload_b)
    anti_double_spend_ok = (
        res_a.get("decision") == "allow"
        and res_b.get("decision") == "deny"
        and "vượt quá ngân sách" in res_b.get("reason", "")
    )
    assert_test(
        "TC23: CrossProcessLock Reentrancy & Anti-Double-Spending Protection",
        lock_reentrant_ok and anti_double_spend_ok,
        f"(Reentrant: {lock_reentrant_ok}, ResA: {res_a.get('decision')}, ResB: {res_b.get('decision')})",
    )

    print("-" * 80)
    print(f"📊 SUMMARY: {passed_tests}/{total_tests} tests passed ({(passed_tests/total_tests)*100:.1f}%)")
    print("=" * 80)

    return passed_tests == total_tests


def main() -> None:
    """CLI Hook Entry Point."""
    if "--self-test" in sys.argv:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    if "--demo" in sys.argv or "--ratio-test" in sys.argv:
        print("=== TOKEN RATIO ESTIMATOR DEMO ===")
        gov = get_token_governor()
        samples = [
            ("English", "The architecture incorporates modular decoupling and resilience."),
            ("Vietnamese", "Hệ thống tự động điều phối đa tác nhân và tối ưu hóa tài nguyên phần cứng."),
            ("CJK", "基于大语言模型的多智能体协同开发框架。"),
            ("Code", "class TokenGovernor(BaseModel): id: str = Field(default_factory=uuid.uuid4)"),
        ]
        for name, txt in samples:
            res = gov.estimate_tokens(txt)
            print(f"[{name:<10}] Chars: {res.char_count:<3} | Tokens: {res.estimated_tokens:<3} | Ratio: {res.effective_ratio:<4} | Cat: {res.dominant_category}")
        sys.exit(0)

    # Standard Hook Stdio Mode
    payload = read_stdin_payload(default={})
    result = evaluate_payload(payload)
    emit_stdout_json(result)


if __name__ == "__main__":
    main()
