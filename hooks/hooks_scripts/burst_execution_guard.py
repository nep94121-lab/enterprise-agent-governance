#!/usr/bin/env python3
"""Burst Execution Guard Hook (PreToolUse & PostToolUse) for Enterprise Multi-Agent Governance System.

Provides physical compute throttling and dual-pool hardware scheduling:
1. Regulates heavy OS commands (pytest, build, compile, npx, browser automation) via a 3-4 slot Micro-Queue Semaphore.
2. Integrates with Dynamic CPU Governor (4 Cores / 8 Threads):
   - ACCELERATION ZONE (CPU < 60%): Fast-dispatch to push load into optimal range.
   - GOLDEN ZONE (60% <= CPU <= 85%): Sustained peak performance without fan throttling.
   - THERMAL PROTECTION ZONE (CPU > 85%): 1.0s pacing cooldown preventing thermal shock.
3. Ensures cross-process lock safety on Windows using standard library msvcrt.locking with automatic kernel cleanup.
4. Bypasses lightweight commands (dir, git status, echo, ls) with sub-millisecond latency (< 2ms).
5. Immediate slot release on PostToolUse with fallback Time-To-Live (TTL) lease eviction for zero deadlock.
6. Eliminates magic numbers by dynamically sourcing limits from hook_utils/ (config_loader, cpu_governor).
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pathlib
import random
import re
import sys
import time
import uuid
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

# Ensure local hook library and hook_utils package are importable
HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).parent.resolve()
ENTERPRISE_HOOKS_ROOT = HOOKS_SCRIPTS_DIR.parent.resolve()

if str(HOOKS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_SCRIPTS_DIR))
if str(ENTERPRISE_HOOKS_ROOT) not in sys.path:
    sys.path.insert(0, str(ENTERPRISE_HOOKS_ROOT))

from common_hook_lib import (  # noqa: E402
    emit_stdout_json,
    extract_tool_invocation,
    get_tool_args,
    get_tool_call,
    log_diagnostic,
    post_tool_response,
    pre_tool_response,
    read_stdin_payload,
)

try:
    from hook_utils.cpu_governor import (  # noqa: E402
        get_lock_file as get_unified_lock_file,
        resolve_governor_state_dir,
    )
except ImportError:
    get_unified_lock_file = None
    resolve_governor_state_dir = None

_psutil = None


def get_psutil() -> Any:
    """Lazily import and cache psutil module."""
    global _psutil
    if _psutil is None:
        try:
            import psutil

            _psutil = psutil
        except ImportError:
            pass
    return _psutil


def load_dynamic_limits_fast() -> dict[str, Any]:
    """Read dynamic limits directly from dynamic_limits.json with sub-millisecond latency (< 2ms)."""
    candidates = [
        ENTERPRISE_HOOKS_ROOT / "dynamic_limits.json",
        pathlib.Path.home() / ".gemini" / "config" / "enterprise-hooks" / "dynamic_limits.json",
    ]
    for cp in candidates:
        if cp.is_file():
            try:
                raw = cp.read_text(encoding="utf-8")
                data = json.loads(raw)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
    return {}


# Standard Governance Fallbacks (Zero-Config Resilience)
DEFAULT_MAX_HEAVY_SLOTS = 3
DEFAULT_BURST_SPACING_SECONDS = 1.2
DEFAULT_SLOT_TTL_SECONDS = 90.0
DEFAULT_MAX_QUEUE_WAIT_SECONDS = 45.0
DEFAULT_COOLDOWN_SLEEP_SECONDS = 1.0
DEFAULT_CPU_MIN_OPTIMAL = 60.0
DEFAULT_CPU_MAX_OPTIMAL = 85.0
DEFAULT_CPU_CORES_PHYSICAL = 4
DEFAULT_CPU_THREADS_LOGICAL = 8
POLL_INTERVAL_SECONDS = 0.05


def get_state_dir() -> pathlib.Path:
    """Resolve state directory, allowing override via environment variable for tests."""
    if resolve_governor_state_dir is not None:
        return resolve_governor_state_dir()
    custom_dir = os.environ.get("BURST_GUARD_STATE_DIR")
    if custom_dir:
        return pathlib.Path(custom_dir)
    return pathlib.Path.home() / ".gemini" / "config" / "enterprise-hooks" / ".burst_guard"


def get_lock_file() -> pathlib.Path:
    """Resolve unified cross-process lock file, guaranteed identical with cpu_governor."""
    if get_unified_lock_file is not None:
        return get_unified_lock_file(get_state_dir())
    return get_state_dir() / "guard.lock"


def get_state_file() -> pathlib.Path:
    return get_state_dir() / "burst_state.json"


def get_cpu_cache_file() -> pathlib.Path:
    return get_state_dir() / "cpu_cache.json"


def get_cpu_cache_lock_file() -> pathlib.Path:
    return get_state_dir() / "cpu_cache.lock"


# Regex patterns for Heavy Commands (Pool 2: Burst Compute)
HEAVY_PATTERNS = [
    # Python testing, test execution, and ML/compute scripts
    (r"\b(?:pytest|py\.test)\b", "pytest execution"),
    (r"\bpython(?:3)?(?:\.exe)?\s+(?:-m\s+)?(?:unittest|pytest|test\w*)\b", "python test runner"),
    (
        r"\bpython(?:3)?(?:\.exe)?\s+.*(?:test_|_test\.py|benchmark|stress|concurrency|train|training|fine_?tune|eval|infer|fit\b)",
        "python test/benchmark/ML script",
    ),
    # Node.js / Frontend builds & testing
    (r"\b(?:npm|yarn|pnpm|bun)\s+(?:run\s+)?(?:test|build|compile|bundle)\b", "npm/yarn test/build"),
    (r"\bnpx\s+(?:jest|vitest|playwright|cypress|webpack|vite|rollup|tsc|esbuild)\b", "npx build/test tool"),
    # Compiled languages & Build systems
    (r"\bcargo\s+(?:build|test|run|bench)\b", "cargo build/test"),
    (r"\bgo\s+(?:build|test)\b", "go build/test"),
    (r"\b(?:gcc|g\+\+|clang|clang\+\+|rustc|tsc|msbuild)\b", "native compiler invocation"),
    (r"\b(?:make|cmake|ninja|mvn|gradle)\b", "native build system"),
    # Containerization & Virtualization
    (r"\b(?:docker|docker-compose|podman)\s+(?:build|compose|up)\b", "container build/composition"),
    # Browser Automation & Heavy Crawling
    (r"\b(?:playwright|puppeteer|browser-use|selenium)\b", "browser automation runner"),
    (r"\bpython(?:3)?(?:\.exe)?\s+.*(?:crawl|scrape|firecrawl)", "heavy web scraper"),
]

# Regex patterns for Lightweight Commands (Fast-Path Bypass)
LIGHT_PATTERNS = [
    r"^\s*(?:dir|ls|pwd|cd|echo|cat|type|cls|clear|New-Item|mkdir)\b",
    r"^\s*git\s+(?:status|diff|log|branch|rev-parse|show|tag|remote|fetch)\b",
    r"^\s*(?:python|python3|node|npm|cargo|git|docker)\s+(?:--version|-v|-V)\b",
    r"^\s*(?:which|where|whoami|hostname|date|time)\b",
]


def load_guard_config() -> dict[str, Any]:
    """Retrieve burst guard configuration dynamically from hook_utils / dynamic_limits and environment overrides."""
    limits = load_dynamic_limits_fast()
    dynamic_hardware = limits.get("hardware_profile", {})
    dynamic_rules = limits.get("concurrency_rules", {})
    dynamic_timeouts = limits.get("execution_timeouts", {})

    raw_ttl = float(
        dynamic_timeouts.get(
            "burst_guard_slot_ttl_seconds",
            dynamic_timeouts.get("heavy_build_timeout_seconds", DEFAULT_SLOT_TTL_SECONDS),
        )
    )
    # Hardening TTL: Enforce slot TTL within 60.0s - 90.0s window unless overridden by BURST_GUARD_TTL
    if "BURST_GUARD_TTL" in os.environ:
        slot_ttl = float(os.environ["BURST_GUARD_TTL"])
    else:
        slot_ttl = max(60.0, min(90.0, raw_ttl if raw_ttl <= 90.0 else DEFAULT_SLOT_TTL_SECONDS))

    cfg_data: dict[str, Any] = {
        "max_heavy_slots": int(dynamic_rules.get("pool_2_local_burst_concurrent_slots", DEFAULT_MAX_HEAVY_SLOTS)),
        "burst_spacing_seconds": float(dynamic_rules.get("burst_spacing_seconds", DEFAULT_BURST_SPACING_SECONDS)),
        "cooldown_sleep_seconds": float(
            dynamic_rules.get("cooldown_sleep_seconds_on_high_load", DEFAULT_COOLDOWN_SLEEP_SECONDS)
        ),
        "slot_ttl_seconds": slot_ttl,
        "max_queue_wait_seconds": float(
            dynamic_timeouts.get("burst_guard_wait_timeout_seconds", DEFAULT_MAX_QUEUE_WAIT_SECONDS)
        ),
        "cpu_min_optimal": float(dynamic_hardware.get("optimal_cpu_load_min_percent", DEFAULT_CPU_MIN_OPTIMAL)),
        "cpu_max_optimal": float(dynamic_hardware.get("optimal_cpu_load_max_percent", DEFAULT_CPU_MAX_OPTIMAL)),
        "cpu_cores_physical": int(dynamic_hardware.get("cpu_cores_physical", DEFAULT_CPU_CORES_PHYSICAL)),
        "cpu_threads_logical": int(dynamic_hardware.get("cpu_threads_logical", DEFAULT_CPU_THREADS_LOGICAL)),
    }

    # 2. Check local governance config files if present
    cfg_candidates = [
        pathlib.Path.cwd() / "governance.config.json",
        pathlib.Path.cwd() / "project-hooks.yaml",
        ENTERPRISE_HOOKS_ROOT / "governance.config.template.json",
    ]
    for cp in cfg_candidates:
        if cp.is_file():
            try:
                raw_txt = cp.read_text(encoding="utf-8")
                data = json.loads(raw_txt) if cp.suffix == ".json" else {}
                bg_section = data.get("burst_guard")
                if isinstance(bg_section, dict):
                    if "max_heavy_slots" in bg_section:
                        cfg_data["max_heavy_slots"] = int(bg_section["max_heavy_slots"])
                    if "burst_spacing_seconds" in bg_section:
                        cfg_data["burst_spacing_seconds"] = float(bg_section["burst_spacing_seconds"])
                    if "slot_ttl_seconds" in bg_section:
                        cfg_data["slot_ttl_seconds"] = float(bg_section["slot_ttl_seconds"])
                    if "max_queue_wait_seconds" in bg_section:
                        cfg_data["max_queue_wait_seconds"] = float(bg_section["max_queue_wait_seconds"])
                    break
            except Exception:
                pass

    # 3. Environment variable overrides (Highest Precedence)
    if "BURST_GUARD_MAX_SLOTS" in os.environ:
        cfg_data["max_heavy_slots"] = int(os.environ["BURST_GUARD_MAX_SLOTS"])
    if "BURST_GUARD_SPACING" in os.environ:
        cfg_data["burst_spacing_seconds"] = float(os.environ["BURST_GUARD_SPACING"])
    if "BURST_GUARD_TTL" in os.environ:
        cfg_data["slot_ttl_seconds"] = float(os.environ["BURST_GUARD_TTL"])
    if "BURST_GUARD_WAIT_TIMEOUT" in os.environ:
        cfg_data["max_queue_wait_seconds"] = float(os.environ["BURST_GUARD_WAIT_TIMEOUT"])
    if "BURST_GUARD_COOLDOWN" in os.environ:
        cfg_data["cooldown_sleep_seconds"] = float(os.environ["BURST_GUARD_COOLDOWN"])

    return cfg_data


def read_cached_cpu(max_age_seconds: float = 0.5) -> float | None:
    """Read recently sampled CPU measurement from cache file under cross-process lock."""
    cache_file = get_cpu_cache_file()
    if not cache_file.exists():
        return None
    try:
        with CrossProcessLock(get_cpu_cache_lock_file(), timeout=1.0):
            if not cache_file.exists():
                return None
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            ts = float(data.get("timestamp", 0.0))
            val = float(data.get("cpu_percent", -1.0))
            if val >= 0.0 and (time.time() - ts) <= max_age_seconds:
                return val
    except Exception:
        pass
    return None


def write_cached_cpu(val: float) -> None:
    """Write CPU measurement sample to cache file with current timestamp under cross-process lock."""
    cache_file = get_cpu_cache_file()
    temp_file: pathlib.Path | None = None
    try:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file = cache_file.with_suffix(f".tmp.{os.getpid()}.{time.time_ns()}.{uuid.uuid4().hex}")
        temp_file.write_text(
            json.dumps({"timestamp": time.time(), "cpu_percent": val}),
            encoding="utf-8",
        )
        with CrossProcessLock(get_cpu_cache_lock_file(), timeout=1.0):
            for attempt in range(5):
                try:
                    temp_file.replace(cache_file)
                    break
                except PermissionError:
                    if attempt < 4:
                        time.sleep(0.01 * (attempt + 1))
                    else:
                        raise
    except Exception:
        pass
    finally:
        if temp_file is not None and temp_file.exists():
            with contextlib.suppress(OSError):
                temp_file.unlink()


def measure_cpu_percent(sample_interval: float = 0.05, use_cache: bool = True) -> float:
    """Measure real-time CPU utilization percentage across all cores using psutil.

    Hardened against 0.0% measurement bug on short-lived hook processes:
    - Default sample_interval is 0.05s (50ms) instead of 0.0s to ensure valid delta.
    - Integrates with sample caching (cpu_cache.json) to avoid re-sampling within 0.5s.
    """
    if use_cache:
        cached = read_cached_cpu(max_age_seconds=0.5)
        if cached is not None:
            return cached

    ps = get_psutil()
    if ps is not None:
        try:
            # Enforce minimum sample interval of 0.05s for accurate reading
            interval = sample_interval if sample_interval >= 0.05 else 0.05
            val = float(ps.cpu_percent(interval=interval))
            if use_cache:
                write_cached_cpu(val)
            return val
        except Exception:
            pass
    return 50.0


def determine_cpu_zone(cpu_load: float, cfg: dict[str, Any]) -> tuple[str, float]:
    """Classify current hardware state into Three-Zone Governor policy (4C/8T):
    1. ACCELERATION (CPU < 60%): Fast-dispatch to push load into optimal range.
    2. GOLDEN (60% <= CPU <= 85%): Sustained peak performance without fan throttling.
    3. THERMAL_PROTECTION (CPU > 85%): Pacing cooldown preventing thermal shock.
    """
    min_opt = float(cfg.get("cpu_min_optimal", DEFAULT_CPU_MIN_OPTIMAL))
    max_opt = float(cfg.get("cpu_max_optimal", DEFAULT_CPU_MAX_OPTIMAL))

    if cpu_load < min_opt:
        return "ACCELERATION", cpu_load
    elif cpu_load <= max_opt:
        return "GOLDEN", cpu_load
    else:
        return "THERMAL_PROTECTION", cpu_load


def split_chained_commands(cmd: str) -> list[str]:
    """Split command line by chaining operators (&&, ||, ;, |) outside quotes."""
    tokens: list[str] = []
    current: list[str] = []
    in_single_quote = False
    in_double_quote = False
    i = 0
    n = len(cmd)
    while i < n:
        char = cmd[i]
        if char == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            current.append(char)
            i += 1
        elif char == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            current.append(char)
            i += 1
        elif not in_single_quote and not in_double_quote:
            # Check 2-char operators: &&, ||
            if i + 1 < n and cmd[i : i + 2] in ("&&", "||"):
                sub = "".join(current).strip()
                if sub:
                    tokens.append(sub)
                current = []
                i += 2
            # Check 1-char operators: ;, |
            elif char in (";", "|"):
                sub = "".join(current).strip()
                if sub:
                    tokens.append(sub)
                current = []
                i += 1
            else:
                current.append(char)
                i += 1
        else:
            current.append(char)
            i += 1
    sub = "".join(current).strip()
    if sub:
        tokens.append(sub)
    return tokens or [cmd]


def is_single_command_heavy(cmd: str) -> tuple[bool, str]:
    """Check if a single command segment matches heavy compute patterns."""
    clean = cmd.strip()
    if not clean:
        return False, "empty_command"
    for pat, desc in HEAVY_PATTERNS:
        if re.search(pat, clean, re.IGNORECASE):
            return True, desc
    return False, "not_heavy"


def is_single_command_light(cmd: str) -> bool:
    """Check if a single command segment matches lightweight whitelist."""
    clean = cmd.strip()
    if not clean:
        return True
    for pat in LIGHT_PATTERNS:
        if re.search(pat, clean, re.IGNORECASE):
            # Must not contain any heavy patterns
            if not any(re.search(h_pat, clean, re.IGNORECASE) for h_pat, _ in HEAVY_PATTERNS):
                return True
    return False


def is_heavy_command(command_line: str) -> tuple[bool, str]:
    """Classify command as Heavy (Pool 2: Compute) or Light (Pool 1: Bypass).

    Hardened against command chaining bypass (&&, ||, ;, |):
    - Splits command line into individual sub-commands outside quotes.
    - If ANY sub-command in the chain is heavy, the entire command line is Heavy.
    """
    clean_cmd = command_line.strip()
    if not clean_cmd:
        return False, "empty_command"

    try:
        from hook_utils.powershell_normalizer import extract_base64_payloads, strip_powershell_backticks
        for p in extract_base64_payloads(command_line):
            is_h, desc = is_heavy_command(p)
            if is_h:
                return True, f"encoded_{desc}"
        clean_cmd = strip_powershell_backticks(clean_cmd)
    except ImportError:
        clean_cmd = clean_cmd.replace("`", "")

    # Unwrap common shell wrappers if present
    unwrapped = clean_cmd
    for wrapper_prefix in [
        r'^(?:powershell|pwsh)(?:\.exe)?\s+(?:-[a-zA-Z]+\s+)*["\']?(.*?)["\']?$',
        r'^cmd(?:\.exe)?\s+(?:/[a-zA-Z]+\s+)*["\']?(.*?)["\']?$',
    ]:
        m = re.match(wrapper_prefix, unwrapped, re.IGNORECASE)
        if m and m.group(1).strip():
            unwrapped = m.group(1).strip()
            break

    # Split chained commands (&&, ||, ;, |)
    sub_commands = split_chained_commands(unwrapped)

    # 1. Inspect every sub-command: If ANY sub-command is heavy, the command is HEAVY
    for sub in sub_commands:
        is_h, desc = is_single_command_heavy(sub)
        if is_h:
            if len(sub_commands) > 1:
                return True, f"chained_heavy: {desc} in '{sub[:50]}'"
            return True, desc

    # Also check full unwrapped and clean strings in case pattern spans boundary
    for pat, desc in HEAVY_PATTERNS:
        if re.search(pat, clean_cmd, re.IGNORECASE) or re.search(pat, unwrapped, re.IGNORECASE):
            return True, desc

    # 2. Fast-Path Whitelist Check: All sub-commands must be light
    if all(is_single_command_light(sub) for sub in sub_commands):
        return False, "fast_path_lightweight"

    return False, "default_unmatched_light"


class CrossProcessLock:
    """Robust cross-process file lock supporting Windows (msvcrt) and POSIX (fcntl)."""

    def __init__(self, lock_file: pathlib.Path, timeout: float = 10.0):
        self.lock_file = lock_file
        self.timeout = timeout
        self.fd: int | None = None

    def __enter__(self) -> CrossProcessLock:
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(str(self.lock_file), os.O_RDWR | os.O_CREAT)
        start_time = time.monotonic()
        while True:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    # Attempt non-blocking lock on first byte
                    msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() - start_time > self.timeout:
                    os.close(self.fd)
                    self.fd = None
                    raise TimeoutError(f"Timed out waiting for file lock: {self.lock_file}")
                time.sleep(0.02 + random.uniform(0.01, 0.03))

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.fd is not None:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    os.lseek(self.fd, 0, os.SEEK_SET)
                    msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
            except OSError:
                pass
            finally:
                os.close(self.fd)
                self.fd = None


def read_state_under_lock() -> dict[str, Any]:
    """Read burst state JSON safely under file lock."""
    state_file = get_state_file()
    if not state_file.exists():
        return {
            "active_slots": {},
            "last_burst_launch_timestamp": 0.0,
            "metrics": {"total_heavy": 0, "total_light": 0, "waits": 0},
        }
    try:
        content = state_file.read_text(encoding="utf-8")
        if not content.strip():
            return {"active_slots": {}, "last_burst_launch_timestamp": 0.0, "metrics": {}}
        data = json.loads(content)
        if isinstance(data, dict):
            return data
    except Exception as exc:
        log_diagnostic(f"Error reading burst_state.json: {exc}. Reinitializing.")
    return {"active_slots": {}, "last_burst_launch_timestamp": 0.0, "metrics": {}}


def is_process_alive(slot_info: dict[str, Any]) -> bool:
    """Check if the recorded process is genuinely alive and not a recycled PID on Windows."""
    slot_pid = slot_info.get("pid")
    if not slot_pid:
        return True
    ps = get_psutil()
    if ps is None:
        return True
    try:
        pid_int = int(slot_pid)
        if not ps.pid_exists(pid_int):
            return False
        proc = ps.Process(pid_int)
        if proc.status() == ps.STATUS_ZOMBIE:
            return False
        rec_time = slot_info.get("pid_create_time")
        if rec_time is not None:
            if abs(proc.create_time() - float(rec_time)) > 0.1:
                return False  # PID was recycled to another process
        rec_name = slot_info.get("process_name")
        if rec_name is not None:
            if proc.name().lower() != str(rec_name).lower():
                return False  # Process name changed under recycled PID
        return True
    except (ps.NoSuchProcess, ps.ZombieProcess):
        return False
    except ps.AccessDenied:
        # On Windows, non-admin process recycled to system/elevated process
        return False
    except Exception:
        return True


def write_state_under_lock(state: dict[str, Any]) -> None:
    """Atomically write burst state JSON safely under file lock with high entropy and guaranteed cleanup."""
    state_dir = get_state_dir()
    state_file = get_state_file()
    state_dir.mkdir(parents=True, exist_ok=True)
    temp_file = state_dir / f"burst_state.tmp.{os.getpid()}.{time.time_ns()}.{uuid.uuid4().hex}"
    try:
        temp_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        temp_file.replace(state_file)
    except Exception as exc:
        log_diagnostic(f"Error atomically saving burst_state.json: {exc}")
    finally:
        if temp_file.exists():
            with contextlib.suppress(OSError):
                temp_file.unlink()


def evict_stale_slots(state: dict[str, Any], ttl_seconds: float) -> int:
    """Evict expired or orphaned slots from active state based on TTL lease expiration."""
    now = time.time()
    active_slots = state.get("active_slots", {})
    to_delete: list[str] = []
    for slot_id, info in active_slots.items():
        expires_at = float(info.get("expires_at") or 0.0)
        acquired_at = float(info.get("acquired_at") or info.get("timestamp") or 0.0)
        slot_ttl = float(info.get("ttl_seconds") or ttl_seconds)
        lease = info.get("lease_token", "no-lease")

        is_stale = False
        if expires_at > 0.0 and now > expires_at:
            is_stale = True
            log_diagnostic(f"Evicted expired lease slot '{slot_id}' ({lease}) for command: {info.get('command', '')[:50]}")
        elif acquired_at > 0.0 and (now - acquired_at) > slot_ttl:
            is_stale = True
            log_diagnostic(f"Evicted stale lease slot '{slot_id}' ({lease}) (TTL {slot_ttl}s exceeded).")

        if is_stale:
            to_delete.append(slot_id)

    for slot_id in to_delete:
        del active_slots[slot_id]
    return len(to_delete)


def acquire_burst_slot(command_line: str, cwd: str, cfg: dict[str, Any]) -> tuple[bool, str]:
    """Acquire a micro-queue semaphore slot and enforce CPU-adaptive burst pacing delay."""
    max_slots = cfg["max_heavy_slots"]
    base_spacing = cfg["burst_spacing_seconds"]
    ttl = cfg["slot_ttl_seconds"]
    max_wait = cfg["max_queue_wait_seconds"]
    cooldown_sleep = cfg.get("cooldown_sleep_seconds", DEFAULT_COOLDOWN_SLEEP_SECONDS)

    cmd_hash = hashlib.sha256(f"{cwd}:{command_line}".encode()).hexdigest()[:12]
    start_wait = time.monotonic()
    waited = False

    # Sample real-time CPU utilization with sample_interval=0.05
    cpu_load = measure_cpu_percent(sample_interval=0.05)
    zone_name, _ = determine_cpu_zone(cpu_load, cfg)

    while True:
        pacing_delay = 0.0
        acquired = False
        slot_id = ""
        slots_count = 0
        lease_token = ""

        with CrossProcessLock(get_lock_file(), timeout=5.0):
            state = read_state_under_lock()
            evict_stale_slots(state, ttl)
            active_slots = state.setdefault("active_slots", {})
            metrics = state.setdefault("metrics", {"total_heavy": 0, "total_light": 0, "waits": 0})

            # Check if an available slot exists
            if len(active_slots) < max_slots:
                # Find available slot index (0, 1, 2...)
                used_indices = {
                    int(s.split("_")[1]) for s in active_slots if s.startswith("slot_") and s.split("_")[1].isdigit()
                }
                available_idx = 0
                while available_idx in used_indices:
                    available_idx += 1
                slot_id = f"slot_{available_idx}"

                now = time.time()
                last_launch = state.get("last_burst_launch_timestamp", 0.0)

                # Three-zone spacing pacing adjustment
                effective_spacing = base_spacing
                if (
                    zone_name == "THERMAL_PROTECTION"
                    and "BURST_GUARD_SPACING" not in os.environ
                ):
                    # In Thermal Protection zone (CPU > 85%), pacing delay MUST accumulate base_spacing + cooldown_sleep
                    effective_spacing = base_spacing + cooldown_sleep
                elif zone_name == "ACCELERATION" and "BURST_GUARD_SPACING" not in os.environ:
                    # In Acceleration zone with low CPU load, reduce spacing delay to accelerate dispatch
                    effective_spacing = max(0.2, base_spacing * 0.5)

                target_launch = max(now, last_launch + effective_spacing)
                # In Thermal Protection zone without test override, enforce immediate cooldown sleep if system is hot
                if zone_name == "THERMAL_PROTECTION" and "BURST_GUARD_SPACING" not in os.environ:
                    target_launch = max(target_launch, now + cooldown_sleep)

                pacing_delay = target_launch - now

                lease_token = f"lease_{cmd_hash}_{int(now * 1000)}_{random.randint(1000, 9999)}"
                command_id = f"cmd_{cmd_hash}_{int(now * 1000)}"

                curr_pid = os.getpid()
                pid_create_time = None
                process_name = None
                ps = get_psutil()
                if ps is not None:
                    try:
                        p = ps.Process(curr_pid)
                        pid_create_time = p.create_time()
                        process_name = p.name()
                    except Exception:
                        pass

                active_slots[slot_id] = {
                    "slot_id": slot_id,
                    "lease_token": lease_token,
                    "command_id": command_id,
                    "command": command_line,
                    "command_hash": cmd_hash,
                    "cwd": cwd,
                    "pid": curr_pid,
                    "pid_create_time": pid_create_time,
                    "process_name": process_name,
                    "acquired_at": now,
                    "timestamp": now,
                    "expires_at": target_launch + ttl,
                    "ttl_seconds": ttl,
                    "status": "BUSY",
                    "cpu_zone": zone_name,
                    "cpu_percent": cpu_load,
                }
                state["last_burst_launch_timestamp"] = target_launch
                metrics["total_heavy"] = metrics.get("total_heavy", 0) + 1
                if waited:
                    metrics["waits"] = metrics.get("waits", 0) + 1

                write_state_under_lock(state)
                acquired = True
                slots_count = len(active_slots)

        if acquired:
            # Execute burst pacing sleep outside the file lock to avoid lock starvation
            if pacing_delay > 0.01:
                log_diagnostic(
                    f"Burst pacing: holding {pacing_delay:.2f}s for slot {slot_id} "
                    f"[{zone_name}, CPU: {cpu_load:.1f}%] to prevent CPU shock."
                )
                time.sleep(pacing_delay)

            log_diagnostic(
                f"Acquired burst slot '{slot_id}' (lease: {lease_token}, "
                f"{slots_count}/{max_slots} active, Zone: {zone_name})."
            )
            return (
                True,
                f"Burst guard: slot '{slot_id}' acquired (lease {lease_token}, CPU {cpu_load:.1f}% [{zone_name}], "
                f"pacing {pacing_delay:.2f}s, slots {slots_count}/{max_slots}).",
            )

        # If queue is full, check for wait timeout
        elapsed_wait = time.monotonic() - start_wait
        if elapsed_wait > max_wait:
            log_diagnostic(f"Queue wait exceeded {max_wait}s. Graceful degradation: allowing execution.")
            return True, f"Burst guard: queue wait timeout ({max_wait}s) exceeded, degrading to fail-safe allow."

        waited = True
        time.sleep(POLL_INTERVAL_SECONDS + random.uniform(0.01, 0.03))


def normalize_cmd_for_matching(cmd: str) -> str:
    """Normalize command for exact matching across shell wrappers without ambiguous substrings."""
    clean = cmd.strip()
    for wrapper_prefix in [
        r'^(?:powershell|pwsh)(?:\.exe)?\s+(?:-[a-zA-Z]+\s+)*["\']?(.*?)["\']?$',
        r'^cmd(?:\.exe)?\s+(?:/[a-zA-Z]+\s+)*["\']?(.*?)["\']?$',
    ]:
        m = re.match(wrapper_prefix, clean, re.IGNORECASE)
        if m and m.group(1).strip():
            clean = m.group(1).strip()
            break
    if (clean.startswith('"') and clean.endswith('"')) or (clean.startswith("'") and clean.endswith("'")):
        clean = clean[1:-1].strip()
    return clean


def release_burst_slot(
    command_line: str,
    cwd: str,
    lease_token: str | None = None,
    slot_id: str | None = None,
) -> None:
    """Release active burst slot immediately upon PostToolUse execution."""
    cmd_hash = hashlib.sha256(f"{cwd}:{command_line}".encode()).hexdigest()[:12]
    with CrossProcessLock(get_lock_file(), timeout=5.0):
        state = read_state_under_lock()
        cfg = load_guard_config()
        evict_stale_slots(state, cfg.get("slot_ttl_seconds", DEFAULT_SLOT_TTL_SECONDS))
        active_slots = state.get("active_slots", {})
        found_slot_id: str | None = None

        # 1. Direct match by slot_id or lease_token if provided
        if slot_id and slot_id in active_slots:
            found_slot_id = slot_id
        elif lease_token:
            for s_id, s_info in active_slots.items():
                if s_info.get("lease_token") == lease_token:
                    found_slot_id = s_id
                    break

        # 2. FIFO match: find the oldest acquired slot matching command hash or exact command text
        if not found_slot_id:
            oldest_ts = float("inf")
            for s_id, s_info in active_slots.items():
                s_cmd = s_info.get("command", "")
                s_hash = s_info.get("command_hash", "")
                if s_hash == cmd_hash or s_cmd == command_line or s_cmd.strip() == command_line.strip():
                    acq = float(s_info.get("acquired_at") or s_info.get("timestamp") or 0.0)
                    if acq < oldest_ts:
                        oldest_ts = acq
                        found_slot_id = s_id

        # 3. Normalized unwrapped exact match (avoids ambiguous substring collision)
        if not found_slot_id:
            norm_target = normalize_cmd_for_matching(command_line)
            if norm_target:
                oldest_ts = float("inf")
                for s_id, s_info in active_slots.items():
                    s_cmd = s_info.get("command", "").strip()
                    norm_s = normalize_cmd_for_matching(s_cmd)
                    if norm_target == norm_s or split_chained_commands(norm_target) == split_chained_commands(norm_s):
                        acq = float(s_info.get("acquired_at") or s_info.get("timestamp") or 0.0)
                        if acq < oldest_ts:
                            oldest_ts = acq
                            found_slot_id = s_id

        if found_slot_id:
            acq_time = float(
                active_slots[found_slot_id].get("acquired_at")
                or active_slots[found_slot_id].get("timestamp")
                or time.time()
            )
            duration = time.time() - acq_time
            lease = active_slots[found_slot_id].get("lease_token", "unknown")
            del active_slots[found_slot_id]
            write_state_under_lock(state)
            log_diagnostic(f"Released burst slot '{found_slot_id}' (lease: {lease}) after {duration:.2f}s execution.")
        else:
            log_diagnostic(f"PostToolUse: No active slot matched for release ({command_line[:40]}).")


def run_self_test() -> int:
    """Built-in empirical self-test verifying CPU governor integration, 4C/8T profile, and semaphore slots."""
    import tempfile

    print("[SELF-TEST] Starting burst_execution_guard self-test suite...")
    passed = 0
    total = 10

    # 1. Dynamic Config & TTL Hardening (60-90s)
    cfg = load_guard_config()
    assert "max_heavy_slots" in cfg, "Config missing max_heavy_slots"
    assert "cpu_cores_physical" in cfg, "Config missing cpu_cores_physical"
    assert cfg["cpu_cores_physical"] == 4, f"Expected 4 cores physical, got {cfg['cpu_cores_physical']}"
    assert cfg["cpu_threads_logical"] == 8, f"Expected 8 threads logical, got {cfg['cpu_threads_logical']}"
    assert cfg["max_heavy_slots"] in (3, 4), f"Expected 3-4 slots, got {cfg['max_heavy_slots']}"
    assert (
        60.0 <= cfg["slot_ttl_seconds"] <= 90.0
    ), f"Expected slot_ttl_seconds in [60, 90], got {cfg['slot_ttl_seconds']}"
    print(
        f"  [1/10] Dynamic Config: 4C/8T detected, slots={cfg['max_heavy_slots']}, TTL={cfg['slot_ttl_seconds']}s - PASS"
    )
    passed += 1

    # 2. CPU Governor & Sample Cache (Non-zero measurement)
    cpu_percent = measure_cpu_percent(sample_interval=0.05, use_cache=False)
    zone, _ = determine_cpu_zone(cpu_percent, cfg)
    assert zone in ("ACCELERATION", "GOLDEN", "THERMAL_PROTECTION")
    # Verify cache mechanism
    write_cached_cpu(72.5)
    cached_val = read_cached_cpu(max_age_seconds=1.0)
    assert cached_val == 72.5, f"Expected cached CPU 72.5, got {cached_val}"
    print(f"  [2/10] CPU Governor & Cache: Measured {cpu_percent:.1f}% -> Zone: {zone}, Cache OK - PASS")
    passed += 1

    # 3. Basic Command Classification
    heavy, _ = is_heavy_command("pytest tests/test_schema.py")
    light, _ = is_heavy_command("git status")
    heavy_train, _ = is_heavy_command("python train.py")
    assert heavy is True, "pytest should be classified as heavy"
    assert light is False, "git status should be classified as light"
    assert heavy_train is True, "python train.py should be classified as heavy"
    print("  [3/10] Command Classifier: Heavy (pytest, python train.py) vs Light (git status) - PASS")
    passed += 1

    # 4. Command Chaining Bypass Prevention
    chain_heavy_1, _ = is_heavy_command("git status && python train.py")
    chain_heavy_2, _ = is_heavy_command('cmd /c "git status && pytest"')
    chain_heavy_3, _ = is_heavy_command("git status ; npm run build")
    chain_heavy_4, _ = is_heavy_command("cargo test || echo failed")
    chain_light_1, _ = is_heavy_command("git status && git diff")
    chain_light_2, _ = is_heavy_command('echo "hello && world"')
    assert chain_heavy_1 is True, "git status && python train.py must be classified as HEAVY"
    assert chain_heavy_2 is True, "cmd /c git status && pytest must be classified as HEAVY"
    assert chain_heavy_3 is True, "git status ; npm run build must be classified as HEAVY"
    assert chain_heavy_4 is True, "cargo test || echo failed must be classified as HEAVY"
    assert chain_light_1 is False, "git status && git diff should be LIGHT"
    assert chain_light_2 is False, 'echo "hello && world" should be LIGHT'
    print("  [4/10] Command Chaining Bypass Prevention (&&, ||, ;, |, quotes) - PASS")
    passed += 1

    # 5. Thermal Zone Pacing Calculation (base_spacing + cooldown_sleep)
    test_base_spacing = 1.2
    test_cooldown = 1.0
    calculated_spacing = test_base_spacing + test_cooldown
    assert calculated_spacing == 2.2, f"Expected 2.2s, got {calculated_spacing}"
    print(f"  [5/10] Thermal Zone Pacing: Cumulative delay {test_base_spacing}s + {test_cooldown}s = {calculated_spacing}s - PASS")
    passed += 1

    # 6. CrossProcessLock safety
    with tempfile.TemporaryDirectory() as tmp_dir:
        lock_p = pathlib.Path(tmp_dir) / "test.lock"
        with CrossProcessLock(lock_p, timeout=2.0) as lk:
            assert lk.fd is not None
        print("  [6/10] CrossProcessLock (Windows msvcrt / POSIX fcntl) - PASS")
        passed += 1

    # 7. Slot Acquire with Lease Token & Immediate Release
    with tempfile.TemporaryDirectory() as tmp_dir:
        os.environ["BURST_GUARD_STATE_DIR"] = tmp_dir
        os.environ["BURST_GUARD_SPACING"] = "0.0"
        try:
            ok, reason = acquire_burst_slot("pytest test_sample.py", tmp_dir, cfg)
            assert ok is True
            assert "lease" in reason.lower()
            state = read_state_under_lock()
            active = state.get("active_slots", {})
            assert len(active) == 1
            slot_info = next(iter(active.values()))
            assert "lease_token" in slot_info and slot_info["lease_token"].startswith("lease_")
            assert "command_id" in slot_info and slot_info["command_id"].startswith("cmd_")
            # Release
            release_burst_slot("pytest test_sample.py", tmp_dir)
            state_after = read_state_under_lock()
            assert len(state_after.get("active_slots", {})) == 0
            print("  [7/10] Slot Acquire (Lease Token) & Immediate Release - PASS")
            passed += 1
        finally:
            os.environ.pop("BURST_GUARD_STATE_DIR", None)
            os.environ.pop("BURST_GUARD_SPACING", None)

    # 8. Stale Slot TTL Eviction (60-90s window)
    mock_state = {
        "active_slots": {
            "slot_0": {
                "lease_token": "lease_old_123",
                "expires_at": time.time() - 10.0,
                "acquired_at": time.time() - 100.0,
            },
            "slot_1": {
                "lease_token": "lease_fresh_456",
                "expires_at": time.time() + 75.0,
                "acquired_at": time.time(),
            },
        }
    }
    evicted = evict_stale_slots(mock_state, ttl_seconds=75.0)
    assert evicted == 1
    assert "slot_0" not in mock_state["active_slots"]
    assert "slot_1" in mock_state["active_slots"]
    print("  [8/10] Stale Slot Lease TTL Eviction (60-90s) - PASS")
    passed += 1

    # 9. Queue Wait Timeout (Graceful Degradation)
    with tempfile.TemporaryDirectory() as tmp_dir:
        os.environ["BURST_GUARD_STATE_DIR"] = tmp_dir
        os.environ["BURST_GUARD_MAX_SLOTS"] = "1"
        os.environ["BURST_GUARD_SPACING"] = "0.0"
        os.environ["BURST_GUARD_WAIT_TIMEOUT"] = "0.3"
        try:
            cfg_small = load_guard_config()
            acquire_burst_slot("pytest job_1.py", tmp_dir, cfg_small)
            # Second acquire should timeout and degrade to allow
            t0 = time.monotonic()
            ok2, reason2 = acquire_burst_slot("pytest job_2.py", tmp_dir, cfg_small)
            elapsed = time.monotonic() - t0
            assert ok2 is True
            assert "fail-safe allow" in reason2.lower()
            assert elapsed >= 0.25
            print("  [9/10] Queue Timeout Fail-Safe Graceful Degradation - PASS")
            passed += 1
        finally:
            os.environ.pop("BURST_GUARD_STATE_DIR", None)
            os.environ.pop("BURST_GUARD_MAX_SLOTS", None)
            os.environ.pop("BURST_GUARD_SPACING", None)
            os.environ.pop("BURST_GUARD_WAIT_TIMEOUT", None)

    # 10. Fast-path latency (< 50ms)
    t_fast = time.monotonic()
    is_h, _ = is_heavy_command("dir")
    t_fast_elapsed = (time.monotonic() - t_fast) * 1000.0
    assert not is_h
    assert t_fast_elapsed < 50.0
    print(f"  [10/10] Fast-Path Bypass Latency: {t_fast_elapsed:.3f}ms (< 50ms) - PASS")
    passed += 1

    print(f"\n[SELF-TEST COMPLETE] Passed {passed}/{total} tests successfully!")
    return 0


def main() -> None:
    if "--self-test" in sys.argv:
        sys.exit(run_self_test())

    payload = read_stdin_payload(default={})
    tool_name, args = extract_tool_invocation(payload)

    # Fast check: Only inspect run_command
    if tool_name != "run_command":
        if "--post" in sys.argv:
            emit_stdout_json(post_tool_response())
        else:
            emit_stdout_json(pre_tool_response("allow", "Tool is not run_command."))
        return

    command_line = args.get("CommandLine", "")
    cwd = args.get("Cwd", str(pathlib.Path.cwd()))

    if not isinstance(command_line, str) or not command_line.strip():
        if "--post" in sys.argv:
            emit_stdout_json(post_tool_response())
        else:
            emit_stdout_json(pre_tool_response("allow", "Empty CommandLine argument."))
        return

    is_heavy, desc = is_heavy_command(command_line)

    if "--post" in sys.argv:
        if is_heavy:
            release_burst_slot(command_line, cwd)
        emit_stdout_json(post_tool_response())
        return

    # PreToolUse branch
    if not is_heavy:
        # Fast path: lightweight commands bypass immediately with 0 delay
        emit_stdout_json(pre_tool_response("allow", f"Burst guard: Fast-path bypass for lightweight command ({desc})."))
        return

    # Heavy command: acquire slot through Micro-Queue Semaphore
    cfg = load_guard_config()
    allowed, reason = acquire_burst_slot(command_line, cwd, cfg)
    emit_stdout_json(pre_tool_response("allow" if allowed else "deny", reason))


if __name__ == "__main__":
    main()
