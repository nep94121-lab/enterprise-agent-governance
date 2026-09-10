#!/usr/bin/env python3
"""Enterprise Hook Utilities - Dynamic CPU Governor.

Adapts physical execution concurrency to CPU load (Dynamic Host Cores & Threads (os.cpu_count())):
- Pool 1: Cloud Thinking & Light I/O (Unlimited Concurrency).
- Pool 2: Local Burst Compute (Micro-Queue Semaphore with 3-4 Slots).

Implements the Three-Zone Governor Algorithm:
1. ACCELERATION ZONE (CPU < 60%): Fast-dispatch to push load into optimal range.
2. GOLDEN ZONE (60% <= CPU <= 85%): Sustained peak performance without fan throttling.
3. THERMAL PROTECTION ZONE (CPU > 85%): 1.0s pacing cooldown preventing thermal shock.
"""

from __future__ import annotations

import contextlib
from enum import Enum
import json
import logging
import os
import pathlib
import random
import re
import sys
import time
from typing import Any, Generator

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

from .config_loader import (
    get_concurrency_rules,
    get_execution_timeouts,
    get_hardware_profile,
)

logger = logging.getLogger("enterprise_hooks.cpu_governor")

# Default values if dynamic config is unreachable
DEFAULT_BURST_SLOTS = 3
DEFAULT_CPU_MIN_OPTIMAL = 60.0
DEFAULT_CPU_MAX_OPTIMAL = 85.0
DEFAULT_COOLDOWN_SECONDS = 1.0
DEFAULT_HEAVY_TIMEOUT_SECONDS = 180.0
DEFAULT_WAIT_TIMEOUT_SECONDS = 45.0
POLL_INTERVAL_SECONDS = 0.08


class CPUZone(str, Enum):
    """Execution zones determined by real-time CPU utilization."""

    ACCELERATION = "ACCELERATION"  # CPU < 60% (ép tăng tải)
    GOLDEN = "GOLDEN"  # 60% <= CPU <= 85% (vùng hoàng kim)
    THERMAL_PROTECTION = "THERMAL_PROTECTION"  # CPU > 85% (nghỉ luân phiên)


# Patterns for Heavy Commands (Pool 2: Compute)
HEAVY_COMMAND_PATTERNS = [
    (r"\b(?:pytest|py\.test)\b", "pytest execution"),
    (r"\bpython(?:\.exe)?\s+(?:-m\s+)?(?:unittest|pytest|test\w*)\b", "python test runner"),
    (r"\bpython(?:\.exe)?\s+.*(?:test_|_test\.py|benchmark|stress|concurrency)", "python test/benchmark script"),
    (r"\b(?:npm|yarn|pnpm|bun)\s+(?:run\s+)?(?:test|build|compile|bundle)\b", "npm/yarn test/build"),
    (r"\bnpx\s+(?:jest|vitest|playwright|cypress|webpack|vite|rollup|tsc|esbuild)\b", "npx build/test tool"),
    (r"\bcargo\s+(?:build|test|run|bench)\b", "cargo build/test"),
    (r"\bgo\s+(?:build|test)\b", "go build/test"),
    (r"\b(?:gcc|g\+\+|clang|clang\+\+|rustc|tsc|msbuild)\b", "compiler invocation"),
    (r"\b(?:make|cmake|ninja|mvn|gradle)\b", "build system"),
    (r"\b(?:docker|docker-compose|podman)\s+(?:build|compose|up)\b", "container build"),
    (r"\b(?:playwright|puppeteer|browser-use|selenium)\b", "browser automation runner"),
    (r"\bpython(?:\.exe)?\s+.*(?:crawl|scrape|firecrawl)", "web scraper"),
]

# Patterns for Lightweight Commands (Pool 1: Bypass)
LIGHT_COMMAND_PATTERNS = [
    r"^\s*(?:dir|ls|pwd|cd|echo|cat|type|cls|clear|New-Item|mkdir)\b",
    r"^\s*git\s+(?:status|diff|log|branch|rev-parse|show|tag|remote|fetch)\b",
    r"^\s*(?:python|node|npm|cargo|git|docker)\s+(?:--version|-v|-V)\b",
    r"^\s*(?:which|where|whoami|hostname|date|time)\b",
]


def resolve_governor_state_dir() -> pathlib.Path:
    """Resolve state directory for semaphore and locking."""
    custom_dir = os.environ.get("BURST_GUARD_STATE_DIR")
    if custom_dir:
        return pathlib.Path(custom_dir)
    return pathlib.Path.home() / ".gemini" / "config" / "enterprise-hooks" / ".burst_guard"


def classify_command(command_line: str) -> tuple[bool, str]:
    """Classify a command line as Heavy (Pool 2) or Light (Pool 1 Bypass)."""
    clean = command_line.strip()
    if not clean:
        return False, "empty_command"

    # Unwrap shell wrappers
    unwrapped = clean
    for wrapper in [
        r'^(?:powershell|pwsh)(?:\.exe)?\s+(?:-[a-zA-Z]+\s+)*["\']?(.*?)["\']?$',
        r'^cmd(?:\.exe)?\s+(?:/[a-zA-Z]+\s+)*["\']?(.*?)["\']?$',
    ]:
        match = re.match(wrapper, unwrapped, re.IGNORECASE)
        if match and match.group(1).strip():
            unwrapped = match.group(1).strip()
            break

    # 1. Fast-Path Light Check
    for pat in LIGHT_COMMAND_PATTERNS:
        if re.search(pat, clean, re.IGNORECASE) or re.search(pat, unwrapped, re.IGNORECASE):
            # Verify it does not embed heavy subcommands
            if not any(re.search(h_pat, clean, re.IGNORECASE) for h_pat, _ in HEAVY_COMMAND_PATTERNS):
                return False, "lightweight_bypass"

    # 2. Heavy Check
    for pat, desc in HEAVY_COMMAND_PATTERNS:
        if re.search(pat, clean, re.IGNORECASE) or re.search(pat, unwrapped, re.IGNORECASE):
            return True, desc

    return False, "default_light_unmatched"


class CrossProcessLock:
    """Cross-process file lock supporting Windows msvcrt and POSIX fcntl."""

    def __init__(self, lock_file: pathlib.Path, timeout: float = 10.0) -> None:
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

                    msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() - start_time > self.timeout:
                    os.close(self.fd)
                    self.fd = None
                    raise TimeoutError(f"Timed out waiting for file lock: {self.lock_file}") from None
                time.sleep(0.01 + random.uniform(0.01, 0.02))

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


class CPUGovernor:
    """Three-Zone Adaptive Hardware Governor and Micro-Queue Semaphore."""

    def __init__(self, state_dir: pathlib.Path | None = None) -> None:
        self.state_dir: pathlib.Path = state_dir or resolve_governor_state_dir()
        self.lock_file: pathlib.Path = self.state_dir / "governor.lock"
        self.state_file: pathlib.Path = self.state_dir / "burst_state.json"

    def get_cpu_usage(self, sample_interval: float = 0.05) -> float:
        """Measure real-time CPU utilization percentage with psutil."""
        if psutil is not None:
            try:
                return float(psutil.cpu_percent(interval=sample_interval))
            except Exception as exc:
                logger.debug("Failed psutil measurement: %s", exc)
        return 50.0

    def get_current_zone(self, sample_interval: float = 0.05) -> tuple[CPUZone, float]:
        """Classify current hardware state into one of the three governor zones."""
        cpu = self.get_cpu_usage(sample_interval=sample_interval)
        profile = get_hardware_profile()
        min_opt = float(profile.get("optimal_cpu_load_min_percent", DEFAULT_CPU_MIN_OPTIMAL))
        max_opt = float(profile.get("optimal_cpu_load_max_percent", DEFAULT_CPU_MAX_OPTIMAL))

        if cpu < min_opt:
            return CPUZone.ACCELERATION, cpu
        elif cpu <= max_opt:
            return CPUZone.GOLDEN, cpu
        else:
            return CPUZone.THERMAL_PROTECTION, cpu

    def _read_state_locked(self) -> dict[str, Any]:
        """Read state JSON safely under file lock."""
        if not self.state_file.exists():
            return {"active_slots": {}, "last_burst_timestamp": 0.0, "metrics": {}}
        try:
            raw = self.state_file.read_text(encoding="utf-8")
            if not raw.strip():
                return {"active_slots": {}, "last_burst_timestamp": 0.0, "metrics": {}}
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
        except Exception as exc:
            logger.debug("Error reading burst_state.json: %s", exc)
        return {"active_slots": {}, "last_burst_timestamp": 0.0, "metrics": {}}

    def _write_state_locked(self, state: dict[str, Any]) -> None:
        """Atomically write state JSON under file lock."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = self.state_file.with_suffix(f".tmp.{os.getpid()}.{random.randint(100, 999)}")
        try:
            tmp_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
            tmp_path.replace(self.state_file)
        except Exception as exc:
            logger.debug("Failed writing state file: %s", exc)
            if tmp_path.exists():
                with contextlib.suppress(OSError):
                    tmp_path.unlink()

    def cleanup_zombies(self, max_ttl: float | None = None) -> int:
        """Evict stale slots or slots whose PID is no longer alive."""
        timeouts = get_execution_timeouts()
        ttl = max_ttl or float(timeouts.get("heavy_build_timeout_seconds", DEFAULT_HEAVY_TIMEOUT_SECONDS))
        evicted = 0
        now = time.time()

        with CrossProcessLock(self.lock_file):
            state = self._read_state_locked()
            active_slots = state.get("active_slots", {})
            retained = {}

            for slot_id, slot_info in active_slots.items():
                slot_ts = float(slot_info.get("timestamp", 0.0))
                slot_pid = slot_info.get("pid")
                is_stale = (now - slot_ts) > ttl

                is_dead = False
                if slot_pid and psutil is not None:
                    try:
                        if not psutil.pid_exists(int(slot_pid)):
                            is_dead = True
                    except Exception:
                        pass

                if is_stale or is_dead:
                    evicted += 1
                    logger.debug("Evicted zombie slot %s (stale=%s, dead=%s)", slot_id, is_stale, is_dead)
                else:
                    retained[slot_id] = slot_info

            if evicted > 0:
                state["active_slots"] = retained
                self._write_state_locked(state)

        return evicted

    def acquire_slot(
        self,
        command: str,
        pid: int | None = None,
        task_id: str | None = None,
        timeout: float = DEFAULT_WAIT_TIMEOUT_SECONDS,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Acquire a concurrent execution slot in Pool 2.

        Applies Three-Zone Governor policy:
        - Accelerates entry when CPU < 60%.
        - Sustains slot throughput when 60% <= CPU <= 85%.
        - Inserts pacing sleep when CPU > 85% before entry.
        """
        rules = get_concurrency_rules()
        max_slots = int(rules.get("pool_2_local_burst_concurrent_slots", DEFAULT_BURST_SLOTS))
        cooldown_sleep = float(rules.get("cooldown_sleep_seconds_on_high_load", DEFAULT_COOLDOWN_SECONDS))

        slot_id = f"slot_{os.getpid()}_{task_id or random.randint(1000, 9999)}"
        assigned_pid = pid or os.getpid()
        start_wait = time.monotonic()

        while True:
            # 1. Clean up dead/stale processes
            self.cleanup_zombies()

            # 2. Check real-time CPU zone
            zone, cpu_load = self.get_current_zone(sample_interval=0.03)

            # In Thermal Protection zone, apply pacing cooldown
            if zone == CPUZone.THERMAL_PROTECTION:
                logger.info("Thermal Protection active (CPU=%.1f%% > 85%%). Cooling down %.1fs", cpu_load, cooldown_sleep)
                time.sleep(cooldown_sleep)

            # 3. Attempt slot acquisition under file lock
            with CrossProcessLock(self.lock_file):
                state = self._read_state_locked()
                active_slots = state.get("active_slots", {})

                if len(active_slots) < max_slots:
                    active_slots[slot_id] = {
                        "command": command[:120],
                        "pid": assigned_pid,
                        "timestamp": time.time(),
                        "zone_at_entry": zone.value,
                        "cpu_at_entry": cpu_load,
                    }
                    state["active_slots"] = active_slots
                    state["last_burst_timestamp"] = time.time()
                    metrics = state.setdefault("metrics", {})
                    metrics["total_heavy_dispatched"] = metrics.get("total_heavy_dispatched", 0) + 1
                    self._write_state_locked(state)

                    telemetry = {
                        "slot_id": slot_id,
                        "active_slots": len(active_slots),
                        "max_slots": max_slots,
                        "cpu_zone": zone.value,
                        "cpu_percent": cpu_load,
                        "wait_seconds": round(time.monotonic() - start_wait, 3),
                    }
                    return True, slot_id, telemetry

            # Check timeout
            elapsed = time.monotonic() - start_wait
            if elapsed > timeout:
                telemetry = {
                    "active_slots": max_slots,
                    "max_slots": max_slots,
                    "cpu_zone": zone.value,
                    "cpu_percent": cpu_load,
                    "wait_seconds": round(elapsed, 3),
                }
                return False, "", telemetry

            time.sleep(POLL_INTERVAL_SECONDS + random.uniform(0.01, 0.03))

    def release_slot(self, slot_id: str) -> bool:
        """Release an occupied execution slot immediately."""
        with CrossProcessLock(self.lock_file):
            state = self._read_state_locked()
            active_slots = state.get("active_slots", {})
            if slot_id in active_slots:
                del active_slots[slot_id]
                state["active_slots"] = active_slots
                self._write_state_locked(state)
                return True
        return False

    def get_state(self) -> dict[str, Any]:
        """Retrieve current governor telemetry snapshot."""
        with CrossProcessLock(self.lock_file):
            return self._read_state_locked()


@contextlib.contextmanager
def governor_guard(
    command_line: str,
    timeout: float = DEFAULT_WAIT_TIMEOUT_SECONDS,
) -> Generator[dict[str, Any], None, None]:
    """Context manager wrapping command execution with adaptive CPU governance.

    If command is lightweight -> executes immediately (Bypass).
    If command is heavy -> acquires Micro-Queue slot and regulates CPU load.
    """
    is_heavy, reason = classify_command(command_line)
    governor = CPUGovernor()

    if not is_heavy:
        yield {
            "mode": "LIGHT_BYPASS",
            "reason": reason,
            "slot_acquired": False,
            "cpu_zone": CPUZone.ACCELERATION.value,
        }
        return

    # Heavy execution: Acquire slot
    success, slot_id, telemetry = governor.acquire_slot(command=command_line, timeout=timeout)
    if not success:
        raise TimeoutError(f"CPU Governor timeout after {timeout}s: Slots saturated ({telemetry})")

    telemetry["mode"] = "HEAVY_SLOT"
    telemetry["reason"] = reason
    telemetry["slot_acquired"] = True

    try:
        yield telemetry
    finally:
        governor.release_slot(slot_id)
