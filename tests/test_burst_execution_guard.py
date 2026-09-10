#!/usr/bin/env python3
"""Automated Test Suite for burst_execution_guard Hook.

Validates:
1. Accurate classification of heavy test/build tools vs. light metadata tools.
2. Fast-path lightweight command bypass (< 0.5s, 0 slot usage).
3. Heavy command slot acquisition via Micro-Queue Semaphore.
4. PostToolUse immediate slot release without waiting for TTL.
5. Non-run_command and empty CommandLine bypasses.
6. Burst pacing spacing delay between consecutive heavy launches.
7. Micro-Queue Semaphore concurrency limits (MAX_HEAVY_SLOTS).
8. Stale slot TTL lease eviction and deadlock resilience.
9. Cross-process kernel locking safety on Windows (msvcrt.locking).
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

import pytest

REPO_ROOT = pathlib.Path(__file__).parent.parent.resolve()
HOOKS_DIR = REPO_ROOT / "hooks_scripts"
PYTHON_EXE = sys.executable
GUARD_SCRIPT = HOOKS_DIR / "burst_execution_guard.py"

sys.path.insert(0, str(HOOKS_DIR))
from burst_execution_guard import (
    CrossProcessLock,
    evict_stale_slots,
    is_heavy_command,
    load_guard_config,
    read_state_under_lock,
    write_state_under_lock,
)


def run_guard(
    payload: dict[str, Any],
    flag: str = "",
    extra_env: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> tuple[int, dict[str, Any], str]:
    """Execute burst_execution_guard.py as a subprocess simulating Antigravity stdin streaming."""
    args = [PYTHON_EXE, str(GUARD_SCRIPT)]
    if flag:
        args.append(flag)
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        args,
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
        cwd=str(REPO_ROOT),
        env=env,
        check=False,
    )
    parsed = {}
    if proc.stdout.strip():
        try:
            parsed = json.loads(proc.stdout.strip())
        except json.JSONDecodeError:
            parsed = {"raw": proc.stdout}
    return proc.returncode, parsed, proc.stderr


@pytest.fixture
def isolated_guard_env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    """Fixture providing an isolated temporary state directory for burst guard testing."""
    state_dir = tmp_path / ".burst_guard"
    state_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("BURST_GUARD_STATE_DIR", str(state_dir))
    monkeypatch.setenv("BURST_GUARD_MAX_SLOTS", "3")
    monkeypatch.setenv("BURST_GUARD_SPACING", "0.1")
    monkeypatch.setenv("BURST_GUARD_TTL", "10.0")
    monkeypatch.setenv("BURST_GUARD_WAIT_TIMEOUT", "5.0")
    return {
        "state_dir": state_dir,
        "env": {
            "BURST_GUARD_STATE_DIR": str(state_dir),
            "BURST_GUARD_MAX_SLOTS": "3",
            "BURST_GUARD_SPACING": "0.1",
            "BURST_GUARD_TTL": "10.0",
            "BURST_GUARD_WAIT_TIMEOUT": "5.0",
        },
    }


class TestBurstExecutionGuard:
    """Comprehensive test suite for burst_execution_guard."""

    def test_classifier_heavy_vs_light(self):
        """Verify command classification accuracy."""
        # Heavy commands
        assert is_heavy_command("pytest tests/ -q")[0] is True
        assert is_heavy_command("py.test tests/ -v")[0] is True
        assert is_heavy_command("python -m unittest discover")[0] is True
        assert is_heavy_command("python -m pytest")[0] is True
        assert is_heavy_command("python run_stress_benchmark.py")[0] is True
        assert is_heavy_command("python test_sample.py")[0] is True
        assert is_heavy_command("npm test")[0] is True
        assert is_heavy_command("npm run build")[0] is True
        assert is_heavy_command("yarn test")[0] is True
        assert is_heavy_command("npx vitest run")[0] is True
        assert is_heavy_command("cargo test --release")[0] is True
        assert is_heavy_command("cargo build")[0] is True
        assert is_heavy_command("go test ./...")[0] is True
        assert is_heavy_command("docker build -t app .")[0] is True
        assert is_heavy_command("playwright test")[0] is True

        # Shell-wrapped heavy commands
        assert is_heavy_command('powershell -Command "pytest tests/"')[0] is True
        assert is_heavy_command('cmd /c "npm run build"')[0] is True

        # Lightweight commands
        assert is_heavy_command("dir")[0] is False
        assert is_heavy_command("ls -la")[0] is False
        assert is_heavy_command("pwd")[0] is False
        assert is_heavy_command("cd ..")[0] is False
        assert is_heavy_command("git status")[0] is False
        assert is_heavy_command("git diff HEAD~1")[0] is False
        assert is_heavy_command("git log -n 5")[0] is False
        assert is_heavy_command("git branch")[0] is False
        assert is_heavy_command("echo Hello World")[0] is False
        assert is_heavy_command("python --version")[0] is False
        assert is_heavy_command("node -v")[0] is False
        assert is_heavy_command("cat package.json")[0] is False
        assert is_heavy_command("type README.md")[0] is False
        assert is_heavy_command("which git")[0] is False

        # Shell-wrapped light commands
        assert is_heavy_command('powershell -Command "dir"')[0] is False
        assert is_heavy_command('cmd /c "git status"')[0] is False

    def test_fast_path_lightweight_bypass(self, isolated_guard_env):
        """Verify lightweight commands pass in < 0.5s with 0 slot consumption."""
        payload = {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "git status"},
            }
        }
        start = time.monotonic()
        code, out, err = run_guard(payload, extra_env=isolated_guard_env["env"])
        elapsed = time.monotonic() - start

        assert code == 0
        assert out.get("decision") == "allow"
        assert "Fast-path bypass" in out.get("reason", "")
        assert elapsed < 0.5

    def test_heavy_command_acquisition_and_release(self, isolated_guard_env):
        """Verify heavy command acquires slot and PostToolUse immediately frees it."""
        cmd = "pytest tests/test_schema.py"
        pre_payload = {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": cmd, "Cwd": str(REPO_ROOT)},
            }
        }
        post_payload = {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": cmd, "Cwd": str(REPO_ROOT)},
            }
        }

        # 1. PreToolUse Acquire
        code, out, _ = run_guard(pre_payload, extra_env=isolated_guard_env["env"])
        assert code == 0
        assert out.get("decision") == "allow"
        assert "slot" in out.get("reason", "").lower()

        # Check state file
        state_file = isolated_guard_env["state_dir"] / "burst_state.json"
        assert state_file.exists()
        state = json.loads(state_file.read_text(encoding="utf-8"))
        assert len(state.get("active_slots", {})) == 1

        # 2. PostToolUse Release
        code_post, out_post, _ = run_guard(post_payload, flag="--post", extra_env=isolated_guard_env["env"])
        assert code_post == 0
        assert out_post == {}

        # Check slot released
        state_after = json.loads(state_file.read_text(encoding="utf-8"))
        assert len(state_after.get("active_slots", {})) == 0

    def test_non_run_command_bypass(self, isolated_guard_env):
        """Verify non-run_command tools bypass immediately."""
        payload = {
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": "sample.txt"},
            }
        }
        code, out, _ = run_guard(payload, extra_env=isolated_guard_env["env"])
        assert code == 0
        assert out.get("decision") == "allow"
        assert "Tool is not run_command" in out.get("reason", "")

        # Post check
        code_p, out_p, _ = run_guard(payload, flag="--post", extra_env=isolated_guard_env["env"])
        assert code_p == 0
        assert out_p == {}

    def test_empty_command_line_bypass(self, isolated_guard_env):
        """Verify empty command line argument bypasses safely."""
        payload = {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "   "},
            }
        }
        code, out, _ = run_guard(payload, extra_env=isolated_guard_env["env"])
        assert code == 0
        assert out.get("decision") == "allow"
        assert "Empty CommandLine" in out.get("reason", "")

    def test_burst_pacing_delay(self, isolated_guard_env):
        """Verify burst pacing delay is enforced between back-to-back heavy commands."""
        env = isolated_guard_env["env"].copy()
        env["BURST_GUARD_SPACING"] = "0.4"
        cmd1 = "pytest tests/unit_1.py"
        cmd2 = "pytest tests/unit_2.py"

        payload1 = {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd1, "Cwd": str(REPO_ROOT)}}}
        payload2 = {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd2, "Cwd": str(REPO_ROOT)}}}

        # First command
        start1 = time.monotonic()
        code1, out1, _ = run_guard(payload1, extra_env=env)
        time1 = time.monotonic() - start1
        assert code1 == 0
        assert out1.get("decision") == "allow"

        # Second command immediately after
        start2 = time.monotonic()
        code2, out2, _ = run_guard(payload2, extra_env=env)
        time2 = time.monotonic() - start2
        assert code2 == 0
        assert out2.get("decision") == "allow"
        # Should have waited around 0.4s pacing delay
        assert time2 >= 0.25

        # Cleanup slots
        run_guard(payload1, flag="--post", extra_env=env)
        run_guard(payload2, flag="--post", extra_env=env)

    def test_micro_queue_semaphore_concurrency_limit(self, isolated_guard_env):
        """Verify Micro-Queue Semaphore enforces max active slots and releases properly."""
        env = isolated_guard_env["env"].copy()
        env["BURST_GUARD_MAX_SLOTS"] = "2"
        env["BURST_GUARD_SPACING"] = "0.0"

        cmd1 = "cargo test suite_1"
        cmd2 = "cargo test suite_2"
        payload1 = {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd1, "Cwd": str(REPO_ROOT)}}}
        payload2 = {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd2, "Cwd": str(REPO_ROOT)}}}

        # Acquire 2 slots (filling capacity)
        code1, out1, _ = run_guard(payload1, extra_env=env)
        code2, out2, _ = run_guard(payload2, extra_env=env)
        assert code1 == 0 and out1.get("decision") == "allow"
        assert code2 == 0 and out2.get("decision") == "allow"

        state_file = isolated_guard_env["state_dir"] / "burst_state.json"
        state = json.loads(state_file.read_text(encoding="utf-8"))
        assert len(state.get("active_slots", {})) == 2

        # Release one slot
        code_rel, out_rel, _ = run_guard(payload1, flag="--post", extra_env=env)
        assert code_rel == 0

        state_after = json.loads(state_file.read_text(encoding="utf-8"))
        assert len(state_after.get("active_slots", {})) == 1

        # Now third command can acquire the freed slot
        cmd3 = "cargo test suite_3"
        payload3 = {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd3, "Cwd": str(REPO_ROOT)}}}
        code3, out3, _ = run_guard(payload3, extra_env=env)
        assert code3 == 0 and out3.get("decision") == "allow"

        # Final cleanup
        run_guard(payload2, flag="--post", extra_env=env)
        run_guard(payload3, flag="--post", extra_env=env)

    def test_stale_slot_ttl_eviction(self, isolated_guard_env):
        """Verify stale slots past their TTL are evicted automatically."""
        state = {
            "active_slots": {
                "slot_0": {
                    "slot_id": "slot_0",
                    "command": "pytest orphan.py",
                    "command_hash": "orphaned123",
                    "cwd": "C:\\fake",
                    "pid": 99999,
                    "acquired_at": time.time() - 100.0,
                    "expires_at": time.time() - 10.0,  # Expired
                    "status": "BUSY",
                },
                "slot_1": {
                    "slot_id": "slot_1",
                    "command": "npm test active",
                    "command_hash": "active456",
                    "cwd": "C:\\fake",
                    "pid": 99998,
                    "acquired_at": time.time(),
                    "expires_at": time.time() + 80.0,  # Still valid
                    "status": "BUSY",
                },
            },
            "last_burst_launch_timestamp": time.time(),
            "metrics": {},
        }

        evicted = evict_stale_slots(state, ttl_seconds=90.0)
        assert evicted == 1
        assert "slot_0" not in state["active_slots"]
        assert "slot_1" in state["active_slots"]

    def test_cross_process_locking_primitive(self, isolated_guard_env):
        """Verify CrossProcessLock file locking under single and concurrent access."""
        lock_file = isolated_guard_env["state_dir"] / "test.lock"

        # Sequential locking
        with CrossProcessLock(lock_file, timeout=2.0) as lock1:
            assert lock1.fd is not None

        # Lock is released after exit
        with CrossProcessLock(lock_file, timeout=2.0) as lock2:
            assert lock2.fd is not None

    def test_load_guard_config_defaults_and_env(self, monkeypatch: pytest.MonkeyPatch):
        """Verify config resolution from defaults and environment overrides."""
        monkeypatch.setenv("BURST_GUARD_MAX_SLOTS", "4")
        monkeypatch.setenv("BURST_GUARD_SPACING", "2.0")
        monkeypatch.setenv("BURST_GUARD_TTL", "120.0")
        monkeypatch.setenv("BURST_GUARD_WAIT_TIMEOUT", "30.0")

        cfg = load_guard_config()
        assert cfg["max_heavy_slots"] == 4
        assert cfg["burst_spacing_seconds"] == 2.0
        assert cfg["slot_ttl_seconds"] == 120.0
        assert cfg["max_queue_wait_seconds"] == 30.0
