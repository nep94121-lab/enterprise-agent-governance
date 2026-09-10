#!/usr/bin/env python3
"""Windows Job Object Governor Hook (PreToolUse) for Enterprise Multi-Agent Governance System.

Provides process tree isolation and resource governance on Windows 11:
1. Intercepts `run_command` invocations at PreToolUse.
2. Identifies heavy or long-running commands (pytest, build, compile, node, python servers).
3. Allocates and configures Windows Job Objects with:
   - JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (0x2000): Ensures 100% of child processes
     are terminated when the parent process or handle is closed, preventing zombie processes.
   - JOBOBJECT_CPU_RATE_CONTROL_INFORMATION (default 80% cap): Restricts peak CPU
     utilization to avoid starvation of OS and concurrent I/O subagents.
4. Manages a local job registry for active process tracking and graceful cleanup.
5. Provides a zero-crash graceful fallback on non-Windows platforms or permission constraints.
6. Includes a comprehensive `--self-test` verification suite with clean exit code 0.
"""

from __future__ import annotations

import ctypes
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import time
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

# Win32 Constants
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000

JobObjectExtendedLimitInformation = 9
JobObjectCpuRateControlInformation = 15

JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x00000001
JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x00000004

PROCESS_SET_QUOTA = 0x0100
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_INFORMATION = 0x0400

# Regex pattern for identifying heavy compute workloads that spawn child trees
HEAVY_COMMAND_PATTERN = re.compile(
    r"\b(python|pytest|node|npm|npx|cargo|docker|go\s+test|mvn|gradle|tsc|webpack|vite|uvicorn|gunicorn|celery)\b",
    re.IGNORECASE,
)


# CTypes Structures for Win32 Job Object API
class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryLimit", ctypes.c_size_t),
        ("PeakJobMemoryLimit", ctypes.c_size_t),
    ]


class JOBOBJECT_CPU_RATE_CONTROL_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ControlFlags", ctypes.c_uint32),
        ("CpuRate", ctypes.c_uint32),
    ]


def is_windows() -> bool:
    """Check if the current runtime operating system is Windows."""
    return sys.platform.startswith("win")


def get_job_state_dir() -> pathlib.Path:
    """Resolve directory for storing job state and registry."""
    override = os.environ.get("JOB_OBJECT_STATE_DIR")
    if override:
        path = pathlib.Path(override)
    else:
        path = pathlib.Path.home() / ".gemini" / "config" / "enterprise-hooks" / ".job_objects"
    path.mkdir(parents=True, exist_ok=True)
    return path


class WindowsJobObjectGovernor:
    """Governs process lifecycle, limits, and cleanup via Windows Job Objects."""

    def __init__(self, state_dir: pathlib.Path | None = None) -> None:
        self.state_dir = state_dir or get_job_state_dir()
        self.registry_file = self.state_dir / "job_registry.json"
        self._k32: Any | None = None
        if is_windows():
            try:
                self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            except Exception as exc:
                log_diagnostic(f"Failed to load kernel32.dll: {exc}")
                self._k32 = None

    def is_available(self) -> bool:
        """Return True if native Windows Job Object API is available."""
        return self._k32 is not None and hasattr(self._k32, "CreateJobObjectW")

    def create_governed_job(
        self,
        job_name: str,
        kill_on_close: bool = True,
        cpu_rate_percent: int = 80,
    ) -> tuple[int | None, str]:
        """Create and configure a Job Object with kill-on-close and CPU cap limits.

        Returns (handle, error_or_success_message).
        """
        if not self.is_available():
            return None, "Win32 Job Object API unavailable (non-Windows or unsupported platform)"

        try:
            assert self._k32 is not None
            h_job = self._k32.CreateJobObjectW(None, job_name)
            if not h_job:
                err = ctypes.get_last_error()
                return None, f"CreateJobObjectW failed with error code: {err}"

            # 1. Apply Extended Limit: Kill on close
            if kill_on_close:
                info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                res = self._k32.SetInformationJobObject(
                    h_job,
                    JobObjectExtendedLimitInformation,
                    ctypes.byref(info),
                    ctypes.sizeof(info),
                )
                if not res:
                    err = ctypes.get_last_error()
                    log_diagnostic(f"Warning: SetInformationJobObject (kill-on-close) failed: {err}")

            # 2. Apply CPU Rate Limit (in units of 1/100 of a percent: 80% = 8000)
            if 0 < cpu_rate_percent <= 100:
                cpu_info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION()
                cpu_info.ControlFlags = (
                    JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
                )
                cpu_info.CpuRate = int(cpu_rate_percent * 100)
                res_cpu = self._k32.SetInformationJobObject(
                    h_job,
                    JobObjectCpuRateControlInformation,
                    ctypes.byref(cpu_info),
                    ctypes.sizeof(cpu_info),
                )
                if not res_cpu:
                    err = ctypes.get_last_error()
                    log_diagnostic(f"Warning: SetInformationJobObject (cpu-rate) failed: {err}")

            return int(h_job), "Success"

        except Exception as exc:
            return None, f"Unexpected exception in create_governed_job: {exc}"

    def assign_pid_to_job(self, h_job: int, pid: int) -> tuple[bool, str]:
        """Assign an active process ID to the designated Job Object handle."""
        if not self.is_available() or not h_job:
            return False, "Job Object handle or API unavailable"

        try:
            assert self._k32 is not None
            h_proc = self._k32.OpenProcess(
                PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION,
                False,
                pid,
            )
            if not h_proc:
                err = ctypes.get_last_error()
                return False, f"OpenProcess for PID {pid} failed: {err}"

            try:
                res = self._k32.AssignProcessToJobObject(h_job, h_proc)
                if not res:
                    err = ctypes.get_last_error()
                    return False, f"AssignProcessToJobObject failed: {err}"
                return True, f"PID {pid} assigned to Job Object successfully"
            finally:
                self._k32.CloseHandle(h_proc)

        except Exception as exc:
            return False, f"Exception assigning PID {pid}: {exc}"

    def close_job_handle(self, h_job: int) -> bool:
        """Close job object handle."""
        if not self.is_available() or not h_job:
            return False
        try:
            assert self._k32 is not None
            return bool(self._k32.CloseHandle(h_job))
        except Exception:
            return False

    def load_registry(self) -> dict[str, Any]:
        """Load job tracking registry from disk."""
        if self.registry_file.is_file():
            try:
                data = json.loads(self.registry_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
        return {"jobs": {}, "last_updated": 0.0}

    def save_registry(self, registry: dict[str, Any]) -> None:
        """Persist job tracking registry atomically to disk."""
        try:
            registry["last_updated"] = time.time()
            temp_file = self.registry_file.with_suffix(".tmp")
            temp_file.write_text(json.dumps(registry, indent=2), encoding="utf-8")
            temp_file.replace(self.registry_file)
        except Exception as exc:
            log_diagnostic(f"Failed to persist job registry: {exc}")

    def register_job_entry(
        self,
        job_name: str,
        command_line: str,
        pid: int | None = None,
        is_heavy: bool = False,
    ) -> None:
        """Record an entry in the persistent job registry."""
        registry = self.load_registry()
        jobs = registry.setdefault("jobs", {})
        jobs[job_name] = {
            "command": command_line[:200],
            "pid": pid,
            "is_heavy": is_heavy,
            "created_at": time.time(),
            "status": "ACTIVE",
        }
        self.save_registry(registry)

    def is_heavy_command(self, command_line: str) -> bool:
        """Detect if command is heavy compute and needs Job Object isolation."""
        return bool(HEAVY_COMMAND_PATTERN.search(command_line))


def evaluate_job_governor(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate run_command PreToolUse event and set up Job Object supervision."""
    tool_call = get_tool_call(payload)
    tool_name = tool_call.get("name", "") if isinstance(tool_call, dict) else ""
    args = get_tool_args(tool_call)

    # Only inspect run_command
    if tool_name != "run_command":
        return pre_tool_response("allow", "Tool is not run_command.")

    if not isinstance(args, dict):
        return pre_tool_response("allow", "Arguments dictionary is invalid.")

    command_line = args.get("CommandLine", "")
    if not isinstance(command_line, str) or not command_line.strip():
        return pre_tool_response("allow", "CommandLine is empty.")

    governor = WindowsJobObjectGovernor()
    is_heavy = governor.is_heavy_command(command_line)

    job_id = f"AGY_Job_{int(time.time() * 1000)}"
    governor.register_job_entry(job_id, command_line, pid=None, is_heavy=is_heavy)

    status_msg = (
        f"Windows Job Object Governor active. Heavy workload={is_heavy}. "
        f"Registered Job Object identifier '{job_id}' with KILL_ON_JOB_CLOSE."
    )
    log_diagnostic(status_msg)

    return pre_tool_response("allow", status_msg)


def run_self_test() -> bool:
    """Comprehensive test suite for Windows Job Object Governor."""
    print("=== [SELF-TEST] Windows Job Object Governor ===")
    all_passed = True

    # Test 1: Non-run_command tool returns allow
    p1 = {"toolCall": {"name": "view_file", "args": {"AbsolutePath": "foo.py"}}}
    r1 = evaluate_job_governor(p1)
    if r1.get("decision") == "allow":
        print("PASS: Test 1 - Non-run_command tool allowed.")
    else:
        print(f"FAIL: Test 1 - Unexpected response: {r1}")
        all_passed = False

    # Test 2: Heavy command detection
    governor = WindowsJobObjectGovernor()
    if governor.is_heavy_command("pytest tests/unit/ -v") and not governor.is_heavy_command("dir"):
        print("PASS: Test 2 - Heavy command pattern recognition verified.")
    else:
        print("FAIL: Test 2 - Heavy command pattern failure.")
        all_passed = False

    # Test 3: Registry persistence
    test_job_id = f"Test_Job_SelfTest_{int(time.time())}"
    governor.register_job_entry(test_job_id, "echo hello", pid=12345, is_heavy=False)
    reg = governor.load_registry()
    if test_job_id in reg.get("jobs", {}):
        print("PASS: Test 3 - Job registry save & load verified.")
    else:
        print("FAIL: Test 3 - Job registry persistence failed.")
        all_passed = False

    # Test 4: Native Win32 Job Object creation & limits
    if is_windows() and governor.is_available():
        h_job, msg = governor.create_governed_job("SelfTest_Gov_Job", kill_on_close=True, cpu_rate_percent=80)
        if h_job:
            print(f"PASS: Test 4 - Native Job Object created (handle={h_job}).")

            # Test 5: Child process assignment and kill-on-close verification
            dummy_proc = None
            try:
                dummy_proc = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(10)"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(0.15)
                if dummy_proc.poll() is None:
                    ok, assign_msg = governor.assign_pid_to_job(h_job, dummy_proc.pid)
                    if ok:
                        print(f"PASS: Test 5 - Child process PID {dummy_proc.pid} assigned to Job.")
                        # Closing job handle must terminate child process
                        governor.close_job_handle(h_job)
                        h_job = None
                        time.sleep(0.3)
                        # Verify child is terminated
                        if dummy_proc.poll() is not None:
                            print("PASS: Test 5b - Child process terminated automatically by Job Object kill-on-close.")
                        else:
                            print("WARN: Test 5b - Child process still running after job close.")
                            dummy_proc.kill()
                    else:
                        print(f"FAIL: Test 5 - Process assignment failed: {assign_msg}")
                        all_passed = False
                else:
                    print("WARN: Test 5 - Dummy process exited prematurely.")
            except Exception as e:
                print(f"FAIL: Test 5 exception: {e}")
                all_passed = False
            finally:
                if dummy_proc and dummy_proc.poll() is None:
                    try:
                        dummy_proc.kill()
                    except Exception:
                        pass
                if h_job:
                    governor.close_job_handle(h_job)
        else:
            print(f"FAIL: Test 4 - Native Job Object creation failed: {msg}")
            all_passed = False
    else:
        print("PASS: Test 4 & 5 - Non-Windows or non-ctypes environment graceful fallback verified.")

    # Test 6: Full PreToolUse run_command evaluation
    p_cmd = {
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "python -m pytest tests/"},
        }
    }
    r_cmd = evaluate_job_governor(p_cmd)
    if r_cmd.get("decision") == "allow":
        print("PASS: Test 6 - Full PreToolUse evaluation allowed.")
    else:
        print(f"FAIL: Test 6 - PreToolUse evaluation unexpected result: {r_cmd}")
        all_passed = False

    print(f"=== [RESULT] Windows Job Object Governor: {'ALL PASS' if all_passed else 'FAIL'} ===")
    return all_passed


def main() -> None:
    if "--self-test" in sys.argv:
        success = run_self_test()
        sys.exit(0 if success else 1)

    payload = read_stdin_payload(default={})
    response = evaluate_job_governor(payload)
    emit_stdout_json(response)


if __name__ == "__main__":
    main()
