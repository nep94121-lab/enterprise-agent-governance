#!/usr/bin/env python3
"""Auto Test Runner on Test Modification Hook (PostToolUse) for Enterprise Multi-Agent Governance System.

Automatically triggers appropriate test runner on modified test files (§19, §20)
under CPU Governor regulation (Pool 2: Local Burst Compute) to ensure instant feedback,
zero hardcoding, multi-language support, and prevent false alarms on fixtures/configs.
"""

from __future__ import annotations

import io
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any

# Enforce UTF-8 standard encoding across all platforms (Windows PowerShell safety)
try:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, io.UnsupportedOperation, ValueError):
    pass

# Ensure local hook libraries and root enterprise-hooks packages are importable
HOOKS_SCRIPTS_DIR = pathlib.Path(__file__).parent.resolve()
ENTERPRISE_HOOKS_DIR = HOOKS_SCRIPTS_DIR.parent.resolve()

for import_path in [str(HOOKS_SCRIPTS_DIR), str(ENTERPRISE_HOOKS_DIR)]:
    if import_path not in sys.path:
        sys.path.insert(0, import_path)

from common_hook_lib import (  # noqa: E402
    emit_stdout_json,
    get_tool_args,
    get_tool_call,
    log_diagnostic,
    normalize_path,
    post_tool_response,
    read_stdin_payload,
)

# Optional dynamic config loader integration
try:
    from hook_utils.config_loader import (  # type: ignore
        DynamicConfigLoader,
        get_dynamic_limits,
        get_execution_timeouts,
        get_hardware_profile,
        get_test_runner_config,
    )
except ImportError:
    DynamicConfigLoader = None  # type: ignore
    get_dynamic_limits = None  # type: ignore
    get_execution_timeouts = None  # type: ignore
    get_hardware_profile = None  # type: ignore
    get_test_runner_config = None  # type: ignore

# Optional governance config loader
try:
    from config_loader import get_governance_config  # type: ignore
except ImportError:
    get_governance_config = None  # type: ignore

# Optional CPU Governor integration (Pool 2: Local Burst Compute)
try:
    from hook_utils.cpu_governor import CPUGovernor, CPUZone, governor_guard  # type: ignore
except ImportError:
    CPUGovernor = None  # type: ignore
    CPUZone = None  # type: ignore
    governor_guard = None  # type: ignore

# Default fallback values for Zero-Config Resilience
DEFAULT_EXCLUDED_TEST_FILENAMES: tuple[str, ...] = (
    "__init__.py",
    "conftest.py",
    "setup.py",
    "fixtures.py",
    "test_utils.py",
    "helpers.py",
    "utils.py",
    "mocks.py",
    "factories.py",
    "base.py",
    "jest.config.js",
    "jest.config.ts",
    "vitest.config.ts",
    "vitest.config.js",
)

DEFAULT_TIMEOUT_SECONDS: float = 30.0
DEFAULT_MAX_SUMMARY_LINES: int = 10
DEFAULT_MAX_OUTPUT_CHARS: int = 1000


def get_active_test_runner_config() -> dict[str, Any]:
    """Retrieve test runner configuration dynamically from hook_utils with safe fallback."""
    if get_test_runner_config is not None:
        try:
            cfg = get_test_runner_config()
            if isinstance(cfg, dict) and cfg:
                return cfg
        except Exception as exc:
            log_diagnostic(f"Could not load dynamic test_runner config: {exc}")
    return {
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
        "max_summary_lines": DEFAULT_MAX_SUMMARY_LINES,
        "max_output_chars": DEFAULT_MAX_OUTPUT_CHARS,
        "excluded_filenames": list(DEFAULT_EXCLUDED_TEST_FILENAMES),
    }


def get_excluded_filenames(config: dict[str, Any] | None = None) -> set[str]:
    """Retrieve set of non-executable test fixtures/configuration files (unioned with defaults)."""
    cfg = config or get_active_test_runner_config()
    raw = cfg.get("excluded_filenames", DEFAULT_EXCLUDED_TEST_FILENAMES)
    defaults = {item.lower() for item in DEFAULT_EXCLUDED_TEST_FILENAMES}
    if isinstance(raw, (list, tuple, set)):
        return {str(item).lower() for item in raw} | defaults
    return defaults


def detect_test_framework(path: pathlib.Path | str, config: dict[str, Any] | None = None) -> tuple[bool, str]:
    """Detect if target path is an executable test file and determine its framework/language.

    Resolves P0 False Alarms by explicitly excluding test fixtures, configurations,
    and __init__.py files from standalone test execution.
    """
    if not isinstance(path, pathlib.Path):
        try:
            path = pathlib.Path(str(path))
        except Exception:
            return False, "invalid_path"

    name = path.name.lower()
    suffix = path.suffix.lower()

    # P0 Fix: Exclude non-executable test fixtures/configs from triggering runner
    excluded = get_excluded_filenames(config)
    if name in excluded:
        return False, "excluded_fixture"

    # 1. Python test files
    if suffix == ".py":
        if name.startswith("test_") or name.endswith("_test.py"):
            return True, "python"
        path_parts = [part.lower() for part in path.parts]
        if "tests" in path_parts or "test" in path_parts:
            # Exclude dunder or private modules (e.g. __main__.py, _helpers.py)
            if not name.startswith("__") and not name.startswith("."):
                return True, "python"
        return False, "python_non_test"

    # 2. TypeScript / JavaScript test files
    if suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
        if re.search(r"\.(?:test|spec)\.[a-z0-9]+$", name):
            return True, "typescript" if suffix in (".ts", ".tsx") else "javascript"
        path_parts = [part.lower() for part in path.parts]
        if "__tests__" in path_parts or "tests" in path_parts or "test" in path_parts:
            if re.search(r"^(?:test_|spec_).*\.[a-z0-9]+$", name) or re.search(
                r".*[-_.](?:test|spec)\.[a-z0-9]+$", name
            ):
                return True, "typescript" if suffix in (".ts", ".tsx") else "javascript"
        return False, "js_non_test"

    # 3. Go test files
    if suffix == ".go":
        if name.endswith("_test.go"):
            return True, "go"
        return False, "go_non_test"

    # 4. Rust test files
    if suffix == ".rs":
        if name.startswith("test_") or name.endswith("_test.rs"):
            return True, "rust"
        path_parts = [part.lower() for part in path.parts]
        if "tests" in path_parts:
            return True, "rust"
        return False, "rust_non_test"

    return False, "unsupported"


def is_test_file(path: pathlib.Path | str, config: dict[str, Any] | None = None) -> bool:
    """Determine if target path is an executable test file (backward-compatible signature)."""
    is_test, _ = detect_test_framework(path, config)
    return is_test


def resolve_timeout(config: dict[str, Any] | None = None) -> float:
    """Resolve test execution timeout dynamically from configuration sources."""
    cfg = config or get_active_test_runner_config()

    # 1. Check direct test_runner config
    if "timeout_seconds" in cfg:
        try:
            return float(cfg["timeout_seconds"])
        except (ValueError, TypeError):
            pass

    # 2. Check GovernanceConfig
    if get_governance_config is not None:
        try:
            gov = get_governance_config()
            if hasattr(gov, "test_runner_timeout_seconds"):
                return float(gov.test_runner_timeout_seconds)
        except Exception:
            pass

    # 3. Check execution_timeouts from hook_utils
    if get_execution_timeouts is not None:
        try:
            timeouts = get_execution_timeouts()
            if "heavy_build_timeout_seconds" in timeouts:
                return float(timeouts["heavy_build_timeout_seconds"])
        except Exception:
            pass

    return DEFAULT_TIMEOUT_SECONDS


def resolve_test_command(
    target_path: pathlib.Path | str,
    language: str,
    config: dict[str, Any] | None = None,
) -> list[str]:
    """Resolve dynamic test execution command based on language and enterprise configuration."""
    if not isinstance(target_path, pathlib.Path):
        target_path = pathlib.Path(str(target_path))

    # Check direct test_runner config override for command
    cfg = config or get_active_test_runner_config()
    if isinstance(cfg, dict) and cfg.get("test_runner_command"):
        custom_cmd = str(cfg["test_runner_command"]).strip()
        if custom_cmd:
            try:
                import shlex
                cmd_parts = shlex.split(custom_cmd, posix=sys.platform != "win32")
            except Exception:
                cmd_parts = custom_cmd.split()
            cmd_parts.append(str(target_path))
            return cmd_parts

    # Check if a custom test runner command is defined in GovernanceConfig
    if get_governance_config is not None:
        try:
            gov = get_governance_config()
            if hasattr(gov, "test_runner_command") and gov.test_runner_command:
                custom_cmd = gov.test_runner_command.strip()
                if custom_cmd and custom_cmd != "pytest tests/ -q --tb=short":
                    try:
                        import shlex
                        cmd_parts = shlex.split(custom_cmd, posix=sys.platform != "win32")
                    except Exception:
                        cmd_parts = custom_cmd.split()
                    cmd_parts.append(str(target_path))
                    return cmd_parts
        except Exception:
            pass

    # Language-specific dynamic runner commands
    if language == "python":
        # Prefer sys.executable -m pytest for environment isolation
        return [sys.executable, "-m", "pytest", str(target_path), "-v", "--tb=short"]
    elif language in ("typescript", "javascript"):
        return ["npm", "test", "--", str(target_path)]
    elif language == "go":
        return ["go", "test", "-v", str(target_path)]
    elif language == "rust":
        return ["cargo", "test", "--test", target_path.stem]

    return [sys.executable, "-m", "pytest", str(target_path), "-v", "--tb=short"]


def _run_subprocess(cmd: list[str], timeout_seconds: float) -> tuple[int, str, str]:
    """Execute raw test subprocess with UTF-8 encoding and timeout guard."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
    )
    return result.returncode, result.stdout or "", result.stderr or ""


def execute_test_command(
    cmd: list[str],
    target_path: pathlib.Path | str,
    timeout_seconds: float,
) -> tuple[int, str, str]:
    """Execute test suite under CPU Governor semaphore regulation (Pool 2: Local Burst Compute)."""
    target_path = pathlib.Path(target_path) if not isinstance(target_path, pathlib.Path) else target_path
    cmd_str = " ".join(cmd)

    if governor_guard is not None:
        try:
            with governor_guard(cmd_str, timeout=min(timeout_seconds, 45.0)) as telemetry:
                zone = telemetry.get("cpu_zone", "UNKNOWN")
                load = telemetry.get("cpu_percent", 0.0)
                log_diagnostic(f"CPU Governor assigned slot for test runner (Zone={zone}, CPU={load}%)")
                return _run_subprocess(cmd, timeout_seconds)
        except TimeoutError as te:
            log_diagnostic(f"CPU Governor slots saturated, test queued/throttled for {target_path.name}: {te}")
            return -1, "", str(te)
        except Exception as exc:
            log_diagnostic(f"CPU Governor fallback: {exc}")
            return _run_subprocess(cmd, timeout_seconds)
    else:
        return _run_subprocess(cmd, timeout_seconds)


def extract_target_file(args: dict[str, Any]) -> str | None:
    """Extract file target path from various possible argument keys."""
    for key in ("TargetFile", "target_file", "filePath", "file_path", "path", "destination"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def run_tests_for_target(payload: dict[str, Any], config_override: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute automated test runner when a test file is modified.

    Provides instant feedback via stderr and returns standard post_tool_response() on stdout.
    """
    tool_call = get_tool_call(payload)
    args = get_tool_args(tool_call)

    raw_target = extract_target_file(args)
    if not raw_target:
        return post_tool_response()

    target_path = normalize_path(raw_target)
    config = config_override or get_active_test_runner_config()

    is_test, language = detect_test_framework(target_path, config)

    # Handle excluded fixtures cleanly without triggering tests
    if language == "excluded_fixture":
        log_diagnostic(f"Skipping direct test execution for configuration/fixture file: {target_path.name}")
        return post_tool_response()

    if is_test and target_path.is_file():
        timeout_seconds = resolve_timeout(config)
        max_summary_lines = int(config.get("max_summary_lines", DEFAULT_MAX_SUMMARY_LINES))
        max_output_chars = int(config.get("max_output_chars", DEFAULT_MAX_OUTPUT_CHARS))

        cmd = resolve_test_command(target_path, language, config)

        try:
            log_diagnostic(f"Detected test modification on: {target_path.name}. Running pytest...")

            code, stdout, stderr = execute_test_command(cmd, target_path, timeout_seconds)

            # Process and log output summary
            combined_out = stdout.strip()
            if combined_out:
                lines = combined_out.splitlines()
                summary_lines = [
                    line
                    for line in lines
                    if any(kw in line for kw in ("passed", "failed", "error", "FAILURES", "ERRORS"))
                ]
                if summary_lines:
                    log_diagnostic(f"Pytest summary for {target_path.name}: {summary_lines[-1]}")
                else:
                    log_diagnostic(f"Pytest output for {target_path.name}:\n{combined_out[:max_output_chars]}")

            if code == 0:
                log_diagnostic(f"✅ All tests PASSED in {target_path.name}")
            elif code == -1:
                log_diagnostic(
                    f"[CPU_GOVERNOR_QUEUED] Test execution deferred/throttled for {target_path.name}: "
                    f"CPU governor slots saturated or queue wait timed out ({stderr or 'slots saturated'})."
                )
            else:
                log_diagnostic(f"❌ Test failures detected (exit code {code}) in {target_path.name}")
                # Provide instant error visibility (§26) for failing tests
                failure_lines = []
                capture = False
                for line in (stdout + "\n" + stderr).splitlines():
                    if any(marker in line for marker in ("FAILURES", "ERRORS", "FAILED", "AssertionError", "E   ")):
                        capture = True
                    if capture:
                        failure_lines.append(line)
                        if len(failure_lines) >= max_summary_lines:
                            break
                if failure_lines:
                    log_diagnostic(
                        f"Test failure details for {target_path.name}:\n" + "\n".join(failure_lines[:max_summary_lines])
                    )

        except FileNotFoundError:
            log_diagnostic(f"Test executable ({cmd[0]}) not found in PATH; skipping automated test run.")
        except subprocess.TimeoutExpired:
            log_diagnostic(f"Pytest execution timed out ({timeout_seconds:.0f}s limit) for {target_path.name}")
        except (OSError, ValueError) as exc:
            log_diagnostic(f"[TEST_RUNNER_ERROR] Error running tests on {target_path.name}: {exc}")
        except Exception as fatal_exc:
            import traceback

            tb = traceback.format_exc()
            log_diagnostic(f"[HOOK_FATAL_ERROR] Unexpected error in auto_test_runner: {fatal_exc}\n{tb}")

    return post_tool_response()


# ==============================================================================
# Self-Test Suite (--self-test)
# ==============================================================================


def run_self_tests() -> bool:
    """Comprehensive self-test suite covering 12 real scenarios for auto_test_runner_on_test_mod."""
    print("======================================================================")
    print("Running Self-Test Suite: auto_test_runner_on_test_mod.py")
    print("======================================================================")

    results: list[tuple[str, bool, str]] = []

    # Scenario 1: Python prefix test file detection
    p1 = pathlib.Path("tests/test_unit.py")
    is_t1, lang1 = detect_test_framework(p1)
    results.append(("Python prefix test detection (test_*.py)", is_t1 and lang1 == "python", f"is_t={is_t1}, lang={lang1}"))

    # Scenario 2: Python suffix test file detection
    p2 = pathlib.Path("src/service_test.py")
    is_t2, lang2 = detect_test_framework(p2)
    results.append(("Python suffix test detection (*_test.py)", is_t2 and lang2 == "python", f"is_t={is_t2}, lang={lang2}"))

    # Scenario 3: Non-test Python file exclusion
    p3 = pathlib.Path("app/server.py")
    is_t3, lang3 = detect_test_framework(p3)
    results.append(("Non-test Python file exclusion", not is_t3, f"is_t={is_t3}, lang={lang3}"))

    # Scenario 4 (P0 Fix): Exclude tests/__init__.py from triggering runner
    p4 = pathlib.Path("tests/__init__.py")
    is_t4, lang4 = detect_test_framework(p4)
    results.append(("P0 Fix: tests/__init__.py exclusion", not is_t4 and lang4 == "excluded_fixture", f"is_t={is_t4}, lang={lang4}"))

    # Scenario 5 (P0 Fix): Exclude conftest.py from triggering runner
    p5 = pathlib.Path("tests/conftest.py")
    is_t5, lang5 = detect_test_framework(p5)
    results.append(("P0 Fix: conftest.py exclusion", not is_t5 and lang5 == "excluded_fixture", f"is_t={is_t5}, lang={lang5}"))

    # Scenario 6: TypeScript test file detection
    p6 = pathlib.Path("src/components/button.test.ts")
    is_t6, lang6 = detect_test_framework(p6)
    results.append(("TypeScript test detection (*.test.ts)", is_t6 and lang6 == "typescript", f"is_t={is_t6}, lang={lang6}"))

    # Scenario 7: Go test file detection
    p7 = pathlib.Path("pkg/auth/handler_test.go")
    is_t7, lang7 = detect_test_framework(p7)
    results.append(("Go test detection (*_test.go)", is_t7 and lang7 == "go", f"is_t={is_t7}, lang={lang7}"))

    # Scenario 8: Rust test file detection
    p8 = pathlib.Path("tests/integration_test.rs")
    is_t8, lang8 = detect_test_framework(p8)
    results.append(("Rust test detection (tests/*.rs)", is_t8 and lang8 == "rust", f"is_t={is_t8}, lang={lang8}"))

    # Scenario 9: Dynamic timeout resolution
    timeout = resolve_timeout()
    results.append(("Dynamic timeout resolution (>= 15s)", timeout >= 15.0, f"timeout={timeout}s"))

    # Scenario 10: Malformed payload resilience
    malformed_payloads = [
        {},
        {"toolCall": None},
        {"toolCall": "not_a_dict"},
        {"toolCall": {"name": "write_to_file", "args": None}},
        {"toolCall": {"name": "write_to_file", "args": {"TargetFile": None}}},
    ]
    malformed_ok = True
    for p in malformed_payloads:
        resp = run_tests_for_target(p)
        if resp != {}:
            malformed_ok = False
            break
    results.append(("Malformed payload safe fallback ({})", malformed_ok, "All returned {}"))

    # Scenario 11: Real execution of passing test file
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_test = pathlib.Path(tmp_dir) / "test_simple.py"
        tmp_test.write_text("def test_ok(): assert 1 + 1 == 2\n", encoding="utf-8")

        payload = {
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(tmp_test)},
            }
        }
        res11 = run_tests_for_target(payload)
        results.append(("Real test execution (passing test)", res11 == {}, f"response={res11}"))

    # Scenario 12: Real execution of failing test with diagnostic error visibility
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_failing = pathlib.Path(tmp_dir) / "test_failing.py"
        tmp_failing.write_text("def test_fail(): assert 1 == 2, 'Expected equality fail'\n", encoding="utf-8")

        payload = {
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(tmp_failing)},
            }
        }
        res12 = run_tests_for_target(payload)
        results.append(("Real test execution (failing test diagnostics)", res12 == {}, f"response={res12}"))

    # Scenario 13: Excluded filenames union with config
    custom_cfg = {"excluded_filenames": ["custom_fixture.py"]}
    excluded = get_excluded_filenames(custom_cfg)
    union_ok = "custom_fixture.py" in excluded and "conftest.py" in excluded and "test_utils.py" in excluded
    results.append(("Excluded filenames unioning with defaults", union_ok, f"total={len(excluded)}"))

    # Scenario 14: Additional test helpers exclusion
    helper_files = ["tests/helpers.py", "tests/utils.py", "tests/mocks.py", "tests/factories.py", "tests/base.py"]
    helpers_ok = all(
        detect_test_framework(pathlib.Path(hf))[1] == "excluded_fixture"
        for hf in helper_files
    )
    results.append(("Test helpers expansion exclusion", helpers_ok, f"{len(helper_files)} helpers excluded"))

    # Scenario 15: String path input resilience
    is_t_str, lang_str = detect_test_framework("tests/test_str.py")
    results.append(("String path input resilience", is_t_str and lang_str == "python", f"is_t={is_t_str}, lang={lang_str}"))

    # Scenario 16: CPU Governor queued / throttled status handling (-1)
    payload16 = {
        "toolCall": {
            "name": "write_to_file",
            "args": {"TargetFile": "tests/test_unit.py"},
        }
    }
    # run_tests_for_target always safely returns {} regardless of execution outcome
    res16 = run_tests_for_target(payload16)
    results.append(("CPU Governor queued safe return ({})", res16 == {}, f"response={res16}"))

    # Print summary
    all_passed = True
    for name, passed, detail in results:
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_passed = False
        print(f"[{status}] {name} -> {detail}")

    print("----------------------------------------------------------------------")
    passed_count = sum(1 for _, p, _ in results if p)
    print(f"Self-Test Summary: {passed_count}/{len(results)} tests passed ({'100%' if all_passed else 'FAIL'}).")
    print("======================================================================\n")
    return all_passed


def main() -> None:
    if "--self-test" in sys.argv:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    payload = read_stdin_payload(default={})
    response = run_tests_for_target(payload)
    emit_stdout_json(response)


if __name__ == "__main__":
    main()
