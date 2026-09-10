"""Unit and integration test suite for Enterprise Circuit Breaker Pattern.

Tests the complete Closed -> Open -> Half-Open state machine:
1. Normal CLOSED state operation, metric tracking, and threshold boundaries.
2. Fast-fail OPEN state behavior and CircuitBreakerOpenError rejection.
3. Fallback handlers (sync and async) on failure and OPEN state.
4. Auto-transition from OPEN to HALF_OPEN after recovery timeout.
5. HALF_OPEN behavior: trial limits, trial failures tripping to OPEN, consecutive successes closing circuit.
6. Rolling window failure rate threshold calculations.
7. Exception filtering: monitored vs. ignored exceptions.
8. Interfaces: call, call_async, @protect decorators, with/async with context managers.
9. Administrative controls: reset, force_open, force_closed, force_half_open, disable/enable.
10. State transition event listeners and telemetry callbacks.
11. CircuitBreakerRegistry singleton and multi-breaker metrics.
12. Dynamic config loading, environment variable overrides, and thread safety.
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import sys
import threading
import time
from typing import Any

import pytest

# Ensure hook directory is in sys.path
_HOOKS_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOKS_DIR))

from circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitBreakerOpenError,
    CircuitBreakerRegistry,
    CircuitState,
    circuit_breaker,
    get_circuit_breaker,
)
from hook_utils.config_loader import get_circuit_breaker_config


# -----------------------------------------------------------------------------
# 1. Closed State & Normal Execution
# -----------------------------------------------------------------------------


def test_initial_state_closed() -> None:
    """Verify circuit starts in CLOSED state with clean counters."""
    cb = CircuitBreaker("test-initial", failure_threshold=3, recovery_timeout_seconds=5.0)
    assert cb.state == CircuitState.CLOSED
    assert cb.is_closed is True
    assert cb.is_open is False
    assert cb.is_half_open is False
    assert cb.consecutive_failures == 0
    assert cb.consecutive_successes == 0
    assert cb.name == "test-initial"

    metrics = cb.get_metrics()
    assert metrics["total_calls"] == 0
    assert metrics["successful_calls"] == 0
    assert metrics["failed_calls"] == 0
    assert metrics["rejected_calls"] == 0


def test_successful_call_execution() -> None:
    """Verify successful calls increment metrics and maintain CLOSED state."""
    cb = CircuitBreaker("test-success", failure_threshold=3)

    def dummy_success(a: int, b: int) -> int:
        return a + b

    result = cb.call(dummy_success, 10, 20)
    assert result == 30
    assert cb.state == CircuitState.CLOSED
    assert cb.consecutive_successes == 1
    assert cb.consecutive_failures == 0

    metrics = cb.get_metrics()
    assert metrics["total_calls"] == 1
    assert metrics["successful_calls"] == 1
    assert metrics["failed_calls"] == 0


# -----------------------------------------------------------------------------
# 2. Transition from CLOSED to OPEN
# -----------------------------------------------------------------------------


def test_transition_closed_to_open_on_consecutive_failures() -> None:
    """Verify consecutive failures trip the breaker from CLOSED to OPEN."""
    transitions: list[tuple[CircuitState, CircuitState]] = []

    def on_change(b: CircuitBreaker, old: CircuitState, new: CircuitState, reason: str) -> None:
        transitions.append((old, new))

    cb = CircuitBreaker(
        "test-trip",
        failure_threshold=3,
        recovery_timeout_seconds=10.0,
        on_state_change=on_change,
    )

    def faulty_func() -> None:
        raise RuntimeError("Service unavailable")

    # Failures 1 and 2 should stay CLOSED
    for i in range(2):
        with pytest.raises(RuntimeError):
            cb.call(faulty_func)
        assert cb.state == CircuitState.CLOSED
        assert cb.consecutive_failures == i + 1

    # Failure 3 reaches failure_threshold -> transitions to OPEN
    with pytest.raises(RuntimeError):
        cb.call(faulty_func)

    assert cb.state == CircuitState.OPEN
    assert cb.is_open is True
    assert cb.is_closed is False
    assert len(transitions) == 1
    assert transitions[0] == (CircuitState.CLOSED, CircuitState.OPEN)


def test_open_state_fast_fails_without_execution() -> None:
    """Verify calls in OPEN state immediately reject without calling underlying function."""
    cb = CircuitBreaker("test-fast-fail", failure_threshold=1, recovery_timeout_seconds=30.0)

    # Trip breaker
    with pytest.raises(ValueError):
        cb.call(lambda: (_ for _ in ()).throw(ValueError("Tripping failure")))
    assert cb.state == CircuitState.OPEN

    mock_executed = False

    def should_not_run() -> str:
        nonlocal mock_executed
        mock_executed = True
        return "ran"

    with pytest.raises(CircuitBreakerOpenError) as exc_info:
        cb.call(should_not_run)

    assert mock_executed is False
    assert exc_info.value.state == CircuitState.OPEN
    assert exc_info.value.name == "test-fast-fail"
    assert exc_info.value.time_until_retry > 0.0

    metrics = cb.get_metrics()
    assert metrics["rejected_calls"] == 1


# -----------------------------------------------------------------------------
# 3. Fallback Mechanism
# -----------------------------------------------------------------------------


def test_fallback_on_open_and_error() -> None:
    """Verify fallback callable handles errors and OPEN state smoothly."""
    def safe_fallback(err: Exception) -> str:
        return f"fallback_handled: {type(err).__name__}"

    cb = CircuitBreaker(
        "test-fallback",
        failure_threshold=1,
        recovery_timeout_seconds=20.0,
        fallback=safe_fallback,
    )

    # First call fails -> fallback returns safely, circuit trips to OPEN
    res1 = cb.call(lambda: (_ for _ in ()).throw(ConnectionError("remote host down")))
    assert "fallback_handled: ConnectionError" in res1
    assert cb.state == CircuitState.OPEN

    # Second call is fast-failed by circuit breaker -> fallback handles CircuitBreakerOpenError
    res2 = cb.call(lambda: "never executed")
    assert "fallback_handled: CircuitBreakerOpenError" in res2


# -----------------------------------------------------------------------------
# 4. State Transitions: OPEN -> HALF_OPEN -> CLOSED (Recovery Flow)
# -----------------------------------------------------------------------------


def test_transition_open_to_half_open_after_cooldown() -> None:
    """Verify circuit transitions to HALF_OPEN after recovery_timeout_seconds elapses."""
    cb = CircuitBreaker(
        "test-recovery-timeout",
        failure_threshold=1,
        recovery_timeout_seconds=0.1,  # Fast timeout for test
    )

    # Trip to OPEN
    with pytest.raises(RuntimeError):
        cb.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
    assert cb.state == CircuitState.OPEN

    # Wait for cooldown to elapse
    time.sleep(0.15)

    # Checking state property or attempting next call transitions to HALF_OPEN
    assert cb.state == CircuitState.HALF_OPEN
    assert cb.is_half_open is True


def test_half_open_failure_immediately_re_trips_to_open() -> None:
    """Verify any failure in HALF_OPEN trips immediately back to OPEN."""
    cb = CircuitBreaker(
        "test-half-open-fail",
        failure_threshold=1,
        recovery_timeout_seconds=0.1,
    )

    # Trip to OPEN
    with pytest.raises(RuntimeError):
        cb.call(lambda: (_ for _ in ()).throw(RuntimeError("fail 1")))
    assert cb.state == CircuitState.OPEN

    time.sleep(0.15)
    assert cb.state == CircuitState.HALF_OPEN

    # Failure during trial probe
    with pytest.raises(RuntimeError):
        cb.call(lambda: (_ for _ in ()).throw(RuntimeError("trial fail")))

    # Must immediately trip back to OPEN
    assert cb.state == CircuitState.OPEN


def test_half_open_consecutive_successes_recovers_to_closed() -> None:
    """Verify consecutive successes in HALF_OPEN successfully recovers to CLOSED."""
    cb = CircuitBreaker(
        "test-half-open-recovery",
        failure_threshold=1,
        recovery_timeout_seconds=0.1,
        half_open_max_trials=3,
        consecutive_success_threshold=2,
    )

    # Trip to OPEN
    with pytest.raises(RuntimeError):
        cb.call(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
    assert cb.state == CircuitState.OPEN

    time.sleep(0.15)
    assert cb.state == CircuitState.HALF_OPEN

    # First successful trial: remains HALF_OPEN
    res1 = cb.call(lambda: "trial 1 ok")
    assert res1 == "trial 1 ok"
    assert cb.state == CircuitState.HALF_OPEN
    assert cb.consecutive_successes == 1

    # Second successful trial: meets consecutive_success_threshold (2) -> recovers to CLOSED!
    res2 = cb.call(lambda: "trial 2 ok")
    assert res2 == "trial 2 ok"
    assert cb.state == CircuitState.CLOSED
    assert cb.is_closed is True
    assert cb.consecutive_failures == 0


def test_half_open_max_trials_exhaustion() -> None:
    """Verify HALF_OPEN rejects excess trial attempts beyond capacity."""
    cb = CircuitBreaker(
        "test-trials-cap",
        failure_threshold=1,
        recovery_timeout_seconds=0.1,
        half_open_max_trials=1,
        consecutive_success_threshold=5,
    )

    with pytest.raises(RuntimeError):
        cb.call(lambda: (_ for _ in ()).throw(RuntimeError("trip")))
    time.sleep(0.15)
    assert cb.state == CircuitState.HALF_OPEN

    # Saturated by 1 trial attempt
    cb.call(lambda: "ok 1")

    # Second attempt exceeds max_trials before threshold is reached
    with pytest.raises(CircuitBreakerOpenError) as exc:
        cb.call(lambda: "ok 2")
    assert "saturated" in exc.value.reason.lower()


# -----------------------------------------------------------------------------
# 5. Exception Filtering: Monitored vs Ignored
# -----------------------------------------------------------------------------


def test_ignored_exceptions_do_not_trip_circuit() -> None:
    """Verify ignored exceptions are propagated but do not count as failures."""
    cb = CircuitBreaker(
        "test-ignored-exc",
        failure_threshold=2,
        ignored_exceptions=(KeyError, ValueError),
    )

    # Raising ignored exception
    for _ in range(5):
        with pytest.raises(KeyError):
            cb.call(lambda: (_ for _ in ()).throw(KeyError("ignored key")))

    assert cb.state == CircuitState.CLOSED
    assert cb.consecutive_failures == 0
    assert cb.get_metrics()["failed_calls"] == 0


# -----------------------------------------------------------------------------
# 6. Rolling Window Failure Rate Tripping
# -----------------------------------------------------------------------------


def test_failure_rate_threshold_in_rolling_window() -> None:
    """Verify high failure rate in rolling window trips to OPEN even if not consecutive."""
    cb = CircuitBreaker(
        "test-failure-rate",
        failure_threshold=10,  # High consecutive threshold
        failure_rate_threshold=0.5,  # 50% rate trips
        rolling_window_size=10,
    )

    # Alternate success, failure, success, failure, failure
    # [S, F, S, F, F]
    cb.call(lambda: "ok")
    with pytest.raises(RuntimeError):
        cb.call(lambda: (_ for _ in ()).throw(RuntimeError("err 1")))
    cb.call(lambda: "ok")
    with pytest.raises(RuntimeError):
        cb.call(lambda: (_ for _ in ()).throw(RuntimeError("err 2")))
    # At 5th call: 3 failures / 5 total = 60% >= 50% -> trips to OPEN
    with pytest.raises(RuntimeError):
        cb.call(lambda: (_ for _ in ()).throw(RuntimeError("err 3")))

    assert cb.state == CircuitState.OPEN

    # Subsequent call fast-fails immediately
    with pytest.raises(CircuitBreakerOpenError):
        cb.call(lambda: "blocked")


# -----------------------------------------------------------------------------
# 7. Asynchronous Execution & Async Fallback
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_call_success_and_trip() -> None:
    """Verify call_async functions properly for coroutines."""
    cb = CircuitBreaker("test-async", failure_threshold=2, recovery_timeout_seconds=5.0)

    async def async_worker(val: int) -> int:
        await asyncio.sleep(0.01)
        return val * 2

    res = await cb.call_async(async_worker, 21)
    assert res == 42
    assert cb.state == CircuitState.CLOSED

    async def async_failing() -> None:
        await asyncio.sleep(0.01)
        raise ConnectionResetError("network lost")

    for _ in range(2):
        with pytest.raises(ConnectionResetError):
            await cb.call_async(async_failing)

    assert cb.state == CircuitState.OPEN

    # Async call during OPEN should fast fail
    with pytest.raises(CircuitBreakerOpenError):
        await cb.call_async(async_worker, 1)


@pytest.mark.asyncio
async def test_async_fallback() -> None:
    """Verify async fallback coroutine executes when OPEN."""
    async def async_fb(err: Exception) -> str:
        await asyncio.sleep(0.01)
        return "async_fallback_success"

    cb = CircuitBreaker("test-async-fb", failure_threshold=1, fallback=async_fb)
    cb.force_open()

    async def target() -> str:
        return "should not run"

    result = await cb.call_async(target)
    assert result == "async_fallback_success"


# -----------------------------------------------------------------------------
# 8. Decorator Syntax (Sync & Async)
# -----------------------------------------------------------------------------


def test_sync_decorator() -> None:
    """Verify @cb.protect decorator on sync function."""
    cb = CircuitBreaker("test-sync-dec", failure_threshold=2)

    @cb.protect()
    def multiply(x: int, y: int) -> int:
        return x * y

    assert multiply(3, 7) == 21


@pytest.mark.asyncio
async def test_async_decorator() -> None:
    """Verify @cb.protect decorator on async function."""
    cb = CircuitBreaker("test-async-dec", failure_threshold=2)

    @cb.protect()
    async def async_add(x: int, y: int) -> int:
        await asyncio.sleep(0.01)
        return x + y

    result = await async_add(15, 25)
    assert result == 40


# -----------------------------------------------------------------------------
# 9. Context Managers (Sync & Async)
# -----------------------------------------------------------------------------


def test_sync_context_manager() -> None:
    """Verify with circuit_breaker block semantics."""
    cb = CircuitBreaker("test-sync-cm", failure_threshold=2)

    with cb:
        val = 100

    assert val == 100
    assert cb.get_metrics()["successful_calls"] == 1

    with pytest.raises(ZeroDivisionError):
        with cb:
            _ = 1 / 0

    assert cb.consecutive_failures == 1


@pytest.mark.asyncio
async def test_async_context_manager() -> None:
    """Verify async with circuit_breaker block semantics."""
    cb = CircuitBreaker("test-async-cm", failure_threshold=2)

    async with cb:
        await asyncio.sleep(0.01)
        res = "async_cm_ok"

    assert res == "async_cm_ok"
    assert cb.get_metrics()["successful_calls"] == 1


# -----------------------------------------------------------------------------
# 10. Administrative Controls
# -----------------------------------------------------------------------------


def test_administrative_overrides() -> None:
    """Verify manual administrative overrides: force_open, force_closed, force_half_open, disable."""
    cb = CircuitBreaker("test-admin", failure_threshold=5)

    cb.force_open("Scheduled maintenance")
    assert cb.state == CircuitState.FORCED_OPEN
    assert cb.is_open is True

    with pytest.raises(CircuitBreakerOpenError):
        cb.call(lambda: "fail")

    cb.force_half_open()
    assert cb.state == CircuitState.HALF_OPEN

    cb.force_closed()
    assert cb.state == CircuitState.CLOSED

    cb.disable()
    assert cb.state == CircuitState.DISABLED

    # When disabled, failures do not trip the circuit
    for _ in range(10):
        with pytest.raises(RuntimeError):
            cb.call(lambda: (_ for _ in ()).throw(RuntimeError("error")))
    assert cb.state == CircuitState.DISABLED

    cb.enable()
    assert cb.state == CircuitState.CLOSED
    assert cb.consecutive_failures == 0


# -----------------------------------------------------------------------------
# 11. Registry & Factory Functionality
# -----------------------------------------------------------------------------


def test_circuit_breaker_registry() -> None:
    """Verify CircuitBreakerRegistry singleton and multi-breaker metrics."""
    registry = CircuitBreakerRegistry()
    b1 = registry.get_or_create("service-a", failure_threshold=3)
    b2 = registry.get_or_create("service-b", failure_threshold=5)

    assert registry.get("service-a") is b1
    assert registry.get("service-b") is b2

    b1.call(lambda: "ok")
    all_metrics = registry.get_all_metrics()
    assert "service-a" in all_metrics
    assert "service-b" in all_metrics
    assert all_metrics["service-a"]["successful_calls"] == 1

    registry.reset_all()
    assert b1.state == CircuitState.CLOSED
    assert b2.state == CircuitState.CLOSED


def test_convenience_functions() -> None:
    """Verify global get_circuit_breaker and circuit_breaker decorator."""
    breaker = get_circuit_breaker("global-test", failure_threshold=4)
    assert breaker.name == "global-test"

    @circuit_breaker("global-decorator-test")
    def compute(x: int) -> int:
        return x ** 2

    assert compute(5) == 25


# -----------------------------------------------------------------------------
# 12. Dynamic Configuration & Thread Safety
# -----------------------------------------------------------------------------


def test_dynamic_config_loading() -> None:
    """Verify configuration loads dynamically from hook_utils.config_loader."""
    cfg = get_circuit_breaker_config()
    assert "failure_threshold" in cfg
    assert "recovery_timeout_seconds" in cfg

    cb = CircuitBreaker("test-dynamic-loader")
    assert cb.failure_threshold == cfg["failure_threshold"]
    assert cb.recovery_timeout_seconds == cfg["recovery_timeout_seconds"]


def test_environment_variable_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify environment variables override defaults cleanly without hardcoding."""
    monkeypatch.setenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "8")
    monkeypatch.setenv("CIRCUIT_BREAKER_RECOVERY_TIMEOUT", "45.5")

    cb = CircuitBreaker("test-env-override")
    assert cb.failure_threshold == 8
    assert cb.recovery_timeout_seconds == 45.5


def test_thread_safety_concurrency() -> None:
    """Verify concurrent threads executing calls do not corrupt state or deadlock."""
    cb = CircuitBreaker(
        "test-threads",
        failure_threshold=50,
        recovery_timeout_seconds=10.0,
    )

    errors = []

    def worker(tid: int) -> None:
        try:
            for i in range(20):
                if (tid + i) % 7 == 0:
                    try:
                        cb.call(lambda: (_ for _ in ()).throw(ValueError("transient")))
                    except ValueError:
                        pass
                else:
                    res = cb.call(lambda x: x + 1, i)
                    assert res == i + 1
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    metrics = cb.get_metrics()
    assert metrics["total_calls"] == 200
