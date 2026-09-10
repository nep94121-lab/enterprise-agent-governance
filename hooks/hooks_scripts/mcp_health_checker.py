#!/usr/bin/env python3
"""MCP Tool Health Checker.

This module provides health monitoring, status checking, latency tracking,
and alerting capabilities for MCP tools within the Enterprise Multi-Agent Governance System.

Key Capabilities:
- Dynamic configuration via hook_utils.config_loader (100% zero-hardcoding)
- P0 Patches:
  * Default ping check metrics & alerts update (fixed early return bypass)
  * Synchronous check timeout isolation in worker threads (zero event loop hang)
  * Dynamic failure and degraded threshold evaluation in metrics
  * Thread-safe singleton management with RLock
  * Windows UTF-8 stdout/stdin stream encoding reconfiguration
- Rolling latency tracking with percentiles (p50, p95, p99) and trend detection
- Multi-channel alerting (status changes, latency degradation, availability drops)
- Comprehensive built-in self-test suite (--self-test)
- Full CLI hook lifecycle support (PreInvocation and PreToolUse)
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import math
import pathlib
import sys
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
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
ENTERPRISE_HOOKS_DIR = HOOKS_SCRIPTS_DIR.parent.resolve()

if str(HOOKS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(HOOKS_SCRIPTS_DIR))
if str(ENTERPRISE_HOOKS_DIR) not in sys.path:
    sys.path.insert(0, str(ENTERPRISE_HOOKS_DIR))

# Dynamic config loader integration from hook_utils
try:
    from hook_utils.config_loader import (  # noqa: E402
        DynamicConfigLoader,
        get_config_loader,
        get_dynamic_limits,
        get_execution_timeouts,
        get_mcp_health_checker_config,
    )
except ImportError:
    DynamicConfigLoader = None  # type: ignore[assignment,misc]
    get_config_loader = None  # type: ignore[assignment]
    get_dynamic_limits = None  # type: ignore[assignment]
    get_execution_timeouts = None  # type: ignore[assignment]
    get_mcp_health_checker_config = None  # type: ignore[assignment]

from common_hook_lib import (  # noqa: E402
    emit_stdout_json,
    get_tool_call,
    log_diagnostic,
    pre_invocation_response,
    pre_tool_response,
    read_stdin_payload,
)

logger = logging.getLogger("enterprise_hooks.mcp_health_checker")

# Zero-Config Fallback Defaults (Enterprise Resilience Standard)
FALLBACK_MCP_HEALTH_CONFIG: dict[str, Any] = {
    "check_interval_seconds": 60,
    "failure_threshold": 3,
    "degraded_threshold": 1,
    "latency_window_size": 100,
    "max_window_size": 1000,
    "enable_trend_analysis": True,
    "default_warning_latency_ms": 1000.0,
    "default_critical_latency_ms": 5000.0,
    "default_availability_warning": 95.0,
    "default_availability_critical": 90.0,
    "timeout_seconds": 5.0,
    "min_samples_for_trend": 10,
    "trend_change_threshold": 10.0,
    "trend_confidence_divisor": 50.0,
    "trend_confidence_min": 0.7,
    "max_results_history": 100,
    "max_alerts_history": 1000,
    "default_history_limit": 100,
    "availability_recommendation_threshold": 95.0,
}


def load_effective_config() -> dict[str, Any]:
    """Load effective config merging dynamic_limits.json and zero-config fallbacks."""
    if get_mcp_health_checker_config is not None:
        try:
            cfg = get_mcp_health_checker_config()
            if isinstance(cfg, dict) and cfg:
                merged = dict(FALLBACK_MCP_HEALTH_CONFIG)
                merged.update(cfg)
                return merged
        except Exception as exc:
            logger.debug("Failed to load mcp_health_checker config via hook_utils: %s", exc)
    return dict(FALLBACK_MCP_HEALTH_CONFIG)


class HealthStatus(Enum):
    """Health status enumeration."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"
    CHECKING = "checking"


class HealthCheckType(Enum):
    """Types of health checks."""

    PING = "ping"
    SYNTHETIC_INVOCATION = "synthetic_invocation"
    DEPENDENCY_CHECK = "dependency_check"
    RESOURCE_CHECK = "resource_check"
    CUSTOM = "custom"


class TrendDirection(Enum):
    """Trend analysis direction."""

    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a health check."""

    tool_name: str
    status: HealthStatus
    check_type: HealthCheckType
    timestamp: datetime
    latency_ms: float
    message: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "status": self.status.value,
            "check_type": self.check_type.value,
            "timestamp": self.timestamp.isoformat(),
            "latency_ms": round(self.latency_ms, 2),
            "message": self.message,
            "details": self.details,
            "error": self.error,
        }


@dataclass
class LatencyStats:
    """Rolling latency statistics with percentiles."""

    values: deque[float] = field(default_factory=deque)
    max_window_size: int = 1000

    def __post_init__(self) -> None:
        if self.values.maxlen != self.max_window_size:
            self.values = deque(self.values, maxlen=self.max_window_size)

    def add(self, latency_ms: float) -> None:
        """Add a latency sample."""
        self.values.append(latency_ms)

    @property
    def count(self) -> int:
        """Number of samples."""
        return len(self.values)

    @property
    def average(self) -> float:
        """Calculate average latency."""
        if not self.values:
            return 0.0
        return sum(self.values) / len(self.values)

    @property
    def min(self) -> float:
        """Minimum latency."""
        if not self.values:
            return 0.0
        return min(self.values)

    @property
    def max(self) -> float:
        """Maximum latency."""
        if not self.values:
            return 0.0
        return max(self.values)

    def percentile(self, p: float) -> float:
        """Calculate percentile (0-100)."""
        if not self.values:
            return 0.0
        sorted_values = sorted(self.values)
        index = int(len(sorted_values) * p / 100)
        index = min(index, len(sorted_values) - 1)
        return sorted_values[index]

    @property
    def p50(self) -> float:
        """50th percentile (median)."""
        return self.percentile(50)

    @property
    def p95(self) -> float:
        """95th percentile."""
        return self.percentile(95)

    @property
    def p99(self) -> float:
        """99th percentile."""
        return self.percentile(99)

    @property
    def std_dev(self) -> float:
        """Standard deviation."""
        if len(self.values) < 2:
            return 0.0
        mean = self.average
        variance = sum((x - mean) ** 2 for x in self.values) / len(self.values)
        return math.sqrt(variance)

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "average_ms": round(self.average, 2),
            "min_ms": round(self.min, 2),
            "max_ms": round(self.max, 2),
            "p50_ms": round(self.p50, 2),
            "p95_ms": round(self.p95, 2),
            "p99_ms": round(self.p99, 2),
            "std_dev_ms": round(self.std_dev, 2),
        }


@dataclass
class LatencyTrend:
    """Trend analysis for latency."""

    direction: TrendDirection = TrendDirection.UNKNOWN
    change_percentage: float = 0.0
    samples_compared: int = 0
    confidence: float = 0.0  # 0.0 to 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "direction": self.direction.value,
            "change_percentage": round(self.change_percentage, 2),
            "samples_compared": self.samples_compared,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ToolHealthMetrics:
    """Aggregated health metrics for a tool."""

    tool_name: str
    current_status: HealthStatus
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    total_checks: int = 0
    total_failures: int = 0
    total_successes: int = 0
    last_check_time: datetime | None = None
    last_failure_time: datetime | None = None
    last_success_time: datetime | None = None
    availability_percentage: float = 100.0
    latency_stats: LatencyStats = field(default_factory=LatencyStats)
    latency_trend: LatencyTrend = field(default_factory=LatencyTrend)

    # Dynamic thresholds (sourced from config_loader)
    latency_warning_ms: float = 1000.0
    latency_critical_ms: float = 5000.0
    availability_warning_threshold: float = 95.0
    availability_critical_threshold: float = 90.0
    failure_threshold: int = 3
    degraded_threshold: int = 1
    min_samples_for_trend: int = 10
    trend_change_threshold: float = 10.0
    trend_confidence_divisor: float = 50.0

    def update_from_result(self, result: HealthCheckResult) -> None:
        """Update metrics from a health check result."""
        self.total_checks += 1
        self.last_check_time = result.timestamp

        if result.status == HealthStatus.HEALTHY:
            self.consecutive_successes += 1
            self.consecutive_failures = 0
            self.total_successes += 1
            self.last_success_time = result.timestamp
        else:
            self.consecutive_failures += 1
            self.consecutive_successes = 0
            self.total_failures += 1
            self.last_failure_time = result.timestamp

        # Update latency stats
        if result.latency_ms > 0:
            self.latency_stats.add(result.latency_ms)
            self._update_latency_trend()

        # Calculate availability
        if self.total_checks > 0:
            self.availability_percentage = self.total_successes / self.total_checks * 100

        # Determine current status
        self._update_status()

    def _update_latency_trend(self) -> None:
        """Update latency trend based on recent samples."""
        samples = list(self.latency_stats.values)
        if len(samples) < self.min_samples_for_trend:
            self.latency_trend = LatencyTrend(direction=TrendDirection.UNKNOWN)
            return

        # Compare recent window to older window
        mid_point = len(samples) // 2
        older_window = samples[:mid_point]
        recent_window = samples[mid_point:]

        if not older_window or not recent_window:
            return

        older_avg = sum(older_window) / len(older_window)
        recent_avg = sum(recent_window) / len(recent_window)

        if older_avg == 0:
            return

        change_pct = ((recent_avg - older_avg) / older_avg) * 100
        self.latency_trend.change_percentage = change_pct
        self.latency_trend.samples_compared = min(len(older_window), len(recent_window))

        # Determine direction and confidence via dynamic thresholds
        threshold = self.trend_change_threshold
        divisor = self.trend_confidence_divisor
        if change_pct > threshold:
            self.latency_trend.direction = TrendDirection.DEGRADING
            self.latency_trend.confidence = min(abs(change_pct) / divisor, 1.0)
        elif change_pct < -threshold:
            self.latency_trend.direction = TrendDirection.IMPROVING
            self.latency_trend.confidence = min(abs(change_pct) / divisor, 1.0)
        else:
            self.latency_trend.direction = TrendDirection.STABLE
            self.latency_trend.confidence = max(0.0, 1.0 - (abs(change_pct) / threshold))

    def _update_status(self) -> None:
        """Update health status based on metrics and dynamic thresholds."""
        if self.total_checks == 0:
            self.current_status = HealthStatus.UNKNOWN
            return

        # Check consecutive failures against dynamic thresholds first
        if self.consecutive_failures >= self.failure_threshold:
            self.current_status = HealthStatus.UNHEALTHY
            return
        elif self.consecutive_failures >= self.degraded_threshold:
            self.current_status = HealthStatus.DEGRADED
            return
        else:
            self.current_status = HealthStatus.HEALTHY

        # Check statistical availability thresholds only when sufficient checks have accumulated
        if self.total_checks >= max(self.failure_threshold, self.min_samples_for_trend):
            if self.availability_percentage < self.availability_critical_threshold:
                self.current_status = HealthStatus.UNHEALTHY
                return
            if self.availability_percentage < self.availability_warning_threshold:
                self.current_status = HealthStatus.DEGRADED
                return

        # Check latency thresholds
        if self.current_status == HealthStatus.HEALTHY:
            recent_latency = self.latency_stats.p95
            if recent_latency > self.latency_critical_ms:
                self.current_status = HealthStatus.DEGRADED
            elif recent_latency > self.latency_warning_ms:
                pass

    def get_latency_status(self) -> tuple[HealthStatus, str]:
        """Get status based on latency alone."""
        if self.latency_stats.count == 0:
            return HealthStatus.UNKNOWN, "No latency data"

        p95 = self.latency_stats.p95
        if p95 > self.latency_critical_ms:
            return HealthStatus.UNHEALTHY, f"Critical latency: {p95:.0f}ms (p95)"
        if p95 > self.latency_warning_ms:
            return HealthStatus.DEGRADED, f"High latency: {p95:.0f}ms (p95)"
        return HealthStatus.HEALTHY, f"Latency OK: {p95:.0f}ms (p95)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "current_status": self.current_status.value,
            "consecutive_failures": self.consecutive_failures,
            "consecutive_successes": self.consecutive_successes,
            "total_checks": self.total_checks,
            "total_failures": self.total_failures,
            "total_successes": self.total_successes,
            "last_check_time": self.last_check_time.isoformat() if self.last_check_time else None,
            "last_failure_time": self.last_failure_time.isoformat() if self.last_failure_time else None,
            "last_success_time": self.last_success_time.isoformat() if self.last_success_time else None,
            "availability_percentage": round(self.availability_percentage, 2),
            "latency_stats": self.latency_stats.to_dict(),
            "latency_trend": self.latency_trend.to_dict(),
        }


@dataclass
class HealthAlert:
    """Health alert for a tool."""

    tool_name: str
    alert_type: str  # "status_change", "latency_threshold", "availability_threshold", "trend_alert"
    severity: str  # "info", "warning", "error", "critical"
    message: str
    timestamp: datetime
    resolved: bool = False
    resolved_at: datetime | None = None
    metrics_snapshot: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "resolved": self.resolved,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "metrics_snapshot": self.metrics_snapshot,
        }


HealthCheckFunc = Callable[[str], Any]


class MCPToolHealthChecker:
    """Health monitoring system for MCP tools with latency tracking and alerting."""

    def __init__(
        self,
        check_interval_seconds: int | None = None,
        failure_threshold: int | None = None,
        degraded_threshold: int | None = None,
        latency_window_size: int | None = None,
        enable_trend_analysis: bool | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the health checker with dynamic limits configuration."""
        self._config = dict(config or load_effective_config())

        self._check_interval = (
            check_interval_seconds
            if check_interval_seconds is not None
            else int(self._config.get("check_interval_seconds", 60))
        )
        self._failure_threshold = (
            failure_threshold if failure_threshold is not None else int(self._config.get("failure_threshold", 3))
        )
        self._degraded_threshold = (
            degraded_threshold if degraded_threshold is not None else int(self._config.get("degraded_threshold", 1))
        )
        self._latency_window_size = (
            latency_window_size
            if latency_window_size is not None
            else int(self._config.get("latency_window_size", 100))
        )
        self._max_window_size = int(self._config.get("max_window_size", 1000))
        self._enable_trend_analysis = (
            enable_trend_analysis
            if enable_trend_analysis is not None
            else bool(self._config.get("enable_trend_analysis", True))
        )

        self._default_warning_latency_ms = float(self._config.get("default_warning_latency_ms", 1000.0))
        self._default_critical_latency_ms = float(self._config.get("default_critical_latency_ms", 5000.0))
        self._default_availability_warning = float(self._config.get("default_availability_warning", 95.0))
        self._default_availability_critical = float(self._config.get("default_availability_critical", 90.0))
        self._default_timeout_seconds = float(self._config.get("timeout_seconds", 5.0))
        self._min_samples_for_trend = int(self._config.get("min_samples_for_trend", 10))
        self._trend_change_threshold = float(self._config.get("trend_change_threshold", 10.0))
        self._trend_confidence_divisor = float(self._config.get("trend_confidence_divisor", 50.0))
        self._trend_confidence_min = float(self._config.get("trend_confidence_min", 0.7))
        self._max_results_history = int(self._config.get("max_results_history", 100))
        self._max_alerts_history = int(self._config.get("max_alerts_history", 1000))
        self._default_history_limit = int(self._config.get("default_history_limit", 100))
        self._availability_recommendation_threshold = float(
            self._config.get("availability_recommendation_threshold", 95.0)
        )

        self._tools_under_monitoring: set[str] = set()
        self._health_metrics: dict[str, ToolHealthMetrics] = {}
        self._health_check_results: dict[str, list[HealthCheckResult]] = {}
        self._health_checks: dict[str, HealthCheckFunc] = {}
        self._alert_handlers: list[Callable[[HealthAlert], None]] = []
        self._active_alerts: dict[str, HealthAlert] = {}
        self._alert_history: list[HealthAlert] = []
        self._latency_thresholds: dict[str, tuple[float, float]] = {}

        self._monitoring_task: asyncio.Task[Any] | None = None
        self._running = False
        self._lock = threading.RLock()

        # Register built-in logging handler
        self.add_alert_handler(self._log_alert_handler)
        logger.debug("MCP Tool Health Checker initialized")

    def reload_config(self) -> None:
        """Reload configuration dynamically from disk."""
        with self._lock:
            self._config = load_effective_config()
            self._check_interval = int(self._config.get("check_interval_seconds", self._check_interval))
            self._failure_threshold = int(self._config.get("failure_threshold", self._failure_threshold))
            self._degraded_threshold = int(self._config.get("degraded_threshold", self._degraded_threshold))
            self._latency_window_size = int(self._config.get("latency_window_size", self._latency_window_size))
            self._max_window_size = int(self._config.get("max_window_size", self._max_window_size))
            self._enable_trend_analysis = bool(self._config.get("enable_trend_analysis", self._enable_trend_analysis))
            self._default_warning_latency_ms = float(
                self._config.get("default_warning_latency_ms", self._default_warning_latency_ms)
            )
            self._default_critical_latency_ms = float(
                self._config.get("default_critical_latency_ms", self._default_critical_latency_ms)
            )
            self._default_availability_warning = float(
                self._config.get("default_availability_warning", self._default_availability_warning)
            )
            self._default_availability_critical = float(
                self._config.get("default_availability_critical", self._default_availability_critical)
            )
            self._default_timeout_seconds = float(self._config.get("timeout_seconds", self._default_timeout_seconds))
            self._min_samples_for_trend = int(self._config.get("min_samples_for_trend", self._min_samples_for_trend))
            self._trend_change_threshold = float(
                self._config.get("trend_change_threshold", self._trend_change_threshold)
            )
            self._trend_confidence_divisor = float(
                self._config.get("trend_confidence_divisor", self._trend_confidence_divisor)
            )
            self._trend_confidence_min = float(self._config.get("trend_confidence_min", self._trend_confidence_min))
            self._max_results_history = int(self._config.get("max_results_history", self._max_results_history))
            self._max_alerts_history = int(self._config.get("max_alerts_history", self._max_alerts_history))
            self._default_history_limit = int(self._config.get("default_history_limit", self._default_history_limit))
            self._availability_recommendation_threshold = float(
                self._config.get("availability_recommendation_threshold", self._availability_recommendation_threshold)
            )

            for tool_name, metrics in self._health_metrics.items():
                if tool_name not in self._latency_thresholds:
                    metrics.latency_warning_ms = self._default_warning_latency_ms
                    metrics.latency_critical_ms = self._default_critical_latency_ms
                metrics.failure_threshold = self._failure_threshold
                metrics.degraded_threshold = self._degraded_threshold
                metrics.min_samples_for_trend = self._min_samples_for_trend
                metrics.trend_change_threshold = self._trend_change_threshold
                metrics.trend_confidence_divisor = self._trend_confidence_divisor

    def _create_tool_metrics(self, tool_name: str) -> ToolHealthMetrics:
        """Helper to create initialized ToolHealthMetrics with dynamic limits."""
        warning_ms, critical_ms = self._latency_thresholds.get(
            tool_name,
            (self._default_warning_latency_ms, self._default_critical_latency_ms),
        )
        metrics = ToolHealthMetrics(
            tool_name=tool_name,
            current_status=HealthStatus.UNKNOWN,
            latency_stats=LatencyStats(max_window_size=self._max_window_size),
            latency_warning_ms=warning_ms,
            latency_critical_ms=critical_ms,
            availability_warning_threshold=self._default_availability_warning,
            availability_critical_threshold=self._default_availability_critical,
            failure_threshold=self._failure_threshold,
            degraded_threshold=self._degraded_threshold,
            min_samples_for_trend=self._min_samples_for_trend,
            trend_change_threshold=self._trend_change_threshold,
            trend_confidence_divisor=self._trend_confidence_divisor,
        )
        return metrics

    def _log_alert_handler(self, alert: HealthAlert) -> None:
        """Built-in handler that logs alerts."""
        log_level = {
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL,
        }.get(alert.severity, logging.INFO)

        log_msg = f"[{alert.severity.upper()}] {alert.tool_name}: {alert.message}"
        logger.log(log_level, log_msg)

    def register_tool_for_monitoring(self, tool_name: str) -> None:
        """Register a tool for health monitoring."""
        with self._lock:
            self._tools_under_monitoring.add(tool_name)
            if tool_name not in self._health_metrics:
                self._health_metrics[tool_name] = self._create_tool_metrics(tool_name)
            if tool_name not in self._health_check_results:
                self._health_check_results[tool_name] = []
            logger.debug("Registered tool for monitoring: %s", tool_name)

    def unregister_tool(self, tool_name: str) -> None:
        """Remove a tool from health monitoring."""
        with self._lock:
            self._tools_under_monitoring.discard(tool_name)
            logger.info("Unregistered tool from monitoring: %s", tool_name)

    def set_latency_thresholds(
        self,
        tool_name: str,
        warning_ms: float,
        critical_ms: float,
    ) -> None:
        """Set custom latency thresholds for a tool."""
        with self._lock:
            self._latency_thresholds[tool_name] = (warning_ms, critical_ms)
            if tool_name in self._health_metrics:
                self._health_metrics[tool_name].latency_warning_ms = warning_ms
                self._health_metrics[tool_name].latency_critical_ms = critical_ms

    def set_availability_thresholds(
        self,
        tool_name: str,
        warning_threshold: float,
        critical_threshold: float,
    ) -> None:
        """Set custom availability thresholds for a tool."""
        with self._lock:
            if tool_name in self._health_metrics:
                self._health_metrics[tool_name].availability_warning_threshold = warning_threshold
                self._health_metrics[tool_name].availability_critical_threshold = critical_threshold

    def register_health_check(
        self,
        tool_name: str,
        check_func: HealthCheckFunc,
        check_type: HealthCheckType = HealthCheckType.PING,
    ) -> None:
        """Register a custom health check function for a tool."""
        with self._lock:
            self._health_checks[tool_name] = check_func
            self.register_tool_for_monitoring(tool_name)
            logger.info("Registered custom health check for %s", tool_name)

    def add_alert_handler(self, handler: Callable[[HealthAlert], None]) -> None:
        """Add a handler for health alerts."""
        with self._lock:
            self._alert_handlers.append(handler)

    def remove_alert_handler(self, handler: Callable[[HealthAlert], None]) -> bool:
        """Remove an alert handler. Returns True if found and removed."""
        with self._lock:
            try:
                self._alert_handlers.remove(handler)
                return True
            except ValueError:
                return False

    async def perform_health_check(
        self,
        tool_name: str,
        check_func: HealthCheckFunc | None = None,
        timeout_seconds: float | None = None,
    ) -> HealthCheckResult:
        """Perform a health check for a specific tool.

        Args:
            tool_name: Name of the tool to check
            check_func: Optional custom check function
            timeout_seconds: Timeout for the check (defaults to configured timeout)

        Returns:
            Health check result
        """
        timeout = timeout_seconds if timeout_seconds is not None else self._default_timeout_seconds
        start_time = time.perf_counter()
        status = HealthStatus.CHECKING
        error = None
        message = None
        details: dict[str, Any] = {}
        check_type = HealthCheckType.PING

        func = check_func or self._health_checks.get(tool_name)

        if not func:
            # Default ping check - verify tool exists in registry or server
            try:
                from mcp_tool_registry import ToolRegistry

                registry = ToolRegistry.get_instance()
                tool = registry.get_tool(tool_name)
                if tool:
                    status = HealthStatus.HEALTHY
                    message = "Tool exists and is registered"
                else:
                    status = HealthStatus.UNHEALTHY
                    message = "Tool not found in registry"
            except ImportError:
                if tool_name in self._tools_under_monitoring:
                    status = HealthStatus.HEALTHY
                    message = "Tool monitored and operational"
                else:
                    status = HealthStatus.UNKNOWN
                    message = "Tool registry not available and tool unmonitored"
        else:
            try:
                # Execute health check with strict timeout for both async and sync functions (P0 Fix)
                if asyncio.iscoroutinefunction(func):
                    result = await asyncio.wait_for(func(tool_name), timeout=timeout)
                else:
                    loop = asyncio.get_running_loop()
                    result = await asyncio.wait_for(
                        loop.run_in_executor(None, func, tool_name),
                        timeout=timeout,
                    )

                if result is True or result is None:
                    status = HealthStatus.HEALTHY
                    message = "Health check passed"
                elif result is False:
                    status = HealthStatus.UNHEALTHY
                    message = "Health check returned False"
                elif isinstance(result, dict):
                    status_val = result.get("status", "healthy")
                    try:
                        status = HealthStatus(status_val)
                    except ValueError:
                        status = HealthStatus.HEALTHY
                    message = result.get("message", "Health check completed")
                    details = result.get("details", {})
                    check_type_val = result.get("check_type")
                    if check_type_val:
                        try:
                            check_type = HealthCheckType(check_type_val)
                        except ValueError:
                            pass
                elif isinstance(result, HealthStatus):
                    status = result
                    message = f"Health check returned status {result.value}"
                else:
                    status = HealthStatus.HEALTHY
                    message = str(result)

            except TimeoutError:
                status = HealthStatus.UNHEALTHY
                error = f"Health check timed out after {timeout}s"
                message = "Health check timed out"
            except Exception as exc:
                status = HealthStatus.UNHEALTHY
                error = str(exc)
                message = f"Health check failed: {exc}"

        latency_ms = (time.perf_counter() - start_time) * 1000

        with self._lock:
            if tool_name not in self._health_metrics:
                self._health_metrics[tool_name] = self._create_tool_metrics(tool_name)
            metrics = self._health_metrics[tool_name]
            warning_threshold = metrics.latency_warning_ms
            critical_threshold = metrics.latency_critical_ms

            # Latency-adjusted status
            if status == HealthStatus.HEALTHY:
                if latency_ms > critical_threshold:
                    status = HealthStatus.DEGRADED
                    message = f"Health check passed but latency is critical: {latency_ms:.0f}ms"
                elif latency_ms > warning_threshold:
                    message = f"Latency warning: {latency_ms:.0f}ms"

            result = HealthCheckResult(
                tool_name=tool_name,
                status=status,
                check_type=check_type,
                timestamp=datetime.now(),
                latency_ms=latency_ms,
                message=message,
                details=details,
                error=error,
            )

            # P0 Fix: Update metrics, latency alerts, and history for ALL checks
            self._update_metrics(result)
            self._check_latency_alerts(result, warning_threshold, critical_threshold)

            if tool_name not in self._health_check_results:
                self._health_check_results[tool_name] = []
            self._health_check_results[tool_name].append(result)
            if len(self._health_check_results[tool_name]) > self._max_results_history:
                self._health_check_results[tool_name] = self._health_check_results[tool_name][
                    -self._max_results_history :
                ]

        return result

    def _update_metrics(self, result: HealthCheckResult) -> None:
        """Update health metrics from a check result."""
        tool_name = result.tool_name
        if tool_name not in self._health_metrics:
            self._health_metrics[tool_name] = self._create_tool_metrics(tool_name)

        metrics = self._health_metrics[tool_name]
        old_status = metrics.current_status
        metrics.update_from_result(result)

        # Generate alert if status changed
        if old_status != metrics.current_status:
            self._generate_status_change_alert(result, old_status, metrics.current_status)

    def _check_latency_alerts(
        self,
        result: HealthCheckResult,
        warning_threshold: float,
        critical_threshold: float,
    ) -> None:
        """Check and generate latency-based alerts."""
        tool_name = result.tool_name
        metrics = self._health_metrics.get(tool_name)
        if not metrics:
            return

        p95 = metrics.latency_stats.p95
        alert_key = f"{tool_name}_latency"

        # Critical latency alert
        if p95 > critical_threshold:
            existing = self._active_alerts.get(alert_key)
            if not existing or existing.severity != "critical":
                alert = HealthAlert(
                    tool_name=tool_name,
                    alert_type="latency_threshold",
                    severity="critical",
                    message=f"Critical latency detected: p95={p95:.0f}ms (threshold: {critical_threshold:.0f}ms)",
                    timestamp=datetime.now(),
                    metrics_snapshot=metrics.to_dict(),
                )
                self._active_alerts[alert_key] = alert
                self._alert_history.append(alert)
                self._notify_handlers(alert)

        # Warning latency alert
        elif p95 > warning_threshold:
            existing = self._active_alerts.get(alert_key)
            if not existing or existing.severity not in ["warning", "critical"]:
                alert = HealthAlert(
                    tool_name=tool_name,
                    alert_type="latency_threshold",
                    severity="warning",
                    message=f"High latency detected: p95={p95:.0f}ms (threshold: {warning_threshold:.0f}ms)",
                    timestamp=datetime.now(),
                    metrics_snapshot=metrics.to_dict(),
                )
                self._active_alerts[alert_key] = alert
                self._alert_history.append(alert)
                self._notify_handlers(alert)

        # Clear latency alert if back to normal
        elif alert_key in self._active_alerts:
            alert = self._active_alerts.pop(alert_key)
            alert.resolved = True
            alert.resolved_at = datetime.now()
            self._alert_history.append(alert)
            self._notify_handlers(alert)

        # Trim alert history using dynamic limits
        if len(self._alert_history) > self._max_alerts_history:
            self._alert_history = self._alert_history[-self._max_alerts_history :]

    def _generate_status_change_alert(
        self,
        result: HealthCheckResult,
        old_status: HealthStatus,
        new_status: HealthStatus,
    ) -> None:
        """Generate an alert for status changes."""
        tool_name = result.tool_name

        if new_status == HealthStatus.UNHEALTHY:
            severity = "critical" if old_status == HealthStatus.HEALTHY else "error"
        elif new_status == HealthStatus.DEGRADED:
            severity = "warning"
        elif new_status == HealthStatus.HEALTHY and old_status != HealthStatus.UNKNOWN:
            severity = "info"
        else:
            return

        metrics = self._health_metrics.get(tool_name)
        snapshot = metrics.to_dict() if metrics else None

        alert = HealthAlert(
            tool_name=tool_name,
            alert_type="status_change",
            severity=severity,
            message=f"Tool {tool_name} changed from {old_status.value} to {new_status.value}",
            timestamp=datetime.now(),
            metrics_snapshot=snapshot,
        )

        self._active_alerts[tool_name] = alert
        self._alert_history.append(alert)

        if len(self._alert_history) > self._max_alerts_history:
            self._alert_history = self._alert_history[-self._max_alerts_history :]

        self._notify_handlers(alert)

    def _generate_trend_alert(self, result: HealthCheckResult) -> None:
        """Generate alert for significant latency trends."""
        if not self._enable_trend_analysis:
            return

        tool_name = result.tool_name
        metrics = self._health_metrics.get(tool_name)
        if not metrics:
            return

        trend = metrics.latency_trend
        if trend.direction == TrendDirection.UNKNOWN or trend.confidence < self._trend_confidence_min:
            return

        alert_key = f"{tool_name}_trend"

        if trend.direction == TrendDirection.DEGRADING:
            existing = self._active_alerts.get(alert_key)
            if not existing:
                alert = HealthAlert(
                    tool_name=tool_name,
                    alert_type="trend_alert",
                    severity="warning",
                    message=(
                        f"Latency trend degrading: {trend.change_percentage:+.1f}% (confidence: {trend.confidence:.0%})"
                    ),
                    timestamp=datetime.now(),
                    metrics_snapshot=metrics.to_dict(),
                )
                self._active_alerts[alert_key] = alert
                self._alert_history.append(alert)
                self._notify_handlers(alert)

    def _notify_handlers(self, alert: HealthAlert) -> None:
        """Notify all registered alert handlers safely."""
        with self._lock:
            handlers = list(self._alert_handlers)
        for handler in handlers:
            try:
                handler(alert)
            except Exception as exc:
                logger.error("Alert handler failed: %s", exc)

    async def check_all_tools(self) -> dict[str, HealthCheckResult]:
        """Perform health checks on all monitored tools concurrently."""
        with self._lock:
            tools = list(self._tools_under_monitoring)

        results: dict[str, HealthCheckResult] = {}
        if not tools:
            return results

        tasks = [self.perform_health_check(t) for t in tools]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for tool_name, result in zip(tools, completed):
            if isinstance(result, Exception):
                logger.error("Health check failed for %s: %s", tool_name, result)
                err_res = HealthCheckResult(
                    tool_name=tool_name,
                    status=HealthStatus.UNHEALTHY,
                    check_type=HealthCheckType.PING,
                    timestamp=datetime.now(),
                    latency_ms=0.0,
                    error=str(result),
                )
                results[tool_name] = err_res
            else:
                results[tool_name] = result

        return results

    async def start_monitoring(self) -> None:
        """Start automatic health monitoring background loop."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Health monitoring loop started")

    async def stop_monitoring(self) -> None:
        """Stop automatic health monitoring background loop."""
        with self._lock:
            self._running = False
            task = self._monitoring_task
            self._monitoring_task = None

        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        logger.info("Health monitoring loop stopped")

    async def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self._running:
            try:
                results = await self.check_all_tools()
                if self._enable_trend_analysis:
                    for result in results.values():
                        self._generate_trend_alert(result)
            except Exception as exc:
                logger.error("Monitoring loop error: %s", exc)

            await asyncio.sleep(self._check_interval)

    def get_tool_health(self, tool_name: str) -> ToolHealthMetrics | None:
        """Get health metrics for a specific tool."""
        with self._lock:
            return self._health_metrics.get(tool_name)

    def get_all_health(self) -> dict[str, ToolHealthMetrics]:
        """Get health metrics for all monitored tools."""
        with self._lock:
            return dict(self._health_metrics)

    def get_health_history(
        self,
        tool_name: str,
        since: datetime | None = None,
        limit: int | None = None,
    ) -> list[HealthCheckResult]:
        """Get health check history for a tool."""
        eff_limit = limit if limit is not None else self._default_history_limit
        with self._lock:
            results = list(self._health_check_results.get(tool_name, []))

        if since:
            results = [r for r in results if r.timestamp >= since]

        return results[-eff_limit:]

    def get_active_alerts(
        self,
        severity: str | None = None,
        tool_name: str | None = None,
    ) -> list[HealthAlert]:
        """Get currently active alerts, optionally filtered."""
        with self._lock:
            alerts = list(self._active_alerts.values())

        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if tool_name:
            alerts = [a for a in alerts if a.tool_name == tool_name]

        return alerts

    def get_alert_history(
        self,
        since: datetime | None = None,
        limit: int | None = None,
        severity: str | None = None,
    ) -> list[HealthAlert]:
        """Get alert history."""
        eff_limit = limit if limit is not None else self._default_history_limit
        with self._lock:
            alerts = list(self._alert_history)

        if since:
            alerts = [a for a in alerts if a.timestamp >= since]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        return alerts[-eff_limit:]

    def resolve_alert(self, tool_name: str, alert_type: str | None = None) -> int:
        """Mark alerts as resolved."""
        resolved_count = 0
        with self._lock:
            to_remove: list[str] = []
            for key, alert in self._active_alerts.items():
                if alert.tool_name == tool_name:
                    if alert_type is None or alert.alert_type == alert_type:
                        alert.resolved = True
                        alert.resolved_at = datetime.now()
                        to_remove.append(key)
                        resolved_count += 1

            for key in to_remove:
                del self._active_alerts[key]

        if resolved_count > 0:
            logger.info("Resolved %d alert(s) for %s", resolved_count, tool_name)
        return resolved_count

    def resolve_all_alerts(self) -> int:
        """Mark all active alerts as resolved."""
        with self._lock:
            resolved_count = len(self._active_alerts)
            for alert in self._active_alerts.values():
                alert.resolved = True
                alert.resolved_at = datetime.now()
            self._active_alerts.clear()

        logger.info("Resolved all %d alerts", resolved_count)
        return resolved_count

    def get_availability_matrix(self) -> dict[str, dict[str, Any]]:
        """Generate health-based availability matrix."""
        matrix: dict[str, dict[str, Any]] = {}

        with self._lock:
            monitored_tools = list(self._tools_under_monitoring)
            for tool_name in monitored_tools:
                metrics = self._health_metrics.get(tool_name)
                if metrics:
                    latency_status, latency_msg = metrics.get_latency_status()
                    matrix[tool_name] = {
                        "status": metrics.current_status.value,
                        "healthy": metrics.current_status == HealthStatus.HEALTHY,
                        "availability_percentage": round(metrics.availability_percentage, 2),
                        "total_checks": metrics.total_checks,
                        "consecutive_failures": metrics.consecutive_failures,
                        "average_latency_ms": round(metrics.latency_stats.average, 2),
                        "p95_latency_ms": round(metrics.latency_stats.p95, 2),
                        "p99_latency_ms": round(metrics.latency_stats.p99, 2),
                        "latency_trend": metrics.latency_trend.to_dict(),
                        "latency_status": latency_status.value,
                        "latency_message": latency_msg,
                        "last_check_time": (metrics.last_check_time.isoformat() if metrics.last_check_time else None),
                        "has_active_alert": tool_name in self._active_alerts,
                    }
                else:
                    matrix[tool_name] = {
                        "status": HealthStatus.UNKNOWN.value,
                        "healthy": False,
                        "availability_percentage": 0.0,
                        "total_checks": 0,
                        "consecutive_failures": 0,
                        "average_latency_ms": 0.0,
                        "p95_latency_ms": 0.0,
                        "p99_latency_ms": 0.0,
                        "latency_trend": LatencyTrend().to_dict(),
                        "latency_status": HealthStatus.UNKNOWN.value,
                        "latency_message": "No data",
                        "last_check_time": None,
                        "has_active_alert": False,
                    }

        return matrix

    def get_health_summary(self) -> dict[str, Any]:
        """Get overall health summary."""
        with self._lock:
            total = len(self._health_metrics)
            healthy = sum(1 for m in self._health_metrics.values() if m.current_status == HealthStatus.HEALTHY)
            degraded = sum(1 for m in self._health_metrics.values() if m.current_status == HealthStatus.DEGRADED)
            unhealthy = sum(1 for m in self._health_metrics.values() if m.current_status == HealthStatus.UNHEALTHY)
            unknown = sum(1 for m in self._health_metrics.values() if m.current_status == HealthStatus.UNKNOWN)

            latencies = [m.latency_stats.average for m in self._health_metrics.values() if m.latency_stats.count > 0]
            p95s = [m.latency_stats.p95 for m in self._health_metrics.values() if m.latency_stats.count > 0]
            p99s = [m.latency_stats.p99 for m in self._health_metrics.values() if m.latency_stats.count > 0]
            latency_sample_count = sum(m.latency_stats.count for m in self._health_metrics.values())

            avg_latency = (sum(latencies) / len(latencies)) if latencies else 0.0
            avg_p95 = (sum(p95s) / len(p95s)) if p95s else 0.0
            avg_p99 = (sum(p99s) / len(p99s)) if p99s else 0.0

            availabilities = [m.availability_percentage for m in self._health_metrics.values()]
            overall_availability = (sum(availabilities) / len(availabilities)) if availabilities else 0.0

            alert_counts = {"info": 0, "warning": 0, "error": 0, "critical": 0}
            for alert in self._active_alerts.values():
                if alert.severity in alert_counts:
                    alert_counts[alert.severity] += 1

            return {
                "total_tools": total,
                "healthy": healthy,
                "degraded": degraded,
                "unhealthy": unhealthy,
                "unknown": unknown,
                "active_alerts": len(self._active_alerts),
                "alerts_by_severity": alert_counts,
                "average_latency_ms": round(avg_latency, 2),
                "average_p95_latency_ms": round(avg_p95, 2),
                "average_p99_latency_ms": round(avg_p99, 2),
                "latency_samples_collected": latency_sample_count,
                "overall_availability_percentage": round(overall_availability, 2),
                "monitoring_active": self._running,
                "check_interval_seconds": self._check_interval,
            }

    def export_health_report(self) -> dict[str, Any]:
        """Export comprehensive health report."""
        summary = self.get_health_summary()
        availability_matrix = self.get_availability_matrix()
        with self._lock:
            active_alerts = [a.to_dict() for a in self._active_alerts.values()]

        recommendations: list[dict[str, Any]] = []
        for tool_name, data in availability_matrix.items():
            if data["latency_trend"]["direction"] == "degrading":
                recommendations.append(
                    {
                        "tool": tool_name,
                        "priority": "medium",
                        "issue": "Latency degradation trend detected",
                        "recommendation": (
                            f"Investigate performance for {tool_name}. "
                            f"Latency increased by {data['latency_trend']['change_percentage']:.1f}%"
                        ),
                    }
                )

            if data["consecutive_failures"] > 0:
                recommendations.append(
                    {
                        "tool": tool_name,
                        "priority": "high",
                        "issue": f"{data['consecutive_failures']} consecutive failures",
                        "recommendation": f"Check {tool_name} for errors or dependency issues",
                    }
                )

            if data["availability_percentage"] < self._availability_recommendation_threshold:
                recommendations.append(
                    {
                        "tool": tool_name,
                        "priority": "medium",
                        "issue": f"Low availability: {data['availability_percentage']:.1f}%",
                        "recommendation": f"Review {tool_name} for reliability issues",
                    }
                )

        return {
            "generated_at": datetime.now().isoformat(),
            "summary": summary,
            "availability_matrix": availability_matrix,
            "active_alerts": active_alerts,
            "recommendations": recommendations,
        }


# Thread-safe global health checker singleton
_GLOBAL_CHECKER_LOCK = threading.RLock()
_health_checker: MCPToolHealthChecker | None = None


def get_health_checker(config: dict[str, Any] | None = None) -> MCPToolHealthChecker:
    """Get or create the global thread-safe health checker instance."""
    global _health_checker
    with _GLOBAL_CHECKER_LOCK:
        if _health_checker is None:
            _health_checker = MCPToolHealthChecker(config=config)
        return _health_checker


def reset_health_checker() -> None:
    """Reset the global health checker singleton (for testing)."""
    global _health_checker
    with _GLOBAL_CHECKER_LOCK:
        if _health_checker is not None and _health_checker._running:
            try:
                asyncio.run(_health_checker.stop_monitoring())
            except Exception:
                pass
        _health_checker = None


async def quick_health_check(tool_name: str) -> HealthCheckResult:
    """Perform a quick health check on a single tool."""
    checker = get_health_checker()
    return await checker.perform_health_check(tool_name)


def quick_health_check_sync(tool_name: str, timeout_seconds: float | None = None) -> HealthCheckResult:
    """Synchronous wrapper for quick_health_check protecting against event loop collisions."""
    checker = get_health_checker()
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                lambda: asyncio.run(checker.perform_health_check(tool_name, timeout_seconds=timeout_seconds))
            )
            return future.result()
    else:
        return asyncio.run(checker.perform_health_check(tool_name, timeout_seconds=timeout_seconds))


def get_health_status(tool_name: str) -> ToolHealthMetrics | None:
    """Get health metrics for a tool."""
    checker = get_health_checker()
    return checker.get_tool_health(tool_name)


def run_self_tests() -> bool:
    """Execute comprehensive self-test suite covering 16 test scenarios."""
    test_results: list[tuple[str, bool, str]] = []

    def record_test(tc_id: str, name: str, passed: bool, detail: str = "") -> None:
        status_str = "PASS" if passed else "FAIL"
        test_results.append((f"{tc_id}: {name}", passed, detail))
        print(f"[{status_str}] {tc_id}: {name} {f'- {detail}' if detail else ''}")

    print("======================================================================")
    print("Executing MCP Health Checker Self-Test Suite (16 Scenarios)...")
    print("======================================================================\n")

    reset_health_checker()

    # TC01: Zero-config initialization & dynamic config loader integration
    try:
        checker = MCPToolHealthChecker()
        cfg_loaded = checker._check_interval == 60 and checker._failure_threshold == 3
        record_test("TC01", "zero_config_initialization", cfg_loaded, f"interval={checker._check_interval}s")
    except Exception as exc:
        record_test("TC01", "zero_config_initialization", False, str(exc))

    # TC02: Dynamic configuration reload
    try:
        checker.reload_config()
        record_test("TC02", "dynamic_config_reload", True, "Config reloaded cleanly")
    except Exception as exc:
        record_test("TC02", "dynamic_config_reload", False, str(exc))

    # TC03: P0 Fix - Default ping check updates metrics without early return
    try:
        reset_health_checker()
        checker = MCPToolHealthChecker()
        checker.register_tool_for_monitoring("ping_tool_1")
        res03 = asyncio.run(checker.perform_health_check("ping_tool_1"))
        m03 = checker.get_tool_health("ping_tool_1")
        history03 = checker.get_health_history("ping_tool_1")
        tc03_passed = (
            m03 is not None
            and m03.total_checks == 1
            and len(history03) == 1
            and res03.status in [HealthStatus.HEALTHY, HealthStatus.UNHEALTHY, HealthStatus.UNKNOWN]
        )
        record_test("TC03", "default_ping_updates_metrics", tc03_passed, f"checks={m03.total_checks if m03 else 0}")
    except Exception as exc:
        record_test("TC03", "default_ping_updates_metrics", False, str(exc))

    # TC04: Successful synchronous health check function
    try:
        checker = MCPToolHealthChecker()
        checker.register_health_check("sync_tool", lambda name: True)
        res04 = asyncio.run(checker.perform_health_check("sync_tool"))
        m04 = checker.get_tool_health("sync_tool")
        tc04_passed = res04.status == HealthStatus.HEALTHY and m04 is not None and m04.total_successes == 1
        record_test("TC04", "sync_health_check", tc04_passed, f"status={res04.status.value}")
    except Exception as exc:
        record_test("TC04", "sync_health_check", False, str(exc))

    # TC05: Successful asynchronous health check coroutine
    try:
        checker = MCPToolHealthChecker()

        async def async_check(name: str) -> dict[str, Any]:
            await asyncio.sleep(0.01)
            return {"status": "healthy", "message": "All sub-services OK"}

        checker.register_health_check("async_tool", async_check)
        res05 = asyncio.run(checker.perform_health_check("async_tool"))
        tc05_passed = res05.status == HealthStatus.HEALTHY and res05.message == "All sub-services OK"
        record_test("TC05", "async_coroutine_health_check", tc05_passed, f"msg={res05.message}")
    except Exception as exc:
        record_test("TC05", "async_coroutine_health_check", False, str(exc))

    # TC06: P0 Fix - Synchronous check timeout isolation
    try:
        checker = MCPToolHealthChecker()

        def slow_sync(name: str) -> bool:
            time.sleep(0.3)
            return True

        checker.register_health_check("slow_sync_tool", slow_sync)
        res06 = asyncio.run(checker.perform_health_check("slow_sync_tool", timeout_seconds=0.05))
        tc06_passed = res06.status == HealthStatus.UNHEALTHY and "timed out" in (res06.error or "").lower()
        record_test("TC06", "sync_timeout_enforcement", tc06_passed, f"error={res06.error}")
    except Exception as exc:
        record_test("TC06", "sync_timeout_enforcement", False, str(exc))

    # TC07: Asynchronous coroutine timeout isolation
    try:
        checker = MCPToolHealthChecker()

        async def slow_async(name: str) -> bool:
            await asyncio.sleep(0.3)
            return True

        checker.register_health_check("slow_async_tool", slow_async)
        res07 = asyncio.run(checker.perform_health_check("slow_async_tool", timeout_seconds=0.05))
        tc07_passed = res07.status == HealthStatus.UNHEALTHY and "timed out" in (res07.error or "").lower()
        record_test("TC07", "async_timeout_enforcement", tc07_passed, f"error={res07.error}")
    except Exception as exc:
        record_test("TC07", "async_timeout_enforcement", False, str(exc))

    # TC08: Consecutive failures threshold triggering DEGRADED then UNHEALTHY
    try:
        checker = MCPToolHealthChecker(failure_threshold=3, degraded_threshold=1)
        checker.register_health_check("failing_tool", lambda name: False)

        # First failure -> DEGRADED
        asyncio.run(checker.perform_health_check("failing_tool"))
        m08_1 = checker.get_tool_health("failing_tool")
        status1 = m08_1.current_status if m08_1 else None

        # Second failure -> DEGRADED
        asyncio.run(checker.perform_health_check("failing_tool"))

        # Third failure -> UNHEALTHY
        asyncio.run(checker.perform_health_check("failing_tool"))
        m08_3 = checker.get_tool_health("failing_tool")
        status3 = m08_3.current_status if m08_3 else None

        tc08_passed = status1 == HealthStatus.DEGRADED and status3 == HealthStatus.UNHEALTHY
        record_test(
            "TC08",
            "consecutive_failures_progression",
            tc08_passed,
            f"1st={status1.value if status1 else 'None'}, 3rd={status3.value if status3 else 'None'}",
        )
    except Exception as exc:
        record_test("TC08", "consecutive_failures_progression", False, str(exc))

    # TC09: Dynamic threshold overrides in ToolHealthMetrics
    try:
        checker = MCPToolHealthChecker(failure_threshold=5, degraded_threshold=2)
        checker.register_health_check("delayed_unhealthy_tool", lambda name: False)

        # 1 failure -> still HEALTHY because degraded_threshold=2
        asyncio.run(checker.perform_health_check("delayed_unhealthy_tool"))
        m09_1 = checker.get_tool_health("delayed_unhealthy_tool")
        st1 = m09_1.current_status if m09_1 else None

        # 2 failures -> DEGRADED
        asyncio.run(checker.perform_health_check("delayed_unhealthy_tool"))
        m09_2 = checker.get_tool_health("delayed_unhealthy_tool")
        st2 = m09_2.current_status if m09_2 else None

        tc09_passed = st1 == HealthStatus.HEALTHY and st2 == HealthStatus.DEGRADED
        record_test("TC09", "dynamic_threshold_overrides", tc09_passed, f"1st={st1.value}, 2nd={st2.value}")
    except Exception as exc:
        record_test("TC09", "dynamic_threshold_overrides", False, str(exc))

    # TC10: Latency threshold alerting and status degradation
    try:
        checker = MCPToolHealthChecker()
        checker.register_tool_for_monitoring("latency_test_tool")
        checker.set_latency_thresholds("latency_test_tool", warning_ms=10.0, critical_ms=30.0)

        # Ingest simulated high latency samples into metrics
        m10 = checker.get_tool_health("latency_test_tool")
        assert m10 is not None
        for _ in range(10):
            m10.latency_stats.add(50.0)

        # Trigger check_latency_alerts
        dummy_res = HealthCheckResult(
            tool_name="latency_test_tool",
            status=HealthStatus.HEALTHY,
            check_type=HealthCheckType.PING,
            timestamp=datetime.now(),
            latency_ms=50.0,
        )
        checker._check_latency_alerts(dummy_res, warning_threshold=10.0, critical_threshold=30.0)
        alerts10 = checker.get_active_alerts(tool_name="latency_test_tool")
        tc10_passed = len(alerts10) > 0 and alerts10[0].severity == "critical"
        record_test(
            "TC10",
            "latency_alert_generation",
            tc10_passed,
            f"alert severity={alerts10[0].severity if alerts10 else 'None'}",
        )
    except Exception as exc:
        record_test("TC10", "latency_alert_generation", False, str(exc))

    # TC11: Latency trend analysis (degrading detection)
    try:
        metrics11 = ToolHealthMetrics(
            tool_name="trend_tool",
            current_status=HealthStatus.HEALTHY,
            min_samples_for_trend=4,
            trend_change_threshold=10.0,
        )
        # Older window low latency
        for lat in [10.0, 12.0, 11.0, 10.0]:
            metrics11.latency_stats.add(lat)
        # Recent window high latency
        for lat in [30.0, 35.0, 32.0, 34.0]:
            metrics11.latency_stats.add(lat)

        metrics11._update_latency_trend()
        tc11_passed = (
            metrics11.latency_trend.direction == TrendDirection.DEGRADING
            and metrics11.latency_trend.change_percentage > 100.0
        )
        record_test(
            "TC11",
            "latency_trend_detection",
            tc11_passed,
            f"direction={metrics11.latency_trend.direction.value}, change={metrics11.latency_trend.change_percentage:.1f}%",
        )
    except Exception as exc:
        record_test("TC11", "latency_trend_detection", False, str(exc))

    # TC12: Alert handlers and status change alert creation
    try:
        checker = MCPToolHealthChecker()
        handled_alerts: list[HealthAlert] = []
        checker.add_alert_handler(lambda a: handled_alerts.append(a))

        checker.register_health_check("alert_tool", lambda name: False)
        asyncio.run(checker.perform_health_check("alert_tool"))
        tc12_passed = len(handled_alerts) > 0 and handled_alerts[0].alert_type == "status_change"
        record_test("TC12", "alert_handler_invocation", tc12_passed, f"captured={len(handled_alerts)}")
    except Exception as exc:
        record_test("TC12", "alert_handler_invocation", False, str(exc))

    # TC13: Alert resolution (single tool and resolve_all_alerts)
    try:
        checker = MCPToolHealthChecker()
        checker.register_health_check("resolve_tool_1", lambda name: False)
        checker.register_health_check("resolve_tool_2", lambda name: False)
        asyncio.run(checker.perform_health_check("resolve_tool_1"))
        asyncio.run(checker.perform_health_check("resolve_tool_2"))

        # Resolve 1 tool
        r_single = checker.resolve_alert("resolve_tool_1")
        active_after_single = checker.get_active_alerts()

        # Resolve all
        r_all = checker.resolve_all_alerts()
        active_after_all = checker.get_active_alerts()

        tc13_passed = r_single == 1 and len(active_after_single) == 1 and len(active_after_all) == 0
        record_test("TC13", "alert_resolution", tc13_passed, f"resolved_single={r_single}, resolved_all={r_all}")
    except Exception as exc:
        record_test("TC13", "alert_resolution", False, str(exc))

    # TC14: Availability matrix and health summary export
    try:
        checker = MCPToolHealthChecker()
        checker.register_tool_for_monitoring("summary_tool_1")
        checker.register_health_check("summary_tool_2", lambda name: True)
        asyncio.run(checker.perform_health_check("summary_tool_1"))
        asyncio.run(checker.perform_health_check("summary_tool_2"))

        summary = checker.get_health_summary()
        matrix = checker.get_availability_matrix()
        report = checker.export_health_report()

        tc14_passed = (
            summary["total_tools"] == 2
            and "summary_tool_1" in matrix
            and "summary_tool_2" in matrix
            and "recommendations" in report
        )
        record_test("TC14", "health_summary_and_matrix_export", tc14_passed, f"total_tools={summary['total_tools']}")
    except Exception as exc:
        record_test("TC14", "health_summary_and_matrix_export", False, str(exc))

    # TC15: Thread-safe singleton access
    try:
        reset_health_checker()
        instances: list[MCPToolHealthChecker] = []

        def worker() -> None:
            c = get_health_checker()
            instances.append(c)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        all_same = all(inst is instances[0] for inst in instances) and len(instances) == 10
        record_test("TC15", "thread_safe_singleton_access", all_same, f"unique={len(set(instances))}")
    except Exception as exc:
        record_test("TC15", "thread_safe_singleton_access", False, str(exc))

    # TC16: CLI hook execution (PreInvocation & PreToolUse compliance)
    try:
        # PreToolUse evaluation test
        pre_tool_res = pre_tool_response("allow", "MCP tools healthy.")
        # PreInvocation evaluation test
        pre_inv_res = pre_invocation_response(inject_steps=[])
        tc16_passed = pre_tool_res.get("decision") == "allow" and "injectSteps" in pre_inv_res
        record_test("TC16", "cli_hook_response_compliance", tc16_passed, "Hook payloads formatted correctly")
    except Exception as exc:
        record_test("TC16", "cli_hook_response_compliance", False, str(exc))

    total_passed = sum(1 for _, passed, _ in test_results if passed)
    total_cases = len(test_results)
    all_passed = total_passed == total_cases

    print("\n----------------------------------------------------------------------")
    print(f"Self-Test Summary: {total_passed}/{total_cases} tests passed ({'100%' if all_passed else 'FAILED'}).")
    print("----------------------------------------------------------------------\n")
    return all_passed


def main() -> None:
    """CLI hook entrypoint for MCP health checks."""
    if "--self-test" in sys.argv:
        success = run_self_tests()
        sys.exit(0 if success else 1)

    checker = get_health_checker()

    if "--report" in sys.argv:
        report = checker.export_health_report()
        print(json.dumps(report, indent=2, ensure_ascii=False))
        sys.exit(0)

    if "--check" in sys.argv:
        try:
            tool_idx = sys.argv.index("--check") + 1
            tool_name = sys.argv[tool_idx]
            result = quick_health_check_sync(tool_name)
            print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
            sys.exit(0 if result.status != HealthStatus.UNHEALTHY else 1)
        except (IndexError, ValueError):
            print(json.dumps({"error": "Missing tool name after --check"}, ensure_ascii=False))
            sys.exit(1)

    payload = read_stdin_payload(default={})

    if "--pre-tool" in sys.argv:
        tool_call = get_tool_call(payload)
        tool_name = tool_call.get("name") if isinstance(tool_call, dict) else None
        if tool_name and tool_name in checker._tools_under_monitoring:
            status = checker.get_tool_health(tool_name)
            if status and status.current_status == HealthStatus.UNHEALTHY:
                log_diagnostic(f"MCP Tool '{tool_name}' is UNHEALTHY. Proceeding with caution.")
        emit_stdout_json(pre_tool_response("allow", "MCP tools checked."))
        sys.exit(0)

    # PreInvocation hook (Default)
    inject_steps: list[str] = []
    try:
        log_diagnostic("MCP health checker verified operational status.")
        # Discover and check unhealthy tools if any
        summary = checker.get_health_summary()
        if summary.get("unhealthy", 0) > 0:
            unhealthy_tools = [
                name for name, m in checker.get_all_health().items() if m.current_status == HealthStatus.UNHEALTHY
            ]
            inject_steps.append(
                f"[SYSTEM HEALTH WARNING] Unhealthy MCP tools detected: {', '.join(unhealthy_tools)}. "
                "Verify connections or fallback mechanisms."
            )
    except Exception as exc:
        log_diagnostic(f"MCP health checker evaluation error: {exc}")

    emit_stdout_json(pre_invocation_response(inject_steps=inject_steps))
    sys.exit(0)


if __name__ == "__main__":
    main()
