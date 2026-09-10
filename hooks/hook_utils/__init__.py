"""Enterprise Hook Utilities Package.

Shared utility modules for Enterprise Hooks:
- config_loader: Dynamic limits and hardware profile configuration loader with mtime cache.
- workload_sensor: Dynamic workload sensing without whitelists, AST/structural complexity analysis.
- cpu_governor: psutil-based 3-zone CPU governor and micro-queue semaphore scheduler.
- circuit_breaker: Circuit breaker pattern implementation for service resilience.
"""

from .circuit_breaker import (
    CallRecord,
    CircuitBreaker,
    CircuitBreakerError,
    CircuitBreakerOpenError,
    CircuitBreakerRegistry,
    CircuitState,
    RollingWindow,
    circuit_breaker,
    get_circuit_breaker,
)
from .command_validator import (
    CommandSafetyValidator,
    evaluate_command_safety,
    get_command_validator,
)
from .config_loader import (
    DynamicConfigLoader,
    get_audit_trail_config,
    get_auto_lint_config,
    get_circuit_breaker_config,
    get_concurrency_rules,
    get_context_compression_config,
    get_dangerous_command_rules,
    get_diff_security_config,
    get_dynamic_limits,
    get_execution_timeouts,
    get_format_check_config,
    get_hallucination_guard_config,
    get_hardware_profile,
    get_mcp_health_checker_config,
    get_pre_stop_audit_config,
    get_regression_detector_config,
    get_scope_boundary_rules,
    get_self_healing_config,
    get_session_compaction_config,
    get_test_runner_config,
    get_token_budget_config,
    get_trajectory_guard_config,
)
from .cpu_governor import CPUGovernor, CPUZone, governor_guard
from .workload_sensor import ComplexityResult, WorkloadSensor

__all__ = [
    "CallRecord",
    "CircuitBreaker",
    "CircuitBreakerError",
    "CircuitBreakerOpenError",
    "CircuitBreakerRegistry",
    "CircuitState",
    "CommandSafetyValidator",
    "ComplexityResult",
    "CPUGovernor",
    "CPUZone",
    "DynamicConfigLoader",
    "RollingWindow",
    "WorkloadSensor",
    "circuit_breaker",
    "evaluate_command_safety",
    "get_audit_trail_config",
    "get_auto_lint_config",
    "get_circuit_breaker",
    "get_circuit_breaker_config",
    "get_command_validator",
    "get_concurrency_rules",
    "get_context_compression_config",
    "get_dangerous_command_rules",
    "get_diff_security_config",
    "get_dynamic_limits",
    "get_execution_timeouts",
    "get_format_check_config",
    "get_hallucination_guard_config",
    "get_hardware_profile",
    "get_mcp_health_checker_config",
    "get_pre_stop_audit_config",
    "get_regression_detector_config",
    "get_scope_boundary_rules",
    "get_self_healing_config",
    "get_session_compaction_config",
    "get_test_runner_config",
    "get_token_budget_config",
    "get_trajectory_guard_config",
    "governor_guard",
]
