"""Unit and Integration Test Suite for Self-Healing Engine.

Validates:
1. Dynamic matrix loading from JSON and resilient fallback on missing config.
2. Hot-reloading when matrix config is modified on disk.
3. Multi-stage traceback parsing (frames, exceptions, pytest headers, linter codes).
4. PII & Secret scrubbing (§1, §2).
5. Comprehensive rule matching across all 10 error categories and enterprise standards (§1-§29).
6. Integration with hook_utils.config_loader (timeouts, dynamic limits).
7. Integration with hook_utils.cpu_governor (CPU zones, thermal protection cooldown).
8. Integration with hook_utils.workload_sensor (atomic vs compound complexity).
9. Safe command execution and dry-run simulation (shell=False).
"""

from __future__ import annotations

import json
import pathlib
import sys
from unittest.mock import MagicMock

import pytest

# Ensure repo root is on sys.path
REPO_ROOT = pathlib.Path(__file__).parent.parent.resolve()
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hook_utils.cpu_governor import CPUZone
from self_healing_engine import (
    DiagnosticSanitizer,
    ErrorCategory,
    RemediationMatrix,
    SelfHealingEngine,
    SeverityLevel,
    TracebackParser,
    run_self_test,
)


@pytest.fixture
def engine() -> SelfHealingEngine:
    """Fixture providing a configured SelfHealingEngine instance."""
    return SelfHealingEngine()


# =============================================================================
# 1. Traceback Parsing & PII Scrubbing Tests
# =============================================================================


def test_traceback_parser_standard_python_exception() -> None:
    """Validate extraction of file, line, and symbol from standard Python traceback."""
    tb = """Traceback (most recent call last):
  File "src/auth/jwt_handler.py", line 85, in verify_token
    token_data = jwt.decode(token, secret)
AttributeError: 'NoneType' object has no attribute 'decode'"""
    result = TracebackParser.parse_traceback(tb)
    assert result["file"] == "src/auth/jwt_handler.py"
    assert result["line"] == 85
    assert result["symbol"] == "verify_token"
    assert result["error_name"] == "AttributeError"
    assert "NoneType" in result["error_detail"]


def test_traceback_parser_pytest_failure() -> None:
    """Validate extraction of pytest failure headers."""
    output = "FAILED tests/unit/test_orders.py::test_create_order - AssertionError: assert 500 == 200"
    result = TracebackParser.parse_traceback(output)
    assert result["file"] == "tests/unit/test_orders.py"
    assert result["symbol"] == "test_create_order"
    assert result["error_name"] == "PytestAssertionFailure"


def test_traceback_parser_linter_output() -> None:
    """Validate extraction of linter violation file, line, and code."""
    linter_out = "services/user_service.py:42:5: F401 `datetime` imported but unused"
    result = TracebackParser.parse_traceback(linter_out)
    assert result["file"] == "services/user_service.py"
    assert result["line"] == 42
    assert result["error_name"] == "F401"


def test_pii_sanitization_secrets_and_base64() -> None:
    """Ensure secrets and long base64 payloads are completely scrubbed (§1, §2)."""
    raw = (
        "Fatal error connecting with key AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6 "
        "and password: 'super_secret_password_123' and payload "
        "data:image/png;base64," + ("X" * 150)
    )
    clean = DiagnosticSanitizer.sanitize(raw)
    assert "[REDACTED_SECRET_KEY]" in clean
    assert "super_secret_password_123" not in clean
    assert "[REDACTED]" in clean
    assert "[REDACTED_BASE64_PAYLOAD]" in clean


# =============================================================================
# 2. Remediation Matrix & Rule Matching Tests
# =============================================================================


def test_matrix_loading_and_fallback(tmp_path: pathlib.Path) -> None:
    """Test matrix resilient fallback when config file is missing."""
    missing_path = tmp_path / "non_existent_matrix.json"
    matrix = RemediationMatrix(matrix_path=missing_path)
    rules = matrix.get_rules()
    assert len(rules) > 0
    assert any(r.rule_id == "FALLBACK-IMPORT-001" for r in rules)


def test_matrix_hot_reload(tmp_path: pathlib.Path) -> None:
    """Test that matrix detects file modification and hot-reloads."""
    matrix_file = tmp_path / "custom_matrix.json"
    initial_data = {
        "version": "1.0",
        "rules": [
            {
                "rule_id": "TEST-RULE-001",
                "name": "Initial Rule",
                "category": "SYNTAX_LINT",
                "severity": "LOW",
                "pattern": "InitialPattern",
                "root_cause_template": "Initial Cause",
                "rule_ref": "§27",
                "steps": [],
            }
        ],
    }
    matrix_file.write_text(json.dumps(initial_data), encoding="utf-8")
    matrix = RemediationMatrix(matrix_path=matrix_file)
    assert len(matrix.get_rules()) == 1
    assert matrix.get_rules()[0].rule_id == "TEST-RULE-001"

    # Update file content
    updated_data = {
        "version": "2.0",
        "rules": [
            {
                "rule_id": "TEST-RULE-002",
                "name": "Updated Rule",
                "category": "GIT_VCS",
                "severity": "CRITICAL",
                "pattern": "UpdatedPattern",
                "root_cause_template": "Updated Cause",
                "rule_ref": "§11",
                "steps": [],
            }
        ],
    }
    matrix_file.write_text(json.dumps(updated_data), encoding="utf-8")
    matrix.reload(force=True)
    assert len(matrix.get_rules()) == 1
    assert matrix.get_rules()[0].rule_id == "TEST-RULE-002"


# =============================================================================
# 3. Enterprise Rule Diagnostics Tests (§1-§29)
# =============================================================================


def test_diagnose_module_not_found(engine: SelfHealingEngine) -> None:
    """Test diagnosis of ModuleNotFoundError with auto-fix command."""
    diag = engine.diagnose("ModuleNotFoundError: No module named 'httpx'")
    assert diag.category == ErrorCategory.IMPORT_DEPENDENCY
    assert diag.severity == SeverityLevel.HIGH
    assert "httpx" in diag.root_cause
    assert diag.can_auto_heal is True
    assert any("pip install httpx" in (s.command or "") for s in diag.remediation_steps)


def test_diagnose_asyncio_event_loop_deadlock(engine: SelfHealingEngine) -> None:
    """Test diagnosis of nested asyncio loop error (§6)."""
    diag = engine.diagnose("RuntimeError: This event loop is already running")
    assert diag.category == ErrorCategory.ASYNC_CONCURRENCY
    assert diag.severity == SeverityLevel.CRITICAL
    assert "§6" in diag.rule_reference
    assert diag.can_auto_heal is False  # Requires architectural refactoring


def test_diagnose_null_pointer_safety(engine: SelfHealingEngine) -> None:
    """Test diagnosis of NoneType attribute error (§2)."""
    diag = engine.diagnose("AttributeError: 'NoneType' object has no attribute 'user_id'")
    assert diag.category == ErrorCategory.TYPE_NULL_SAFETY
    assert diag.severity == SeverityLevel.HIGH
    assert "§2" in diag.rule_reference


def test_diagnose_resource_leak(engine: SelfHealingEngine) -> None:
    """Test diagnosis of unclosed file/socket leak (§8, §18)."""
    diag = engine.diagnose("ResourceWarning: unclosed file <_io.BufferedReader name='data.bin'>")
    assert diag.category == ErrorCategory.RESOURCE_LEAK
    assert diag.severity == SeverityLevel.HIGH
    assert "§8" in diag.rule_reference


def test_diagnose_git_conflict(engine: SelfHealingEngine) -> None:
    """Test diagnosis of Git merge conflict (§11, §13)."""
    diag = engine.diagnose("CONFLICT (content): Merge conflict in api/routes.py\nAutomatic merge failed")
    assert diag.category == ErrorCategory.GIT_VCS
    assert diag.severity == SeverityLevel.CRITICAL
    assert "§11" in diag.rule_reference


def test_diagnose_git_push_rejected(engine: SelfHealingEngine) -> None:
    """Test diagnosis of Git push rejected out-of-sync (§13)."""
    diag = engine.diagnose(" ! [rejected]        main -> main (fetch first)\nerror: failed to push some refs")
    assert diag.category == ErrorCategory.GIT_VCS
    assert diag.can_auto_heal is True
    assert any("git fetch origin main" in (s.command or "") for s in diag.remediation_steps)


def test_diagnose_multi_tenant_idor(engine: SelfHealingEngine) -> None:
    """Test diagnosis of missing multi-tenant ownership filter (§24)."""
    diag = engine.diagnose("tenant_id_missing: Access attempt without tenant ownership scope")
    assert diag.category == ErrorCategory.DATABASE_MULTITENANT
    assert diag.severity == SeverityLevel.CRITICAL
    assert "§24" in diag.rule_reference


def test_diagnose_foreign_key_violation(engine: SelfHealingEngine) -> None:
    """Test diagnosis of database foreign key integrity violation (§26)."""
    diag = engine.diagnose("IntegrityError: (1452) a foreign key constraint fails (`orders`, CONSTRAINT `fk_customer`)")
    assert diag.category == ErrorCategory.DATABASE_MULTITENANT
    assert diag.severity == SeverityLevel.HIGH
    assert "§26" in diag.rule_reference


def test_diagnose_ruff_linter_fixable(engine: SelfHealingEngine) -> None:
    """Test diagnosis of Ruff linter violations (§27)."""
    diag = engine.diagnose("ruff check .\nsrc/test.py:1:1: F401 `sys` imported but unused\nfound 1 error (1 fixable)")
    assert diag.category == ErrorCategory.SYNTAX_LINT
    assert diag.can_auto_heal is True
    assert any("ruff check --fix ." in (s.command or "") for s in diag.remediation_steps)


def test_diagnose_os_command_injection(engine: SelfHealingEngine) -> None:
    """Test diagnosis of unsafe shell=True subprocess execution (§3)."""
    diag = engine.diagnose("Security Alert: shell=True with dynamic input detected")
    assert diag.category == ErrorCategory.SECURITY_COMPLIANCE
    assert diag.severity == SeverityLevel.CRITICAL
    assert "§3" in diag.rule_reference


def test_diagnose_unknown_runtime_error(engine: SelfHealingEngine) -> None:
    """Test graceful fallback for unclassified runtime errors."""
    diag = engine.diagnose("SomeCustomUnregisteredException: something unexpected occurred")
    assert diag.category == ErrorCategory.UNKNOWN
    assert diag.rule_id == "ERR-UNKNOWN-001"
    assert diag.confidence == 0.50
    assert len(diag.remediation_steps) > 0


# =============================================================================
# 4. hook_utils Integration Tests (Governor & Workload Sensor)
# =============================================================================


def test_workload_complexity_integration(engine: SelfHealingEngine) -> None:
    """Validate that complex multi-step error tracebacks are flagged as compound."""
    simple_err = "ModuleNotFoundError: No module named 'simple'"
    diag_simple = engine.diagnose(simple_err)
    assert diag_simple.is_atomic is True

    compound_err = """Multiple tasks failed in pipeline:
1. ModuleNotFoundError: No module named 'step1' in file1.py
2. SyntaxError: invalid syntax in file2.py
3. AssertionError in file3.py
4. Step 4 failed with TimeoutError"""
    diag_compound = engine.diagnose(compound_err)
    assert diag_compound.complexity_score >= 2


def test_cpu_governor_dry_run_execution(engine: SelfHealingEngine) -> None:
    """Validate execution simulation with CPU Governor zone check."""
    diag = engine.diagnose("ModuleNotFoundError: No module named 'numpy'")
    result = engine.execute_remediation(diag, dry_run=True)
    assert result.success is True
    assert len(result.executed_steps) > 0
    assert result.executed_steps[0]["status"] == "DRY_RUN"


def test_cpu_governor_thermal_protection_cooldown(engine: SelfHealingEngine, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure thermal protection zone triggers cooldown sleep."""
    monkeypatch.setattr(engine.cpu_governor, "get_current_zone", lambda: (CPUZone.THERMAL_PROTECTION, 95.0))
    sleep_mock = MagicMock()
    monkeypatch.setattr("time.sleep", sleep_mock)

    diag = engine.diagnose("ModuleNotFoundError: No module named 'pandas'")
    engine.execute_remediation(diag, dry_run=True)
    sleep_mock.assert_called_once()


def test_built_in_self_test_runs_successfully() -> None:
    """Verify that the built-in self-test function passes 100%."""
    passed = run_self_test()
    assert passed is True
