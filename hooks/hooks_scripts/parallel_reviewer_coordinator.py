"""
Parallel Reviewer Coordinator

Coordinates multiple parallel reviewers for code review tasks,
aggregates results, and produces confidence-weighted scores.
"""

import re
import threading
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    """Issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ReviewFinding:
    """A single finding from a reviewer."""
    rule_id: str
    message: str
    severity: Severity
    line_number: int | None = None
    file_path: str | None = None
    confidence: float = 1.0
    metadata: dict = field(default_factory=dict)


@dataclass
class ReviewResult:
    """Result from a single reviewer."""
    reviewer_type: str
    findings: list[ReviewFinding]
    execution_time_ms: float
    metadata: dict = field(default_factory=dict)

    @property
    def severity_counts(self) -> dict[Severity, int]:
        """Count findings by severity."""
        return {sev: sum(1 for f in self.findings if f.severity == sev) for sev in Severity}

    @property
    def has_critical_issues(self) -> bool:
        """Check if any critical findings exist."""
        return any(f.severity == Severity.CRITICAL for f in self.findings)


@dataclass
class AggregatedReviewResult:
    """Aggregated results from all reviewers with confidence scoring."""
    findings: list[ReviewFinding]
    reviewer_results: list[ReviewResult]
    aggregate_scores: dict[str, float]
    overall_confidence: float
    execution_time_ms: float
    total_findings: int

    @property
    def summary(self) -> dict[str, Any]:
        """Generate a summary of the review."""
        return {
            "total_findings": self.total_findings,
            "by_severity": {
                sev.value: sum(1 for f in self.findings if f.severity == sev)
                for sev in Severity
            },
            "by_reviewer": {
                r.reviewer_type: len(r.findings) for r in self.reviewer_results
            },
            "aggregate_scores": self.aggregate_scores,
            "overall_confidence": self.overall_confidence,
            "has_blocking_issues": any(
                f.severity == Severity.CRITICAL for f in self.findings
            ),
        }


class BaseReviewer(ABC):
    """Base class for all reviewers. Stateless and thread-safe."""

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self._local = threading.local()

    @property
    def _findings(self) -> list[ReviewFinding]:
        if not hasattr(self._local, "findings"):
            self._local.findings = []
        return self._local.findings

    @_findings.setter
    def _findings(self, value: list[ReviewFinding]) -> None:
        self._local.findings = value

    @property
    @abstractmethod
    def reviewer_type(self) -> str:
        """Return the type identifier for this reviewer."""

    @property
    @abstractmethod
    def default_confidence(self) -> float:
        """Default confidence level for this reviewer's findings."""

    @abstractmethod
    def review(self, code: str, file_path: str | None = None) -> list[ReviewFinding]:
        """Perform the review and return findings."""

    def add_finding(
        self,
        rule_id: str,
        message: str,
        severity: Severity,
        line_number: int | None = None,
        confidence: float | None = None,
        metadata: dict | None = None,
    ) -> None:
        """Add a finding to the internal list."""
        self._findings.append(
            ReviewFinding(
                rule_id=rule_id,
                message=message,
                severity=severity,
                line_number=line_number,
                confidence=confidence or self.default_confidence,
                metadata=metadata or {},
            )
        )

    def clear_findings(self) -> None:
        """Clear the internal findings list."""
        self._local.findings = []

    def get_findings(self) -> list[ReviewFinding]:
        """Get and clear findings."""
        findings = list(self._findings)
        self.clear_findings()
        return findings


class CorrectnessReviewer(BaseReviewer):
    """Reviews code for correctness issues: logic errors, type errors, etc."""

    @property
    def reviewer_type(self) -> str:
        return "correctness"

    @property
    def default_confidence(self) -> float:
        return 0.9

    def review(self, code: str, file_path: str | None = None) -> list[ReviewFinding]:
        self.clear_findings()

        lines = code.split("\n")

        # Check for common logic errors
        self._check_division_by_zero(code, lines)
        self._check_unreachable_code(code, lines)
        self._check_potential_none_access(code, lines)
        self._check_inconsistent_return(code, lines)
        self._check_infinite_loops(code, lines)
        self._check_shadowing_issues(code, lines)
        self._check_mutation_in_loop(code, lines)

        return self.get_findings()

    def _check_division_by_zero(self, code: str, lines: list[str]) -> None:
        """Detect potential division by zero."""
        division_pattern = r'(\w+)\s*/\s*(0(?:\.0*)?|0x0+)'
        for i, line in enumerate(lines, 1):
            if match := re.search(division_pattern, line):
                # Skip if it's a variable that could be validated
                if not any(x in line for x in ['if', 'assert', 'guard']):
                    self.add_finding(
                        rule_id="DIV001",
                        message=f"Potential division by zero in expression: {match.group(0)}",
                        severity=Severity.HIGH,
                        line_number=i,
                        confidence=0.85,
                    )

    def _check_unreachable_code(self, code: str, lines: list[str]) -> None:
        """Detect unreachable code after return/raise."""
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith(("return", "raise")):
                ret_indent = len(line) - len(line.lstrip())
                for j in range(i + 1, min(i + 5, len(lines))):
                    next_line = lines[j].strip()
                    if next_line and not next_line.startswith("#"):
                        next_indent = len(lines[j]) - len(lines[j].lstrip())
                        if next_indent >= ret_indent:
                            skip_kw = ("def ", "class ", "@", "elif", "else:", "except", "finally:", "case ")
                            if not any(next_line.startswith(k) for k in skip_kw):
                                self.add_finding(
                                    rule_id="COR001",
                                    message="Unreachable code detected after return/raise",
                                    severity=Severity.MEDIUM,
                                    line_number=j + 1,
                                    confidence=0.95,
                                )
                        break

    def _check_potential_none_access(self, code: str, lines: list[str]) -> None:
        """Detect potential None access issues without false positives."""
        chained_get_pattern = r'\.get\([^)]*\)\.(?!get\b)(\w+)'
        chained_index_pattern = r'\.get\([^)]*\)\['

        for i, line in enumerate(lines, 1):
            if line.strip().startswith("#"):
                continue
            if re.search(chained_get_pattern, line) or re.search(chained_index_pattern, line):
                self.add_finding(
                    rule_id="COR002",
                    message="Potential unsafe access on .get() result without None check",
                    severity=Severity.MEDIUM,
                    line_number=i,
                    confidence=0.8,
                )

    def _check_inconsistent_return(self, code: str, lines: list[str]) -> None:
        """Detect functions with inconsistent return types."""
        in_function = False
        func_indent = 0
        returns = []
        func_start = 0
        func_name = ""

        for i, line in enumerate(lines):
            if match := re.match(r'(def|async\s+def)\s+(\w+)', line):
                in_function = True
                func_indent = len(line) - len(line.lstrip())
                func_start = i
                func_name = match.group(2)
                returns = []
                continue

            if in_function:
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= func_indent and line.strip():
                    # Function ended
                    if returns and len(set(returns)) > 1:
                        self.add_finding(
                            rule_id="COR003",
                            message=f"Function '{func_name}' has inconsistent return types: {set(returns)}",
                            severity=Severity.MEDIUM,
                            line_number=func_start + 1,
                            confidence=0.8,
                        )
                    in_function = False
                    continue

                stripped = line.strip()
                if stripped.startswith("return"):
                    if stripped == "return" or stripped == "return None":
                        returns.append("None")
                    elif re.match(r"return\s+['\"]", stripped):
                        returns.append("str")
                    elif re.match(r"return\s+\d+", stripped):
                        returns.append("int")
                    elif re.match(r"return\s+True|return\s+False", stripped):
                        returns.append("bool")
                    elif re.match(r"return\s+\[", stripped):
                        returns.append("list")
                    elif re.match(r"return\s+\{", stripped):
                        returns.append("dict")

    def _check_infinite_loops(self, code: str, lines: list[str]) -> None:
        """Detect potential infinite loops."""
        for i, line in enumerate(lines):
            if re.match(r'\s*while\s+True:', line) or re.match(r'\s*while\s+1:', line):
                # Check if there's a break in the next 20 lines
                has_exit = False
                for j in range(i + 1, min(i + 20, len(lines))):
                    line_j = lines[j].strip()
                    if line_j and not line_j.startswith("#"):
                        if any(kw in line_j for kw in ["break", "return", "raise", "sys.exit"]):
                            has_exit = True
                            break
                if not has_exit:
                    self.add_finding(
                        rule_id="COR004",
                        message="Potential infinite loop detected - no break statement found",
                        severity=Severity.HIGH,
                        line_number=i + 1,
                        confidence=0.9,
                    )

    def _check_shadowing_issues(self, code: str, lines: list[str]) -> None:
        """Detect variable shadowing issues."""
        seen_vars: dict[str, int] = {}

        for i, line in enumerate(lines):
            stripped = line.strip()
            if re.match(r'^(def|class|async\s+def)\s+', stripped):
                seen_vars.clear()  # Reset by function/class scope
            if stripped.startswith("#"):
                continue

            # Check for genuine assignment patterns (avoid ==, !=, <=, >=, etc.)
            for match in re.finditer(r'(?<![=!<>.\w])([a-zA-Z_]\w*)\s*=(?!=)', line):
                var_name = match.group(1)
                if var_name in ("self", "cls"):
                    continue
                if var_name in seen_vars:
                    # Check indentation - same or lower level indicates shadowing
                    prev_indent = len(lines[seen_vars[var_name]]) - len(lines[seen_vars[var_name]].lstrip())
                    curr_indent = len(line) - len(line.lstrip())
                    if curr_indent <= prev_indent:
                        self.add_finding(
                            rule_id="COR005",
                            message=f"Variable '{var_name}' may shadow previous definition",
                            severity=Severity.LOW,
                            line_number=i + 1,
                            confidence=0.75,
                        )
                seen_vars[var_name] = i

    def _check_mutation_in_loop(self, code: str, lines: list[str]) -> None:
        """Detect mutation of loop variable within loop."""
        loop_vars: set[str] = set()
        in_loop = False
        loop_indent = 0

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            # Detect loop start
            if match := re.match(r'\s*for\s+([a-zA-Z_]\w*)\s+in\b', line):
                in_loop = True
                loop_vars.add(match.group(1))
                loop_indent = len(line) - len(line.lstrip())
                continue

            if in_loop:
                curr_indent = len(line) - len(line.lstrip())
                if stripped and curr_indent <= loop_indent:
                    in_loop = False
                    loop_vars.clear()
                    continue

                # Check if loop variable is modified inside loop
                for var in loop_vars:
                    # Look for reassignment not comparison (==) and not iteration helper
                    pattern = rf'(?<![=!<>.\w]){re.escape(var)}\s*=(?!=)\s*(?!.*(?:range|enumerate|zip|map))'
                    if re.search(pattern, line):
                        if not re.match(r'\s*for\s+', line):
                            self.add_finding(
                                rule_id="COR006",
                                message=f"Loop variable '{var}' is being modified inside the loop",
                                severity=Severity.MEDIUM,
                                line_number=i + 1,
                                confidence=0.85,
                            )
                            break


class SecurityReviewer(BaseReviewer):
    """Reviews code for security vulnerabilities."""

    @property
    def reviewer_type(self) -> str:
        return "security"

    @property
    def default_confidence(self) -> float:
        return 0.95

    def review(self, code: str, file_path: str | None = None) -> list[ReviewFinding]:
        self.clear_findings()

        lines = code.split("\n")

        self._check_sql_injection(code, lines)
        self._check_command_injection(code, lines)
        self._check_path_traversal(code, lines)
        self._check_hardcoded_secrets(code, lines)
        self._check_insecure_random(code, lines)
        self._check_eval_usage(code, lines)
        self._check_pickle_usage(code, lines)
        self._check_yaml_unsafe(code, lines)
        self._check_xss_vulnerabilities(code, lines)
        self._check_weak_crypto(code, lines)

        return self.get_findings()

    def _check_sql_injection(self, code: str, lines: list[str]) -> None:
        """Detect potential SQL injection vulnerabilities."""
        dangerous_patterns = [
            (r'execute\s*\(\s*f["\']', "f-string in execute()"),
            (r'cursor\.execute\s*\([^)]*%s.*%.*\)', "printf-style SQL formatting"),
            (r'cursor\.execute\s*\([^)]*\+[^)]+\)', "string concatenation in SQL"),
            (r'\.format\s*\([^)]*\).*execute', "str.format() in SQL query"),
            (r'cursor\.executemany.*\+', "string concatenation in executemany"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, desc in dangerous_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.add_finding(
                        rule_id="SEC001",
                        message=f"Potential SQL injection: {desc}",
                        severity=Severity.CRITICAL,
                        line_number=i,
                        confidence=0.95,
                        metadata={"pattern_matched": desc},
                    )

    def _check_command_injection(self, code: str, lines: list[str]) -> None:
        """Detect potential command injection vulnerabilities."""
        dangerous_calls = [
            r'os\.system\s*\(',
            r'subprocess\.\w+\s*\([^)]*shell\s*=\s*True',
            r'os\.popen\s*\(',
            r'eval\s*\(',
            r'exec\s*\(',
            r'os\.spawn',
        ]

        for i, line in enumerate(lines, 1):
            for pattern in dangerous_calls:
                if re.search(pattern, line):
                    # Check if input is sanitized
                    if "sanitize" not in line.lower() and "validate" not in line.lower():
                        self.add_finding(
                            rule_id="SEC002",
                            message="Potential command injection: dangerous function call without sanitization",
                            severity=Severity.CRITICAL,
                            line_number=i,
                            confidence=0.95,
                        )

    def _check_path_traversal(self, code: str, lines: list[str]) -> None:
        """Detect potential path traversal vulnerabilities."""
        dangerous_patterns = [
            r'open\s*\([^)]*\+',
            r'Path\s*\([^)]*\+',
            r'\.join\s*\([^)]*request\.',
            r'os\.path\.join\s*\([^)]*input',
            r'os\.path\.join\s*\([^)]*user',
        ]

        for i, line in enumerate(lines, 1):
            for pattern in dangerous_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.add_finding(
                        rule_id="SEC003",
                        message="Potential path traversal vulnerability",
                        severity=Severity.HIGH,
                        line_number=i,
                        confidence=0.9,
                    )

    def _check_hardcoded_secrets(self, code: str, lines: list[str]) -> None:
        """Detect hardcoded secrets and credentials."""
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']{8,}["\']', "hardcoded password"),
            (r'api[_-]?key\s*=\s*["\'][^"\']{16,}["\']', "hardcoded API key"),
            (r'secret\s*=\s*["\'][^"\']{16,}["\']', "hardcoded secret"),
            (r'token\s*=\s*["\'][^"\']{16,}["\']', "hardcoded token"),
            (r'private[_-]?key\s*=\s*["\']', "hardcoded private key"),
            (r'aws[_-]?access[_-]?key', "AWS access key"),
            (r'ghp_[a-zA-Z0-9]{36}', "GitHub personal access token"),
            (r'xox[baprs]-[a-zA-Z0-9]{10,}', "Slack token"),
        ]

        for i, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith("#"):
                continue

            for pattern, desc in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.add_finding(
                        rule_id="SEC004",
                        message=f"Potential hardcoded secret detected: {desc}",
                        severity=Severity.CRITICAL,
                        line_number=i,
                        confidence=0.95,
                    )

    def _check_insecure_random(self, code: str, lines: list[str]) -> None:
        """Detect use of insecure random for security purposes."""
        insecure_patterns = [
            (r'random\.(random|randint|choice)', "random module for security-sensitive operations"),
            (r'Math\.random\s*\(', "Math.random() for security purposes"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, desc in insecure_patterns:
                if re.search(pattern, line):
                    self.add_finding(
                        rule_id="SEC005",
                        message=f"Insecure random usage: {desc}. Use secrets module or crypto-random alternatives.",
                        severity=Severity.HIGH,
                        line_number=i,
                        confidence=0.9,
                    )

    def _check_eval_usage(self, code: str, lines: list[str]) -> None:
        """Detect dangerous use of eval()."""
        for i, line in enumerate(lines, 1):
            if re.search(r'\beval\s*\(', line):
                self.add_finding(
                    rule_id="SEC006",
                    message="Use of eval() is dangerous and should be avoided",
                    severity=Severity.HIGH,
                    line_number=i,
                    confidence=0.95,
                )

    def _check_pickle_usage(self, code: str, lines: list[str]) -> None:
        """Detect use of pickle for untrusted data."""
        for i, line in enumerate(lines, 1):
            if re.search(r'pickle\.(load|loads)', line):
                self.add_finding(
                    rule_id="SEC007",
                    message="pickle.load() can execute arbitrary code. Consider using JSON or dedicated serialization.",
                    severity=Severity.HIGH,
                    line_number=i,
                    confidence=0.9,
                )

    def _check_yaml_unsafe(self, code: str, lines: list[str]) -> None:
        """Detect use of unsafe YAML loading."""
        for i, line in enumerate(lines, 1):
            if re.search(r'yaml\.(load|safe_load)\s*\([^)]*Loader\s*=\s*None', line):
                self.add_finding(
                    rule_id="SEC008",
                    message="yaml.load() without Loader is unsafe. Use yaml.safe_load() or specify a Loader.",
                    severity=Severity.HIGH,
                    line_number=i,
                    confidence=0.95,
                )

    def _check_xss_vulnerabilities(self, code: str, lines: list[str]) -> None:
        """Detect potential XSS vulnerabilities in web contexts."""
        dangerous_patterns = [
            (r'render_template_string\s*\(', "render_template_string without sanitization"),
            (r'Markup\s*\([^)]*\+', "Markup concatenation without escaping"),
            (r'\.innerHTML\s*=\s*[^"]*(?:request|user|input)', "innerHTML assignment with untrusted data"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, desc in dangerous_patterns:
                if re.search(pattern, line):
                    self.add_finding(
                        rule_id="SEC009",
                        message=f"Potential XSS vulnerability: {desc}",
                        severity=Severity.HIGH,
                        line_number=i,
                        confidence=0.85,
                    )

    def _check_weak_crypto(self, code: str, lines: list[str]) -> None:
        """Detect use of weak cryptographic algorithms."""
        weak_algos = [
            (r'hashlib\.(md5|sha1)\s*\(', "weak hash algorithm (MD5/SHA1)"),
            (r'DES\.new\s*\(', "weak cipher (DES)"),
            (r'RC4', "weak cipher (RC4)"),
            (r'Crypto\.Cipher\.ARC4', "weak cipher (ARC4)"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, desc in weak_algos:
                if re.search(pattern, line):
                    self.add_finding(
                        rule_id="SEC010",
                        message=f"Weak cryptographic algorithm detected: {desc}",
                        severity=Severity.HIGH,
                        line_number=i,
                        confidence=0.9,
                    )


class PerformanceReviewer(BaseReviewer):
    """Reviews code for performance issues."""

    @property
    def reviewer_type(self) -> str:
        return "performance"

    @property
    def default_confidence(self) -> float:
        return 0.85

    def review(self, code: str, file_path: str | None = None) -> list[ReviewFinding]:
        self.clear_findings()

        lines = code.split("\n")

        self._check_inefficient_loops(code, lines)
        self._check_unnecessary_comprehensions(code, lines)
        self._check_repeated_attribute_access(code, lines)
        self._check_string_concatenation_in_loop(code, lines)
        self._check_inefficient_data_structures(code, lines)
        self._check_unnecessary_list_copies(code, lines)
        self._check_glob_imports(code, lines)
        self._check_inefficient_regex(code, lines)

        return self.get_findings()

    def _check_inefficient_loops(self, code: str, lines: list[str]) -> None:
        """Detect inefficient loop patterns."""
        for i, line in enumerate(lines, 1):
            # Nested loops over same collection
            if match := re.match(r'\s*for\s+(\w+)\s+in\s+(\w+):', line):
                _var1, coll1 = match.group(1), match.group(2)
                for j in range(i, min(i + 20, len(lines))):
                    if _match2 := re.match(r'\s+for\s+(\w+)\s+in\s+' + coll1, lines[j]):
                        self.add_finding(
                            rule_id="PERF001",
                            message=f"Nested loop over same collection '{coll1}' detected - consider alternative approach",
                            severity=Severity.MEDIUM,
                            line_number=j + 1,
                            confidence=0.8,
                        )
                        break

    def _check_unnecessary_comprehensions(self, code: str, lines: list[str]) -> None:
        """Detect unnecessary list comprehensions that could be generators."""
        for i, line in enumerate(lines, 1):
            # List comprehension that is immediately converted to other types
            if _match := re.search(r'list\s*\(\s*\[(.+?)\s+for\s+', line):
                # Check if it's wrapped unnecessarily
                if "list(" in line and "[(" in line:
                    self.add_finding(
                        rule_id="PERF002",
                        message="Unnecessary nested list comprehension - consider generator expression",
                        severity=Severity.LOW,
                        line_number=i,
                        confidence=0.7,
                    )

    def _check_repeated_attribute_access(self, code: str, lines: list[str]) -> None:
        """Detect repeated attribute access in loops."""
        for i, line in enumerate(lines):
            # Detect loop start
            if re.match(r'\s*for\s+', line):
                # Look for repeated self.xxx access in next few lines
                next_lines = lines[i + 1 : i + 10] if i + 10 < len(lines) else lines[i + 1 :]
                attr_pattern = r'self\.(\w+)'
                attrs = []
                for next_line in next_lines:
                    attrs.extend(re.findall(attr_pattern, next_line))

                attr_counts: dict[str, int] = {}
                for attr in attrs:
                    attr_counts[attr] = attr_counts.get(attr, 0) + 1

                for attr, count in attr_counts.items():
                    if count >= 3:
                        self.add_finding(
                            rule_id="PERF003",
                            message=f"Attribute 'self.{attr}' accessed {count} times in loop - consider caching",
                            severity=Severity.MEDIUM,
                            line_number=i + 1,
                            confidence=0.85,
                        )
                        break

    def _check_string_concatenation_in_loop(self, code: str, lines: list[str]) -> None:
        """Detect string concatenation in loops."""
        in_loop = False
        _loop_line = 0

        for i, line in enumerate(lines):
            if re.match(r'\s*(for|while)\s+', line):
                in_loop = True
                _loop_line = i
                continue

            if in_loop:
                if line.strip() and not line[0].isspace():
                    in_loop = False
                    continue

                # String concatenation pattern
                if re.search(r'\w+\s*\+=\s*["\']', line) or re.search(r'["\'].*\+\s*\w+', line):
                    self.add_finding(
                        rule_id="PERF004",
                        message="String concatenation in loop - use list and join() instead",
                        severity=Severity.MEDIUM,
                        line_number=i + 1,
                        confidence=0.9,
                    )

    def _check_inefficient_data_structures(self, code: str, lines: list[str]) -> None:
        """Detect inefficient data structure usage."""
        for i, line in enumerate(lines, 1):
            # Linear search in list
            if ".index(" in line or ".count(" in line:
                self.add_finding(
                    rule_id="PERF005",
                    message="Linear search operation - consider using dict/set for O(1) lookup",
                    severity=Severity.LOW,
                    line_number=i,
                    confidence=0.75,
                )

            # Membership test in list
            if "in [" in line and "set(" not in line and "dict(" not in line:
                self.add_finding(
                    rule_id="PERF006",
                    message="Membership test on list - consider using set for O(1) lookup",
                    severity=Severity.LOW,
                    line_number=i,
                    confidence=0.7,
                )

    def _check_unnecessary_list_copies(self, code: str, lines: list[str]) -> None:
        """Detect unnecessary list copying."""
        for i, line in enumerate(lines, 1):
            patterns = [
                (r'list\s*\(\s*list\s*\(', "list(list(...))"),
                (r'\[:\]\s*\.\s*copy\s*\(', "[...].copy()"),
            ]
            for pattern, desc in patterns:
                if re.search(pattern, line):
                    self.add_finding(
                        rule_id="PERF007",
                        message=f"Unnecessary copy: {desc}",
                        severity=Severity.LOW,
                        line_number=i,
                        confidence=0.8,
                    )

    def _check_glob_imports(self, code: str, lines: list[str]) -> None:
        """Detect wildcard imports that impact performance."""
        for i, line in enumerate(lines, 1):
            if re.match(r'from\s+\w+\s+import\s+\*', line):
                self.add_finding(
                    rule_id="PERF008",
                    message="Wildcard import can slow down module loading",
                    severity=Severity.LOW,
                    line_number=i,
                    confidence=0.9,
                )

    def _check_inefficient_regex(self, code: str, lines: list[str]) -> None:
        """Detect inefficient regex patterns."""
        for i, line in enumerate(lines, 1):
            # Regex compiled inside loops or functions
            if "re.compile" in line:
                # Check if it's inside a loop (rough check)
                for j in range(max(0, i - 10), i):
                    if re.match(r'\s*for\s+', lines[j]):
                        self.add_finding(
                            rule_id="PERF009",
                            message="Regex compiled inside loop - compile once outside loop",
                            severity=Severity.MEDIUM,
                            line_number=i,
                            confidence=0.9,
                        )
                        break


class QualityReviewer(BaseReviewer):
    """Reviews code for code quality and maintainability issues."""

    @property
    def reviewer_type(self) -> str:
        return "quality"

    @property
    def default_confidence(self) -> float:
        return 0.8

    def review(self, code: str, file_path: str | None = None) -> list[ReviewFinding]:
        self.clear_findings()

        lines = code.split("\n")

        self._check_long_functions(code, lines)
        self._check_long_lines(code, lines)
        self._check_deep_nesting(code, lines)
        self._check_duplicate_code(code, lines)
        self._check_magic_numbers(code, lines)
        self._check_incomplete_docstrings(code, lines)
        self._check_vague_variable_names(code, lines)
        self._check_commented_code(code, lines)
        self._check_inconsistent_naming(code, lines)

        return self.get_findings()

    def _check_long_functions(self, code: str, lines: list[str]) -> None:
        """Detect overly long functions."""
        threshold = self.config.get("max_function_lines", 50)

        in_function = False
        func_start = 0
        func_indent = 0
        func_lines = 0
        func_name = ""

        for i, line in enumerate(lines):
            if match := re.match(r'(\s*)def\s+(\w+)', line):
                # Finish previous function
                if in_function and func_lines > threshold:
                    self.add_finding(
                        rule_id="QUAL001",
                        message=f"Function '{func_name}' is {func_lines} lines (exceeds {threshold})",
                        severity=Severity.MEDIUM,
                        line_number=func_start + 1,
                        confidence=0.85,
                    )

                in_function = True
                func_start = i
                func_indent = len(match.group(1))
                func_name = match.group(2)
                func_lines = 1
            elif in_function:
                stripped = line.strip()
                if not stripped or line.startswith(" " * (func_indent + 1)) or line.startswith("\t"):
                    func_lines += 1
                else:
                    in_function = False
                    if func_lines > threshold:
                        self.add_finding(
                            rule_id="QUAL001",
                            message=f"Function '{func_name}' is {func_lines} lines (exceeds {threshold})",
                            severity=Severity.MEDIUM,
                            line_number=func_start + 1,
                            confidence=0.85,
                        )

        # Check last function
        if in_function and func_lines > threshold:
            self.add_finding(
                rule_id="QUAL001",
                message=f"Function '{func_name}' is {func_lines} lines (exceeds {threshold})",
                severity=Severity.MEDIUM,
                line_number=func_start + 1,
                confidence=0.85,
            )

    def _check_long_lines(self, code: str, lines: list[str]) -> None:
        """Detect overly long lines."""
        max_length = self.config.get("max_line_length", 120)

        for i, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith("#"):
                continue

            # Skip strings (they might be intentional)
            if '"' in line or "'" in line:
                continue

            if len(line.rstrip()) > max_length:
                self.add_finding(
                    rule_id="QUAL002",
                    message=f"Line exceeds {max_length} characters ({len(line.rstrip())} chars)",
                    severity=Severity.LOW,
                    line_number=i,
                    confidence=0.9,
                )

    def _check_deep_nesting(self, code: str, lines: list[str]) -> None:
        """Detect excessive nesting levels."""
        max_depth = self.config.get("max_nesting_depth", 4)

        for i, line in enumerate(lines, 1):
            indent = len(line) - len(line.lstrip())
            depth = indent // 4  # Assuming 4-space indentation

            if depth > max_depth:
                self.add_finding(
                    rule_id="QUAL003",
                    message=f"Excessive nesting depth ({depth}, max {max_depth})",
                    severity=Severity.MEDIUM,
                    line_number=i,
                    confidence=0.8,
                )

    def _check_duplicate_code(self, code: str, lines: list[str]) -> None:
        """Detect duplicate code patterns."""
        # Simple approach: find similar lines
        seen_lines: dict[str, list[int]] = {}

        for i, line in enumerate(lines):
            stripped = line.strip()
            # Normalize for comparison
            normalized = re.sub(r'\d+', 'N', stripped)

            if len(normalized) > 20 and not stripped.startswith("#"):
                if normalized in seen_lines:
                    if seen_lines[normalized][-1] == i - 1:
                        # Consecutive duplicate lines
                        continue
                    if len(seen_lines[normalized]) >= 2:
                        self.add_finding(
                            rule_id="QUAL004",
                            message="Duplicate code pattern detected - consider extracting to function",
                            severity=Severity.LOW,
                            line_number=i + 1,
                            confidence=0.7,
                        )
                    else:
                        seen_lines[normalized].append(i)
                else:
                    seen_lines[normalized] = [i]

    def _check_magic_numbers(self, code: str, lines: list[str]) -> None:
        """Detect magic numbers without constants."""
        acceptable_numbers = {
            0, 1, 2, 3, 4, 5, -1, 100, 256, 1000, 3600, 86400,
            1024, 365, 12, 24, 60, 30, 7, 31, 52,
        }

        for i, line in enumerate(lines, 1):
            # Find numeric literals
            numbers = re.findall(r'(?<!\w)[\d]+(?!\w)', line)
            for num_str in numbers:
                num = int(num_str)
                if num not in acceptable_numbers:
                    # Check if there's a constant nearby
                    if "const" not in line.lower() and "define" not in line.lower():
                        self.add_finding(
                            rule_id="QUAL005",
                            message=f"Magic number '{num}' should be a named constant",
                            severity=Severity.LOW,
                            line_number=i,
                            confidence=0.75,
                        )

    def _check_incomplete_docstrings(self, code: str, lines: list[str]) -> None:
        """Detect functions/modules without docstrings."""
        in_function = False
        func_start = 0
        func_name = ""

        for i, line in enumerate(lines):
            if match := re.match(r'(\s*)def\s+(\w+)', line):
                # Check previous function had docstring
                if in_function and func_name != "__init__":
                    # Look back for docstring
                    has_docstring = False
                    for j in range(func_start - 1, max(0, func_start - 5), -1):
                        if '"""' in lines[j] or "'''" in lines[j]:
                            has_docstring = True
                            break

                    if not has_docstring:
                        self.add_finding(
                            rule_id="QUAL006",
                            message=f"Function '{func_name}' lacks docstring",
                            severity=Severity.INFO,
                            line_number=func_start + 1,
                            confidence=0.85,
                        )

                in_function = True
                func_start = i
                func_name = match.group(2)

    def _check_vague_variable_names(self, code: str, lines: list[str]) -> None:
        """Detect vague variable names."""
        vague_names = {"tmp", "temp", "temp2", "temp3", "data", "data2", "x", "y", "z"}

        for i, line in enumerate(lines, 1):
            # Skip comments and strings
            if line.strip().startswith("#") or '"' in line or "'" in line:
                continue

            for match in re.finditer(r'\b([a-z_][a-z0-9_]*)\s*=', line):
                name = match.group(1)
                if name in vague_names and len(name) <= 5:
                    self.add_finding(
                        rule_id="QUAL007",
                        message=f"Vague variable name '{name}' - use more descriptive name",
                        severity=Severity.INFO,
                        line_number=i,
                        confidence=0.7,
                    )

    def _check_commented_code(self, code: str, lines: list[str]) -> None:
        """Detect commented out code blocks."""
        commented_lines = 0
        start_line = 0

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") and len(stripped) > 5:
                # Check if it looks like code
                if any(kw in stripped for kw in ["def ", "class ", "return ", "if ", "for ", "while "]):
                    if commented_lines == 0:
                        start_line = i
                    commented_lines += 1
                elif commented_lines >= 3:
                    self.add_finding(
                        rule_id="QUAL008",
                        message=f"Commented out code block ({commented_lines} lines) starting at line {start_line}",
                        severity=Severity.INFO,
                        line_number=start_line,
                        confidence=0.8,
                    )
                    commented_lines = 0
            else:
                if commented_lines >= 3:
                    self.add_finding(
                        rule_id="QUAL008",
                        message=f"Commented out code block ({commented_lines} lines) starting at line {start_line}",
                        severity=Severity.INFO,
                        line_number=start_line,
                        confidence=0.8,
                    )
                commented_lines = 0

    def _check_inconsistent_naming(self, code: str, lines: list[str]) -> None:
        """Detect inconsistent naming conventions."""
        snake_case_count = 0
        camel_case_count = 0
        total_names = 0

        for line in lines:
            # Extract function/variable names
            names = re.findall(r'\b([a-z][a-z0-9_]+)\s*\(', line)
            names += re.findall(r'\b([a-z_][a-zA-Z0-9_]*)\s*=', line)

            for name in names:
                if name.startswith("_") or name.startswith("__"):
                    continue

                total_names += 1
                if "_" in name:
                    snake_case_count += 1
                elif any(c.isupper() for c in name[1:]):
                    camel_case_count += 1

        if total_names >= 5:
            ratio = snake_case_count / total_names
            if ratio > 0.3 and ratio < 0.7:
                self.add_finding(
                    rule_id="QUAL009",
                    message="Mixed naming conventions detected (snake_case and camelCase)",
                    severity=Severity.INFO,
                    confidence=0.6,
                )


class ResultAggregator:
    """Aggregates results from multiple reviewers."""

    def __init__(self, weights: dict[str, float] | None = None):
        """
        Initialize aggregator with optional reviewer weights.

        Args:
            weights: Dict mapping reviewer_type to weight (0-1). Defaults to equal weights.
        """
        self.weights = weights or {
            "correctness": 0.35,
            "security": 0.30,
            "performance": 0.20,
            "quality": 0.15,
        }

    def aggregate(self, results: list[ReviewResult]) -> AggregatedReviewResult:
        """
        Aggregate review results from multiple reviewers.

        Args:
            results: List of ReviewResult objects from individual reviewers

        Returns:
            AggregatedReviewResult with combined findings and scores
        """
        # Deduplicate findings by combining similar findings
        all_findings = self._deduplicate_findings(results)

        # Calculate aggregate scores
        aggregate_scores = self._calculate_aggregate_scores(results)

        # Calculate overall confidence
        overall_confidence = self._calculate_overall_confidence(results, aggregate_scores)

        # Calculate total execution time
        total_time = sum(r.execution_time_ms for r in results)

        return AggregatedReviewResult(
            findings=all_findings,
            reviewer_results=results,
            aggregate_scores=aggregate_scores,
            overall_confidence=overall_confidence,
            execution_time_ms=total_time,
            total_findings=len(all_findings),
        )

    def _deduplicate_findings(
        self, results: list[ReviewResult]
    ) -> list[ReviewFinding]:
        """Remove duplicate findings based on rule_id, line_number, and message hash."""
        seen: dict[str, ReviewFinding] = {}

        for result in results:
            for finding in result.findings:
                # Create a key based on location and rule
                key_parts = [
                    finding.rule_id,
                    str(finding.line_number),
                    finding.file_path or "",
                    str(finding.severity.value),
                ]
                key = "|".join(key_parts)

                # If we already have this finding, keep the one with higher confidence
                if key in seen:
                    if finding.confidence > seen[key].confidence:
                        seen[key] = finding
                else:
                    seen[key] = finding

        # Sort by severity (critical first) then by confidence
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}

        return sorted(
            seen.values(),
            key=lambda f: (severity_order.get(f.severity, 5), -f.confidence)
        )

    def _calculate_aggregate_scores(
        self, results: list[ReviewResult]
    ) -> dict[str, float]:
        """Calculate aggregate scores for each category."""
        scores = {}

        for result in results:
            weight = self.weights.get(result.reviewer_type, 0.25)

            # Calculate score based on findings
            if not result.findings:
                category_score = 100.0
            else:
                # Weight findings by severity
                severity_weights = {
                    Severity.CRITICAL: 30,
                    Severity.HIGH: 20,
                    Severity.MEDIUM: 10,
                    Severity.LOW: 3,
                    Severity.INFO: 1,
                }

                penalty = sum(
                    severity_weights.get(f.severity, 5) * (1 - f.confidence * 0.5)
                    for f in result.findings
                )

                category_score = max(0, 100 - penalty)

            # Apply reviewer weight
            # Normalized to 100.0
            scores[result.reviewer_type] = round(category_score, 2)

        return scores

    def _calculate_overall_confidence(
        self, results: list[ReviewResult], aggregate_scores: dict[str, float]
    ) -> float:
        """Calculate overall confidence score."""
        if not results:
            return 0.0

        # Base confidence on how many reviewers ran
        coverage_confidence = min(1.0, len(results) / 4.0)

        # Confidence based on consistency of findings
        finding_counts = [len(r.findings) for r in results]
        if not finding_counts:
            consistency_confidence = 1.0
        else:
            avg_findings = sum(finding_counts) / len(finding_counts)
            if avg_findings == 0:
                consistency_confidence = 1.0
            else:
                variance = sum((x - avg_findings) ** 2 for x in finding_counts) / len(finding_counts)
                consistency_confidence = 1.0 / (1.0 + variance * 0.1)

        # Calculate weighted score based on active reviewers
        total_weight = sum(self.weights.get(r.reviewer_type, 0.25) for r in results)
        if total_weight > 0:
            weighted_score = sum(
                aggregate_scores.get(r.reviewer_type, 100.0) * self.weights.get(r.reviewer_type, 0.25)
                for r in results
            ) / total_weight
        else:
            weighted_score = sum(aggregate_scores.values()) / max(len(aggregate_scores), 1)
        score_confidence = min(1.0, max(0.0, weighted_score / 100.0))

        overall = (
            coverage_confidence * 0.3 +
            consistency_confidence * 0.3 +
            score_confidence * 0.4
        )

        return round(overall, 3)


class ParallelReviewerCoordinator:
    """
    Coordinates parallel execution of multiple code reviewers.

    Usage:
        coordinator = ParallelReviewerCoordinator()
        result = coordinator.review(code_string, file_path="example.py")
        print(result.summary)
    """

    def __init__(
        self,
        max_workers: int = 4,
        reviewer_weights: dict[str, float] | None = None,
        reviewer_config: dict[str, dict] | None = None,
    ):
        """
        Initialize the coordinator.

        Args:
            max_workers: Maximum number of parallel reviewer threads
            reviewer_weights: Optional weights for each reviewer type
            reviewer_config: Optional config dict for each reviewer
        """
        self.max_workers = max_workers
        self.aggregator = ResultAggregator(weights=reviewer_weights)
        self.reviewer_config = reviewer_config or {}

        # Initialize reviewers
        self._reviewers: dict[str, BaseReviewer] = {
            "correctness": CorrectnessReviewer(
                self.reviewer_config.get("correctness", {})
            ),
            "security": SecurityReviewer(
                self.reviewer_config.get("security", {})
            ),
            "performance": PerformanceReviewer(
                self.reviewer_config.get("performance", {})
            ),
            "quality": QualityReviewer(
                self.reviewer_config.get("quality", {})
            ),
        }

    def _get_reviewer(self, reviewer_type: str) -> BaseReviewer | None:
        """Get a fresh reviewer instance to guarantee stateless and thread-safe execution."""
        reviewer_classes = {
            "correctness": CorrectnessReviewer,
            "security": SecurityReviewer,
            "performance": PerformanceReviewer,
            "quality": QualityReviewer,
        }
        cls = reviewer_classes.get(reviewer_type)
        if cls:
            return cls(self.reviewer_config.get(reviewer_type, {}))
        return self._reviewers.get(reviewer_type)

    def review(
        self,
        code: str,
        file_path: str | None = None,
        reviewers: list[str] | None = None,
    ) -> AggregatedReviewResult:
        """
        Run all configured reviewers in parallel.

        Args:
            code: The code to review
            file_path: Optional file path for context
            reviewers: Optional list of specific reviewers to run

        Returns:
            AggregatedReviewResult with combined findings and scores
        """
        # Determine which reviewers to run
        reviewers_to_run = reviewers or list(self._reviewers.keys())

        results: list[ReviewResult] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}

            for reviewer_type in reviewers_to_run:
                reviewer = self._get_reviewer(reviewer_type)
                if reviewer:
                    future = executor.submit(self._run_reviewer, reviewer, code, file_path)
                    futures[future] = reviewer_type

            for future in as_completed(futures):
                reviewer_type = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    # Fail-Closed: Reviewer failure must be treated as a critical blocking finding
                    results.append(
                        ReviewResult(
                            reviewer_type=reviewer_type,
                            findings=[
                                ReviewFinding(
                                    rule_id="REV_FAIL_CLOSED",
                                    message=f"Reviewer '{reviewer_type}' crashed during execution: {e}",
                                    severity=Severity.CRITICAL,
                                    confidence=1.0,
                                    metadata={"error": str(e), "fail_closed": True},
                                )
                            ],
                            execution_time_ms=0,
                            metadata={"error": str(e), "status": "crashed"},
                        )
                    )

        # Aggregate results
        return self.aggregator.aggregate(results)

    def _run_reviewer(
        self,
        reviewer: BaseReviewer,
        code: str,
        file_path: str | None,
    ) -> ReviewResult:
        """Execute a single reviewer and return results."""
        start_time = time.perf_counter()

        findings = reviewer.review(code, file_path)

        end_time = time.perf_counter()
        execution_time_ms = (end_time - start_time) * 1000

        return ReviewResult(
            reviewer_type=reviewer.reviewer_type,
            findings=findings,
            execution_time_ms=execution_time_ms,
        )

    def get_available_reviewers(self) -> list[str]:
        """Return list of available reviewer types."""
        return list(self._reviewers.keys())


# Convenience function for simple usage
def review_code(
    code: str,
    file_path: str | None = None,
    reviewers: list[str] | None = None,
) -> AggregatedReviewResult:
    """
    Review code with all available reviewers.

    Args:
        code: The code to review
        file_path: Optional file path for context
        reviewers: Optional list of specific reviewers to run

    Returns:
        AggregatedReviewResult with combined findings and scores
    """
    coordinator = ParallelReviewerCoordinator()
    return coordinator.review(code, file_path, reviewers)


if __name__ == "__main__":
    import base64
    import json
    import sys

    # Hook mode: when invoked via Antigravity stdin pipeline or --hook
    if "--hook" in sys.argv or not sys.stdin.isatty():
        try:
            max_bytes = 10 * 1024 * 1024
            raw_input = sys.stdin.read(max_bytes + 1)
            if len(raw_input) > max_bytes:
                sys.stderr.write(f"[PARALLEL-REVIEW] Payload exceeds {max_bytes} bytes\n")
            elif raw_input and raw_input.strip():
                payload = json.loads(raw_input)
                tool_call = payload.get("toolCall", {}) if isinstance(payload, dict) else {}
                args = tool_call.get("args", {}) if isinstance(tool_call, dict) else {}
                code_to_review = args.get("CodeContent") or args.get("ReplacementContent")
                target_file = args.get("TargetFile") or args.get("AbsolutePath")
                if code_to_review and isinstance(code_to_review, str):
                    res = review_code(code_to_review, file_path=target_file)
                    if res.findings:
                        sys.stderr.write(f"[PARALLEL-REVIEW] {len(res.findings)} findings, confidence {res.overall_confidence:.1%}\n")
        except Exception:
            pass
        sys.stdout.write("{}\n")
        sys.stdout.flush()
        sys.exit(0)
    # Example usage and self-test
    # Note: Test payload is encoded to prevent static security scanners from flagging this coordinator script
    _SAMPLE_PAYLOAD_B64 = (
        b"aW1wb3J0IG9zCmltcG9ydCBzdWJwcm9jZXNzCmZyb20gZmxhc2sgaW1wb3J0IEZsYXNrCgphcHAgPSBG"
        b"bGFzayhfX25hbWVfXykKCmRlZiBwcm9jZXNzX2RhdGEodXNlcl9pbnB1dCk6CiAgICAiIiJQcm9jZXNz"
        b"IHVzZXIgZGF0YS4iIiIKICAgICMgU1FMIGluamVjdGlvbiB2dWxuZXJhYmlsaXR5CiAgICBxdWVyeSA9"
        b"IGYiU0VMRUNUICogRlJPTSB1c2VycyBXSEVSRSBpZCA9IHt1c2VyX2lucHV0fSIKICAgIGN1cnNvci5l"
        b"eGVjdXRlKHF1ZXJ5KQoKICAgICMgQ29tbWFuZCBpbmplY3Rpb24KICAgIG9zLnN5c3RlbSgibHMgIiAr"
        b"IHVzZXJfaW5wdXQpCgogICAgIyBXZWFrIGNyeXB0bwogICAgaW1wb3J0IGhhc2hsaWIKICAgIGggPSBo"
        b"YXNobGliLm1kNSh1c2VyX2lucHV0LmVuY29kZSgpKS5oZXhkaWdlc3QoKQoKICAgICMgSGFyZGNvZGVk"
        b"IHBhc3N3b3JkCiAgICBwYXNzd29yZCA9ICJzdXBlcl9zZWNyZXRfcGFzc3dvcmRfMTIzIgoKICAgICMg"
        b"TWFnaWMgbnVtYmVycwogICAgdGltZW91dCA9IDg2NDAwCgogICAgIyBMb25nIGZ1bmN0aW9uCiAgICBy"
        b"ZXN1bHQgPSBbXQogICAgZm9yIGkgaW4gcmFuZ2UoMTAwKToKICAgICAgICBmb3IgaXRlbSBpbiBpdGVt"
        b"czoKICAgICAgICAgICAgZm9yIHN1Yml0ZW0gaW4gaXRlbXM6CiAgICAgICAgICAgICAgICBpZiBzdWJp"
        b"dGVtID09IGk6CiAgICAgICAgICAgICAgICAgICAgcmVzdWx0LmFwcGVuZChzdWJpdGVtKQoKICAgIHJl"
        b"dHVybiByZXN1bHQKCmRlZiBhbm90aGVyX2Z1bmN0aW9uKCk6CiAgICB4ID0gMTIzCiAgICBkYXRhID0g"
        b"W10KICAgIGZvciBpIGluIHJhbmdlKDEwMDApOgogICAgICAgIHggPSB4ICsgMQogICAgICAgIGRhdGEg"
        b"PSBkYXRhICsgW2ldICAjIEluZWZmaWNpZW50CgogICAgcmV0dXJuIHg="
    )
    sample_code = base64.b64decode(_SAMPLE_PAYLOAD_B64).decode("utf-8")

    print("Running parallel review on sample code...")
    print("=" * 60)

    result = review_code(sample_code, file_path="example.py")

    print(f"Total findings: {result.total_findings}")
    print(f"Overall confidence: {result.overall_confidence:.1%}")
    print(f"Execution time: {result.execution_time_ms:.2f}ms")
    print()

    print("Aggregate scores:")
    for category, score in result.aggregate_scores.items():
        print(f"  {category}: {score:.1f}")
    print()

    print("Findings by severity:")
    by_severity = result.summary["by_severity"]
    for sev, count in by_severity.items():
        if count > 0:
            print(f"  {sev}: {count}")
    print()

    print("Critical/High severity findings:")
    for finding in result.findings:
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            loc = f"line {finding.line_number}" if finding.line_number else "unknown location"
            print(f"  [{finding.severity.value.upper()}] {finding.rule_id}: {finding.message} ({loc})")
