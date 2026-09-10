#!/usr/bin/env python3
"""
Severity Calculator with CVSS v3.1 Standard Scoring

Implements a CVSS-based severity scoring system for security vulnerabilities.
Complies with FIRST CVSS v3.1 specification for base and temporal score calculation.
Supports base score calculation, temporal adjustments, vector parsing, and JSON output.
"""

import json
import math
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, unique

# ============================================================================
# Enumerations
# ============================================================================

@unique
class AttackVector(str, Enum):
    """Network exploitable attack vector."""
    NETWORK = "N"
    ADJACENT_NETWORK = "A"
    LOCAL = "L"
    PHYSICAL = "P"


@unique
class AttackComplexity(str, Enum):
    """Attack complexity requirements."""
    LOW = "L"
    HIGH = "H"


@unique
class PrivilegesRequired(str, Enum):
    """Privileges required for exploitation."""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


@unique
class UserInteraction(str, Enum):
    """User interaction required."""
    NONE = "N"
    REQUIRED = "R"


@unique
class Scope(str, Enum):
    """Changed scope indicator."""
    UNCHANGED = "U"
    CHANGED = "C"


@unique
class ConfidentialityImpact(str, Enum):
    """Confidentiality impact level."""
    HIGH = "H"
    LOW = "L"
    NONE = "N"


@unique
class IntegrityImpact(str, Enum):
    """Integrity impact level."""
    HIGH = "H"
    LOW = "L"
    NONE = "N"


@unique
class AvailabilityImpact(str, Enum):
    """Availability impact level."""
    HIGH = "H"
    LOW = "L"
    NONE = "N"


# ----------------------------------------------------------------------------
# Separated Temporal Enums (Eliminating Duplicate Alias Bug)
# ----------------------------------------------------------------------------

@unique
class ExploitCodeMaturity(str, Enum):
    """CVSS 3.1 Exploit Code Maturity (E)."""
    NOT_DEFINED = "X"
    HIGH = "H"
    FUNCTIONAL = "F"
    PROOF_OF_CONCEPT = "P"
    UNPROVEN = "U"


@unique
class RemediationLevel(str, Enum):
    """CVSS 3.1 Remediation Level (RL)."""
    NOT_DEFINED = "X"
    OFFICIAL_FIX = "O"
    TEMPORARY_FIX = "T"
    WORKAROUND = "W"
    UNAVAILABLE = "U"


@unique
class ReportConfidence(str, Enum):
    """CVSS 3.1 Report Confidence (RC)."""
    NOT_DEFINED = "X"
    CONFIRMED = "C"
    REASONABLE = "R"
    UNCONFIRMED = "U"


# Backward compatibility alias - unique values only
@unique
class TemporalMetric(str, Enum):
    """Generic temporal metric levels (backward compatible without alias collision)."""
    NOT_DEFINED = "X"
    HIGH = "H"
    FUNCTIONAL = "F"
    PROOF_OF_CONCEPT = "P"
    OFFICIAL_FIX = "O"
    TEMPORARY_FIX = "T"
    WORKAROUND = "W"
    CONFIRMED = "C"
    REASONABLE = "R"
    UNPROVEN = "U"


@unique
class SeverityRating(str, Enum):
    """Severity rating categories."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


# ============================================================================
# CVSS Rounding Function (FIRST CVSS v3.1 Appendix A Specification)
# ============================================================================

def roundup(val: float) -> float:
    """
    Roundup function defined by CVSS v3.1 specification.

    Returns the smallest number, specified to 1 decimal place, that is
    equal to or higher than its input, using integer arithmetic to prevent
    floating point inaccuracies.
    """
    int_input = round(val * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    else:
        return (int_input // 10000 + 1) / 10.0


# ============================================================================
# CVSS Metric Values
# ============================================================================

@dataclass(frozen=True)
class MetricValues:
    """CVSS 3.1 metric values strictly following FIRST specifications."""

    # Impact multiplier constant
    MP: float = 6.42

    # Exploitability multiplier constant
    MS: float = 8.22

    # Attack Vector (AV)
    AV_N: float = 0.85  # Network
    AV_A: float = 0.62  # Adjacent Network
    AV_L: float = 0.55  # Local
    AV_P: float = 0.20  # Physical

    # Attack Complexity (AC)
    AC_L: float = 0.77  # Low
    AC_H: float = 0.44  # High

    # Privileges Required (PR) - Scope Unchanged
    PR_N_U: float = 0.85  # None
    PR_L_U: float = 0.62  # Low
    PR_H_U: float = 0.27  # High

    # Privileges Required - Scope Changed
    PR_N_C: float = 0.85  # None
    PR_L_C: float = 0.68  # Low
    PR_H_C: float = 0.50  # High

    # User Interaction (UI)
    UI_N: float = 0.85  # None
    UI_R: float = 0.62  # Required

    # Confidentiality (C)
    C_H: float = 0.56
    C_L: float = 0.22
    C_N: float = 0.00

    # Integrity (I)
    I_H: float = 0.56
    I_L: float = 0.22
    I_N: float = 0.00

    # Availability (A)
    A_H: float = 0.56
    A_L: float = 0.22
    A_N: float = 0.00

    # Temporal metrics (E: Exploit Code Maturity)
    E_X: float = 1.00  # Not defined
    E_H: float = 1.00  # High
    E_F: float = 0.97  # Functional
    E_P: float = 0.94  # Proof-of-concept
    E_U: float = 0.91  # Unproven

    # Temporal metrics (RL: Remediation Level - Verified CVSS 3.1 Standards)
    RL_X: float = 1.00  # Not defined
    RL_U: float = 1.00  # Unavailable
    RL_W: float = 0.97  # Workaround
    RL_T: float = 0.96  # Temporary Fix
    RL_O: float = 0.95  # Official Fix
    RL_H: float = 1.00  # Fallback for High if passed

    # Temporal metrics (RC: Report Confidence - Verified CVSS 3.1 Standards)
    RC_X: float = 1.00  # Not defined
    RC_C: float = 1.00  # Confirmed
    RC_R: float = 0.96  # Reasonable
    RC_U: float = 0.92  # Unconfirmed / Unknown
    RC_H: float = 1.00  # Fallback for High if passed


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class CVSSBaseMetrics:
    """Base metrics for CVSS score calculation."""
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: ConfidentialityImpact = ConfidentialityImpact.HIGH
    integrity: IntegrityImpact = IntegrityImpact.HIGH
    availability: AvailabilityImpact = AvailabilityImpact.HIGH


@dataclass
class CVSSTemporalMetrics:
    """Temporal metrics for score adjustment."""
    exploit_code_maturity: ExploitCodeMaturity | str = ExploitCodeMaturity.NOT_DEFINED
    remediation_level: RemediationLevel | str = RemediationLevel.NOT_DEFINED
    report_confidence: ReportConfidence | str = ReportConfidence.NOT_DEFINED


@dataclass
class SeverityScore:
    """Complete severity calculation result."""
    base_score: float = 0.0
    temporal_score: float = 0.0
    impact_score: float = 0.0
    exploitability_score: float = 0.0
    base_severity: SeverityRating = SeverityRating.NONE
    temporal_severity: SeverityRating = SeverityRating.NONE
    vector_string: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "base_score": round(self.base_score, 1),
            "temporal_score": round(self.temporal_score, 1),
            "impact_score": round(self.impact_score, 1),
            "exploitability_score": round(self.exploitability_score, 1),
            "base_severity": self.base_severity.value,
            "temporal_severity": self.temporal_severity.value,
            "vector_string": self.vector_string,
            "timestamp": self.timestamp,
        }


@dataclass
class SeverityInput:
    """Input parameters for severity calculation."""
    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope_changed: bool = False
    confidentiality_impact: str = "H"
    integrity_impact: str = "H"
    availability_impact: str = "H"
    exploit_code_maturity: str = "X"
    remediation_level: str = "X"
    report_confidence: str = "X"


# ============================================================================
# CVSS Calculator
# ============================================================================

class SeverityCalculator:
    """
    CVSS 3.1 Base and Temporal Score Calculator.

    Implements the CVSS 3.1 formula for calculating base and temporal scores
    strictly according to the FIRST CVSS specification.
    """

    def __init__(self):
        self._vals = MetricValues()

    def calculate_base_score(self, metrics: CVSSBaseMetrics) -> tuple[float, float, float]:
        """
        Calculate CVSS 3.1 base score according to FIRST specifications.

        Args:
            metrics: Base metrics for calculation

        Returns:
            Tuple of (base_score, impact_score, exploitability_score)
        """
        # Get metric values
        av = self._get_av_value(metrics.attack_vector)
        ac = self._get_ac_value(metrics.attack_complexity)
        pr = self._get_pr_value(metrics.privileges_required, metrics.scope)
        ui = self._get_ui_value(metrics.user_interaction)
        c = self._get_c_value(metrics.confidentiality)
        i = self._get_i_value(metrics.integrity)
        a = self._get_a_value(metrics.availability)

        # Calculate Impact Sub-Score (ISS)
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        # Calculate Impact according to FIRST CVSS v3.1
        if metrics.scope == Scope.UNCHANGED:
            impact = self._vals.MP * iss
        else:  # Changed scope
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # Handle impact <= 0
        if impact <= 0:
            impact_score = 0.0
            base_score = 0.0
        else:
            impact_score = impact

        # Calculate Exploitability
        exploitability = self._vals.MS * av * ac * pr * ui

        # Calculate Base Score according to FIRST CVSS v3.1
        if impact_score <= 0:
            base_score = 0.0
        else:
            if metrics.scope == Scope.UNCHANGED:
                base_score = min(roundup(impact_score + exploitability), 10.0)
            else:
                base_score = min(roundup(1.08 * (impact_score + exploitability)), 10.0)

        return base_score, impact_score, exploitability

    def calculate_temporal_score(
        self,
        base_score: float,
        temporal_metrics: CVSSTemporalMetrics
    ) -> float:
        """
        Calculate temporal score adjustment according to CVSS 3.1.

        Args:
            base_score: The base score to adjust
            temporal_metrics: Temporal metric values

        Returns:
            Adjusted temporal score
        """
        if base_score <= 0.0:
            return 0.0

        e = self._get_e_value(temporal_metrics.exploit_code_maturity)
        rl = self._get_rl_value(temporal_metrics.remediation_level)
        rc = self._get_rc_value(temporal_metrics.report_confidence)

        temporal_score = min(roundup(base_score * e * rl * rc), 10.0)
        return temporal_score

    def calculate_from_input(self, input_data: SeverityInput) -> SeverityScore:
        """
        Calculate severity from simple input parameters.

        Args:
            input_data: Input parameters

        Returns:
            SeverityScore with all calculated values
        """
        # Build base metrics
        base_metrics = CVSSBaseMetrics(
            attack_vector=AttackVector(input_data.attack_vector.upper()),
            attack_complexity=AttackComplexity(input_data.attack_complexity.upper()),
            privileges_required=PrivilegesRequired(input_data.privileges_required.upper()),
            user_interaction=UserInteraction(input_data.user_interaction.upper()),
            scope=Scope.CHANGED if input_data.scope_changed else Scope.UNCHANGED,
            confidentiality=ConfidentialityImpact(input_data.confidentiality_impact.upper()),
            integrity=IntegrityImpact(input_data.integrity_impact.upper()),
            availability=AvailabilityImpact(input_data.availability_impact.upper()),
        )

        # Build temporal metrics
        temporal_metrics = CVSSTemporalMetrics(
            exploit_code_maturity=input_data.exploit_code_maturity.upper(),
            remediation_level=input_data.remediation_level.upper(),
            report_confidence=input_data.report_confidence.upper(),
        )

        # Calculate base score
        base_score, impact_score, exploitability_score = self.calculate_base_score(base_metrics)

        # Calculate temporal score
        temporal_score = self.calculate_temporal_score(base_score, temporal_metrics)

        # Determine severity ratings
        base_severity = self._score_to_severity(base_score)
        temporal_severity = self._score_to_severity(temporal_score)

        # Build vector string
        vector_string = self._build_vector_string(base_metrics, temporal_metrics)

        return SeverityScore(
            base_score=base_score,
            temporal_score=temporal_score,
            impact_score=impact_score,
            exploitability_score=exploitability_score,
            base_severity=base_severity,
            temporal_severity=temporal_severity,
            vector_string=vector_string,
        )

    def parse_vector_string(self, vector: str) -> SeverityInput | None:
        """
        Parse a CVSS vector string into input parameters.

        Args:
            vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        Returns:
            SeverityInput or None if parsing fails
        """
        try:
            # Remove prefix if present
            if "/" in vector:
                parts = vector.split("/")
                if parts[0].startswith("CVSS"):
                    parts = parts[1:]
            else:
                parts = vector.split(":")

            input_data = SeverityInput()

            for part in parts:
                if ":" in part:
                    key, value = part.split(":", 1)
                else:
                    continue

                key = key.upper().strip()
                value = value.strip().upper()

                if key == "AV":
                    input_data.attack_vector = value
                elif key == "AC":
                    input_data.attack_complexity = value
                elif key == "PR":
                    input_data.privileges_required = value
                elif key == "UI":
                    input_data.user_interaction = value
                elif key == "S":
                    input_data.scope_changed = (value == "C")
                elif key == "C":
                    input_data.confidentiality_impact = value
                elif key == "I":
                    input_data.integrity_impact = value
                elif key == "A":
                    input_data.availability_impact = value
                elif key == "E":
                    input_data.exploit_code_maturity = value
                elif key == "RL":
                    input_data.remediation_level = value
                elif key == "RC":
                    input_data.report_confidence = value

            return input_data
        except Exception:
            return None

    def calculate_from_vector(self, vector: str) -> SeverityScore | None:
        """
        Calculate severity from a CVSS vector string.

        Args:
            vector: CVSS vector string

        Returns:
            SeverityScore or None if vector is invalid
        """
        input_data = self.parse_vector_string(vector)
        if input_data is None:
            return None
        return self.calculate_from_input(input_data)

    # Metric value getters
    def _get_av_value(self, av: AttackVector | str) -> float:
        """Get Attack Vector metric value."""
        val = av.value if isinstance(av, AttackVector) else str(av).upper()
        mapping = {
            "N": self._vals.AV_N,
            "A": self._vals.AV_A,
            "L": self._vals.AV_L,
            "P": self._vals.AV_P,
        }
        return mapping.get(val, self._vals.AV_N)

    def _get_ac_value(self, ac: AttackComplexity | str) -> float:
        """Get Attack Complexity metric value."""
        val = ac.value if isinstance(ac, AttackComplexity) else str(ac).upper()
        mapping = {
            "L": self._vals.AC_L,
            "H": self._vals.AC_H,
        }
        return mapping.get(val, self._vals.AC_L)

    def _get_pr_value(self, pr: PrivilegesRequired | str, scope: Scope | str) -> float:
        """Get Privileges Required metric value based on Scope."""
        pr_val = pr.value if isinstance(pr, PrivilegesRequired) else str(pr).upper()
        scope_val = scope.value if isinstance(scope, Scope) else str(scope).upper()

        if scope_val == "U":
            mapping = {
                "N": self._vals.PR_N_U,
                "L": self._vals.PR_L_U,
                "H": self._vals.PR_H_U,
            }
        else:
            mapping = {
                "N": self._vals.PR_N_C,
                "L": self._vals.PR_L_C,
                "H": self._vals.PR_H_C,
            }
        return mapping.get(pr_val, self._vals.PR_N_U)

    def _get_ui_value(self, ui: UserInteraction | str) -> float:
        """Get User Interaction metric value."""
        val = ui.value if isinstance(ui, UserInteraction) else str(ui).upper()
        mapping = {
            "N": self._vals.UI_N,
            "R": self._vals.UI_R,
        }
        return mapping.get(val, self._vals.UI_N)

    def _get_c_value(self, c: ConfidentialityImpact | str) -> float:
        """Get Confidentiality metric value."""
        val = c.value if isinstance(c, ConfidentialityImpact) else str(c).upper()
        mapping = {
            "H": self._vals.C_H,
            "L": self._vals.C_L,
            "N": self._vals.C_N,
        }
        return mapping.get(val, self._vals.C_N)

    def _get_i_value(self, i: IntegrityImpact | str) -> float:
        """Get Integrity metric value."""
        val = i.value if isinstance(i, IntegrityImpact) else str(i).upper()
        mapping = {
            "H": self._vals.I_H,
            "L": self._vals.I_L,
            "N": self._vals.I_N,
        }
        return mapping.get(val, self._vals.I_N)

    def _get_a_value(self, a: AvailabilityImpact | str) -> float:
        """Get Availability metric value."""
        val = a.value if isinstance(a, AvailabilityImpact) else str(a).upper()
        mapping = {
            "H": self._vals.A_H,
            "L": self._vals.A_L,
            "N": self._vals.A_N,
        }
        return mapping.get(val, self._vals.A_N)

    def _get_e_value(self, e: ExploitCodeMaturity | TemporalMetric | str) -> float:
        """Get Exploit Code Maturity value."""
        val = e.value if hasattr(e, "value") else str(e).upper()
        mapping = {
            "X": self._vals.E_X,
            "H": self._vals.E_H,
            "F": self._vals.E_F,
            "P": self._vals.E_P,
            "U": self._vals.E_U,
        }
        return mapping.get(val, self._vals.E_X)

    def _get_rl_value(self, rl: RemediationLevel | TemporalMetric | str) -> float:
        """Get Remediation Level value."""
        val = rl.value if hasattr(rl, "value") else str(rl).upper()
        mapping = {
            "X": self._vals.RL_X,
            "O": self._vals.RL_O,
            "T": self._vals.RL_T,
            "W": self._vals.RL_W,
            "U": self._vals.RL_U,
            "H": self._vals.RL_H,
        }
        return mapping.get(val, self._vals.RL_X)

    def _get_rc_value(self, rc: ReportConfidence | TemporalMetric | str) -> float:
        """Get Report Confidence value."""
        val = rc.value if hasattr(rc, "value") else str(rc).upper()
        mapping = {
            "X": self._vals.RC_X,
            "C": self._vals.RC_C,
            "R": self._vals.RC_R,
            "U": self._vals.RC_U,
            "H": self._vals.RC_H,
        }
        return mapping.get(val, self._vals.RC_X)

    def _score_to_severity(self, score: float) -> SeverityRating:
        """Convert numeric score to severity rating per CVSS 3.1 standard."""
        if score >= 9.0:
            return SeverityRating.CRITICAL
        elif score >= 7.0:
            return SeverityRating.HIGH
        elif score >= 4.0:
            return SeverityRating.MEDIUM
        elif score > 0.0:
            return SeverityRating.LOW
        else:
            return SeverityRating.NONE

    def _build_vector_string(
        self,
        base: CVSSBaseMetrics,
        temporal: CVSSTemporalMetrics
    ) -> str:
        """Build valid standard CVSS vector string from metrics."""
        parts = [
            f"CVSS:3.1/AV:{base.attack_vector.value}",
            f"AC:{base.attack_complexity.value}",
            f"PR:{base.privileges_required.value}",
            f"UI:{base.user_interaction.value}",
            f"S:{base.scope.value}",
            f"C:{base.confidentiality.value}",
            f"I:{base.integrity.value}",
            f"A:{base.availability.value}",
        ]

        # Add temporal metrics if not default (X)
        e_val = temporal.exploit_code_maturity.value if hasattr(temporal.exploit_code_maturity, "value") else str(temporal.exploit_code_maturity).upper()
        rl_val = temporal.remediation_level.value if hasattr(temporal.remediation_level, "value") else str(temporal.remediation_level).upper()
        rc_val = temporal.report_confidence.value if hasattr(temporal.report_confidence, "value") else str(temporal.report_confidence).upper()

        if e_val != "X":
            parts.append(f"E:{e_val}")
        if rl_val != "X":
            parts.append(f"RL:{rl_val}")
        if rc_val != "X":
            parts.append(f"RC:{rc_val}")

        return "/".join(parts)


# ============================================================================
# JSON Output Formatter
# ============================================================================

class SeverityReport:
    """Formatted output for severity calculation results."""

    def __init__(self, score: SeverityScore):
        self.score = score

    def to_json(self, indent: int = 2) -> str:
        """Return JSON-formatted output."""
        return json.dumps(self.score.to_dict(), indent=indent)

    def to_dict(self) -> dict:
        """Return dictionary output."""
        return self.score.to_dict()

    def summary(self) -> str:
        """Return human-readable summary."""
        lines = [
            "=" * 50,
            "CVSS Severity Calculation Report",
            "=" * 50,
            f"Base Score:        {self.score.base_score:.1f} ({self.score.base_severity.value.upper()})",
            f"Temporal Score:    {self.score.temporal_score:.1f} ({self.score.temporal_severity.value.upper()})",
            f"Impact Sub-Score:  {self.score.impact_score:.1f}",
            f"Exploitability:    {self.score.exploitability_score:.1f}",
            "",
            f"Vector: {self.score.vector_string}",
            f"Calculated: {self.score.timestamp}",
            "=" * 50,
        ]
        return "\n".join(lines)


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """Command-line interface for the severity calculator."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="CVSS 3.1 Severity Calculator"
    )
    parser.add_argument(
        "--vector", "-v",
        help="CVSS vector string to parse"
    )
    parser.add_argument(
        "--av",
        choices=["N", "A", "L", "P"],
        default="N",
        help="Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)"
    )
    parser.add_argument(
        "--ac",
        choices=["L", "H"],
        default="L",
        help="Attack Complexity (L=Low, H=High)"
    )
    parser.add_argument(
        "--pr",
        choices=["N", "L", "H"],
        default="N",
        help="Privileges Required (N=None, L=Low, H=High)"
    )
    parser.add_argument(
        "--ui",
        choices=["N", "R"],
        default="N",
        help="User Interaction (N=None, R=Required)"
    )
    parser.add_argument(
        "--scope", "-s",
        choices=["U", "C"],
        default="U",
        help="Scope (U=Unchanged, C=Changed)"
    )
    parser.add_argument(
        "--c",
        choices=["H", "L", "N"],
        default="H",
        help="Confidentiality Impact (H=High, L=Low, N=None)"
    )
    parser.add_argument(
        "--i",
        choices=["H", "L", "N"],
        default="H",
        help="Integrity Impact (H=High, L=Low, N=None)"
    )
    parser.add_argument(
        "--a",
        choices=["H", "L", "N"],
        default="H",
        help="Availability Impact (H=High, L=Low, N=None)"
    )
    parser.add_argument(
        "--e",
        choices=["X", "H", "F", "P", "U"],
        default="X",
        help="Exploit Code Maturity (X=Not Defined, H=High, F=Functional, P=PoC, U=Unproven)"
    )
    parser.add_argument(
        "--rl",
        choices=["X", "H", "O", "T", "W", "U"],
        default="X",
        help="Remediation Level (X=Not Defined, H=High, O=Official, T=Temporary, W=Workaround, U=Unavailable)"
    )
    parser.add_argument(
        "--rc",
        choices=["X", "H", "C", "R", "U"],
        default="X",
        help="Report Confidence (X=Not Defined, H=High, C=Confirmed, R=Reasonable, U=Unconfirmed)"
    )
    parser.add_argument(
        "--output", "-o",
        choices=["json", "summary", "dict"],
        default="summary",
        help="Output format"
    )

    args = parser.parse_args()
    calculator = SeverityCalculator()

    if args.vector:
        score = calculator.calculate_from_vector(args.vector)
        if score is None:
            print("Error: Invalid CVSS vector string", file=sys.stderr)
            sys.exit(1)
    else:
        input_data = SeverityInput(
            attack_vector=args.av,
            attack_complexity=args.ac,
            privileges_required=args.pr,
            user_interaction=args.ui,
            scope_changed=args.scope == "C",
            confidentiality_impact=args.c,
            integrity_impact=args.i,
            availability_impact=args.a,
            exploit_code_maturity=args.e,
            remediation_level=args.rl,
            report_confidence=args.rc,
        )
        score = calculator.calculate_from_input(input_data)

    report = SeverityReport(score)

    if args.output == "json":
        print(report.to_json())
    elif args.output == "dict":
        print(report.to_dict())
    else:
        print(report.summary())


if __name__ == "__main__":
    main()
