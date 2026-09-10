"""
CVSS Calculator - Common Vulnerability Scoring System 3.1

Implements metric value mapping, base score formula, temporal score adjustment,
and environmental score calculation per CVSS 3.1 specification.
"""

import math
from dataclasses import dataclass
from typing import Any

def cvss_roundup(input_val: float) -> float:
    """Implement official CVSS 3.1 Roundup function using integer arithmetic."""
    int_input = round(input_val * 100000)
    if (int_input % 10000) == 0:
        return int_input / 100000.0
    else:
        return (math.floor(int_input / 10000) + 1) / 10.0

def _normalize_metric(val: Any) -> str:
    """Safely convert metric value to uppercase string, or empty string if None/invalid."""
    if not isinstance(val, str):
        return ""
    return val.strip().upper()

# =============================================================================
# Metric Value Mappings
# =============================================================================

@dataclass
class MetricValue:
    """Represents a CVSS metric with its abbreviation and weight."""
    abbreviation: str
    name: str
    weight: float


# Attack Vector (AV) - measures how the vulnerability is exploited
ATTACK_VECTOR = {
    'N': MetricValue('N', 'Network', 0.85),       # Exploitable over network
    'A': MetricValue('A', 'Adjacent', 0.62),      # Exploitable from adjacent network
    'L': MetricValue('L', 'Local', 0.55),        # Requires local access
    'P': MetricValue('P', 'Physical', 0.20),     # Requires physical access
}

# Attack Complexity (AC) - measures conditions beyond attacker's control
ATTACK_COMPLEXITY = {
    'L': MetricValue('L', 'Low', 0.77),          # No special conditions
    'H': MetricValue('H', 'High', 0.44),         # Requires special conditions
}

# Privileges Required (PR) - measures privileges attacker needs
# Values differ based on whether Scope is Changed or Unchanged
PRIVILEGES_REQUIRED_UNCHANGED = {
    'N': MetricValue('N', 'None', 0.85),         # No privileges needed
    'L': MetricValue('L', 'Low', 0.62),          # Some privileges needed
    'H': MetricValue('H', 'High', 0.27),         # Elevated privileges needed
}

PRIVILEGES_REQUIRED_CHANGED = {
    'N': MetricValue('N', 'None', 0.85),
    'L': MetricValue('L', 'Low', 0.68),          # Different weights when scope changed
    'H': MetricValue('H', 'High', 0.50),
}

# User Interaction (UI) - measures requirement for user participation
USER_INTERACTION = {
    'N': MetricValue('N', 'None', 0.85),        # No user interaction
    'R': MetricValue('R', 'Required', 0.62),     # Requires user action
}

# Scope (S) - measures whether vulnerable component differs from impacted component
SCOPE = {
    'U': MetricValue('U', 'Unchanged', None),    # No scope change
    'C': MetricValue('C', 'Changed', None),      # Scope changed
}

# Confidentiality Impact (C) - measures impact on confidentiality
CONFIDENTIALITY_IMPACT = {
    'H': MetricValue('H', 'High', 0.56),         # Complete loss
    'L': MetricValue('L', 'Low', 0.22),          # Partial loss
    'N': MetricValue('N', 'None', 0.00),        # No loss
}

# Integrity Impact (I) - measures impact on integrity
INTEGRITY_IMPACT = {
    'H': MetricValue('H', 'High', 0.56),
    'L': MetricValue('L', 'Low', 0.22),
    'N': MetricValue('N', 'None', 0.00),
}

# Availability Impact (A) - measures impact on availability
AVAILABILITY_IMPACT = {
    'H': MetricValue('H', 'High', 0.56),
    'L': MetricValue('L', 'Low', 0.22),
    'N': MetricValue('N', 'None', 0.00),
}


# =============================================================================
# Temporal Metrics - measures exploitability factors over time
# =============================================================================

# Exploit Code Maturity (E) - measures existence of exploit code
EXPLOIT_CODE_MATURITY = {
    'X': MetricValue('X', 'Not Defined', 1.00),  # Override value
    'H': MetricValue('H', 'High', 1.00),        # Autonomous replication
    'F': MetricValue('F', 'Functional', 0.97),  # Working exploit exists
    'P': MetricValue('P', 'Proof-of-Concept', 0.94),  # Conceptual exploit
    'U': MetricValue('U', 'Unproven', 0.91),    # No exploit available
}

# Remediation Level (RL) - measures availability of fixes
REMEDIATION_LEVEL = {
    'X': MetricValue('X', 'Not Defined', 1.00),
    'U': MetricValue('U', 'Unavailable', 1.00),  # No fix available
    'W': MetricValue('W', 'Workaround', 0.97),   # Unofficial fix exists
    'T': MetricValue('T', 'Temporary', 0.96),    # Temporary fix available
    'O': MetricValue('O', 'Official', 0.95),     # Official fix available
}

# Report Confidence (RC) - measures confidence in vulnerability existence
REPORT_CONFIDENCE = {
    'X': MetricValue('X', 'Not Defined', 1.00),
    'C': MetricValue('C', 'Confirmed', 1.00),    # Full disclosure
    'R': MetricValue('R', 'Reasonable', 0.96),  # Some validation
    'U': MetricValue('U', 'Unknown', 0.92),      # Limited information
}


# =============================================================================
# Environmental Metrics - Modified Base Metrics for specific environments
# =============================================================================

# Modified versions use same weight values as base metrics
# but allow "Not Defined" (X) which uses base metric value

MODIFIED_ATTACK_VECTOR = ATTACK_VECTOR.copy()
MODIFIED_ATTACK_VECTOR['X'] = MetricValue('X', 'Not Defined', 1.00)

MODIFIED_ATTACK_COMPLEXITY = ATTACK_COMPLEXITY.copy()
MODIFIED_ATTACK_COMPLEXITY['X'] = MetricValue('X', 'Not Defined', 1.00)

MODIFIED_PRIVILEGES_REQUIRED_UNCHANGED = PRIVILEGES_REQUIRED_UNCHANGED.copy()
MODIFIED_PRIVILEGES_REQUIRED_UNCHANGED['X'] = MetricValue('X', 'Not Defined', 1.00)

MODIFIED_PRIVILEGES_REQUIRED_CHANGED = PRIVILEGES_REQUIRED_CHANGED.copy()
MODIFIED_PRIVILEGES_REQUIRED_CHANGED['X'] = MetricValue('X', 'Not Defined', 1.00)

MODIFIED_USER_INTERACTION = USER_INTERACTION.copy()
MODIFIED_USER_INTERACTION['X'] = MetricValue('X', 'Not Defined', 1.00)

MODIFIED_SCOPE = SCOPE.copy()
MODIFIED_SCOPE['X'] = MetricValue('X', 'Not Defined', None)

MODIFIED_CONFIDENTIALITY_IMPACT = CONFIDENTIALITY_IMPACT.copy()
MODIFIED_CONFIDENTIALITY_IMPACT['X'] = MetricValue('X', 'Not Defined', 1.00)

MODIFIED_INTEGRITY_IMPACT = INTEGRITY_IMPACT.copy()
MODIFIED_INTEGRITY_IMPACT['X'] = MetricValue('X', 'Not Defined', 1.00)

MODIFIED_AVAILABILITY_IMPACT = AVAILABILITY_IMPACT.copy()
MODIFIED_AVAILABILITY_IMPACT['X'] = MetricValue('X', 'Not Defined', 1.00)

# Confidentiality Requirement (CR) - confidentiality impact weight
CONFIDENTIALITY_REQUIREMENT = {
    'X': MetricValue('X', 'Not Defined', 1.00),
    'H': MetricValue('H', 'High', 1.50),
    'M': MetricValue('M', 'Medium', 1.00),
    'L': MetricValue('L', 'Low', 0.50),
}

# Integrity Requirement (IR) - integrity impact weight
INTEGRITY_REQUIREMENT = {
    'X': MetricValue('X', 'Not Defined', 1.00),
    'H': MetricValue('H', 'High', 1.50),
    'M': MetricValue('M', 'Medium', 1.00),
    'L': MetricValue('L', 'Low', 0.50),
}

# Availability Requirement (AR) - availability impact weight
AVAILABILITY_REQUIREMENT = {
    'X': MetricValue('X', 'Not Defined', 1.00),
    'H': MetricValue('H', 'High', 1.50),
    'M': MetricValue('M', 'Medium', 1.00),
    'L': MetricValue('L', 'Low', 0.50),
}


# =============================================================================
# Score Ranges and Severity Ratings
# =============================================================================

SEVERITY_RATINGS = [
    (0.0, 0.0, 'None', 'N'),
    (0.1, 3.9, 'Low', 'L'),
    (4.0, 6.9, 'Medium', 'M'),
    (7.0, 8.9, 'High', 'H'),
    (9.0, 10.0, 'Critical', 'C'),
]


def get_severity(score: float) -> dict[str, str]:
    """Get severity rating for a given CVSS score."""
    if not isinstance(score, (int, float)) or math.isnan(score):
        return {'name': 'Unknown', 'abbreviation': '?'}
    if score < 0.0 or score > 10.0:
        return {'name': 'Unknown', 'abbreviation': '?'}

    rounded_score = cvss_roundup(score)
    if rounded_score <= 0.0:
        return {'name': 'None', 'abbreviation': 'N'}
    elif rounded_score <= 3.9:
        return {'name': 'Low', 'abbreviation': 'L'}
    elif rounded_score <= 6.9:
        return {'name': 'Medium', 'abbreviation': 'M'}
    elif rounded_score <= 8.9:
        return {'name': 'High', 'abbreviation': 'H'}
    elif rounded_score <= 10.0:
        return {'name': 'Critical', 'abbreviation': 'C'}
    return {'name': 'Unknown', 'abbreviation': '?'}


# =============================================================================
# CVSS Score Calculator Classes
# =============================================================================

class CVSSCalculator:
    """CVSS 3.1 Base Score Calculator."""

    def __init__(
        self,
        attack_vector: str,
        attack_complexity: str,
        privileges_required: str,
        user_interaction: str,
        scope: str,
        confidentiality: str,
        integrity: str,
        availability: str
    ):
        """
        Initialize calculator with base metric values.

        Args:
            attack_vector: Network (N), Adjacent (A), Local (L), Physical (P)
            attack_complexity: Low (L), High (H)
            privileges_required: None (N), Low (L), High (H)
            user_interaction: None (N), Required (R)
            scope: Unchanged (U), Changed (C)
            confidentiality: High (H), Low (L), None (N)
            integrity: High (H), Low (L), None (N)
            availability: High (H), Low (L), None (N)
        """
        self.attack_vector = _normalize_metric(attack_vector)
        self.attack_complexity = _normalize_metric(attack_complexity)
        self.privileges_required = _normalize_metric(privileges_required)
        self.user_interaction = _normalize_metric(user_interaction)
        self.scope = _normalize_metric(scope)
        self.confidentiality = _normalize_metric(confidentiality)
        self.integrity = _normalize_metric(integrity)
        self.availability = _normalize_metric(availability)

        self._validate_metrics()

    def _validate_metrics(self) -> None:
        """Validate all metric values are valid CVSS values."""
        errors = []

        if self.attack_vector not in ATTACK_VECTOR:
            errors.append(f"Invalid Attack Vector: {self.attack_vector}")
        if self.attack_complexity not in ATTACK_COMPLEXITY:
            errors.append(f"Invalid Attack Complexity: {self.attack_complexity}")
        if self.user_interaction not in USER_INTERACTION:
            errors.append(f"Invalid User Interaction: {self.user_interaction}")
        if self.scope not in SCOPE:
            errors.append(f"Invalid Scope: {self.scope}")
        if self.confidentiality not in CONFIDENTIALITY_IMPACT:
            errors.append(f"Invalid Confidentiality: {self.confidentiality}")
        if self.integrity not in INTEGRITY_IMPACT:
            errors.append(f"Invalid Integrity: {self.integrity}")
        if self.availability not in AVAILABILITY_IMPACT:
            errors.append(f"Invalid Availability: {self.availability}")

        # Privileges Required depends on Scope
        if self.scope == 'C':
            if self.privileges_required not in PRIVILEGES_REQUIRED_CHANGED:
                errors.append(f"Invalid Privileges Required: {self.privileges_required} (Scope Changed)")
        else:
            if self.privileges_required not in PRIVILEGES_REQUIRED_UNCHANGED:
                errors.append(f"Invalid Privileges Required: {self.privileges_required} (Scope Unchanged)")

        if errors:
            raise ValueError("; ".join(errors))

    def _get_privileges_required_weight(self) -> float:
        """Get Privileges Required weight based on Scope."""
        if self.scope == 'C':
            return PRIVILEGES_REQUIRED_CHANGED[self.privileges_required].weight
        return PRIVILEGES_REQUIRED_UNCHANGED[self.privileges_required].weight

    def calculate_impact_sub_score(self) -> float:
        """
        Calculate the Impact Sub-Score (ISS).

        ISS = 1 - [(1-Conf)*(1-Integ)*(1-Avail)]
        """
        conf_weight = CONFIDENTIALITY_IMPACT[self.confidentiality].weight
        integ_weight = INTEGRITY_IMPACT[self.integrity].weight
        avail_weight = AVAILABILITY_IMPACT[self.availability].weight

        iss = 1 - ((1 - conf_weight) * (1 - integ_weight) * (1 - avail_weight))
        return iss

    def calculate_impact(self) -> float:
        """
        Calculate the Impact score.

        If Scope Unchanged: Impact = 6.42 * ISS
        If Scope Changed: Impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS * 0.9723)^15
        """
        iss = self.calculate_impact_sub_score()

        if self.scope == 'U':
            # Unchanged scope
            impact = 6.42 * iss
        else:
            # Changed scope
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        return impact

    def calculate_exploitability(self) -> float:
        """
        Calculate the Exploitability score.

        Exploitability = 8.22 * AV * AC * PR * UI
        """
        av_weight = ATTACK_VECTOR[self.attack_vector].weight
        ac_weight = ATTACK_COMPLEXITY[self.attack_complexity].weight
        pr_weight = self._get_privileges_required_weight()
        ui_weight = USER_INTERACTION[self.user_interaction].weight

        exploitability = 8.22 * av_weight * ac_weight * pr_weight * ui_weight
        return exploitability

    def calculate_base_score(self) -> float:
        """
        Calculate the CVSS 3.1 Base Score.

        BaseScore = min(10, 0 if Impact < 0 else ceil(min(Impact + Exploitability, 10)))
        """
        impact = self.calculate_impact()
        exploitability = self.calculate_exploitability()

        if impact <= 0:
            return 0.0

        if self.scope == 'U':
            raw_score = min(impact + exploitability, 10.0)
        else:
            raw_score = min(1.08 * (impact + exploitability), 10.0)

        return cvss_roundup(raw_score)

    def get_vector_string(self) -> str:
        """Generate CVSS vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/A:{self.availability}"
        )

    def get_all_scores(self) -> dict[str, float]:
        """Get all calculated scores and intermediate values."""
        return {
            'base_score': self.calculate_base_score(),
            'impact_sub_score': round(self.calculate_impact_sub_score(), 4),
            'impact': round(self.calculate_impact(), 4),
            'exploitability': round(self.calculate_exploitability(), 4),
            'severity': get_severity(self.calculate_base_score())['name'],
        }


class TemporalScoreCalculator(CVSSCalculator):
    """CVSS 3.1 Temporal Score Calculator - extends base with temporal metrics."""

    def __init__(
        self,
        attack_vector: str,
        attack_complexity: str,
        privileges_required: str,
        user_interaction: str,
        scope: str,
        confidentiality: str,
        integrity: str,
        availability: str,
        exploit_code_maturity: str = 'X',
        remediation_level: str = 'X',
        report_confidence: str = 'X'
    ):
        """
        Initialize temporal calculator with base and temporal metrics.

        Args:
            All base metrics from CVSSCalculator
            exploit_code_maturity: High (H), Functional (F), Proof-of-Concept (P), Unproven (U)
            remediation_level: Unavailable (U), Workaround (W), Temporary (T), Official (O)
            report_confidence: Confirmed (C), Reasonable (R), Unknown (U)
        """
        super().__init__(
            attack_vector, attack_complexity, privileges_required,
            user_interaction, scope, confidentiality, integrity, availability
        )

        self.exploit_code_maturity = _normalize_metric(exploit_code_maturity)
        self.remediation_level = _normalize_metric(remediation_level)
        self.report_confidence = _normalize_metric(report_confidence)

        self._validate_temporal_metrics()

    def _validate_temporal_metrics(self) -> None:
        """Validate temporal metric values."""
        errors = []

        if self.exploit_code_maturity not in EXPLOIT_CODE_MATURITY:
            errors.append(f"Invalid Exploit Code Maturity: {self.exploit_code_maturity}")
        if self.remediation_level not in REMEDIATION_LEVEL:
            errors.append(f"Invalid Remediation Level: {self.remediation_level}")
        if self.report_confidence not in REPORT_CONFIDENCE:
            errors.append(f"Invalid Report Confidence: {self.report_confidence}")

        if errors:
            raise ValueError("; ".join(errors))

    def _get_temporal_multiplier(self) -> float:
        """Calculate the temporal score multiplier."""
        e_weight = EXPLOIT_CODE_MATURITY[self.exploit_code_maturity].weight
        rl_weight = REMEDIATION_LEVEL[self.remediation_level].weight
        rc_weight = REPORT_CONFIDENCE[self.report_confidence].weight

        return e_weight * rl_weight * rc_weight

    def calculate_temporal_score(self) -> float:
        """
        Calculate the CVSS Temporal Score.

        TemporalScore = BaseScore * E * RL * RC
        """
        base = super().calculate_base_score()
        temporal_mult = self._get_temporal_multiplier()
        return cvss_roundup(base * temporal_mult)

    def get_vector_string(self) -> str:
        """Override to include temporal metrics in vector."""
        base_vector = super().get_vector_string().replace('CVSS:3.1/', 'CVSS:3.1/')
        temporal_part = f"/E:{self.exploit_code_maturity}/RL:{self.remediation_level}/RC:{self.report_confidence}"
        return base_vector + temporal_part

    def get_all_scores(self) -> dict[str, float]:
        """Override to include temporal-specific scores."""
        base_scores = super().get_all_scores()
        temporal_scores = {
            'temporal_score': self.calculate_temporal_score(),
            'exploit_code_maturity_mult': EXPLOIT_CODE_MATURITY[self.exploit_code_maturity].weight,
            'remediation_level_mult': REMEDIATION_LEVEL[self.remediation_level].weight,
            'report_confidence_mult': REPORT_CONFIDENCE[self.report_confidence].weight,
            'temporal_multiplier': round(self._get_temporal_multiplier(), 4),
        }
        return {**base_scores, **temporal_scores}


class EnvironmentalScoreCalculator(TemporalScoreCalculator):
    """CVSS 3.1 Environmental Score Calculator - adds environmental metrics."""

    def __init__(
        self,
        attack_vector: str,
        attack_complexity: str,
        privileges_required: str,
        user_interaction: str,
        scope: str,
        confidentiality: str,
        integrity: str,
        availability: str,
        exploit_code_maturity: str = 'X',
        remediation_level: str = 'X',
        report_confidence: str = 'X',
        # Modified base metrics (environmental override)
        modified_attack_vector: str = 'X',
        modified_attack_complexity: str = 'X',
        modified_privileges_required: str = 'X',
        modified_user_interaction: str = 'X',
        modified_scope: str = 'X',
        modified_confidentiality: str = 'X',
        modified_integrity: str = 'X',
        modified_availability: str = 'X',
        # Security requirement weights
        confidentiality_requirement: str = 'X',
        integrity_requirement: str = 'X',
        availability_requirement: str = 'X'
    ):
        """
        Initialize environmental calculator with all metric types.

        Modified metrics override base metrics when not set to 'X'.
        Security requirements weight the impact components.
        """
        super().__init__(
            attack_vector, attack_complexity, privileges_required,
            user_interaction, scope, confidentiality, integrity, availability,
            exploit_code_maturity, remediation_level, report_confidence
        )

        # Modified metrics
        self.modified_attack_vector = _normalize_metric(modified_attack_vector)
        self.modified_attack_complexity = _normalize_metric(modified_attack_complexity)
        self.modified_privileges_required = _normalize_metric(modified_privileges_required)
        self.modified_user_interaction = _normalize_metric(modified_user_interaction)
        self.modified_scope = _normalize_metric(modified_scope)
        self.modified_confidentiality = _normalize_metric(modified_confidentiality)
        self.modified_integrity = _normalize_metric(modified_integrity)
        self.modified_availability = _normalize_metric(modified_availability)

        # Security requirements
        self.confidentiality_requirement = _normalize_metric(confidentiality_requirement)
        self.integrity_requirement = _normalize_metric(integrity_requirement)
        self.availability_requirement = _normalize_metric(availability_requirement)

        self._validate_environmental_metrics()

    def _validate_environmental_metrics(self) -> None:
        """Validate environmental metric values."""
        errors = []

        # Modified metrics
        if self.modified_attack_vector not in MODIFIED_ATTACK_VECTOR:
            errors.append(f"Invalid Modified Attack Vector: {self.modified_attack_vector}")
        if self.modified_attack_complexity not in MODIFIED_ATTACK_COMPLEXITY:
            errors.append(f"Invalid Modified Attack Complexity: {self.modified_attack_complexity}")
        if self.modified_user_interaction not in MODIFIED_USER_INTERACTION:
            errors.append(f"Invalid Modified User Interaction: {self.modified_user_interaction}")
        if self.modified_scope not in MODIFIED_SCOPE:
            errors.append(f"Invalid Modified Scope: {self.modified_scope}")
        if self.modified_confidentiality not in MODIFIED_CONFIDENTIALITY_IMPACT:
            errors.append(f"Invalid Modified Confidentiality: {self.modified_confidentiality}")
        if self.modified_integrity not in MODIFIED_INTEGRITY_IMPACT:
            errors.append(f"Invalid Modified Integrity: {self.modified_integrity}")
        if self.modified_availability not in MODIFIED_AVAILABILITY_IMPACT:
            errors.append(f"Invalid Modified Availability: {self.modified_availability}")

        # Modified Privileges Required depends on effective scope
        effective_scope = self.scope if self.modified_scope == 'X' else self.modified_scope
        if effective_scope == 'C':
            if self.modified_privileges_required not in MODIFIED_PRIVILEGES_REQUIRED_CHANGED:
                errors.append(f"Invalid Modified Privileges Required (Scope Changed): {self.modified_privileges_required}")
        else:
            if self.modified_privileges_required not in MODIFIED_PRIVILEGES_REQUIRED_UNCHANGED:
                errors.append(f"Invalid Modified Privileges Required (Scope Unchanged): {self.modified_privileges_required}")

        # Security requirements
        if self.confidentiality_requirement not in CONFIDENTIALITY_REQUIREMENT:
            errors.append(f"Invalid Confidentiality Requirement: {self.confidentiality_requirement}")
        if self.integrity_requirement not in INTEGRITY_REQUIREMENT:
            errors.append(f"Invalid Integrity Requirement: {self.integrity_requirement}")
        if self.availability_requirement not in AVAILABILITY_REQUIREMENT:
            errors.append(f"Invalid Availability Requirement: {self.availability_requirement}")

        if errors:
            raise ValueError("; ".join(errors))

    def _get_effective_metric(self, metric_type: str) -> str:
        """Get effective metric value (modified or base)."""
        effective_scope = self.scope if self.modified_scope == 'X' else self.modified_scope
        modified_map = {
            'av': (self.modified_attack_vector, ATTACK_VECTOR),
            'ac': (self.modified_attack_complexity, ATTACK_COMPLEXITY),
            'pr': (self.modified_privileges_required,
                   PRIVILEGES_REQUIRED_CHANGED if effective_scope == 'C'
                   else PRIVILEGES_REQUIRED_UNCHANGED),
            'ui': (self.modified_user_interaction, USER_INTERACTION),
            'c': (self.modified_confidentiality, CONFIDENTIALITY_IMPACT),
            'i': (self.modified_integrity, INTEGRITY_IMPACT),
            'a': (self.modified_availability, AVAILABILITY_IMPACT),
        }

        modified_val, _base_map = modified_map[metric_type]

        # If modified is 'X', use base value
        if modified_val == 'X':
            if metric_type == 'av':
                return self.attack_vector
            elif metric_type == 'ac':
                return self.attack_complexity
            elif metric_type == 'pr':
                return self.privileges_required
            elif metric_type == 'ui':
                return self.user_interaction
            elif metric_type == 'c':
                return self.confidentiality
            elif metric_type == 'i':
                return self.integrity
            elif metric_type == 'a':
                return self.availability

        return modified_val

    def _get_modified_privileges_weight(self) -> float:
        """Get modified Privileges Required weight based on Scope."""
        pr_value = self._get_effective_metric('pr')
        effective_scope = self.scope if self.modified_scope == 'X' else self.modified_scope
        if effective_scope == 'C':
            return MODIFIED_PRIVILEGES_REQUIRED_CHANGED[pr_value].weight
        return MODIFIED_PRIVILEGES_REQUIRED_UNCHANGED[pr_value].weight

    def calculate_modified_impact_sub_score(self) -> float:
        """
        Calculate modified Impact Sub-Score with security requirements.

        ModifiedISS = min(1 - [(1-MConf*CR)*(1-MInteg*IR)*(1-MAvail*AR)], 0.915)
        """
        mconf = MODIFIED_CONFIDENTIALITY_IMPACT[self._get_effective_metric('c')].weight
        minteg = MODIFIED_INTEGRITY_IMPACT[self._get_effective_metric('i')].weight
        mavail = MODIFIED_AVAILABILITY_IMPACT[self._get_effective_metric('a')].weight

        cr = CONFIDENTIALITY_REQUIREMENT[self.confidentiality_requirement].weight
        ir = INTEGRITY_REQUIREMENT[self.integrity_requirement].weight
        ar = AVAILABILITY_REQUIREMENT[self.availability_requirement].weight

        miss = 1 - ((1 - mconf * cr) * (1 - minteg * ir) * (1 - mavail * ar))
        return min(miss, 0.915)

    def calculate_modified_impact(self) -> float:
        """
        Calculate the Modified Impact score with environmental adjustments.
        """
        miss = self.calculate_modified_impact_sub_score()
        effective_scope = self.scope if self.modified_scope == 'X' else self.modified_scope

        if effective_scope == 'U':
            impact = 6.42 * miss
        else:
            impact = 7.52 * (miss - 0.029) - 3.25 * ((miss * 0.9731 - 0.02) ** 13)

        return impact

    def calculate_modified_exploitability(self) -> float:
        """
        Calculate the Modified Exploitability score.
        """
        mav = MODIFIED_ATTACK_VECTOR[self._get_effective_metric('av')].weight
        mac = MODIFIED_ATTACK_COMPLEXITY[self._get_effective_metric('ac')].weight
        mpr = self._get_modified_privileges_weight()
        mui = MODIFIED_USER_INTERACTION[self._get_effective_metric('ui')].weight

        exploitability = 8.22 * mav * mac * mpr * mui
        return exploitability

    def calculate_environmental_score(self) -> float:
        """
        Calculate the CVSS Environmental Score.

        EnvironmentalScore = round(min(10, (ModifiedImpact + ModifiedExploitability) * TemporalMultiplier), 1)
        """
        impact = self.calculate_modified_impact()
        exploitability = self.calculate_modified_exploitability()
        temporal_mult = self._get_temporal_multiplier()
        effective_scope = self.scope if self.modified_scope == 'X' else self.modified_scope

        if impact <= 0:
            return 0.0

        if effective_scope == 'U':
            intermediate = cvss_roundup(min(impact + exploitability, 10.0))
        else:
            intermediate = cvss_roundup(min(1.08 * (impact + exploitability), 10.0))

        return cvss_roundup(intermediate * temporal_mult)

    def get_vector_string(self) -> str:
        """Override to include environmental metrics in vector."""
        base_vector = super().get_vector_string()
        env_part = (
            f"/MAV:{self.modified_attack_vector}/MAC:{self.modified_attack_complexity}/"
            f"MPR:{self.modified_privileges_required}/MUI:{self.modified_user_interaction}/MS:{self.modified_scope}/"
            f"MC:{self.modified_confidentiality}/MI:{self.modified_integrity}/MA:{self.modified_availability}/"
            f"CR:{self.confidentiality_requirement}/IR:{self.integrity_requirement}/AR:{self.availability_requirement}"
        )
        return base_vector + env_part

    def get_all_scores(self) -> dict[str, float]:
        """Override to include all environmental-specific scores."""
        scores = super().get_all_scores()
        environmental_scores = {
            'environmental_score': self.calculate_environmental_score(),
            'modified_impact_sub_score': round(self.calculate_modified_impact_sub_score(), 4),
            'modified_impact': round(self.calculate_modified_impact(), 4),
            'modified_exploitability': round(self.calculate_modified_exploitability(), 4),
        }
        return {**scores, **environmental_scores}


# =============================================================================
# Convenience Functions
# =============================================================================

def calculate_cvss_base(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str
) -> dict[str, float]:
    """Calculate CVSS base score with all intermediate values."""
    calc = CVSSCalculator(
        attack_vector, attack_complexity, privileges_required,
        user_interaction, scope, confidentiality, integrity, availability
    )
    return calc.get_all_scores()


def calculate_cvss_temporal(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str,
    exploit_code_maturity: str = 'X',
    remediation_level: str = 'X',
    report_confidence: str = 'X'
) -> dict[str, float]:
    """Calculate CVSS temporal score with all intermediate values."""
    calc = TemporalScoreCalculator(
        attack_vector, attack_complexity, privileges_required,
        user_interaction, scope, confidentiality, integrity, availability,
        exploit_code_maturity, remediation_level, report_confidence
    )
    return calc.get_all_scores()


def calculate_cvss_environmental(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str,
    exploit_code_maturity: str = 'X',
    remediation_level: str = 'X',
    report_confidence: str = 'X',
    modified_attack_vector: str = 'X',
    modified_attack_complexity: str = 'X',
    modified_privileges_required: str = 'X',
    modified_user_interaction: str = 'X',
    modified_scope: str = 'X',
    modified_confidentiality: str = 'X',
    modified_integrity: str = 'X',
    modified_availability: str = 'X',
    confidentiality_requirement: str = 'X',
    integrity_requirement: str = 'X',
    availability_requirement: str = 'X'
) -> dict[str, float]:
    """Calculate CVSS environmental score with all intermediate values."""
    calc = EnvironmentalScoreCalculator(
        attack_vector, attack_complexity, privileges_required,
        user_interaction, scope, confidentiality, integrity, availability,
        exploit_code_maturity, remediation_level, report_confidence,
        modified_attack_vector, modified_attack_complexity,
        modified_privileges_required, modified_user_interaction,
        modified_scope, modified_confidentiality, modified_integrity, modified_availability,
        confidentiality_requirement, integrity_requirement, availability_requirement
    )
    return calc.get_all_scores()


def parse_vector_string(vector: str) -> dict[str, str]:
    """
    Parse a CVSS 3.1 vector string into metric dictionary.

    Args:
        vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    Returns:
        Dictionary of metric abbreviations to values
    """
    result = {}

    # Remove CVSS prefix
    if vector.startswith('CVSS:'):
        parts = vector.split('/', 1)
        if len(parts) > 1:
            vector = parts[1]

    # Parse each metric
    for metric in vector.split('/'):
        if ':' in metric:
            key, value = metric.split(':', 1)
            result[key] = value.upper()

    return result


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == '__main__':
    # Example usage demonstrating all features
    print("=" * 70)
    print("CVSS 3.1 Calculator Examples")
    print("=" * 70)

    # Example 1: Base score calculation (Critical vulnerability)
    print("\n1. Base Score Example (Critical)")
    print("-" * 40)
    scores = calculate_cvss_base(
        attack_vector='N',
        attack_complexity='L',
        privileges_required='N',
        user_interaction='N',
        scope='U',
        confidentiality='H',
        integrity='H',
        availability='H'
    )
    for key, value in scores.items():
        print(f"  {key}: {value}")

    # Example 2: Temporal score calculation
    print("\n2. Temporal Score Example")
    print("-" * 40)
    scores = calculate_cvss_temporal(
        attack_vector='N',
        attack_complexity='L',
        privileges_required='N',
        user_interaction='N',
        scope='U',
        confidentiality='H',
        integrity='H',
        availability='H',
        exploit_code_maturity='H',
        remediation_level='O',
        report_confidence='C'
    )
    for key, value in scores.items():
        print(f"  {key}: {value}")

    # Example 3: Environmental score calculation
    print("\n3. Environmental Score Example")
    print("-" * 40)
    scores = calculate_cvss_environmental(
        attack_vector='N',
        attack_complexity='L',
        privileges_required='N',
        user_interaction='N',
        scope='U',
        confidentiality='H',
        integrity='H',
        availability='H',
        exploit_code_maturity='F',
        remediation_level='T',
        report_confidence='R',
        modified_attack_vector='A',
        modified_attack_complexity='X',
        modified_confidentiality='H',
        modified_integrity='H',
        modified_availability='H',
        confidentiality_requirement='H',
        integrity_requirement='M',
        availability_requirement='L'
    )
    for key, value in scores.items():
        print(f"  {key}: {value}")

    # Example 4: Vector string generation
    print("\n4. Vector String Generation")
    print("-" * 40)
    calc = EnvironmentalScoreCalculator(
        attack_vector='N', attack_complexity='L', privileges_required='N',
        user_interaction='N', scope='C', confidentiality='H',
        integrity='H', availability='H',
        exploit_code_maturity='H', remediation_level='O', report_confidence='C',
        modified_attack_vector='N', modified_confidentiality='H'
    )
    print(f"  Vector: {calc.get_vector_string()}")

    # Example 5: Parsing vector string
    print("\n5. Vector String Parsing")
    print("-" * 40)
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C"
    parsed = parse_vector_string(vector)
    for key, value in parsed.items():
        print(f"  {key}: {value}")
