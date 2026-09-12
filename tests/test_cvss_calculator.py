from pathlib import Path
"""
Unit tests for CVSS Calculator.

Tests cover base score calculation, attack vector scoring,
temporal adjustment, and environmental score calculation.
"""

import importlib.util

import pytest

# Load cvss_calculator module directly to avoid hooks_scripts/__init__.py dependencies
_cvss_path = Path(__file__).resolve().parent.parent / "hooks" / "hooks_scripts" / "cvss_calculator.py"
if not _cvss_path.exists():
    _cvss_path = Path(__file__).resolve().parent.parent / "hooks_scripts" / "cvss_calculator.py"
spec = importlib.util.spec_from_file_location("cvss_calculator", str(_cvss_path))
cvss_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cvss_module)

# Extract classes and functions for use in tests
CVSSCalculator = cvss_module.CVSSCalculator
TemporalScoreCalculator = cvss_module.TemporalScoreCalculator
EnvironmentalScoreCalculator = cvss_module.EnvironmentalScoreCalculator
calculate_cvss_base = cvss_module.calculate_cvss_base
calculate_cvss_temporal = cvss_module.calculate_cvss_temporal
calculate_cvss_environmental = cvss_module.calculate_cvss_environmental
get_severity = cvss_module.get_severity
ATTACK_VECTOR = cvss_module.ATTACK_VECTOR


class TestBaseScoreCalculation:
    """Tests for CVSS base score calculation."""

    def test_base_score_calculation(self):
        """Test CVSS base score calculation with known vectors."""
        # Test case: Critical vulnerability (Network, Low complexity, no privileges)
        calc = CVSSCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H'
        )
        base_score = calc.calculate_base_score()

        # Critical severity should have base score between 9.0 and 10.0
        assert 9.0 <= base_score <= 10.0, f"Expected critical score, got {base_score}"
        assert calc.get_all_scores()['severity'] == 'Critical'

    def test_base_score_low_impact(self):
        """Test base score calculation with low impact metrics."""
        calc = CVSSCalculator(
            attack_vector='L',
            attack_complexity='H',
            privileges_required='H',
            user_interaction='R',
            scope='U',
            confidentiality='L',
            integrity='L',
            availability='L'
        )
        base_score = calc.calculate_base_score()

        # Low confidentiality/integrity/availability impact should give low score
        assert 0.0 <= base_score <= 3.9, f"Expected low score, got {base_score}"
        assert calc.get_all_scores()['severity'] == 'Low'

    def test_base_score_medium_impact(self):
        """Test base score calculation with medium impact."""
        calc = CVSSCalculator(
            attack_vector='A',
            attack_complexity='L',
            privileges_required='L',
            user_interaction='N',
            scope='U',
            confidentiality='L',
            integrity='L',
            availability='L'
        )
        base_score = calc.calculate_base_score()

        # Medium impact should produce medium severity
        assert 4.0 <= base_score <= 6.9, f"Expected medium score, got {base_score}"
        assert calc.get_all_scores()['severity'] == 'Medium'

    def test_base_score_unchanged_scope(self):
        """Test base score with unchanged scope."""
        calc = CVSSCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='L',
            availability='N'
        )
        impact = calc.calculate_impact()
        iss = calc.calculate_impact_sub_score()

        # Verify impact sub-score calculation
        assert 0 < iss < 1, "ISS should be between 0 and 1"
        # With unchanged scope: Impact = 6.42 * ISS
        expected_impact = 6.42 * iss
        assert abs(impact - expected_impact) < 0.01

    def test_base_score_changed_scope(self):
        """Test base score with changed scope."""
        calc = CVSSCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='L',
            user_interaction='N',
            scope='C',
            confidentiality='H',
            integrity='H',
            availability='H'
        )
        base_score = calc.calculate_base_score()

        # Base score should be a valid value between 0 and 10
        assert 0.0 <= base_score <= 10.0, f"Base score should be valid, got {base_score}"

    def test_impact_sub_score_calculation(self):
        """Test ISS (Impact Sub-Score) calculation."""
        calc = CVSSCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H'
        )
        iss = calc.calculate_impact_sub_score()

        # ISS = 1 - ((1 - Conf) * (1 - Integ) * (1 - Avail))
        # H = 0.56
        # Expected: 1 - (0.44 * 0.44 * 0.44) = 1 - 0.0852 = 0.9148
        expected_iss = 1 - ((1 - 0.56) ** 3)
        assert abs(iss - expected_iss) < 0.001, f"Expected ISS {expected_iss}, got {iss}"

    def test_exploitability_calculation(self):
        """Test exploitability score calculation."""
        calc = CVSSCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H'
        )
        exploitability = calc.calculate_exploitability()

        # Exploitability = 8.22 * AV * AC * PR * UI
        # N=0.85, L=0.77, N=0.85, N=0.85
        expected = 8.22 * 0.85 * 0.77 * 0.85 * 0.85
        assert abs(exploitability - expected) < 0.01, f"Expected {expected}, got {exploitability}"

    def test_vector_string_generation(self):
        """Test CVSS vector string generation."""
        calc = CVSSCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H'
        )
        vector = calc.get_vector_string()

        assert vector.startswith('CVSS:3.1/')
        assert 'AV:N' in vector
        assert 'AC:L' in vector
        assert 'PR:N' in vector
        assert 'S:U' in vector
        assert 'C:H' in vector
        assert 'I:H' in vector
        assert 'A:H' in vector

    def test_invalid_metric_raises_error(self):
        """Test that invalid metrics raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            CVSSCalculator(
                attack_vector='X',  # Invalid
                attack_complexity='L',
                privileges_required='N',
                user_interaction='N',
                scope='U',
                confidentiality='H',
                integrity='H',
                availability='H'
            )
        assert 'Invalid Attack Vector' in str(exc_info.value)


class TestAttackVectorScoring:
    """Tests for Attack Vector metric scoring."""

    def test_attack_vector_scoring(self):
        """Test that all attack vector values produce correct weights."""
        # Network - highest weight (0.85)
        calc_net = CVSSCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H'
        )
        net_exploitability = calc_net.calculate_exploitability()

        # Adjacent - medium-high weight (0.62)
        calc_adj = CVSSCalculator(
            attack_vector='A',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H'
        )
        adj_exploitability = calc_adj.calculate_exploitability()

        # Local - lower weight (0.55)
        calc_loc = CVSSCalculator(
            attack_vector='L',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H'
        )
        loc_exploitability = calc_loc.calculate_exploitability()

        # Physical - lowest weight (0.20)
        calc_phys = CVSSCalculator(
            attack_vector='P',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H'
        )
        phys_exploitability = calc_phys.calculate_exploitability()

        # Verify relative ordering: Network > Adjacent > Local > Physical
        assert net_exploitability > adj_exploitability, \
            f"Network ({net_exploitability}) should be > Adjacent ({adj_exploitability})"
        assert adj_exploitability > loc_exploitability, \
            f"Adjacent ({adj_exploitability}) should be > Local ({loc_exploitability})"
        assert loc_exploitability > phys_exploitability, \
            f"Local ({loc_exploitability}) should be > Physical ({phys_exploitability})"

    def test_attack_vector_weights_defined(self):
        """Test that all attack vector weights are correctly defined."""
        assert ATTACK_VECTOR['N'].weight == 0.85
        assert ATTACK_VECTOR['A'].weight == 0.62
        assert ATTACK_VECTOR['L'].weight == 0.55
        assert ATTACK_VECTOR['P'].weight == 0.20

    def test_attack_vector_network_highest_score(self):
        """Test that Network attack vector produces highest base score."""
        calc_n = CVSSCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H'
        )

        calc_p = CVSSCalculator(
            attack_vector='P',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H'
        )

        # Network should produce higher base score than Physical
        assert calc_n.calculate_base_score() > calc_p.calculate_base_score()

    def test_case_insensitive_attack_vector(self):
        """Test that attack vector accepts lowercase input."""
        calc_lower = CVSSCalculator(
            attack_vector='n',
            attack_complexity='l',
            privileges_required='n',
            user_interaction='n',
            scope='u',
            confidentiality='h',
            integrity='h',
            availability='h'
        )

        calc_upper = CVSSCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H'
        )

        # Both should produce identical scores
        assert calc_lower.calculate_base_score() == calc_upper.calculate_base_score()


class TestTemporalAdjustment:
    """Tests for CVSS temporal score adjustment."""

    def test_temporal_adjustment(self):
        """Test temporal score calculation with various temporal metrics."""
        # Base case with default temporal values (all X = 1.0)
        base_calc = TemporalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H',
            exploit_code_maturity='X',
            remediation_level='X',
            report_confidence='X'
        )

        # Temporal with all max values (should not change score)
        max_calc = TemporalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H',
            exploit_code_maturity='H',
            remediation_level='U',
            report_confidence='C'
        )

        # Temporal with all min values (should reduce score)
        min_calc = TemporalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H',
            exploit_code_maturity='U',
            remediation_level='O',
            report_confidence='U'
        )

        # All X should equal High temporal
        assert base_calc.calculate_temporal_score() == max_calc.calculate_temporal_score()

        # Min temporal should be less than max temporal
        assert min_calc.calculate_temporal_score() < max_calc.calculate_temporal_score()

    def test_temporal_multiplier_calculation(self):
        """Test temporal multiplier calculation."""
        calc = TemporalScoreCalculator(
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
            report_confidence='R'
        )

        temporal_mult = calc._get_temporal_multiplier()

        # E=F(0.97) * RL=T(0.96) * RC=R(0.96)
        expected = 0.97 * 0.96 * 0.96
        assert abs(temporal_mult - expected) < 0.001, \
            f"Expected {expected}, got {temporal_mult}"

    def test_temporal_score_roundtrip(self):
        """Test temporal score produces valid result."""
        calc = TemporalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H',
            exploit_code_maturity='P',
            remediation_level='W',
            report_confidence='R'
        )

        temporal_score = calc.calculate_temporal_score()

        # Score should be between 0 and 10
        assert 0.0 <= temporal_score <= 10.0, \
            f"Temporal score {temporal_score} out of range"

    def test_temporal_vector_string(self):
        """Test temporal vector string includes temporal metrics."""
        calc = TemporalScoreCalculator(
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

        vector = calc.get_vector_string()

        assert 'E:H' in vector
        assert 'RL:O' in vector
        assert 'RC:C' in vector

    def test_temporal_invalid_metric_raises_error(self):
        """Test that invalid temporal metrics raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            TemporalScoreCalculator(
                attack_vector='N',
                attack_complexity='L',
                privileges_required='N',
                user_interaction='N',
                scope='U',
                confidentiality='H',
                integrity='H',
                availability='H',
                exploit_code_maturity='Z',  # Invalid
                remediation_level='X',
                report_confidence='X'
            )
        assert 'Invalid Exploit Code Maturity' in str(exc_info.value)

    def test_temporal_convenience_function(self):
        """Test convenience function for temporal calculation."""
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

        assert 'temporal_score' in scores
        assert 'base_score' in scores
        assert 0.0 <= scores['temporal_score'] <= 10.0


class TestEnvironmentalScore:
    """Tests for CVSS environmental score calculation."""

    def test_environmental_score(self):
        """Test environmental score calculation with modified metrics."""
        calc = EnvironmentalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H',
            exploit_code_maturity='X',
            remediation_level='X',
            report_confidence='X',
            modified_attack_vector='A',  # Changed from N to A
            modified_attack_complexity='X',
            modified_privileges_required='X',
            modified_user_interaction='X',
            modified_confidentiality='X',
            modified_integrity='X',
            modified_availability='X',
            confidentiality_requirement='H',
            integrity_requirement='M',
            availability_requirement='L'
        )

        env_score = calc.calculate_environmental_score()

        # Environmental score should be valid
        assert 0.0 <= env_score <= 10.0, f"Environmental score {env_score} out of range"

    def test_modified_attack_vector_affects_score(self):
        """Test that modified attack vector changes the environmental score."""
        # With Network (most severe)
        calc_net = EnvironmentalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H',
            modified_attack_vector='N'
        )

        # With Physical (least severe)
        calc_phys = EnvironmentalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H',
            modified_attack_vector='P'
        )

        # Network modifier should produce higher score than Physical
        assert calc_net.calculate_environmental_score() > calc_phys.calculate_environmental_score()

    def test_security_requirements_affect_score(self):
        """Test that security requirements modify the environmental score."""
        # High requirements
        calc_high = EnvironmentalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H',
            confidentiality_requirement='H',
            integrity_requirement='H',
            availability_requirement='H'
        )

        # Low requirements
        calc_low = EnvironmentalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H',
            confidentiality_requirement='L',
            integrity_requirement='L',
            availability_requirement='L'
        )

        # High requirements should produce higher score than low
        assert calc_high.calculate_environmental_score() >= calc_low.calculate_environmental_score()

    def test_modified_impact_sub_score_cap(self):
        """Test that modified ISS is capped at 0.915."""
        calc = EnvironmentalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H',
            confidentiality_requirement='H',  # CR = 1.5
            integrity_requirement='H',  # IR = 1.5
            availability_requirement='H'  # AR = 1.5
        )

        miss = calc.calculate_modified_impact_sub_score()

        # Modified ISS should be capped at 0.915
        assert miss <= 0.915, f"Modified ISS {miss} exceeds cap of 0.915"

    def test_not_defined_uses_base_value(self):
        """Test that X (Not Defined) uses base metric value."""
        calc = EnvironmentalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H',
            modified_attack_vector='X',  # Should use base N
        )

        # When modified is X, effective AV should be N (0.85)
        effective_av = calc._get_effective_metric('av')
        assert effective_av == 'N', f"Expected N, got {effective_av}"

    def test_environmental_vector_string(self):
        """Test environmental vector string includes all environmental metrics."""
        calc = EnvironmentalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='C',
            confidentiality='H',
            integrity='H',
            availability='H',
            modified_attack_vector='A',
            modified_attack_complexity='H',
            modified_privileges_required='L',
            modified_confidentiality='H',
            confidentiality_requirement='H',
            integrity_requirement='M',
            availability_requirement='L'
        )

        vector = calc.get_vector_string()

        assert 'MAV:A' in vector
        assert 'MAC:H' in vector
        assert 'CR:H' in vector
        assert 'IR:M' in vector
        assert 'AR:L' in vector

    def test_environmental_invalid_metric_raises_error(self):
        """Test that invalid environmental metrics raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            EnvironmentalScoreCalculator(
                attack_vector='N',
                attack_complexity='L',
                privileges_required='N',
                user_interaction='N',
                scope='U',
                confidentiality='H',
                integrity='H',
                availability='H',
                modified_attack_vector='Z'  # Invalid
            )
        assert 'Invalid Modified Attack Vector' in str(exc_info.value)

    def test_environmental_convenience_function(self):
        """Test convenience function for environmental calculation."""
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
            confidentiality_requirement='H',
            integrity_requirement='H',
            availability_requirement='H'
        )

        assert 'environmental_score' in scores
        assert 'base_score' in scores
        assert 'temporal_score' in scores
        assert 0.0 <= scores['environmental_score'] <= 10.0

    def test_scope_changed_privileges_required(self):
        """Test privileges required weights differ when scope is changed."""
        calc_unchanged = EnvironmentalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='L',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H'
        )

        calc_changed = EnvironmentalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='L',
            user_interaction='N',
            scope='C',
            confidentiality='H',
            integrity='H',
            availability='H'
        )

        # Low PR weight differs: Unchanged=0.62, Changed=0.68
        unchanged_pr = calc_unchanged._get_modified_privileges_weight()
        changed_pr = calc_changed._get_modified_privileges_weight()

        assert unchanged_pr == 0.62, f"Unchanged scope PR should be 0.62, got {unchanged_pr}"
        assert changed_pr == 0.68, f"Changed scope PR should be 0.68, got {changed_pr}"


class TestSeverityRatings:
    """Tests for severity rating functions."""

    def test_severity_none(self):
        """Test severity rating for score 0.0."""
        severity = get_severity(0.0)
        assert severity['name'] == 'None'
        assert severity['abbreviation'] == 'N'

    def test_severity_low(self):
        """Test severity rating for low scores."""
        severity = get_severity(3.5)
        assert severity['name'] == 'Low'
        assert severity['abbreviation'] == 'L'

    def test_severity_medium(self):
        """Test severity rating for medium scores."""
        severity = get_severity(6.5)
        assert severity['name'] == 'Medium'
        assert severity['abbreviation'] == 'M'

    def test_severity_high(self):
        """Test severity rating for high scores."""
        severity = get_severity(8.0)
        assert severity['name'] == 'High'
        assert severity['abbreviation'] == 'H'

    def test_severity_critical(self):
        """Test severity rating for critical scores."""
        severity = get_severity(9.5)
        assert severity['name'] == 'Critical'
        assert severity['abbreviation'] == 'C'


class TestConvenienceFunctions:
    """Tests for convenience calculation functions."""

    def test_calculate_cvss_base(self):
        """Test base score convenience function."""
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

        assert 'base_score' in scores
        assert 'impact_sub_score' in scores
        assert 'impact' in scores
        assert 'exploitability' in scores
        assert 'severity' in scores
        assert 0.0 <= scores['base_score'] <= 10.0

    def test_calculate_cvss_base_all_metrics(self):
        """Test that all expected metrics are returned."""
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

        expected_keys = {
            'base_score', 'impact_sub_score', 'impact',
            'exploitability', 'severity'
        }
        assert set(scores.keys()) == expected_keys


class TestCVSS31RobustnessAndAdversarial:
    """Adversarial, null-safety, and official standard validation tests."""

    def test_null_metric_raises_value_error(self):
        """Test that None metric raises ValueError rather than AttributeError."""
        with pytest.raises(ValueError):
            CVSSCalculator(
                attack_vector=None,
                attack_complexity='L',
                privileges_required='N',
                user_interaction='N',
                scope='U',
                confidentiality='H',
                integrity='H',
                availability='H'
            )

    def test_modified_scope_privileges_required(self):
        """Test that modified_scope='C' overrides base scope='U' for PR weight."""
        calc = EnvironmentalScoreCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='L',
            user_interaction='N',
            scope='U',
            confidentiality='H',
            integrity='H',
            availability='H',
            modified_scope='C'
        )
        assert calc._get_modified_privileges_weight() == 0.68

    def test_invalid_modified_scope_raises_error(self):
        """Test that invalid modified_scope raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            EnvironmentalScoreCalculator(
                attack_vector='N',
                attack_complexity='L',
                privileges_required='N',
                user_interaction='N',
                scope='U',
                confidentiality='H',
                integrity='H',
                availability='H',
                modified_scope='Z'
            )
        assert "Invalid Modified Scope" in str(exc_info.value)

    def test_severity_boundary_and_edge_cases(self):
        """Test severity scale on boundaries, float artifacts, and out-of-range inputs."""
        assert get_severity(3.95)['name'] == 'Medium'
        assert get_severity(6.91)['name'] == 'High'
        assert get_severity(-1.0)['name'] == 'Unknown'
        assert get_severity(11.0)['name'] == 'Unknown'
        assert get_severity(float('nan'))['name'] == 'Unknown'
        assert get_severity("invalid")['name'] == 'Unknown'

    def test_official_first_cvss31_vectors(self):
        """Test official FIRST CVSS v3.1 standard vectors."""
        # CVE-2018-0114: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N -> Base Score 8.6
        cve_86 = CVSSCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='C',
            confidentiality='H',
            integrity='N',
            availability='N'
        )
        assert cve_86.calculate_base_score() == 8.6

        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H -> Base Score 10.0
        cve_10 = CVSSCalculator(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='C',
            confidentiality='H',
            integrity='H',
            availability='H'
        )
        assert cve_10.calculate_base_score() == 10.0
