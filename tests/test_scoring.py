"""
Tests for auditor/scoring.py

Covers the full scoring pipeline:
  - RiskScore formula: impact × exploitability × governance_failure
  - RiskScore input clamping
  - FamilyScore severity counts
  - compute_tenant_health: family weights sum to 1.0
  - compute_tenant_health: coverage confidence adjustment applied
  - Health band assignment at boundary values
  - Critical conditions: fire on correct detector IDs
  - Critical conditions: do NOT fire when findings are absent

Closes #28
"""

from __future__ import annotations

import pytest

from auditor.models import (
    AuditResult,
    CollectionStatus,
    ControlFamily,
    CoverageConfidence,
    Finding,
    FindingEvidence,
    HealthBand,
    RiskScore,
    Severity,
)
from auditor.scoring import (
    CRITICAL_CONDITION_DETECTORS,
    compute_family_score,
    compute_tenant_health,
    detect_critical_conditions,
    score_finding,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    detector_id: str,
    severity: Severity = Severity.HIGH,
    suppressed: bool = False,
    object_id: str = "obj-001",
    source_data: dict | None = None,
) -> Finding:
    """Build a minimal Finding for testing."""
    return Finding(
        finding_id=f"{detector_id}-test",
        detector_id=detector_id,
        family=ControlFamily.MI,
        title=f"Test finding for {detector_id}",
        severity=severity,
        suppressed=suppressed,
        evidence=FindingEvidence(
            affected_object_ids=[object_id],
            affected_object_names=[object_id],
            why_fired="Test",
            recommended_fix="Test",
            collection_status=CollectionStatus.FULL,
            source_data=source_data or {},
        ),
    )


# ---------------------------------------------------------------------------
# RiskScore model
# ---------------------------------------------------------------------------

class TestRiskScore:
    """Tests for the RiskScore model and its normalized property."""

    def test_normalized_is_product_of_three_axes(self):
        """
        The normalized score must be impact × exploitability × governance_failure
        scaled to 0–100.
        """
        rs = RiskScore(impact=0.8, exploitability=0.5, governance_failure=0.6)
        expected = round(0.8 * 0.5 * 0.6 * 100, 1)
        assert rs.normalized == expected

    def test_all_ones_gives_100(self):
        """Maximum inputs should produce a score of 100."""
        rs = RiskScore(impact=1.0, exploitability=1.0, governance_failure=1.0)
        assert rs.normalized == 100.0

    def test_zero_impact_gives_zero(self):
        """Zero impact should collapse the entire score to 0."""
        rs = RiskScore(impact=0.0, exploitability=1.0, governance_failure=1.0)
        assert rs.normalized == 0.0

    def test_inputs_clamped_above_one(self):
        """Inputs above 1.0 must be clamped to 1.0."""
        rs = RiskScore(impact=2.0, exploitability=1.5, governance_failure=1.0)
        assert rs.impact <= 1.0
        assert rs.exploitability <= 1.0

    def test_inputs_clamped_below_zero(self):
        """Inputs below 0.0 must be clamped to 0.0."""
        rs = RiskScore(impact=-0.5, exploitability=-1.0, governance_failure=0.5)
        assert rs.impact >= 0.0
        assert rs.exploitability >= 0.0


# ---------------------------------------------------------------------------
# score_finding
# ---------------------------------------------------------------------------

class TestScoreFinding:
    """Tests for the score_finding() function."""

    def test_critical_finding_gets_high_impact(self):
        """Critical severity should produce impact=1.0."""
        finding = _make_finding("LI-01", severity=Severity.CRITICAL)
        scored = score_finding(finding)
        assert scored.risk_score is not None
        assert scored.risk_score.impact == 1.0

    def test_medium_finding_gets_lower_impact(self):
        """Medium severity should produce lower impact than critical."""
        finding = _make_finding("IH-05", severity=Severity.MEDIUM)
        scored = score_finding(finding)
        assert scored.risk_score.impact < 1.0
        assert scored.risk_score.impact > 0.0

    def test_enabled_account_raises_exploitability(self):
        """An enabled account should increase exploitability above baseline."""
        finding = _make_finding("IH-02", source_data={"enabled": True})
        scored = score_finding(finding)
        baseline = _make_finding("IH-02", source_data={})
        scored_baseline = score_finding(baseline)
        assert scored.risk_score.exploitability > scored_baseline.risk_score.exploitability

    def test_no_owner_raises_governance_failure(self):
        """Missing owner should increase governance_failure above baseline."""
        finding = _make_finding("MI-01", source_data={"has_owner": False})
        scored = score_finding(finding)
        baseline = _make_finding("MI-01", source_data={"has_owner": True})
        scored_baseline = score_finding(baseline)
        assert scored.risk_score.governance_failure > scored_baseline.risk_score.governance_failure

    def test_risk_score_attached_to_finding(self):
        """score_finding() must attach a RiskScore to the finding."""
        finding = _make_finding("AR-01")
        assert finding.risk_score is None
        score_finding(finding)
        assert finding.risk_score is not None

    def test_normalized_score_within_bounds(self):
        """Normalized risk score must always be between 0 and 100."""
        for sev in Severity:
            finding = _make_finding("MI-01", severity=sev, source_data={
                "enabled": True,
                "privileged": True,
                "no_mfa": True,
                "has_owner": False,
                "ever_reviewed": False,
            })
            score_finding(finding)
            assert 0.0 <= finding.risk_score.normalized <= 100.0


# ---------------------------------------------------------------------------
# FamilyScore — severity counts
# ---------------------------------------------------------------------------

class TestFamilyScoreSeverityCounts:
    """Tests that FamilyScore correctly counts critical/high/medium findings."""

    def test_high_count_populated_correctly(self):
        """high_count must reflect the number of active HIGH findings."""
        findings = [
            _make_finding("MI-01", severity=Severity.HIGH),
            _make_finding("MI-02", severity=Severity.HIGH),
            _make_finding("MI-03", severity=Severity.CRITICAL),
        ]
        findings_by_detector = {
            "MI-01": [findings[0]],
            "MI-02": [findings[1]],
            "MI-03": [findings[2]],
        }
        fs = compute_family_score(ControlFamily.MI, findings_by_detector, {"MI-01": 10, "MI-02": 10, "MI-03": 10})
        assert fs.high_count == 2

    def test_medium_count_populated_correctly(self):
        """medium_count must reflect the number of active MEDIUM findings."""
        findings = [
            _make_finding("MI-01", severity=Severity.MEDIUM),
            _make_finding("MI-02", severity=Severity.MEDIUM),
        ]
        findings_by_detector = {
            "MI-01": [findings[0]],
            "MI-02": [findings[1]],
        }
        fs = compute_family_score(ControlFamily.MI, findings_by_detector, {"MI-01": 10, "MI-02": 10})
        assert fs.medium_count == 2

    def test_suppressed_findings_not_counted(self):
        """Suppressed findings must not appear in severity counts."""
        active     = _make_finding("MI-01", severity=Severity.CRITICAL)
        suppressed = _make_finding("MI-02", severity=Severity.CRITICAL, suppressed=True)
        findings_by_detector = {
            "MI-01": [active],
            "MI-02": [suppressed],
        }
        fs = compute_family_score(
            ControlFamily.MI, findings_by_detector, {"MI-01": 10, "MI-02": 10}
        )
        assert fs.critical_count == 1

    def test_no_findings_gives_perfect_score(self):
        """A family with no findings should score 100.0."""
        fs = compute_family_score(ControlFamily.GQ, {}, {})
        assert fs.score == 100.0
        assert fs.finding_count == 0
        assert fs.critical_count == 0
        assert fs.high_count == 0
        assert fs.medium_count == 0


# ---------------------------------------------------------------------------
# compute_tenant_health
# ---------------------------------------------------------------------------

class TestComputeTenantHealth:
    """Tests for the main compute_tenant_health() entry point."""

    def test_family_weights_sum_to_one(self):
        """
        The family weights used in posture calculation must sum to 1.0.
        If weights don't sum to 1.0, the posture score is miscalibrated.
        """
        result = AuditResult(tenant_url="https://acme.identitynow.com", policy_pack="default")
        health = compute_tenant_health(result, {})
        total_weight = sum(fs.weight for fs in health.family_scores.values())
        assert abs(total_weight - 1.0) < 0.001, (
            f"Family weights sum to {total_weight}, expected 1.0. "
            "Scoring is miscalibrated."
        )

    def test_no_findings_gives_high_score(self):
        """A clean environment with no findings should score near 100."""
        result = AuditResult(tenant_url="https://acme.identitynow.com", policy_pack="default")
        # Set coverage confidence signals to perfect
        result.health_score.coverage_confidence = CoverageConfidence(
            critical_sources_connected=1.0,
            sources_recently_aggregated=1.0,
            entitlements_with_owners=1.0,
            machine_identities_visible=1.0,
            high_risk_apps_governed=1.0,
            lifecycle_populations_covered=1.0,
            certification_coverage=1.0,
        )
        health = compute_tenant_health(result, {})
        assert health.tenant_health >= 90.0

    def test_coverage_confidence_applied_to_posture(self):
        """
        tenant_health = posture × (0.80 + 0.20 × coverage_confidence).
        Low coverage must reduce the health score below the raw posture score.
        """
        result = AuditResult(tenant_url="https://acme.identitynow.com", policy_pack="default")
        result.health_score.coverage_confidence = CoverageConfidence(
            critical_sources_connected=0.0,
            sources_recently_aggregated=0.0,
            entitlements_with_owners=0.0,
            machine_identities_visible=0.0,
            high_risk_apps_governed=0.0,
            lifecycle_populations_covered=0.0,
            certification_coverage=0.0,
        )
        health = compute_tenant_health(result, {})
        # With zero coverage, tenant_health = posture × 0.80
        # So tenant_health must be lower than posture_score
        assert health.tenant_health <= health.posture_score

    def test_health_score_bounded_0_to_100(self):
        """tenant_health must always be between 0 and 100."""
        result = AuditResult(tenant_url="https://acme.identitynow.com", policy_pack="default")
        health = compute_tenant_health(result, {})
        assert 0.0 <= health.tenant_health <= 100.0


# ---------------------------------------------------------------------------
# Health band assignment
# ---------------------------------------------------------------------------

class TestHealthBandAssignment:
    """Tests that health bands are assigned at the correct boundary values."""

    def _health_at(self, score: float) -> HealthBand:
        from auditor.models import TenantHealthScore, CoverageConfidence
        h = TenantHealthScore(
            tenant_health=score,
            posture_score=score,
            coverage_confidence=CoverageConfidence(),
        )
        h.compute_band()
        return h.band

    def test_90_is_healthy(self):
        assert self._health_at(90.0) == HealthBand.HEALTHY

    def test_89_is_stable(self):
        assert self._health_at(89.0) == HealthBand.STABLE

    def test_75_is_stable(self):
        assert self._health_at(75.0) == HealthBand.STABLE

    def test_74_is_exposed(self):
        assert self._health_at(74.0) == HealthBand.EXPOSED

    def test_60_is_exposed(self):
        assert self._health_at(60.0) == HealthBand.EXPOSED

    def test_59_is_high_risk(self):
        assert self._health_at(59.0) == HealthBand.HIGH_RISK

    def test_40_is_high_risk(self):
        assert self._health_at(40.0) == HealthBand.HIGH_RISK

    def test_39_is_critical(self):
        assert self._health_at(39.0) == HealthBand.CRITICAL

    def test_100_is_healthy(self):
        assert self._health_at(100.0) == HealthBand.HEALTHY

    def test_0_is_critical(self):
        assert self._health_at(0.0) == HealthBand.CRITICAL


# ---------------------------------------------------------------------------
# Critical conditions
# ---------------------------------------------------------------------------

class TestCriticalConditions:
    """
    Tests that critical conditions fire on the correct detector IDs
    and do NOT fire when findings are absent.
    """

    def test_li_01_fires_critical_condition(self):
        """LI-01 (terminated with active accounts) must trigger a critical condition."""
        finding = _make_finding("LI-01", severity=Severity.CRITICAL)
        conditions = detect_critical_conditions([finding])
        detector_ids = [c.detector_id for c in conditions]
        assert "LI-01" in detector_ids

    def test_ar_01_fires_critical_condition(self):
        """AR-01 (active SOD violation) must trigger a critical condition."""
        finding = _make_finding("AR-01", severity=Severity.CRITICAL)
        conditions = detect_critical_conditions([finding])
        detector_ids = [c.detector_id for c in conditions]
        assert "AR-01" in detector_ids

    def test_all_critical_detectors_fire(self):
        """Every detector in CRITICAL_CONDITION_DETECTORS must fire when present."""
        for det_id in CRITICAL_CONDITION_DETECTORS:
            finding = _make_finding(det_id, severity=Severity.CRITICAL)
            conditions = detect_critical_conditions([finding])
            detector_ids = [c.detector_id for c in conditions]
            assert det_id in detector_ids, (
                f"Expected critical condition for {det_id} but it did not fire."
            )

    def test_no_findings_no_critical_conditions(self):
        """No findings must produce no critical conditions."""
        conditions = detect_critical_conditions([])
        assert conditions == []

    def test_suppressed_findings_do_not_fire_critical_conditions(self):
        """
        A suppressed LI-01 finding must NOT trigger a critical condition.
        Suppressions are user-acknowledged — they should silence the banner.
        """
        finding = _make_finding("LI-01", severity=Severity.CRITICAL, suppressed=True)
        conditions = detect_critical_conditions([finding])
        assert conditions == []

    def test_non_critical_detector_does_not_fire(self):
        """A finding from IH-05 (non-critical detector) must not trigger a banner."""
        finding = _make_finding("IH-05", severity=Severity.MEDIUM)
        conditions = detect_critical_conditions([finding])
        assert conditions == []

    def test_critical_condition_includes_finding_ids(self):
        """The critical condition record must include the finding IDs that triggered it."""
        finding = _make_finding("LI-01", severity=Severity.CRITICAL)
        conditions = detect_critical_conditions([finding])
        li01 = next(c for c in conditions if c.detector_id == "LI-01")
        assert finding.finding_id in li01.finding_ids
