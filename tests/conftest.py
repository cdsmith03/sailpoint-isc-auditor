"""
Shared pytest fixtures for sailpoint-isc-auditor tests.

Fixtures here are available to all test files automatically.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from auditor.models import (
    AuditResult,
    CollectionStatus,
    ControlFamily,
    CoverageConfidence,
    DetectorCoverage,
    Finding,
    FindingEvidence,
    HealthBand,
    RiskScore,
    Severity,
    Suppression,
    FamilyScore,
    TenantHealthScore,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def active_finding() -> Finding:
    """A normal active finding — not suppressed."""
    return Finding(
        finding_id="LI-01-abc123",
        detector_id="LI-01",
        family=ControlFamily.LI,
        title="Terminated identity with active accounts",
        severity=Severity.CRITICAL,
        evidence=FindingEvidence(
            affected_object_ids=["id-001"],
            affected_object_names=["john.smith@acme.com"],
            object_type="identity",
            why_fired="Identity is terminated but has 3 active accounts.",
            recommended_fix="Disable all active accounts immediately.",
            confidence=0.95,
        ),
        risk_score=RiskScore(impact=1.0, exploitability=0.9, governance_failure=0.85),
        suppressed=False,
    )


@pytest.fixture
def suppressed_finding() -> Finding:
    """A finding that has been suppressed with a ticket reference."""
    return Finding(
        finding_id="MI-06-def456",
        detector_id="MI-06",
        family=ControlFamily.MI,
        title="Service account outside naming policy",
        severity=Severity.MEDIUM,
        evidence=FindingEvidence(
            affected_object_ids=["svc-legacy-001"],
            affected_object_names=["svc-legacy-payments"],
            object_type="machine_identity",
            why_fired="Service account missing required naming prefix.",
            recommended_fix="Rename or migrate the account.",
            confidence=0.80,
        ),
        risk_score=RiskScore(impact=0.5, exploitability=0.4, governance_failure=0.6),
        suppressed=True,
        suppression=Suppression(
            detector_id="MI-06",
            object_id="svc-legacy-001",
            reason="Legacy system migration tracked in JIRA-4521",
            ticket="JIRA-4521",
            suppressed_at=_utcnow(),
        ),
    )


@pytest.fixture
def minimal_health_score() -> TenantHealthScore:
    """A minimal health score for use in tests that need one."""
    return TenantHealthScore(
        tenant_health=75.0,
        posture_score=80.0,
        band=HealthBand.STABLE,
        coverage_confidence=CoverageConfidence(
            score=0.75,
            score_display=75,
        ),
        family_scores={
            "MI": FamilyScore(family=ControlFamily.MI, score=75.0, weight=0.25),
            "LI": FamilyScore(family=ControlFamily.LI, score=75.0, weight=0.20),
            "AR": FamilyScore(family=ControlFamily.AR, score=75.0, weight=0.20),
            "IH": FamilyScore(family=ControlFamily.IH, score=75.0, weight=0.15),
            "GQ": FamilyScore(family=ControlFamily.GQ, score=75.0, weight=0.10),
            "CR": FamilyScore(family=ControlFamily.CR, score=75.0, weight=0.10),
        },
    )


@pytest.fixture
def minimal_audit_result(
    active_finding: Finding,
    suppressed_finding: Finding,
    minimal_health_score: TenantHealthScore,
) -> AuditResult:
    """A minimal AuditResult with one active and one suppressed finding."""
    return AuditResult(
        tenant_url="https://acme.identitynow.com",
        policy_pack="default",
        findings=[active_finding, suppressed_finding],
        health_score=minimal_health_score,
        detector_coverage=[
            DetectorCoverage(
                detector_id="LI-01",
                family=ControlFamily.LI,
                status=CollectionStatus.FULL,
                eligible_count=100,
                affected_count=1,
            ),
            DetectorCoverage(
                detector_id="MI-06",
                family=ControlFamily.MI,
                status=CollectionStatus.FULL,
                eligible_count=50,
                affected_count=1,
            ),
        ],
    )
