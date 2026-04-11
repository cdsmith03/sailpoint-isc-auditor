"""
Scoring engine for sailpoint-isc-auditor.

Implements the full scoring model from the design spec:

  Step 1: Score each finding
          risk = impact × exploitability × governance_failure

  Step 2: Roll up into detector scores
          detector_score = 100 - (weight × normalized_exposure × severity_multiplier)

  Step 3: Roll up into family scores (weighted average of detector scores)

  Step 4: Compute posture score
          posture = Σ(family_score × family_weight)

  Step 5: Apply coverage confidence
          tenant_health = posture × (0.80 + 0.20 × coverage_confidence)

  Critical conditions: applied AFTER scoring as a separate banner.
  "Green score, red reality" prevention.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from .models import (
    AuditResult,
    ControlFamily,
    CriticalCondition,
    FamilyScore,
    Finding,
    HealthBand,
    RiskScore,
    Severity,
    TenantHealthScore,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity weights (used in detector penalty calculation)
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 1.00,
    Severity.HIGH:     0.70,
    Severity.MEDIUM:   0.40,
    Severity.LOW:      0.15,
    Severity.INFO:     0.05,
}

# ---------------------------------------------------------------------------
# Detector weights within each family
# Higher = more penalty when this detector fires
# ---------------------------------------------------------------------------

DETECTOR_WEIGHTS: dict[str, float] = {
    # Machine & Privileged Identity
    "MI-01": 1.00,  # No owner — worst possible for machine identity
    "MI-02": 1.00,  # Privileged machine identity
    "MI-03": 0.75,  # Dormant but enabled
    "MI-04": 0.75,  # Shared privileged account
    "MI-05": 1.00,  # Break-glass with no controls
    "MI-06": 0.35,  # Policy/naming violation
    "MI-07": 0.35,  # Never reviewed

    # Identity Hygiene
    "IH-01": 1.00,  # Orphaned account
    "IH-02": 0.70,  # Stale enabled
    "IH-03": 0.70,  # Disabled/active mismatch
    "IH-04": 0.60,  # Duplicate identity
    "IH-05": 0.30,  # Missing attributes
    "IH-06": 0.25,  # Stale aggregation

    # Lifecycle Integrity
    "LI-01": 1.00,  # Terminated with active accounts
    "LI-02": 1.00,  # Terminated with privileged access
    "LI-03": 0.70,  # Mover retained stale access
    "LI-04": 0.35,  # Joiner gap
    "LI-05": 1.00,  # Non-employee past end date
    "LI-06": 0.65,  # Status mismatch

    # Access Risk
    "AR-01": 1.00,  # Active SOD violation
    "AR-02": 0.80,  # Toxic combo (informal)
    "AR-03": 0.70,  # Peer group outlier
    "AR-04": 0.30,  # Direct entitlement drift
    "AR-05": 0.60,  # Role entitlement bloat
    "AR-06": 1.00,  # Sensitive access, broad population
    "AR-07": 0.25,  # Redundant paths

    # Governance Quality
    "GQ-01": 0.70,  # Overdue campaign
    "GQ-02": 0.70,  # Low coverage on high-risk access
    "GQ-03": 0.70,  # Rubber-stamp pattern
    "GQ-04": 0.70,  # Unowned object
    "GQ-05": 0.40,  # Weak governance group
    "GQ-06": 0.40,  # Self/conflicted review
    "GQ-07": 0.25,  # Missing context
    "GQ-08": 0.25,  # Blind spot (informational)

    # Coverage & Reconciliation
    "CR-01": 0.70,  # Source with no owner
    "CR-02": 0.30,  # Stale aggregation
    "CR-03": 0.65,  # Stuck provisioning
    "CR-04": 1.00,  # Deprovisioning not completed — critical
    "CR-05": 1.00,  # Revoked but still present — critical
    "CR-06": 0.65,  # Disconnected hot spot
    "CR-07": 0.35,  # Low policy attachment
    "CR-08": 0.35,  # Abnormal ratios
}

# Max penalty a single detector can contribute to its family score (prevents runaway)
MAX_DETECTOR_PENALTY = 40.0

# Detectors that trigger a critical condition banner regardless of overall score
CRITICAL_CONDITION_DETECTORS = {
    "LI-01": "Terminated identity with active accounts",
    "LI-02": "Terminated identity with privileged access",
    "AR-01": "Active SOD violation",
    "AR-06": "Sensitive access held by broad population",
    "MI-05": "Break-glass account with no control evidence",
    "CR-04": "Deprovisioning requested but not completed",
    "CR-05": "Revoked in ISC, still present in target system",
}


# ---------------------------------------------------------------------------
# Finding-level risk score
# ---------------------------------------------------------------------------

def score_finding(finding: Finding) -> Finding:
    """
    Compute and attach a RiskScore to a finding.

    impact             — how valuable/dangerous is this object?
    exploitability     — how easy is it to abuse right now?
    governance_failure — how badly did controls fail?
    """
    sev = finding.severity
    ev  = finding.evidence

    # Impact: driven by object type and severity
    impact_map = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH:     0.75,
        Severity.MEDIUM:   0.45,
        Severity.LOW:      0.20,
        Severity.INFO:     0.05,
    }
    impact = impact_map[sev]

    # Exploitability: is the account/object in an exploitable state?
    exploitability = 0.5   # default mid-range
    if ev.source_data.get("enabled") is True:
        exploitability += 0.3
    if ev.source_data.get("privileged") is True:
        exploitability += 0.2
    if ev.source_data.get("no_mfa") is True:
        exploitability += 0.15
    if ev.source_data.get("externally_reachable") is True:
        exploitability += 0.1
    exploitability = min(exploitability, 1.0)

    # Governance failure: how badly did controls fail?
    gov_failure = 0.4   # default — some failure (otherwise we wouldn't be here)
    if not ev.source_data.get("has_owner"):
        gov_failure += 0.25
    if not ev.source_data.get("ever_reviewed"):
        gov_failure += 0.20
    if ev.source_data.get("deprovisioning_failed") is True:
        gov_failure += 0.20
    if ev.source_data.get("drift_confirmed") is True:
        gov_failure += 0.15
    gov_failure = min(gov_failure, 1.0)

    finding.risk_score = RiskScore(
        impact=impact,
        exploitability=exploitability,
        governance_failure=gov_failure,
    )
    return finding


# ---------------------------------------------------------------------------
# Detector-level penalty
# Normalized by eligible population so large tenants aren't unfairly penalized
# ---------------------------------------------------------------------------

def compute_detector_penalty(
    detector_id: str,
    findings: list[Finding],
    eligible_count: int,
) -> float:
    """
    detector_penalty = detector_weight × normalized_exposure × severity_multiplier

    Capped at MAX_DETECTOR_PENALTY so one bad detector can't destroy the whole score.
    """
    if eligible_count == 0 or not findings:
        return 0.0

    weight = DETECTOR_WEIGHTS.get(detector_id, 0.5)

    # Normalized exposure: affected / eligible (bounded 0–1)
    affected = len([f for f in findings if not f.suppressed])
    normalized_exposure = min(affected / max(eligible_count, 1), 1.0)

    # Severity multiplier: weight by how bad the findings are
    if findings:
        avg_severity_weight = sum(
            SEVERITY_WEIGHTS.get(f.severity, 0.5) for f in findings
        ) / len(findings)
    else:
        avg_severity_weight = 0.0

    penalty = weight * normalized_exposure * avg_severity_weight * 100
    return min(penalty, MAX_DETECTOR_PENALTY)


# ---------------------------------------------------------------------------
# Family scoring
# ---------------------------------------------------------------------------

FAMILY_DETECTOR_MAP: dict[ControlFamily, list[str]] = {
    ControlFamily.MI: ["MI-01","MI-02","MI-03","MI-04","MI-05","MI-06","MI-07"],
    ControlFamily.IH: ["IH-01","IH-02","IH-03","IH-04","IH-05","IH-06"],
    ControlFamily.LI: ["LI-01","LI-02","LI-03","LI-04","LI-05","LI-06"],
    ControlFamily.AR: ["AR-01","AR-02","AR-03","AR-04","AR-05","AR-06","AR-07"],
    ControlFamily.GQ: ["GQ-01","GQ-02","GQ-03","GQ-04","GQ-05","GQ-06","GQ-07","GQ-08"],
    ControlFamily.CR: ["CR-01","CR-02","CR-03","CR-04","CR-05","CR-06","CR-07","CR-08"],
}


def compute_family_score(
    family: ControlFamily,
    findings_by_detector: dict[str, list[Finding]],
    eligible_by_detector: dict[str, int],
) -> FamilyScore:
    """
    Compute a 0–100 score for one control family.
    Starts at 100, applies detector penalties.
    """
    score = 100.0
    detector_scores: dict[str, float] = {}

    for det_id in FAMILY_DETECTOR_MAP.get(family, []):
        det_findings = findings_by_detector.get(det_id, [])
        eligible     = eligible_by_detector.get(det_id, 0)
        penalty      = compute_detector_penalty(det_id, det_findings, eligible)
        det_score    = max(0.0, 100.0 - penalty)
        detector_scores[det_id] = det_score
        score -= penalty

    score = max(0.0, score)

    all_findings = [f for flist in [findings_by_detector.get(d, []) for d in FAMILY_DETECTOR_MAP.get(family, [])] for f in flist]
    critical = sum(1 for f in all_findings if f.severity == Severity.CRITICAL and not f.suppressed)

    return FamilyScore(
        family=family,
        score=round(score, 1),
        weight=TenantHealthScore.model_fields["FAMILY_WEIGHTS"].default.get(family.name, 0.0),
        detector_scores=detector_scores,
        finding_count=len([f for f in all_findings if not f.suppressed]),
        critical_count=critical,
    )


# ---------------------------------------------------------------------------
# Critical conditions
# Applied after scoring — prevents "green score, red reality"
# ---------------------------------------------------------------------------

def detect_critical_conditions(findings: list[Finding]) -> list[CriticalCondition]:
    conditions: list[CriticalCondition] = []
    by_detector: dict[str, list[Finding]] = defaultdict(list)

    for f in findings:
        if not f.suppressed:
            by_detector[f.detector_id].append(f)

    for det_id, label in CRITICAL_CONDITION_DETECTORS.items():
        det_findings = by_detector.get(det_id, [])
        if det_findings:
            conditions.append(CriticalCondition(
                detector_id=det_id,
                title=label,
                description=(
                    f"{len(det_findings)} finding(s) from {det_id}. "
                    f"This condition is flagged regardless of overall health score."
                ),
                finding_ids=[f.finding_id for f in det_findings],
            ))

    return conditions


# ---------------------------------------------------------------------------
# Main scoring entry point
# ---------------------------------------------------------------------------

def compute_tenant_health(
    result: AuditResult,
    eligible_by_detector: dict[str, int],
) -> TenantHealthScore:
    """
    Compute the full tenant health score from an AuditResult.

    Args:
        result:                 The completed audit result with all findings.
        eligible_by_detector:   Map of detector_id → count of eligible objects
                                (used to normalize exposure rates).

    Returns:
        A fully populated TenantHealthScore.
    """
    # Step 1: Score every finding
    for finding in result.findings:
        score_finding(finding)

    # Bucket findings by detector
    findings_by_detector: dict[str, list[Finding]] = defaultdict(list)
    for f in result.findings:
        findings_by_detector[f.detector_id].append(f)

    # Step 2 + 3: Compute family scores
    family_scores: dict[str, FamilyScore] = {}
    for family in ControlFamily:
        fs = compute_family_score(family, findings_by_detector, eligible_by_detector)
        family_scores[family.name] = fs

    # Step 4: Posture score (weighted average of family scores)
    family_weights = {
        "MI": 0.25,
        "LI": 0.20,
        "AR": 0.20,
        "IH": 0.15,
        "GQ": 0.10,
        "CR": 0.10,
    }
    posture_score = sum(
        family_scores[name].score * weight
        for name, weight in family_weights.items()
        if name in family_scores
    )

    # Step 5: Apply coverage confidence
    cov   = result.health_score.coverage_confidence
    cov.compute()
    tenant_health = posture_score * (0.80 + 0.20 * cov.score)
    tenant_health = max(0.0, min(100.0, round(tenant_health, 1)))

    # Critical conditions
    critical_conditions = detect_critical_conditions(result.findings)

    # Build result
    health = TenantHealthScore(
        tenant_health=tenant_health,
        posture_score=round(posture_score, 1),
        coverage_confidence=cov,
        family_scores=family_scores,
        FAMILY_WEIGHTS=family_weights,
        critical_conditions=critical_conditions,
        has_critical_conditions=len(critical_conditions) > 0,
    )
    health.compute_band()

    logger.info(
        f"Tenant health score: {tenant_health:.1f} ({health.band.value}) | "
        f"Coverage confidence: {cov.score_display}/100"
    )
    return health
