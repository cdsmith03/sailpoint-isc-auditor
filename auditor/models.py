"""
Core data models for sailpoint-isc-auditor.

Every finding, collection result, score, and report is typed here.
These models are the contract between collectors, detectors, AI, and reporters.

Design principles:
  - Evidence-first: every finding carries full provenance
  - Suppressible: every finding can be muted with a reason + expiry
  - Scorable: every finding feeds the two-axis risk model
  - Transparent: coverage gaps are surfaced, not hidden
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime.

    Replaces datetime.utcnow() which is deprecated in Python 3.12+ and
    returns a naive datetime that cannot be compared with aware datetimes.
    """
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class CollectionStatus(StrEnum):
    FULL     = "full"
    PARTIAL  = "partial"
    FALLBACK = "fallback"
    SKIPPED  = "skipped"
    FAILED   = "failed"


class HealthBand(StrEnum):
    HEALTHY   = "Healthy"
    STABLE    = "Stable"
    EXPOSED   = "Exposed"
    HIGH_RISK = "High Risk"
    CRITICAL  = "Critical"


class ControlFamily(StrEnum):
    MI = "Machine & Privileged Identity"
    IH = "Identity Hygiene"
    LI = "Lifecycle Integrity"
    AR = "Access Risk"
    GQ = "Governance Quality"
    CR = "Coverage & Reconciliation"


# ---------------------------------------------------------------------------
# Collection result
# ---------------------------------------------------------------------------

class CollectionResult(BaseModel):
    """Wraps data returned by a collector with provenance and fallback metadata."""
    data:         list[dict[str, Any]] = Field(default_factory=list)
    source:       str | None           = None
    status:       CollectionStatus     = CollectionStatus.FULL
    warning:      str | None           = None
    record_count: int                  = 0
    collected_at: datetime             = Field(default_factory=_utcnow)

    def model_post_init(self, __context: Any) -> None:
        if self.record_count == 0:
            self.record_count = len(self.data)


# ---------------------------------------------------------------------------
# Finding evidence
# ---------------------------------------------------------------------------

class FindingEvidence(BaseModel):
    """
    Structured evidence attached to every finding.
    Ensures findings are reproducible and auditor-defensible.
    Claude reads why_fired and source_data to write its explanations —
    it summarises facts established here, never invents context.
    """
    affected_object_ids:   list[str]        = Field(default_factory=list)
    affected_object_names: list[str]        = Field(default_factory=list)
    object_type:           str              = ""
    why_fired:             str              = ""
    source_data:           dict[str, Any]   = Field(default_factory=dict)
    recommended_fix:       str              = ""
    collection_status:     CollectionStatus = CollectionStatus.FULL
    confidence:            float            = 1.0


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------

class RiskScore(BaseModel):
    """
    Three-factor risk score: impact × exploitability × governance_failure.
    All inputs validated to [0.0, 1.0]. raw_score and normalized auto-computed.
    """
    impact:             float = Field(ge=0.0, le=1.0)
    exploitability:     float = Field(ge=0.0, le=1.0)
    governance_failure: float = Field(ge=0.0, le=1.0)
    raw_score:          float = 0.0
    normalized:         float = 0.0

    def model_post_init(self, __context: Any) -> None:
        self.raw_score  = self.impact * self.exploitability * self.governance_failure
        self.normalized = round(self.raw_score * 100, 1)


# ---------------------------------------------------------------------------
# Suppression
# ---------------------------------------------------------------------------

class Suppression(BaseModel):
    detector_id:   str
    object_id:     str
    reason:        str
    ticket:        str | None      = None
    suppressed_by: str             = ""
    suppressed_at: datetime        = Field(default_factory=_utcnow)
    expires_at:    datetime | None = None


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """
    A single security finding from a detector. Enriched in stages:
      1. Detectors populate:   finding_id, detector_id, family, title, severity, evidence
      2. Scoring engine adds:  risk_score
      3. Claude analyzer adds: ai_explanation, ai_blast_radius, ai_remediation, ai_audit_note
      4. Suppression engine:   suppressed, suppression
    """
    finding_id:  str           = ""
    detector_id: str           = ""
    family:      ControlFamily = ControlFamily.MI
    title:       str           = ""
    severity:    Severity      = Severity.MEDIUM
    evidence:    FindingEvidence = Field(default_factory=FindingEvidence)

    risk_score:      RiskScore | None = None
    ai_explanation:  str | None = None
    ai_blast_radius: str | None = None
    ai_remediation:  str | None = None
    ai_audit_note:   str | None = None

    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen:  datetime = Field(default_factory=_utcnow)

    suppressed:  bool               = False
    suppression: Suppression | None = None


# ---------------------------------------------------------------------------
# Detector coverage
# ---------------------------------------------------------------------------

class DetectorCoverage(BaseModel):
    detector_id:    str
    family:         ControlFamily
    status:         CollectionStatus
    eligible_count: int        = 0
    affected_count: int        = 0
    warning:        str | None = None


# ---------------------------------------------------------------------------
# Coverage confidence
# ---------------------------------------------------------------------------

class CoverageConfidence(BaseModel):
    """
    Measures how much of the ISC environment the auditor could see.

    Formula: tenant_health = posture_score × (0.80 + 0.20 × coverage_confidence)

    The 0.80 / 0.20 split is intentional:
    - Coverage matters — poor visibility prevents a clean bill of health.
    - Coverage does not dominate — a genuinely secure tenant scores well even
      if some API endpoints are unavailable.
    """
    critical_sources_connected:    float = 0.0
    sources_recently_aggregated:   float = 0.0
    entitlements_with_owners:      float = 0.0
    machine_identities_visible:    float = 0.0
    high_risk_apps_governed:       float = 0.0
    lifecycle_populations_covered: float = 0.0
    certification_coverage:        float = 0.0

    score:         float = 0.0
    score_display: int   = 0

    def compute(self) -> None:
        signals = [
            self.critical_sources_connected,
            self.sources_recently_aggregated,
            self.entitlements_with_owners,
            self.machine_identities_visible,
            self.high_risk_apps_governed,
            self.lifecycle_populations_covered,
            self.certification_coverage,
        ]
        self.score         = sum(signals) / len(signals)
        self.score_display = round(self.score * 100)


# ---------------------------------------------------------------------------
# Family score
# ---------------------------------------------------------------------------

class FamilyScore(BaseModel):
    family:          ControlFamily
    score:           float            = 100.0
    weight:          float            = 0.0
    detector_scores: dict[str, float] = Field(default_factory=dict)
    finding_count:   int              = 0
    critical_count:  int              = 0
    high_count:      int              = 0
    medium_count:    int              = 0


# ---------------------------------------------------------------------------
# Critical condition
# ---------------------------------------------------------------------------

class CriticalCondition(BaseModel):
    """
    Certain findings are so dangerous they surface as a banner regardless
    of the overall health score — preventing "green score, red reality."
    """
    detector_id: str
    title:       str
    description: str
    finding_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Tenant health score
# ---------------------------------------------------------------------------

class TenantHealthScore(BaseModel):
    """
    Three numbers, not one:

      Tenant Health Score:  77  (Stable)
      Coverage Confidence:  60
      30-Day Trend:         +5

    Family weights (must sum to 1.0):
      MI 25% — machine identity is the fastest-growing attack surface
      LI 20% — terminated users and contractor access are highest-stakes
      AR 20% — SOD violations and over-provisioning
      IH 15% — orphaned and stale accounts
      GQ 10% — certification and governance quality
      CR 10% — coverage gaps and provisioning failures
    """
    tenant_health:       float              = 0.0
    posture_score:       float              = 0.0
    coverage_confidence: CoverageConfidence = Field(default_factory=CoverageConfidence)
    band:                HealthBand         = HealthBand.CRITICAL
    family_scores:       dict[str, FamilyScore] = Field(default_factory=dict)

    FAMILY_WEIGHTS: dict[str, float] = Field(default={
        "MI": 0.25,
        "LI": 0.20,
        "AR": 0.20,
        "IH": 0.15,
        "GQ": 0.10,
        "CR": 0.10,
    })

    previous_score:          float | None            = None
    trend:                   float | None            = None
    critical_conditions:     list[CriticalCondition] = Field(default_factory=list)
    has_critical_conditions: bool                    = False
    scored_at:               datetime                = Field(default_factory=_utcnow)

    def compute_band(self) -> None:
        s = self.tenant_health
        if s >= 90:
            self.band = HealthBand.HEALTHY
        elif s >= 75:
            self.band = HealthBand.STABLE
        elif s >= 60:
            self.band = HealthBand.EXPOSED
        elif s >= 40:
            self.band = HealthBand.HIGH_RISK
        else:
            self.band = HealthBand.CRITICAL

    def compute_trend(self) -> None:
        if self.previous_score is not None:
            self.trend = round(self.tenant_health - self.previous_score, 1)


# ---------------------------------------------------------------------------
# Audit result
# ---------------------------------------------------------------------------

class AuditResult(BaseModel):
    """
    Complete output of one full audit run. Passed to all reporters.

    policy_pack stores the policy name or path only — not the serialised
    policy contents — to avoid leaking classification data in JSON output.
    """
    tenant_url:  str
    tenant_id:   str      = ""
    audited_at:  datetime = Field(default_factory=_utcnow)
    policy_pack: str      = "default"

    findings:          list[Finding]          = Field(default_factory=list)
    suppressed:        list[Finding]          = Field(default_factory=list)
    detector_coverage: list[DetectorCoverage] = Field(default_factory=list)
    health_score:      TenantHealthScore      = Field(default_factory=TenantHealthScore)

    @property
    def critical_count(self) -> int:
        return sum(
            1 for f in self.findings
            if f.severity == Severity.CRITICAL and not f.suppressed
        )

    @property
    def high_count(self) -> int:
        return sum(
            1 for f in self.findings
            if f.severity == Severity.HIGH and not f.suppressed
        )

    @property
    def medium_count(self) -> int:
        return sum(
            1 for f in self.findings
            if f.severity == Severity.MEDIUM and not f.suppressed
        )

    @property
    def total_active(self) -> int:
        return sum(1 for f in self.findings if not f.suppressed)
