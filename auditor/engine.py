"""
Audit engine — orchestrates collectors, detectors, AI analysis, and scoring.

Run order:
  1. Collect data from ISC (one collector per family)
  2. Run detectors (deterministic — no AI here)
  3. Apply suppressions
  4. Compute risk scores
  5. Compute tenant health score
  6. Run Claude AI analysis on findings
  7. Return AuditResult to CLI/reporters
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Callable

from .client import ISCClient
from .config import AuditorConfig, PolicyPack
from .models import AuditResult, CoverageConfidence
from .scoring import compute_tenant_health
from .suppressions import apply_suppressions

logger = logging.getLogger(__name__)


def run_audit(
    config: AuditorConfig,
    policy: PolicyPack,
    run_all: bool = True,
    families: list[str] | None = None,
    detectors: list[str] | None = None,
    run_ai: bool = True,
    progress_callback: Callable[[str], None] | None = None,
) -> AuditResult:
    """
    Main audit entry point.
    Returns a fully populated AuditResult ready for reporting.
    """
    def progress(msg: str) -> None:
        if progress_callback:
            progress_callback(msg)
        logger.info(msg)

    families  = [f.upper() for f in (families or [])]
    detectors = [d.upper() for d in (detectors or [])]

    def should_run(family: str) -> bool:
        if run_all:
            return True
        if families and family in families:
            return True
        if detectors and any(d.startswith(family) for d in detectors):
            return True
        return False

    with ISCClient(config) as client:
        result = AuditResult(
            tenant_url=config.tenant_url,
            policy_pack=policy.model_dump_json(),
        )

        all_findings:  list = []
        all_coverage:  list = []
        eligible_by_detector: dict[str, int] = {}

        # ── MI: Machine & Privileged Identity ──────────────────────────────
        if should_run("MI"):
            progress("Collecting machine identity data...")
            from .modules.mi import run_mi_detectors
            findings, coverage = run_mi_detectors(client, policy)
            all_findings.extend(findings)
            all_coverage.extend(coverage)
            for cov in coverage:
                eligible_by_detector[cov.detector_id] = cov.eligible_count

        # ── IH: Identity Hygiene ────────────────────────────────────────────
        if should_run("IH"):
            progress("Collecting identity and account data...")
            from .modules.ih import run_ih_detectors
            findings, coverage = run_ih_detectors(client, policy)
            all_findings.extend(findings)
            all_coverage.extend(coverage)
            for cov in coverage:
                eligible_by_detector[cov.detector_id] = cov.eligible_count

        # ── LI: Lifecycle Integrity ─────────────────────────────────────────
        if should_run("LI"):
            progress("Collecting lifecycle and non-employee data...")
            from .modules.li import run_li_detectors
            findings, coverage = run_li_detectors(client, policy)
            all_findings.extend(findings)
            all_coverage.extend(coverage)
            for cov in coverage:
                eligible_by_detector[cov.detector_id] = cov.eligible_count

        # ── AR: Access Risk ─────────────────────────────────────────────────
        if should_run("AR"):
            progress("Collecting roles, entitlements, and SOD violations...")
            from .modules.ar import run_ar_detectors
            findings, coverage = run_ar_detectors(client, policy)
            all_findings.extend(findings)
            all_coverage.extend(coverage)
            for cov in coverage:
                eligible_by_detector[cov.detector_id] = cov.eligible_count

        # ── GQ: Governance Quality ──────────────────────────────────────────
        if should_run("GQ"):
            progress("Collecting certification and governance data...")
            from .modules.gq import run_gq_detectors
            findings, coverage = run_gq_detectors(client, policy)
            all_findings.extend(findings)
            all_coverage.extend(coverage)
            for cov in coverage:
                eligible_by_detector[cov.detector_id] = cov.eligible_count

        # ── CR: Coverage & Reconciliation ───────────────────────────────────
        if should_run("CR"):
            progress("Collecting source and provisioning data...")
            from .modules.cr import run_cr_detectors
            findings, coverage = run_cr_detectors(client, policy)
            all_findings.extend(findings)
            all_coverage.extend(coverage)
            for cov in coverage:
                eligible_by_detector[cov.detector_id] = cov.eligible_count

        # Apply suppressions
        progress("Applying suppressions...")
        all_findings = apply_suppressions(all_findings)

        result.findings          = all_findings
        result.detector_coverage = all_coverage

        # Compute coverage confidence from what we collected
        result.health_score.coverage_confidence = _estimate_coverage_confidence(
            all_coverage, client, policy
        )

        # Score everything
        progress("Computing tenant health score...")
        result.health_score = compute_tenant_health(result, eligible_by_detector)

        # AI analysis
        if run_ai and all_findings:
            progress("Analyzing findings with Claude AI...")
            from .ai.analyzer import analyze_findings
            result.findings = analyze_findings(
                findings=[f for f in all_findings if not f.suppressed],
                config=config,
                health_score=result.health_score,
            )

        return result


def _estimate_coverage_confidence(
    coverage: list,
    client: ISCClient,
    policy: PolicyPack,
) -> CoverageConfidence:
    """
    Estimate coverage confidence from collection results.
    This drives the coverage confidence factor in the health score.
    """
    from .models import CollectionStatus

    full_count    = sum(1 for c in coverage if c.status == CollectionStatus.FULL)
    total_count   = max(len(coverage), 1)
    api_coverage  = full_count / total_count

    # Simplified signals — expanded in later builds
    return CoverageConfidence(
        critical_sources_connected=0.8,       # TODO: query sources
        sources_recently_aggregated=api_coverage,
        entitlements_with_owners=0.5,          # TODO: query entitlements
        machine_identities_visible=api_coverage,
        high_risk_apps_governed=0.6,           # TODO: derive from sources
        lifecycle_populations_covered=0.7,     # TODO: derive from identities
        certification_coverage=0.6,            # TODO: derive from certifications
    )
