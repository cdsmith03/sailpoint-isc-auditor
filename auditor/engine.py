"""
Audit engine — orchestrates collectors, detectors, AI analysis, and scoring.

Run order:
  1. Collect data from ISC (one collector per family)
  2. Run detectors (deterministic — no AI here)
  3. Apply suppressions
  4. Compute coverage confidence from real collected data
  5. Compute tenant health score
  6. Run Claude AI analysis on findings
  7. Return AuditResult to CLI/reporters
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from .client import ISCClient
from .config import AuditorConfig, PolicyPack
from .models import AuditResult, CollectionStatus, CoverageConfidence
from .scoring import compute_tenant_health
from .suppressions import apply_suppressions

logger = logging.getLogger(__name__)


def run_audit(
    config: AuditorConfig,
    policy: PolicyPack,
    policy_name: str = "default",
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
            policy_pack=policy_name,
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

        # Compute coverage confidence from real collected data
        progress("Computing coverage confidence...")
        result.health_score.coverage_confidence = _compute_coverage_confidence(
            all_coverage=all_coverage,
            client=client,
            policy=policy,
        )

        # Score everything
        progress("Computing tenant health score...")
        result.health_score = compute_tenant_health(result, eligible_by_detector)

        # Wire trend — load the most recent score for this tenant from history
        # and compute the delta. This must happen AFTER scoring so we have
        # the current score to compare against.
        # Pass config.history_file explicitly so save and load are symmetric —
        # both the CLI writer and trend reader use the same file.
        _wire_trend(result, config.tenant_url, config.history_file)

        # AI analysis
        # analyze_findings() mutates finding objects in-place — do NOT reassign
        # result.findings here or suppressed findings will be silently dropped
        # from the output. The full list (active + suppressed) must stay intact.
        if run_ai and all_findings:
            progress("Analyzing findings with Claude AI...")
            from .ai.analyzer import analyze_findings
            analyze_findings(
                findings=[f for f in all_findings if not f.suppressed],
                config=config,
                health_score=result.health_score,
            )

        return result


def _safe_ratio(numerator: int, denominator: int) -> float:
    """Return numerator/denominator bounded to [0.0, 1.0], or 0.0 if denominator is zero."""
    if denominator == 0:
        return 0.0
    return max(0.0, min(1.0, numerator / denominator))


def _compute_coverage_confidence(
    all_coverage: list,
    client: ISCClient,
    policy: PolicyPack,
) -> CoverageConfidence:
    """
    Compute coverage confidence from real data collected during the audit run.

    Each signal is a ratio from 0.0 (none covered) to 1.0 (fully covered).
    These feed into the tenant health score formula:

        tenant_health = posture_score × (0.80 + 0.20 × coverage_confidence)

    Signals that cannot be computed (e.g. API unavailable) default to 0.0
    so that missing visibility is penalised rather than assumed healthy.
    """
    logger.info("Computing coverage confidence signals from real data")

    # ── Signal 1: sources_recently_aggregated ──────────────────────────────
    # Ratio of detectors that returned FULL status vs fallback/skipped.
    # Already computed correctly — this reflects API availability.
    full_count   = sum(1 for c in all_coverage if c.status == CollectionStatus.FULL)
    total_count  = max(len(all_coverage), 1)
    api_coverage = _safe_ratio(full_count, total_count)

    # ── Signal 2: critical_sources_connected ───────────────────────────────
    # Ratio of policy.critical_sources that appear in ISC with a recent
    # aggregation (lastAggregationDate within source_stale_days).
    critical_sources_connected = _compute_critical_sources_signal(client, policy)

    # ── Signal 3: entitlements_with_owners ─────────────────────────────────
    # Ratio of entitlements that have an owner assigned.
    # Sampled from the first page to avoid fetching thousands of entitlements.
    entitlements_with_owners = _compute_entitlement_ownership_signal(client)

    # ── Signal 4: high_risk_apps_governed ──────────────────────────────────
    # Ratio of policy.privileged_apps that appear in at least one
    # active certification campaign's scope.
    high_risk_apps_governed = _compute_privileged_app_governance_signal(client, policy)

    # ── Signal 5: lifecycle_populations_covered ────────────────────────────
    # Ratio of identities that have all required governance attributes
    # (manager, department, employmentType) populated.
    # Sampled from the first page to avoid fetching all identities again.
    lifecycle_populations_covered = _compute_lifecycle_coverage_signal(client)

    # ── Signal 6: certification_coverage ──────────────────────────────────
    # Ratio of policy.critical_sources that are covered by at least one
    # active certification campaign.
    certification_coverage = _compute_certification_coverage_signal(client, policy)

    conf = CoverageConfidence(
        critical_sources_connected=critical_sources_connected,
        sources_recently_aggregated=api_coverage,
        entitlements_with_owners=entitlements_with_owners,
        machine_identities_visible=api_coverage,   # proxy: MI API availability
        high_risk_apps_governed=high_risk_apps_governed,
        lifecycle_populations_covered=lifecycle_populations_covered,
        certification_coverage=certification_coverage,
    )
    conf.compute()

    logger.info(
        "Coverage confidence: %d/100 "
        "(sources=%.2f, ents_owned=%.2f, privileged_governed=%.2f, "
        "lifecycle=%.2f, cert_coverage=%.2f)",
        conf.score_display,
        critical_sources_connected,
        entitlements_with_owners,
        high_risk_apps_governed,
        lifecycle_populations_covered,
        certification_coverage,
    )
    return conf


def _compute_critical_sources_signal(client: ISCClient, policy: PolicyPack) -> float:
    """
    Ratio of policy.critical_sources that exist in ISC and have been
    aggregated within policy.source_stale_days.
    """
    if not policy.critical_sources:
        return 1.0   # No critical sources defined — not a gap

    try:
        sources = client.get_sources()
    except Exception as exc:
        logger.warning("Coverage: could not fetch sources for critical_sources signal: %s", exc)
        return 0.0

    from datetime import UTC, datetime
    now = datetime.now(UTC)

    source_map = {s.get("name", ""): s for s in sources}
    connected = 0

    for critical_name in policy.critical_sources:
        source = source_map.get(critical_name)
        if not source:
            logger.debug("Coverage: critical source '%s' not found in ISC", critical_name)
            continue

        last_agg = (
            source.get("lastAggregationDate")
            or source.get("lastSuccessfulAggregation")
            or source.get("modified")
        )

        if not last_agg:
            logger.debug("Coverage: critical source '%s' has no aggregation date", critical_name)
            continue

        try:
            dt = datetime.fromisoformat(last_agg.replace("Z", "+00:00"))
            days_stale = (now - dt).days
            if days_stale <= policy.source_stale_days:
                connected += 1
            else:
                logger.debug(
                    "Coverage: critical source '%s' is stale (%d days)",
                    critical_name, days_stale,
                )
        except (ValueError, TypeError):
            pass

    return _safe_ratio(connected, len(policy.critical_sources))


def _compute_entitlement_ownership_signal(client: ISCClient) -> float:
    """
    Ratio of entitlements that have an owner assigned.
    Samples up to 500 entitlements to avoid long fetch times.
    """
    try:
        entitlements = client.get_all("/v3/entitlements", max_records=500)
    except Exception as exc:
        logger.warning("Coverage: could not fetch entitlements for ownership signal: %s", exc)
        return 0.0

    if not entitlements:
        return 0.0

    owned = sum(
        1 for e in entitlements
        if e.get("owner") or e.get("ownerId") or e.get("ownerName")
    )
    return _safe_ratio(owned, len(entitlements))


def _compute_privileged_app_governance_signal(
    client: ISCClient,
    policy: PolicyPack,
) -> float:
    """
    Ratio of policy.privileged_apps that appear in at least one
    active certification campaign's scope.
    """
    if not policy.privileged_apps:
        return 1.0

    try:
        certifications = client.get_certifications()
    except Exception as exc:
        logger.warning(
            "Coverage: could not fetch certifications for privileged_apps signal: %s", exc
        )
        return 0.0

    # Collect source/app names referenced in active certifications
    governed_apps: set[str] = set()
    active_statuses = {"ACTIVE", "OPEN", "IN_PROGRESS", "STAGED"}

    for cert in certifications:
        status = (cert.get("status") or "").upper()
        if status not in active_statuses:
            continue
        # Certifications reference apps/sources in their scope
        for item in cert.get("items") or []:
            source_name = (item.get("source") or {}).get("name", "")
            if source_name:
                governed_apps.add(source_name)
        # Also check direct scope references
        for scope in cert.get("scope") or []:
            app_name = scope.get("name") or scope.get("applicationName") or ""
            if app_name:
                governed_apps.add(app_name)

    covered = sum(
        1 for app in policy.privileged_apps
        if any(app.lower() in g.lower() for g in governed_apps)
    )
    return _safe_ratio(covered, len(policy.privileged_apps))


def _compute_lifecycle_coverage_signal(client: ISCClient) -> float:
    """
    Ratio of identities that have all required governance attributes populated.
    Required: manager, department, employmentType.
    Samples up to 500 identities to avoid long fetch times.
    """
    required_attrs = ("manager", "department", "employmentType")

    try:
        identities = client.get_all("/v3/identities", max_records=500)
    except Exception as exc:
        logger.warning("Coverage: could not fetch identities for lifecycle signal: %s", exc)
        return 0.0

    if not identities:
        return 0.0

    complete = 0
    for identity in identities:
        attrs = identity.get("attributes") or {}
        has_all = all(
            identity.get(attr) or attrs.get(attr)
            for attr in required_attrs
        )
        if has_all:
            complete += 1

    return _safe_ratio(complete, len(identities))


def _compute_certification_coverage_signal(
    client: ISCClient,
    policy: PolicyPack,
) -> float:
    """
    Ratio of policy.critical_sources covered by at least one
    active or recent certification campaign.
    """
    if not policy.critical_sources:
        return 1.0

    try:
        certifications = client.get_certifications()
    except Exception as exc:
        logger.warning("Coverage: could not fetch certifications for coverage signal: %s", exc)
        return 0.0

    # Collect source names that appear in any certification
    certified_sources: set[str] = set()
    for cert in certifications:
        for item in cert.get("items") or []:
            source_name = (item.get("source") or {}).get("name", "")
            if source_name:
                certified_sources.add(source_name.lower())
        # Check scope references
        for scope in cert.get("scope") or []:
            name = (scope.get("name") or scope.get("applicationName") or "").lower()
            if name:
                certified_sources.add(name)

    covered = sum(
        1 for cs in policy.critical_sources
        if cs.lower() in certified_sources
    )
    return _safe_ratio(covered, len(policy.critical_sources))

def _wire_trend(result: AuditResult, tenant_url: str, history_file: Path) -> None:
    """
    Load the most recent health score for this tenant from history and
    compute the trend delta.

    This mutates result.health_score in-place:
      - previous_score: the tenant_health from the last run
      - trend: current - previous (positive = improving, negative = degrading)

    If no history exists for this tenant, both fields remain None and the
    report shows "First run — no trend data."

    Args:
        result:       The AuditResult being finalized.
        tenant_url:   Used to key history — multi-tenant safe.
        history_file: Must match the path used by _save_history() so that
                      save and load are symmetric. Pass config.history_file.

    History is keyed by tenant_url so multi-tenant users get correct per-tenant
    trends rather than comparing scores across different environments.
    """
    try:
        from .suppressions import load_history
        records = load_history(history_file)
    except Exception as exc:
        logger.debug("Trend: could not load history: %s", exc)
        return

    # Find all records for this tenant.
    # Sort by date field when present so the most recent entry is always
    # correct even if records were written out of order or the file was
    # manually edited. Falls back to append order (the common case) when
    # no date field is present.
    tenant_records = [
        r for r in records
        if r.get("tenant_url") == tenant_url
    ]

    if not tenant_records:
        logger.debug("Trend: no history found for tenant %s", tenant_url)
        return

    # "%Y-%m-%d %H:%M" strings sort correctly lexicographically — ISO-8601
    # order matches chronological order, so string comparison is safe here.
    # "%Y-%m-%d %H:%M" strings sort correctly lexicographically as ISO-8601,
    # so string comparison gives the right chronological order.
    tenant_records.sort(key=lambda r: r.get("date", ""))

    # Use the most recent previous run
    last = tenant_records[-1]
    previous_score = last.get("tenant_health")

    if previous_score is None:
        logger.debug("Trend: last history record missing tenant_health")
        return

    try:
        result.health_score.previous_score = float(previous_score)
        result.health_score.compute_trend()
        logger.info(
            "Trend: %.1f → %.1f (delta: %+.1f)",
            previous_score,
            result.health_score.tenant_health,
            result.health_score.trend or 0,
        )
    except (ValueError, TypeError) as exc:
        logger.debug("Trend: could not compute trend: %s", exc)
