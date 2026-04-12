"""
CR — Coverage & Reconciliation detectors.

The module most teams forget — and the one that makes the tool feel mature.
These detectors surface gaps in what ISC can actually see and govern,
and catch provisioning failures that other modules miss.

Detectors:
  CR-01  Connected source with no governance owner              [High]
  CR-02  Source not recently aggregated (stale visibility)      [Medium]
  CR-03  Provisioning failure or stuck account activity         [High]
  CR-04  Deprovisioning requested but not completed             [Critical]
  CR-05  Revoked in ISC, still present in target system         [Critical]
  CR-06  Manual / disconnected governance hot spots             [High]
  CR-07  Critical source with low policy attachment             [Medium]
  CR-08  High-volume source with abnormal risk ratios           [Medium]
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime

from ..client import ISCClient
from ..config import PolicyPack
from ..models import (
    CollectionStatus,
    ControlFamily,
    DetectorCoverage,
    Finding,
    FindingEvidence,
    Severity,
)

logger = logging.getLogger(__name__)

STUCK_ACTIVITY_STATUSES = {"PENDING", "IN_PROGRESS", "RETRYING", "FAILED"}


def _make_finding_id(detector_id: str, object_id: str) -> str:
    digest = hashlib.sha256(f"{detector_id}:{object_id}".encode()).hexdigest()[:12]
    return f"{detector_id}-{digest}"


def _days_since(date_str: str | None) -> int | None:
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return (datetime.now(UTC) - dt).days
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# CR-01: Connected source with no governance owner
# ---------------------------------------------------------------------------

def detect_cr_01(
    sources: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Every source that feeds accounts into ISC should have an accountable owner.
    Without one, nobody is responsible for aggregation health, access reviews,
    or data quality for that source.
    """
    findings: list[Finding] = []
    detector_id = "CR-01"

    for source in sources:
        sid   = source.get("id", "unknown")
        sname = source.get("name") or sid
        owner = source.get("owner") or source.get("ownerId")

        if not owner:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, sid),
                detector_id=detector_id,
                family=ControlFamily.CR,
                title="Connected source with no owner",
                severity=Severity.HIGH,
                evidence=FindingEvidence(
                    affected_object_ids=[sid],
                    affected_object_names=[sname],
                    object_type="source",
                    why_fired=(
                        f"Source '{sname}' has no assigned owner. Without an owner, "
                        f"there is no accountable party for aggregation failures, "
                        f"access review campaigns, or data quality issues for the "
                        f"accounts that flow from this source."
                    ),
                    source_data={"has_owner": False, "connector_type": source.get("connectorName")},
                    recommended_fix=(
                        "Assign a business owner to this source in ISC. The owner should "
                        "be the application or system owner, not an ISC administrator."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.95,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.CR,
        status=CollectionStatus.FULL,
        eligible_count=len(sources),
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} unowned sources / {len(sources)} total")
    return findings, coverage


# ---------------------------------------------------------------------------
# CR-02: Source not recently aggregated
# ---------------------------------------------------------------------------

def detect_cr_02(
    sources: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    If ISC hasn't successfully aggregated a source recently, every finding
    for accounts in that source is based on potentially stale data.
    Flags this explicitly so the report is honest about its own confidence.
    """
    findings: list[Finding] = []
    detector_id = "CR-02"
    threshold   = policy.source_stale_days
    eligible    = 0

    for source in sources:
        sid   = source.get("id", "unknown")
        sname = source.get("name") or sid

        last_agg = (
            source.get("lastAggregationDate")
            or source.get("lastSuccessfulAggregation")
            or source.get("modified")
        )
        days = _days_since(last_agg)

        if days is None:
            continue

        eligible += 1

        if days > threshold:
            is_critical = sname in policy.critical_sources
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, sid),
                detector_id=detector_id,
                family=ControlFamily.CR,
                status=CollectionStatus.FULL,
                title=(
                    f"Source not recently aggregated"
                    f"{'  [critical source]' if is_critical else ''}"
                ),
                severity=Severity.HIGH if is_critical else Severity.MEDIUM,
                evidence=FindingEvidence(
                    affected_object_ids=[sid],
                    affected_object_names=[sname],
                    object_type="source",
                    why_fired=(
                        f"Source '{sname}' was last successfully aggregated {days} days ago "
                        f"(threshold: {threshold} days). "
                        f"{'This is a critical source — ' if is_critical else ''}"
                        f"{'stale data here has the highest impact. ' if is_critical else ''}"
                        f"Account data from this source may not reflect the current state "
                        "in the target system, making all downstream "
                        "governance decisions unreliable."
                    ),
                    source_data={
                        "last_aggregation": last_agg,
                        "days_stale": days,
                        "is_critical_source": is_critical,
                        "connector_type": source.get("connectorName"),
                    },
                    recommended_fix=(
                        "Investigate the aggregation failure. Check connector health, "
                        "VA connectivity, source credentials, and ISC logs. Run a manual "
                        "aggregation once the root cause is resolved."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.90,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.CR,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(
        "  %s: %d stale sources / %d sources with agg date",
        detector_id, len(findings), eligible,
    )
    return findings, coverage


# ---------------------------------------------------------------------------
# CR-03: Provisioning failure or stuck account activity
# ---------------------------------------------------------------------------

def detect_cr_03(
    account_activities: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Use account activities to catch failed, pending, or inconsistent operations.
    A stuck provisioning operation means access was requested but may not have
    actually been granted or revoked — a governance gap.
    """
    findings: list[Finding] = []
    detector_id = "CR-03"
    eligible    = 0

    stuck_threshold_hours = 24

    for activity in account_activities:
        status = (activity.get("status") or "").upper()
        if status not in STUCK_ACTIVITY_STATUSES:
            continue

        eligible += 1
        aid   = activity.get("id", "unknown")
        atype = activity.get("type") or activity.get("operation") or "unknown"
        created = activity.get("created")
        hours_old = None

        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                hours_old = (datetime.now(UTC) - dt).total_seconds() / 3600
            except (ValueError, TypeError):
                pass

        if hours_old is not None and hours_old < stuck_threshold_hours:
            continue   # Give recent activities time to complete

        identity_name = (activity.get("identity") or {}).get("name") or "unknown identity"
        source_name   = (activity.get("source") or {}).get("name") or "unknown source"

        findings.append(Finding(
            finding_id=_make_finding_id(detector_id, aid),
            detector_id=detector_id,
            family=ControlFamily.CR,
            title="Stuck or failed provisioning activity",
            severity=Severity.HIGH,
            evidence=FindingEvidence(
                affected_object_ids=[aid],
                affected_object_names=[f"{atype} for {identity_name} in {source_name}"],
                object_type="account_activity",
                why_fired=(
                    f"Account activity '{atype}' for '{identity_name}' in '{source_name}' "
                    f"has been in status '{status}' for "
                    f"{f'{hours_old:.0f} hours' if hours_old else 'an unknown duration'}. "
                    f"Stuck operations mean the actual access state in the target system "
                    f"may not match what ISC believes — a reconciliation gap."
                ),
                source_data={
                    "activity_type": atype,
                    "status": status,
                    "hours_stuck": hours_old,
                    "source": source_name,
                    "identity": identity_name,
                },
                recommended_fix=(
                    "Investigate the failed operation in ISC → Account Activities. "
                    "Check connector logs and VA health. Manually verify the account "
                    "state in the target system and reconcile with ISC."
                ),
                collection_status=CollectionStatus.FULL,
                confidence=0.85,
            ),
        ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.CR,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} stuck operations / {eligible} checked")
    return findings, coverage


# ---------------------------------------------------------------------------
# CR-04: Deprovisioning requested but not completed
# ---------------------------------------------------------------------------

def detect_cr_04(
    account_activities: list[dict],
    accounts: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    The most important reconciliation detector.
    A deprovision was requested in ISC but the account still exists
    in the target system — the most legally dangerous gap.
    """
    findings: list[Finding] = []
    detector_id = "CR-04"

    # Build set of active account IDs for fast lookup
    active_account_ids = {
        a.get("id") for a in accounts
        if a.get("enabled", a.get("status") == "ENABLED")
    }

    eligible = 0
    for activity in account_activities:
        op_type = (activity.get("type") or activity.get("operation") or "").upper()
        status  = (activity.get("status") or "").upper()

        if "DEPROVISION" not in op_type and "DISABLE" not in op_type and "REMOVE" not in op_type:
            continue

        eligible += 1

        # Deprovision was requested but account is still active
        account_id = activity.get("accountId") or (activity.get("account") or {}).get("id")

        if account_id and account_id in active_account_ids:
            aid           = activity.get("id", "unknown")
            identity_name = (activity.get("identity") or {}).get("name") or "unknown"
            source_name   = (activity.get("source") or {}).get("name") or "unknown"
            requested_at  = activity.get("created")

            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, aid),
                detector_id=detector_id,
                family=ControlFamily.CR,
                title="Deprovisioning requested but account still active",
                severity=Severity.CRITICAL,
                evidence=FindingEvidence(
                    affected_object_ids=[aid, account_id],
                    affected_object_names=[f"{identity_name} in {source_name}"],
                    object_type="account_activity",
                    why_fired=(
                        f"A deprovision request was submitted for '{identity_name}' "
                        f"in source '{source_name}' on {requested_at or 'unknown date'}, "
                        f"but the account is still active. The intended access removal "
                        f"did not complete — the identity may still have access they "
                        f"should not have."
                    ),
                    source_data={
                        "operation": op_type,
                        "activity_status": status,
                        "account_id": account_id,
                        "requested_at": requested_at,
                        "deprovisioning_failed": True,
                        "has_owner": False,
                    },
                    recommended_fix=(
                        "Manually disable the account in the target system immediately. "
                        "Investigate the provisioning failure in ISC logs. Fix the "
                        "connector issue to prevent recurrence. Document for audit evidence."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.90,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.CR,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(
        "  %s: %d failed deprovisions / %d deprovision ops",
        detector_id, len(findings), eligible,
    )
    return findings, coverage


# ---------------------------------------------------------------------------
# CR-05: Revoked in ISC, still present in target account state
# ---------------------------------------------------------------------------

def detect_cr_05(
    accounts: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    High-value drift check: ISC believes access was revoked, but the account
    still exists in the target system in an enabled state. This is the most
    direct evidence of a control failure — ISC said revoke, reality didn't follow.
    """
    findings: list[Finding] = []
    detector_id = "CR-05"
    eligible    = 0

    for acct in accounts:
        # An account ISC considers revoked/disabled
        isc_status = (acct.get("status") or "").upper()
        if isc_status not in ("REVOKED", "DISABLED", "INACTIVE"):
            continue

        eligible += 1

        # But the native identity attribute or last aggregated state shows enabled
        native_enabled = (
            acct.get("nativeIdentity") and
            acct.get("attributes", {}).get("active") is True
        )
        raw_enabled    = acct.get("attributes", {}).get("enabled") is True

        if native_enabled or raw_enabled:
            acct_id   = acct.get("id", "unknown")
            acct_name = acct.get("name") or acct.get("displayName") or acct_id
            source    = acct.get("sourceName") or "unknown source"
            identity  = (acct.get("identity") or {}).get("name") or "uncorrelated"

            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, acct_id),
                detector_id=detector_id,
                family=ControlFamily.CR,
                title="Access revoked in ISC but active in target system",
                severity=Severity.CRITICAL,
                evidence=FindingEvidence(
                    affected_object_ids=[acct_id],
                    affected_object_names=[acct_name],
                    object_type="account",
                    why_fired=(
                        f"Account '{acct_name}' (identity: {identity}) in source '{source}' "
                        f"is marked '{isc_status}' in ISC but the target system's native "
                        f"state shows the account is still enabled. This is confirmed "
                        f"access drift — ISC's governance view does not match reality."
                    ),
                    source_data={
                        "isc_status": isc_status,
                        "target_enabled": True,
                        "source": source,
                        "drift_confirmed": True,
                        "deprovisioning_failed": True,
                    },
                    recommended_fix=(
                        "Disable the account directly in the target system immediately. "
                        "Run a full aggregation to sync the state back to ISC. "
                        "Investigate the connector to understand why revocation did not "
                        "propagate. This is an audit-reportable control failure."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.85,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.CR,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} drift findings / {eligible} revoked accounts")
    return findings, coverage


# ---------------------------------------------------------------------------
# CR-06: Manual / disconnected governance hot spots
# ---------------------------------------------------------------------------

def detect_cr_06(
    sources: list[dict],
    accounts: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    High-risk source populations living in poorly governed or low-visibility
    parts of the estate — typically flat-file or manual sources with no
    automation, no owner, and no certification coverage.
    """
    findings: list[Finding] = []
    detector_id = "CR-06"

    # Count accounts per source
    accts_per_source: dict[str, int] = {}
    for acct in accounts:
        sid = (acct.get("source") or {}).get("id") or acct.get("sourceId")
        if sid:
            accts_per_source[sid] = accts_per_source.get(sid, 0) + 1

    for source in sources:
        sid         = source.get("id", "unknown")
        sname       = source.get("name") or sid
        connector   = (source.get("connectorName") or "").lower()
        owner       = source.get("owner")
        acct_count  = accts_per_source.get(sid, 0)

        # Flag manual/flat-file sources with significant populations and no owner
        is_manual   = "manual" in connector or "flat" in connector or "csv" in connector
        is_high_vol = acct_count > 50

        if is_manual and is_high_vol and not owner:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, sid),
                detector_id=detector_id,
                family=ControlFamily.CR,
                title="Manual source — high-risk governance hot spot",
                severity=Severity.HIGH,
                evidence=FindingEvidence(
                    affected_object_ids=[sid],
                    affected_object_names=[sname],
                    object_type="source",
                    why_fired=(
                        f"Source '{sname}' uses a manual/flat-file connector and has "
                        f"{acct_count} accounts with no owner assigned. Manual sources "
                        f"have no automated lifecycle management — accounts are only "
                        f"updated when someone manually intervenes. This is a high-risk "
                        f"governance blind spot."
                    ),
                    source_data={
                        "connector_type": connector,
                        "account_count": acct_count,
                        "has_owner": False,
                    },
                    recommended_fix=(
                        "Assign an owner to this source. Conduct a full manual review "
                        "of all accounts. Plan to migrate to a connected connector or "
                        "implement a formal manual review cycle with documented evidence."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.80,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.CR,
        status=CollectionStatus.FULL,
        eligible_count=len(sources),
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} manual hot spots / {len(sources)} sources")
    return findings, coverage


# ---------------------------------------------------------------------------
# CR-07: Critical source with low policy attachment
# ---------------------------------------------------------------------------

def detect_cr_07(
    sources: list[dict],
    certifications: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    A critical source (defined in policy pack) that has no certification,
    no SOD relationship, no ownership — basically no accountability model.
    """
    findings: list[Finding] = []
    detector_id = "CR-07"

    critical = [s for s in sources if s.get("name") in policy.critical_sources]
    eligible  = len(critical)

    # Which sources appear in any certification scope?
    certified_sources: set[str] = set()
    for cert in certifications:
        for item in cert.get("items") or []:
            src = (item.get("source") or {}).get("id")
            if src:
                certified_sources.add(src)

    for source in critical:
        sid   = source.get("id", "unknown")
        sname = source.get("name") or sid
        owner = source.get("owner")
        in_cert_scope = sid in certified_sources

        issues = []
        if not owner:
            issues.append("no owner assigned")
        if not in_cert_scope:
            issues.append("not in any certification campaign scope")

        if issues:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, sid),
                detector_id=detector_id,
                family=ControlFamily.CR,
                title="Critical source with low governance coverage",
                severity=Severity.MEDIUM,
                evidence=FindingEvidence(
                    affected_object_ids=[sid],
                    affected_object_names=[sname],
                    object_type="source",
                    why_fired=(
                        f"Critical source '{sname}' has governance gaps: "
                        f"{', '.join(issues)}. Critical sources should have the "
                        f"highest level of governance coverage — any gaps here "
                        f"represent the highest-risk blind spots in the environment."
                    ),
                    source_data={
                        "is_critical": True,
                        "has_owner": bool(owner),
                        "in_certification_scope": in_cert_scope,
                        "issues": issues,
                    },
                    recommended_fix=(
                        f"Address all gaps for '{sname}': {'; '.join(issues)}. "
                        f"Critical sources should be reviewed quarterly at minimum."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.90,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.CR,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(
        "  %s: %d undergoverned critical sources / %d critical",
        detector_id, len(findings), eligible,
    )
    return findings, coverage


# ---------------------------------------------------------------------------
# CR-08: High-volume source with abnormal risk ratios
# ---------------------------------------------------------------------------

def detect_cr_08(
    sources: list[dict],
    accounts: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Ranks which sources have the worst ratios of orphaned, stale, or
    privileged accounts relative to their total population. Useful for
    prioritising where to focus remediation effort.
    """
    findings: list[Finding] = []
    detector_id = "CR-08"

    # Build per-source stats
    stats: dict[str, dict] = {}
    for acct in accounts:
        sid = (acct.get("source") or {}).get("id") or acct.get("sourceId")
        if not sid:
            continue
        s = stats.setdefault(sid, {"total": 0, "orphaned": 0, "enabled": 0})
        s["total"] += 1
        if acct.get("enabled", acct.get("status") == "ENABLED"):
            s["enabled"] += 1
        if not (acct.get("identityId") or acct.get("identity")):
            s["orphaned"] += 1

    eligible = 0
    for source in sources:
        sid   = source.get("id", "unknown")
        sname = source.get("name") or sid
        s     = stats.get(sid)

        if not s or s["total"] < 20:   # Too small for meaningful ratios
            continue

        eligible += 1
        orphan_ratio = s["orphaned"] / s["total"] if s["total"] else 0

        # Flag sources where >15% of accounts are orphaned
        if orphan_ratio > 0.15:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, sid),
                detector_id=detector_id,
                family=ControlFamily.CR,
                title="Source with abnormally high orphan ratio",
                severity=Severity.MEDIUM,
                evidence=FindingEvidence(
                    affected_object_ids=[sid],
                    affected_object_names=[sname],
                    object_type="source",
                    why_fired=(
                        f"Source '{sname}' has {s['orphaned']} orphaned accounts "
                        f"out of {s['total']} total ({orphan_ratio*100:.1f}% — "
                        f"threshold: 15%). A high orphan ratio suggests systemic "
                        f"correlation problems or poor lifecycle management for "
                        f"this source's population."
                    ),
                    source_data={
                        "total_accounts": s["total"],
                        "orphaned_accounts": s["orphaned"],
                        "orphan_ratio": round(orphan_ratio, 3),
                        "enabled_accounts": s["enabled"],
                    },
                    recommended_fix=(
                        "Investigate the correlation rules for this source. Run a manual "
                        "correlation review. Consider whether the HR source has the "
                        "attributes needed to reliably correlate accounts from this system."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.85,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.CR,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} high-ratio sources / {eligible} eligible")
    return findings, coverage


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run_cr_detectors(
    client: ISCClient,
    policy: PolicyPack,
) -> tuple[list[Finding], list[DetectorCoverage]]:
    logger.info("Running CR — Coverage & Reconciliation detectors")

    sources            = client.get_sources()
    accounts           = client.get_accounts()
    certifications     = client.get_certifications()
    account_activities = client.get_account_activities(
        filters="status in (\"PENDING\",\"FAILED\",\"RETRYING\")"
    )

    all_findings: list[Finding]          = []
    all_coverage: list[DetectorCoverage] = []

    for detector_fn, kwargs in [
        (detect_cr_01, {"sources": sources, "policy": policy}),
        (detect_cr_02, {"sources": sources, "policy": policy}),
        (detect_cr_03, {"account_activities": account_activities, "policy": policy}),
        (detect_cr_04, {
            "account_activities": account_activities,
            "accounts": accounts, "policy": policy,
        }),
        (detect_cr_05, {"accounts": accounts, "policy": policy}),
        (detect_cr_06, {"sources": sources, "accounts": accounts, "policy": policy}),
        (detect_cr_07, {"sources": sources, "certifications": certifications, "policy": policy}),
        (detect_cr_08, {"sources": sources, "accounts": accounts, "policy": policy}),
    ]:
        det_id = detector_fn.__name__.replace("detect_", "").replace("_", "-").upper()
        if not policy.is_detector_enabled(det_id):
            logger.info(f"  {det_id}: disabled in policy pack — skipping")
            continue

        findings, coverage = detector_fn(**kwargs)
        all_findings.extend(findings)
        all_coverage.append(coverage)

    logger.info(f"CR complete: {len(all_findings)} total findings")
    return all_findings, all_coverage
