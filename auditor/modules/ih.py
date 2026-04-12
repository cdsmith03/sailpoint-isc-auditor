"""
IH — Identity Hygiene detectors.

The "classic audit findings" bucket. These are the issues external auditors
look for first and the ones that accumulate silently over time.

Detectors:
  IH-01  Orphaned account (no correlated identity)              [Critical]
  IH-02  Stale enabled account (90+ days inactive)              [High]
  IH-03  Disabled in source, still active in governance view    [High]
  IH-04  Duplicate identity collision indicators                [High]
  IH-05  Missing core identity attributes                       [Medium]
  IH-06  Account with no recent aggregation confidence          [Medium]
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

REQUIRED_IDENTITY_ATTRS = ["manager", "department", "employmentType", "email"]


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
# IH-01: Orphaned account
# ---------------------------------------------------------------------------

def detect_ih_01(
    accounts: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Flag accounts that exist in a source but are not correlated
    to any identity. These have no accountable human owner.
    """
    findings: list[Finding] = []
    detector_id = "IH-01"

    for acct in accounts:
        acct_id   = acct.get("id", "unknown")
        acct_name = acct.get("name") or acct.get("displayName") or acct_id
        identity  = acct.get("identityId") or acct.get("identity")
        enabled   = acct.get("enabled", acct.get("status") == "ENABLED")

        if not identity and enabled:
            source = acct.get("sourceName") or acct.get("source", {}).get("name", "unknown")
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, acct_id),
                detector_id=detector_id,
                family=ControlFamily.IH,
                title="Orphaned account — no correlated identity",
                severity=Severity.CRITICAL,
                evidence=FindingEvidence(
                    affected_object_ids=[acct_id],
                    affected_object_names=[acct_name],
                    object_type="account",
                    why_fired=(
                        f"Account '{acct_name}' in source '{source}' is enabled but "
                        f"has no correlated identity. Orphaned accounts cannot be "
                        f"attributed to a person, cannot be included in access reviews, "
                        f"and are a favourite target for attackers — valid credentials "
                        f"with no one watching."
                    ),
                    source_data={
                        "enabled": True,
                        "has_owner": False,
                        "ever_reviewed": False,
                        "source": source,
                    },
                    recommended_fix=(
                        "Investigate immediately. Correlate to a valid identity or "
                        "disable and schedule for removal. Add to a manual review "
                        "campaign if correlation cannot be automated."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.95,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.IH,
        status=CollectionStatus.FULL,
        eligible_count=len(accounts),
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {len(accounts)} accounts")
    return findings, coverage


# ---------------------------------------------------------------------------
# IH-02: Stale enabled account
# ---------------------------------------------------------------------------

def detect_ih_02(
    accounts: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Flag enabled accounts that have had no activity for more than
    policy.stale_account_days. These are dormant but still have valid
    credentials — an easy entry point.
    """
    findings: list[Finding] = []
    detector_id = "IH-02"
    threshold   = policy.stale_account_days
    eligible    = 0

    for acct in accounts:
        acct_id   = acct.get("id", "unknown")
        acct_name = acct.get("name") or acct.get("displayName") or acct_id
        enabled   = acct.get("enabled", acct.get("status") == "ENABLED")

        if not enabled:
            continue

        eligible += 1
        last_activity = acct.get("lastActivity") or acct.get("lastRefreshed")
        days = _days_since(last_activity)

        if days is not None and days > threshold:
            identity_name = (acct.get("identity") or {}).get("name") or "no correlated identity"
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, acct_id),
                detector_id=detector_id,
                family=ControlFamily.IH,
                title="Stale enabled account",
                severity=Severity.HIGH,
                evidence=FindingEvidence(
                    affected_object_ids=[acct_id],
                    affected_object_names=[acct_name],
                    object_type="account",
                    why_fired=(
                        f"Account '{acct_name}' (identity: {identity_name}) has been "
                        f"inactive for {days} days (threshold: {threshold}) but remains "
                        f"enabled. Stale accounts with valid credentials expand the "
                        f"attack surface without providing any business value."
                    ),
                    source_data={
                        "enabled": True,
                        "days_inactive": days,
                        "last_activity": last_activity,
                        "source": acct.get("sourceName", "unknown"),
                    },
                    recommended_fix=(
                        "Disable this account immediately. Confirm with the identity's "
                        "manager whether access is still needed. If not, deprovision "
                        "and document the action for audit trail."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.90,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.IH,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {eligible} enabled accounts")
    return findings, coverage


# ---------------------------------------------------------------------------
# IH-03: Disabled in source, still active in governance view
# ---------------------------------------------------------------------------

def detect_ih_03(
    accounts: list[dict],
    identities: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Catch mismatches where the source system shows the account as disabled,
    but ISC still treats the identity as active — creating a governance blind spot.
    """
    findings: list[Finding] = []
    detector_id = "IH-03"

    # Build identity status index
    identity_status = {
        i.get("id"): i.get("status") or i.get("employeeNumber")
        for i in identities
    }

    eligible = 0
    for acct in accounts:
        acct_id    = acct.get("id", "unknown")
        acct_name  = acct.get("name") or acct.get("displayName") or acct_id
        acct_enabled = acct.get("enabled", True)
        identity_id  = acct.get("identityId") or (acct.get("identity") or {}).get("id")

        if not identity_id:
            continue

        eligible += 1
        not_active = ("INACTIVE", "TERMINATED", "DISABLED")
        identity_active = identity_status.get(identity_id) not in not_active

        # The mismatch: account is disabled at source, but identity is still active in ISC
        if not acct_enabled and identity_active:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, acct_id),
                detector_id=detector_id,
                family=ControlFamily.IH,
                title="Account disabled in source, active in governance view",
                severity=Severity.HIGH,
                evidence=FindingEvidence(
                    affected_object_ids=[acct_id],
                    affected_object_names=[acct_name],
                    object_type="account",
                    why_fired=(
                        f"Account '{acct_name}' is disabled in its source system, "
                        f"but the correlated identity in ISC is still marked active. "
                        f"This mismatch means ISC certifications and governance rules "
                        f"may still consider this access 'live', leading to "
                        f"misleading audit reports and incorrect certifications."
                    ),
                    source_data={
                        "account_enabled": False,
                        "identity_status": identity_status.get(identity_id),
                        "source": acct.get("sourceName", "unknown"),
                    },
                    recommended_fix=(
                        "Trigger an identity refresh to sync the account state from "
                        "the source. Review the correlation rule to ensure lifecycle "
                        "events are propagating correctly."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.80,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.IH,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {eligible} correlated accounts")
    return findings, coverage


# ---------------------------------------------------------------------------
# IH-04: Duplicate identity collision indicators
# ---------------------------------------------------------------------------

def detect_ih_04(
    identities: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Detect when the same person appears to be split across multiple identities —
    a common result of HR system mismatches or manual identity creation.
    """
    findings: list[Finding] = []
    detector_id = "IH-04"

    # Group by email (most reliable dedup signal)
    email_index: dict[str, list[dict]] = {}
    for identity in identities:
        email = (
            identity.get("email")
            or (identity.get("attributes") or {}).get("email")
            or ""
        ).lower().strip()

        if email:
            email_index.setdefault(email, []).append(identity)

    eligible = len(identities)
    seen_ids: set[str] = set()

    for email, dupes in email_index.items():
        if len(dupes) < 2:
            continue

        ids   = [d.get("id", "?") for d in dupes]
        names = [d.get("displayName") or d.get("name") or d.get("id") for d in dupes]

        # Avoid double-reporting the same group
        group_key = frozenset(ids)
        if group_key in seen_ids:
            continue
        seen_ids.add(str(group_key))

        primary_id = ids[0]
        findings.append(Finding(
            finding_id=_make_finding_id(detector_id, primary_id),
            detector_id=detector_id,
            family=ControlFamily.IH,
            title="Duplicate identity collision indicators",
            severity=Severity.HIGH,
            evidence=FindingEvidence(
                affected_object_ids=ids,
                affected_object_names=names,
                object_type="identity",
                why_fired=(
                    f"{len(dupes)} identities share email address '{email}': "
                    f"{', '.join(names)}. Duplicate identities cause access to be "
                    f"split across multiple governance records, making it impossible "
                    f"to get a complete picture of what a person can access."
                ),
                source_data={
                    "shared_email": email,
                    "identity_count": len(dupes),
                    "identity_ids": ids,
                },
                recommended_fix=(
                    "Investigate whether these represent the same person. If so, "
                    "merge identities using ISC's identity merge capability, or "
                    "fix the upstream HR source that is creating duplicates."
                ),
                collection_status=CollectionStatus.FULL,
                confidence=0.85,
            ),
        ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.IH,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} duplicate groups / {eligible} identities")
    return findings, coverage


# ---------------------------------------------------------------------------
# IH-05: Missing core identity attributes
# ---------------------------------------------------------------------------

def detect_ih_05(
    identities: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Flag identities missing manager, department, employment type, or other
    governance-critical attributes. Missing attributes break peer-group
    analysis (AR-03), JML automation, and certification routing.
    """
    findings: list[Finding] = []
    detector_id = "IH-05"

    for identity in identities:
        iid   = identity.get("id", "unknown")
        iname = identity.get("displayName") or identity.get("name") or iid
        attrs = identity.get("attributes") or {}

        missing = []
        for attr in REQUIRED_IDENTITY_ATTRS:
            val = identity.get(attr) or attrs.get(attr)
            if not val:
                missing.append(attr)

        if missing:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, iid),
                detector_id=detector_id,
                family=ControlFamily.IH,
                title="Identity missing core governance attributes",
                severity=Severity.MEDIUM,
                evidence=FindingEvidence(
                    affected_object_ids=[iid],
                    affected_object_names=[iname],
                    object_type="identity",
                    why_fired=(
                        f"Identity '{iname}' is missing: {', '.join(missing)}. "
                        f"These attributes are required for peer-group analysis, "
                        f"JML lifecycle automation, and certification campaign routing. "
                        f"Without them, governance decisions for this identity are "
                        f"based on incomplete data."
                    ),
                    source_data={
                        "missing_attributes": missing,
                        "status": identity.get("status"),
                    },
                    recommended_fix=(
                        "Populate the missing attributes in the authoritative HR source "
                        "and trigger an identity refresh. If attributes are intentionally "
                        "absent (e.g. contractors), update your governance model to "
                        "account for this population."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.90,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.IH,
        status=CollectionStatus.FULL,
        eligible_count=len(identities),
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {len(identities)} identities")
    return findings, coverage


# ---------------------------------------------------------------------------
# IH-06: Account with no recent aggregation confidence
# ---------------------------------------------------------------------------

def detect_ih_06(
    accounts: list[dict],
    sources: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Flag accounts whose source has not been successfully aggregated recently.
    Stale aggregation means ISC's picture of access is potentially outdated —
    making all other findings for those accounts less trustworthy.
    """
    findings: list[Finding] = []
    detector_id = "IH-06"
    threshold   = policy.source_stale_days

    # Build index of stale sources
    stale_sources: set[str] = set()
    for source in sources:
        last_agg = source.get("lastAggregationDate") or source.get("modified")
        days     = _days_since(last_agg)
        if days is not None and days > threshold:
            stale_sources.add(source.get("id", ""))

    eligible = 0
    for acct in accounts:
        source_id = (acct.get("source") or {}).get("id") or acct.get("sourceId")
        if not source_id or source_id not in stale_sources:
            continue

        eligible += 1
        acct_id   = acct.get("id", "unknown")
        acct_name = acct.get("name") or acct.get("displayName") or acct_id
        source_name = acct.get("sourceName") or "unknown source"

        findings.append(Finding(
            finding_id=_make_finding_id(detector_id, acct_id),
            detector_id=detector_id,
            family=ControlFamily.IH,
            title="Account from stale aggregation source",
            severity=Severity.MEDIUM,
            evidence=FindingEvidence(
                affected_object_ids=[acct_id],
                affected_object_names=[acct_name],
                object_type="account",
                why_fired=(
                    f"Account '{acct_name}' belongs to source '{source_name}', "
                    f"which has not been successfully aggregated in over {threshold} days. "
                    f"The access data for this account may not reflect reality — "
                    f"accounts that were deprovisioned in the target system may still "
                    f"appear active in ISC."
                ),
                source_data={
                    "source_id": source_id,
                    "source_name": source_name,
                    "stale_source": True,
                },
                recommended_fix=(
                    f"Investigate why '{source_name}' is not aggregating successfully. "
                    f"Check connector health, VA connectivity, and source credentials. "
                    f"Run a manual aggregation once the root cause is resolved."
                ),
                collection_status=CollectionStatus.FULL,
                confidence=0.85,
            ),
        ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.IH,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(
        "  %s: %d findings from %d stale sources",
        detector_id, len(findings), len(stale_sources),
    )
    return findings, coverage


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run_ih_detectors(
    client: ISCClient,
    policy: PolicyPack,
) -> tuple[list[Finding], list[DetectorCoverage]]:
    logger.info("Running IH — Identity Hygiene detectors")

    accounts   = client.get_accounts()
    identities = client.get_identities()
    sources    = client.get_sources()

    all_findings: list[Finding]          = []
    all_coverage: list[DetectorCoverage] = []

    for detector_fn, kwargs in [
        (detect_ih_01, {"accounts": accounts, "policy": policy}),
        (detect_ih_02, {"accounts": accounts, "policy": policy}),
        (detect_ih_03, {"accounts": accounts, "identities": identities, "policy": policy}),
        (detect_ih_04, {"identities": identities, "policy": policy}),
        (detect_ih_05, {"identities": identities, "policy": policy}),
        (detect_ih_06, {"accounts": accounts, "sources": sources, "policy": policy}),
    ]:
        det_id = detector_fn.__name__.replace("detect_", "").replace("_", "-").upper()
        if not policy.is_detector_enabled(det_id):
            logger.info(f"  {det_id}: disabled in policy pack — skipping")
            continue

        findings, coverage = detector_fn(**kwargs)
        all_findings.extend(findings)
        all_coverage.append(coverage)

    logger.info(f"IH complete: {len(all_findings)} total findings")
    return all_findings, all_coverage
