"""
LI — Lifecycle Integrity detectors.

Where real operational pain shows up. Terminations, role changes,
contractor expirations, and authoritative source drift are the most
common causes of serious audit findings.

Detectors:
  LI-01  Terminated identity with active accounts              [Critical]
  LI-02  Terminated identity with privileged access            [Critical]
  LI-03  Mover retained stale access after job change          [High]
  LI-04  Joiner missing baseline, manual compensating access   [Medium]
  LI-05  Non-employee past end date still active               [Critical]
  LI-06  Identity status mismatch across authoritative systems [High]
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime, timezone

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

TERMINATED_STATUSES = {"TERMINATED", "INACTIVE", "DISABLED", "LEAVER", "OFFBOARDED"}
PRIVILEGED_KEYWORDS = {"admin", "administrator", "privileged", "superuser", "root",
                       "global", "owner", "manage", "payroll", "finance", "hr admin"}


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


def _is_terminated(identity: dict) -> bool:
    status = (identity.get("status") or "").upper()
    emp_status = (
        (identity.get("attributes") or {}).get("employmentStatus") or ""
    ).upper()
    return status in TERMINATED_STATUSES or emp_status in TERMINATED_STATUSES


def _has_privileged_access(accounts: list[dict], entitlements: list[dict]) -> bool:
    for acct in accounts:
        name = (acct.get("name") or "").lower()
        if any(kw in name for kw in PRIVILEGED_KEYWORDS):
            return True
    for ent in entitlements:
        name = (ent.get("name") or "").lower()
        if any(kw in name for kw in PRIVILEGED_KEYWORDS):
            return True
    return False


# ---------------------------------------------------------------------------
# LI-01: Terminated identity with active accounts
# ---------------------------------------------------------------------------

def detect_li_01(
    identities: list[dict],
    accounts_by_identity: dict[str, list[dict]],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    A leaver still has one or more enabled downstream accounts.
    This is one of the most serious and most common lifecycle failures.
    """
    findings: list[Finding] = []
    detector_id = "LI-01"
    eligible = 0

    for identity in identities:
        if not _is_terminated(identity):
            continue

        iid   = identity.get("id", "unknown")
        iname = identity.get("displayName") or identity.get("name") or iid
        eligible += 1

        active_accounts = [
            a for a in accounts_by_identity.get(iid, [])
            if a.get("enabled", a.get("status") == "ENABLED")
        ]

        if active_accounts:
            account_names = [
                a.get("name") or a.get("displayName") or a.get("id")
                for a in active_accounts[:5]
            ]
            termination_date = (
                identity.get("terminationDate")
                or (identity.get("attributes") or {}).get("terminationDate")
            )
            days_since_term = _days_since(termination_date)

            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, iid),
                detector_id=detector_id,
                family=ControlFamily.LI,
                title="Terminated identity with active accounts",
                severity=Severity.CRITICAL,
                evidence=FindingEvidence(
                    affected_object_ids=[iid] + [a.get("id", "") for a in active_accounts],
                    affected_object_names=[iname] + account_names,
                    object_type="identity",
                    why_fired=(
                        f"Identity '{iname}' is marked as terminated"
                        f"{f' ({days_since_term} days ago)' if days_since_term else ''} "
                        f"but still has {len(active_accounts)} active downstream account(s): "
                        f"{', '.join(account_names)}. "
                        f"Former employees with active credentials represent one of the "
                        f"highest-risk scenarios in identity security."
                    ),
                    source_data={
                        "enabled": True,
                        "identity_status": identity.get("status"),
                        "active_account_count": len(active_accounts),
                        "termination_date": termination_date,
                        "days_since_termination": days_since_term,
                        "has_owner": False,
                        "ever_reviewed": False,
                    },
                    recommended_fix=(
                        "Disable all active accounts immediately. Review provisioning "
                        "policies to determine why deprovisioning did not complete. "
                        "Investigate for any access that may have been used post-termination."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.95,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.LI,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {eligible} terminated identities")
    return findings, coverage


# ---------------------------------------------------------------------------
# LI-02: Terminated identity with privileged access
# ---------------------------------------------------------------------------

def detect_li_02(
    identities: list[dict],
    accounts_by_identity: dict[str, list[dict]],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Same as LI-01 but specifically targeting terminated identities
    that still hold privileged or sensitive access. Always Critical.
    """
    findings: list[Finding] = []
    detector_id = "LI-02"
    eligible = 0

    for identity in identities:
        if not _is_terminated(identity):
            continue

        iid   = identity.get("id", "unknown")
        iname = identity.get("displayName") or identity.get("name") or iid
        eligible += 1

        active_accounts = [
            a for a in accounts_by_identity.get(iid, [])
            if a.get("enabled", a.get("status") == "ENABLED")
        ]

        if not active_accounts:
            continue

        privileged_accounts = [
            a for a in active_accounts
            if any(kw in (a.get("name") or "").lower() for kw in PRIVILEGED_KEYWORDS)
            or a.get("privileged") is True
        ]

        if privileged_accounts:
            priv_names = [a.get("name") or a.get("id") for a in privileged_accounts[:5]]
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, iid),
                detector_id=detector_id,
                family=ControlFamily.LI,
                title="Terminated identity with privileged access",
                severity=Severity.CRITICAL,
                evidence=FindingEvidence(
                    affected_object_ids=[iid] + [a.get("id", "") for a in privileged_accounts],
                    affected_object_names=[iname] + priv_names,
                    object_type="identity",
                    why_fired=(
                        f"Terminated identity '{iname}' retains privileged access in "
                        f"{len(privileged_accounts)} account(s): {', '.join(priv_names)}. "
                        f"Privileged access for a former employee is a critical control "
                        f"failure and likely a regulatory violation."
                    ),
                    source_data={
                        "enabled": True,
                        "privileged": True,
                        "identity_status": identity.get("status"),
                        "privileged_account_count": len(privileged_accounts),
                        "has_owner": False,
                        "ever_reviewed": False,
                    },
                    recommended_fix=(
                        "Revoke all privileged access immediately. Escalate to security "
                        "and compliance teams. Document the gap and the remediation "
                        "action for audit evidence. Review PAM vault access logs for "
                        "any post-termination usage."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.97,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.LI,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {eligible} terminated identities")
    return findings, coverage


# ---------------------------------------------------------------------------
# LI-03: Mover retained stale access after job change
# ---------------------------------------------------------------------------

def detect_li_03(
    identities: list[dict],
    accounts_by_identity: dict[str, list[dict]],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Role/department/title changed but previous access remains beyond grace period.
    Movers are the most dangerous unchecked group — they accumulate access silently.
    """
    findings: list[Finding] = []
    detector_id = "LI-03"
    grace_days  = policy.mover_grace_days
    eligible    = 0

    for identity in identities:
        if _is_terminated(identity):
            continue

        iid   = identity.get("id", "unknown")
        iname = identity.get("displayName") or identity.get("name") or iid
        attrs = identity.get("attributes") or {}

        # Look for a recent job change signal
        last_role_change = (
            attrs.get("lastDepartmentChange")
            or attrs.get("lastJobCodeChange")
            or attrs.get("lastTitleChange")
            or identity.get("modified")
        )

        if not last_role_change:
            continue

        days_since_change = _days_since(last_role_change)
        if days_since_change is None or days_since_change <= grace_days:
            continue

        eligible += 1
        active_accounts = accounts_by_identity.get(iid, [])

        # Look for access that predates the role change — heuristic based on account age
        potentially_stale = []
        for acct in active_accounts:
            created = acct.get("created") or acct.get("createdDate")
            days_old = _days_since(created)
            if days_old and days_old > days_since_change + grace_days:
                potentially_stale.append(acct)

        if potentially_stale:
            stale_names = [a.get("name") or a.get("id") for a in potentially_stale[:5]]
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, iid),
                detector_id=detector_id,
                family=ControlFamily.LI,
                title="Mover with potentially stale access after role change",
                severity=Severity.HIGH,
                evidence=FindingEvidence(
                    affected_object_ids=[iid],
                    affected_object_names=[iname],
                    object_type="identity",
                    why_fired=(
                        f"Identity '{iname}' had a role change {days_since_change} days ago "
                        f"(grace period: {grace_days} days) and still holds "
                        f"{len(potentially_stale)} account(s) that predate the change: "
                        f"{', '.join(stale_names)}. Movers accumulate access over time "
                        f"if role changes don't trigger access reviews."
                    ),
                    source_data={
                        "days_since_role_change": days_since_change,
                        "grace_days": grace_days,
                        "potentially_stale_count": len(potentially_stale),
                        "last_role_change": last_role_change,
                    },
                    recommended_fix=(
                        "Launch a targeted access review for this identity. Focus on "
                        "access granted before the role change date. Remove anything "
                        "not required for the current role."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.70,  # Heuristic — some false positives expected
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.LI,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {eligible} movers checked")
    return findings, coverage


# ---------------------------------------------------------------------------
# LI-04: Joiner missing baseline, manual compensating access granted
# ---------------------------------------------------------------------------

def detect_li_04(
    identities: list[dict],
    accounts_by_identity: dict[str, list[dict]],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Catches messy onboarding patterns: a new joiner didn't get their
    role-based baseline access, so someone manually granted compensating
    access instead — creating long-term drift.
    """
    findings: list[Finding] = []
    detector_id = "LI-04"
    eligible = 0

    for identity in identities:
        if _is_terminated(identity):
            continue

        iid   = identity.get("id", "unknown")
        iname = identity.get("displayName") or identity.get("name") or iid
        created = identity.get("created") or identity.get("createdDate")
        days_old = _days_since(created)

        # Only look at identities created in the last 90 days (joiners)
        if not days_old or days_old > 90:
            continue

        eligible += 1
        accounts = accounts_by_identity.get(iid, [])

        # Heuristic: joiner has manually provisioned accounts but no role-based ones
        manual_accounts = [
            a for a in accounts
            if a.get("manuallyCorrelated") or a.get("origin") == "MANUAL"
        ]
        role_accounts = [
            a for a in accounts
            if a.get("origin") in ("ROLE", "ACCESS_PROFILE", "RULE")
        ]

        if manual_accounts and not role_accounts:
            manual_names = [a.get("name") or a.get("id") for a in manual_accounts[:5]]
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, iid),
                detector_id=detector_id,
                family=ControlFamily.LI,
                title="Joiner with manual access, no role-based baseline",
                severity=Severity.MEDIUM,
                evidence=FindingEvidence(
                    affected_object_ids=[iid],
                    affected_object_names=[iname],
                    object_type="identity",
                    why_fired=(
                        f"New joiner '{iname}' (created {days_old} days ago) has "
                        f"{len(manual_accounts)} manually granted account(s) but no "
                        f"role or access profile-based access: {', '.join(manual_names)}. "
                        f"This indicates the role model did not cover this joiner's "
                        f"profile, and someone worked around it manually."
                    ),
                    source_data={
                        "days_old": days_old,
                        "manual_account_count": len(manual_accounts),
                        "role_account_count": len(role_accounts),
                    },
                    recommended_fix=(
                        "Review whether existing roles cover this joiner's profile. "
                        "If not, create a role to cover this population and migrate "
                        "the manual grants. Manual access should be the exception, "
                        "not the pattern."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.70,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.LI,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {eligible} joiners checked")
    return findings, coverage


# ---------------------------------------------------------------------------
# LI-05: Non-employee past end date still active
# ---------------------------------------------------------------------------

def detect_li_05(
    non_employees: list[dict],
    accounts_by_identity: dict[str, list[dict]],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Contractor/vendor/non-employee record has expired, but access remains.
    ISC explicitly supports non-employee lifecycle management — this is first-class coverage.
    """
    findings: list[Finding] = []
    detector_id = "LI-05"
    grace_days  = policy.non_employee_grace_days

    for ne in non_employees:
        ne_id   = ne.get("id", "unknown")
        ne_name = (
            f"{ne.get('firstName', '')} {ne.get('lastName', '')}".strip()
            or ne.get("displayName") or ne_id
        )
        end_date = ne.get("endDate") or ne.get("contractEndDate")
        if not end_date:
            continue

        days_past = _days_since(end_date)
        if days_past is None or days_past <= grace_days:
            continue

        # Check if they still have active accounts
        identity_id = ne.get("accountName") or ne.get("identityId")
        active_accounts = [
            a for a in accounts_by_identity.get(identity_id or ne_id, [])
            if a.get("enabled", a.get("status") == "ENABLED")
        ]

        # Flag even without active accounts if the record itself is still active
        ne_active = ne.get("status", "").upper() not in ("TERMINATED", "INACTIVE", "EXPIRED")

        if active_accounts or ne_active:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, ne_id),
                detector_id=detector_id,
                family=ControlFamily.LI,
                title="Non-employee past contract end date still active",
                severity=Severity.CRITICAL,
                evidence=FindingEvidence(
                    affected_object_ids=[ne_id],
                    affected_object_names=[ne_name],
                    object_type="non_employee",
                    why_fired=(
                        f"Non-employee '{ne_name}' passed their contract end date "
                        f"{days_past} days ago (grace period: {grace_days} days) and "
                        f"{'still has ' + str(len(active_accounts)) + ' active account(s)' if active_accounts else 'the non-employee record is still active'}. "
                        f"Expired contractors with active access represent a direct "
                        f"compliance violation in most regulatory frameworks."
                    ),
                    source_data={
                        "end_date": end_date,
                        "days_past_end_date": days_past,
                        "grace_days": grace_days,
                        "active_account_count": len(active_accounts),
                        "ne_status": ne.get("status"),
                        "has_owner": False,
                        "ever_reviewed": False,
                    },
                    recommended_fix=(
                        "Terminate the non-employee record in ISC and deprovision all "
                        "associated accounts immediately. If the contract was extended, "
                        "update the end date and document the approval. Review for "
                        "any access used post-expiry."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.92,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.LI,
        status=CollectionStatus.FULL,
        eligible_count=len(non_employees),
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {len(non_employees)} non-employees")
    return findings, coverage


# ---------------------------------------------------------------------------
# LI-06: Identity status mismatch across authoritative and target systems
# ---------------------------------------------------------------------------

def detect_li_06(
    identities: list[dict],
    accounts_by_identity: dict[str, list[dict]],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    The authoritative source says this identity is inactive or changed,
    but downstream target systems haven't reflected it. A data propagation failure.
    """
    findings: list[Finding] = []
    detector_id = "LI-06"
    eligible = 0

    for identity in identities:
        iid    = identity.get("id", "unknown")
        iname  = identity.get("displayName") or identity.get("name") or iid
        status = (identity.get("status") or "").upper()
        attrs  = identity.get("attributes") or {}

        auth_status = (attrs.get("employmentStatus") or attrs.get("status") or "").upper()

        # Only interested in identities where ISC and HR disagree
        if not auth_status or auth_status == status:
            continue

        eligible += 1

        # ISC says active, HR says something else (or vice versa)
        is_mismatch = (
            (status == "ACTIVE" and auth_status in TERMINATED_STATUSES)
            or (status in TERMINATED_STATUSES and auth_status == "ACTIVE")
        )

        if not is_mismatch:
            continue

        active_accounts = [
            a for a in accounts_by_identity.get(iid, [])
            if a.get("enabled", a.get("status") == "ENABLED")
        ]

        findings.append(Finding(
            finding_id=_make_finding_id(detector_id, iid),
            detector_id=detector_id,
            family=ControlFamily.LI,
            title="Identity status mismatch — authoritative vs ISC",
            severity=Severity.HIGH,
            evidence=FindingEvidence(
                affected_object_ids=[iid],
                affected_object_names=[iname],
                object_type="identity",
                why_fired=(
                    f"Identity '{iname}' has a status conflict: ISC shows '{status}' "
                    f"but the authoritative HR source shows '{auth_status}'. "
                    f"This identity has {len(active_accounts)} active downstream account(s). "
                    f"Status mismatches indicate the lifecycle automation is not functioning "
                    f"correctly and create governance blind spots."
                ),
                source_data={
                    "isc_status": status,
                    "authoritative_status": auth_status,
                    "active_account_count": len(active_accounts),
                },
                recommended_fix=(
                    "Trigger an identity refresh from the authoritative source. "
                    "Investigate the correlation rule and lifecycle event handling. "
                    "If the HR source is authoritative, ISC should reflect it within "
                    "one aggregation cycle."
                ),
                collection_status=CollectionStatus.FULL,
                confidence=0.80,
            ),
        ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.LI,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {eligible} identities with auth status")
    return findings, coverage


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run_li_detectors(
    client: ISCClient,
    policy: PolicyPack,
) -> tuple[list[Finding], list[DetectorCoverage]]:
    logger.info("Running LI — Lifecycle Integrity detectors")

    identities    = client.get_identities()
    accounts      = client.get_accounts()
    non_employees = client.get_non_employees()

    # Build accounts-by-identity index once (used by multiple detectors)
    accounts_by_identity: dict[str, list[dict]] = {}
    for acct in accounts:
        iid = acct.get("identityId") or (acct.get("identity") or {}).get("id")
        if iid:
            accounts_by_identity.setdefault(iid, []).append(acct)

    all_findings: list[Finding]          = []
    all_coverage: list[DetectorCoverage] = []

    for detector_fn, kwargs in [
        (detect_li_01, {"identities": identities, "accounts_by_identity": accounts_by_identity, "policy": policy}),
        (detect_li_02, {"identities": identities, "accounts_by_identity": accounts_by_identity, "policy": policy}),
        (detect_li_03, {"identities": identities, "accounts_by_identity": accounts_by_identity, "policy": policy}),
        (detect_li_04, {"identities": identities, "accounts_by_identity": accounts_by_identity, "policy": policy}),
        (detect_li_05, {"non_employees": non_employees, "accounts_by_identity": accounts_by_identity, "policy": policy}),
        (detect_li_06, {"identities": identities, "accounts_by_identity": accounts_by_identity, "policy": policy}),
    ]:
        det_id = detector_fn.__name__.replace("detect_", "").replace("_", "-").upper()
        if not policy.is_detector_enabled(det_id):
            logger.info(f"  {det_id}: disabled in policy pack — skipping")
            continue

        findings, coverage = detector_fn(**kwargs)
        all_findings.extend(findings)
        all_coverage.append(coverage)

    logger.info(f"LI complete: {len(all_findings)} total findings")
    return all_findings, all_coverage
