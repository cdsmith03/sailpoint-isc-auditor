"""
MI — Machine & Privileged Identity detectors.

The headline feature of the auditor. Covers the fastest-growing attack surface
in enterprise identity security: service accounts, automation principals,
break-glass accounts, and unmanaged machine identities.

Detectors:
  MI-01  Machine identity without owner                  [Critical]
  MI-02  Machine identity with privileged access         [Critical]
  MI-03  Dormant machine identity still enabled          [High]
  MI-04  Shared privileged account not tied to a person  [High]
  MI-05  Break-glass access with no control evidence     [Critical]
  MI-06  Service account outside naming/tagging policy   [Medium]
  MI-07  Machine identity created but never reviewed     [Medium]
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import UTC, datetime

from ..client import ISCClient, ISCEndpointUnavailable, ISCPermissionDenied
from ..config import PolicyPack
from ..models import (
    CollectionResult,
    CollectionStatus,
    ControlFamily,
    DetectorCoverage,
    Finding,
    FindingEvidence,
    Severity,
)

logger = logging.getLogger(__name__)


def _make_finding_id(detector_id: str, object_id: str) -> str:
    digest = hashlib.sha256(f"{detector_id}:{object_id}".encode()).hexdigest()[:12]
    return f"{detector_id}-{digest}"


def _days_since(date_str: str | None) -> int | None:
    """Parse an ISO8601 date string and return days since that date."""
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return (datetime.now(UTC) - dt).days
    except (ValueError, TypeError):
        return None


def _is_machine_identity(account: dict) -> bool:
    """
    Heuristic: is this account likely a machine/service identity?
    Used as fallback when the machine identity API is unavailable.
    """
    name = (account.get("name") or "").lower()
    acct_type = (account.get("type") or "").lower()

    if acct_type in ("service", "machine", "system", "application"):
        return True

    machine_prefixes = ("svc-", "svc_", "app-", "app_", "bot-", "bot_",
                        "sys-", "sys_", "sa-", "sa_", "automation-")
    return any(name.startswith(p) for p in machine_prefixes)


# ---------------------------------------------------------------------------
# Collector — fetches machine identity data with graceful fallback
# ---------------------------------------------------------------------------

def collect_machine_identities(client: ISCClient) -> CollectionResult:
    """
    Attempt to collect machine identities from the ISC beta API.
    Falls back to heuristic detection from accounts if the endpoint
    is unavailable (experimental tier restriction).
    """
    try:
        data = client.get_machine_identities()
        logger.info(f"  MI: collected {len(data)} machine identities from API")
        return CollectionResult(
            data=data,
            source="machine_identity_api",
            status=CollectionStatus.FULL,
        )

    except ISCEndpointUnavailable:
        logger.warning(
            "  MI: machine identity API unavailable on this tenant. "
            "Falling back to account-based heuristic detection."
        )
        try:
            all_accounts = client.get_accounts()
            machine_accounts = [a for a in all_accounts if _is_machine_identity(a)]
            logger.info(
                f"  MI: heuristic identified {len(machine_accounts)} "
                f"probable machine identities from {len(all_accounts)} accounts"
            )
            return CollectionResult(
                data=machine_accounts,
                source="account_heuristic_fallback",
                status=CollectionStatus.FALLBACK,
                warning=(
                    "Machine identity API unavailable. Results based on account "
                    "naming patterns and type classification. Enable Machine Identity "
                    "Security in ISC Admin for full coverage. Confidence is reduced."
                ),
            )
        except ISCPermissionDenied:
            return CollectionResult(
                data=[],
                source=None,
                status=CollectionStatus.SKIPPED,
                warning="Insufficient permissions for account data. Add isc:account:read scope.",
            )

    except ISCPermissionDenied:
        return CollectionResult(
            data=[],
            source=None,
            status=CollectionStatus.SKIPPED,
            warning=(
                "Insufficient permissions for machine identity API. "
                "Add isc:machine-identity:read scope to your API client."
            ),
        )


# ---------------------------------------------------------------------------
# MI-01: Machine identity without owner
# ---------------------------------------------------------------------------

def detect_mi_01(
    machine_identities: CollectionResult,
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Flag any machine identity with no owner, no accountable team,
    or no governance group attached.
    """
    findings: list[Finding] = []
    detector_id = "MI-01"
    confidence = 0.9 if machine_identities.status == CollectionStatus.FULL else 0.6

    for mi in machine_identities.data:
        mi_id   = mi.get("id", "unknown")
        mi_name = mi.get("name", mi_id)
        owner   = mi.get("owner") or mi.get("ownerId") or mi.get("ownerName")
        team    = mi.get("team") or mi.get("accountingTeam")

        if not owner and not team:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, mi_id),
                detector_id=detector_id,
                family=ControlFamily.MI,
                title="Machine identity without owner",
                severity=Severity.CRITICAL,
                evidence=FindingEvidence(
                    affected_object_ids=[mi_id],
                    affected_object_names=[mi_name],
                    object_type="machine_identity",
                    why_fired=(
                        f"Machine identity '{mi_name}' has no owner and no accountable "
                        f"team. Without an owner, this identity cannot be reviewed, "
                        f"rotated, or decommissioned — making it a permanent liability."
                    ),
                    source_data={
                        "enabled": mi.get("enabled", mi.get("status") == "ACTIVE"),
                        "has_owner": False,
                        "ever_reviewed": False,
                        "type": mi.get("type", "unknown"),
                    },
                    recommended_fix=(
                        "Assign an owner in ISC. If this identity is no longer used, "
                        "disable and schedule for decommissioning."
                    ),
                    collection_status=machine_identities.status,
                    confidence=confidence,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.MI,
        status=machine_identities.status,
        eligible_count=len(machine_identities.data),
        affected_count=len(findings),
        warning=machine_identities.warning,
    )
    logger.info(
        "  %s: %d findings / %d eligible",
        detector_id, len(findings), len(machine_identities.data),
    )
    return findings, coverage


# ---------------------------------------------------------------------------
# MI-02: Machine identity with privileged access
# ---------------------------------------------------------------------------

def detect_mi_02(
    machine_identities: CollectionResult,
    roles: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Flag machine identities holding admin-like roles, broad entitlements,
    or membership in privileged groups.
    """
    findings: list[Finding] = []
    detector_id = "MI-02"
    confidence = 0.85 if machine_identities.status == CollectionStatus.FULL else 0.55

    # Build a quick lookup of role names to IDs
    privileged_role_names = {
        r["name"].lower() for r in roles
        if any(
            kw in r.get("name", "").lower()
            for kw in ("admin", "administrator", "privileged", "superuser",
                       "root", "global", "owner", "manage")
        )
    }

    for mi in machine_identities.data:
        mi_id   = mi.get("id", "unknown")
        mi_name = mi.get("name", mi_id)

        # Check assigned roles
        assigned_roles = mi.get("roles", []) or []
        privileged_assigned = [
            r for r in assigned_roles
            if (r.get("name") or "").lower() in privileged_role_names
        ]

        # Check entitlements for admin patterns
        entitlements = mi.get("entitlements", []) or []
        privileged_ents = [
            e for e in entitlements
            if any(kw in (e.get("name") or "").lower()
                   for kw in ("admin", "superuser", "root", "owner", "manage", "full"))
        ]

        # Check privileged apps
        sources = [e.get("source", {}).get("name", "") for e in entitlements]
        privileged_app_hits = [s for s in sources if s in policy.privileged_apps]

        if privileged_assigned or privileged_ents or privileged_app_hits:
            priv_detail = (
                f"Privileged roles: {[r['name'] for r in privileged_assigned]}. "
                if privileged_assigned else ""
            ) + (
                f"Privileged entitlements: {[e['name'] for e in privileged_ents[:3]]}. "
                if privileged_ents else ""
            ) + (
                f"Access to privileged apps: {list(set(privileged_app_hits[:3]))}."
                if privileged_app_hits else ""
            )

            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, mi_id),
                detector_id=detector_id,
                family=ControlFamily.MI,
                title="Machine identity with privileged access",
                severity=Severity.CRITICAL,
                evidence=FindingEvidence(
                    affected_object_ids=[mi_id],
                    affected_object_names=[mi_name],
                    object_type="machine_identity",
                    why_fired=(
                        f"Machine identity '{mi_name}' holds privileged access. "
                        f"Unlike human accounts, machine identities cannot use MFA "
                        f"and typically have non-expiring credentials. {priv_detail}"
                    ),
                    source_data={
                        "enabled": mi.get("enabled", True),
                        "privileged": True,
                        "has_owner": bool(mi.get("owner")),
                        "ever_reviewed": False,
                        "privileged_roles": [r.get("name") for r in privileged_assigned],
                        "privileged_entitlements": [e.get("name") for e in privileged_ents[:5]],
                    },
                    recommended_fix=(
                        "Apply least-privilege. Remove any privileged roles or entitlements "
                        "not strictly required. Ensure this identity has an owner and is "
                        "included in certification scope."
                    ),
                    collection_status=machine_identities.status,
                    confidence=confidence,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.MI,
        status=machine_identities.status,
        eligible_count=len(machine_identities.data),
        affected_count=len(findings),
        warning=machine_identities.warning,
    )
    logger.info(
        "  %s: %d findings / %d eligible",
        detector_id, len(findings), len(machine_identities.data),
    )
    return findings, coverage


# ---------------------------------------------------------------------------
# MI-03: Dormant machine identity still enabled
# ---------------------------------------------------------------------------

def detect_mi_03(
    machine_identities: CollectionResult,
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Flag machine identities that have had no activity and no rotation
    evidence for more than policy.inactivity_days, but are still enabled.
    """
    findings: list[Finding] = []
    detector_id = "MI-03"
    threshold   = policy.inactivity_days
    confidence  = 0.85 if machine_identities.status == CollectionStatus.FULL else 0.55

    for mi in machine_identities.data:
        mi_id   = mi.get("id", "unknown")
        mi_name = mi.get("name", mi_id)
        enabled = mi.get("enabled", mi.get("status") == "ACTIVE", )

        if not enabled:
            continue

        last_activity = (
            mi.get("lastActivity")
            or mi.get("lastAuthentication")
            or mi.get("lastModified")
        )
        days = _days_since(last_activity)

        if days is not None and days > threshold:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, mi_id),
                detector_id=detector_id,
                family=ControlFamily.MI,
                title="Dormant machine identity still enabled",
                severity=Severity.HIGH,
                evidence=FindingEvidence(
                    affected_object_ids=[mi_id],
                    affected_object_names=[mi_name],
                    object_type="machine_identity",
                    why_fired=(
                        f"Machine identity '{mi_name}' has had no recorded activity "
                        f"for {days} days (threshold: {threshold}) but remains enabled. "
                        f"Dormant machine identities with valid credentials are a "
                        f"prime target — attackers specifically seek them out because "
                        f"they are unlikely to trigger behavioral alerts."
                    ),
                    source_data={
                        "enabled": True,
                        "days_inactive": days,
                        "last_activity": last_activity,
                        "has_owner": bool(mi.get("owner")),
                        "ever_reviewed": False,
                    },
                    recommended_fix=(
                        "Disable this identity immediately and investigate whether it "
                        "is still needed. If not, decommission and revoke all "
                        "associated credentials. Schedule for formal offboarding."
                    ),
                    collection_status=machine_identities.status,
                    confidence=confidence,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.MI,
        status=machine_identities.status,
        eligible_count=len([m for m in machine_identities.data if m.get("enabled", True)]),
        affected_count=len(findings),
        warning=machine_identities.warning,
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {coverage.eligible_count} eligible")
    return findings, coverage


# ---------------------------------------------------------------------------
# MI-04: Shared privileged account not tied to a person
# ---------------------------------------------------------------------------

def detect_mi_04(
    accounts: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Catch generic admin accounts, shared operational accounts, and
    local break-glass style identities that are not individually attributable.
    """
    findings: list[Finding] = []
    detector_id = "MI-04"
    shared_pattern = re.compile(
        policy.naming_conventions.get("shared_accounts", r"^(shared|generic|admin)[-_]"),
        re.IGNORECASE,
    )

    eligible = 0
    for acct in accounts:
        name     = acct.get("name") or acct.get("displayName") or ""
        identity = acct.get("identityId") or acct.get("identity")
        enabled  = acct.get("enabled", acct.get("status") == "ENABLED")

        if not enabled:
            continue

        if shared_pattern.match(name) and not identity:
            eligible += 1
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, acct.get("id", name)),
                detector_id=detector_id,
                family=ControlFamily.MI,
                title="Shared privileged account not tied to a person",
                severity=Severity.HIGH,
                evidence=FindingEvidence(
                    affected_object_ids=[acct.get("id", "unknown")],
                    affected_object_names=[name],
                    object_type="account",
                    why_fired=(
                        f"Account '{name}' appears to be a shared or generic account "
                        f"and is not correlated to any individual identity. Shared "
                        f"accounts make it impossible to audit who performed an action, "
                        f"violating non-repudiation requirements."
                    ),
                    source_data={
                        "enabled": True,
                        "has_owner": False,
                        "correlated_identity": False,
                        "source": acct.get("sourceName", "unknown"),
                    },
                    recommended_fix=(
                        "Correlate this account to a named identity or service owner. "
                        "If it is a true shared account, implement a vaulted credential "
                        "solution with session recording (PAM) and full audit trail."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.75,  # pattern matching — some false positives expected
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.MI,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {len(accounts)} accounts scanned")
    return findings, coverage


# ---------------------------------------------------------------------------
# MI-05: Break-glass access with no control evidence
# ---------------------------------------------------------------------------

def detect_mi_05(
    accounts: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Emergency accounts with no owner, no naming standard, no review
    evidence, or standing access that looks permanent.
    """
    findings: list[Finding] = []
    detector_id = "MI-05"
    bg_pattern = re.compile(
        policy.naming_conventions.get("break_glass", r"^(bg|emergency|breakglass)[-_]"),
        re.IGNORECASE,
    )

    eligible = 0
    for acct in accounts:
        name    = acct.get("name") or acct.get("displayName") or ""
        enabled = acct.get("enabled", acct.get("status") == "ENABLED")

        name_lower = name.lower()
        is_bg = bg_pattern.match(name) or "breakglass" in name_lower or "break-glass" in name_lower
        if not is_bg:
            continue

        eligible += 1
        owner    = acct.get("owner") or acct.get("ownerId")
        reviewed = acct.get("lastCertified") or acct.get("lastReviewed")
        issues   = []

        if not owner:
            issues.append("no owner assigned")
        if not reviewed:
            issues.append("never certified or reviewed")
        if enabled:
            issues.append("standing access is permanently enabled (should be disabled by default)")

        if issues:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, acct.get("id", name)),
                detector_id=detector_id,
                family=ControlFamily.MI,
                title="Break-glass account with no control evidence",
                severity=Severity.CRITICAL,
                evidence=FindingEvidence(
                    affected_object_ids=[acct.get("id", "unknown")],
                    affected_object_names=[name],
                    object_type="account",
                    why_fired=(
                        f"Break-glass account '{name}' has control failures: "
                        f"{', '.join(issues)}. Break-glass accounts are among the "
                        f"most sensitive identities in any environment — they exist "
                        f"for emergencies but must be tightly controlled."
                    ),
                    source_data={
                        "enabled": enabled,
                        "has_owner": bool(owner),
                        "ever_reviewed": bool(reviewed),
                        "standing_access": enabled,
                        "issues": issues,
                    },
                    recommended_fix=(
                        "1. Assign a named owner immediately. "
                        "2. Disable the account and implement a vaulted check-out process. "
                        "3. Add to certification scope with quarterly review cadence. "
                        "4. Enable access event alerting for any use of this account."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.90,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.MI,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {eligible} break-glass accounts")
    return findings, coverage


# ---------------------------------------------------------------------------
# MI-06: Service account outside naming/tagging policy
# ---------------------------------------------------------------------------

def detect_mi_06(
    machine_identities: CollectionResult,
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Flag service accounts that don't follow naming conventions,
    lack required tags (description, environment, criticality, system).
    """
    findings: list[Finding] = []
    detector_id = "MI-06"
    svc_pattern = re.compile(
        policy.naming_conventions.get("service_accounts", r"^svc[-_]"),
        re.IGNORECASE,
    )
    required_attrs = ["description", "environment", "criticality"]

    for mi in machine_identities.data:
        mi_id   = mi.get("id", "unknown")
        mi_name = mi.get("name", mi_id)

        # Only check things that look like service accounts
        if not (svc_pattern.match(mi_name) or (mi.get("type") or "").lower() == "service"):
            continue

        missing = [
            attr for attr in required_attrs
            if not mi.get(attr) and not (mi.get("attributes") or {}).get(attr)
        ]

        if not svc_pattern.match(mi_name):
            missing.append("naming convention")

        if missing:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, mi_id),
                detector_id=detector_id,
                family=ControlFamily.MI,
                title="Service account outside naming/tagging policy",
                severity=Severity.MEDIUM,
                evidence=FindingEvidence(
                    affected_object_ids=[mi_id],
                    affected_object_names=[mi_name],
                    object_type="machine_identity",
                    why_fired=(
                        f"Service account '{mi_name}' is missing: {', '.join(missing)}. "
                        f"Without standardized naming and tagging, machine identities "
                        f"cannot be reliably discovered, governed, or decommissioned."
                    ),
                    source_data={
                        "missing_attributes": missing,
                        "has_owner": bool(mi.get("owner")),
                    },
                    recommended_fix=(
                        f"Add the missing attributes: {', '.join(missing)}. "
                        f"Ensure the name follows the "
                        f"'{policy.naming_conventions.get('service_accounts')}' "
                        f"convention defined in your policy pack."
                    ),
                    collection_status=machine_identities.status,
                    confidence=0.80,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.MI,
        status=machine_identities.status,
        eligible_count=len(machine_identities.data),
        affected_count=len(findings),
        warning=machine_identities.warning,
    )
    logger.info(
        "  %s: %d findings / %d eligible",
        detector_id, len(findings), len(machine_identities.data),
    )
    return findings, coverage


# ---------------------------------------------------------------------------
# MI-07: Machine identity created but never reviewed
# ---------------------------------------------------------------------------

def detect_mi_07(
    machine_identities: CollectionResult,
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Machine identities that exist in ISC but have never been part of
    certification scope or had meaningful governance attached.
    """
    findings: list[Finding] = []
    detector_id = "MI-07"
    confidence  = 0.80 if machine_identities.status == CollectionStatus.FULL else 0.50

    for mi in machine_identities.data:
        mi_id   = mi.get("id", "unknown")
        mi_name = mi.get("name", mi_id)

        last_certified = mi.get("lastCertified") or mi.get("lastReviewed")
        if not last_certified:
            created = mi.get("created") or mi.get("createdAt")
            days_old = _days_since(created) or 0

            if days_old > 30:   # Give 30 days grace after creation
                findings.append(Finding(
                    finding_id=_make_finding_id(detector_id, mi_id),
                    detector_id=detector_id,
                    family=ControlFamily.MI,
                    title="Machine identity created but never reviewed",
                    severity=Severity.MEDIUM,
                    evidence=FindingEvidence(
                        affected_object_ids=[mi_id],
                        affected_object_names=[mi_name],
                        object_type="machine_identity",
                        why_fired=(
                            f"Machine identity '{mi_name}' was created {days_old} days ago "
                            f"but has never been included in a certification campaign or "
                            f"manually reviewed. Unreviewed machine identities may hold "
                            f"access that was never formally approved."
                        ),
                        source_data={
                            "days_old": days_old,
                            "ever_reviewed": False,
                            "has_owner": bool(mi.get("owner")),
                        },
                        recommended_fix=(
                            "Add this identity to an active certification campaign. "
                            "Review its access and confirm or revoke entitlements. "
                            "Assign an owner to maintain ongoing governance."
                        ),
                        collection_status=machine_identities.status,
                        confidence=confidence,
                    ),
                ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.MI,
        status=machine_identities.status,
        eligible_count=len(machine_identities.data),
        affected_count=len(findings),
        warning=machine_identities.warning,
    )
    logger.info(
        "  %s: %d findings / %d eligible",
        detector_id, len(findings), len(machine_identities.data),
    )
    return findings, coverage


# ---------------------------------------------------------------------------
# Module entry point — run all MI detectors
# ---------------------------------------------------------------------------

def run_mi_detectors(
    client: ISCClient,
    policy: PolicyPack,
) -> tuple[list[Finding], list[DetectorCoverage]]:
    """
    Run all MI detectors and return findings + coverage metadata.
    Called by the main audit engine.
    """
    logger.info("Running MI — Machine & Privileged Identity detectors")

    # Collect data
    machine_ids = collect_machine_identities(client)
    accounts    = client.get_accounts()
    roles       = client.get_roles()

    all_findings:  list[Finding]          = []
    all_coverage:  list[DetectorCoverage] = []

    # Run each detector
    for detector_fn, kwargs in [
        (detect_mi_01, {"machine_identities": machine_ids, "policy": policy}),
        (detect_mi_02, {"machine_identities": machine_ids, "roles": roles, "policy": policy}),
        (detect_mi_03, {"machine_identities": machine_ids, "policy": policy}),
        (detect_mi_04, {"accounts": accounts, "policy": policy}),
        (detect_mi_05, {"accounts": accounts, "policy": policy}),
        (detect_mi_06, {"machine_identities": machine_ids, "policy": policy}),
        (detect_mi_07, {"machine_identities": machine_ids, "policy": policy}),
    ]:
        det_id = detector_fn.__name__.replace("detect_", "").replace("_", "-").upper()
        if not policy.is_detector_enabled(det_id):
            logger.info(f"  {det_id}: disabled in policy pack — skipping")
            continue

        findings, coverage = detector_fn(**kwargs)
        all_findings.extend(findings)
        all_coverage.append(coverage)

    logger.info(f"MI complete: {len(all_findings)} total findings")
    return all_findings, all_coverage
