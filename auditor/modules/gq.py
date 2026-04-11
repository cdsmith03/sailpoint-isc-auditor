"""
GQ — Governance Quality detectors.

The best place to showcase the AI layer. These detectors surface
behavioral patterns (rubber-stamping, blind spots, missing ownership)
that deterministic checks alone cannot fully explain — Claude adds
the "why this matters" context that makes these findings actionable.

Detectors:
  GQ-01  Overdue certification campaign                      [High]
  GQ-02  Low coverage on high-risk access                    [High]
  GQ-03  Bulk-approval / rubber-stamp pattern                [High]
  GQ-04  Unowned governance object                           [High]
  GQ-05  Empty or weak governance group                      [Medium]
  GQ-06  Self-review or conflicted review path               [Medium]
  GQ-07  Access item missing business context                [Medium]
  GQ-08  Certification blind spots (governance-group model)  [Medium]
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

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


def _make_finding_id(detector_id: str, object_id: str) -> str:
    digest = hashlib.sha256(f"{detector_id}:{object_id}".encode()).hexdigest()[:12]
    return f"{detector_id}-{digest}"


def _days_since(date_str: str | None) -> int | None:
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# GQ-01: Overdue certification campaign
# ---------------------------------------------------------------------------

def detect_gq_01(
    certifications: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Certification campaigns still open past their due date.
    Overdue reviews mean access hasn't been confirmed as appropriate —
    a direct compliance gap.
    """
    findings: list[Finding] = []
    detector_id = "GQ-01"
    threshold   = policy.certification_overdue_days
    eligible    = 0

    for cert in certifications:
        status = (cert.get("status") or "").upper()
        if status in ("COMPLETE", "CLOSED", "CANCELLED"):
            continue

        eligible += 1
        due_date = cert.get("deadline") or cert.get("dueDate")
        days_overdue = _days_since(due_date)

        if days_overdue is not None and days_overdue > threshold:
            cid   = cert.get("id", "unknown")
            cname = cert.get("name") or f"Campaign {cid}"
            reviewer_count = cert.get("totalReviewers") or cert.get("reviewerCount") or 0
            items_pending  = cert.get("pendingItems") or cert.get("itemsCount") or 0

            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, cid),
                detector_id=detector_id,
                family=ControlFamily.GQ,
                title="Overdue certification campaign",
                severity=Severity.HIGH,
                evidence=FindingEvidence(
                    affected_object_ids=[cid],
                    affected_object_names=[cname],
                    object_type="certification",
                    why_fired=(
                        f"Certification campaign '{cname}' is {days_overdue} days "
                        f"overdue (threshold: {threshold} days). "
                        f"{items_pending} items remain pending across "
                        f"{reviewer_count} reviewers. Overdue campaigns mean access "
                        f"decisions are being deferred — a direct compliance gap."
                    ),
                    source_data={
                        "due_date": due_date,
                        "days_overdue": days_overdue,
                        "status": status,
                        "pending_items": items_pending,
                        "reviewer_count": reviewer_count,
                    },
                    recommended_fix=(
                        "Escalate to campaign owners and reviewers immediately. "
                        "Send reminder notifications. If the campaign cannot be "
                        "completed, document the reason and the compensating control."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.95,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.GQ,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} overdue campaigns / {eligible} active")
    return findings, coverage


# ---------------------------------------------------------------------------
# GQ-02: Low coverage on high-risk access
# ---------------------------------------------------------------------------

def detect_gq_02(
    certifications: list[dict],
    roles: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Critical apps and privileged roles not entering review scope often enough.
    Governance without coverage of the highest-risk items is security theater.
    """
    findings: list[Finding] = []
    detector_id = "GQ-02"

    # What roles are considered privileged?
    privileged_roles = [
        r for r in roles
        if any(kw in (r.get("name") or "").lower()
               for kw in ("admin", "privileged", "superuser", "global"))
    ]

    # Which privileged roles appear in any certification scope?
    certified_role_ids: set[str] = set()
    for cert in certifications:
        for item in cert.get("items") or []:
            if item.get("type") == "ROLE":
                certified_role_ids.add(item.get("id") or item.get("roleId") or "")

    uncertified_privileged = [
        r for r in privileged_roles
        if r.get("id") not in certified_role_ids
    ]

    eligible = len(privileged_roles)

    if uncertified_privileged:
        names = [r.get("name") or r.get("id") for r in uncertified_privileged[:8]]
        findings.append(Finding(
            finding_id=_make_finding_id(detector_id, "privileged-roles"),
            detector_id=detector_id,
            family=ControlFamily.GQ,
            title="Privileged roles not in certification scope",
            severity=Severity.HIGH,
            evidence=FindingEvidence(
                affected_object_ids=[r.get("id", "") for r in uncertified_privileged],
                affected_object_names=names,
                object_type="role",
                why_fired=(
                    f"{len(uncertified_privileged)} privileged role(s) are not included "
                    f"in any certification campaign: {', '.join(names[:5])}. "
                    f"High-risk access that is never reviewed is a systematic governance "
                    f"gap — exactly what external auditors look for."
                ),
                source_data={
                    "uncertified_count": len(uncertified_privileged),
                    "total_privileged": len(privileged_roles),
                    "role_names": names,
                },
                recommended_fix=(
                    "Add these privileged roles to an active certification campaign "
                    "immediately. Schedule quarterly reviews as a minimum cadence."
                ),
                collection_status=CollectionStatus.FULL,
                confidence=0.85,
            ),
        ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.GQ,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(uncertified_privileged)} uncertified privileged roles")
    return findings, coverage


# ---------------------------------------------------------------------------
# GQ-03: Bulk-approval / rubber-stamp pattern
# ---------------------------------------------------------------------------

def detect_gq_03(
    certifications: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Reviewer behavior looks mechanical: unusually fast approvals, near-100%
    approve rate, identical rationale, minimal variance across items.
    This is the "green score, real risk" problem in certifications.
    """
    findings: list[Finding] = []
    detector_id = "GQ-03"
    eligible = 0

    FAST_APPROVAL_SECONDS = 30    # less than 30s per decision = suspicious
    HIGH_APPROVE_RATE     = 0.98  # 98%+ approve rate on large campaigns

    for cert in certifications:
        status = (cert.get("status") or "").upper()
        if status not in ("COMPLETE", "CLOSED"):
            continue

        eligible += 1
        cid   = cert.get("id", "unknown")
        cname = cert.get("name") or f"Campaign {cid}"

        total_items    = cert.get("totalItems") or cert.get("itemsCount") or 0
        approved_items = cert.get("approvedItems") or 0
        revoked_items  = cert.get("revokedItems") or 0
        duration_secs  = cert.get("durationSeconds")

        if total_items < 10:   # Too small for meaningful stats
            continue

        approve_rate = approved_items / total_items if total_items else 0
        issues = []

        if approve_rate >= HIGH_APPROVE_RATE and total_items >= 20:
            issues.append(
                f"{approve_rate*100:.1f}% approval rate across {total_items} items "
                f"({revoked_items} revocations)"
            )

        if duration_secs and total_items:
            avg_secs = duration_secs / total_items
            if avg_secs < FAST_APPROVAL_SECONDS:
                issues.append(
                    f"Average {avg_secs:.0f}s per decision "
                    f"(threshold: {FAST_APPROVAL_SECONDS}s)"
                )

        if issues:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, cid),
                detector_id=detector_id,
                family=ControlFamily.GQ,
                title="Rubber-stamp pattern in certification campaign",
                severity=Severity.HIGH,
                evidence=FindingEvidence(
                    affected_object_ids=[cid],
                    affected_object_names=[cname],
                    object_type="certification",
                    why_fired=(
                        f"Certification '{cname}' shows rubber-stamp indicators: "
                        f"{'; '.join(issues)}. "
                        f"Mechanical approvals defeat the purpose of access reviews — "
                        f"the access is certified but not genuinely reviewed."
                    ),
                    source_data={
                        "total_items": total_items,
                        "approved_items": approved_items,
                        "revoked_items": revoked_items,
                        "approve_rate": approve_rate,
                        "avg_seconds_per_decision": duration_secs / total_items if duration_secs and total_items else None,
                    },
                    recommended_fix=(
                        "Review the certification design. Consider AI-assisted "
                        "recommendations to guide reviewers. Add mandatory comments "
                        "for approvals of sensitive access. Consider splitting large "
                        "campaigns into smaller, more focused reviews."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.80,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.GQ,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} rubber-stamp campaigns / {eligible} completed")
    return findings, coverage


# ---------------------------------------------------------------------------
# GQ-04: Unowned governance object
# ---------------------------------------------------------------------------

def detect_gq_04(
    roles: list[dict],
    access_profiles: list[dict],
    sources: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Roles, access profiles, sources, or entitlements with no owner.
    Without an owner, governance decisions cannot be made authoritatively.
    """
    findings: list[Finding] = []
    detector_id = "GQ-04"

    all_objects = (
        [("role", r) for r in roles] +
        [("access_profile", ap) for ap in access_profiles] +
        [("source", s) for s in sources]
    )

    eligible = len(all_objects)

    for obj_type, obj in all_objects:
        obj_id   = obj.get("id", "unknown")
        obj_name = obj.get("name") or obj_id
        owner    = obj.get("owner") or obj.get("ownerId") or obj.get("ownerName")

        if not owner:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, obj_id),
                detector_id=detector_id,
                family=ControlFamily.GQ,
                title=f"Unowned {obj_type.replace('_', ' ')}",
                severity=Severity.HIGH,
                evidence=FindingEvidence(
                    affected_object_ids=[obj_id],
                    affected_object_names=[obj_name],
                    object_type=obj_type,
                    why_fired=(
                        f"{obj_type.replace('_', ' ').title()} '{obj_name}' has no owner. "
                        f"Without an owner, nobody is accountable for approving access "
                        f"requests, reviewing certifications, or making governance decisions "
                        f"for this object. It cannot be properly governed."
                    ),
                    source_data={
                        "has_owner": False,
                        "object_type": obj_type,
                    },
                    recommended_fix=(
                        f"Assign an owner to '{obj_name}' immediately. The owner should "
                        f"be the business stakeholder responsible for this access, not "
                        f"an IT administrator. Schedule a review of all ownership gaps."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.95,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.GQ,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} unowned objects / {eligible} total")
    return findings, coverage


# ---------------------------------------------------------------------------
# GQ-05: Empty or weak governance group
# ---------------------------------------------------------------------------

def detect_gq_05(
    governance_groups: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Governance groups used for certification or access request decisions
    that have no members, inactive members, or wrong composition.
    """
    findings: list[Finding] = []
    detector_id = "GQ-05"

    for gg in governance_groups:
        gg_id   = gg.get("id", "unknown")
        gg_name = gg.get("name") or gg_id
        members = gg.get("members") or gg.get("memberCount") or 0

        if isinstance(members, list):
            member_count = len(members)
        else:
            member_count = int(members)

        if member_count == 0:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, gg_id),
                detector_id=detector_id,
                family=ControlFamily.GQ,
                title="Empty governance group",
                severity=Severity.MEDIUM,
                evidence=FindingEvidence(
                    affected_object_ids=[gg_id],
                    affected_object_names=[gg_name],
                    object_type="governance_group",
                    why_fired=(
                        f"Governance group '{gg_name}' has no members. If this group "
                        f"is used for access request approvals or certification assignments, "
                        f"those processes will fail or route incorrectly."
                    ),
                    source_data={"member_count": 0, "has_owner": bool(gg.get("owner"))},
                    recommended_fix=(
                        "Add appropriate members to this governance group, or deactivate "
                        "it if it is no longer needed. Check what workflows reference it."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.95,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.GQ,
        status=CollectionStatus.FULL,
        eligible_count=len(governance_groups),
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} empty groups / {len(governance_groups)} total")
    return findings, coverage


# ---------------------------------------------------------------------------
# GQ-06: Self-review or conflicted review path
# ---------------------------------------------------------------------------

def detect_gq_06(
    certifications: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Reviewer is also the owner/requester/beneficiary — a basic conflict of interest.
    """
    findings: list[Finding] = []
    detector_id = "GQ-06"
    eligible    = 0

    for cert in certifications:
        cid   = cert.get("id", "unknown")
        cname = cert.get("name") or f"Campaign {cid}"

        for item in cert.get("items") or []:
            eligible += 1
            reviewer_id  = (item.get("reviewer") or {}).get("id")
            subject_id   = (item.get("subject") or item.get("identity") or {}).get("id")
            requester_id = (item.get("requestedBy") or {}).get("id")

            if not reviewer_id:
                continue

            if reviewer_id == subject_id:
                findings.append(Finding(
                    finding_id=_make_finding_id(detector_id, f"{cid}-{item.get('id', '')}"),
                    detector_id=detector_id,
                    family=ControlFamily.GQ,
                    title="Self-review detected in certification",
                    severity=Severity.MEDIUM,
                    evidence=FindingEvidence(
                        affected_object_ids=[cid],
                        affected_object_names=[cname],
                        object_type="certification_item",
                        why_fired=(
                            f"In campaign '{cname}', an identity is reviewing their own "
                            f"access. Self-reviews are a direct conflict of interest and "
                            f"are prohibited by most compliance frameworks (SOX, SOC2)."
                        ),
                        source_data={
                            "reviewer_id": reviewer_id,
                            "subject_id": subject_id,
                            "self_review": True,
                        },
                        recommended_fix=(
                            "Reassign this review item to an independent reviewer — "
                            "the subject's manager, or a designated compliance approver. "
                            "Update the certification workflow to prevent self-reviews automatically."
                        ),
                        collection_status=CollectionStatus.FULL,
                        confidence=0.90,
                    ),
                ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.GQ,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} self-reviews / {eligible} items checked")
    return findings, coverage


# ---------------------------------------------------------------------------
# GQ-07: Access item missing business context
# ---------------------------------------------------------------------------

def detect_gq_07(
    roles: list[dict],
    access_profiles: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Roles and access profiles with no description, classification, or
    justification text. Without context, reviewers can't make informed decisions.
    """
    findings: list[Finding] = []
    detector_id = "GQ-07"

    all_objects = [("role", r) for r in roles] + [("access_profile", ap) for ap in access_profiles]
    eligible    = len(all_objects)

    for obj_type, obj in all_objects:
        obj_id      = obj.get("id", "unknown")
        obj_name    = obj.get("name") or obj_id
        description = obj.get("description") or ""

        if not description or len(description.strip()) < 20:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, obj_id),
                detector_id=detector_id,
                family=ControlFamily.GQ,
                title=f"{obj_type.replace('_', ' ').title()} missing description",
                severity=Severity.MEDIUM,
                evidence=FindingEvidence(
                    affected_object_ids=[obj_id],
                    affected_object_names=[obj_name],
                    object_type=obj_type,
                    why_fired=(
                        f"{obj_type.replace('_', ' ').title()} '{obj_name}' has no "
                        f"meaningful description. Reviewers in certification campaigns "
                        f"cannot make informed approve/revoke decisions without knowing "
                        f"what access this object grants and why it exists."
                    ),
                    source_data={"has_description": bool(description), "description_length": len(description)},
                    recommended_fix=(
                        f"Add a clear business-language description to '{obj_name}' that "
                        f"explains: what access it grants, who should have it, and why it exists."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.90,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.GQ,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} undescribed objects / {eligible} total")
    return findings, coverage


# ---------------------------------------------------------------------------
# GQ-08: Certification blind spots (governance-group assigned certifications)
# ---------------------------------------------------------------------------

def detect_gq_08(
    certifications: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    NOTE: The ISC access-review-items API does not support certifications
    assigned to Governance Groups. This detector surfaces that blind spot
    explicitly so the audit report is honest about its own coverage limits.
    """
    findings: list[Finding] = []
    detector_id = "GQ-08"

    gg_certs = [
        c for c in certifications
        if c.get("reviewerType") == "GOVERNANCE_GROUP"
        or c.get("certifierType") == "GOVERNANCE_GROUP"
    ]

    if gg_certs:
        names = [c.get("name") or c.get("id") for c in gg_certs[:5]]
        findings.append(Finding(
            finding_id=_make_finding_id(detector_id, "gg-blind-spot"),
            detector_id=detector_id,
            family=ControlFamily.GQ,
            title="Certification blind spot — governance group assignments",
            severity=Severity.MEDIUM,
            evidence=FindingEvidence(
                affected_object_ids=[c.get("id", "") for c in gg_certs],
                affected_object_names=names,
                object_type="certification",
                why_fired=(
                    f"{len(gg_certs)} certification campaign(s) are assigned to "
                    f"Governance Groups: {', '.join(names[:3])}. "
                    f"The ISC access-review-items API does not return item-level data "
                    f"for governance-group-assigned certifications, meaning this audit "
                    f"cannot inspect the individual decisions within these campaigns."
                ),
                source_data={
                    "governance_group_cert_count": len(gg_certs),
                    "campaign_names": names,
                },
                recommended_fix=(
                    "This is an ISC API limitation, not a configuration error. "
                    "Review these campaigns manually in the ISC UI, or use the "
                    "ISC reporting module to export item-level data. Consider "
                    "switching high-risk campaigns to individual reviewer assignment "
                    "for full audit visibility."
                ),
                collection_status=CollectionStatus.PARTIAL,
                confidence=1.0,  # The blind spot itself is certain
            ),
        ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.GQ,
        status=CollectionStatus.PARTIAL if gg_certs else CollectionStatus.FULL,
        eligible_count=len(certifications),
        affected_count=len(gg_certs),
        warning=(
            f"API limitation: {len(gg_certs)} certification(s) assigned to "
            f"Governance Groups cannot be fully inspected at item level."
            if gg_certs else None
        ),
    )
    logger.info(f"  {detector_id}: {len(gg_certs)} governance-group campaigns flagged")
    return findings, coverage


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run_gq_detectors(
    client: ISCClient,
    policy: PolicyPack,
) -> tuple[list[Finding], list[DetectorCoverage]]:
    logger.info("Running GQ — Governance Quality detectors")

    certifications    = client.get_certifications()
    roles             = client.get_roles()
    access_profiles   = client.get_access_profiles()
    sources           = client.get_sources()
    governance_groups = client.get_governance_groups()

    all_findings: list[Finding]          = []
    all_coverage: list[DetectorCoverage] = []

    for detector_fn, kwargs in [
        (detect_gq_01, {"certifications": certifications, "policy": policy}),
        (detect_gq_02, {"certifications": certifications, "roles": roles, "policy": policy}),
        (detect_gq_03, {"certifications": certifications, "policy": policy}),
        (detect_gq_04, {"roles": roles, "access_profiles": access_profiles, "sources": sources, "policy": policy}),
        (detect_gq_05, {"governance_groups": governance_groups, "policy": policy}),
        (detect_gq_06, {"certifications": certifications, "policy": policy}),
        (detect_gq_07, {"roles": roles, "access_profiles": access_profiles, "policy": policy}),
        (detect_gq_08, {"certifications": certifications, "policy": policy}),
    ]:
        det_id = detector_fn.__name__.replace("detect_", "").replace("_", "-").upper()
        if not policy.is_detector_enabled(det_id):
            logger.info(f"  {det_id}: disabled in policy pack — skipping")
            continue

        findings, coverage = detector_fn(**kwargs)
        all_findings.extend(findings)
        all_coverage.append(coverage)

    logger.info(f"GQ complete: {len(all_findings)} total findings")
    return all_findings, all_coverage
