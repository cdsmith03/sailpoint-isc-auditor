"""
AR — Access Risk detectors.

Combines hard policy checks (SOD violations from ISC's own engine)
with peer-based statistical analysis and structural access anti-patterns.

Detectors:
  AR-01  Active SOD violation                              [Critical]
  AR-02  Toxic entitlement combo (no formal SOD policy)   [High]
  AR-03  Excessive access vs peer group                   [High]
  AR-04  Direct entitlement where role should be used     [Medium]
  AR-05  Role or access profile with entitlement bloat    [High]
  AR-06  Sensitive access held by broad population        [Critical]
  AR-07  Redundant access paths                           [Medium]
"""

from __future__ import annotations

import hashlib
import logging
import statistics
from collections import defaultdict

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

# Known toxic combinations even without a formal SOD policy
# Format: (entitlement_keyword_a, entitlement_keyword_b, description)
KNOWN_TOXIC_COMBOS = [
    ("payroll", "gl posting", "Payroll + GL Posting — classic segregation of duties violation"),
    ("payroll", "finance admin",   "Payroll + Finance Admin — ability to pay and approve payments"),
    ("iam admin", "audit",         "IAM Admin + Audit — ability to manage and audit own access"),
    ("create user", "approve",     "User creation + approval — self-approval of privileged access"),
    ("deploy", "approve deploy", "Deploy + Approve Deploy — self-approve production changes"),
    ("hr admin", "payroll",        "HR Admin + Payroll — full compensation chain control"),
]


def _make_finding_id(detector_id: str, object_id: str) -> str:
    digest = hashlib.sha256(f"{detector_id}:{object_id}".encode()).hexdigest()[:12]
    return f"{detector_id}-{digest}"


def _entitlement_names(identity: dict) -> list[str]:
    return [
        e.get("name") or ""
        for e in (identity.get("access") or [])
        if e.get("type") == "ENTITLEMENT"
    ]


# ---------------------------------------------------------------------------
# AR-01: Active SOD violation (from ISC's own engine)
# ---------------------------------------------------------------------------

def detect_ar_01(
    sod_violations: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Use ISC's SOD violations data directly — the most reliable signal.
    These are policy-defined conflicts that ISC has already flagged.
    """
    findings: list[Finding] = []
    detector_id = "AR-01"

    for violation in sod_violations:
        vid      = violation.get("id", "unknown")
        identity = violation.get("identity") or {}
        iid      = identity.get("id", "unknown")
        iname    = identity.get("name") or identity.get("displayName") or iid
        policy_name = (
            violation.get("policyName")
            or violation.get("policy", {}).get("name")
            or "Unknown policy"
        )
        created  = violation.get("created")

        conflicting = violation.get("conflictingEntitlements") or []
        conflict_names = [c.get("name") or c.get("id") for c in conflicting[:4]]

        findings.append(Finding(
            finding_id=_make_finding_id(detector_id, vid),
            detector_id=detector_id,
            family=ControlFamily.AR,
            title="Active SOD violation",
            severity=Severity.CRITICAL,
            evidence=FindingEvidence(
                affected_object_ids=[iid, vid],
                affected_object_names=[iname],
                object_type="sod_violation",
                why_fired=(
                    f"Identity '{iname}' has an active SOD violation under policy "
                    f"'{policy_name}'. Conflicting entitlements: {', '.join(conflict_names)}. "
                    f"SOD violations represent a direct failure of your access control "
                    f"model and are typically a high-priority audit finding."
                ),
                source_data={
                    "policy_name": policy_name,
                    "conflicting_entitlements": conflict_names,
                    "violation_created": created,
                    "enabled": True,
                    "has_owner": True,
                    "ever_reviewed": False,
                },
                recommended_fix=(
                    "Review immediately. Either remediate by revoking one of the "
                    "conflicting entitlements, or obtain a documented compensating "
                    "control exception approved by the appropriate risk owner."
                ),
                collection_status=CollectionStatus.FULL,
                confidence=1.0,  # Straight from ISC's own engine
            ),
        ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.AR,
        status=CollectionStatus.FULL,
        eligible_count=len(sod_violations),
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} active SOD violations")
    return findings, coverage


# ---------------------------------------------------------------------------
# AR-02: Toxic entitlement combination (no formal SOD policy)
# ---------------------------------------------------------------------------

def detect_ar_02(
    identities: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Heuristic layer for toxic combos the customer forgot to encode as policy.
    Uses known high-risk patterns to surface violations outside the SOD engine.
    """
    findings: list[Finding] = []
    detector_id = "AR-02"
    eligible = 0

    for identity in identities:
        iid   = identity.get("id", "unknown")
        iname = identity.get("displayName") or identity.get("name") or iid
        ents  = [e.lower() for e in _entitlement_names(identity)]

        if not ents:
            continue

        eligible += 1
        for kw_a, kw_b, description in KNOWN_TOXIC_COMBOS:
            has_a = any(kw_a in e for e in ents)
            has_b = any(kw_b in e for e in ents)

            if has_a and has_b:
                findings.append(Finding(
                    finding_id=_make_finding_id(detector_id, f"{iid}-{kw_a}"),
                    detector_id=detector_id,
                    family=ControlFamily.AR,
                    title="Toxic entitlement combination (outside formal SOD)",
                    severity=Severity.HIGH,
                    evidence=FindingEvidence(
                        affected_object_ids=[iid],
                        affected_object_names=[iname],
                        object_type="identity",
                        why_fired=(
                            f"Identity '{iname}' holds a known toxic access combination: "
                            f"{description}. This combination is not currently modeled "
                            f"as a formal SOD policy in ISC, meaning it won't appear "
                            f"in SOD violation reports."
                        ),
                        source_data={
                            "toxic_pattern": f"{kw_a} + {kw_b}",
                            "description": description,
                        },
                        recommended_fix=(
                            "Review and remediate. Consider formalizing this combination "
                            "as an SOD policy in ISC so future violations are automatically "
                            "detected and prevented."
                        ),
                        collection_status=CollectionStatus.FULL,
                        confidence=0.75,
                    ),
                ))
                break  # One finding per identity per pass

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.AR,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} toxic combos / {eligible} identities checked")
    return findings, coverage


# ---------------------------------------------------------------------------
# AR-03: Excessive access vs peer group
# ---------------------------------------------------------------------------

def detect_ar_03(
    identities: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Outlier detection: identities with significantly more access than their
    peers (same department + job code). Normalized so large tenants aren't
    unfairly penalized — it's about relative outliers, not raw counts.
    """
    findings: list[Finding] = []
    detector_id = "AR-03"
    outlier_pct  = policy.peer_group_outlier_pct / 100.0

    # Group by department + job code
    peer_groups: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
    for identity in identities:
        attrs  = identity.get("attributes") or {}
        dept   = attrs.get("department") or identity.get("department") or "unknown"
        job    = attrs.get("jobCode") or attrs.get("title") or "unknown"
        key    = f"{dept}|{job}"
        iid    = identity.get("id", "unknown")
        iname  = identity.get("displayName") or identity.get("name") or iid
        ent_count = len(_entitlement_names(identity))
        peer_groups[key].append((iid, iname, ent_count))

    eligible = 0
    for group_key, members in peer_groups.items():
        if len(members) < 3:   # Too small to do meaningful statistics
            continue

        counts = [m[2] for m in members]
        if not any(counts):
            continue

        eligible += len(members)
        threshold = statistics.quantiles(counts, n=100)[int(outlier_pct * 100) - 1]

        for iid, iname, ent_count in members:
            if ent_count > threshold:
                dept, job = group_key.split("|", 1)
                peer_avg  = round(statistics.mean(counts), 1)
                findings.append(Finding(
                    finding_id=_make_finding_id(detector_id, iid),
                    detector_id=detector_id,
                    family=ControlFamily.AR,
                    title="Excessive access vs peer group",
                    severity=Severity.HIGH,
                    evidence=FindingEvidence(
                        affected_object_ids=[iid],
                        affected_object_names=[iname],
                        object_type="identity",
                        why_fired=(
                            f"Identity '{iname}' ({dept} / {job}) holds {ent_count} "
                            f"entitlements — above the {int(policy.peer_group_outlier_pct)}th "
                            f"percentile ({threshold:.0f}) for their peer group "
                            f"(avg: {peer_avg}, n={len(members)}). "
                            f"Significant outliers often indicate access accumulation "
                            f"over time or role changes without cleanup."
                        ),
                        source_data={
                            "entitlement_count": ent_count,
                            "peer_avg": peer_avg,
                            "peer_p95": threshold,
                            "peer_group_size": len(members),
                            "department": dept,
                            "job_code": job,
                        },
                        recommended_fix=(
                            "Review all entitlements for this identity. Focus on those "
                            "not held by any peer. Remove anything that cannot be "
                            "justified by current role requirements."
                        ),
                        collection_status=CollectionStatus.FULL,
                        confidence=0.80,
                    ),
                ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.AR,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} outliers / {eligible} in peer groups")
    return findings, coverage


# ---------------------------------------------------------------------------
# AR-04: Direct entitlement where role should be used
# ---------------------------------------------------------------------------

def detect_ar_04(
    identities: list[dict],
    roles: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Flags identities that have direct entitlement grants in areas where
    a role or access profile should have been used. Direct grants create
    governance drift and certification pain.
    """
    findings: list[Finding] = []
    detector_id = "AR-04"

    # Build set of entitlement IDs covered by roles
    role_covered_entitlements: set[str] = set()
    for role in roles:
        for ent in role.get("entitlements") or []:
            eid = ent.get("id") or ent.get("entitlementId")
            if eid:
                role_covered_entitlements.add(eid)

    eligible = 0
    for identity in identities:
        iid   = identity.get("id", "unknown")
        iname = identity.get("displayName") or identity.get("name") or iid

        direct_ents = [
            e for e in (identity.get("access") or [])
            if e.get("type") == "ENTITLEMENT"
            and e.get("source") not in ("ROLE", "ACCESS_PROFILE")
            and e.get("id") in role_covered_entitlements
        ]

        if not (identity.get("access") or []):
            continue

        eligible += 1

        if direct_ents:
            ent_names = [e.get("name") or e.get("id") for e in direct_ents[:5]]
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, iid),
                detector_id=detector_id,
                family=ControlFamily.AR,
                title="Direct entitlement grant where role should be used",
                severity=Severity.MEDIUM,
                evidence=FindingEvidence(
                    affected_object_ids=[iid],
                    affected_object_names=[iname],
                    object_type="identity",
                    why_fired=(
                        f"Identity '{iname}' has {len(direct_ents)} entitlement(s) "
                        f"granted directly that are also covered by existing roles: "
                        f"{', '.join(ent_names)}. Direct grants bypass role governance, "
                        f"create certification complexity, and often signal one-off "
                        f"workarounds that become permanent."
                    ),
                    source_data={
                        "direct_grant_count": len(direct_ents),
                        "entitlement_names": ent_names,
                    },
                    recommended_fix=(
                        "Assign the appropriate role instead of the direct entitlement. "
                        "Once the role is in place, revoke the direct grant. This "
                        "reduces certification burden and improves governance visibility."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.75,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.AR,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {eligible} identities")
    return findings, coverage


# ---------------------------------------------------------------------------
# AR-05: Role or access profile with entitlement bloat
# ---------------------------------------------------------------------------

def detect_ar_05(
    roles: list[dict],
    access_profiles: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Roles and access profiles that have accumulated too many entitlements,
    or contain overly broad/critical ones. Large roles are hard to certify
    and violate least-privilege principles.
    """
    findings: list[Finding] = []
    detector_id = "AR-05"

    all_objects = [
        ("role", r) for r in roles
    ] + [
        ("access_profile", ap) for ap in access_profiles
    ]

    eligible = len(all_objects)

    for obj_type, obj in all_objects:
        obj_id   = obj.get("id", "unknown")
        obj_name = obj.get("name") or obj_id
        ents     = obj.get("entitlements") or []

        # Bloat thresholds
        high_count = 50
        critical_count = 100

        if len(ents) < high_count:
            continue

        sensitive_ents = [
            e for e in ents
            if any(kw in (e.get("name") or "").lower()
                   for kw in ("admin", "privileged", "payroll", "finance", "root"))
        ]

        severity = Severity.CRITICAL if len(ents) >= critical_count else Severity.HIGH
        findings.append(Finding(
            finding_id=_make_finding_id(detector_id, obj_id),
            detector_id=detector_id,
            family=ControlFamily.AR,
            title=f"Entitlement bloat in {obj_type.replace('_', ' ')}",
            severity=severity,
            evidence=FindingEvidence(
                affected_object_ids=[obj_id],
                affected_object_names=[obj_name],
                object_type=obj_type,
                why_fired=(
                    f"{obj_type.replace('_', ' ').title()} '{obj_name}' contains "
                    f"{len(ents)} entitlements"
                    + (f", including {len(sensitive_ents)} sensitive ones" if sensitive_ents else "")
                    + ". Oversized roles violate least-privilege, are difficult to certify "
                    "meaningfully, and create a large blast radius if misassigned."
                ),
                source_data={
                    "entitlement_count": len(ents),
                    "sensitive_count": len(sensitive_ents),
                    "object_type": obj_type,
                },
                recommended_fix=(
                    "Decompose this role into smaller, more targeted roles aligned "
                    "with specific job functions. Prioritize removing sensitive "
                    "entitlements that should be in a separate privileged role."
                ),
                collection_status=CollectionStatus.FULL,
                confidence=0.90,
            ),
        ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.AR,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} bloated objects / {eligible} total")
    return findings, coverage


# ---------------------------------------------------------------------------
# AR-06: Sensitive access held by broad population
# ---------------------------------------------------------------------------

def detect_ar_06(
    identities: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Surfaces cases where sensitive entitlements are held by far too many
    people. A sensitive entitlement held by 1 person is governance;
    held by 200 people is a control failure.
    """
    findings: list[Finding] = []
    detector_id = "AR-06"

    # Count holders per sensitive entitlement
    ent_holders: dict[str, list[str]] = defaultdict(list)
    for identity in identities:
        iname = identity.get("displayName") or identity.get("name") or identity.get("id", "?")
        for ent_name in _entitlement_names(identity):
            for sensitive in policy.sensitive_entitlements:
                if sensitive.lower() in ent_name.lower():
                    ent_holders[sensitive].append(iname)

    # Flag entitlements held by more than 5% of the identity population
    total_identities = max(len(identities), 1)
    broad_threshold  = max(10, int(total_identities * 0.05))

    for ent_name, holders in ent_holders.items():
        if len(holders) > broad_threshold:
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, ent_name.replace(" ", "_")),
                detector_id=detector_id,
                family=ControlFamily.AR,
                title="Sensitive entitlement held by broad population",
                severity=Severity.CRITICAL,
                evidence=FindingEvidence(
                    affected_object_ids=[],
                    affected_object_names=holders[:10],
                    object_type="entitlement",
                    why_fired=(
                        f"Sensitive entitlement '{ent_name}' is held by {len(holders)} "
                        f"identities — {len(holders)/total_identities*100:.1f}% of the "
                        f"total population (threshold: {broad_threshold}). "
                        f"Sensitive access at this scale is almost certainly excessive "
                        f"and represents a significant blast radius."
                    ),
                    source_data={
                        "entitlement_name": ent_name,
                        "holder_count": len(holders),
                        "total_population": total_identities,
                        "percentage": round(len(holders) / total_identities * 100, 1),
                        "sample_holders": holders[:10],
                        "enabled": True,
                        "ever_reviewed": False,
                    },
                    recommended_fix=(
                        f"Launch an immediate certification campaign for all holders of "
                        f"'{ent_name}'. Remove this entitlement from anyone who cannot "
                        f"justify a business need. Consider restricting future assignment "
                        f"via a request workflow with business owner approval."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.90,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.AR,
        status=CollectionStatus.FULL,
        eligible_count=len(policy.sensitive_entitlements),
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} over-distributed sensitive entitlements")
    return findings, coverage


# ---------------------------------------------------------------------------
# AR-07: Redundant access paths
# ---------------------------------------------------------------------------

def detect_ar_07(
    identities: list[dict],
    policy: PolicyPack,
) -> tuple[list[Finding], DetectorCoverage]:
    """
    Detects identities that receive the same effective access through
    multiple paths (role + access profile + direct grant). Redundant paths
    create certification complexity and confusion about the intended model.
    """
    findings: list[Finding] = []
    detector_id = "AR-07"
    eligible = 0

    for identity in identities:
        iid   = identity.get("id", "unknown")
        iname = identity.get("displayName") or identity.get("name") or iid
        access = identity.get("access") or []

        if not access:
            continue
        eligible += 1

        # Group by entitlement ID, collect all sources
        ent_sources: dict[str, list[str]] = defaultdict(list)
        for item in access:
            eid    = item.get("id") or item.get("entitlementId")
            source = item.get("source") or item.get("type") or "DIRECT"
            if eid:
                ent_sources[eid].append(source)

        redundant = {
            eid: sources
            for eid, sources in ent_sources.items()
            if len(sources) > 1
        }

        if len(redundant) >= 3:   # Only flag if meaningfully redundant
            findings.append(Finding(
                finding_id=_make_finding_id(detector_id, iid),
                detector_id=detector_id,
                family=ControlFamily.AR,
                title="Redundant access paths",
                severity=Severity.MEDIUM,
                evidence=FindingEvidence(
                    affected_object_ids=[iid],
                    affected_object_names=[iname],
                    object_type="identity",
                    why_fired=(
                        f"Identity '{iname}' receives {len(redundant)} entitlement(s) "
                        f"through multiple overlapping paths (role + direct, etc.). "
                        f"Redundant paths complicate certifications, make it harder "
                        f"to reason about effective access, and can mask unintended grants."
                    ),
                    source_data={
                        "redundant_entitlement_count": len(redundant),
                    },
                    recommended_fix=(
                        "Consolidate access through a single path — preferably role or "
                        "access profile based. Remove direct grants where a role already "
                        "provides the same entitlement."
                    ),
                    collection_status=CollectionStatus.FULL,
                    confidence=0.75,
                ),
            ))

    coverage = DetectorCoverage(
        detector_id=detector_id,
        family=ControlFamily.AR,
        status=CollectionStatus.FULL,
        eligible_count=eligible,
        affected_count=len(findings),
    )
    logger.info(f"  {detector_id}: {len(findings)} findings / {eligible} identities")
    return findings, coverage


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run_ar_detectors(
    client: ISCClient,
    policy: PolicyPack,
) -> tuple[list[Finding], list[DetectorCoverage]]:
    logger.info("Running AR — Access Risk detectors")

    identities      = client.get_identities()
    roles           = client.get_roles()
    access_profiles = client.get_access_profiles()
    sod_violations  = client.get_sod_violations()

    all_findings: list[Finding]          = []
    all_coverage: list[DetectorCoverage] = []

    for detector_fn, kwargs in [
        (detect_ar_01, {"sod_violations": sod_violations, "policy": policy}),
        (detect_ar_02, {"identities": identities, "policy": policy}),
        (detect_ar_03, {"identities": identities, "policy": policy}),
        (detect_ar_04, {"identities": identities, "roles": roles, "policy": policy}),
        (detect_ar_05, {"roles": roles, "access_profiles": access_profiles, "policy": policy}),
        (detect_ar_06, {"identities": identities, "policy": policy}),
        (detect_ar_07, {"identities": identities, "policy": policy}),
    ]:
        det_id = detector_fn.__name__.replace("detect_", "").replace("_", "-").upper()
        if not policy.is_detector_enabled(det_id):
            logger.info(f"  {det_id}: disabled in policy pack — skipping")
            continue

        findings, coverage = detector_fn(**kwargs)
        all_findings.extend(findings)
        all_coverage.append(coverage)

    logger.info(f"AR complete: {len(all_findings)} total findings")
    return all_findings, all_coverage
