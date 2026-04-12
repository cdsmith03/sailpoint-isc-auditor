"""
JSON reporter for sailpoint-isc-auditor.

Produces two output files optimized for different consumers:

  report.json   — One complete audit document per run.
                  Best for: archival, dashboards, BI tools, APIs, run comparison.
                  Schema: versioned summary block + detailed findings array.

  findings.ndjson — One finding per line (Newline-Delimited JSON).
                    Best for: SIEM ingestion (Splunk, Sentinel), log pipelines,
                    ticket creation automation, streaming/append-style ingestion.

Schema version: 1
Both outputs share the same schema_version field so consumers can detect
breaking changes and gate on compatibility.

Design principles:
  - SIEM-first: every field has a stable, predictable name and type
  - Flat where possible: nested objects are minimized in NDJSON findings
  - Explicit nulls: missing AI fields are null, not absent
  - Timestamps are ISO-8601 with timezone (never naive)
  - All IDs are strings (finding_id, detector_id, tenant_url)
  - Severity is always lowercase string: critical/high/medium/low/info
  - Suppressed findings are included with suppressed: true (never silently dropped)

Usage:
    from auditor.reporters.json_reporter import generate_json_report
    report_path, ndjson_path = generate_json_report(result, Path("audit_2026-04-12"))
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import __version__
from ..models import AuditResult, Finding

SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Internal serialisers
# ---------------------------------------------------------------------------

def _fmt_dt(dt: datetime | None) -> str | None:
    """Serialise a datetime to ISO-8601 with UTC timezone."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        # Treat naive as UTC and flag it
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ (assumed UTC)")
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _finding_to_dict(
    f: Finding, audit_run_id: str, tenant_url: str, audited_at: str,
) -> dict[str, Any]:
    """
    Serialise a single finding to a flat dict suitable for both the
    findings array in report.json and a single NDJSON line.

    All fields are present on every finding — missing values are null,
    not absent. This makes SIEM field mapping reliable.
    """
    return {
        # Run context — repeated on every finding for NDJSON consumers
        # who process one line at a time without access to the summary block
        "schema_version":  SCHEMA_VERSION,
        "audit_run_id":    audit_run_id,
        "tenant_url":      tenant_url,
        "audited_at":      audited_at,

        # Finding identity
        "finding_id":      f.finding_id,
        "detector_id":     f.detector_id,
        "family":          f.family.value,
        "title":           f.title,
        "severity":        f.severity.value,

        # Risk score
        "risk_score":      f.risk_score.normalized if f.risk_score else None,
        "risk_impact":     f.risk_score.impact if f.risk_score else None,
        "risk_exploitability": f.risk_score.exploitability if f.risk_score else None,
        "risk_governance_failure": f.risk_score.governance_failure if f.risk_score else None,

        # Evidence
        "why_fired":            f.evidence.why_fired or None,
        "recommended_fix":      f.evidence.recommended_fix or None,
        "affected_object_ids":  f.evidence.affected_object_ids,
        "affected_object_names": f.evidence.affected_object_names,
        "object_type":          f.evidence.object_type or None,
        "evidence_confidence":  f.evidence.confidence,
        "collection_status":    f.evidence.collection_status.value,

        # Suppression
        "suppressed":           f.suppressed,
        "suppression_reason":   f.suppression.reason if f.suppression else None,
        "suppression_ticket":   f.suppression.ticket if f.suppression else None,
        "suppressed_at":        _fmt_dt(f.suppression.suppressed_at) if f.suppression else None,
        "suppression_expires":  _fmt_dt(f.suppression.expires_at) if f.suppression else None,

        # AI analysis — explicit null when --no-ai was used
        "ai_explanation":   f.ai_explanation,
        "ai_blast_radius":  f.ai_blast_radius,
        "ai_remediation":   f.ai_remediation,
        "ai_audit_note":    f.ai_audit_note,

        # Timestamps
        "first_seen":       _fmt_dt(f.first_seen),
        "last_seen":        _fmt_dt(f.last_seen),
    }


def _build_summary(result: AuditResult, audit_run_id: str) -> dict[str, Any]:
    """
    Build the top-level summary block for report.json.
    Dashboards and BI tools read this without touching the findings array.
    """
    health = result.health_score
    cov    = health.coverage_confidence

    active     = [f for f in result.findings if not f.suppressed]
    suppressed = [f for f in result.findings if f.suppressed]

    # Severity counts (active only)
    from ..models import Severity
    sev_counts = {s.value: 0 for s in Severity}
    for f in active:
        sev_counts[f.severity.value] += 1

    # Family counts
    family_scores = {
        name: {
            "score":          round(fs.score, 1),
            "finding_count":  fs.finding_count,
            "critical_count": fs.critical_count,
            "high_count":     fs.high_count,
            "medium_count":   fs.medium_count,
            "weight":         fs.weight,
        }
        for name, fs in health.family_scores.items()
    }

    return {
        "schema_version":    SCHEMA_VERSION,
        "audit_run_id":      audit_run_id,
        "tool_version":      __version__,
        "audited_at":        _fmt_dt(result.audited_at),
        "tenant_url":        result.tenant_url,
        "policy_pack":       result.policy_pack,

        "health": {
            "tenant_health":   round(health.tenant_health, 1),
            "posture_score":   round(health.posture_score, 1),
            "band":            health.band.value,
            "trend":           health.trend,
            "previous_score":  health.previous_score,
        },

        "coverage": {
            "score":                        cov.score_display,
            "critical_sources_connected":   round(cov.critical_sources_connected * 100),
            "sources_recently_aggregated":  round(cov.sources_recently_aggregated * 100),
            "entitlements_with_owners":     round(cov.entitlements_with_owners * 100),
            "machine_identities_visible":   round(cov.machine_identities_visible * 100),
            "high_risk_apps_governed":      round(cov.high_risk_apps_governed * 100),
            "lifecycle_populations_covered": round(cov.lifecycle_populations_covered * 100),
            "certification_coverage":       round(cov.certification_coverage * 100),
        },

        "critical_conditions": [
            {
                "detector_id":  cc.detector_id,
                "title":        cc.title,
                "description":  cc.description,
                "finding_ids":  cc.finding_ids,
            }
            for cc in health.critical_conditions
        ],
        "has_critical_conditions": health.has_critical_conditions,

        "finding_counts": {
            "total_active":    len(active),
            "total_suppressed": len(suppressed),
            **sev_counts,
        },

        "family_scores": family_scores,

        "detector_coverage": [
            {
                "detector_id":    c.detector_id,
                "family":         c.family.value,
                "status":         c.status.value,
                "eligible_count": c.eligible_count,
                "affected_count": c.affected_count,
                "warning":        c.warning,
            }
            for c in result.detector_coverage
        ],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_json_report(
    result: AuditResult,
    base_path: Path,
) -> tuple[Path, Path]:
    """
    Generate both JSON output files and return their paths.

    Args:
        result:    The completed AuditResult to serialise.
        base_path: Base path without extension. The reporter appends
                   .json and .ndjson automatically.
                   Example: Path("audit_2026-04-12") produces:
                     audit_2026-04-12.json
                     audit_2026-04-12.ndjson

    Returns:
        (report_path, ndjson_path) — paths to the two output files.

    Both files use schema_version: 1. Consumers should gate on this
    field to detect breaking schema changes in future releases.
    """
    base_path = Path(base_path)
    base_path.parent.mkdir(parents=True, exist_ok=True)

    report_path = base_path.with_suffix(".json")
    ndjson_path = base_path.with_suffix(".ndjson")

    # Stable run ID — same value appears in both files so consumers can join them
    audit_run_id = _fmt_dt(result.audited_at) or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    audited_at   = _fmt_dt(result.audited_at) or audit_run_id

    summary  = _build_summary(result, audit_run_id)
    findings = [
        _finding_to_dict(f, audit_run_id, result.tenant_url, audited_at)
        for f in result.findings  # includes suppressed — never silently drop
    ]

    # ── report.json ────────────────────────────────────────────────────────
    report_doc = {
        **summary,
        "findings": findings,
    }

    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report_doc, fh, indent=2, default=str)

    # ── findings.ndjson ────────────────────────────────────────────────────
    # One finding per line — no trailing newline on empty files
    with open(ndjson_path, "w", encoding="utf-8") as fh:
        for finding_dict in findings:
            fh.write(json.dumps(finding_dict, default=str))
            fh.write("\n")

    return report_path, ndjson_path
