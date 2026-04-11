"""
HTML reporter for sailpoint-isc-auditor.

Generates a self-contained HTML audit report — no external dependencies,
works offline, readable on any device, safe for untrusted tenant data.

Three-layer structure:
  Layer 1 (Executive):    Health score, coverage confidence, critical conditions,
                          top risk drivers, family breakdown
  Layer 2 (Practitioner): Filterable findings table with expandable detail panels
  Layer 3 (Auditor):      Coverage summary, suppressed findings, methodology,
                          audit metadata

Security:
  All dynamic values are HTML-escaped before interpolation into the template.
  All values passed to JavaScript are JSON-encoded (not string-concatenated).
  Numeric values (scores, widths) are clamped to valid ranges before use.

Usage:
    from auditor.reporters.html_reporter import generate_html_report
    generate_html_report(result, Path("report.html"))
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from ..models import AuditResult, ControlFamily, HealthBand, Severity

try:
    from .. import __version__ as VERSION
except ImportError:
    VERSION = "0.1.0-dev"

# Severity colour config
SEV_COLOR = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH:     "#ea580c",
    Severity.MEDIUM:   "#d97706",
    Severity.LOW:      "#6b7280",
    Severity.INFO:     "#9ca3af",
}

SEV_BG = {
    Severity.CRITICAL: "#fef2f2",
    Severity.HIGH:     "#fff7ed",
    Severity.MEDIUM:   "#fffbeb",
    Severity.LOW:      "#f9fafb",
    Severity.INFO:     "#f9fafb",
}

BAND_COLOR = {
    HealthBand.HEALTHY:   "#16a34a",
    HealthBand.STABLE:    "#0284c7",
    HealthBand.EXPOSED:   "#d97706",
    HealthBand.HIGH_RISK: "#dc2626",
    HealthBand.CRITICAL:  "#7f1d1d",
}


def _e(value: object) -> str:
    """HTML-escape any value for safe interpolation into the template."""
    return html.escape(str(value) if value is not None else "")


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    """Clamp a numeric value to [lo, hi]."""
    return max(lo, min(hi, value))


def _fmt_dt(dt: datetime | None) -> str:
    """Format a datetime as a UTC string.

    Timezone-aware datetimes are converted to UTC before formatting.
    Naive datetimes are treated as UTC (all internal timestamps in this
    tool are created via _utcnow() which always produces aware UTC values;
    naive values indicate legacy data or a caller error and are labelled
    accordingly so the report is never silently wrong).
    """
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        # Treat as UTC but flag it so the report is honest about the assumption.
        return dt.strftime("%Y-%m-%d %H:%M UTC (assumed)")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _severity_badge(sev: Severity) -> str:
    color = SEV_COLOR.get(sev, "#6b7280")
    bg    = SEV_BG.get(sev, "#f9fafb")
    label = _e(sev.value.upper())
    return (
        f'<span class="badge" style="color:{color};background:{bg};'
        f'border:1px solid {color}33">{label}</span>'
    )


def _score_ring(score: float, color: str, size: int = 120) -> str:
    """SVG circular score ring. Score is clamped to [0, 100]."""
    score   = _clamp(score)
    radius  = (size - 16) // 2
    circumf = 2 * 3.14159 * radius
    filled  = circumf * (score / 100)
    font_sz = size // 5
    cx = cy = size // 2
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" '
        f'role="img" aria-label="Score {score:.0f} out of 100">'
        f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" stroke="#e5e7eb" stroke-width="8"/>'
        f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" stroke="{color}" stroke-width="8" '
        f'stroke-dasharray="{filled:.1f} {circumf:.1f}" stroke-linecap="round" '
        f'transform="rotate(-90 {cx} {cy})"/>'
        f'<text x="{cx}" y="{cy + font_sz // 3}" text-anchor="middle" '
        f'font-size="{font_sz}" font-weight="700" fill="{color}">{score:.0f}</text>'
        f'</svg>'
    )


def _findings_to_json(active: list) -> str:
    """
    Serialise active findings to JSON for the client-side filter/search script.
    All string values are included as-is (json.dumps handles escaping for JS).
    The JS layer uses textContent / createElement — not innerHTML — for these values.
    """
    rows = []
    for f in active:
        rows.append({
            "id":         f.finding_id,
            "detector":   f.detector_id,
            "family":     f.family.value,
            "title":      f.title,
            "severity":   f.severity.value,
            "objects":    ", ".join(f.evidence.affected_object_names[:3]),
            "why":        f.evidence.why_fired,
            "fix":        f.evidence.recommended_fix,
            "confidence": round(f.evidence.confidence * 100),
            "ai_exp":     f.ai_explanation  or "",
            "ai_blast":   f.ai_blast_radius or "",
            "ai_rem":     f.ai_remediation  or "",
            "ai_audit":   f.ai_audit_note   or "",
            "risk":       round(f.risk_score.normalized if f.risk_score else 0, 1),
        })
    return json.dumps(rows, ensure_ascii=True)


def generate_html_report(result: AuditResult, output_path: Path) -> None:
    """Generate a self-contained HTML audit report and write it to output_path."""

    health     = result.health_score
    band       = health.band
    band_color = BAND_COLOR.get(band, "#6b7280")

    cov_score  = _clamp(health.coverage_confidence.score_display)
    cov_color  = "#16a34a" if cov_score >= 75 else "#d97706" if cov_score >= 50 else "#dc2626"
    cov_label  = (
        "High confidence — score is trustworthy" if cov_score >= 75
        else "Moderate confidence — some visibility gaps" if cov_score >= 50
        else "Low confidence — significant visibility gaps exist"
    )

    active     = [f for f in result.findings if not f.suppressed]
    suppressed = [f for f in result.findings if f.suppressed]

    # Top 3 risk drivers
    top_findings = sorted(
        active,
        key=lambda f: (
            f.risk_score.normalized if f.risk_score else 0,
            f.severity == Severity.CRITICAL,
        ),
        reverse=True,
    )[:3]

    findings_json = _findings_to_json(active)

    # ── Trend indicator ────────────────────────────────────────────────────
    if health.trend is not None:
        t = health.trend
        trend_color  = "#16a34a" if t > 0 else "#dc2626" if t < 0 else "#6b7280"
        trend_arrow  = "▲" if t > 0 else "▼" if t < 0 else "→"
        trend_html   = (
            f'<div class="score-trend" style="color:{trend_color}">'
            f'{_e(trend_arrow)} {abs(t):.1f} vs last run</div>'
        )
    else:
        trend_html = '<div class="score-label" style="margin-top:4px">First run — no trend data</div>'

    # ── Critical conditions banner ─────────────────────────────────────────
    if health.has_critical_conditions:
        items_html = "".join(
            f'<div class="critical-item">'
            f'<div class="critical-dot" aria-hidden="true"></div>'
            f'<div><strong>{_e(cc.title)}</strong><br>'
            f'<span style="color:#6b7280;font-size:12px">{_e(cc.description)}</span></div>'
            f'</div>'
            for cc in health.critical_conditions
        )
        critical_banner = (
            '<div class="critical-banner" role="alert">'
            '<div class="critical-banner-title">⚠ Critical Conditions Present'
            ' — review regardless of health score</div>'
            f'{items_html}</div>'
        )
    else:
        critical_banner = ""

    # ── Family breakdown ───────────────────────────────────────────────────
    # Explicit family order — consistent across every report regardless of dict insertion order.
    # Ordered by strategic weight: highest-impact families first.
    FAMILY_ORDER = ["MI", "LI", "AR", "IH", "GQ", "CR"]
    ordered_families = sorted(
        health.family_scores.items(),
        key=lambda x: FAMILY_ORDER.index(x[0]) if x[0] in FAMILY_ORDER else 99,
    )

    family_cards_html = ""
    for name, fs in ordered_families:
        s = _clamp(fs.score)
        sc = "#16a34a" if s >= 80 else "#d97706" if s >= 60 else "#dc2626"
        count_str = f'{fs.finding_count} finding{"s" if fs.finding_count != 1 else ""}'
        crit_str  = f" · {fs.critical_count} critical" if fs.critical_count else ""
        family_cards_html += (
            f'<div class="family-card">'
            f'<div class="family-name">{_e(name)}</div>'
            f'<div class="family-score" style="color:{sc}">{s:.0f}</div>'
            f'<div class="family-count">{_e(count_str)}{_e(crit_str)}</div>'
            f'</div>'
        )

    # ── Top risk drivers ───────────────────────────────────────────────────
    drivers_html = ""
    for i, f in enumerate(top_findings):
        obj_names = f.evidence.affected_object_names
        extra     = f" +{len(obj_names) - 2} more" if len(obj_names) > 2 else ""
        sub       = f"{_e(f.detector_id)} · {_e(f.family.value)} · {_e(', '.join(obj_names[:2]))}{_e(extra)}"
        drivers_html += (
            f'<div class="risk-driver">'
            f'<div class="risk-num" aria-hidden="true">{i+1}</div>'
            f'<div class="risk-info">'
            f'<div class="risk-title">{_e(f.title)}</div>'
            f'<div class="risk-sub">{sub}</div>'
            f'</div>'
            f'{_severity_badge(f.severity)}'
            f'</div>'
        )
    top_drivers_card = (
        f'<div class="card"><div class="card-title">Top Risk Drivers</div>{drivers_html}</div>'
        if top_findings else ""
    )

    # ── Coverage summary table ─────────────────────────────────────────────
    cov_rows_html = ""
    for c in result.detector_coverage:
        status_class = f"status-{c.status.value}"
        warning_text = _e(c.warning) if c.warning else "—"
        cov_rows_html += (
            f'<tr>'
            f'<td><span class="det-id">{_e(c.detector_id)}</span></td>'
            f'<td style="color:#6b7280">{_e(c.family.value)}</td>'
            f'<td><span class="status-pill {status_class}">{_e(c.status.value.upper())}</span></td>'
            f'<td>{c.eligible_count:,}</td>'
            f'<td>{c.affected_count:,}</td>'
            f'<td style="color:#6b7280;font-size:12px">{warning_text}</td>'
            f'</tr>'
        )

    # ── Suppressed findings table ──────────────────────────────────────────
    suppressed_section = ""
    if suppressed:
        sup_rows = ""
        for f in suppressed:
            reason  = _e(f.suppression.reason   if f.suppression else "—")
            ticket  = _e(f.suppression.ticket   if f.suppression and f.suppression.ticket else "—")
            expires = _e(_fmt_dt(f.suppression.expires_at) if f.suppression and f.suppression.expires_at else "Never")
            objs    = _e(", ".join(f.evidence.affected_object_names[:2]))
            sup_rows += (
                f'<tr class="suppressed-row">'
                f'<td><span class="det-id">{_e(f.detector_id)}</span></td>'
                f'<td>{_e(f.title)}</td>'
                f'<td>{objs}</td>'
                f'<td>{reason}</td>'
                f'<td>{ticket}</td>'
                f'<td>{expires}</td>'
                f'</tr>'
            )
        suppressed_section = f"""
<div class="section-label">Suppressed Findings ({len(suppressed)})</div>
<div class="card">
  <div class="table-scroll">
  <table class="findings-table" aria-label="Suppressed findings">
    <thead><tr>
      <th>Detector</th><th>Title</th><th>Objects</th>
      <th>Reason</th><th>Ticket</th><th>Expires</th>
    </tr></thead>
    <tbody>{sup_rows}</tbody>
  </table>
  </div>
</div>"""

    # ── Family filter options ──────────────────────────────────────────────
    family_options = "".join(
        f'<option value="{_e(f.value)}">{_e(f.value)}</option>'
        for f in ControlFamily
    )

    # ── Metadata table ─────────────────────────────────────────────────────
    meta_rows = (
        f'<tr><td>Tenant URL</td><td>{_e(result.tenant_url)}</td></tr>'
        f'<tr><td>Audit date</td><td>{_e(_fmt_dt(result.audited_at))}</td></tr>'
        f'<tr><td>Policy pack</td><td>{_e(result.policy_pack)}</td></tr>'
        f'<tr><td>Tool version</td><td>sailpoint-isc-auditor v{_e(VERSION)}</td></tr>'
        f'<tr><td>Detectors run</td><td>{len(result.detector_coverage)} of 25</td></tr>'
        f'<tr><td>Active findings</td><td>{len(active)}</td></tr>'
        f'<tr><td>Suppressed findings</td><td>{len(suppressed)}</td></tr>'
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ISC Audit Report — {_e(result.tenant_url)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px; line-height: 1.6; color: #1f2937; background: #f3f4f6;
  }}
  .page {{ max-width: 1200px; margin: 0 auto; padding: 24px 16px; }}

  .header {{
    background: #1e293b; color: white; padding: 20px 28px;
    border-radius: 12px; margin-bottom: 24px;
    display: flex; justify-content: space-between; align-items: center;
    flex-wrap: wrap; gap: 12px;
  }}
  .header-title {{ font-size: 20px; font-weight: 700; }}
  .header-meta {{ font-size: 12px; color: #94a3b8; line-height: 1.8; text-align: right; }}

  .card {{
    background: white; border-radius: 12px; padding: 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 20px;
  }}
  .card-title {{
    font-size: 13px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.05em; color: #6b7280; margin-bottom: 16px;
  }}

  .exec-row {{ display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 20px; }}
  .exec-card {{
    background: white; border-radius: 12px; padding: 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08); flex: 1; min-width: 240px;
  }}

  .score-block {{ display: flex; align-items: center; gap: 20px; }}
  .score-detail {{ flex: 1; }}
  .score-band {{ font-size: 22px; font-weight: 800; color: {band_color}; }}
  .score-label {{ font-size: 12px; color: #6b7280; margin-top: 4px; }}
  .score-trend {{ font-size: 13px; margin-top: 8px; }}

  .cov-bar-bg {{ background: #e5e7eb; border-radius: 99px; height: 8px; margin: 8px 0; }}
  .cov-bar-fill {{ height: 8px; border-radius: 99px; background: {cov_color}; width: {cov_score:.0f}%; }}

  .critical-banner {{
    background: #fef2f2; border: 1.5px solid #dc2626;
    border-radius: 10px; padding: 16px 20px; margin-bottom: 20px;
  }}
  .critical-banner-title {{ color: #dc2626; font-weight: 700; font-size: 14px; margin-bottom: 10px; }}
  .critical-item {{
    display: flex; align-items: flex-start; gap: 8px;
    padding: 6px 0; border-bottom: 1px solid #fecaca; font-size: 13px;
  }}
  .critical-item:last-child {{ border-bottom: none; }}
  .critical-dot {{
    width: 8px; height: 8px; border-radius: 50%;
    background: #dc2626; margin-top: 5px; flex-shrink: 0;
  }}

  .family-grid {{
    display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 12px;
  }}
  .family-card {{
    border: 1px solid #e5e7eb; border-radius: 8px; padding: 14px; text-align: center;
  }}
  .family-name {{ font-size: 11px; color: #6b7280; margin-bottom: 6px; font-weight: 600; }}
  .family-score {{ font-size: 28px; font-weight: 800; }}
  .family-count {{ font-size: 11px; color: #9ca3af; margin-top: 4px; }}

  .risk-driver {{
    display: flex; align-items: center; gap: 12px;
    padding: 10px 0; border-bottom: 1px solid #f3f4f6;
  }}
  .risk-driver:last-child {{ border-bottom: none; }}
  .risk-num {{
    width: 24px; height: 24px; border-radius: 50%; background: #1e293b;
    color: white; font-size: 11px; font-weight: 700;
    display: flex; align-items: center; justify-content: center; flex-shrink: 0;
  }}
  .risk-info {{ flex: 1; }}
  .risk-title {{ font-weight: 600; font-size: 13px; }}
  .risk-sub {{ font-size: 11px; color: #6b7280; margin-top: 2px; }}

  .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 99px;
    font-size: 11px; font-weight: 600; white-space: nowrap;
  }}

  .filters {{
    display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 16px;
  }}
  .filter-input {{
    border: 1px solid #e5e7eb; border-radius: 8px; padding: 8px 12px;
    font-size: 13px; outline: none; flex: 1; min-width: 180px;
  }}
  .filter-input:focus {{ border-color: #2563eb; box-shadow: 0 0 0 2px #bfdbfe; }}
  .filter-select {{
    border: 1px solid #e5e7eb; border-radius: 8px; padding: 8px 12px;
    font-size: 13px; outline: none; background: white; cursor: pointer;
  }}
  .filter-select:focus {{ border-color: #2563eb; box-shadow: 0 0 0 2px #bfdbfe; }}

  /* Scrollable table wrapper for mobile */
  .table-scroll {{ overflow-x: auto; -webkit-overflow-scrolling: touch; }}

  .findings-table {{ width: 100%; border-collapse: collapse; min-width: 600px; }}
  .findings-table th {{
    text-align: left; padding: 10px 12px; font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.05em;
    color: #6b7280; border-bottom: 2px solid #e5e7eb; background: #f9fafb;
    white-space: nowrap;
  }}
  .findings-table td {{
    padding: 12px; border-bottom: 1px solid #f3f4f6;
    vertical-align: top; font-size: 13px;
  }}
  .expand-btn {{
    background: none; border: none; cursor: pointer;
    width: 100%; text-align: left; padding: 0;
    display: flex; align-items: center; gap: 8px;
    font: inherit; color: inherit;
  }}
  .expand-btn:focus {{ outline: 2px solid #2563eb; border-radius: 2px; }}
  .expand-arrow {{ font-size: 10px; color: #9ca3af; transition: transform 0.15s; }}
  .expand-arrow.open {{ transform: rotate(90deg); }}
  tr.finding-row:hover td {{ background: #f9fafb; }}
  .det-id {{
    font-family: monospace; font-size: 12px;
    background: #f3f4f6; padding: 2px 6px; border-radius: 4px;
    white-space: nowrap;
  }}

  .detail-panel {{ display: none; }}
  .detail-panel.open {{ display: table-row; }}
  .detail-inner {{
    padding: 20px; display: grid;
    grid-template-columns: 1fr 1fr; gap: 16px;
  }}
  .detail-section {{ }}
  .detail-section.full {{ grid-column: 1 / -1; }}
  .detail-label {{
    font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.05em; color: #6b7280; margin-bottom: 6px;
  }}
  .detail-value {{ font-size: 13px; color: #374151; line-height: 1.6; white-space: pre-wrap; }}
  .ai-section {{
    background: #eff6ff; border: 1px solid #bfdbfe;
    border-radius: 8px; padding: 14px; margin-top: 8px;
  }}
  .ai-label {{
    font-size: 11px; font-weight: 600; color: #2563eb;
    text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px;
  }}

  .cov-table {{ width: 100%; border-collapse: collapse; min-width: 500px; }}
  .cov-table th {{
    text-align: left; padding: 8px 12px; font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.05em;
    color: #6b7280; border-bottom: 2px solid #e5e7eb; white-space: nowrap;
  }}
  .cov-table td {{ padding: 10px 12px; border-bottom: 1px solid #f3f4f6; font-size: 13px; }}
  .status-pill {{
    display: inline-block; padding: 2px 8px; border-radius: 99px;
    font-size: 11px; font-weight: 600;
  }}
  .status-full     {{ background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }}
  .status-partial  {{ background: #fffbeb; color: #d97706; border: 1px solid #fde68a; }}
  .status-fallback {{ background: #fff7ed; color: #ea580c; border: 1px solid #fed7aa; }}
  .status-skipped  {{ background: #f9fafb; color: #6b7280; border: 1px solid #e5e7eb; }}
  .status-failed   {{ background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }}

  .suppressed-row td {{ color: #9ca3af; font-style: italic; }}

  .section-label {{
    font-size: 18px; font-weight: 700; color: #1e293b;
    margin: 28px 0 16px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb;
  }}

  .methodology {{ font-size: 13px; color: #4b5563; line-height: 1.8; }}
  .methodology h4 {{ font-weight: 600; color: #1e293b; margin: 12px 0 4px; }}
  .meta-table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 20px; }}
  .meta-table td {{ padding: 6px 0; border-bottom: 1px solid #f3f4f6; }}
  .meta-table td:first-child {{ color: #6b7280; width: 180px; }}

  #no-results {{
    display: none; text-align: center; padding: 32px; color: #6b7280;
  }}

  @media print {{
    body {{ background: white; }}
    .filters {{ display: none; }}
    .detail-panel {{ display: table-row !important; }}
    .card {{ box-shadow: none; border: 1px solid #e5e7eb; page-break-inside: avoid; }}
  }}

  @media (max-width: 640px) {{
    .exec-row {{ flex-direction: column; }}
    .detail-inner {{ grid-template-columns: 1fr; }}
    .detail-section.full {{ grid-column: 1; }}
    .header-meta {{ text-align: left; }}
  }}
</style>
</head>
<body>
<div class="page">

<!-- HEADER -->
<header class="header">
  <div>
    <div class="header-title">SailPoint ISC Audit Report</div>
    <div style="color:#94a3b8;font-size:13px;margin-top:4px">{_e(result.tenant_url)}</div>
  </div>
  <div class="header-meta">
    Generated: {_e(_fmt_dt(result.audited_at))}<br>
    Policy pack: {_e(result.policy_pack)}<br>
    Tool version: v{_e(VERSION)}
  </div>
</header>

<!-- LAYER 1: EXECUTIVE -->
<h2 class="section-label">Executive Summary</h2>

{critical_banner}

<div class="exec-row">

  <!-- Health score -->
  <section class="exec-card" aria-label="Tenant health score">
    <div class="card-title">Tenant Health Score</div>
    <div class="score-block">
      {_score_ring(health.tenant_health, band_color, 110)}
      <div class="score-detail">
        <div class="score-band">{_e(band.value)}</div>
        <div class="score-label">Overall posture rating</div>
        {trend_html}
      </div>
    </div>
  </section>

  <!-- Coverage confidence -->
  <section class="exec-card" aria-label="Coverage confidence">
    <div class="card-title">Coverage Confidence</div>
    <div style="font-size:36px;font-weight:800;color:{cov_color}">
      {cov_score:.0f}<span style="font-size:16px;font-weight:400;color:#6b7280">/100</span>
    </div>
    <div class="cov-bar-bg" role="progressbar"
         aria-valuenow="{cov_score:.0f}" aria-valuemin="0" aria-valuemax="100">
      <div class="cov-bar-fill"></div>
    </div>
    <div style="font-size:12px;color:#6b7280;margin-top:6px">{_e(cov_label)}</div>
    <div style="font-size:12px;color:#6b7280;margin-top:8px;line-height:1.6">
      The health score is adjusted by coverage confidence.<br>
      Missing visibility is penalised, not assumed healthy.
    </div>
  </section>

  <!-- Finding summary -->
  <section class="exec-card" aria-label="Finding summary">
    <div class="card-title">Finding Summary</div>
    <div style="display:flex;flex-direction:column;gap:0">
      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid #f3f4f6">
        <span style="color:#dc2626;font-weight:700">Critical</span>
        <span style="font-size:22px;font-weight:800;color:#dc2626">{result.critical_count}</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid #f3f4f6">
        <span style="color:#ea580c;font-weight:700">High</span>
        <span style="font-size:22px;font-weight:800;color:#ea580c">{result.high_count}</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0">
        <span style="color:#d97706;font-weight:700">Medium</span>
        <span style="font-size:22px;font-weight:800;color:#d97706">{result.medium_count}</span>
      </div>
      <!-- Low and Info severities are intentionally excluded from the executive summary.
           They appear in the full findings table below. The summary is designed for
           leadership who need signal, not noise. -->
    </div>
  </section>

</div>

{top_drivers_card}

<!-- Family breakdown -->
<div class="card" aria-label="Control family scores">
  <div class="card-title">Control Family Scores</div>
  <div class="family-grid">{family_cards_html}</div>
</div>

<!-- LAYER 2: PRACTITIONER -->
<h2 class="section-label">Findings ({len(active)} active)</h2>

<div class="card">
  <div class="filters" role="search" aria-label="Filter findings">
    <label class="sr-only" for="search">Search findings</label>
    <input class="filter-input" id="search" type="search"
           placeholder="Search findings, objects, detectors..."
           aria-label="Search findings"
           oninput="filterFindings()">
    <label class="sr-only" for="sev-filter">Filter by severity</label>
    <select class="filter-select" id="sev-filter"
            aria-label="Filter by severity" onchange="filterFindings()">
      <option value="">All severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
    </select>
    <label class="sr-only" for="family-filter">Filter by family</label>
    <select class="filter-select" id="family-filter"
            aria-label="Filter by family" onchange="filterFindings()">
      <option value="">All families</option>
      {family_options}
    </select>
  </div>

  <div class="table-scroll">
    <table class="findings-table" id="findings-table"
           aria-label="Security findings">
      <thead>
        <tr>
          <th scope="col">Severity</th>
          <th scope="col">Detector</th>
          <th scope="col">Title</th>
          <th scope="col">Family</th>
          <th scope="col">Objects</th>
          <th scope="col">Risk</th>
        </tr>
      </thead>
      <tbody id="findings-body"></tbody>
    </table>
  </div>
  <div id="no-results" role="status" aria-live="polite">No findings match your filters.</div>
</div>

<!-- LAYER 3: AUDITOR -->
<h2 class="section-label">Coverage Summary</h2>
<div class="card">
  <div class="table-scroll">
    <table class="cov-table" aria-label="Detector coverage summary">
      <thead>
        <tr>
          <th scope="col">Detector</th>
          <th scope="col">Family</th>
          <th scope="col">Status</th>
          <th scope="col">Eligible</th>
          <th scope="col">Affected</th>
          <th scope="col">Notes</th>
        </tr>
      </thead>
      <tbody>{cov_rows_html}</tbody>
    </table>
  </div>
</div>

{suppressed_section}

<h2 class="section-label">Methodology &amp; Audit Metadata</h2>
<div class="card">
  <table class="meta-table" aria-label="Audit metadata">
    <tbody>{meta_rows}</tbody>
  </table>
  <div class="methodology">
    <h4>Scoring methodology</h4>
    <p>Each finding is scored on three axes:
    <strong>impact</strong> (how dangerous is this object?),
    <strong>exploitability</strong> (how easy is it to abuse right now?), and
    <strong>governance failure</strong> (how badly did controls fail?).
    The formula is: <code>risk&nbsp;=&nbsp;impact&nbsp;×&nbsp;exploitability&nbsp;×&nbsp;governance_failure</code>.
    Findings roll up into family scores, which roll up into a posture score.
    The posture score is then adjusted by coverage confidence:
    <code>tenant_health&nbsp;=&nbsp;posture&nbsp;×&nbsp;(0.80&nbsp;+&nbsp;0.20&nbsp;×&nbsp;coverage_confidence)</code>.</p>

    <h4>Coverage confidence</h4>
    <p>Coverage confidence reflects how much of the ISC environment was visible
    during this audit run. Low confidence means the health score should be
    interpreted with caution — missing visibility is penalised, not assumed healthy.</p>

    <h4>Critical conditions</h4>
    <p>Certain findings (terminated users with active access, active SOD violations,
    failed deprovisionings) are surfaced as critical conditions regardless of the
    overall health score. A high score does not mean these findings are acceptable.</p>

    <h4>Detectors</h4>
    <p>25 deterministic detectors across 6 control families:
    Machine &amp; Privileged Identity (MI-01–07),
    Identity Hygiene (IH-01–06),
    Lifecycle Integrity (LI-01–06),
    Access Risk (AR-01–07),
    Governance Quality (GQ-01–08),
    Coverage &amp; Reconciliation (CR-01–08).
    AI analysis is applied after detection — Claude explains findings but never
    decides whether a control failed.</p>
  </div>
</div>

</div><!-- /page -->

<!-- Screen-reader only utility class -->
<style>.sr-only{{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}}</style>

<script>
/* All finding data is JSON-encoded server-side — no string concatenation. */
const FINDINGS = {findings_json};

/* Severity colours for badge rendering */
const SEV_COLOR = {{
  critical: ['#dc2626','#fef2f2'],
  high:     ['#ea580c','#fff7ed'],
  medium:   ['#d97706','#fffbeb'],
  low:      ['#6b7280','#f9fafb'],
  info:     ['#9ca3af','#f9fafb'],
}};

function badge(s) {{
  const [c, bg] = SEV_COLOR[s] || ['#6b7280','#f9fafb'];
  const span = document.createElement('span');
  span.className = 'badge';
  span.style.cssText = `color:${{c}};background:${{bg}};border:1px solid ${{c}}33`;
  span.textContent = s.toUpperCase();
  return span;
}}

function riskColor(r) {{
  return r > 66 ? '#dc2626' : r > 33 ? '#d97706' : '#6b7280';
}}

/* Build a text node — never innerHTML for user data */
function t(str) {{ return document.createTextNode(str || '—'); }}

function renderFindings(list) {{
  const tbody = document.getElementById('findings-body');
  tbody.innerHTML = '';
  document.getElementById('no-results').style.display = list.length ? 'none' : 'block';

  list.forEach((f, idx) => {{
    /* ── Main row ── */
    const tr = document.createElement('tr');
    tr.className = 'finding-row';
    tr.setAttribute('aria-expanded', 'false');

    const cells = [
      () => {{ const td = document.createElement('td'); td.appendChild(badge(f.severity)); return td; }},
      () => {{ const td = document.createElement('td'); const s = document.createElement('span'); s.className='det-id'; s.textContent=f.detector; td.appendChild(s); return td; }},
      () => {{
        const td = document.createElement('td');
        const btn = document.createElement('button');
        btn.className = 'expand-btn';
        btn.setAttribute('aria-controls', `detail-${{idx}}`);
        btn.setAttribute('aria-expanded', 'false');
        const arrow = document.createElement('span');
        arrow.className = 'expand-arrow';
        arrow.textContent = '▶';
        btn.appendChild(arrow);
        btn.appendChild(document.createTextNode('\u00a0'));
        const strong = document.createElement('strong');
        strong.textContent = f.title;
        btn.appendChild(strong);
        btn.onclick = () => toggleDetail(idx, btn, arrow, tr);
        td.appendChild(btn);
        return td;
      }},
      () => {{ const td = document.createElement('td'); td.style.cssText='color:#6b7280;font-size:12px'; td.appendChild(t(f.family)); return td; }},
      () => {{ const td = document.createElement('td'); td.style.cssText='color:#6b7280;font-size:12px'; td.appendChild(t(f.objects)); return td; }},
      () => {{ const td = document.createElement('td'); td.style.cssText=`font-weight:700;color:${{riskColor(f.risk)}}`; td.appendChild(t(String(f.risk))); return td; }},
    ];
    cells.forEach(fn => tr.appendChild(fn()));
    tbody.appendChild(tr);

    /* ── Detail panel ── */
    const det = document.createElement('tr');
    det.className = 'detail-panel';
    det.id = `detail-${{idx}}`;
    const dtd = document.createElement('td');
    dtd.colSpan = 6;

    const inner = document.createElement('div');
    inner.className = 'detail-inner';

    function section(label, content, full) {{
      const div = document.createElement('div');
      div.className = 'detail-section' + (full ? ' full' : '');
      const lbl = document.createElement('div');
      lbl.className = 'detail-label';
      lbl.textContent = label;
      const val = document.createElement('div');
      val.className = 'detail-value';
      val.textContent = content || '—';
      div.appendChild(lbl);
      div.appendChild(val);
      return div;
    }}

    inner.appendChild(section('Why this fired', f.why, true));
    inner.appendChild(section('Recommended fix', f.fix, false));
    inner.appendChild(section('Affected objects', f.objects, false));

    if (f.ai_exp) {{
      const aiDiv = document.createElement('div');
      aiDiv.className = 'detail-section full';
      const aiBox = document.createElement('div');
      aiBox.className = 'ai-section';

      function aiSection(label, content) {{
        if (!content) return;
        const lbl = document.createElement('div');
        lbl.className = 'ai-label';
        lbl.textContent = label;
        const val = document.createElement('div');
        val.className = 'detail-value';
        val.textContent = content;
        aiBox.appendChild(lbl);
        aiBox.appendChild(val);
      }}
      aiSection('Claude AI — Explanation', f.ai_exp);
      aiSection('Blast radius', f.ai_blast);
      aiSection('Remediation', f.ai_rem);
      aiSection('Auditor note', f.ai_audit);
      aiDiv.appendChild(aiBox);
      inner.appendChild(aiDiv);
    }}

    const meta = document.createElement('div');
    meta.className = 'detail-section';
    meta.style.cssText = 'color:#9ca3af;font-size:11px';
    meta.textContent = `Confidence: ${{f.confidence}}% · Risk score: ${{f.risk}}`;
    inner.appendChild(meta);

    dtd.appendChild(inner);
    det.appendChild(dtd);
    tbody.appendChild(det);
  }});
}}

function toggleDetail(idx, btn, arrow, tr) {{
  const panel = document.getElementById(`detail-${{idx}}`);
  const isOpen = panel.classList.toggle('open');
  arrow.classList.toggle('open', isOpen);
  btn.setAttribute('aria-expanded', String(isOpen));
  tr.setAttribute('aria-expanded', String(isOpen));
}}

function filterFindings() {{
  const q      = document.getElementById('search').value.toLowerCase();
  const sev    = document.getElementById('sev-filter').value;
  const family = document.getElementById('family-filter').value;

  const filtered = FINDINGS.filter(f => {{
    if (sev && f.severity !== sev) return false;
    if (family && f.family !== family) return false;
    if (q) {{
      /* Targeted search — only meaningful fields, not the whole object */
      const searchable = [f.title, f.detector, f.objects, f.why, f.fix].join(' ').toLowerCase();
      if (!searchable.includes(q)) return false;
    }}
    return true;
  }});
  renderFindings(filtered);
}}

renderFindings(FINDINGS);
</script>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)

    print(f"HTML report written to: {output_path}")
