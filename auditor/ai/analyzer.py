"""
Claude AI analyzer for sailpoint-isc-auditor.

Runs AFTER all deterministic detectors have fired and findings have been scored.
Claude's role is strictly to explain, prioritise, and write auditor-ready notes —
never to decide whether a control failed.

Design rules:
  GOOD AI jobs:  explain why a finding matters, describe blast radius,
                 suggest remediation order, write auditor-ready notes,
                 group related findings into one story.

  BAD AI jobs:   decide whether a control failed, invent ownership context,
                 replace threshold logic, generate findings independently.

Error handling:
  AI analysis is enhancement, not a dependency. If Claude is unavailable or
  returns unexpected output, findings are returned without AI fields and the
  run continues normally. All errors are logged with sufficient detail to debug.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import anthropic

from ..config import AuditorConfig
from ..models import Finding, Severity, TenantHealthScore

logger = logging.getLogger(__name__)

MODEL = "claude-sonnet-4-6"
MAX_FINDINGS_PER_BATCH = 10


def _build_system_prompt() -> str:
    return (
        "You are an Identity Security expert analysing audit findings from "
        "SailPoint Identity Security Cloud (ISC).\n\n"
        "Your role:\n"
        "1. Explain why each finding matters — for both engineers and business stakeholders.\n"
        "2. Describe the blast radius: what could an attacker reach if exploited?\n"
        "3. Suggest remediation priority and first steps.\n"
        "4. Write a concise auditor-ready note suitable for a SOX/SOC2/HIPAA audit package.\n\n"
        "Rules:\n"
        "- Be specific and factual — only reference what is in the finding evidence.\n"
        "- Never invent context you do not have.\n"
        "- Keep explanations clear enough for a non-technical CISO to understand.\n"
        "- Auditor notes must be formal, defensible, and action-oriented.\n"
        "- If a finding appears to be a false positive given the evidence, say so clearly.\n\n"
        "Respond ONLY with a valid JSON array. Each element must have exactly these keys:\n"
        '{"finding_id": "...", "ai_explanation": "...", "ai_blast_radius": "...", '
        '"ai_remediation": "...", "ai_audit_note": "..."}\n'
        "Do not include markdown fences, preamble, or any text outside the JSON array."
    )


def _build_findings_prompt(
    findings: list[Finding],
    health_score: TenantHealthScore,
) -> str:
    findings_data: list[dict[str, Any]] = []
    for f in findings:
        findings_data.append({
            "finding_id":      f.finding_id,
            "detector_id":     f.detector_id,
            "family":          f.family.value,
            "title":           f.title,
            "severity":        f.severity.value,
            "why_fired":       f.evidence.why_fired,
            "affected":        f.evidence.affected_object_names[:5],
            "object_type":     f.evidence.object_type,
            "recommended_fix": f.evidence.recommended_fix,
            "risk_score":      f.risk_score.normalized if f.risk_score else None,
        })

    return (
        f"Tenant health score: {health_score.tenant_health:.0f}/100 "
        f"({health_score.band.value})\n"
        f"Critical conditions present: {health_score.has_critical_conditions}\n\n"
        f"Analyse these {len(findings)} identity security findings and return a "
        f"JSON array with your analysis:\n\n"
        f"{json.dumps(findings_data, indent=2)}"
    )


def analyze_findings(
    findings: list[Finding],
    config: AuditorConfig,
    health_score: TenantHealthScore,
) -> list[Finding]:
    """Send findings to Claude in batches and attach AI explanations.

    Returns the same findings list with ai_* fields populated where Claude
    succeeded. Findings for which analysis failed retain their original values
    (ai_* fields remain None). The run never fails due to AI errors.
    """
    if not findings:
        return findings

    client = anthropic.Anthropic(api_key=config.anthropic_api_key)

    # Sort by severity so the most important findings are analysed first.
    # If we hit a rate limit or token limit partway through, critical findings
    # have already been processed.
    priority_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH:     1,
        Severity.MEDIUM:   2,
        Severity.LOW:      3,
        Severity.INFO:     4,
    }
    sorted_findings = sorted(findings, key=lambda f: priority_order.get(f.severity, 5))
    findings_index  = {f.finding_id: f for f in findings}

    for batch_start in range(0, len(sorted_findings), MAX_FINDINGS_PER_BATCH):
        batch      = sorted_findings[batch_start : batch_start + MAX_FINDINGS_PER_BATCH]
        batch_num  = batch_start // MAX_FINDINGS_PER_BATCH + 1
        batch_desc = f"batch {batch_num} ({len(batch)} findings)"
        logger.debug("AI: analysing %s", batch_desc)

        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=1000,
                system=_build_system_prompt(),
                messages=[{
                    "role":    "user",
                    "content": _build_findings_prompt(batch, health_score),
                }],
            )
            raw = response.content[0].text.strip()

        except anthropic.AuthenticationError:
            logger.error("AI: authentication failed — check ANTHROPIC_API_KEY.")
            break  # No point continuing if auth is broken.

        except anthropic.RateLimitError:
            logger.warning("AI: rate limit hit on %s — skipping remaining batches.", batch_desc)
            break

        except anthropic.APIConnectionError as exc:
            logger.warning("AI: connection error on %s: %s", batch_desc, exc)
            continue

        except anthropic.APIError as exc:
            logger.warning("AI: API error on %s (status %s): %s", batch_desc, exc.status_code, exc)
            continue

        # Parse Claude's JSON response.
        try:
            # Strip markdown fences if Claude included them despite instructions.
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()

            analyses: list[dict[str, Any]] = json.loads(raw)

            if not isinstance(analyses, list):
                logger.warning("AI: unexpected response type on %s (expected list).", batch_desc)
                continue

        except json.JSONDecodeError as exc:
            logger.warning("AI: JSON parse error on %s: %s", batch_desc, exc)
            logger.debug("AI: raw response was: %.500s", raw)
            continue

        # Attach analysis back to the original finding objects.
        for analysis in analyses:
            if not isinstance(analysis, dict):
                continue
            fid = analysis.get("finding_id")
            if fid and fid in findings_index:
                f = findings_index[fid]
                f.ai_explanation  = str(analysis.get("ai_explanation")  or "")
                f.ai_blast_radius = str(analysis.get("ai_blast_radius") or "")
                f.ai_remediation  = str(analysis.get("ai_remediation")  or "")
                f.ai_audit_note   = str(analysis.get("ai_audit_note")   or "")

    return findings
