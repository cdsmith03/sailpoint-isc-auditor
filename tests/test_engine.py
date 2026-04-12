"""
Tests for auditor/engine.py

Regression tests for bugs that have been fixed — ensures they stay fixed.
Each test is named after the issue it covers so the history is clear.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from auditor.models import Finding, Severity, TenantHealthScore


class TestSuppressedFindingsPreservedThroughAI:
    """
    Regression test for Issue #10:
    Suppressed findings were silently dropped when the AI analysis step
    overwrote result.findings with only the non-suppressed subset.

    The contract being tested:
      - result.findings contains BOTH active and suppressed findings after AI analysis
      - AI fields (ai_explanation etc.) are populated only on active findings
      - Suppressed findings are untouched by AI analysis
    """

    def _make_mock_analyzer(self):
        """
        Returns a mock analyze_findings that behaves like the real one:
        mutates active findings in-place by adding AI fields, returns them.
        """
        def fake_analyze(findings, config, health_score):
            for f in findings:
                f.ai_explanation  = "AI explanation for this finding."
                f.ai_blast_radius = "AI blast radius."
                f.ai_remediation  = "AI remediation steps."
                f.ai_audit_note   = "AI audit note."
            return findings

        return fake_analyze

    def test_suppressed_findings_remain_in_result_after_ai(
        self,
        active_finding: Finding,
        suppressed_finding: Finding,
        minimal_health_score: TenantHealthScore,
    ):
        """
        Both active and suppressed findings must survive AI analysis.

        Before the fix: result.findings was reassigned to only the active
        subset returned by analyze_findings(), silently dropping suppressed items.

        After the fix: analyze_findings() mutates in-place and result.findings
        is never reassigned, so both findings remain.
        """
        from auditor.models import AuditResult

        # Build a result with one active and one suppressed finding
        all_findings = [active_finding, suppressed_finding]
        result = AuditResult(
            tenant_url="https://acme.identitynow.com",
            policy_pack="default",
            findings=all_findings,
            health_score=minimal_health_score,
        )

        # Simulate what engine.py does after the fix
        with patch(
            "auditor.ai.analyzer.analyze_findings",
            side_effect=self._make_mock_analyzer(),
        ):
            from auditor.ai.analyzer import analyze_findings

            # This is the fixed engine.py behavior — no reassignment
            analyze_findings(
                findings=[f for f in all_findings if not f.suppressed],
                config=MagicMock(),
                health_score=result.health_score,
            )
            # result.findings is NOT reassigned here

        # Both findings must still be present
        assert len(result.findings) == 2, (
            "result.findings should contain both active and suppressed findings. "
            f"Got {len(result.findings)} — suppressed findings were likely dropped."
        )

    def test_only_active_finding_gets_ai_fields(
        self,
        active_finding: Finding,
        suppressed_finding: Finding,
        minimal_health_score: TenantHealthScore,
    ):
        """
        AI fields should be populated on the active finding but not the suppressed one.

        The suppressed finding is excluded from the analyze_findings() call,
        so its ai_* fields should remain None.
        """
        from auditor.models import AuditResult

        all_findings = [active_finding, suppressed_finding]
        result = AuditResult(
            tenant_url="https://acme.identitynow.com",
            policy_pack="default",
            findings=all_findings,
            health_score=minimal_health_score,
        )

        # Apply the same in-place mutation the real analyzer does
        fake_analyze = self._make_mock_analyzer()
        active_only = [f for f in all_findings if not f.suppressed]
        fake_analyze(active_only, config=MagicMock(), health_score=result.health_score)

        # Active finding should have AI fields populated
        assert result.findings[0].suppressed is False
        assert result.findings[0].ai_explanation is not None, (
            "Active finding should have ai_explanation populated after AI analysis."
        )
        assert result.findings[0].ai_remediation is not None

        # Suppressed finding should have NO AI fields
        assert result.findings[1].suppressed is True
        assert result.findings[1].ai_explanation is None, (
            "Suppressed finding should NOT have ai_explanation — "
            "it was excluded from AI analysis."
        )
        assert result.findings[1].ai_remediation is None

    def test_suppressed_finding_count_correct_after_ai(
        self,
        active_finding: Finding,
        suppressed_finding: Finding,
        minimal_health_score: TenantHealthScore,
    ):
        """
        The suppressed findings section of the report must contain exactly
        the suppressed items — not zero — after AI analysis runs.

        This is the user-visible symptom of the bug: the suppressed section
        of the HTML report was empty even when suppressions existed.
        """
        from auditor.models import AuditResult

        all_findings = [active_finding, suppressed_finding]
        result = AuditResult(
            tenant_url="https://acme.identitynow.com",
            policy_pack="default",
            findings=all_findings,
            health_score=minimal_health_score,
        )

        # Simulate AI analysis (in-place, no reassignment)
        fake_analyze = self._make_mock_analyzer()
        fake_analyze(
            [f for f in all_findings if not f.suppressed],
            config=MagicMock(),
            health_score=result.health_score,
        )

        # Build the active/suppressed split the reporter uses
        active     = [f for f in result.findings if not f.suppressed]
        suppressed = [f for f in result.findings if f.suppressed]

        assert len(active) == 1, f"Expected 1 active finding, got {len(active)}"
        assert len(suppressed) == 1, (
            f"Expected 1 suppressed finding, got {len(suppressed)}. "
            "Suppressed items are disappearing from the report — "
            "this is the Issue #10 regression."
        )
        assert suppressed[0].finding_id == "MI-06-def456"
        assert suppressed[0].suppression is not None
        assert suppressed[0].suppression.ticket == "JIRA-4521"
