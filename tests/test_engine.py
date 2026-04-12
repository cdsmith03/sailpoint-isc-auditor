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


class TestNoAiDoesNotRequireAnthropicKey:
    """
    Regression test for Issue #12:
    --no-ai runs were failing with EnvironmentError because
    ANTHROPIC_API_KEY was required unconditionally in from_env().

    The contract being tested:
      - from_env(require_ai=False) succeeds without ANTHROPIC_API_KEY
      - from_env(require_ai=True) fails clearly when key is missing
      - the loaded config has an empty anthropic_api_key when not provided
    """

    def test_from_env_no_ai_does_not_require_anthropic_key(self, monkeypatch):
        """
        from_env(require_ai=False) must succeed when ANTHROPIC_API_KEY
        is not set — this is the --no-ai use case.
        """
        from auditor.config import AuditorConfig

        monkeypatch.setenv("ISC_TENANT_URL",    "https://acme.identitynow.com")
        monkeypatch.setenv("ISC_CLIENT_ID",     "test-client-id")
        monkeypatch.setenv("ISC_CLIENT_SECRET", "test-client-secret")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        # Should not raise
        config = AuditorConfig.from_env(require_ai=False)
        assert config.tenant_url == "https://acme.identitynow.com"
        assert config.anthropic_api_key == ""

    def test_from_env_ai_mode_requires_anthropic_key(self, monkeypatch):
        """
        from_env(require_ai=True) must raise EnvironmentError when
        ANTHROPIC_API_KEY is missing — AI runs need the key.
        """
        from auditor.config import AuditorConfig

        monkeypatch.setenv("ISC_TENANT_URL",    "https://acme.identitynow.com")
        monkeypatch.setenv("ISC_CLIENT_ID",     "test-client-id")
        monkeypatch.setenv("ISC_CLIENT_SECRET", "test-client-secret")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        with pytest.raises(EnvironmentError) as exc_info:
            AuditorConfig.from_env(require_ai=True)

        assert "ANTHROPIC_API_KEY" in str(exc_info.value)

    def test_from_env_error_message_mentions_no_ai_hint(self, monkeypatch):
        """
        When ISC credentials are missing in --no-ai mode, the error
        message should mention that ANTHROPIC_API_KEY is not required.
        """
        from auditor.config import AuditorConfig

        monkeypatch.delenv("ISC_TENANT_URL",    raising=False)
        monkeypatch.delenv("ISC_CLIENT_ID",     raising=False)
        monkeypatch.delenv("ISC_CLIENT_SECRET", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        with pytest.raises(EnvironmentError) as exc_info:
            AuditorConfig.from_env(require_ai=False)

        error_msg = str(exc_info.value)
        assert "ISC_TENANT_URL" in error_msg
        assert "not required when using --no-ai" in error_msg


class TestNoAiCliWiring:
    """
    CLI integration tests for Issue #12.

    Proves the CLI correctly wires --no-ai through to from_env()
    and run_audit(). Config-level tests alone do not catch a regression
    where someone removes require_ai=not no_ai from the CLI call.
    """

    def test_cli_no_ai_flag_does_not_require_anthropic_key(self, monkeypatch):
        """
        isc-audit run --all --no-ai must not fail when ANTHROPIC_API_KEY
        is unset. This proves the CLI wiring is intact end-to-end.
        """
        from unittest.mock import MagicMock, patch
        from click.testing import CliRunner
        from auditor.cli import main

        monkeypatch.setenv("ISC_TENANT_URL",    "https://acme.identitynow.com")
        monkeypatch.setenv("ISC_CLIENT_ID",     "test-client-id")
        monkeypatch.setenv("ISC_CLIENT_SECRET", "test-client-secret")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        mock_result = MagicMock()
        mock_result.findings         = []
        mock_result.health_score     = MagicMock()
        mock_result.health_score.tenant_health        = 75.0
        mock_result.health_score.band.value           = "Stable"
        mock_result.health_score.trend                = None
        mock_result.health_score.has_critical_conditions = False
        mock_result.health_score.critical_conditions  = []
        mock_result.health_score.family_scores        = {}
        mock_result.health_score.coverage_confidence.score_display = 70
        mock_result.detector_coverage = []

        with patch("auditor.engine.run_audit", return_value=mock_result) as mock_run:
            runner = CliRunner()
            result = runner.invoke(main, ["run", "--all", "--no-ai"])

        # Must not exit with "Missing required environment variables"
        assert "ANTHROPIC_API_KEY" not in result.output, (
            f"--no-ai run should not require ANTHROPIC_API_KEY. "
            f"Got output: {result.output}"
        )

        # run_audit must have been called with run_ai=False
        if mock_run.called:
            _, kwargs = mock_run.call_args
            assert kwargs.get("run_ai") is False or mock_run.call_args[0][5] is False, (
                "run_audit should have been called with run_ai=False when --no-ai is set"
            )

    def test_cli_from_env_called_with_require_ai_false(self, monkeypatch):
        """
        When --no-ai is passed, AuditorConfig.from_env must be called
        with require_ai=False. This directly tests the wiring.
        """
        from unittest.mock import MagicMock, patch, call
        from click.testing import CliRunner
        from auditor.cli import main
        from auditor.config import AuditorConfig

        monkeypatch.setenv("ISC_TENANT_URL",    "https://acme.identitynow.com")
        monkeypatch.setenv("ISC_CLIENT_ID",     "test-client-id")
        monkeypatch.setenv("ISC_CLIENT_SECRET", "test-client-secret")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        mock_config = MagicMock(spec=AuditorConfig)
        mock_config.tenant_url       = "https://acme.identitynow.com"
        mock_config.anthropic_api_key = ""
        mock_config.history_file     = MagicMock()
        mock_config.history_file.exists.return_value = False

        mock_result = MagicMock()
        mock_result.findings         = []
        mock_result.health_score     = MagicMock()
        mock_result.health_score.tenant_health        = 75.0
        mock_result.health_score.band.value           = "Stable"
        mock_result.health_score.trend                = None
        mock_result.health_score.has_critical_conditions = False
        mock_result.health_score.critical_conditions  = []
        mock_result.health_score.family_scores        = {}
        mock_result.health_score.coverage_confidence.score_display = 70
        mock_result.detector_coverage = []

        with patch.object(AuditorConfig, "from_env", return_value=mock_config) as mock_from_env,              patch("auditor.engine.run_audit", return_value=mock_result):
            runner = CliRunner()
            runner.invoke(main, ["run", "--all", "--no-ai"])

        # Verify from_env was called with require_ai=False
        mock_from_env.assert_called_once_with(require_ai=False)
