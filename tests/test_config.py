"""
Tests for auditor/config.py

Covers PolicyPack.from_yaml() format compatibility and
AuditorConfig.from_env() validation behavior.

Regression tests for Issue #22:
  PolicyPack.from_yaml() was silently ignoring nested thresholds: blocks.
  Users who configured thresholds under thresholds: got class defaults
  instead of their values — with no error and no warning.
"""

from __future__ import annotations

import pytest

from auditor.config import AuditorConfig, PolicyPack


# ---------------------------------------------------------------------------
# PolicyPack.from_yaml — format compatibility (Issue #22)
# ---------------------------------------------------------------------------

class TestPolicyPackFromYaml:
    """
    Regression tests for Issue #22 — nested thresholds: block silently ignored.

    The fix supports both flat and nested formats. These tests prove:
      1. Nested thresholds: block is applied correctly
      2. Flat format still works as before
      3. Top-level values win when both formats are present
      4. Invalid thresholds: type raises a clear error
    """

    def test_nested_thresholds_block_is_applied(self, tmp_path):
        """
        Nested thresholds: block must be applied — not silently ignored.

        This is the core regression test. Before the fix, this would have
        returned stale_account_days=90 (the class default) instead of 123.
        """
        path = tmp_path / "policy.yaml"
        path.write_text(
            """
thresholds:
  stale_account_days: 123
  inactivity_days: 45
""",
            encoding="utf-8",
        )

        policy = PolicyPack.from_yaml(path)

        assert policy.stale_account_days == 123, (
            "stale_account_days from thresholds: block was ignored. "
            "Got class default instead of configured value."
        )
        assert policy.inactivity_days == 45

    def test_flat_format_still_works(self, tmp_path):
        """Flat top-level format must continue to work as before."""
        path = tmp_path / "policy.yaml"
        path.write_text(
            """
stale_account_days: 111
inactivity_days: 22
""",
            encoding="utf-8",
        )

        policy = PolicyPack.from_yaml(path)

        assert policy.stale_account_days == 111
        assert policy.inactivity_days == 22

    def test_top_level_overrides_thresholds_block(self, tmp_path):
        """
        When both formats are present, top-level values must win.

        This ensures the merge order is safe — the more explicit format
        (top-level) takes precedence over the grouped format (thresholds:).
        """
        path = tmp_path / "policy.yaml"
        path.write_text(
            """
thresholds:
  stale_account_days: 123

stale_account_days: 999
""",
            encoding="utf-8",
        )

        policy = PolicyPack.from_yaml(path)

        assert policy.stale_account_days == 999, (
            "Top-level stale_account_days should override the thresholds: block value."
        )

    def test_invalid_thresholds_type_raises_clearly(self, tmp_path):
        """
        A non-dict thresholds: value must raise ValueError with a clear message.

        Without this, a misconfigured YAML like `thresholds: 123` would
        silently fall through to class defaults.
        """
        path = tmp_path / "policy.yaml"
        path.write_text(
            """
thresholds: 123
""",
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="thresholds"):
            PolicyPack.from_yaml(path)

    def test_empty_thresholds_block_uses_defaults(self, tmp_path):
        """An empty thresholds: block should not crash — fall through to defaults."""
        path = tmp_path / "policy.yaml"
        path.write_text(
            """
thresholds:
""",
            encoding="utf-8",
        )

        policy = PolicyPack.from_yaml(path)

        # Should load with class defaults
        assert policy.stale_account_days == 90
        assert policy.inactivity_days == 60

    def test_default_yaml_loads_correctly(self):
        """
        The default policy pack must load without errors and apply its
        nested thresholds: block correctly.

        This is an integration test — it loads the actual default.yaml
        from the repo and verifies the values match what the file contains.
        """
        policy = PolicyPack.default()

        # Values from the nested thresholds: block in default.yaml
        assert policy.stale_account_days == 90
        assert policy.inactivity_days == 60
        assert policy.non_employee_grace_days == 7
        assert policy.source_stale_days == 3
        assert policy.certification_overdue_days == 7

        # Lists should be populated
        assert len(policy.privileged_apps) > 0
        assert len(policy.sensitive_entitlements) > 0
        assert len(policy.critical_sources) > 0


    def test_root_must_be_mapping_not_list(self, tmp_path):
        """A YAML file whose root is a list must raise ValueError clearly."""
        path = tmp_path / "policy.yaml"
        path.write_text("- item1\n- item2\n", encoding="utf-8")

        with pytest.raises(ValueError, match="root must be a mapping"):
            PolicyPack.from_yaml(path)

    def test_root_must_be_mapping_not_scalar(self, tmp_path):
        """A YAML file whose root is a scalar must raise ValueError clearly."""
        path = tmp_path / "policy.yaml"
        path.write_text("just a string\n", encoding="utf-8")

        with pytest.raises(ValueError, match="root must be a mapping"):
            PolicyPack.from_yaml(path)

    def test_non_existent_yaml_raises(self, tmp_path):
        """Loading a missing file should raise an appropriate error."""
        with pytest.raises((FileNotFoundError, OSError)):
            PolicyPack.from_yaml(tmp_path / "does_not_exist.yaml")


# ---------------------------------------------------------------------------
# AuditorConfig.from_env — validation behavior
# ---------------------------------------------------------------------------

class TestAuditorConfigFromEnv:
    """
    Tests for AuditorConfig.from_env() validation.

    Covers the require_ai parameter and clear error messages
    for missing environment variables.
    """

    def test_missing_isc_vars_raises_with_clear_message(self, monkeypatch):
        """Missing ISC credentials should raise OSError listing all missing vars."""
        monkeypatch.delenv("ISC_TENANT_URL",    raising=False)
        monkeypatch.delenv("ISC_CLIENT_ID",     raising=False)
        monkeypatch.delenv("ISC_CLIENT_SECRET", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        with pytest.raises(OSError) as exc_info:
            AuditorConfig.from_env()

        error = str(exc_info.value)
        assert "ISC_TENANT_URL"    in error
        assert "ISC_CLIENT_ID"     in error
        assert "ISC_CLIENT_SECRET" in error
        assert "ANTHROPIC_API_KEY" in error

    def test_require_ai_false_does_not_require_anthropic_key(self, monkeypatch):
        """
        require_ai=False must succeed without ANTHROPIC_API_KEY.
        Regression test for Issue #12.
        """
        monkeypatch.setenv("ISC_TENANT_URL",    "https://acme.identitynow.com")
        monkeypatch.setenv("ISC_CLIENT_ID",     "test-client-id")
        monkeypatch.setenv("ISC_CLIENT_SECRET", "test-secret")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        config = AuditorConfig.from_env(require_ai=False)

        assert config.tenant_url == "https://acme.identitynow.com"
        assert config.anthropic_api_key == ""

    def test_invalid_api_timeout_raises_with_clear_message(self, monkeypatch):
        """Non-integer env var should raise ValueError with the var name."""
        monkeypatch.setenv("ISC_TENANT_URL",    "https://acme.identitynow.com")
        monkeypatch.setenv("ISC_CLIENT_ID",     "test-client-id")
        monkeypatch.setenv("ISC_CLIENT_SECRET", "test-secret")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("ISC_API_TIMEOUT",   "thirty")

        with pytest.raises(ValueError, match="ISC_API_TIMEOUT"):
            AuditorConfig.from_env()

    def test_out_of_bounds_api_timeout_raises(self, monkeypatch):
        """Out-of-range env var should raise ValueError."""
        monkeypatch.setenv("ISC_TENANT_URL",    "https://acme.identitynow.com")
        monkeypatch.setenv("ISC_CLIENT_ID",     "test-client-id")
        monkeypatch.setenv("ISC_CLIENT_SECRET", "test-secret")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("ISC_API_TIMEOUT",   "9999")

        with pytest.raises(ValueError, match="ISC_API_TIMEOUT"):
            AuditorConfig.from_env()

    def test_tenant_url_trailing_slash_stripped(self, monkeypatch):
        """Trailing slashes on tenant URL must be stripped to prevent double-slash API paths."""
        monkeypatch.setenv("ISC_TENANT_URL",    "https://acme.identitynow.com/")
        monkeypatch.setenv("ISC_CLIENT_ID",     "test-client-id")
        monkeypatch.setenv("ISC_CLIENT_SECRET", "test-secret")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        config = AuditorConfig.from_env()

        assert not config.tenant_url.endswith("/"), (
            "Trailing slash was not stripped from tenant URL. "
            "This causes double-slash paths in API calls."
        )
        assert config.tenant_url == "https://acme.identitynow.com"
