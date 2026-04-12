"""
Configuration loader for sailpoint-isc-auditor.

Two distinct concerns:
  AuditorConfig  — credentials and connection settings (from environment variables)
  PolicyPack     — audit thresholds and classifications (from YAML policy pack)

Credentials are never logged, never serialized into AuditResult output,
and read exclusively from environment variables — never from code.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

load_dotenv()


def _parse_positive_int(value: str, name: str, minimum: int = 1, maximum: int = 10_000) -> int:
    """Parse an integer environment variable with bounds validation.

    Raises ValueError with a clear message if the value is not a valid
    integer or is outside the expected bounds.
    """
    try:
        parsed = int(value)
    except ValueError:
        raise ValueError(
            f"Environment variable {name} must be an integer, got: {value!r}"
        )
    if not (minimum <= parsed <= maximum):
        raise ValueError(
            f"Environment variable {name} must be between {minimum} and {maximum}, got: {parsed}"
        )
    return parsed


class PolicyPack(BaseModel):
    """
    Tenant-specific audit thresholds and classifications.
    Loaded from a YAML file so teams can customise without changing code.
    """
    # Thresholds
    stale_account_days:         int   = 90
    inactivity_days:            int   = 60
    non_employee_grace_days:    int   = 7
    mover_grace_days:           int   = 30
    peer_group_outlier_pct:     float = 95.0
    certification_overdue_days: int   = 7
    source_stale_days:          int   = 3

    # Classifications
    privileged_apps: list[str] = Field(default_factory=lambda: [
        "AWS", "Azure", "GCP", "Workday", "SAP", "Snowflake",
        "GitHub Enterprise", "Okta", "Active Directory",
    ])

    sensitive_entitlements: list[str] = Field(default_factory=lambda: [
        "Payroll Admin", "GL Posting", "IAM Admin",
        "Production Deploy", "HR Admin", "Finance Admin",
        "Root Access", "Domain Admin", "Global Admin",
    ])

    critical_sources: list[str] = Field(default_factory=lambda: [
        "Workday", "Active Directory", "AWS", "Azure AD",
    ])

    # Naming convention patterns (regex)
    naming_conventions: dict[str, str] = Field(default_factory=lambda: {
        "service_accounts": r"^svc[-_]",
        "break_glass":      r"^(bg|emergency|breakglass)[-_]",
        "shared_accounts":  r"^(shared|generic|admin)[-_]",
    })

    # Per-detector overrides: {"MI-03": {"enabled": false}}
    detector_overrides: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyPack:
        """Load a policy pack from a YAML file.

        Supports two formats — both load identically:

        Flat format:
            stale_account_days: 90
            inactivity_days: 60

        Nested format (groups thresholds for readability):
            thresholds:
              stale_account_days: 90
              inactivity_days: 60

        If a thresholds: block is present, its contents are merged into
        the top level. Keys defined at the top level always take precedence
        over keys inside thresholds: when both are present.

        The default policy pack uses the nested format. Both are equally
        supported — use whichever is clearer for your team.
        """
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        if not isinstance(data, dict):
            raise ValueError(
                f"Policy pack root must be a mapping/object, "
                f"got {type(data).__name__!r}. "
                f"Check that your policy pack YAML file is not a list or scalar."
            )

        # Support nested thresholds: block — merge into top level.
        # This was the format used by default.yaml and documented in the
        # README, but PolicyPack expects flat top-level fields.
        thresholds = data.pop("thresholds", None)

        if thresholds is not None and not isinstance(thresholds, dict):
            raise ValueError(
                f"Policy pack 'thresholds' must be a mapping/object, "
                f"got {type(thresholds).__name__!r}. "
                f"Check the format of your policy pack YAML."
            )

        if isinstance(thresholds, dict):
            # Top-level keys win over thresholds: keys if both are present.
            merged = {**thresholds, **data}
        else:
            merged = data

        return cls(**merged)

    @classmethod
    def default(cls) -> PolicyPack:
        default_path = Path(__file__).parent.parent / "policy_packs" / "default.yaml"
        if default_path.exists():
            return cls.from_yaml(default_path)
        return cls()

    def is_detector_enabled(self, detector_id: str) -> bool:
        override = self.detector_overrides.get(detector_id, {})
        return bool(override.get("enabled", True))

    def detector_threshold(self, detector_id: str, key: str, default: Any = None) -> Any:
        override = self.detector_overrides.get(detector_id, {})
        return override.get(key, default)


class AuditorConfig(BaseModel):
    """
    Runtime configuration from environment variables.

    Credentials (client_secret, anthropic_api_key) are stored only in memory
    for the duration of the process. They are never written to disk, logged,
    or included in AuditResult output.
    """
    # ISC connection
    tenant_url:    str
    client_id:     str
    client_secret: str

    # Anthropic — optional when running with --no-ai
    anthropic_api_key: str = ""

    # Tuning — bounds-validated at load time
    api_timeout: int   = 30     # seconds; range 5–300
    max_retries: int   = 3      # range 1–10
    page_size:   int   = 250    # records per page; range 10–1000
    log_level:   str   = "INFO"

    # History file for trend tracking
    history_file: Path = Field(
        default_factory=lambda: Path.home() / ".isc-audit" / "history.json"
    )

    @field_validator("tenant_url")
    @classmethod
    def normalise_tenant_url(cls, v: str) -> str:
        """Strip trailing slashes to prevent double-slash API paths."""
        return v.rstrip("/")

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got: {v!r}")
        return upper

    @classmethod
    def from_env(cls, require_ai: bool = True) -> AuditorConfig:
        """Load configuration from environment variables.

        Args:
            require_ai: If True (default), ANTHROPIC_API_KEY is required.
                        Set to False when running with --no-ai to allow
                        offline/CI runs without an Anthropic account.

        Raises EnvironmentError with a clear message listing all missing
        required variables so the user can fix them all at once.
        """
        always_required = ("ISC_TENANT_URL", "ISC_CLIENT_ID", "ISC_CLIENT_SECRET")
        ai_required     = ("ANTHROPIC_API_KEY",) if require_ai else ()
        required        = always_required + ai_required

        missing = [k for k in required if not os.getenv(k)]
        if missing:
            hint = (
                "Copy .env.example to .env and fill in your credentials."
                if require_ai else
                "Copy .env.example to .env and fill in your ISC credentials."
                " ANTHROPIC_API_KEY is not required when using --no-ai."
            )
            raise OSError(
                f"Missing required environment variables: {', '.join(missing)}\n{hint}"
            )

        return cls(
            tenant_url=os.environ["ISC_TENANT_URL"],
            client_id=os.environ["ISC_CLIENT_ID"],
            client_secret=os.environ["ISC_CLIENT_SECRET"],
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
            api_timeout=_parse_positive_int(
                os.getenv("ISC_API_TIMEOUT", "30"), "ISC_API_TIMEOUT",
                minimum=5, maximum=300,
            ),
            max_retries=_parse_positive_int(
                os.getenv("ISC_MAX_RETRIES", "3"), "ISC_MAX_RETRIES",
                minimum=1, maximum=10,
            ),
            page_size=_parse_positive_int(
                os.getenv("ISC_PAGE_SIZE", "250"), "ISC_PAGE_SIZE",
                minimum=10, maximum=1000,
            ),
            log_level=os.getenv("AUDIT_LOG_LEVEL", "INFO"),
        )
