"""
SailPoint ISC REST API client.

All network calls to ISC go through this file — nothing else calls the API directly.
This centralises auth, retry, pagination, and exception handling in one place.

Security notes:
  - OAuth tokens are cached in memory only, never logged or written to disk.
  - The Retry-After header is clamped to MAX_RETRY_AFTER_SECONDS to prevent
    a malicious or misconfigured server from inducing an arbitrarily long sleep.
  - A 401 mid-run triggers one token refresh and one retry. If the second attempt
    also returns 401, ISCAuthError is raised rather than looping indefinitely.
  - Credentials are never included in log output at any level.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .config import AuditorConfig

logger = logging.getLogger(__name__)

# Hard ceiling on Retry-After sleep to prevent server-induced denial of service.
MAX_RETRY_AFTER_SECONDS = 60


# ---------------------------------------------------------------------------
# Typed exceptions — one per meaningful failure mode
# ---------------------------------------------------------------------------

class ISCClientError(Exception):
    """Base class for all ISC client errors."""

class ISCAuthError(ISCClientError):
    """OAuth token request failed or credentials are invalid."""

class ISCPermissionDenied(ISCClientError):
    """403 — the API client is missing a required scope."""

class ISCEndpointUnavailable(ISCClientError):
    """404 / 501 — endpoint is experimental or not enabled on this tenant tier."""

class ISCRateLimitExceeded(ISCClientError):
    """429 — rate limited. Tenacity will retry with backoff."""

class ISCServerError(ISCClientError):
    """5xx — transient server error. Tenacity will retry with backoff."""


# ---------------------------------------------------------------------------
# Token cache — in-process, single-run lifetime
# ---------------------------------------------------------------------------

class _TokenCache:
    """Caches the OAuth bearer token for the lifetime of the audit run.

    Tokens are held in memory only. The 30-second margin on expiry prevents
    using a token that expires between the cache check and the API call.
    """

    _EXPIRY_MARGIN_SECONDS = 30

    def __init__(self) -> None:
        self._token: str | None = None
        self._expires_at: float = 0.0

    def get(self) -> str | None:
        if self._token and time.monotonic() < self._expires_at - self._EXPIRY_MARGIN_SECONDS:
            return self._token
        return None

    def set(self, token: str, expires_in: int) -> None:
        self._token = token
        self._expires_at = time.monotonic() + expires_in

    def clear(self) -> None:
        self._token = None
        self._expires_at = 0.0


# ---------------------------------------------------------------------------
# ISC API client
# ---------------------------------------------------------------------------

class ISCClient:
    """
    Thin wrapper around the SailPoint ISC REST API.

    Usage:
        with ISCClient(config) as client:
            identities = client.get_identities()
    """

    def __init__(self, config: AuditorConfig) -> None:
        self._config = config
        self._cache  = _TokenCache()
        self._http   = httpx.Client(
            base_url=config.tenant_url,
            timeout=config.api_timeout,
            follow_redirects=True,
        )

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def _get_token(self) -> str:
        """Return a valid OAuth bearer token, fetching a new one if needed.

        Credentials are passed as form data (not logged at any level).
        """
        cached = self._cache.get()
        if cached:
            return cached

        logger.debug("Requesting new OAuth access token")
        resp = self._http.post(
            "/oauth/token",
            data={
                "grant_type":    "client_credentials",
                "client_id":     self._config.client_id,
                "client_secret": self._config.client_secret,
            },
        )
        if resp.status_code == 401:
            raise ISCAuthError(
                "OAuth token request failed (401). "
                "Verify ISC_CLIENT_ID and ISC_CLIENT_SECRET in your .env file."
            )
        resp.raise_for_status()
        data       = resp.json()
        token      = data["access_token"]
        expires_in = int(data.get("expires_in", 3600))
        self._cache.set(token, expires_in)
        return token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        }

    # ------------------------------------------------------------------
    # Core request (tenacity retries on transient errors)
    # ------------------------------------------------------------------

    @retry(
        retry=retry_if_exception_type((ISCRateLimitExceeded, ISCServerError)),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(4),
    )
    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Execute one HTTP request, mapping status codes to typed exceptions.

        401 handling: clears the token cache and retries exactly once. If the
        second attempt also returns 401, ISCAuthError is raised immediately —
        there is no further retry to prevent an infinite loop on bad credentials.
        """
        resp = self._http.request(method, path, headers=self._headers(), **kwargs)

        if resp.status_code == 200:
            return resp

        if resp.status_code == 401:
            # Token may have expired mid-run — refresh once and retry.
            self._cache.clear()
            resp = self._http.request(method, path, headers=self._headers(), **kwargs)
            if resp.status_code == 401:
                raise ISCAuthError(
                    f"Authentication failed on {path} after token refresh. "
                    "Verify that the API client credentials are valid and have not been rotated."
                )
            resp.raise_for_status()
            return resp

        if resp.status_code == 403:
            raise ISCPermissionDenied(
                f"Permission denied: {path}\n"
                "Check that your API client has all required scopes (see README)."
            )

        if resp.status_code in (404, 501):
            raise ISCEndpointUnavailable(
                f"Endpoint unavailable: {path} (HTTP {resp.status_code}). "
                "This endpoint may be experimental or not enabled on this tenant tier."
            )

        if resp.status_code == 429:
            raw_retry_after = resp.headers.get("Retry-After", "5")
            try:
                retry_after = min(int(raw_retry_after), MAX_RETRY_AFTER_SECONDS)
            except ValueError:
                retry_after = 5
            logger.warning("Rate limited by ISC. Waiting %ds before retry.", retry_after)
            time.sleep(retry_after)
            raise ISCRateLimitExceeded(f"Rate limited on {path}")

        if resp.status_code >= 500:
            raise ISCServerError(f"Server error {resp.status_code} on {path}")

        resp.raise_for_status()
        return resp

    # ------------------------------------------------------------------
    # Pagination helper
    # ISC uses offset/limit with optional X-Total-Count header.
    # ------------------------------------------------------------------

    def get_all(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        max_records: int | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all records from a paginated ISC endpoint.

        Handles the slight inconsistency across ISC endpoints where some return
        a plain JSON array and others return {"items": [...]} or {"data": [...]}.
        """
        params  = dict(params or {})
        results: list[dict[str, Any]] = []
        offset  = 0
        limit   = self._config.page_size

        while True:
            params.update({"limit": limit, "offset": offset})
            resp = self._request("GET", path, params=params)
            page = resp.json()

            if not isinstance(page, list):
                page = page.get("items", page.get("data", [page]))

            results.extend(page)
            logger.debug("%s: fetched %d records (offset=%d)", path, len(results), offset)

            if len(page) < limit:
                break
            if max_records and len(results) >= max_records:
                break

            offset += limit

        return results[:max_records] if max_records else results

    def get_one(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Fetch a single object."""
        return self._request("GET", path, params=params).json()

    # ------------------------------------------------------------------
    # Resource-specific convenience methods
    # ------------------------------------------------------------------

    def get_identities(self, filters: str | None = None) -> list[dict[str, Any]]:
        params = {"filters": filters} if filters else {}
        return self.get_all("/v3/identities", params=params)

    def get_accounts(self, filters: str | None = None) -> list[dict[str, Any]]:
        params = {"filters": filters} if filters else {}
        return self.get_all("/v3/accounts", params=params)

    def get_roles(self) -> list[dict[str, Any]]:
        return self.get_all("/v3/roles")

    def get_entitlements(self, source_id: str | None = None) -> list[dict[str, Any]]:
        params = ({"filters": f'source.id eq "{source_id}"'} if source_id else {})
        return self.get_all("/v3/entitlements", params=params)

    def get_access_profiles(self) -> list[dict[str, Any]]:
        return self.get_all("/v3/access-profiles")

    def get_sod_violations(self) -> list[dict[str, Any]]:
        return self.get_all("/v3/sod-violations")

    def get_sod_policies(self) -> list[dict[str, Any]]:
        return self.get_all("/v3/sod-policies")

    def get_certifications(self) -> list[dict[str, Any]]:
        return self.get_all("/v3/certifications")

    def get_certification_items(self, certification_id: str) -> list[dict[str, Any]]:
        return self.get_all(f"/v3/certifications/{certification_id}/items")

    def get_sources(self) -> list[dict[str, Any]]:
        return self.get_all("/v3/sources")

    def get_account_activities(self, filters: str | None = None) -> list[dict[str, Any]]:
        params = {"filters": filters} if filters else {}
        return self.get_all("/v3/account-activities", params=params)

    def get_governance_groups(self) -> list[dict[str, Any]]:
        return self.get_all("/v3/workgroups")

    def get_non_employees(self) -> list[dict[str, Any]]:
        return self.get_all("/v3/non-employee-records")

    def get_machine_identities(self) -> list[dict[str, Any]]:
        """Experimental endpoint — collectors must handle ISCEndpointUnavailable."""
        return self.get_all("/beta/machine-identities")

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ISCClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
