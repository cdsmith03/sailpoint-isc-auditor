"""
Tests for auditor/suppressions.py

Covers the full suppression lifecycle:
  - add_suppression: persists correctly to disk
  - list_suppressions: expired suppressions pruned automatically
  - is_suppressed: returns correct result for active suppression
  - is_suppressed: returns None for non-existent suppression
  - apply_suppressions: marks correct findings as suppressed
  - apply_suppressions: does not suppress non-matching findings
  - Future expiry stays active
  - Past expiry is pruned

All tests use a tmp_path fixture and patch SUPPRESSIONS_FILE so they
never touch the real ~/.isc-audit/suppressions.json on disk.

Closes #29
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from auditor.models import (
    CollectionStatus,
    ControlFamily,
    Finding,
    FindingEvidence,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    detector_id: str = "LI-01",
    object_id: str = "obj-001",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        finding_id=f"{detector_id}-test",
        detector_id=detector_id,
        family=ControlFamily.LI,
        title=f"Test finding {detector_id}",
        severity=severity,
        evidence=FindingEvidence(
            affected_object_ids=[object_id],
            affected_object_names=[object_id],
            why_fired="Test",
            recommended_fix="Test",
            collection_status=CollectionStatus.FULL,
        ),
    )


def _future_date(days: int = 30) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


def _past_date(days: int = 30) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).isoformat()


# ---------------------------------------------------------------------------
# add_suppression
# ---------------------------------------------------------------------------

class TestAddSuppression:
    """Tests that add_suppression() persists correctly to disk."""

    def test_suppression_persisted_to_disk(self, tmp_path):
        """add_suppression() must write a record that can be read back."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, list_suppressions
            add_suppression("LI-01", "obj-001", "Known risk", None, None)
            records = list_suppressions()

        assert len(records) == 1
        assert records[0]["detector_id"] == "LI-01"
        assert records[0]["object_id"]   == "obj-001"
        assert records[0]["reason"]      == "Known risk"

    def test_ticket_reference_persisted(self, tmp_path):
        """Ticket reference must be saved and returned."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, list_suppressions
            add_suppression("AR-01", "obj-002", "SOD exception", "JIRA-1234", None)
            records = list_suppressions()

        assert records[0]["ticket"] == "JIRA-1234"

    def test_expiry_date_persisted(self, tmp_path):
        """Expiry date must be saved and returned."""
        sup_file = tmp_path / "suppressions.json"
        expiry = _future_date(60)
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, list_suppressions
            add_suppression("MI-01", "obj-003", "Scheduled fix", None, expiry)
            records = list_suppressions()

        assert records[0]["expires_at"] == expiry

    def test_duplicate_suppression_replaced(self, tmp_path):
        """Adding a second suppression for the same (detector, object) replaces the first."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, list_suppressions
            add_suppression("LI-01", "obj-001", "First reason", None, None)
            add_suppression("LI-01", "obj-001", "Updated reason", None, None)
            records = list_suppressions()

        assert len(records) == 1
        assert records[0]["reason"] == "Updated reason"

    def test_suppressed_at_timestamp_set(self, tmp_path):
        """suppressed_at must be populated automatically."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, list_suppressions
            add_suppression("LI-01", "obj-001", "Test", None, None)
            records = list_suppressions()

        assert records[0]["suppressed_at"] is not None
        # Should be parseable as ISO-8601
        datetime.fromisoformat(records[0]["suppressed_at"])


# ---------------------------------------------------------------------------
# list_suppressions — expiry pruning
# ---------------------------------------------------------------------------

class TestListSuppressions:
    """Tests that list_suppressions() prunes expired records automatically."""

    def test_active_suppression_returned(self, tmp_path):
        """A non-expired suppression must be returned."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, list_suppressions
            add_suppression("LI-01", "obj-001", "Active", None, _future_date(30))
            records = list_suppressions()

        assert len(records) == 1

    def test_expired_suppression_pruned(self, tmp_path):
        """An expired suppression must be pruned and not returned."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, list_suppressions
            add_suppression("LI-01", "obj-001", "Expired", None, _past_date(1))
            records = list_suppressions()

        assert len(records) == 0

    def test_expired_suppression_removed_from_file(self, tmp_path):
        """Pruning must write the cleaned list back to disk."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, list_suppressions
            add_suppression("LI-01", "obj-001", "Expired", None, _past_date(1))
            list_suppressions()  # triggers pruning
            records = list_suppressions()  # read back from disk

        assert len(records) == 0

    def test_mixed_active_and_expired(self, tmp_path):
        """Only active suppressions should be returned when both exist."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, list_suppressions
            add_suppression("LI-01", "obj-001", "Active",  None, _future_date(30))
            add_suppression("LI-02", "obj-002", "Expired", None, _past_date(1))
            records = list_suppressions()

        assert len(records) == 1
        assert records[0]["detector_id"] == "LI-01"

    def test_no_expiry_never_pruned(self, tmp_path):
        """A suppression with no expiry date must never be pruned."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, list_suppressions
            add_suppression("MI-01", "obj-001", "Permanent", None, None)
            records = list_suppressions()

        assert len(records) == 1

    def test_empty_store_returns_empty_list(self, tmp_path):
        """When no suppressions exist, must return an empty list."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import list_suppressions
            records = list_suppressions()

        assert records == []


# ---------------------------------------------------------------------------
# is_suppressed
# ---------------------------------------------------------------------------

class TestIsSuppressed:
    """Tests for is_suppressed() — the point-in-time lookup function."""

    def test_returns_record_for_active_suppression(self, tmp_path):
        """is_suppressed() must return the record when a suppression is active."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, is_suppressed
            add_suppression("LI-01", "obj-001", "Known risk", "JIRA-999", None)
            result = is_suppressed("LI-01", "obj-001")

        assert result is not None
        assert result["reason"] == "Known risk"
        assert result["ticket"] == "JIRA-999"

    def test_returns_none_for_missing_suppression(self, tmp_path):
        """is_suppressed() must return None when no suppression exists."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import is_suppressed
            result = is_suppressed("LI-01", "obj-999")

        assert result is None

    def test_returns_none_for_expired_suppression(self, tmp_path):
        """An expired suppression must return None — it is no longer active."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, is_suppressed
            add_suppression("LI-01", "obj-001", "Expired", None, _past_date(1))
            result = is_suppressed("LI-01", "obj-001")

        assert result is None

    def test_wrong_detector_returns_none(self, tmp_path):
        """A suppression for LI-01 must not match a lookup for LI-02."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, is_suppressed
            add_suppression("LI-01", "obj-001", "Test", None, None)
            result = is_suppressed("LI-02", "obj-001")

        assert result is None

    def test_wrong_object_returns_none(self, tmp_path):
        """A suppression for obj-001 must not match a lookup for obj-002."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, is_suppressed
            add_suppression("LI-01", "obj-001", "Test", None, None)
            result = is_suppressed("LI-01", "obj-002")

        assert result is None


# ---------------------------------------------------------------------------
# apply_suppressions
# ---------------------------------------------------------------------------

class TestApplySuppressions:
    """Tests for apply_suppressions() — the bulk finding mutation function."""

    def test_matching_finding_marked_suppressed(self, tmp_path):
        """A finding that matches an active suppression must be marked suppressed=True."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, apply_suppressions
            add_suppression("LI-01", "obj-001", "Known risk", None, None)
            findings = [_make_finding("LI-01", "obj-001")]
            apply_suppressions(findings)

        assert findings[0].suppressed is True

    def test_suppression_record_attached_to_finding(self, tmp_path):
        """The Suppression model must be attached to the finding after apply."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, apply_suppressions
            add_suppression("LI-01", "obj-001", "Known risk", "JIRA-100", None)
            findings = [_make_finding("LI-01", "obj-001")]
            apply_suppressions(findings)

        assert findings[0].suppression is not None
        assert findings[0].suppression.reason == "Known risk"
        assert findings[0].suppression.ticket == "JIRA-100"

    def test_non_matching_finding_not_suppressed(self, tmp_path):
        """A finding that does not match any suppression must remain unsuppressed."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, apply_suppressions
            add_suppression("LI-01", "obj-001", "Known risk", None, None)
            findings = [_make_finding("LI-02", "obj-999")]
            apply_suppressions(findings)

        assert findings[0].suppressed is False

    def test_only_matching_finding_suppressed_in_list(self, tmp_path):
        """Only the matching finding should be suppressed, not all findings."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, apply_suppressions
            add_suppression("LI-01", "obj-001", "Known risk", None, None)
            findings = [
                _make_finding("LI-01", "obj-001"),  # should be suppressed
                _make_finding("LI-01", "obj-002"),  # should NOT be suppressed
                _make_finding("LI-02", "obj-001"),  # should NOT be suppressed
            ]
            apply_suppressions(findings)

        assert findings[0].suppressed is True
        assert findings[1].suppressed is False
        assert findings[2].suppressed is False

    def test_finding_remains_in_list_when_suppressed(self, tmp_path):
        """
        Suppressed findings must remain in the list — never silently dropped.
        Reporters use suppressed=True to show them separately.
        """
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, apply_suppressions
            add_suppression("LI-01", "obj-001", "Known risk", None, None)
            findings = [_make_finding("LI-01", "obj-001")]
            result = apply_suppressions(findings)

        assert len(result) == 1

    def test_expired_suppression_does_not_suppress_finding(self, tmp_path):
        """An expired suppression must not mark a finding as suppressed."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import add_suppression, apply_suppressions
            add_suppression("LI-01", "obj-001", "Expired", None, _past_date(1))
            findings = [_make_finding("LI-01", "obj-001")]
            apply_suppressions(findings)

        assert findings[0].suppressed is False

    def test_empty_findings_list_returns_empty(self, tmp_path):
        """apply_suppressions() on an empty list must return an empty list."""
        sup_file = tmp_path / "suppressions.json"
        with patch("auditor.suppressions.SUPPRESSIONS_FILE", sup_file):
            from auditor.suppressions import apply_suppressions
            result = apply_suppressions([])

        assert result == []
