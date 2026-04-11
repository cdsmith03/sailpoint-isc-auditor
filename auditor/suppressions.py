"""
Suppression store for sailpoint-isc-auditor.

Suppressions are persisted to ~/.isc-audit/suppressions.json.
The directory is created with mode 0o700 (owner-only) to prevent
other users on the same system from reading suppression records.

Each suppression has:
  - detector_id + object_id  (the specific finding being muted)
  - reason                   (mandatory — forces documentation)
  - ticket                   (optional — links to the remediation work)
  - suppressed_at            (when it was created)
  - expires_at               (optional — ISO8601; auto-cleared when past)

Expired suppressions are pruned automatically on every load.
"""

from __future__ import annotations

import json
import logging
import stat
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

SUPPRESSIONS_FILE = Path.home() / ".isc-audit" / "suppressions.json"
HISTORY_FILE      = Path.home() / ".isc-audit" / "history.json"

# Permissions for the ~/.isc-audit directory: owner read/write/execute only.
_DIR_MODE = 0o700


def _ensure_store_dir() -> None:
    """Create ~/.isc-audit with restricted permissions if it does not exist."""
    directory = SUPPRESSIONS_FILE.parent
    directory.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
    # Enforce permissions even if the directory already existed.
    directory.chmod(_DIR_MODE)


def _load_raw() -> list[dict]:
    if not SUPPRESSIONS_FILE.exists():
        return []
    with open(SUPPRESSIONS_FILE, encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            logger.warning("Suppression file is corrupted — returning empty list.")
            return []


def _save_raw(records: list[dict]) -> None:
    _ensure_store_dir()
    with open(SUPPRESSIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)


def _is_expired(record: dict) -> bool:
    exp = record.get("expires_at")
    if not exp:
        return False
    try:
        expires = datetime.fromisoformat(exp)
        # Make expires timezone-aware if it is naive (legacy records).
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires < datetime.now(timezone.utc)
    except (ValueError, TypeError):
        return False


def list_suppressions() -> list[dict]:
    """Return all active (non-expired) suppressions, pruning expired ones."""
    records = [r for r in _load_raw() if not _is_expired(r)]
    _save_raw(records)
    return records


def add_suppression(
    detector_id: str,
    object_id: str,
    reason: str,
    ticket: str | None,
    expires: str | None,
) -> None:
    """Add or replace a suppression for a specific detector + object pair."""
    records = list_suppressions()
    # Remove any existing suppression for this exact (detector, object) pair.
    records = [
        r for r in records
        if not (r["detector_id"] == detector_id and r["object_id"] == object_id)
    ]
    records.append({
        "detector_id":   detector_id,
        "object_id":     object_id,
        "reason":        reason,
        "ticket":        ticket,
        "suppressed_at": datetime.now(timezone.utc).isoformat(),
        "expires_at":    expires,
    })
    _save_raw(records)


def is_suppressed(detector_id: str, object_id: str) -> dict | None:
    """Return the suppression record if this (detector, object) pair is suppressed."""
    for s in list_suppressions():
        if s["detector_id"] == detector_id and s["object_id"] == object_id:
            return s
    return None


def apply_suppressions(findings: list) -> list:
    """Mark findings as suppressed if they match an active suppression record.

    Findings are mutated in-place: .suppressed is set to True and
    .suppression is populated. The finding remains in the list so reporters
    can show suppressed findings separately with their suppression reason.
    """
    active    = list_suppressions()
    sup_index = {
        (s["detector_id"], s["object_id"]): s
        for s in active
    }

    for finding in findings:
        for obj_id in finding.evidence.affected_object_ids:
            key = (finding.detector_id, obj_id)
            if key in sup_index:
                s = sup_index[key]
                from .models import Suppression
                expires_raw = s.get("expires_at")
                expires_dt: datetime | None = None
                if expires_raw:
                    try:
                        expires_dt = datetime.fromisoformat(expires_raw)
                        if expires_dt.tzinfo is None:
                            expires_dt = expires_dt.replace(tzinfo=timezone.utc)
                    except (ValueError, TypeError):
                        pass

                finding.suppressed  = True
                finding.suppression = Suppression(
                    detector_id=s["detector_id"],
                    object_id=obj_id,
                    reason=s["reason"],
                    ticket=s.get("ticket"),
                    suppressed_at=datetime.fromisoformat(s["suppressed_at"]).replace(
                        tzinfo=timezone.utc
                    ),
                    expires_at=expires_dt,
                )
                break  # One suppression match per finding is enough.

    return findings


def load_history() -> list[dict]:
    """Load audit run history for trend tracking."""
    if not HISTORY_FILE.exists():
        return []
    with open(HISTORY_FILE, encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            logger.warning("History file is corrupted — returning empty list.")
            return []
