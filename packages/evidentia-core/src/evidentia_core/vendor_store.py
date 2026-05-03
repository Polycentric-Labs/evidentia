"""Persistent vendor inventory store (v0.7.9 P0.1.2).

Mirrors the :mod:`evidentia_core.gap_store` pattern adapted for the
TPRM Vendor model:

- One JSON file per vendor, named ``<vendor_id>.json`` where
  ``vendor_id`` is the model's UUID-v4 string identifier (defined by
  :func:`evidentia_core.models.common.new_id`).
- Storage location follows the standard ``platformdirs``-backed
  precedence used elsewhere in the codebase:
    1. Explicit ``override`` argument (CLI flag or test fixture)
    2. ``EVIDENTIA_VENDOR_STORE_DIR`` environment variable
    3. Platform default via ``platformdirs.user_data_dir`` —
       Windows: ``%APPDATA%\\Evidentia\\vendor_store\\``;
       macOS:   ``~/Library/Application Support/evidentia/vendor_store/``;
       Linux:   ``~/.local/share/evidentia/vendor_store/``.

CRUD surface (mirrors gap_store except where a vendor-specific verb
makes more sense):

  - :func:`save_vendor` — write or overwrite a single vendor record;
    refreshes ``vendor.updated_at`` to the current UTC time before
    persisting (the model's auto-stamping handles ``created_at``)
  - :func:`load_vendor_by_id` — read a single vendor by ID; returns
    ``None`` for well-formed-but-unknown IDs;
    :class:`InvalidVendorIdError` on shape violations
  - :func:`list_vendors` — return every vendor in the store, sorted
    by ``(criticality_tier, name)`` for ergonomic CLI output
  - :func:`delete_vendor` — remove a vendor file; returns ``True``
    if a record was actually removed, ``False`` if the well-formed
    ID had no record on disk

Path-traversal protection mirrors gap_store via
:func:`evidentia_core.security.paths.validate_within`. The shape
check on the ID rejects anything that isn't a canonical UUID-v4 hex
form (``hex8-hex4-hex4-hex4-hex12``), so a malicious ``../../etc``
input fails the shape gate before reaching the path resolver.
Belt-and-suspenders.

This module ships in v0.7.9 P0.1.2; the CLI surface (P0.1.3) and
REST router (P0.1.4) build on top of these primitives.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from uuid import UUID

from platformdirs import user_data_dir

from evidentia_core.models.common import utc_now
from evidentia_core.models.tprm import CriticalityTier, Vendor
from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)

logger = logging.getLogger(__name__)

VENDOR_STORE_ENV_VAR = "EVIDENTIA_VENDOR_STORE_DIR"


class InvalidVendorIdError(ValueError):
    """Raised when a candidate vendor ID isn't a valid UUID-v4 string.

    Subclasses :class:`ValueError` so existing ``except ValueError``
    handlers continue to work.
    """


def _validate_id_shape(vendor_id: str) -> None:
    """Reject IDs that aren't a canonical UUID string.

    Accepts any UUID variant (v1/v3/v4/v5) — the v0.7.9 P0.1.1
    Vendor model stamps v4 via :func:`new_id`, but any record
    imported from an external system might carry a different
    variant, and that's fine. What we reject is anything that
    isn't UUID-shaped at all (path-traversal segments, empty
    strings, raw integers, etc.) so the resolved file path can
    never escape the store directory.
    """
    try:
        UUID(vendor_id)
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidVendorIdError(
            f"Invalid vendor ID format (expected UUID string): {vendor_id!r}"
        ) from exc


def get_vendor_store_dir(override: Path | None = None) -> Path:
    """Resolve the vendor store directory.

    Precedence:
      1. Explicit ``override`` argument (CLI flag or test fixture)
      2. ``EVIDENTIA_VENDOR_STORE_DIR`` environment variable
      3. Platform default via ``platformdirs.user_data_dir``
    """
    if override is not None:
        return Path(override).expanduser().resolve()
    env = os.environ.get(VENDOR_STORE_ENV_VAR)
    if env:
        return Path(env).expanduser().resolve()
    return Path(user_data_dir("evidentia", "Evidentia")) / "vendor_store"


def save_vendor(
    vendor: Vendor,
    vendor_store_dir: Path | None = None,
) -> Path:
    """Persist a vendor record to the user-dir store.

    Refreshes ``vendor.updated_at`` to the current UTC time before
    writing. Returns the absolute path of the written JSON file.
    The file is a plain ``model_dump_json(indent=2)`` of the vendor
    — no special framing, so an operator can edit it by hand if
    needed (and reload via :func:`load_vendor_by_id`).
    """
    _validate_id_shape(vendor.id)
    store = get_vendor_store_dir(vendor_store_dir)
    store.mkdir(parents=True, exist_ok=True)

    vendor.updated_at = utc_now()
    out_path = store / f"{vendor.id}.json"
    out_path.write_text(vendor.model_dump_json(indent=2), encoding="utf-8")
    logger.debug("Saved vendor record: %s", out_path)
    return out_path


def load_vendor_by_id(
    vendor_id: str,
    vendor_store_dir: Path | None = None,
) -> Vendor | None:
    """Load a saved vendor by its UUID.

    Validates the ID shape and confirms the resolved path lies
    within the store directory before reading. Returns ``None`` if
    the well-formed ID does not correspond to a stored record.
    Raises :class:`InvalidVendorIdError` on shape violation and
    :class:`evidentia_core.security.paths.PathTraversalError` on
    resolved-path violation (which the shape check should already
    have rejected — the path check is belt-and-suspenders).
    """
    _validate_id_shape(vendor_id)
    store = get_vendor_store_dir(vendor_store_dir)
    candidate = store / f"{vendor_id}.json"
    path = validate_within(candidate, store)
    if not path.is_file():
        return None
    return Vendor.model_validate_json(path.read_text(encoding="utf-8"))


# Numeric ranks used to order CriticalityTier values in
# :func:`list_vendors`. Lower number = "more important" — critical
# first, then high, medium, low. Defined as a module constant so
# the order is stable across Python sessions (Enum iteration order
# is deterministic per the Python language spec but explicit is
# better than implicit here).
_TIER_RANK = {
    CriticalityTier.CRITICAL.value: 0,
    CriticalityTier.HIGH.value: 1,
    CriticalityTier.MEDIUM.value: 2,
    CriticalityTier.LOW.value: 3,
}


def list_vendors(
    vendor_store_dir: Path | None = None,
) -> list[Vendor]:
    """Return every vendor in the store, sorted (criticality, name).

    Sort key:
      1. Criticality tier rank (critical → high → medium → low)
      2. Name (case-insensitive)

    This is the canonical ordering for CLI output and the default
    REST listing. Empty list if the store directory doesn't exist
    or contains no records.
    """
    store = get_vendor_store_dir(vendor_store_dir)
    if not store.exists():
        return []
    vendors: list[Vendor] = []
    for path in store.glob("*.json"):
        try:
            vendors.append(
                Vendor.model_validate_json(path.read_text(encoding="utf-8"))
            )
        except Exception as exc:  # pragma: no cover — defensive
            # A malformed file in the store shouldn't crash the listing
            # of all the well-formed records. Log + skip. Operators
            # can spot it via the warning + manually inspect.
            logger.warning(
                "Skipping malformed vendor record %s: %s", path, exc
            )
    vendors.sort(
        key=lambda v: (_TIER_RANK.get(v.criticality_tier, 99), v.name.lower())
    )
    return vendors


def delete_vendor(
    vendor_id: str,
    vendor_store_dir: Path | None = None,
) -> bool:
    """Delete a vendor record by ID.

    Returns ``True`` if a file was actually removed, ``False`` if
    the well-formed ID had no file on disk. Raises
    :class:`InvalidVendorIdError` on shape violation.
    """
    _validate_id_shape(vendor_id)
    store = get_vendor_store_dir(vendor_store_dir)
    candidate = store / f"{vendor_id}.json"
    path = validate_within(candidate, store)
    if not path.is_file():
        return False
    path.unlink()
    logger.debug("Deleted vendor record: %s", path)
    return True


__all__ = [
    "VENDOR_STORE_ENV_VAR",
    "InvalidVendorIdError",
    "PathTraversalError",
    "delete_vendor",
    "get_vendor_store_dir",
    "list_vendors",
    "load_vendor_by_id",
    "save_vendor",
]
