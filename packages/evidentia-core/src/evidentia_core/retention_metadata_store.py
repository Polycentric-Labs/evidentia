"""Persistent retention-metadata store (v0.7.11 P0).

JSON-file-per-record persistence following the harmonized v0.7.11
store pattern. Stores RetentionMetadata records (not the underlying
evidence — that lives in a WORM backend per
:mod:`evidentia_core.retention.worm`).

Storage location precedence:

    1. Explicit ``override`` argument
    2. ``EVIDENTIA_RETENTION_STORE_DIR`` environment variable
    3. Platform default via ``platformdirs.user_data_dir``
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from uuid import UUID

from platformdirs import user_data_dir

from evidentia_core.models.common import utc_now
from evidentia_core.retention.metadata import RetentionMetadata
from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)

logger = logging.getLogger(__name__)

RETENTION_STORE_ENV_VAR = "EVIDENTIA_RETENTION_STORE_DIR"


class InvalidRetentionIdError(ValueError):
    """Raised when a candidate retention metadata ID isn't a valid UUID."""


def _validate_id_shape(retention_id: str) -> None:
    if not isinstance(retention_id, str) or not retention_id:
        raise InvalidRetentionIdError(
            f"Invalid retention ID: empty or non-string: {retention_id!r}"
        )
    try:
        UUID(retention_id)
    except (ValueError, AttributeError, TypeError) as e:
        raise InvalidRetentionIdError(
            f"Invalid retention ID: not a UUID-shaped string: "
            f"{retention_id!r} ({type(e).__name__}: {e})"
        ) from e


def get_retention_store_dir(override: Path | None = None) -> Path:
    """Resolve the retention metadata store directory."""
    if override is not None:
        return Path(override).expanduser().resolve()
    env = os.environ.get(RETENTION_STORE_ENV_VAR)
    if env:
        # v0.7.12 P3 cosmetic harmonization: match vendor_store +
        # model_risk_store pattern.
        return Path(env).expanduser().resolve()
    return Path(user_data_dir("evidentia", appauthor=False)) / "retention_store"


def save_retention(
    metadata: RetentionMetadata, *, override: Path | None = None
) -> Path:
    """Persist retention metadata. Atomic via os.replace."""
    _validate_id_shape(metadata.id)
    store_dir = get_retention_store_dir(override)
    store_dir.mkdir(parents=True, exist_ok=True)

    refreshed = metadata.model_copy(update={"updated_at": utc_now()})
    payload = refreshed.model_dump_json(indent=2)

    candidate = store_dir / f"{metadata.id}.json"
    try:
        out_path = validate_within(candidate, store_dir)
    except PathTraversalError as e:
        raise InvalidRetentionIdError(
            f"Invalid retention ID: path-traversal violation: {metadata.id!r}"
        ) from e
    tmp_path = store_dir / f"{metadata.id}.json.tmp"
    tmp_path.write_text(payload, encoding="utf-8")
    os.replace(tmp_path, out_path)
    logger.debug("saved retention metadata %s to %s", metadata.id, out_path)
    return out_path


def load_retention_by_id(
    retention_id: str, *, override: Path | None = None
) -> RetentionMetadata | None:
    """Load retention metadata by ID."""
    _validate_id_shape(retention_id)
    store_dir = get_retention_store_dir(override)
    candidate = store_dir / f"{retention_id}.json"
    try:
        path = validate_within(candidate, store_dir)
    except PathTraversalError as e:
        raise InvalidRetentionIdError(
            f"Invalid retention ID: path-traversal violation: {retention_id!r}"
        ) from e
    if not path.exists():
        return None
    return RetentionMetadata.model_validate_json(
        path.read_text(encoding="utf-8")
    )


def list_retention(
    *, override: Path | None = None
) -> list[RetentionMetadata]:
    """List all retention records sorted by classification then created_at."""
    store_dir = get_retention_store_dir(override)
    if not store_dir.exists():
        return []
    items: list[RetentionMetadata] = []
    for path in store_dir.glob("*.json"):
        if path.name.endswith(".tmp"):
            continue
        try:
            items.append(
                RetentionMetadata.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            )
        except Exception as e:
            logger.warning(
                "Skipping malformed retention file %s: %s", path, e
            )
            continue
    items.sort(key=lambda m: (m.classification, m.created_at))
    return items


def delete_retention(
    retention_id: str, *, override: Path | None = None
) -> bool:
    """Delete a retention metadata record. Returns True if removed."""
    _validate_id_shape(retention_id)
    store_dir = get_retention_store_dir(override)
    candidate = store_dir / f"{retention_id}.json"
    try:
        path = validate_within(candidate, store_dir)
    except PathTraversalError as e:
        raise InvalidRetentionIdError(
            f"Invalid retention ID: path-traversal violation: {retention_id!r}"
        ) from e
    if not path.exists():
        return False
    path.unlink()
    return True
