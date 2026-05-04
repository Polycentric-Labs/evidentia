"""Persistent Model Risk Management inventory store (v0.7.10 P0.6.1).

Mirrors the v0.7.9 :mod:`evidentia_core.vendor_store` pattern adapted
for the :class:`evidentia_core.models.model_risk.ModelInventory` model:

- One JSON file per model, named ``<model_id>.json`` where
  ``model_id`` is the model's UUID-v4 string identifier (defined by
  :func:`evidentia_core.models.common.new_id`).
- Storage location follows the standard ``platformdirs``-backed
  precedence used elsewhere in the codebase:
    1. Explicit ``override`` argument (CLI flag or test fixture)
    2. ``EVIDENTIA_MODEL_STORE_DIR`` environment variable
    3. Platform default via ``platformdirs.user_data_dir`` —
       Windows: ``%APPDATA%\\Evidentia\\model_store\\``;
       macOS:   ``~/Library/Application Support/evidentia/model_store/``;
       Linux:   ``~/.local/share/evidentia/model_store/``.

CRUD surface (mirrors vendor_store):

  - :func:`save_model` — write or overwrite a single model record;
    refreshes ``model.updated_at`` to the current UTC time before
    persisting (the model's auto-stamping handles ``created_at``).
    Atomic ``os.replace`` save semantics.
  - :func:`load_model_by_id` — read a single model by ID; returns
    ``None`` for well-formed-but-unknown IDs;
    :class:`InvalidModelIdError` on shape violations.
  - :func:`list_models` — return every model in the store, sorted by
    ``(tier, name)`` for ergonomic CLI output (Tier 1 → Tier 3).
  - :func:`delete_model` — remove a model file; returns ``True`` if a
    record was actually removed, ``False`` if the well-formed ID had
    no record on disk.

Path-traversal protection mirrors vendor_store via
:func:`evidentia_core.security.paths.validate_within`. UUID-shape
gate rejects path-traversal segments / empty strings / raw integers
before the path resolver, belt-and-suspenders style.

This module ships in v0.7.10 P0.6.1 alongside the
:mod:`evidentia_core.models.model_risk` Pydantic models. The CLI
surface (P0.6 CLI work) and REST router (P0.6.5) build on top of
these primitives.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from uuid import UUID

from platformdirs import user_data_dir

from evidentia_core.models.common import utc_now
from evidentia_core.models.model_risk import ModelInventory, Tier
from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)

logger = logging.getLogger(__name__)

MODEL_STORE_ENV_VAR = "EVIDENTIA_MODEL_STORE_DIR"


class InvalidModelIdError(ValueError):
    """Raised when a candidate model ID isn't a valid UUID-v4 string.

    Subclasses :class:`ValueError` so existing ``except ValueError``
    handlers continue to work.
    """


def _validate_id_shape(model_id: str) -> None:
    """Reject IDs that aren't a canonical UUID string.

    Accepts any UUID variant (v1/v3/v4/v5) — the v0.7.10 P0.6.1
    ModelInventory model stamps v4 via :func:`new_id`, but any
    record imported from an external system might carry a different
    variant, and that's fine. What we reject is anything that isn't
    UUID-shaped at all (path-traversal segments, empty strings, raw
    integers, etc.) so the resolved file path can never escape the
    store directory.
    """
    try:
        UUID(model_id)
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidModelIdError(
            f"Invalid model ID format (expected UUID string): {model_id!r}"
        ) from exc


def get_model_store_dir(override: Path | None = None) -> Path:
    """Resolve the model-risk store directory.

    Precedence:
      1. Explicit ``override`` argument (CLI flag or test fixture)
      2. ``EVIDENTIA_MODEL_STORE_DIR`` environment variable
      3. Platform default via ``platformdirs.user_data_dir``
    """
    if override is not None:
        return Path(override).expanduser().resolve()
    env = os.environ.get(MODEL_STORE_ENV_VAR)
    if env:
        return Path(env).expanduser().resolve()
    return Path(user_data_dir("evidentia", "Evidentia")) / "model_store"


def save_model(
    model: ModelInventory,
    model_store_dir: Path | None = None,
) -> Path:
    """Persist a model record to the user-dir store atomically.

    Refreshes ``model.updated_at`` to the current UTC time before
    writing. Returns the absolute path of the written JSON file.
    The file is a plain ``model_dump_json(indent=2)`` of the model
    record — no special framing, so an operator can edit it by hand
    if needed (and reload via :func:`load_model_by_id`).

    Atomic-write semantics (mirrors v0.7.9 P0.1 vendor_store M-1
    fix): writes to ``<id>.json.tmp`` first then ``os.replace`` to
    the canonical name. ``os.replace`` is atomic on both POSIX and
    Windows per the Python docs. A crash mid-write leaves either
    the prior valid JSON intact OR the new valid JSON in place —
    never a half-written file that :func:`list_models` would have
    to silently skip.
    """
    _validate_id_shape(model.id)
    store = get_model_store_dir(model_store_dir)
    store.mkdir(parents=True, exist_ok=True)

    model.updated_at = utc_now()
    out_path = store / f"{model.id}.json"
    tmp_path = store / f"{model.id}.json.tmp"
    tmp_path.write_text(model.model_dump_json(indent=2), encoding="utf-8")
    os.replace(tmp_path, out_path)
    logger.debug("Saved model record (atomic): %s", out_path)
    return out_path


def load_model_by_id(
    model_id: str,
    model_store_dir: Path | None = None,
) -> ModelInventory | None:
    """Load a saved model by its UUID.

    Validates the ID shape and confirms the resolved path lies
    within the store directory before reading. Returns ``None`` if
    the well-formed ID does not correspond to a stored record.
    Raises :class:`InvalidModelIdError` on shape violation and
    :class:`evidentia_core.security.paths.PathTraversalError` on
    resolved-path violation (which the shape check should already
    have rejected — the path check is belt-and-suspenders).
    """
    _validate_id_shape(model_id)
    store = get_model_store_dir(model_store_dir)
    candidate = store / f"{model_id}.json"
    path = validate_within(candidate, store)
    if not path.is_file():
        return None
    return ModelInventory.model_validate_json(path.read_text(encoding="utf-8"))


# Numeric ranks used to order Tier values in :func:`list_models`.
# Lower number = "more important" — Tier 1 first, then Tier 2, Tier 3.
_TIER_RANK = {
    Tier.TIER_1.value: 0,
    Tier.TIER_2.value: 1,
    Tier.TIER_3.value: 2,
}


def list_models(
    model_store_dir: Path | None = None,
) -> list[ModelInventory]:
    """Return every model in the store, sorted (tier, name).

    Sort key:
      1. Tier rank (Tier 1 → Tier 2 → Tier 3)
      2. Name (case-insensitive)

    This is the canonical ordering for CLI output and the default
    REST listing. Empty list if the store directory doesn't exist
    or contains no records.
    """
    store = get_model_store_dir(model_store_dir)
    if not store.exists():
        return []
    models: list[ModelInventory] = []
    for path in store.glob("*.json"):
        try:
            models.append(
                ModelInventory.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            )
        except Exception as exc:  # pragma: no cover — defensive
            # A malformed file shouldn't crash the listing of
            # well-formed records. Log + skip. Operators can spot it
            # via the warning + manually inspect.
            logger.warning(
                "Skipping malformed model record %s: %s", path, exc
            )
    models.sort(
        key=lambda m: (_TIER_RANK.get(m.tier, 99), m.name.lower())
    )
    return models


def delete_model(
    model_id: str,
    model_store_dir: Path | None = None,
) -> bool:
    """Delete a model record by ID.

    Returns ``True`` if a file was actually removed, ``False`` if
    the well-formed ID had no file on disk. Raises
    :class:`InvalidModelIdError` on shape violation.
    """
    _validate_id_shape(model_id)
    store = get_model_store_dir(model_store_dir)
    candidate = store / f"{model_id}.json"
    path = validate_within(candidate, store)
    if not path.is_file():
        return False
    path.unlink()
    logger.debug("Deleted model record: %s", path)
    return True


__all__ = [
    "MODEL_STORE_ENV_VAR",
    "InvalidModelIdError",
    "PathTraversalError",
    "delete_model",
    "get_model_store_dir",
    "list_models",
    "load_model_by_id",
    "save_model",
]
