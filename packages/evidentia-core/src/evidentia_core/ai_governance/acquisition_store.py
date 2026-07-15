"""JSON file-backed AI acquisition store (v0.11 Wave 2).

Mirrors :mod:`evidentia_core.ai_governance.registry_store` (itself the
v0.7.9 vendor_store + v0.9.0 poam_store pattern):

- One JSON file per tracked acquisition, named
  ``<acquisition_id>.json`` where ``acquisition_id`` is the UUID v4
  stamp.
- Storage location precedence:
    1. Explicit ``override`` argument (CLI flag or test fixture)
    2. ``EVIDENTIA_AI_ACQUISITION_DIR`` environment variable
    3. Platform default via ``platformdirs.user_data_dir`` →
       ``ai_acquisitions/``

Path-traversal protection + UUID-shape validation match
registry_store exactly. Single-writer per record is the documented
mode; multi-writer deployments must serialize at the application
layer.

**Trust boundary**: the directory named by
``EVIDENTIA_AI_ACQUISITION_DIR`` is a **trusted boundary** — files
within are treated as authoritative records Evidentia itself wrote
(same posture, mitigations, and operator guidance as the AI registry:
UUID-shaped filenames only; Pydantic validation skips malformed files
with a logged warning; deploy ``chmod 0700`` + a dedicated service
user).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from uuid import UUID

from platformdirs import user_data_dir

from evidentia_core.ai_governance.omb_m_25_22 import AIAcquisition
from evidentia_core.models.common import utc_now
from evidentia_core.security.paths import validate_within

logger = logging.getLogger(__name__)

AI_ACQUISITION_ENV_VAR = "EVIDENTIA_AI_ACQUISITION_DIR"


class InvalidAcquisitionIdError(ValueError):
    """Raised when a candidate acquisition ID isn't a valid UUID string."""


def _validate_id_shape(acquisition_id: str) -> str:
    """Canonicalize an acquisition ID via :class:`UUID`."""
    try:
        return str(UUID(acquisition_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidAcquisitionIdError(
            f"Invalid acquisition ID format (expected UUID): "
            f"{acquisition_id!r}"
        ) from exc


def get_ai_acquisition_dir(override: Path | None = None) -> Path:
    """Resolve the acquisition-store directory.

    Precedence: override → env → platformdirs default.
    """
    if override is not None:
        return Path(override).expanduser().resolve()
    env = os.environ.get(AI_ACQUISITION_ENV_VAR)
    if env:
        return Path(env).expanduser().resolve()
    return Path(user_data_dir("evidentia", "Evidentia")) / "ai_acquisitions"


class AIAcquisitionStore:
    """CRUD over the JSON file-backed AI acquisition store.

    Operators pass an explicit ``store_dir`` for test isolation; omit
    it in production to use the platformdirs default.
    """

    def __init__(self, store_dir: Path | None = None) -> None:
        self._dir = get_ai_acquisition_dir(store_dir)

    @property
    def directory(self) -> Path:
        return self._dir

    def save(self, acquisition: AIAcquisition) -> Path:
        """Persist an acquisition atomically (write to temp + rename).

        Bumps ``updated_at`` to now() in-place on the supplied record.
        Returns the absolute path of the written file.
        """
        canonical = _validate_id_shape(str(acquisition.acquisition_id))
        # In-place timestamp bump — matches registry_store (model_copy
        # corrupts UUID-typed fields under use_enum_values).
        acquisition.updated_at = utc_now()
        self._dir.mkdir(parents=True, exist_ok=True)
        out_path = validate_within(self._dir / f"{canonical}.json", self._dir)
        tmp = out_path.with_suffix(".json.tmp")
        tmp.write_text(
            acquisition.model_dump_json(indent=2),
            encoding="utf-8",
        )
        os.replace(tmp, out_path)
        return out_path

    def load(self, acquisition_id: str) -> AIAcquisition | None:
        """Read a single record by ID; returns None for well-formed-but-
        unknown IDs. Raises :class:`InvalidAcquisitionIdError` on shape
        violations."""
        canonical = _validate_id_shape(str(acquisition_id))
        candidate = self._dir / f"{canonical}.json"
        path = validate_within(candidate, self._dir)
        if not path.is_file():
            return None
        return AIAcquisition.model_validate_json(
            path.read_text(encoding="utf-8")
        )

    def list_all(self) -> list[AIAcquisition]:
        """Return every record, sorted by ``created_at`` ascending.
        Skips files that fail validation (logged as warnings)."""
        if not self._dir.is_dir():
            return []
        records: list[AIAcquisition] = []
        for path in sorted(self._dir.glob("*.json")):
            try:
                records.append(
                    AIAcquisition.model_validate_json(
                        path.read_text(encoding="utf-8")
                    )
                )
            except Exception as exc:  # pragma: no cover — defensive
                logger.warning(
                    "Skipping malformed AI acquisition file %s: %s",
                    path,
                    exc,
                )
        records.sort(key=lambda a: a.created_at)
        return records

    def delete(self, acquisition_id: str) -> bool:
        """Remove a record. Returns True if a file was actually removed,
        False if the well-formed ID had no record."""
        canonical = _validate_id_shape(str(acquisition_id))
        candidate = self._dir / f"{canonical}.json"
        path = validate_within(candidate, self._dir)
        if not path.is_file():
            return False
        path.unlink()
        return True


__all__ = [
    "AI_ACQUISITION_ENV_VAR",
    "AIAcquisitionStore",
    "InvalidAcquisitionIdError",
    "get_ai_acquisition_dir",
]
