"""JSON file-backed AI system registry store (v0.9.3 P2.4).

Mirrors the v0.7.9 vendor_store + v0.9.0 poam_store pattern:

- One JSON file per registered AI system, named
  ``<system_id>.json`` where ``system_id`` is the UUID v4 stamp.
- Storage location precedence:
    1. Explicit ``override`` argument (CLI flag or test fixture)
    2. ``EVIDENTIA_AI_REGISTRY_DIR`` environment variable
    3. Platform default via ``platformdirs.user_data_dir`` →
       ``ai_registry/``

Path-traversal protection + UUID-shape validation match
poam_store exactly. Single-writer per record is the documented
mode; multi-writer deployments must serialize at the application
layer.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from uuid import UUID

from platformdirs import user_data_dir

from evidentia_core.ai_governance.registry import AISystemRegistryEntry
from evidentia_core.models.common import utc_now
from evidentia_core.security.paths import validate_within

logger = logging.getLogger(__name__)

AI_REGISTRY_ENV_VAR = "EVIDENTIA_AI_REGISTRY_DIR"


class InvalidAISystemIdError(ValueError):
    """Raised when a candidate system ID isn't a valid UUID string."""


def _validate_id_shape(system_id: str) -> str:
    """Canonicalize an AI system ID via :class:`UUID`. Mirrors
    poam_store + vendor_store invariants."""
    try:
        return str(UUID(system_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidAISystemIdError(
            f"Invalid AI system ID format (expected UUID): {system_id!r}"
        ) from exc


def get_ai_registry_dir(override: Path | None = None) -> Path:
    """Resolve the AI registry directory.

    Precedence: override → env → platformdirs default.
    """
    if override is not None:
        return Path(override).expanduser().resolve()
    env = os.environ.get(AI_REGISTRY_ENV_VAR)
    if env:
        return Path(env).expanduser().resolve()
    return Path(user_data_dir("evidentia", "Evidentia")) / "ai_registry"


class AIRegistryStore:
    """CRUD over the JSON file-backed AI system registry.

    Operators pass an explicit ``registry_dir`` for test isolation;
    omit it in production to use the platformdirs default.
    """

    def __init__(self, registry_dir: Path | None = None) -> None:
        self._dir = get_ai_registry_dir(registry_dir)

    @property
    def directory(self) -> Path:
        return self._dir

    def save(self, entry: AISystemRegistryEntry) -> Path:
        """Persist a registry entry atomically (write to temp + rename).

        Bumps ``updated_at`` to now() in-place on the supplied entry.
        Returns the absolute path of the written file.
        """
        canonical = _validate_id_shape(str(entry.system_id))
        # Bump updated_at in-place. EvidentiaModel is mutable; this
        # matches the v0.9.0 poam_store + v0.7.9 vendor_store
        # convention where the input entry's timestamp reflects the
        # last save. Avoid model_copy here — it corrupts the UUID
        # type when use_enum_values=True is set on the base model.
        entry.updated_at = utc_now()
        self._dir.mkdir(parents=True, exist_ok=True)
        out_path = validate_within(
            self._dir / f"{canonical}.json", self._dir
        )
        tmp = out_path.with_suffix(".json.tmp")
        tmp.write_text(
            entry.model_dump_json(indent=2),
            encoding="utf-8",
        )
        os.replace(tmp, out_path)
        return out_path

    def load(self, system_id: str) -> AISystemRegistryEntry | None:
        """Read a single entry by system ID; returns None for
        well-formed-but-unknown IDs. Raises
        :class:`InvalidAISystemIdError` on shape violations."""
        canonical = _validate_id_shape(str(system_id))
        candidate = self._dir / f"{canonical}.json"
        path = validate_within(candidate, self._dir)
        if not path.is_file():
            return None
        return AISystemRegistryEntry.model_validate_json(
            path.read_text(encoding="utf-8")
        )

    def list_all(self) -> list[AISystemRegistryEntry]:
        """Return every entry in the store, sorted by ``created_at``
        ascending (oldest first). Skips files that fail validation
        (logged as warnings)."""
        if not self._dir.is_dir():
            return []
        entries: list[AISystemRegistryEntry] = []
        for path in sorted(self._dir.glob("*.json")):
            try:
                entries.append(
                    AISystemRegistryEntry.model_validate_json(
                        path.read_text(encoding="utf-8")
                    )
                )
            except Exception as exc:  # pragma: no cover — defensive
                logger.warning(
                    "Skipping malformed AI registry file %s: %s",
                    path,
                    exc,
                )
        entries.sort(key=lambda e: e.created_at)
        return entries

    def delete(self, system_id: str) -> bool:
        """Remove an entry. Returns True if a file was actually
        removed, False if the well-formed ID had no record."""
        canonical = _validate_id_shape(str(system_id))
        candidate = self._dir / f"{canonical}.json"
        path = validate_within(candidate, self._dir)
        if not path.is_file():
            return False
        path.unlink()
        return True


def get_default_registry_store() -> AIRegistryStore:
    """Factory for the env/platformdirs-resolved registry store."""
    return AIRegistryStore()
