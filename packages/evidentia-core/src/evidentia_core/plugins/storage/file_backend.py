"""Filesystem-based StorageBackend reference implementation
(v0.8.0 P0.4).

The simplest possible storage backend — JSON files in a
directory. Path traversal is gated via the canonical
:func:`evidentia_core.security.paths.validate_within` helper.

This is intentionally a thin wrapper around the existing
in-tree store pattern (gap_store, vendor_store, etc.) so
out-of-tree authors can copy + modify it as a starting point
for custom backends (S3, IPFS, etc.).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from pydantic import BaseModel

from evidentia_core.plugins.storage._base import StorageBackend
from evidentia_core.security.paths import validate_within


class FilesystemStorageBackend[T: BaseModel](StorageBackend[T]):
    """Reference :class:`StorageBackend` implementation.

    Stores each record as ``<record_id>.json`` under a base
    directory. Path traversal is gated via the
    ``validate_within`` helper — record IDs that resolve outside
    the base directory raise :class:`ValueError`.

    Generic over a Pydantic model type ``T``. Records are
    serialized via ``model_dump_json()`` and deserialized via
    ``T.model_validate_json()``.

    Args:
        base_dir: The directory where records live.
        record_type: The Pydantic model class for type
            recovery on load.
    """

    # Record IDs allow alphanumeric + dash + underscore only.
    # Lowercase enforcement is implementation-defined; this
    # backend allows mixed case.
    _ID_VALID: ClassVar[frozenset[str]] = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")

    def __init__(
        self,
        *,
        base_dir: Path | str,
        record_type: type[T],
    ) -> None:
        self._base = Path(base_dir).expanduser().resolve()
        self._base.mkdir(parents=True, exist_ok=True)
        self._record_type = record_type

    def _validate_id(self, record_id: str) -> None:
        if not record_id:
            raise ValueError("record_id must be non-empty")
        if any(ch not in self._ID_VALID for ch in record_id):
            raise ValueError(
                f"record_id {record_id!r} contains invalid characters; allowed: alphanumeric + dash + underscore"
            )

    def _path_for(self, record_id: str) -> Path:
        self._validate_id(record_id)
        candidate = self._base / f"{record_id}.json"
        # Defense-in-depth: ensure the resolved path is within
        # the base directory. ID-validation above is the
        # primary guard; this catches any edge cases (symlinks,
        # etc.).
        return validate_within(candidate, self._base)

    def save(self, *, record_id: str, record: T) -> None:
        path = self._path_for(record_id)
        path.write_text(record.model_dump_json(indent=2), encoding="utf-8")

    def load(self, record_id: str) -> T:
        path = self._path_for(record_id)
        if not path.exists():
            raise KeyError(f"No record at {record_id!r}")
        try:
            return self._record_type.model_validate_json(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(f"Record {record_id!r} cannot be parsed as {self._record_type.__name__}: {e}") from e

    def list_records(self) -> Iterator[str]:
        for p in self._base.glob("*.json"):
            yield p.stem

    def delete(self, record_id: str) -> None:
        path = self._path_for(record_id)
        if not path.exists():
            raise KeyError(f"No record at {record_id!r}")
        path.unlink()

    def name(self) -> str:
        return "filesystem"
