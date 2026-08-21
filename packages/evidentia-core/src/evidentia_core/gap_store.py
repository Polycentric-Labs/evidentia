"""Persistent gap report store.

v0.2.1 introduces this module so `evidentia risk generate --gap-id GAP-…`
can resolve a single gap without re-running full gap analysis or needing
the user to pass `--gaps`. Every `gap analyze` run writes its report to a
user-dir directory; `risk generate` looks up the most recent report by
modification time and filters to the requested gap ID.

Location follows the same ``platformdirs``-backed convention as the user
catalog directory (``evidentia_core.catalogs.user_dir``):

- Windows:  ``%APPDATA%\\Evidentia\\gap_store\\``
- macOS:    ``~/Library/Application Support/evidentia/gap_store/``
- Linux:    ``~/.local/share/evidentia/gap_store/``

Override with the ``EVIDENTIA_GAP_STORE_DIR`` environment variable
or a ``gap_store_dir`` argument to ``save_report`` / ``load_latest_report``.

File naming: ``<sha256-16hex>.json``, where the hash is computed from
``(inventory_source_file or organization) + '|' + sorted_frameworks_csv``.
This lets multiple concurrent projects coexist (different inventories +
frameworks produce different hashes) while still letting `risk generate`
pick the newest matching report.
"""

from __future__ import annotations

import hashlib
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from platformdirs import user_data_dir

from evidentia_core.models.gap import GapAnalysisReport
from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)

logger = logging.getLogger(__name__)

GAP_STORE_ENV_VAR = "EVIDENTIA_GAP_STORE_DIR"

REPORT_KEY_HEX_CHARS = frozenset("0123456789abcdef")
REPORT_KEY_LENGTH = 16


class InvalidReportKeyError(ValueError):
    """Raised when a candidate report key fails the shape check.

    Subclasses :class:`ValueError` so existing ``except ValueError``
    handlers continue to work.
    """


class GapStoreRootChangedError(RuntimeError):
    """Raised when operation-time validation returns a different root."""


@dataclass(frozen=True, slots=True)
class GapReportRepository:
    """Root-bound access to persisted gap reports.

    ``root`` is mandatory and resolved once at construction, so later
    environment changes cannot redirect repository operations. Callers with
    stronger path-identity requirements may supply ``root_revalidator``; it is
    invoked immediately before every store operation and must return the same
    canonical root.
    """

    root: Path
    root_revalidator: Callable[[], Path] | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if self.root is None:
            raise TypeError("GapReportRepository requires an explicit root.")
        object.__setattr__(self, "root", get_gap_store_dir(self.root))

    def _operation_root(self) -> Path:
        if self.root_revalidator is None:
            return self.root
        candidate = self.root_revalidator()
        if candidate is None:
            raise GapStoreRootChangedError(
                "Gap report repository root changed during operation-time "
                "revalidation."
            )
        revalidated = get_gap_store_dir(candidate)
        if revalidated != self.root:
            raise GapStoreRootChangedError(
                "Gap report repository root changed during operation-time "
                "revalidation."
            )
        return self.root

    def save(self, report: GapAnalysisReport) -> Path:
        """Persist ``report`` beneath this repository's explicit root."""
        return save_report(report, gap_store_dir=self._operation_root())

    def load_latest(self) -> GapAnalysisReport | None:
        """Load the newest report beneath this repository's explicit root."""
        return load_latest_report(gap_store_dir=self._operation_root())

    def list(self) -> list[Path]:
        """List report paths beneath this repository's explicit root."""
        return list_reports(gap_store_dir=self._operation_root())

    def load_by_key(self, key: str) -> GapAnalysisReport | None:
        """Load ``key`` beneath this repository's explicit root."""
        _validate_key_shape(key)
        return load_report_by_key(
            key,
            gap_store_dir=self._operation_root(),
        )


def _validate_key_shape(key: str) -> None:
    """Reject keys that don't match the ``sha256-16hex`` format.

    The shape is ``[0-9a-f]{16}`` — same as the output of
    :func:`_compute_key`. Anything else (length mismatch, uppercase
    letters, non-hex characters, ``..`` segments, path separators)
    raises :class:`InvalidReportKeyError`.
    """
    if len(key) != REPORT_KEY_LENGTH or not all(
        c in REPORT_KEY_HEX_CHARS for c in key
    ):
        raise InvalidReportKeyError(
            "Invalid report key format (expected 16 hex characters)."
        )


def get_gap_store_dir(override: Path | None = None) -> Path:
    """Resolve the gap store directory.

    Precedence (matching catalogs/user_dir.get_user_catalog_dir):
      1. Explicit ``override`` argument (CLI flag or test fixture)
      2. ``EVIDENTIA_GAP_STORE_DIR`` environment variable
      3. Platform default via ``platformdirs.user_data_dir``
    """
    if override is not None:
        return Path(override).expanduser().resolve()
    env = os.environ.get(GAP_STORE_ENV_VAR)
    if env:
        return Path(env).expanduser().resolve()
    return Path(user_data_dir("evidentia", "Evidentia")) / "gap_store"


def _compute_key(
    inventory_source: str | None, organization: str, frameworks: list[str]
) -> str:
    """Compute a stable 16-hex-char key for a (inventory, frameworks) pair.

    Uses ``inventory_source`` (absolute file path) when available since
    that's the most-specific identifier a user can have. Falls back to
    ``organization`` for in-memory inventories with no source file.
    """
    basis = inventory_source or organization
    seed = f"{basis}|{'|'.join(sorted(frameworks))}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def save_report(
    report: GapAnalysisReport,
    gap_store_dir: Path | None = None,
) -> Path:
    """Persist a gap report to the user-dir store.

    Returns the absolute path of the written JSON. The file is a plain
    ``model_dump_json(indent=2)`` of the report — no special framing, so
    the same file can be used directly with ``evidentia risk generate
    --gaps <path>``.
    """
    store = get_gap_store_dir(gap_store_dir)
    store.mkdir(parents=True, exist_ok=True)

    key = _compute_key(
        report.inventory_source,
        report.organization,
        report.frameworks_analyzed,
    )
    out_path = store / f"{key}.json"
    out_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    logger.debug("Saved gap report: %s", out_path)
    return out_path


def load_latest_report(
    gap_store_dir: Path | None = None,
) -> GapAnalysisReport | None:
    """Return the most recent saved report by mtime, or None if empty.

    Callers should treat None as "no prior `gap analyze` run exists" and
    guide the user to run one first.
    """
    store = get_gap_store_dir(gap_store_dir)
    if not store.exists():
        return None

    reports = sorted(store.glob("*.json"), key=lambda p: p.stat().st_mtime)
    if not reports:
        return None

    latest = reports[-1]
    logger.debug("Loading latest gap report: %s", latest)
    return GapAnalysisReport.model_validate_json(
        latest.read_text(encoding="utf-8")
    )


def list_reports(
    gap_store_dir: Path | None = None,
) -> list[Path]:
    """Return all stored report paths sorted newest-first."""
    store = get_gap_store_dir(gap_store_dir)
    if not store.exists():
        return []
    return sorted(store.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)


def load_report_by_key(
    key: str,
    gap_store_dir: Path | None = None,
) -> GapAnalysisReport | None:
    """Load a saved gap report by its 16-hex-char key.

    Validates the key shape and confirms the resolved path lies within
    the store directory before reading. Returns ``None`` if the
    well-formed key does not correspond to a stored report. Raises
    :class:`InvalidReportKeyError` on shape violation and
    :class:`evidentia_core.security.paths.PathTraversalError` on
    resolved-path violation (which the shape check should already have
    rejected — the path check is belt-and-suspenders).

    API + CLI callers wrap the two error types with their own
    user-facing 4xx / non-zero-exit translation.
    """
    _validate_key_shape(key)
    store = get_gap_store_dir(gap_store_dir)
    candidate = store / f"{key}.json"
    path = validate_within(candidate, store)
    if not path.is_file():
        return None
    return GapAnalysisReport.model_validate_json(
        path.read_text(encoding="utf-8")
    )


__all__ = [
    "GAP_STORE_ENV_VAR",
    "GapReportRepository",
    "GapStoreRootChangedError",
    "InvalidReportKeyError",
    "PathTraversalError",
    "get_gap_store_dir",
    "list_reports",
    "load_latest_report",
    "load_report_by_key",
    "save_report",
]
