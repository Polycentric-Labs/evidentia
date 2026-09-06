"""Persistent Plan-of-Action-and-Milestones (POA&M) store (v0.9.0 P1).

Mirrors the v0.7.9 P0.1.2 :mod:`evidentia_core.vendor_store` pattern
adapted for tracked POA&M items. Each POA&M item is a
:class:`evidentia_core.models.gap.ControlGap` record — the gap is
"promoted" from a one-off finding into a tracked remediation entry by
landing in this store + accumulating
:class:`evidentia_core.models.gap.Milestone` records on its
``poam_milestones`` field over time.

Storage layout:

- One JSON file per POA&M item, named ``<gap_id>.json`` where
  ``gap_id`` is the ``ControlGap.id`` UUID stamp (UUID v4 by default
  via :func:`evidentia_core.models.common.new_id`; UUID v1/v3/v5 also
  accepted for records imported from external systems).
- Storage location follows the standard ``platformdirs``-backed
  precedence used elsewhere in the codebase:
    1. Explicit ``override`` argument (CLI flag or test fixture)
    2. ``EVIDENTIA_POAM_STORE_DIR`` environment variable
    3. Platform default via ``platformdirs.user_data_dir`` —
       Windows: ``%APPDATA%\\Evidentia\\poam_store\\``;
       macOS:   ``~/Library/Application Support/evidentia/poam_store/``;
       Linux:   ``~/.local/share/evidentia/poam_store/``.

CRUD surface:

  - :func:`save_poam` — write or overwrite a single POA&M record;
    refreshes any stale ``Milestone.updated_at`` on milestones whose
    state changed vs the on-disk version
  - :func:`load_poam_by_id` — read a single POA&M by ID; returns
    ``None`` for well-formed-but-unknown IDs;
    :class:`InvalidPoamIdError` on shape violations
  - :func:`list_poams` — return every POA&M in the store, sorted by
    ``(gap_severity, target_date_of_next_open_milestone, control_id)``
    for ergonomic CLI output (high severity + earliest deadline first)
  - :func:`delete_poam` — remove a POA&M file; returns ``True`` if a
    record was actually removed, ``False`` if the well-formed ID had
    no record on disk

Operational constraints:

- **Single-writer per record**: Concurrent ``save_poam`` calls on
  the same ``poam.id`` last-writer-wins via ``os.replace``. The
  read-modify-write step inside ``save_poam`` (parse prior file →
  refresh stale ``Milestone.updated_at`` → write) is NOT
  serialized; multi-writer deployments must serialize at the
  application layer (e.g., the API server's request handler) OR
  accept that interleaved writes may produce non-deterministic
  ``updated_at`` refreshes. Single-writer is the documented mode
  and matches the v0.7.9 vendor_store invariant.
- **Indicative scale ceiling**: tested cleanly through O(10^3)
  POA&M items. For larger registers, consider migrating to a
  SQLite-backed store via the v0.8.0 P0.4 ``StorageBackend``
  plugin contract. ``list_poams`` reads every JSON file on every
  call (no caching layer); at scale this becomes the hot path.

Path-traversal protection mirrors gap_store + vendor_store via
:func:`evidentia_core.security.paths.validate_within`. The shape
check on the ID rejects anything that isn't a canonical UUID hex
form, so a malicious ``../../etc`` input fails the shape gate before
reaching the path resolver. Belt-and-suspenders.

This module ships in v0.9.0 P1; the CLI surface (P2) and REST router
(P2) build on top of these primitives.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from uuid import UUID

from platformdirs import user_data_dir

from evidentia_core.models.common import utc_now
from evidentia_core.models.gap import ControlGap, GapSeverity, POAMState
from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)

logger = logging.getLogger(__name__)

POAM_STORE_ENV_VAR = "EVIDENTIA_POAM_STORE_DIR"


class InvalidPoamIdError(ValueError):
    """Raised when a candidate POA&M ID isn't a valid UUID string.

    Subclasses :class:`ValueError` so existing ``except ValueError``
    handlers continue to work.
    """


def _validate_id_shape(poam_id: str) -> str:
    """Validate a candidate POA&M ID and return its canonical form.

    Accepts any UUID variant (v1/v3/v4/v5) — :func:`new_id` stamps
    v4 by default, but a record imported from an external POA&M
    system might carry a different variant, and that's fine. What
    we reject is anything that isn't UUID-shaped at all (path-
    traversal segments, empty strings, raw integers, etc.) so the
    resolved file path can never escape the store directory.

    **Canonicalization (v0.9.0 P5 F-V90-15)**: Python's :class:`UUID`
    parser accepts four lexical forms of the same semantic UUID:
    canonical hyphenated, brace-wrapped ``{...}``, URN-prefixed
    ``urn:uuid:...``, and hex-without-hyphens (32-char). Without
    canonicalization, the same logical UUID can produce distinct
    filenames in the store + non-conformant OSCAL ``uuid`` emit.
    This function returns ``str(UUID(poam_id))`` — the canonical
    lowercase hyphenated form. Callers MUST use the returned value
    for filename composition + persisted-id rewriting, not the raw
    input string.
    """
    try:
        return str(UUID(poam_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidPoamIdError(f"Invalid POA&M ID format (expected UUID string): {poam_id!r}") from exc


def get_poam_store_dir(
    override: Path | None = None,
    *,
    tenant: str | None = None,
) -> Path:
    """Resolve the POA&M store directory.

    Precedence (for the base path):
      1. Explicit ``override`` argument (CLI flag or test fixture)
      2. ``EVIDENTIA_POAM_STORE_DIR`` environment variable
      3. Platform default via ``platformdirs.user_data_dir``

    v0.9.8 P1.6: when ``tenant`` is supplied, the resolved base is
    extended with ``tenants/<tenant>/`` so multi-tenant deployments
    keep each tenant's POA&M items physically isolated on disk.
    Mirrors the :func:`evidentia_core.evidence_store.get_evidence_store_dir`
    pattern. The tenant id is validated via
    :func:`evidentia_core.rbac.validate_tenant_id`; invalid ids raise
    :class:`InvalidTenantIdError`.

    The single-tenant call (``tenant=None``) preserves the v0.9.7
    layout — operators with single-tenant deployments see ZERO
    behavior change.

    Args:
        override: Optional explicit path that wins over env vars.
        tenant: Optional tenant id. When supplied, appended as
            ``tenants/<tenant>/`` to the resolved base.

    Returns:
        The resolved store-root path.

    Raises:
        InvalidTenantIdError: When ``tenant`` is non-None but fails
            the slug-format check.
    """
    if override is not None:
        base = Path(override).expanduser().resolve()
    else:
        env = os.environ.get(POAM_STORE_ENV_VAR)
        base = Path(env).expanduser().resolve() if env else Path(user_data_dir("evidentia", "Evidentia")) / "poam_store"
    if tenant is None:
        return base
    from evidentia_core.rbac import validate_tenant_id

    return base / "tenants" / validate_tenant_id(tenant)


def save_poam(
    poam: ControlGap,
    poam_store_dir: Path | None = None,
) -> Path:
    """Persist a POA&M record to the user-dir store atomically.

    Refreshes ``Milestone.updated_at`` for each milestone whose
    state differs from the on-disk version (if any). Returns the
    absolute path of the written JSON file. The file is a plain
    ``model_dump_json(indent=2)`` of the ControlGap — no special
    framing, so an operator can edit it by hand if needed (and
    reload via :func:`load_poam_by_id`).

    Atomic-write semantics (mirrors vendor_store v0.7.9 P0.1
    Continuous-review M-1): writes to ``<id>.json.tmp`` first then
    ``os.replace`` to the canonical name. ``os.replace`` is atomic
    on both POSIX and Windows per the Python docs. A crash mid-
    write leaves either the prior valid JSON intact OR the new
    valid JSON in place — never a half-written file that
    :func:`list_poams` would have to silently skip.
    """
    # Canonicalize before path composition + rewrite poam.id so
    # the persisted record, OSCAL emit, and audit-event payloads
    # all agree on the canonical lowercase hyphenated form
    # (v0.9.0 P5 F-V90-15). Concurrent-save invariant: this store
    # is single-writer per record; multi-writer deployments must
    # serialize at the application layer.
    canonical_id = _validate_id_shape(poam.id)
    if poam.id != canonical_id:
        poam.id = canonical_id
    store = get_poam_store_dir(poam_store_dir)
    store.mkdir(parents=True, exist_ok=True)

    # Refresh milestone timestamps for any whose state changed vs
    # the on-disk version. A milestone that was edited (status
    # transition) gets a fresh updated_at; one that's unchanged
    # keeps its prior timestamp. This is opportunistic — if there's
    # no on-disk version, we don't refresh (the milestone's
    # default_factory already stamped utc_now at construction).
    candidate = store / f"{canonical_id}.json"
    out_path = validate_within(candidate, store)
    if out_path.is_file():
        try:
            prior = ControlGap.model_validate_json(out_path.read_text(encoding="utf-8"))
            prior_by_id = {m.id: m for m in prior.poam_milestones}
            for milestone in poam.poam_milestones:
                prior_m = prior_by_id.get(milestone.id)
                if prior_m is not None and prior_m.status != milestone.status:
                    milestone.updated_at = utc_now()
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning(
                "Could not parse prior POA&M record for milestone-timestamp refresh: %s",
                exc,
            )

    tmp_path = store / f"{canonical_id}.json.tmp"
    tmp_path.write_text(poam.model_dump_json(indent=2), encoding="utf-8")
    os.replace(tmp_path, out_path)
    logger.debug("Saved POA&M record (atomic): %s", out_path)
    return out_path


def load_poam_by_id(
    poam_id: str,
    poam_store_dir: Path | None = None,
) -> ControlGap | None:
    """Load a saved POA&M by its UUID.

    Validates the ID shape and confirms the resolved path lies
    within the store directory before reading. Returns ``None`` if
    the well-formed ID does not correspond to a stored record.
    Raises :class:`InvalidPoamIdError` on shape violation and
    :class:`evidentia_core.security.paths.PathTraversalError` on
    resolved-path violation (which the shape check should already
    have rejected — the path check is belt-and-suspenders).
    """
    canonical_id = _validate_id_shape(poam_id)
    store = get_poam_store_dir(poam_store_dir)
    candidate = store / f"{canonical_id}.json"
    path = validate_within(candidate, store)
    if not path.is_file():
        return None
    return ControlGap.model_validate_json(path.read_text(encoding="utf-8"))


# Numeric ranks used to order GapSeverity values in
# :func:`list_poams`. Lower number = "more important" — critical
# first, then high, medium, low, informational. Defined as a
# module constant so the order is stable across Python sessions.
_SEVERITY_RANK = {
    GapSeverity.CRITICAL.value: 0,
    GapSeverity.HIGH.value: 1,
    GapSeverity.MEDIUM.value: 2,
    GapSeverity.LOW.value: 3,
    GapSeverity.INFORMATIONAL.value: 4,
}


def _next_open_milestone_date(poam: ControlGap) -> tuple[int, str]:
    """Return a sort key for the earliest open milestone's date.

    Returns ``(0, iso_date)`` if at least one milestone is open
    (PLANNED, IN_PROGRESS, or OVERDUE), where ``iso_date`` is the
    earliest such milestone's ``target_date.isoformat()``. Returns
    ``(1, "")`` if all milestones are closed (COMPLETED or
    VERIFIED) OR if the POA&M has no milestones at all — those go
    AFTER POA&Ms with open work in the canonical sort.
    """
    open_states = {
        POAMState.PLANNED.value,
        POAMState.IN_PROGRESS.value,
        POAMState.OVERDUE.value,
    }
    open_dates = [m.target_date.isoformat() for m in poam.poam_milestones if m.status in open_states]
    if open_dates:
        return (0, min(open_dates))
    return (1, "")


def list_poams(
    poam_store_dir: Path | None = None,
) -> list[ControlGap]:
    """Return every POA&M in the store, sorted by canonical order.

    Sort key:
      1. Gap severity rank (critical → high → medium → low → info)
      2. Has-open-milestones flag (POA&Ms with open work first)
      3. Earliest-open-milestone target date (ascending)
      4. Control ID (lexicographic)

    This is the canonical ordering for CLI output and the default
    REST listing. Empty list if the store directory doesn't exist
    or contains no records.
    """
    store = get_poam_store_dir(poam_store_dir)
    if not store.exists():
        return []
    poams: list[ControlGap] = []
    for path in store.glob("*.json"):
        try:
            poams.append(ControlGap.model_validate_json(path.read_text(encoding="utf-8")))
        except Exception as exc:  # pragma: no cover — defensive
            # A malformed file in the store shouldn't crash the
            # listing of all the well-formed records. Log + skip.
            # Operators can spot it via the warning + manually
            # inspect.
            logger.warning("Skipping malformed POA&M record %s: %s", path, exc)

    def _sort_key(poam: ControlGap) -> tuple[int, int, str, str]:
        severity_rank = _SEVERITY_RANK.get(poam.gap_severity, 99)
        open_flag, next_date = _next_open_milestone_date(poam)
        return (severity_rank, open_flag, next_date, poam.control_id)

    poams.sort(key=_sort_key)
    return poams


def delete_poam(
    poam_id: str,
    poam_store_dir: Path | None = None,
) -> bool:
    """Delete a POA&M record by ID.

    Returns ``True`` if a file was actually removed, ``False`` if
    the well-formed ID had no file on disk. Raises
    :class:`InvalidPoamIdError` on shape violation.
    """
    canonical_id = _validate_id_shape(poam_id)
    store = get_poam_store_dir(poam_store_dir)
    candidate = store / f"{canonical_id}.json"
    path = validate_within(candidate, store)
    if not path.is_file():
        return False
    path.unlink()
    logger.debug("Deleted POA&M record: %s", path)
    return True


__all__ = [
    "POAM_STORE_ENV_VAR",
    "InvalidPoamIdError",
    "PathTraversalError",
    "delete_poam",
    "get_poam_store_dir",
    "list_poams",
    "load_poam_by_id",
    "save_poam",
]
