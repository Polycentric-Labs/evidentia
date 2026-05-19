"""Append-only evidence-artifact store (v0.9.6 P2).

Closes the v0.9.5 P3.2 deferral: the v0.9.5 cycle shipped the
:class:`EvidenceArtifact.version` / ``lineage_id`` / ``predecessor_id``
data model + :meth:`EvidenceArtifact.new_version` helper but
delegated WORM (Write-Once-Read-Many) store-side enforcement to
v0.9.6. This module ships the enforcement layer.

Storage layout: one directory per lineage chain, one JSON file
per version within the chain::

    <store_root>/
      <lineage_id_A>/
        v1.json
        v2.json
        v3.json
      <lineage_id_B>/
        v1.json

The layout serves three properties simultaneously:

1. **Versions are discoverable by directory listing** — operators
   can ``ls`` the lineage directory and see the chain length
   without reading any JSON.
2. **Append-only enforcement is per-file** — :func:`save_evidence`
   refuses to write ``v<N>.json`` if it already exists. The
   :meth:`EvidenceArtifact.new_version` helper produces v<N+1>
   so a normal-path "edit" is automatically a fresh file.
3. **The directory IS the lineage** — there's no separate
   manifest file to keep in sync. The directory's existence
   implies the lineage exists; the largest version present is
   the chain head.

Path resolution mirrors :mod:`evidentia_core.poam_store`:

  1. Explicit ``override`` argument (CLI flag or test fixture)
  2. ``EVIDENTIA_EVIDENCE_STORE_DIR`` environment variable
  3. ``platformdirs.user_data_dir("evidentia") / "evidence_store"``

UUID-shape validation + ``validate_within`` path-traversal protection
mirror the v0.9.0 poam_store + v0.7.9 vendor_store pattern.

**Backward-compat with v0.9.5 artifacts**: artifacts saved before
v0.9.6 (pre-WORM) live under the legacy single-file
``<store>/<id>.json`` layout. This store does NOT migrate them
automatically; operators can re-save legacy artifacts via the
``v1`` path or simply leave them as historical records. The
v0.9.6 CLI verbs (``evidence save / history / show``) operate
solely on the new lineage-directory layout.

**Threat-model boundary**: WORM enforcement here is *application-
layer*. A privileged operator can delete the JSON files via OS
tools. For regulator-grade WORM (hardware enforcement), operators
ALSO wire :mod:`evidentia_core.evidence_store_worm` against a
cloud-WORM backend (S3 Object Lock / Azure Immutable Blob / GCS
Bucket Lock).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from uuid import UUID

from platformdirs import user_data_dir

from evidentia_core.models.evidence import EvidenceArtifact
from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)

logger = logging.getLogger(__name__)

EVIDENCE_STORE_ENV_VAR = "EVIDENTIA_EVIDENCE_STORE_DIR"
EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR = "EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM"
"""v0.9.7 P1.1: closes F-V96-worm-app-layer. When set to a
non-empty value, :func:`save_evidence` calls
:func:`evidentia_core.evidence_store_worm.mirror_to_worm` AFTER
the local-store write succeeds. The mirror backend is provided
by the caller via a dotted-path module reference (e.g.,
``my_project.worm_backend:make_backend``) — see
:func:`_resolve_auto_mirror_backend` for the import + retention-
metadata resolution. Default unset → no auto-mirror (preserves
v0.9.6 behavior).
"""

EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR = "EVIDENTIA_EVIDENCE_WORM_BACKEND_FACTORY"
"""v0.9.7 P1.1: dotted-path reference to a callable returning a
``(backend, retention_metadata)`` tuple. Format:
``module.submodule:callable_name``. Required when
:data:`EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR` is set; otherwise the
auto-mirror raises a configuration error at first save.

The callable signature::

    def make_backend() -> tuple[WORMBackend, RetentionMetadata]: ...

Operators wire this to their site-specific cloud-WORM backend +
the retention policy classification appropriate for their
evidence (SOX 7yr / HIPAA 6yr / FedRAMP 5yr / etc.).
"""


class InvalidEvidenceIdError(ValueError):
    """Raised when a candidate evidence/lineage ID isn't a valid UUID.

    Subclasses :class:`ValueError` so existing ``except ValueError``
    handlers continue to work. Mirrors :class:`evidentia_core.
    poam_store.InvalidPoamIdError`.
    """


class EvidenceWORMViolation(RuntimeError):
    """Raised when a save would overwrite a persisted version.

    The WORM (Write-Once-Read-Many) contract: once
    ``<lineage_id>/v<N>.json`` is written, it cannot be replaced.
    Callers MUST construct v<N+1> via :meth:`EvidenceArtifact.
    new_version` and save that instead.

    The exception message names both the lineage_id and the
    conflicting version so operators can diagnose the collision
    directly (most commonly: re-saving without bumping ``version``,
    or two writers racing on the same artifact). The
    ``next_version`` attribute provides the canonical recovery
    suggestion (the lineage head + 1) so wrapping CLI/API code
    can surface it directly.
    """

    def __init__(
        self,
        lineage_id: str,
        attempted_version: int,
        next_version: int,
    ) -> None:
        self.lineage_id = lineage_id
        self.attempted_version = attempted_version
        self.next_version = next_version
        super().__init__(
            f"WORM violation: lineage {lineage_id!r} already has "
            f"v{attempted_version}.json on disk; cannot overwrite. "
            f"Call EvidenceArtifact.new_version() to construct "
            f"v{next_version} and save that instead."
        )


def _validate_id_shape(candidate: str) -> str:
    """Validate a candidate UUID and return its canonical form.

    Accepts any UUID variant (v1/v3/v4/v5). Returns the canonical
    lowercase hyphenated form (``str(UUID(...))``) so filenames are
    stable across the four lexical UUID forms Python accepts
    (canonical / brace-wrapped / urn-prefixed / hex-without-hyphens).
    Mirrors the v0.9.0 F-V90-15 canonicalization rule applied in
    poam_store + vendor_store.
    """
    try:
        return str(UUID(candidate))
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidEvidenceIdError(
            f"Invalid evidence/lineage ID format "
            f"(expected UUID string): {candidate!r}"
        ) from exc


def get_evidence_store_dir(override: Path | None = None) -> Path:
    """Resolve the evidence store root directory.

    Precedence:
      1. Explicit ``override`` argument (CLI flag or test fixture)
      2. :data:`EVIDENCE_STORE_ENV_VAR` environment variable
      3. ``platformdirs.user_data_dir("evidentia") / "evidence_store"``
    """
    if override is not None:
        return Path(override).expanduser().resolve()
    env = os.environ.get(EVIDENCE_STORE_ENV_VAR)
    if env:
        return Path(env).expanduser().resolve()
    return Path(user_data_dir("evidentia", "Evidentia")) / "evidence_store"


def _lineage_dir(
    lineage_id: str,
    store_root: Path,
) -> Path:
    """Resolve + validate the per-lineage subdirectory path.

    Belt-and-suspenders: the UUID-shape check on ``lineage_id``
    should already prevent path-traversal, but
    :func:`validate_within` confirms the resolved path lies under
    ``store_root``. A malicious ``../../etc`` input fails the shape
    gate FIRST; this is the second wall.
    """
    canonical = _validate_id_shape(lineage_id)
    candidate = store_root / canonical
    try:
        return validate_within(candidate, store_root)
    except PathTraversalError as exc:
        raise InvalidEvidenceIdError(
            f"Lineage id {lineage_id!r} would escape store root"
        ) from exc


def _version_path(
    lineage_id: str,
    version: int,
    store_root: Path,
) -> Path:
    """Resolve the file path for one version within a lineage chain."""
    if version < 1:
        raise ValueError(
            f"version must be >= 1 (per EvidenceArtifact.version "
            f"invariant); got {version}"
        )
    lineage = _lineage_dir(lineage_id, store_root)
    candidate = lineage / f"v{version}.json"
    return validate_within(candidate, store_root)


def _resolve_auto_mirror_backend() -> (
    tuple[object, object] | None
):
    """Resolve the auto-mirror backend factory from env vars (v0.9.7 P1.1).

    Returns ``None`` when :data:`EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR`
    is unset / empty → no auto-mirror should run. Returns
    ``(backend, retention_metadata)`` otherwise.

    Raises:
        RuntimeError: If the auto-mirror env var is set but the
            factory env var is unset / unresolvable. The error
            surfaces at first save (not server-start) so that
            operators who never save evidence don't hit a
            spurious config error.
    """
    if not os.environ.get(EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR):
        return None
    factory_ref = os.environ.get(EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR)
    if not factory_ref:
        raise RuntimeError(
            f"{EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR} is set but "
            f"{EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR} is empty. "
            f"Format: 'module.submodule:callable_name'. The callable "
            f"must return (backend, retention_metadata)."
        )
    if ":" not in factory_ref:
        raise RuntimeError(
            f"{EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR}={factory_ref!r} "
            f"must be of the form 'module.submodule:callable_name'"
        )
    import importlib

    module_path, _, attr = factory_ref.partition(":")
    try:
        module = importlib.import_module(module_path)
    except ImportError as exc:
        raise RuntimeError(
            f"Could not import {module_path!r} for auto-mirror "
            f"backend factory: {exc}"
        ) from exc
    factory = getattr(module, attr, None)
    if factory is None or not callable(factory):
        raise RuntimeError(
            f"{factory_ref!r} did not resolve to a callable in "
            f"{module_path!r}"
        )
    result: tuple[object, object] = factory()
    return result


def save_evidence(
    artifact: EvidenceArtifact,
    evidence_store_dir: Path | None = None,
) -> Path:
    """Persist an evidence artifact to the WORM-enforced store.

    Append-only enforcement: refuses to write
    ``<lineage>/v<N>.json`` if the file already exists, raising
    :class:`EvidenceWORMViolation`. The recovery path is to call
    :meth:`EvidenceArtifact.new_version` on the conflicting
    artifact and save the resulting v<N+1> version.

    v0.9.7 P1.1 auto-mirror: when
    :data:`EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR` is set + a backend
    factory is configured via
    :data:`EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR`, this function
    also pushes the persisted version to the cloud-WORM backend
    via :func:`evidentia_core.evidence_store_worm.mirror_to_worm`.
    The mirror runs AFTER the local-store write succeeds; mirror
    failure surfaces as a non-fatal warning by default (the local
    file is already in place + WORM-protected at the application
    layer). Operators wanting fail-fast on mirror failure raise
    the exception in their factory.

    Atomic-write semantics (mirrors poam_store v0.9.0 +
    vendor_store v0.7.9): writes to ``v<N>.json.tmp`` then
    ``os.replace`` to the canonical name. A crash mid-write
    leaves either no file (callers see "lineage version missing")
    OR the complete valid JSON in place — never a half-written
    file.

    Args:
        artifact: The evidence artifact to persist. Its
            ``effective_lineage_id`` (the explicit ``lineage_id``
            field or, for chain roots, ``id``) determines the
            directory; ``version`` determines the filename.
        evidence_store_dir: Optional override for the store
            root. Defaults to :func:`get_evidence_store_dir`.

    Returns:
        Absolute path of the written ``v<N>.json`` file.

    Raises:
        EvidenceWORMViolation: If ``<lineage>/v<artifact.version>.
            json`` already exists on disk.
        InvalidEvidenceIdError: If ``effective_lineage_id`` is
            not a valid UUID string.
    """
    lineage_id = artifact.effective_lineage_id
    canonical_lineage = _validate_id_shape(lineage_id)
    # Persist the canonical form back on the artifact so future
    # callers see the stable identifier (mirrors poam_store
    # F-V90-15 canonicalization).
    if artifact.lineage_id is not None and artifact.lineage_id != canonical_lineage:
        artifact.lineage_id = canonical_lineage

    store = get_evidence_store_dir(evidence_store_dir)
    lineage_dir = _lineage_dir(canonical_lineage, store)
    lineage_dir.mkdir(parents=True, exist_ok=True)

    out_path = _version_path(canonical_lineage, artifact.version, store)
    if out_path.exists():
        # Find the chain head so the violation message can point at
        # the canonical recovery (call new_version on the head).
        head = _chain_head_version(canonical_lineage, store)
        raise EvidenceWORMViolation(
            lineage_id=canonical_lineage,
            attempted_version=artifact.version,
            next_version=head + 1,
        )

    tmp_path = out_path.with_suffix(".json.tmp")
    tmp_path.write_text(
        artifact.model_dump_json(indent=2), encoding="utf-8"
    )
    os.replace(tmp_path, out_path)
    logger.debug(
        "Saved evidence v%d for lineage %s: %s",
        artifact.version,
        canonical_lineage,
        out_path,
    )

    # v0.9.7 P1.1: auto-mirror to cloud-WORM backend if configured.
    # Runs AFTER the local write succeeds, so a mirror failure
    # never leaves the local store in an inconsistent state. The
    # local-store version is the source-of-truth; the mirror is
    # a regulator-grade durability layer composed on top.
    mirror_config = _resolve_auto_mirror_backend()
    if mirror_config is not None:
        backend, retention_metadata = mirror_config
        try:
            from evidentia_core.evidence_store_worm import mirror_to_worm

            mirror_to_worm(artifact, backend, retention_metadata)  # type: ignore[arg-type]
            logger.debug(
                "Auto-mirrored evidence v%d for lineage %s to WORM backend",
                artifact.version,
                canonical_lineage,
            )
        except Exception:
            # Non-fatal: the local-store write already succeeded
            # + the WORM record is the optional durability layer.
            # Operators wanting fail-fast on mirror failure raise
            # the exception in their factory function rather than
            # catching it here.
            logger.warning(
                "Auto-mirror to WORM backend failed for lineage %s "
                "v%d; local-store write succeeded.",
                canonical_lineage,
                artifact.version,
                exc_info=True,
            )

    return out_path


def _chain_head_version(
    lineage_id: str,
    store_root: Path,
) -> int:
    """Return the largest version number currently on disk for a lineage.

    Returns 0 if the lineage directory doesn't exist OR contains
    no ``v<N>.json`` files. Used by :class:`EvidenceWORMViolation`
    to suggest the canonical next version + by :func:`list_lineage`
    to know how many entries to expect.
    """
    lineage_dir = _lineage_dir(lineage_id, store_root)
    if not lineage_dir.exists():
        return 0
    versions = []
    for path in lineage_dir.glob("v*.json"):
        stem = path.stem  # "vN"
        if stem.startswith("v"):
            try:
                versions.append(int(stem[1:]))
            except ValueError:
                # Skip files like "vfoo.json" — defensive
                continue
    return max(versions, default=0)


def load_evidence_version(
    lineage_id: str,
    version: int,
    evidence_store_dir: Path | None = None,
) -> EvidenceArtifact | None:
    """Load one specific version of a lineage chain.

    Args:
        lineage_id: The lineage identifier (UUID string).
        version: Sequence number within the chain (1-based).
        evidence_store_dir: Optional store-root override.

    Returns:
        The :class:`EvidenceArtifact` at that version, or ``None``
        if the well-formed ID + version has no record on disk.

    Raises:
        InvalidEvidenceIdError: If ``lineage_id`` is not a valid
            UUID string.
        ValueError: If ``version`` is < 1.
    """
    canonical_lineage = _validate_id_shape(lineage_id)
    store = get_evidence_store_dir(evidence_store_dir)
    path = _version_path(canonical_lineage, version, store)
    if not path.is_file():
        return None
    return EvidenceArtifact.model_validate_json(
        path.read_text(encoding="utf-8")
    )


def list_lineage(
    lineage_id: str,
    evidence_store_dir: Path | None = None,
) -> list[EvidenceArtifact]:
    """Return all versions of a lineage chain, sorted ascending.

    Returns an empty list if the lineage has no records on disk
    (well-formed but unknown lineage_id). Skips malformed JSON
    files with a logger warning rather than crashing.

    Args:
        lineage_id: The lineage identifier (UUID string).
        evidence_store_dir: Optional store-root override.

    Returns:
        ``[v1, v2, ..., vN]`` sorted by ``version`` ascending.

    Raises:
        InvalidEvidenceIdError: If ``lineage_id`` is not a valid
            UUID string.
    """
    canonical_lineage = _validate_id_shape(lineage_id)
    store = get_evidence_store_dir(evidence_store_dir)
    lineage_dir = _lineage_dir(canonical_lineage, store)
    if not lineage_dir.exists():
        return []
    artifacts: list[EvidenceArtifact] = []
    for path in sorted(lineage_dir.glob("v*.json")):
        try:
            artifacts.append(
                EvidenceArtifact.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            )
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning(
                "Skipping malformed evidence record %s: %s", path, exc
            )
    artifacts.sort(key=lambda a: a.version)
    return artifacts


def list_lineages(
    evidence_store_dir: Path | None = None,
) -> list[str]:
    """Return every lineage ID currently in the store.

    A "lineage" is any directory directly under the store root
    whose name parses as a UUID. Non-UUID directories are silently
    skipped (a defensive choice — operators may stage backups in
    the same parent directory).

    Returns:
        Sorted list of canonical UUID strings.
    """
    store = get_evidence_store_dir(evidence_store_dir)
    if not store.exists():
        return []
    lineages = []
    for entry in store.iterdir():
        if not entry.is_dir():
            continue
        try:
            lineages.append(_validate_id_shape(entry.name))
        except InvalidEvidenceIdError:
            continue
    lineages.sort()
    return lineages


__all__ = [
    "EVIDENCE_STORE_ENV_VAR",
    "EvidenceWORMViolation",
    "InvalidEvidenceIdError",
    "PathTraversalError",
    "get_evidence_store_dir",
    "list_lineage",
    "list_lineages",
    "load_evidence_version",
    "save_evidence",
]
