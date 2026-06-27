"""Catalog management router — user-import + cross-framework lookups (v0.10.12).

Surfaces the ``evidentia catalog`` management verbs over HTTP under the
``/api/catalog`` prefix:

  - ``GET    /api/catalog/crosswalk`` — cross-framework control mappings
    (read-only; mirrors ``catalog crosswalk``).
  - ``GET    /api/catalog/where`` — where a framework resolves from
    (user / bundled) + its path (read-only; mirrors ``catalog where``).
  - ``GET    /api/catalog/license-info/{framework_id}`` — licensing
    metadata for a framework (read-only; mirrors ``catalog license-info``).
  - ``POST   /api/catalog/import`` — import a user-supplied catalog into
    the local user catalog dir (LOCAL WRITE; ``require_role("write")``).
  - ``DELETE /api/catalog/{framework_id}`` — remove a user-imported
    catalog (LOCAL WRITE; ``require_role("admin")``).

Distinct from the read-only ``frameworks`` router (``/api/frameworks``),
which *browses* the bundled catalogs. This router *manages* the
user-import layer + exposes the cross-framework lookups.

Auth posture (v0.10.12 threat model)
------------------------------------
The CLI carries no RBAC. The HTTP surface adds it on the mutating verbs:
``import`` is gated on ``require_role("write")`` and ``remove`` on
``require_role("admin")``; the three read verbs are open. Under the
default permissive policy (no ``EVIDENTIA_RBAC_POLICY_FILE``) every
identity is admin, so behavior is unchanged for un-configured operators.

Security
--------
- ``import`` / ``remove`` only ever touch the user catalog directory via
  the ``evidentia_core.catalogs.user_dir`` helpers — never an arbitrary
  filesystem path. ``import`` accepts the catalog *content* in the body
  (NOT a server-side path to read), so there is no SSRF / arbitrary-file-
  read surface.
- ``framework_id`` shape is validated against
  :data:`_FRAMEWORK_ID_RE` before it is used to derive an on-disk
  filename, defending against path traversal (``..``, ``/``, ``\\``).
"""

from __future__ import annotations

import json
import re

import yaml
from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.catalogs.loader import load_evidentia_catalog
from evidentia_core.catalogs.manifest import (
    FrameworkManifest,
    FrameworkManifestEntry,
    load_manifest,
)
from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.catalogs.user_dir import (
    ensure_user_dir,
    get_user_catalog_dir,
    load_user_manifest,
    resolve_catalog_path,
    save_user_manifest,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from evidentia_api.rbac_dependency import require_role

router = APIRouter()
_log = get_logger("evidentia.api.catalog")

# Kebab/dot framework IDs only. Must start with an alphanumeric and may
# contain lowercase letters, digits, dots, hyphens, and underscores. This
# excludes path separators (``/``, ``\\``) and the parent-dir token
# (``..`` cannot match because a leading ``.`` is disallowed and no ``/``
# is permitted), so a validated ID can never traverse out of the user
# catalog dir when used to build ``<user_dir>/<framework_id>.json``.
_FRAMEWORK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


def _validate_framework_id(framework_id: str) -> None:
    """Reject framework IDs whose shape could enable path traversal.

    Raises ``HTTPException(400)`` on an invalid shape. Bundled +
    user-imported IDs are all kebab-case (e.g. ``nist-csf-2.0``), so a
    well-formed ID always matches; only crafted inputs fail here.
    """
    if ".." in framework_id or not _FRAMEWORK_ID_RE.match(framework_id):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid framework_id {framework_id!r}; expected a "
                "kebab-case identifier matching "
                f"{_FRAMEWORK_ID_RE.pattern} (no path separators)."
            ),
        )


# ── crosswalk (read) ───────────────────────────────────────────────


@router.get("/catalog/crosswalk")
async def get_crosswalk(
    source: str = Query(..., description="Source framework ID."),
    target: str = Query(..., description="Target framework ID."),
    control: str = Query(..., description="Source control ID."),
) -> dict[str, object]:
    """Cross-framework mappings for a control (read-only).

    Mirrors ``evidentia catalog crosswalk --source --target --control``.
    Returns a list envelope; an empty ``mappings`` list (total 0) when no
    mapping exists — consistent with the CLI's "no mappings found" path
    (a successful zero-result, not a 404).
    """
    crosswalk = FrameworkRegistry.get_instance().crosswalk
    mappings = crosswalk.get_mapped_controls(source, control, target)
    return {
        "source": source,
        "target": target,
        "control": control,
        "total": len(mappings),
        "mappings": [m.model_dump(mode="json") for m in mappings],
    }


# ── where (read) ───────────────────────────────────────────────────


@router.get("/catalog/where")
async def where_framework(
    framework_id: str = Query(..., description="Framework ID to locate."),
) -> dict[str, object]:
    """Show where a framework resolves from — user, bundled, or 404.

    Mirrors ``evidentia catalog where``. The user catalog dir is the one
    the ``EVIDENTIA_CATALOG_DIR`` env var (or platform default) points at.
    """
    _validate_framework_id(framework_id)
    bundled = load_manifest()
    user = load_user_manifest()
    try:
        path, entry, source = resolve_catalog_path(
            framework_id,
            bundled_manifest=bundled,
            user_manifest=user,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown framework {framework_id!r}.",
        ) from exc

    shadowed = source == "user" and bundled.get(framework_id) is not None
    return {
        "framework_id": framework_id,
        "name": entry.name,
        "source": source,
        "shadowed": shadowed,
        "path": str(path),
        "tier": entry.tier,
        "category": entry.category,
        "placeholder": entry.placeholder,
    }


# ── license-info (read) ────────────────────────────────────────────


@router.get("/catalog/license-info/{framework_id}")
async def license_info(framework_id: str) -> dict[str, object]:
    """Licensing metadata for a framework (read-only).

    Mirrors ``evidentia catalog license-info``: user-imported entries
    take precedence over bundled, then 404 if neither knows the ID.
    """
    _validate_framework_id(framework_id)
    bundled = load_manifest()
    user = load_user_manifest()
    entry = user.get(framework_id) or bundled.get(framework_id)
    if entry is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown framework {framework_id!r}.",
        )
    return {
        "framework_id": framework_id,
        "name": entry.name,
        "tier": entry.tier,
        "license_required": entry.license_required,
        "placeholder": entry.placeholder,
        "license": entry.license,
        "license_url": entry.license_url,
        "source_url": entry.source_url,
    }


# ── import (local write) ───────────────────────────────────────────


class CatalogImportPayload(BaseModel):
    """Body shape for ``POST /api/catalog/import``.

    The catalog is supplied as inline ``content`` (NOT a server-side
    path) so the API never reads an operator-chosen file off the server
    — closing the path-traversal / arbitrary-read surface the CLI's
    file-path argument would expose over HTTP.
    """

    framework_id: str = Field(
        description=(
            "Framework ID the catalog is imported under. Authoritative "
            "for the on-disk filename + the manifest entry; overrides any "
            "framework_id inside the content."
        ),
    )
    content: str = Field(
        min_length=1,
        max_length=20_000_000,
        description="Raw catalog document (JSON or YAML text).",
    )
    format: str = Field(
        default="json",
        description="Content format: 'json' or 'yaml'.",
    )
    name: str | None = Field(
        default=None,
        max_length=512,
        description="Override the human-readable framework name.",
    )
    license_terms: str | None = Field(
        default=None,
        max_length=4096,
        description="Statement about the content's source + licensing.",
    )
    tier: str = Field(
        default="C",
        description="Redistribution tier of imported content (A/B/C/D).",
    )
    force: bool = Field(
        default=False,
        description="Overwrite an existing user import with the same ID.",
    )


@router.post(
    "/catalog/import",
    status_code=201,
    dependencies=[require_role("write")],
)
async def import_catalog(payload: CatalogImportPayload) -> dict[str, object]:
    """Import a user-supplied catalog into the local user catalog dir.

    LOCAL WRITE. Gated on ``require_role("write")``. Parses the inline
    content, rewrites its ``framework_id`` / ``framework_name`` to the
    authoritative values, validates the shape via
    :func:`load_evidentia_catalog`, then persists it + a manifest entry
    via the ``user_dir`` helpers. Never touches a path outside the user
    catalog dir.
    """
    _validate_framework_id(payload.framework_id)

    tier = payload.tier.upper()
    if tier not in ("A", "B", "C", "D"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid tier {payload.tier!r}; expected one of A, B, C, D.",
        )

    fmt = payload.format.lower()
    if fmt not in ("json", "yaml", "yml"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format {payload.format!r}; expected json or yaml.",
        )

    # Parse the inline content into a dict.
    try:
        data = (
            json.loads(payload.content)
            if fmt == "json"
            else yaml.safe_load(payload.content)
        )
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not parse catalog content as {fmt}: {exc}",
        ) from exc
    if not isinstance(data, dict):
        raise HTTPException(
            status_code=400,
            detail="Catalog content top-level must be a mapping/object.",
        )

    # Path/body framework_id is authoritative; rewrite the content so the
    # persisted catalog + manifest agree on the ID it lands under.
    data["framework_id"] = payload.framework_id
    if payload.name:
        data["framework_name"] = payload.name
    resolved_name = data.get("framework_name") or payload.framework_id
    version = str(data.get("version", "unknown"))
    placeholder = bool(data.get("placeholder", False))

    user_dir = ensure_user_dir()
    out_path = user_dir / f"{payload.framework_id}.json"
    # Defense-in-depth (belt-and-suspenders over _validate_framework_id, which
    # already rejects '..' + path separators): assert the resolved write target
    # stays within the user catalog dir before it is written + loaded (CWE-22).
    if not out_path.resolve().is_relative_to(user_dir.resolve()):
        raise HTTPException(
            status_code=400,
            detail="Resolved catalog path escapes the user catalog directory.",
        )
    if out_path.exists() and not payload.force:
        raise HTTPException(
            status_code=400,
            detail=(
                f"A user-imported {payload.framework_id!r} already exists; "
                "set force=true to overwrite."
            ),
        )

    # Validate the catalog shape BEFORE writing so a malformed body never
    # leaves a half-imported file on disk. Write to the canonical path,
    # then load it back through the core loader.
    out_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    try:
        load_evidentia_catalog(out_path)
    except Exception as exc:  # normalize any load error to 400
        # Roll back the partial write so a bad import is a no-op.
        out_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=400,
            detail=f"Catalog content failed validation: {exc}",
        ) from exc

    _add_to_user_manifest(
        framework_id=payload.framework_id,
        name=resolved_name,
        version=version,
        tier=tier,
        path=out_path.name,
        placeholder=placeholder,
        license_terms=payload.license_terms,
    )

    shadows_bundled = load_manifest().get(payload.framework_id) is not None
    _log.info(
        action=EventAction.CATALOG_IMPORTED,
        outcome=EventOutcome.SUCCESS,
        message=f"User catalog imported via API: {payload.framework_id}",
        evidentia={
            "framework_id": payload.framework_id,
            "tier": tier,
            "shadows_bundled": shadows_bundled,
        },
    )
    return {
        "framework_id": payload.framework_id,
        "name": resolved_name,
        "source": "user",
        "shadows_bundled": shadows_bundled,
        "path": str(out_path),
    }


# ── remove (local delete) ──────────────────────────────────────────


@router.delete(
    "/catalog/{framework_id}",
    status_code=204,
    dependencies=[require_role("admin")],
)
async def remove_catalog(framework_id: str) -> None:
    """Remove a user-imported catalog. 204 on success; 404 otherwise.

    LOCAL DELETE. Gated on ``require_role("admin")``. Bundled catalogs
    are never user-imported, so they cannot be removed — an attempt to
    remove one (or an unknown ID) returns 404, mirroring the CLI's
    "no user-imported framework; bundled catalogs cannot be removed"
    behavior.
    """
    _validate_framework_id(framework_id)
    user = load_user_manifest()
    entry = user.get(framework_id)
    if entry is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No user-imported framework {framework_id!r}. Bundled "
                "catalogs cannot be removed."
            ),
        )

    user_dir = get_user_catalog_dir()
    catalog_path = user_dir / entry.path
    if catalog_path.exists():
        catalog_path.unlink()

    updated = FrameworkManifest(
        version=user.version,
        frameworks=[fw for fw in user.frameworks if fw.id != framework_id],
    )
    save_user_manifest(updated)
    _log.info(
        action=EventAction.CATALOG_REMOVED,
        outcome=EventOutcome.SUCCESS,
        message=f"User catalog removed via API: {framework_id}",
        evidentia={"framework_id": framework_id},
    )


# ── helpers ────────────────────────────────────────────────────────


def _add_to_user_manifest(
    *,
    framework_id: str,
    name: str,
    version: str,
    tier: str,
    path: str,
    placeholder: bool,
    license_terms: str | None,
) -> None:
    """Append or replace an entry in the user manifest.

    Mirrors the CLI's ``_add_to_user_manifest`` (catalog.py) — kept local
    rather than imported because the CLI helper lives in the
    ``evidentia`` package, which the API layer does not depend on.
    """
    user = load_user_manifest()
    kept = [fw for fw in user.frameworks if fw.id != framework_id]
    new_entry = FrameworkManifestEntry(
        id=framework_id,
        name=name,
        version=version,
        tier=tier,  # type: ignore[arg-type]  # validated upstream to A/B/C/D shape
        category="control",
        path=path,
        license=license_terms,
        placeholder=placeholder,
    )
    updated = FrameworkManifest(version=user.version, frameworks=[*kept, new_entry])
    save_user_manifest(updated)
