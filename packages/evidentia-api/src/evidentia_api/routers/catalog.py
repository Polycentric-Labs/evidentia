"""Catalog management router - user-import + cross-framework lookups (v0.10.12).

Surfaces the ``evidentia catalog`` management verbs over HTTP under the
``/api/catalog`` prefix:

  - ``GET    /api/catalog/crosswalk`` - cross-framework control mappings
    (read-only; mirrors ``catalog crosswalk``).
  - ``GET    /api/catalog/where`` - where a framework resolves from
    (user / bundled) + its path (read-only; mirrors ``catalog where``).
  - ``GET    /api/catalog/license-info/{framework_id}`` - licensing
    metadata for a framework (read-only; mirrors ``catalog license-info``).
  - ``POST   /api/catalog/import`` - import a user-supplied catalog into
    the local user catalog dir (LOCAL WRITE; ``require_role("write")``).
  - ``DELETE /api/catalog/{framework_id}`` - remove a user-imported
    catalog (LOCAL WRITE; ``require_role("admin")``).

Distinct from the read-only ``frameworks`` router (``/api/frameworks``),
which *browses* the bundled catalogs. This router *manages* the
user-import layer + exposes the cross-framework lookups.

Auth posture (v0.10.12 threat model)
------------------------------------
Both CLI and HTTP surfaces apply the existing roles on mutating verbs:
``import`` is gated on ``require_role("write")`` and ``remove`` on
``require_role("admin")``; the three read verbs are open. Under the
default permissive policy (no ``EVIDENTIA_RBAC_POLICY_FILE``) every
identity is admin, so behavior is unchanged for un-configured operators.

Security
--------
- ``import`` / ``remove`` only ever touch the user catalog directory via
  the ``evidentia_core.catalogs.user_dir`` helpers - never an arbitrary
  filesystem path. ``import`` accepts the catalog *content* in the body
  (NOT a server-side path to read), so there is no SSRF / arbitrary-file-
  read surface.
- ``framework_id`` shape is validated against
  :data:`_FRAMEWORK_ID_RE` before it is used to derive an on-disk
  filename, defending against path traversal (``..``, ``/``, ``\\``).
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import sys
from contextlib import suppress
from datetime import date
from pathlib import Path
from tempfile import mkdtemp
from typing import Any, cast

import yaml
from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.catalogs.loader import load_evidentia_catalog
from evidentia_core.catalogs.manifest import (
    FrameworkManifestEntry,
    load_manifest,
)
from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.catalogs.user_dir import (
    CatalogManifestTransaction,
    CatalogMutationIntent,
    catalog_entry_sha256,
    load_user_manifest,
    resolve_catalog_path,
)
from evidentia_core.models.catalog import ControlCatalog, TextDepth
from evidentia_core.models.common import NonBlankStr
from evidentia_core.models.open_corpora import (
    CatalogStorageErrorEnvelope,
    ExternalImportRequest,
    ImportResult,
    NativeReadError,
    NativeSourceError,
    native_operation,
)
from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.responses import Response

from evidentia_api.errors import (
    BODY_PARSE_ERROR_400,
    RBAC_DENIED_403,
    api_error,
    error_responses,
)
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
# DOS device basenames stay reserved when followed by an extension.
_RESERVED_FRAMEWORK_IDS = frozenset(
    {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}
)


def _validate_framework_id(framework_id: str) -> str:
    """Validate a framework ID's shape and RETURN the validated value.

    Raises a 400 ``api_error`` (``error: invalid_id``) on an invalid
    shape. Bundled +
    user-imported IDs are all kebab-case (e.g. ``nist-csf-2.0``), so a
    well-formed ID always matches; only crafted inputs fail here.

    The whole value must match, including its final character. Filesystem
    callers also resolve and check the destination against the user root.
    """
    if (
        ".." in framework_id
        or not _FRAMEWORK_ID_RE.fullmatch(framework_id)
        or framework_id.partition(".")[0] in _RESERVED_FRAMEWORK_IDS
    ):
        raise api_error(
            400,
            "invalid_id",
            (
                f"Invalid framework_id {framework_id!r}; expected a "
                "kebab-case identifier matching "
                f"{_FRAMEWORK_ID_RE.pattern} (no path separators or reserved device names)."
            ),
            resource="framework",
        )
    return framework_id


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
    mapping exists - consistent with the CLI's "no mappings found" path
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


@router.get(
    "/catalog/where",
    responses=error_responses(
        {
            400: "Malformed ``framework_id`` (``error: invalid_id``).",
            404: "Unknown framework (``error: not_found``).",
        }
    ),
)
async def where_framework(
    framework_id: str = Query(..., description="Framework ID to locate."),
) -> dict[str, object]:
    """Show where a framework resolves from - user, bundled, or 404.

    Mirrors ``evidentia catalog where``. The user catalog dir is the one
    the ``EVIDENTIA_CATALOG_DIR`` env var (or platform default) points at.
    """
    framework_id = _validate_framework_id(framework_id)
    bundled = load_manifest()
    user = load_user_manifest()
    try:
        path, entry, source = resolve_catalog_path(
            framework_id,
            bundled_manifest=bundled,
            user_manifest=user,
        )
    except ValueError as exc:
        raise api_error(
            404,
            "not_found",
            f"Unknown framework {framework_id!r}.",
            resource="framework",
            resource_id=framework_id,
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
        "text_depth": entry.text_depth,
        "status": entry.status,
        "notes": entry.notes,
        "verified_on": entry.verified_on,
        "superseded_by": entry.superseded_by,
    }


# ── license-info (read) ────────────────────────────────────────────


@router.get(
    "/catalog/license-info/{framework_id}",
    responses=error_responses(
        {
            400: "Malformed ``framework_id`` (``error: invalid_id``).",
            404: "Unknown framework (``error: not_found``).",
        }
    ),
)
async def license_info(framework_id: str) -> dict[str, object]:
    """Licensing metadata for a framework (read-only).

    Mirrors ``evidentia catalog license-info``: user-imported entries
    take precedence over bundled, then 404 if neither knows the ID.
    """
    framework_id = _validate_framework_id(framework_id)
    bundled = load_manifest()
    user = load_user_manifest()
    entry = user.get(framework_id) or bundled.get(framework_id)
    if entry is None:
        raise api_error(
            404,
            "not_found",
            f"Unknown framework {framework_id!r}.",
            resource="framework",
            resource_id=framework_id,
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
        "text_depth": entry.text_depth,
        "status": entry.status,
        "notes": entry.notes,
        "verified_on": entry.verified_on,
        "superseded_by": entry.superseded_by,
    }


# ── import (local write) ───────────────────────────────────────────


def _write_error_responses(errors: dict[int, str]) -> dict[int | str, dict[str, Any]]:
    return {
        **error_responses(errors),
        409: {"model": CatalogStorageErrorEnvelope, "description": "Catalog transaction or generation conflict."},
        503: {"model": CatalogStorageErrorEnvelope, "description": "Catalog publication or storage failure."},
    }


class CatalogImportPayload(BaseModel):
    """Body shape for ``POST /api/catalog/import``.

    The catalog is supplied as inline ``content`` (NOT a server-side
    path) so the API never reads an operator-chosen file off the server
    - closing the path-traversal / arbitrary-read surface the CLI's
    file-path argument would expose over HTTP.
    """

    framework_id: str = Field(
        description=(
            "Framework ID the catalog is imported under. Authoritative "
            "for the on-disk filename + the manifest entry; overrides any "
            "framework_id inside the content."
        ),
    )
    content: NonBlankStr = Field(
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


def _require_string_mapping_keys(data: object) -> None:
    """Reject keys that JSON would coerce before catalog validation sees them."""
    pending = [data]
    seen: set[int] = set()
    while pending:
        value = pending.pop()
        if not isinstance(value, (dict, list)) or id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError("Catalog mapping keys must be strings; YAML keys are not converted")
            pending.extend(value.values())
        else:
            pending.extend(value)


def _json_catalog_date(value: object) -> str:
    """Preserve YAML date scalars as ISO strings; reject other non-JSON values."""
    if isinstance(value, date):
        return value.isoformat()
    raise TypeError(f"Unsupported catalog value type: {type(value).__name__}")


@router.post(
    "/catalog/import",
    status_code=201,
    response_model=dict[str, object],
    dependencies=[require_role("write")],
    responses=_write_error_responses(
        {
            400: (
                "Malformed ``framework_id``, invalid ``tier``, "
                "unsupported ``format``, unparseable/invalid catalog "
                "content, a duplicate import without ``force``, or an "
                "undecodable request body "
                "(``error: invalid_id`` / ``invalid_field`` / "
                "``unsupported_format`` / ``invalid_body`` / "
                f"``already_exists``; {BODY_PARSE_ERROR_400})."
            ),
            403: RBAC_DENIED_403,
        }
    ),
    # 2026-07-06 stateful-DAST prep (Step 2): OpenAPI link chaining this
    # response's ``framework_id`` into the DELETE lifecycle op, mirroring
    # the ai-gov register links above.
    openapi_extra={
        "responses": {
            "201": {
                "links": {
                    "DeleteCatalog": {
                        "operationId": ("remove_catalog_api_catalog__framework_id__delete"),
                        "parameters": {"framework_id": "$response.body#/framework_id"},
                    }
                }
            }
        }
    },
)
async def import_catalog(payload: CatalogImportPayload) -> dict[str, object] | Response:
    """Import a user-supplied catalog into the local user catalog dir.

    LOCAL WRITE. Gated on ``require_role("write")``. Parses the inline
    content, rewrites its ``framework_id`` / ``framework_name`` to the
    authoritative values, validates the shape via
    :func:`load_evidentia_catalog`, then persists it + a manifest entry
    via the ``user_dir`` helpers. Never touches a path outside the user
    catalog dir.
    """
    framework_id = _validate_framework_id(payload.framework_id)

    tier = payload.tier.upper()
    if tier not in ("A", "B", "C", "D"):
        raise api_error(
            400,
            "invalid_field",
            f"Invalid tier {payload.tier!r}; expected one of A, B, C, D.",
            field="tier",
        )

    fmt = payload.format.lower()
    if fmt not in ("json", "yaml", "yml"):
        raise api_error(
            400,
            "unsupported_format",
            f"Unsupported format {payload.format!r}; expected json or yaml.",
            format=payload.format,
            supported=["json", "yaml", "yml"],
        )

    # Parse the inline content into a dict.
    try:
        data = json.loads(payload.content) if fmt == "json" else yaml.safe_load(payload.content)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise api_error(
            400,
            "invalid_body",
            f"Could not parse catalog content as {fmt}: {exc}",
        ) from exc
    if not isinstance(data, dict):
        raise api_error(
            400,
            "invalid_body",
            "Catalog content top-level must be a mapping/object.",
        )

    # Path/body framework_id is authoritative; rewrite the content so the
    # persisted catalog + manifest agree on the ID it lands under.
    data["framework_id"] = framework_id
    if payload.name:
        data["framework_name"] = payload.name
    resolved_name = data.get("framework_name") or framework_id
    version = str(data.get("version", "unknown"))
    placeholder = bool(data.get("placeholder", False))

    # Validation happens before storage; the shared transaction publishes an immutable generation.
    staging_dir = mkdtemp(prefix=".catalog-import-")
    try:
        staged_path = Path(staging_dir) / "catalog.json"
        try:
            _require_string_mapping_keys(data)
            serialized = json.dumps(data, indent=2, ensure_ascii=False, default=_json_catalog_date)
        except (TypeError, ValueError) as exc:
            raise api_error(400, "invalid_body", f"Catalog content cannot be represented as JSON: {exc}") from exc
        staged_path.write_text(serialized, encoding="utf-8", newline="\n")
        try:
            loaded_catalog = load_evidentia_catalog(staged_path)
        except Exception as exc:
            raise api_error(400, "invalid_body", "Catalog content failed validation.") from exc
        entry = _manifest_entry(
            framework_id=payload.framework_id,
            name=resolved_name,
            version=version,
            tier=tier,
            placeholder=placeholder,
            license_terms=payload.license_terms,
            text_depth=loaded_catalog.text_depth,
            catalog=loaded_catalog,
        )
        outcome = _commit_catalog(CatalogMutationIntent.legacy(entry, staged_path.read_bytes(), force=payload.force))
        if isinstance(outcome, Response):
            return outcome
        out_path = outcome
    finally:
        _cleanup_staging(staging_dir)

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
    response_model=None,
    dependencies=[require_role("admin")],
    responses=_write_error_responses(
        {
            400: "Malformed ``framework_id`` (``error: invalid_id``).",
            403: RBAC_DENIED_403,
            404: ("No user-imported framework under that ID (``error: not_found``)."),
        }
    ),
)
async def remove_catalog(framework_id: str) -> Response | None:
    """Remove a user-imported catalog. 204 on success; 404 otherwise.

    LOCAL DELETE. Gated on ``require_role("admin")``. Bundled catalogs
    are never user-imported, so they cannot be removed - an attempt to
    remove one (or an unknown ID) returns 404, mirroring the CLI's
    "no user-imported framework; bundled catalogs cannot be removed"
    behavior.
    """
    framework_id = _validate_framework_id(framework_id)
    user = load_user_manifest()
    entry = user.get(framework_id)
    if entry is None:
        raise api_error(
            404,
            "not_found",
            (f"No user-imported framework {framework_id!r}. Bundled catalogs cannot be removed."),
            resource="user_catalog",
            resource_id=framework_id,
        )

    outcome = _commit_catalog(
        CatalogMutationIntent.remove(framework_id, expected_entry_sha256=catalog_entry_sha256(entry))
    )
    if isinstance(outcome, Response):
        return outcome
    _log.info(
        action=EventAction.CATALOG_REMOVED,
        outcome=EventOutcome.SUCCESS,
        message=f"User catalog removed via API: {framework_id}",
        evidentia={"framework_id": framework_id},
    )
    return None


# ── helpers ────────────────────────────────────────────────────────


def _cleanup_staging(staging_dir: str) -> None:
    """Keep an active failure or cancellation when scratch cleanup also fails."""
    primary = sys.exception()
    try:
        shutil.rmtree(staging_dir, ignore_errors=True)
    except BaseException:
        if primary is None:
            raise


def _manifest_entry(
    *,
    framework_id: str,
    name: str,
    version: str,
    tier: str,
    placeholder: bool,
    license_terms: str | None,
    text_depth: TextDepth | None = None,
    catalog: ControlCatalog | None = None,
) -> FrameworkManifestEntry:
    """Capture manifest metadata without reading or publishing the user manifest."""
    return FrameworkManifestEntry(
        id=framework_id,
        name=name,
        version=version,
        tier=tier,  # type: ignore[arg-type]  # validated upstream to A/B/C/D shape
        category="control",
        path="catalog.json",
        license=license_terms if license_terms is not None else catalog.license_terms if catalog else None,
        placeholder=placeholder,
        text_depth=text_depth,
        status=catalog.status if catalog else None,
        notes=catalog.notes if catalog else None,
        verified_on=catalog.verified_on if catalog else None,
        superseded_by=catalog.superseded_by if catalog else None,
        source_url=catalog.source if catalog else None,
        license_url=catalog.license_url if catalog else None,
        license_required=catalog.license_required if catalog else False,
    )


def _catalog_failure(
    transaction: CatalogManifestTransaction, intent: CatalogMutationIntent, exc: Exception
) -> JSONResponse:
    """Translate the terminal failure after the caller's operation scope exits."""
    if type(exc) is ValueError and exc.args == ("Framework is already registered; use force to replace it",):
        raise api_error(
            400,
            "already_exists",
            "A user catalog with this ID exists; set force=true to replace it.",
            resource="user_catalog",
            resource_id=intent.framework_id,
        ) from exc
    observation = transaction.observation
    if observation is None:
        raise exc
    envelope = CatalogStorageErrorEnvelope.model_validate(
        {
            "code": observation.error_code,
            "publication": observation.model_dump(mode="json"),
        }
    )
    status = 409 if envelope.code in ("catalog_transaction_conflict", "catalog_generation_conflict") else 503
    return JSONResponse(status_code=status, content=envelope.model_dump(mode="json"))


def _catalog_success(transaction: CatalogManifestTransaction, result: Path | ImportResult) -> Path | ImportResult:
    observation = transaction.observation
    if observation is None or observation.error_code is not None or observation.readback_result != "matches_proposed":
        raise RuntimeError("catalog_publication_indeterminate")
    return result


def _commit_catalog(intent: CatalogMutationIntent) -> Path | ImportResult | JSONResponse:
    """Translate ordinary transaction failures without hiding publication facts."""
    transaction = CatalogManifestTransaction()
    try:
        result = transaction.commit(intent)
    except Exception as exc:
        return _catalog_failure(transaction, intent, exc)
    return _catalog_success(transaction, result)


def _native_refusal(code: str = "native_source_invalid", status: int = 422) -> JSONResponse:
    return JSONResponse(
        status_code=status, content=NativeReadError.model_validate({"code": code}).model_dump(mode="json")
    )


def _native_import_schema() -> dict[str, Any]:
    """Inline this finite request model without adding a FastAPI body reader."""
    schema = ExternalImportRequest.model_json_schema(mode="validation")
    definitions = schema.pop("$defs", {})

    def inline(value: Any) -> Any:
        if isinstance(value, list):
            return [inline(item) for item in value]
        if not isinstance(value, dict):
            return value
        if "$ref" in value:
            reference = value["$ref"]
            if not reference.startswith("#/$defs/") or len(value) != 1:
                raise RuntimeError("Unexpected native request schema reference")
            return inline(definitions[reference.removeprefix("#/$defs/")])
        return {key: inline(item) for key, item in value.items()}

    return cast(dict[str, Any], inline(schema))


@router.post(
    "/catalog/import-native",
    status_code=201,
    response_model=ImportResult,
    dependencies=[require_role("write")],
    responses={
        413: {"model": NativeReadError, "description": "Raw request body exceeds 16 MiB."},
        422: {"model": NativeReadError, "description": "Invalid pinned native source request."},
        409: {"model": CatalogStorageErrorEnvelope, "description": "Catalog transaction or generation conflict."},
        503: {
            "model": CatalogStorageErrorEnvelope | NativeReadError,
            "description": "Catalog publication, storage or deadline failure.",
        },
        **error_responses({403: RBAC_DENIED_403}),
    },
    openapi_extra={
        "requestBody": {"required": True, "content": {"application/json": {"schema": _native_import_schema()}}}
    },
)
async def import_native_catalog(request: Request) -> ImportResult | Response:
    """Import the pinned BSI sources after authorization and bounded body admission."""
    from evidentia_core.catalogs.loader import _load_catalog_data
    from evidentia_core.catalogs.open_corpora import _source_snapshot

    # No typed body parameter: FastAPI must finish dependencies before reading bytes.
    transaction: CatalogManifestTransaction | None = None
    intent: CatalogMutationIntent | None = None
    try:
        with native_operation() as budget:
            content_types = request.headers.getlist("content-type")
            encodings = request.headers.getlist("content-encoding")
            if (
                len(content_types) != 1
                or content_types[0].lower().replace(" ", "")
                not in (
                    "application/json",
                    "application/json;charset=utf-8",
                )
                or encodings
            ):
                return _native_refusal()
            lengths = request.headers.getlist("content-length")
            if len(lengths) > 1 or (lengths and not re.fullmatch(r"[0-9]{1,16}", lengths[0])):
                return _native_refusal()
            declared = int(lengths[0]) if lengths else None
            if declared is not None and declared > 16_777_216:
                return _native_refusal(status=413)
            body = bytearray()
            stream = request.stream()
            while True:
                budget.check()
                pending = asyncio.create_task(anext(stream))
                try:
                    while not pending.done():
                        await asyncio.wait({pending}, timeout=0.1)
                        budget.check()
                    try:
                        chunk = pending.result()
                    except StopAsyncIteration:
                        break
                    if len(body) + len(chunk) > 16_777_216:
                        return _native_refusal(status=413)
                    body.extend(chunk)
                    budget.check()
                finally:
                    if not pending.done():
                        pending.cancel()
                        # Preserve the active deadline or caller cancellation.
                        with suppress(BaseException):
                            await pending
            if declared is not None and declared != len(body):
                return _native_refusal()
            parsed = _load_catalog_data(None, raw_bytes=bytes(body), mode="wire_json")
            payload = ExternalImportRequest.model_validate(parsed.data)
            filenames = {
                "bsi-catalog": "Grundschutz++-resolved_catalog.json",
                "bsi-license": "LICENSE",
                "bsi-readme": "README.md",
            }
            sources = {
                filenames[document.source_key]: document.raw_utf8.encode("utf-8") for document in payload.documents
            }
            _source_snapshot(payload.profile, sources, budget)
            intent = CatalogMutationIntent.native(sources)
            transaction = CatalogManifestTransaction()
            result = transaction.commit(intent)
    except Exception as exc:
        if transaction is not None and intent is not None:
            return _catalog_failure(transaction, intent, exc)
        if isinstance(exc, NativeSourceError):
            return _native_refusal(exc.code, 503 if exc.code == "processing_deadline_exceeded" else 422)
        if isinstance(exc, (ValueError, UnicodeError)):
            return _native_refusal()
        if isinstance(exc, OSError):
            return _native_refusal("native_source_unavailable", 503)
        raise
    _catalog_success(transaction, result)
    wire = transaction.result_json
    if not isinstance(result, ImportResult) or wire is None:
        raise RuntimeError("catalog_publication_indeterminate")
    return Response(status_code=201, content=wire, media_type="application/json")
