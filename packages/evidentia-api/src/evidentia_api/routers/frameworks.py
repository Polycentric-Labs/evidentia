"""Frameworks router - list, inspect, and drill into the 82 bundled catalogs.

These endpoints feed the GUI's Frameworks browser page:
- ``GET /api/frameworks`` - list all (optionally filtered by tier/category)
- ``GET /api/frameworks/{id}`` - framework metadata + full control list
- ``GET /api/frameworks/{id}/controls/{control_id}`` - single control detail
"""

from __future__ import annotations

from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.models.catalog import CatalogControl, ControlCatalog
from evidentia_core.models.open_corpora import (
    NativeBundle,
    NativeReadError,
    NativeReadRequest,
    NativeSourceError,
    native_operation,
)
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from starlette.responses import Response

from evidentia_api.deps import get_registry
from evidentia_api.errors import api_error, error_responses

router = APIRouter()


@router.get("/frameworks")
async def list_frameworks(
    tier: str | None = Query(
        None,
        description="Filter by redistribution tier (A|B|C|D).",
    ),
    category: str | None = Query(
        None,
        description="Filter by catalog category (control|technique|vulnerability|obligation).",
    ),
    registry: FrameworkRegistry = Depends(get_registry),
) -> dict[str, object]:
    """Return the manifest-derived framework list with optional filtering.

    Matches :meth:`FrameworkRegistry.list_frameworks` exactly - callers can
    expect the stable dict shape documented there.
    """
    entries = registry.list_frameworks(tier=tier, category=category)
    return {"total": len(entries), "frameworks": entries}


@router.get(
    "/frameworks/{framework_id}",
    response_model=ControlCatalog,
    responses=error_responses({404: "Unknown ``framework_id`` (``error: not_found``)."}),
)
async def get_framework(
    framework_id: str,
    registry: FrameworkRegistry = Depends(get_registry),
) -> ControlCatalog:
    """Load the full catalog for a framework ID.

    Response includes every control + enhancement tree. Large frameworks
    (full NIST 800-53 Rev 5 is ~3MB) are delivered as single responses;
    the UI renders with TanStack Virtual for scroll performance.
    """
    try:
        return registry.get_catalog(framework_id)
    except (FileNotFoundError, KeyError, ValueError) as e:
        raise api_error(
            404,
            "not_found",
            f"Framework '{framework_id}' not found in registered catalogs.",
            resource="framework",
            resource_id=framework_id,
        ) from e


@router.get(
    "/frameworks/{framework_id}/controls/{control_id}",
    response_model=CatalogControl,
    responses=error_responses(
        {
            404: ("Unknown ``framework_id`` or ``control_id`` (``error: not_found``)."),
        }
    ),
)
async def get_control(
    framework_id: str,
    control_id: str,
    registry: FrameworkRegistry = Depends(get_registry),
) -> CatalogControl:
    """Look up a single control by (framework, control_id).

    Accepts either NIST-publication-style (``AC-2(1)``) or NIST-OSCAL-style
    (``ac-2.1``) IDs - the catalog's normalizer resolves both.
    """
    try:
        catalog = registry.get_catalog(framework_id)
    except (FileNotFoundError, KeyError, ValueError) as e:
        # ValueError fires when ``resolve_catalog_path`` cannot find the
        # framework_id in either the user-imported or bundled manifest;
        # FileNotFoundError + KeyError cover late-stage failures during
        # catalog file resolution. All three normalize to 404 from the
        # client's perspective.
        raise api_error(
            404,
            "not_found",
            f"Framework '{framework_id}' not found.",
            resource="framework",
            resource_id=framework_id,
        ) from e

    control = catalog.get_control(control_id)
    if control is None:
        raise api_error(
            404,
            "not_found",
            (
                f"Control '{control_id}' not found in framework '{framework_id}'. "
                f"Try one of: {', '.join(c.id for c in catalog.controls[:5])}..."
            ),
            resource="control",
            resource_id=control_id,
        )
    return control


@router.get(
    "/frameworks/{framework_id}/native-source",
    response_model=NativeBundle,
    responses={
        404: {"model": NativeReadError, "description": "Native source is unavailable."},
        409: {"model": NativeReadError, "description": "The requested native generation is no longer current."},
        422: {"model": NativeReadError, "description": "Invalid framework or exact bundle digest."},
        503: {"model": NativeReadError, "description": "Native source processing failed."},
    },
    openapi_extra={
        "parameters": [
            {
                "name": "bundle_sha256",
                "in": "query",
                "required": True,
                "schema": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            }
        ]
    },
)
async def get_native_source(
    framework_id: str,
    request: Request,
    registry: FrameworkRegistry = Depends(get_registry),
) -> NativeBundle | Response:
    """Return only the complete validated source generation requested by the caller."""
    try:
        with native_operation() as budget:
            if (
                set(request.query_params) != {"bundle_sha256"}
                or len(request.query_params.getlist("bundle_sha256")) != 1
            ):
                raise NativeSourceError()
            selection = NativeReadRequest.model_validate(
                {"framework_id": framework_id, "bundle_sha256": request.query_params["bundle_sha256"]}
            )
            catalog = registry.get_catalog(selection.framework_id)
            bundle = catalog.native_source
            if bundle is None:
                raise NativeSourceError("native_source_unavailable")
            if bundle.bundle_sha256 != selection.bundle_sha256:
                raise NativeSourceError("catalog_generation_changed")
            response = JSONResponse(content=bundle.model_dump(mode="json"))
            budget.check()
            return response
    except NativeSourceError as exc:
        status = {
            "native_source_invalid": 422,
            "native_source_unavailable": 404,
            "catalog_generation_changed": 409,
            "processing_deadline_exceeded": 503,
        }[exc.code]
        return JSONResponse(
            status_code=status, content=NativeReadError.model_validate({"code": exc.code}).model_dump(mode="json")
        )
    except (FileNotFoundError, KeyError):
        return JSONResponse(status_code=404, content={"code": "native_source_unavailable"})
    except ValueError:
        return JSONResponse(status_code=422, content={"code": "native_source_invalid"})
    except OSError:
        return JSONResponse(status_code=503, content={"code": "native_source_unavailable"})
