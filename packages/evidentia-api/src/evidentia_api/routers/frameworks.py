"""Frameworks router — list, inspect, and drill into the 82 bundled catalogs.

These endpoints feed the GUI's Frameworks browser page:
- ``GET /api/frameworks`` — list all (optionally filtered by tier/category)
- ``GET /api/frameworks/{id}`` — framework metadata + full control list
- ``GET /api/frameworks/{id}/controls/{control_id}`` — single control detail
"""

from __future__ import annotations

from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.models.catalog import CatalogControl, ControlCatalog
from fastapi import APIRouter, Depends, Query

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

    Matches :meth:`FrameworkRegistry.list_frameworks` exactly — callers can
    expect the stable dict shape documented there.
    """
    entries = registry.list_frameworks(tier=tier, category=category)
    return {"total": len(entries), "frameworks": entries}


@router.get(
    "/frameworks/{framework_id}",
    response_model=ControlCatalog,
    responses=error_responses(
        {404: "Unknown ``framework_id`` (``error: not_found``)."}
    ),
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
            404: (
                "Unknown ``framework_id`` or ``control_id`` "
                "(``error: not_found``)."
            ),
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
    (``ac-2.1``) IDs — the catalog's normalizer resolves both.
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
