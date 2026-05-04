"""Model-risk router — model inventory CRUD endpoints (v0.7.10 P0.6).

Surfaces the v0.7.10 P0.6.1 ModelInventory model + model_risk_store
persistence over HTTP under the ``/api/model-risk/models`` prefix.

Endpoints (mirroring the v0.7.9 P0.1.4 TPRM router pattern):

  - ``GET    /api/model-risk/models`` — list models with optional
    skip/limit pagination + tier/methodology/vendor_or_internal filters
  - ``POST   /api/model-risk/models`` — create a new model; server
    fills id / created_at / updated_at / evidentia_version via
    Pydantic default_factory
  - ``GET    /api/model-risk/models/{model_id}`` — fetch single model
  - ``PUT    /api/model-risk/models/{model_id}`` — full-replace
    (preserves id + created_at; refreshes updated_at; auto-recomputes
    next_validation_due if anchor changed and operator did not override)
  - ``DELETE /api/model-risk/models/{model_id}`` — remove from store
  - ``GET    /api/model-risk/models/{model_id}/next-validation-due``
    — compute (without persisting) the next-validation-due date for
    UI previews

Error normalization follows the v0.7.8 F-V08-DAST-3 fix: manual
HTTPException uses status 400 (not 422) for runtime body-content
validation errors so the ``{detail: string}`` response shape matches
the OpenAPI declaration. Pydantic auto-validation 422s (from FastAPI's
request-body parsing) keep their array-shape detail.

SR 11-7 / SR 26-02 / OCC Bulletin 2011-12 / OCC Bulletin 2026-13a
model risk management framework alignment carries over from the
v0.7.10 P0.6.1 schemas.
"""

from __future__ import annotations

from datetime import date

from evidentia_core.model_risk_store import (
    InvalidModelIdError,
    delete_model,
    list_models,
    load_model_by_id,
    save_model,
)
from evidentia_core.models.model_risk import (
    Methodology,
    ModelInventory,
    Provenance,
    Tier,
)
from fastapi import APIRouter, HTTPException, Query

router = APIRouter()


# ── helpers ────────────────────────────────────────────────────────


def _filter_models(
    models: list[ModelInventory],
    tier: str | None,
    methodology: str | None,
    vendor_or_internal: str | None,
) -> list[ModelInventory]:
    # Enum-or-string equality: Pydantic may deserialize enum-valued
    # fields as either Enum instances (during request validation) or
    # raw strings (when loaded from JSON store), depending on the
    # use_enum_values config. Mirroring the v0.7.9 P0.1.4 vendor
    # router pattern, compare against the .value of the enum if it's
    # an Enum, else direct string compare.
    if tier:
        models = [m for m in models if _eq(m.tier, tier)]
    if methodology:
        models = [m for m in models if _eq(m.methodology, methodology)]
    if vendor_or_internal:
        models = [
            m for m in models if _eq(m.vendor_or_internal, vendor_or_internal)
        ]
    return models


def _eq(field_value: object, query_value: str) -> bool:
    """Compare an Enum or str field to a query string."""
    if hasattr(field_value, "value"):
        return bool(getattr(field_value, "value") == query_value)  # noqa: B009
    return bool(field_value == query_value)


# ── endpoints ──────────────────────────────────────────────────────


@router.get("/model-risk/models")
async def list_models_endpoint(
    skip: int = Query(
        0,
        ge=0,
        description="Number of records to skip (pagination offset).",
    ),
    limit: int = Query(
        100,
        ge=1,
        le=1000,
        description="Maximum number of records to return (1-1000).",
    ),
    tier: str | None = Query(
        None,
        description="Filter by tier: tier_1 / tier_2 / tier_3.",
    ),
    methodology: str | None = Query(
        None,
        description=(
            "Filter by methodology: statistical / ml / rules_based / "
            "llm / expert_judgment / hybrid."
        ),
    ),
    vendor_or_internal: str | None = Query(
        None,
        description="Filter by provenance: internal / vendor.",
    ),
) -> dict[str, object]:
    """List models in the inventory.

    Sort order matches `evidentia_core.model_risk_store.list_models`:
    tier (Tier 1 → Tier 3) then name (case-insensitive). Pagination
    is applied AFTER filtering so ``total`` reflects the filter-matched
    count, not the unfiltered store size.
    """
    if tier and tier not in {e.value for e in Tier}:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown tier {tier!r}; valid: "
                f"{sorted(e.value for e in Tier)}"
            ),
        )
    if methodology and methodology not in {e.value for e in Methodology}:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown methodology {methodology!r}; valid: "
                f"{sorted(e.value for e in Methodology)}"
            ),
        )
    if vendor_or_internal and vendor_or_internal not in {
        e.value for e in Provenance
    }:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown vendor_or_internal {vendor_or_internal!r}; "
                f"valid: {sorted(e.value for e in Provenance)}"
            ),
        )

    all_models = list_models()
    filtered = _filter_models(all_models, tier, methodology, vendor_or_internal)
    total = len(filtered)
    page = filtered[skip : skip + limit]
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "models": [m.model_dump(mode="json") for m in page],
    }


@router.post(
    "/model-risk/models", response_model=ModelInventory, status_code=201
)
async def create_model(payload: ModelInventory) -> ModelInventory:
    """Create a new model record.

    Body shape is the full ModelInventory model. Server fills
    ``id`` / ``created_at`` / ``updated_at`` / ``evidentia_version``
    via Pydantic default_factory when the client omits them.
    ``next_validation_due`` is auto-computed from
    ``last_validation_date`` + tier cadence when the client provides
    the former and omits the latter.

    Operates on a `model_copy` of the FastAPI-parsed request body
    rather than mutating the body directly — matches the convention
    from v0.7.9 P0.1 Continuous-review H-3.
    """
    if payload.last_validation_date and payload.next_validation_due is None:
        model = payload.model_copy(
            update={"next_validation_due": payload.compute_next_validation_due()}
        )
    else:
        model = payload.model_copy()
    save_model(model)
    return model


@router.get(
    "/model-risk/models/{model_id}", response_model=ModelInventory
)
async def get_model(model_id: str) -> ModelInventory:
    """Fetch a single model by ID."""
    try:
        model = load_model_by_id(model_id)
    except InvalidModelIdError as exc:
        # Match the v0.7.8 F-V08-DAST-1 widening pattern: shape
        # violations + not-found both normalize to 404 from the
        # client's perspective.
        raise HTTPException(
            status_code=404,
            detail=f"Model {model_id!r} not found.",
        ) from exc
    if model is None:
        raise HTTPException(
            status_code=404,
            detail=f"Model {model_id!r} not found.",
        )
    return model


@router.put(
    "/model-risk/models/{model_id}", response_model=ModelInventory
)
async def replace_model(
    model_id: str, payload: ModelInventory
) -> ModelInventory:
    """Replace a model record by ID (full update).

    Preserves the original ``id`` + ``created_at`` even if the
    client supplies different values — the path parameter is
    authoritative for identity, and ``created_at`` is immutable
    once the record exists. ``updated_at`` is refreshed by
    `model_risk_store.save_model` regardless.

    Re-runs the auto-cadence helper if `last_validation_date` is set
    and the client did NOT supply an explicit `next_validation_due`
    — operator override always wins.
    """
    try:
        existing = load_model_by_id(model_id)
    except InvalidModelIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Model {model_id!r} not found.",
        ) from exc
    if existing is None:
        raise HTTPException(
            status_code=404,
            detail=f"Model {model_id!r} not found.",
        )
    update: dict[str, object] = {
        "id": existing.id,
        "created_at": existing.created_at,
    }
    # Operator-explicit `next_validation_due` always wins; only
    # auto-recompute if anchor exists AND client omitted it.
    if payload.last_validation_date and payload.next_validation_due is None:
        update["next_validation_due"] = payload.compute_next_validation_due()
    model = payload.model_copy(update=update)
    save_model(model)
    return model


@router.delete("/model-risk/models/{model_id}", status_code=204)
async def delete_model_endpoint(model_id: str) -> None:
    """Delete a model by ID.

    Returns 204 on successful delete, 404 on shape-violation OR
    well-formed-unknown ID. No body in either case (HEAD-like
    semantics for DELETE).
    """
    try:
        removed = delete_model(model_id)
    except InvalidModelIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Model {model_id!r} not found.",
        ) from exc
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"Model {model_id!r} not found.",
        )


# ── helper endpoint: cadence preview ──────────────────────────────


@router.get("/model-risk/models/{model_id}/next-validation-due")
async def preview_next_validation_due(
    model_id: str,
) -> dict[str, str | None]:
    """Compute (without persisting) the next validation due date.

    Returns ``{"next_validation_due": "<YYYY-MM-DD>"}`` or
    ``{"next_validation_due": null}`` if the model has no
    ``last_validation_date`` anchor. Useful for UI previews that
    want to show "if you set the validation date to today, your
    next validation would be due on…".
    """
    try:
        model = load_model_by_id(model_id)
    except InvalidModelIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Model {model_id!r} not found.",
        ) from exc
    if model is None:
        raise HTTPException(
            status_code=404,
            detail=f"Model {model_id!r} not found.",
        )
    computed: date | None = model.compute_next_validation_due()
    return {
        "next_validation_due": computed.isoformat() if computed else None,
    }
