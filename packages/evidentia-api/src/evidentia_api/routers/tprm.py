"""TPRM router — vendor inventory CRUD endpoints (v0.7.9 P0.1.4).

Surfaces the v0.7.9 P0.1.1 Vendor model + P0.1.2 vendor_store
persistence over HTTP under the ``/api/tprm/vendors`` prefix.

Endpoints (resolved per plan §17.B1-B4):

  - ``GET    /api/tprm/vendors`` — list vendors with optional
    skip/limit pagination + criticality_tier/type filters
  - ``POST   /api/tprm/vendors`` — create a new vendor; server
    fills id / created_at / updated_at / evidentia_version via
    Pydantic default_factory
  - ``GET    /api/tprm/vendors/{vendor_id}`` — fetch single vendor
  - ``PUT    /api/tprm/vendors/{vendor_id}`` — full-replace
    (preserves id + created_at; refreshes updated_at)
  - ``DELETE /api/tprm/vendors/{vendor_id}`` — remove from store

Error normalization follows the v0.7.8 F-V08-DAST-3 fix
(plan §17.B4): manual HTTPException uses status 400 (not 422)
for runtime body-content validation errors so the
``{detail: string}`` response shape matches the OpenAPI
declaration. Pydantic auto-validation 422s (from FastAPI's
request-body parsing) keep their array-shape detail.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date

from evidentia_core.audit import EventOutcome, get_logger
from evidentia_core.models.tprm import (
    CriticalityTier,
    EvidenceRef,
    Vendor,
    VendorType,
)
from evidentia_core.tprm.concentration import (
    SUPPORTED_DIMENSIONS,
    ConcentrationReport,
    compute_concentration,
)
from evidentia_core.tprm.questionnaire import (
    Questionnaire,
    QuestionnaireFormat,
    generate_questionnaire,
)
from evidentia_core.vendor_store import (
    InvalidVendorIdError,
    delete_vendor,
    list_vendors,
    load_vendor_by_id,
    save_vendor,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from evidentia_api.rbac_dependency import require_role

router = APIRouter()
_log = get_logger("evidentia.api.tprm")

# Audit action string. No TPRM-specific EventAction enum member exists in
# evidentia_core.audit.events, and this router may not edit that file
# (strict scope). The audit logger's `action` parameter is typed
# `EventAction | str`, so this stable ECS-style dotted string is a
# type-clean fit, consistent with the events.py namespace convention
# (``evidentia.<domain>.<verb>``) and the governance router precedent.
# A future refactor can promote it to an enum member.
_ACTION_DD_QUESTIONNAIRE_INGESTED = "evidentia.tprm.dd_questionnaire_ingested"


# ── helpers ────────────────────────────────────────────────────────


def _filter_vendors(
    vendors: list[Vendor],
    criticality_tier: str | None,
    type_: str | None,
) -> list[Vendor]:
    if criticality_tier:
        vendors = [v for v in vendors if v.criticality_tier == criticality_tier]
    if type_:
        vendors = [v for v in vendors if v.type == type_]
    return vendors


# ── endpoints ──────────────────────────────────────────────────────


@router.get("/tprm/vendors")
async def list_vendors_endpoint(
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
    criticality_tier: str | None = Query(
        None,
        description=(
            "Filter by criticality tier: critical / high / medium / low."
        ),
    ),
    type_: str | None = Query(
        None,
        alias="type",
        description=(
            "Filter by vendor type: saas / subservice_org / contractor / "
            "data_processor / cloud_provider / open_source."
        ),
    ),
) -> dict[str, object]:
    """List vendors in the inventory.

    Sort order matches `evidentia_core.vendor_store.list_vendors`:
    criticality (critical → low) then name (case-insensitive).
    Pagination is applied AFTER filtering so ``total`` reflects
    the filter-matched count, not the unfiltered store size.
    """
    if criticality_tier and criticality_tier not in {
        e.value for e in CriticalityTier
    }:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown criticality_tier {criticality_tier!r}; valid: "
                f"{sorted(e.value for e in CriticalityTier)}"
            ),
        )
    if type_ and type_ not in {e.value for e in VendorType}:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown type {type_!r}; valid: "
                f"{sorted(e.value for e in VendorType)}"
            ),
        )

    all_vendors = list_vendors()
    filtered = _filter_vendors(all_vendors, criticality_tier, type_)
    total = len(filtered)
    page = filtered[skip : skip + limit]
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "vendors": [v.model_dump(mode="json") for v in page],
    }


@router.post("/tprm/vendors", response_model=Vendor, status_code=201)
async def create_vendor(payload: Vendor) -> Vendor:
    """Create a new vendor record.

    Body shape is the full Vendor model (resolved per §17.B2).
    Server fills ``id`` / ``created_at`` / ``updated_at`` /
    ``evidentia_version`` via Pydantic default_factory when the
    client omits them. ``next_review_due`` is auto-computed from
    ``last_due_diligence_review`` + criticality cadence when the
    client provides the former and omits the latter.

    Operates on a `model_copy` of the FastAPI-parsed request body
    rather than mutating the body directly — closes v0.7.9 P0.1
    Continuous-review H-3 (FastAPI anti-pattern; matches the
    convention used in the rest of `evidentia-api`).
    """
    if payload.last_due_diligence_review and payload.next_review_due is None:
        vendor = payload.model_copy(
            update={"next_review_due": payload.compute_next_review_due()}
        )
    else:
        vendor = payload.model_copy()
    save_vendor(vendor)
    return vendor


@router.get("/tprm/vendors/{vendor_id}", response_model=Vendor)
async def get_vendor(vendor_id: str) -> Vendor:
    """Fetch a single vendor by ID."""
    try:
        vendor = load_vendor_by_id(vendor_id)
    except InvalidVendorIdError as exc:
        # Match the v0.7.8 F-V08-DAST-1 widening pattern: shape
        # violations + not-found both normalize to 404 from the
        # client's perspective.
        raise HTTPException(
            status_code=404,
            detail=f"Vendor {vendor_id!r} not found.",
        ) from exc
    if vendor is None:
        raise HTTPException(
            status_code=404,
            detail=f"Vendor {vendor_id!r} not found.",
        )
    return vendor


@router.put("/tprm/vendors/{vendor_id}", response_model=Vendor)
async def replace_vendor(vendor_id: str, payload: Vendor) -> Vendor:
    """Replace a vendor record by ID (full update).

    Preserves the original ``id`` + ``created_at`` even if the
    client supplies different values — the path parameter is
    authoritative for identity, and ``created_at`` is immutable
    once the record exists. ``updated_at`` is refreshed by
    `vendor_store.save_vendor` regardless.
    """
    try:
        existing = load_vendor_by_id(vendor_id)
    except InvalidVendorIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Vendor {vendor_id!r} not found.",
        ) from exc
    if existing is None:
        raise HTTPException(
            status_code=404,
            detail=f"Vendor {vendor_id!r} not found.",
        )
    # Authoritatively pin id + created_at via `model_copy` rather
    # than mutating the FastAPI-parsed `payload` directly — closes
    # v0.7.9 P0.1 Continuous-review H-3. Refresh `next_review_due`
    # if the anchor changed (uses the about-to-be-saved values, not
    # the existing record's, so a client update to either
    # `criticality_tier` or `last_due_diligence_review` recomputes
    # correctly).
    update: dict[str, object] = {
        "id": existing.id,
        "created_at": existing.created_at,
    }
    if payload.last_due_diligence_review:
        update["next_review_due"] = payload.compute_next_review_due()
    vendor = payload.model_copy(update=update)
    save_vendor(vendor)
    return vendor


@router.delete("/tprm/vendors/{vendor_id}", status_code=204)
async def delete_vendor_endpoint(vendor_id: str) -> None:
    """Delete a vendor by ID.

    Returns 204 on successful delete, 404 on shape-violation OR
    well-formed-unknown ID. No body in either case (HEAD-like
    semantics for DELETE).
    """
    try:
        removed = delete_vendor(vendor_id)
    except InvalidVendorIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Vendor {vendor_id!r} not found.",
        ) from exc
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"Vendor {vendor_id!r} not found.",
        )


# ── helper endpoint: cadence preview ──────────────────────────────


@router.get("/tprm/vendors/{vendor_id}/next-review-due")
async def preview_next_review_due(vendor_id: str) -> dict[str, str | None]:
    """Compute (without persisting) the next review due date.

    Returns ``{"next_review_due": "<YYYY-MM-DD>"}`` or
    ``{"next_review_due": null}`` if the vendor has no
    ``last_due_diligence_review`` anchor. Useful for UI previews
    that want to show "if you set the DD review to today, your
    next review would be on…".
    """
    try:
        vendor = load_vendor_by_id(vendor_id)
    except InvalidVendorIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Vendor {vendor_id!r} not found.",
        ) from exc
    if vendor is None:
        raise HTTPException(
            status_code=404,
            detail=f"Vendor {vendor_id!r} not found.",
        )
    computed: date | None = vendor.compute_next_review_due()
    return {
        "next_review_due": computed.isoformat() if computed else None,
    }


# ── concentration-risk reporting (v0.7.9 P0.3) ─────────────────────


@router.get("/tprm/concentration", response_model=ConcentrationReport)
async def concentration(
    by: str = Query(
        "region,cloud-provider",
        description=(
            "Comma-separated dimensions to aggregate by. Valid: "
            f"{', '.join(sorted(SUPPORTED_DIMENSIONS))}."
        ),
    ),
    threshold: float | None = Query(
        None,
        ge=0.0,
        le=100.0,
        description=(
            "Concentration percentage (0.0-100.0). Per-value rows whose "
            "vendor share meets-or-exceeds this get flagged. Omit for "
            "unflagged distribution."
        ),
    ),
) -> ConcentrationReport:
    """Concentration-risk report across the vendor inventory.

    Aggregates the v0.7.9 P0.1 vendor inventory across configurable
    dimensions to surface concentration risk per FFIEC + OCC Bulletin
    2013-29 + FRB SR 13-19 expectations. Returns a JSON
    :class:`ConcentrationReport`. For HTML / CSV rendering, use the
    `evidentia tprm concentration-report --format html|csv` CLI
    surface — REST is JSON-only by design.
    """
    dimensions = [d.strip() for d in by.split(",") if d.strip()]
    if not dimensions:
        raise HTTPException(
            status_code=400,
            detail="`by` must list at least one dimension.",
        )
    bad = [d for d in dimensions if d not in SUPPORTED_DIMENSIONS]
    if bad:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported dimension(s) {bad!r}; "
                f"valid: {sorted(SUPPORTED_DIMENSIONS)}"
            ),
        )
    vendors = list_vendors()
    return compute_concentration(vendors, dimensions, threshold=threshold)


# ── DD-questionnaire generation (v0.7.9 P0.2) ─────────────────────


@router.post(
    "/tprm/vendors/{vendor_id}/dd-questionnaire",
    response_model=Questionnaire,
    status_code=201,
)
async def generate_dd_questionnaire(
    vendor_id: str,
    format: str = Query(
        "evidentia-generic",
        description=(
            "Questionnaire framework: 'evidentia-generic' (FFIEC-aligned "
            "Apache-2.0 baseline; ~20 questions) or 'caiq-lite' (CSA "
            "CAIQ v4.0.3 CC BY 4.0 representative subset; ~25 "
            "questions). 'sig' / 'sig-lite' are stubs that 501 today "
            "— Shared Assessments paywalls the question content."
        ),
    ),
) -> Questionnaire:
    """Generate a pre-filled DD questionnaire for a vendor.

    Pre-fills vendor metadata (name / type / criticality tier /
    contract dates / region / regulatory classification / 4th-party
    disclosures) so the receiving party only sees control questions.
    Response shape is the full :class:`Questionnaire` Pydantic model.
    For CSV rendering, use the
    `evidentia tprm dd-questionnaire generate --output-format csv`
    CLI surface — REST is JSON-only by design.
    """
    try:
        fmt = QuestionnaireFormat(format)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown questionnaire format {format!r}; valid: "
                f"{[f.value for f in QuestionnaireFormat]}"
            ),
        ) from exc

    try:
        vendor = load_vendor_by_id(vendor_id)
    except InvalidVendorIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Vendor {vendor_id!r} not found.",
        ) from exc
    if vendor is None:
        raise HTTPException(
            status_code=404,
            detail=f"Vendor {vendor_id!r} not found.",
        )

    try:
        return generate_questionnaire(vendor, fmt)
    except NotImplementedError as exc:
        # SIG / SIG-Lite stubs — clear 501 with the BYO-template
        # narrative in the detail.
        raise HTTPException(status_code=501, detail=str(exc)) from exc


# ── DD-questionnaire ingest (v0.10.12) ────────────────────────────


class CompletedQuestionnaireIngest(BaseModel):
    """Request body for the DD-questionnaire ingest endpoint.

    Carries the completed (or partially-completed) questionnaire
    content the API caller posts back after a vendor returns it. The
    HTTP surface receives structured JSON directly (the CLI's
    ``parse_completed_questionnaire`` file-parsing path has no
    equivalent need here — the body IS the parsed content).

    ``responses`` is the per-question answer map keyed by question.id
    (e.g. ``EVG-GOV-01``). An empty map is a malformed ingest (nothing
    to record) and the endpoint rejects it with a 400.
    """

    questionnaire_id: str | None = Field(
        default=None,
        description=(
            "UUID from the originating Questionnaire (when the caller "
            "carries it forward from the generate step). Recorded on the "
            "evidence reference for correlation; not required."
        ),
    )
    format: str | None = Field(
        default=None,
        description=(
            "Questionnaire framework the responses correspond to "
            "(e.g. 'evidentia-generic' / 'caiq-lite'). Free-text; "
            "recorded on the evidence reference for context."
        ),
    )
    responses: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Per-question vendor responses keyed by question.id. Empty "
            "string == 'no response'. At least one entry is required — "
            "an empty map is rejected as a malformed ingest (400)."
        ),
    )
    source_path: str | None = Field(
        default=None,
        description=(
            "Optional provenance label — e.g. the filename the operator "
            "received the completed questionnaire as. Recorded on the "
            "evidence reference's notes for audit context."
        ),
    )


@router.post(
    "/tprm/vendors/{vendor_id}/dd-questionnaire/ingest",
    response_model=Vendor,
    dependencies=[require_role("write")],
)
async def ingest_dd_questionnaire(
    vendor_id: str, payload: CompletedQuestionnaireIngest
) -> Vendor:
    """Ingest a completed DD questionnaire into a vendor record.

    Records the completed-questionnaire responses as an
    :class:`EvidenceRef` appended to ``vendor.evidence_refs`` and
    persists the mutated vendor — the persistence-to-vendor phase the
    v0.7.9 ``evidentia tprm dd-questionnaire ingest`` CLI verb
    deferred (the CLI parses + correlates, then prints for review).

    Local store mutation only — no credentials, no network. Returns
    the updated :class:`Vendor`.

    Error contract (matches the rest of this router):

      - 404 on shape-violation OR well-formed-unknown ``vendor_id``
        (F-V08-DAST-1 widening pattern).
      - 400 (string detail, F-V08-DAST-3 invariant) when the
        questionnaire content is malformed — i.e. ``responses`` is
        empty (nothing to ingest). Pydantic auto-validation 422s
        (wrong-typed body) keep their array-shape detail.
      - 403 when an RBAC policy denies the ``write`` action.
    """
    if not payload.responses:
        raise HTTPException(
            status_code=400,
            detail=(
                "Malformed questionnaire content: `responses` is empty. "
                "Provide at least one per-question response keyed by "
                "question.id (e.g. {'EVG-GOV-01': 'Yes'})."
            ),
        )

    try:
        vendor = load_vendor_by_id(vendor_id)
    except InvalidVendorIdError as exc:
        raise HTTPException(
            status_code=404,
            detail=f"Vendor {vendor_id!r} not found.",
        ) from exc
    if vendor is None:
        raise HTTPException(
            status_code=404,
            detail=f"Vendor {vendor_id!r} not found.",
        )

    answered = sum(1 for v in payload.responses.values() if v)
    title = "Completed DD questionnaire"
    if payload.format:
        title = f"{title} ({payload.format})"
    note_bits = [
        f"{len(payload.responses)} response(s); {answered} answered",
    ]
    if payload.questionnaire_id:
        note_bits.append(f"questionnaire_id={payload.questionnaire_id}")
    if payload.source_path:
        note_bits.append(f"source={payload.source_path}")
    # EvidenceRef's two-mode contract requires a paired sha256 whenever
    # file_path is set (tamper detection). The ingested responses ARE the
    # evidence content here, so hash their canonical JSON serialization —
    # a genuine digest the operator can later recompute to detect drift.
    digest = hashlib.sha256(
        json.dumps(payload.responses, sort_keys=True).encode("utf-8")
    ).hexdigest()
    evidence = EvidenceRef(
        title=title,
        file_path=payload.source_path or "(ingested via API)",
        sha256=digest,
        notes="; ".join(note_bits),
    )

    # Append to a model_copy rather than mutating the FastAPI-parsed
    # vendor in place — matches the H-3 anti-pattern fix used across
    # this router (create_vendor / replace_vendor).
    vendor = vendor.model_copy(
        update={"evidence_refs": [*vendor.evidence_refs, evidence]}
    )
    save_vendor(vendor)

    _log.info(
        action=_ACTION_DD_QUESTIONNAIRE_INGESTED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Completed DD questionnaire ingested via API for vendor "
            f"{vendor.name}"
        ),
        evidentia={
            "vendor_id": vendor.id,
            "questionnaire_id": payload.questionnaire_id,
            "format": payload.format,
            "response_count": len(payload.responses),
            "answered_count": answered,
        },
    )
    return vendor
