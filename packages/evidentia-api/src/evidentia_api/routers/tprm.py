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

import json
import tempfile
from datetime import date
from pathlib import Path

from evidentia_core.models.tprm import (
    CriticalityTier,
    Vendor,
    VendorType,
)
from evidentia_core.tprm.concentration import (
    SUPPORTED_DIMENSIONS,
    ConcentrationReport,
    compute_concentration,
)
from evidentia_core.tprm.questionnaire import (
    CompletedQuestionnaire,
    Questionnaire,
    QuestionnaireFormat,
    generate_questionnaire,
    parse_completed_questionnaire,
)
from evidentia_core.vendor_store import (
    InvalidVendorIdError,
    delete_vendor,
    list_vendors,
    load_vendor_by_id,
    save_vendor,
)
from fastapi import APIRouter, Body, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter()


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
    try:
        save_vendor(vendor)
    except (InvalidVendorIdError, ValueError) as exc:
        # A client-supplied empty/malformed id must be a 422, not an unhandled
        # 500 (F-V1012-S4-1; mirrors the GET/PUT paths in this router).
        raise HTTPException(status_code=422, detail=str(exc)) from exc
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


class DDQuestionnaireIngestResult(BaseModel):
    """Correlation result returned by the DD-questionnaire ingest endpoint.

    Mirrors the ``evidentia tprm dd-questionnaire ingest`` CLI verb's
    ``--output-format json`` shape: the parsed responses (keyed by
    question.id) correlated to a resolved vendor, plus the carry-forward
    context (questionnaire id / format) and the ingest timestamp. Like
    the CLI, this is PARSE-ONLY — persistence to ``vendor.evidence_refs``
    stays deferred, so no vendor mutation occurs.
    """

    vendor: dict[str, str] = Field(
        description=(
            "The resolved vendor the questionnaire correlated to: "
            "``{'id': ..., 'name': ...}``. Mirrors the CLI's vendor block."
        ),
    )
    questionnaire_id: str | None = Field(
        default=None,
        description=(
            "UUID carried forward from the originating Questionnaire's "
            "``id`` field, when the posted document includes it."
        ),
    )
    format: str | None = Field(
        default=None,
        description=(
            "Questionnaire framework parsed from the document's ``format`` "
            "field (e.g. 'evidentia-generic' / 'caiq-lite'); null when "
            "absent or unrecognized."
        ),
    )
    responses: dict[str, str] = Field(
        description=(
            "Per-question vendor responses correlated by question.id "
            "(e.g. ``EVG-GOV-01``). Empty string == 'no response'."
        ),
    )
    ingested_at: str = Field(
        description="ISO-8601 timestamp the parse/correlation ran.",
    )


@router.post(
    "/tprm/vendors/{vendor_id}/dd-questionnaire/ingest",
    response_model=DDQuestionnaireIngestResult,
)
async def ingest_dd_questionnaire(
    vendor_id: str,
    document: dict[str, object] = Body(
        ...,
        description=(
            "The completed questionnaire document in the canonical "
            "Questionnaire shape — a top-level ``questions`` array whose "
            "entries carry an ``id`` + a ``vendor_response`` value, plus "
            "optional top-level ``id`` (questionnaire UUID) and "
            "``format``. This is exactly the JSON the "
            "``evidentia tprm dd-questionnaire generate --output-format "
            "json`` step emits, returned by the vendor with responses "
            "filled in."
        ),
    ),
) -> DDQuestionnaireIngestResult:
    """Parse + correlate a completed DD questionnaire (parse-only).

    Matches the ``evidentia tprm dd-questionnaire ingest`` CLI verb
    exactly: PARSES the posted completed-questionnaire document and
    CORRELATES the responses to the vendor record, then RETURNS the
    correlation result. It does NOT mutate or save the vendor and does
    NOT create an :class:`EvidenceRef` — persistence stays deferred,
    matching the CLI's documented scope (the CLI parses + correlates,
    then prints for review).

    The core :func:`parse_completed_questionnaire` is file-based
    (extension-dispatched). Over HTTP the body IS the document, so it is
    written to an ephemeral ``.json`` temp file, parsed, and the temp
    file is removed in a ``finally`` — no path/secret leakage and no
    persistent on-disk state.

    Local parse only — no credentials, no network. Returns the parsed
    :class:`DDQuestionnaireIngestResult`.

    Error contract (matches the rest of this router):

      - 404 on shape-violation OR well-formed-unknown ``vendor_id``
        (F-V08-DAST-1 widening pattern). The endpoint is vendor-scoped.
      - 400 (string detail, F-V08-DAST-3 invariant) when the
        questionnaire content is unparseable or correlates to no
        responses (nothing to ingest). Pydantic auto-validation 422s
        (wrong-typed body) keep their array-shape detail.

    No ``require_role("write")`` gate: a parse is a read-style operation
    (no vendor mutation), so it is open like the other read endpoints on
    this router.
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

    # The core parser is file-based + extension-dispatched. Write the
    # posted document to an ephemeral .json temp file, parse, and clean
    # up — the temp path never escapes this handler (no leakage).
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
            encoding="utf-8",
        ) as tmp:
            json.dump(document, tmp)
            tmp_path = Path(tmp.name)
        completed: CompletedQuestionnaire = parse_completed_questionnaire(
            tmp_path
        )
    except (ValueError, ImportError) as exc:
        # Unparseable / malformed questionnaire content. Use a generic
        # string detail (no path/internal leakage; F-V08-DAST-3 shape).
        raise HTTPException(
            status_code=400,
            detail=(
                "Malformed questionnaire content: could not parse the "
                "posted document. Expected the canonical Questionnaire "
                "shape with a `questions` array of "
                "{id, vendor_response} entries."
            ),
        ) from exc
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)

    if not completed.responses:
        raise HTTPException(
            status_code=400,
            detail=(
                "Malformed questionnaire content: no per-question "
                "responses correlated. Provide a `questions` array whose "
                "entries carry an `id` and a `vendor_response` "
                "(e.g. {'id': 'EVG-GOV-01', 'vendor_response': 'Yes'})."
            ),
        )

    fmt = completed.format
    fmt_value = (
        fmt.value if isinstance(fmt, QuestionnaireFormat) else fmt
    )

    return DDQuestionnaireIngestResult(
        vendor={"id": vendor.id, "name": vendor.name},
        questionnaire_id=completed.questionnaire_id,
        format=fmt_value,
        responses=completed.responses,
        ingested_at=completed.ingested_at.isoformat(),
    )
