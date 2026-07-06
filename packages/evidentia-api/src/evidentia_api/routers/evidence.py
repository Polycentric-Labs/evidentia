"""Evidence-artifact lineage router — WORM-store REST surface (v0.10.12).

Surfaces the v0.9.6 WORM-enforced evidence store
(:mod:`evidentia_core.evidence_store`) over HTTP under the ``/api``
prefix the app applies at registration time. Mirrors the v0.9.6 P2
``evidentia evidence`` CLI verbs (``save`` / ``history`` / ``show``)
one-for-one, and inherits the poam router's conventions: bare-segment
paths (``@router.post("/evidence")``), ``evidentia_core.audit`` emits,
``Invalid*IdError`` → 404 normalization, and the list envelope shape.

Endpoints:

  - ``POST /evidence`` — persist a new lineage root OR a new version
    in an existing chain. Body = the full :class:`EvidenceArtifact`
    model (``extra="forbid"`` inherited from EvidentiaModel). Returns
    a summary dict mirroring the CLI ``save`` output. WORM collisions
    → 409 with the structured ``{error: worm_violation, lineage_id,
    attempted_version, next_version, message}`` detail; invalid
    lineage id → 404.
  - ``GET /evidence/{lineage_id}/history`` — walk a lineage chain,
    returning every persisted version sorted by version ascending
    (the store already sorts). Invalid lineage id → 404.
  - ``GET /evidence/{lineage_id}/versions/{version}`` — render one
    specific version; 404 when the version is absent OR the lineage
    id is malformed.

RBAC posture: mirrors the CLI's ``@require_role_cli`` gates on these
exact verbs (``save`` = ``write``; ``history`` / ``show`` = ``read``).
The default policy is permissive (anonymous passes) — RBAC only bites
when an operator configures ``EVIDENTIA_RBAC_POLICY_FILE``.

DO NOT call :meth:`EvidenceArtifact.compute_hash` server-side — the
CLI does not, and parity is the contract.
"""

from __future__ import annotations

from typing import Any

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.evidence_store import (
    EvidenceWORMViolation,
    InvalidEvidenceIdError,
    list_lineage,
    load_evidence_version,
    save_evidence,
)
from evidentia_core.models.evidence import EvidenceArtifact
from fastapi import APIRouter, Path

from evidentia_api.errors import (
    RBAC_DENIED_403,
    api_error,
    error_responses,
)
from evidentia_api.rbac_dependency import require_role

router = APIRouter()
_log = get_logger("evidentia.api.evidence")


# ── save ───────────────────────────────────────────────────────────


@router.post(
    "/evidence",
    status_code=201,
    dependencies=[require_role("write")],
    responses=error_responses(
        {
            403: RBAC_DENIED_403,
            404: "Malformed lineage id (``error: not_found``).",
            409: (
                "WORM collision — the version already exists "
                "(``error: worm_violation``); ``detail`` carries the "
                "canonical ``next_version`` recovery hint."
            ),
        }
    ),
)
async def save_evidence_artifact(
    payload: EvidenceArtifact,
) -> dict[str, Any]:
    """Persist an evidence artifact (new lineage or new version).

    Body shape is the full :class:`EvidenceArtifact` model. For a new
    lineage, leave ``lineage_id`` + ``predecessor_id`` unset and
    ``version=1`` (the defaults). For a new version in an existing
    chain, set ``lineage_id`` to the chain root + ``predecessor_id``
    to the prior version's ``id`` + ``version=N+1`` (use
    :meth:`EvidenceArtifact.new_version` client-side to construct it).

    Returns a summary dict mirroring the CLI ``save`` output. WORM
    enforcement: re-saving a persisted version raises
    :class:`EvidenceWORMViolation` → HTTP 409 with the structured
    ``worm_violation`` detail carrying the canonical ``next_version``
    recovery hint. A malformed lineage id → 404.
    """
    artifact = payload.model_copy()
    try:
        path = save_evidence(artifact)
    except EvidenceWORMViolation as exc:
        _log.warning(
            action=EventAction.EVIDENCE_WORM_VIOLATION_BLOCKED,
            outcome=EventOutcome.FAILURE,
            message=str(exc),
            evidentia={
                "lineage_id": exc.lineage_id,
                "attempted_version": exc.attempted_version,
                "next_version": exc.next_version,
            },
        )
        raise api_error(
            409,
            "worm_violation",
            str(exc),
            lineage_id=exc.lineage_id,
            attempted_version=exc.attempted_version,
            next_version=exc.next_version,
        ) from exc
    except InvalidEvidenceIdError as exc:
        raise api_error(
            404, "not_found", str(exc), resource="evidence_lineage"
        ) from exc

    _log.info(
        action=EventAction.EVIDENCE_VERSION_PERSISTED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Persisted evidence v{artifact.version} for lineage "
            f"{artifact.effective_lineage_id} via API"
        ),
        evidentia={
            "artifact_id": artifact.id,
            "lineage_id": artifact.effective_lineage_id,
            "version": artifact.version,
            "predecessor_id": artifact.predecessor_id,
            "path": str(path),
        },
    )
    # The on-disk store path is deliberately omitted from the HTTP
    # response: the REST surface is a different trust boundary than the
    # local CLI, and leaking the absolute evidence-store path would
    # disclose the server filesystem layout to API clients. The path is
    # still recorded in the server-side audit event above for operators.
    return {
        "artifact_id": artifact.id,
        "lineage_id": artifact.effective_lineage_id,
        "version": artifact.version,
        "predecessor_id": artifact.predecessor_id,
    }


# ── history ────────────────────────────────────────────────────────


@router.get(
    "/evidence/{lineage_id}/history",
    dependencies=[require_role("read")],
    responses=error_responses(
        {
            403: RBAC_DENIED_403,
            404: "Malformed lineage id (``error: not_found``).",
        }
    ),
)
async def get_evidence_history(lineage_id: str) -> dict[str, Any]:
    """Walk a lineage chain — every persisted version, sorted ascending.

    A well-formed but unknown lineage id returns an empty envelope
    (``total=0``). A malformed lineage id → 404 (shape-violation
    normalized per the poam/TPRM precedent).
    """
    try:
        artifacts = list_lineage(lineage_id)
    except InvalidEvidenceIdError as exc:
        raise api_error(
            404,
            "not_found",
            f"Lineage {lineage_id!r} not found.",
            resource="evidence_lineage",
            resource_id=lineage_id,
        ) from exc

    _log.info(
        action=EventAction.EVIDENCE_LINEAGE_QUERIED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Queried lineage {lineage_id} ({len(artifacts)} versions) "
            f"via API"
        ),
        evidentia={
            "lineage_id": lineage_id,
            "version_count": len(artifacts),
        },
    )
    return {
        "total": len(artifacts),
        "items": [a.model_dump(mode="json") for a in artifacts],
    }


# ── show ───────────────────────────────────────────────────────────


@router.get(
    "/evidence/{lineage_id}/versions/{version}",
    response_model=EvidenceArtifact,
    dependencies=[require_role("read")],
    responses=error_responses(
        {
            403: RBAC_DENIED_403,
            404: (
                "Malformed lineage id OR no such version "
                "(``error: not_found``)."
            ),
        }
    ),
)
async def get_evidence_version(
    lineage_id: str,
    version: int = Path(ge=1, description="Sequence number within the chain (>=1)."),
) -> EvidenceArtifact:
    """Render one specific version of a lineage chain.

    404 when the well-formed lineage id + version has no record on
    disk OR the lineage id is malformed.
    """
    try:
        artifact = load_evidence_version(lineage_id, version)
    except InvalidEvidenceIdError as exc:
        raise api_error(
            404,
            "not_found",
            f"Lineage {lineage_id!r} not found.",
            resource="evidence_lineage",
            resource_id=lineage_id,
        ) from exc

    if artifact is None:
        raise api_error(
            404,
            "not_found",
            f"No v{version} found for lineage {lineage_id!r}.",
            resource="evidence_version",
            resource_id=lineage_id,
            version=version,
        )

    _log.info(
        action=EventAction.EVIDENCE_LINEAGE_QUERIED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Loaded v{version} of lineage {lineage_id} (artifact "
            f"{artifact.id}) via API"
        ),
        evidentia={
            "lineage_id": lineage_id,
            "version": version,
            "artifact_id": artifact.id,
        },
    )
    return artifact
