"""Structured HTTP error convention for the Evidentia REST API.

Every deliberate ``HTTPException`` raised by an Evidentia router
carries a machine-readable ``detail`` object (2026-07-06 error-shape
convergence; generalizes the v0.9.5 ``rbac_denied`` 403 and the
2026-07-06 DAST follow-up ``unknown_tier`` 400)::

    {"detail": {"error": "<snake_case_key>", ..., "message": "<human text>"}}

``error`` is a stable snake_case key clients can dispatch on;
``message`` is the human-readable explanation (the pre-convergence
bare-string text lives here verbatim). Site-specific context fields
sit between them (e.g. ``next_version`` on WORM 409s, ``valid`` on
enum-filter 400s).

Relationship to the v0.7.8 F-V08-DAST-3 invariant: the status-code
normalization is UNCHANGED — manual body-content validation is 400
(never Pydantic's 422), invalid-id-shape normalizes per-router to
400/404. Only the ``detail`` payload evolved from a bare string to
the structured object above; FastAPI/Pydantic request-validation 422s
keep their array-shape ``detail``, so the manual-vs-automatic
discrimination survives (object vs array).

Error-key registry (keep this the single source of truth — reuse an
existing key before minting a new one):

===========================  ==========================================
Key                          Meaning (typical status)
===========================  ==========================================
``invalid_id``               Malformed resource identifier (400)
``not_found``                Resource does not exist (404)
``unknown_<field>``          Enum/filter value outside the valid set
                             (400); context: ``<field>``, ``valid``
``missing_field``            Required body key absent (400); context:
                             ``field``
``invalid_field``            Body/query field present but invalid
                             (400); context: ``field``
``invalid_body``             Body-level semantic/domain validation
                             failure (400, or manual 422)
``unsupported_format``       Requested format not supported (400);
                             context: ``format``, ``supported``
``idempotency_key_conflict`` Idempotency-key reuse with a different
                             body (409)
``already_exists``           Duplicate creation without an explicit
                             force/overwrite flag (400)
``worm_violation``           Evidence WORM version collision (409);
                             context: ``lineage_id``, ``next_version``
``verification_failed``      Signed-artifact verification failed (400)
``feature_unavailable``      Optional dependency/extra not installed
                             or subsystem not configured (400/500/503)
``credentials_missing``      Server-side credential env var not set
                             (503); context: ``env_var``
``upstream_error``           Upstream service call failed (502/503)
``collector_failed``         Unexpected collector failure (500)
``internal_error``           Unexpected server-side failure (500)
``not_implemented``          Recognized but unimplemented mode (501)
``rate_limited``             Token-bucket throttle (429, middleware)
``rbac_denied``              RBAC deny (403, dependency)
===========================  ==========================================

Usage::

    from evidentia_api.errors import api_error, error_responses

    @router.get(
        "/thing/{thing_id}",
        responses=error_responses(
            {404: "Unknown ``thing_id`` (``error: not_found``)."}
        ),
    )
    async def get_thing(thing_id: str) -> Thing:
        ...
        raise api_error(
            404,
            "not_found",
            f"Thing {thing_id!r} not found.",
            resource="thing",
        )

``error_responses`` attaches :class:`ErrorEnvelope` as the documented
response model, so the OpenAPI schema (and the generated UI types)
carry the shape — and schemathesis can hold every 4xx/5xx a route
deliberately raises to it (undocumented-status noise → contract).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field


class ErrorDetail(BaseModel):
    """Machine-readable ``detail`` payload of a deliberate 4xx/5xx.

    ``extra="allow"`` — sites attach context fields between ``error``
    and ``message`` (``next_version``, ``valid``, ``resource``, …).
    """

    model_config = ConfigDict(extra="allow")

    error: str = Field(
        description=(
            "Stable snake_case error key (see the registry in "
            "evidentia_api.errors). Clients dispatch on this."
        )
    )
    message: str = Field(
        description="Human-readable explanation of the failure."
    )


class ErrorEnvelope(BaseModel):
    """Wire shape of a deliberate error response: ``{"detail": {...}}``.

    FastAPI wraps ``HTTPException.detail`` under a top-level
    ``detail`` key; this model documents that envelope for OpenAPI
    ``responses`` declarations (via :func:`error_responses`).
    """

    model_config = ConfigDict(extra="forbid")

    detail: ErrorDetail


def api_error(
    status_code: int,
    error: str,
    message: str,
    *,
    headers: dict[str, str] | None = None,
    **context: Any,
) -> HTTPException:
    """Build an :class:`HTTPException` carrying the structured detail.

    Key order in the payload is ``error`` first, context fields in
    call order, ``message`` last — matching the ``rbac_denied`` /
    ``unknown_tier`` precedents. ``error`` / ``message`` cannot be
    shadowed by context (duplicate-keyword ``TypeError`` at the call
    site).

    Callers ``raise api_error(...)`` (optionally ``from exc``) — the
    helper does not raise.
    """
    detail: dict[str, Any] = {"error": error, **context, "message": message}
    return HTTPException(
        status_code=status_code, detail=detail, headers=headers
    )


def error_responses(
    by_status: Mapping[int, str],
) -> dict[int | str, dict[str, Any]]:
    """Build a route-decorator ``responses=`` dict for deliberate errors.

    Each entry documents the status with :class:`ErrorEnvelope` as the
    response model plus the supplied description. Descriptions should
    name the error key(s) the route raises for that status, e.g.
    ``"Unknown ``tier`` filter (``error: unknown_tier``)."``.
    """
    return {
        status: {"model": ErrorEnvelope, "description": description}
        for status, description in by_status.items()
    }


RBAC_DENIED_403 = (
    "RBAC deny under an operator-configured policy "
    "(``error: rbac_denied``; inert under the default permissive "
    "policy). ``detail`` carries ``action`` + ``identity``."
)
"""Shared ``responses`` description for ``require_role``-gated routes."""

RATE_LIMITED_429 = (
    "Per-client token-bucket throttle (``error: rate_limited``). "
    "Carries a ``Retry-After`` header."
)
"""Shared ``responses`` description for rate-limited paths."""
