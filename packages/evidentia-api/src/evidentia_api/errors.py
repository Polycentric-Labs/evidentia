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
normalization is UNCHANGED — manual body-content validation normalizes
to 400 in most routers, invalid-id-shape normalizes per-router to
400/404. The documented exception is the F-V1012-S4-1 per-router
convention (model_risk/tprm/poam/governance), which raises a manual
422 for save-time domain/id failures instead of 400. Only the
``detail`` payload evolved from a bare string to the structured object
above; FastAPI/Pydantic request-validation 422s keep their array-shape
``detail``, so the manual-vs-automatic discrimination still holds
(object vs array) — and where both a manual and an automatic 422 can
occur on the same route, ``error_responses()`` documents the union of
both shapes (see its docstring).

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
                             context: ``lineage_id``,
                             ``attempted_version``, ``next_version``
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

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException


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

    422 is special-cased: on body-bearing routes, FastAPI's own
    request-validation 422 (``HTTPValidationError``, array-shape
    ``detail``) fires ahead of any route code whenever the body fails
    schema validation, while the F-V1012-S4-1 per-router convention
    (model_risk/tprm/poam/governance) also raises a *manual* 422
    (``ErrorEnvelope``, object-shape ``detail``) for save-time
    domain/id failures. FastAPI's explicit ``responses=`` entry
    replaces the auto-generated one rather than merging with it, so a
    plain ``{"model": ErrorEnvelope}`` entry would mis-advertise 422 as
    always object-shaped. Document the union of both shapes instead so
    the generated schema (and schemathesis / the UI's generated types)
    reflect what the route can actually return.
    """
    responses: dict[int | str, dict[str, Any]] = {}
    for status, description in by_status.items():
        if status == 422:
            responses[status] = {
                "description": description,
                "content": {
                    "application/json": {
                        "schema": {
                            "anyOf": [
                                {
                                    "$ref": "#/components/schemas/ErrorEnvelope"
                                },
                                {
                                    "$ref": "#/components/schemas/HTTPValidationError"
                                },
                            ]
                        }
                    }
                },
            }
        else:
            responses[status] = {
                "model": ErrorEnvelope,
                "description": description,
            }
    return responses


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

BODY_PARSE_ERROR_400 = (
    "Request body could not be decoded (e.g. invalid UTF-8) before "
    "route-level validation ran (``error: body_parse_error``)."
)
"""Shared ``responses`` description for the app-wide body-parse-error 400.

Route decorators on body-bearing operations should include this in
their ``error_responses()`` call alongside their own domain-specific
400s so the documented response set matches what FastAPI can actually
return (see :func:`body_parse_error_handler`).
"""


async def body_parse_error_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Normalize FastAPI's own body-decode 400 to the structured shape.

    2026-07-06 stateful-DAST finding (Step 4 of the H-2 deliverable):
    when a request body fails to decode (e.g. invalid UTF-8 bytes sent
    with a ``Content-Type: application/json`` header), FastAPI's routing
    layer raises a hardcoded ``HTTPException(400, "There was an error
    parsing the body")`` from its own ``except Exception`` catch-all in
    ``fastapi.routing`` — BEFORE any route code (or its documented
    ``responses=``) ever runs. That bare string violates the
    :class:`ErrorEnvelope` shape every OTHER deliberate 400 in this API
    carries, so schemathesis's ``response_schema_conformance`` check
    flagged it as a schema violation on ``PUT
    /api/ai-gov/systems/{system_id}`` (and it is reachable identically
    on every body-bearing route in the API — not specific to ai-gov).

    Registering a handler on ``starlette.exceptions.HTTPException``
    REPLACES FastAPI's own default handler app-wide (Starlette allows
    exactly one handler per exception class, keyed by exact class
    identity — NOT ``fastapi.HTTPException``, which is a subclass and
    would never match: the ``except Exception`` catch-all in
    ``fastapi/routing.py`` raises the STARLETTE base class directly,
    and FastAPI's own default handler is itself registered under that
    same base-class key per ``fastapi/applications.py``) — so every
    OTHER deliberate ``api_error(...)`` raise (a ``fastapi.HTTPException``,
    which IS an instance of the Starlette base class via inheritance)
    also flows through here. Non-matching exceptions are handled by
    delegating to ``fastapi.exception_handlers.http_exception_handler``
    (FastAPI's own default) rather than re-raising — re-raising here
    would escape Starlette's exception middleware entirely and crash
    the request instead of falling through to the default behavior.
    """
    if (
        isinstance(exc, StarletteHTTPException)
        and exc.status_code == 400
        and exc.detail == "There was an error parsing the body"
    ):
        return JSONResponse(
            status_code=400,
            content={
                "detail": {
                    "error": "body_parse_error",
                    "message": (
                        "Request body could not be decoded (invalid "
                        "encoding or malformed content)."
                    ),
                }
            },
        )
    # Not our target shape — delegate to FastAPI's own default
    # HTTPException handler so every other deliberate api_error(...)
    # raise (and any other HTTPException) behaves exactly as if this
    # handler were never registered.
    from fastapi.exception_handlers import (
        http_exception_handler as _default_http_exception_handler,
    )

    assert isinstance(exc, StarletteHTTPException)  # narrows for the call
    return await _default_http_exception_handler(request, exc)  # type: ignore[return-value]
