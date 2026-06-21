"""Traceability router — emit the Control↔Threat matrix as UNSIGNED OSCAL.

Surfaces the ``evidentia traceability emit`` verb over HTTP under the
``/api/traceability`` prefix as a READ-MOSTLY, GUI-backing endpoint:

  - ``POST /api/traceability/emit`` — render an inline Control↔Threat
    :class:`~evidentia_core.models.traceability.TraceabilityMatrix` as a
    Sigstore-signable OSCAL **profile** (the 2026-06-17 representation
    decision: a profile, NOT Assessment Results and NOT the OSCAL
    ``mapping`` model). Returns the **UNSIGNED** profile JSON.

Read-mostly: the endpoint computes/emits purely from the request body —
it reads no server-side path and persists nothing. It is open (no RBAC),
matching the other browse/compute endpoints.

Signing posture (v0.10.12 threat model)
---------------------------------------
The CLI's ``traceability emit`` can additionally GPG-/Sigstore-sign the
emitted profile (``--sign-with-gpg`` / ``--sign-with-sigstore``). That
signing path is deliberately **CLI-only** — it is NOT exposed over HTTP.
This router emits the unsigned matrix ONLY:

- It never imports or invokes ``evidentia_core.oscal.signing`` /
  ``evidentia_core.oscal.sigstore`` (the GPG / Sigstore signers).
- The request body is the bare
  :class:`~evidentia_core.models.traceability.TraceabilityMatrix`, whose
  base model forbids extra fields, so a ``sign_with_gpg`` /
  ``sign_with_sigstore`` knob smuggled into the body is structurally
  rejected (422) rather than honored.

Security
--------
- The matrix is supplied as inline body content (NOT a server-side path
  to read), so there is no SSRF / arbitrary-file-read surface — the same
  posture as the catalog ``import`` endpoint.
- Errors normalize to 400 (string ``detail``) for a schema-valid but
  insufficient matrix (no mappings → nothing to emit, mirroring the CLI
  guard); Pydantic returns 422 for shape-invalid bodies. No filesystem
  path or secret is ever surfaced in an error (G-9).
"""

from __future__ import annotations

from typing import Any

from evidentia_core.audit import EventOutcome, get_logger
from evidentia_core.models.traceability import TraceabilityMatrix
from evidentia_core.oscal.traceability_exporter import (
    traceability_matrix_to_oscal_profile,
)
from fastapi import APIRouter, HTTPException

router = APIRouter()
_log = get_logger("evidentia.api.traceability")

# Audit action string. No traceability-specific EventAction enum member
# exists in evidentia_core.audit.events, and this router may not edit that
# file (strict scope). The audit logger's ``action`` parameter is typed
# ``EventAction | str``, so a stable ECS-style dotted string is a
# type-clean fit, consistent with the events.py namespace convention
# (``evidentia.<domain>.<verb>``) — see the catalog router for the same
# pattern. A future refactor can promote it to an enum member.
_ACTION_TRACEABILITY_EMITTED = "evidentia.traceability.emitted"


@router.post("/traceability/emit")
async def emit_traceability_matrix(matrix: TraceabilityMatrix) -> dict[str, Any]:
    """Emit the Control↔Threat Traceability Matrix as an UNSIGNED OSCAL profile.

    READ-MOSTLY. The matrix is supplied inline (no server path); the
    response is the bare OSCAL profile dict. Signing is CLI-only and is
    NOT performed here — the returned document is always unsigned.

    400 when the matrix is schema-valid but has no mappings (nothing to
    emit, mirroring the CLI guard). 422 (Pydantic) for a shape-invalid
    body, including any signing knob smuggled into the request (the body
    model forbids extra fields).
    """
    if not matrix.mappings:
        raise HTTPException(
            status_code=400,
            detail="The matrix has no mappings — nothing to emit.",
        )

    profile = traceability_matrix_to_oscal_profile(matrix)

    _log.info(
        action=_ACTION_TRACEABILITY_EMITTED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Traceability matrix emitted via API (unsigned): "
            f"{len(matrix.mappings)} mappings across "
            f"{len(matrix.control_ids)} controls"
        ),
        evidentia={
            "framework_id": matrix.framework_id,
            "crosswalk_source": matrix.crosswalk_source,
            "mapping_count": len(matrix.mappings),
            "control_count": len(matrix.control_ids),
            "signed": False,
        },
    )
    return profile
