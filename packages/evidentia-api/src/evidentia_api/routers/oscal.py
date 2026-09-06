"""OSCAL router — read-only Assessment Result verification (v0.10.12).

Surfaces the CLI-only ``evidentia oscal verify`` integrity check as a
GUI-backing REST endpoint. Mirrors the read/verify half of the OSCAL
chain-of-custody story (back-matter SHA-256 digests + detached GPG
signature + Sigstore/Rekor identity) so the web console can verify an
operator-supplied Assessment Result without shelling out to the CLI.

Endpoint:

  - ``POST /oscal/verify`` — verify an OSCAL Assessment Result supplied
    as inline ``content`` (a JSON string). READ-ONLY: no mutation, no
    persistence, and — critically — **no signing**. The signing side of
    the story (``evidentia gap analyze --sign-with-gpg / --sign-with-sigstore``)
    stays CLI-only by design; this endpoint only ever VERIFIES.

Design choices that close obvious abuse surfaces:

  - **Inline content, never a server path.** The body carries the AR
    document as a JSON string, not a filesystem path, so there is no
    arbitrary-file-read surface (the verifier wants a file, so we write
    the supplied content to a private temp file, verify, and delete it).
  - **Offline-aware.** The Sigstore/Rekor leg is the only outbound-network
    check. When the process is in air-gapped mode
    (:func:`evidentia_core.network_guard.is_offline` or the
    ``EVIDENTIA_API_OFFLINE`` env var) the Sigstore leg is skipped and
    reported as ``"skipped (offline)"`` rather than attempted — the
    digest + local-GPG checks still run. This keeps an air-gapped GUI
    from hanging on a Rekor round-trip.
  - **G-9: no path / secret leak.** Parse + validation errors return
    the structured ``detail`` object from :mod:`evidentia_api.errors`
    whose ``message`` never echoes the temp path or any secret. The
    temp file is always cleaned up.

Auth posture: open (no RBAC). Verification is a read — anyone who can
reach the API can check an AR they already hold. Matches the open
read-side posture of the poam / governance read endpoints.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from evidentia_core.models.common import NonBlankStr
from evidentia_core.network_guard import is_offline
from evidentia_core.oscal.verify import verify_ar_file
from fastapi import APIRouter
from pydantic import BaseModel, Field

from evidentia_api.errors import api_error, error_responses

router = APIRouter()


# ── request / response shapes ──────────────────────────────────────


class VerifyRequest(BaseModel):
    """Body for ``POST /oscal/verify``.

    ``content`` is the OSCAL Assessment Result document as a JSON string
    (inline — not a server path). The two ``expected_sigstore_*`` fields
    are PUBLIC identity strings pinning the Sigstore signer; they are
    both-or-neither (cosign model, F-V109-1) — supplying exactly one is a
    usage error.
    """

    content: NonBlankStr = Field(
        max_length=8_000_000,
        description=(
            "The OSCAL Assessment Result document, inline, as a JSON "
            "string. NOT a filesystem path — the server writes this to a "
            "private temp file, verifies it, and deletes it. Bounded at "
            "~8 MB so an oversized body is rejected (422) before any disk "
            "write, independent of any reverse-proxy body limit."
        ),
    )
    expected_sigstore_identity: str | None = Field(
        default=None,
        description=(
            "Expected Sigstore signer identity (email or OIDC subject). "
            "Public identity string. Both-or-neither with "
            "expected_sigstore_issuer (cosign model)."
        ),
    )
    expected_sigstore_issuer: str | None = Field(
        default=None,
        description=(
            "Expected Sigstore identity issuer URL (e.g. "
            "'https://token.actions.githubusercontent.com'). Public "
            "identity string. Both-or-neither with "
            "expected_sigstore_identity."
        ),
    )
    dsse_envelope: str | None = Field(
        default=None,
        description=(
            "Optional DSSE envelope (the <ar>.dsse.json contents), inline as a "
            "JSON string. Requires verify_public_key (both-or-neither)."
        ),
    )
    verify_public_key: str | None = Field(
        default=None,
        description=(
            "Optional PEM public key (Ed25519 or RSA) pinning the DSSE signer. "
            "Requires dsse_envelope (both-or-neither)."
        ),
    )


def _api_offline() -> bool:
    """True if the API should treat outbound network as unavailable.

    Honors the process-wide air-gap flag
    (:func:`evidentia_core.network_guard.is_offline`) and the
    ``EVIDENTIA_API_OFFLINE`` env var (truthy values: ``1`` / ``true`` /
    ``yes`` / ``on``, case-insensitive).
    """
    if is_offline():
        return True
    raw = os.environ.get("EVIDENTIA_API_OFFLINE", "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@router.post(
    "/oscal/verify",
    responses=error_responses(
        {
            400: (
                "Both-or-neither pinning violation "
                "(``error: invalid_body``) or unparseable ``content`` "
                "(``error: verification_failed``)."
            ),
        }
    ),
)
async def verify_assessment_result(payload: VerifyRequest) -> dict[str, Any]:
    """Verify an inline OSCAL Assessment Result document. READ-ONLY.

    Runs the chain-of-custody check: back-matter SHA-256 digests, then a
    detached GPG signature (only ever present in offline-safe form here —
    no signature artifacts travel with inline content, so the signature
    legs are typically "not checked"), then the Sigstore/Rekor identity
    leg (skipped in offline mode).

    Returns 200 with a structured verdict whether the document is valid
    OR invalid — a tampered AR is a NEGATIVE verdict, not a server error
    (the verification ran successfully and concluded the document is
    bad). 400 is reserved for input that cannot be verified at all
    (unparseable JSON, both-or-neither identity violation). Pydantic body
    validation failures surface as 422.
    """
    # Both-or-neither identity pinning (cosign model, F-V109-1). The body
    # schema can't express the constraint, so guard here and fail as a
    # clean 400 usage error rather than letting verify_ar_file surface it
    # as a report error.
    if (payload.expected_sigstore_identity is None) != (
        payload.expected_sigstore_issuer is None
    ):
        raise api_error(
            400,
            "invalid_body",
            (
                "expected_sigstore_identity and expected_sigstore_issuer "
                "must be provided together; identity pinning requires "
                "both (cosign model)."
            ),
        )

    if (payload.dsse_envelope is None) != (payload.verify_public_key is None):
        raise api_error(
            400,
            "invalid_body",
            (
                "dsse_envelope and verify_public_key must be provided together "
                "(pinned-key DSSE verification)."
            ),
        )

    # Parse BEFORE touching disk so malformed input never creates a temp
    # file. A clean 400 whose structured detail carries a generic
    # message (no path / secret).
    try:
        json.loads(payload.content)
    except json.JSONDecodeError as exc:
        raise api_error(
            400,
            "verification_failed",
            f"Content is not valid JSON: {exc.msg} (line {exc.lineno}).",
        ) from exc

    offline = _api_offline()
    # The Sigstore/Rekor leg is the only outbound-network check. Skip it
    # in offline mode so an air-gapped GUI doesn't hang on a Rekor
    # round-trip; the digest + local-GPG legs still run.
    check_sigstore = not offline

    tmp_path: Path | None = None
    dsse_tmp: Path | None = None
    key_tmp: Path | None = None
    try:
        # Write the inline content to a private temp file (the core
        # verifier is file-based). NamedTemporaryFile with delete=False so
        # we control cleanup in the finally; suffix matches the verifier's
        # sibling-artifact convention (.asc / .sigstore.json), though none
        # accompany inline content.
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".oscal-ar.json",
            delete=False,
        ) as handle:
            handle.write(payload.content)
            tmp_path = Path(handle.name)

        verify_key_arg: Path | None = None
        dsse_bundle_arg: Path | None = None
        if payload.dsse_envelope is not None and payload.verify_public_key is not None:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                suffix=tmp_path.name + ".dsse.json",
                delete=False,
            ) as dh:
                dh.write(payload.dsse_envelope)
                dsse_tmp = Path(dh.name)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                suffix=".pub.pem",
                delete=False,
            ) as kh:
                kh.write(payload.verify_public_key)
                key_tmp = Path(kh.name)
            verify_key_arg = key_tmp
            dsse_bundle_arg = dsse_tmp

        report = verify_ar_file(
            tmp_path,
            require_signature=False,
            check_sigstore=check_sigstore,
            expected_sigstore_identity=payload.expected_sigstore_identity,
            expected_sigstore_issuer=payload.expected_sigstore_issuer,
            verify_key_path=verify_key_arg,
            dsse_bundle_path=dsse_bundle_arg,
        )
    finally:
        for p in (tmp_path, dsse_tmp, key_tmp):
            if p is not None:
                p.unlink(missing_ok=True)

    # Build the GUI-facing result. We deliberately DO NOT echo
    # report.ar_path (the temp path) — G-9, no filesystem-path leak.
    if offline:
        sigstore_status = "skipped (offline)"
    elif report.sigstore_signature_valid is None:
        sigstore_status = "not checked (no Sigstore bundle)"
    elif report.sigstore_signature_valid:
        sigstore_status = "valid"
    else:
        sigstore_status = "invalid"

    return {
        "overall_valid": report.overall_valid,
        "has_verification_surface": report.has_verification_surface,
        "digests_valid": report.digests_valid,
        "signature_valid": report.signature_valid,
        "signature_signer": report.signature_signer,
        "signature_fingerprint": report.signature_fingerprint,
        # Offline + Sigstore reporting so a GUI can render the Rekor leg
        # as "skipped (offline)" instead of a failure.
        "offline": offline,
        "sigstore_checked": check_sigstore
        and report.sigstore_signature_valid is not None,
        "sigstore_status": sigstore_status,
        "sigstore_signature_valid": report.sigstore_signature_valid,
        "sigstore_signer_identity": report.sigstore_signer_identity,
        "sigstore_signer_issuer": report.sigstore_signer_issuer,
        "sigstore_rekor_log_index": report.sigstore_rekor_log_index,
        "dsse_signature_valid": report.dsse_signature_valid,
        "dsse_signer_key_id": report.dsse_signer_key_id,
        "dsse_algorithm": report.dsse_algorithm,
        "dsse_status": (
            "not checked (no DSSE envelope)"
            if report.dsse_signature_valid is None
            else ("valid" if report.dsse_signature_valid else "invalid")
        ),
        "errors": report.errors,
        "warnings": report.warnings,
        "digest_checks": [
            {
                "resource_uuid": c.resource_uuid,
                "title": c.title,
                "expected_digest": c.expected_digest,
                "actual_digest": c.actual_digest,
                "valid": c.valid,
            }
            for c in report.digest_checks
        ],
    }
