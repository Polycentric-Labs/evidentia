"""First-class Sigstore signing for ``evidentia eval`` output (v0.8.2 P3.2).

The DFAH harness output IS audit evidence — it's the artifact
that proves an operator ran the determinism / replay /
faithfulness check before shipping. This module wraps the
v0.7.x OSCAL Sigstore signing helpers with an eval-output-
specific interface so operators get the same keyless-OIDC +
Rekor-transparency-log integrity guarantees on the eval
artifact that they get on OSCAL Assessment Results.

Public API:

- :func:`sign_eval_result` — write the EvalResult JSON to disk
  + produce a sibling ``.sigstore.json`` Sigstore bundle.
- :func:`verify_eval_result` — verify a previously-signed
  bundle, returning the canonical :class:`SigstoreVerifyResult`.

The actual cryptographic work delegates to
:mod:`evidentia_core.oscal.sigstore`. We don't re-implement
key handling, OIDC token detection, or Rekor log inclusion
proofs — the v0.7.x OSCAL pattern is already battle-tested.

Operators wanting to sign locally need a Sigstore-compatible
OIDC identity (e.g., GitHub Actions workflow OIDC token, an
ambient gcloud / azure-cli login). When no identity is
detected, :class:`SigstoreSigningError` is raised — no silent
fall-through to unsigned output.

Reference:
- :mod:`evidentia_core.oscal.sigstore` — canonical signing
- §25.2 P3.2 / §25.3 step 7 (v0.8.2 cycle plan)
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.oscal.sigstore import (
    default_bundle_path,
    sign_file,
    verify_file,
)

if TYPE_CHECKING:
    from evidentia_core.oscal.sigstore import SigstoreVerifyResult

    from evidentia_ai.eval.harness import EvalResult

_log = get_logger("evidentia.ai.eval.signing")


def sign_eval_result(
    result: EvalResult,
    output_path: Path | str,
    *,
    identity_token: str | None = None,
    bundle_path: Path | str | None = None,
) -> tuple[Path, Path]:
    """Write an ``EvalResult`` to disk + produce its Sigstore bundle.

    The eval output JSON lands at ``output_path``; the Sigstore
    bundle defaults to a sibling ``.sigstore.json`` (same naming
    convention as the OSCAL signing path).

    Args:
        result: The :class:`EvalResult` to sign. Serialized via
            ``model_dump_json(indent=2)`` for human-readable
            review + stable hashing.
        output_path: Where to write the JSON output. Parent
            directory must exist.
        identity_token: Optional explicit OIDC token for the
            Sigstore signer. When ``None`` (the typical case),
            :func:`sigstore.oidc.detect_credential` is used
            (resolves GitHub Actions OIDC, gcloud / azure-cli
            ambient identity, etc.).
        bundle_path: Optional override for the bundle file
            location. When ``None``, falls back to
            :func:`default_bundle_path` ("<output>.sigstore.json").

    Returns:
        ``(output_path, bundle_path)`` as resolved Paths — both
        files exist on disk on successful return.

    Raises:
        FileNotFoundError: ``output_path`` parent directory
            doesn't exist.
        SigstoreError: signing fails for any reason (no OIDC
            credential, network failure, etc.). The eval JSON
            IS written before the signing attempt — operators
            re-running with a credential available get the
            bundle without re-running the eval.
    """
    out = Path(output_path)
    if not out.parent.is_dir():
        raise FileNotFoundError(
            f"Output directory does not exist: {out.parent}"
        )

    out.write_text(
        result.model_dump_json(indent=2),
        encoding="utf-8",
    )
    resolved_bundle_path = (
        Path(bundle_path) if bundle_path else default_bundle_path(out)
    )
    sign_file(
        out,
        bundle_path=resolved_bundle_path,
        identity_token=identity_token,
    )
    _log.info(
        action=EventAction.AI_EVAL_OUTPUT_SIGNED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Signed eval output {out.name} → "
            f"{resolved_bundle_path.name}"
        ),
        evidentia={
            "run_id": result.run_id,
            "output_path": str(out),
            "bundle_path": str(resolved_bundle_path),
            "prompt_count": len(result.samples),
            "evidentia_version": result.evidentia_version,
        },
    )
    return (out, resolved_bundle_path)


def verify_eval_result(
    output_path: Path | str,
    *,
    bundle_path: Path | str | None = None,
    expected_identity: str | None = None,
    expected_issuer: str | None = None,
) -> SigstoreVerifyResult:
    """Verify a signed ``EvalResult`` JSON against its Sigstore bundle.

    Thin wrapper around :func:`evidentia_core.oscal.sigstore.verify_file`
    that names the eval-specific call site for audit-log filtering.
    Returns the canonical :class:`SigstoreVerifyResult` — operators
    inspect the ``valid`` / ``signer_identity`` / ``rekor_log_index``
    fields to confirm provenance.

    Args:
        output_path: Path to the eval output JSON to verify.
        bundle_path: Optional override for the Sigstore bundle
            location. When ``None``, falls back to
            :func:`default_bundle_path`.
        expected_identity: Optional. When set, verification
            additionally requires the signer's certificate
            identity matches this string (e.g.,
            ``"https://github.com/polycentric-labs/evidentia/.github/workflows/release.yml@refs/tags/v0.9.2"``).
        expected_issuer: Optional. When set, verification
            additionally requires the OIDC issuer matches
            (e.g., ``"https://token.actions.githubusercontent.com"``).

    Returns:
        :class:`SigstoreVerifyResult` with ``valid=True`` on a
        clean verification + ``valid=False`` with ``details``
        populated on any failure mode.

    Raises:
        SigstoreError: infrastructure-level verification failure
            (missing files, malformed bundle, unreachable
            transparency log). Distinct from ``valid=False``
            which means the cryptographic check ran cleanly but
            the result was negative.
    """
    return verify_file(
        output_path,
        bundle_path=bundle_path,
        expected_identity=expected_identity,
        expected_issuer=expected_issuer,
    )
