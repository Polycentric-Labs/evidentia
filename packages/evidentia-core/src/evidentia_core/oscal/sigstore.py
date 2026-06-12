"""Sigstore/Rekor signing for OSCAL AR documents (v0.7.0).

Enterprise-grade evidence integrity, addressing checklist item H4
(RFC 3161 timestamps or Sigstore/Rekor). Sigstore combines:

- **Keyless signing** via Fulcio — short-lived signing certs tied to
  an OIDC identity (GitHub Actions, Google Workspace, etc.). No
  operator-managed private keys to rotate or leak.
- **Transparency log** via Rekor — every signature is logged to an
  append-only public ledger. Auditors independently verify that the
  signature was issued at a specific time by a specific identity.
- **Bundle format** — the ``.sigstore.json`` artifact carries the
  cert chain, signature, and Rekor inclusion proof in one file.

Design rules:

- **Additive to GPG, not replacement.** Evidentia keeps shipping
  GPG + SHA-256. Sigstore stacks on top when the environment allows.
- **Air-gap refusal.** Sigstore requires network access to Fulcio
  and Rekor. If :func:`~evidentia_core.network_guard.is_offline`
  returns True, every Sigstore call raises :class:`SigstoreAirGapError`
  before any network IO.
- **Optional dependency.** ``sigstore-python`` pulls in ~30 MB of
  crypto/cosign deps. Installed via ``pip install
  'evidentia-core[sigstore]'``. Missing → :class:`SigstoreNotAvailableError`.
- **Bundle sidecar.** For ``audit.oscal-ar.json``, bundle is at
  ``audit.oscal-ar.json.sigstore.json``. Coexists with GPG ``.asc``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidentia_core.audit.events import EventAction, EventOutcome
from evidentia_core.audit.logger import get_logger

_log = get_logger("evidentia.oscal.sigstore")

# Fulcio OIDC-issuer (v2) certificate extension OID. The extension value
# is a DER-encoded UTF8String per RFC 5280 — see
# https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md.
_FULCIO_OIDC_ISSUER_V2_OID = "1.3.6.1.4.1.57264.1.8"


class SigstoreError(Exception):
    """Base class for Sigstore integration errors."""


class SigstoreNotAvailableError(SigstoreError):
    """Raised when ``sigstore-python`` is not installed."""


class SigstoreAirGapError(SigstoreError):
    """Raised when Sigstore is attempted in air-gap mode."""


class SigstoreSigningError(SigstoreError):
    """Raised when Sigstore signing fails."""


class SigstoreVerifyError(SigstoreError):
    """Raised when verification fails for infrastructure reasons."""


@dataclass(frozen=True)
class SigstoreVerifyResult:
    """Outcome of verifying a Sigstore bundle."""

    valid: bool
    signer_identity: str | None = None
    signer_issuer: str | None = None
    rekor_log_index: int | None = None
    details: str = ""


def sigstore_available() -> bool:
    """Return True iff ``sigstore-python`` is importable."""
    try:
        import sigstore  # noqa: F401

        return True
    except ImportError:
        return False


def _ensure_available() -> None:
    if not sigstore_available():
        raise SigstoreNotAvailableError(
            "The 'sigstore' Python package is not installed. "
            "Install it via `pip install 'evidentia-core[sigstore]'` "
            "to enable Sigstore/Rekor signing, or use GPG signing via "
            "`evidentia_core.oscal.signing.sign_file` for air-gapped "
            "deployments."
        )


def _ensure_online() -> None:
    from evidentia_core.network_guard import is_offline

    if is_offline():
        raise SigstoreAirGapError(
            "Sigstore signing/verification requires network access to "
            "Fulcio (issuer) and Rekor (transparency log). Air-gap mode "
            "forbids both. Use GPG signing (`evidentia_core.oscal."
            "signing.sign_file`) for offline deployments."
        )


def default_bundle_path(artifact_path: str | Path) -> Path:
    """Return the canonical ``.sigstore.json`` bundle path for an artifact."""
    artifact = Path(artifact_path)
    return artifact.with_suffix(artifact.suffix + ".sigstore.json")


def sign_file(
    artifact_path: str | Path,
    *,
    bundle_path: str | Path | None = None,
    identity_token: str | None = None,
) -> Path:
    """Produce a Sigstore bundle for ``artifact_path``.

    Keyless signing via Fulcio + Rekor. Resulting bundle contains cert,
    signature, and Rekor inclusion proof — everything a verifier needs
    without consulting any external key material.
    """
    _ensure_available()
    _ensure_online()

    artifact = Path(artifact_path)
    if not artifact.is_file():
        raise SigstoreSigningError(f"Artifact not found: {artifact}")
    resolved_bundle = (
        Path(bundle_path) if bundle_path else default_bundle_path(artifact)
    )

    from sigstore.models import ClientTrustConfig
    from sigstore.oidc import IdentityToken, detect_credential
    from sigstore.sign import SigningContext

    try:
        if identity_token is None:
            raw_token = detect_credential()
            if raw_token is None:
                raise SigstoreSigningError(
                    "No OIDC credential detected. Set up GitHub Actions "
                    "OIDC, run in a workload-identity-enabled "
                    "environment, or pass identity_token= explicitly."
                )
            token = IdentityToken(raw_token)
        else:
            token = IdentityToken(identity_token)

        ctx = SigningContext.from_trust_config(ClientTrustConfig.production())
        with ctx.signer(token) as signer, artifact.open("rb") as fh:
            bundle = signer.sign_artifact(fh.read())

        resolved_bundle.write_bytes(bundle.to_json().encode("utf-8"))
    except SigstoreError:
        raise
    except Exception as e:
        raise SigstoreSigningError(f"Sigstore signing failed: {e}") from e

    _log.info(
        action=EventAction.SIGN_SIGSTORE_SIGNED,
        outcome=EventOutcome.SUCCESS,
        message=f"Sigstore bundle written for {artifact.name}",
        evidentia={
            "artifact_path": str(artifact),
            "bundle_path": str(resolved_bundle),
        },
    )
    return resolved_bundle


def verify_file(
    artifact_path: str | Path,
    *,
    bundle_path: str | Path | None = None,
    expected_identity: str | None = None,
    expected_issuer: str | None = None,
) -> SigstoreVerifyResult:
    """Verify a Sigstore bundle against its artifact.

    Identity pinning follows the cosign model: ``expected_identity``
    and ``expected_issuer`` are both-or-neither. Supplying exactly one
    raises :class:`ValueError` (F-V109-1) — the pre-v0.10.9 behavior
    silently discarded the lone constraint and verified under an
    any-signer ``UnsafeNoOp`` policy.
    """
    # F-V109-1: exactly one identity-pinning kwarg is a usage error —
    # fail closed rather than silently dropping the supplied constraint.
    if (expected_identity is None) != (expected_issuer is None):
        raise ValueError(
            "--expected-identity and --expected-issuer must be "
            "provided together; identity pinning requires both "
            "(cosign model)."
        )

    _ensure_available()
    _ensure_online()

    artifact = Path(artifact_path)
    if not artifact.is_file():
        raise SigstoreVerifyError(f"Artifact not found: {artifact}")
    resolved_bundle = (
        Path(bundle_path) if bundle_path else default_bundle_path(artifact)
    )
    if not resolved_bundle.is_file():
        raise SigstoreVerifyError(f"Sigstore bundle not found: {resolved_bundle}")

    from sigstore.models import Bundle
    from sigstore.verify import Verifier, policy

    try:
        bundle = Bundle.from_json(resolved_bundle.read_text(encoding="utf-8"))
        verifier = Verifier.production()

        # ``Any`` annotation because sigstore-python's policy types
        # don't share a public base class that mypy can resolve cleanly.
        verify_policy: object
        if expected_identity is not None and expected_issuer is not None:
            verify_policy = policy.Identity(
                identity=expected_identity,
                issuer=expected_issuer,
            )
        else:
            # Neither pinning kwarg (the single-flag case raised above):
            # signature + transparency-log inclusion only — the CLI layer
            # warns that ANY Sigstore identity would pass (F-V109-2).
            verify_policy = policy.UnsafeNoOp()

        with artifact.open("rb") as fh:
            verifier.verify_artifact(fh.read(), bundle, verify_policy)

        signer_identity, signer_issuer = _extract_signer_metadata(bundle)
        _log.info(
            action=EventAction.VERIFY_SIGNATURE_PASSED,
            message=f"Sigstore signature valid for {artifact.name}",
        )
        return SigstoreVerifyResult(
            valid=True,
            signer_identity=signer_identity,
            signer_issuer=signer_issuer,
            rekor_log_index=_extract_rekor_index(bundle),
        )
    except SigstoreError:
        raise
    except Exception as e:
        _log.warning(
            action=EventAction.VERIFY_SIGNATURE_FAILED,
            outcome=EventOutcome.FAILURE,
            message=f"Sigstore verification failed: {e}",
            error={"type": type(e).__name__, "message": str(e)},
        )
        return SigstoreVerifyResult(
            valid=False,
            details=str(e),
        )


def _extract_signer_metadata(bundle: object) -> tuple[str | None, str | None]:
    """Best-effort extraction of signer identity and OIDC issuer from a bundle."""
    try:
        cert = bundle.signing_certificate  # type: ignore[attr-defined]
        from cryptography import x509

        sans = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        identity = next(
            (str(n.value) for n in sans if hasattr(n, "value")), None
        )
        return identity, _extract_oidc_issuer(cert)
    except Exception:
        return None, None


def _extract_oidc_issuer(cert: Any) -> str | None:
    """Extract the OIDC issuer from a Fulcio signing certificate.

    F-V109-3: pre-v0.10.9 this surface reported
    ``cert.issuer.rfc4514_string()`` — the Fulcio X.509 issuer DN
    (``O=sigstore.dev,CN=sigstore-intermediate``), NOT the OIDC issuer
    the signer authenticated against. The real OIDC issuer lives in the
    Fulcio v2 certificate extension (OID 1.3.6.1.4.1.57264.1.8) as a
    DER-encoded UTF8String; decoded here the same way sigstore-python's
    ``OIDCIssuerV2`` policy does. Falls back to the X.509 DN — clearly
    labeled so it can't be mistaken for the OIDC issuer — when the
    extension is absent or undecodable (e.g. a pre-v2 Fulcio cert).
    """
    from cryptography import x509

    try:
        ext = cert.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(_FULCIO_OIDC_ISSUER_V2_OID)
        ).value
        from pyasn1.codec.der.decoder import decode as der_decode
        from pyasn1.type.char import UTF8String

        # ``.decode()`` mirrors sigstore-python's ``_SingleX509ExtPolicyV2``
        # — the pyasn1 object is bytes-like, not directly str()-able.
        return str(der_decode(ext.value, UTF8String)[0].decode())
    except Exception:
        try:
            return (
                f"{cert.issuer.rfc4514_string()} "
                f"(X.509 DN; OIDC issuer unavailable)"
            )
        except Exception:
            return None


def _extract_rekor_index(bundle: object) -> int | None:
    """Best-effort extraction of Rekor transparency-log index."""
    try:
        entry = bundle.log_entry  # type: ignore[attr-defined]
        return int(entry.log_index)
    except Exception:
        return None


__all__ = [
    "SigstoreAirGapError",
    "SigstoreError",
    "SigstoreNotAvailableError",
    "SigstoreSigningError",
    "SigstoreVerifyError",
    "SigstoreVerifyResult",
    "default_bundle_path",
    "sign_file",
    "sigstore_available",
    "verify_file",
]
