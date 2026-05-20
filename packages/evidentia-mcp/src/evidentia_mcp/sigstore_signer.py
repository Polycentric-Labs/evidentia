"""Sigstore-keyless reference signer for MCP tool outputs (v0.9.8 P1.2).

Closes the v0.9.7 deferral noted in :mod:`evidentia_mcp.signatures`:

    **v1.0 follow-up scope** (deferred):
    - Sigstore-keyless reference backend in
      :mod:`evidentia_mcp.signatures.sigstore_signer`

And closes the v0.9.7 F-V97-mcp-signer-trust INFO finding by shipping
an in-tree signer that removes operator key material from the trust
path entirely — short-lived Fulcio certs tied to OIDC identity replace
any long-lived private key the operator would otherwise manage.

Operator usage
--------------

::

    export EVIDENTIA_MCP_SIGN_OUTPUTS=1
    export EVIDENTIA_MCP_SIGNER_FACTORY=evidentia_mcp.sigstore_signer:make_sigstore_signer
    evidentia mcp serve --transport stdio

The factory:

1. Verifies ``sigstore`` is importable (the ``[sigstore]`` extra of
   evidentia-mcp installs it).
2. Verifies the deployment is NOT in air-gap mode (Sigstore needs
   network access to Fulcio + Rekor).
3. Resolves an OIDC identity via :func:`sigstore.oidc.detect_credential`
   (GitHub Actions OIDC, GCP/AWS workload identity, ambient env).
4. Returns a signer callable that, on each MCP tool dispatch, signs
   the canonical JSON of the tool's output via Fulcio short-lived
   cert + records inclusion in the Rekor transparency log.

The signature dict returned to
:class:`evidentia_mcp.signatures.SignedToolOutput.signature` carries:

- ``alg``: ``"sigstore-keyless"``
- ``bundle``: full Sigstore bundle JSON (cert chain + signature +
  Rekor inclusion proof — everything a verifier needs without
  consulting external key material).

Performance characteristic
--------------------------

Each tool dispatch opens a fresh signer context against Fulcio. This
matches the per-file pattern in :mod:`evidentia_core.oscal.sigstore`.
The Sigstore client caches the Fulcio cert internally for the OIDC
token's TTL (typically minutes), so subsequent calls within that
window do not pay the full handshake cost — but they still pay the
Rekor inclusion-proof RPC latency. Deployments with sub-second MCP
latency budgets should fall back to a custom signer that batches
inclusion or uses GPG offline.

Verifier
--------

:func:`make_sigstore_verifier` builds a companion verifier callable
suitable for :func:`evidentia_mcp.signatures.verify_tool_output`.
Verification requires an expected OIDC identity + issuer pair (to
prevent a Sigstore signature from a DIFFERENT identity being accepted
as valid) — operators wire those via factory kwargs.

Threat-model boundary
---------------------

Sigstore-keyless eliminates the **operator-key-material** threat in
F-V97-mcp-signer-trust. It does NOT eliminate:

- **Identity-compromise threats**: an attacker holding the operator's
  OIDC credential can sign arbitrary payloads. The transparency log
  records the abuse, but doesn't prevent it.
- **Replay threats**: a captured signed envelope can be replayed
  later. Mitigation: the envelope's ``signed_at`` UTC timestamp is
  itself part of the canonical-JSON-signed bytes via Pydantic's
  ``model_dump_json`` deterministic ordering, but the wrapping
  callsite must surface the timestamp to verifiers.
- **Transport-tampering threats**: the signed envelope still travels
  over whatever transport the MCP client uses. If the transport is
  unauthenticated (a malicious HTTP intermediary), the envelope is
  the integrity boundary — verify it before trusting.
"""

from __future__ import annotations

from collections.abc import Callable

SignerCallable = Callable[[bytes], dict[str, str]]
"""Same shape as :data:`evidentia_mcp.signatures.SignerCallable`.

Locally aliased here to avoid a circular import — the signatures
module re-exports an identical type alias.
"""

VerifierCallable = Callable[[bytes, dict[str, str]], bool]
"""Same shape as :data:`evidentia_mcp.signatures.VerifierCallable`."""


class SigstoreMCPSignerError(Exception):
    """Raised when the MCP Sigstore signer cannot be built or used."""


def _ensure_sigstore_available() -> None:
    """Raise if the ``sigstore`` Python package is not importable."""
    from evidentia_core.oscal.sigstore import sigstore_available

    if not sigstore_available():
        raise SigstoreMCPSignerError(
            "The 'sigstore' Python package is not installed. "
            "Install via `pip install 'evidentia-mcp[sigstore]'` "
            "(or `evidentia-core[sigstore]` for shared install) to "
            "enable the Sigstore-keyless MCP signer. Alternatively, "
            "use a custom signer factory (operator-supplied HMAC for "
            "dev, GPG for air-gap)."
        )


def _ensure_sigstore_online() -> None:
    """Raise if air-gap mode forbids Sigstore's network calls."""
    from evidentia_core.network_guard import is_offline

    if is_offline():
        raise SigstoreMCPSignerError(
            "Sigstore signing requires network access to Fulcio "
            "(issuer) and Rekor (transparency log). Air-gap mode "
            "forbids both. Use a GPG-based signer factory for "
            "offline deployments — see the operator guide in "
            "`docs/mcp-signing.md` (v0.9.8+)."
        )


def make_sigstore_signer(
    *,
    identity_token: str | None = None,
) -> SignerCallable:
    """Build a Sigstore-keyless signer suitable for MCP dispatch.

    Resolves the OIDC identity ONCE at factory-invocation time and
    captures it in the returned signer's closure. The shared
    :func:`evidentia_core.factory_resolver.resolve_factory` caches
    the result, so this initialization only runs once per process
    lifetime per env-var combination.

    Args:
        identity_token: Explicit raw OIDC token. When ``None``
            (default), :func:`sigstore.oidc.detect_credential` is
            invoked to discover an ambient credential (GitHub
            Actions OIDC env, workload-identity sidecar, etc.).
            Operators with non-standard environments pass the
            token explicitly.

    Returns:
        A :class:`SignerCallable` matching the
        :data:`evidentia_mcp.signatures.SignerCallable` shape — takes
        canonical JSON bytes, returns a ``{"alg": "sigstore-keyless",
        "bundle": <Sigstore JSON>}`` dict.

    Raises:
        SigstoreMCPSignerError: When the ``sigstore`` package is
            missing, the deployment is in air-gap mode, or no OIDC
            credential could be discovered. Surfaces at factory
            invocation, NOT at first tool dispatch, so operators
            see misconfigurations at server startup.
    """
    _ensure_sigstore_available()
    _ensure_sigstore_online()

    from sigstore.oidc import IdentityToken, detect_credential
    from sigstore.sign import SigningContext

    if identity_token is None:
        raw_token = detect_credential()
        if raw_token is None:
            raise SigstoreMCPSignerError(
                "No OIDC credential detected. Set up GitHub Actions "
                "OIDC, run in a workload-identity-enabled "
                "environment, or pass identity_token= explicitly via "
                "a custom factory wrapper. See "
                "`evidentia_core.oscal.sigstore` for the file-based "
                "equivalent and the OIDC providers supported by "
                "sigstore-python."
            )
        token = IdentityToken(raw_token)
    else:
        token = IdentityToken(identity_token)

    ctx = SigningContext.production()

    def _sign(payload: bytes) -> dict[str, str]:
        # Per-call signer context: Sigstore caches the Fulcio cert
        # for the OIDC token's TTL, so subsequent calls within that
        # window avoid the cert-issuance round-trip but still pay
        # the Rekor inclusion-proof RPC latency.
        try:
            with ctx.signer(token) as signer:
                bundle = signer.sign_artifact(payload)
        except Exception as exc:
            # Re-raise as our exception type so the signatures-module
            # non-fatal-failure path captures the contextualized
            # error in ``envelope.signing_error``.
            raise SigstoreMCPSignerError(
                f"Sigstore signing failed: {exc}"
            ) from exc
        return {
            "alg": "sigstore-keyless",
            "bundle": bundle.to_json(),
        }

    return _sign


def make_sigstore_verifier(
    *,
    expected_identity: str,
    expected_issuer: str,
) -> VerifierCallable:
    """Build a Sigstore-keyless verifier for MCP envelope verification.

    Args:
        expected_identity: OIDC identity (e.g.,
            ``https://github.com/Polycentric-Labs/evidentia/.github/workflows/release.yml@refs/tags/v0.9.8``)
            that MUST appear in the signing certificate's Subject
            Alternative Name. Failing to set this leaves the verifier
            accepting signatures from any identity — sufficient only
            for development.
        expected_issuer: OIDC issuer URL (e.g.,
            ``https://token.actions.githubusercontent.com``). Pinning
            the issuer prevents a different OIDC provider's identity
            from impersonating the expected one.

    Returns:
        A :class:`VerifierCallable` matching the
        :data:`evidentia_mcp.signatures.VerifierCallable` shape —
        takes ``(payload_bytes, signature_dict)``, returns True iff
        the Sigstore bundle verifies the bytes AND the certificate
        matches the expected identity + issuer.

    Raises:
        SigstoreMCPSignerError: When the ``sigstore`` package is
            missing or the deployment is in air-gap mode. Surfaces
            at factory invocation, mirroring the signer path.
    """
    _ensure_sigstore_available()
    _ensure_sigstore_online()

    from sigstore.models import Bundle
    from sigstore.verify import Verifier, policy

    verifier = Verifier.production()
    verify_policy = policy.Identity(
        identity=expected_identity,
        issuer=expected_issuer,
    )

    def _verify(payload: bytes, signature: dict[str, str]) -> bool:
        if signature.get("alg") != "sigstore-keyless":
            return False
        bundle_json = signature.get("bundle")
        if not bundle_json:
            return False
        try:
            bundle = Bundle.from_json(bundle_json)
            verifier.verify_artifact(payload, bundle, verify_policy)
            return True
        except Exception:
            # Verification can fail for many reasons (bad cert chain,
            # Rekor inclusion proof mismatch, identity policy
            # violation, network outage). Collapse all into a False
            # return — callers wanting structured failure diagnostics
            # use :func:`evidentia_core.oscal.sigstore.verify_file`
            # which preserves the exception details.
            return False

    return _verify


__all__ = [
    "SignerCallable",
    "SigstoreMCPSignerError",
    "VerifierCallable",
    "make_sigstore_signer",
    "make_sigstore_verifier",
]
