"""Unit tests for the v0.9.8 P1.2 Sigstore-keyless MCP signer.

Closes the v0.9.7 F-V97-mcp-signer-trust INFO finding by shipping an
in-tree signer that removes operator key material from the trust
path.

Tests do NOT hit real Fulcio / Rekor — every Sigstore primitive is
mocked. Real-world signing requires an OIDC credential + network
access; those paths are exercised in the v0.7.0+ ``evidentia eval``
end-to-end smoke tests (gated behind opt-in env vars).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ── 1. Availability + air-gap gates ──────────────────────────────


class TestAvailabilityGates:
    def test_factory_raises_when_sigstore_not_installed(
        self,
    ) -> None:
        """Factory surfaces a clear error when the optional dep is absent."""
        from evidentia_mcp.sigstore_signer import (
            SigstoreMCPSignerError,
            make_sigstore_signer,
        )

        with patch(
            "evidentia_core.oscal.sigstore.sigstore_available",
            return_value=False,
        ), pytest.raises(SigstoreMCPSignerError, match="not installed"):
            make_sigstore_signer()

    def test_factory_raises_when_air_gap_enabled(self) -> None:
        """Air-gap mode forbids Sigstore's network calls."""
        from evidentia_mcp.sigstore_signer import (
            SigstoreMCPSignerError,
            make_sigstore_signer,
        )

        with (
            patch(
                "evidentia_core.oscal.sigstore.sigstore_available",
                return_value=True,
            ),
            patch(
                "evidentia_core.network_guard.is_offline",
                return_value=True,
            ),
            pytest.raises(SigstoreMCPSignerError, match="Air-gap"),
        ):
            make_sigstore_signer()

    def test_verifier_raises_when_sigstore_not_installed(
        self,
    ) -> None:
        """Verifier mirrors the factory gating."""
        from evidentia_mcp.sigstore_signer import (
            SigstoreMCPSignerError,
            make_sigstore_verifier,
        )

        with patch(
            "evidentia_core.oscal.sigstore.sigstore_available",
            return_value=False,
        ), pytest.raises(SigstoreMCPSignerError, match="not installed"):
            make_sigstore_verifier(
                expected_identity="x",
                expected_issuer="y",
            )


# ── 2. OIDC credential resolution ────────────────────────────────


def _patch_sigstore_for_signer(
    detect_returns: str | None = "fake-oidc-token",
    sign_returns: Any = None,
) -> Any:
    """Build the patch context for a signer-factory test.

    Layers the mocks needed to exercise :func:`make_sigstore_signer`
    without an actual sigstore install — :func:`sigstore_available`,
    :func:`is_offline`, the OIDC detect path, the IdentityToken
    constructor, and the SigningContext + signer chain.
    """
    if sign_returns is None:
        sign_returns = MagicMock()
        sign_returns.to_json.return_value = '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}'

    detect_credential_mock = MagicMock(return_value=detect_returns)
    identity_token_class = MagicMock()
    identity_token_instance = MagicMock(name="IdentityToken-instance")
    identity_token_class.return_value = identity_token_instance

    bundle = sign_returns
    signer_instance = MagicMock(name="signer")
    signer_instance.sign_artifact.return_value = bundle
    signer_context_mgr = MagicMock()
    signer_context_mgr.__enter__ = MagicMock(return_value=signer_instance)
    signer_context_mgr.__exit__ = MagicMock(return_value=False)

    signing_ctx_instance = MagicMock(name="SigningContext-instance")
    signing_ctx_instance.signer.return_value = signer_context_mgr
    signing_ctx_class = MagicMock()
    signing_ctx_class.production.return_value = signing_ctx_instance

    fake_oidc = MagicMock(
        detect_credential=detect_credential_mock,
        IdentityToken=identity_token_class,
    )
    fake_sign = MagicMock(SigningContext=signing_ctx_class)

    return {
        "available": patch(
            "evidentia_core.oscal.sigstore.sigstore_available",
            return_value=True,
        ),
        "online": patch(
            "evidentia_core.network_guard.is_offline",
            return_value=False,
        ),
        "oidc_module": patch.dict(
            "sys.modules",
            {"sigstore.oidc": fake_oidc, "sigstore.sign": fake_sign},
        ),
        "signer_instance": signer_instance,
        "detect_credential": detect_credential_mock,
        "bundle": bundle,
    }


class TestOIDCCredentialResolution:
    def test_no_credential_detected_raises(self) -> None:
        """When :func:`detect_credential` returns None → clear error."""
        from evidentia_mcp.sigstore_signer import (
            SigstoreMCPSignerError,
            make_sigstore_signer,
        )

        patches = _patch_sigstore_for_signer(detect_returns=None)
        with (
            patches["available"],
            patches["online"],
            patches["oidc_module"],
            pytest.raises(
                SigstoreMCPSignerError, match="No OIDC credential"
            ),
        ):
            make_sigstore_signer()

    def test_explicit_identity_token_bypasses_detect(self) -> None:
        """Passing identity_token= skips :func:`detect_credential`."""
        from evidentia_mcp.sigstore_signer import make_sigstore_signer

        patches = _patch_sigstore_for_signer(detect_returns=None)
        with (
            patches["available"],
            patches["online"],
            patches["oidc_module"],
        ):
            # Should NOT raise even though detect_credential would
            # have returned None — the explicit token bypasses it.
            signer = make_sigstore_signer(
                identity_token="explicit-token-value"
            )
            assert callable(signer)
            # detect_credential should NOT have been called.
            patches["detect_credential"].assert_not_called()


# ── 3. Happy-path signing ────────────────────────────────────────


class TestSigningHappyPath:
    def test_factory_returns_callable(self) -> None:
        """Happy path produces a callable suitable for SignerCallable."""
        from evidentia_mcp.sigstore_signer import make_sigstore_signer

        patches = _patch_sigstore_for_signer()
        with (
            patches["available"],
            patches["online"],
            patches["oidc_module"],
        ):
            signer = make_sigstore_signer()
            assert callable(signer)

    def test_signer_call_produces_alg_and_bundle_dict(self) -> None:
        """Calling the signer with bytes returns the expected dict shape."""
        from evidentia_mcp.sigstore_signer import make_sigstore_signer

        patches = _patch_sigstore_for_signer()
        with (
            patches["available"],
            patches["online"],
            patches["oidc_module"],
        ):
            signer = make_sigstore_signer()
            sig = signer(b'{"foo":"bar"}')

        assert sig["alg"] == "sigstore-keyless"
        assert "bundle" in sig
        # bundle is the JSON returned by Bundle.to_json() — opaque to
        # this module + verified downstream by make_sigstore_verifier.
        assert sig["bundle"].startswith('{"mediaType"')
        # sign_artifact was invoked with our canonical-JSON bytes.
        patches["signer_instance"].sign_artifact.assert_called_once_with(
            b'{"foo":"bar"}'
        )

    def test_signer_handles_repeated_calls(self) -> None:
        """The signer can be invoked multiple times in a row."""
        from evidentia_mcp.sigstore_signer import make_sigstore_signer

        patches = _patch_sigstore_for_signer()
        with (
            patches["available"],
            patches["online"],
            patches["oidc_module"],
        ):
            signer = make_sigstore_signer()
            sig1 = signer(b"payload-1")
            sig2 = signer(b"payload-2")

        assert sig1["alg"] == sig2["alg"] == "sigstore-keyless"
        # Each call opens a fresh signer context (per-call Fulcio
        # cert lookup — Sigstore client caches under the hood).
        assert (
            patches["signer_instance"].sign_artifact.call_count == 2
        )


# ── 4. Error wrapping ────────────────────────────────────────────


class TestSigningErrorWrapping:
    def test_sign_artifact_failure_wrapped_in_signer_error(self) -> None:
        """Sigstore exceptions are wrapped in SigstoreMCPSignerError.

        Re-raising as our exception type lets the signatures-module's
        non-fatal-failure path (``envelope.signing_error``) capture a
        contextualized message rather than the raw sigstore traceback.
        """
        from evidentia_mcp.sigstore_signer import (
            SigstoreMCPSignerError,
            make_sigstore_signer,
        )

        patches = _patch_sigstore_for_signer()
        patches["signer_instance"].sign_artifact.side_effect = RuntimeError(
            "fulcio outage"
        )
        with (
            patches["available"],
            patches["online"],
            patches["oidc_module"],
        ):
            signer = make_sigstore_signer()
            with pytest.raises(
                SigstoreMCPSignerError, match="Sigstore signing failed"
            ):
                signer(b"some-payload")


# ── 5. Verifier shape + dispatch behavior ────────────────────────


def _patch_sigstore_for_verifier(
    bundle_from_json_returns: Any = None,
    verify_artifact_raises: Exception | None = None,
) -> Any:
    """Mock the verifier-side Sigstore primitives."""
    bundle_instance = (
        bundle_from_json_returns
        if bundle_from_json_returns is not None
        else MagicMock(name="Bundle-instance")
    )
    bundle_class = MagicMock()
    bundle_class.from_json.return_value = bundle_instance

    verifier_instance = MagicMock(name="Verifier-instance")
    if verify_artifact_raises is not None:
        verifier_instance.verify_artifact.side_effect = (
            verify_artifact_raises
        )
    verifier_class = MagicMock()
    verifier_class.production.return_value = verifier_instance

    policy_module = MagicMock(name="policy-module")
    policy_module.Identity = MagicMock()

    fake_models = MagicMock(Bundle=bundle_class)
    fake_verify = MagicMock(Verifier=verifier_class, policy=policy_module)

    return {
        "available": patch(
            "evidentia_core.oscal.sigstore.sigstore_available",
            return_value=True,
        ),
        "online": patch(
            "evidentia_core.network_guard.is_offline",
            return_value=False,
        ),
        "verify_module": patch.dict(
            "sys.modules",
            {"sigstore.models": fake_models, "sigstore.verify": fake_verify},
        ),
        "verifier_instance": verifier_instance,
        "bundle_class": bundle_class,
    }


class TestVerifierBehavior:
    def test_verifier_returns_false_for_wrong_alg(self) -> None:
        """Mismatched ``alg`` short-circuits before bundle parsing."""
        from evidentia_mcp.sigstore_signer import make_sigstore_verifier

        patches = _patch_sigstore_for_verifier()
        with (
            patches["available"],
            patches["online"],
            patches["verify_module"],
        ):
            verifier = make_sigstore_verifier(
                expected_identity="x", expected_issuer="y"
            )
        # Wrong alg → False without touching Bundle.from_json.
        result = verifier(b"payload", {"alg": "hmac-sha256", "sig": "abc"})
        assert result is False
        patches["bundle_class"].from_json.assert_not_called()

    def test_verifier_returns_false_for_missing_bundle(self) -> None:
        """No ``bundle`` field → False (treat as malformed)."""
        from evidentia_mcp.sigstore_signer import make_sigstore_verifier

        patches = _patch_sigstore_for_verifier()
        with (
            patches["available"],
            patches["online"],
            patches["verify_module"],
        ):
            verifier = make_sigstore_verifier(
                expected_identity="x", expected_issuer="y"
            )
        result = verifier(b"payload", {"alg": "sigstore-keyless"})
        assert result is False

    def test_verifier_returns_true_for_valid_bundle(self) -> None:
        """Mocked Sigstore verify success → True."""
        from evidentia_mcp.sigstore_signer import make_sigstore_verifier

        patches = _patch_sigstore_for_verifier()
        with (
            patches["available"],
            patches["online"],
            patches["verify_module"],
        ):
            verifier = make_sigstore_verifier(
                expected_identity="x", expected_issuer="y"
            )
            result = verifier(
                b"payload",
                {
                    "alg": "sigstore-keyless",
                    "bundle": '{"mediaType":"..."}',
                },
            )
        assert result is True
        patches["verifier_instance"].verify_artifact.assert_called_once()

    def test_verifier_returns_false_on_policy_failure(self) -> None:
        """Sigstore raises → verifier returns False (no exception leak)."""
        from evidentia_mcp.sigstore_signer import make_sigstore_verifier

        patches = _patch_sigstore_for_verifier(
            verify_artifact_raises=RuntimeError("identity mismatch")
        )
        with (
            patches["available"],
            patches["online"],
            patches["verify_module"],
        ):
            verifier = make_sigstore_verifier(
                expected_identity="x", expected_issuer="y"
            )
            result = verifier(
                b"payload",
                {
                    "alg": "sigstore-keyless",
                    "bundle": '{"mediaType":"..."}',
                },
            )
        assert result is False


# ── 6. Integration with signatures module ────────────────────────


class TestIntegrationWithSignaturesModule:
    def test_signer_factory_compatible_with_sign_tool_output(self) -> None:
        """Factory output plugs into :func:`sign_tool_output` cleanly.

        Verifies the type-level contract: factory returns a callable
        of the right shape that produces dicts the SignedToolOutput
        model accepts as ``signature``.
        """
        from evidentia_mcp.signatures import sign_tool_output
        from evidentia_mcp.sigstore_signer import make_sigstore_signer

        patches = _patch_sigstore_for_signer()
        with (
            patches["available"],
            patches["online"],
            patches["oidc_module"],
        ):
            signer = make_sigstore_signer()
            envelope = sign_tool_output(
                {"tool": "list_frameworks", "count": 89},
                tool_name="list_frameworks",
                signer=signer,
            )

        assert envelope.signature is not None
        assert envelope.signature["alg"] == "sigstore-keyless"
        assert "bundle" in envelope.signature
        assert envelope.signing_error is None
        assert envelope.tool_name == "list_frameworks"
