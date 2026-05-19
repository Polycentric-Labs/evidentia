"""Tests for v0.9.7 P2.4 MCP output signatures groundwork.

Uses HMAC signers for deterministic test behavior (no Sigstore
network dep needed). Production deployments wire Sigstore-keyless
or GPG via the operator-supplied factory.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest
from evidentia_mcp.signatures import (
    EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR,
    EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR,
    SignedToolOutput,
    sign_tool_output,
    verify_tool_output,
)

# ── Test signers (deterministic HMAC) ──────────────────────────────


_TEST_HMAC_KEY = b"v0.9.7-test-key-do-not-use-in-prod"


def make_hmac_signer():
    """Factory used by env-var-driven tests."""

    def _sign(payload: bytes) -> dict[str, str]:
        mac = hmac.new(_TEST_HMAC_KEY, payload, hashlib.sha256).hexdigest()
        return {"alg": "hmac-sha256", "sig": mac}

    return _sign


def make_hmac_verifier():
    def _verify(payload: bytes, signature: dict[str, str]) -> bool:
        if signature.get("alg") != "hmac-sha256":
            return False
        expected = hmac.new(
            _TEST_HMAC_KEY, payload, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature.get("sig", ""))

    return _verify


# ── Envelope model ─────────────────────────────────────────────────


class TestSignedToolOutputModel:
    def test_default_unsigned_envelope(self) -> None:
        env = SignedToolOutput(payload={"foo": "bar"})
        assert env.signature is None
        assert env.signing_error is None
        assert env.schema_version == 1
        assert env.tool_name is None

    def test_with_tool_name(self) -> None:
        env = SignedToolOutput(
            payload={"x": 1}, tool_name="gap_analyze"
        )
        assert env.tool_name == "gap_analyze"

    def test_round_trip_json(self) -> None:
        env = SignedToolOutput(
            payload={"foo": "bar"},
            tool_name="test_tool",
            signature={"alg": "hmac-sha256", "sig": "abc123"},
        )
        json_blob = env.model_dump_json()
        loaded = SignedToolOutput.model_validate_json(json_blob)
        assert loaded.payload == {"foo": "bar"}
        assert loaded.tool_name == "test_tool"
        assert loaded.signature == {"alg": "hmac-sha256", "sig": "abc123"}


# ── sign_tool_output (explicit signer) ─────────────────────────────


class TestSignToolOutputExplicit:
    def test_no_signer_returns_unsigned_envelope(self) -> None:
        env = sign_tool_output({"x": 1})
        assert isinstance(env, SignedToolOutput)
        assert env.signature is None
        assert env.signing_error is None
        assert env.payload == {"x": 1}

    def test_explicit_signer_wraps_payload(self) -> None:
        signer = make_hmac_signer()
        env = sign_tool_output({"x": 1, "y": 2}, signer=signer)
        assert env.signature is not None
        assert env.signature["alg"] == "hmac-sha256"
        # signature dict carries a stable hex digest.
        assert len(env.signature["sig"]) == 64

    def test_signing_is_deterministic_for_same_payload(self) -> None:
        signer = make_hmac_signer()
        env1 = sign_tool_output({"x": 1, "y": 2}, signer=signer)
        env2 = sign_tool_output({"y": 2, "x": 1}, signer=signer)
        # Canonical JSON (sort_keys) → identical signature bytes
        # despite different dict construction order.
        assert env1.signature == env2.signature

    def test_signing_differs_for_different_payloads(self) -> None:
        signer = make_hmac_signer()
        env1 = sign_tool_output({"x": 1}, signer=signer)
        env2 = sign_tool_output({"x": 2}, signer=signer)
        assert env1.signature != env2.signature

    def test_signer_exception_yields_signing_error(self) -> None:
        def broken_signer(payload: bytes) -> dict[str, str]:
            raise RuntimeError("HSM unavailable")

        env = sign_tool_output(
            {"x": 1}, signer=broken_signer, tool_name="test"
        )
        assert env.signature is None
        assert env.signing_error is not None
        assert "HSM unavailable" in env.signing_error


# ── verify_tool_output ─────────────────────────────────────────────


class TestVerifyToolOutput:
    def test_verify_signed_envelope_succeeds(self) -> None:
        signer = make_hmac_signer()
        verifier = make_hmac_verifier()
        env = sign_tool_output({"x": 1}, signer=signer)
        assert verify_tool_output(env, verifier=verifier)

    def test_verify_unsigned_envelope_returns_false(self) -> None:
        env = SignedToolOutput(payload={"x": 1})
        verifier = make_hmac_verifier()
        assert not verify_tool_output(env, verifier=verifier)

    def test_verify_tampered_payload_fails(self) -> None:
        signer = make_hmac_signer()
        verifier = make_hmac_verifier()
        env = sign_tool_output({"x": 1}, signer=signer)
        tampered = env.model_copy(update={"payload": {"x": 999}})
        assert not verify_tool_output(tampered, verifier=verifier)

    def test_verify_tampered_signature_fails(self) -> None:
        signer = make_hmac_signer()
        verifier = make_hmac_verifier()
        env = sign_tool_output({"x": 1}, signer=signer)
        bad_sig = (env.signature or {}).copy()
        bad_sig["sig"] = "0" * 64
        tampered = env.model_copy(update={"signature": bad_sig})
        assert not verify_tool_output(tampered, verifier=verifier)

    def test_verifier_exception_returns_false(self) -> None:
        signer = make_hmac_signer()
        env = sign_tool_output({"x": 1}, signer=signer)

        def broken_verifier(p: bytes, s: dict[str, str]) -> bool:
            raise RuntimeError("verifier broken")

        assert not verify_tool_output(env, verifier=broken_verifier)


# ── Env-var-driven signer resolution ───────────────────────────────


class TestSignerEnvVar:
    def test_no_env_unsigned(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(
            EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR, raising=False
        )
        env = sign_tool_output({"x": 1})
        assert env.signature is None

    def test_env_set_without_factory_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR, "1")
        monkeypatch.delenv(
            EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR, raising=False
        )
        with pytest.raises(RuntimeError, match="FACTORY"):
            sign_tool_output({"x": 1})

    def test_env_set_with_factory_signs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sys
        import types

        # Register a synthetic module exposing make_hmac_signer for
        # the env-resolved factory path. Tests are NOT installed as
        # a Python package, so direct dotted-path import of the
        # test module would fail.
        mod = types.ModuleType("test_signer_factory_mod")
        mod.make_hmac_signer = make_hmac_signer  # type: ignore[attr-defined]
        sys.modules["test_signer_factory_mod"] = mod
        try:
            monkeypatch.setenv(EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR, "1")
            monkeypatch.setenv(
                EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR,
                "test_signer_factory_mod:make_hmac_signer",
            )
            env = sign_tool_output({"x": 1})
            assert env.signature is not None
            assert env.signature["alg"] == "hmac-sha256"
        finally:
            sys.modules.pop("test_signer_factory_mod", None)

    def test_malformed_factory_ref_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR, "1")
        monkeypatch.setenv(
            EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR,
            "module.without.callable.ref",
        )
        with pytest.raises(RuntimeError, match=r"'module.submodule:callable_name'"):
            sign_tool_output({"x": 1})

    def test_unimportable_module_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR, "1")
        monkeypatch.setenv(
            EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR,
            "no_such_module_zzz:make_signer",
        )
        with pytest.raises(RuntimeError, match="Could not import"):
            sign_tool_output({"x": 1})

    def test_missing_callable_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR, "1")
        monkeypatch.setenv(
            EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR,
            "evidentia_mcp.signatures:no_such_function",
        )
        with pytest.raises(RuntimeError, match="did not resolve to a callable"):
            sign_tool_output({"x": 1})
