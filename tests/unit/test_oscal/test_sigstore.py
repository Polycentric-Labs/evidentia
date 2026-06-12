"""Tests for :mod:`evidentia_core.oscal.sigstore` (v0.7.0)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from evidentia_core.oscal.sigstore import (
    SigstoreAirGapError,
    SigstoreError,
    SigstoreNotAvailableError,
    SigstoreSigningError,
    SigstoreVerifyError,
    SigstoreVerifyResult,
    _extract_signer_metadata,
    default_bundle_path,
    sign_file,
    sigstore_available,
    verify_file,
)


def test_error_class_hierarchy() -> None:
    assert issubclass(SigstoreNotAvailableError, SigstoreError)
    assert issubclass(SigstoreAirGapError, SigstoreError)
    assert issubclass(SigstoreSigningError, SigstoreError)
    assert issubclass(SigstoreVerifyError, SigstoreError)


def test_verify_result_frozen_dataclass() -> None:
    result = SigstoreVerifyResult(valid=True, signer_identity="x", signer_issuer="y")
    with pytest.raises(AttributeError):
        result.valid = False  # type: ignore[misc]


def test_default_bundle_path_appends_sigstore_json() -> None:
    assert (
        default_bundle_path("audit.oscal-ar.json")
        == Path("audit.oscal-ar.json.sigstore.json")
    )


def test_sigstore_available_returns_bool() -> None:
    assert isinstance(sigstore_available(), bool)


def test_sign_raises_not_available_when_library_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "evidentia_core.oscal.sigstore.sigstore_available", lambda: False
    )
    artifact = tmp_path / "x.json"
    artifact.write_text("{}")
    with pytest.raises(SigstoreNotAvailableError, match="pip install"):
        sign_file(artifact)


def test_verify_raises_not_available_when_library_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "evidentia_core.oscal.sigstore.sigstore_available", lambda: False
    )
    artifact = tmp_path / "x.json"
    artifact.write_text("{}")
    with pytest.raises(SigstoreNotAvailableError):
        verify_file(artifact)


def test_sign_raises_airgap_error_in_offline_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "evidentia_core.oscal.sigstore.sigstore_available", lambda: True
    )
    monkeypatch.setattr(
        "evidentia_core.network_guard.is_offline", lambda: True
    )
    artifact = tmp_path / "x.json"
    artifact.write_text("{}")
    with pytest.raises(SigstoreAirGapError, match=r"[Aa]ir-gap"):
        sign_file(artifact)


def test_verify_raises_airgap_error_in_offline_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "evidentia_core.oscal.sigstore.sigstore_available", lambda: True
    )
    monkeypatch.setattr(
        "evidentia_core.network_guard.is_offline", lambda: True
    )
    artifact = tmp_path / "x.json"
    artifact.write_text("{}")
    with pytest.raises(SigstoreAirGapError):
        verify_file(artifact)


def test_sign_raises_signing_error_for_missing_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "evidentia_core.oscal.sigstore.sigstore_available", lambda: True
    )
    monkeypatch.setattr(
        "evidentia_core.network_guard.is_offline", lambda: False
    )
    with pytest.raises(SigstoreSigningError, match="Artifact not found"):
        sign_file(tmp_path / "does-not-exist.json")


def test_verify_raises_verify_error_for_missing_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "evidentia_core.oscal.sigstore.sigstore_available", lambda: True
    )
    monkeypatch.setattr(
        "evidentia_core.network_guard.is_offline", lambda: False
    )
    artifact = tmp_path / "x.json"
    artifact.write_text("{}")
    with pytest.raises(SigstoreVerifyError, match="bundle not found"):
        verify_file(artifact)


# ── F-V109-1: identity pinning is both-or-neither (cosign model) ─────────


def test_verify_identity_without_issuer_raises_value_error(
    tmp_path: Path,
) -> None:
    """Exactly one pinning kwarg (identity) → ValueError, never UnsafeNoOp.

    The guard is a pure usage check that fires before the availability /
    air-gap probes, so no monkeypatching is needed.
    """
    artifact = tmp_path / "x.json"
    artifact.write_text("{}")
    with pytest.raises(ValueError, match="provided together"):
        verify_file(artifact, expected_identity="ci@example.com")


def test_verify_issuer_without_identity_raises_value_error(
    tmp_path: Path,
) -> None:
    """Exactly one pinning kwarg (issuer) → ValueError, never UnsafeNoOp."""
    artifact = tmp_path / "x.json"
    artifact.write_text("{}")
    with pytest.raises(ValueError, match="provided together"):
        verify_file(
            artifact,
            expected_issuer="https://token.actions.githubusercontent.com",
        )


def _patch_verify_env(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, MagicMock]:
    """Stub the sigstore verify modules + availability/network probes.

    Same ``sys.modules`` fake-module pattern as
    ``tests/unit/test_mcp/test_sigstore_signer.py`` — exercises the
    control flow without network access or real Sigstore infra.
    """
    monkeypatch.setattr(
        "evidentia_core.oscal.sigstore.sigstore_available", lambda: True
    )
    monkeypatch.setattr(
        "evidentia_core.network_guard.is_offline", lambda: False
    )
    bundle_class = MagicMock()
    bundle_class.from_json.return_value = MagicMock(name="Bundle-instance")
    verifier_class = MagicMock()
    verifier_class.production.return_value = MagicMock(name="Verifier-instance")
    policy_module = MagicMock(name="policy-module")
    fake_models = MagicMock(Bundle=bundle_class)
    fake_verify = MagicMock(Verifier=verifier_class, policy=policy_module)
    monkeypatch.setitem(sys.modules, "sigstore.models", fake_models)
    monkeypatch.setitem(sys.modules, "sigstore.verify", fake_verify)
    return {"policy": policy_module}


def test_verify_both_flags_builds_identity_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Both pinning kwargs → policy.Identity carries them verbatim."""
    stubs = _patch_verify_env(monkeypatch)
    artifact = tmp_path / "x.json"
    artifact.write_text("{}")
    default_bundle_path(artifact).write_text('{"fake": "bundle"}')

    result = verify_file(
        artifact,
        expected_identity="ci@example.com",
        expected_issuer="https://token.actions.githubusercontent.com",
    )
    assert result.valid is True
    stubs["policy"].Identity.assert_called_once_with(
        identity="ci@example.com",
        issuer="https://token.actions.githubusercontent.com",
    )
    stubs["policy"].UnsafeNoOp.assert_not_called()


def test_verify_no_flags_uses_unsafe_noop_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Neither pinning kwarg → UnsafeNoOp (the CLI layer warns, F-V109-2)."""
    stubs = _patch_verify_env(monkeypatch)
    artifact = tmp_path / "x.json"
    artifact.write_text("{}")
    default_bundle_path(artifact).write_text('{"fake": "bundle"}')

    result = verify_file(artifact)
    assert result.valid is True
    stubs["policy"].UnsafeNoOp.assert_called_once_with()
    stubs["policy"].Identity.assert_not_called()


# ── F-V109-3: signer_issuer is the OIDC issuer, not the X.509 DN ─────────

_OIDC_ISSUER_URL = "https://token.actions.githubusercontent.com"


def _der_utf8(value: str) -> bytes:
    """Minimal DER UTF8String encoding (tag 0x0C, short-form length)."""
    raw = value.encode("utf-8")
    assert len(raw) < 128
    return b"\x0c" + bytes([len(raw)]) + raw


def _fake_fulcio_cert(
    *,
    identity: str = "ci@example.com",
    oidc_issuer: str | None = _OIDC_ISSUER_URL,
    dn: str = "CN=sigstore-intermediate,O=sigstore.dev",
) -> MagicMock:
    """A stub Fulcio cert: SAN identity + optional OIDC-issuer extension.

    The OID 1.3.6.1.4.1.57264.1.8 extension value mirrors the real
    Fulcio v2 shape — an ``UnrecognizedExtension`` whose ``.value`` is
    the DER-encoded UTF8String of the OIDC issuer URL.
    """
    from cryptography import x509

    cert = MagicMock(name="fulcio-cert")
    san_entry = MagicMock()
    san_entry.value = identity
    san_ext = MagicMock()
    san_ext.value = [san_entry]

    def _get_ext(oid: x509.ObjectIdentifier) -> MagicMock:
        if oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            return san_ext
        if (
            oid.dotted_string == "1.3.6.1.4.1.57264.1.8"
            and oidc_issuer is not None
        ):
            unrecognized = MagicMock(name="UnrecognizedExtension")
            unrecognized.value = _der_utf8(oidc_issuer)
            ext = MagicMock(name="Extension")
            ext.value = unrecognized
            return ext
        raise x509.ExtensionNotFound("not present", oid)

    cert.extensions.get_extension_for_oid.side_effect = _get_ext
    cert.issuer.rfc4514_string.return_value = dn
    return cert


def test_extract_signer_metadata_reads_oidc_issuer_extension() -> None:
    """The issuer comes from the Fulcio v2 extension, not the cert DN."""
    bundle = MagicMock()
    bundle.signing_certificate = _fake_fulcio_cert()
    identity, issuer = _extract_signer_metadata(bundle)
    assert identity == "ci@example.com"
    assert issuer == _OIDC_ISSUER_URL


def test_extract_signer_metadata_falls_back_to_labeled_dn() -> None:
    """No OIDC-issuer extension → the X.509 DN, clearly labeled."""
    bundle = MagicMock()
    bundle.signing_certificate = _fake_fulcio_cert(oidc_issuer=None)
    identity, issuer = _extract_signer_metadata(bundle)
    assert identity == "ci@example.com"
    assert issuer is not None
    assert "OIDC issuer unavailable" in issuer
    assert "sigstore-intermediate" in issuer


def test_extract_signer_metadata_handles_broken_bundle() -> None:
    """A bundle without a signing certificate → (None, None)."""
    identity, issuer = _extract_signer_metadata(object())
    assert identity is None
    assert issuer is None


# ── CI-gated integration tests (Q5=A) ────────────────────────────────────


def _sigstore_integration_ready() -> bool:
    """True when the ambient environment can actually run Sigstore."""
    if not sigstore_available():
        return False
    if os.environ.get("CI", "").lower() != "true":
        return False
    if os.environ.get("RUNNER_OS", "") != "Linux":
        return False
    return bool(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"))


sigstore_integration = pytest.mark.skipif(
    not _sigstore_integration_ready(),
    reason=(
        "Sigstore sign/verify integration tests require CI=true, "
        "RUNNER_OS=Linux, and GitHub Actions OIDC token env vars "
        "(ACTIONS_ID_TOKEN_REQUEST_URL). Skipping on local and non-"
        "GitHub-Actions CI runs — see Q5=A gating rule."
    ),
)


@sigstore_integration
def test_sign_then_verify_integration(tmp_path: Path) -> None:
    artifact = tmp_path / "audit.oscal-ar.json"
    artifact.write_text(
        '{"assessment-results": {"test": true}}', encoding="utf-8"
    )

    bundle_path = sign_file(artifact)
    assert bundle_path.is_file()
    assert bundle_path.name.endswith(".sigstore.json")

    result = verify_file(artifact)
    assert result.valid is True


@sigstore_integration
def test_verify_detects_tampered_artifact_integration(tmp_path: Path) -> None:
    artifact = tmp_path / "audit.oscal-ar.json"
    artifact.write_text('{"hello": "world"}', encoding="utf-8")

    sign_file(artifact)
    artifact.write_text('{"hello": "tampered"}', encoding="utf-8")

    result = verify_file(artifact)
    assert result.valid is False
