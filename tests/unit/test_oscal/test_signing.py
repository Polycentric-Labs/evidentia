"""Tests for :mod:`evidentia_core.oscal.signing` (v0.7.0).

GPG round-trip: generate a throwaway key in an ephemeral GNUPGHOME,
sign a test artifact, verify the signature, then verify that tampering
fails the check. Whole suite is skipped gracefully when the ``gpg``
binary isn't available — keeps CI portable without forcing every runner
to install GnuPG.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from evidentia_core.oscal.signing import (
    GPGNotAvailableError,
    GPGSigningError,
    GPGVerifyError,
    gpg_available,
    sign_file,
    verify_file,
)

# Every test in this module needs GnuPG. Skip the whole module when
# it's unavailable rather than marking each test individually.
pytestmark = pytest.mark.skipif(not gpg_available(), reason="gpg binary not installed")


_TEST_KEY_EMAIL = "evidentia-test@example.invalid"
_TEST_KEY_NAME = "Evidentia Signing Test"


@pytest.fixture(scope="module")
def gnupghome(tmp_path_factory) -> Path:
    """Provision a throwaway GNUPGHOME with a signing-capable key.

    Scoped to the test module so the key-generation cost (can be a few
    seconds on low-entropy CI runners) is paid once. The tmpdir is
    destroyed when the module finishes — no leftover keys on disk.

    The subprocess inherits the full environment (``GNUPGHOME`` overridden)
    so the platform's ``gpg-agent``, ``TEMP``, ``APPDATA``, etc. resolve
    correctly. Stripping env down to PATH + GNUPGHOME breaks MSYS/Cygwin
    GnuPG builds that rely on ``HOME`` / ``USERPROFILE`` to find their
    IPC sockets.
    """
    import os

    home = tmp_path_factory.mktemp("gnupghome")
    # GnuPG refuses to init on world-readable dirs on POSIX; 0700 matches
    # the usual ~/.gnupg permissions. No-op on Windows NTFS.
    home.chmod(0o700)

    env = dict(os.environ)
    env["GNUPGHOME"] = str(home.resolve())

    # Non-interactive key generation. ``%no-protection`` omits a
    # passphrase — safe for a throwaway test key but would be a
    # disastrous choice for any real signing key.
    batch_script = f"""
%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: {_TEST_KEY_NAME}
Name-Email: {_TEST_KEY_EMAIL}
Expire-Date: 0
%commit
"""

    result = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--generate-key"],
        input=batch_script,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"GnuPG test-key generation failed (likely a sandbox / entropy issue): {result.stderr.strip()}")
    return home


# ── sign + verify happy path ──────────────────────────────────────────────


def test_sign_then_verify_roundtrip(tmp_path: Path, gnupghome: Path) -> None:
    artifact = tmp_path / "audit.oscal-ar.json"
    artifact.write_text('{"hello": "world"}', encoding="utf-8")

    sig_path = sign_file(artifact, key_id=_TEST_KEY_EMAIL, gnupghome=gnupghome)
    assert sig_path == artifact.with_suffix(".json.asc")
    assert sig_path.is_file()
    # ASCII-armored sig starts with the PGP header.
    assert sig_path.read_text(encoding="utf-8").startswith("-----BEGIN PGP SIGNATURE-----")

    result = verify_file(artifact, gnupghome=gnupghome)
    assert result.valid is True
    # Signer id/fingerprint should both be populated on a good verify.
    assert result.signer_key_id
    assert result.signer_fingerprint


def test_verify_detects_tampered_artifact(tmp_path: Path, gnupghome: Path) -> None:
    artifact = tmp_path / "audit.json"
    artifact.write_text("original content", encoding="utf-8")
    sign_file(artifact, key_id=_TEST_KEY_EMAIL, gnupghome=gnupghome)

    # Tamper AFTER signing.
    artifact.write_text("tampered content", encoding="utf-8")

    result = verify_file(artifact, gnupghome=gnupghome)
    assert result.valid is False


def test_sign_custom_signature_path(tmp_path: Path, gnupghome: Path) -> None:
    """Explicit --signature lets callers co-locate sigs in a sidecar dir."""
    artifact = tmp_path / "ar.json"
    artifact.write_text('{"a": 1}', encoding="utf-8")

    custom_sig = tmp_path / "signatures" / "ar.sig.asc"
    custom_sig.parent.mkdir()

    returned_sig = sign_file(
        artifact,
        key_id=_TEST_KEY_EMAIL,
        signature_path=custom_sig,
        gnupghome=gnupghome,
    )
    assert returned_sig == custom_sig
    assert custom_sig.is_file()

    result = verify_file(artifact, signature_path=custom_sig, gnupghome=gnupghome)
    assert result.valid is True


# ── error paths ───────────────────────────────────────────────────────────


def test_sign_missing_artifact_raises(tmp_path: Path, gnupghome: Path) -> None:
    with pytest.raises(GPGSigningError, match="Artifact not found"):
        sign_file(
            tmp_path / "missing.json",
            key_id=_TEST_KEY_EMAIL,
            gnupghome=gnupghome,
        )


def test_verify_missing_signature_raises(tmp_path: Path, gnupghome: Path) -> None:
    artifact = tmp_path / "unsigned.json"
    artifact.write_text("{}", encoding="utf-8")
    with pytest.raises(GPGVerifyError, match="Signature not found"):
        verify_file(artifact, gnupghome=gnupghome)


def test_sign_unknown_key_raises_signing_error(tmp_path: Path, gnupghome: Path) -> None:
    artifact = tmp_path / "x.json"
    artifact.write_text("{}", encoding="utf-8")
    with pytest.raises(GPGSigningError):
        sign_file(artifact, key_id="nonexistent-key@invalid", gnupghome=gnupghome)


def test_gpg_not_available_error_class_exists() -> None:
    """The class is exposed so callers can catch it without a bare except."""
    assert issubclass(GPGNotAvailableError, Exception)
