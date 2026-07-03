"""cryptography-native + DSSE/in-toto air-gap signing for OSCAL docs (v0.11).

Binary-free detached signatures (Ed25519 or RSA-PSS, auto-detected from the
operator's PEM key) wrapped in a DSSE envelope carrying an in-toto Statement
v1. Works air-gapped IN distroless/DHI (no gpg binary, no network). The
counterpart to :mod:`.signing` (gpg) and :mod:`.sigstore` (keyless, online).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import (
    InvalidSignature,
    UnsupportedAlgorithm,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from evidentia_core.audit.events import EventAction, EventOutcome
from evidentia_core.audit.logger import get_logger
from evidentia_core.oscal import dsse
from evidentia_core.oscal.digest import canonical_json_bytes, digest_json

_log = get_logger("evidentia.oscal.keysign")

EVIDENTIA_SIGNING_KEY_PASSPHRASE = "EVIDENTIA_SIGNING_KEY_PASSPHRASE"
EVIDENTIA_SIGNING_KEY_PASSPHRASE_FILE = "EVIDENTIA_SIGNING_KEY_PASSPHRASE_FILE"

_PAYLOAD_TYPE = "application/vnd.in-toto+json"
_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_PREDICATE_TYPE = "https://evidentia.dev/attestations/oscal-signing/v1"
_ALG_ED25519 = "ed25519"
_ALG_RSA_PSS = "rsa-pss-sha256"

_PrivateKey = Ed25519PrivateKey | RSAPrivateKey
_PublicKey = Ed25519PublicKey | RSAPublicKey


class KeySignError(Exception):
    """Base class for key-based signing/verification errors."""


class UnsupportedKeyError(KeySignError):
    """Key type is not Ed25519 or RSA."""


class SigningKeyError(KeySignError):
    """Private key could not be loaded (malformed / passphrase / encryption)."""


class VerifyKeyError(KeySignError):
    """Public key or DSSE envelope could not be loaded."""


def _read_passphrase() -> bytes | None:
    """Resolve the signing-key passphrase from env (value, then *_FILE).

    Empty / unset == no passphrase. Never logged, never echoed. The ``_FILE``
    value is read file->memory and never placed in the environment.
    """
    raw = os.environ.get(EVIDENTIA_SIGNING_KEY_PASSPHRASE)
    if raw:
        return raw.encode("utf-8")
    file_path = os.environ.get(EVIDENTIA_SIGNING_KEY_PASSPHRASE_FILE)
    if file_path:
        data = Path(file_path).read_bytes().rstrip(b"\n")
        return data or None
    return None


def _load_private_key(pem: bytes) -> _PrivateKey:
    password = _read_passphrase()
    try:
        key = serialization.load_pem_private_key(pem, password=password)
    except TypeError as e:
        msg = str(e).lower()
        if "not encrypted" in msg:
            # Unencrypted key but a stray passphrase was supplied — retry clean.
            try:
                key = serialization.load_pem_private_key(pem, password=None)
            except (ValueError, TypeError) as e2:
                raise SigningKeyError("malformed or undecodable private key") from e2
        elif "encrypted" in msg:
            raise SigningKeyError(
                f"encrypted signing key requires {EVIDENTIA_SIGNING_KEY_PASSPHRASE}"
            ) from e
        else:
            raise SigningKeyError(f"could not load private key: {e}") from e
    except ValueError as e:
        msg = str(e).lower()
        if "password" in msg or "decrypt" in msg or "passphrase" in msg:
            raise SigningKeyError("incorrect passphrase for signing key") from e
        if password is not None:
            # A passphrase was supplied but the upstream error wording is
            # unrecognized (cryptography/OpenSSL variants drift across
            # versions/platforms): report both plausible causes rather than
            # misclassifying as key corruption.
            raise SigningKeyError(
                "could not decrypt signing key: incorrect passphrase or "
                "malformed key data"
            ) from e
        raise SigningKeyError("malformed or undecodable private key") from e
    except UnsupportedAlgorithm as e:
        raise UnsupportedKeyError(f"unsupported key algorithm: {e}") from e

    if isinstance(key, (Ed25519PrivateKey, RSAPrivateKey)):
        if isinstance(key, RSAPrivateKey) and key.key_size < 2048:
            raise UnsupportedKeyError(
                f"RSA signing key is {key.key_size} bits; minimum is 2048 (recommend 3072+)"
            )
        return key
    raise UnsupportedKeyError(
        f"unsupported signing key type {type(key).__name__}; use Ed25519 or RSA"
    )


def _load_public_key(pem: bytes) -> _PublicKey:
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, UnsupportedAlgorithm) as e:
        raise VerifyKeyError(f"could not load public key: {e}") from e
    if isinstance(key, (Ed25519PublicKey, RSAPublicKey)):
        if isinstance(key, RSAPublicKey) and key.key_size < 2048:
            raise UnsupportedKeyError(
                f"RSA verify key is {key.key_size} bits; minimum is 2048 (recommend 3072+)"
            )
        return key
    raise UnsupportedKeyError(
        f"unsupported verify key type {type(key).__name__}; use Ed25519 or RSA"
    )


def _algorithm_for(key: _PrivateKey | _PublicKey) -> str:
    if isinstance(key, (Ed25519PrivateKey, Ed25519PublicKey)):
        return _ALG_ED25519
    if isinstance(key, (RSAPrivateKey, RSAPublicKey)):
        return _ALG_RSA_PSS
    raise UnsupportedKeyError(f"unsupported key type {type(key).__name__}")


def _key_id(public_key: _PublicKey) -> str:
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def default_dsse_path(artifact_path: str | Path) -> Path:
    p = Path(artifact_path)
    return p.with_suffix(p.suffix + ".dsse.json")


def _tool_version() -> str:
    try:
        from importlib.metadata import version

        return version("evidentia-core")
    except Exception:  # pragma: no cover - metadata always present in tests
        return "unknown"


def _sign(private_key: _PrivateKey, message: bytes) -> bytes:
    if isinstance(private_key, Ed25519PrivateKey):
        return private_key.sign(message)
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )


def sign_oscal_file(
    artifact_path: str | Path,
    *,
    key_path: str | Path,
    dsse_path: str | Path | None = None,
    tool_version: str | None = None,
) -> Path:
    """DSSE-sign any emitted OSCAL JSON document (AR or profile).

    Writes ``<artifact>.dsse.json``. The subject digest is the artifact's
    canonical-JSON digest, so the signature binds content (not raw bytes).
    Algorithm is auto-detected from the key type. Air-gap clean: no network,
    no subprocess.
    """
    artifact = Path(artifact_path)
    if not artifact.is_file():
        raise SigningKeyError(f"Artifact not found: {artifact}")
    try:
        private_key = _load_private_key(Path(key_path).read_bytes())
        public_key = private_key.public_key()
        algorithm = _algorithm_for(private_key)
        key_id = _key_id(public_key)

        parsed = json.loads(artifact.read_text(encoding="utf-8"))
        statement = {
            "_type": _STATEMENT_TYPE,
            "subject": [
                {"name": artifact.name, "digest": {"sha256": digest_json(parsed)}}
            ],
            "predicateType": _PREDICATE_TYPE,
            "predicate": {
                "algorithm": algorithm,
                "keyId": key_id,
                "tool": "evidentia",
                "toolVersion": tool_version or _tool_version(),
                "signedAt": datetime.now(UTC).isoformat(),
            },
        }
        statement_bytes = canonical_json_bytes(statement)
        signature = _sign(private_key, dsse.pae(_PAYLOAD_TYPE, statement_bytes))
        envelope = dsse.Envelope(
            payload_type=_PAYLOAD_TYPE,
            payload_b64=dsse.b64encode_std(statement_bytes),
            signatures=(
                dsse.Signature(keyid=key_id, sig=dsse.b64encode_std(signature)),
            ),
        )
    except KeySignError as e:
        _log.warning(
            action=EventAction.SIGN_FAILED,
            outcome=EventOutcome.FAILURE,
            message=f"DSSE signing failed for {artifact.name}",
            error={"type": type(e).__name__},
            evidentia={"artifact_path": str(artifact)},
        )
        raise

    resolved = Path(dsse_path) if dsse_path else default_dsse_path(artifact)
    resolved.write_text(dsse.serialize_envelope(envelope), encoding="utf-8")
    _log.info(
        action=EventAction.SIGN_KEY_SIGNED,
        outcome=EventOutcome.SUCCESS,
        message=f"DSSE envelope written for {artifact.name}",
        evidentia={
            "artifact_path": str(artifact),
            "dsse_path": str(resolved),
            "key_id": key_id,
            "algorithm": algorithm,
        },
    )
    return resolved


@dataclass(frozen=True)
class DSSEVerifyResult:
    valid: bool
    signer_key_id: str | None = None
    algorithm: str | None = None
    details: str = ""


def _verify_sig(public_key: _PublicKey, signature: bytes, message: bytes) -> None:
    """Raise InvalidSignature on failure. Params derived from the key type only."""
    if isinstance(public_key, Ed25519PublicKey):
        public_key.verify(signature, message)
    else:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO),
            hashes.SHA256(),
        )


def verify_oscal_file(
    artifact_path: str | Path,
    *,
    verify_key_path: str | Path,
    dsse_path: str | Path | None = None,
) -> DSSEVerifyResult:
    """Verify a `.dsse.json` envelope against an OSCAL artifact + pinned key.

    Follows the normative order (§4.6): parse -> derive routine from the pinned
    key ONLY -> verify signature over PAE -> check payloadType -> check
    _type/predicateType -> enforce predicate.algorithm cross-check -> compare
    subject digest. Any failure is a fail-closed False (or VerifyKeyError for a
    missing artifact / unloadable key), never an exception escaping mid-verify.
    """
    artifact = Path(artifact_path)
    resolved = Path(dsse_path) if dsse_path else default_dsse_path(artifact)
    if not artifact.is_file():
        raise VerifyKeyError(f"Artifact not found: {artifact}")
    if not resolved.is_file():
        raise VerifyKeyError(f"DSSE envelope not found: {resolved}")
    if not Path(verify_key_path).is_file():
        raise VerifyKeyError(f"verify key not found: {verify_key_path}")

    public_key = _load_public_key(Path(verify_key_path).read_bytes())
    expected_alg = _algorithm_for(public_key)  # routine selector — pinned key only
    key_id = _key_id(public_key)

    def fail(details: str) -> DSSEVerifyResult:
        _log.warning(
            action=EventAction.VERIFY_SIGNATURE_FAILED,
            outcome=EventOutcome.FAILURE,
            message=f"DSSE verification failed for {artifact.name}: {details}",
            evidentia={"artifact_path": str(artifact), "details": details},
        )
        return DSSEVerifyResult(
            valid=False, signer_key_id=key_id, algorithm=expected_alg, details=details
        )

    try:
        envelope = dsse.parse_envelope(resolved.read_text(encoding="utf-8"))
        payload_bytes = dsse.decode_b64(envelope.payload_b64)
    except dsse.DSSEError as e:
        return fail(f"malformed envelope: {e}")

    message = dsse.pae(envelope.payload_type, payload_bytes)
    verified = False
    for sig in envelope.signatures:
        try:
            _verify_sig(public_key, dsse.decode_b64(sig.sig), message)
            verified = True
            break
        except (InvalidSignature, dsse.DSSEError):
            continue
    if not verified:
        return fail("signature did not verify with the pinned key")

    if envelope.payload_type != _PAYLOAD_TYPE:
        return fail(f"unsupported payloadType {envelope.payload_type!r}")

    try:
        statement = json.loads(payload_bytes)
    except json.JSONDecodeError as e:
        return fail(f"payload is not JSON: {e}")
    if not isinstance(statement, dict):
        return fail("payload is not a JSON object")
    if statement.get("_type") != _STATEMENT_TYPE:
        return fail("unexpected statement _type")
    if statement.get("predicateType") != _PREDICATE_TYPE:
        return fail("unexpected predicateType")

    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return fail("predicate is not an object")
    alg = predicate.get("algorithm")
    if alg not in (_ALG_ED25519, _ALG_RSA_PSS) or alg != expected_alg:
        return fail(f"algorithm cross-check failed (envelope={alg!r}, key={expected_alg!r})")

    try:
        artifact_digest = digest_json(json.loads(artifact.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        return fail(f"artifact is not readable JSON: {e}")
    subjects = statement.get("subject") or []
    matched = any(
        isinstance(s, dict)
        and isinstance(s.get("digest"), dict)
        and s["digest"].get("sha256") == artifact_digest
        for s in subjects
    )
    if not matched:
        return fail("subject digest mismatch (artifact content changed)")

    _log.info(
        action=EventAction.VERIFY_SIGNATURE_PASSED,
        outcome=EventOutcome.SUCCESS,
        message=f"DSSE signature valid for {artifact.name}",
        evidentia={"artifact_path": str(artifact), "signer_key_id": key_id, "algorithm": alg},
    )
    return DSSEVerifyResult(valid=True, signer_key_id=key_id, algorithm=alg)
