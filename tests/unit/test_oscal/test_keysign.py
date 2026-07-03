import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from evidentia_core.oscal import keysign


def _ed25519_pem(encrypted: bytes | None = None) -> bytes:
    key = Ed25519PrivateKey.generate()
    enc = (
        serialization.BestAvailableEncryption(encrypted)
        if encrypted
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc
    )


def test_load_unencrypted_key_with_stray_env_passphrase_does_not_crash(monkeypatch):
    # The footgun: env var still exported but the key is unencrypted.
    monkeypatch.setenv(keysign.EVIDENTIA_SIGNING_KEY_PASSPHRASE, "leftover")
    key = keysign._load_private_key(_ed25519_pem())  # must NOT raise TypeError
    assert isinstance(key, Ed25519PrivateKey)


def test_load_encrypted_key_without_passphrase_is_clean_error(monkeypatch):
    monkeypatch.delenv(keysign.EVIDENTIA_SIGNING_KEY_PASSPHRASE, raising=False)
    monkeypatch.delenv(keysign.EVIDENTIA_SIGNING_KEY_PASSPHRASE_FILE, raising=False)
    with pytest.raises(keysign.SigningKeyError, match="EVIDENTIA_SIGNING_KEY_PASSPHRASE"):
        keysign._load_private_key(_ed25519_pem(encrypted=b"pw"))


def test_load_encrypted_key_with_wrong_passphrase_is_clean_error(monkeypatch):
    monkeypatch.setenv(keysign.EVIDENTIA_SIGNING_KEY_PASSPHRASE, "wrong")
    # (?i)passphrase tolerates both classifier outcomes: the specific
    # "incorrect passphrase for signing key" and the passphrase-aware
    # fallback — upstream (cryptography/OpenSSL) wording varies by
    # version/platform and must not decide this test.
    with pytest.raises(keysign.SigningKeyError, match=r"(?i)passphrase"):
        keysign._load_private_key(_ed25519_pem(encrypted=b"right"))


def test_wrong_passphrase_with_unrecognized_upstream_message(monkeypatch):
    # If cryptography's ValueError wording drifts past the keyword classifier,
    # a supplied passphrase must still yield a passphrase-mentioning error —
    # never the bare "malformed" message (the #136 macOS failure mode).
    monkeypatch.setenv(keysign.EVIDENTIA_SIGNING_KEY_PASSPHRASE, "wrong")

    def _raise_unrecognized(*args, **kwargs):
        raise ValueError("PKCS8 data checksum failure")  # no 'password'/'decrypt'

    monkeypatch.setattr(
        keysign.serialization, "load_pem_private_key", _raise_unrecognized
    )
    with pytest.raises(keysign.SigningKeyError, match=r"(?i)passphrase"):
        keysign._load_private_key(_ed25519_pem(encrypted=b"right"))


def test_load_encrypted_key_with_correct_passphrase(monkeypatch):
    monkeypatch.setenv(keysign.EVIDENTIA_SIGNING_KEY_PASSPHRASE, "right")
    key = keysign._load_private_key(_ed25519_pem(encrypted=b"right"))
    assert isinstance(key, Ed25519PrivateKey)


def test_load_malformed_pem_is_clean_error():
    # Undecodable / non-PEM bytes must map to a clean SigningKeyError, not a
    # raw exception. Deliberately NOT a fake "BEGIN PRIVATE KEY" armor block —
    # that adds zero test value but trips the pre-push secret scanner.
    with pytest.raises(keysign.SigningKeyError, match="malformed"):
        keysign._load_private_key(b"not a valid PEM document")


def test_unsupported_key_type_loads_then_gate_rejects():
    # ECDSA loads fine in cryptography; the isinstance gate must reject it.
    ec_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(keysign.UnsupportedKeyError):
        keysign._load_private_key(ec_pem)


def test_rsa_key_loads():
    rsa_pem = generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    assert isinstance(keysign._load_private_key(rsa_pem), RSAPrivateKey)


def _write_ed25519_keypair(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    priv = tmp_path / "signing.key"
    pub = tmp_path / "signing.pub"
    priv.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv, pub


def test_sign_oscal_file_writes_envelope(tmp_path):
    priv, _ = _write_ed25519_keypair(tmp_path)
    ar = tmp_path / "audit.oscal-ar.json"
    ar.write_text(json.dumps({"assessment-results": {"uuid": "u1"}}), encoding="utf-8")

    out = keysign.sign_oscal_file(ar, key_path=priv)

    assert out == tmp_path / "audit.oscal-ar.json.dsse.json"
    env = keysign.dsse.parse_envelope(out.read_text(encoding="utf-8"))
    assert env.payload_type == "application/vnd.in-toto+json"
    statement = json.loads(keysign.dsse.decode_b64(env.payload_b64))
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicateType"] == "https://evidentia.dev/attestations/oscal-signing/v1"
    assert statement["predicate"]["algorithm"] == "ed25519"
    assert statement["subject"][0]["name"] == "audit.oscal-ar.json"


def _rsa_keypair(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

    key = generate_private_key(public_exponent=65537, key_size=2048)
    priv = tmp_path / "rsa.key"
    pub = tmp_path / "rsa.pub"
    priv.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv, pub


def _sign_fixture(tmp_path, keypair):
    priv, pub = keypair
    ar = tmp_path / "audit.oscal-ar.json"
    ar.write_text(json.dumps({"assessment-results": {"uuid": "u1"}}), encoding="utf-8")
    dsse_path = keysign.sign_oscal_file(ar, key_path=priv)
    return ar, pub, dsse_path


def test_verify_round_trip_ed25519(tmp_path):
    ar, pub, _ = _sign_fixture(tmp_path, _write_ed25519_keypair(tmp_path))
    result = keysign.verify_oscal_file(ar, verify_key_path=pub)
    assert result.valid is True
    assert result.algorithm == "ed25519"


def test_verify_round_trip_rsa(tmp_path):
    ar, pub, _ = _sign_fixture(tmp_path, _rsa_keypair(tmp_path))
    result = keysign.verify_oscal_file(ar, verify_key_path=pub)
    assert result.valid is True
    assert result.algorithm == "rsa-pss-sha256"


def test_verify_fails_on_content_tamper(tmp_path):
    ar, pub, _ = _sign_fixture(tmp_path, _write_ed25519_keypair(tmp_path))
    ar.write_text(json.dumps({"assessment-results": {"uuid": "TAMPERED"}}), encoding="utf-8")
    assert keysign.verify_oscal_file(ar, verify_key_path=pub).valid is False


def test_verify_fails_on_signature_tamper(tmp_path):
    ar, pub, dsse_path = _sign_fixture(tmp_path, _write_ed25519_keypair(tmp_path))
    env = keysign.dsse.parse_envelope(dsse_path.read_text(encoding="utf-8"))
    bad = keysign.dsse.Envelope(
        payload_type=env.payload_type,
        payload_b64=env.payload_b64,
        signatures=(keysign.dsse.Signature(keyid=env.signatures[0].keyid,
                    sig=keysign.dsse.b64encode_std(b"\x00" * 64)),),
    )
    dsse_path.write_text(keysign.dsse.serialize_envelope(bad), encoding="utf-8")
    assert keysign.verify_oscal_file(ar, verify_key_path=pub).valid is False


def test_verify_fails_with_wrong_key_type_before_crypto(tmp_path):
    # Signed with Ed25519, verified with an RSA key -> algorithm mismatch, fail-closed.
    ar, _, _ = _sign_fixture(tmp_path, _write_ed25519_keypair(tmp_path))
    _, rsa_pub = _rsa_keypair(tmp_path)
    assert keysign.verify_oscal_file(ar, verify_key_path=rsa_pub).valid is False


def test_verify_rejects_wrong_payload_type(tmp_path):
    ar, pub, dsse_path = _sign_fixture(tmp_path, _write_ed25519_keypair(tmp_path))
    env = keysign.dsse.parse_envelope(dsse_path.read_text(encoding="utf-8"))
    tampered = keysign.dsse.Envelope(
        payload_type="application/x-evil", payload_b64=env.payload_b64,
        signatures=env.signatures,
    )
    dsse_path.write_text(keysign.dsse.serialize_envelope(tampered), encoding="utf-8")
    # payloadType is in the PAE, so the signature no longer verifies -> invalid.
    assert keysign.verify_oscal_file(ar, verify_key_path=pub).valid is False


def test_verify_fails_on_non_json_artifact_tamper(tmp_path):
    ar, pub, _ = _sign_fixture(tmp_path, _write_ed25519_keypair(tmp_path))
    ar.write_bytes(b"\x00\x01\x02 not json at all \xff\xfe")
    result = keysign.verify_oscal_file(ar, verify_key_path=pub)
    assert result.valid is False  # fail-closed, no exception


def test_load_rsa_key_below_2048_rejected():
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

    pem = generate_private_key(public_exponent=65537, key_size=1024).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with pytest.raises(keysign.UnsupportedKeyError):
        keysign._load_private_key(pem)


def test_verify_fails_with_wrong_ed25519_key(tmp_path):
    ar, _, _ = _sign_fixture(tmp_path, _write_ed25519_keypair(tmp_path))
    kp_b = tmp_path / "kp_b"
    kp_b.mkdir(parents=True, exist_ok=True)
    _, wrong_pub = _write_ed25519_keypair(kp_b)
    result = keysign.verify_oscal_file(ar, verify_key_path=wrong_pub)
    assert result.valid is False
    assert "signature did not verify" in result.details


def test_verify_fails_with_wrong_rsa_key(tmp_path):
    ar, _, _ = _sign_fixture(tmp_path, _rsa_keypair(tmp_path))
    kp_b = tmp_path / "kp_b"
    kp_b.mkdir(parents=True, exist_ok=True)
    _, wrong_pub = _rsa_keypair(kp_b)
    result = keysign.verify_oscal_file(ar, verify_key_path=wrong_pub)
    assert result.valid is False
    assert "signature did not verify" in result.details


def _resign_with_statement(tmp_path, statement_dict, priv_path, ar_path):
    """Sign a mutated statement with the real key and write the DSSE envelope."""
    priv = keysign._load_private_key(priv_path.read_bytes())
    sb = keysign.canonical_json_bytes(statement_dict)
    sig = keysign._sign(priv, keysign.dsse.pae(keysign._PAYLOAD_TYPE, sb))
    env = keysign.dsse.Envelope(
        payload_type=keysign._PAYLOAD_TYPE,
        payload_b64=keysign.dsse.b64encode_std(sb),
        signatures=(keysign.dsse.Signature(keyid="x", sig=keysign.dsse.b64encode_std(sig)),),
    )
    keysign.default_dsse_path(ar_path).write_text(
        keysign.dsse.serialize_envelope(env), encoding="utf-8"
    )


def _get_base_statement(ar_path, dsse_path):
    """Parse the existing DSSE envelope and decode the statement."""
    env = keysign.dsse.parse_envelope(dsse_path.read_text(encoding="utf-8"))
    return json.loads(keysign.dsse.decode_b64(env.payload_b64))


def test_verify_rejects_wrong_predicate_type(tmp_path):
    ar, pub, dsse_path = _sign_fixture(tmp_path, _write_ed25519_keypair(tmp_path))
    priv = tmp_path / "signing.key"
    stmt = _get_base_statement(ar, dsse_path)
    stmt["predicateType"] = "https://evil.example/wrong/v1"
    _resign_with_statement(tmp_path, stmt, priv, ar)
    result = keysign.verify_oscal_file(ar, verify_key_path=pub)
    assert result.valid is False
    assert "predicateType" in result.details


def test_verify_rejects_wrong_statement_type(tmp_path):
    ar, pub, dsse_path = _sign_fixture(tmp_path, _write_ed25519_keypair(tmp_path))
    priv = tmp_path / "signing.key"
    stmt = _get_base_statement(ar, dsse_path)
    stmt["_type"] = "https://evil.example/wrong/statement/v1"
    _resign_with_statement(tmp_path, stmt, priv, ar)
    result = keysign.verify_oscal_file(ar, verify_key_path=pub)
    assert result.valid is False


def test_verify_rejects_non_dict_payload(tmp_path):
    ar, pub, _ = _sign_fixture(tmp_path, _write_ed25519_keypair(tmp_path))
    priv = tmp_path / "signing.key"
    # Build a statement that is a JSON string (not an object) — bypasses
    # the dict check after the signature passes.
    priv_key = keysign._load_private_key(priv.read_bytes())
    raw_str = '"this is not an object"'
    sb = raw_str.encode("utf-8")
    sig = keysign._sign(priv_key, keysign.dsse.pae(keysign._PAYLOAD_TYPE, sb))
    env = keysign.dsse.Envelope(
        payload_type=keysign._PAYLOAD_TYPE,
        payload_b64=keysign.dsse.b64encode_std(sb),
        signatures=(keysign.dsse.Signature(keyid="x", sig=keysign.dsse.b64encode_std(sig)),),
    )
    keysign.default_dsse_path(ar).write_text(
        keysign.dsse.serialize_envelope(env), encoding="utf-8"
    )
    result = keysign.verify_oscal_file(ar, verify_key_path=pub)
    assert result.valid is False
