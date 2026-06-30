"""CLI tests for `evidentia oscal verify`."""

from __future__ import annotations

import json as _json

from evidentia.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


def test_oscal_verify_dsse_json_output(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from evidentia_core.oscal import keysign

    key = Ed25519PrivateKey.generate()
    priv = tmp_path / "k.key"
    pub = tmp_path / "k.pub"
    priv.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    ar = tmp_path / "audit.oscal-ar.json"
    ar.write_text(_json.dumps({"assessment-results": {"uuid": "u1"}}), encoding="utf-8")
    keysign.sign_oscal_file(ar, key_path=priv)

    res = runner.invoke(app, ["oscal", "verify", str(ar), "--verify-key", str(pub), "--json"])
    assert res.exit_code == 0, res.output
    payload = _json.loads(res.stdout)
    assert payload["dsse_signature_valid"] is True
    assert payload["dsse_algorithm"] == "ed25519"
