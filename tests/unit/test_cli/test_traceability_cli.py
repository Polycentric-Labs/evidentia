"""CLI tests for `evidentia traceability emit`."""

from __future__ import annotations

import json
from pathlib import Path

from evidentia.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

_REPO_ROOT = Path(__file__).resolve().parents[3]
_EXAMPLE = _REPO_ROOT / "examples" / "traceability-DEMO-example.yaml"


def test_emit_writes_a_signable_oscal_profile(tmp_path: Path) -> None:
    out = tmp_path / "profile.json"
    result = runner.invoke(app, ["traceability", "emit","-i", str(_EXAMPLE), "-o", str(out)])

    assert result.exit_code == 0, result.output
    assert out.exists()
    prof = json.loads(out.read_text(encoding="utf-8"))["profile"]
    assert prof["imports"][0]["href"] == "nist-800-53-rev5-moderate.json"
    control_ids = {a["control-id"] for a in prof["modify"]["alters"]}
    assert "ac-2" in control_ids
    assert "si-10" in control_ids
    # Every threat is an integrity-hashed back-matter resource.
    resources = prof["back-matter"]["resources"]
    assert resources
    assert all(
        r["rlinks"][0]["hashes"][0]["algorithm"] == "SHA-256" for r in resources
    )


def test_invalid_input_exits_nonzero(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("not_a_matrix: true\n", encoding="utf-8")
    out = tmp_path / "p.json"

    result = runner.invoke(app, ["traceability", "emit","-i", str(bad), "-o", str(out)])

    assert result.exit_code == 2
    assert not out.exists()


def test_empty_mappings_exits_nonzero(tmp_path: Path) -> None:
    empty = tmp_path / "empty.yaml"
    empty.write_text(
        "title: T\ncatalog_href: c.json\nframework_id: f\nmappings: []\n",
        encoding="utf-8",
    )
    out = tmp_path / "p.json"

    result = runner.invoke(app, ["traceability", "emit","-i", str(empty), "-o", str(out)])

    assert result.exit_code == 2


def test_traceability_emit_sign_with_key(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    priv = tmp_path / "k.key"
    priv.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    out = tmp_path / "profile.json"
    result = runner.invoke(
        app,
        [
            "traceability",
            "emit",
            "--input",
            str(_EXAMPLE),
            "--output",
            str(out),
            "--sign-with-key",
            str(priv),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "profile.json.dsse.json").is_file()
