"""Integration test for `evidentia collect ocsf` (v0.10.1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("py_ocsf_models")

from evidentia.cli.main import app
from typer.testing import CliRunner

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ocsf"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_collect_ocsf_file_mode_writes_findings_json(
    runner: CliRunner, tmp_path: Path
) -> None:
    """`collect ocsf -i <file>` reads the fixture and writes SecurityFinding JSON."""
    out = tmp_path / "findings.json"
    result = runner.invoke(
        app,
        [
            "collect",
            "ocsf",
            "--input",
            str(FIXTURES / "mixed-batch.json"),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    findings = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(findings, list)
    assert len(findings) == 2
    # First is the Compliance Finding (FAIL); second is the Detection Finding (WARNING).
    assert findings[0]["compliance_status"] == "fail"
    assert findings[1]["compliance_status"] == "warning"


def test_collect_ocsf_url_mode_rejects_http(
    runner: CliRunner, tmp_path: Path
) -> None:
    """The CLI surfaces the HTTPS-only policy as a non-zero exit + clear error."""
    result = runner.invoke(
        app,
        [
            "collect",
            "ocsf",
            "--input",
            "http://example.com/ocsf.json",
            "--output",
            str(tmp_path / "out.json"),
        ],
    )
    assert result.exit_code == 1
    assert "HTTPS-only" in result.output


def test_collect_ocsf_rejects_unsupported_class_uid(
    runner: CliRunner, tmp_path: Path
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"class_uid": 9999, "category_uid": 2}), encoding="utf-8")
    result = runner.invoke(
        app,
        ["collect", "ocsf", "--input", str(bad), "--output", str(tmp_path / "out.json")],
    )
    assert result.exit_code == 1
    assert "unsupported OCSF class_uid" in result.output
