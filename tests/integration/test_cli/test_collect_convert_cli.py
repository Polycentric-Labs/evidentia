"""Integration tests for `evidentia collect convert` (v0.10.1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("py_ocsf_models")

from evidentia.cli.main import app
from evidentia_core.audit.events import EventAction
from evidentia_core.models.common import Severity
from evidentia_core.models.finding import (
    ComplianceStatus,
    Finding,
    SecurityFinding,
)
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _findings_json_fixture(tmp_path: Path) -> Path:
    """Write a small SecurityFinding JSON list to disk."""
    f1 = SecurityFinding(
        title="Root account MFA missing",
        description="The AWS root account has no MFA device.",
        severity=Severity.HIGH,
        compliance_status=ComplianceStatus.FAIL,
        remediation="Enable a hardware MFA device on the root user.",
        source_system="aws-config",
    )
    f2 = Finding(  # exercise the v0.10.1 canonical name too
        title="CloudTrail not multi-region",
        description="CloudTrail is single-region only.",
        severity=Severity.MEDIUM,
        compliance_status=ComplianceStatus.FAIL,
        source_system="aws-config",
    )
    path = tmp_path / "findings.json"
    path.write_text(
        json.dumps([f1.model_dump(mode="json"), f2.model_dump(mode="json")]),
        encoding="utf-8",
    )
    return path


def test_convert_writes_ocsf_bundle(runner: CliRunner, tmp_path: Path) -> None:
    """`collect convert --format ocsf` reads SecurityFinding JSON and
    writes an OCSF Compliance Finding bundle."""
    findings_in = _findings_json_fixture(tmp_path)
    out = tmp_path / "ocsf-bundle.json"
    result = runner.invoke(
        app,
        [
            "collect",
            "convert",
            "--input",
            str(findings_in),
            "--format",
            "ocsf",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(bundle, list)
    assert len(bundle) == 2
    # Each entry is an OCSF Compliance Finding (class_uid 2003).
    for entry in bundle:
        assert entry["class_uid"] == 2003
        assert entry["category_uid"] == 2
    # The first finding survives the round-trip with its FAIL status.
    assert bundle[0]["compliance"]["status_id"] == 3
    # finding_to_ocsf preserves the original SecurityFinding under
    # unmapped["evidentia"] for lossless ingestion -- the metadata.product
    # name is fixed to "Evidentia", but source_system rides in the block.
    assert bundle[0]["unmapped"]["evidentia"]["source_system"] == "aws-config"


def test_convert_rejects_unsupported_format(runner: CliRunner, tmp_path: Path) -> None:
    """Only `ocsf` is supported in v0.10.1."""
    findings_in = _findings_json_fixture(tmp_path)
    result = runner.invoke(
        app,
        [
            "collect",
            "convert",
            "--input",
            str(findings_in),
            "--format",
            "sarif",
        ],
    )
    assert result.exit_code == 2
    assert "Unsupported --format" in result.output


def test_convert_rejects_non_list_input(runner: CliRunner, tmp_path: Path) -> None:
    """Input must be a JSON array of SecurityFinding objects."""
    bad = tmp_path / "scalar.json"
    bad.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "collect",
            "convert",
            "--input",
            str(bad),
            "--format",
            "ocsf",
        ],
    )
    assert result.exit_code == 1
    # Rich's console renderer wraps the error message across lines on
    # narrow CI terminals (caught by the v0.10.1 Linux pytest run —
    # the literal substring split across "must \nbe a JSON array").
    # Collapse whitespace before the substring check so the assertion
    # is wrap-resistant.
    normalized = " ".join(result.output.split())
    assert "must be a JSON array" in normalized


def test_collect_ocsf_emitted_event_action_exists() -> None:
    """The v0.10.1 EventAction.COLLECT_OCSF_EMITTED is defined."""
    assert EventAction.COLLECT_OCSF_EMITTED.value == "evidentia.collect.ocsf_emitted"
