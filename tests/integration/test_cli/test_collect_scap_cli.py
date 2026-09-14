"""Verify the actual SCAP command, role gate, claims and output selection."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from evidentia.cli import _rbac, _scap_io
from evidentia.cli.main import app
from evidentia_core.rbac import RBACPolicy, Role
from typer.testing import CliRunner, Result

from .test_scap_io import PROFILES, assertion_bytes, source_bytes


@pytest.fixture
def cli_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    monkeypatch.chdir(tmp_path)
    for key in ("EVIDENTIA_RBAC_POLICY_FILE", "EVIDENTIA_RBAC_IDENTITY", "EVIDENTIA_RBAC_TENANT"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(_rbac, "get_rbac_policy", lambda: RBACPolicy(default_role=Role.READER))
    monkeypatch.setattr(_rbac, "get_rbac_identity", lambda: "Synthetic reader")
    config, source = tmp_path / "settings.yaml", tmp_path / "source.xml"
    config.write_bytes(b"{}\n")
    source.write_bytes(source_bytes("xccdf-1.2-native.xml"))
    return config, source


def invoke(settings: tuple[Path, Path], *options: str, profile: str = "xccdf-1.2-results") -> Result:
    config, source = settings
    return CliRunner().invoke(
        app,
        [
            "--config",
            str(config),
            "collect",
            "scap",
            "--file",
            str(source),
            "--source-profile",
            profile,
            "--assessment-index",
            "0",
            *options,
        ],
    )


def test_read_rbac_refuses_before_adapter_or_file_work(
    cli_settings: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_rbac, "get_rbac_policy", lambda: RBACPolicy(default_role=Role.DENY))
    run = Mock(side_effect=AssertionError("Unauthorized CLI reached file work"))
    monkeypatch.setattr(_scap_io, "run_scap", run)
    result = invoke(cli_settings)
    assert result.exit_code == 77 and result.stdout == ""
    run.assert_not_called()


@pytest.mark.parametrize("profile,filename", PROFILES)
def test_actual_command_preserves_full_null_or_qualified_result(
    cli_settings: tuple[Path, Path],
    profile: str,
    filename: str,
) -> None:
    cli_settings[1].write_bytes(source_bytes(filename))
    result = invoke(cli_settings, profile=profile)
    assert result.exit_code == 0, result.stderr
    assert result.stderr == ""
    body = json.loads(result.stdout)
    assert body["source"]["profile"] == profile
    assert body["assessment"]["selection"]["assessment_index"] == 0
    assert (body["evidence_artifact"] is None) == profile.startswith("oval-")
    assert len(body["findings"]) == 1


@pytest.mark.parametrize("profile,filename", PROFILES[1:])
def test_cli_assertion_records_caller_actor_and_exact_source(
    cli_settings: tuple[Path, Path],
    tmp_path: Path,
    profile: str,
    filename: str,
) -> None:
    raw = source_bytes(filename)
    cli_settings[1].write_bytes(raw)
    sidecar = tmp_path / "claim.json"
    sidecar.write_bytes(assertion_bytes(raw, profile))
    result = invoke(
        cli_settings,
        "--completion-assertion",
        str(sidecar),
        "--asserted-by",
        "Synthetic operator",
        "--output-view",
        "artifact",
        profile=profile,
    )
    assert result.exit_code == 0, result.stderr
    artifact = json.loads(result.stdout)
    assert artifact["version"] == 1 and artifact["lineage_id"] is None
    actor = artifact["content"]["completion"]["assertion"]["actor"]
    assert actor == {"basis": "caller_declared", "subject": "Synthetic operator", "provider": None}
    assert artifact["collected_at"] == "2024-03-01T00:00:00Z"


@pytest.mark.parametrize("options", [("--asserted-by", "Synthetic operator"), ("--output-view", "unknown")])
def test_invalid_options_emit_no_result(cli_settings: tuple[Path, Path], options: tuple[str, str]) -> None:
    result = invoke(cli_settings, *options)
    assert result.exit_code == 2 and result.stdout == ""


@pytest.mark.parametrize("body", [b"<broken", b"", b"<!DOCTYPE a [<!ENTITY x 'value'>]><a>&x;</a>"])
def test_source_refusal_preserves_existing_output(
    cli_settings: tuple[Path, Path],
    tmp_path: Path,
    body: bytes,
) -> None:
    cli_settings[1].write_bytes(body)
    output = tmp_path / "result.json"
    output.write_bytes(b"existing output")
    result = invoke(cli_settings, "--output", str(output))
    assert result.exit_code == 2 and result.stdout == ""
    assert output.read_bytes() == b"existing output"
    assert str(cli_settings[1]) not in result.stderr and "<broken" not in result.stderr


def test_unknown_profile_and_missing_selection_are_explicit(cli_settings: tuple[Path, Path]) -> None:
    wrong = invoke(cli_settings, profile="oval-5")
    assert wrong.exit_code == 2 and wrong.stdout == "" and "Unsupported SCAP source profile." in wrong.stderr
    missing = invoke(cli_settings, "--assessment-index", "255")
    assert missing.exit_code == 2 and missing.stdout == "" and "selected assessment" in missing.stderr


def test_claim_binding_refusal_is_fixed(cli_settings: tuple[Path, Path], tmp_path: Path) -> None:
    raw = source_bytes("oval-5.8-native.xml")
    cli_settings[1].write_bytes(raw)
    claim = tmp_path / "claim.json"
    claim.write_bytes(assertion_bytes(raw, source_sha256="0" * 64))
    result = invoke(
        cli_settings,
        "--completion-assertion",
        str(claim),
        "--asserted-by",
        "Synthetic operator",
        profile="oval-5.8-core-results",
    )
    assert result.exit_code == 2 and result.stdout == ""
    assert result.stderr.strip() == "The completion assertion does not match the selected source."
