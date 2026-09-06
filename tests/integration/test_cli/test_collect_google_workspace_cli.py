"""Integration test for `evidentia collect google-workspace` (v0.13 batch 7)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from evidentia.cli.main import app
from evidentia_core.models.finding import SecurityFinding
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _fixture_findings() -> list[SecurityFinding]:
    return [
        SecurityFinding(
            title="Google Workspace user inventory: 2 total, 2 active, 0 suspended, 0 archived",
            description="Fixture finding one for the CLI happy-path test.",
            severity="informational",
            source_system="google-workspace",
            source_finding_id="user-inventory:google-workspace:my_customer",
        ),
        SecurityFinding(
            title="Google Workspace admin accounts: 1 super admin(s), 0 delegated admin(s)",
            description="Fixture finding two for the CLI happy-path test.",
            severity="informational",
            source_system="google-workspace",
            source_finding_id="admin-accounts:google-workspace:my_customer",
        ),
    ]


class _FakeGoogleWorkspaceCollector:
    """A context-manager stand-in for GoogleWorkspaceCollector: no network."""

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs

    def __enter__(self) -> _FakeGoogleWorkspaceCollector:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def collect(self) -> list[SecurityFinding]:
        return _fixture_findings()


def test_missing_env_var_exits_1_and_names_it(runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GOOGLE_WORKSPACE_ACCESS_TOKEN", raising=False)
    result = runner.invoke(app, ["collect", "google-workspace"])
    assert result.exit_code == 1
    assert "GOOGLE_WORKSPACE_ACCESS_TOKEN" in result.output


def test_login_window_days_out_of_range_exits_2(runner: CliRunner) -> None:
    result = runner.invoke(
        app,
        ["collect", "google-workspace", "--login-window-days", "181"],
    )
    assert result.exit_code == 2


def test_happy_path_writes_findings_and_renders_summary(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GOOGLE_WORKSPACE_ACCESS_TOKEN", "dummy-token")
    monkeypatch.setattr(
        "evidentia_collectors.google_workspace.GoogleWorkspaceCollector",
        _FakeGoogleWorkspaceCollector,
    )
    out = tmp_path / "findings.json"
    result = runner.invoke(
        app,
        [
            "collect",
            "google-workspace",
            "--customer",
            "my_customer",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    findings = json.loads(out.read_text(encoding="utf-8"))
    assert len(findings) == 2
    assert "Wrote 2 findings" in result.output
    assert "2 total" in result.output
