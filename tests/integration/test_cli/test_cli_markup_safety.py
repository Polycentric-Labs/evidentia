"""Identifiers echoed by the CLI are markup-escaped (v0.13.0 review, probe-core LOW)."""

from __future__ import annotations

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.mark.parametrize("verb", ["show", "license-info", "where"])
def test_catalog_verbs_echo_hostile_framework_ids_safely(runner: CliRunner, verb: str) -> None:
    result = runner.invoke(app, ["catalog", verb, "[/x]nope[link=https://evil.example]"])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "MarkupError" not in result.output


def test_catalog_crosswalk_echoes_hostile_ids_safely(runner: CliRunner) -> None:
    result = runner.invoke(app, ["catalog", "crosswalk", "[/x]src", "AC-2", "--to", "[/y]dst"])
    assert "Traceback" not in result.output
    assert "MarkupError" not in result.output
