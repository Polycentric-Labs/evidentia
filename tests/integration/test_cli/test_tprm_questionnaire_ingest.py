"""Regression tests for `evidentia tprm dd-questionnaire ingest` rendering.

``CompletedQuestionnaire.format`` is an enum field on an ``EvidentiaModel``
(``use_enum_values=True``), so a questionnaire parsed from disk carries
``format`` as a plain ``str``. The ingest command rendered it via
``completed.format.value`` unconditionally, which crashed with
``AttributeError: 'str' object has no attribute 'value'`` for every file
``dd-questionnaire generate`` produces. These tests pin the str-safe render on
both the table and JSON output paths.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _isolated_vendor_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Scope EVIDENTIA_VENDOR_STORE_DIR to a per-test tmp dir."""
    store = tmp_path / "vendor-store"
    monkeypatch.setenv("EVIDENTIA_VENDOR_STORE_DIR", str(store))
    return store


def _add_vendor(runner: CliRunner) -> str:
    """Add a vendor and return its UUID (parsed from `vendor list --json`)."""
    add = runner.invoke(
        app,
        [
            "tprm",
            "vendor",
            "add",
            "--name",
            "Acme Cloud",
            "--type",
            "cloud_provider",
            "--criticality-tier",
            "critical",
            "--owner",
            "allen@example.com",
            "--contract-start-date",
            "2025-01-01",
        ],
    )
    assert add.exit_code == 0, add.output
    listing = runner.invoke(app, ["tprm", "vendor", "list", "--json"])
    assert listing.exit_code == 0, listing.output
    match = _UUID_RE.search(listing.output)
    assert match is not None, f"no vendor UUID in: {listing.output}"
    return match.group(0)


def _generate(runner: CliRunner, vendor_id: str, dest: Path) -> None:
    gen = runner.invoke(
        app,
        [
            "tprm",
            "dd-questionnaire",
            "generate",
            "--vendor-id",
            vendor_id,
            "--format",
            "evidentia-generic",
            "--output-format",
            "json",
            "--output",
            str(dest),
        ],
    )
    assert gen.exit_code == 0, gen.output
    assert dest.exists()


class TestDdQuestionnaireIngestRender:
    def test_ingest_table_output_does_not_crash(self, runner: CliRunner, tmp_path: Path) -> None:
        vendor_id = _add_vendor(runner)
        qfile = tmp_path / "completed.json"
        _generate(runner, vendor_id, qfile)

        result = runner.invoke(
            app,
            [
                "tprm",
                "dd-questionnaire",
                "ingest",
                "--questionnaire",
                str(qfile),
                "--vendor-id",
                vendor_id,
            ],
        )

        assert result.exit_code == 0, result.output
        assert "AttributeError" not in result.output
        # The format field renders as its string value, not a crash.
        assert "evidentia-generic" in result.output

    def test_ingest_json_output_renders_format_value(self, runner: CliRunner, tmp_path: Path) -> None:
        vendor_id = _add_vendor(runner)
        qfile = tmp_path / "completed.json"
        _generate(runner, vendor_id, qfile)

        result = runner.invoke(
            app,
            [
                "tprm",
                "dd-questionnaire",
                "ingest",
                "--questionnaire",
                str(qfile),
                "--vendor-id",
                vendor_id,
                "--output-format",
                "json",
            ],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["format"] == "evidentia-generic"
