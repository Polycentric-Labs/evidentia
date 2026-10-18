"""Signing flags with a format that cannot be signed are a usage error (v0.13.0 review, CWE-636)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_BOX = re.compile(f"[{chr(0x2500)}-{chr(0x257F)}]")  # box drawing block


def _plain(text: str) -> str:
    """Collapse Rich rendering: strip ANSI codes and box drawing, join wrapped lines."""
    return " ".join(_BOX.sub(" ", _ANSI.sub("", text)).split())


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.mark.parametrize("fmt", ["json", "sarif", "csv"])
def test_sign_with_key_and_non_oscal_format_exit_2(runner: CliRunner, tmp_path: Path, fmt: str) -> None:
    key = tmp_path / "signing.pem"
    key.write_text("not a real key; never read because the usage error fires first\n", encoding="utf-8")
    out = tmp_path / f"report.{fmt}"
    result = runner.invoke(
        app,
        [
            "gap",
            "analyze",
            "--inventory",
            str(FIXTURES / "sample-inventory.yaml"),
            "--frameworks",
            "nist-800-53-mod",
            "--output",
            str(out),
            "--format",
            fmt,
            "--sign-with-key",
            str(key),
        ],
    )
    assert result.exit_code == 2, result.output
    # Typer renders the usage error in a Rich panel whose width depends on the
    # runner, so the message is checked after the rendering is flattened.
    assert "only applies to --format oscal-ar" in _plain(result.output)
    assert not out.exists()


def test_sign_with_sigstore_and_json_format_exit_2(runner: CliRunner, tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "gap",
            "analyze",
            "--inventory",
            str(FIXTURES / "sample-inventory.yaml"),
            "--frameworks",
            "nist-800-53-mod",
            "--output",
            str(out),
            "--format",
            "json",
            "--sign-with-sigstore",
        ],
    )
    assert result.exit_code == 2, result.output
    assert "--sign-with-sigstore" in _plain(result.output)
    assert not out.exists()
