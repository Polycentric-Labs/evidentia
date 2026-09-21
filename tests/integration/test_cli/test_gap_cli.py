"""Integration tests for `evidentia gap analyze` — SARIF output (v0.10.0).

v0.10.0 adds a ``sarif`` choice to ``evidentia gap analyze --format``.
These tests drive the command end-to-end via Typer's CliRunner against
the persistent fixture inventory, so the test exercises argument
parsing, the format plumbing through ``export_report``, and the written
artifact — not just the library serializer (covered by
``tests/unit/test_gap_analyzer/test_sarif.py``).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from evidentia.cli.main import app
from evidentia_core.catalogs.registry import FrameworkRegistry
from typer.testing import CliRunner

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep the gap-store snapshot side effect out of the real profile."""
    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(tmp_path / "gap-store"))
    FrameworkRegistry.reset_instance()
    yield
    FrameworkRegistry.reset_instance()


def test_gap_analyze_sarif_format(runner: CliRunner, tmp_path: Path) -> None:
    """`gap analyze --format sarif` writes a valid SARIF 2.1.0 log."""
    out = tmp_path / "gaps.sarif"
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
            "sarif",
        ],
    )

    assert result.exit_code == 0, result.output
    assert out.exists()

    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Evidentia"
    # The sample inventory is intentionally incomplete, so analysis
    # against nist-800-53-mod yields gaps -> SARIF results.
    assert run["results"], "expected the fixture analysis to surface gaps"
    for res in run["results"]:
        assert res["ruleId"]
        assert res["level"] in {"error", "warning", "note", "none"}
        assert res["partialFingerprints"]


@pytest.mark.parametrize("version", [None, "1.6", "1.7"])
def test_gap_analyze_vex_version_is_explicit(
    runner: CliRunner,
    tmp_path: Path,
    version: str | None,
) -> None:
    output = tmp_path / "gap.vex.cdx.json"
    argv = [
        "gap",
        "analyze",
        "--inventory",
        str(FIXTURES / "sample-inventory.yaml"),
        "--frameworks",
        "soc2-tsc",
        "--format",
        "cyclonedx-vex",
        "--output",
        str(output),
    ]
    if version is not None:
        argv += ["--vex-spec-version", version]
    result = runner.invoke(app, argv)
    assert result.exit_code == 0, result.output
    document = json.loads(output.read_bytes())
    assert document["specVersion"] == (version or "1.6")
    assert document["bomFormat"] == "CycloneDX"
    assert document["vulnerabilities"]
    assert all(set(item["analysis"]) == {"detail"} for item in document["vulnerabilities"])


@pytest.mark.parametrize(
    "format,version",
    [
        ("cyclonedx-vex", "1.5"),
        ("cyclonedx-vex", "1.8"),
        ("cyclonedx-vex", " 1.7"),
        ("cyclonedx-vex", "1.7 "),
        ("cyclonedx-vex", ""),
        ("json", "1.6"),
        ("json", "1.7"),
        ("oscal-ar", "1.7"),
        ("sarif", "1.6"),
    ],
)
def test_vex_option_refuses_before_inventory_analyzer_export_store_or_signing(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    format: str,
    version: str,
) -> None:
    from unittest.mock import Mock

    from evidentia.cli import gap as command
    from evidentia_core import gap_store

    inventory = tmp_path / "inventory.json"
    inventory.write_text("{}", encoding="utf-8")
    output = tmp_path / "existing.json"
    output.write_bytes(b"original artifact")
    effects = Mock(side_effect=AssertionError("effect before selector validation"))
    for name in ("load_inventory", "GapAnalyzer", "export_report"):
        monkeypatch.setattr(command, name, effects)
    monkeypatch.setattr(gap_store, "save_report", effects)
    result = runner.invoke(
        app,
        [
            "gap",
            "analyze",
            "--inventory",
            str(inventory),
            "--frameworks",
            "soc2-tsc",
            "--output",
            str(output),
            "--format",
            format,
            "--vex-spec-version",
            version,
            "--sign-with-sigstore",
        ],
    )
    assert result.exit_code == 2, result.output
    effects.assert_not_called()
    assert output.read_bytes() == b"original artifact"
    assert not (tmp_path / "gap-store").exists()
