"""Integration tests for `evidentia catalog` subcommands (v0.2.1 D7).

The v0.2.0 release introduced four new subcommands — ``import``, ``where``,
``license-info``, ``remove`` — and zero tests for any of them. These
tests run the commands end-to-end via Typer's CliRunner against a
tmp_path user-catalog directory so no state leaks into the real user
profile.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia.cli.main import app
from evidentia_core.catalogs.registry import FrameworkRegistry
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _isolated_user_dir(tmp_path: Path, monkeypatch):
    """Point EVIDENTIA_CATALOG_DIR at an isolated tmp for each test."""
    user_dir = tmp_path / "user-catalogs"
    monkeypatch.setenv("EVIDENTIA_CATALOG_DIR", str(user_dir))
    # Also reset the registry singleton so it doesn't cache the bundled
    # manifest across tests.
    FrameworkRegistry.reset_instance()
    yield user_dir
    FrameworkRegistry.reset_instance()


def _minimal_user_catalog(tmp_path: Path, framework_id: str = "my-custom-fw") -> Path:
    """Write a tiny Evidentia-format catalog to disk for import."""
    path = tmp_path / f"{framework_id}.json"
    path.write_text(
        json.dumps(
            {
                "framework_id": framework_id,
                "framework_name": "My Custom Framework",
                "version": "1.0",
                "source": "Local test fixture",
                "tier": "A",
                "category": "control",
                "placeholder": False,
                "families": ["Access Control"],
                "controls": [
                    {
                        "id": "CUST-1",
                        "title": "Custom Control 1",
                        "description": "Do something important.",
                        "family": "Access Control",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


# -----------------------------------------------------------------------------
# catalog list (with new filters)
# -----------------------------------------------------------------------------


def test_catalog_list_runs_without_error(runner: CliRunner) -> None:
    result = runner.invoke(app, ["catalog", "list"])
    assert result.exit_code == 0, result.output
    assert "Framework" in result.output


def test_catalog_list_tier_filter(runner: CliRunner) -> None:
    """--tier A narrows to Tier-A frameworks only."""
    result = runner.invoke(app, ["catalog", "list", "--tier", "A"])
    assert result.exit_code == 0, result.output
    # Bundled NIST 800-53-mod is Tier A — should appear
    assert "nist-800-53-mod" in result.output


def test_catalog_list_category_filter(runner: CliRunner) -> None:
    result = runner.invoke(app, ["catalog", "list", "--category", "obligation"])
    assert result.exit_code == 0, result.output
    # GDPR is an obligation catalog
    assert "eu-gdpr" in result.output or "obligation" in result.output


# -----------------------------------------------------------------------------
# catalog import / where / license-info / remove — round trip
# -----------------------------------------------------------------------------


def test_catalog_import_then_where_then_remove(runner: CliRunner, tmp_path: Path, _isolated_user_dir: Path) -> None:
    """Full round trip: import a user catalog, look it up, remove it."""
    source = _minimal_user_catalog(tmp_path)

    # Import
    result = runner.invoke(app, ["catalog", "import", str(source)])
    assert result.exit_code == 0, result.output
    assert "Imported" in result.output or "imported" in result.output

    # Where
    result = runner.invoke(app, ["catalog", "where", "my-custom-fw"])
    assert result.exit_code == 0, result.output
    assert "user" in result.output.lower()

    # License-info
    result = runner.invoke(app, ["catalog", "license-info", "my-custom-fw"])
    assert result.exit_code == 0, result.output

    # Remove (with --yes to skip confirmation)
    result = runner.invoke(app, ["catalog", "remove", "my-custom-fw", "--yes"])
    assert result.exit_code == 0, result.output

    # Where should now fail
    result = runner.invoke(app, ["catalog", "where", "my-custom-fw"])
    assert result.exit_code != 0, (
        f"Expected failure after remove, got exit_code={result.exit_code} output={result.output!r}"
    )


def test_catalog_import_with_framework_id_override(runner: CliRunner, tmp_path: Path) -> None:
    """--framework-id flag overrides the ID in the source JSON."""
    source = _minimal_user_catalog(tmp_path, framework_id="original-id")
    result = runner.invoke(
        app,
        [
            "catalog",
            "import",
            str(source),
            "--framework-id",
            "overridden-id",
        ],
    )
    assert result.exit_code == 0, result.output
    # where with overridden id should succeed
    result = runner.invoke(app, ["catalog", "where", "overridden-id"])
    assert result.exit_code == 0, result.output


def test_catalog_import_refuses_duplicate_without_force(runner: CliRunner, tmp_path: Path) -> None:
    """Second import with the same id errors out without --force."""
    source = _minimal_user_catalog(tmp_path)
    r1 = runner.invoke(app, ["catalog", "import", str(source)])
    assert r1.exit_code == 0, r1.output

    r2 = runner.invoke(app, ["catalog", "import", str(source)])
    assert r2.exit_code != 0, r2.output
    assert "force" in r2.output.lower()


def test_catalog_import_force_overwrites(runner: CliRunner, tmp_path: Path) -> None:
    source = _minimal_user_catalog(tmp_path)
    r1 = runner.invoke(app, ["catalog", "import", str(source)])
    assert r1.exit_code == 0, r1.output
    r2 = runner.invoke(app, ["catalog", "import", str(source), "--force"])
    assert r2.exit_code == 0, r2.output


def test_catalog_remove_unknown_framework_errors(runner: CliRunner) -> None:
    result = runner.invoke(app, ["catalog", "remove", "nonexistent-fw", "--yes"])
    assert result.exit_code != 0, result.output


def test_catalog_where_unknown_framework_errors(runner: CliRunner) -> None:
    result = runner.invoke(app, ["catalog", "where", "bogus-fw-id"])
    assert result.exit_code != 0, result.output


# -----------------------------------------------------------------------------
# User-import shadowing of bundled catalogs
# -----------------------------------------------------------------------------


def test_user_catalog_shadows_bundled(runner: CliRunner, tmp_path: Path) -> None:
    """A user-imported catalog with the same id as bundled should take precedence."""
    # Import a custom version of nist-800-53-mod (a bundled id)
    source = _minimal_user_catalog(tmp_path, framework_id="nist-800-53-mod")
    result = runner.invoke(app, ["catalog", "import", str(source), "--force"])
    assert result.exit_code == 0, result.output

    # where should report user source
    result = runner.invoke(app, ["catalog", "where", "nist-800-53-mod"])
    assert result.exit_code == 0, result.output
    assert "user" in result.output.lower() or "shadow" in result.output.lower()


# -----------------------------------------------------------------------------
# doctor (smoke)
# -----------------------------------------------------------------------------


def test_doctor_runs_cleanly(runner: CliRunner) -> None:
    """`evidentia doctor` must report all components at 'OK'."""
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    # Must report at least the NIST catalog count
    assert "frameworks registered" in result.output


def test_version_command(runner: CliRunner) -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0, result.output
    assert "Evidentia" in result.output
