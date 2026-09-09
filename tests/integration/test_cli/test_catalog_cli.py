"""Integration tests for `evidentia catalog` subcommands (v0.2.1 D7).

The v0.2.0 release introduced four new subcommands — ``import``, ``where``,
``license-info``, ``remove`` — and zero tests for any of them. These
tests run the commands end-to-end via Typer's CliRunner against a
tmp_path user-catalog directory so no state leaks into the real user
profile.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from evidentia.cli import catalog as catalog_cli
from evidentia.cli.main import app
from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.catalogs.user_dir import load_user_manifest
from rich.console import Console
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


def test_catalog_list_runs_without_error(runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(catalog_cli, "console", Console(width=80))
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


def test_catalog_list_shows_text_depth_column(runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    """The Text column shows each catalog's derived depth, not a declared one."""
    monkeypatch.setattr(catalog_cli, "console", Console(width=200))
    result = runner.invoke(app, ["catalog", "list"])
    assert result.exit_code == 0, result.output
    assert "Text" in result.output
    # The bundled set spans every depth except partial (none currently
    # exists): at least one full and one headings-only catalog ship.
    assert "headings" in result.output
    assert "full" in result.output


def test_catalog_license_info_shows_text_depth(runner: CliRunner) -> None:
    """nist-800-53-rev5 carries authoritative NIST text end to end."""
    result = runner.invoke(app, ["catalog", "license-info", "nist-800-53-rev5"])
    assert result.exit_code == 0, result.output
    assert "Text depth: full" in result.output


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

    # The user manifest entry carries a derived (non-null) text_depth,
    # computed from the imported catalog rather than left unset.
    user_manifest = load_user_manifest()
    imported_entry = user_manifest.get("my-custom-fw")
    assert imported_entry is not None
    assert imported_entry.text_depth is not None

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


@pytest.mark.parametrize("replace_existing", [False, True])
def test_invalid_catalog_import_preserves_existing_state(
    runner: CliRunner, tmp_path: Path, replace_existing: bool
) -> None:
    """Validation rejects content before publishing it in the user directory."""
    user_catalog = tmp_path / "user-catalogs" / "my-custom-fw.json"
    if replace_existing:
        original = _minimal_user_catalog(tmp_path)
        imported = runner.invoke(app, ["catalog", "import", str(original)])
        assert imported.exit_code == 0, imported.output
    previous_bytes = user_catalog.read_bytes() if replace_existing else None
    previous_manifest = load_user_manifest().model_dump()
    invalid = tmp_path / "invalid.json"
    invalid.write_text(
        json.dumps({"framework_id": "my-custom-fw", "controls": "invalid"}),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["catalog", "import", str(invalid), "--force"])

    assert result.exit_code == 1
    if replace_existing:
        assert user_catalog.read_bytes() == previous_bytes
    else:
        assert not user_catalog.exists()
    assert load_user_manifest().model_dump() == previous_manifest
    assert "Catalog validation failed" in result.output


def _profile_import_files(tmp_path: Path, shape: str = "grouped") -> tuple[Path, Path]:
    """Write valid OSCAL fixtures with a deliberately missing original href."""
    metadata = {
        "title": "Synthetic baseline",
        "last-modified": "2026-09-08T00:00:00Z",
        "version": "1.0",
        "oscal-version": "1.1.2",
    }
    control = {"id": "ac-1", "title": "Policy", "parts": [{"name": "statement", "prose": "Approve policy."}]}
    catalog = {"uuid": "a833f48b-3058-453b-a5bd-1f8e467ea0ac", "metadata": metadata}
    if shape == "top-level":
        catalog["controls"] = [control]
    else:
        group = {"id": "ac", "title": "Access Control", "controls": [control]}
        catalog["groups"] = [{"id": "security", "title": "Security", "groups": [group]} if shape == "nested" else group]
    source_path = tmp_path / "source.json"
    source_path.write_text(json.dumps({"catalog": catalog}), encoding="utf-8")
    profile = {
        "profile": {
            "uuid": "2528c1d6-9628-4a20-b5ed-04b8d0ddbc9b",
            "metadata": metadata,
            "imports": [{"href": "missing-original.json", "include-controls": [{"with-ids": ["ac-1"]}]}],
        }
    }
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    return profile_path, source_path


@pytest.mark.parametrize("shape", ["top-level", "grouped", "nested"])
def test_profile_import_uses_explicit_catalog(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    """--catalog supplies the source even when the original href is missing."""
    profile, source = _profile_import_files(tmp_path, shape)

    def unexpected_registry(*args: object, **kwargs: object) -> None:
        pytest.fail("Profile import consulted the unrelated bundled registry")

    monkeypatch.setattr(FrameworkRegistry, "get_instance", unexpected_registry)
    result = runner.invoke(
        app,
        ["catalog", "import", "--profile", str(profile), "--catalog", str(source), "--framework-id", "my-baseline"],
    )

    assert result.exit_code == 0, result.output
    assert "(1 controls)" in result.output
    saved = json.loads((tmp_path / "user-catalogs" / "my-baseline.json").read_text(encoding="utf-8"))
    assert [control["id"] for control in saved["controls"]] == ["AC-1"]
    assert saved["controls"][0]["description"] == "Approve policy."
    assert saved["families"] == ([] if shape == "top-level" else ["Access Control"])
    entry = load_user_manifest().get("my-baseline")
    assert entry is not None
    assert entry.text_depth == "full"


def test_profile_import_missing_override_preserves_user_state(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing explicit source fails before --force can replace a catalog."""
    original = _minimal_user_catalog(tmp_path)
    imported = runner.invoke(app, ["catalog", "import", str(original)])
    assert imported.exit_code == 0, imported.output
    saved_path = tmp_path / "user-catalogs" / "my-custom-fw.json"
    saved_bytes = saved_path.read_bytes()
    previous_manifest = load_user_manifest().model_dump()
    profile, source = _profile_import_files(tmp_path)
    profile_data = json.loads(profile.read_text(encoding="utf-8"))
    profile_data["profile"]["imports"][0]["href"] = source.name
    profile.write_text(json.dumps(profile_data), encoding="utf-8")
    missing_source = tmp_path / "missing-override.json"
    monkeypatch.setattr(catalog_cli, "console", Console(width=len(str(missing_source)) + 100))

    result = runner.invoke(
        app,
        [
            "catalog",
            "import",
            "--profile",
            str(profile),
            "--catalog",
            str(missing_source),
            "--framework-id",
            "my-custom-fw",
            "--force",
        ],
    )

    assert result.exit_code == 1, result.output
    assert "Profile resolution failed" in result.output
    assert "missing-override.json" in result.output
    assert saved_path.read_bytes() == saved_bytes
    assert load_user_manifest().model_dump() == previous_manifest


def test_profile_import_rejects_ambiguous_override(runner: CliRunner, tmp_path: Path) -> None:
    """A CLI override for multiple imports is rejected before publishing output."""
    profile, source = _profile_import_files(tmp_path)
    profile_data = json.loads(profile.read_text(encoding="utf-8"))
    profile_data["profile"]["imports"] = [
        {"href": source.name, "include-all": {}},
        {"href": "another.json", "include-all": {}},
    ]
    profile.write_text(json.dumps(profile_data), encoding="utf-8")

    result = runner.invoke(
        app,
        ["catalog", "import", "--profile", str(profile), "--catalog", str(source), "--framework-id", "my-baseline"],
    )

    assert result.exit_code == 1, result.output
    assert "multiple imports" in result.output
    assert not (tmp_path / "user-catalogs" / "my-baseline.json").exists()
    assert load_user_manifest().get("my-baseline") is None


@pytest.mark.parametrize("posix_directory_unlink", [False, True])
@pytest.mark.parametrize("replace_existing", [False, True])
def test_catalog_import_publishes_manifest_before_scratch_cleanup(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replace_existing: bool,
    posix_directory_unlink: bool,
) -> None:
    """A locked staging directory cannot leave the published catalog without its manifest."""
    source = _minimal_user_catalog(tmp_path)
    if replace_existing:
        initial = runner.invoke(app, ["catalog", "import", str(source)])
        assert initial.exit_code == 0, initial.output
    replacement = json.loads(source.read_text(encoding="utf-8"))
    replacement["framework_name"] = "Replacement framework"
    replacement["version"] = "2.0"
    replacement["controls"][0]["description"] = ""
    source.write_text(json.dumps(replacement), encoding="utf-8")
    real_rmdir = os.rmdir
    real_unlink = os.unlink
    manifests_at_cleanup = []

    def locked_staging_directory(path: str, *args: object, **kwargs: object) -> None:
        if Path(path).name.startswith(".catalog-import-"):
            manifests_at_cleanup.append(load_user_manifest().model_dump(mode="json"))
            raise PermissionError("Synthetic staging directory lock")
        real_rmdir(path, *args, **kwargs)

    def posix_unlink(path: str, *args: object, **kwargs: object) -> None:
        if Path(path).name.startswith(".catalog-import-"):
            raise IsADirectoryError("POSIX unlink cannot remove a staging directory")
        real_unlink(path, *args, **kwargs)

    with monkeypatch.context() as cleanup_fault:
        cleanup_fault.setattr(os, "rmdir", locked_staging_directory)
        if posix_directory_unlink:
            cleanup_fault.setattr(os, "unlink", posix_unlink)
        result = runner.invoke(
            app,
            ["catalog", "import", str(source), "--force", "--tier", "B", "--license-terms", "Synthetic license"],
        )

    assert manifests_at_cleanup, "The test must exercise real temporary-directory cleanup"
    assert result.exit_code == 0, result.output
    saved = json.loads((tmp_path / "user-catalogs" / "my-custom-fw.json").read_text(encoding="utf-8"))
    assert saved == replacement
    entry = load_user_manifest().get("my-custom-fw")
    assert entry is not None
    assert entry.name == "Replacement framework"
    assert entry.version == "2.0"
    assert entry.tier == "B"
    assert entry.path == "my-custom-fw.json"
    assert entry.placeholder is False
    assert entry.license == "Synthetic license"
    assert entry.text_depth == "headings"
    assert all(manifest == load_user_manifest().model_dump(mode="json") for manifest in manifests_at_cleanup)


def test_imported_currency_is_visible_and_preserved(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(catalog_cli, "console", Console(width=200))
    path = _minimal_user_catalog(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data.update(
        {
            "status": "retired",
            "notes": "[source] Consult successor.",
            "verified_on": "2026-09-09",
            "superseded_by": "my-next-fw",
            "source": "https://example.org/source",
            "license_url": "https://example.org/license",
            "license_required": True,
        }
    )
    path.write_text(json.dumps(data), encoding="utf-8")
    result = runner.invoke(app, ["catalog", "import", str(path), "--tier", "C"])
    assert result.exit_code == 0, result.output
    entry = load_user_manifest().get("my-custom-fw")
    assert entry and entry.status == "retired"
    assert entry.superseded_by == "my-next-fw"
    assert entry.license_required
    for command in ("where", "license-info", "show"):
        result = runner.invoke(app, ["catalog", command, "my-custom-fw"])
        assert result.exit_code == 0, result.output
        assert "retired" in result.output
        assert "[source] Consult successor." in result.output
        assert "2026-09-09" in result.output
    listing = runner.invoke(app, ["catalog", "list", "--user-only"])
    assert listing.exit_code == 0, listing.output
    assert "retired" in listing.output


def test_show_exposes_dates_without_treating_publications_as_controls(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(catalog_cli, "console", Console(width=200))
    result = runner.invoke(app, ["catalog", "show", "nerc-cip-v7"])
    assert result.exit_code == 0, result.output
    assert "Published revisions" in result.output
    assert "CIP-015-2" in result.output
    assert "2029-10-01" in result.output
    assert "Total: 13 controls" in result.output
    result = runner.invoke(app, ["catalog", "show", "nerc-cip-v7", "--control", "CIP-012-2"])
    assert result.exit_code == 0, result.output
    assert "2026-07-01" in result.output


@pytest.mark.parametrize("field", ["source", "license_url", "license_terms"])
def test_imported_license_metadata_is_rendered_literally(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    monkeypatch.setattr(catalog_cli, "console", Console(width=200))
    source = _minimal_user_catalog(tmp_path)
    data = json.loads(source.read_text(encoding="utf-8"))
    data[field] = "https://example.org/[/bold]"
    source.write_text(json.dumps(data), encoding="utf-8")
    result = runner.invoke(app, ["catalog", "import", str(source), "--tier", "C"])
    assert result.exit_code == 0, result.output
    result = runner.invoke(app, ["catalog", "license-info", "my-custom-fw"])
    assert result.exit_code == 0, result.output
    assert "https://example.org/[/bold]" in result.output
