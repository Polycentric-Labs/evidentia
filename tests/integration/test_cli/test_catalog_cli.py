"""Integration tests for `evidentia catalog` subcommands (v0.2.1 D7).

The v0.2.0 release introduced four new subcommands - ``import``, ``where``,
``license-info``, ``remove`` - and zero tests for any of them. These
tests run the commands end-to-end via Typer's CliRunner against a
tmp_path user-catalog directory so no state leaks into the real user
profile.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from types import FunctionType, SimpleNamespace

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


def _imported_path(tmp_path: Path, framework_id: str) -> Path:
    entry = load_user_manifest().get(framework_id)
    assert entry is not None
    return tmp_path / "user-catalogs" / entry.path


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
    # Bundled NIST 800-53-mod is Tier A - should appear
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
# catalog import / where / license-info / remove - round trip
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
    user_catalog = tmp_path / "user-catalogs" / "never-published.json"
    if replace_existing:
        original = _minimal_user_catalog(tmp_path)
        imported = runner.invoke(app, ["catalog", "import", str(original)])
        assert imported.exit_code == 0, imported.output
        user_catalog = _imported_path(tmp_path, "my-custom-fw")
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
    saved = json.loads(_imported_path(tmp_path, "my-baseline").read_text(encoding="utf-8"))
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
    saved_path = _imported_path(tmp_path, "my-custom-fw")
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
    saved = json.loads(_imported_path(tmp_path, "my-custom-fw").read_text(encoding="utf-8"))
    assert saved == replacement
    entry = load_user_manifest().get("my-custom-fw")
    assert entry is not None
    assert entry.name == "Replacement framework"
    assert entry.version == "2.0"
    assert entry.tier == "B"
    assert entry.path == "legacy/" + hashlib.sha256(source.read_bytes()).hexdigest() + "/catalog.json"
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


@pytest.mark.parametrize("nested", [False, True])
def test_source_rows_are_visible_without_becoming_controls(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, nested: bool
) -> None:
    monkeypatch.setattr(catalog_cli, "console", Console(width=200))
    source = _minimal_user_catalog(tmp_path)
    data = json.loads(source.read_text(encoding="utf-8"))
    row = {
        "source_sha256": "a" * 64,
        "sheet": "Evidence [/bold]",
        "row": 1461,
        "source_id": 5.2,
        "source_id_format": "0.00",
        "interpreted_id": "5.20",
        "kind": "fragment",
        "values": {
            "Location": 5.2,
            "Physical blank": None,
            "Empty text": "",
            "Boolean": False,
            "Whole number": 5,
            "Decimal": 5.0,
            "Negative zero": -0.0,
            "Large number": 2**80,
            "Literal": "[/bold] <script>alert(1)</script>",
            "Date": "2026-06-25",
        },
        "resolved_values": {"Physical blank": "Existing"},
        "provenance": {"Physical blank": "U1460:U1462; anchor U1460"},
    }
    ctrl = data["controls"][0]
    if nested:
        leaf = {"id": "CUST-1-A-I", "title": "Nested source", "description": "Source statement", "source_rows": [row]}
        ctrl["enhancements"] = [
            {"id": "CUST-1-A", "title": "Intermediate", "description": "Group", "enhancements": [leaf]}
        ]
        target = leaf["id"]
    else:
        ctrl["source_rows"] = [row]
        target = ctrl["id"]
    source.write_text(json.dumps(data), encoding="utf-8")
    imported = runner.invoke(app, ["catalog", "import", str(source)])
    assert imported.exit_code == 0, imported.output
    shown = runner.invoke(app, ["catalog", "show", "my-custom-fw", "--control", target])
    assert shown.exit_code == 0, shown.output
    assert "Source evidence" in shown.output
    for key, value in row.items():
        if isinstance(value, dict):
            for cell, scalar in value.items():
                assert json.dumps(cell) + ": " + json.dumps(scalar) in shown.output
        else:
            assert json.dumps(key) + ": " + json.dumps(value) in shown.output
    listing = runner.invoke(app, ["catalog", "show", "my-custom-fw"])
    assert listing.exit_code == 0, listing.output
    assert "Total: 1 controls" in listing.output
    assert "Source evidence" not in listing.output


@pytest.mark.parametrize("field", ["title", "description", "family", "objective", "guidance"])
def test_control_source_text_is_rendered_literally(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    monkeypatch.setattr(catalog_cli, "console", Console(width=200))
    source = _minimal_user_catalog(tmp_path)
    data = json.loads(source.read_text(encoding="utf-8"))
    literal = "Source [/bold] <script>alert(1)</script>"
    data["controls"][0][field] = literal
    source.write_text(json.dumps(data), encoding="utf-8")
    imported = runner.invoke(app, ["catalog", "import", str(source)])
    assert imported.exit_code == 0, imported.output
    shown = runner.invoke(app, ["catalog", "show", "my-custom-fw", "--control", "CUST-1"])
    assert shown.exit_code == 0, shown.output
    assert literal in shown.output


# Optional API discovery is separate from importing an installed package.
class _AirGapStop(BaseException):
    pass


class _AirGapTable:
    def __init__(self, *, title: str) -> None:
        self.title = title
        self.columns: list[tuple[str, dict[str, object]]] = []
        self.rows: list[tuple[str, ...]] = []

    def add_column(self, label: str, **options: object) -> None:
        self.columns.append((label, options))

    def add_row(self, *cells: str) -> None:
        self.rows.append(cells)


def _isolated_air_gap_report(
    *,
    available: bool = True,
    discovery_error: BaseException | None = None,
    import_error: BaseException | None = None,
) -> tuple[Callable[[], None], list[str], list[object]]:
    """Run the real report code with private globals and closed import stubs."""
    from evidentia.cli import main as cli_main

    events: list[str] = []
    emitted: list[object] = []

    def discover(name: str) -> object | None:
        assert name == "evidentia_api"
        events.append("discover")
        if discovery_error is not None:
            raise discovery_error
        return object() if available else None

    def config() -> SimpleNamespace:
        events.append("config")
        return SimpleNamespace(llm=None)

    def import_stub(
        name: str,
        globals: object = None,
        locals: object = None,
        fromlist: object = (),
        level: int = 0,
    ) -> object:
        assert level == 0
        if name == "os":
            return SimpleNamespace(environ={"EVIDENTIA_LLM_MODEL": "ollama/synthetic"})
        if name == "importlib.util":
            assert fromlist == ("find_spec",)
            return SimpleNamespace(find_spec=discover)
        if name == "evidentia_core.config":
            return SimpleNamespace(load_config=config)
        if name == "evidentia_core.network_guard":
            return SimpleNamespace(LOCAL_LLM_PREFIXES=("ollama/",), is_loopback_or_private=unexpected_host_check)
        if name == "evidentia_api":
            events.append("import")
            if import_error is not None:
                raise import_error
            if not available:
                raise ModuleNotFoundError("Synthetic absent package", name="evidentia_api")
            return SimpleNamespace()
        raise AssertionError("Unexpected import in isolated report: " + name)

    def unexpected_host_check(host: str) -> bool:
        raise AssertionError("The local model prefix needs no host check")

    original = cli_main._render_air_gap_report
    private_builtins = dict(vars(builtins))
    private_builtins["__import__"] = import_stub
    private_globals = dict(original.__globals__)
    private_globals.update(
        __builtins__=private_builtins,
        Table=_AirGapTable,
        console=SimpleNamespace(print=emitted.append),
    )
    report = FunctionType(
        original.__code__, private_globals, original.__name__, original.__defaults__, original.__closure__
    )
    return report, events, emitted


@pytest.mark.parametrize("available", [False, True], ids=["absent", "installed"])
def test_air_gap_optional_api_preserves_normal_table(available: bool) -> None:
    report, events, emitted = _isolated_air_gap_report(available=available)
    report()
    assert events == ["config", "discover"] + (["import"] if available else [])
    assert len(emitted) == 2
    table = emitted[0]
    assert isinstance(table, _AirGapTable)
    assert table.title == "Air-gap Posture Report"
    assert table.columns == [
        ("Subsystem", {"style": "cyan"}),
        ("Posture", {"style": "green"}),
        ("Detail", {}),
    ]
    rows = [
        ("LLM client", "AIR-GAP READY", "model=ollama/synthetic (local prefix)"),
        ("Catalog loader", "AIR-GAP READY", "v0.4.0 loads only from bundled + user-dir catalogs (no URL fetch)"),
        ("AI telemetry", "AIR-GAP READY", "LiteLLM + Instructor do not emit telemetry"),
        ("Gap store", "AIR-GAP READY", "platformdirs user-data (local filesystem only)"),
    ]
    if available:
        rows.append(("Web UI", "AIR-GAP READY", "\x60evidentia serve\x60 binds to 127.0.0.1 by default"))
    assert table.rows == rows
    assert emitted[1] == (
        "\n[dim]Pass [bold cyan]--offline[/bold cyan] on any command to enforce; "
        "this report audits the configuration, not live traffic.[/dim]"
    )


@pytest.mark.parametrize(
    "failure",
    [
        ModuleNotFoundError("Synthetic transitive import failure", name="synthetic_dependency"),
        ModuleNotFoundError("Synthetic package disappeared after discovery", name="evidentia_api"),
        ImportError("Synthetic ordinary import failure"),
        RuntimeError("Synthetic package initialization failure"),
    ],
    ids=["transitive", "disappeared", "ordinary-import", "initialization"],
)
def test_air_gap_installed_api_failure_propagates(failure: Exception) -> None:
    report, events, emitted = _isolated_air_gap_report(import_error=failure)
    with pytest.raises(type(failure)) as caught:
        report()
    assert caught.value is failure
    assert events == ["config", "discover", "import"]
    assert emitted == []


@pytest.mark.parametrize(
    "failure",
    [
        ModuleNotFoundError("Synthetic discovery import failure", name="synthetic_finder"),
        ImportError("Synthetic finder import failure"),
        ValueError("Synthetic unavailable module spec"),
        RuntimeError("Synthetic finder failure"),
    ],
    ids=["discovery-module", "discovery-import", "invalid-spec", "finder"],
)
def test_air_gap_api_discovery_failure_propagates(failure: Exception) -> None:
    report, events, emitted = _isolated_air_gap_report(discovery_error=failure)
    with pytest.raises(type(failure)) as caught:
        report()
    assert caught.value is failure
    assert events == ["config", "discover"]
    assert emitted == []


@pytest.mark.parametrize("stage", ["discovery", "import"])
@pytest.mark.parametrize("failure_type", [_AirGapStop, KeyboardInterrupt, SystemExit])
def test_air_gap_api_cancellation_identity(stage: str, failure_type: type[BaseException]) -> None:
    failure = failure_type("Synthetic stop")
    report, events, emitted = _isolated_air_gap_report(
        discovery_error=failure if stage == "discovery" else None,
        import_error=failure if stage == "import" else None,
    )
    with pytest.raises(failure_type) as caught:
        report()
    assert caught.value is failure
    assert events == ["config", "discover"] + (["import"] if stage == "import" else [])
    assert emitted == []


@pytest.mark.parametrize(
    "arguments",
    [
        ["import", "catalog-denied-probe/source.json"],
        ["import", "--profile", "catalog-denied-probe/profile.json", "--catalog", "catalog-denied-probe/catalog.json"],
        ["import", "catalog-denied-probe/source.json", "--catalog-dir", "catalog-denied-probe/store"],
        ["remove", "synthetic-denied", "--catalog-dir", "catalog-denied-probe/store", "--yes"],
        [
            "import",
            "--native-profile",
            "bsi-grundschutz-plus-plus-367d7750",
            "--source-dir",
            "catalog-denied-probe/native",
        ],
        [
            "import",
            "--native-profile",
            "invalid-profile",
            "--source-dir",
            "catalog-denied-probe/native",
            "--profile",
            "catalog-denied-probe/profile.json",
        ],
        ["import", "--source-dir", "catalog-denied-probe/native"],
    ],
)
def test_role_precedes_catalog_path_io(
    arguments: list[str], runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Denied commands keep data paths lexical through parsing and authorization."""
    import builtins
    import os

    from evidentia.cli import _rbac
    from evidentia.cli import catalog as catalog_module
    from evidentia_core.rbac import RBACPolicy, Role

    assert Path(catalog_module.__file__).resolve() == (
        Path(__file__).resolve().parents[3] / "packages/evidentia/src/evidentia/cli/catalog.py"
    )
    monkeypatch.setattr(_rbac, "get_rbac_policy", lambda: RBACPolicy(default_role=Role.READER))
    monkeypatch.setattr(_rbac, "get_rbac_identity", lambda: "synthetic-reader")
    calls: list[str] = []

    def guarded(original: object, operation: str):
        def invoke(value, *args, **kwargs):
            if isinstance(value, (str, bytes, os.PathLike)) and "catalog-denied-probe" in os.fsdecode(value):
                calls.append(operation)
                raise AssertionError("denied_catalog_path_io")
            return original(value, *args, **kwargs)

        return invoke

    monkeypatch.setattr(os, "stat", guarded(os.stat, "stat"))
    monkeypatch.setattr(os, "access", guarded(os.access, "access"))
    monkeypatch.setattr(os, "mkdir", guarded(os.mkdir, "mkdir"))
    monkeypatch.setattr(builtins, "open", guarded(builtins.open, "open"))
    result = runner.invoke(app, ["catalog", *arguments])
    assert result.exit_code == 77, result.output
    assert calls == []


@pytest.mark.parametrize("role,can_remove", [("editor", False), ("admin", True)])
def test_catalog_configured_write_and_admin_roles(role, can_remove, runner, tmp_path, monkeypatch):
    from evidentia.cli import _rbac
    from evidentia_core.rbac import RBACPolicy, Role

    monkeypatch.setattr(_rbac, "get_rbac_policy", lambda: RBACPolicy(default_role=Role(role)))
    source = _minimal_user_catalog(tmp_path)
    imported = runner.invoke(app, ["catalog", "import", str(source)])
    assert imported.exit_code == 0, imported.output
    payload = _imported_path(tmp_path, "my-custom-fw")
    original = payload.read_bytes()
    removed = runner.invoke(app, ["catalog", "remove", "my-custom-fw", "--yes"])
    assert removed.exit_code == (0 if can_remove else 77), removed.output
    assert payload.read_bytes() == original
    assert (load_user_manifest().get("my-custom-fw") is None) == can_remove


@pytest.mark.parametrize(
    "options",
    [
        ["--native-profile", "bsi-grundschutz-plus-plus-367d7750"],
        ["--source-dir", "catalog-denied-probe/native"],
        ["--native-profile", "unsupported", "--source-dir", "catalog-denied-probe/native"],
        [
            "catalog-denied-probe/source.json",
            "--native-profile",
            "bsi-grundschutz-plus-plus-367d7750",
            "--source-dir",
            "catalog-denied-probe/native",
        ],
        [
            "--native-profile",
            "bsi-grundschutz-plus-plus-367d7750",
            "--source-dir",
            "catalog-denied-probe/native",
            "--profile",
            "catalog-denied-probe/profile.json",
        ],
        [
            "--native-profile",
            "bsi-grundschutz-plus-plus-367d7750",
            "--source-dir",
            "catalog-denied-probe/native",
            "--name",
            "changed",
        ],
        [
            "--native-profile",
            "bsi-grundschutz-plus-plus-367d7750",
            "--source-dir",
            "catalog-denied-probe/native",
            "--framework-id",
            "changed",
        ],
        [
            "--native-profile",
            "bsi-grundschutz-plus-plus-367d7750",
            "--source-dir",
            "catalog-denied-probe/native",
            "--force",
        ],
    ],
)
def test_authorized_native_conflicts_precede_source_io(options, runner, monkeypatch):
    from evidentia_core.catalogs import open_corpora

    def forbidden(*args, **kwargs):
        pytest.fail("Conflicting native flags reached source or transaction work")

    monkeypatch.setattr(open_corpora, "read_source_directory", forbidden)
    monkeypatch.setattr(catalog_cli.CatalogManifestTransaction, "commit", forbidden)
    original_stat = os.stat

    def guarded_stat(value, *args, **kwargs):
        if "catalog-denied-probe" in os.fsdecode(value):
            pytest.fail("Conflicting native flags triggered path stat")
        return original_stat(value, *args, **kwargs)

    monkeypatch.setattr(os, "stat", guarded_stat)
    result = runner.invoke(app, ["catalog", "import", *options])
    assert result.exit_code == 1, result.output
    assert "Native import requires" in result.output


@pytest.mark.parametrize("mode", ["direct", "profile"])
def test_catalog_direct_path_callers_use_the_transaction(mode, tmp_path, monkeypatch):
    operations = []
    original_commit = catalog_cli.CatalogManifestTransaction.commit

    def record(transaction, intent):
        operations.append(intent.operation)
        return original_commit(transaction, intent)

    monkeypatch.setattr(catalog_cli.CatalogManifestTransaction, "commit", record)
    source = _minimal_user_catalog(tmp_path) if mode == "direct" else None
    profile, catalog = _profile_import_files(tmp_path) if mode == "profile" else (None, None)
    catalog_cli.import_catalog(
        source=source,
        framework_id="path-caller",
        name=None,
        license_terms=None,
        force=False,
        profile=profile,
        catalog=catalog,
        tier="C",
        catalog_dir=tmp_path / "user-catalogs",
    )
    imported = _imported_path(tmp_path, "path-caller")
    before = imported.read_bytes()
    catalog_cli.remove_framework("path-caller", catalog_dir=tmp_path / "user-catalogs", yes=True)
    assert operations == ["legacy_import", "remove"]
    assert imported.read_bytes() == before


@pytest.mark.parametrize("after_replace", [False, True])
def test_cli_reports_publication_facts_without_false_success(after_replace, runner, tmp_path, monkeypatch):
    from evidentia_core.catalogs import user_dir

    source = _minimal_user_catalog(tmp_path)
    imported = runner.invoke(app, ["catalog", "import", str(source)])
    assert imported.exit_code == 0, imported.output
    payload = _imported_path(tmp_path, "my-custom-fw")
    original = user_dir.os.replace
    failure = OSError("synthetic-private-path-must-not-be-emitted")

    def fail_replace(src, dst):
        if Path(dst).name == "frameworks.yaml":
            if after_replace:
                original(src, dst)
            raise failure
        return original(src, dst)

    monkeypatch.setattr(user_dir.os, "replace", fail_replace)
    result = runner.invoke(app, ["catalog", "remove", "my-custom-fw", "--yes"])
    assert result.exit_code == 1
    exception_chain = []
    current = result.exception
    while current is not None and all(current is not item for item in exception_chain):
        exception_chain.append(current)
        current = current.__cause__ or current.__context__
    assert any(item is failure for item in exception_chain)
    assert "synthetic-private-path" not in result.output
    assert "Removed user-imported" not in result.output
    observation, _ = json.JSONDecoder().raw_decode(result.output[result.output.index("{") :])
    assert observation["error_code"] == "catalog_publication_failed"
    assert observation["publication_state"] == ("committed" if after_replace else "not_committed")
    assert observation["readback_result"] == ("matches_proposed" if after_replace else "matches_prior")
    assert (load_user_manifest().get("my-custom-fw") is None) == after_replace
    assert payload.is_file()


@pytest.mark.parametrize("after_replace", [False, True])
def test_cli_preserves_interruption_identity_and_observation(after_replace, runner, tmp_path, monkeypatch, capsys):
    from evidentia_core.catalogs import user_dir

    source = _minimal_user_catalog(tmp_path)
    imported = runner.invoke(app, ["catalog", "import", str(source)])
    assert imported.exit_code == 0, imported.output
    original = user_dir.os.replace
    failure = KeyboardInterrupt("synthetic-interruption")

    def interrupt(src, dst):
        if Path(dst).name == "frameworks.yaml":
            if after_replace:
                original(src, dst)
            raise failure
        return original(src, dst)

    monkeypatch.setattr(user_dir.os, "replace", interrupt)
    with pytest.raises(KeyboardInterrupt) as caught:
        catalog_cli.remove_framework("my-custom-fw", catalog_dir=tmp_path / "user-catalogs", yes=True)
    assert caught.value is failure
    output = capsys.readouterr().out
    observation, _ = json.JSONDecoder().raw_decode(output[output.index("{") :])
    assert observation["error_code"] == "catalog_interrupted"
    assert observation["publication_state"] == ("committed" if after_replace else "not_committed")
    assert "Removed user-imported" not in output


def test_confirmation_refuses_concurrently_changed_entry(runner, tmp_path, monkeypatch):
    from evidentia_core.catalogs.user_dir import CatalogManifestTransaction, CatalogMutationIntent

    source = _minimal_user_catalog(tmp_path)
    assert runner.invoke(app, ["catalog", "import", str(source)]).exit_code == 0
    previous = load_user_manifest().get("my-custom-fw")
    assert previous is not None
    raw = _imported_path(tmp_path, "my-custom-fw").read_bytes()
    replacement = previous.model_copy(update={"name": "Concurrent replacement"})

    def confirm(_prompt):
        CatalogManifestTransaction().commit(CatalogMutationIntent.legacy(replacement, raw, force=True))
        return True

    monkeypatch.setattr(catalog_cli.typer, "confirm", confirm)
    result = runner.invoke(app, ["catalog", "remove", "my-custom-fw"])
    assert result.exit_code == 1, result.output
    assert "catalog_transaction_conflict" in result.output
    assert load_user_manifest().get("my-custom-fw").name == "Concurrent replacement"


def test_native_show_unavailable_is_a_fixed_failure(runner):
    result = runner.invoke(app, ["catalog", "show", "nist-800-53-mod", "--native-source"])
    assert result.exit_code == 1
    assert result.output.strip() == "native_source_unavailable"


def test_native_source_output_preserves_complete_bundle_and_control_context(runner, monkeypatch):
    catalog = FrameworkRegistry.get_instance().get_catalog("cisa-scuba")
    bundle = catalog.native_source
    assert bundle is not None
    captured = []
    monkeypatch.setattr(catalog_cli.console, "print_json", lambda *, json, highlight: captured.append(json))
    result = runner.invoke(app, ["catalog", "show", "cisa-scuba", "--native-source"])
    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    full = json.loads(captured.pop())
    assert full == bundle.model_dump(mode="json")
    assert any(occurrence["parent_index"] is None for occurrence in full["data"]["occurrences"])
    control = next(item for item in catalog.controls if item.native_source_ref is not None)
    result = runner.invoke(app, ["catalog", "show", "cisa-scuba", "--control", control.id, "--native-source"])
    assert result.exit_code == 0, result.output
    selected = json.loads(captured.pop())
    assert selected["native_source_ref"] == control.native_source_ref.model_dump(mode="json")
    assert selected["occurrence"] == full["data"]["occurrences"][control.native_source_ref.occurrence_index]
    assert selected["declared_context"] == [
        full["data"]["occurrences"][index] for index in full["data"]["context_indices"]
    ]
    parent = selected["occurrence"]["parent_index"]
    expected_parents = []
    while parent is not None:
        item = full["data"]["occurrences"][parent]
        expected_parents.append(item)
        parent = item["parent_index"]
    assert selected["enclosing_context"] == list(reversed(expected_parents))
    assert "documents" not in selected
    assert "raw_utf8" not in json.dumps(selected)


def test_native_cli_refuses_extra_source_leaf_before_transaction(runner, tmp_path, monkeypatch):
    source_dir = tmp_path / "native-input"
    source_dir.mkdir()
    (source_dir / "unexpected.txt").write_text("Synthetic source", encoding="utf-8")

    def forbidden(*args, **kwargs):
        pytest.fail("Invalid source reached publication")

    monkeypatch.setattr(catalog_cli.CatalogManifestTransaction, "commit", forbidden)
    result = runner.invoke(
        app,
        [
            "catalog",
            "import",
            "--native-profile",
            "bsi-grundschutz-plus-plus-367d7750",
            "--source-dir",
            str(source_dir),
        ],
    )
    assert result.exit_code == 1
    assert result.output.strip() == "native_source_invalid"
    assert not (tmp_path / "user-catalogs").exists()


def test_cli_staging_cleanup_preserves_primary_exception(tmp_path, monkeypatch):
    from evidentia_core.catalogs import loader

    source = _minimal_user_catalog(tmp_path)
    primary = KeyboardInterrupt("synthetic primary")

    def validation(*args, **kwargs):
        raise primary

    def cleanup(*args, **kwargs):
        raise SystemExit("synthetic cleanup")

    monkeypatch.setattr(loader, "load_any_catalog", validation)
    monkeypatch.setattr(catalog_cli.shutil, "rmtree", cleanup)
    with pytest.raises(KeyboardInterrupt) as caught:
        catalog_cli.import_catalog(
            source=source,
            framework_id=None,
            name=None,
            license_terms=None,
            force=False,
            profile=None,
            catalog=None,
            tier="C",
            catalog_dir=tmp_path / "catalogs",
        )
    assert caught.value is primary
