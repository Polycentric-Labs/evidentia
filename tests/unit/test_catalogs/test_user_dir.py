"""Tests for the user-catalog directory facility (catalogs/user_dir.py)."""

from __future__ import annotations

import json

import pytest
from evidentia_core.catalogs.manifest import (
    FrameworkManifest,
    FrameworkManifestEntry,
    load_manifest,
)
from evidentia_core.catalogs.user_dir import (
    get_user_catalog_dir,
    load_user_manifest,
    resolve_catalog_path,
    save_user_manifest,
    user_manifest_path,
)


def test_default_user_dir_under_platform_dirs(tmp_path, monkeypatch) -> None:
    """Without override, the user dir falls under platformdirs' app dir."""
    monkeypatch.delenv("EVIDENTIA_CATALOG_DIR", raising=False)
    path = get_user_catalog_dir()
    # We don't hardcode the exact path (varies by OS) — just sanity check
    # it ends with our app folder
    assert "evidentia" in str(path).lower() or "Evidentia" in str(path)


def test_env_override_wins(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("EVIDENTIA_CATALOG_DIR", str(tmp_path))
    assert get_user_catalog_dir() == tmp_path.resolve()


def test_explicit_override_wins_over_env(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("EVIDENTIA_CATALOG_DIR", str(tmp_path / "env"))
    override = tmp_path / "explicit"
    assert get_user_catalog_dir(override) == override.resolve()


def test_missing_user_manifest_returns_empty(tmp_path) -> None:
    manifest = load_user_manifest(tmp_path)
    assert manifest.version == 1
    assert manifest.frameworks == []


def test_roundtrip_user_manifest(tmp_path) -> None:
    entry = FrameworkManifestEntry(
        id="my-iso27001",
        name="ISO 27001:2022 (licensed copy)",
        version="2022",
        tier="C",
        category="control",
        path="my-iso27001.json",
        license="Copyright ISO/IEC — licensed copy",
        placeholder=False,
    )
    saved = save_user_manifest(
        FrameworkManifest(version=1, frameworks=[entry]), tmp_path
    )
    assert saved == user_manifest_path(tmp_path)
    assert saved.exists()

    reloaded = load_user_manifest(tmp_path)
    assert len(reloaded.frameworks) == 1
    assert reloaded.frameworks[0].id == "my-iso27001"
    assert reloaded.frameworks[0].tier == "C"


def test_user_entry_shadows_bundled(tmp_path) -> None:
    """A user-dir catalog with the same ID as a bundled one wins."""
    bundled = load_manifest()
    assert bundled.get("nist-800-53-mod") is not None

    # Drop a fake user catalog for nist-800-53-mod
    fake_json = tmp_path / "nist-800-53-mod.json"
    fake_json.write_text(
        json.dumps(
            {
                "framework_id": "nist-800-53-mod",
                "framework_name": "Custom NIST 800-53 Moderate",
                "version": "custom",
                "source": "user override",
                "controls": [],
            }
        )
    )
    save_user_manifest(
        FrameworkManifest(
            version=1,
            frameworks=[
                FrameworkManifestEntry(
                    id="nist-800-53-mod",
                    name="Custom NIST 800-53 Moderate",
                    version="custom",
                    tier="A",
                    category="control",
                    path="nist-800-53-mod.json",
                )
            ],
        ),
        tmp_path,
    )

    path, _entry, source = resolve_catalog_path(
        "nist-800-53-mod",
        bundled_manifest=bundled,
        user_dir_override=tmp_path,
    )
    assert source == "user"
    assert path == fake_json


def test_resolve_falls_through_to_bundled(tmp_path) -> None:
    bundled = load_manifest()
    path, _entry, source = resolve_catalog_path(
        "nist-800-53-mod",
        bundled_manifest=bundled,
        user_dir_override=tmp_path,
    )
    assert source == "bundled"
    assert path.name == "nist-800-53-mod.json"


def test_resolve_unknown_framework_raises(tmp_path) -> None:
    bundled = load_manifest()
    with pytest.raises(ValueError, match="Unknown framework"):
        resolve_catalog_path(
            "not-a-framework",
            bundled_manifest=bundled,
            user_dir_override=tmp_path,
        )


def test_resolve_rejects_user_path_escaping_user_dir(tmp_path) -> None:
    """A user-manifest entry whose path escapes the user dir is refused
    (defense-in-depth path containment, CWE-22). The API import endpoint never
    writes such a path (``framework_id`` is regex-validated), but a hand-edited
    or otherwise-tampered manifest could carry one — it must never reach the
    file loader. The manifest model itself does not validate the path, so this
    containment check in ``resolve_catalog_path`` is the guard.
    """
    bundled = load_manifest()
    save_user_manifest(
        FrameworkManifest(
            version=1,
            frameworks=[
                FrameworkManifestEntry(
                    id="evil",
                    name="Escaping catalog",
                    version="x",
                    tier="A",
                    category="control",
                    path="../../escape.json",
                )
            ],
        ),
        tmp_path,
    )
    with pytest.raises(ValueError, match="escapes the user"):
        resolve_catalog_path(
            "evil",
            bundled_manifest=bundled,
            user_dir_override=tmp_path,
        )
