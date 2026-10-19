"""Read-only catalog loads follow a symlinked catalog directory; mutators stay strict (v0.13.0 review M9)."""

from __future__ import annotations

from pathlib import Path

import pytest
from evidentia_core.catalogs import user_dir
from evidentia_core.catalogs.manifest import FrameworkManifest


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # unprivileged Windows sessions
        pytest.skip(f"symlinks unavailable here: {exc.__class__.__name__}")


def test_manifest_loads_through_a_symlinked_ancestor(tmp_path: Path) -> None:
    real_home = tmp_path / "real-home"
    catalogs = real_home / "catalogs"
    catalogs.mkdir(parents=True)
    user_dir.save_user_manifest(FrameworkManifest(version=1, frameworks=[]), catalogs)

    linked_home = tmp_path / "linked-home"
    _symlink_or_skip(linked_home, real_home)
    via_link = linked_home / "catalogs"

    manifest = user_dir.load_user_manifest(via_link)
    assert manifest.frameworks == []


def test_mutators_still_refuse_a_symlinked_ancestor(tmp_path: Path) -> None:
    real_home = tmp_path / "real-home"
    (real_home / "catalogs").mkdir(parents=True)
    linked_home = tmp_path / "linked-home"
    _symlink_or_skip(linked_home, real_home)

    with pytest.raises(user_dir.CatalogStorageError, match="catalog_storage_unsupported"):
        user_dir.save_user_manifest(FrameworkManifest(version=1, frameworks=[]), linked_home / "catalogs")


def test_missing_directory_still_reads_as_empty(tmp_path: Path) -> None:
    assert user_dir.load_user_manifest(tmp_path / "absent" / "catalogs").frameworks == []


def test_read_directory_refuses_unc_and_parent_segments(tmp_path: Path) -> None:
    with pytest.raises(user_dir.CatalogStorageError):
        user_dir._read_directory(tmp_path / ".." / "catalogs")
