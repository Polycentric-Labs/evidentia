"""Keep the project license present and consistent in every Python package."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECTS = sorted((REPO_ROOT / "packages").glob("*/pyproject.toml"))


@pytest.mark.parametrize("manifest", PROJECTS, ids=lambda p: p.parent.name)
def test_package_license_matches_repository(manifest: Path) -> None:
    project = tomllib.loads(manifest.read_text(encoding="utf-8"))["project"]
    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == ["LICENSE"]
    assert (manifest.parent / "LICENSE").read_bytes() == (REPO_ROOT / "LICENSE").read_bytes()
