"""Build one wheel end-to-end and assert the PEP 770 sboms/ payload.

Marked slow: invokes `uv build` in a subprocess. Skips when uv is
unavailable (e.g. minimal CI containers).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="uv not on PATH")


def test_core_wheel_embeds_sbom_via_sdist_path(tmp_path: Path) -> None:
    """Plain `uv build` = sdist->wheel — the SAME path release.yml uses.
    A --wheel shortcut here would pass while the release path breaks
    (gitignored sbom/ must ride the sdist via the artifacts config)."""
    gen = subprocess.run(
        [sys.executable, "scripts/gen_package_sboms.py", "--only", "evidentia-core"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert gen.returncode == 0, gen.stderr
    build = subprocess.run(
        ["uv", "build", "--package", "evidentia-core", "-o", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert build.returncode == 0, build.stderr
    wheel = next(tmp_path.glob("evidentia_core-*.whl"))
    names = zipfile.ZipFile(wheel).namelist()
    sboms = [n for n in names if "/sboms/" in n and n.endswith(".cdx.json")]
    assert sboms, f"no .dist-info/sboms/ in {wheel.name}: {names[:20]}"


def test_core_wheel_builds_clean_without_sboms(tmp_path: Path) -> None:
    """Skip-clean invariant: no generated sbom/ -> build still succeeds
    (fresh clones and CI syncs must never depend on the generator)."""
    sbom_dir = REPO_ROOT / "packages" / "evidentia-core" / "sbom"
    if sbom_dir.exists():
        shutil.rmtree(sbom_dir)
    build = subprocess.run(
        ["uv", "build", "--package", "evidentia-core", "-o", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert build.returncode == 0, build.stderr
    wheel = next(tmp_path.glob("evidentia_core-*.whl"))
    names = zipfile.ZipFile(wheel).namelist()
    assert not [n for n in names if "/sboms/" in n], "unexpected sboms/ without generator"
