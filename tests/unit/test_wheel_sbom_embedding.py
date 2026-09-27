"""Build one wheel end-to-end and assert the PEP 770 sboms/ payload.

Marked slow: invokes `uv build` in a subprocess. Skips when uv is
unavailable (e.g. minimal CI containers).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tarfile
import zipfile
from email.parser import BytesParser
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
    _assert_license_in_archives(wheel, next(tmp_path.glob("evidentia_core-*.tar.gz")))


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
    _assert_license_in_archives(wheel, next(tmp_path.glob("evidentia_core-*.tar.gz")))


def _assert_license_in_archives(wheel: Path, sdist: Path) -> None:
    expected = (REPO_ROOT / "LICENSE").read_bytes()
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        metadata = BytesParser().parsebytes(archive.read(metadata_name))
        assert metadata.get_all("License-File") == ["LICENSE"]
        assert metadata["License-Expression"] == "Apache-2.0"
        license_name = metadata_name.removesuffix("METADATA") + "licenses/LICENSE"
        assert archive.read(license_name) == expected
    with tarfile.open(sdist, "r:gz") as archive:
        metadata_member = next(m for m in archive.getmembers() if m.name.endswith("/PKG-INFO"))
        metadata_stream = archive.extractfile(metadata_member)
        assert metadata_stream is not None
        metadata = BytesParser().parsebytes(metadata_stream.read())
        assert metadata.get_all("License-File") == ["LICENSE"]
        license_member = archive.getmember(metadata_member.name.removesuffix("PKG-INFO") + "LICENSE")
        license_stream = archive.extractfile(license_member)
        assert license_stream is not None
        assert license_stream.read() == expected
