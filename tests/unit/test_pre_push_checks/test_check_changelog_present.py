"""Tests for ``scripts/pre_push/check_changelog_present.py`` (D5, v0.10.7).

Pre-push gate L2 check: a pyproject ``version`` bump in the push range must
have a matching ``## [X.Y.Z]`` block in CHANGELOG.md (the v0.10.4 P5 lesson).

These tests pin the pure detection logic against inline fixtures plus a
throwaway git repo built in ``tmp_path`` (real commits, no network). The
script has no ``__init__.py`` (it lives under ``scripts/pre_push/``), so it
is loaded via importlib like the other ``scripts/`` test suites.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CHECK_PATH = REPO_ROOT / "scripts" / "pre_push" / "check_changelog_present.py"


@pytest.fixture(scope="module")
def mod() -> Any:
    """Import scripts/pre_push/check_changelog_present.py (no __init__.py)."""
    spec = importlib.util.spec_from_file_location("check_changelog_present", CHECK_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_changelog_present"] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# changelog_has_block — the heading detector.
# ---------------------------------------------------------------------------


def test_changelog_block_plain(mod: Any) -> None:
    text = "# Changelog\n\n## [0.10.7]\n\n- stuff\n"
    assert mod.changelog_has_block(text, "0.10.7") is True


def test_changelog_block_with_date(mod: Any) -> None:
    text = "## [0.10.7] - 2026-06-10\n\n- stuff\n"
    assert mod.changelog_has_block(text, "0.10.7") is True


def test_changelog_block_link_reference(mod: Any) -> None:
    text = "## [0.10.7](https://example/compare/v0.10.6...v0.10.7)\n"
    assert mod.changelog_has_block(text, "0.10.7") is True


def test_changelog_block_absent(mod: Any) -> None:
    text = "# Changelog\n\n## [0.10.6]\n\n- old\n"
    assert mod.changelog_has_block(text, "0.10.7") is False


def test_changelog_block_no_prefix_substring_match(mod: Any) -> None:
    """A 0.10.7 query must NOT match a 0.10.70 heading (escaped + anchored)."""
    text = "## [0.10.70]\n"
    assert mod.changelog_has_block(text, "0.10.7") is False


# ---------------------------------------------------------------------------
# extract_versions / project_version — pyproject parsing.
# ---------------------------------------------------------------------------


def test_extract_versions_finds_literal(mod: Any) -> None:
    text = '[project]\nname = "x"\nversion = "0.10.7"\n'
    assert "0.10.7" in mod.extract_versions(text)


def test_project_version_via_toml(mod: Any) -> None:
    text = '[project]\nname = "x"\nversion = "0.10.7"\n'
    assert mod.project_version(text) == "0.10.7"


def test_project_version_missing(mod: Any) -> None:
    text = '[tool.foo]\nbar = 1\n'
    assert mod.project_version(text) is None


# ---------------------------------------------------------------------------
# bumped_versions — git-range diff (real throwaway repo).
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """A throwaway git repo with an initial pyproject + CHANGELOG commit."""
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@example.com")
    _git(r, "config", "user.name", "Test")
    (r / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0.10.6"\n', encoding="utf-8")
    (r / "CHANGELOG.md").write_text("# Changelog\n\n## [0.10.6]\n\n- base\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    return r


def test_bumped_versions_detects_bump(mod: Any, repo: Path) -> None:
    base = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    (repo / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0.10.7"\n', encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "bump")
    tip = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()

    bumped = mod.bumped_versions(base, tip, repo)
    assert bumped == {"0.10.7"}


def test_bumped_versions_no_bump(mod: Any, repo: Path) -> None:
    base = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    # Touch a non-version line in the SAME pyproject; version unchanged.
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0.10.6"\ndescription = "y"\n', encoding="utf-8"
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "no bump")
    tip = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()

    assert mod.bumped_versions(base, tip, repo) == set()


def test_main_blocks_on_bump_without_block(mod: Any, repo: Path) -> None:
    """End-to-end: bump version, do NOT add a CHANGELOG block -> exit 1."""
    base = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    (repo / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0.10.7"\n', encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "bump no changelog")
    tip = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()

    # Run main() with cwd inside the repo so rev-parse --show-toplevel resolves.
    rc = _run_main_in(mod, repo, [base, tip])
    assert rc == 1


def test_main_passes_when_block_present(mod: Any, repo: Path) -> None:
    """End-to-end: bump version AND add the CHANGELOG block -> exit 0."""
    base = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    (repo / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0.10.7"\n', encoding="utf-8")
    (repo / "CHANGELOG.md").write_text(
        "# Changelog\n\n## [0.10.7] - 2026-06-10\n\n- new\n\n## [0.10.6]\n\n- base\n",
        encoding="utf-8",
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "bump with changelog")
    tip = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()

    rc = _run_main_in(mod, repo, [base, tip])
    assert rc == 0


def _run_main_in(mod: Any, repo: Path, argv: list[str]) -> int:
    """Invoke mod.main(argv) with the process cwd temporarily set to repo."""
    import os

    prev = Path.cwd()
    try:
        os.chdir(repo)
        return int(mod.main(argv))
    finally:
        os.chdir(prev)
