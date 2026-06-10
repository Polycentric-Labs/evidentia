"""Tests for ``scripts/pre_push/check_uv_lock_pin_drift.py`` (D5, v0.10.7).

Pre-push gate L2 check: a workspace-package version bump in ``uv.lock`` must
NOT drag any third-party (registry-sourced) package's pinned version (the
v0.10.0 F-V100-M1 pattern). These tests pin the pure parse + diff logic
against inline ``uv.lock`` fixtures (no git, no network), plus the
per-commit attribution path (SF-V108-3, v0.10.9 item B) against a throwaway
git repo built in ``tmp_path`` (real commits, no network).
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CHECK_PATH = REPO_ROOT / "scripts" / "pre_push" / "check_uv_lock_pin_drift.py"


@pytest.fixture(scope="module")
def mod() -> Any:
    """Import scripts/pre_push/check_uv_lock_pin_drift.py (no __init__.py)."""
    spec = importlib.util.spec_from_file_location("check_uv_lock_pin_drift", CHECK_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_uv_lock_pin_drift"] = module
    spec.loader.exec_module(module)
    return module


# A miniature uv.lock: one workspace member (editable), the virtual root,
# and two third-party (registry) packages.
def _lock(core_ver: str, urllib3_ver: str, requests_ver: str = "2.32.0", root_ver: str = "0.10.6") -> str:
    return f"""version = 1
revision = 3
requires-python = ">=3.12"

[manifest]
members = ["evidentia-core", "evidentia-workspace"]

[[package]]
name = "evidentia-core"
version = "{core_ver}"
source = {{ editable = "packages/evidentia-core" }}
dependencies = [
    {{ name = "urllib3" }},
]

[[package]]
name = "evidentia-workspace"
version = "{root_ver}"
source = {{ virtual = "." }}

[[package]]
name = "urllib3"
version = "{urllib3_ver}"
source = {{ registry = "https://pypi.org/simple" }}

[[package]]
name = "requests"
version = "{requests_ver}"
source = {{ registry = "https://pypi.org/simple" }}
"""


# ---------------------------------------------------------------------------
# parse_lock — name/version/source extraction.
# ---------------------------------------------------------------------------


def test_parse_lock_extracts_name_version_source(mod: Any) -> None:
    pkgs = mod.parse_lock(_lock("0.10.6", "2.7.0"))
    assert pkgs["evidentia-core"] == ("0.10.6", "editable")
    assert pkgs["evidentia-workspace"] == ("0.10.6", "virtual")
    assert pkgs["urllib3"] == ("2.7.0", "registry")
    assert pkgs["requests"] == ("2.32.0", "registry")


def test_parse_lock_stops_at_next_table(mod: Any) -> None:
    """A non-[[package]] table must not bleed into the last package block."""
    text = _lock("0.10.6", "2.7.0") + "\n[other.section]\nfoo = 1\n"
    pkgs = mod.parse_lock(text)
    # requests is the last package and must retain its own version.
    assert pkgs["requests"][0] == "2.32.0"


# ---------------------------------------------------------------------------
# workspace_bumped — detects a workspace version move.
# ---------------------------------------------------------------------------


def test_workspace_bumped_detects_editable_move(mod: Any) -> None:
    base = mod.parse_lock(_lock("0.10.6", "2.7.0"))
    tip = mod.parse_lock(_lock("0.10.7", "2.7.0"))
    bumped = mod.workspace_bumped(base, tip)
    names = {b[0] for b in bumped}
    assert "evidentia-core" in names


def test_workspace_bumped_detects_root_move(mod: Any) -> None:
    base = mod.parse_lock(_lock("0.10.6", "2.7.0", root_ver="0.10.6"))
    tip = mod.parse_lock(_lock("0.10.6", "2.7.0", root_ver="0.10.7"))
    bumped = mod.workspace_bumped(base, tip)
    names = {b[0] for b in bumped}
    assert "evidentia-workspace" in names


def test_workspace_not_bumped_when_versions_equal(mod: Any) -> None:
    base = mod.parse_lock(_lock("0.10.6", "2.7.0"))
    tip = mod.parse_lock(_lock("0.10.6", "2.8.0"))  # only third-party moved
    assert mod.workspace_bumped(base, tip) == []


# ---------------------------------------------------------------------------
# third_party_drift — the F-V100-M1 signature.
# ---------------------------------------------------------------------------


def test_third_party_drift_flags_moved_registry_pin(mod: Any) -> None:
    base = mod.parse_lock(_lock("0.10.6", "2.7.0"))
    tip = mod.parse_lock(_lock("0.10.7", "3.0.0"))  # workspace AND urllib3 moved
    drift = mod.third_party_drift(base, tip)
    moved = {d[0] for d in drift}
    assert "urllib3" in moved
    assert "evidentia-core" not in moved  # workspace excluded from drift set


def test_third_party_drift_empty_when_pins_stable(mod: Any) -> None:
    base = mod.parse_lock(_lock("0.10.6", "2.7.0"))
    tip = mod.parse_lock(_lock("0.10.7", "2.7.0"))  # only workspace moved
    assert mod.third_party_drift(base, tip) == []


def test_third_party_drift_ignores_add_remove(mod: Any) -> None:
    """A package present in only one side is NOT flagged as drift."""
    base = mod.parse_lock(_lock("0.10.6", "2.7.0"))
    # Tip drops `requests` entirely (a legit dependency removal).
    tip_text = """version = 1

[[package]]
name = "evidentia-core"
version = "0.10.7"
source = { editable = "packages/evidentia-core" }

[[package]]
name = "urllib3"
version = "2.7.0"
source = { registry = "https://pypi.org/simple" }
"""
    tip = mod.parse_lock(tip_text)
    # urllib3 stable, requests removed -> no *version-movement* drift.
    assert mod.third_party_drift(base, tip) == []


# ---------------------------------------------------------------------------
# Combined signature: the exact F-V100-M1 scenario the gate must BLOCK.
# ---------------------------------------------------------------------------


def test_combined_bump_plus_drift_is_the_block_condition(mod: Any) -> None:
    base = mod.parse_lock(_lock("0.10.6", "2.7.0"))
    tip = mod.parse_lock(_lock("0.10.7", "3.0.0"))
    assert mod.workspace_bumped(base, tip)  # truthy -> a bump happened
    assert mod.third_party_drift(base, tip)  # truthy -> third-party moved
    # Orchestrator BLOCKs iff both are truthy.


# ---------------------------------------------------------------------------
# Anti-rot floor: the hardcoded fallback set MUST equal the set parsed from
# [tool.uv.workspace].members in the root pyproject.toml. If a 9th workspace
# package is added without updating the fallback literal, this fails loud —
# closing the silent-rot footgun even on the read-failure fallback path.
# ---------------------------------------------------------------------------


def test_parse_workspace_packages_matches_repo_members(mod: Any) -> None:
    """Parsed members + root project name == the current authoritative set."""
    parsed = mod.parse_workspace_packages(REPO_ROOT)
    assert parsed is not None, "root pyproject.toml [tool.uv.workspace].members must parse"
    # Source-of-truth members (8 packages) + the virtual root [project].name.
    assert parsed == {
        "evidentia",
        "evidentia-ai",
        "evidentia-api",
        "evidentia-collectors",
        "evidentia-core",
        "evidentia-eval",
        "evidentia-integrations",
        "evidentia-mcp",
        "evidentia-workspace",
    }


def test_fallback_equals_parsed_members(mod: Any) -> None:
    """The hardcoded fallback MUST equal the parsed members (no silent rot).

    This is the floor requirement: the moment a workspace package is added to
    ``[tool.uv.workspace].members`` without updating
    ``_FALLBACK_WORKSPACE_PACKAGES``, this assertion fails — so the
    read-failure fallback can never silently misclassify a new package's bump
    as a third-party pin.
    """
    parsed = mod.parse_workspace_packages(REPO_ROOT)
    assert parsed is not None
    assert parsed == mod._FALLBACK_WORKSPACE_PACKAGES


def test_module_workspace_packages_resolves_to_parsed(mod: Any) -> None:
    """The module-global authoritative set equals the parsed members on this repo."""
    parsed = mod.parse_workspace_packages(REPO_ROOT)
    assert parsed is not None
    assert parsed == mod.WORKSPACE_PACKAGES


def test_parse_workspace_packages_handles_glob_members(mod: Any, tmp_path: Path) -> None:
    """A glob-style member entry (e.g. ``packages/*``) expands against the FS."""
    (tmp_path / "packages" / "pkg-a").mkdir(parents=True)
    (tmp_path / "packages" / "pkg-b").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "root-pkg"\n\n[tool.uv.workspace]\nmembers = ["packages/*"]\n',
        encoding="utf-8",
    )
    parsed = mod.parse_workspace_packages(tmp_path)
    assert parsed == {"pkg-a", "pkg-b", "root-pkg"}


def test_parse_workspace_packages_returns_none_when_missing(mod: Any, tmp_path: Path) -> None:
    """No pyproject.toml -> None so the caller uses the hardcoded fallback."""
    assert mod.parse_workspace_packages(tmp_path) is None


# ---------------------------------------------------------------------------
# Per-commit attribution (SF-V108-3, v0.10.9 item B) — end-to-end main()
# against a throwaway git repo (real commits, no network). The aggregate
# base..tip diff misattributed a separately-committed third-party bump to
# the workspace version bump (the v0.10.8 false positive); the BLOCK
# condition must now hold within a SINGLE commit.
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def _rev_head(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()


def _commit_lock(repo: Path, lock_text: str, msg: str) -> str:
    """Write uv.lock, commit it, return the new HEAD sha."""
    (repo / "uv.lock").write_text(lock_text, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", msg)
    return _rev_head(repo)


@pytest.fixture()
def lock_repo(tmp_path: Path) -> Path:
    """A throwaway git repo with an initial uv.lock commit."""
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@example.com")
    _git(r, "config", "user.name", "Test")
    _commit_lock(r, _lock("0.10.6", "2.7.0"), "base")
    return r


def _run_main_in(mod: Any, repo: Path, argv: list[str]) -> int:
    """Invoke mod.main(argv) with the process cwd temporarily set to repo."""
    prev = Path.cwd()
    try:
        os.chdir(repo)
        return int(mod.main(argv))
    finally:
        os.chdir(prev)


def test_separate_commits_dep_bump_then_version_bump_pass(
    mod: Any, lock_repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The v0.10.8 false positive (SF-V108-3): a third-party dep-bump commit
    followed by a clean workspace version-bump commit in the same push range
    must PASS — neither commit alone combines bump + drift."""
    base = _rev_head(lock_repo)
    _commit_lock(lock_repo, _lock("0.10.6", "3.0.0"), "Bump urllib3 (dep change only)")
    tip = _commit_lock(lock_repo, _lock("0.10.7", "3.0.0"), "Bump workspace version only")

    rc = _run_main_in(mod, lock_repo, [base, tip])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PASS check_uv_lock_pin_drift" in out


def test_single_commit_bump_plus_drift_blocks(
    mod: Any, lock_repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """True positive: ONE commit bumping workspace AND moving a third-party
    pin (the F-V100-M1 signature) stays red, with the commit attributed."""
    base = _rev_head(lock_repo)
    tip = _commit_lock(lock_repo, _lock("0.10.7", "3.0.0"), "Bump version and drag urllib3")

    rc = _run_main_in(mod, lock_repo, [base, tip])
    assert rc == 1
    captured = capsys.readouterr()
    assert "BLOCK check_uv_lock_pin_drift" in captured.out
    assert "urllib3" in captured.err
    assert f"commit {tip[:12]}" in captured.err


def test_working_tree_pair_blocks_on_combined_change(
    mod: Any, lock_repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No-args invocation (working-tree tip): an uncommitted bump + drift in
    the HEAD -> working-tree pair must still BLOCK."""
    _git(lock_repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    (lock_repo / "uv.lock").write_text(_lock("0.10.7", "3.0.0"), encoding="utf-8")

    rc = _run_main_in(mod, lock_repo, [])
    assert rc == 1
    captured = capsys.readouterr()
    assert "BLOCK check_uv_lock_pin_drift" in captured.out
    assert "working tree" in captured.err


def test_working_tree_clean_bump_passes(
    mod: Any, lock_repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Working-tree pair with a workspace bump but stable pins -> PASS."""
    _git(lock_repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    (lock_repo / "uv.lock").write_text(_lock("0.10.7", "2.7.0"), encoding="utf-8")

    rc = _run_main_in(mod, lock_repo, [])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PASS check_uv_lock_pin_drift" in out
    assert "evidentia-core 0.10.6->0.10.7" in out
