"""Tests for scripts/bump_version.py — closes F-V100-M1 (v0.10.1).

The v0.10.0 ship surfaced bump_version.py over-bumping a third-party
version pin (`py-ocsf-models>=0.9.0,<0.10.0` → `>=0.10.0,<0.11.0`,
which was unsatisfiable and would have broken every fresh install
had it shipped). The v0.10.1 fix reads `[tool.uv.sources]` as the
workspace allowlist and constrains the pin substitution to those
package names. These tests assert that:

1. `bump_pin_range` requires a non-empty allowlist (refuses to fall
   back to a package-agnostic regex).
2. The generated regex matches workspace package pins ONLY.
3. A synthetic mini-monorepo with mixed workspace + third-party pins
   bumps the workspace pins and leaves third-party pins untouched.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
BUMP_VERSION_PATH = REPO_ROOT / "scripts" / "bump_version.py"


@pytest.fixture(scope="module")
def bv() -> object:
    """Import scripts/bump_version.py as a module (it has no __init__.py)."""
    spec = importlib.util.spec_from_file_location("bump_version", BUMP_VERSION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["bump_version"] = module
    spec.loader.exec_module(module)
    return module


def test_workspace_packages_reads_tool_uv_sources(bv, tmp_path: Path) -> None:
    """Reading [tool.uv.sources] returns the workspace member names."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[tool.uv.sources]\n"
        "evidentia-core = { workspace = true }\n"
        "evidentia-ai = { workspace = true }\n"
        # Non-workspace source (e.g. a git pin) must be excluded.
        'some-other-pkg = { git = "https://example.com/x.git" }\n',
        encoding="utf-8",
    )
    pkgs = bv.workspace_packages(pyproject)
    assert pkgs == ["evidentia-ai", "evidentia-core"]


def test_workspace_packages_returns_empty_when_missing(bv, tmp_path: Path) -> None:
    """Missing pyproject.toml OR missing [tool.uv.sources] section -> []."""
    missing = tmp_path / "missing.toml"
    assert bv.workspace_packages(missing) == []

    empty = tmp_path / "empty.toml"
    empty.write_text("[project]\nname = 'x'\n", encoding="utf-8")
    assert bv.workspace_packages(empty) == []


def test_bump_pin_range_refuses_empty_allowlist(bv) -> None:
    """F-V100-M1: empty allowlist would re-introduce the bug. Refuse."""
    with pytest.raises(ValueError, match="F-V100-M1"):
        bv.bump_pin_range("0.9.9", "0.10.0", [])


def test_bump_pin_range_matches_only_workspace_pins(bv) -> None:
    """The regex requires a workspace package name to precede the range."""
    pattern, replacement = bv.bump_pin_range("0.9.9", "0.10.0", ["evidentia-core", "evidentia-ai"])
    regex = re.compile(pattern)
    # Workspace pin -> matches.
    workspace_line = '"evidentia-core>=0.9.0,<0.10.0"'
    assert regex.search(workspace_line)
    bumped = regex.sub(replacement, workspace_line)
    assert bumped == '"evidentia-core>=0.10.0,<0.11.0"'

    # Third-party pin with the SAME range shape -> does NOT match.
    third_party_line = '"py-ocsf-models>=0.9.0,<0.10.0"'
    assert not regex.search(third_party_line)


def test_synthetic_monorepo_bumps_workspace_leaves_third_party(bv, tmp_path: Path) -> None:
    """End-to-end on a tiny monorepo: a workspace pin + a third-party pin
    that uses the exact same range shape. Only the workspace pin moves.

    This is the close-out acceptance gate from docs/v0.10.1-plan.md §6:
    `bump_version.py --to <next>` must NOT change py-ocsf-models,
    pydantic, boto3, or any other third-party version pin.
    """
    # Mini monorepo: root + 1 workspace member.
    root_pyproject = tmp_path / "pyproject.toml"
    root_pyproject.write_text(
        "[project]\nname = 'evidentia-monorepo-test'\nversion = '0.9.9'\n\n"
        "[tool.uv.sources]\n"
        "evidentia-core = { workspace = true }\n",
        encoding="utf-8",
    )
    member_pyproject = tmp_path / "packages" / "evidentia-core" / "pyproject.toml"
    member_pyproject.parent.mkdir(parents=True)
    member_pyproject.write_text(
        "[project]\n"
        'name = "evidentia-core"\n'
        'version = "0.9.9"\n'
        "dependencies = [\n"
        '    "evidentia-core>=0.9.0,<0.10.0",\n'  # workspace pin — bump
        '    "py-ocsf-models>=0.9.0,<0.10.0",\n'  # third-party — leave alone
        '    "boto3>=0.9.0,<0.10.0",\n'  # third-party — leave alone (even though boto3 doesn't really pin like this)
        "]\n",
        encoding="utf-8",
    )

    # Drive the substitution by calling bump_pin_range + applying to text.
    packages = bv.workspace_packages(root_pyproject)
    assert packages == ["evidentia-core"]
    pattern, replacement = bv.bump_pin_range("0.9.9", "0.10.0", packages)
    text = member_pyproject.read_text(encoding="utf-8")
    new_text = re.sub(pattern, replacement, text)

    # Workspace pin moved.
    assert "evidentia-core>=0.10.0,<0.11.0" in new_text
    # Third-party pins UNCHANGED — the v0.10.0 F-V100-M1 bug fixed.
    assert "py-ocsf-models>=0.9.0,<0.10.0" in new_text
    assert "boto3>=0.9.0,<0.10.0" in new_text


def test_real_workspace_allowlist_includes_all_evidentia_packages(bv) -> None:
    """The actual root pyproject.toml lists every evidentia-* package."""
    real_pkgs = bv.workspace_packages(REPO_ROOT / "pyproject.toml")
    # All 7 publishable packages are workspace members.
    expected = {
        "evidentia",
        "evidentia-core",
        "evidentia-ai",
        "evidentia-api",
        "evidentia-collectors",
        "evidentia-integrations",
        "evidentia-mcp",
    }
    assert expected.issubset(set(real_pkgs))
    # py-ocsf-models is NOT in the allowlist (it's a third-party dep).
    assert "py-ocsf-models" not in real_pkgs
