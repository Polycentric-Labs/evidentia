"""Tests for ``scripts/pre_push/check_uv_lock_pin_drift.py`` (D5, v0.10.7).

Pre-push gate L2 check: a workspace-package version bump in ``uv.lock`` must
NOT drag any third-party (registry-sourced) package's pinned version (the
v0.10.0 F-V100-M1 pattern). These tests pin the pure parse + diff logic
against inline ``uv.lock`` fixtures (no git, no network).
"""

from __future__ import annotations

import importlib.util
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
