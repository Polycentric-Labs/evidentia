"""Tests for v0.10.3 Phase 1 YAML catalog loader support.

The loader now accepts catalog files in JSON OR YAML format; the
file extension dispatches via `_load_catalog_data`. YAML is the
hand-author-friendly format (comments, multi-line strings, no
escape/comma headaches).

Proof of concept in v0.10.3: `iso-27017-2015.yaml` replaced the
JSON equivalent at the same `framework_id`. These tests assert:

1. `_load_catalog_data` dispatches correctly by extension
2. The bundled iso-27017-2015 YAML loads via the registry
3. A YAML file produces the SAME ControlCatalog as the equivalent
   JSON (round-trip equivalence)
4. Malformed YAML / unsupported extensions raise clear errors
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from evidentia_core.catalogs.loader import (
    _load_catalog_data,
    load_evidentia_catalog,
)
from evidentia_core.catalogs.registry import FrameworkRegistry


@pytest.fixture(autouse=True)
def _reset_registry():
    FrameworkRegistry.reset_instance()
    yield
    FrameworkRegistry.reset_instance()


# ── _load_catalog_data dispatch ─────────────────────────────────────


def test_load_catalog_data_dispatches_json(tmp_path: Path) -> None:
    path = tmp_path / "x.json"
    path.write_text(json.dumps({"framework_id": "x", "controls": []}), encoding="utf-8")
    data = _load_catalog_data(path)
    assert data == {"framework_id": "x", "controls": []}


def test_load_catalog_data_dispatches_yaml(tmp_path: Path) -> None:
    path = tmp_path / "x.yaml"
    path.write_text("framework_id: x\ncontrols: []\n", encoding="utf-8")
    data = _load_catalog_data(path)
    assert data == {"framework_id": "x", "controls": []}


def test_load_catalog_data_dispatches_yml_extension(tmp_path: Path) -> None:
    """`.yml` is treated identically to `.yaml`."""
    path = tmp_path / "x.yml"
    path.write_text("framework_id: x\ncontrols: []\n", encoding="utf-8")
    data = _load_catalog_data(path)
    assert data == {"framework_id": "x", "controls": []}


def test_load_catalog_data_rejects_unsupported_extension(tmp_path: Path) -> None:
    path = tmp_path / "x.toml"
    path.write_text("framework_id = 'x'\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported catalog file extension"):
        _load_catalog_data(path)


def test_load_catalog_data_rejects_non_mapping_yaml(tmp_path: Path) -> None:
    """A YAML file whose root is a list (or scalar) is rejected with
    a clear error — catalogs MUST be mappings."""
    path = tmp_path / "list-root.yaml"
    path.write_text("- one\n- two\n", encoding="utf-8")
    with pytest.raises(ValueError, match="top-level must be a mapping"):
        _load_catalog_data(path)


# ── bundled iso-27017-2015 YAML loads via the registry ─────────────


def test_bundled_iso_27017_yaml_loads_via_registry() -> None:
    """The v0.10.3 proof YAML catalog loads end-to-end via the registry."""
    registry = FrameworkRegistry()
    catalog = registry.get_catalog("iso-27017-2015")
    assert catalog.framework_id == "iso-27017-2015"
    assert catalog.framework_name == "ISO/IEC 27017:2015 — Cloud services"
    assert catalog.tier == "C"
    assert catalog.placeholder is True
    # All 7 controls present.
    assert len(catalog.controls) == 7
    # Spot-check a single control.
    cld_6_3_1 = next(c for c in catalog.controls if c.id == "CLD.6.3.1")
    assert "Shared roles" in cld_6_3_1.title
    assert cld_6_3_1.placeholder is True


# ── round-trip equivalence: same content via JSON or YAML ──────────


def test_yaml_and_json_load_to_identical_catalogs(tmp_path: Path) -> None:
    """A catalog defined identically in JSON and YAML produces the same
    ControlCatalog when loaded — proves the YAML support is a pure
    format addition, not a semantic change."""
    content = {
        "framework_id": "round-trip-test",
        "framework_name": "Round-trip equivalence",
        "version": "1.0",
        "source": "test",
        "tier": "A",
        "category": "control",
        "families": ["F1"],
        "controls": [
            {
                "id": "C1",
                "title": "First control",
                "description": "Body.",
                "family": "F1",
            }
        ],
    }
    json_path = tmp_path / "rt.json"
    yaml_path = tmp_path / "rt.yaml"
    json_path.write_text(json.dumps(content), encoding="utf-8")
    yaml_path.write_text(yaml.safe_dump(content), encoding="utf-8")

    from_json = load_evidentia_catalog(json_path)
    from_yaml = load_evidentia_catalog(yaml_path)

    assert from_json.framework_id == from_yaml.framework_id
    assert from_json.framework_name == from_yaml.framework_name
    assert [c.id for c in from_json.controls] == [c.id for c in from_yaml.controls]
    assert from_json.tier == from_yaml.tier
    assert from_json.families == from_yaml.families
