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


def test_yaml_and_json_round_trip_preserves_multi_line_fields(
    tmp_path: Path,
) -> None:
    """v0.10.4 P4 hardening: round-trip equivalence holds for the
    fields YAML hand-authoring actually targets — multi-line
    ``description`` blocks, multi-element ``assessment_objectives``
    lists, and populated ``parameters`` dicts.

    The v0.10.3 baseline test (above) only covered single-line
    string fields. The first contributor to hand-author a YAML
    catalog with a literal-block-scalar (``|``) description would
    not be protected against a regression in the YAML loader's
    handling of multi-line strings without this case.
    """
    multi_line_description = (
        "This control requires multi-paragraph description text.\n"
        "\n"
        "  Including leading whitespace on continuation lines\n"
        "  and a YAML literal-block-scalar friendly layout.\n"
    )
    content = {
        "framework_id": "multi-line-round-trip",
        "framework_name": "Multi-line round-trip equivalence",
        "version": "1.0",
        "source": "test",
        "tier": "A",
        "category": "control",
        "families": ["F1"],
        "controls": [
            {
                "id": "C1",
                "title": "Control with multi-line body",
                "description": multi_line_description,
                "family": "F1",
                "assessment_objectives": [
                    "Objective 1: verify the implementation exists.",
                    "Objective 2: verify the implementation is effective.\n"
                    "  Sub-criterion 2.a: monthly cadence.\n"
                    "  Sub-criterion 2.b: documented review.",
                    "Objective 3: verify retention.",
                ],
                "parameters": {
                    "frequency": "monthly | quarterly | annual",
                    "review_role": "compliance-officer",
                    "evidence_text": "Multi-line\nevidence\ntext block.",
                },
            },
        ],
    }
    json_path = tmp_path / "ml.json"
    yaml_path = tmp_path / "ml.yaml"
    # default_flow_style=False forces block-style YAML which is the
    # human-author target; this is what YAML hand-editors emit.
    json_path.write_text(json.dumps(content), encoding="utf-8")
    yaml_path.write_text(
        yaml.safe_dump(content, default_flow_style=False, allow_unicode=True),
        encoding="utf-8",
    )

    from_json = load_evidentia_catalog(json_path)
    from_yaml = load_evidentia_catalog(yaml_path)

    # Top-level equivalence
    assert from_json.framework_id == from_yaml.framework_id
    assert from_json.framework_name == from_yaml.framework_name
    assert from_json.tier == from_yaml.tier
    assert from_json.families == from_yaml.families

    # Per-control field-by-field equivalence
    assert len(from_json.controls) == len(from_yaml.controls) == 1
    c_json, c_yaml = from_json.controls[0], from_yaml.controls[0]
    assert c_json.id == c_yaml.id
    assert c_json.title == c_yaml.title
    assert c_json.family == c_yaml.family
    # The critical multi-line equivalence assertions:
    assert c_json.description == c_yaml.description
    assert "multi-paragraph" in c_yaml.description
    assert "continuation lines" in c_yaml.description
    assert c_json.assessment_objectives == c_yaml.assessment_objectives
    assert len(c_yaml.assessment_objectives) == 3
    assert "Sub-criterion 2.a" in c_yaml.assessment_objectives[1]
    assert c_json.parameters == c_yaml.parameters
    assert "\n" in c_yaml.parameters["evidence_text"]


# ── v0.10.4 P3 framework_id collision guard ──────────────────────


def test_regenerate_manifest_scan_dir_rejects_framework_id_collision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v0.10.4 P3: ``scan_dir`` raises ValueError when two catalog
    files in the same tier directory resolve to the same framework_id.

    Realistic trigger: a contributor converts ``foo.json`` to
    ``foo.yaml`` for the v0.10.3+ YAML affordance but forgets to
    delete the JSON. Both files carry the same ``framework_id:`` and
    both would be ingested. P3 catches the drift at manifest-regen
    time before frameworks.yaml ships.
    """
    # Set up a fake "stubs" tier dir with a JSON + a YAML that share
    # the same framework_id (the typical conversion-mistake shape).
    fake_root = tmp_path / "data"
    stubs = fake_root / "stubs"
    stubs.mkdir(parents=True)
    payload = {
        "framework_id": "collide-id",
        "framework_name": "Collision proof",
        "version": "1.0",
        "tier": "C",
        "category": "control",
        "controls": [],
    }
    (stubs / "collide.json").write_text(json.dumps(payload), encoding="utf-8")
    (stubs / "collide.yaml").write_text(yaml.safe_dump(payload), encoding="utf-8")

    # scripts/catalogs is intentionally NOT a Python package (the
    # files are runnable scripts, not library code), so we load
    # `regenerate_manifest` and its `_generators` neighbor via
    # importlib + a sys.path tweak. Monkey-patch DATA_ROOT after so
    # scan_dir sees our tmp_path fixture instead of the bundled
    # data dir.
    import importlib.util
    import sys

    scripts_catalogs = (
        Path(__file__).resolve().parents[3] / "scripts" / "catalogs"
    )
    monkeypatch.syspath_prepend(str(scripts_catalogs))

    gen_spec = importlib.util.spec_from_file_location(
        "_generators", scripts_catalogs / "_generators.py"
    )
    assert gen_spec is not None and gen_spec.loader is not None
    gen_mod = importlib.util.module_from_spec(gen_spec)
    sys.modules["_generators"] = gen_mod
    gen_spec.loader.exec_module(gen_mod)

    rm_spec = importlib.util.spec_from_file_location(
        "regenerate_manifest", scripts_catalogs / "regenerate_manifest.py"
    )
    assert rm_spec is not None and rm_spec.loader is not None
    rm = importlib.util.module_from_spec(rm_spec)
    rm_spec.loader.exec_module(rm)
    monkeypatch.setattr(rm, "DATA_ROOT", fake_root)

    with pytest.raises(ValueError, match=r"framework_id collision in stubs/"):
        rm.scan_dir("stubs")
