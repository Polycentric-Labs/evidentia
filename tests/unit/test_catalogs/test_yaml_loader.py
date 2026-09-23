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


def test_load_catalog_data_rejects_no_extension(tmp_path: Path) -> None:
    """Operator drag-and-drops a catalog file without an extension ;
    the loader should refuse with a clear, self-resolving error that
    names the case and tells the operator the fix (rename to
    .yaml / .yml / .json). v0.10.4 P2 polish landed the explicit
    branch; this test guards against future-contributor regression
    that would remove the defensive arm.
    """
    path = tmp_path / "no_extension_here"
    path.write_text("framework_id: 'x'\ncontrols: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="has no file extension"):
        _load_catalog_data(path)


def test_load_catalog_data_rejects_non_mapping_yaml(tmp_path: Path) -> None:
    """A YAML file whose root is a list (or scalar) is rejected with
    a clear error ; catalogs MUST be mappings."""
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
    assert catalog.framework_name == "ISO/IEC 27017:2015 \u2014 Cloud services"
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
    ControlCatalog when loaded ; proves the YAML support is a pure
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
    fields YAML hand-authoring actually targets ; multi-line
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


# ── v0.10.4 A4 loader-helper choke-point lint ────────────────────


def test_no_sibling_json_loads_or_yaml_safe_load_in_catalogs_module() -> None:
    """v0.10.4 A4: mechanically enforces the v0.10.4 P1 invariant that
    catalog file reads MUST go through ``_load_catalog_data``.

    Walks every ``.py`` in ``evidentia_core.catalogs.*`` and asserts
    that no module besides ``loader.py`` (where the helper itself
    lives) calls ``json.loads(`` or ``yaml.safe_load(`` directly.
    Catches the failure mode of a future contributor adding a new
    catalog loader that bypasses the extension dispatch + non-mapping-
    root rejection at the choke point.

    Why a lint test and not a runtime check: the only way to catch
    bypasses is at module-load time of every catalogs/* file, and
    that's exactly what pytest collection does for free.
    """
    import re

    catalogs_dir = (
        Path(__file__).resolve().parents[3] / "packages" / "evidentia-core" / "src" / "evidentia_core" / "catalogs"
    )
    forbidden_calls = re.compile(r"\b(json\.loads|yaml\.safe_load)\s*\(")
    # The choke-point invariant applies to CATALOG FILE reads. Files
    # whose explicit job is reading the manifest / framework-index
    # (the YAML inventory OF catalogs, not the catalogs themselves)
    # are out of scope and are listed here. Adding a file here is the
    # documented escape hatch; do it only when the file genuinely
    # reads non-catalog data.
    allowlisted_non_catalog_loaders = {
        # manifest.py reads `frameworks.yaml`, the registry index of
        # bundled catalogs. The index itself is not a catalog file.
        "manifest.py",
        # user_dir.py reads operator-imported framework metadata
        # (user-catalogs.yaml index), not the catalog payloads.
        "user_dir.py",
    }
    violations: list[str] = []
    for py_path in catalogs_dir.glob("*.py"):
        if py_path.name == "loader.py":
            # The choke point itself MUST call json.loads + yaml.safe_load.
            continue
        if py_path.name in allowlisted_non_catalog_loaders:
            continue
        if py_path.name.startswith("__"):
            continue
        text = py_path.read_text(encoding="utf-8")
        for match in forbidden_calls.finditer(text):
            line_no = text[: match.start()].count("\n") + 1
            violations.append(
                f"{py_path.name}:{line_no} calls {match.group(0)!r} directly; "
                "use evidentia_core.catalogs.loader._load_catalog_data instead "
                "(v0.10.4 P1 choke-point invariant)."
            )

    assert not violations, "v0.10.4 P1 choke-point invariant violated:\n  " + "\n  ".join(violations)


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

    scripts_catalogs = Path(__file__).resolve().parents[3] / "scripts" / "catalogs"
    monkeypatch.syspath_prepend(str(scripts_catalogs))

    gen_spec = importlib.util.spec_from_file_location("_generators", scripts_catalogs / "_generators.py")
    assert gen_spec is not None and gen_spec.loader is not None
    gen_mod = importlib.util.module_from_spec(gen_spec)
    monkeypatch.setitem(sys.modules, "_generators", gen_mod)
    gen_spec.loader.exec_module(gen_mod)

    rm_spec = importlib.util.spec_from_file_location("regenerate_manifest", scripts_catalogs / "regenerate_manifest.py")
    assert rm_spec is not None and rm_spec.loader is not None
    rm = importlib.util.module_from_spec(rm_spec)
    rm_spec.loader.exec_module(rm)
    monkeypatch.setattr(rm, "DATA_ROOT", fake_root)

    with pytest.raises(ValueError, match=r"framework_id collision in stubs/"):
        rm.scan_dir("stubs")


@pytest.fixture
def manifest_generator(monkeypatch: pytest.MonkeyPatch):
    """Import the script without leaking its helper module into other tests."""
    import importlib.util
    import sys

    scripts = Path(__file__).resolve().parents[3] / "scripts" / "catalogs"
    monkeypatch.syspath_prepend(str(scripts))
    helper_spec = importlib.util.spec_from_file_location("_generators", scripts / "_generators.py")
    assert helper_spec is not None and helper_spec.loader is not None
    helper = importlib.util.module_from_spec(helper_spec)
    monkeypatch.setitem(sys.modules, "_generators", helper)
    helper_spec.loader.exec_module(helper)
    spec = importlib.util.spec_from_file_location("regenerate_manifest", scripts / "regenerate_manifest.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestManifestRegeneration:
    @pytest.mark.parametrize("existing_manifest", [True, False])
    def test_full_regeneration_preserves_reviewed_inventory(
        self, manifest_generator, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_manifest: bool
    ) -> None:
        import shutil

        original = manifest_generator.DATA_ROOT
        expected = (original / "frameworks.yaml").read_text(encoding="utf-8")
        expected_rows = yaml.safe_load(expected)["frameworks"]
        assert len(expected_rows) == 107
        data = tmp_path / "data"
        shutil.copytree(original, data)
        manifest = data / "frameworks.yaml"
        if not existing_manifest:
            manifest.unlink()
        protected = {p.relative_to(data): p.read_bytes() for p in data.rglob("*") if p.is_file() and p != manifest}
        monkeypatch.setattr(manifest_generator, "DATA_ROOT", data)

        manifest_generator.main()

        actual = manifest.read_text(encoding="utf-8")
        actual_rows = yaml.safe_load(actual)["frameworks"]
        assert actual_rows == expected_rows
        assert [list(row) for row in actual_rows] == [list(row) for row in expected_rows]
        assert actual == expected
        assert {
            p.relative_to(data): p.read_bytes() for p in data.rglob("*") if p.is_file() and p != manifest
        } == protected

    @pytest.mark.parametrize("relative", ["international/au-ism.json", "cisa/scuba.json"])
    def test_native_registration_matches_reviewed_manifest(self, manifest_generator, relative: str) -> None:
        expected = yaml.safe_load((manifest_generator.DATA_ROOT / "frameworks.yaml").read_text(encoding="utf-8"))
        expected_row = next(row for row in expected["frameworks"] if row["path"] == relative)
        rows = manifest_generator.scan_dir(relative.split("/")[0])
        assert next(row for row in rows if row["path"] == relative) == expected_row

    @pytest.mark.parametrize("field", ["framework_id", "version", "source"])
    def test_native_source_change_requires_review(
        self, manifest_generator, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
    ) -> None:
        relative = "cisa/scuba.json"
        data = json.loads((manifest_generator.DATA_ROOT / relative).read_text(encoding="utf-8"))
        data[field] = "unreviewed-change"
        target = tmp_path / relative
        target.parent.mkdir()
        target.write_text(json.dumps(data), encoding="utf-8")
        manifest = tmp_path / "frameworks.yaml"
        manifest.write_bytes(b"keep the prior manifest\n")
        monkeypatch.setattr(manifest_generator, "DATA_ROOT", tmp_path)

        with pytest.raises(ValueError, match="Native registration source identity changed"):
            manifest_generator.main()
        assert manifest.read_bytes() == b"keep the prior manifest\n"

    @pytest.mark.parametrize("problem", ["null-tier", "duplicate", "malformed-json", "non-mapping-yaml"])
    def test_invalid_inventory_preserves_output(
        self, manifest_generator, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, problem: str
    ) -> None:
        payload = {
            "framework_id": "test-framework",
            "framework_name": "Test framework",
            "version": "1.0",
            "tier": None if problem == "null-tier" else "C",
            "category": "control",
            "controls": [],
        }
        stubs = tmp_path / "stubs"
        stubs.mkdir()
        (stubs / "test.json").write_text(json.dumps(payload), encoding="utf-8")
        expected_error = "tier"
        if problem == "duplicate":
            other = tmp_path / "international"
            other.mkdir()
            (other / "duplicate.json").write_text(json.dumps(payload), encoding="utf-8")
            expected_error = "Duplicate framework ID across catalog directories"
        elif problem == "malformed-json":
            (stubs / "broken.json").write_text("{", encoding="utf-8")
            expected_error = "Malformed catalog file"
        elif problem == "non-mapping-yaml":
            (stubs / "broken.yaml").write_text("- item\n", encoding="utf-8")
            expected_error = "Malformed catalog file"
        manifest = tmp_path / "frameworks.yaml"
        manifest.write_bytes(b"keep the prior manifest\n")
        monkeypatch.setattr(manifest_generator, "DATA_ROOT", tmp_path)

        with pytest.raises(ValueError, match=expected_error):
            manifest_generator.main()
        assert manifest.read_bytes() == b"keep the prior manifest\n"

    def test_missing_native_files_do_not_create_registrations(
        self, manifest_generator, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(manifest_generator, "DATA_ROOT", tmp_path)
        manifest_generator.main()
        actual = yaml.safe_load((tmp_path / "frameworks.yaml").read_text(encoding="utf-8"))
        assert actual == {"version": 1, "frameworks": []}
