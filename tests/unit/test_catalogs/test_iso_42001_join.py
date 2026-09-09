"""ISO/IEC 42001:2023 Annex A stub and its NIST AI RMF crosswalk.

The ISO 42001 stub used to number its 38 placeholder controls ``A.1``
through ``A.38``, which are not Annex A identifiers. It now carries the
published Annex A control ids and neutral titles across the standard's
nine objectives (``A.2`` through ``A.10``). The
``nist-ai-rmf-1.0_to_iso-42001-2023`` crosswalk used to target
identifiers of the form ``ISO42001.A.6.1``, which matched nothing in any
bundled catalog and resolved at zero percent; it is now keyed on the same
Annex A numbering as the stub, so every row resolves on both sides.

These tests pin:
  1. The stub's 38 control ids, in Annex A order, and its nine families,
     in objective order.
  2. Every stub control is a placeholder requiring a license.
  3. The crosswalk loads as ``CrosswalkDefinition`` with 28 rows.
  4. Every row's ``target_control_id`` resolves in the stub and every
     row's ``source_control_id`` resolves in the ``nist-ai-rmf-1.0``
     catalog.
  5. The crosswalk's verification posture and per-row confidence values.
"""

from __future__ import annotations

import importlib.util
import json
import runpy
import sys
from pathlib import Path
from typing import Any

import pytest
from evidentia_core.catalogs.loader import load_any_catalog
from evidentia_core.models.catalog import ControlCatalog, CrosswalkDefinition

# Path-arithmetic: this file lives at
#   tests/unit/test_catalogs/test_iso_42001_join.py
# so ``parent`` is ``test_catalogs``, ``parent.parent`` is ``unit``,
# ``parent.parent.parent`` is ``tests``, and ``parent.parent.parent.parent``
# is the repo root.
DATA_ROOT = (
    Path(__file__).parent.parent.parent.parent
    / "packages"
    / "evidentia-core"
    / "src"
    / "evidentia_core"
    / "catalogs"
    / "data"
)
CROSSWALK_PATH = DATA_ROOT / "mappings" / "nist-ai-rmf-1.0_to_iso-42001-2023.json"

# The published Annex A control ids, in the order they appear under their
# nine objectives (A.2 through A.10). The first entry under each objective
# is the objective statement itself, so numbering inside each objective
# starts at .2.
EXPECTED_ANNEX_A_IDS = [
    "A.2.2",
    "A.2.3",
    "A.2.4",
    "A.3.2",
    "A.3.3",
    "A.4.2",
    "A.4.3",
    "A.4.4",
    "A.4.5",
    "A.4.6",
    "A.5.2",
    "A.5.3",
    "A.5.4",
    "A.5.5",
    "A.6.1.2",
    "A.6.1.3",
    "A.6.2.2",
    "A.6.2.3",
    "A.6.2.4",
    "A.6.2.5",
    "A.6.2.6",
    "A.6.2.7",
    "A.6.2.8",
    "A.7.2",
    "A.7.3",
    "A.7.4",
    "A.7.5",
    "A.7.6",
    "A.8.2",
    "A.8.3",
    "A.8.4",
    "A.8.5",
    "A.9.2",
    "A.9.3",
    "A.9.4",
    "A.10.2",
    "A.10.3",
    "A.10.4",
]

EXPECTED_FAMILIES = [
    "A.2 Policies related to AI",
    "A.3 Internal organization",
    "A.4 Resources for AI systems",
    "A.5 Assessing impacts of AI systems",
    "A.6 AI system life cycle",
    "A.7 Data for AI systems",
    "A.8 Information for interested parties of AI systems",
    "A.9 Use of AI systems",
    "A.10 Third-party and customer relationships",
]


def _load_stub() -> ControlCatalog:
    catalog = load_any_catalog("iso-42001-2023")
    assert isinstance(catalog, ControlCatalog)
    return catalog


def _load_rmf() -> ControlCatalog:
    catalog = load_any_catalog("nist-ai-rmf-1.0")
    assert isinstance(catalog, ControlCatalog)
    return catalog


def _load_crosswalk() -> CrosswalkDefinition:
    with CROSSWALK_PATH.open(encoding="utf-8") as f:
        return CrosswalkDefinition.model_validate(json.load(f))


def test_stub_has_38_controls_matching_annex_a_order() -> None:
    stub = _load_stub()
    assert len(EXPECTED_ANNEX_A_IDS) == 38
    assert [c.id for c in stub.controls] == EXPECTED_ANNEX_A_IDS


def test_stub_families_match_the_nine_objectives_in_order() -> None:
    stub = _load_stub()
    assert stub.families == EXPECTED_FAMILIES
    assert len(stub.families) == 9


def test_stub_controls_are_all_placeholders_requiring_a_license() -> None:
    stub = _load_stub()
    for control in stub.controls:
        assert control.placeholder is True, control.id
        assert control.license_required is True, control.id


def test_crosswalk_loads_with_28_rows() -> None:
    xwalk = _load_crosswalk()
    assert xwalk.source_framework == "nist-ai-rmf-1.0"
    assert xwalk.target_framework == "iso-42001-2023"
    assert len(xwalk.mappings) == 28


def test_crosswalk_verification_is_self_attested() -> None:
    xwalk = _load_crosswalk()
    assert xwalk.verification == "self-attested"
    assert xwalk.verification_note is not None
    assert xwalk.verification_note != ""


def test_crosswalk_preserves_the_ratified_authoring_date() -> None:
    assert _load_crosswalk().generated_at == "2026-09-07"


def test_stub_generator_leaves_yaml_catalogs_to_their_canonical_files(monkeypatch: pytest.MonkeyPatch) -> None:
    scripts_dir = Path(__file__).resolve().parents[3] / "scripts" / "catalogs"
    helper_spec = importlib.util.spec_from_file_location(
        "stub_generator_helpers_under_test", scripts_dir / "_generators.py"
    )
    assert helper_spec is not None and helper_spec.loader is not None
    helpers = importlib.util.module_from_spec(helper_spec)
    helper_spec.loader.exec_module(helpers)
    emitted: set[str] = set()

    def capture_emission(*, framework_id: str, **kwargs: Any) -> None:
        emitted.add(framework_id)

    monkeypatch.setattr(helpers, "emit_control_catalog", capture_emission)
    monkeypatch.setitem(sys.modules, "_generators", helpers)
    monkeypatch.syspath_prepend(str(scripts_dir))
    # The legacy entry point delegates Swift to a sibling module. Bind that
    # module to the same capture helper and restore both cache entries after.
    headings_spec = importlib.util.spec_from_file_location(
        "gen_currency_headings", scripts_dir / "gen_currency_headings.py"
    )
    assert headings_spec is not None and headings_spec.loader is not None
    headings = importlib.util.module_from_spec(headings_spec)
    monkeypatch.setitem(sys.modules, "gen_currency_headings", headings)
    headings_spec.loader.exec_module(headings)
    runpy.run_path(str(scripts_dir / "gen_stubs.py"))

    assert "iso-42001-2023" in emitted
    assert emitted.isdisjoint({"iso-27017-2015", "cis-controls-v8.1"})


def test_every_target_control_id_resolves_in_the_stub() -> None:
    stub = _load_stub()
    xwalk = _load_crosswalk()
    unresolved = [m.target_control_id for m in xwalk.mappings if stub.get_control(m.target_control_id) is None]
    assert unresolved == []


def test_every_source_control_id_resolves_in_the_ai_rmf_catalog() -> None:
    rmf = _load_rmf()
    xwalk = _load_crosswalk()
    unresolved = [m.source_control_id for m in xwalk.mappings if rmf.get_control(m.source_control_id) is None]
    assert unresolved == []


def test_every_row_has_a_recognized_confidence_value() -> None:
    xwalk = _load_crosswalk()
    allowed = {"high", "medium", "low"}
    for mapping in xwalk.mappings:
        assert mapping.confidence in allowed, (mapping.source_control_id, mapping.confidence)


def test_every_row_carries_a_nonempty_target_control_title() -> None:
    # The old crosswalk left target_control_title unset; the re-targeted
    # version carries the stub's neutral title for every row so a reader
    # doesn't have to cross-reference the stub to see what a row means.
    xwalk = _load_crosswalk()
    for mapping in xwalk.mappings:
        assert mapping.target_control_title, mapping.source_control_id
