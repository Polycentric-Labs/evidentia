"""Tests for the FDA 524B pack's standard stubs + pairwise crosswalks.

The FDA 524B pack adds two license-respecting Tier-C standard stubs —
``iso-14971`` (ISO 14971:2019 risk-management clauses) and ``aami-sw96``
(ANSI/AAMI SW96:2023 security-risk-management process areas) — and two
illustrative crosswalks mapping the eight FDA Section 524B premarket
security control categories onto each standard.

These tests assert:

(a) both stubs appear in ``evidentia catalog list`` and load as Tier-C
    placeholders carrying the license metadata (no normative text), and
(b) both crosswalk JSONs are valid, load via ``CrosswalkDefinition`` and
    the ``CrosswalkEngine``, map all eight 524B categories, and carry the
    differentiated-risk-model note + the illustrative/self-attested
    verification posture.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia.cli.main import app
from evidentia_core.catalogs.crosswalk import CrosswalkEngine
from evidentia_core.catalogs.loader import load_any_catalog
from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.models.catalog import CrosswalkDefinition
from typer.testing import CliRunner

MAPPINGS_DIR = (
    Path(__file__).resolve().parents[3]
    / "packages"
    / "evidentia-core"
    / "src"
    / "evidentia_core"
    / "catalogs"
    / "data"
    / "mappings"
)

# The eight §V.B.1 security control category IDs, in order.
FDA_524B_CONTROL_IDS = [
    "524b-scc-1-authentication",
    "524b-scc-2-authorization",
    "524b-scc-3-cryptography",
    "524b-scc-4-code-data-execution-integrity",
    "524b-scc-5-confidentiality",
    "524b-scc-6-event-detection-logging",
    "524b-scc-7-resiliency-recovery",
    "524b-scc-8-updatability-patchability",
]

STUB_IDS = ["iso-14971", "aami-sw96"]

CROSSWALK_FILES = [
    "fda-524b-appendix1_to_iso-14971.json",
    "fda-524b-appendix1_to_aami-sw96.json",
]


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _reset_registry():
    FrameworkRegistry.reset_instance()
    yield
    FrameworkRegistry.reset_instance()


# -----------------------------------------------------------------------------
# Stubs
# -----------------------------------------------------------------------------


def test_stubs_appear_in_catalog_list(runner: CliRunner) -> None:
    """`catalog list` includes both FDA-pack stubs."""
    result = runner.invoke(app, ["catalog", "list"])
    assert result.exit_code == 0, result.output
    for fid in STUB_IDS:
        assert fid in result.output, f"{fid} missing from catalog list"


def test_stubs_appear_in_tier_c_filter(runner: CliRunner) -> None:
    """Both stubs surface under the Tier-C filter (registered as Tier C)."""
    result = runner.invoke(app, ["catalog", "list", "--tier", "C"])
    assert result.exit_code == 0, result.output
    for fid in STUB_IDS:
        assert fid in result.output, f"{fid} missing from Tier-C catalog list"


@pytest.mark.parametrize("framework_id", STUB_IDS)
def test_stub_loads_as_tier_c_placeholder(framework_id: str) -> None:
    """Each stub loads as a Tier-C placeholder with per-control license metadata."""
    catalog = load_any_catalog(framework_id)
    assert catalog is not None
    assert catalog.framework_id == framework_id
    assert catalog.tier == "C"
    assert catalog.placeholder is True
    assert len(catalog.controls) > 0

    for ctrl in catalog.controls:
        # No normative text — only the licensed-content placeholder.
        assert ctrl.description == (
            "[Licensed content — see license_url for authoritative text.]"
        )
        assert ctrl.license_required is True
        assert ctrl.license_url


def test_iso_14971_clause_ids_and_designation() -> None:
    """ISO 14971 stub carries the verified clause IDs + 2019 designation."""
    catalog = load_any_catalog("iso-14971")
    assert catalog is not None
    assert catalog.version == "ISO 14971:2019"
    ids = {c.id for c in catalog.controls}
    assert ids == {f"iso-14971-cl{n}" for n in range(4, 11)}


def test_aami_sw96_designation() -> None:
    """AAMI SW96 stub carries the verified 2023 designation."""
    catalog = load_any_catalog("aami-sw96")
    assert catalog is not None
    assert catalog.version == "ANSI/AAMI SW96:2023"


# -----------------------------------------------------------------------------
# Crosswalks
# -----------------------------------------------------------------------------

# The exact differentiated-risk-model note, verbatim, that BOTH crosswalks
# must carry in their top-level ``risk_model_note`` field.
EXPECTED_RISK_MODEL_NOTE = (
    "Safety risk management (ISO 14971:2019) characterizes risk as a "
    "combination of the probability of occurrence of harm and the severity "
    "of that harm (commonly operationalized as probability × severity). "
    "Security risk management (ANSI/AAMI SW96:2023, building on AAMI "
    "TIR57:2016 (R2023)) characterizes security risk in terms of "
    "exploitability rather than probability of occurrence, while sharing the "
    "same patient-harm severity axis — a security exploit is assessed by how "
    "readily it can be carried out (exploitability) combined with the "
    "severity of the resulting patient harm. The FDA Section 524B premarket "
    "security controls feed the device's security risk management, which in "
    "turn informs the ISO 14971 safety risk file via the shared severity "
    "axis. This characterization is a paraphrase of the ISO 14971 and AAMI "
    "SW96/TIR57 methodologies, not a quotation from the FDA guidance or the "
    "standards."
)


@pytest.mark.parametrize("filename", CROSSWALK_FILES)
def test_crosswalk_json_is_valid_and_loads(filename: str) -> None:
    """Each crosswalk JSON parses + validates against CrosswalkDefinition."""
    path = MAPPINGS_DIR / filename
    assert path.exists(), f"missing crosswalk file {filename}"

    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    obj = CrosswalkDefinition.model_validate(data)
    assert obj.source_framework == "fda-524b-appendix1"
    assert obj.target_framework in ("iso-14971", "aami-sw96")
    assert obj.provenance == "hand-authored"
    assert obj.verification == "self-attested"
    assert obj.verification_note is not None
    assert "illustrative" in obj.verification_note.lower()
    assert "not independently audited" in obj.verification_note.lower()


@pytest.mark.parametrize("filename", CROSSWALK_FILES)
def test_crosswalk_maps_all_eight_524b_categories(filename: str) -> None:
    """Every one of the eight 524B categories is mapped at least once."""
    path = MAPPINGS_DIR / filename
    with path.open(encoding="utf-8") as f:
        obj = CrosswalkDefinition.model_validate(json.load(f))

    mapped_sources = {m.source_control_id for m in obj.mappings}
    assert mapped_sources == set(FDA_524B_CONTROL_IDS)

    # All links are "related" (illustrative conceptual links).
    assert all(m.relationship == "related" for m in obj.mappings)


@pytest.mark.parametrize("filename", CROSSWALK_FILES)
def test_crosswalk_carries_verbatim_risk_model_note(filename: str) -> None:
    """Both crosswalks carry the differentiated-risk-model note VERBATIM."""
    path = MAPPINGS_DIR / filename
    with path.open(encoding="utf-8") as f:
        obj = CrosswalkDefinition.model_validate(json.load(f))

    assert obj.risk_model_note == EXPECTED_RISK_MODEL_NOTE


def test_crosswalk_engine_indexes_fda_to_iso_mappings() -> None:
    """The crosswalk engine loads + indexes the 524B→ISO 14971 mappings."""
    engine = CrosswalkEngine()
    engine.load_all()

    mapped = engine.get_mapped_controls(
        "fda-524b-appendix1",
        "524b-scc-8-updatability-patchability",
        "iso-14971",
    )
    assert mapped, "expected at least one mapped ISO 14971 control"
    assert any(m.target_control_id == "iso-14971-cl10" for m in mapped)


def test_crosswalk_engine_indexes_fda_to_sw96_mappings() -> None:
    """The crosswalk engine loads + indexes the 524B→AAMI SW96 mappings."""
    engine = CrosswalkEngine()
    engine.load_all()

    mapped = engine.get_mapped_controls(
        "fda-524b-appendix1",
        "524b-scc-1-authentication",
        "aami-sw96",
    )
    assert mapped, "expected at least one mapped SW96 process area"
    assert any(
        m.target_control_id == "aami-sw96-pa-security-risk-control" for m in mapped
    )
