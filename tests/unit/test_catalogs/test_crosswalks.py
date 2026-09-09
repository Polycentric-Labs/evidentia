"""Schema + provenance validation tests for OSPS crosswalks.

v0.10.6 Phase C5 — extends ``CrosswalkDefinition`` with 3 optional
provenance fields (``provenance``, ``verification``,
``verification_note``) and lands 5 OSPS-Baseline crosswalks alongside
the 8 pre-existing in-tree crosswalks.

These tests verify:
  1. The extended schema accepts the new optional fields.
  2. Existing pre-v0.10.6 crosswalks still load (backward-compat).
  3. ``verification`` rejects values outside the allowed ``Literal``.
  4. Each of the 5 OSPS crosswalk files loads + carries the expected
     upstream-attested provenance posture.

See ``docs/api-stability.md`` revision-history row for v0.10.6 +
``docs/v0.10.6-plan.md`` §Phase 5 for the upstream-attested rationale.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from evidentia_core.catalogs.crosswalk import CrosswalkEngine
from evidentia_core.models.catalog import CrosswalkDefinition

# Path-arithmetic: this file lives at
#   tests/unit/test_catalogs/test_crosswalks.py
# so ``parent`` is ``test_catalogs``, ``parent.parent`` is ``unit``,
# ``parent.parent.parent`` is ``tests``, and ``parent.parent.parent.parent``
# is the repo root. Verified empirically before committing.
MAPPINGS_DIR = (
    Path(__file__).parent.parent.parent.parent
    / "packages"
    / "evidentia-core"
    / "src"
    / "evidentia_core"
    / "catalogs"
    / "data"
    / "mappings"
)


def test_crosswalkdefinition_accepts_optional_provenance_fields() -> None:
    """Extended schema accepts provenance/verification/verification_note as optional."""
    obj = CrosswalkDefinition(
        source_framework="osps-baseline-2026.02.19",
        target_framework="nist-ssdf-800-218",
        version="OSPS Baseline / NIST SSDF",
        generated_at="2026-05-26",
        source="Auto-extracted upstream OSPS guidelines[]",
        provenance="upstream-osps-guidelines",
        verification="self-attested-via-upstream",
        verification_note="Mappings auto-extracted; not independently verified.",
        mappings=[],
    )
    assert obj.provenance == "upstream-osps-guidelines"
    assert obj.verification == "self-attested-via-upstream"
    assert obj.verification_note is not None
    assert obj.verification_note.startswith("Mappings")


def test_crosswalkdefinition_backward_compat_without_provenance_fields() -> None:
    """Existing crosswalks without new fields still load (fields default to None)."""
    obj = CrosswalkDefinition(
        source_framework="fedramp-rev5-moderate",
        target_framework="cmmc-2-l2",
        version="...",
        generated_at="2026-04-16",
        source="Evidentia-authored",
        mappings=[],
    )
    assert obj.provenance is None
    assert obj.verification is None
    assert obj.verification_note is None


def test_crosswalkdefinition_rejects_invalid_verification_literal() -> None:
    """verification must be one of the allowed literals."""
    with pytest.raises(ValueError):
        CrosswalkDefinition(
            source_framework="x",
            target_framework="y",
            version="...",
            generated_at="...",
            source="...",
            verification="bogus-value",  # type: ignore[arg-type]
            mappings=[],
        )


@pytest.mark.parametrize(
    "filename",
    [
        "osps-baseline_to_nist-ssdf-800-218.json",
        "osps-baseline_to_nist-csf-2.0.json",
        "osps-baseline_to_eu-cra.json",
        "osps-baseline_to_pci-dss-4.0.json",
        "osps-baseline_to_nist-800-161.json",
    ],
)
def test_osps_crosswalks_load_and_self_attest(filename: str) -> None:
    """Each OSPS crosswalk loads + declares upstream-osps provenance.

    ``source_framework`` is the exact ``osps-baseline`` family id (the
    three bundled maturity-level catalogs' ``crosswalk_family``), not a
    version-suffixed string, so the crosswalk engine's family resolution
    applies. Rows are keyed at assessment-requirement level.
    """
    path = MAPPINGS_DIR / filename
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    obj = CrosswalkDefinition.model_validate(data)
    assert obj.source_framework == "osps-baseline"
    assert obj.provenance == "upstream-osps-guidelines"
    assert obj.verification == "self-attested-via-upstream"
    assert len(obj.mappings) > 0
    requirement_id_re = re.compile(r"^OSPS-[A-Z]{2}-\d{2}\.\d{2}$")
    for mapping in obj.mappings:
        assert requirement_id_re.match(mapping.source_control_id), mapping.source_control_id


def _write_crosswalk(
    path: Path,
    source: str,
    target: str,
    pairs: list[tuple[str, str]],
) -> Path:
    path.write_text(
        json.dumps(
            {
                "source_framework": source,
                "target_framework": target,
                "version": "1",
                "generated_at": "2026-09-08",
                "source": "Synthetic lookup regression fixture",
                "mappings": [
                    {"source_control_id": src, "target_control_id": dst, "relationship": "related"}
                    for src, dst in pairs
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_all_mappings_preserve_interleaved_family_and_direction_order(tmp_path: Path) -> None:
    """Forward groups precede reverse groups, retaining load order and duplicates."""
    crosswalks = [
        ("reverse-first", "child", [("R-1", "ac-1")]),
        ("beta", "family", [("R-B0", "AC-1")]),
        ("family", "alpha", [("AC-1", "F-A"), ("AC-1", "F-A")]),
        ("child", "beta", [("AC-1", "D-B")]),
        ("child", "alpha", [("AC-1", "D-A")]),
        ("family", "beta", [("AC-1", "F-B")]),
        ("beta", "child", [("R-B1", "AC-1")]),
        ("unrelated", "noise", [("AC-1", "NOISE")]),
        ("child", "noise", [("ZZ-1", "OTHER")]),
    ]
    for index, (source, target, pairs) in enumerate(crosswalks):
        _write_crosswalk(tmp_path / f"{index}.json", source, target, pairs)
    engine = CrosswalkEngine(tmp_path, families={"child": "family"})
    engine.load_all()

    mappings = engine.get_all_mapped_controls("child", " ac-1 ")

    assert [(target, [m.target_control_id for m in rows]) for target, rows in mappings.items()] == [
        ("alpha", ["F-A", "F-A", "D-A"]),
        ("beta", ["D-B", "F-B", "R-B0", "R-B1"]),
        ("reverse-first", ["R-1"]),
    ]
    assert engine.get_cross_framework_value("child", "AC-1") == [
        "alpha:F-A",
        "alpha:F-A",
        "alpha:D-A",
        "beta:D-B",
        "beta:F-B",
        "beta:R-B0",
        "beta:R-B1",
        "reverse-first:R-1",
    ]
    assert [m.target_control_id for m in engine.get_mapped_controls("child", "AC-1", "alpha")] == [
        "D-A",
        "F-A",
    ]
    assert engine.get_all_mapped_controls("child", "missing") == {}


def test_all_mappings_include_incremental_rows_in_existing_and_new_groups(tmp_path: Path) -> None:
    """Later loads update existing groups without moving them or stale lookup results."""
    engine = CrosswalkEngine(tmp_path, families={"child": "family"})
    engine.load_crosswalk(_write_crosswalk(tmp_path / "direct.json", "child", "alpha", [("AC-1", "D-1")]))
    engine.load_crosswalk(_write_crosswalk(tmp_path / "family.json", "family", "alpha", [("AC-1", "F-1")]))
    previous = engine.get_all_mapped_controls("child", "AC-1")
    assert [m.target_control_id for m in previous["alpha"]] == ["D-1", "F-1"]
    assert engine.get_all_mapped_controls("child", "AC-NEW") == {}

    engine.load_crosswalk(
        _write_crosswalk(
            tmp_path / "later.json", "child", "alpha", [("AC-1", "D-2"), ("AC-1", "D-1"), ("AC-NEW", "NEW")]
        )
    )
    engine.load_crosswalk(_write_crosswalk(tmp_path / "beta.json", "family", "beta", [("AC-1", "F-B")]))
    reverse = _write_crosswalk(tmp_path / "reverse.json", "beta", "child", [("R-B", "AC-1")])
    engine.load_crosswalk(reverse)
    engine.load_crosswalk(reverse)

    assert engine.get_cross_framework_value("child", "AC-1") == [
        "alpha:D-1",
        "alpha:D-2",
        "alpha:D-1",
        "alpha:F-1",
        "beta:F-B",
        "beta:R-B",
        "beta:R-B",
    ]
    assert engine.get_cross_framework_value("child", "AC-NEW") == ["alpha:NEW"]
    assert [m.target_control_id for m in previous["alpha"]] == ["D-1", "F-1"]


def test_all_mappings_returns_independent_result_lists(tmp_path: Path) -> None:
    """Fresh containers retain the existing mutable mapping objects across lookups."""
    engine = CrosswalkEngine(tmp_path)
    crosswalk = engine.load_crosswalk(
        _write_crosswalk(tmp_path / "mapping.json", "source", "target", [("AC-1", "T-1")])
    )

    result = engine.get_all_mapped_controls("source", "AC-1")
    row = result["target"][0]
    assert row is crosswalk.mappings[0]
    row.notes = "Updated forward mapping"
    result["target"].clear()
    result.clear()

    assert engine.get_cross_framework_value("source", "AC-1") == ["target:T-1"]
    assert [m.target_control_id for m in engine.get_mapped_controls("source", "AC-1", "target")] == ["T-1"]
    next_row = engine.get_all_mapped_controls("source", "AC-1")["target"][0]
    assert next_row is row
    assert next_row.notes == "Updated forward mapping"

    reverse = engine.get_all_mapped_controls("target", "T-1")["source"][0]
    assert reverse is not row
    reverse.notes = "Updated reverse mapping"
    assert engine.get_all_mapped_controls("target", "T-1")["source"][0] is reverse
    assert row.notes == "Updated forward mapping"
