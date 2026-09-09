"""Tests for ``scripts/catalogs/gen_osps_crosswalks.py``.

v0.13 moved the 5 ``osps-baseline_to_*.json`` crosswalks from control
level to assessment-requirement level, since the bundled OSPS catalogs
(``osps-baseline-m1/m2/m3``) key on assessment-requirement ids
(``OSPS-AC-01.01``), not the top-level control id. These tests pin the
*transformation* contract against a tiny inline fixture (no network / no
``gh`` calls), plus the normalization, SSDF practice-expansion,
de-duplication and serialization invariants.

Test plan:

1. ``extract_entries_by_standard`` fans out one row per assessment
   requirement of a control, preserves family -> control -> requirement
   -> guideline-entry order, collects ONLY mapped standards, and skips a
   control with no assessment requirements even when it has guideline
   mappings.
2. Title + entry-id whitespace from upstream block scalars / trailing
   spaces is normalized (matching the shipped data).
3. ``normalize_target_id`` applies the known upstream transcription-error
   fixes and names the correction; ``ssdf_task_ids`` reads a bundled
   SSDF-shaped catalog with the stdlib only; ``expand_ssdf_practice``
   expands a practice-level id to its catalog tasks (or leaves it
   unchanged when it is not practice-level or has no bundled tasks).
4. ``build_standard_mappings`` normalizes, expands and de-duplicates on
   ``(source_control_id, target_control_id)``, keeping the first
   occurrence and preserving requirement -> guideline-entry ->
   expanded-task order.
5. ``build_mapping`` / ``build_crosswalk`` produce the exact field order
   + templated ``notes`` / ``verification_note`` / ``version`` strings.
6. ``serialize`` is ``indent=2`` + ``ensure_ascii=False`` + one trailing
   newline.
7. ``build_all_crosswalks`` emits one ``osps-baseline_to_<slug>.json``
   per configured standard.
8. The ``_osps_upstream.py`` pin constants are internally consistent with
   the regenerator's static parameters (SHA shape; the family id;
   ``_baseline_version_display``'s prefix-stripping).
9. ``_compare`` (the pure comparison the ``--check`` drift gate builds on)
   returns no drift when committed bytes match, flags the single file
   whose committed copy diverges, and reports a missing committed file --
   all via inline fixtures + ``tmp_path`` (no network / no ``gh``).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GEN_PATH = REPO_ROOT / "scripts" / "catalogs" / "gen_osps_crosswalks.py"


@pytest.fixture(scope="module")
def gen() -> Any:
    """Import scripts/catalogs/gen_osps_crosswalks.py (no __init__.py).

    The module imports only stdlib + ``yaml`` at module scope (it does
    NOT import the sibling ``_generators`` helper), so it loads cleanly
    via importlib without putting ``scripts/catalogs/`` on ``sys.path``.
    """
    spec = importlib.util.spec_from_file_location("gen_osps_crosswalks", GEN_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_osps_crosswalks"] = module
    spec.loader.exec_module(module)
    return module


# A miniature upstream baseline: 3 controls in one family. OSPS-AC-01 has
# one assessment requirement and mixes a task-level SSDF id, a
# practice-level SSDF id, a CSF typo, an ignored OpenCRE block, and a
# PCIDSS id with upstream trailing spaces. OSPS-AC-02 has TWO assessment
# requirements (fan-out) and an SSDF practice id alongside one of its own
# tasks (de-duplication after expansion). OSPS-AC-03 has guideline
# mappings but NO assessment requirements, so it must contribute nothing.
# This mirrors the real ``baseline/OSPS-*.yaml`` shape (guideline
# reference-id = standard key; entries[].reference-id = target control
# id; assessment-requirements[].id = the catalog-level id).
FIXTURE_DOCS: dict[str, dict[str, Any]] = {
    "AC": {
        "controls": [
            {
                "id": "OSPS-AC-01",
                "title": "Use MFA for Sensitive Actions\n",
                "guidelines": [
                    {
                        "reference-id": "SSDF",
                        "entries": [
                            {"reference-id": "PO.3.2"},
                            {"reference-id": "PS.1"},
                        ],
                    },
                    {
                        "reference-id": "CSF",
                        "entries": [{"reference-id": "PR.A-02"}],
                    },
                    {
                        "reference-id": "OpenCRE",
                        "entries": [{"reference-id": "486-813"}],
                    },
                    {
                        "reference-id": "PCIDSS",
                        "entries": [{"reference-id": "8.2.1   "}],
                    },
                ],
                "assessment-requirements": [
                    {"id": "OSPS-AC-01.01"},
                ],
            },
            {
                "id": "OSPS-AC-02",
                "title": "Restrict Collaborator Permissions\n",
                "guidelines": [
                    {
                        "reference-id": "SSDF",
                        "entries": [
                            {"reference-id": "PO.2"},
                            {"reference-id": "PO.2.1"},
                        ],
                    },
                ],
                "assessment-requirements": [
                    {"id": "OSPS-AC-02.01"},
                    {"id": "OSPS-AC-02.02"},
                ],
            },
            {
                "id": "OSPS-AC-03",
                "title": "Has Mappings But No Requirements\n",
                "guidelines": [
                    {
                        "reference-id": "SSDF",
                        "entries": [{"reference-id": "PO.1.1"}],
                    },
                ],
                "assessment-requirements": [],
            },
        ]
    },
}

# Restrict to the standards the fixture exercises so we don't have to
# populate every real target.
FIXTURE_STANDARDS = {
    "SSDF": ("nist-ssdf-800-218", "NIST SSDF SP 800-218"),
    "PCIDSS": ("pci-dss-4.0", "PCI DSS 4.0"),
    "CSF": ("nist-csf-2.0", "NIST CSF 2.0"),
}

# The SSDF task ids the fixture's practice-level entries (PS.1, PO.2)
# expand against. Deliberately a small synthetic set, not the real
# bundled catalog, so this test file has no dependency on its contents.
FIXTURE_SSDF_TASKS = ["PO.1.1", "PO.1.2", "PO.2.1", "PO.2.2", "PO.2.3", "PO.3.2", "PS.1.1"]

FIXTURE_SHA = "0123456789abcdef0123456789abcdef01234567"
FIXTURE_BASELINE_VERSION = "2026.02.19"


@pytest.fixture(scope="module")
def ssdf_catalog_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A synthetic SSDF catalog JSON exposing exactly :data:`FIXTURE_SSDF_TASKS`.

    Written once per test module so ``build_all_crosswalks`` can be
    exercised end-to-end (including its SSDF-expansion branch) without
    touching the real bundled catalog.
    """
    path = tmp_path_factory.mktemp("ssdf-catalog") / "nist-ssdf-800-218.json"
    controls = [{"id": task_id, "title": task_id} for task_id in FIXTURE_SSDF_TASKS]
    path.write_text(json.dumps({"controls": controls}), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# extract_entries_by_standard: requirement-level fan-out + ordering.
# ---------------------------------------------------------------------------


def test_extract_fans_out_by_requirement_and_filters_standards(gen: Any) -> None:
    by_std = gen.extract_entries_by_standard(FIXTURE_DOCS, FIXTURE_STANDARDS)
    assert set(by_std) == {"SSDF", "PCIDSS", "CSF"}
    # AC-01 has one requirement; both its SSDF entries attach to it, in
    # guideline-entry order. AC-02 has two requirements; each gets the
    # full set of AC-02's SSDF entries (fan-out). AC-03 has a mapped SSDF
    # entry but no assessment requirements, so it contributes nothing.
    assert by_std["SSDF"] == [
        ("OSPS-AC-01.01", "OSPS-AC-01", "Use MFA for Sensitive Actions", "PO.3.2"),
        ("OSPS-AC-01.01", "OSPS-AC-01", "Use MFA for Sensitive Actions", "PS.1"),
        ("OSPS-AC-02.01", "OSPS-AC-02", "Restrict Collaborator Permissions", "PO.2"),
        ("OSPS-AC-02.01", "OSPS-AC-02", "Restrict Collaborator Permissions", "PO.2.1"),
        ("OSPS-AC-02.02", "OSPS-AC-02", "Restrict Collaborator Permissions", "PO.2"),
        ("OSPS-AC-02.02", "OSPS-AC-02", "Restrict Collaborator Permissions", "PO.2.1"),
    ]
    # PCIDSS: single entry on AC-01's one requirement; trailing whitespace
    # on the raw id is stripped here (typo normalization happens later,
    # once the target standard is known).
    assert by_std["PCIDSS"] == [
        ("OSPS-AC-01.01", "OSPS-AC-01", "Use MFA for Sensitive Actions", "8.2.1"),
    ]
    assert by_std["CSF"] == [
        ("OSPS-AC-01.01", "OSPS-AC-01", "Use MFA for Sensitive Actions", "PR.A-02"),
    ]


def test_extract_ignores_unmapped_standard_and_missing_standards(gen: Any) -> None:
    # Default STANDARD_TARGETS has 5 keys; the fixture only maps SSDF +
    # PCIDSS + CSF + the ignored OpenCRE block. With the default
    # standards, OpenCRE stays ignored and the other 2 real standards
    # yield empty lists.
    by_std = gen.extract_entries_by_standard(FIXTURE_DOCS)
    assert set(by_std) == set(gen.STANDARD_TARGETS)
    assert by_std["CRA"] == []
    assert by_std["800-161"] == []
    assert len(by_std["SSDF"]) == 6
    assert len(by_std["PCIDSS"]) == 1
    assert len(by_std["CSF"]) == 1


def test_extract_control_with_no_requirements_emits_nothing(gen: Any) -> None:
    """A control with guideline mappings but no requirements contributes nothing.

    There is no testable requirement id to attach the mapping to, so the
    control is skipped entirely -- covers both an explicit empty list and
    a missing ``assessment-requirements`` key.
    """
    docs = {
        "AC": {
            "controls": [
                {
                    "id": "OSPS-AC-98",
                    "title": "Explicit Empty List\n",
                    "guidelines": [{"reference-id": "SSDF", "entries": [{"reference-id": "PO.1.1"}]}],
                    "assessment-requirements": [],
                },
                {
                    "id": "OSPS-AC-99",
                    "title": "Missing Key Entirely\n",
                    "guidelines": [{"reference-id": "SSDF", "entries": [{"reference-id": "PO.1.2"}]}],
                },
            ]
        },
    }
    by_std = gen.extract_entries_by_standard(docs, FIXTURE_STANDARDS)
    assert by_std["SSDF"] == []


def test_extract_orders_family_before_control(gen: Any) -> None:
    """``family_docs`` iteration order drives the output, not control-id order."""
    docs = {
        "BR": {
            "controls": [
                {
                    "id": "OSPS-BR-01",
                    "title": "Br Title\n",
                    "guidelines": [{"reference-id": "SSDF", "entries": [{"reference-id": "PW.1.1"}]}],
                    "assessment-requirements": [{"id": "OSPS-BR-01.01"}],
                },
            ]
        },
        "AC": {
            "controls": [
                {
                    "id": "OSPS-AC-01",
                    "title": "Ac Title\n",
                    "guidelines": [{"reference-id": "SSDF", "entries": [{"reference-id": "PW.2.1"}]}],
                    "assessment-requirements": [{"id": "OSPS-AC-01.01"}],
                },
            ]
        },
    }
    by_std = gen.extract_entries_by_standard(docs, {"SSDF": ("nist-ssdf-800-218", "NIST SSDF SP 800-218")})
    # BR comes first because family_docs (a dict) is iterated in insertion
    # order -- BR then AC -- regardless of alphabetical control-id order.
    assert [row[0] for row in by_std["SSDF"]] == ["OSPS-BR-01.01", "OSPS-AC-01.01"]


# ---------------------------------------------------------------------------
# normalize_target_id: the six upstream transcription-error fixes.
# ---------------------------------------------------------------------------


def test_normalize_target_id_applies_all_six_fixes(gen: Any) -> None:
    total = 0
    for std_key, fixes in gen.TARGET_ID_FIXES.items():
        for raw, expected in fixes.items():
            fixed, suffix = gen.normalize_target_id(std_key, raw)
            assert fixed == expected
            assert suffix == f" Upstream id {raw!r} normalized to {expected!r}."
            total += 1
    assert total == 6


def test_normalize_target_id_passes_through_unmatched_id(gen: Any) -> None:
    fixed, suffix = gen.normalize_target_id("SSDF", "PO.3.2")
    assert fixed == "PO.3.2"
    assert suffix == ""
    # A raw id that only matches under a DIFFERENT standard's fix table is
    # also left untouched.
    fixed, suffix = gen.normalize_target_id("PCIDSS", "P0.3.1")
    assert fixed == "P0.3.1"
    assert suffix == ""


# ---------------------------------------------------------------------------
# ssdf_task_ids + expand_ssdf_practice: the SSDF practice-level expansion.
# ---------------------------------------------------------------------------


def test_ssdf_task_ids_reads_a_temp_catalog_in_file_order(gen: Any, tmp_path: Path) -> None:
    catalog = tmp_path / "fake-ssdf.json"
    catalog.write_text(
        json.dumps({"controls": [{"id": "PO.1.1"}, {"id": "PO.1.2"}, {"id": "PS.1.1"}]}),
        encoding="utf-8",
    )
    assert gen.ssdf_task_ids(catalog) == ["PO.1.1", "PO.1.2", "PS.1.1"]


def test_expand_ssdf_practice_matches_only_its_own_prefix(gen: Any) -> None:
    # "PO.10.1" must NOT be swept up by practice "PO.1" (a naive substring
    # match would; the "." separator in the prefix check prevents it).
    tasks = ["PO.1.1", "PO.1.2", "PO.2.1", "PO.10.1"]
    assert gen.expand_ssdf_practice("PO.1", tasks) == ["PO.1.1", "PO.1.2"]


def test_expand_ssdf_practice_leaves_task_level_id_unchanged(gen: Any) -> None:
    assert gen.expand_ssdf_practice("PO.1.1", ["PO.1.1", "PO.1.2"]) == ["PO.1.1"]


def test_expand_ssdf_practice_keeps_id_when_no_tasks_match(gen: Any) -> None:
    # An upstream practice with no bundled task is a data problem the
    # truth gate should surface loudly, not one this function papers over.
    assert gen.expand_ssdf_practice("RV.9", ["PO.1.1"]) == ["RV.9"]


# ---------------------------------------------------------------------------
# build_standard_mappings: normalize + expand + de-duplicate + order.
# ---------------------------------------------------------------------------


def test_build_standard_mappings_expands_dedupes_and_orders(gen: Any) -> None:
    entries = gen.extract_entries_by_standard(FIXTURE_DOCS, FIXTURE_STANDARDS)["SSDF"]
    mappings = gen.build_standard_mappings(entries, "SSDF", "NIST SSDF SP 800-218", FIXTURE_SSDF_TASKS)
    got = [(m["source_control_id"], m["target_control_id"]) for m in mappings]
    assert got == [
        ("OSPS-AC-01.01", "PO.3.2"),
        ("OSPS-AC-01.01", "PS.1.1"),  # PS.1 (practice) expanded to its one task.
        ("OSPS-AC-02.01", "PO.2.1"),  # PO.2 (practice) expanded first...
        ("OSPS-AC-02.01", "PO.2.2"),
        ("OSPS-AC-02.01", "PO.2.3"),
        # ...so the explicit PO.2.1 entry that follows is a duplicate and is dropped.
        ("OSPS-AC-02.02", "PO.2.1"),
        ("OSPS-AC-02.02", "PO.2.2"),
        ("OSPS-AC-02.02", "PO.2.3"),
    ]
    expanded_notes = [m for m in mappings if "expanded to its SSDF tasks" in m["notes"]]
    # Every row came from a practice expansion except the one PO.3.2 row,
    # which was already task-level in the upstream guideline entry.
    assert len(expanded_notes) == 7
    assert sum(1 for m in mappings if m["target_control_id"] == "PO.3.2") == 1


def test_build_standard_mappings_normalization_suffix_on_real_typo(gen: Any) -> None:
    entries = gen.extract_entries_by_standard(FIXTURE_DOCS, FIXTURE_STANDARDS)["CSF"]
    mappings = gen.build_standard_mappings(entries, "CSF", "NIST CSF 2.0", ssdf_tasks=None)
    assert len(mappings) == 1
    assert mappings[0]["target_control_id"] == "PR.AA-02"
    assert mappings[0]["notes"].endswith("Upstream id 'PR.A-02' normalized to 'PR.AA-02'.")


def test_build_standard_mappings_no_expansion_for_non_ssdf(gen: Any) -> None:
    """``ssdf_tasks=None`` means no id is ever treated as practice-level."""
    entries = gen.extract_entries_by_standard(FIXTURE_DOCS, FIXTURE_STANDARDS)["PCIDSS"]
    mappings = gen.build_standard_mappings(entries, "PCIDSS", "PCI DSS 4.0", ssdf_tasks=None)
    assert [m["target_control_id"] for m in mappings] == ["8.2.1"]
    assert "expanded" not in mappings[0]["notes"]


# ---------------------------------------------------------------------------
# build_mapping / build_crosswalk: field order + templated text.
# ---------------------------------------------------------------------------


def test_build_mapping_field_order_and_notes(gen: Any) -> None:
    m = gen.build_mapping(
        "OSPS-AC-01.01",
        "OSPS-AC-01",
        "Use MFA for Sensitive Actions",
        "PO.3.2",
        "NIST SSDF SP 800-218",
    )
    # Field order must match the shipped data exactly.
    assert list(m.keys()) == [
        "source_control_id",
        "source_control_title",
        "target_control_id",
        "target_control_title",
        "relationship",
        "notes",
    ]
    assert m["source_control_id"] == "OSPS-AC-01.01"
    assert m["relationship"] == "related"
    assert m["target_control_title"] == ""
    assert m["notes"] == (
        "Inherited from upstream OSPS-AC-01 guidelines[] by assessment "
        "requirement OSPS-AC-01.01; verify against NIST SSDF SP 800-218 "
        "before relying on for audit."
    )


def test_build_mapping_appends_note_suffix_verbatim(gen: Any) -> None:
    m = gen.build_mapping(
        "OSPS-AC-01.01",
        "OSPS-AC-01",
        "Use MFA for Sensitive Actions",
        "PR.AA-02",
        "NIST CSF 2.0",
        " Upstream id 'PR.A-02' normalized to 'PR.AA-02'.",
    )
    assert m["notes"].endswith(" Upstream id 'PR.A-02' normalized to 'PR.AA-02'.")


def test_build_crosswalk_top_level_shape(gen: Any) -> None:
    mappings = [
        gen.build_mapping(
            "OSPS-AC-01.01",
            "OSPS-AC-01",
            "Use MFA for Sensitive Actions",
            "PO.3.2",
            "NIST SSDF SP 800-218",
        )
    ]
    payload = gen.build_crosswalk(
        "nist-ssdf-800-218", "NIST SSDF SP 800-218", mappings, FIXTURE_SHA, FIXTURE_BASELINE_VERSION
    )
    assert list(payload.keys()) == [
        "source_framework",
        "target_framework",
        "version",
        "generated_at",
        "source",
        "provenance",
        "verification",
        "verification_note",
        "mappings",
    ]
    assert payload["source_framework"] == "osps-baseline"
    assert payload["target_framework"] == "nist-ssdf-800-218"
    assert payload["version"] == "OSPS Baseline v2026.02.19 / NIST SSDF SP 800-218"
    # The pinned SHA is interpolated into source + verification_note.
    assert FIXTURE_SHA in payload["source"]
    assert FIXTURE_SHA in payload["verification_note"]
    assert "NIST SSDF SP 800-218" in payload["verification_note"]
    assert "assessment requirements" in payload["verification_note"]
    assert len(payload["mappings"]) == 1


def test_serialize_is_indent2_ensure_ascii_false_trailing_newline(gen: Any) -> None:
    mappings = [
        gen.build_mapping(
            "OSPS-AC-01.01",
            "OSPS-AC-01",
            "Use MFA for Sensitive Actions",
            "PO.3.2",
            "NIST SSDF SP 800-218",
        )
    ]
    payload = gen.build_crosswalk(
        "nist-ssdf-800-218", "NIST SSDF SP 800-218", mappings, FIXTURE_SHA, FIXTURE_BASELINE_VERSION
    )
    text = gen.serialize(payload)
    assert text.endswith("\n")
    assert not text.endswith("\n\n")
    # indent=2 (two-space first-level indent on the opening field).
    assert '\n  "source_framework"' in text
    # Round-trips back to the same object.
    assert json.loads(text) == payload


def test_serialize_preserves_non_ascii_unescaped(gen: Any) -> None:
    # ensure_ascii=False means a non-ASCII char survives unescaped. (The
    # real OSPS crosswalks are pure ASCII, but the serializer must be the
    # ensure_ascii=False variant to reproduce other catalogs' bytes; this
    # guards against a regression to the default.)
    mappings = [gen.build_mapping("OSPS-AC-01.01", "OSPS-AC-01", "Tïtle", "1", "Frámework")]
    payload = gen.build_crosswalk("x", "Frámework", mappings, FIXTURE_SHA, FIXTURE_BASELINE_VERSION)
    text = gen.serialize(payload)
    assert "Frámework" in text
    assert "\\u" not in text


# ---------------------------------------------------------------------------
# build_all_crosswalks: one file per standard, wired end to end.
# ---------------------------------------------------------------------------


def test_build_all_crosswalks_emits_one_file_per_standard(gen: Any, ssdf_catalog_path: Path) -> None:
    out = gen.build_all_crosswalks(
        FIXTURE_DOCS,
        FIXTURE_SHA,
        FIXTURE_BASELINE_VERSION,
        FIXTURE_STANDARDS,
        ssdf_catalog_path=ssdf_catalog_path,
    )
    assert set(out) == {
        "osps-baseline_to_nist-ssdf-800-218.json",
        "osps-baseline_to_pci-dss-4.0.json",
        "osps-baseline_to_nist-csf-2.0.json",
    }
    # Each value is serialized JSON ending in a newline + parseable.
    for name, content in out.items():
        assert content.endswith("\n")
        parsed = json.loads(content)
        assert parsed["target_framework"] in name
        assert parsed["source_framework"] == "osps-baseline"


# ---------------------------------------------------------------------------
# _compare: the pure comparison the --check drift gate builds on.
# ---------------------------------------------------------------------------


def test_compare_no_drift_when_committed_matches(gen: Any, tmp_path: Path, ssdf_catalog_path: Path) -> None:
    """``_compare`` returns no drift when committed bytes match regenerated."""
    regenerated = gen.build_all_crosswalks(
        FIXTURE_DOCS, FIXTURE_SHA, FIXTURE_BASELINE_VERSION, FIXTURE_STANDARDS, ssdf_catalog_path=ssdf_catalog_path
    )
    # Write the regenerated bytes as the "committed" copies.
    for name, content in regenerated.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    # Identical bytes on both sides -> zero/no-drift signal.
    assert gen._compare(regenerated, tmp_path) == []


def test_compare_detects_drift_on_mutated_committed_byte(gen: Any, tmp_path: Path, ssdf_catalog_path: Path) -> None:
    """``_compare`` flags the file whose committed copy diverges by one field."""
    regenerated = gen.build_all_crosswalks(
        FIXTURE_DOCS, FIXTURE_SHA, FIXTURE_BASELINE_VERSION, FIXTURE_STANDARDS, ssdf_catalog_path=ssdf_catalog_path
    )
    for name, content in regenerated.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    # Mutate ONE field of ONE committed file so it differs from regenerated.
    drifted_name = "osps-baseline_to_nist-ssdf-800-218.json"
    committed = json.loads((tmp_path / drifted_name).read_text(encoding="utf-8"))
    committed["mappings"][0]["target_control_id"] = "MUTATED.0.0"
    (tmp_path / drifted_name).write_text(gen.serialize(committed), encoding="utf-8")
    drift = gen._compare(regenerated, tmp_path)
    # Exactly the mutated file is reported; the untouched files are not.
    assert len(drift) == 1
    assert drifted_name in drift[0]
    assert "osps-baseline_to_pci-dss-4.0.json" not in "".join(drift)


def test_compare_flags_missing_committed_file(gen: Any, tmp_path: Path, ssdf_catalog_path: Path) -> None:
    """``_compare`` reports a committed file that does not exist on disk."""
    regenerated = gen.build_all_crosswalks(
        FIXTURE_DOCS, FIXTURE_SHA, FIXTURE_BASELINE_VERSION, FIXTURE_STANDARDS, ssdf_catalog_path=ssdf_catalog_path
    )
    # Write only ONE of the three committed files; the others are "missing".
    present = "osps-baseline_to_pci-dss-4.0.json"
    (tmp_path / present).write_text(regenerated[present], encoding="utf-8")
    drift = gen._compare(regenerated, tmp_path)
    assert len(drift) == 2
    assert any("osps-baseline_to_nist-ssdf-800-218.json" in line and "missing" in line for line in drift)
    assert any("osps-baseline_to_nist-csf-2.0.json" in line and "missing" in line for line in drift)


# ---------------------------------------------------------------------------
# Upstream pin constants.
# ---------------------------------------------------------------------------


def test_baseline_version_display_strips_the_family_prefix(gen: Any) -> None:
    assert gen._baseline_version_display("osps-baseline-2026.02.19") == "2026.02.19"


def test_baseline_version_display_rejects_an_unexpected_shape(gen: Any) -> None:
    with pytest.raises(ValueError, match="unexpected OSPS_BASELINE_VERSION"):
        gen._baseline_version_display("2026.02.19")


def test_upstream_pin_constants_consistent(gen: Any) -> None:
    """The co-located _osps_upstream.py pin is internally consistent."""
    sha, repo, version = gen._load_upstream_pin()
    # 40-char lowercase hex git SHA.
    assert len(sha) == 40
    assert all(c in "0123456789abcdef" for c in sha)
    assert "/" in repo  # owner/repo form
    # SOURCE_FRAMEWORK is the catalog family id every bundled OSPS
    # maturity-level catalog declares as its crosswalk_family;
    # OSPS_BASELINE_VERSION carries that same id as a prefix, plus the
    # upstream release date this regenerator derives and interpolates
    # into each crosswalk's "version" field.
    assert gen.SOURCE_FRAMEWORK == "osps-baseline"
    assert version == f"{gen.SOURCE_FRAMEWORK}-2026.02.19"
    assert gen._baseline_version_display(version) == "2026.02.19"
