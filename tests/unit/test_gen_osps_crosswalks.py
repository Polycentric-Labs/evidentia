"""Tests for ``scripts/catalogs/gen_osps_crosswalks.py`` (D2.1, v0.10.7).

The regenerator reproduces the 5 ``osps-baseline_to_*.json`` crosswalks
byte-for-byte from the pinned upstream OSPS Baseline YAML. These tests
pin the *transformation* contract against a tiny inline fixture (no
network / no ``gh`` calls), plus assert serialization invariants and the
co-located upstream-pin constants.

Test plan:

1. ``extract_entries_by_standard`` preserves family -> control ->
   guideline-block -> entry order and collects ONLY mapped standards.
2. Title + entry-id whitespace from upstream block scalars / trailing
   spaces is normalized (matching the shipped data).
3. ``build_mapping`` / ``build_crosswalk`` produce the exact field order
   + templated ``notes`` / ``verification_note`` / ``version`` strings.
4. ``serialize`` is ``indent=2`` + ``ensure_ascii=False`` + one trailing
   newline.
5. ``build_all_crosswalks`` emits one ``osps-baseline_to_<slug>.json``
   per configured standard.
6. The ``_osps_upstream.py`` pin constants are internally consistent with
   the regenerator's static parameters (SHA shape; version string).
7. ``_compare`` (the pure comparison the ``--check`` drift gate builds on)
   returns no drift when committed bytes match, flags the single file
   whose committed copy diverges, and reports a missing committed file —
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


# A miniature upstream baseline: 2 controls in one family, each with a
# couple of mapped standards (SSDF + PCIDSS) plus an UNmapped block
# (OpenCRE) that must be ignored. Title carries the upstream block-scalar
# trailing newline; one entry id has trailing spaces — both must be
# normalized by the extractor. This mirrors the real
# ``baseline/OSPS-*.yaml`` shape (guideline reference-id = standard key;
# entries[].reference-id = target control id).
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
                        "reference-id": "OpenCRE",
                        "entries": [{"reference-id": "486-813"}],
                    },
                    {
                        "reference-id": "PCIDSS",
                        "entries": [{"reference-id": "8.2.1   "}],
                    },
                ],
            },
            {
                "id": "OSPS-AC-02",
                "title": "Restrict Collaborator Permissions\n",
                "guidelines": [
                    {
                        "reference-id": "SSDF",
                        "entries": [{"reference-id": "PO.2"}],
                    },
                ],
            },
        ]
    },
}

# Restrict to the two standards the fixture exercises so we don't have to
# populate every real target.
FIXTURE_STANDARDS = {
    "SSDF": ("nist-ssdf-800-218", "NIST SSDF SP 800-218"),
    "PCIDSS": ("pci-dss-4.0", "PCI DSS 4.0"),
}

FIXTURE_SHA = "0123456789abcdef0123456789abcdef01234567"


def test_extract_preserves_order_and_filters_standards(gen: Any) -> None:
    by_std = gen.extract_entries_by_standard(FIXTURE_DOCS, FIXTURE_STANDARDS)
    # Only the two configured standards appear; OpenCRE is dropped.
    assert set(by_std) == {"SSDF", "PCIDSS"}
    # SSDF: AC-01's two entries (in order) then AC-02's one entry.
    assert by_std["SSDF"] == [
        ("OSPS-AC-01", "Use MFA for Sensitive Actions", "PO.3.2"),
        ("OSPS-AC-01", "Use MFA for Sensitive Actions", "PS.1"),
        ("OSPS-AC-02", "Restrict Collaborator Permissions", "PO.2"),
    ]
    # PCIDSS: single entry; trailing whitespace on the id is stripped.
    assert by_std["PCIDSS"] == [
        ("OSPS-AC-01", "Use MFA for Sensitive Actions", "8.2.1"),
    ]


def test_extract_ignores_unmapped_standard_only(gen: Any) -> None:
    # Default STANDARD_TARGETS has 5 keys; the fixture only has SSDF +
    # PCIDSS + OpenCRE. With the default standards, OpenCRE is still
    # ignored and the other 3 real standards yield empty lists.
    by_std = gen.extract_entries_by_standard(FIXTURE_DOCS)
    assert set(by_std) == set(gen.STANDARD_TARGETS)
    assert by_std["CRA"] == []
    assert by_std["CSF"] == []
    assert by_std["800-161"] == []
    assert len(by_std["SSDF"]) == 3
    assert len(by_std["PCIDSS"]) == 1


def test_build_mapping_field_order_and_notes(gen: Any) -> None:
    m = gen.build_mapping(
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
    assert m["relationship"] == "related"
    assert m["target_control_title"] == ""
    assert m["notes"] == (
        "Auto-extracted from upstream OSPS-AC-01 guidelines[]; "
        "verify against NIST SSDF SP 800-218 before relying on for audit."
    )


def test_build_crosswalk_top_level_shape(gen: Any) -> None:
    entries = [("OSPS-AC-01", "Use MFA for Sensitive Actions", "PO.3.2")]
    payload = gen.build_crosswalk("nist-ssdf-800-218", "NIST SSDF SP 800-218", entries, FIXTURE_SHA)
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
    assert payload["source_framework"] == "osps-baseline-2026.02.19"
    assert payload["target_framework"] == "nist-ssdf-800-218"
    assert payload["version"] == "OSPS Baseline v2026.02.19 / NIST SSDF SP 800-218"
    # The pinned SHA is interpolated into source + verification_note.
    assert FIXTURE_SHA in payload["source"]
    assert FIXTURE_SHA in payload["verification_note"]
    assert "NIST SSDF SP 800-218" in payload["verification_note"]
    assert len(payload["mappings"]) == 1


def test_serialize_is_indent2_ensure_ascii_false_trailing_newline(gen: Any) -> None:
    payload = gen.build_crosswalk(
        "nist-ssdf-800-218",
        "NIST SSDF SP 800-218",
        [("OSPS-AC-01", "Use MFA for Sensitive Actions", "PO.3.2")],
        FIXTURE_SHA,
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
    payload = gen.build_crosswalk(
        "x",
        "Frámework",  # non-ASCII display name for the assertion
        [("OSPS-AC-01", "Tïtle", "1")],
        FIXTURE_SHA,
    )
    text = gen.serialize(payload)
    assert "Frámework" in text
    assert "\\u" not in text


def test_build_all_crosswalks_emits_one_file_per_standard(gen: Any) -> None:
    out = gen.build_all_crosswalks(FIXTURE_DOCS, FIXTURE_SHA, FIXTURE_STANDARDS)
    assert set(out) == {
        "osps-baseline_to_nist-ssdf-800-218.json",
        "osps-baseline_to_pci-dss-4.0.json",
    }
    # Each value is serialized JSON ending in a newline + parseable.
    for name, content in out.items():
        assert content.endswith("\n")
        parsed = json.loads(content)
        assert parsed["target_framework"] in name


def test_compare_no_drift_when_committed_matches(gen: Any, tmp_path: Path) -> None:
    """``_compare`` returns no drift when committed bytes match regenerated."""
    regenerated = gen.build_all_crosswalks(FIXTURE_DOCS, FIXTURE_SHA, FIXTURE_STANDARDS)
    # Write the regenerated bytes as the "committed" copies.
    for name, content in regenerated.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    # Identical bytes on both sides -> zero/no-drift signal.
    assert gen._compare(regenerated, tmp_path) == []


def test_compare_detects_drift_on_mutated_committed_byte(gen: Any, tmp_path: Path) -> None:
    """``_compare`` flags the file whose committed copy diverges by one field."""
    regenerated = gen.build_all_crosswalks(FIXTURE_DOCS, FIXTURE_SHA, FIXTURE_STANDARDS)
    for name, content in regenerated.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    # Mutate ONE field of ONE committed file so it differs from regenerated.
    drifted_name = "osps-baseline_to_nist-ssdf-800-218.json"
    committed = json.loads((tmp_path / drifted_name).read_text(encoding="utf-8"))
    committed["mappings"][0]["target_control_id"] = "MUTATED.0.0"
    (tmp_path / drifted_name).write_text(gen.serialize(committed), encoding="utf-8")
    drift = gen._compare(regenerated, tmp_path)
    # Exactly the mutated file is reported; the untouched file is not.
    assert len(drift) == 1
    assert drifted_name in drift[0]
    assert "osps-baseline_to_pci-dss-4.0.json" not in "".join(drift)


def test_compare_flags_missing_committed_file(gen: Any, tmp_path: Path) -> None:
    """``_compare`` reports a committed file that does not exist on disk."""
    regenerated = gen.build_all_crosswalks(FIXTURE_DOCS, FIXTURE_SHA, FIXTURE_STANDARDS)
    # Write only ONE of the two committed files; the other is "missing".
    present = "osps-baseline_to_pci-dss-4.0.json"
    (tmp_path / present).write_text(regenerated[present], encoding="utf-8")
    drift = gen._compare(regenerated, tmp_path)
    assert len(drift) == 1
    assert "osps-baseline_to_nist-ssdf-800-218.json" in drift[0]
    assert "missing" in drift[0]


def test_upstream_pin_constants_consistent(gen: Any) -> None:
    """The co-located _osps_upstream.py pin is internally consistent."""
    sha, repo = gen._load_upstream_pin()
    # 40-char lowercase hex git SHA.
    assert len(sha) == 40
    assert all(c in "0123456789abcdef" for c in sha)
    assert "/" in repo  # owner/repo form
    # The regenerator's static SOURCE_FRAMEWORK matches the pinned version
    # string in the constant module (read via the same exec path).
    namespace: dict[str, Any] = {}
    # Reading our own in-repo constant module via the same exec path the
    # regenerator uses.
    exec(gen._OSPS_UPSTREAM_PATH.read_text(encoding="utf-8"), namespace)
    assert namespace["OSPS_BASELINE_VERSION"] == gen.SOURCE_FRAMEWORK
