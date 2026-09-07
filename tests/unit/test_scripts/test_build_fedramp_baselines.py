"""Tests for ``scripts/catalogs/build_fedramp_baselines.py``, the in-repo
FedRAMP Rev 5 baseline extractor.

Exercises the extraction logic (id conversion, membership, method props),
the invariant gate, the derived provenance text, and the ``main`` CLI end to
end against small synthetic OSCAL profiles, so nothing here depends on the
real 156/323/410/156 counts or on network access. The final test checks the
real vendored file against its own published counts, still with no network.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import re
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = REPO_ROOT / "scripts" / "catalogs" / "build_fedramp_baselines.py"
VENDORED_PATH = REPO_ROOT / "scripts" / "catalogs" / "upstream" / "fedramp-rev5-baselines.json"


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def bfb() -> Any:
    return _load_module("build_fedramp_baselines_under_test", SCRIPT_PATH)


def _profile(with_ids: list[str], *, alters: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "profile": {
            "metadata": {"oscal-version": "1.1.3", "version": "test-1", "published": "2024-01-01T00:00:00Z"},
            "imports": [{"include-controls": [{"with-ids": with_ids}]}],
        }
    }
    if alters is not None:
        doc["profile"]["modify"] = {"alters": alters}
    return doc


# Synthetic baselines: low == li-saas == {AC-1, AC-2, AC-2(1)}; moderate adds
# AC-3; high adds AC-4. Small enough that expected_counts is trivial to state.
_LI_SAAS_ALTERS = [
    {"control-id": "ac-1", "adds": [{"props": [{"name": "method", "value": "ATTEST"}]}]},
    {
        "control-id": "ac-2",
        "adds": [
            {
                "props": [
                    {"name": "method", "value": "ASSESS"},
                    {"name": "method", "value": "ASSESS"},
                    {"name": "method", "value": "CONDITIONAL"},
                ]
            }
        ],
    },
    # AC-2(1)'s alteration adds only a response-point prop: no method entry.
    {"control-id": "ac-2.1", "adds": [{"props": [{"name": "response-point", "value": "Required"}]}]},
]

SYNTHETIC_PROFILES: dict[str, dict[str, Any]] = {
    "low": _profile(["ac-2", "ac-1", "ac-2", "ac-2.1"]),  # repeated id: tests ordered de-dup
    "moderate": _profile(["ac-1", "ac-2", "ac-2.1", "ac-3"]),
    "high": _profile(["ac-1", "ac-2", "ac-2.1", "ac-3", "ac-4"]),
    "li-saas": _profile(["ac-1", "ac-2", "ac-2.1"], alters=_LI_SAAS_ALTERS),
}
SYNTHETIC_COUNTS = {"low": 3, "moderate": 4, "high": 5, "li-saas": 3}
SYNTHETIC_BASELINES = {
    "low": ["AC-2", "AC-1", "AC-2(1)"],
    "moderate": ["AC-1", "AC-2", "AC-2(1)", "AC-3"],
    "high": ["AC-1", "AC-2", "AC-2(1)", "AC-3", "AC-4"],
    "li-saas": ["AC-1", "AC-2", "AC-2(1)"],
}
SYNTHETIC_METHODS = {"AC-1": ["ATTEST"], "AC-2": ["ASSESS", "CONDITIONAL"]}
SYNTHETIC_NOTE = (
    "2 of the 3 LI-SaaS controls carry at least one FedRAMP Tailored method "
    "(ASSESS 1, ATTEST 1, CONDITIONAL 1); 1 carry two. Controls with no method "
    "prop: AC-2(1) (its profile alteration adds no method)."
)


# ── id conversion ───────────────────────────────────────────────────


class TestOscalToRepoId:
    def test_enhancement(self, bfb: Any) -> None:
        assert bfb.oscal_to_repo_id("ac-2.1") == "AC-2(1)"

    def test_base_control(self, bfb: Any) -> None:
        assert bfb.oscal_to_repo_id("ac-1") == "AC-1"

    def test_three_digit_number(self, bfb: Any) -> None:
        assert bfb.oscal_to_repo_id("sc-100") == "SC-100"


# ── membership ───────────────────────────────────────────────────────


class TestMembership:
    def test_orders_and_deduplicates(self, bfb: Any) -> None:
        profile = _profile(["ac-2", "ac-1", "ac-2", "ac-2.1", "ac-1"])
        assert bfb.membership(profile) == ["AC-2", "AC-1", "AC-2(1)"]

    def test_walks_every_import_and_include_controls_block(self, bfb: Any) -> None:
        profile = {
            "profile": {
                "imports": [
                    {"include-controls": [{"with-ids": ["ac-1"]}, {"with-ids": ["ac-2"]}]},
                    {"include-controls": [{"with-ids": ["ac-1", "ac-3"]}]},
                ]
            }
        }
        assert bfb.membership(profile) == ["AC-1", "AC-2", "AC-3"]


# ── li_saas_methods ──────────────────────────────────────────────────


class TestLiSaasMethods:
    def test_ignores_response_point_and_deduplicates(self, bfb: Any) -> None:
        assert bfb.li_saas_methods(SYNTHETIC_PROFILES["li-saas"]) == SYNTHETIC_METHODS

    def test_sorted_by_control_id(self, bfb: Any) -> None:
        assert list(bfb.li_saas_methods(SYNTHETIC_PROFILES["li-saas"])) == ["AC-1", "AC-2"]


# ── git_blob_sha ─────────────────────────────────────────────────────


def test_git_blob_sha_matches_git_hash_object(bfb: Any) -> None:
    assert bfb.git_blob_sha(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


# ── assert_invariants ────────────────────────────────────────────────


class TestAssertInvariants:
    def test_passes_on_synthetic_data(self, bfb: Any) -> None:
        bfb.assert_invariants(SYNTHETIC_BASELINES, SYNTHETIC_METHODS, expected_counts=SYNTHETIC_COUNTS)

    def test_wrong_count(self, bfb: Any) -> None:
        bad_counts = {**SYNTHETIC_COUNTS, "low": 999}
        with pytest.raises(RuntimeError, match="counts changed"):
            bfb.assert_invariants(SYNTHETIC_BASELINES, SYNTHETIC_METHODS, expected_counts=bad_counts)

    def test_duplicate_control_id(self, bfb: Any) -> None:
        baselines = copy.deepcopy(SYNTHETIC_BASELINES)
        baselines["low"] = ["AC-1", "AC-1", "AC-2"]
        counts = {**SYNTHETIC_COUNTS, "low": 3}
        with pytest.raises(RuntimeError, match="duplicate"):
            bfb.assert_invariants(baselines, SYNTHETIC_METHODS, expected_counts=counts)

    def test_pm_control(self, bfb: Any) -> None:
        baselines = copy.deepcopy(SYNTHETIC_BASELINES)
        baselines["high"] = [*baselines["high"], "PM-1"]
        counts = {**SYNTHETIC_COUNTS, "high": len(baselines["high"])}
        with pytest.raises(RuntimeError, match="PM controls"):
            bfb.assert_invariants(baselines, SYNTHETIC_METHODS, expected_counts=counts)

    def test_withdrawn_control(self, bfb: Any) -> None:
        baselines = copy.deepcopy(SYNTHETIC_BASELINES)
        baselines["high"] = [*baselines["high"], "SC-13(1)"]
        counts = {**SYNTHETIC_COUNTS, "high": len(baselines["high"])}
        with pytest.raises(RuntimeError, match="withdrawn"):
            bfb.assert_invariants(baselines, SYNTHETIC_METHODS, expected_counts=counts)

    def test_broken_nesting(self, bfb: Any) -> None:
        """Dropping a low-only control from moderate breaks low < moderate."""
        baselines = copy.deepcopy(SYNTHETIC_BASELINES)
        baselines["moderate"] = ["AC-1"]
        counts = {**SYNTHETIC_COUNTS, "moderate": 1}
        with pytest.raises(RuntimeError, match="subset"):
            bfb.assert_invariants(baselines, SYNTHETIC_METHODS, expected_counts=counts)

    def test_method_key_outside_li_saas(self, bfb: Any) -> None:
        methods = {**SYNTHETIC_METHODS, "AC-99": ["ATTEST"]}
        with pytest.raises(RuntimeError, match="outside LI-SaaS"):
            bfb.assert_invariants(SYNTHETIC_BASELINES, methods, expected_counts=SYNTHETIC_COUNTS)


# ── methods_note ─────────────────────────────────────────────────────


def test_methods_note_wording_on_synthetic_data(bfb: Any) -> None:
    assert bfb.methods_note(SYNTHETIC_BASELINES, SYNTHETIC_METHODS) == SYNTHETIC_NOTE


# ── build_document ───────────────────────────────────────────────────


def test_build_document_key_order(bfb: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bfb, "EXPECTED_COUNTS", SYNTHETIC_COUNTS)
    profiles = {key: json.dumps(profile).encode("utf-8") for key, profile in SYNTHETIC_PROFILES.items()}

    doc = bfb.build_document(profiles, retrieved="2026-01-01", reverified="2026-01-02")

    assert list(doc) == ["_comment", "provenance", "notes", "baselines", "li_saas_methods"]
    assert list(doc["provenance"]) == [
        "source_name",
        "source_url",
        "republisher",
        "published",
        "retrieved",
        "reverified",
        "validation",
        "builder",
        "files",
        "shelf_life",
    ]
    assert list(doc["notes"]) == ["pm_pt_excluded", "li_saas", "withdrawn", "li_saas_methods"]
    assert doc["baselines"] == SYNTHETIC_BASELINES
    assert doc["li_saas_methods"] == SYNTHETIC_METHODS
    assert doc["provenance"]["retrieved"] == "2026-01-01"
    assert doc["provenance"]["reverified"] == "2026-01-02"
    assert doc["notes"]["li_saas_methods"] == SYNTHETIC_NOTE


# ── main, end to end over a temp dir ────────────────────────────────


def _write_synthetic_profiles(directory: Path, bfb: Any) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for key, filename in bfb.PROFILE_FILES.items():
        (directory / filename).write_bytes(json.dumps(SYNTHETIC_PROFILES[key]).encode("utf-8"))


def test_main_end_to_end(bfb: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(bfb, "EXPECTED_COUNTS", SYNTHETIC_COUNTS)
    profiles_dir = tmp_path / "profiles"
    _write_synthetic_profiles(profiles_dir, bfb)
    out_path = tmp_path / "vendored.json"

    # First build: --out does not exist yet, so there is no pin to check.
    assert bfb.main(["--from-dir", str(profiles_dir), "--out", str(out_path), "--retrieved", "2026-01-01"]) == 0
    assert out_path.exists()

    # --check against an unchanged derivation: OK.
    assert bfb.main(["--from-dir", str(profiles_dir), "--out", str(out_path), "--check"]) == 0

    # Tamper the output directly: --check must catch it.
    tampered = json.loads(out_path.read_text(encoding="utf-8"))
    tampered["baselines"]["low"].pop(0)
    out_path.write_text(json.dumps(tampered, indent=2) + "\n", encoding="utf-8")
    assert bfb.main(["--from-dir", str(profiles_dir), "--out", str(out_path), "--check"]) == 1

    # A plain build (profiles unchanged, so the pin check still passes)
    # overwrites the tampered file with a fresh, correct one. Byte-identical
    # profiles keep the original retrieval date; the re-derivation date is
    # the one given.
    assert bfb.main(["--from-dir", str(profiles_dir), "--out", str(out_path), "--reverified", "2026-02-01"]) == 0
    assert bfb.main(["--from-dir", str(profiles_dir), "--out", str(out_path), "--check"]) == 0
    rebuilt = json.loads(out_path.read_text(encoding="utf-8"))
    assert rebuilt["provenance"]["retrieved"] == "2026-01-01"
    assert rebuilt["provenance"]["reverified"] == "2026-02-01"

    # Change one byte's worth of a source profile: sha256 no longer matches
    # the pin recorded in --out, so a plain build refuses.
    low_path = profiles_dir / bfb.PROFILE_FILES["low"]
    changed = json.loads(low_path.read_text(encoding="utf-8"))
    changed["profile"]["metadata"]["published"] = "2024-01-02T00:00:00Z"
    low_path.write_text(json.dumps(changed), encoding="utf-8")

    assert bfb.main(["--from-dir", str(profiles_dir), "--out", str(out_path)]) == 2
    # A refused build must not touch --out: it still holds the fresh,
    # correct build from before the profile changed.
    assert json.loads(out_path.read_text(encoding="utf-8"))["baselines"] == SYNTHETIC_BASELINES

    # ... and succeeds once the change is acknowledged, with the retrieval
    # date reset because these profile bytes are new.
    assert (
        bfb.main(
            [
                "--from-dir",
                str(profiles_dir),
                "--out",
                str(out_path),
                "--allow-upstream-change",
                "--reverified",
                "2026-03-01",
            ]
        )
        == 0
    )
    accepted = json.loads(out_path.read_text(encoding="utf-8"))
    assert accepted["provenance"]["retrieved"] != "2026-01-01"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", accepted["provenance"]["retrieved"])
    assert accepted["provenance"]["reverified"] == "2026-03-01"


# ── the real vendored file, no network ──────────────────────────────


def test_real_vendored_file_satisfies_invariants(bfb: Any) -> None:
    doc = json.loads(VENDORED_PATH.read_text(encoding="utf-8"))
    bfb.assert_invariants(doc["baselines"], doc["li_saas_methods"], expected_counts=bfb.EXPECTED_COUNTS)
    assert bfb.methods_note(doc["baselines"], doc["li_saas_methods"]) == doc["notes"]["li_saas_methods"]
