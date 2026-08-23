"""Regression tests for the bundled FedRAMP Rev 5 baseline catalogs.

Through v0.12.0 all four baselines shipped with WRONG control membership. The
generator derived Low and LI-SaaS as a truncation of Moderate
(``[c for c in FEDRAMP_MODERATE if "(" not in c][:125]`` and ``[:150]``), and
because the source list is family-ordered that silently dropped every family
from PS onward. The shipped Low baseline was missing PS, RA, SA, SC, SI and SR
in their entirety, 69 controls including ``RA-5``, ``SC-7`` and ``SI-2``, while
carrying 33 PM-family controls that SP 800-53B allocates to no baseline.

The control TEXT was correct throughout, which is why the defect was invisible
to a reader and survived many releases: nothing asserted membership.

These tests are the assertion. Each one corresponds to a defect actually
shipped, so none of them is hypothetical.

Authoritative membership: the FedRAMP PMO OSCAL profiles, vendored at
``scripts/catalogs/upstream/fedramp-rev5-baselines.json`` with provenance.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = (
    REPO_ROOT / "packages" / "evidentia-core" / "src" / "evidentia_core"
    / "catalogs" / "data" / "us-federal"
)
UPSTREAM = REPO_ROOT / "scripts" / "catalogs" / "upstream" / "fedramp-rev5-baselines.json"

BASELINES = {
    "low": "fedramp-rev5-low.json",
    "moderate": "fedramp-rev5-moderate.json",
    "high": "fedramp-rev5-high.json",
    "li-saas": "fedramp-rev5-li-saas.json",
}

# Published FedRAMP Rev 5 counts, from the PMO's own OSCAL profiles.
EXPECTED_COUNTS = {"low": 156, "moderate": 323, "high": 410, "li-saas": 156}

# Withdrawn in NIST SP 800-53 Rev 5. These cannot resolve against the Rev 5
# catalog, so a baseline claiming one is broken by construction.
WITHDRAWN = {"CM-8(5)", "CP-2(4)", "SA-12", "SC-13(1)"}


def _ids(name: str) -> list[str]:
    data = json.loads((DATA_DIR / BASELINES[name]).read_text(encoding="utf-8"))
    return [c["id"] for c in data["controls"]]


@pytest.fixture(scope="module")
def vendored() -> dict:
    return json.loads(UPSTREAM.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", sorted(BASELINES))
def test_matches_vendored_source_exactly(name: str, vendored: dict) -> None:
    """The shipped catalog is the vendored membership, in order, with nothing added."""
    assert _ids(name) == vendored["baselines"][name]


@pytest.mark.parametrize("name", sorted(BASELINES))
def test_control_count(name: str) -> None:
    assert len(_ids(name)) == EXPECTED_COUNTS[name]


@pytest.mark.parametrize("name", sorted(BASELINES))
def test_no_duplicate_controls(name: str) -> None:
    """High shipped AC-4(21), AC-6(7) and MA-3(3) twice: the delta list re-added
    controls already present in Moderate."""
    ids = _ids(name)
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"{name} has duplicate control ids: {dupes}"


@pytest.mark.parametrize("name", sorted(BASELINES))
def test_no_pm_or_pt_controls(name: str) -> None:
    """SP 800-53B Table 3-13 (PM) and Table 3-15 (PT): neither family is
    allocated to the security control baselines."""
    ids = _ids(name)
    assert not [i for i in ids if i.startswith("PM-")], f"{name} contains PM controls"
    assert not [i for i in ids if i.startswith("PT-")], f"{name} contains PT controls"


@pytest.mark.parametrize("name", sorted(BASELINES))
def test_no_withdrawn_controls(name: str) -> None:
    present = sorted(set(_ids(name)) & WITHDRAWN)
    assert not present, f"{name} claims controls withdrawn in Rev 5: {present}"


def test_low_contains_the_controls_the_truncation_dropped() -> None:
    """The three named in the original bug report, and one from each family that
    the truncation removed wholesale."""
    low = set(_ids("low"))
    for cid in ("RA-5", "SC-7", "SI-2", "PS-1", "SA-4", "SR-2"):
        assert cid in low, f"FedRAMP Low must contain {cid}"


def test_low_covers_every_expected_family() -> None:
    """Low lost six entire families (PS, RA, SA, SC, SI, SR) to the truncation."""
    families = {i.split("-")[0] for i in _ids("low")}
    for fam in ("PS", "RA", "SA", "SC", "SI", "SR"):
        assert fam in families, f"FedRAMP Low is missing the {fam} family entirely"


def test_baselines_nest_strictly() -> None:
    """Low equals LI-SaaS as a set, Low is inside Moderate, Moderate inside High,
    and the union is exactly High. Cheap invariants that catch any regeneration
    that goes wrong in a new way."""
    low, mod = set(_ids("low")), set(_ids("moderate"))
    high, li = set(_ids("high")), set(_ids("li-saas"))
    assert low == li, "LI-SaaS selects the same control set as Low"
    assert low < mod, "Low must be a strict subset of Moderate"
    assert mod < high, "Moderate must be a strict subset of High"
    assert low | mod | high | li == high, "the union of all baselines must equal High"


def test_no_pointer_placeholder_text_survives() -> None:
    """Every control carries real NIST text. A surviving pointer means
    rewrite_fedramp_pointers.py did not resolve it, which is now a hard failure
    in that script but is also worth asserting on the shipped artifact."""
    for name, fname in BASELINES.items():
        data = json.loads((DATA_DIR / fname).read_text(encoding="utf-8"))
        unresolved = [
            c["id"] for c in data["controls"]
            if "See nist-800-53-rev5 catalog" in c.get("description", "")
        ]
        assert not unresolved, f"{name} still has pointer placeholders: {unresolved[:10]}"


def test_vendored_provenance_is_recorded(vendored: dict) -> None:
    """The membership must stay traceable to a named source with a retrieval
    date. GSA/fedramp-automation was deleted, so the provenance block is the
    only record of where this data legitimately came from."""
    prov = vendored["provenance"]
    assert prov["source_url"].startswith("https://")
    assert prov["published"] and prov["retrieved"]
    for key in ("low", "moderate", "high", "li-saas"):
        assert len(prov["files"][key]["sha256"]) == 64
