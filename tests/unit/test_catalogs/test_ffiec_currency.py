"""Pin public FFIEC heading fidelity and preserve historical assessment references."""

from __future__ import annotations

import hashlib
import importlib
import json
import runpy
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from evidentia_core.catalogs.loader import load_evidentia_catalog

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts/catalogs"
DATA = ROOT / "packages/evidentia-core/src/evidentia_core/catalogs/data/us-federal"
SOURCE = SCRIPTS / "sources/ffiec-current-headings.json"
CURRENT_SCRIPT = SCRIPTS / "gen_ffiec_current.py"
VERIFIED_ON = date(2026, 9, 9)
SUNSET_SOURCE = (
    "https://www.ffiec.gov/sites/default/files/media/press-releases/2024/cat-sunset-statement-ffiec-letterhead.pdf"
)
AIO_RELEASE = "https://www.ffiec.gov/news/press-releases/2021/pr-06-30"

# These hashes pin every ordered ID, literal title, family, source URL, and ID
# origin to the reviewed HTML snapshot, independently of the generator input.
EXPECTED = {
    "ffiec-aio": ("June 2021", 104, "7504dc0fedf71a10a79f2f5b81f414a53b7e3f4b702dab386ec56b6201f0c872"),
    "ffiec-business-continuity-management": (
        "November 2019",
        54,
        "724bce37225652aeea3de9ec6430fcf293c5592419fc95beb2024ff5b8590c25",
    ),
    "ffiec-development-acquisition-maintenance": (
        "August 2024",
        109,
        "b14b87d973d70b1fdb65bb38b875a39a57e7ae2d8260d198981e954ec7b5d76b",
    ),
    "ffiec-retail-payment-systems": (
        "April 2016",
        43,
        "5d4fababcb35f74f8898bb027a3cb9ba624c380fd6d68726d3f0cee5b56aa205",
    ),
    "ffiec-supervision-technology-service-providers": (
        "October 2012",
        26,
        "251741f39eaa15b27e5b4a44619d6d18ceda4a906330d57d4a956c0caaa98993",
    ),
    "ffiec-wholesale-payment-systems": (
        "July 2004",
        37,
        "5f252b06cdd79911bc04c23d3c42505e8e7a56ff611b0add00966ebe673095fa",
    ),
}
LEGACY_UNCHANGED = {
    "ffiec-audit": "34471de230e697fbed6d7e8438373646deb42e69c5efafd5becdd39ca7a1fd4c",
    "ffiec-information-security": "34ed904bd4090b7f4267b58eadc587725e0208cd46b9119b6bd909a701302136",
    "ffiec-management": "225c47ecbf02c7ebfdbce54ee1134f65d2f6a396e580a7021d02ad64b24fc198",
    "ffiec-outsourcing": "3b71d0513a45ab8f18e55037d2a02845fa2f5e71d40393eb78a1003393f317c9",
}
HISTORICAL = {
    "ffiec-operations": (27, "07aba8aaf5a83e09600cc936bb3c847e808c4863396d50fdf4de5dff70f4209b"),
    "ffiec-cat": (33, "2b0c6410f476c2aca13fff3f5dc99597946dbf020f839e6925a8b96e31f6e32e"),
}


def _digest(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _lf(path: Path) -> bytes:
    """Normalize checkout CRLF only; all other bytes remain significant."""
    return path.read_bytes().replace(b"\r\n", b"\n")


@pytest.mark.parametrize("framework_id", EXPECTED)
def test_current_booklet_matches_reviewed_source(framework_id: str) -> None:
    version, count, fingerprint = EXPECTED[framework_id]
    catalog = load_evidentia_catalog(DATA / f"{framework_id}.json")
    assert catalog.framework_id == framework_id
    assert catalog.version == version
    assert catalog.control_count == len(catalog.controls) == count
    assert catalog.status == "current"
    assert catalog.verified_on == VERIFIED_ON
    assert catalog.superseded_by is None
    assert catalog.tier == "A"
    assert catalog.text_depth == "headings"
    assert catalog.placeholder is False
    assert catalog.license_required is False
    assert catalog.publication_notices == []
    assert catalog.notes and "headings" in catalog.notes and "assessment coverage" in catalog.notes
    rows = [[c.id, c.title, c.family, c.properties["source_url"], c.properties["id_origin"]] for c in catalog.controls]
    assert _digest(rows) == fingerprint
    assert len({c.id for c in catalog.controls}) == count
    assert catalog.families == list(dict.fromkeys(c.family for c in catalog.controls))
    for control in catalog.controls:
        assert control.description == ""
        assert not control.placeholder and not control.withdrawn
        assert not control.guidance and not control.objective and not control.examples
        assert control.title != "Introduction" and not control.title.startswith("Appendix ")
        assert "examination-procedures" not in control.properties["source_url"]
        assert control.properties["source_url"].startswith(catalog.source)
        if control.properties["id_origin"] == "local":
            assert control.id.startswith("local.")
        else:
            assert control.properties["id_origin"] == "published_heading_locator"
            assert control.title.startswith(control.id + " ")


def test_compact_input_contains_only_reviewed_body_headings() -> None:
    source = _read(SOURCE)
    assert source["verified_on"] == "2026-09-09"
    assert {b["id"] for b in source["booklets"]} == set(EXPECTED)
    assert len(source["booklets"]) == 6
    for booklet in source["booklets"]:
        version, count, fingerprint = EXPECTED[booklet["id"]]
        assert booklet["version"] == version
        assert len(booklet["rows"]) == count
        rows = [
            [id_, title, family, booklet["source_url"] + relative, booklet["id_origin"]]
            for id_, title, family, relative in booklet["rows"]
        ]
        assert _digest(rows) == fingerprint
        assert len({row[0] for row in rows}) == count
        assert all(row[1] != "Introduction" and not row[1].startswith("Appendix ") for row in rows)
        assert "e-banking" not in booklet["id"]
        if booklet["id"] == "ffiec-supervision-technology-service-providers":
            assert ".pdf" not in json.dumps(booklet).lower()
            assert booklet["edition_source"] == booklet["source_url"]


@pytest.mark.parametrize("framework_id", HISTORICAL)
def test_historical_assessment_payload_is_preserved(framework_id: str) -> None:
    count, fingerprint = HISTORICAL[framework_id]
    data = _read(DATA / f"{framework_id}.json")
    assert len(data["controls"]) == count
    preserved = {
        k: v for k, v in data.items() if k not in {"source", "status", "notes", "verified_on", "superseded_by"}
    }
    assert _digest(preserved) == fingerprint
    catalog = load_evidentia_catalog(DATA / f"{framework_id}.json")
    assert catalog.control_count == count
    assert not any(c.withdrawn for c in catalog.controls)


def test_operations_is_superseded_without_replacing_its_controls() -> None:
    catalog = load_evidentia_catalog(DATA / "ffiec-operations.json")
    assert catalog.status == "superseded"
    assert catalog.superseded_by == "ffiec-aio"
    assert catalog.verified_on == VERIFIED_ON
    assert catalog.source == AIO_RELEASE
    assert catalog.version == "July 2004"
    assert catalog.notes and "2021-06-30" in catalog.notes and "historical" in catalog.notes


def test_cat_retirement_has_alternatives_without_a_claimed_successor() -> None:
    catalog = load_evidentia_catalog(DATA / "ffiec-cat.json")
    assert catalog.status == "retired"
    assert catalog.superseded_by is None
    assert catalog.verified_on == VERIFIED_ON
    assert catalog.source == SUNSET_SOURCE
    assert catalog.version == "2017 (representative subset)"
    assert catalog.notes
    for phrase in ("2025-08-31", "NIST CSF 2.0", "CISA", "alternatives", "equivalence"):
        assert phrase in catalog.notes


def test_current_generator_is_import_safe_isolated_and_deterministic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(SCRIPTS))
    helper = importlib.import_module("_generators")
    first = tmp_path / "first"
    monkeypatch.setattr(helper, "DATA_ROOT", first)
    namespace = runpy.run_path(str(CURRENT_SCRIPT))
    assert not first.exists()
    namespace["main"]()
    emitted = {p.name: p.read_bytes() for p in (first / "us-federal").glob("*.json")}
    assert set(emitted) == {f"{id_}.json" for id_ in EXPECTED}
    for name, payload in emitted.items():
        assert b"\r" not in payload
        assert payload == _lf(DATA / name)
    second = tmp_path / "second"
    second.mkdir()
    sentinel = second / "unrelated.json"
    sentinel.write_bytes(b"do not modify")
    monkeypatch.setattr(helper, "DATA_ROOT", second)
    namespace["main"]()
    assert sentinel.read_bytes() == b"do not modify"
    assert {p.name: p.read_bytes() for p in (second / "us-federal").glob("*.json")} == emitted


def test_legacy_generator_includes_successors_and_preserves_other_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = {p: p.read_bytes() for p in DATA.glob("ffiec-*.json")}
    monkeypatch.syspath_prepend(str(SCRIPTS))
    helper = importlib.import_module("_generators")
    monkeypatch.setattr(helper, "DATA_ROOT", tmp_path)
    runpy.run_path(str(SCRIPTS / "gen_ffiec.py"), run_name="__main__")
    emitted = {p.stem: p for p in (tmp_path / "us-federal").glob("*.json")}
    assert set(emitted) == set(EXPECTED) | set(LEGACY_UNCHANGED) | set(HISTORICAL)
    for id_, fingerprint in LEGACY_UNCHANGED.items():
        assert hashlib.sha256(_lf(emitted[id_])).hexdigest() == fingerprint
        assert _lf(emitted[id_]) == _lf(DATA / f"{id_}.json")
    for id_ in EXPECTED.keys() | HISTORICAL.keys():
        assert _lf(emitted[id_]) == _lf(DATA / f"{id_}.json")
    assert {p: p.read_bytes() for p in before} == before
