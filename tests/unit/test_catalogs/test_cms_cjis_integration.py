"""Catalog integration preserves historical references and keeps evidence uncounted."""

from __future__ import annotations

import hashlib
import json
import runpy
from datetime import date
from pathlib import Path

import pytest
from evidentia_core.catalogs.loader import load_evidentia_catalog
from evidentia_core.catalogs.manifest import load_manifest
from evidentia_core.catalogs.registry import FrameworkRegistry

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts/catalogs"
DATA = ROOT / "packages/evidentia-core/src/evidentia_core/catalogs/data"


@pytest.mark.parametrize(
    ("framework", "successor", "edition", "count", "payload_hash"),
    [
        (
            "cms-ars-5.1",
            "cms-ars-5.2",
            "5.1 (2023-07-26)",
            19,
            "624c9f1685f48811e343ebccc211e87400408812ece12640de7a45d85ed1502e",
        ),
        (
            "cjis-v6",
            "cjis-v6.1",
            "6.0 (2024-12-27)",
            24,
            "4311b04bb6d05eb35ef538e47d095242f340e4d9437d3ba681430f832e815330",
        ),
    ],
)
def test_historical_payloads_and_notices(
    framework: str, successor: str, edition: str, count: int, payload_hash: str
) -> None:
    path = DATA / "us-federal" / f"{framework}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    retained = {key: data[key] for key in ("families", "controls")}
    encoded = json.dumps(retained, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == payload_hash
    catalog = load_evidentia_catalog(path)
    assert catalog.control_count == count
    assert catalog.text_depth == "headings"
    assert catalog.version == edition
    assert catalog.status == "historical"
    assert catalog.superseded_by == successor
    assert catalog.verified_on == date(2026, 9, 9)
    assert catalog.notes and "automatically" in catalog.notes
    manifest = load_manifest().get(framework)
    assert manifest is not None
    assert manifest.status == catalog.status
    assert manifest.version == catalog.version
    assert manifest.superseded_by == successor
    assert manifest.notes == catalog.notes


@pytest.mark.parametrize(
    ("framework", "units", "source_rows"),
    [("cms-ars-5.2", 605, 1681), ("cjis-v6.1", 324, 1533)],
)
def test_current_catalogs_are_discoverable_without_counting_source_rows(
    framework: str, units: int, source_rows: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EVIDENTIA_CATALOG_DIR", str(tmp_path / "user"))
    catalog = FrameworkRegistry(data_dir=DATA).get_catalog(framework)
    assert catalog.control_count == units
    assert len(catalog.statement_rows()) == units
    assert sum(len(control.source_rows) for control in catalog.controls) == source_rows
    assert catalog.status == "current"
    manifest = load_manifest().get(framework)
    assert manifest is not None
    assert manifest.status == catalog.status
    assert manifest.text_depth == catalog.text_depth
    assert manifest.source_url == catalog.source
    assert manifest.license == catalog.license_terms
    assert manifest.crosswalk_family is None
    if framework == "cjis-v6.1":
        assert set(catalog.audit_contexts) == {"US-TX"}
        context = catalog.audit_contexts["US-TX"]
        assert context.version == "5.9.5"
        assert context.valid_through == date(2027, 3, 31)


def test_integrated_generator_is_isolated_and_preserves_other_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(SCRIPTS))
    import _generators

    before = {path: path.read_bytes() for path in DATA.rglob("*.json")}
    output = tmp_path / "generated"
    monkeypatch.setattr(_generators, "DATA_ROOT", output)
    runpy.run_path(str(SCRIPTS / "gen_us_regulatory.py"), run_name="__main__")
    generated = {path.relative_to(output).as_posix(): path.read_bytes() for path in output.rglob("*.json")}
    assert {
        "us-federal/cms-ars-5.1.json",
        "us-federal/cms-ars-5.2.json",
        "us-federal/cjis-v6.json",
        "us-federal/cjis-v6.1.json",
    } <= set(generated)
    for relative, content in generated.items():
        assert b"\r\n" not in content
        assert content == (DATA / relative).read_bytes().replace(b"\r\n", b"\n")
    assert {path: path.read_bytes() for path in DATA.rglob("*.json")} == before
