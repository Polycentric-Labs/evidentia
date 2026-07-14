"""Tests for scripts/enrich_release_sbom.py + scripts/check_sbom_ntia.py (H4/#17)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_sbom_ntia as ntia  # noqa: E402
import enrich_release_sbom as enrich  # noqa: E402


def _bare_environment_sbom() -> dict:
    """Shape cyclonedx-py environment actually emits (v0.10.17 observed):
    no metadata.supplier, first-party components without purl."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": "2026-07-09T20:35:10+00:00",
            "tools": [],
            "component": {
                "bom-ref": "root-component",
                "type": "application",
                "name": "evidentia-core",
                "version": "0.10.17",
            },
        },
        "components": [
            {
                "bom-ref": "evidentia==0.10.17",
                "type": "library",
                "name": "evidentia",
                "version": "0.10.17",
            },
            {
                "bom-ref": "Jinja2==3.1.6",
                "type": "library",
                "name": "Jinja2",
                "version": "3.1.6",
                "purl": "pkg:pypi/jinja2@3.1.6",
            },
        ],
        "dependencies": [{"ref": "root-component"}],
    }


def test_enrich_fills_first_party_identity() -> None:
    doc = _bare_environment_sbom()
    report = enrich.enrich(doc)
    assert doc["metadata"]["supplier"]["name"] == "Polycentric Labs"
    assert doc["metadata"]["authors"] == [{"name": "Polycentric Labs"}]
    root = doc["metadata"]["component"]
    assert root["purl"] == "pkg:pypi/evidentia-core@0.10.17"
    assert root["supplier"]["name"] == "Polycentric Labs"
    fp = doc["components"][0]
    assert fp["purl"] == "pkg:pypi/evidentia@0.10.17"
    assert fp["supplier"]["name"] == "Polycentric Labs"
    assert any(r["type"] == "vcs" for r in fp["externalReferences"])
    # Third-party untouched.
    assert "supplier" not in doc["components"][1]
    assert "(document)" in report


def test_enrich_is_idempotent() -> None:
    doc = _bare_environment_sbom()
    enrich.enrich(doc)
    first = json.dumps(doc, sort_keys=True)
    report_second = enrich.enrich(doc)
    assert json.dumps(doc, sort_keys=True) == first
    assert report_second == {}


def test_enrich_never_overwrites_existing_values() -> None:
    doc = _bare_environment_sbom()
    doc["components"][0]["supplier"] = {"name": "Someone Else"}
    doc["components"][0]["purl"] = "pkg:pypi/evidentia@0.0.0"
    enrich.enrich(doc)
    assert doc["components"][0]["supplier"] == {"name": "Someone Else"}
    assert doc["components"][0]["purl"] == "pkg:pypi/evidentia@0.0.0"


def test_ntia_gate_fails_bare_sbom_and_passes_enriched() -> None:
    doc = _bare_environment_sbom()
    failures, _ = ntia.check(doc)
    # Bare environment SBOM must FAIL: no supplier, first-party purls missing.
    assert any("metadata.supplier" in f for f in failures)
    assert any("purl" in f for f in failures)
    enrich.enrich(doc)
    failures, advisories = ntia.check(doc)
    assert failures == []
    # Jinja2 has no supplier -> advisory, never a failure.
    assert advisories and "third-party" in advisories[0]


def test_ntia_gate_hard_fails() -> None:
    doc = _bare_environment_sbom()
    enrich.enrich(doc)
    del doc["metadata"]["timestamp"]
    doc["components"][1].pop("version")
    doc["dependencies"] = []
    failures, _ = ntia.check(doc)
    assert any("timestamp" in f for f in failures)
    assert any("version missing" in f for f in failures)
    assert any("dependencies" in f for f in failures)


def test_cli_roundtrip(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text(json.dumps(_bare_environment_sbom()), encoding="utf-8")
    assert ntia.main([str(sbom)]) == 1  # bare -> gate red
    assert enrich.main([str(sbom)]) == 0
    assert ntia.main([str(sbom)]) == 0  # enriched -> gate green
    # Enriched file is valid JSON with sorted keys (deterministic).
    text = sbom.read_text(encoding="utf-8")
    assert json.loads(text)["metadata"]["supplier"]["name"] == "Polycentric Labs"


def test_non_cyclonedx_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8")
    assert enrich.main([str(bad)]) == 1
    assert ntia.main([str(bad)]) == 1
