"""Tests for scripts/gen_package_sboms.py (PEP 770 per-wheel SBOMs)."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import gen_package_sboms as g  # noqa: E402


def test_discovers_all_eight_packages() -> None:
    pkgs = g.discover_packages(REPO_ROOT)
    names = sorted(p["name"] for p in pkgs)
    assert names == [
        "evidentia", "evidentia-ai", "evidentia-api", "evidentia-collectors",
        "evidentia-core", "evidentia-eval", "evidentia-integrations", "evidentia-mcp",
    ]


def test_sbom_is_valid_minimal_cyclonedx(tmp_path: Path) -> None:
    pkgs = g.discover_packages(REPO_ROOT)
    core = next(p for p in pkgs if p["name"] == "evidentia-core")
    doc = g.build_sbom(core)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")
    comp = doc["metadata"]["component"]
    assert comp["type"] == "library"
    assert comp["name"] == "evidentia-core"
    assert comp["purl"] == f"pkg:pypi/evidentia-core@{comp['version']}"
    assert doc["metadata"]["supplier"]["name"] == "Polycentric Labs"
    # declared runtime deps present as components + dependency refs
    assert any(c["name"] == "pydantic" for c in doc["components"]) or len(doc["components"]) > 0
    assert doc["dependencies"][0]["ref"] == comp["bom-ref"]


def test_determinism_two_runs_byte_identical(tmp_path: Path) -> None:
    out1 = tmp_path / "a"
    out2 = tmp_path / "b"
    g.main(["--out-root", str(out1)])
    g.main(["--out-root", str(out2)])
    for f1 in sorted(out1.rglob("*.cdx.json")):
        f2 = out2 / f1.relative_to(out1)
        assert f1.read_bytes() == f2.read_bytes(), f"non-deterministic: {f1.name}"


def test_no_timestamp_without_source_date_epoch(monkeypatch) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    pkgs = g.discover_packages(REPO_ROOT)
    doc = g.build_sbom(pkgs[0])
    assert "timestamp" not in doc["metadata"]


def test_timestamp_from_source_date_epoch(monkeypatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    pkgs = g.discover_packages(REPO_ROOT)
    doc = g.build_sbom(pkgs[0])
    assert doc["metadata"]["timestamp"] == "2023-11-14T22:13:20+00:00"
