"""Tests for the v0.10.2 MCP tool surface expansion.

4 new tools added per docs/v0.10.2-plan.md §2:

- ``gap_analyze_sarif`` — gap analysis + SARIF 2.1.0 output
- ``collect_ocsf`` — OCSF file ingestion (file mode only)
- ``tprm_vendor_list`` — list vendors from local store
- ``poam_list`` — list POA&Ms from local store

All read-only. Tests exercise the tool functions directly via the
``_register_tools`` machinery, mirroring the v0.9.6 conmon tool test
pattern.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("py_ocsf_models")

from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.models.common import Severity
from evidentia_core.models.finding import ComplianceStatus
from evidentia_mcp.server import build_server
from mcp.server.fastmcp import FastMCP

FIXTURES_GAP = Path(__file__).resolve().parents[2] / "fixtures"
FIXTURES_OCSF = Path(__file__).resolve().parents[2] / "fixtures" / "ocsf"


@pytest.fixture()
def server() -> FastMCP:
    """Reset the framework registry singleton + return a fresh server."""
    FrameworkRegistry.reset_instance()
    s = build_server()
    yield s
    FrameworkRegistry.reset_instance()


def _tool_fn(server: FastMCP, name: str):
    """Pull the underlying Python function out of a FastMCP tool."""
    tools = server._tool_manager._tools  # type: ignore[attr-defined]
    assert name in tools, f"{name} not registered; have: {sorted(tools)}"
    return tools[name].fn


# ── gap_analyze_sarif ─────────────────────────────────────────────────


def test_gap_analyze_sarif_returns_sarif_2_1_0(server: FastMCP) -> None:
    """The new tool returns a SARIF 2.1.0 log dict, not a GapAnalysisReport."""
    fn = _tool_fn(server, "gap_analyze_sarif")
    sarif = fn(
        inventory_path=str(FIXTURES_GAP / "sample-inventory.yaml"),
        frameworks=["nist-800-53-mod"],
    )
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Evidentia"
    # Results carry the SARIF-required level + ruleId fields.
    for result in sarif["runs"][0]["results"]:
        assert result["ruleId"]
        assert result["level"] in {"error", "warning", "note", "none"}


def test_gap_analyze_sarif_missing_inventory_raises(server: FastMCP) -> None:
    fn = _tool_fn(server, "gap_analyze_sarif")
    with pytest.raises(FileNotFoundError):
        fn(inventory_path="/no/such/file.yaml", frameworks=["nist-800-53-mod"])


# ── collect_ocsf ──────────────────────────────────────────────────────


def test_collect_ocsf_ingests_prowler_detection_finding(server: FastMCP) -> None:
    fn = _tool_fn(server, "collect_ocsf")
    findings = fn(input_path=str(FIXTURES_OCSF / "prowler-detection-finding.json"))
    assert len(findings) == 1
    f = findings[0]
    assert f["title"] == "S3 Bucket Public Read"
    assert f["severity"] == Severity.HIGH.value
    # Detection Finding severity HIGH -> FAIL per v0.10.1 heuristic.
    assert f["compliance_status"] == ComplianceStatus.FAIL.value


def test_collect_ocsf_ingests_mixed_batch(server: FastMCP) -> None:
    fn = _tool_fn(server, "collect_ocsf")
    findings = fn(input_path=str(FIXTURES_OCSF / "mixed-batch.json"))
    assert len(findings) == 2
    # First is Compliance Finding (FAIL), second is Detection Finding (WARNING).
    assert findings[0]["compliance_status"] == "fail"
    assert findings[1]["compliance_status"] == "warning"


def test_collect_ocsf_missing_file_raises(server: FastMCP) -> None:
    fn = _tool_fn(server, "collect_ocsf")
    with pytest.raises(FileNotFoundError):
        fn(input_path="/no/such/file.json")


def test_collect_ocsf_invalid_json_raises(server: FastMCP, tmp_path: Path) -> None:
    bad = tmp_path / "broken.json"
    bad.write_text("not valid json", encoding="utf-8")
    fn = _tool_fn(server, "collect_ocsf")
    with pytest.raises(RuntimeError):  # OCSFIngestError is a RuntimeError
        fn(input_path=str(bad))


# ── tprm_vendor_list ──────────────────────────────────────────────────


def test_tprm_vendor_list_empty_store(
    server: FastMCP, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the vendor store is empty, returns an empty list (no error)."""
    monkeypatch.setenv("EVIDENTIA_VENDOR_STORE_DIR", str(tmp_path / "vendors"))
    fn = _tool_fn(server, "tprm_vendor_list")
    assert fn() == []


def test_tprm_vendor_list_returns_stored_vendors(
    server: FastMCP, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vendors written to the store come back as JSON-serializable dicts."""
    from evidentia_core.models.tprm import CriticalityTier, Vendor, VendorType
    from evidentia_core.vendor_store import save_vendor

    monkeypatch.setenv("EVIDENTIA_VENDOR_STORE_DIR", str(tmp_path / "vendors"))
    import datetime as _dt

    v = Vendor(
        name="Synthetic Vendor",
        type=VendorType.SAAS,
        criticality_tier=CriticalityTier.HIGH,
        relationship_owner="owner@example.com",
        contract_start_date=_dt.date(2026, 1, 1),
    )
    save_vendor(v)
    fn = _tool_fn(server, "tprm_vendor_list")
    vendors = fn()
    assert len(vendors) == 1
    assert vendors[0]["name"] == "Synthetic Vendor"
    assert vendors[0]["criticality_tier"] == "high"


# ── poam_list ─────────────────────────────────────────────────────────


def test_poam_list_empty_store(
    server: FastMCP, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the POA&M store is empty, returns an empty list (no error)."""
    monkeypatch.setenv("EVIDENTIA_POAM_STORE_DIR", str(tmp_path / "poams"))
    fn = _tool_fn(server, "poam_list")
    assert fn() == []


def test_poam_list_returns_stored_poams(
    server: FastMCP, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidentia_core.models.gap import (
        ControlGap,
        GapSeverity,
        ImplementationEffort,
    )
    from evidentia_core.poam_store import save_poam

    monkeypatch.setenv("EVIDENTIA_POAM_STORE_DIR", str(tmp_path / "poams"))
    g = ControlGap(
        framework="nist-800-53-rev5",
        control_id="AC-2",
        control_title="Account Management",
        control_description="d",
        gap_severity=GapSeverity.HIGH,
        implementation_status="missing",
        gap_description="g",
        remediation_guidance="r",
        implementation_effort=ImplementationEffort.MEDIUM,
    )
    save_poam(g)
    fn = _tool_fn(server, "poam_list")
    poams = fn()
    assert len(poams) == 1
    assert poams[0]["control_id"] == "AC-2"
    assert poams[0]["gap_severity"] == "high"


# ── all 4 tools registered (api-stability NORMATIVE check) ─────────────


def test_all_v0_10_2_tools_registered(server: FastMCP) -> None:
    """api-stability.md §MCP tool contract lists these 4 as v0.10.2."""
    tools = server._tool_manager._tools  # type: ignore[attr-defined]
    for name in (
        "gap_analyze_sarif",
        "collect_ocsf",
        "tprm_vendor_list",
        "poam_list",
    ):
        assert name in tools, f"{name} missing from MCP tool registry"
