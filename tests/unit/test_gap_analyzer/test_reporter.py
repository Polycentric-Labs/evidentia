"""Tests for the gap-analysis report export_report dispatcher (v0.11).

Focuses on the key-sign (DSSE) path added in v0.11. The GapAnalysisReport
construction follows the same inline factory pattern used across
test_sarif.py / test_ocsf_emit.py in this package.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    ImplementationEffort,
)


def _gap(control_id: str, severity: GapSeverity, **kw: Any) -> ControlGap:
    return ControlGap(
        framework="nist-800-53-rev5",
        control_id=control_id,
        control_title=f"{control_id} title",
        control_description=f"{control_id} description",
        gap_severity=severity,
        implementation_status="missing",
        gap_description=f"{control_id} is not implemented.",
        remediation_guidance=f"Implement {control_id}.",
        implementation_effort=ImplementationEffort.MEDIUM,
        **kw,
    )


def _report(gaps: list[ControlGap] | None = None) -> GapAnalysisReport:
    if gaps is None:
        gaps = [_gap("AC-2", GapSeverity.HIGH)]
    sev = [g.gap_severity for g in gaps]
    return GapAnalysisReport(
        organization="Acme",
        frameworks_analyzed=["nist-800-53-rev5"],
        total_controls_required=100,
        total_controls_in_inventory=80,
        total_gaps=len(gaps),
        critical_gaps=sum(1 for s in sev if s == GapSeverity.CRITICAL),
        high_gaps=sum(1 for s in sev if s == GapSeverity.HIGH),
        medium_gaps=sum(1 for s in sev if s == GapSeverity.MEDIUM),
        low_gaps=sum(1 for s in sev if s == GapSeverity.LOW),
        coverage_percentage=80.0,
        gaps=gaps,
        inventory_source="inventory.yaml",
    )


def test_export_report_key_sign_writes_dsse(tmp_path: Path) -> None:
    """export_report with key_sign_path= writes a .dsse.json sidecar."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from evidentia_core.gap_analyzer.reporter import export_report

    key = Ed25519PrivateKey.generate()
    priv = tmp_path / "k.key"
    priv.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    out = tmp_path / "ar.json"
    export_report(_report(), out, format="oscal-ar", key_sign_path=priv)
    assert (tmp_path / "ar.json.dsse.json").is_file()
