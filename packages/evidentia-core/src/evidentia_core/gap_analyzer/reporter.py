"""Gap analysis report output formatters.

Supports: JSON, CSV, Markdown, OSCAL Assessment Results, SARIF, OCSF
Compliance Finding, OCSF Detection Finding, CycloneDX VEX.

v0.7.0: the ``oscal-ar`` format optionally accepts a list of
:class:`SecurityFinding` objects (``findings=``) to embed as hashed
OSCAL resources, and a ``gpg_key_id`` to produce a detached ASCII-armored
signature alongside the JSON. See :mod:`evidentia_core.oscal.verify`
for the corresponding integrity checks.

v0.10.5 Phase 7: ``ocsf-detection`` emits OCSF Detection Finding
(``class_uid`` 2004) records — the SIEM-target counterpart to v0.10.4's
``ocsf`` (Compliance Finding 2003). Splunk / Elastic / Microsoft
Sentinel / Datadog ingest 2004 natively.

v0.10.5 Phase 8: ``cyclonedx-vex`` emits CycloneDX 1.6 VEX — the
supply-chain VEX surface complementing Evidentia's CycloneDX SBOM emit.
Federal supply-chain mandates (EO 14028, SEC 2026 supply-chain
enforcement) drive CycloneDX VEX adoption.
"""

from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from evidentia_core.models.gap import GapAnalysisReport

if TYPE_CHECKING:
    from evidentia_core.models.finding import SecurityFinding
    from evidentia_core.models.tprm import Vendor

OutputFormat = Literal[
    "json",
    "csv",
    "markdown",
    "oscal-ar",
    "sarif",
    "ocsf",
    "ocsf-detection",
    "cyclonedx-vex",
]


def export_report(
    report: GapAnalysisReport,
    output_path: str | Path,
    format: OutputFormat = "json",
    *,
    findings: list[SecurityFinding] | None = None,
    vendor_inventory: list[Vendor] | None = None,
    gpg_key_id: str | None = None,
    gnupghome: str | Path | None = None,
    sign_with_sigstore: bool = False,
    sigstore_bundle_path: str | Path | None = None,
    sigstore_identity_token: str | None = None,
    key_sign_path: str | Path | None = None,
) -> Path:
    """Export a gap analysis report in the specified format.

    Parameters
    ----------
    report:
        The gap analysis to export.
    output_path:
        Destination file path.
    format:
        One of ``json``, ``csv``, ``markdown``, ``oscal-ar``, ``sarif``,
        ``ocsf`` (OCSF Compliance Finding 2003, v0.10.4), ``ocsf-detection``
        (OCSF Detection Finding 2004, v0.10.5 — SIEM-target), or
        ``cyclonedx-vex`` (CycloneDX 1.6 VEX, v0.10.5 — supply-chain).
    findings:
        Optional :class:`SecurityFinding` list for the ``oscal-ar`` format.
        Each finding becomes a hashed OSCAL back-matter resource and is
        cross-referenced from observations that share a control ID.
        Ignored by non-OSCAL formats.
    gpg_key_id:
        Optional GPG key identifier. When supplied alongside ``format="oscal-ar"``,
        the AR JSON is signed with a detached ASCII-armored signature
        written to ``<output_path>.asc``. Ignored by non-OSCAL formats.
    gnupghome:
        Optional ``GNUPGHOME`` override passed to the GPG subprocess.
    sign_with_sigstore:
        When True (and ``format="oscal-ar"``), produces a Sigstore/Rekor
        keyless-signing bundle alongside the AR JSON. Defaults to
        ``<output_path>.sigstore.json`` unless ``sigstore_bundle_path``
        is supplied. Refused in air-gap mode.
    sigstore_bundle_path:
        Custom Sigstore bundle output path. Defaults to
        ``<output_path>.sigstore.json``. Only used with
        ``sign_with_sigstore=True``.
    sigstore_identity_token:
        Optional explicit OIDC token for Sigstore signing. When omitted,
        sigstore-python's ``detect_credential()`` resolves it from the
        ambient GitHub Actions / GCP / AWS environment.
    key_sign_path:
        Optional path to a PEM/PKCS#8 private key (Ed25519 or RSA). When
        supplied alongside ``format="oscal-ar"``, the AR JSON is DSSE-signed
        (in-toto Statement v1) and written to ``<output_path>.dsse.json``.
        Air-gap-clean: no gpg binary, no network. Encrypted keys: set
        ``$EVIDENTIA_SIGNING_KEY_PASSPHRASE``. Ignored by non-OSCAL formats.
    """
    path = Path(output_path)

    if format == "json":
        return _export_json(report, path)
    if format == "csv":
        return _export_csv(report, path)
    if format == "markdown":
        return _export_markdown(report, path)
    if format == "oscal-ar":
        return _export_oscal_ar(
            report,
            path,
            findings=findings,
            vendor_inventory=vendor_inventory,
            gpg_key_id=gpg_key_id,
            gnupghome=gnupghome,
            sign_with_sigstore=sign_with_sigstore,
            sigstore_bundle_path=sigstore_bundle_path,
            sigstore_identity_token=sigstore_identity_token,
            key_sign_path=key_sign_path,
        )
    if format == "sarif":
        return _export_sarif(report, path)
    if format == "ocsf":
        return _export_ocsf(report, path)
    if format == "ocsf-detection":
        return _export_ocsf_detection(report, path)
    if format == "cyclonedx-vex":
        return _export_cyclonedx_vex(report, path)

    raise ValueError(f"Unsupported format: {format}")


def _export_json(report: GapAnalysisReport, path: Path) -> Path:
    """Export as JSON."""
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def _export_csv(report: GapAnalysisReport, path: Path) -> Path:
    """Export gaps as CSV (one row per gap)."""
    output = StringIO()
    writer = csv.writer(output)

    writer.writerow(
        [
            "gap_id",
            "framework",
            "control_id",
            "control_title",
            "gap_severity",
            "implementation_status",
            "gap_description",
            "cross_framework_value",
            "remediation_guidance",
            "implementation_effort",
            "priority_score",
            "jira_issue_key",
            "servicenow_ticket_id",
        ]
    )

    for gap in report.gaps:
        writer.writerow(
            [
                gap.id,
                gap.framework,
                gap.control_id,
                gap.control_title,
                gap.gap_severity,
                gap.implementation_status,
                gap.gap_description,
                "; ".join(gap.cross_framework_value),
                gap.remediation_guidance,
                gap.implementation_effort,
                gap.priority_score,
                gap.jira_issue_key or "",
                gap.servicenow_ticket_id or "",
            ]
        )

    path.write_text(output.getvalue(), encoding="utf-8")
    return path


def _export_markdown(report: GapAnalysisReport, path: Path) -> Path:
    """Export as Markdown report."""
    lines: list[str] = []

    lines.append(f"# Gap Analysis Report: {report.organization}")
    lines.append("")
    lines.append(f"**Date:** {report.analyzed_at.isoformat()}")
    lines.append(f"**Frameworks:** {', '.join(report.frameworks_analyzed)}")
    lines.append(f"**Evidentia Version:** {report.evidentia_version}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Total Controls Required | {report.total_controls_required} |")
    lines.append(f"| Controls in Inventory | {report.total_controls_in_inventory} |")
    lines.append(f"| Total Gaps | {report.total_gaps} |")
    lines.append(f"| Critical | {report.critical_gaps} |")
    lines.append(f"| High | {report.high_gaps} |")
    lines.append(f"| Medium | {report.medium_gaps} |")
    lines.append(f"| Low | {report.low_gaps} |")
    lines.append(f"| Coverage | {report.coverage_percentage}% |")
    lines.append("")

    lines.append("## Gaps (Prioritized)")
    lines.append("")
    lines.append("| # | Framework | Control | Severity | Status | Effort | Priority | Cross-FW Value |")
    lines.append("|---|---|---|---|---|---|---|---|")

    for i, gap in enumerate(report.gaps, 1):
        cross_fw = len(gap.cross_framework_value)
        lines.append(
            f"| {i} | {gap.framework} | {gap.control_id} — {gap.control_title} | "
            f"{gap.gap_severity} | {gap.implementation_status} | "
            f"{gap.implementation_effort} | {gap.priority_score} | "
            f"{cross_fw} frameworks |"
        )

    if report.efficiency_opportunities:
        lines.append("")
        lines.append("## Efficiency Opportunities")
        lines.append("")
        lines.append("Controls that satisfy 3+ framework requirements simultaneously:")
        lines.append("")
        lines.append("| Control | Title | Frameworks | Gaps Closed | Effort | Value Score |")
        lines.append("|---|---|---|---|---|---|")
        for opp in report.efficiency_opportunities:
            lines.append(
                f"| {opp.control_id} | {opp.control_title} | "
                f"{opp.framework_count} | {opp.total_gaps_closed} | "
                f"{opp.implementation_effort} | {opp.value_score} |"
            )

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _export_oscal_ar(
    report: GapAnalysisReport,
    path: Path,
    *,
    findings: list[SecurityFinding] | None = None,
    vendor_inventory: list[Vendor] | None = None,
    gpg_key_id: str | None = None,
    gnupghome: str | Path | None = None,
    sign_with_sigstore: bool = False,
    sigstore_bundle_path: str | Path | None = None,
    sigstore_identity_token: str | None = None,
    key_sign_path: str | Path | None = None,
) -> Path:
    """Export as OSCAL Assessment Results JSON.

    Maps Evidentia gap report to a minimal OSCAL assessment-results structure.

    v0.7.0: when ``findings`` is provided, each is embedded in the AR's
    ``back-matter.resources[]`` with a SHA-256 digest. When
    ``gpg_key_id`` is provided, a detached ASCII-armored signature is
    written to ``<path>.asc``. When ``sign_with_sigstore=True``, a
    Sigstore bundle is also written to ``<path>.sigstore.json``. GPG
    and Sigstore are independent — both can coexist for defence-in-depth.

    v0.7.9 P0.5: when ``vendor_inventory`` is provided, each vendor is
    added to ``metadata.parties[]`` (standard OSCAL discovery) and
    ``back-matter.resources[]`` (tamper-evident record). Same integrity
    model as findings: tampering with a vendor record changes its hash
    and fails :func:`evidentia_core.oscal.verify.verify_ar_file`.
    """
    from evidentia_core.oscal.exporter import gap_report_to_oscal_ar

    oscal_ar = gap_report_to_oscal_ar(
        report, findings=findings, vendor_inventory=vendor_inventory
    )
    path.write_text(json.dumps(oscal_ar, indent=2, default=str), encoding="utf-8")

    if gpg_key_id:
        from evidentia_core.oscal.signing import sign_file

        sign_file(path, key_id=gpg_key_id, gnupghome=gnupghome)

    if sign_with_sigstore:
        from evidentia_core.oscal.sigstore import sign_file as sigstore_sign

        sigstore_sign(
            path,
            bundle_path=sigstore_bundle_path,
            identity_token=sigstore_identity_token,
        )

    if key_sign_path:
        from evidentia_core.oscal.keysign import sign_oscal_file

        sign_oscal_file(path, key_path=key_sign_path)

    return path


def _export_sarif(report: GapAnalysisReport, path: Path) -> Path:
    """Export the gap report as a SARIF 2.1.0 log (v0.10.0).

    Each ControlGap becomes a SARIF result, so gap analysis can run as
    a CI gate — rendered in GitHub code scanning / GitLab security
    dashboards, or consumed as a standalone SARIF artifact.
    """
    from evidentia_core.gap_analyzer.sarif import gap_report_to_sarif

    sarif_log = gap_report_to_sarif(report)
    path.write_text(json.dumps(sarif_log, indent=2), encoding="utf-8")
    return path


def _export_ocsf(report: GapAnalysisReport, path: Path) -> Path:
    """Export the gap report as an OCSF Compliance Finding JSON
    array (v0.10.4 A2).

    Each ControlGap becomes one OCSF Compliance Finding (class_uid
    2003), suitable for SIEM ingest / data-lake landing zones. This
    is the symmetric counterpart to the v0.10.1 ``evidentia collect
    ocsf`` ingest verb — gap output now flows into the same OCSF
    pipeline as collector-shaped findings.

    Requires the ``[ocsf]`` extra (``pip install
    'evidentia-core[ocsf]'``); raises :class:`OCSFMappingError`
    otherwise.
    """
    from evidentia_core.gap_analyzer.ocsf import gap_report_to_ocsf_array

    ocsf_array = gap_report_to_ocsf_array(report)
    path.write_text(json.dumps(ocsf_array, indent=2), encoding="utf-8")
    return path


def _export_ocsf_detection(report: GapAnalysisReport, path: Path) -> Path:
    """Export the gap report as an OCSF Detection Finding JSON array
    (v0.10.5 Phase 7).

    Each ControlGap becomes one OCSF Detection Finding (``class_uid``
    2004), the SIEM-target OCSF class. Splunk / Elastic / Microsoft
    Sentinel / Datadog consume Detection Finding natively as
    production traffic; Compliance Finding (the v0.10.4 ``ocsf``
    format) is the semantically correct class for control pass/fail
    but is under-adopted by SIEM ingest pipelines.

    Operators who want SIEM ingest pick ``--format ocsf-detection``;
    operators who want OCSF-aware GRC tooling stay on ``--format
    ocsf``. The two emits carry the same gap data with the same
    severity mappings — the only structural difference is the OCSF
    class.

    Requires the ``[ocsf]`` extra (``pip install
    'evidentia-core[ocsf]'``); raises :class:`OCSFMappingError`
    otherwise.
    """
    from evidentia_core.gap_analyzer.ocsf_detection import (
        gap_report_to_ocsf_detection_array,
    )

    detection_array = gap_report_to_ocsf_detection_array(report)
    path.write_text(json.dumps(detection_array, indent=2), encoding="utf-8")
    return path


def _export_cyclonedx_vex(report: GapAnalysisReport, path: Path) -> Path:
    """Export the gap report as a CycloneDX 1.6 VEX document
    (v0.10.5 Phase 8).

    Each ControlGap becomes one CycloneDX ``vulnerability`` entry
    with the analysis state mapped from the gap's ``implementation_status``
    and ``status`` (GapStatus). Federal supply-chain mandates
    (EO 14028, SEC 2026 supply-chain enforcement) are driving
    CycloneDX VEX adoption — Dependency-Track and other CycloneDX-
    aware tooling consume this surface directly.

    CycloneDX is already used in Evidentia's SBOM emit (the release
    workflow ships ``evidentia-sbom.cdx.json``), so VEX is an additive
    surface over the existing supply-chain artifact stack.
    """
    from evidentia_core.gap_analyzer.vex import gap_report_to_cyclonedx_vex

    vex_doc = gap_report_to_cyclonedx_vex(report)
    path.write_text(json.dumps(vex_doc, indent=2), encoding="utf-8")
    return path
