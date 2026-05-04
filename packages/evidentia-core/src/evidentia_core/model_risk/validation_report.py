"""SR 11-7 / SR 26-02 model validation report generator.

Produces a Markdown validation-cycle report from a
:class:`evidentia_core.models.model_risk.ModelInventory` record's
`validation_findings[]` list. The report layout follows SR 11-7
§III.D "Validation" expectations: independent challenge, ongoing
monitoring, outcomes analysis, finding disposition.

Validation-finding-status counts in the executive summary and the
findings table give validators + auditors a quick disposition view.
A model with HIGH-severity findings open should not be in
production use; this report makes that visible at a glance.

Output is plain Markdown — diff-able, version-controllable, and
portable across every common auditor toolchain (Word via pandoc,
PDF via pandoc, HTML, plain text).
"""

from __future__ import annotations

from collections import Counter
from datetime import date

from evidentia_core.models.model_risk import (
    ModelInventory,
    ValidationFinding,
    ValidationSeverity,
    ValidationStatus,
)


def _format_date(d: date | None) -> str:
    return d.isoformat() if d else "_Not set_"


def _disposition_table(findings: list[ValidationFinding]) -> str:
    """Render the validation-finding disposition counts."""
    if not findings:
        return (
            "| Severity | Open | Remediated | Accepted | Deferred | Total |\n"
            "| --- | --- | --- | --- | --- | --- |\n"
            "| (no findings) | 0 | 0 | 0 | 0 | 0 |\n"
        )
    # NOTE: EvidentiaModel base sets `use_enum_values=True`, so
    # `f.severity` and `f.status` are STRINGS post-validation, not
    # Enum members. Compare via .value to keep this code agnostic.
    rows = []
    grand_open = 0
    grand_total = 0
    for severity in (
        ValidationSeverity.HIGH,
        ValidationSeverity.MEDIUM,
        ValidationSeverity.LOW,
    ):
        sev_findings = [f for f in findings if f.severity == severity.value]
        # use_enum_values=True on EvidentiaModel base → f.status is
        # str at runtime; annotate Counter explicitly so mypy aligns
        # with the runtime contract.
        counts: Counter[str] = Counter(str(f.status) for f in sev_findings)
        open_ = counts.get(ValidationStatus.OPEN.value, 0)
        rem = counts.get(ValidationStatus.REMEDIATED.value, 0)
        acc = counts.get(ValidationStatus.ACCEPTED.value, 0)
        defr = counts.get(ValidationStatus.DEFERRED.value, 0)
        total = open_ + rem + acc + defr
        rows.append(
            f"| {severity.value} | {open_} | {rem} | {acc} | {defr} | {total} |"
        )
        grand_open += open_
        grand_total += total
    rows.append(
        f"| **All** | **{grand_open}** | "
        f"{sum(1 for f in findings if f.status == ValidationStatus.REMEDIATED.value)} | "
        f"{sum(1 for f in findings if f.status == ValidationStatus.ACCEPTED.value)} | "
        f"{sum(1 for f in findings if f.status == ValidationStatus.DEFERRED.value)} | "
        f"**{grand_total}** |"
    )
    return (
        "| Severity | Open | Remediated | Accepted | Deferred | Total |\n"
        "| --- | --- | --- | --- | --- | --- |\n"
        + "\n".join(rows)
        + "\n"
    )


def _findings_table(findings: list[ValidationFinding]) -> str:
    """Render full findings detail table."""
    if not findings:
        return "_No validation findings recorded._\n"
    rows = []
    for f in sorted(findings, key=lambda x: (x.severity, x.detected_at)):
        rem_due = _format_date(f.remediation_due_date)
        rem_done = _format_date(f.remediated_at)
        rows.append(
            f"| `{f.id[:8]}` | {f.detected_at.isoformat()} | "
            f"{f.severity} | {f.status} | "
            f"{f.title} | {rem_due} | {rem_done} |"
        )
    return (
        "| ID | Detected | Severity | Status | Title | Remediation due | Remediated on |\n"
        "| --- | --- | --- | --- | --- | --- | --- |\n"
        + "\n".join(rows)
        + "\n"
    )


def _open_high_warning(findings: list[ValidationFinding]) -> str:
    """If any HIGH-severity finding is OPEN, prepend a warning callout."""
    open_high = [
        f
        for f in findings
        if f.severity == ValidationSeverity.HIGH.value
        and f.status == ValidationStatus.OPEN.value
    ]
    if not open_high:
        return ""
    return (
        f"> ⚠️ **HIGH-severity findings open**: {len(open_high)}\n"
        ">\n"
        "> Per SR 11-7 §III.D, HIGH-severity validation findings should "
        "block the model from production use until remediated. Review "
        "the open findings below and the operator's remediation plans.\n\n"
    )


def generate_validation_report(model: ModelInventory) -> str:
    """Generate SR 11-7-aligned validation report as Markdown.

    Parameters
    ----------
    model
        The ModelInventory record whose validation findings to report.

    Returns
    -------
    str
        Markdown document. Caller decides where to write it (file,
        REST response body, etc.).

    Notes
    -----
    Output is deterministic — same input produces the same output
    character-for-character. Operators can therefore commit
    generated reports to git and audit-diff them across validation
    cycles.
    """
    sections: list[str] = []
    findings = model.validation_findings

    # ── Header ───────────────────────────────────────────────────
    sections.append(
        f"# Validation Report — {model.name}\n\n"
        f"_SR 11-7 / SR 26-02 / OCC Bulletin 2011-12 / OCC Bulletin "
        f"2026-13a aligned validation report. Generated by Evidentia "
        f"v{model.evidentia_version} from ModelInventory record._\n"
    )

    # ── Executive summary ────────────────────────────────────────
    sections.append(
        "## Executive summary\n\n"
        f"{_open_high_warning(findings)}"
        f"| Field | Value |\n"
        f"| --- | --- |\n"
        f"| Model ID | `{model.id}` |\n"
        f"| Model name | {model.name} |\n"
        f"| Tier | {model.tier} |\n"
        f"| Methodology | {model.methodology} |\n"
        f"| Provenance | {model.vendor_or_internal} |\n"
        f"| Owner | {model.owner} |\n"
        f"| Last validation | {_format_date(model.last_validation_date)} |\n"
        f"| Next validation due | {_format_date(model.next_validation_due)} |\n"
        f"| Total findings | {len(findings)} |\n"
    )

    # ── Disposition ──────────────────────────────────────────────
    sections.append(
        "## Finding disposition\n\n"
        f"{_disposition_table(findings)}"
    )

    # ── Detail ───────────────────────────────────────────────────
    sections.append(
        "## Findings detail\n\n"
        f"{_findings_table(findings)}"
    )

    # ── Per-finding remediation narrative ───────────────────────
    if findings:
        narrative_chunks = []
        for f in sorted(findings, key=lambda x: (x.severity, x.detected_at)):
            narrative_chunks.append(
                f"### {f.severity.upper()} — {f.title}\n\n"
                f"**ID**: `{f.id}`  \n"
                f"**Detected**: {f.detected_at.isoformat()}  \n"
                f"**Status**: {f.status}\n\n"
                f"**Description**:\n\n{f.description}\n\n"
                f"**Remediation plan**: "
                f"{f.remediation_plan if f.remediation_plan else '_None recorded_'}\n"
            )
        sections.append(
            "## Remediation narrative\n\n" + "\n".join(narrative_chunks)
        )

    # ── Cycle context ────────────────────────────────────────────
    sections.append(
        "## Validation cycle context\n\n"
        f"**Tier `{model.tier}` cadence**: "
        f"{_cadence_text(model.tier)}.\n\n"
        f"This report reflects validation activity through "
        f"{_format_date(model.last_validation_date)}. "
        "Subsequent validation cycles will append new findings to the "
        "ModelInventory record; re-run "
        f"`evidentia model-risk validation-report generate {model.id}` "
        "to refresh.\n"
    )

    return "\n".join(sections)


def _cadence_text(tier_value: str) -> str:
    """Map tier value to validation-cadence narrative."""
    return {
        "tier_1": "annual independent validation per SR 11-7 §III.D",
        "tier_2": "biennial independent validation per SR 11-7 §III.D",
        "tier_3": "triennial validation per SR 11-7 §III.D",
    }.get(tier_value, "tier classification unrecognized")
