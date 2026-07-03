"""Concentration-risk reporting engine (v0.7.9 P0.3).

Aggregates a vendor inventory across configurable dimensions to
surface concentration risk per FFIEC + OCC Bulletin 2013-29 + FRB
SR 13-19 expectations. The classic example: discovering that 9 of
your 12 ostensibly-independent SaaS vendors all run on the same
hyperscaler region — a single failure mode the regulator wants you
to be aware of and mitigating.

Supported dimensions (per `docs/releases/plans/v0.7.9-plan.md` §P0.3):

- ``region`` — ``vendor.region`` (free-text geo / cloud-region label)
- ``cloud-provider`` — ``vendor.fourth_parties[].name`` filtered to
  ``type=cloud_provider``, plus the vendor itself when
  ``vendor.type`` is ``cloud_provider``
- ``4th-party`` — ``vendor.fourth_parties[].name`` (any type)
- ``service-category`` — ``vendor.type``
- ``criticality-tier`` — ``vendor.criticality_tier``
- ``regulatory-classification`` — ``vendor.regulatory_classification[]``
  (multi-valued per vendor)

Per-dimension distribution counts the number of distinct vendor IDs
contributing each value. Vendors with multiple values for the same
dimension (e.g., a vendor with 3 disclosed fourth-parties under the
``4th-party`` dimension) count once per value — so the total per
dimension equals the sum of distinct (vendor, value) tuples and CAN
exceed the vendor count for that dimension. Percentage is computed
relative to the vendor count, NOT the (vendor, value) count, so an
operator reading "57% of vendors depend on AWS" sees the truth
even when 4th-party disclosures are dense.

Threshold semantics: when ``threshold`` is set, every distribution
entry with ``percentage >= threshold`` is flagged via
``exceeds_threshold=True``. Operators receive the concrete row to
investigate. Default ``threshold=None`` (no flagging; render all
entries unmarked).

Outputs:

- :class:`ConcentrationReport` Pydantic model — JSON-serialisable
  for REST + machine consumers
- :func:`render_html_report` — single-file HTML with sortable
  tables (no JS deps; client-sortable via ``data-sort`` headers
  + a small inline script)
- :func:`render_csv_report` — flat CSV (one row per dimension ×
  value) for spreadsheet imports
"""

from __future__ import annotations

import csv
import html
import io
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime

from pydantic import Field

from evidentia_core.models.common import (
    EvidentiaModel,
    current_version,
    utc_now,
)
from evidentia_core.models.tprm import Vendor, VendorType

# Characters that, when leading a CSV cell, trigger formula
# interpretation in Excel / LibreOffice / Google Sheets. Per OWASP
# CSV Injection guidance: `=`, `+`, `-`, `@`, plus tab + carriage
# return (which can be used to lead-rotate fields in some parsers).
# Fix lands here in the v0.7.9 P0.3 + P0.2 Continuous-review
# (security review M-1 / code-quality H-1) so the CSV that goes to
# the vendor — and the concentration CSV that gets shared with
# regulators / auditors — cannot be weaponized via a crafted vendor
# name or 4th-party name.
_CSV_FORMULA_LEAD_CHARS: frozenset[str] = frozenset(
    ["=", "+", "-", "@", "\t", "\r"]
)


def _csv_safe(value: object) -> str:
    """Defuse CSV-injection vectors before writing a cell.

    Prefixes a single-quote (``'``) when the stringified value's
    first character is in :data:`_CSV_FORMULA_LEAD_CHARS`. The
    single-quote is the OWASP-recommended neutralizer + survives
    round-tripping in most spreadsheet consumers (Excel renders
    it but doesn't interpret as formula; LibreOffice + Sheets
    likewise). Non-string values pass through unchanged after
    str() coercion (so ``int`` / ``float`` cells emit cleanly).
    """
    s = str(value)
    if s and s[0] in _CSV_FORMULA_LEAD_CHARS:
        return "'" + s
    return s


SUPPORTED_DIMENSIONS: frozenset[str] = frozenset(
    [
        "region",
        "cloud-provider",
        "4th-party",
        "service-category",
        "criticality-tier",
        "regulatory-classification",
    ]
)
"""The full set of dimensions :func:`compute_concentration` accepts.

Extending this set requires a matching branch in
:func:`_extract_values_for_dimension`. Frozen + module-level so the
CLI + REST surfaces can render valid-choices help text without
hard-coding the list in two more places.
"""


class ValueCount(EvidentiaModel):
    """One row of a dimension's distribution: a value + its vendor share."""

    value: str = Field(description="The dimension value (e.g., 'aws', 'us-east-1').")
    count: int = Field(
        ge=0,
        description=(
            "Number of distinct vendors carrying this value on this "
            "dimension."
        ),
    )
    percentage: float = Field(
        ge=0.0,
        le=100.0,
        description=(
            "``count / total_vendors * 100`` rounded to one decimal place. "
            "Computed against the report's total vendor count, NOT the "
            "sum of counts (which can exceed the vendor count for "
            "multi-valued dimensions like 4th-party)."
        ),
    )
    exceeds_threshold: bool = Field(
        default=False,
        description=(
            "True when the report's threshold was set and this value's "
            "percentage meets-or-exceeds it."
        ),
    )


class DimensionAnalysis(EvidentiaModel):
    """Per-dimension distribution + summary stats."""

    dimension: str = Field(description="Dimension name (one of SUPPORTED_DIMENSIONS).")
    total_unique_values: int = Field(
        ge=0,
        description="Number of distinct values observed across the inventory.",
    )
    distribution: list[ValueCount] = Field(
        default_factory=list,
        description=(
            "Per-value counts sorted descending by count then ascending "
            "by value (alphabetical tie-break). Always shows every value "
            "— no truncation; operators reviewing a regulator-facing "
            "report want the full picture."
        ),
    )
    vendors_with_value: int = Field(
        ge=0,
        description=(
            "Distinct vendors that have at least one value on this "
            "dimension. Different from ``total_vendors`` when some "
            "vendors are missing the dimension entirely (e.g., region "
            "left blank)."
        ),
    )

    @property
    def threshold_violations(self) -> list[ValueCount]:
        """Return only the rows flagged ``exceeds_threshold=True``."""
        return [v for v in self.distribution if v.exceeds_threshold]


class ConcentrationReport(EvidentiaModel):
    """Top-level concentration-risk report for a vendor inventory."""

    generated_at: datetime = Field(
        default_factory=utc_now,
        description="Report-generation timestamp (UTC).",
    )
    total_vendors: int = Field(
        ge=0, description="Total vendor count this report was computed against."
    )
    threshold: float | None = Field(
        default=None,
        description=(
            "Concentration-percentage threshold (0.0-100.0). When set, "
            "any per-value percentage meeting-or-exceeding it gets "
            "``exceeds_threshold=True``. ``None`` means no flagging."
        ),
    )
    dimensions: list[DimensionAnalysis] = Field(
        default_factory=list,
        description="Per-dimension analyses, in the order requested.",
    )
    evidentia_version: str = Field(
        default_factory=current_version,
        description="evidentia-core version that produced this report.",
    )


# ── extraction ────────────────────────────────────────────────────


def _extract_values_for_dimension(
    vendor: Vendor, dimension: str
) -> list[str]:
    """Return the set of value labels a vendor contributes for a dimension.

    Multi-valued dimensions (``4th-party``, ``cloud-provider``,
    ``regulatory-classification``) can return >1 entry per vendor;
    single-valued dimensions return at most 1. Empty list means
    "vendor doesn't carry a value on this dimension" (e.g.,
    ``region=None`` → no contribution to the region dimension).
    """
    if dimension == "region":
        return [vendor.region] if vendor.region else []
    if dimension == "service-category":
        return [str(vendor.type)]
    if dimension == "criticality-tier":
        return [str(vendor.criticality_tier)]
    if dimension == "regulatory-classification":
        return [str(c) for c in vendor.regulatory_classification]
    if dimension == "4th-party":
        return [fp.name for fp in vendor.fourth_parties]
    if dimension == "cloud-provider":
        # Two contributions, each with a source-distinguishing suffix
        # so an FFIEC-facing report doesn't merge "direct AWS contract"
        # with "AWS shows up as a downstream 4P" into one bucket
        # labeled simply "AWS" — they're materially different
        # concentration risks. Closes v0.7.9 P0.3+P0.2 Continuous-
        # review H-2.
        #
        #   1. The vendor itself, if its primary type is cloud_provider
        #      (direct AWS contract) — labeled "<vendor name> (direct)"
        #   2. Each disclosed 4th-party with type=cloud_provider —
        #      labeled "<4P name> (4th-party)"
        #
        # An operator running concentration with `--by cloud-provider`
        # then sees two rows for the same provider — "AWS (direct)" +
        # "AWS (4th-party)" — and can investigate each independently.
        # If they want the merged view, adding both row counts is
        # trivial in their downstream tool.
        out: list[str] = []
        if str(vendor.type) == VendorType.CLOUD_PROVIDER.value:
            out.append(f"{vendor.name} (direct)")
        for fp in vendor.fourth_parties:
            if str(fp.type) == VendorType.CLOUD_PROVIDER.value:
                out.append(f"{fp.name} (4th-party)")
        return out
    raise ValueError(
        f"Unsupported concentration dimension {dimension!r}; "
        f"valid: {sorted(SUPPORTED_DIMENSIONS)}"
    )


# ── core ──────────────────────────────────────────────────────────


def compute_concentration(
    vendors: Iterable[Vendor],
    dimensions: list[str],
    threshold: float | None = None,
) -> ConcentrationReport:
    """Compute a concentration-risk report across the given dimensions.

    Args:
        vendors: Vendor inventory iterable.
        dimensions: Ordered list of dimension names from
            :data:`SUPPORTED_DIMENSIONS`. Order is preserved in the
            output so a `--by region,cloud-provider` CLI invocation
            produces region first.
        threshold: Optional concentration percentage (0.0-100.0).
            When set, per-value percentages meeting-or-exceeding it
            get ``exceeds_threshold=True``. ``None`` means no flagging.

    Returns:
        ConcentrationReport with one DimensionAnalysis per requested
        dimension, in input order.

    Raises:
        ValueError: any unsupported dimension; threshold out of range.
    """
    # Validate up-front so a typo doesn't burn through the inventory
    # before failing.
    bad = [d for d in dimensions if d not in SUPPORTED_DIMENSIONS]
    if bad:
        raise ValueError(
            f"Unsupported dimension(s) {bad!r}; "
            f"valid: {sorted(SUPPORTED_DIMENSIONS)}"
        )
    if threshold is not None and not (0.0 <= threshold <= 100.0):
        raise ValueError(
            f"threshold must be in [0.0, 100.0]; got {threshold}"
        )

    vendor_list = list(vendors)
    total = len(vendor_list)

    analyses: list[DimensionAnalysis] = []
    for dimension in dimensions:
        # value → set of vendor IDs (so duplicate 4th-party disclosures
        # within one vendor count once)
        value_to_vendors: dict[str, set[str]] = defaultdict(set)
        vendors_with_any_value: set[str] = set()
        for v in vendor_list:
            for value in _extract_values_for_dimension(v, dimension):
                value_to_vendors[value].add(v.id)
                vendors_with_any_value.add(v.id)

        distribution: list[ValueCount] = []
        for value, vendor_ids in value_to_vendors.items():
            count = len(vendor_ids)
            pct = (count / total * 100.0) if total > 0 else 0.0
            pct_rounded = round(pct, 1)
            exceeds = (
                threshold is not None and pct_rounded >= threshold
            )
            distribution.append(
                ValueCount(
                    value=value,
                    count=count,
                    percentage=pct_rounded,
                    exceeds_threshold=exceeds,
                )
            )
        # Sort: count desc, then value asc for stable tie-break
        distribution.sort(key=lambda vc: (-vc.count, vc.value.lower()))
        analyses.append(
            DimensionAnalysis(
                dimension=dimension,
                total_unique_values=len(distribution),
                distribution=distribution,
                vendors_with_value=len(vendors_with_any_value),
            )
        )

    return ConcentrationReport(
        total_vendors=total,
        threshold=threshold,
        dimensions=analyses,
    )


# ── HTML rendering ────────────────────────────────────────────────

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Evidentia — Vendor Concentration Risk Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          max-width: 1100px; margin: 2em auto; padding: 0 1em; color: #1a1a1a; }}
  h1 {{ border-bottom: 2px solid #2c3e50; padding-bottom: 0.3em; }}
  h2 {{ color: #2c3e50; margin-top: 2em; }}
  .meta {{ color: #555; font-size: 0.9em; margin-bottom: 2em; }}
  .meta code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
  th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
  th {{ background: #2c3e50; color: white; cursor: pointer; user-select: none; }}
  th:hover {{ background: #34495e; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
  tr.exceeds {{ background: #fff5f5; }}
  tr.exceeds td {{ font-weight: 600; }}
  .pct {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .flag {{ color: #c0392b; font-weight: 600; }}
  .summary {{ background: #ecf0f1; padding: 1em; border-radius: 4px; margin: 1em 0; }}
  .empty {{ color: #888; font-style: italic; }}
</style>
</head>
<body>
<h1>Vendor Concentration Risk Report</h1>
<div class="meta">
  Generated: <code>{generated_at}</code><br>
  Total vendors: <code>{total_vendors}</code><br>
  Threshold: <code>{threshold_label}</code><br>
  Evidentia version: <code>{evidentia_version}</code>
</div>
{dimension_sections}
<script>
  // Lightweight click-to-sort: any th with a data-sort attribute
  // toggles ascending/descending sort on its column.
  document.querySelectorAll('th[data-sort]').forEach(function(th, i) {{
    th.addEventListener('click', function() {{
      var table = th.closest('table');
      var idx = Array.from(th.parentNode.children).indexOf(th);
      var rows = Array.from(table.tBodies[0].rows);
      var asc = th.dataset.asc !== 'true';
      rows.sort(function(a, b) {{
        var va = a.cells[idx].dataset.sortValue || a.cells[idx].textContent;
        var vb = b.cells[idx].dataset.sortValue || b.cells[idx].textContent;
        var na = parseFloat(va), nb = parseFloat(vb);
        if (!isNaN(na) && !isNaN(nb)) {{ return asc ? na - nb : nb - na; }}
        return asc ? va.localeCompare(vb) : vb.localeCompare(va);
      }});
      rows.forEach(function(r) {{ table.tBodies[0].appendChild(r); }});
      th.dataset.asc = asc;
    }});
  }});
</script>
</body>
</html>
"""


def _render_dimension_html(dim: DimensionAnalysis) -> str:
    if not dim.distribution:
        return (
            f"<h2>Dimension: {html.escape(dim.dimension)}</h2>"
            f'<p class="empty">No vendors contribute a value on this dimension.</p>'
        )
    flagged = sum(1 for d in dim.distribution if d.exceeds_threshold)
    summary = (
        f'<div class="summary">'
        f"<strong>{dim.total_unique_values}</strong> unique values across "
        f"<strong>{dim.vendors_with_value}</strong> vendor(s). "
    )
    if flagged:
        summary += (
            f'<span class="flag">{flagged} value(s) exceed the threshold.</span>'
        )
    summary += "</div>"

    rows = []
    for vc in dim.distribution:
        cls = ' class="exceeds"' if vc.exceeds_threshold else ""
        flag_cell = '<span class="flag">⚠</span>' if vc.exceeds_threshold else ""
        rows.append(
            f"<tr{cls}>"
            f"<td>{html.escape(vc.value)}</td>"
            f'<td class="pct" data-sort-value="{vc.count}">{vc.count}</td>'
            f'<td class="pct" data-sort-value="{vc.percentage}">{vc.percentage}%</td>'
            f"<td>{flag_cell}</td>"
            f"</tr>"
        )
    table = (
        f"<h2>Dimension: {html.escape(dim.dimension)}</h2>"
        + summary
        + '<table><thead><tr>'
        + '<th data-sort="text">Value</th>'
        + '<th data-sort="number">Vendor count</th>'
        + '<th data-sort="number">Percentage</th>'
        + '<th>Flag</th>'
        + '</tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table>"
    )
    return table


def render_html_report(report: ConcentrationReport) -> str:
    """Render a ConcentrationReport as a self-contained HTML document.

    Single-file output: inline CSS + small inline JS for click-to-sort.
    No external dependencies — drop into any browser. HTML-escapes all
    user-supplied vendor + value names.
    """
    threshold_label = (
        f"≥{report.threshold}%" if report.threshold is not None else "n/a"
    )
    sections = "\n".join(
        _render_dimension_html(d) for d in report.dimensions
    )
    return _HTML_TEMPLATE.format(
        generated_at=html.escape(report.generated_at.isoformat()),
        total_vendors=report.total_vendors,
        threshold_label=html.escape(threshold_label),
        evidentia_version=html.escape(report.evidentia_version),
        dimension_sections=sections,
    )


# ── CSV rendering ─────────────────────────────────────────────────


def render_csv_report(report: ConcentrationReport) -> str:
    """Render a ConcentrationReport as flat CSV.

    One row per (dimension, value) pair. Header columns: dimension,
    value, count, percentage, exceeds_threshold. Useful for
    spreadsheet imports + Excel pivoting without bringing in xlsx
    dep.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["dimension", "value", "count", "percentage", "exceeds_threshold"]
    )
    for dim in report.dimensions:
        for vc in dim.distribution:
            # Apply _csv_safe to the only user-supplied cell — `vc.value`
            # carries vendor / 4th-party / region names + regulatory-
            # classification labels. Other columns (`dim.dimension` is
            # closed-set per SUPPORTED_DIMENSIONS; `count` / `percentage`
            # are numeric; `exceeds_threshold` is constant) cannot
            # carry attacker-controlled formula content.
            writer.writerow(
                [
                    dim.dimension,
                    _csv_safe(vc.value),
                    vc.count,
                    vc.percentage,
                    "true" if vc.exceeds_threshold else "false",
                ]
            )
    return buf.getvalue()
