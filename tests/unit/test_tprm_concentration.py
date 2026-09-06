"""Unit tests for evidentia_core.tprm.concentration (v0.7.9 P0.3)."""

from __future__ import annotations

from datetime import date

import pytest
from evidentia_core.models.tprm import (
    CriticalityTier,
    FourthParty,
    RegulatoryClassification,
    Vendor,
    VendorType,
)
from evidentia_core.tprm.concentration import (
    SUPPORTED_DIMENSIONS,
    ConcentrationReport,
    compute_concentration,
    render_csv_report,
    render_html_report,
)


def _make_vendor(
    name: str,
    type_: VendorType = VendorType.SAAS,
    region: str | None = None,
    fourth_parties: list[FourthParty] | None = None,
    regulatory_classification: list[RegulatoryClassification] | None = None,
    criticality_tier: CriticalityTier = CriticalityTier.MEDIUM,
) -> Vendor:
    return Vendor(
        name=name,
        type=type_,
        criticality_tier=criticality_tier,
        relationship_owner="x@x.com",
        contract_start_date=date(2025, 1, 1),
        region=region,
        fourth_parties=fourth_parties or [],
        regulatory_classification=regulatory_classification or [],
    )


# ── compute_concentration core ─────────────────────────────────────


class TestComputeConcentration:
    def test_empty_inventory_returns_zero_total(self) -> None:
        report = compute_concentration([], ["region"])
        assert report.total_vendors == 0
        assert len(report.dimensions) == 1
        assert report.dimensions[0].distribution == []

    def test_unsupported_dimension_rejected(self) -> None:
        with pytest.raises(ValueError, match="Unsupported"):
            compute_concentration([_make_vendor("A")], ["nonexistent-dim"])

    def test_threshold_out_of_range_rejected(self) -> None:
        with pytest.raises(ValueError, match="threshold"):
            compute_concentration([_make_vendor("A")], ["region"], threshold=150.0)
        with pytest.raises(ValueError, match="threshold"):
            compute_concentration([_make_vendor("A")], ["region"], threshold=-1.0)

    def test_region_dimension_distribution(self) -> None:
        vendors = [
            _make_vendor("A", region="us-east-1"),
            _make_vendor("B", region="us-east-1"),
            _make_vendor("C", region="us-west-2"),
            _make_vendor("D", region=None),  # excluded from this dim
        ]
        report = compute_concentration(vendors, ["region"])
        assert report.total_vendors == 4
        dim = report.dimensions[0]
        assert dim.dimension == "region"
        assert dim.total_unique_values == 2
        assert dim.vendors_with_value == 3  # D has no region
        # us-east-1 has 2 vendors → 50%; us-west-2 has 1 → 25%
        values_by_name = {v.value: v for v in dim.distribution}
        assert values_by_name["us-east-1"].count == 2
        assert values_by_name["us-east-1"].percentage == 50.0
        assert values_by_name["us-west-2"].count == 1
        assert values_by_name["us-west-2"].percentage == 25.0

    def test_distribution_sorted_count_desc_then_value_asc(self) -> None:
        vendors = [
            _make_vendor("A", region="z-region"),
            _make_vendor("B", region="z-region"),
            _make_vendor("C", region="a-region"),
            _make_vendor("D", region="a-region"),
            _make_vendor("E", region="m-region"),
        ]
        report = compute_concentration(vendors, ["region"])
        dim = report.dimensions[0]
        # Counts: a=2, m=1, z=2. Sort: count desc → ties broken by value asc
        # Expected order: a-region (2), z-region (2), m-region (1)
        assert [v.value for v in dim.distribution] == [
            "a-region",
            "z-region",
            "m-region",
        ]

    def test_threshold_flags_correctly(self) -> None:
        # 3 of 4 vendors → 75%, exceeds threshold=50%
        vendors = [
            _make_vendor("A", region="us-east-1"),
            _make_vendor("B", region="us-east-1"),
            _make_vendor("C", region="us-east-1"),
            _make_vendor("D", region="eu-west-1"),
        ]
        report = compute_concentration(vendors, ["region"], threshold=50.0)
        dim = report.dimensions[0]
        flagged = dim.threshold_violations
        assert len(flagged) == 1
        assert flagged[0].value == "us-east-1"
        assert flagged[0].percentage == 75.0
        assert flagged[0].exceeds_threshold is True

    def test_threshold_inclusive_at_exact_boundary(self) -> None:
        # 1 of 2 = 50.0%; threshold=50 should flag (>= semantic)
        vendors = [
            _make_vendor("A", region="us-east-1"),
            _make_vendor("B", region="eu-west-1"),
        ]
        report = compute_concentration(vendors, ["region"], threshold=50.0)
        flagged_count = len(report.dimensions[0].threshold_violations)
        assert flagged_count == 2  # both at 50%; both flagged

    def test_cloud_provider_dimension_combines_self_and_4p(
        self,
    ) -> None:
        vendors = [
            # Vendor that IS a cloud provider — contributes its own name
            _make_vendor("AWS Direct", type_=VendorType.CLOUD_PROVIDER),
            # SaaS vendor disclosing AWS as 4th-party
            _make_vendor(
                "SaaS-on-AWS",
                type_=VendorType.SAAS,
                fourth_parties=[
                    FourthParty(
                        name="AWS Direct",  # same name as direct vendor
                        type=VendorType.CLOUD_PROVIDER,
                        relationship="underlying IaaS",
                    )
                ],
            ),
            # Different cloud
            _make_vendor(
                "SaaS-on-Azure",
                type_=VendorType.SAAS,
                fourth_parties=[
                    FourthParty(
                        name="Azure",
                        type=VendorType.CLOUD_PROVIDER,
                        relationship="underlying IaaS",
                    )
                ],
            ),
            # 4th-party that is NOT a cloud provider — should be ignored
            _make_vendor(
                "SaaS-with-Stripe",
                type_=VendorType.SAAS,
                fourth_parties=[
                    FourthParty(
                        name="Stripe",
                        type=VendorType.SAAS,
                        relationship="payment provider",
                    )
                ],
            ),
        ]
        report = compute_concentration(vendors, ["cloud-provider"])
        dim = report.dimensions[0]
        values = {v.value: v.count for v in dim.distribution}
        # H-2 Continuous-review fix: source-distinguishing suffix.
        # Direct AWS-Direct contract appears as "AWS Direct (direct)"
        # (1 vendor); the 4th-party AWS-Direct disclosure on
        # SaaS-on-AWS appears as "AWS Direct (4th-party)" (1 vendor).
        # Two rows, not one merged row — operators reviewing the
        # concentration report can distinguish "we have a direct
        # AWS contract" from "AWS is a downstream 4P".
        assert values["AWS Direct (direct)"] == 1
        assert values["AWS Direct (4th-party)"] == 1
        # Azure: 1 vendor (SaaS-on-Azure) as 4th-party
        assert values["Azure (4th-party)"] == 1
        # Stripe is not a cloud provider — must NOT appear in any form
        assert all("Stripe" not in v for v in values), f"Stripe leaked into cloud-provider dimension: {values!r}"
        # Old un-suffixed labels must NOT appear
        assert "AWS Direct" not in values
        assert "Azure" not in values

    def test_4p_dimension_includes_all_4p_types(self) -> None:
        vendors = [
            _make_vendor(
                "A",
                fourth_parties=[
                    FourthParty(
                        name="AWS",
                        type=VendorType.CLOUD_PROVIDER,
                        relationship="iaas",
                    ),
                    FourthParty(
                        name="Stripe",
                        type=VendorType.SAAS,
                        relationship="payments",
                    ),
                ],
            ),
        ]
        report = compute_concentration(vendors, ["4th-party"])
        values = {v.value: v.count for v in report.dimensions[0].distribution}
        assert values["AWS"] == 1
        assert values["Stripe"] == 1

    def test_service_category_dimension_uses_vendor_type(self) -> None:
        vendors = [
            _make_vendor("A", type_=VendorType.SAAS),
            _make_vendor("B", type_=VendorType.SAAS),
            _make_vendor("C", type_=VendorType.CONTRACTOR),
        ]
        report = compute_concentration(vendors, ["service-category"])
        values = {v.value: v.count for v in report.dimensions[0].distribution}
        assert values[VendorType.SAAS.value] == 2
        assert values[VendorType.CONTRACTOR.value] == 1

    def test_regulatory_classification_dimension_multivalue(
        self,
    ) -> None:
        vendors = [
            _make_vendor(
                "A",
                regulatory_classification=[
                    RegulatoryClassification.MODEL,
                    RegulatoryClassification.CUSTODY,
                ],
            ),
            _make_vendor(
                "B",
                regulatory_classification=[
                    RegulatoryClassification.MODEL,
                ],
            ),
        ]
        report = compute_concentration(vendors, ["regulatory-classification"])
        values = {v.value: v.count for v in report.dimensions[0].distribution}
        assert values[RegulatoryClassification.MODEL.value] == 2
        assert values[RegulatoryClassification.CUSTODY.value] == 1

    def test_multiple_dimensions_preserve_input_order(self) -> None:
        vendors = [_make_vendor("A", region="us-east-1")]
        report = compute_concentration(vendors, ["service-category", "region", "criticality-tier"])
        assert [d.dimension for d in report.dimensions] == [
            "service-category",
            "region",
            "criticality-tier",
        ]


# ── HTML rendering ─────────────────────────────────────────────────


class TestRenderHtmlReport:
    def test_renders_full_report(self) -> None:
        vendors = [
            _make_vendor("A", region="us-east-1"),
            _make_vendor("B", region="us-east-1"),
            _make_vendor("C", region="eu-west-1"),
        ]
        report = compute_concentration(vendors, ["region"], threshold=50.0)
        html_str = render_html_report(report)
        assert "<!DOCTYPE html>" in html_str
        assert "Vendor Concentration Risk Report" in html_str
        assert "us-east-1" in html_str
        assert "eu-west-1" in html_str
        # Threshold flag: us-east-1 at 66.7% > 50% should get class="exceeds"
        assert "exceeds" in html_str

    def test_empty_dimension_renders_placeholder(self) -> None:
        # No vendors → distribution is empty
        report = compute_concentration([], ["region"])
        html_str = render_html_report(report)
        assert "No vendors contribute" in html_str

    def test_html_escapes_user_supplied_values(self) -> None:
        # XSS-safety: a 4th-party name with < > should be HTML-escaped
        # in the rendered report. 4th-party names are user-supplied
        # free-text and surface verbatim into the distribution table.
        vendors = [
            _make_vendor(
                "ParentVendor",
                fourth_parties=[
                    FourthParty(
                        name="<script>alert(1)</script>",
                        type=VendorType.SAAS,
                        relationship="malicious-name-test",
                    ),
                ],
            ),
        ]
        report = compute_concentration(vendors, ["4th-party"])
        html_str = render_html_report(report)
        # Escaped form must be present; raw script must not
        assert "&lt;script&gt;" in html_str
        # The HTML template has a legitimate <script> block at the
        # bottom for click-to-sort. So we check that the *malicious*
        # script payload (with alert(1)) does not appear unescaped.
        assert "<script>alert(1)</script>" not in html_str

    def test_threshold_label_renders(self) -> None:
        report = compute_concentration(
            [_make_vendor("A", region="x")],
            ["region"],
            threshold=33.3,
        )
        html_str = render_html_report(report)
        assert "≥33.3%" in html_str

    def test_threshold_label_when_unset(self) -> None:
        report = compute_concentration([_make_vendor("A", region="x")], ["region"])
        html_str = render_html_report(report)
        assert "n/a" in html_str


# ── CSV rendering ──────────────────────────────────────────────────


class TestCsvInjectionDefense:
    """H-1 Continuous-review regression — _csv_safe neutralizes
    formula-injection vectors in vendor-controlled CSV cells.

    Closes v0.7.9 P0.3 + P0.2 Continuous-review H-1 / security M-1
    (CWE-1236 Improper Neutralization of Formula Elements in CSV
    File). The CSV is specifically designed to be opened in Excel /
    LibreOffice / Sheets where leading `=` `+` `-` `@` interpret
    as formula start; a single-quote prefix neutralizes per OWASP
    guidance.
    """

    def test_csv_safe_set_includes_owasp_chars(self) -> None:
        # Verify the formula-lead set covers the OWASP-recommended
        # set: =, +, -, @ (Excel/Sheets formula leads), plus tab + CR
        # (defense-in-depth against parser quirks). Tab/CR aren't
        # round-trip-testable through csv.reader (which strips leading
        # whitespace on parse), so we assert the set membership
        # directly.
        from evidentia_core.tprm.concentration import (
            _CSV_FORMULA_LEAD_CHARS,
        )

        for ch in ("=", "+", "-", "@", "\t", "\r"):
            assert ch in _CSV_FORMULA_LEAD_CHARS

    @pytest.mark.parametrize(
        "malicious_name",
        [
            "=cmd|'/c calc'!A0",
            '=HYPERLINK("http://attacker.example","Click")',
            "+SUM(A1)",
            "-2+3",
            "@SUM(1+1)",
        ],
    )
    def test_concentration_csv_neutralizes_formula_lead_chars(self, malicious_name: str) -> None:
        # 4th-party name is one of the user-controlled cells
        v = Vendor(
            name="Parent",
            type=VendorType.SAAS,
            criticality_tier=CriticalityTier.HIGH,
            relationship_owner="x@x.com",
            contract_start_date=date(2025, 1, 1),
            fourth_parties=[
                FourthParty(
                    name=malicious_name,
                    type=VendorType.SAAS,
                    relationship="malicious-test",
                ),
            ],
        )
        report = compute_concentration([v], ["4th-party"])
        csv_str = render_csv_report(report)
        # Parse the CSV and inspect the value cell directly — avoids
        # substring/escape headaches with `csv.writer`'s embedded-
        # quote / tab / CR handling.
        import csv as _csv
        import io as _io

        rows = list(_csv.reader(_io.StringIO(csv_str)))
        # Header row + data rows; the data row has the malicious name
        # in the `value` column (index 1)
        data_rows = rows[1:]
        assert len(data_rows) == 1
        value_cell = data_rows[0][1]
        # Defused: cell starts with a single-quote
        assert value_cell.startswith("'"), f"Expected single-quote prefix on defused cell; got {value_cell!r}"
        # Original malicious name follows the prefix unchanged
        assert value_cell == "'" + malicious_name

    def test_concentration_csv_passes_safe_values_through(self) -> None:
        # Normal (non-formula-leading) vendor name should NOT get
        # a single-quote prefix.
        v = Vendor(
            name="Acme Cloud",
            type=VendorType.SAAS,
            criticality_tier=CriticalityTier.HIGH,
            relationship_owner="x@x.com",
            contract_start_date=date(2025, 1, 1),
            region="us-east-1",
        )
        report = compute_concentration([v], ["region"])
        csv_str = render_csv_report(report)
        # us-east-1 should appear unprefixed (the leading char `u`
        # is not in the formula-lead set)
        for line in csv_str.split("\n"):
            if "us-east-1" in line:
                assert "'us-east-1" not in line, f"Safe value should not be prefixed: {line!r}"


class TestRenderCsvReport:
    def test_csv_header_and_rows(self) -> None:
        vendors = [
            _make_vendor("A", region="us-east-1"),
            _make_vendor("B", region="us-east-1"),
            _make_vendor("C", region="eu-west-1"),
        ]
        report = compute_concentration(vendors, ["region"], threshold=50.0)
        csv_str = render_csv_report(report)
        lines = csv_str.strip().split("\n")
        assert lines[0].rstrip("\r") == ("dimension,value,count,percentage,exceeds_threshold")
        # 2 distinct values → 2 rows + 1 header
        assert len(lines) == 3
        # us-east-1 row should have exceeds_threshold=true (66.7% > 50)
        assert any("us-east-1,2,66.7,true" in line for line in lines)


# ── ConcentrationReport JSON round-trip ────────────────────────────


class TestReportRoundTrip:
    def test_model_dump_then_validate(self) -> None:
        vendors = [_make_vendor("A", region="us-east-1")]
        report = compute_concentration(vendors, ["region"], threshold=10.0)
        data = report.model_dump(mode="json")
        restored = ConcentrationReport.model_validate(data)
        assert restored.total_vendors == 1
        assert restored.threshold == 10.0
        assert restored.dimensions[0].dimension == "region"


# ── SUPPORTED_DIMENSIONS ───────────────────────────────────────────


def test_supported_dimensions_contains_expected() -> None:
    expected = {
        "region",
        "cloud-provider",
        "4th-party",
        "service-category",
        "criticality-tier",
        "regulatory-classification",
    }
    assert frozenset(expected) == SUPPORTED_DIMENSIONS
