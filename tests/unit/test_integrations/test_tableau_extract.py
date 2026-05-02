"""Unit tests for evidentia_integrations.tableau.extract (v0.7.8 P1.1).

Pure-functional CSV-builder coverage — no live Tableau required.
"""

from __future__ import annotations

from datetime import UTC, datetime

from evidentia_core.audit import CollectionContext
from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    GapStatus,
    ImplementationEffort,
)
from evidentia_core.models.risk import (
    ImpactRating,
    LikelihoodRating,
    RiskLevel,
    RiskStatement,
    RiskTreatment,
)
from evidentia_integrations.tableau.extract import (
    build_collection_run_dataset_csv,
    build_gap_dataset_csv,
    build_risk_dataset_csv,
)


def _gap(**overrides: object) -> ControlGap:
    defaults = {
        "framework": "nist-800-53-rev5-moderate",
        "control_id": "AC-2",
        "control_title": "Account Management",
        "control_description": "Manage information system accounts.",
        "gap_severity": GapSeverity.HIGH,
        "implementation_status": "missing",
        "gap_description": "No centralized account-management process.",
        "remediation_guidance": "Deploy Okta with quarterly access reviews.",
        "implementation_effort": ImplementationEffort.MEDIUM,
    }
    defaults.update(overrides)
    return ControlGap(**defaults)  # type: ignore[arg-type]


def _report(gaps: list[ControlGap]) -> GapAnalysisReport:
    severities = [g.gap_severity for g in gaps]
    return GapAnalysisReport(
        organization="ACME Corp",
        frameworks_analyzed=["nist-800-53-rev5-moderate"],
        total_controls_required=300,
        total_controls_in_inventory=250,
        total_gaps=len(gaps),
        critical_gaps=severities.count(GapSeverity.CRITICAL),
        high_gaps=severities.count(GapSeverity.HIGH),
        medium_gaps=severities.count(GapSeverity.MEDIUM),
        low_gaps=severities.count(GapSeverity.LOW),
        coverage_percentage=83.3,
        gaps=gaps,
    )


def _risk(**overrides: object) -> RiskStatement:
    defaults = {
        "asset": "PHI database",
        "threat_source": "External attacker",
        "threat_event": "SQL injection extraction of PHI",
        "vulnerability": "Web app has unsanitized SQL input on /search",
        "likelihood": LikelihoodRating.HIGH,
        "likelihood_rationale": (
            "Public-facing endpoint with no WAF and no input validation."
        ),
        "impact": ImpactRating.HIGH,
        "impact_rationale": (
            "10M PHI records exposed; HIPAA reportable; class action risk."
        ),
        "risk_level": RiskLevel.HIGH,
        "risk_description": (
            "External attacker exploits unsanitized SQL input on /search "
            "to extract 10M PHI records, triggering HIPAA breach reporting."
        ),
        "recommended_controls": ["SI-10", "SC-7", "AU-2"],
        "remediation_priority": 1,
    }
    defaults.update(overrides)
    return RiskStatement(**defaults)  # type: ignore[arg-type]


def _ctx() -> CollectionContext:
    return CollectionContext(
        collector_id="snowflake-scan",
        collector_version="0.7.7.1",
        run_id="01JZTVE9X2N9R6MJV1NWQM5ZC0",
        credential_identity="snowflake-user:EVIDENTIA_AUDIT_RO",
        source_system_id="snowflake:ACME-PROD",
        filter_applied={
            "account": "ACME-PROD",
            "user": "EVIDENTIA_AUDIT_RO",
        },
    )


# ── TestGapDataset ─────────────────────────────────────────────────


class TestGapDataset:
    def test_emits_header_row(self) -> None:
        report = _report([_gap()])
        csv_bytes = build_gap_dataset_csv(report)
        text = csv_bytes.decode("utf-8")
        first = text.splitlines()[0]
        assert first.startswith("gap_id,organization,analyzed_at,framework")
        assert "remediation_guidance" in first

    def test_one_data_row_per_gap(self) -> None:
        report = _report([_gap(), _gap(control_id="AC-3")])
        csv_bytes = build_gap_dataset_csv(report)
        # 1 header + 2 data rows
        assert len(csv_bytes.decode("utf-8").splitlines()) == 3

    def test_empty_gaps_just_header(self) -> None:
        report = _report([])
        csv_bytes = build_gap_dataset_csv(report)
        assert len(csv_bytes.decode("utf-8").splitlines()) == 1

    def test_severity_serialized_as_string_value(self) -> None:
        report = _report(
            [_gap(gap_severity=GapSeverity.CRITICAL)]
        )
        text = build_gap_dataset_csv(report).decode("utf-8")
        assert "critical" in text  # not GapSeverity.CRITICAL repr

    def test_status_lifecycle_emitted(self) -> None:
        report = _report(
            [_gap(status=GapStatus.IN_PROGRESS)]
        )
        text = build_gap_dataset_csv(report).decode("utf-8")
        assert "in_progress" in text

    def test_list_columns_semicolon_joined(self) -> None:
        report = _report(
            [
                _gap(
                    equivalent_controls_in_inventory=["EVIDENTIA-AC-2", "ABC-1"],
                    cross_framework_value=[
                        "soc2-tsc:CC6.1",
                        "iso27001:A.9.2.1",
                    ],
                )
            ]
        )
        text = build_gap_dataset_csv(report).decode("utf-8")
        assert "EVIDENTIA-AC-2;ABC-1" in text
        assert "soc2-tsc:CC6.1;iso27001:A.9.2.1" in text

    def test_iso8601_timestamps(self) -> None:
        report = _report([_gap()])
        text = build_gap_dataset_csv(report).decode("utf-8")
        # analyzed_at datetime must be ISO 8601 with timezone
        assert "+00:00" in text or "Z" in text

    def test_organization_and_analyzed_at_denormalized(self) -> None:
        report = _report([_gap(), _gap(control_id="AC-3")])
        text = build_gap_dataset_csv(report).decode("utf-8")
        # Both data rows should include the org name
        assert text.count("ACME Corp") == 2


# ── TestRiskDataset ────────────────────────────────────────────────


class TestRiskDataset:
    def test_header_includes_provenance_columns(self) -> None:
        text = build_risk_dataset_csv([]).decode("utf-8")
        first = text.splitlines()[0]
        for col in [
            "risk_id",
            "asset",
            "threat_source",
            "vulnerability",
            "likelihood",
            "impact",
            "risk_level",
            "treatment",
            "model_used",
            "temperature",
            "prompt_hash",
            "run_id",
        ]:
            assert col in first

    def test_risks_serialized_to_rows(self) -> None:
        risks = [_risk(), _risk(asset="Customer data warehouse")]
        csv_bytes = build_risk_dataset_csv(risks)
        text = csv_bytes.decode("utf-8")
        assert "PHI database" in text
        assert "Customer data warehouse" in text
        # 1 header + 2 data rows
        assert len(text.splitlines()) == 3

    def test_treatment_serialized_as_string_value(self) -> None:
        risk = _risk(treatment=RiskTreatment.MITIGATE)
        text = build_risk_dataset_csv([risk]).decode("utf-8")
        assert "mitigate" in text

    def test_recommended_controls_semicolon_joined(self) -> None:
        risk = _risk(recommended_controls=["SI-10", "SC-7", "AU-2"])
        text = build_risk_dataset_csv([risk]).decode("utf-8")
        assert "SI-10;SC-7;AU-2" in text

    def test_no_generation_context_emits_blank_provenance(self) -> None:
        risk = _risk()  # no generation_context
        text = build_risk_dataset_csv([risk]).decode("utf-8")
        # When no ctx, the trailing temperature/prompt_hash/run_id
        # columns should be empty strings — confirm by checking
        # that the row has the expected number of comma-separated
        # cells (one per fieldname).
        rows = text.splitlines()
        # field count == 23
        assert text.splitlines()[0].count(",") == 22
        # Data row should still have 22 commas (some cells may be
        # empty but the column count is fixed).
        assert rows[1].count(",") >= 22


# ── TestCollectionRunDataset ───────────────────────────────────────


class TestCollectionRunDataset:
    def test_header_present(self) -> None:
        text = build_collection_run_dataset_csv([]).decode("utf-8")
        first = text.splitlines()[0]
        for col in [
            "run_id",
            "collector_id",
            "collector_version",
            "collected_at",
            "credential_identity",
            "source_system_id",
            "filter_applied",
            "evidentia_version",
        ]:
            assert col in first

    def test_one_row_per_context(self) -> None:
        text = build_collection_run_dataset_csv(
            [_ctx(), _ctx()]
        ).decode("utf-8")
        # 1 header + 2 rows
        assert len(text.splitlines()) == 3

    def test_filter_applied_is_json(self) -> None:
        text = build_collection_run_dataset_csv([_ctx()]).decode(
            "utf-8"
        )
        # The CSV writer escapes embedded double-quotes by doubling
        # them. Check the JSON tokens appear in CSV-escaped form.
        assert '""account"": ""ACME-PROD""' in text
        # Round-trip via Python's csv module to verify the JSON
        # dict is recoverable cleanly.
        import csv
        import io
        import json

        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        assert len(rows) == 1
        parsed = json.loads(rows[0]["filter_applied"])
        assert parsed["account"] == "ACME-PROD"
        assert parsed["user"] == "EVIDENTIA_AUDIT_RO"

    def test_credential_identity_does_not_leak_secret(self) -> None:
        # Defense-in-depth: CollectionContext.credential_identity
        # is the principal name, never the secret. Confirm.
        text = build_collection_run_dataset_csv([_ctx()]).decode(
            "utf-8"
        )
        # No high-entropy strings or 'sk-...' patterns expected.
        assert "EVIDENTIA_AUDIT_RO" in text
        assert "sk-" not in text


# ── TestSerializerEdgeCases ────────────────────────────────────────


class TestSerializerEdgeCases:
    def test_none_emits_empty_string(self) -> None:
        from evidentia_integrations.tableau.extract import _serialize

        assert _serialize(None) == ""

    def test_bool_lowercase(self) -> None:
        from evidentia_integrations.tableau.extract import _serialize

        assert _serialize(True) == "true"
        assert _serialize(False) == "false"

    def test_datetime_iso_8601(self) -> None:
        from evidentia_integrations.tableau.extract import _serialize

        dt = datetime(2026, 5, 1, 12, 30, tzinfo=UTC)
        assert "2026-05-01T12:30" in _serialize(dt)
        assert "+00:00" in _serialize(dt)

    def test_list_semicolon_join(self) -> None:
        from evidentia_integrations.tableau.extract import _serialize

        assert _serialize(["a", "b", "c"]) == "a;b;c"

    def test_nested_list_semicolon_join(self) -> None:
        from evidentia_integrations.tableau.extract import _serialize

        # The nested-list contract isn't deeply spec'd; just confirm
        # it doesn't crash.
        result = _serialize([["a", "b"], ["c"]])
        assert "a" in result and "b" in result and "c" in result
