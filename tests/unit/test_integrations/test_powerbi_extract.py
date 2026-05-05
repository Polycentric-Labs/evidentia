"""Unit tests for evidentia_integrations.powerbi.extract (v0.7.8 P1.2).

Pure-functional row-builder coverage — no live Power BI required.
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
from evidentia_integrations.powerbi.extract import (
    COLLECTION_RUN_DATASET_SCHEMA,
    GAP_DATASET_SCHEMA,
    RISK_DATASET_SCHEMA,
    _row_value,
    build_collection_run_dataset_rows,
    build_gap_dataset_rows,
    build_risk_dataset_rows,
)


def _gap(**overrides: object) -> ControlGap:
    defaults: dict[str, object] = {
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
    defaults: dict[str, object] = {
        "asset": "PHI database",
        "threat_source": "External attacker",
        "threat_event": "SQL injection extraction of PHI",
        "vulnerability": "Web app has unsanitized SQL input on /search",
        "likelihood": LikelihoodRating.HIGH,
        "likelihood_rationale": "Public-facing endpoint with no WAF.",
        "impact": ImpactRating.HIGH,
        "impact_rationale": "10M PHI records exposed; HIPAA breach.",
        "risk_level": RiskLevel.HIGH,
        "risk_description": "External attacker exploits SQL input.",
        "recommended_controls": ["SI-10", "SC-7"],
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
        filter_applied={"account": "ACME-PROD"},
    )


# ── TestRowValue ───────────────────────────────────────────────────


class TestRowValue:
    def test_none_to_none(self) -> None:
        assert _row_value(None) is None

    def test_bool_to_bool(self) -> None:
        assert _row_value(True) is True
        assert _row_value(False) is False

    def test_int_passthrough(self) -> None:
        assert _row_value(42) == 42

    def test_float_passthrough(self) -> None:
        assert _row_value(3.14) == 3.14

    def test_string_passthrough(self) -> None:
        assert _row_value("hello") == "hello"

    def test_datetime_iso(self) -> None:
        dt = datetime(2026, 5, 1, 12, 30, tzinfo=UTC)
        assert "2026-05-01T12:30" in _row_value(dt)

    def test_list_semicolon_join(self) -> None:
        assert _row_value(["a", "b", "c"]) == "a;b;c"

    def test_enum_value(self) -> None:
        assert _row_value(GapSeverity.HIGH) == "high"

    def test_list_with_nones_filters(self) -> None:
        """v0.7.13 P3 LOW item 5 closure: None elements in lists
        are filtered before join, not stringified as 'None'."""
        assert _row_value([None, "x", None, "y"]) == "x;y"

    def test_empty_list_yields_empty_string(self) -> None:
        assert _row_value([]) == ""

    def test_tuple_treated_like_list(self) -> None:
        """list and tuple share the same join branch."""
        assert _row_value(("a", "b")) == "a;b"

    def test_nested_list_recurses(self) -> None:
        """A list inside a list still gets stringified (the inner
        list takes the list branch + joins; outer wraps that
        result)."""
        result = _row_value([["a", "b"], "c"])
        # Outer list joins with semi-colon; inner list also joins
        # with semi-colon; the outer result becomes "a;b;c".
        assert result == "a;b;c"

    def test_unknown_type_falls_back_to_str(self) -> None:
        """Type the helper doesn't recognize → str() fallback.

        Covers the line 64 fallback path. A class instance
        without isoformat()/.value/numeric type should land on
        the final return.
        """
        class Custom:
            def __str__(self) -> str:
                return "custom-repr"

        assert _row_value(Custom()) == "custom-repr"

    def test_pydantic_model_with_value_field_does_not_match_enum_branch(
        self,
    ) -> None:
        """v0.7.13 P3 LOW items 7+8: a Pydantic model with a
        ``value`` field should NOT take the Enum branch (which
        was the duck-typing collision the v0.7.13 fix tightened
        away)."""
        from pydantic import BaseModel

        class FakeWithValue(BaseModel):
            value: str = "should-not-leak"

        result = _row_value(FakeWithValue())
        # The Pydantic model takes the str() fallback, NOT the
        # value-extraction branch.
        assert "should-not-leak" not in result or result.startswith(
            "value="
        ) or result.startswith("FakeWithValue")


# ── TestSchemas ────────────────────────────────────────────────────


class TestSchemas:
    def test_gap_schema_columns_unique(self) -> None:
        names = [c["name"] for c in GAP_DATASET_SCHEMA]
        assert len(names) == len(set(names))

    def test_risk_schema_columns_unique(self) -> None:
        names = [c["name"] for c in RISK_DATASET_SCHEMA]
        assert len(names) == len(set(names))

    def test_collection_run_schema_columns_unique(self) -> None:
        names = [c["name"] for c in COLLECTION_RUN_DATASET_SCHEMA]
        assert len(names) == len(set(names))

    def test_all_schemas_use_supported_data_types(self) -> None:
        # Power BI Push Datasets accept these types per the public
        # API docs.
        valid_types = {
            "String",
            "Datetime",
            "Boolean",
            "Int64",
            "Double",
        }
        for schema in (
            GAP_DATASET_SCHEMA,
            RISK_DATASET_SCHEMA,
            COLLECTION_RUN_DATASET_SCHEMA,
        ):
            for col in schema:
                assert col["dataType"] in valid_types

    def test_gap_schema_includes_priority_score_double(self) -> None:
        priority = next(
            c for c in GAP_DATASET_SCHEMA if c["name"] == "priority_score"
        )
        assert priority["dataType"] == "Double"


# ── TestGapRows ────────────────────────────────────────────────────


class TestGapRows:
    def test_one_row_per_gap(self) -> None:
        report = _report([_gap(), _gap(control_id="AC-3")])
        rows = build_gap_dataset_rows(report)
        assert len(rows) == 2

    def test_empty_report_empty_rows(self) -> None:
        rows = build_gap_dataset_rows(_report([]))
        assert rows == []

    def test_row_has_every_schema_column(self) -> None:
        rows = build_gap_dataset_rows(_report([_gap()]))
        row_keys = set(rows[0].keys())
        schema_keys = {c["name"] for c in GAP_DATASET_SCHEMA}
        # Every schema column should be in the row dict.
        assert schema_keys == row_keys

    def test_severity_serialized_as_string_value(self) -> None:
        rows = build_gap_dataset_rows(
            _report([_gap(gap_severity=GapSeverity.CRITICAL)])
        )
        assert rows[0]["gap_severity"] == "critical"

    def test_status_serialized_as_string_value(self) -> None:
        rows = build_gap_dataset_rows(
            _report([_gap(status=GapStatus.IN_PROGRESS)])
        )
        assert rows[0]["status"] == "in_progress"

    def test_lists_semicolon_joined(self) -> None:
        rows = build_gap_dataset_rows(
            _report(
                [
                    _gap(
                        equivalent_controls_in_inventory=[
                            "EVIDENTIA-AC-2",
                            "ABC-1",
                        ],
                        cross_framework_value=[
                            "soc2-tsc:CC6.1",
                        ],
                    )
                ]
            )
        )
        assert rows[0]["equivalent_controls"] == "EVIDENTIA-AC-2;ABC-1"
        assert rows[0]["cross_framework_satisfies"] == "soc2-tsc:CC6.1"

    def test_priority_score_remains_float(self) -> None:
        rows = build_gap_dataset_rows(_report([_gap()]))
        assert isinstance(rows[0]["priority_score"], float)


# ── TestRiskRows ───────────────────────────────────────────────────


class TestRiskRows:
    def test_one_row_per_risk(self) -> None:
        rows = build_risk_dataset_rows(
            [_risk(), _risk(asset="PCI cardholder data store")]
        )
        assert len(rows) == 2

    def test_empty_iterable_empty_rows(self) -> None:
        assert build_risk_dataset_rows([]) == []

    def test_row_has_every_schema_column(self) -> None:
        rows = build_risk_dataset_rows([_risk()])
        row_keys = set(rows[0].keys())
        schema_keys = {c["name"] for c in RISK_DATASET_SCHEMA}
        assert schema_keys == row_keys

    def test_remediation_priority_int(self) -> None:
        rows = build_risk_dataset_rows([_risk(remediation_priority=2)])
        assert rows[0]["remediation_priority"] == 2

    def test_treatment_serialized_as_string_value(self) -> None:
        rows = build_risk_dataset_rows(
            [_risk(treatment=RiskTreatment.MITIGATE)]
        )
        assert rows[0]["treatment"] == "mitigate"

    def test_no_generation_context_blank_provenance(self) -> None:
        rows = build_risk_dataset_rows([_risk()])
        # No generation_context attached → temperature/prompt_hash/
        # run_id should be None.
        assert rows[0]["temperature"] is None
        assert rows[0]["prompt_hash"] is None
        assert rows[0]["run_id"] is None


# ── TestCollectionRunRows ──────────────────────────────────────────


class TestCollectionRunRows:
    def test_one_row_per_context(self) -> None:
        rows = build_collection_run_dataset_rows([_ctx(), _ctx()])
        assert len(rows) == 2

    def test_filter_applied_is_json_string(self) -> None:
        import json

        rows = build_collection_run_dataset_rows([_ctx()])
        decoded = json.loads(rows[0]["filter_applied"])
        assert decoded["account"] == "ACME-PROD"

    def test_credential_identity_does_not_leak_secret(self) -> None:
        rows = build_collection_run_dataset_rows([_ctx()])
        # Identity, not secret.
        assert "EVIDENTIA_AUDIT_RO" in rows[0]["credential_identity"]
        # No high-entropy strings expected.
        assert "sk-" not in str(rows)
