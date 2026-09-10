"""DLP preflight and interpretation against the shared admission ledger."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

import pytest
from evidentia_collectors.entra_m365._client import EntraM365GraphReader
from evidentia_collectors.entra_m365._contracts import (
    EntraM365CollectRequest,
    EntraM365CollectResult,
    EntraM365InputError,
    EntraM365RunContext,
)
from evidentia_collectors.entra_m365.dlp_export import parse_dlp_export, read_dlp_export
from evidentia_core.models.finding import SecurityFinding

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures/entra_m365/purview"
NOW = datetime(2026, 1, 31, tzinfo=UTC)


def observed(finding: SecurityFinding) -> dict[str, Any]:
    assert isinstance(finding.raw_data, dict)
    value = finding.raw_data["observation"]
    assert isinstance(value, dict)
    return value


def policy(identifier: str = "policy-1", **changes: Any) -> dict[str, Any]:
    return {
        "Guid": identifier,
        "Name": "Policy " + identifier,
        "Mode": "Enable",
        "DistributionStatus": "Pending",
        "Workload": "Exchange",
        "Enabled": True,
        "IsValid": True,
        **changes,
    }


def rule(identifier: str = "rule-1", **changes: Any) -> dict[str, Any]:
    return {
        "Guid": identifier,
        "Policy": "policy-1",
        "ParentPolicyName": "Policy policy-1",
        "Mode": "Enforce",
        "Workload": "Exchange",
        "Disabled": False,
        "IsValid": True,
        **changes,
    }


def envelope(policies: list[dict[str, Any]] | None = None, rules: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source": {
            "kind": "authored-synthetic",
            "producer": "Evidentia tests",
            "producer_version": None,
            "captured_at": None,
            "parent_sha256": None,
            "source_uri": None,
            "sanitization": "synthetic",
        },
        "policies": [policy()] if policies is None else policies,
        "rules": [rule()] if rules is None else rules,
    }


def context(request: EntraM365CollectRequest) -> EntraM365RunContext:
    return EntraM365RunContext.start(
        request,
        utc_clock=lambda: NOW,
        monotonic_clock=lambda: 0.0,
        sleep=lambda seconds: None,
        run_id_factory=lambda: "synthetic-dlp-run",
    )


class NoGraph:
    def read_collection(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("DLP must never call Graph")


def collect(value: dict[str, Any], *, max_items: int = 10000) -> EntraM365CollectResult:
    request = EntraM365CollectRequest(tenant_label="synthetic", capabilities=["dlp-export"], max_items=max_items)
    run = context(request)
    export = parse_dlp_export(json.dumps(value), format="evidentia-dlp-v1")
    read = read_dlp_export(request, cast(EntraM365GraphReader, NoGraph()), run, export)
    result = run.build_result([read])
    return EntraM365CollectResult.model_validate_json(result.model_dump_json())


def test_recorded_pending_inventory_is_complete_and_preserves_all_fields() -> None:
    value = json.loads((FIXTURES / "cisa-dlp-recorded.json").read_text(encoding="utf-8"))
    result = collect(value)
    cap = result.capabilities[6]
    assert (
        result.status,
        cap.scanned,
        cap.matched_filter,
        cap.collected,
        cap.pages_completed,
        cap.requests_attempted,
    ) == ("complete", 26, 26, 11, 1, 0)
    assert cap.credential_basis == "unverified:dlp-export"
    assert cap.declared_auth_mode is None
    observations = [observed(item) for item in result.findings]
    assert Counter(item["configuration_state"] for item in observations) == {
        "disabled": 7,
        "configured_enforce": 2,
        "test": 2,
    }
    assert all(item["distribution_status"] == "Pending" for item in observations)
    assert [item.raw_data["source"] for item in result.findings] == value["policies"]
    actual_rules = [row["source"] for item in observations for row in item["rules"]]
    assert len(actual_rules) == 15
    assert {row["Guid"]: row for row in actual_rules} == {row["Guid"]: row for row in value["rules"]}
    assert sum(len(row) for row in value["policies"] + value["rules"]) == 182
    assert all(item["export_source"] == value["source"] for item in observations)
    assert all(
        item.compliance_status.value == "unknown"
        and item.severity.value == "informational"
        and item.status.value == "active"
        for item in result.findings
    )
    assert result.manifest.is_complete and not result.full_surface_complete


@pytest.mark.parametrize(
    ("mode", "enabled", "valid", "expected", "diagnostic"),
    [
        ("Disable", False, True, "disabled", None),
        ("Enable", True, True, "configured_enforce", None),
        ("TestWithNotifications", True, True, "test", None),
        ("TestWithoutNotifications", True, True, "test", None),
        ("Disable", True, True, "unknown", "conflicting_state"),
        ("Enable", False, True, "unknown", "conflicting_state"),
        ("TestWithNotifications", False, True, "unknown", "conflicting_state"),
        ("TestWithoutNotifications", False, True, "unknown", "conflicting_state"),
        ("Enable", None, True, "unknown", None),
        (None, True, True, "unknown", None),
        ("NEW_VENDOR_MODE", True, True, "unknown", None),
        ("Enable", True, False, "unknown", "source_validity_unknown"),
        ("Enable", True, None, "unknown", "source_validity_unknown"),
    ],
)
def test_policy_state_is_conservative(
    mode: object, enabled: object, valid: object, expected: str, diagnostic: str | None
) -> None:
    result = collect(envelope([policy(Mode=mode, Enabled=enabled, IsValid=valid)], []))
    assert observed(result.findings[0])["configuration_state"] == expected
    assert result.status == ("partial" if diagnostic else "complete")
    assert {item.code for item in result.capabilities[6].diagnostics} == ({diagnostic} if diagnostic else set())


@pytest.mark.parametrize(
    ("mode", "enabled", "disabled", "valid", "rule_mode", "expected", "partial"),
    [
        ("Enable", True, False, True, "Enforce", "configured_enforce", False),
        ("Enable", True, True, True, "Enforce", "disabled", False),
        ("Disable", False, False, True, "Enforce", "disabled", False),
        ("TestWithNotifications", True, False, True, "Enforce", "test", False),
        ("Enable", True, None, True, "Enforce", "unknown", False),
        ("Enable", True, False, True, "NEW_MODE", "unknown", False),
        ("Enable", True, False, False, "Enforce", "unknown", True),
        ("Enable", True, False, None, "Enforce", "unknown", True),
    ],
)
def test_rule_flags_never_override_parent(
    mode: str, enabled: bool, disabled: bool | None, valid: bool | None, rule_mode: str, expected: str, partial: bool
) -> None:
    result = collect(
        envelope([policy(Mode=mode, Enabled=enabled)], [rule(Disabled=disabled, IsValid=valid, Mode=rule_mode)])
    )
    assert observed(result.findings[0])["rules"][0]["configuration_state"] == expected
    assert result.status == ("partial" if partial else "complete")


@pytest.mark.parametrize(
    "changes",
    [
        {"Policy": None},
        {"Policy": "missing"},
        {"Policy": "Policy policy-1"},
        {"ParentPolicyName": "wrong"},
        {"Policy": " policy-1"},
    ],
)
def test_unresolved_rule_is_standalone_and_never_guessed(changes: dict[str, Any]) -> None:
    source_rule = rule(**changes)
    result = collect(envelope(rules=[source_rule]))
    assert result.status == "partial"
    assert len(result.findings) == 2
    assert observed(result.findings[0])["rules"] == []
    assert result.findings[1].source_finding_id == "synthetic:dlp-export:unresolved-rule:rule-1"
    assert result.findings[1].raw_data["source"] == source_rule
    assert observed(result.findings[1])["configuration_state"] == "unknown"
    assert [(item.code, item.count) for item in result.capabilities[6].diagnostics] == [("unresolved_parent", 1)]


def test_parser_validates_full_envelope_without_rejecting_duplicate_ids() -> None:
    value = envelope([policy(), policy(), policy(Mode="Disable", Enabled=False)])
    parsed = parse_dlp_export(json.dumps(value), format="evidentia-dlp-v1")
    assert len(parsed.policies) == 3
    result = collect(value)
    assert result.status == "partial"
    assert result.capabilities[6].duplicate_records == 1
    assert result.capabilities[6].matched_filter == 1
    assert len(result.findings) == 1
    assert result.findings[0].source_finding_id == "synthetic:dlp-export:unresolved-rule:rule-1"
    assert {item.code for item in result.capabilities[6].diagnostics} == {"conflicting_duplicate", "unresolved_parent"}


@pytest.mark.parametrize(
    ("cap", "expected_policies", "expected_rules", "status"),
    [(1, 1, 0, "partial"), (2, 2, 0, "partial"), (3, 2, 1, "partial"), (4, 2, 2, "complete")],
)
def test_policy_first_combined_admission_never_embeds_unadmitted_rules(
    cap: int, expected_policies: int, expected_rules: int, status: str
) -> None:
    value = envelope(
        [policy(), policy("policy-2")], [rule(), rule("rule-2", Policy="policy-2", ParentPolicyName="Policy policy-2")]
    )
    result = collect(value, max_items=cap)
    assert result.status == status
    assert len(result.findings) == expected_policies
    assert sum(len(observed(item)["rules"]) for item in result.findings) == expected_rules
    assert result.capabilities[6].scanned == 4
    assert result.capabilities[6].matched_filter == cap


def test_guid_namespace_is_kind_distinct_and_null_parent_name_uses_guid() -> None:
    result = collect(envelope([policy("same")], [rule("same", Policy="same", ParentPolicyName=None)]))
    assert result.status == "complete" and result.capabilities[6].matched_filter == 2
    assert observed(result.findings[0])["rules"][0]["source"]["Guid"] == "same"


def test_empty_export_is_observed_but_missing_export_is_unavailable() -> None:
    empty = collect(envelope([], []))
    assert empty.status == "complete" and not empty.findings
    assert empty.manifest.empty_categories == ["dlp-export"]
    request = EntraM365CollectRequest(tenant_label="synthetic", capabilities=["dlp-export"])
    run = context(request)
    missing = read_dlp_export(request, cast(EntraM365GraphReader, NoGraph()), run)
    result = run.build_result([missing])
    assert result.status == "unavailable" and not result.findings
    assert result.capabilities[6].pages_completed == 0
    assert [item.code for item in result.capabilities[6].diagnostics] == ["input_missing"]
    assert result.manifest.empty_categories == []


@pytest.mark.parametrize("field", ["schema_version", "source", "policies", "rules"])
def test_missing_envelope_field_is_sanitized(field: str) -> None:
    value = envelope()
    del value[field]
    with pytest.raises(EntraM365InputError, match=r"^invalid_field$"):
        parse_dlp_export(json.dumps(value), format="evidentia-dlp-v1")


@pytest.mark.parametrize(
    ("section", "field"),
    [("policies", field) for field in ("Guid", "Name", "Mode", "DistributionStatus", "Workload", "Enabled", "IsValid")]
    + [("rules", field) for field in ("Guid", "Policy", "ParentPolicyName", "Mode", "Workload", "Disabled", "IsValid")],
)
def test_missing_selected_fields_are_input_errors_even_on_final_rule(section: str, field: str) -> None:
    value = envelope(rules=[rule(), rule("last")])
    del value[section][-1][field]
    with pytest.raises(EntraM365InputError, match=r"^invalid_field$"):
        parse_dlp_export(json.dumps(value), format="evidentia-dlp-v1")


@pytest.mark.parametrize("value", [True, "1", 1.0, 0, 2, None])
def test_schema_version_is_strict(value: object) -> None:
    data = envelope()
    data["schema_version"] = value
    with pytest.raises(EntraM365InputError, match=r"^invalid_field$"):
        parse_dlp_export(json.dumps(data), format="evidentia-dlp-v1")


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("policies", "Enabled", 1),
        ("policies", "IsValid", "true"),
        ("rules", "Disabled", 0),
        ("rules", "IsValid", 1.0),
        ("policies", "Name", " \t"),
        ("policies", "Guid", ""),
        ("rules", "Policy", " "),
        ("rules", "ParentPolicyName", "x" * 513),
        ("policies", "Mode", "x" * 129),
        ("rules", "Workload", []),
    ],
)
def test_wrong_selected_scalar_types_and_bounds_reject(section: str, field: str, value: object) -> None:
    data = envelope()
    data[section][0][field] = value
    with pytest.raises(EntraM365InputError, match=r"^invalid_field$"):
        parse_dlp_export(json.dumps(data), format="evidentia-dlp-v1")


@pytest.mark.parametrize(
    "suffix",
    [
        ', "dup":1, "dup":2}',
        ', "ignored":NaN}',
        ', "ignored":Infinity}',
        ', "ignored":1e9999}',
        ', "ignored":' + "[" * 33 + "0" + "]" * 33 + "}",
    ],
)
def test_strict_json_rejects_invalid_discarded_provider_fields(suffix: str) -> None:
    raw = '{"dlp_compliance_policies":[],"dlp_compliance_rules":[]' + suffix
    with pytest.raises(EntraM365InputError, match=r"^invalid_body$"):
        parse_dlp_export(raw, format="scubagear-provider-v1")


def test_byte_limit_utf8_and_safe_error_messages() -> None:
    for raw, code in [
        (" " * 4194305, "response_limit"),
        ('"' + "\u00e9" * 2097152 + '"', "response_limit"),
        ("\ud800", "invalid_body"),
        ('{"SENSITIVE_INPUT":', "invalid_body"),
    ]:
        with pytest.raises(EntraM365InputError) as exc:
            parse_dlp_export(raw, format="evidentia-dlp-v1")
        assert exc.value.code == code and str(exc.value) == code
    with pytest.raises(EntraM365InputError, match=r"^invalid_field$"):
        parse_dlp_export(json.dumps(envelope()), format=cast(Any, "guessed"))


def test_provider_adapter_projects_only_selected_fields_and_hashes_actual_input() -> None:
    value = {
        "dlp_compliance_policies": [policy(Id="not-a-guid", Identity="not-a-guid", AdvancedRule="DO_NOT_EXECUTE")],
        "dlp_compliance_rules": [rule(Recipients=["DO_NOT_PERSIST"])],
        "dlp_policies": [{"wrong": "unrelated"}],
    }
    raw = json.dumps(value, indent=2)
    export = parse_dlp_export(raw, format="scubagear-provider-v1")
    assert export.policies[0].model_dump() == policy()
    assert export.rules[0].model_dump() == rule()
    assert export.source.model_dump() == {
        "kind": "operator-export",
        "producer": "ScubaGear",
        "producer_version": None,
        "captured_at": None,
        "source_uri": None,
        "parent_sha256": sha256(raw.encode()).hexdigest(),
        "sanitization": "operator-declared",
    }
    assert "DO_NOT_" not in export.model_dump_json()
    assert "not-a-guid" not in export.model_dump_json()
    with pytest.raises(EntraM365InputError):
        parse_dlp_export(raw, format="evidentia-dlp-v1")
    with pytest.raises(EntraM365InputError):
        parse_dlp_export(json.dumps({"dlp_policies": [], "dlp_compliance_rules": []}), format="scubagear-provider-v1")


@pytest.mark.parametrize("parent_name", [None, "same name"])
def test_duplicate_policy_names_only_block_supplied_name_cross_check(parent_name: str | None) -> None:
    result = collect(
        envelope([policy(Name="same name"), policy("policy-2", Name="same name")], [rule(ParentPolicyName=parent_name)])
    )
    assert result.status == ("complete" if parent_name is None else "partial")
    assert len(result.findings) == (2 if parent_name is None else 3)
    assert len(observed(result.findings[0])["rules"]) == (1 if parent_name is None else 0)


def test_captured_time_retains_source_precision_and_does_not_change_inventory() -> None:
    value = envelope()
    value["source"]["captured_at"] = "2026-01-30t23:59:59.999999900z"
    value["source"]["source_uri"] = "file:///DO_NOT_READ"
    result = collect(value)
    observation = observed(result.findings[0])
    assert observation["export_source"] == value["source"]
    assert observation["source_age_seconds"] == "0.0000001"
    assert result.status == "complete"
    value["source"]["captured_at"] = "2026-01-31T00:00:00.000000000001Z"
    result = collect(value)
    assert observed(result.findings[0])["source_age_seconds"] is None
    assert result.status == "complete"
    assert [item.code for item in result.capabilities[6].diagnostics] == ["future_timestamp"]


@pytest.mark.parametrize(
    "captured", ["2026-01-01", "2026-01-01T00:00:00", "2026-02-30T00:00:00Z", "2026-01-31T00:00:60Z"]
)
def test_invalid_export_time_rejects_before_admission(captured: str) -> None:
    value = envelope()
    value["source"]["captured_at"] = captured
    with pytest.raises(EntraM365InputError, match=r"^invalid_field$"):
        parse_dlp_export(json.dumps(value), format="evidentia-dlp-v1")


def test_authored_negative_fixture_keeps_conflicts_distinct() -> None:
    value = json.loads((FIXTURES / "dlp-contradictions-synthetic.json").read_text(encoding="utf-8"))
    result = collect(value)
    assert result.status == "partial" and len(result.findings) == 2
    assert {item.code for item in result.capabilities[6].diagnostics} == {"conflicting_state", "unresolved_parent"}
    assert observed(result.findings[0])["configuration_state"] == "unknown"
    assert observed(result.findings[0])["rules"] == []
    assert result.findings[1].raw_data["source"] == value["rules"][0]
    raw = (FIXTURES / "dlp-invalid-flag-synthetic.json").read_text(encoding="utf-8")
    with pytest.raises(EntraM365InputError, match=r"^invalid_field$"):
        parse_dlp_export(raw, format="evidentia-dlp-v1")


def test_conflict_after_admission_cap_cannot_leave_a_policy_or_attached_rules() -> None:
    value = envelope([policy(), policy("overflow"), policy(Name="changed")], [rule()])
    result = collect(value, max_items=1)
    assert result.status == "partial" and not result.findings
    assert result.capabilities[6].matched_filter == 0
    assert {item.code for item in result.capabilities[6].diagnostics} == {"item_limit", "conflicting_duplicate"}
    assert result.manifest.empty_categories == []


def test_duplicate_rule_variants_never_restore_quarantined_evidence() -> None:
    result = collect(envelope(rules=[rule(), rule(Disabled=True), rule()]))
    cap = result.capabilities[6]
    assert (cap.scanned, cap.matched_filter, cap.duplicate_records) == (4, 1, 1)
    assert result.status == "partial"
    assert len(result.findings) == 1 and observed(result.findings[0])["rules"] == []
    assert [(item.code, item.count) for item in cap.diagnostics] == [("conflicting_duplicate", 1)]


def test_repeated_valid_rule_coalesces_and_exact_cap_is_complete() -> None:
    result = collect(envelope(rules=[rule(), rule()]), max_items=2)
    assert result.status == "complete"
    assert result.capabilities[6].duplicate_records == 1
    assert len(observed(result.findings[0])["rules"]) == 1


def test_unresolved_rules_count_independently_and_cannot_replace_policy_coverage() -> None:
    result = collect(envelope(rules=[rule("a", Policy=None), rule("b", Policy="missing", IsValid=None)]))
    cap = result.capabilities[6]
    assert len(result.findings) == 3 and cap.collected == 3
    assert {item.code: item.count for item in cap.diagnostics} == {"unresolved_parent": 2, "source_validity_unknown": 1}
    assert result.findings[0].resource_type == "MicrosoftPurview::DlpPolicy"
    for finding in result.findings[1:]:
        assert [mapping.control_id for mapping in finding.control_mappings] == ["AC-4"]
        assert all(mapping.relationship == "related-to" for mapping in finding.control_mappings)


def test_literal_identity_and_container_ownership_survive_round_trip() -> None:
    value = envelope(
        [policy(" literal ", Name=" name ")], [rule(" rule ", Policy=" literal ", ParentPolicyName=" name ")]
    )
    result = collect(value)
    assert result.status == "complete"
    assert result.findings[0].source_finding_id == "synthetic:dlp-export:policy: literal "
    observation = observed(result.findings[0])
    assert observation["rules"][0]["source"]["Guid"] == " rule "
    observation["rules"][0]["source"]["Guid"] = "caller mutation"
    value["policies"][0]["Name"] = "caller mutation"
    next_result = collect(envelope())
    assert "caller mutation" not in next_result.model_dump_json()
    assert next_result.findings[0].collection_context.run_id == "synthetic-dlp-run"


@pytest.mark.parametrize(
    ("section", "value"),
    [("policies", None), ("rules", {}), ("rules", "bad"), ("policies", [None]), ("rules", [False])],
)
def test_invalid_array_envelopes_are_not_empty_success(section: str, value: object) -> None:
    data = envelope()
    data[section] = value
    with pytest.raises(EntraM365InputError, match=r"^invalid_field$"):
        parse_dlp_export(json.dumps(data), format="evidentia-dlp-v1")


@pytest.mark.parametrize("section", ["policies", "rules"])
def test_each_array_has_a_hard_structural_limit(section: str) -> None:
    data = envelope([], [])
    row = policy() if section == "policies" else rule()
    data[section] = [row] * 10001
    with pytest.raises(EntraM365InputError, match=r"^invalid_field$"):
        parse_dlp_export(json.dumps(data), format="evidentia-dlp-v1")


@pytest.mark.parametrize("location", ["envelope", "source", "policies", "rules"])
def test_normalized_extra_fields_never_survive(location: str) -> None:
    value = envelope()
    target = value if location == "envelope" else value[location] if location == "source" else value[location][0]
    target["SENSITIVE_EXTRA_KEY"] = "SENSITIVE_INPUT"
    with pytest.raises(EntraM365InputError) as exc:
        parse_dlp_export(json.dumps(value), format="evidentia-dlp-v1")
    assert str(exc.value) == "invalid_field"


def test_parser_does_not_read_source_uri_or_change_working_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = envelope()
    path = tmp_path / "untouched.txt"
    path.write_text("original", encoding="utf-8")
    value["source"]["source_uri"] = path.as_uri()
    original_open = Path.open

    def refuse_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Export source metadata must never become a file read")

    monkeypatch.setattr(Path, "open", refuse_open)
    export = parse_dlp_export(json.dumps(value), format="evidentia-dlp-v1")
    assert export.source.source_uri == path.as_uri()
    monkeypatch.setattr(Path, "open", original_open)
    assert path.read_text(encoding="utf-8") == "original"
