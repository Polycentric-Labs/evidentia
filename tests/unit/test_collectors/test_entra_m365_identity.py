"""Synthetic transport acceptance for Entra identity observations."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from evidentia_collectors.entra_m365._contracts import EntraM365CollectResult
from evidentia_collectors.entra_m365.identity import (
    read_authentication_registration,
    read_conditional_access,
    read_directory_roles,
    read_sign_ins,
)

from .entra_m365._transport_support import (
    CA_PATH,
    NOW,
    ORIGIN,
    PRIMARY,
    SIGN_PATH,
    Reply,
    assert_closed,
    codes,
    encode_page,
    sign_in,
)
from .entra_m365.conftest import make_run as make_run
from .entra_m365.conftest import runtime as runtime

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "entra_m365" / "identity"
READERS = {
    "conditional-access": read_conditional_access,
    "authentication-registration": read_authentication_registration,
    "sign-ins": read_sign_ins,
    "directory-roles": read_directory_roles,
}


def _fixture_run(make_run, capability):
    fixture = json.loads((FIXTURES / f"{capability}.json").read_text(encoding="utf-8"))
    assert fixture["kind"] == "authored-synthetic"
    replies = [
        Reply(json.dumps(row["body"]).encode(), status=row["status"], headers=row["headers"])
        for row in fixture["exchanges"]
    ]
    run = make_run(replies, capabilities=[capability], request_fields={"lookback_days": fixture["lookback_days"]})
    read = READERS[capability](run.request, run.reader, run.context)
    assert len(run.scenario.requests) == len(fixture["exchanges"])
    for actual, expected in zip(run.scenario.requests, fixture["exchanges"], strict=True):
        assert actual.method == expected["method"]
        assert actual.url.host == "graph.microsoft.com"
        assert actual.url.path == expected["route"]
        assert actual.url.query.decode() == expected["query"]
        assert actual.headers["authorization"] == "Bearer " + PRIMARY
        assert "prefer" not in actual.headers
    assert run.provider.calls == ["primary"]
    assert_closed(run)
    return run, read, fixture


def _wire_result(run, read):
    result = run.context.build_result([read])
    restored = EntraM365CollectResult.model_validate_json(result.model_dump_json())
    assert restored.model_dump_json() == result.model_dump_json()
    assert len(result.capabilities) == 9
    assert result.full_surface_complete is False
    assert result.manifest.total_findings == len(read.findings) == read.capability.collected
    return result


@pytest.mark.parametrize("capability", READERS)
def test_empty_identity_source_is_complete_without_an_observation(make_run, capability):
    run = make_run([Reply()], capabilities=[capability])
    read = READERS[capability](run.request, run.reader, run.context)
    result = _wire_result(run, read)
    assert read.findings == ()
    assert read.capability.state == "complete"
    assert read.capability.pages_completed == read.capability.requests_attempted == 1
    assert read.capability.scanned == read.capability.matched_filter == read.capability.collected == 0
    assert result.manifest.is_complete
    assert result.manifest.empty_categories == [capability]
    assert result.manifest.errors == []
    assert read.capability.credential_basis == "unverified:primary-token"
    assert read.capability.declared_auth_mode == "application"
    assert_closed(run)


def test_conditional_access_keeps_configuration_and_literal_selected_source(make_run):
    run, read, _ = _fixture_run(make_run, "conditional-access")
    result = _wire_result(run, read)
    assert read.capability.state == "complete"
    assert read.capability.scanned == read.capability.matched_filter == read.capability.collected == 6
    assert [item.raw_data["observation"]["configuration_state"] for item in read.findings] == [
        "enabled",
        "disabled",
        "report_only",
        "unknown",
        "unknown",
        "unknown",
    ]
    first = read.findings[0]
    assert first.raw_data["source"] == {
        "id": " policy-a ",
        "state": "enabled",
        "conditions": {"users": {"includeUsers": ["synthetic-scope"]}, "flag": False, "count": 0},
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
        "sessionControls": None,
    }
    assert first.source_finding_id == "synthetic-reader:conditional-access: policy-a "
    assert first.resource_id == " policy-a "
    assert read.findings[3].raw_data["source"]["state"] == "FUTURE-POLICY"
    assert read.capability.field_coverage["state"].model_dump() == {"absent": 1, "null": 1, "known": 3, "unknown": 1}
    for finding in read.findings:
        assert finding.compliance_status.value == "unknown"
        assert finding.severity.value == "informational"
        assert finding.status.value == "active"
        assert [mapping.control_id for mapping in finding.control_mappings] == ["AC-3", "IA-2"]
        assert {mapping.relationship for mapping in finding.control_mappings} == {"intersects-with"}
        assert finding.collection_context.run_id == run.context.run_id
        assert finding.collection_context.credential_identity == "unverified:primary-token"
        assert finding.first_observed == finding.last_observed == NOW
        assert finding.resolved_at is None
    assert "SYNTHETIC-EXCLUDED-NAME" not in result.model_dump_json()
    assert "Effective identity and application coverage is not established." in first.description


def test_registration_uses_independent_final_denominators_methods_and_exact_updates(make_run):
    run, read, _ = _fixture_run(make_run, "authentication-registration")
    result = _wire_result(run, read)
    assert read.capability.state == "complete"
    assert read.capability.scanned == 6
    assert read.capability.matched_filter == 5
    assert read.capability.duplicate_records == 1
    assert read.capability.collected == 1
    observation = read.findings[0].raw_data["observation"]
    assert set(read.findings[0].raw_data) == {"observation"}
    assert observation["observed_records"] == 5
    assert observation["is_mfa_registered"] == {"true": 2, "false": 1, "null": 1, "absent": 1, "unknown": 0}
    assert observation["is_mfa_capable"] == {"true": 2, "false": 1, "null": 1, "absent": 1, "unknown": 0}
    assert observation["methods_registered"] == {
        "absent": 1,
        "null": 1,
        "known": 3,
        "unknown": 0,
        "counts": [
            {"method": " method ", "records": 1},
            {"method": "FUTURE-METHOD", "records": 2},
            {"method": "password", "records": 2},
        ],
    }
    assert observation["last_updated"] == {
        "absent": 1,
        "null": 1,
        "known": 3,
        "unknown": 0,
        "future": 1,
        "values": [
            {"source_timestamp": "2026-09-09t23:59:59.999999999999z", "age_seconds": "0.000000000001", "records": 1},
            {"source_timestamp": "2026-09-10T00:00:00.000000000001Z", "age_seconds": None, "records": 1},
            {"source_timestamp": "2026-09-10T01:59:59+02:00", "age_seconds": "1", "records": 1},
        ],
    }
    assert [(d.code, d.count) for d in read.capability.diagnostics] == [("future_timestamp", 1)]
    assert read.findings[0].source_finding_id == "synthetic-reader:authentication-registration:summary"
    assert [mapping.control_id for mapping in read.findings[0].control_mappings] == ["IA-2", "IA-5"]
    assert "Disabled accounts are excluded" in read.findings[0].description
    assert "registration does not establish enforcement" in read.findings[0].description
    wire = result.model_dump_json()
    assert "SYNTHETIC-USER" not in wire
    assert "SYNTHETIC-EXCLUDED-USER" not in wire


def test_sign_ins_keep_exact_window_status_zero_and_unavailable_detail(make_run):
    run, read, _ = _fixture_run(make_run, "sign-ins")
    result = _wire_result(run, read)
    assert read.capability.state == "partial"
    assert read.capability.scanned == 5
    assert read.capability.matched_filter == read.capability.collected == 3
    assert [item.resource_id for item in read.findings] == ["sign-start", "sign-middle", "sign-end"]
    assert read.capability.observed_first == "2026-09-09T00:00:00.000000Z"
    assert read.capability.observed_last == "2026-09-10T00:00:00.000000000000Z"
    assert {(item.code, item.count) for item in read.capability.diagnostics} == {
        ("future_timestamp", 1),
        ("conditional_access_detail_unavailable", 1),
    }
    assert read.findings[0].raw_data["source"]["status"] == {"errorCode": 0}
    assert read.findings[1].raw_data["source"]["createdDateTime"] == "2026-09-10t00:59:59.123456789123+01:00"
    assert read.findings[1].raw_data["source"]["authenticationRequirement"] == "multiFactorAuthentication"
    assert [finding.raw_data["observation"] for finding in read.findings] == [
        {
            "conditional_access_status": "success",
            "authentication_requirement": "unknown",
            "conditional_access_detail": "available",
        },
        {
            "conditional_access_status": "failure",
            "authentication_requirement": "unknown",
            "conditional_access_detail": "available",
        },
        {
            "conditional_access_status": "notApplied",
            "authentication_requirement": "unknown",
            "conditional_access_detail": "unavailable",
        },
    ]
    assert read.capability.field_coverage["authenticationRequirement"].model_dump() == {
        "absent": 2,
        "null": 0,
        "known": 0,
        "unknown": 1,
    }
    assert not result.manifest.is_complete
    assert result.manifest.empty_categories == []
    assert [mapping.control_id for mapping in read.findings[0].control_mappings] == ["AU-6", "SI-4"]
    assert "SYNTHETIC-EXCLUDED" not in result.model_dump_json()
    assert all(f.collection_context.pagination_context.is_complete is False for f in read.findings)


def test_roles_are_literal_activated_inventory_without_membership(make_run):
    run, read, _ = _fixture_run(make_run, "directory-roles")
    result = _wire_result(run, read)
    assert read.capability.state == "complete"
    assert read.capability.scanned == read.capability.matched_filter == read.capability.collected == 2
    assert read.capability.pages_completed == read.capability.requests_attempted == 1
    assert read.findings[0].raw_data["source"] == {
        "id": " role-a ",
        "roleTemplateId": " template-a ",
        "displayName": "<script>synthetic-role</script>",
    }
    assert read.findings[0].raw_data["observation"] == {
        "inventory_scope": "activated_roles",
        "assignments_assessed": False,
        "membership_assessed": False,
        "eligibility_assessed": False,
    }
    assert [mapping.control_id for mapping in read.findings[0].control_mappings] == ["AC-2", "AC-6"]
    assert "SYNTHETIC-EXCLUDED-MEMBER" not in result.model_dump_json()
    assert read.capability.observed_first is read.capability.observed_last is None


@pytest.mark.parametrize(
    ("capability", "bad"),
    [
        ("conditional-access", {"id": "bad", "state": True}),
        ("conditional-access", {"id": "bad", "conditions": []}),
        ("conditional-access", {"id": "bad", "grantControls": "wrong"}),
        ("conditional-access", {"id": "bad", "sessionControls": 0}),
        ("authentication-registration", {"id": "bad", "isMfaRegistered": 1}),
        ("authentication-registration", {"id": "bad", "isMfaCapable": "false"}),
        ("authentication-registration", {"id": "bad", "methodsRegistered": [None]}),
        ("authentication-registration", {"id": "bad", "lastUpdatedDateTime": "2026-02-30T00:00:00Z"}),
        ("sign-ins", {"id": "bad", "createdDateTime": "2026-09-09T00:00:60Z"}),
        ("sign-ins", sign_in("bad", status={"errorCode": None})),
        ("sign-ins", sign_in("bad", status={"errorCode": True})),
        ("sign-ins", sign_in("bad", appliedConditionalAccessPolicies=["wrong"])),
        ("directory-roles", {"id": "bad", "roleTemplateId": " "}),
        ("directory-roles", {"id": "bad", "displayName": {}}),
    ],
)
def test_malformed_selected_field_rejects_whole_page_without_observation(make_run, capability, bad):
    good = sign_in("good") if capability == "sign-ins" else {"id": "good"}
    run = make_run([Reply(encode_page([good, bad]))], capabilities=[capability])
    read = READERS[capability](run.request, run.reader, run.context)
    result = _wire_result(run, read)
    assert read.capability.state == "unavailable"
    assert read.capability.scanned == read.capability.pages_completed == read.capability.collected == 0
    assert codes(read) == {"invalid_record"}
    assert read.findings == ()
    assert result.manifest.empty_categories == []
    assert_closed(run)


def test_registration_conflict_retracts_denominator_methods_ages_and_future_count(make_run):
    path = "/v1.0/reports/authenticationMethods/userRegistrationDetails"
    original = {
        "id": "quarantined",
        "isMfaRegistered": True,
        "isMfaCapable": True,
        "methodsRegistered": ["discarded-method"],
        "lastUpdatedDateTime": "2026-09-10T00:00:00.000000000001Z",
    }
    survivor = {"id": "survivor", "isMfaRegistered": False, "isMfaCapable": True, "methodsRegistered": [" kept "]}
    run = make_run(
        [
            Reply(encode_page([original, survivor], ORIGIN + path + "?page=2")),
            Reply(encode_page([{**original, "isMfaRegistered": False}])),
        ],
        capabilities=["authentication-registration"],
    )
    read = read_authentication_registration(run.request, run.reader, run.context)
    _wire_result(run, read)
    assert read.capability.state == "partial"
    assert read.capability.matched_filter == 1
    assert codes(read) == {"conflicting_duplicate"}
    observation = read.findings[0].raw_data["observation"]
    assert observation["observed_records"] == 1
    assert observation["is_mfa_registered"] == {"true": 0, "false": 1, "null": 0, "absent": 0, "unknown": 0}
    assert observation["is_mfa_capable"]["true"] == 1
    assert observation["methods_registered"]["counts"] == [{"method": " kept ", "records": 1}]
    assert observation["last_updated"]["values"] == []
    assert observation["last_updated"]["future"] == 0
    assert run.context.slots_used == 2


def test_sign_in_conflict_recomputes_extrema_and_mandatory_detail(make_run):
    first = sign_in("quarantined", "2026-09-09T00:00:00Z", appliedConditionalAccessPolicies=None)
    survivor = sign_in("survivor", "2026-09-09T23:59:59.000000000001Z")
    run = make_run(
        [
            Reply(encode_page([first, survivor], ORIGIN + SIGN_PATH + "?page=2")),
            Reply(encode_page([{**first, "conditionalAccessStatus": "success"}])),
        ],
        capabilities=["sign-ins"],
        request_fields={"lookback_days": 1},
    )
    read = read_sign_ins(run.request, run.reader, run.context)
    _wire_result(run, read)
    assert [item.resource_id for item in read.findings] == ["survivor"]
    assert read.capability.observed_first == read.capability.observed_last == "2026-09-09T23:59:59.000000000001Z"
    assert codes(read) == {"conflicting_duplicate"}


@pytest.mark.parametrize("missing", [True, False])
def test_absent_and_null_sign_in_detail_are_unavailable_without_erasing_events(make_run, missing):
    row = {"id": "event", "createdDateTime": "2026-09-09T00:00:00Z", "conditionalAccessStatus": "FUTURE-STATUS"}
    if not missing:
        row["appliedConditionalAccessPolicies"] = None
    run = make_run([Reply(encode_page([row]))], capabilities=["sign-ins"])
    read = read_sign_ins(run.request, run.reader, run.context)
    _wire_result(run, read)
    assert read.capability.state == "partial"
    assert read.capability.collected == 1
    assert read.findings[0].raw_data["observation"]["conditional_access_status"] == "unknown"
    assert read.findings[0].raw_data["observation"]["conditional_access_detail"] == "unavailable"
    coverage = read.capability.field_coverage["appliedConditionalAccessPolicies"]
    assert (coverage.absent, coverage.null) == ((1, 0) if missing else (0, 1))


def test_roles_continuation_rejects_the_entire_source_page(make_run):
    run = make_run(
        [Reply(encode_page([{"id": "role"}], ORIGIN + "/v1.0/directoryRoles?$skiptoken=synthetic"))],
        capabilities=["directory-roles"],
    )
    read = read_directory_roles(run.request, run.reader, run.context)
    _wire_result(run, read)
    assert read.capability.state == "unavailable"
    assert read.findings == ()
    assert codes(read) == {"continuation_invalid"}
    assert len(run.scenario.requests) == 1


@pytest.mark.parametrize("http_status", [401, 403])
def test_primary_denial_preserves_independent_capability_results(make_run, http_status):
    replies = [Reply(status=http_status)]
    if http_status == 403:
        replies.extend(Reply() for _ in range(3))
    run = make_run(replies, capabilities=list(READERS))
    reads = [reader(run.request, run.reader, run.context) for reader in READERS.values()]
    result = run.context.build_result(reads)
    assert result.status == ("unavailable" if http_status == 401 else "partial")
    assert len(run.scenario.requests) == (1 if http_status == 401 else 4)
    assert run.provider.calls == ["primary"]
    assert reads[0].capability.state == "unavailable"
    assert all(read.capability.state == ("unavailable" if http_status == 401 else "complete") for read in reads[1:])
    assert_closed(run)


def test_rejected_later_page_preserves_only_prior_domain_observations(make_run):
    run = make_run(
        [
            Reply(encode_page([{"id": "prior", "state": "disabled"}], ORIGIN + CA_PATH + "?page=2")),
            Reply(encode_page([{"id": "prior", "state": "enabled"}, {"id": False}])),
        ]
    )
    read = read_conditional_access(run.request, run.reader, run.context)
    _wire_result(run, read)
    assert read.capability.state == "partial"
    assert codes(read) == {"invalid_record"}
    assert read.capability.scanned == read.capability.matched_filter == 1
    assert read.findings[0].raw_data["observation"] == {"configuration_state": "disabled"}


def test_repeated_runs_keep_finding_ids_and_detach_nested_policy_data(make_run):
    body = {"id": " policy ", "state": "enabled", "conditions": {"nested": [{"literal": " kept "}]}}
    first = make_run([Reply(encode_page([body]))])
    read = read_conditional_access(first.request, first.reader, first.context)
    result = _wire_result(first, read)
    saved = deepcopy(result.findings[0].raw_data)
    read.findings[0].raw_data["source"]["conditions"]["nested"][0]["literal"] = "mutated"
    assert result.findings[0].raw_data == saved
    second = make_run([Reply(encode_page([body]))])
    other = read_conditional_access(second.request, second.reader, second.context)
    assert other.findings[0].raw_data == saved
    assert other.findings[0].id == result.findings[0].id
    assert other.findings[0].collection_context.run_id != result.findings[0].collection_context.run_id


def test_registration_grouping_preserves_literal_method_and_timestamp_variants(make_run):
    rows = [
        {
            "id": "a",
            "methodsRegistered": ["\u00a0literal ", "<script>method</script>"],
            "lastUpdatedDateTime": "2026-09-10T00:00:00Z",
        },
        {"id": "b", "methodsRegistered": ["\u00a0literal "], "lastUpdatedDateTime": "2026-09-10T00:00:00.0000000Z"},
        {"id": "c", "methodsRegistered": [], "lastUpdatedDateTime": "2026-09-10T00:00:00Z"},
    ]
    run = make_run([Reply(encode_page(rows))], capabilities=["authentication-registration"])
    read = read_authentication_registration(run.request, run.reader, run.context)
    _wire_result(run, read)
    observation = read.findings[0].raw_data["observation"]
    assert observation["methods_registered"]["counts"] == [
        {"method": "<script>method</script>", "records": 1},
        {"method": "\u00a0literal ", "records": 2},
    ]
    assert observation["last_updated"]["values"] == [
        {"source_timestamp": "2026-09-10T00:00:00.0000000Z", "age_seconds": "0", "records": 1},
        {"source_timestamp": "2026-09-10T00:00:00Z", "age_seconds": "0", "records": 2},
    ]
    assert observation["is_mfa_registered"]["absent"] == observation["is_mfa_capable"]["absent"] == 3
