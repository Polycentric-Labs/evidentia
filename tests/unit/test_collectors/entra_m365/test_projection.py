"""Synthetic projection cases for selected Graph fields."""

import pytest
from evidentia_collectors.entra_m365 import _contracts as contract


@pytest.mark.parametrize(
    "capability,fields",
    [
        ("conditional-access", {"state": "enabled", "conditions": {"unknown": {"x": 1}}, "grantControls": None}),
        (
            "authentication-registration",
            {"isMfaRegistered": False, "isMfaCapable": True, "methodsRegistered": ["unknown-method"]},
        ),
        (
            "sign-ins",
            {
                "createdDateTime": "2026-09-10T00:00:00.0000001Z",
                "status": {"errorCode": 0, "description": "discard"},
                "appliedConditionalAccessPolicies": [],
            },
        ),
        ("directory-roles", {"displayName": "  Role  ", "roleTemplateId": None}),
        ("managed-devices", {"lastSyncDateTime": "2026-09-10T00:00:00Z", "complianceState": "futureVendorValue"}),
        ("retention-labels", {"retentionDuration": {"days": 0}, "actionAfterRetentionPeriod": "none"}),
        ("defender-alerts", {"createdDateTime": "2026-09-10T00:00:00Z", "severity": "high"}),
        ("defender-incidents", {"createdDateTime": "2026-09-10T00:00:00Z", "status": "resolved"}),
    ],
)
def test_frozen_projection(capability, fields):
    raw = {"id": " source-id ", **fields, "userPrincipalName": "discard@example.org", "extra": 9007199254740993}
    record = contract.project_record(capability, raw)
    assert record.kind == "graph" and record.source_id == " source-id "
    assert "extra" not in record.fields and "userPrincipalName" not in record.fields
    expected = {"id": " source-id ", **fields}
    if capability == "sign-ins":
        expected["status"] = {"errorCode": 0}
    assert record.fields == expected
    raw["id"] = "changed"
    assert record.fields["id"] == " source-id "


@pytest.mark.parametrize(
    "capability,record",
    [
        ("conditional-access", {}),
        ("conditional-access", {"id": None}),
        ("conditional-access", {"id": "  "}),
        ("conditional-access", {"id": "x" * 513}),
        ("conditional-access", {"id": "x", "conditions": []}),
        ("conditional-access", {"id": "x", "state": False}),
        ("conditional-access", {"id": "x", "state": "x" * 129}),
        ("authentication-registration", {"id": "x", "isMfaRegistered": 0}),
        ("authentication-registration", {"id": "x", "methodsRegistered": [False]}),
        ("sign-ins", {"id": "x"}),
        ("sign-ins", {"id": "x", "createdDateTime": None}),
        ("sign-ins", {"id": "x", "createdDateTime": "2026-09-10T00:00:00Z", "status": {"errorCode": False}}),
        ("sign-ins", {"id": "x", "createdDateTime": "2026-09-10T00:00:00Z", "appliedConditionalAccessPolicies": [1]}),
        ("managed-devices", {"id": "x", "lastSyncDateTime": "2026-09-10"}),
        ("retention-labels", {"id": "x", "retentionDuration": {"days": 9007199254740993}}),
        ("retention-labels", {"id": "x", "retentionDuration": {"text": "a" * 2049}}),
    ],
)
def test_wrong_selected_shapes_reject(capability, record):
    with pytest.raises(ValueError, match="invalid_record"):
        contract.project_record(capability, record)


def test_nested_depth_and_projected_bytes():
    nested = 0
    for _ in range(17):
        nested = {"x": nested}
    with pytest.raises(ValueError, match="invalid_record"):
        contract.project_record("conditional-access", {"id": "x", "conditions": nested})
    large = {str(i): "a" * 2048 for i in range(17)}
    with pytest.raises(ValueError, match="invalid_record"):
        contract.project_record("conditional-access", {"id": "x", "conditions": large})
    assert contract.project_record("conditional-access", {"id": "x", "discarded": large}).fields == {"id": "x"}


def test_selected_numbers_round_trip_without_affecting_discarded_data():
    for token in ["1.0000000000000001", "1e-400"]:
        raw = contract.parse_strict_json(('{"id":"x","conditions":{"number":' + token + "}}").encode())
        with pytest.raises(ValueError, match="invalid_record"):
            contract.project_record("conditional-access", raw)
        raw = contract.parse_strict_json(('{"id":"x","discarded":' + token + "}").encode())
        assert contract.project_record("conditional-access", raw).fields == {"id": "x"}
    raw = contract.parse_strict_json(b'{"id":"x","conditions":{"number":0.1,"integer":9007199254740991}}')
    result = contract.project_record("conditional-access", raw)
    assert result.fields["conditions"] == {"number": 0.1, "integer": 9007199254740991}
    assert type(result.fields["conditions"]["number"]) is float


def test_absent_null_false_zero_and_independent_nested_copies():
    record = {"id": "x", "conditions": {"null": None, "false": False, "zero": 0, "decimal": 0.0}}
    first = contract.project_record("conditional-access", record)
    second = contract.project_record("conditional-access", record)
    assert first.fields is not second.fields
    first.fields["conditions"]["null"] = "mutated"
    assert second.fields["conditions"]["null"] is None
    assert type(second.fields["conditions"]["false"]) is bool
    assert type(second.fields["conditions"]["zero"]) is int
    assert type(second.fields["conditions"]["decimal"]) is float
