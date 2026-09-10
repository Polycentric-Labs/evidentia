"""Wire model invariants use empty synthetic collection evidence."""

from datetime import UTC, datetime

import pytest
from evidentia_collectors.entra_m365 import _contracts as contract
from pydantic import ValidationError

from ._contract_support import RECORDED_DLP_PATH, capability


def test_request_schema_exposes_constraints():
    properties = contract.EntraM365CollectRequest.model_json_schema()["properties"]
    assert "pattern" in properties["tenant_label"]
    assert properties["capabilities"].get("uniqueItems") is True


def test_complete_empty_model_and_exact_timestamp():
    assert capability().model_dump(mode="json")["started_at"] == "2026-09-10T00:00:00.000000Z"
    event = capability(
        "sign-ins",
        scanned=1,
        matched_filter=1,
        requested_window_start=datetime(2026, 9, 9, tzinfo=UTC),
        requested_window_end=datetime(2026, 9, 10, tzinfo=UTC),
        observed_first="2026-09-09T23:59:59.1234567Z",
        observed_last="2026-09-09T23:59:59.1234567Z",
        field_coverage={
            name: dict(absent=0, null=0, known=1, unknown=0) for name in contract.coverage_fields("sign-ins")
        },
    )
    assert event.model_dump(mode="json")["observed_first"].endswith(".1234567Z")


@pytest.mark.parametrize(
    "changes",
    [
        {"scanned": False},
        {"matched_filter": 1},
        {"collected": 1},
        {"pages_completed": 0},
        {"started_at": datetime(2026, 9, 10)},
        {"state": "unavailable"},
        {"field_coverage": {"unreviewed": {"absent": 0, "null": 0, "known": 0, "unknown": 0}}},
        {"field_coverage": {"state": {"absent": 0, "null": 0, "known": 1, "unknown": 0}}},
        {"observed_first": "2026-09-10T00:00:00Z"},
    ],
)
def test_capability_inconsistent_evidence_rejected(changes):
    with pytest.raises(ValidationError):
        capability(**changes)


@pytest.mark.parametrize(
    "fields",
    [
        {"code": "source-secret"},
        {"code": "permission_denied", "count": 0},
        {"code": "permission_denied", "count": True},
        {"code": "permission_denied", "http_status": 600},
        {"code": "permission_denied", "details": "source text"},
    ],
)
def test_diagnostic_closed_contract(fields):
    model = contract.EntraM365Diagnostic
    with pytest.raises(ValidationError):
        model(**({"code": "permission_denied", "count": 1, "http_status": 403} | fields))


def test_diagnostics_reject_duplicate_pairs():
    diag = contract.EntraM365Diagnostic(code="future_timestamp", count=1, http_status=None)
    with pytest.raises(ValidationError):
        capability(diagnostics=[diag, diag])


def test_recorded_dlp_typed_shape_keeps_literal_values():
    model = contract.EntraM365DlpExport
    content = RECORDED_DLP_PATH.read_text(encoding="utf-8")
    result = model.model_validate_json(content)
    assert len(result.policies) == 11 and len(result.rules) == 15
    assert all(p.DistributionStatus == "Pending" for p in result.policies)
    assert result.source.captured_at is None
    broken = result.model_dump()
    broken["schema_version"] = True
    with pytest.raises(ValidationError):
        model.model_validate(broken)
    broken = result.model_dump()
    broken["policies"][0]["Enabled"] = 1
    with pytest.raises(ValidationError):
        model.model_validate(broken)
    broken = result.model_dump()
    del broken["rules"][0]["Policy"]
    with pytest.raises(ValidationError):
        model.model_validate(broken)


def test_input_error_has_only_fixed_public_code():
    error = contract.EntraM365InputError
    assert str(error("invalid_body")) == "invalid_body"
    with pytest.raises(ValueError):
        error("attacker-selected-message")
