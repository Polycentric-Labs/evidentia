"""Source leaf corrections preserve explicit null and identifier rules."""

from decimal import getcontext

import pytest
from evidentia_collectors.entra_m365 import _contracts as contract


@pytest.mark.parametrize(
    "capability,key,value",
    [
        ("directory-roles", "roleTemplateId", " "),
        ("directory-roles", "roleTemplateId", "x" * 513),
        ("defender-alerts", "incidentId", " "),
        ("defender-alerts", "incidentId", "x" * 513),
        ("sign-ins", "status", {"errorCode": None}),
    ],
)
def test_selected_foreign_ids_and_present_error_code(capability, key, value):
    raw = {"id": "x", "createdDateTime": "2026-09-10T00:00:00Z", key: value}
    with pytest.raises(ValueError, match="invalid_record"):
        contract.project_record(capability, raw)


def test_decimal_validation_preserves_ambient_flags():
    context = getcontext()
    before = dict(context.flags)
    raw = contract.parse_strict_json(b'{"id":"x","conditions":{"n":1e-9999999999999999999}}')
    try:
        with pytest.raises(ValueError, match="invalid_record"):
            contract.project_record("conditional-access", raw)
        assert context.flags == before
    finally:
        context.flags = before


def test_nullable_reference_and_null_status_remain_literal():
    assert (
        contract.project_record("directory-roles", {"id": "x", "roleTemplateId": None}).fields["roleTemplateId"] is None
    )
    raw = {"id": "x", "createdDateTime": "2026-09-10T00:00:00Z", "status": None}
    assert contract.project_record("sign-ins", raw).fields["status"] is None


def test_nonempty_evidence_requires_every_reviewed_field_counter():
    from pydantic import ValidationError

    from ._contract_support import capability

    with pytest.raises(ValidationError, match="invalid_field_coverage"):
        capability(scanned=1, matched_filter=1)


def test_dlp_field_counters_have_kind_specific_denominators():
    from ._contract_support import capability

    fields = c_fields = contract.coverage_fields("dlp-export")
    assert "policies.Guid" in c_fields and "rules.Guid" in c_fields
    counts = {
        name: dict(absent=0, null=0, known=2 if name.startswith("policies.") else 1, unknown=0) for name in fields
    }
    result = capability(
        "dlp-export",
        credential_basis="unverified:dlp-export",
        declared_auth_mode=None,
        requests_attempted=0,
        scanned=3,
        matched_filter=3,
        field_coverage=counts,
    )
    assert result.field_coverage["policies.Guid"].known == 2
