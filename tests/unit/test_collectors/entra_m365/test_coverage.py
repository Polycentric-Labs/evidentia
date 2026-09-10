"""Independent coverage-denominator and empty-event closure controls."""

from __future__ import annotations

import pytest
from evidentia_collectors.entra_m365 import _contracts as contract
from pydantic import ValidationError

from ._contract_support import END, START, event_fields

POLICY_FIELDS = ("Guid", "Name", "Mode", "DistributionStatus", "Workload", "Enabled", "IsValid")
RULE_FIELDS = ("Guid", "Policy", "ParentPolicyName", "Mode", "Workload", "Disabled", "IsValid")
DLP_KEYS = tuple("policies." + field for field in POLICY_FIELDS) + tuple("rules." + field for field in RULE_FIELDS)


def dlp_capability_fields(policies=1, rules=1):
    counts = {
        key: {"absent": 0, "null": 0, "known": policies if key.startswith("policies.") else rules, "unknown": 0}
        for key in DLP_KEYS
    }
    total = policies + rules
    orphan_rules = policies == 0 and rules > 0
    return event_fields() | dict(
        name="dlp-export",
        state="partial" if orphan_rules else "complete",
        credential_basis="unverified:dlp-export",
        declared_auth_mode=None,
        scanned=total,
        matched_filter=total,
        collected=policies if policies else rules,
        pages_completed=1,
        requests_attempted=0,
        requested_window_start=None,
        requested_window_end=None,
        observed_first=None,
        observed_last=None,
        field_coverage=counts,
        diagnostics=[{"code": "unresolved_parent", "count": rules, "http_status": None}] if orphan_rules else [],
    )


@pytest.mark.parametrize("policies,rules", [(1, 1), (2, 0), (0, 2), (0, 0)])
def test_dlp_denominators_remain_separate_and_sum_to_total(policies, rules):
    assert set(contract.coverage_fields("dlp-export")) == set(DLP_KEYS)
    assert len(contract.coverage_fields("dlp-export")) == len(DLP_KEYS)
    result = contract.EntraM365CapabilityResult(**dlp_capability_fields(policies, rules))
    assert result.field_coverage["policies.Guid"].known == policies
    assert result.field_coverage["rules.Guid"].known == rules
    assert result.matched_filter == policies + rules
    wire = result.model_dump(mode="json")
    assert set(wire["field_coverage"]) == set(DLP_KEYS)
    assert sum(wire["field_coverage"]["policies.Name"].values()) == policies
    assert sum(wire["field_coverage"]["rules.Policy"].values()) == rules


@pytest.mark.parametrize("missing", DLP_KEYS)
def test_nonempty_dlp_requires_each_reviewed_field(missing):
    fields = dlp_capability_fields()
    del fields["field_coverage"][missing]
    with pytest.raises(ValidationError, match="invalid_field_coverage"):
        contract.EntraM365CapabilityResult(**fields)


@pytest.mark.parametrize("field", ["policies.Name", "rules.Policy"])
def test_dlp_field_cannot_use_the_combined_denominator(field):
    fields = dlp_capability_fields()
    fields["field_coverage"][field]["known"] = 2
    with pytest.raises(ValidationError, match="invalid_field_coverage"):
        contract.EntraM365CapabilityResult(**fields)


def test_dlp_guid_denominator_sum_must_equal_matched_filter():
    fields = dlp_capability_fields(policies=2, rules=1)
    fields["matched_filter"] = 2
    with pytest.raises(ValidationError, match="invalid_field_coverage"):
        contract.EntraM365CapabilityResult(**fields)


@pytest.mark.parametrize("field", ["policies.Guid", "rules.Guid"])
@pytest.mark.parametrize("bucket", ["absent", "null", "unknown"])
def test_dlp_guid_is_never_an_unavailable_identity(field, bucket):
    fields = dlp_capability_fields()
    fields["field_coverage"][field]["known"] = 0
    fields["field_coverage"][field][bucket] = 1
    with pytest.raises(ValidationError, match="invalid_field_coverage"):
        contract.EntraM365CapabilityResult(**fields)


@pytest.mark.parametrize("value", [True, 1.0, "1", -1])
def test_nested_dlp_counter_is_a_strict_nonnegative_integer(value):
    fields = dlp_capability_fields()
    fields["field_coverage"]["policies.Guid"]["known"] = value
    with pytest.raises(ValidationError):
        contract.EntraM365CapabilityResult(**fields)


@pytest.mark.parametrize("key", ["Guid", "rules.Name", "policies.ParentPolicyName"])
def test_wrong_kind_or_unqualified_field_is_rejected(key):
    fields = dlp_capability_fields()
    fields["field_coverage"][key] = {"absent": 0, "null": 0, "known": 1, "unknown": 0}
    with pytest.raises(ValidationError, match="invalid_field_coverage"):
        contract.EntraM365CapabilityResult(**fields)


def test_graph_nonempty_coverage_requires_each_source_field():
    for missing in (
        "id",
        "createdDateTime",
        "conditionalAccessStatus",
        "authenticationRequirement",
        "status.errorCode",
        "appliedConditionalAccessPolicies",
    ):
        fields = event_fields()
        del fields["field_coverage"][missing]
        with pytest.raises(ValidationError, match="invalid_field_coverage"):
            contract.EntraM365CapabilityResult(**fields)


def test_revalidated_coverage_is_detached_and_rejects_later_corruption():
    model = contract.EntraM365CapabilityResult
    original = model(**dlp_capability_fields())
    checked = model.model_validate(original)
    assert checked.field_coverage is not original.field_coverage
    assert checked.field_coverage["policies.Guid"] is not original.field_coverage["policies.Guid"]
    original.field_coverage["policies.Guid"].known = 2
    assert checked.field_coverage["policies.Guid"].known == 1
    with pytest.raises(ValidationError, match="invalid_field_coverage"):
        model.model_validate(original)


@pytest.mark.parametrize("name", ["sign-ins", "defender-alerts", "defender-incidents"])
@pytest.mark.parametrize("state", ["complete", "unavailable"])
def test_requested_event_scope_remains_visible_with_zero_matches(name, state):
    unavailable = state == "unavailable"
    fields = event_fields() | dict(
        name=name,
        state=state,
        scanned=0,
        matched_filter=0,
        collected=0,
        pages_completed=0 if unavailable else 1,
        requests_attempted=0 if unavailable else 1,
        started_at=None if unavailable else END,
        finished_at=None if unavailable else END,
        observed_first=None,
        observed_last=None,
        field_coverage={},
        diagnostics=[{"code": "run_budget", "count": 1, "http_status": None}] if unavailable else [],
    )
    valid = contract.EntraM365CapabilityResult(**fields)
    assert valid.requested_window_start == START and valid.requested_window_end == END
    assert valid.observed_first is None and valid.observed_last is None
    fields["requested_window_start"] = fields["requested_window_end"] = None
    with pytest.raises(ValidationError, match="event_window_required"):
        contract.EntraM365CapabilityResult(**fields)


@pytest.mark.parametrize("name", ["sign-ins", "defender-alerts", "defender-incidents"])
def test_unrequested_event_has_no_window_or_activity(name):
    fields = event_fields() | dict(
        name=name,
        state="not_requested",
        credential_basis=None,
        declared_auth_mode=None,
        scanned=0,
        matched_filter=0,
        collected=0,
        pages_completed=0,
        requests_attempted=0,
        started_at=None,
        finished_at=None,
        requested_window_start=None,
        requested_window_end=None,
        observed_first=None,
        observed_last=None,
        field_coverage={},
        diagnostics=[],
    )
    result = contract.EntraM365CapabilityResult(**fields)
    assert result.requested_window_start is None and result.requested_window_end is None
    with pytest.raises(ValidationError, match="unexpected_event_times"):
        contract.EntraM365CapabilityResult(**(fields | {"requested_window_start": START, "requested_window_end": END}))
