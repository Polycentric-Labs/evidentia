"""Regression controls for model, decimal and source-time boundaries."""

from __future__ import annotations

import json
import subprocess
import sys
from decimal import InvalidOperation, localcontext

import pytest
from evidentia_collectors.entra_m365 import _contracts as contract
from pydantic import ValidationError

from ._contract_support import START, event_fields


@pytest.mark.parametrize("trap", [False, True])
@pytest.mark.parametrize(
    "token,accepted", [("0.1", True), ("1e-9999999999999999999", False), ("0e9999999999999999999", False)]
)
def test_decimal_validation_isolated_from_context(trap, token, accepted):
    with localcontext() as context:
        context.prec = 2
        context.Emax = 2
        context.Emin = -2
        context.traps[InvalidOperation] = trap
        context.clear_flags()
        before = dict(context.flags)
        raw = contract.parse_strict_json(('{"id":"synthetic","conditions":{"n":' + token + "}}").encode())
        if accepted:
            value = contract.project_record("conditional-access", raw).fields["conditions"]["n"]
            assert type(value) is float and value == 0.1
        else:
            with pytest.raises(ValueError, match=r"^invalid_record$"):
                contract.project_record("conditional-access", raw)
        assert dict(context.flags) == before


def test_long_source_age_fractions_ignore_lower_child_integer_limit():
    parent_limit = sys.get_int_max_str_digits()
    child_code = """
import json
import sys
sys.set_int_max_str_digits(640)
from evidentia_collectors.entra_m365 import _contracts as module
parse = module.parse_source_timestamp
cases = [
    ('2026-01-01T00:00:01Z', '2026-01-01T00:00:00.' + '1' * 2027 + 'Z', '0.' + '8' * 2026 + '9'),
    ('2026-01-01T00:00:01Z', '2026-01-01T00:00:00.' + '9' * 2027 + 'Z', '0.' + '0' * 2026 + '1'),
    ('2026-01-01T00:00:00.' + '1' * 2026 + '2Z', '2026-01-01T00:00:00.' + '1' * 2027 + 'Z', '0.' + '0' * 2026 + '1'),
]
for end, start, expected in cases:
    assert module.source_age_seconds(parse(end), parse(start)) == expected
print(json.dumps({'checked': len(cases), 'digit_limit': sys.get_int_max_str_digits()}))
"""
    completed = subprocess.run(
        [sys.executable, "-B", "-c", child_code],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
        check=False,
    )
    assert sys.get_int_max_str_digits() == parent_limit
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"checked": 3, "digit_limit": 640}


@pytest.mark.parametrize("method", ["copy", "construct"])
@pytest.mark.parametrize(
    "changes",
    [
        {"observed_first": None, "observed_last": None},
        {"observed_first": "2026-01-02T00:00:00.000000000001Z", "observed_last": "2026-01-02T00:00:00.000000000001Z"},
        {"duplicate_records": 1},
        {"declared_auth_mode": None},
        {"requests_attempted": 0},
    ],
)
def test_revalidation_keeps_corrected_capability_invariants(method, changes):
    model = contract.EntraM365CapabilityResult
    if method == "copy":
        unsafe = model(**event_fields()).model_copy(update=changes)
    else:
        unsafe = model.model_construct(**(event_fields() | changes))
    with pytest.raises(ValidationError):
        model.model_validate(unsafe)


@pytest.mark.parametrize("capability,key", [("directory-roles", "roleTemplateId"), ("defender-alerts", "incidentId")])
@pytest.mark.parametrize("value", [None, " literal reference ", "x" * 512])
def test_foreign_id_null_and_exact_bound_are_preserved(capability, key, value):
    raw = {"id": "synthetic", "createdDateTime": "2026-01-01T00:00:00Z", key: value}
    result = contract.project_record(capability, raw)
    assert result.fields[key] == value


def test_complete_empty_event_requires_requested_window():
    fields = event_fields() | dict(
        scanned=0,
        matched_filter=0,
        collected=0,
        field_coverage={},
        observed_first=None,
        observed_last=None,
        requested_window_start=None,
        requested_window_end=None,
    )
    with pytest.raises(ValidationError):
        contract.EntraM365CapabilityResult(**fields)


def test_requested_event_window_has_positive_duration():
    instant = "2026-01-01T00:00:00Z"
    fields = event_fields() | dict(
        requested_window_end=START,
        observed_first=instant,
        observed_last=instant,
    )
    with pytest.raises(ValidationError):
        contract.EntraM365CapabilityResult(**fields)
