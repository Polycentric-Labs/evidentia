"""Independent contract probes using only authored source and model inputs."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from fractions import Fraction

import pytest
from evidentia_collectors.entra_m365 import _contracts as contract
from pydantic import ValidationError

from ._contract_support import END, START, dlp_fields, event_fields


@pytest.mark.parametrize("token", ["1e-9999999999999999999", "0e9999999999999999999", "-1e-9999999999999999999"])
def test_extreme_selected_exponents_have_fixed_value_error(token):
    raw = contract.parse_strict_json(('{"id":"synthetic","conditions":{"number":' + token + "}}").encode())
    with pytest.raises(ValueError, match=r"^invalid_record$"):
        contract.project_record("conditional-access", raw)


@pytest.mark.parametrize("token", ["1e-9999999999999999999", "0e9999999999999999999", "1.0000000000000001", "1e-400"])
def test_discarded_finite_float_tokens_are_not_selected(token):
    raw = contract.parse_strict_json(('{"id":"synthetic","discarded":' + token + "}").encode())
    assert contract.project_record("conditional-access", raw).fields == {"id": "synthetic"}


@pytest.mark.parametrize("token", ["0.1", "1.0", "1.000000", "1e2", "-0.0", "5e-324"])
def test_selected_float_metadata_survives_until_validation_then_is_removed(token):
    raw = contract.parse_strict_json(('{"id":"synthetic","conditions":{"number":' + token + "}}").encode())
    parsed = raw["conditions"]["number"]
    assert parsed.token == token
    assert contract.checked_json(raw)["conditions"]["number"].token == token
    result = contract.project_record("conditional-access", raw)
    number = result.fields["conditions"]["number"]
    assert type(number) is float
    assert not hasattr(number, "token")
    assert Fraction(token) == Fraction(str(number))


@pytest.mark.parametrize("number", [9007199254740991, -9007199254740991])
def test_selected_integer_js_bound_is_inclusive(number):
    result = contract.project_record("conditional-access", {"id": "x", "conditions": {"n": number}})
    assert result.fields["conditions"]["n"] == number


@pytest.mark.parametrize("number", [9007199254740992, -9007199254740992])
def test_selected_integer_over_js_bound_rejects(number):
    with pytest.raises(ValueError, match=r"^invalid_record$"):
        contract.project_record("conditional-access", {"id": "x", "conditions": {"n": number}})


EVENT_CONTRADICTIONS = [
    {"observed_first": None, "observed_last": None},
    {"requested_window_start": END, "requested_window_end": START},
    {"requested_window_start": None, "requested_window_end": None},
    {"observed_first": "2025-12-31T23:59:59.999999999999Z", "observed_last": "2025-12-31T23:59:59.999999999999Z"},
    {"observed_first": "2026-01-02T00:00:00.000000000001Z", "observed_last": "2026-01-02T00:00:00.000000000001Z"},
]


@pytest.mark.parametrize("changes", EVENT_CONTRADICTIONS)
def test_event_model_rejects_extrema_window_contradiction(changes):
    with pytest.raises(ValidationError):
        contract.EntraM365CapabilityResult(**(event_fields() | changes))


@pytest.mark.parametrize("value", ["2026-01-01T00:00:00Z", "2026-01-02T00:00:00.000000000000Z"])
def test_event_extrema_at_inclusive_window_boundaries_accept(value):
    checked = contract.EntraM365CapabilityResult(**(event_fields() | {"observed_first": value, "observed_last": value}))
    assert checked.observed_first == value and checked.observed_last == value


@pytest.mark.parametrize(
    "changes",
    [
        {"started_at": None, "finished_at": None},
        {"requests_attempted": 0},
        {"duplicate_records": 1},
        {"declared_auth_mode": None},
    ],
)
def test_activity_accounting_cannot_claim_impossible_complete_run(changes):
    with pytest.raises(ValidationError):
        contract.EntraM365CapabilityResult(**(event_fields() | changes))


@pytest.mark.parametrize("name", ["directory-roles", "dlp-export"])
def test_single_page_capability_rejects_multiple_completed_pages(name):
    fields = event_fields() | dict(
        name=name,
        scanned=0,
        matched_filter=0,
        collected=0,
        pages_completed=2,
        requests_attempted=2 if name == "directory-roles" else 0,
        requested_window_start=None,
        requested_window_end=None,
        observed_first=None,
        observed_last=None,
        field_coverage={},
        credential_basis="unverified:dlp-export" if name == "dlp-export" else "unverified:primary-token",
        declared_auth_mode=None if name == "dlp-export" else "application",
    )
    with pytest.raises(ValidationError):
        contract.EntraM365CapabilityResult(**fields)


def test_dlp_cannot_claim_network_attempts():
    fields = event_fields() | dict(
        name="dlp-export",
        credential_basis="unverified:dlp-export",
        declared_auth_mode=None,
        requested_window_start=None,
        requested_window_end=None,
        observed_first=None,
        observed_last=None,
        field_coverage={},
    )
    with pytest.raises(ValidationError):
        contract.EntraM365CapabilityResult(**fields)


@pytest.mark.parametrize(
    "clock",
    [
        datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=1))),
        datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone(-timedelta(hours=1))),
    ],
)
def test_clock_utc_overflow_becomes_validation_error(clock):
    with pytest.raises((ValidationError, ValueError)):
        contract.EntraM365CapabilityResult(**(event_fields() | {"started_at": clock, "finished_at": clock}))


@pytest.mark.parametrize(
    "section,key",
    [
        ("source", "producer_version"),
        ("source", "source_uri"),
        ("policies", "Mode"),
        ("policies", "Workload"),
        ("rules", "Mode"),
    ],
)
def test_dlp_direct_model_rejects_non_utf8_strings(section, key):
    fields = dlp_fields()
    target = fields[section] if section == "source" else fields[section][0]
    target[key] = "\ud800"
    with pytest.raises(ValidationError):
        contract.EntraM365DlpExport.model_validate(fields)


def test_dlp_required_nullable_schema_fields_and_literal_unicode():
    fields = dlp_fields()
    fields["policies"][0]["Mode"] = "  synthetic\u00a0\u00e9\U0001f642  "
    result = contract.EntraM365DlpExport.model_validate(fields)
    assert result.policies[0].Mode == fields["policies"][0]["Mode"]
    assert json.loads(result.model_dump_json())["policies"][0]["Mode"] == fields["policies"][0]["Mode"]
    schema = result.model_json_schema()
    assert set(schema["required"]) == {"schema_version", "source", "policies", "rules"}
    for name in ("_DlpSource", "_DlpPolicy", "_DlpRule"):
        definition = schema["$defs"][name]
        assert set(definition["required"]) == set(definition["properties"])
        assert definition["additionalProperties"] is False


def test_capability_and_diagnostic_schema_require_all_nullable_fields():
    for model in (contract.EntraM365CapabilityResult, contract.EntraM365Diagnostic):
        schema = model.model_json_schema()
        assert set(schema["required"]) == set(schema["properties"])
        assert schema["additionalProperties"] is False


def test_selected_depth_exact_boundary_and_detachment():
    nested = {"leaf": "x"}
    for _ in range(14):
        nested = {"x": nested}
    raw = {"id": "\u00e9\U0001f642", "conditions": nested}
    record = contract.project_record("conditional-access", raw)
    assert record.fields == raw
    nested["x"] = "changed"
    assert record.fields != raw
    too_deep = record.fields | {"conditions": {"another": record.fields["conditions"]}}
    with pytest.raises(ValueError, match=r"^invalid_record$"):
        contract.project_record("conditional-access", too_deep)


def test_exact_source_timestamp_fraction_limit_and_age_oracle():
    raw = "2026-01-01t00:00:00." + "1" * 2027 + "z"
    assert len(raw) == 2048
    value = contract.parse_source_timestamp(raw)
    assert value.raw == raw and value.utc == raw.replace("t", "T").replace("z", "Z")
    end = contract.parse_source_timestamp("2026-01-01T00:00:01Z")
    assert Fraction(contract.source_age_seconds(end, value)) == 1 - Fraction(int("1" * 2027), 10**2027)
    with pytest.raises(ValueError, match=r"^invalid_timestamp$"):
        contract.parse_source_timestamp(raw[:-1] + "1Z")


def test_strict_json_quoted_brackets_duplicates_and_invalid_unicode():
    raw = {"text": "[" * 40 + '\\"' + "}" * 40, "unicode": "\u00e9\U0001f642"}
    assert contract.parse_strict_json(json.dumps(raw).encode()) == raw
    for invalid in [b'{"a":1,"\\u0061":2}', b'{"x":"\\udfff"}', b'{"x":1e9999999999999999999}']:
        with pytest.raises(ValueError, match=r"^invalid_envelope$"):
            contract.parse_strict_json(invalid)


@pytest.mark.parametrize("negative", [False, True])
@pytest.mark.parametrize("digits", [640, 641, 4300, 4301])
def test_integer_token_bound_is_explicit_and_ignores_lower_child_limit(digits, negative):
    parent_limit = sys.get_int_max_str_digits()
    child_code = """
import json
import sys
sys.set_int_max_str_digits(640)
from evidentia_collectors.entra_m365 import _contracts as module
digits = int(sys.argv[1])
sign = b'-' if sys.argv[2] == 'negative' else b''
raw = b'{"id":"synthetic","discarded":' + sign + b'1' + b'0' * (digits - 1) + b'}'
try:
    decoded = module.parse_strict_json(raw)
    fields = module.project_record('conditional-access', decoded).fields
except ValueError as exc:
    outcome = {'accepted': False, 'code': str(exc)}
else:
    outcome = {'accepted': True, 'fields': fields}
print(json.dumps({'digit_limit': sys.get_int_max_str_digits(), **outcome}))
"""
    completed = subprocess.run(
        [sys.executable, "-B", "-c", child_code, str(digits), "negative" if negative else "positive"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["digit_limit"] == 640
    if digits <= 4300:
        assert result == {"digit_limit": 640, "accepted": True, "fields": {"id": "synthetic"}}
    else:
        assert result == {"digit_limit": 640, "accepted": False, "code": "invalid_envelope"}
    assert sys.get_int_max_str_digits() == parent_limit
