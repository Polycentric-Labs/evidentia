"""Check literal selected-field fidelity independently of provider projectors."""

from __future__ import annotations

from typing import Any

import pytest
from evidentia_collectors.registries._source_fields import (
    SourceFieldError,
    assert_correspondence,
    expected_fields,
    field_coverage,
    source_times,
    validate_fields,
)


def test_rdap_selection_preserves_omission_null_empty_and_all_ordered_occurrences() -> None:
    source: dict[str, Any] = {
        "objectClassName": "domain",
        "ldhName": "EXAMPLE.ORG.",
        "status": [None, "", "unknown", "unknown"],
        "events": [{"eventAction": "registration", "eventDate": "2026-01-01T00:00:00Z"}, {}, None],
        "notices": [{"description": [], "links": [{"href": "https://example.org/ignored"}]}],
        "unselected": {"value": "omitted"},
        "unicodeName": None,
    }
    expected = {key: value for key, value in source.items() if key != "unselected"}
    expected["notices"] = [{"description": [], "links": [{}]}]
    actual = expected_fields("rdap", "domain_record", source)
    assert actual == expected
    assert_correspondence("rdap", "domain_record", source, actual)
    assert field_coverage("rdap", "domain_record", actual)["/unicodeName"] == "null"
    assert field_coverage("rdap", "domain_record", actual)["/rdapConformance"] == "absent"
    assert source_times("rdap", "domain_record", actual)[0].literal == "2026-01-01T00:00:00Z"


@pytest.mark.parametrize("replacement", [["unknown"], ["unknown", "unknown", "unknown"], ["different", "unknown"]])
def test_dropped_invented_or_changed_occurrences_are_refused(replacement: list[str]) -> None:
    source = {"status": ["unknown", "unknown"]}
    with pytest.raises(SourceFieldError, match=r"^projection_mismatch$"):
        assert_correspondence("rdap", "domain_record", source, {"status": replacement})


@pytest.mark.parametrize("value", [True, 1.0, "1"])
def test_native_integer_coercion_is_refused(value: Any) -> None:
    with pytest.raises(SourceFieldError):
        validate_fields("ssl-labs", "endpoint", {"details": {"hostStartTime": value}})


def test_projected_unknown_key_is_refused_but_source_unknown_key_is_excluded() -> None:
    assert expected_fields("rdap", "domain_record", {"unselected": "literal"}) == {}
    with pytest.raises(SourceFieldError):
        validate_fields("rdap", "domain_record", {"unselected": "literal"})


def test_rdap_expressions_remain_literal_and_are_not_evaluated() -> None:
    source = {"redacted": [{"name": {"description": "literal"}, "prePath": "$..private[?(@.x)]", "method": "unknown"}]}
    assert expected_fields("rdap", "domain_record", source) == source


def test_tls_tuple_groups_and_pair_arity_are_checked() -> None:
    valid = {"certificate": {"subject": [[["commonName", "example.org"], ["organizationName", "Example"]]]}}
    assert validate_fields("tls", "verified_tls_adapter", valid) == valid
    invalid = {"certificate": {"subject": [[["commonName", "example.org", "invented"]]]}}
    with pytest.raises(SourceFieldError):
        validate_fields("tls", "verified_tls_adapter", invalid)


def test_time_values_remain_exact_with_unknown_precision_visible() -> None:
    source = {"events": [{"eventDate": "2026-01-01T00:00:00.1234567Z"}]}
    value = source_times("rdap", "domain_record", source)[0]
    assert value.literal == source["events"][0]["eventDate"] and value.normalized_utc is None
    assert value.path == "/events/0/eventDate"


def test_corrected_fcc_locators_are_not_reported_as_timestamps() -> None:
    source = {
        "source_occurrences": [
            {"inclusion_date_cell": {"document": "DA 26-957", "appendix": "A", "printed_appendix_page": "1"}}
        ]
    }
    assert source_times("fcc-covered-list", "fcc_named_entries", source) == []


def test_native_integer_positive_control_preserves_large_value() -> None:
    value = {"details": {"hostStartTime": 9007199254741009}}
    assert validate_fields("ssl-labs", "endpoint", value) == value


@pytest.mark.parametrize("field", ["source_line", "body_line"])
@pytest.mark.parametrize("value", [0, -1, True, False, 1.0, "1"])
def test_security_text_line_numbers_require_positive_integers(field: str, value: Any) -> None:
    with pytest.raises(SourceFieldError):
        validate_fields("security-txt", "security_text_adapter", {"fields": [{field: value}]})


def test_security_text_line_numbers_accept_first_line() -> None:
    value = {"fields": [{"source_line": 1, "body_line": 1}]}
    assert validate_fields("security-txt", "security_text_adapter", value) == value
