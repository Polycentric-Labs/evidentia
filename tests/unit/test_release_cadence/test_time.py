"""Hand-derived timestamp and exact fixed-day boundary expectations."""

from datetime import datetime, timedelta, timezone

import pytest
from evidentia_core.release_cadence._limits import ReleaseFailure
from evidentia_core.release_cadence._time import (
    classify_publication,
    elapsed_microseconds,
    parse_window_time,
    utc_text,
)


@pytest.mark.parametrize(
    "literal,expected",
    [
        ("2000-01-01T00:00:00Z", "2000-01-01T00:00:00.000000Z"),
        ("2000-01-01t00:00:00z", "2000-01-01T00:00:00.000000Z"),
        ("2000-01-01T00:00:00-00:00", "2000-01-01T00:00:00.000000Z"),
        ("2000-01-01T00:00:00+00:00", "2000-01-01T00:00:00.000000Z"),
        ("2000-01-01T00:00:00.1+00:01", "1999-12-31T23:59:00.100000Z"),
        ("1999-12-31T23:59:59.123456-00:01", "2000-01-01T00:00:59.123456Z"),
        ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00.000000Z"),
    ],
)
def test_native_time_preserves_literal(literal, expected):
    assert classify_publication(literal) == {
        "source_literal": literal,
        "classification": "normalized",
        "normalized_utc": expected,
    }


@pytest.mark.parametrize(
    "literal,classification",
    [
        (None, "absent"),
        ("0000-01-01T00:00:00Z", "unsupported_year"),
        ("1900-02-29T00:00:00Z", "invalid_calendar"),
        ("2000-02-29T24:00:00Z", "unsupported_syntax"),
        ("2000-02-29T00:00:60Z", "unsupported_leap_second"),
        ("2000-02-29T00:00:00.0000000Z", "unsupported_precision"),
        ("0001-01-01T00:00:00+00:01", "utc_out_of_range"),
        ("9999-12-31T23:59:59-00:01", "utc_out_of_range"),
        ("0000-13-01T24:00:60.0000000Z", "unsupported_syntax"),
        ("0000-13-01T00:00:60.0000000Z", "unsupported_year"),
        ("2000-13-01T00:00:60.0000000Z", "invalid_calendar"),
        ("2000-01-01T00:00:60.0000000Z", "unsupported_leap_second"),
        ("2000-01-01T00:00:00Z\n", "unsupported_syntax"),
        ("２０００-01-01T00:00:00Z", "unsupported_syntax"),
    ],
)
def test_time_classification_order(literal, classification):
    assert classify_publication(literal) == {
        "source_literal": literal,
        "classification": classification,
        "normalized_utc": None,
    }


@pytest.mark.parametrize("literal", [True, 1, 1.0, "x" * 129, "é" * 65, "\ud800"])
def test_time_scalar_refuses_without_coercion(literal):
    with pytest.raises(ReleaseFailure):
        classify_publication(literal)


@pytest.mark.parametrize(
    "literal",
    [
        "2000-01-01t00:00:00z",
        "2000-01-01T00:00:00+00:00",
        "2000-01-01T00:00:00.0000000Z",
        "2000-01-01T00:00:60Z",
    ],
)
def test_request_window_uses_stricter_utc_grammar(literal):
    with pytest.raises(ReleaseFailure):
        parse_window_time(literal)


def test_exact_gap_and_trusted_clock():
    start = parse_window_time("2000-01-01T00:00:00Z")
    assert utc_text(start) == "2000-01-01T00:00:00.000000Z"
    assert elapsed_microseconds(start, start + timedelta(days=1)) == 86_400_000_000
    assert elapsed_microseconds(start, start + timedelta(days=1, microseconds=1)) == 86_400_000_001
    assert elapsed_microseconds(start, start + timedelta(hours=47, minutes=59, seconds=59)) == 172_799_000_000
    with pytest.raises(ReleaseFailure):
        utc_text(datetime(2000, 1, 1, tzinfo=timezone(timedelta(hours=1))))


@pytest.mark.parametrize(
    "fraction,microseconds",
    [
        ("", "000000"),
        (".1", "100000"),
        (".12", "120000"),
        (".123", "123000"),
        (".1234", "123400"),
        (".12345", "123450"),
        (".123456", "123456"),
    ],
)
def test_every_admitted_fraction_width_has_exact_microseconds(fraction, microseconds):
    literal = "2000-01-01T00:00:00" + fraction + "Z"
    assert classify_publication(literal) == {
        "source_literal": literal,
        "classification": "normalized",
        "normalized_utc": "2000-01-01T00:00:00." + microseconds + "Z",
    }


@pytest.mark.parametrize(
    "literal,classification,normalized",
    [
        ("2000-02-29T00:00:00Z", "normalized", "2000-02-29T00:00:00.000000Z"),
        ("2000-01-02t00:00:00+23:59", "normalized", "2000-01-01T00:01:00.000000Z"),
        ("2000-01-01T00:00:00-23:59", "normalized", "2000-01-01T23:59:00.000000Z"),
        ("0001-01-01T00:01:00+00:01", "normalized", "0001-01-01T00:00:00.000000Z"),
        ("9999-12-31T23:58:59-00:01", "normalized", "9999-12-31T23:59:59.000000Z"),
        ("2000-01-01T00:00:00", "unsupported_syntax", None),
        ("2000-01-01T00:00:00Z[UTC]", "unsupported_syntax", None),
        ("2000-01-01T00:60:00Z", "unsupported_syntax", None),
        ("2000-01-01T00:00:61Z", "unsupported_syntax", None),
        ("2000-01-01T00:00:00+24:00", "unsupported_syntax", None),
        ("2000-01-01T00:00:00+00:60", "unsupported_syntax", None),
    ],
)
def test_remaining_rc8_rc10_literal_boundaries(literal, classification, normalized):
    assert classify_publication(literal) == {
        "source_literal": literal,
        "classification": classification,
        "normalized_utc": normalized,
    }
