"""Shared contract boundary cases using synthetic source data."""

import json
from datetime import UTC, datetime
from fractions import Fraction

import pytest
from evidentia_collectors.entra_m365 import _contracts as contract


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("2026-09-10T00:00:00.1234567Z", "2026-09-10T00:00:00.1234567Z"),
        ("2026-09-09t20:00:00.1000000000-04:00", "2026-09-10T00:00:00.1000000000Z"),
        ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z"),
        ("9999-12-31T23:59:59.999999999Z", "9999-12-31T23:59:59.999999999Z"),
    ],
)
def test_exact_timestamp(raw, expected):
    stamp = contract.parse_source_timestamp(raw)
    assert stamp.raw == raw and stamp.utc == expected
    assert stamp.whole.tzinfo is UTC and stamp.whole.microsecond == 0


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        1,
        1.0,
        [],
        {},
        b"2026-09-10T00:00:00Z",
        "",
        "2026-09-10",
        "2026-09-10T00:00:60Z",
        "2026-09-10T00:00:00",
        "2026-09-10T00:00:00Z\n",
        "0001-01-01T00:00:00+00:01",
        "9999-12-31T23:59:59-00:01",
        "2026-09-10T00:00:00+24:00",
        "2026-09-10T00:00:00." + "1" * 2028 + "Z",
    ],
)
def test_invalid_exact_time(value):
    parse = contract.parse_source_timestamp
    with pytest.raises(ValueError, match="invalid_timestamp"):
        parse(value)


def test_fraction_order_and_ages():
    parse = contract.parse_source_timestamp
    fractions = ["", "0", "00", "0000001", "000000000001", "123456", "1234567", "9", "90", "999999999"]

    def stamp(f):
        return parse("2026-09-10T00:00:00" + ("." + f if f else "") + "Z")

    for left in fractions:
        for right in fractions:
            expected = Fraction(int(left or "0"), 10 ** len(left)) < Fraction(int(right or "0"), 10 ** len(right))
            assert (stamp(left).key < stamp(right).key) is expected
    end = stamp("123456")
    assert contract.source_age_seconds(end, stamp("1234567")) is None
    assert contract.source_age_seconds(end, stamp("123455999999")) == "0.000000000001"
    assert stamp("123456000").exact_datetime() == datetime(2026, 9, 10, microsecond=123456, tzinfo=UTC)
    assert stamp("1234567").exact_datetime() is None


@pytest.mark.parametrize(
    "data",
    [
        b'{"a":1,"a":2}',
        b'{"a":{"x":1,"x":2}}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":1e9999}',
        b'{"x":"\\ud800"}',
        b"\xff",
        b"\xef\xbb\xbf{}",
        b"{} {}",
        b"[" * 33 + b"0" + b"]" * 33,
    ],
)
def test_strict_json_rejects_ambiguous_data(data):
    parse = contract.parse_strict_json
    with pytest.raises(ValueError, match="invalid_envelope"):
        parse(data)


def test_strict_json_retains_json_types_and_literals():
    data = {"s": "  literal  ", "null": None, "bool": False, "int": 0, "float": 0.0, "list": [True]}
    actual = contract.parse_strict_json(json.dumps(data).encode())
    assert actual == data
    assert (
        type(actual["bool"]) is bool
        and type(actual["int"]) is int
        and isinstance(actual["float"], float)
        and actual["float"].token == "0.0"
    )


def test_json_depth_and_size_before_parser():
    parse = contract.parse_strict_json
    assert parse(b"[" * 32 + b"0" + b"]" * 32)
    with pytest.raises(ValueError, match="response_limit"):
        parse(b" " * (4194304 + 1))


def test_canonical_json_distinguishes_types_and_missing():
    encode = contract.canonical_json
    assert len({encode(x) for x in [{}, {"x": None}, {"x": False}, {"x": 0}, {"x": 0.0}]}) == 5
    assert encode({"x": 1, "y": [2]}) == encode({"y": [2], "x": 1})
