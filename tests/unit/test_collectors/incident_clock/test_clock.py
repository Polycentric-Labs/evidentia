"""Independent calendar and precision cases for the selected incident clock."""

import sys
from dataclasses import FrozenInstanceError
from typing import cast

import pytest
from evidentia_collectors.incident_clock import _clock as clock_module
from evidentia_collectors.incident_clock._clock import (
    ExactInstant,
    Provider,
    UnsupportedTimestamp,
    elapsed_seconds,
    parse_instant,
)


@pytest.mark.parametrize(
    "provider,start,end,expected",
    [
        ("servicenow", "2024-02-28 23:59:59", "2024-02-29 00:00:00", "1"),
        ("servicenow", "2024-02-29 23:59:59", "2024-03-01 00:00:00", "1"),
        ("servicenow", "2000-02-28 00:00:00", "2000-03-01 00:00:00", "172800"),
        ("servicenow", "1900-02-28 00:00:00", "1900-03-01 00:00:00", "86400"),
        ("jira", "2024-03-10T01:59:59-05:00", "2024-03-10T03:00:00-04:00", "1"),
        ("jira", "2024-11-03T01:30:00-04:00", "2024-11-03T01:30:00-05:00", "3600"),
        ("jira", "2024-01-01T14:00:00+1400", "2024-01-01T00:00:00Z", "0"),
        ("pagerduty", "2024-01-01t00:00:00z", "2024-01-01T00:00:01+00:00", "1"),
        ("pagerduty", "2024-01-01T00:00:00.000000001Z", "2024-01-01T00:00:00.000000003Z", "0.000000002"),
        ("jira", "2024-01-01T00:00:00.1000Z", "2024-01-01T00:00:00.200000Z", "0.1"),
        ("pagerduty", "2024-01-01T00:00:00.999999999Z", "2024-01-01T00:00:01.000000001Z", "0.000000002"),
        ("pagerduty", "1969-12-31T23:59:59.9Z", "1970-01-01T00:00:00.1Z", "0.2"),
        ("jira", "2024-12-31T23:30:00-0100", "2025-01-01T00:30:00Z", "0"),
        ("jira", "2024-01-02T00:00:00+23:59", "2024-01-02T00:00:00-23:59", "172680"),
        ("pagerduty", "2024-01-01T00:00:00Z", "2025-01-01T00:00:00Z", "31622400"),
        (
            "pagerduty",
            "2024-01-01T00:00:00." + "0" * 1999 + "1Z",
            "2024-01-01T00:00:00." + "0" * 1999 + "3Z",
            "0." + "0" * 1999 + "2",
        ),
    ],
)
def test_hand_derived_intervals(provider: Provider, start: str, end: str, expected: str) -> None:
    assert elapsed_seconds(parse_instant(start, provider), parse_instant(end, provider)) == expected


@pytest.mark.parametrize(
    "provider,literal",
    [
        ("servicenow", "2024-01-01"),
        ("servicenow", "2024-01-01T00:00:00Z"),
        ("servicenow", "2024-01-01 00:00:00.0"),
        ("servicenow", "1900-02-29 00:00:00"),
        ("jira", "2024-01-01T00:00:00-0000"),
        ("jira", "2024-01-01T00:00:00-00:00"),
        ("jira", "2024-01-01T00:00:00"),
        ("jira", "2024-01-01T24:00:00Z"),
        ("jira", "2024-01-01T00:00:00+24:00"),
        ("jira", "2024-01-01T00:00:00+00:60"),
        ("pagerduty", "2024-01-01T00:00:00+0000"),
        ("pagerduty", "2024-01-01 00:00:00Z"),
        ("pagerduty", "2024-06-30T23:59:60Z"),
        ("pagerduty", "0000-01-01T00:00:00Z"),
        ("pagerduty", "2023-02-29T00:00:00Z"),
        ("pagerduty", "2024-04-31T00:00:00Z"),
        ("pagerduty", "0001-01-01T00:00:00+00:01"),
        ("pagerduty", "9999-12-31T23:59:59-00:01"),
        ("pagerduty", " 2024-01-01T00:00:00Z"),
        ("pagerduty", "2024-01-01T00:00:00.Z"),
        ("pagerduty", "2024-01-01T00:00:00." + "1" * 2001 + "Z"),
        ("jira", "2024-01-01T00:00:00Z\n"),
        ("pagerduty", "2024-01-01T00:00:00Z" + " " * 2048),
        ("jira", "2024-01-01T00:00:00Z" + chr(0)),
        ("jira", "2024-01-01T00:00:00" + chr(0xFF3A)),
    ],
)
def test_unsupported_source_literals(provider: Provider, literal: str) -> None:
    with pytest.raises(UnsupportedTimestamp, match=r"^Unsupported event timestamp$"):
        parse_instant(literal, provider)


@pytest.mark.parametrize(
    "start,end",
    [
        ("2024-01-01T00:00:01Z", "2024-01-01T00:00:00Z"),
        ("1970-01-01T00:00:00.000000001Z", "1970-01-01T00:00:00Z"),
    ],
)
def test_reversed_order_has_no_elapsed_value(start: str, end: str) -> None:
    assert elapsed_seconds(parse_instant(start, "jira"), parse_instant(end, "jira")) is None


@pytest.mark.parametrize(
    "literal,expected",
    [
        ("0001-01-01T00:00:00Z", "-62135596800"),
        ("9999-12-31T23:59:59.999Z", "253402300799.999"),
        ("1969-12-31T23:59:59.1Z", "-0.9"),
        ("1969-12-31T23:59:58.9Z", "-1.1"),
        ("1970-01-01T00:00:00.0000Z", "0"),
        ("1970-01-01T00:00:00.1000Z", "0.1"),
    ],
)
def test_signed_epoch_decimal(literal: str, expected: str) -> None:
    assert parse_instant(literal, "pagerduty").to_decimal() == expected


def test_full_calendar_span_and_maximum_precision() -> None:
    first = parse_instant("0001-01-01T00:00:00Z", "pagerduty")
    last = parse_instant("9999-12-31T23:59:59." + "9" * 2000 + "Z", "pagerduty")
    expected = "315537897599." + "9" * 2000
    assert elapsed_seconds(first, last) == expected
    assert len(expected.encode("ascii")) <= 2024


class TextSubclass(str):
    pass


class IntSubclass(int):
    pass


@pytest.mark.parametrize("value", [None, True, 0, b"2024-01-01T00:00:00Z", TextSubclass("2024-01-01T00:00:00Z")])
def test_parser_requires_native_text(value: object) -> None:
    with pytest.raises(UnsupportedTimestamp):
        parse_instant(cast(str, value), "jira")


@pytest.mark.parametrize("provider", [None, "Jira", "unknown", TextSubclass("jira")])
def test_parser_requires_supported_native_provider(provider: object) -> None:
    with pytest.raises(UnsupportedTimestamp):
        parse_instant("2024-01-01T00:00:00Z", cast(Provider, provider))


@pytest.mark.parametrize(
    "seconds,fraction,scale",
    [
        (True, 0, 0),
        (IntSubclass(0), 0, 0),
        (0, False, 0),
        (0, 0, True),
        (0, 0, -1),
        (0, 0, 2001),
        (0, -1, 1),
        (0, 10, 1),
        (0, 1, 0),
        (-62135596801, 0, 0),
        (253402300800, 0, 0),
    ],
)
def test_invalid_native_instant(seconds: int, fraction: int, scale: int) -> None:
    with pytest.raises(UnsupportedTimestamp):
        ExactInstant(seconds, fraction, scale)


def test_instant_is_frozen() -> None:
    value = ExactInstant(0, 1, 1)
    with pytest.raises(FrozenInstanceError):
        value.seconds = 1  # type: ignore[misc]


@pytest.mark.parametrize("field,value", [("seconds", True), ("fraction", -1), ("scale", 2001)])
def test_public_operations_revalidate_tampered_instant(field: str, value: int) -> None:
    instant = ExactInstant(0, 1, 1)
    object.__setattr__(instant, field, value)
    with pytest.raises(UnsupportedTimestamp):
        instant.to_decimal()
    with pytest.raises(UnsupportedTimestamp):
        elapsed_seconds(instant, ExactInstant(1))
    with pytest.raises(UnsupportedTimestamp):
        elapsed_seconds(ExactInstant(0), instant)


def test_foreign_and_subclass_instants_are_rejected() -> None:
    class ChildInstant(ExactInstant):
        pass

    for value in (object(), ChildInstant(0)):
        with pytest.raises(UnsupportedTimestamp):
            elapsed_seconds(cast(ExactInstant, value), ExactInstant(1))


@pytest.mark.parametrize(
    "missing", [None, "seconds", "fraction", "scale"], ids=["uninitialized", "seconds", "fraction", "scale"]
)
@pytest.mark.parametrize("operation", ["decimal", "start", "end"])
def test_incomplete_exact_instances_use_fixed_refusal(missing: str | None, operation: str) -> None:
    value = object.__new__(ExactInstant) if missing is None else ExactInstant(0)
    if missing is not None:
        object.__delattr__(value, missing)
    with pytest.raises(UnsupportedTimestamp, match=r"^Unsupported event timestamp$"):
        if operation == "decimal":
            value.to_decimal()
        elif operation == "start":
            elapsed_seconds(value, ExactInstant(1))
        else:
            elapsed_seconds(ExactInstant(-1), value)


@pytest.mark.parametrize("operation", ["decimal", "start", "end"])
def test_arithmetic_uses_detached_validated_parts(operation: str) -> None:
    callbacks: list[str] = []

    class Poison(int):
        def __mul__(self, other: object) -> int:
            callbacks.append("mul")
            raise AssertionError("untrusted numeric callback after validation")

        def __sub__(self, other: object) -> int:
            callbacks.append("sub")
            raise AssertionError("untrusted numeric callback after validation")

        def __rsub__(self, other: object) -> int:
            callbacks.append("rsub")
            raise AssertionError("untrusted numeric callback after validation")

    value = clock_module.ExactInstant(0)
    replaced = False
    validation_code = clock_module._validate_instant.__code__

    def trace(frame, event, arg):
        nonlocal replaced
        if (
            event == "return"
            and frame.f_code is validation_code
            and frame.f_locals.get("value") is value
            and not replaced
        ):
            object.__setattr__(value, "seconds", Poison(0))
            replaced = True
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        try:
            if operation == "decimal":
                result = value.to_decimal()
            elif operation == "start":
                result = clock_module.elapsed_seconds(value, clock_module.ExactInstant(1))
            else:
                result = clock_module.elapsed_seconds(clock_module.ExactInstant(-1), value)
        except clock_module.UnsupportedTimestamp:
            result = "refused"
    finally:
        sys.settrace(previous)
    assert replaced
    assert callbacks == []
    assert result in (("0", "refused") if operation == "decimal" else ("1", "refused"))
