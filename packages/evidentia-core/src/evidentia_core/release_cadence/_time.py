"""Exact finite publication timestamps and integer-microsecond spacing."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import cast

from ._limits import ReleaseFailure, text_value

_NATIVE = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]+))?([Zz]|[+-][0-9]{2}:[0-9]{2})"
)
_WINDOW = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z")
_NORMALIZED = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")


def utc_text(value: object) -> str:
    if type(value) is not datetime or cast(datetime, value).tzinfo is not UTC:
        raise ReleaseFailure("clock_invalid")
    instant = cast(datetime, value)
    return (
        f"{instant.year:04d}-{instant.month:02d}-{instant.day:02d}T"
        f"{instant.hour:02d}:{instant.minute:02d}:{instant.second:02d}.{instant.microsecond:06d}Z"
    )


def core_utc_text(value: object) -> str:
    wire = utc_text(value)
    return wire[:-8] + "Z" if wire.endswith(".000000Z") else wire


def classify_publication(value: object) -> dict[str, object]:
    if value is None:
        return {"source_literal": None, "classification": "absent", "normalized_utc": None}
    literal = text_value(value, 128)
    result: dict[str, object] = {
        "source_literal": literal,
        "classification": "unsupported_syntax",
        "normalized_utc": None,
    }
    match = _NATIVE.fullmatch(literal)
    if match is None:
        return result
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    fraction = match[7] or ""
    offset = match[8]
    offset_hour = 0 if offset in ("Z", "z") else int(offset[1:3])
    offset_minute = 0 if offset in ("Z", "z") else int(offset[4:6])
    if hour > 23 or minute > 59 or second > 60 or offset_hour > 23 or offset_minute > 59:
        return result
    if year == 0:
        result["classification"] = "unsupported_year"
        return result
    try:
        instant = datetime(year, month, day, hour, minute, min(second, 59), tzinfo=UTC)
    except ValueError:
        result["classification"] = "invalid_calendar"
        return result
    if second == 60:
        result["classification"] = "unsupported_leap_second"
        return result
    if len(fraction) > 6:
        result["classification"] = "unsupported_precision"
        return result
    microseconds = int(fraction.ljust(6, "0")) if fraction else 0
    instant = instant.replace(microsecond=microseconds)
    shift = offset_hour * 60 + offset_minute
    if offset.startswith("-"):
        shift = -shift
    try:
        instant -= timedelta(minutes=shift)
    except OverflowError:
        result["classification"] = "utc_out_of_range"
        return result
    result["classification"] = "normalized"
    result["normalized_utc"] = utc_text(instant)
    return result


def parse_window_time(value: object, *, normalized: bool = False) -> datetime:
    text = text_value(value, 27)
    if (_NORMALIZED if normalized else _WINDOW).fullmatch(text) is None:
        raise ReleaseFailure()
    classified = classify_publication(text)
    if classified["classification"] != "normalized":
        raise ReleaseFailure()
    # The finite classifier has checked every component before this conversion.
    return datetime.fromisoformat(cast(str, classified["normalized_utc"])).astimezone(UTC)


def elapsed_microseconds(start: object, end: object) -> int:
    utc_text(start)
    utc_text(end)
    delta = cast(datetime, end) - cast(datetime, start)
    return ((delta.days * 86_400) + delta.seconds) * 1_000_000 + delta.microseconds
