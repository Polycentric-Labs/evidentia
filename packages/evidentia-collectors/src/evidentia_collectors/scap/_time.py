"""Source-valid XML dateTime observations with exact bounded UTC normalization.

Negative years use the selected XML Schema 1.0 signed-year divisibility
policy. This importer does not claim that the publisher's BCE ambiguity
has one uniquely required interpretation.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ._contracts import NormalizedSourceTime, TimeNormalization
from ._limits import VALUE_LIMIT, Budget, ScapFailure, text_value, utc_text


def _failure() -> ScapFailure:
    return ScapFailure("source_contract_invalid")


def _days(year: int, month: int) -> int:
    if month == 2:
        return 29 if year % 400 == 0 or (year % 4 == 0 and year % 100 != 0) else 28
    return 30 if month in (4, 6, 9, 11) else 31


def _move_day(year: int, month: int, day: int, direction: int) -> tuple[int, int, int]:
    if direction == 1:
        day += 1
        if day > _days(year, month):
            day = 1
            month += 1
            if month == 13:
                month = 1
                year = 1 if year == -1 else year + 1
    else:
        day -= 1
        if day == 0:
            month -= 1
            if month == 0:
                month = 12
                year = -1 if year == 1 else year - 1
            day = _days(year, month)
    return year, month, day


def normalize_source_time(value: str, budget: Budget) -> NormalizedSourceTime:
    """Validate the complete source datatype before classifying normalization."""
    budget.check()
    try:
        text = text_value(value, 1, VALUE_LIMIT).strip(" \t\r\n")
    except ScapFailure:
        raise _failure() from None
    length = len(text)
    negative = text.startswith("-")
    index = 1 if negative else 0
    start = index
    residue = 0
    magnitude = 0
    while index < length and "0" <= text[index] <= "9":
        digit = ord(text[index]) - 48
        residue = (residue * 10 + digit) % 400
        magnitude = min(10001, magnitude * 10 + digit)
        index += 1
        if index % 4096 == 0:
            budget.check()
    digits = index - start
    if digits < 4 or magnitude == 0 or (digits > 4 and text[start] == "0"):
        raise _failure()
    if index >= length or text[index] != "-":
        raise _failure()

    def pair(position: int) -> int:
        if position + 1 >= length or not ("0" <= text[position] <= "9" and "0" <= text[position + 1] <= "9"):
            raise _failure()
        return (ord(text[position]) - 48) * 10 + ord(text[position + 1]) - 48

    if (
        index + 14 >= length
        or text[index + 3] != "-"
        or text[index + 6] != "T"
        or text[index + 9] != ":"
        or text[index + 12] != ":"
    ):
        raise _failure()
    month, day = pair(index + 1), pair(index + 4)
    hour, minute, second = pair(index + 7), pair(index + 10), pair(index + 13)
    index += 15
    if not 1 <= month <= 12 or not 1 <= day <= _days(residue, month) or hour > 24 or minute > 59 or second > 60:
        raise _failure()
    fraction_digits = 0
    microsecond = 0
    fraction_nonzero = False
    extra_nonzero = False
    if index < length and text[index] == ".":
        index += 1
        fraction_start = index
        while index < length and "0" <= text[index] <= "9":
            digit = ord(text[index]) - 48
            fraction_nonzero = fraction_nonzero or digit != 0
            if fraction_digits < 6:
                microsecond = microsecond * 10 + digit
            else:
                extra_nonzero = extra_nonzero or digit != 0
            fraction_digits += 1
            index += 1
            if index % 4096 == 0:
                budget.check()
        if index == fraction_start:
            raise _failure()
    microsecond *= 10 ** max(0, 6 - fraction_digits)
    if hour == 24 and (minute or second or fraction_nonzero):
        raise _failure()
    offset: int | None = None
    if index < length:
        if text[index] == "Z" and index + 1 == length:
            offset = 0
            index += 1
        elif text[index] in ("+", "-") and index + 6 == length and text[index + 3] == ":":
            zone_hour, zone_minute = pair(index + 1), pair(index + 4)
            if zone_hour > 14 or zone_minute > 59 or (zone_hour == 14 and zone_minute):
                raise _failure()
            offset = (zone_hour * 60 + zone_minute) * (-1 if text[index] == "-" else 1)
            index += 6
        else:
            raise _failure()
    if index != length:
        raise _failure()
    budget.check()
    state: TimeNormalization
    if offset is None:
        state = "timezone_missing"
    elif extra_nonzero:
        state = "precision_unsupported"
    elif second == 60:
        state = "normalization_unsupported"
    elif magnitude > 10000 or (negative and magnitude != 1):
        state = "range_unsupported"
    else:
        year = -magnitude if negative else magnitude
        if hour == 24:
            year, month, day = _move_day(year, month, day, 1)
            hour = 0
        utc_minute = hour * 60 + minute - offset
        if utc_minute < 0:
            year, month, day = _move_day(year, month, day, -1)
            utc_minute += 1440
        elif utc_minute >= 1440:
            year, month, day = _move_day(year, month, day, 1)
            utc_minute -= 1440
        if not 1 <= year <= 9999:
            state = "range_unsupported"
        else:
            normalized = datetime(year, month, day, utc_minute // 60, utc_minute % 60, second, microsecond, tzinfo=UTC)
            budget.check()
            return NormalizedSourceTime(state="normalized", utc=utc_text(normalized))
    return NormalizedSourceTime(state=state, utc=None)
