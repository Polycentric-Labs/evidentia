"""Parse bounded source timestamps without losing fractional precision."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Literal

Provider = Literal["servicenow", "jira", "pagerduty"]
MAX_FRACTION_DIGITS = 2000
MAX_LITERAL_BYTES = 2048
MIN_UTC_SECOND = -62135596800
MAX_UTC_SECOND = 253402300799
_EPOCH_ORDINAL = date(1970, 1, 1).toordinal()
_DATE_TIME = r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
_FRACTION = r"(?:\.([0-9]{1,2000}))?"
_PATTERNS = {
    "servicenow": re.compile(_DATE_TIME.replace("[Tt]", " ")),
    "jira": re.compile(_DATE_TIME + _FRACTION + r"([Zz]|[+-][0-9]{2}:?[0-9]{2})"),
    "pagerduty": re.compile(_DATE_TIME + _FRACTION + r"([Zz]|[+-][0-9]{2}:[0-9]{2})"),
}


class UnsupportedTimestamp(ValueError):
    """The source value cannot establish an instant under this contract."""

    def __init__(self) -> None:
        super().__init__("Unsupported event timestamp")


def _validate_parts(seconds: int, fraction: int, scale: int) -> None:
    if any(type(part) is not int for part in (seconds, fraction, scale)):
        raise UnsupportedTimestamp()
    if not MIN_UTC_SECOND <= seconds <= MAX_UTC_SECOND:
        raise UnsupportedTimestamp()
    if not 0 <= scale <= MAX_FRACTION_DIGITS or not 0 <= fraction < 10**scale:
        raise UnsupportedTimestamp()


def _decimal(ticks: int, scale: int) -> str:
    """Format signed integer ticks using a fixed decimal scale."""
    sign = "-" if ticks < 0 else ""
    whole, fraction = divmod(abs(ticks), 10**scale)
    if fraction == 0:
        return sign + str(whole)
    digits = str(fraction).rjust(scale, "0").rstrip("0")
    return f"{sign}{whole}.{digits}"


@dataclass(frozen=True, slots=True)
class ExactInstant:
    """A UTC floor second and its nonnegative fractional remainder."""

    seconds: int
    fraction: int = 0
    scale: int = 0

    def __post_init__(self) -> None:
        _validate_parts(self.seconds, self.fraction, self.scale)

    def to_decimal(self) -> str:
        """Return canonical signed decimal seconds from the Unix epoch."""
        seconds, fraction, scale = _validate_instant(self)
        return _decimal(seconds * 10**scale + fraction, scale)


def _validate_instant(value: ExactInstant) -> tuple[int, int, int]:
    if type(value) is not ExactInstant:
        raise UnsupportedTimestamp()
    try:
        seconds = object.__getattribute__(value, "seconds")
        fraction = object.__getattribute__(value, "fraction")
        scale = object.__getattribute__(value, "scale")
    except AttributeError:
        raise UnsupportedTimestamp() from None
    _validate_parts(seconds, fraction, scale)
    return seconds, fraction, scale


def parse_instant(literal: str, provider: Provider) -> ExactInstant:
    """Interpret only the pinned native timestamp grammar for this provider."""
    if type(provider) is not str or provider not in _PATTERNS:
        raise UnsupportedTimestamp()
    if type(literal) is not str or len(literal) > MAX_LITERAL_BYTES or not literal.isascii():
        raise UnsupportedTimestamp()
    match = _PATTERNS[provider].fullmatch(literal)
    if match is None:
        raise UnsupportedTimestamp()
    year, month, day, hour, minute, second = (int(match[index]) for index in range(1, 7))
    try:
        ordinal = date(year, month, day).toordinal()
    except ValueError:
        raise UnsupportedTimestamp() from None
    if hour > 23 or minute > 59 or second > 59:
        raise UnsupportedTimestamp()
    offset = 0
    fraction = ""
    if provider != "servicenow":
        fraction = match[7] or ""
        zone = match[8]
        if zone not in ("Z", "z"):
            compact = zone.replace(":", "")
            offset_hours, offset_minutes = int(compact[1:3]), int(compact[3:5])
            if offset_hours > 23 or offset_minutes > 59 or compact == "-0000":
                raise UnsupportedTimestamp()
            offset = (offset_hours * 60 + offset_minutes) * 60
            if compact[0] == "-":
                offset = -offset
    seconds = (ordinal - _EPOCH_ORDINAL) * 86400 + hour * 3600 + minute * 60 + second - offset
    return ExactInstant(seconds, int(fraction) if fraction else 0, len(fraction))


def elapsed_seconds(start: ExactInstant, end: ExactInstant) -> str | None:
    """Subtract exact instants, leaving reversed observations unresolved."""
    start_seconds, start_fraction, start_scale = _validate_instant(start)
    end_seconds, end_fraction, end_scale = _validate_instant(end)
    scale = max(start_scale, end_scale)
    ticks = (end_seconds - start_seconds) * 10**scale
    ticks += end_fraction * 10 ** (scale - end_scale)
    ticks -= start_fraction * 10 ** (scale - start_scale)
    return None if ticks < 0 else _decimal(ticks, scale)
