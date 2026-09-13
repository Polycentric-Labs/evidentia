"""Finite SCAP import limits, fixed failures and the original processing clock."""

from __future__ import annotations

import math
import re
import time
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast

RAW_LIMIT = 8_388_608
READ_LIMIT = RAW_LIMIT + 1
FEED_LIMIT = 8192
TOKEN_LIMIT = 262_144
REFERENCE_LIMIT = 16
TOKEN_COUNT_LIMIT = 262_144
CALLBACK_LIMIT = 524_288
NODE_LIMIT = 32_768
DEPTH_LIMIT = 64
ATTRIBUTE_LIMIT = 64
TOTAL_ATTRIBUTE_LIMIT = 65_536
NAMESPACE_LIMIT = 64
TOTAL_NAMESPACE_LIMIT = 8192
SOURCE_TEXT_LIMIT = 4_194_304
VALUE_LIMIT = 262_144
UNIT_LIMIT = 256
OUTCOME_LIMIT = 10_000
TIME_LIMIT = 10_000
NATIVE_LIMIT = 5_242_880
ASSESSMENT_LIMIT = 2_097_152
REMAINDER_LIMIT = 524_288
RESULT_LIMIT = 16_777_216
ERROR_LIMIT = 65_536
CLAIM_LIMIT = 2048
STABLE_CLAIM_LIMIT = 4096
WALL_SECONDS = 60.0
PUBLICATION_RESERVE = 10.0

ErrorCode = Literal[
    "invalid_request",
    "unsupported_profile",
    "assessment_not_found",
    "completion_assertion_invalid",
    "completion_assertion_binding_mismatch",
    "completion_assertion_not_permitted",
    "completion_assertion_time_ineligible",
    "unsafe_xml",
    "malformed_xml",
    "source_contract_invalid",
    "source_read_failed",
    "source_limit_exceeded",
    "result_limit_exceeded",
    "unsupported_media",
    "collector_unavailable",
    "scan_extra_unavailable",
    "internal_dependency_failure",
    "invalid_internal_result",
    "processing_deadline_exceeded",
    "publication_failed",
    "artifact_unavailable",
]

ERRORS: dict[ErrorCode, tuple[int | None, int, str]] = {
    "invalid_request": (422, 2, "Invalid SCAP import options."),
    "unsupported_profile": (422, 2, "Unsupported SCAP source profile."),
    "assessment_not_found": (422, 2, "The selected assessment occurrence is unavailable."),
    "completion_assertion_invalid": (422, 2, "Invalid SCAP completion assertion."),
    "completion_assertion_binding_mismatch": (422, 2, "The completion assertion does not match the selected source."),
    "completion_assertion_not_permitted": (422, 2, "A completion assertion is not permitted for this source."),
    "completion_assertion_time_ineligible": (422, 2, "The asserted completion time is not eligible."),
    "unsafe_xml": (400, 2, "The XML input is not permitted."),
    "malformed_xml": (400, 2, "The XML input is malformed."),
    "source_contract_invalid": (400, 2, "The input does not satisfy the selected SCAP source contract."),
    "source_read_failed": (400, 2, "The complete source could not be read."),
    "source_limit_exceeded": (413, 2, "The source exceeds a SCAP import limit."),
    "result_limit_exceeded": (413, 2, "The complete result exceeds a SCAP publication limit."),
    "unsupported_media": (415, 2, "The source media type or encoding is not supported."),
    "collector_unavailable": (503, 1, "The SCAP collector is unavailable."),
    "scan_extra_unavailable": (503, 1, "The optional SCAP XML support is unavailable."),
    "internal_dependency_failure": (500, 1, "SCAP import support failed."),
    "invalid_internal_result": (500, 1, "The SCAP result could not be validated."),
    "processing_deadline_exceeded": (503, 1, "The SCAP import deadline was exceeded."),
    "publication_failed": (500, 1, "The complete SCAP result could not be published."),
    "artifact_unavailable": (None, 2, "No eligible evidence artifact is available for this import."),
}


class ScapFailure(ValueError):
    """Carry one fixed value-free failure across the import surfaces."""

    def __init__(self, code: ErrorCode = "invalid_internal_result") -> None:
        if type(code) is not str or code not in ERRORS:
            code = "invalid_internal_result"
        self.code = code
        self.http_status, self.cli_exit, self.message = ERRORS[code]
        super().__init__(self.message)

    def as_dict(self) -> dict[str, str]:
        return {"schema_version": "scap-error-v1", "code": self.code, "message": self.message}


@dataclass(frozen=True, slots=True)
class Budget:
    """Retain the single private deadline through processing and publication."""

    deadline: float

    def __post_init__(self) -> None:
        if type(self.deadline) is not float or not math.isfinite(self.deadline) or self.deadline <= 0:
            raise ScapFailure()

    def check(self, *, publication: bool = False) -> None:
        limit = self.deadline if publication else self.deadline - PUBLICATION_RESERVE
        if time.monotonic() >= limit:
            raise ScapFailure("processing_deadline_exceeded")


def start_budget() -> Budget:
    return Budget(time.monotonic() + WALL_SECONDS)


def text_value(value: object, minimum: int, maximum: int, *, nonblank: bool = False, controls: bool = False) -> str:
    """Admit an exact string without changing source whitespace or Unicode."""
    if type(value) is not str:
        raise ScapFailure()
    text = cast(str, value)
    if len(text) > maximum:
        raise ScapFailure()
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError:
        raise ScapFailure() from None
    if not minimum <= size <= maximum or (nonblank and not text.strip()):
        raise ScapFailure()
    if controls and any(unicodedata.category(char) in ("Cc", "Cf", "Cs") for char in text):
        raise ScapFailure()
    return text


def utc_text(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise ScapFailure()
    stamp = f"{value.year:04d}-{value.month:02d}-{value.day:02d}T{value.hour:02d}:{value.minute:02d}:{value.second:02d}"
    if value.microsecond:
        stamp += "." + f"{value.microsecond:06d}".rstrip("0")
    return stamp + "Z"


_UTC_SHAPE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?Z")


def parse_utc(value: object, *, canonical: bool = False) -> datetime:
    text = text_value(value, 20, 27)
    match = _UTC_SHAPE.fullmatch(text)
    if match is None:
        raise ScapFailure()
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    fraction = match.group(7) or ""
    try:
        result = datetime(year, month, day, hour, minute, second, int(fraction.ljust(6, "0")), tzinfo=UTC)
    except ValueError:
        raise ScapFailure() from None
    if canonical and utc_text(result) != text:
        raise ScapFailure()
    return result
