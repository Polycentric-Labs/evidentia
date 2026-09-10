"""Bounded evidence contracts, transactional accounting and finding provenance."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal, DecimalException, localcontext
from hashlib import sha256
from importlib.metadata import version
from typing import Annotated, Literal, Self, cast

from evidentia_core.audit.provenance import CollectionContext, CollectionManifest, CoverageCount, PaginationContext
from evidentia_core.models.common import ControlMapping, Severity, deterministic_finding_id
from evidentia_core.models.finding import ComplianceStatus, FindingStatus, SecurityFinding
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    ValidationInfo,
    field_validator,
    model_validator,
)

from .mapping import FindingRule, control_mappings, get_rule, rule_specs

CapabilityName = Literal[
    "conditional-access",
    "authentication-registration",
    "sign-ins",
    "directory-roles",
    "managed-devices",
    "retention-labels",
    "dlp-export",
    "defender-alerts",
    "defender-incidents",
]


CAPABILITIES: tuple[CapabilityName, ...] = (
    "conditional-access",
    "authentication-registration",
    "sign-ins",
    "directory-roles",
    "managed-devices",
    "retention-labels",
    "dlp-export",
    "defender-alerts",
    "defender-incidents",
)


DlpFormat = Literal["evidentia-dlp-v1", "scubagear-provider-v1"]


DLP_MAX_BYTES = 4_194_304


class EntraM365CollectRequest(BaseModel):
    """Bounded requested evidence scope with no caller-selected credentials."""

    model_config = ConfigDict(
        extra="forbid", strict=True, str_strip_whitespace=False, validate_default=True, revalidate_instances="always"
    )

    tenant_label: Annotated[
        str, Field(min_length=1, max_length=64, json_schema_extra={"pattern": r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"})
    ]
    capabilities: Annotated[
        list[CapabilityName], Field(min_length=1, max_length=9, json_schema_extra={"uniqueItems": True})
    ] = Field(default_factory=lambda: list(CAPABILITIES))
    lookback_days: Annotated[int, Field(ge=1, le=30)] = 30
    max_items: Annotated[int, Field(ge=1, le=10_000)] = 10_000
    max_pages: Annotated[int, Field(ge=1, le=100)] = 100
    dlp_content: Annotated[str, Field(max_length=DLP_MAX_BYTES)] | None = None
    dlp_format: DlpFormat = "evidentia-dlp-v1"

    @field_validator("tenant_label")
    @classmethod
    def validate_alias(cls, value: str) -> str:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value) is None:
            raise ValueError("invalid_tenant_label")
        return value

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, value: list[CapabilityName]) -> list[CapabilityName]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate_capability")
        return [name for name in CAPABILITIES if name in value]

    @field_validator("dlp_content")
    @classmethod
    def validate_dlp_bytes(cls, value: str | None) -> str | None:
        if value is None:
            return None
        size = 0
        try:
            for offset in range(0, len(value), 4096):
                size += len(value[offset : offset + 4096].encode("utf-8"))
                if size > DLP_MAX_BYTES:
                    raise ValueError("dlp_content_limit")
        except UnicodeEncodeError:
            raise ValueError("invalid_dlp_utf8") from None
        return value

    @model_validator(mode="after")
    def validate_dlp_selection(self) -> Self:
        if self.dlp_content is not None and "dlp-export" not in self.capabilities:
            raise ValueError("dlp_capability_required")
        if "dlp_format" in self.model_fields_set and self.dlp_content is None:
            raise ValueError("dlp_content_required")
        return self


type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None


type JsonObject = dict[str, JsonValue]


PAGE_MAX_BYTES = 4_194_304


_TIMESTAMP = re.compile(
    r"(?P<y>[0-9]{4})-(?P<m>[0-9]{2})-(?P<d>[0-9]{2})"
    r"[Tt](?P<h>[0-9]{2}):(?P<n>[0-9]{2}):(?P<s>[0-9]{2})"
    r"(?:\.(?P<f>[0-9]+))?(?P<z>[Zz]|[+-][0-9]{2}:[0-9]{2})"
)


@dataclass(frozen=True)
class _ExactSourceTimestamp:
    raw: str
    whole: datetime
    fraction: str

    @property
    def key(self) -> tuple[datetime, str]:
        return self.whole, self.fraction.rstrip("0")

    @property
    def utc(self) -> str:
        value = self.whole
        whole = (
            f"{value.year:04d}-{value.month:02d}-{value.day:02d}T{value.hour:02d}:{value.minute:02d}:{value.second:02d}"
        )
        return whole + ("." + self.fraction if self.fraction else "") + "Z"

    def exact_datetime(self) -> datetime | None:
        if self.fraction[6:].strip("0"):
            return None
        return self.whole.replace(microsecond=int(self.fraction[:6].ljust(6, "0")))


def parse_source_timestamp(value: object) -> _ExactSourceTimestamp:
    """Preserve source precision while comparing instants in UTC."""
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("invalid_timestamp")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        raise ValueError("invalid_timestamp")
    fields = match.groupdict()
    zone = fields["z"]
    offset = 0
    if zone not in {"Z", "z"}:
        hours, minutes = int(zone[1:3]), int(zone[4:6])
        if hours > 23 or minutes > 59:
            raise ValueError("invalid_timestamp")
        offset = (hours * 60 + minutes) * (1 if zone[0] == "+" else -1)
    try:
        whole = datetime(
            int(fields["y"]),
            int(fields["m"]),
            int(fields["d"]),
            int(fields["h"]),
            int(fields["n"]),
            int(fields["s"]),
            tzinfo=UTC,
        ) - timedelta(minutes=offset)
    except (ValueError, OverflowError):
        raise ValueError("invalid_timestamp") from None
    return _ExactSourceTimestamp(value, whole, fields["f"] or "")


def source_age_seconds(end: _ExactSourceTimestamp, value: _ExactSourceTimestamp) -> str | None:
    if value.key > end.key:
        return None
    delta = end.whole - value.whole
    seconds = delta.days * 86400 + delta.seconds
    scale = max(len(end.fraction), len(value.fraction))
    factor = 10**scale
    ticks = (
        seconds * factor
        + _bounded_integer(end.fraction.ljust(scale, "0") or "0")
        - _bounded_integer(value.fraction.ljust(scale, "0") or "0")
    )
    whole, remainder = divmod(ticks, factor)
    fractional = _decimal_digits(remainder).rjust(scale, "0").rstrip("0") if scale else ""
    return str(whole) + ("." + fractional if fractional else "")


def _unique_pairs(pairs: list[tuple[str, JsonValue]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("invalid_envelope")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("invalid_envelope")


class _JsonFloat(float):
    token: str

    def __new__(cls, value: str) -> Self:
        result = super().__new__(cls, value)
        result.token = value
        return result


def _bounded_integer(value: str) -> int:
    negative = value.startswith("-")
    digits = value[1:] if negative else value
    if len(digits) > 4300:
        raise ValueError("invalid_envelope")
    result = 0
    for start in range(0, len(digits), 512):
        chunk = digits[start : start + 512]
        result = result * 10 ** len(chunk) + int(chunk)
    return -result if negative else result


def _decimal_digits(value: int) -> str:
    chunks: list[str] = []
    while value >= 10**512:
        value, remainder = divmod(value, 10**512)
        chunks.append(str(remainder).zfill(512))
    return str(value) + "".join(reversed(chunks))


def _finite_float(value: str) -> float:
    result = _JsonFloat(value)
    if not math.isfinite(result):
        raise ValueError("invalid_envelope")
    return result


def checked_json(value: object, *, depth: int = 0) -> JsonValue:
    """Copy finite JSON values without coercing their scalar types."""
    if value is None or type(value) in {bool, int}:
        return cast(JsonValue, value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("invalid_envelope")
        return value
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("invalid_envelope") from None
        return value
    if depth >= 32:
        raise ValueError("invalid_envelope")
    if isinstance(value, list):
        return [checked_json(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        result: JsonObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("invalid_envelope")
            checked_json(key)
            result[key] = checked_json(item, depth=depth + 1)
        return result
    raise ValueError("invalid_envelope")


def parse_strict_json(data: bytes, *, max_bytes: int = PAGE_MAX_BYTES) -> JsonValue:
    """Check byte and nesting bounds before decoding a strict JSON value."""
    if len(data) > max_bytes:
        raise ValueError("response_limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("invalid_envelope") from None
    depth = 0
    quoted = False
    escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 32:
                raise ValueError("invalid_envelope")
        elif char in "]}":
            depth -= 1
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
            parse_int=_bounded_integer,
        )
    except (ValueError, RecursionError):
        raise ValueError("invalid_envelope") from None
    return checked_json(value)


def canonical_json(value: JsonValue) -> str:
    return json.dumps(checked_json(value), ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True)
class EntraM365SourceRecord:
    kind: Literal["graph", "dlp-policy", "dlp-rule"]
    source_id: str
    fields: JsonObject
    event_time: _ExactSourceTimestamp | None


type FieldKind = Literal["text", "id", "enum", "object", "strings", "objects", "status", "bool", "timestamp"]


GRAPH_FIELDS: dict[CapabilityName, dict[str, FieldKind]] = {
    "conditional-access": {
        "state": "enum",
        "conditions": "object",
        "grantControls": "object",
        "sessionControls": "object",
    },
    "authentication-registration": {
        "isMfaRegistered": "bool",
        "isMfaCapable": "bool",
        "methodsRegistered": "strings",
        "lastUpdatedDateTime": "timestamp",
    },
    "sign-ins": {
        "createdDateTime": "timestamp",
        "conditionalAccessStatus": "enum",
        "authenticationRequirement": "enum",
        "status": "status",
        "appliedConditionalAccessPolicies": "objects",
    },
    "directory-roles": {"roleTemplateId": "id", "displayName": "text"},
    "managed-devices": {"complianceState": "enum", "managementState": "enum", "lastSyncDateTime": "timestamp"},
    "retention-labels": {
        "displayName": "text",
        "retentionTrigger": "enum",
        "retentionDuration": "object",
        "behaviorDuringRetentionPeriod": "enum",
        "actionAfterRetentionPeriod": "enum",
    },
    "defender-alerts": {
        "incidentId": "id",
        "severity": "enum",
        "status": "enum",
        "createdDateTime": "timestamp",
        "lastUpdateDateTime": "timestamp",
        "resolvedDateTime": "timestamp",
        "serviceSource": "enum",
        "detectionSource": "enum",
    },
    "defender-incidents": {
        "severity": "enum",
        "status": "enum",
        "createdDateTime": "timestamp",
        "lastUpdateDateTime": "timestamp",
    },
}


EVENT_CAPABILITIES: frozenset[CapabilityName] = frozenset({"sign-ins", "defender-alerts", "defender-incidents"})


def _selected_json(value: object, *, depth: int = 0) -> JsonValue:
    if value is None or type(value) is bool:
        return cast(JsonValue, value)
    if type(value) is int:
        number = value
        if abs(number) > 9_007_199_254_740_991:
            raise ValueError("invalid_record")
        return number
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("invalid_record")
        if isinstance(value, _JsonFloat):
            try:
                with localcontext():
                    if Decimal(value.token) != Decimal(str(float(value))):
                        raise ValueError("invalid_record")
            except DecimalException:
                raise ValueError("invalid_record") from None
        return float(value)
    if isinstance(value, str):
        if len(value) > 2048:
            raise ValueError("invalid_record")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("invalid_record") from None
        return value
    if depth >= 16:
        raise ValueError("invalid_record")
    if isinstance(value, list):
        return [_selected_json(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        output: JsonObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("invalid_record")
            _selected_json(key)
            output[key] = _selected_json(item, depth=depth + 1)
        return output
    raise ValueError("invalid_record")


def _selected_field(kind: FieldKind, value: JsonValue) -> JsonValue:
    if value is None:
        return None
    if kind in {"text", "id", "enum", "timestamp"}:
        if not isinstance(value, str):
            raise ValueError("invalid_record")
        if kind == "id" and (not value.strip() or len(value) > 512):
            raise ValueError("invalid_record")
        if kind == "enum" and len(value) > 128:
            raise ValueError("invalid_record")
        if kind == "timestamp":
            try:
                parse_source_timestamp(value)
            except ValueError:
                raise ValueError("invalid_record") from None
    elif kind in {"object", "status"}:
        if not isinstance(value, dict):
            raise ValueError("invalid_record")
        if kind == "status":
            if "errorCode" not in value:
                return {}
            code = value["errorCode"]
            if type(code) is not int:
                raise ValueError("invalid_record")
            return {"errorCode": _selected_json(code)}
    elif kind == "bool":
        if type(value) is not bool:
            raise ValueError("invalid_record")
    elif kind in {"strings", "objects"}:
        if not isinstance(value, list):
            raise ValueError("invalid_record")
        expected = str if kind == "strings" else dict
        if any(not isinstance(item, expected) for item in value):
            raise ValueError("invalid_record")
    return _selected_json(value, depth=1)


def project_record(capability: CapabilityName, value: object) -> EntraM365SourceRecord:
    """Validate and copy selected fields before a page can enter the ledger."""
    if capability not in GRAPH_FIELDS or not isinstance(value, dict):
        raise ValueError("invalid_record")
    identifier = value.get("id")
    if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 512:
        raise ValueError("invalid_record")
    fields: JsonObject = {"id": _selected_json(identifier)}
    for name, kind in GRAPH_FIELDS[capability].items():
        if name in value:
            fields[name] = _selected_field(kind, value[name])
    event_time = None
    if capability in EVENT_CAPABILITIES:
        try:
            event_time = parse_source_timestamp(fields.get("createdDateTime"))
        except ValueError:
            raise ValueError("invalid_record") from None
    size = 0
    for chunk in json.JSONEncoder(ensure_ascii=False, allow_nan=False, separators=(",", ":")).iterencode(fields):
        size += len(chunk.encode("utf-8"))
        if size > 32_768:
            raise ValueError("invalid_record")
    return EntraM365SourceRecord("graph", identifier, fields, event_time)


class _WireModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, str_strip_whitespace=False, validate_default=True, revalidate_instances="always"
    )


def _utc_clock(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("invalid_clock")
    try:
        return value.astimezone(UTC)
    except (ValueError, OverflowError):
        raise ValueError("invalid_clock") from None


def clock_text(value: datetime) -> str:
    return _utc_clock(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _utc_source_text(value: str) -> str:
    return parse_source_timestamp(value).utc


type UtcClock = Annotated[
    datetime, AfterValidator(_utc_clock), PlainSerializer(clock_text, return_type=str, when_used="json")
]


type UtcSourceText = Annotated[
    str, Field(max_length=2048, json_schema_extra={"format": "date-time"}), AfterValidator(_utc_source_text)
]


type Nonnegative = Annotated[int, Field(ge=0)]


type CapabilityState = Literal["complete", "partial", "unavailable", "not_requested"]


type AuthMode = Literal["application", "delegated"]


type CredentialBasis = Literal["unverified:primary-token", "unverified:retention-token", "unverified:dlp-export"]


type DiagnosticCode = Literal[
    "input_missing",
    "credentials_missing",
    "configuration_invalid",
    "authentication_failed",
    "permission_denied",
    "connection_failed",
    "upstream_error",
    "retry_exhausted",
    "retry_after_invalid",
    "retry_after_budget",
    "redirect_refused",
    "unsafe_destination",
    "invalid_envelope",
    "invalid_record",
    "invalid_timestamp",
    "response_limit",
    "page_limit",
    "item_limit",
    "byte_limit",
    "capability_budget",
    "run_budget",
    "continuation_invalid",
    "continuation_loop",
    "conflicting_duplicate",
    "conditional_access_detail_unavailable",
    "unresolved_parent",
    "conflicting_state",
    "source_validity_unknown",
    "future_timestamp",
    "timestamp_precision_unrepresentable",
    "source_retention_limited",
    "internal_error",
]


NON_PARTIAL_CODES = frozenset({"future_timestamp", "timestamp_precision_unrepresentable", "source_retention_limited"})


class EntraM365InputError(ValueError):
    """A fixed public error code without source data or library diagnostics."""

    def __init__(self, code: str = "invalid_field") -> None:
        if code not in {"invalid_body", "invalid_field", "response_limit"}:
            raise ValueError("invalid_error_code")
        self.code = code
        super().__init__(code)


class EntraM365Diagnostic(_WireModel):
    code: DiagnosticCode
    count: Annotated[int, Field(ge=1)]
    http_status: Annotated[int, Field(ge=100, le=599)] | None


class _FieldCoverage(_WireModel):
    absent: Nonnegative
    null: Nonnegative
    known: Nonnegative
    unknown: Nonnegative


def coverage_fields(capability: CapabilityName) -> tuple[str, ...]:
    if capability == "dlp-export":
        return tuple("policies." + name for name in _DlpPolicy.model_fields) + tuple(
            "rules." + name for name in _DlpRule.model_fields
        )
    return (
        "id",
        *(
            "status.errorCode" if capability == "sign-ins" and key == "status" else key
            for key in GRAPH_FIELDS[capability]
        ),
    )


class EntraM365CapabilityResult(_WireModel):
    name: CapabilityName
    state: CapabilityState
    credential_basis: CredentialBasis | None
    declared_auth_mode: AuthMode | None
    scanned: Nonnegative
    matched_filter: Nonnegative
    collected: Nonnegative
    duplicate_records: Nonnegative
    pages_completed: Nonnegative
    requests_attempted: Nonnegative
    started_at: UtcClock | None
    finished_at: UtcClock | None
    requested_window_start: UtcClock | None
    requested_window_end: UtcClock | None
    observed_first: UtcSourceText | None
    observed_last: UtcSourceText | None
    field_coverage: dict[str, _FieldCoverage]
    diagnostics: list[EntraM365Diagnostic]

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if (
            self.matched_filter > self.scanned
            or self.collected > self.matched_filter
            or self.duplicate_records + self.matched_filter > self.scanned
        ):
            raise ValueError("invalid_accounting")
        if (self.started_at is None) != (self.finished_at is None):
            raise ValueError("invalid_clock_pair")
        if self.started_at is not None and self.finished_at is not None and self.finished_at < self.started_at:
            raise ValueError("invalid_clock_order")
        if self.state in {"complete", "partial"} and (self.pages_completed == 0 or self.started_at is None):
            raise ValueError("accepted_page_required")
        if self.name == "dlp-export":
            if self.requests_attempted or self.pages_completed > 1:
                raise ValueError("invalid_dlp_accounting")
        elif self.pages_completed > self.requests_attempted:
            raise ValueError("invalid_request_accounting")
        if self.name == "directory-roles" and self.pages_completed > 1:
            raise ValueError("invalid_role_accounting")
        if self.state in {"unavailable", "not_requested"} and any(
            (self.pages_completed, self.scanned, self.matched_filter, self.collected, self.duplicate_records)
        ):
            raise ValueError("unavailable_has_records")
        if self.state == "not_requested" and (
            self.credential_basis is not None
            or self.declared_auth_mode is not None
            or self.requests_attempted
            or self.started_at is not None
            or self.diagnostics
            or self.field_coverage
        ):
            raise ValueError("not_requested_has_activity")
        if self.state != "not_requested":
            expected = (
                "unverified:dlp-export"
                if self.name == "dlp-export"
                else "unverified:retention-token"
                if self.name == "retention-labels"
                else "unverified:primary-token"
            )
            if self.credential_basis != expected:
                raise ValueError("invalid_credential_basis")
            if self.name == "dlp-export" and self.declared_auth_mode is not None:
                raise ValueError("invalid_auth_mode")
            if self.name == "retention-labels" and self.declared_auth_mode != "delegated":
                raise ValueError("invalid_auth_mode")
            if (
                self.name not in {"dlp-export", "retention-labels"}
                and self.declared_auth_mode is None
                and (
                    self.state != "unavailable"
                    or not any(
                        item.code
                        in {
                            "configuration_invalid",
                            "unsafe_destination",
                            "run_budget",
                            "capability_budget",
                            "item_limit",
                            "byte_limit",
                            "internal_error",
                        }
                        for item in self.diagnostics
                    )
                )
            ):
                raise ValueError("invalid_auth_mode")
        if (self.requested_window_start is None) != (self.requested_window_end is None):
            raise ValueError("invalid_window_pair")
        if (
            self.requested_window_start is not None
            and self.requested_window_end is not None
            and self.requested_window_start >= self.requested_window_end
        ):
            raise ValueError("invalid_window_order")
        if self.name in EVENT_CAPABILITIES and self.state != "not_requested" and self.requested_window_start is None:
            raise ValueError("event_window_required")
        if (self.name not in EVENT_CAPABILITIES or self.state == "not_requested") and (
            self.requested_window_start is not None or self.observed_first is not None or self.observed_last is not None
        ):
            raise ValueError("unexpected_event_times")
        if (self.observed_first is None) != (self.observed_last is None):
            raise ValueError("invalid_extrema_pair")
        if (
            self.observed_first is not None
            and self.observed_last is not None
            and (
                not self.matched_filter
                or parse_source_timestamp(self.observed_first).key > parse_source_timestamp(self.observed_last).key
            )
        ):
            raise ValueError("invalid_extrema")
        if self.name in EVENT_CAPABILITIES and self.matched_filter:
            if (
                self.observed_first is None
                or self.observed_last is None
                or self.requested_window_start is None
                or self.requested_window_end is None
            ):
                raise ValueError("event_times_required")
            if not (
                parse_source_timestamp(clock_text(self.requested_window_start)).key
                <= parse_source_timestamp(self.observed_first).key
                <= parse_source_timestamp(self.observed_last).key
                <= parse_source_timestamp(clock_text(self.requested_window_end)).key
            ):
                raise ValueError("extrema_outside_window")
        reviewed = set(coverage_fields(self.name))
        if self.matched_filter and set(self.field_coverage) != reviewed:
            raise ValueError("invalid_field_coverage")
        denominators: dict[str, int] = {}
        if self.name == "dlp-export" and self.field_coverage:
            for kind in ("policies", "rules"):
                identifier = self.field_coverage.get(kind + ".Guid")
                if identifier is None or identifier.absent or identifier.null or identifier.unknown:
                    raise ValueError("invalid_field_coverage")
                denominators[kind] = identifier.known
            if sum(denominators.values()) != self.matched_filter:
                raise ValueError("invalid_field_coverage")
        for key, count in self.field_coverage.items():
            expected_count = denominators.get(key.partition(".")[0], self.matched_filter)
            if key not in reviewed or sum(count.model_dump().values()) != expected_count:
                raise ValueError("invalid_field_coverage")
        pairs = [(diagnostic.code, diagnostic.http_status) for diagnostic in self.diagnostics]
        if len(set(pairs)) != len(pairs):
            raise ValueError("duplicate_diagnostic")
        if self.state == "complete" and any(code not in NON_PARTIAL_CODES for code, status in pairs):
            raise ValueError("complete_has_failure")
        return self


def _literal_name(value: str) -> str:
    if not value.strip():
        raise ValueError("blank_identifier")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("invalid_utf8") from None
    return value


type DlpName = Annotated[str, Field(min_length=1, max_length=512), AfterValidator(_literal_name)]


type DlpEnum = Annotated[str, Field(max_length=128)]


class _DlpSource(_WireModel):
    kind: Literal["operator-export", "recorded-provider-projection", "authored-synthetic"]
    producer: Annotated[str, Field(min_length=1, max_length=128), AfterValidator(_literal_name)]
    producer_version: Annotated[str, Field(max_length=64)] | None
    captured_at: Annotated[str, Field(max_length=2048)] | None
    parent_sha256: Annotated[str, Field(min_length=64, max_length=64, pattern="^[0-9a-f]{64}$")] | None
    source_uri: Annotated[str, Field(max_length=2048)] | None
    sanitization: Literal["operator-declared", "publisher-attested", "synthetic"]

    @field_validator("captured_at")
    @classmethod
    def validate_timestamp(cls, value: str | None) -> str | None:
        if value is not None:
            parse_source_timestamp(value)
        return value


class _DlpPolicy(_WireModel):
    Guid: DlpName
    Name: DlpName
    Mode: DlpEnum | None
    DistributionStatus: DlpEnum | None
    Workload: DlpEnum | None
    Enabled: bool | None
    IsValid: bool | None


class _DlpRule(_WireModel):
    Guid: DlpName
    Policy: DlpName | None
    ParentPolicyName: DlpName | None
    Mode: DlpEnum | None
    Workload: DlpEnum | None
    Disabled: bool | None
    IsValid: bool | None


class EntraM365DlpExport(_WireModel):
    schema_version: Literal[1]
    source: _DlpSource
    policies: Annotated[list[_DlpPolicy], Field(max_length=10_000)]
    rules: Annotated[list[_DlpRule], Field(max_length=10_000)]

    @field_validator("schema_version", mode="before")
    @classmethod
    def validate_version(cls, value: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError("invalid_version")
        return value


CAPABILITY_BYTE_LIMIT = 33_554_432


RUN_BYTE_LIMIT = 134_217_728


RUN_ITEM_LIMIT = 40_000


KNOWN_ENUMS: dict[tuple[str, str], tuple[str, ...]] = {
    ("conditional-access", "state"): ("enabled", "disabled", "enabledForReportingButNotEnforced"),
    ("sign-ins", "conditionalAccessStatus"): ("success", "failure", "notApplied"),
    ("sign-ins", "authenticationRequirement"): (),
    ("managed-devices", "complianceState"): (
        "compliant",
        "noncompliant",
        "conflict",
        "error",
        "inGracePeriod",
        "configManager",
    ),
    ("managed-devices", "managementState"): (
        "managed",
        "retirePending",
        "retireFailed",
        "wipePending",
        "wipeFailed",
        "unhealthy",
        "deletePending",
        "retireIssued",
        "wipeIssued",
        "wipeCanceled",
        "retireCanceled",
        "discovered",
    ),
    ("retention-labels", "retentionTrigger"): ("dateLabeled", "dateCreated", "dateModified", "dateOfEvent"),
    ("retention-labels", "behaviorDuringRetentionPeriod"): (
        "doNotRetain",
        "retain",
        "retainAsRecord",
        "retainAsRegulatoryRecord",
    ),
    ("retention-labels", "actionAfterRetentionPeriod"): ("none", "delete", "startDispositionReview", "relabel"),
    ("defender-alerts", "severity"): ("informational", "low", "medium", "high"),
    ("defender-alerts", "status"): ("new", "inProgress", "resolved"),
    ("defender-alerts", "serviceSource"): (
        "microsoftDefenderForEndpoint",
        "microsoftDefenderForIdentity",
        "microsoftDefenderForCloudApps",
        "microsoftDefenderForOffice365",
        "microsoft365Defender",
        "azureAdIdentityProtection",
        "microsoftAppGovernance",
        "dataLossPrevention",
        "microsoftDefenderForCloud",
        "microsoftSentinel",
        "microsoftInsiderRiskManagement",
        "microsoftThreatIntelligence",
        "microsoftSecurityForAI",
    ),
    ("defender-alerts", "detectionSource"): (
        "microsoftDefenderForEndpoint",
        "antivirus",
        "smartScreen",
        "customTi",
        "microsoftDefenderForOffice365",
        "automatedInvestigation",
        "microsoftThreatExperts",
        "customDetection",
        "microsoftDefenderForIdentity",
        "cloudAppSecurity",
        "microsoft365Defender",
        "azureAdIdentityProtection",
        "manual",
        "microsoftDataLossPrevention",
        "appGovernancePolicy",
        "appGovernanceDetection",
        "microsoftDefenderForCloud",
        "microsoftDefenderForIoT",
        "microsoftDefenderForServers",
        "microsoftDefenderForStorage",
        "microsoftDefenderForDNS",
        "microsoftDefenderForDatabases",
        "microsoftDefenderForContainers",
        "microsoftDefenderForNetwork",
        "microsoftDefenderForAppService",
        "microsoftDefenderForKeyVault",
        "microsoftDefenderForResourceManager",
        "microsoftDefenderForApiManagement",
        "nrtAlerts",
        "scheduledAlerts",
        "microsoftDefenderThreatIntelligenceAnalytics",
        "builtInMl",
        "microsoftInsiderRiskManagement",
        "microsoftThreatIntelligence",
        "microsoftDefenderForAIServices",
        "securityCopilot",
        "microsoftSentinel",
    ),
    ("defender-incidents", "severity"): ("informational", "low", "medium", "high"),
    ("defender-incidents", "status"): ("active", "resolved", "inProgress", "redirected", "awaitingAction"),
}


DLP_ENUMS: dict[tuple[str, str], tuple[str, ...]] = {
    ("dlp-policy", "Mode"): ("Disable", "Enable", "TestWithNotifications", "TestWithoutNotifications"),
    ("dlp-rule", "Mode"): ("Enforce",),
    ("dlp-policy", "DistributionStatus"): ("Pending",),
}


@dataclass(frozen=True)
class EntraM365SourceRead:
    capability: EntraM365CapabilityResult
    records: tuple[EntraM365SourceRecord, ...]


@dataclass(frozen=True)
class EntraM365CapabilityRead:
    capability: EntraM365CapabilityResult
    findings: tuple[SecurityFinding, ...]


@dataclass
class _Identity:
    record: EntraM365SourceRecord | None
    variants: set[bytes] = field(default_factory=set)


def _copy_record(name: CapabilityName, record: EntraM365SourceRecord) -> EntraM365SourceRecord:
    if name != "dlp-export":
        if record.kind != "graph":
            raise ValueError("invalid_record")
        return project_record(name, record.fields)
    if record.kind not in {"dlp-policy", "dlp-rule"}:
        raise ValueError("invalid_record")
    model = _DlpPolicy if record.kind == "dlp-policy" else _DlpRule
    fields = cast(JsonObject, model.model_validate(record.fields).model_dump())
    fields = cast(JsonObject, _selected_json(fields))
    if fields["Guid"] != record.source_id:
        raise ValueError("invalid_record")
    return EntraM365SourceRecord(record.kind, record.source_id, fields, None)


def _signature(record: EntraM365SourceRecord) -> bytes:
    return sha256(canonical_json(record.fields).encode("utf-8")).digest()


def _field_coverage(name: CapabilityName, records: Sequence[EntraM365SourceRecord]) -> dict[str, _FieldCoverage]:
    counts = {key: _FieldCoverage(absent=0, null=0, known=0, unknown=0) for key in coverage_fields(name)}
    for record in records:
        prefix = "policies." if record.kind == "dlp-policy" else "rules." if record.kind == "dlp-rule" else ""
        for key, count in counts.items():
            if prefix and not key.startswith(prefix):
                continue
            source_key = key.removeprefix(prefix)
            present = source_key in record.fields
            value = record.fields.get(source_key)
            if source_key == "status.errorCode":
                status = record.fields.get("status")
                present = "status" in record.fields and (
                    status is None or (isinstance(status, dict) and "errorCode" in status)
                )
                value = status.get("errorCode") if isinstance(status, dict) else None
            if not present:
                count.absent += 1
            elif value is None:
                count.null += 1
            else:
                known = KNOWN_ENUMS.get((name, source_key))
                if name == "dlp-export":
                    known = DLP_ENUMS.get((record.kind, source_key))
                if known is not None and value not in known:
                    count.unknown += 1
                else:
                    count.known += 1
    return counts


COLLECTOR_ID = "entra-m365-scan"


SOURCE_SYSTEM = "entra-m365"


class _EntraM365Finding(SecurityFinding):
    model_config = ConfigDict(
        str_strip_whitespace=False, strict=True, extra="forbid", revalidate_instances="always", use_enum_values=False
    )
    raw_data: JsonObject
    first_observed: UtcClock
    last_observed: UtcClock
    resolved_at: UtcClock | None = None

    @field_validator("control_mappings", mode="before")
    @classmethod
    def detached_mappings(cls, value: object) -> object:
        if not isinstance(value, list):
            raise ValueError("invalid_mapping_list")
        return [item.model_dump() if isinstance(item, ControlMapping) else item for item in value]

    @field_validator("collection_context", mode="before")
    @classmethod
    def detached_context(cls, value: object) -> object:
        data = value.model_dump() if isinstance(value, CollectionContext) else value
        if not isinstance(data, dict):
            raise ValueError("invalid_finding_context")
        data = dict(data)
        data["collected_at"] = _clock_value(data.get("collected_at"))
        pagination = data.get("pagination_context")
        if (
            not isinstance(pagination, dict)
            or type(pagination.get("total_pages")) is not int
            or type(pagination.get("is_complete")) is not bool
        ):
            raise ValueError("invalid_finding_pagination")
        return data

    @field_validator("first_observed", "last_observed", "resolved_at", mode="before")
    @classmethod
    def json_clock(cls, value: object, info: ValidationInfo) -> object:
        if info.mode == "json" and isinstance(value, str):
            exact = parse_source_timestamp(value).exact_datetime()
            if exact is None:
                raise ValueError("invalid_clock")
            return exact
        return value


class _Provenance(_WireModel):
    tenant_label: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")]
    identity_basis: Literal["operator-declared"]
    authenticated_identity_verified: Literal[False]
    graph_cloud: Literal["commercial"]

    @field_validator("authenticated_identity_verified", mode="before")
    @classmethod
    def unverified(cls, value: object) -> object:
        if value is not False:
            raise ValueError("invalid_identity_claim")
        return value

    @field_validator("tenant_label")
    @classmethod
    def alias(cls, value: str) -> str:
        return EntraM365CollectRequest.validate_alias(value)


def _digest(value: JsonObject) -> bytes:
    return sha256(canonical_json(value).encode("utf-8")).digest()


def _clock_value(value: object) -> datetime:
    if isinstance(value, str):
        value = parse_source_timestamp(value).exact_datetime()
    if not isinstance(value, datetime):
        raise ValueError("invalid_clock")
    return _utc_clock(value)


def _strict_core_fields(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("invalid_manifest")
    data = dict(value)
    if type(data.get("total_findings")) is not int or type(data.get("is_complete")) is not bool:
        raise ValueError("invalid_manifest_types")
    counts = data.get("coverage_counts")
    if not isinstance(counts, list):
        raise ValueError("invalid_manifest_types")
    for count in counts:
        if not isinstance(count, dict) or any(
            type(count.get(key)) is not int for key in ("scanned", "matched_filter", "collected")
        ):
            raise ValueError("invalid_manifest_types")
    data["collection_started_at"] = _clock_value(data.get("collection_started_at"))
    data["collection_finished_at"] = _clock_value(data.get("collection_finished_at"))
    return data


def _warnings(capabilities: Sequence[EntraM365CapabilityResult]) -> list[str]:
    active = [cap for cap in capabilities if cap.state != "not_requested"]
    result = [
        cap.name + ":" + diagnostic.code
        for cap in active
        for diagnostic in cap.diagnostics
        if diagnostic.code in NON_PARTIAL_CODES
    ]
    result.extend(
        cap.name + ": unknown source values retained"
        for cap in active
        if any(value.unknown or value.absent or value.null for value in cap.field_coverage.values())
    )
    result.extend(
        cap.name + ": source scope and retention limit the observation"
        for cap in active
        if cap.name in {"sign-ins", "defender-alerts", "defender-incidents"}
    )
    return result


def _finding_scope(request: EntraM365CollectRequest, cap: EntraM365CapabilityResult) -> JsonObject:
    return _scope(request) | {
        "capability": cap.name,
        "requested_window_start": clock_text(cap.requested_window_start) if cap.requested_window_start else None,
        "requested_window_end": clock_text(cap.requested_window_end) if cap.requested_window_end else None,
    }


def _validate_finding_content(finding: _EntraM365Finding, cap: EntraM365CapabilityResult, tenant: str) -> None:
    data = finding.raw_data
    if not isinstance(data.get("observation"), dict):
        raise ValueError("invalid_finding_observation")
    _selected_json(data["observation"])
    record = data.get("source")
    source_id: str | None = None
    if cap.name == "authentication-registration":
        if set(data) != {"observation"}:
            raise ValueError("invalid_finding_source")
    else:
        if set(data) != {"source", "observation"} or not isinstance(record, dict):
            raise ValueError("invalid_finding_source")
        raw_source_id = record.get("Guid" if cap.name == "dlp-export" else "id")
        if not isinstance(raw_source_id, str):
            raise ValueError("invalid_finding_source")
        source_id = raw_source_id
    spec = next(
        (
            candidate
            for candidate in rule_specs()
            if candidate.capability == cap.name
            and finding.source_finding_id
            == tenant + ":" + candidate.source_suffix.replace("{source_id}", source_id or "")
        ),
        None,
    )
    if spec is None:
        raise ValueError("invalid_finding_rule")
    if isinstance(record, dict):
        if cap.name == "dlp-export":
            model = _DlpPolicy if spec.rule == "dlp-policy-configuration" else _DlpRule
            selected = cast(JsonObject, model.model_validate(record).model_dump())
        else:
            selected_record = project_record(cap.name, record)
            selected = selected_record.fields
            if selected_record.event_time is not None and (
                cap.requested_window_start is None
                or cap.requested_window_end is None
                or not (
                    parse_source_timestamp(clock_text(cap.requested_window_start)).key
                    <= selected_record.event_time.key
                    <= parse_source_timestamp(clock_text(cap.requested_window_end)).key
                )
            ):
                raise ValueError("invalid_finding_window")
        if canonical_json(selected) != canonical_json(record):
            raise ValueError("invalid_finding_source")
    if (
        (finding.title, finding.description, finding.resource_type, finding.resource_id, finding.resource_account)
        != (spec.title, spec.description, spec.resource_type, source_id, tenant)
        or finding.resource_region is not None
        or finding.remediation is not None
    ):
        raise ValueError("invalid_static_finding")
    if [item.model_dump() for item in finding.control_mappings] != [
        item.model_dump() for item in control_mappings(spec.rule)
    ]:
        raise ValueError("invalid_finding_mappings")
    expected_status = FindingStatus.ACTIVE
    expected_severity = Severity.INFORMATIONAL
    defender = cap.name in {"defender-alerts", "defender-incidents"}
    if defender and isinstance(record, dict):
        expected_status = FindingStatus.RESOLVED if record.get("status") == "resolved" else FindingStatus.ACTIVE
        expected_severity = next(
            (
                level
                for level in (Severity.LOW, Severity.MEDIUM, Severity.HIGH)
                if level.value == record.get("severity")
            ),
            Severity.INFORMATIONAL,
        )
    if finding.status != expected_status or finding.severity != expected_severity:
        raise ValueError("invalid_finding_state")
    if finding.resolved_at is not None:
        raw = record.get("resolvedDateTime") if isinstance(record, dict) else None
        exact = parse_source_timestamp(raw).exact_datetime() if raw is not None else None
        if not defender or finding.status != FindingStatus.RESOLVED or exact is None or exact != finding.resolved_at:
            raise ValueError("invalid_resolution_time")


def _validate_returned_records(cap: EntraM365CapabilityResult, findings: Sequence[_EntraM365Finding]) -> None:
    if cap.name == "dlp-export":
        policies = cap.field_coverage.get("policies.Guid")
        expected = policies.known if policies is not None else 0
        policy_type = get_rule("dlp-policy-configuration").resource_type
        if sum(finding.resource_type == policy_type for finding in findings) != expected:
            raise ValueError("missing_observation")
    else:
        expected = int(cap.matched_filter > 0) if cap.name == "authentication-registration" else cap.matched_filter
        if len(findings) != expected:
            raise ValueError("missing_observation")
    if cap.name in EVENT_CAPABILITIES:
        times = [
            parse_source_timestamp(cast(JsonObject, finding.raw_data["source"])["createdDateTime"])
            for finding in findings
        ]
        first = last = None
        if times:
            first_key = min(stamp.key for stamp in times)
            last_key = max(stamp.key for stamp in times)
            first = max((stamp for stamp in times if stamp.key == first_key), key=lambda stamp: len(stamp.fraction))
            last = max((stamp for stamp in times if stamp.key == last_key), key=lambda stamp: len(stamp.fraction))
        if (cap.observed_first, cap.observed_last) != (first.utc if first else None, last.utc if last else None):
            raise ValueError("invalid_source_extrema")


def _finding_digest(value: SecurityFinding) -> bytes:
    return _digest(cast(JsonObject, value.model_dump(mode="json")))


def _scope(request: EntraM365CollectRequest) -> JsonObject:
    return {
        "tenant_label": request.tenant_label,
        "identity_basis": "operator-declared",
        "authenticated_identity_verified": False,
        "graph_cloud": "commercial",
        "capabilities": list(request.capabilities),
        "lookback_days": request.lookback_days,
        "max_items": request.max_items,
        "max_pages": request.max_pages,
    }


def _errors(capabilities: Sequence[EntraM365CapabilityResult]) -> list[str]:
    return [
        cap.name + ":" + item.code + (":" + str(item.http_status) if item.http_status is not None else "")
        for cap in capabilities
        if cap.state in {"partial", "unavailable"}
        for item in cap.diagnostics
        if item.code not in NON_PARTIAL_CODES
    ]


class EntraM365CollectResult(_WireModel):
    schema_version: Literal["entra-m365-collection/v1"]
    status: Literal["complete", "partial", "unavailable"]
    requested_capabilities: Annotated[list[CapabilityName], Field(min_length=1, max_length=9)]
    full_surface_complete: bool
    provenance: _Provenance
    capabilities: Annotated[list[EntraM365CapabilityResult], Field(min_length=9, max_length=9)]
    findings: list[_EntraM365Finding]
    manifest: CollectionManifest

    @field_validator("manifest", mode="before")
    @classmethod
    def detach_manifest(cls, value: object) -> object:
        return _strict_core_fields(value.model_dump() if isinstance(value, CollectionManifest) else value)

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        requested = [name for name in CAPABILITIES if name in self.requested_capabilities]
        if self.requested_capabilities != requested or [cap.name for cap in self.capabilities] != list(CAPABILITIES):
            raise ValueError("invalid_scope_order")
        for cap in self.capabilities:
            if (cap.state != "not_requested") != (cap.name in requested):
                raise ValueError("invalid_requested_scope")
        active = [cap for cap in self.capabilities if cap.name in requested]
        complete = all(cap.state == "complete" for cap in active)
        expected_status = (
            "complete" if complete else "partial" if any(cap.pages_completed for cap in active) else "unavailable"
        )
        if self.status != expected_status or self.full_surface_complete != (
            complete and requested == list(CAPABILITIES)
        ):
            raise ValueError("invalid_complete_claim")
        manifest = self.manifest
        if (
            not manifest.run_id.strip()
            or manifest.run_id != manifest.run_id.strip()
            or manifest.collector_id != COLLECTOR_ID
        ):
            raise ValueError("invalid_manifest_identity")
        if manifest.is_complete != complete or manifest.total_findings != len(self.findings):
            raise ValueError("invalid_manifest_completeness")
        if sum(cap.collected for cap in active) != len(self.findings):
            raise ValueError("invalid_finding_total")
        expected_counts = [(cap.name, cap.scanned, cap.matched_filter, cap.collected) for cap in active]
        actual_counts = [
            (count.resource_type, count.scanned, count.matched_filter, count.collected)
            for count in manifest.coverage_counts
        ]
        if actual_counts != expected_counts:
            raise ValueError("invalid_manifest_coverage")
        errors = _errors(active)
        if not complete and not errors:
            raise ValueError("incomplete_reason_required")
        if manifest.errors != errors or manifest.incomplete_reason != ("; ".join(errors) if errors else None):
            raise ValueError("invalid_manifest_errors")
        if manifest.empty_categories != [cap.name for cap in active if cap.state == "complete" and cap.collected == 0]:
            raise ValueError("invalid_empty_categories")
        started = _utc_clock(manifest.collection_started_at)
        finished = manifest.collection_finished_at
        if finished is None or _utc_clock(finished) < started:
            raise ValueError("invalid_manifest_clock")
        source_system_id = "entra-m365:operator-label:" + self.provenance.tenant_label
        if manifest.source_system_ids != [source_system_id]:
            raise ValueError("invalid_source_identity")
        scope = manifest.filters_applied
        scope_request = EntraM365CollectRequest.model_validate(
            {
                "tenant_label": self.provenance.tenant_label,
                "capabilities": requested,
                "lookback_days": scope.get("lookback_days"),
                "max_items": scope.get("max_items"),
                "max_pages": scope.get("max_pages"),
            }
        )
        if canonical_json(scope) != canonical_json(_scope(scope_request)):
            raise ValueError("invalid_manifest_scope")
        if manifest.warnings != _warnings(active):
            raise ValueError("invalid_manifest_warnings")
        by_name = {cap.name: cap for cap in active}
        for cap in active:
            if cap.started_at is not None and (
                cap.started_at < started or cap.finished_at is None or cap.finished_at > finished
            ):
                raise ValueError("invalid_capability_clock")
            if cap.pages_completed > scope_request.max_pages or cap.matched_filter > scope_request.max_items:
                raise ValueError("invalid_capability_limits")
            if cap.requested_window_end is not None and (
                cap.requested_window_end != started
                or cap.requested_window_start != started - timedelta(days=scope_request.lookback_days)
            ):
                raise ValueError("invalid_event_window")
        counts = {name: 0 for name in requested}
        returned: dict[CapabilityName, list[_EntraM365Finding]] = {name: [] for name in requested}
        identities = set()
        for finding in self.findings:
            if (
                finding.id in identities
                or finding.compliance_status != ComplianceStatus.UNKNOWN
                or finding.source_system != SOURCE_SYSTEM
            ):
                raise ValueError("invalid_finding_identity")
            identities.add(finding.id)
            context = finding.collection_context
            name = context.filter_applied.get("capability")
            if (
                name not in counts
                or context.run_id != manifest.run_id
                or context.collector_id != COLLECTOR_ID
                or context.source_system_id != source_system_id
            ):
                raise ValueError("invalid_finding_context")
            if not isinstance(finding.source_finding_id, str) or not finding.source_finding_id.startswith(
                self.provenance.tenant_label + ":"
            ):
                raise ValueError("invalid_finding_identity")
            if finding.id != deterministic_finding_id(SOURCE_SYSTEM, finding.source_finding_id):
                raise ValueError("invalid_finding_identity")
            if (
                finding.first_observed < started
                or finding.last_observed > finished
                or finding.first_observed > finding.last_observed
            ):
                raise ValueError("invalid_finding_clock")
            cap = by_name[name]
            if context.credential_identity != cap.credential_basis or canonical_json(
                context.filter_applied
            ) != canonical_json(_finding_scope(scope_request, cap)):
                raise ValueError("invalid_finding_scope")
            pagination = context.pagination_context
            if (
                pagination is None
                or pagination.model_dump()
                != PaginationContext(
                    total_pages=cap.pages_completed, continuation_token=None, is_complete=cap.state == "complete"
                ).model_dump()
            ):
                raise ValueError("invalid_finding_pagination")
            if (
                _utc_clock(context.collected_at) != finding.first_observed
                or context.collector_version != manifest.collector_version
            ):
                raise ValueError("invalid_finding_context")
            _validate_finding_content(finding, cap, self.provenance.tenant_label)
            counts[name] += 1
            returned[name].append(finding)
        if any(counts[cap.name] != cap.collected for cap in active):
            raise ValueError("invalid_capability_finding_total")
        for cap in active:
            _validate_returned_records(cap, returned[cap.name])
        return self


class EntraM365RunContext:
    @classmethod
    def start(
        cls,
        request: EntraM365CollectRequest,
        *,
        utc_clock: Callable[[], datetime],
        monotonic_clock: Callable[[], float],
        sleep: Callable[[float], None],
        run_id_factory: Callable[[], str],
    ) -> EntraM365RunContext:
        return cls(
            request, utc_clock=utc_clock, monotonic_clock=monotonic_clock, sleep=sleep, run_id_factory=run_id_factory
        )

    def __init__(
        self,
        request: EntraM365CollectRequest,
        *,
        utc_clock: Callable[[], datetime],
        monotonic_clock: Callable[[], float],
        sleep: Callable[[float], None],
        run_id_factory: Callable[[], str],
    ) -> None:
        self.request = EntraM365CollectRequest.model_validate(request)
        self._utc_clock = utc_clock
        self._monotonic_clock = monotonic_clock
        self._sleep = sleep
        self.started_at = self.utc_now()
        try:
            self.window_start = self.started_at - timedelta(days=self.request.lookback_days)
        except OverflowError:
            raise ValueError("invalid_clock") from None
        self.window_end = self.started_at
        self._start_exact = parse_source_timestamp(clock_text(self.window_start))
        self._end_exact = parse_source_timestamp(clock_text(self.window_end))
        self.run_id = run_id_factory()
        if not isinstance(self.run_id, str) or not self.run_id.strip() or len(self.run_id) > 128:
            raise ValueError("invalid_run_id")
        self._last_tick: float | None = None
        self._started_tick = self.tick()
        self.slots_used = 0
        self.decoded_bytes = 0
        self._readings: dict[CapabilityName, _Reading] = {}
        self._issued: dict[int, tuple[EntraM365SourceRead, EntraM365SourceRead]] = {}
        self._finished: set[int] = set()

    def utc_now(self) -> datetime:
        value = self._utc_clock()
        if not isinstance(value, datetime):
            raise ValueError("invalid_clock")
        return _utc_clock(value)

    def tick(self) -> float:
        value = self._monotonic_clock()
        if type(value) not in {int, float}:
            raise ValueError("internal_error")
        try:
            checked = float(value)
        except OverflowError:
            raise ValueError("internal_error") from None
        if not math.isfinite(checked) or (self._last_tick is not None and checked < self._last_tick):
            raise ValueError("internal_error")
        self._last_tick = checked
        return self._last_tick

    def begin(self, name: CapabilityName, mode: AuthMode | None) -> _Reading:
        if name not in self.request.capabilities or name in self._readings:
            raise ValueError("invalid_capability_order")
        reading = _Reading(self, name, mode)
        self._readings[name] = reading
        if self.tick() - self._started_tick >= 300:
            reading.add_diagnostic("run_budget")
        elif self.slots_used >= RUN_ITEM_LIMIT:
            reading.add_diagnostic("item_limit")
        elif self.decoded_bytes >= RUN_BYTE_LIMIT:
            reading.add_diagnostic("byte_limit")
        else:
            reading.started_at = self.utc_now()
            reading.started_tick = self.tick()
        return reading

    def not_requested(self, name: CapabilityName) -> EntraM365CapabilityRead:
        if name not in CAPABILITIES or name in self.request.capabilities:
            raise ValueError("invalid_capability_order")
        return EntraM365CapabilityRead(
            EntraM365CapabilityResult(
                name=name,
                state="not_requested",
                credential_basis=None,
                declared_auth_mode=None,
                scanned=0,
                matched_filter=0,
                collected=0,
                duplicate_records=0,
                pages_completed=0,
                requests_attempted=0,
                started_at=None,
                finished_at=None,
                requested_window_start=None,
                requested_window_end=None,
                observed_first=None,
                observed_last=None,
                field_coverage={},
                diagnostics=[],
            ),
            (),
        )

    def admit_dlp_export(self, export: EntraM365DlpExport) -> EntraM365SourceRead:
        checked = EntraM365DlpExport.model_validate(export)
        records = [
            EntraM365SourceRecord("dlp-policy", row.Guid, cast(JsonObject, row.model_dump()), None)
            for row in checked.policies
        ]
        records.extend(
            EntraM365SourceRecord("dlp-rule", row.Guid, cast(JsonObject, row.model_dump()), None)
            for row in checked.rules
        )
        read = self.begin("dlp-export", None)
        if read.started_at is not None:
            read.admit_page(records, continuation=False)
        if (
            checked.source.captured_at is not None
            and parse_source_timestamp(checked.source.captured_at).key > self._end_exact.key
        ):
            read.add_diagnostic("future_timestamp")
        return read.finish_source()

    def _remember(self, source: EntraM365SourceRead) -> None:
        snapshot = EntraM365SourceRead(
            EntraM365CapabilityResult.model_validate(source.capability),
            tuple(_copy_record(source.capability.name, record) for record in source.records),
        )
        self._issued[id(source)] = (source, snapshot)

    def _snapshot(self, source: EntraM365SourceRead) -> EntraM365SourceRead:
        pair = self._issued.get(id(source))
        if pair is None or pair[0] is not source or id(source) in self._finished:
            raise ValueError("invalid_source_read")
        return pair[1]

    def _finish_without_findings(
        self,
        source: EntraM365SourceRead,
        *,
        findings: Sequence[SecurityFinding],
        diagnostics: Sequence[EntraM365Diagnostic] = (),
    ) -> EntraM365CapabilityRead:
        snapshot = self._snapshot(source)
        if findings:
            raise ValueError("finding_factory_required")
        cap = EntraM365CapabilityResult.model_validate(snapshot.capability)
        merged = {(item.code, item.http_status): item.count for item in cap.diagnostics}
        for item in diagnostics:
            item = EntraM365Diagnostic.model_validate(item)
            key = (item.code, item.http_status)
            merged[key] = merged.get(key, 0) + item.count
        cap.diagnostics = [
            EntraM365Diagnostic(code=code, count=count, http_status=status) for (code, status), count in merged.items()
        ]
        if cap.state == "complete" and any(item.code not in NON_PARTIAL_CODES for item in cap.diagnostics):
            cap.state = "partial"
        if cap.started_at is not None:
            cap.finished_at = self.utc_now()
        cap = EntraM365CapabilityResult.model_validate(cap)
        self._finished.add(id(source))
        return EntraM365CapabilityRead(cap, ())

    def _made(self) -> dict[int, dict[str, bytes]]:
        if not hasattr(self, "_made_findings"):
            self._made_findings: dict[int, dict[str, bytes]] = {}
        return self._made_findings

    def make_finding(
        self,
        source: EntraM365SourceRead,
        rule: FindingRule,
        *,
        source_id: str | None,
        raw_data: JsonObject,
        severity: Severity = Severity.INFORMATIONAL,
        status: FindingStatus = FindingStatus.ACTIVE,
        resolved_at: datetime | None = None,
    ) -> _EntraM365Finding:
        snapshot = self._snapshot(source)
        if not isinstance(raw_data, dict):
            raise ValueError("invalid_finding_observation")
        spec = get_rule(rule)
        if spec.capability != snapshot.capability.name:
            raise ValueError("invalid_finding_rule")
        record = None
        if rule == "authentication-registration-summary":
            if source_id is not None or not snapshot.records:
                raise ValueError("invalid_finding_source")
        else:
            kind = (
                "dlp-policy"
                if rule == "dlp-policy-configuration"
                else "dlp-rule"
                if rule == "dlp-unresolved-rule"
                else "graph"
            )
            record = next(
                (item for item in snapshot.records if item.kind == kind and item.source_id == source_id), None
            )
            if record is None:
                raise ValueError("invalid_finding_source")
        defender = rule in {"defender-alert-observation", "defender-incident-observation"}
        if severity not in {Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM, Severity.HIGH} or status not in {
            FindingStatus.ACTIVE,
            FindingStatus.RESOLVED,
        }:
            raise ValueError("invalid_finding_state")
        if not defender and (
            severity != Severity.INFORMATIONAL or status != FindingStatus.ACTIVE or resolved_at is not None
        ):
            raise ValueError("invalid_finding_state")
        if defender and record is not None:
            expected_status = (
                FindingStatus.RESOLVED if record.fields.get("status") == "resolved" else FindingStatus.ACTIVE
            )
            source_severity = record.fields.get("severity")
            expected_severity = next(
                (level for level in (Severity.LOW, Severity.MEDIUM, Severity.HIGH) if level.value == source_severity),
                Severity.INFORMATIONAL,
            )
            if status != expected_status or severity != expected_severity:
                raise ValueError("invalid_finding_state")
        if resolved_at is not None:
            exact = (
                None
                if record is None or record.fields.get("resolvedDateTime") is None
                else parse_source_timestamp(record.fields["resolvedDateTime"]).exact_datetime()
            )
            if status != FindingStatus.RESOLVED or exact is None or _utc_clock(resolved_at) != exact:
                raise ValueError("invalid_resolution_time")
        observed = self.utc_now()
        suffix = spec.source_suffix.replace("{source_id}", source_id if source_id is not None else "")
        natural = self.request.tenant_label + ":" + suffix
        scoped = _scope(self.request) | {
            "capability": snapshot.capability.name,
            "requested_window_start": clock_text(snapshot.capability.requested_window_start)
            if snapshot.capability.requested_window_start
            else None,
            "requested_window_end": clock_text(snapshot.capability.requested_window_end)
            if snapshot.capability.requested_window_end
            else None,
        }
        data: JsonObject = {"observation": _selected_json(raw_data)}
        if record is not None:
            data["source"] = _selected_json(record.fields)
        basis = snapshot.capability.credential_basis
        if basis is None:
            raise ValueError("invalid_finding_source")
        finding = _EntraM365Finding(
            id=deterministic_finding_id(SOURCE_SYSTEM, natural),
            title=spec.title,
            description=spec.description,
            severity=severity,
            status=status,
            compliance_status=ComplianceStatus.UNKNOWN,
            source_system=SOURCE_SYSTEM,
            source_finding_id=natural,
            resource_type=spec.resource_type,
            resource_id=source_id,
            resource_account=self.request.tenant_label,
            control_mappings=control_mappings(rule),
            raw_data=data,
            first_observed=observed,
            last_observed=observed,
            resolved_at=resolved_at,
            collection_context=CollectionContext(
                collector_id=COLLECTOR_ID,
                collector_version=version("evidentia-collectors"),
                run_id=self.run_id,
                collected_at=observed,
                credential_identity=basis,
                source_system_id="entra-m365:operator-label:" + self.request.tenant_label,
                filter_applied=scoped,
                pagination_context=PaginationContext(
                    total_pages=snapshot.capability.pages_completed,
                    continuation_token=None,
                    is_complete=snapshot.capability.state == "complete",
                ),
            ),
        )
        issued = self._made().setdefault(id(source), {})
        if finding.id in issued:
            raise ValueError("duplicate_finding")
        issued[finding.id] = _finding_digest(finding)
        return finding

    def finish_read(
        self,
        source: EntraM365SourceRead,
        *,
        findings: Sequence[SecurityFinding],
        diagnostics: Sequence[EntraM365Diagnostic] = (),
    ) -> EntraM365CapabilityRead:
        snapshot = self._snapshot(source)
        if snapshot.capability.name != "dlp-export":
            expected = (
                1
                if snapshot.capability.name == "authentication-registration" and snapshot.records
                else len(snapshot.records)
            )
            if len(findings) != expected:
                raise ValueError("missing_observation")
        else:
            policy_ids = {
                deterministic_finding_id(
                    SOURCE_SYSTEM, self.request.tenant_label + ":dlp-export:policy:" + record.source_id
                )
                for record in snapshot.records
                if record.kind == "dlp-policy"
            }
            if not policy_ids.issubset({finding.id for finding in findings}):
                raise ValueError("missing_observation")
        copied = []
        identities = set()
        for finding in findings:
            if finding.id in identities or self._made().get(id(source), {}).get(finding.id) != _finding_digest(finding):
                raise ValueError("invalid_finding_evidence")
            identities.add(finding.id)
            copied.append(_EntraM365Finding.model_validate(finding))
        read = self._finish_without_findings(source, findings=[], diagnostics=diagnostics)
        fields = read.capability.model_dump()
        fields["collected"] = len(copied)
        cap = EntraM365CapabilityResult.model_validate(fields)
        for finding in copied:
            if finding.collection_context.pagination_context is not None:
                finding.collection_context.pagination_context.is_complete = cap.state == "complete"
        result = EntraM365CapabilityRead(cap, tuple(copied))
        if not hasattr(self, "_completed_reads"):
            self._completed_reads: dict[str, tuple[EntraM365CapabilityRead, bytes]] = {}
        self._completed_reads[cap.name] = (result, self._read_digest(result))
        return result

    @staticmethod
    def _read_digest(read: EntraM365CapabilityRead) -> bytes:
        return _digest(
            {
                "capability": cast(JsonObject, read.capability.model_dump(mode="json")),
                "findings": [cast(JsonObject, finding.model_dump(mode="json")) for finding in read.findings],
            }
        )

    def build_result(self, reads: Sequence[EntraM365CapabilityRead]) -> EntraM365CollectResult:
        by_name = {read.capability.name: read for read in reads}
        if len(by_name) != len(reads) or set(by_name) != set(self.request.capabilities):
            raise ValueError("invalid_collection_scope")
        if not hasattr(self, "_completed_reads"):
            raise ValueError("invalid_capability_read")
        for name, read in by_name.items():
            pair = self._completed_reads.get(name)
            if pair is None or pair[0] is not read or pair[1] != self._read_digest(read):
                raise ValueError("invalid_capability_read")
        ordered = [by_name[name] if name in by_name else self.not_requested(name) for name in CAPABILITIES]
        caps = [read.capability for read in ordered]
        active = [cap for cap in caps if cap.state != "not_requested"]
        complete = all(cap.state == "complete" for cap in active)
        findings = [_EntraM365Finding.model_validate(finding) for read in ordered for finding in read.findings]
        errors = _errors(active)
        warnings = _warnings(active)
        finished = self.utc_now()
        manifest = CollectionManifest(
            run_id=self.run_id,
            collector_id=COLLECTOR_ID,
            collector_version=version("evidentia-collectors"),
            collection_started_at=self.started_at,
            collection_finished_at=finished,
            source_system_ids=["entra-m365:operator-label:" + self.request.tenant_label],
            filters_applied=_scope(self.request),
            coverage_counts=[
                CoverageCount(
                    resource_type=cap.name,
                    scanned=cap.scanned,
                    matched_filter=cap.matched_filter,
                    collected=cap.collected,
                )
                for cap in active
            ],
            total_findings=len(findings),
            is_complete=complete,
            incomplete_reason="; ".join(errors) if errors else None,
            empty_categories=[cap.name for cap in active if cap.state == "complete" and cap.collected == 0],
            warnings=warnings,
            errors=errors,
        )
        return EntraM365CollectResult(
            schema_version="entra-m365-collection/v1",
            status="complete"
            if complete
            else "partial"
            if any(cap.pages_completed for cap in active)
            else "unavailable",
            requested_capabilities=list(self.request.capabilities),
            full_surface_complete=complete and self.request.capabilities == list(CAPABILITIES),
            provenance=_Provenance(
                tenant_label=self.request.tenant_label,
                identity_basis="operator-declared",
                authenticated_identity_verified=False,
                graph_cloud="commercial",
            ),
            capabilities=caps,
            findings=findings,
            manifest=manifest,
        )


class _Reading:
    def __init__(self, context: EntraM365RunContext, name: CapabilityName, mode: AuthMode | None) -> None:
        self.context = context
        self.name = name
        self.mode = mode
        self.started_at: datetime | None = None
        self.started_tick: float | None = None
        self.raw_bytes = 0
        self.decoded_bytes = 0
        self.pages = 0
        self.attempts = 0
        self.scanned = 0
        self.duplicates = 0
        self._identities: dict[tuple[str, str], _Identity] = {}
        self._diagnostics: dict[tuple[DiagnosticCode, int | None], int] = {}
        self._closed = False
        self._accepting = True

    def add_diagnostic(self, code: DiagnosticCode, *, count: int = 1, status: int | None = None) -> None:
        item = EntraM365Diagnostic(code=code, count=count, http_status=status)
        key = (item.code, item.http_status)
        self._diagnostics[key] = self._diagnostics.get(key, 0) + item.count

    def remaining(self) -> float:
        now = self.context.tick()
        run_remaining = 300 - (now - self.context._started_tick)
        if run_remaining <= 0:
            raise ValueError("run_budget")
        if self.started_tick is None:
            raise ValueError("capability_budget")
        cap_remaining = 60 - (now - self.started_tick)
        if cap_remaining <= 0:
            raise ValueError("capability_budget")
        return min(run_remaining, cap_remaining)

    def consume(self, raw: int, decoded: int) -> None:
        if type(raw) is not int or type(decoded) is not int or raw < 0 or decoded < 0:
            raise ValueError("internal_error")
        self.raw_bytes += raw
        self.decoded_bytes += decoded
        self.context.decoded_bytes += decoded
        if self.decoded_bytes > CAPABILITY_BYTE_LIMIT or self.context.decoded_bytes > RUN_BYTE_LIMIT:
            raise ValueError("byte_limit")
        self.remaining()

    def note_attempt(self) -> None:
        if self._closed or not self._accepting or self.name == "dlp-export":
            raise ValueError("invalid_reading")
        self.remaining()
        if self.decoded_bytes >= CAPABILITY_BYTE_LIMIT or self.context.decoded_bytes >= RUN_BYTE_LIMIT:
            raise ValueError("byte_limit")
        self.attempts += 1

    def wait(self, seconds: float) -> None:
        if not math.isfinite(seconds) or seconds < 0 or seconds > self.remaining():
            raise ValueError("retry_after_budget")
        self.context._sleep(seconds)
        self.remaining()

    def admit_page(self, records: Sequence[EntraM365SourceRecord], *, continuation: bool) -> bool:
        if self._closed or not self._accepting or self.started_at is None:
            raise ValueError("invalid_reading")
        self.remaining()
        if self.pages >= self.context.request.max_pages or (
            self.name in {"directory-roles", "dlp-export"} and self.pages
        ):
            raise ValueError("page_limit")
        if self.name in {"directory-roles", "dlp-export"} and continuation:
            raise ValueError("continuation_invalid")
        if len(records) > (20_000 if self.name == "dlp-export" else 10_000):
            raise ValueError("invalid_envelope")
        validated = [_copy_record(self.name, record) for record in records]
        # Full validation precedes the first identity, counter or diagnostic mutation.
        projected = [(record, _signature(record)) for record in validated]
        self.remaining()
        limited = False
        for record, signature in projected:
            key = (record.kind, record.source_id)
            identity = self._identities.get(key)
            if identity is not None:
                if signature in identity.variants:
                    self.duplicates += 1
                else:
                    if identity.record is not None:
                        self.add_diagnostic("conflicting_duplicate")
                    identity.record = None
                    identity.variants.add(signature)
            elif len(self._identities) < self.context.request.max_items and self.context.slots_used < RUN_ITEM_LIMIT:
                self._identities[key] = _Identity(record, {signature})
                self.context.slots_used += 1
            else:
                limited = True
        self.scanned += len(validated)
        self.pages += 1
        at_cap = len(self._identities) >= self.context.request.max_items or self.context.slots_used >= RUN_ITEM_LIMIT
        if not continuation:
            self._accepting = False
        if limited or (continuation and at_cap):
            self._accepting = False
            self.add_diagnostic("item_limit")
            return False
        if continuation and self.pages >= self.context.request.max_pages:
            self._accepting = False
            self.add_diagnostic("page_limit")
            return False
        return True

    def finish_source(self) -> EntraM365SourceRead:
        if self._closed:
            raise ValueError("invalid_reading")
        derived = dict(self._diagnostics)
        if self.pages and self._accepting and not any(code not in NON_PARTIAL_CODES for code, status in derived):
            derived[("continuation_invalid", None)] = 1

        def diagnose(code: DiagnosticCode) -> None:
            key = (code, None)
            derived[key] = derived.get(key, 0) + 1

        records = []
        for identity in self._identities.values():
            record = identity.record
            if record is None:
                continue
            times = [
                parse_source_timestamp(record.fields[key])
                for key, kind in GRAPH_FIELDS.get(self.name, {}).items()
                if kind == "timestamp" and record.fields.get(key) is not None
            ]
            if any(stamp.key > self.context._end_exact.key for stamp in times):
                diagnose("future_timestamp")
            if (
                record.event_time is not None
                and not self.context._start_exact.key <= record.event_time.key <= self.context._end_exact.key
            ):
                continue
            if self.name == "sign-ins" and record.fields.get("appliedConditionalAccessPolicies") is None:
                diagnose("conditional_access_detail_unavailable")
            records.append(_copy_record(self.name, record))
        times = [record.event_time for record in records if record.event_time is not None]
        first: _ExactSourceTimestamp | None = None
        last: _ExactSourceTimestamp | None = None
        if times:
            first_key = min(stamp.key for stamp in times)
            last_key = max(stamp.key for stamp in times)
            first = max((stamp for stamp in times if stamp.key == first_key), key=lambda stamp: len(stamp.fraction))
            last = max((stamp for stamp in times if stamp.key == last_key), key=lambda stamp: len(stamp.fraction))
        diagnostics = [
            EntraM365Diagnostic(code=code, count=count, http_status=status) for (code, status), count in derived.items()
        ]
        state: CapabilityState = (
            "unavailable"
            if not self.pages
            else "partial"
            if any(item.code not in NON_PARTIAL_CODES for item in diagnostics)
            else "complete"
        )
        basis: CredentialBasis = (
            "unverified:dlp-export"
            if self.name == "dlp-export"
            else "unverified:retention-token"
            if self.name == "retention-labels"
            else "unverified:primary-token"
        )
        event = self.name in EVENT_CAPABILITIES
        result = EntraM365CapabilityResult(
            name=self.name,
            state=state,
            credential_basis=basis,
            declared_auth_mode=self.mode,
            scanned=self.scanned,
            matched_filter=len(records),
            collected=0,
            duplicate_records=self.duplicates,
            pages_completed=self.pages,
            requests_attempted=self.attempts,
            started_at=self.started_at,
            finished_at=self.context.utc_now() if self.started_at is not None else None,
            requested_window_start=self.context.window_start if event else None,
            requested_window_end=self.context.window_end if event else None,
            observed_first=first.utc if first else None,
            observed_last=last.utc if last else None,
            field_coverage=_field_coverage(self.name, records) if self.pages else {},
            diagnostics=diagnostics,
        )
        source = EntraM365SourceRead(result, tuple(records))
        self.context._remember(source)
        self._closed = True
        return source
