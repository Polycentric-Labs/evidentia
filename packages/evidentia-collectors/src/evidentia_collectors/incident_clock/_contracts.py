"""Native incident requests, workflow mappings and selected source values."""

from __future__ import annotations

import hashlib
import re
import unicodedata
import weakref
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta, timezone
from types import UnionType
from typing import TYPE_CHECKING, Annotated, Any, Literal, Self, Union, cast, get_args, get_origin
from uuid import NAMESPACE_URL, uuid5

from evidentia_core.audit.provenance import CollectionContext, CollectionManifest, CoverageCount
from evidentia_core.models.common import ControlMapping, Severity
from evidentia_core.models.finding import ComplianceStatus, FindingStatus, SecurityFinding
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    ValidationInfo,
    field_validator,
    model_validator,
)

from ._clock import Provider, elapsed_seconds, parse_instant
from ._parsing import (
    PROJECTION_BYTE_LIMIT,
    REQUEST_BYTE_LIMIT,
    RESULT_BYTE_LIMIT,
    _string_size,
    canonical_json,
    checked_json,
    parse_result_json,
    parse_strict_json,
    result_json_bytes,
)

if TYPE_CHECKING:
    from ._client import RunAuthority


class IncidentInputError(ValueError):
    """Expose a fixed input or reconstruction diagnostic."""

    def __init__(
        self, code: Literal["invalid_request", "invalid_result", "source_shape", "result_limit"] = "invalid_request"
    ) -> None:
        if type(code) is not str or code not in ("invalid_request", "invalid_result", "source_shape", "result_limit"):
            code = "invalid_request"
        self.code = code
        super().__init__(code)


_MODEL_TYPES: tuple[type[BaseModel], ...] = ()


def bounded_text(value: object, maximum: int, *, nonblank: bool = False, controls: bool = True) -> str:
    if type(value) is not str or len(value) > maximum:
        raise IncidentInputError()
    try:
        if len(value.encode("utf-8")) > maximum or (nonblank and not value.strip()):
            raise IncidentInputError()
    except UnicodeError:
        raise IncidentInputError() from None
    if controls and any(unicodedata.category(char) in ("Cc", "Cf", "Cs") for char in value):
        raise IncidentInputError()
    return value


def _native(value: object, depth: int = 0, budget: list[int] | None = None) -> Any:
    """Detach exact known values within the complete publication byte and node caps."""
    if budget is None:
        budget = [0, 0]
    budget[0] += 1
    if depth > 32 or budget[0] > 8388608:
        raise IncidentInputError()
    native_type = type(value)
    if native_type is str:
        budget[1] += _string_size(cast(str, value))
    elif native_type is int or native_type is float:
        budget[1] += len(canonical_json(value))
    elif native_type is bool:
        budget[1] += 4 if value else 5
    elif value is None:
        budget[1] += 4
    elif native_type is datetime:
        budget[1] += 29
    else:
        budget[1] += 2
    if budget[1] > 16777216:
        raise IncidentInputError()
    if (
        value is None
        or native_type is str
        or native_type is bool
        or native_type is int
        or native_type is float
        or native_type is datetime
    ):
        return value
    if any(native_type is model for model in _MODEL_TYPES):
        model = cast(BaseModel, value)
        model_type = cast(type[BaseModel], native_type)
        fields = object.__getattribute__(model, "__dict__")
        extra = object.__getattribute__(model, "__pydantic_extra__")
        if (
            type(fields) is not dict
            or extra is not None
            or any(type(key) is not str for key in fields)
            or set(fields) != set(model_type.model_fields)
        ):
            raise IncidentInputError()
        data = {model_type.model_fields[key].alias or key: item for key, item in fields.items()}
    elif native_type is dict:
        data = cast(dict[object, object], value)
    elif native_type is list:
        items = cast(list[object], value)
        if len(items) > 100000:
            raise IncidentInputError()
        budget[1] += max(0, len(items) - 1)
        return [_native(item, depth + 1, budget) for item in items]
    else:
        raise IncidentInputError()
    if len(data) > 100000 or any(type(key) is not str for key in data):
        raise IncidentInputError()
    budget[1] += max(0, len(data) - 1)
    result: dict[str, Any] = {}
    for key, item in data.items():
        budget[0] += 1
        budget[1] += _string_size(key) + 1
        result[key] = _native(item, depth + 1, budget)
    return result


def _exact_type(value: object, annotation: object) -> bool:
    if annotation is Any:
        return True
    if annotation is CoverageCount:
        return type(value) is dict
    origin = get_origin(annotation)
    arguments = get_args(annotation)
    if origin is Annotated:
        return _exact_type(value, arguments[0])
    if origin is Union or origin is UnionType:
        return any(_exact_type(value, item) for item in arguments)
    if origin is Literal:
        for item in arguments:
            if any(type(item) is enum for enum in (Severity, FindingStatus, ComplianceStatus)):
                item = item.value
            if type(value) is type(item) and value == item:
                return True
        return False
    if annotation is str or annotation is int or annotation is bool or annotation is float or annotation is datetime:
        return type(value) is annotation
    if annotation is type(None):
        return value is None
    if origin is list:
        return type(value) is list and all(_exact_type(item, arguments[0]) for item in value)
    if origin is dict:
        return type(value) is dict and all(
            _exact_type(key, arguments[0]) and _exact_type(item, arguments[1]) for key, item in value.items()
        )
    if any(annotation is model for model in _MODEL_TYPES):
        return type(value) is dict
    return False


class _WireModel(BaseModel):
    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, validate_default=True, revalidate_instances="always"
    )

    @model_validator(mode="before")
    @classmethod
    def _check_native_fields(cls, value: object, info: ValidationInfo) -> object:
        try:
            data = _native(value)
            if type(data) is not dict:
                raise IncidentInputError()
            names = {field.alias or name: field for name, field in cls.model_fields.items()}
            if not set(data).issubset(names):
                raise IncidentInputError()
            for name, item in data.items():
                annotation = names[name].annotation
                # JSON timestamps are parsed only for declared UTC wall-clock fields.
                if annotation is datetime and info.mode == "json" and type(item) is str:
                    continue
                if not _exact_type(item, annotation):
                    raise IncidentInputError()
            return data
        except (AttributeError, TypeError, ValueError, RuntimeError, RecursionError):
            raise IncidentInputError() from None

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        data = _native(self)
        if update is not None:
            if type(update) is not dict or any(type(key) is not str for key in update):
                raise IncidentInputError()
            data.update(update)
        return type(self).model_validate(data)


def _alias(value: object) -> str:
    text = bounded_text(value, 64, nonblank=True)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", text) is None:
        raise IncidentInputError()
    return text


Alias = Annotated[
    str, BeforeValidator(_alias), Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
]
OpaqueId = Annotated[
    str, BeforeValidator(lambda value: bounded_text(value, 256, nonblank=True)), Field(min_length=1, max_length=256)
]
Sha256 = Annotated[str, Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")]
ReadId = Annotated[str, Field(min_length=69, max_length=69, pattern=r"^read-[0-9a-f]{64}$")]
EventId = Annotated[str, Field(min_length=70, max_length=70, pattern=r"^event-[0-9a-f]{64}$")]


class JiraOccurrence(_WireModel):
    history_id: OpaqueId
    item_index: int = Field(ge=0, le=255)


class PagerDutyOccurrence(_WireModel):
    event_id: OpaqueId


class ServiceNowOccurrence(_WireModel):
    field: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_]{0,79}$")


Occurrence = ServiceNowOccurrence | JiraOccurrence | PagerDutyOccurrence


class _Request(_WireModel):
    profile_alias: Alias
    clock_alias: Alias


class ServiceNowRequest(_Request):
    provider: Literal["servicenow"]
    record_id: str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")


class JiraRequest(_Request):
    provider: Literal["jira"]
    record_id: str = Field(min_length=1, max_length=32, pattern=r"^[1-9][0-9]{0,31}$")
    start_occurrence: JiraOccurrence | None = None
    end_occurrence: JiraOccurrence | None = None


class PagerDutyRequest(_Request):
    provider: Literal["pagerduty"]
    record_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
    since: str = Field(min_length=1, max_length=2048)
    until: str = Field(min_length=1, max_length=2048)
    start_occurrence: PagerDutyOccurrence | None = None
    end_occurrence: PagerDutyOccurrence | None = None

    @model_validator(mode="after")
    def interval(self) -> Self:
        duration = elapsed_seconds(parse_instant(self.since, "pagerduty"), parse_instant(self.until, "pagerduty"))
        if duration is None or duration == "0":
            raise IncidentInputError()
        whole, _, fraction = duration.partition(".")
        if int(whole) > 31622400 or (int(whole) == 31622400 and fraction):
            raise IncidentInputError()
        return self


IncidentClockRequest = Annotated[ServiceNowRequest | JiraRequest | PagerDutyRequest, Field(discriminator="provider")]
_REQUESTS: dict[str, type[ServiceNowRequest] | type[JiraRequest] | type[PagerDutyRequest]] = {
    "servicenow": ServiceNowRequest,
    "jira": JiraRequest,
    "pagerduty": PagerDutyRequest,
}


def validated_request(value: object) -> IncidentClockRequest:
    try:
        data = _native(value)
        if type(data) is not dict:
            raise IncidentInputError()
        data = checked_json(data, max_bytes=REQUEST_BYTE_LIMIT)
        if type(data) is not dict:
            raise IncidentInputError()
        provider = data.get("provider")
        if type(provider) is not str or provider not in _REQUESTS:
            raise IncidentInputError()
        expected = _REQUESTS[provider]
        if any(type(value) is request for request in _REQUESTS.values()) and type(value) is not expected:
            raise IncidentInputError()
        return expected.model_validate(data)
    except (AttributeError, TypeError, ValueError, RuntimeError, RecursionError):
        raise IncidentInputError() from None


def parse_request(content: bytes) -> IncidentClockRequest:
    try:
        return validated_request(parse_strict_json(content, max_bytes=REQUEST_BYTE_LIMIT))
    except (TypeError, ValueError):
        raise IncidentInputError() from None


def request_identity(request: IncidentClockRequest) -> str:
    return hashlib.sha256(canonical_json(_native(validated_request(request)), max_bytes=REQUEST_BYTE_LIMIT)).hexdigest()


class NativeTextCell(_WireModel):
    state: Literal["missing", "null", "empty", "value"]
    value: str | None

    @model_validator(mode="after")
    def state_matches_value(self) -> Self:
        if self.state in ("missing", "null"):
            valid = self.value is None
        elif self.state == "empty":
            valid = self.value == ""
        else:
            valid = self.value is not None and self.value != ""
        if not valid:
            raise IncidentInputError("source_shape")
        if self.value is not None:
            bounded_text(self.value, 65536, controls=False)
        return self

    def bounded(self, maximum: int) -> Self:
        value = type(self).model_validate(self)
        if value.value is not None:
            bounded_text(value.value, maximum, controls=False)
        return value


def native_text_cell(data: object, key: str, *, maximum: int = 65536) -> NativeTextCell:
    if type(data) is not dict or type(key) is not str or any(type(name) is not str for name in data):
        raise IncidentInputError("source_shape")
    if key not in data:
        return NativeTextCell(state="missing", value=None)
    value = data[key]
    if value is None:
        return NativeTextCell(state="null", value=None)
    text = bounded_text(value, maximum, controls=False)
    return NativeTextCell(state="empty" if text == "" else "value", value=text)


class _Mapping(_WireModel):
    label: str = Field(min_length=1, max_length=128)
    meaning: str = Field(min_length=1, max_length=512)

    @field_validator("label", "meaning", mode="before")
    @classmethod
    def text_bounds(cls, value: object, info: ValidationInfo) -> str:
        return bounded_text(value, 128 if info.field_name == "label" else 512, nonblank=True)


class ServiceNowMapping(_Mapping):
    field: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_]{0,79}$")


class JiraMapping(_Mapping):
    field_id: OpaqueId
    from_value: NativeTextCell = Field(alias="from")
    to: NativeTextCell

    @model_validator(mode="after")
    def explicit_transition(self) -> Self:
        if self.from_value.state not in ("null", "value") or self.to.state not in ("null", "value"):
            raise IncidentInputError()
        return self


PagerDutyEventType = Literal[
    "acknowledge_log_entry",
    "annotate_log_entry",
    "assign_log_entry",
    "delegate_log_entry",
    "escalate_log_entry",
    "exhaust_escalation_path_log_entry",
    "notify_log_entry",
    "reach_ack_limit_log_entry",
    "reach_trigger_limit_log_entry",
    "repeat_escalation_path_log_entry",
    "resolve_log_entry",
    "snooze_log_entry",
    "trigger_log_entry",
    "unacknowledge_log_entry",
    "urgency_change_log_entry",
    "field_value_change_log_entry",
    "custom_field_value_change_log_entry",
]


class PagerDutyMapping(_Mapping):
    event_type: PagerDutyEventType


EventMapping = ServiceNowMapping | JiraMapping | PagerDutyMapping


class PublishedClockDefinition(_WireModel):
    clock_alias: Alias
    label: str = Field(min_length=1, max_length=128)
    mapping_reference: str = Field(min_length=1, max_length=512)
    declared_workflow_meaning: str = Field(min_length=1, max_length=1024)
    definition_sha256: Sha256
    start: EventMapping
    end: EventMapping

    @field_validator("label", "mapping_reference", "declared_workflow_meaning", mode="before")
    @classmethod
    def text_bounds(cls, value: object, info: ValidationInfo) -> str:
        bound = {"label": 128, "mapping_reference": 512, "declared_workflow_meaning": 1024}[info.field_name or ""]
        return bounded_text(value, bound, nonblank=True)

    @model_validator(mode="after")
    def digest_matches(self) -> Self:
        data = _native(self)
        data.pop("definition_sha256")
        if hashlib.sha256(canonical_json(data)).hexdigest() != self.definition_sha256:
            raise IncidentInputError()
        if type(self.start) is not type(self.end):
            raise IncidentInputError()
        if (
            type(self.start) is ServiceNowMapping
            and type(self.end) is ServiceNowMapping
            and self.start.field == self.end.field
        ):
            raise IncidentInputError()
        return self


def published_definition(provider: Provider, value: object) -> PublishedClockDefinition:
    try:
        data = _native(value)
        if type(data) is not dict:
            raise IncidentInputError()
        if "definition_sha256" not in data:
            data["definition_sha256"] = hashlib.sha256(canonical_json(data)).hexdigest()
        definition = PublishedClockDefinition.model_validate(data)
        expected = {"servicenow": ServiceNowMapping, "jira": JiraMapping, "pagerduty": PagerDutyMapping}
        if type(provider) is not str or provider not in expected or type(definition.start) is not expected[provider]:
            raise IncidentInputError()
        return definition
    except (AttributeError, TypeError, ValueError, RuntimeError, RecursionError):
        raise IncidentInputError() from None


def utc_clock(value: object) -> datetime:
    if type(value) is not datetime or type(value.tzinfo) is not timezone or value.utcoffset() != timedelta(0):
        raise IncidentInputError()
    return value.replace(tzinfo=UTC)


def _utc_json(value: datetime) -> str:
    return utc_clock(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _utc_input(value: object, info: ValidationInfo) -> datetime:
    if info.mode == "json":
        if (
            type(value) is not str
            or len(value) != 27
            or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z", value) is None
        ):
            raise IncidentInputError()
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            raise IncidentInputError() from None
    return utc_clock(value)


UtcClock = Annotated[
    datetime, BeforeValidator(_utc_input), PlainSerializer(_utc_json, return_type=str, when_used="json")
]

_MODEL_TYPES = (
    JiraOccurrence,
    PagerDutyOccurrence,
    ServiceNowOccurrence,
    ServiceNowRequest,
    JiraRequest,
    PagerDutyRequest,
    NativeTextCell,
    ServiceNowMapping,
    JiraMapping,
    PagerDutyMapping,
    PublishedClockDefinition,
)


SourceState = Literal["complete", "incomplete", "unavailable"]
Side = Literal["start", "end"]
DiagnosticCode = Literal[
    "profile_refused",
    "credential_missing",
    "credential_expired",
    "credential_invalid",
    "offline_refused",
    "destination_refused",
    "dns_failure",
    "dns_timeout",
    "connect_failure",
    "tls_failure",
    "read_timeout",
    "deadline_exceeded",
    "redirect_refused",
    "http_unauthorized",
    "http_forbidden",
    "http_not_found",
    "http_status_refused",
    "body_limit",
    "response_budget",
    "unsupported_encoding",
    "invalid_json",
    "source_shape",
    "record_mismatch",
    "site_grant_refused",
    "pagination_conflict",
    "duplicate_occurrence",
    "source_conflict",
    "page_limit",
    "event_limit",
    "result_limit",
    "timestamp_unsupported",
    "event_missing",
    "event_null",
    "event_empty",
    "event_ambiguous",
    "occurrence_not_found",
    "reversed_order",
    "incomplete_source",
    "cleanup_failure",
    "header_limit",
    "framing_limit",
    "wire_budget",
    "framing_invalid",
]


class Diagnostic(_WireModel):
    code: DiagnosticCode
    read_id: ReadId | None
    side: Side | None


class DeclaredPagination(_WireModel):
    start: int = Field(ge=0, le=10000)
    limit: int = Field(ge=1, le=100)
    total: int = Field(ge=0, le=1000000000)
    terminal: bool
    returned: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def counters_agree(self) -> Self:
        position = self.start + self.returned
        if self.returned > self.limit or position > self.total or self.terminal != (position == self.total):
            raise IncidentInputError("source_shape")
        if not self.terminal and self.returned == 0:
            raise IncidentInputError("source_shape")
        return self


EndpointTemplate = Literal[
    "servicenow_record",
    "jira_accessible_resources",
    "jira_issue",
    "jira_changelog",
    "pagerduty_incident",
    "pagerduty_log_entries",
]


class SourceRead(_WireModel):
    read_id: ReadId
    ordinal: int = Field(ge=0, le=101)
    kind: Literal["jira_access", "record", "history"]
    template: EndpointTemplate
    state: Literal["admitted", "rejected", "unavailable"]
    http_status: int | None = Field(ge=100, le=599)
    retrieved_at: UtcClock
    body_bytes: int = Field(ge=0, le=1048577)
    body_complete: bool
    body_sha256: Sha256 | None
    accepted: bool
    pagination: DeclaredPagination | None
    received_records: int | None = Field(ge=0, le=100000)
    admitted_events: int = Field(ge=0, le=10000)
    diagnostic_codes: list[DiagnosticCode] = Field(max_length=64)
    wire_bytes: int = Field(ge=0, le=1179649)

    @model_validator(mode="after")
    def read_consistency(self) -> Self:
        expected_kind = {
            "servicenow_record": "record",
            "jira_accessible_resources": "jira_access",
            "jira_issue": "record",
            "jira_changelog": "history",
            "pagerduty_incident": "record",
            "pagerduty_log_entries": "history",
        }[self.template]
        if self.kind != expected_kind or self.accepted != (self.state == "admitted"):
            raise IncidentInputError("source_shape")
        if self.body_complete != (self.body_sha256 is not None) or self.wire_bytes < self.body_bytes:
            raise IncidentInputError("source_shape")
        if self.body_complete and (self.body_bytes > 1048576 or self.http_status != 200):
            raise IncidentInputError("source_shape")
        if (not self.body_complete or "invalid_json" in self.diagnostic_codes) and self.received_records is not None:
            raise IncidentInputError("source_shape")
        if len(set(self.diagnostic_codes)) != len(self.diagnostic_codes):
            raise IncidentInputError("source_shape")
        if self.accepted:
            if self.http_status != 200 or not self.body_complete or self.received_records is None:
                raise IncidentInputError("source_shape")
            if self.kind == "record" and (self.received_records != 1 or self.pagination is not None):
                raise IncidentInputError("source_shape")
            if self.kind == "history" and (
                self.pagination is None or self.received_records != self.pagination.returned
            ):
                raise IncidentInputError("source_shape")
            if self.kind == "jira_access" and (self.admitted_events != 0 or self.pagination is not None):
                raise IncidentInputError("source_shape")
        elif self.admitted_events != 0 or self.pagination is not None:
            raise IncidentInputError("source_shape")
        return self


def valid_record_id(provider: Provider, value: object) -> str:
    text = bounded_text(value, 128, nonblank=True)
    patterns = {
        "servicenow": r"[0-9a-f]{32}",
        "jira": r"[1-9][0-9]{0,31}",
        "pagerduty": r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}",
    }
    if type(provider) is not str or provider not in patterns or re.fullmatch(patterns[provider], text) is None:
        raise IncidentInputError("source_shape")
    return text


class SelectedRecordProjection(_WireModel):
    provider: Provider
    record_id: str = Field(min_length=1, max_length=128)
    read_id: ReadId
    fields: dict[str, NativeTextCell] = Field(min_length=2, max_length=3)

    @model_validator(mode="after")
    def fixed_record_fields(self) -> Self:
        valid_record_id(self.provider, self.record_id)
        keys = set(self.fields)
        if self.provider == "servicenow":
            identity = "sys_id"
            if len(keys) != 3 or identity not in keys:
                raise IncidentInputError("source_shape")
            if any(re.fullmatch(r"[a-z][a-z0-9_]{0,79}", key) is None for key in keys):
                raise IncidentInputError("source_shape")
        else:
            identity = "id"
            if keys != ({"id", "fields.created"} if self.provider == "jira" else {"id", "created_at"}):
                raise IncidentInputError("source_shape")
        cell = self.fields[identity]
        if cell.state != "value" or cell.value != self.record_id:
            raise IncidentInputError("source_shape")
        for name, value in self.fields.items():
            value.bounded(128 if name == identity else 2048)
        return self


def occurrence_provider(value: Occurrence) -> Provider:
    if type(value) is ServiceNowOccurrence:
        return "servicenow"
    if type(value) is JiraOccurrence:
        return "jira"
    if type(value) is PagerDutyOccurrence:
        return "pagerduty"
    raise IncidentInputError("source_shape")


class SourceEvent(_WireModel):
    event_id: EventId
    record_id: str = Field(min_length=1, max_length=128)
    read_id: ReadId
    occurrence: Occurrence
    timestamp: NativeTextCell
    native_fields: dict[str, NativeTextCell] = Field(min_length=2, max_length=4)
    matches: list[Side] = Field(max_length=2)

    @model_validator(mode="after")
    def fixed_event_fields(self) -> Self:
        provider = occurrence_provider(self.occurrence)
        valid_record_id(provider, self.record_id)
        self.timestamp.bounded(2048)
        if self.matches not in ([], ["start"], ["end"], ["start", "end"]):
            raise IncidentInputError("source_shape")
        if provider == "servicenow":
            keys, time_key = {"field", "value"}, "value"
            occurrence = cast(ServiceNowOccurrence, self.occurrence)
            identity = ("field", occurrence.field)
        elif provider == "jira":
            keys, time_key = {"fieldId", "from", "to", "created"}, "created"
            identity = None
        else:
            keys, time_key = {"id", "type", "created_at", "incident.id"}, "created_at"
            identity = ("id", cast(PagerDutyOccurrence, self.occurrence).event_id)
        if set(self.native_fields) != keys or self.timestamp != self.native_fields[time_key]:
            raise IncidentInputError("source_shape")
        for name, value in self.native_fields.items():
            bound = 2048 if name == time_key else 65536
            if name == "field":
                bound = 80
            elif name in ("fieldId", "id", "type", "incident.id"):
                bound = 256
            value.bounded(bound)
        if identity is not None:
            cell = self.native_fields[identity[0]]
            if cell.state != "value" or cell.value != identity[1]:
                raise IncidentInputError("source_shape")
        if provider == "pagerduty":
            cell = self.native_fields["incident.id"]
            if cell.state != "value" or cell.value != self.record_id:
                raise IncidentInputError("source_shape")
        if provider == "jira":
            cell = self.native_fields["fieldId"]
            if cell.state != "value":
                raise IncidentInputError("source_shape")
            bounded_text(cell.value, 256, nonblank=True)
        return self


def event_identity(request: IncidentClockRequest, occurrence: Occurrence) -> str:
    selected = validated_request(request)
    data = {
        "provider": selected.provider,
        "profile_alias": selected.profile_alias,
        "record_id": selected.record_id,
        "occurrence": _native(occurrence),
    }
    if occurrence_provider(occurrence) != selected.provider:
        raise IncidentInputError("source_shape")
    return "event-" + hashlib.sha256(canonical_json(data)).hexdigest()


def read_identity(request: IncidentClockRequest, ordinal: int) -> str:
    if type(ordinal) is not int or not 0 <= ordinal <= 101:
        raise IncidentInputError("source_shape")
    return (
        "read-"
        + hashlib.sha256(
            canonical_json({"request_identity": request_identity(request), "ordinal": ordinal})
        ).hexdigest()
    )


def _decimal_bound(value: object, *, signed: bool) -> str:
    text = bounded_text(value, 2024, nonblank=True)
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]{1,2000})?", text) is None:
        raise IncidentInputError()
    if text.startswith("-") and not signed:
        raise IncidentInputError()
    whole, dot, fraction = text.partition(".")
    if (dot and fraction.endswith("0")) or text == "-0":
        raise IncidentInputError()
    scale = 10 ** len(fraction)
    ticks = int(whole) * scale
    ticks += (-1 if text.startswith("-") else 1) * (int(fraction) if fraction else 0)
    minimum, maximum = (-62135596800, 253402300800) if signed else (0, 315537897600)
    if not minimum * scale <= ticks < maximum * scale:
        raise IncidentInputError()
    return text


UtcSeconds = Annotated[str, BeforeValidator(lambda value: _decimal_bound(value, signed=True)), Field(max_length=2024)]
ElapsedSeconds = Annotated[
    str, BeforeValidator(lambda value: _decimal_bound(value, signed=False)), Field(max_length=2024)
]


class EventSelection(_WireModel):
    state: Literal[
        "selected",
        "missing",
        "null",
        "empty",
        "unsupported_timestamp",
        "ambiguous",
        "occurrence_not_found",
        "conflicting_source",
        "incomplete",
    ]
    candidate_event_ids: list[EventId] = Field(max_length=10000)
    selected_event_id: EventId | None
    explicit_occurrence: Occurrence | None
    source_literal: str | None = Field(max_length=2048)
    utc_seconds: UtcSeconds | None

    @model_validator(mode="after")
    def selected_shape(self) -> Self:
        if len(set(self.candidate_event_ids)) != len(self.candidate_event_ids):
            raise IncidentInputError("source_shape")
        if self.source_literal is not None:
            bounded_text(self.source_literal, 2048, controls=False)
        if self.selected_event_id is not None and self.selected_event_id not in self.candidate_event_ids:
            raise IncidentInputError("source_shape")
        if self.state == "selected":
            if self.selected_event_id is None or self.utc_seconds is None or not self.source_literal:
                raise IncidentInputError("source_shape")
        elif self.utc_seconds is not None:
            raise IncidentInputError("source_shape")
        if self.state in ("incomplete", "ambiguous", "occurrence_not_found", "conflicting_source") and (
            self.selected_event_id is not None or self.source_literal is not None
        ):
            raise IncidentInputError("source_shape")
        return self


class ClockOutcome(_WireModel):
    state: Literal["computed", "unresolved_events", "reversed_order", "incomplete_source"]
    start: EventSelection
    end: EventSelection
    elapsed_seconds: ElapsedSeconds | None

    @model_validator(mode="after")
    def outcome_shape(self) -> Self:
        if (self.state == "computed") != (self.elapsed_seconds is not None):
            raise IncidentInputError("source_shape")
        if self.state in ("computed", "reversed_order") and (
            self.start.state != "selected" or self.end.state != "selected"
        ):
            raise IncidentInputError("source_shape")
        if self.state == "incomplete_source" and (self.start.state != "incomplete" or self.end.state != "incomplete"):
            raise IncidentInputError("source_shape")
        return self


def matching_sides(definition: PublishedClockDefinition, event: SourceEvent) -> list[Side]:
    source = SourceEvent.model_validate(event)
    provider = occurrence_provider(source.occurrence)
    bound = published_definition(provider, definition)
    return _matching_sides(bound, source)


def _matching_sides(bound: PublishedClockDefinition, source: SourceEvent) -> list[Side]:
    matched: list[Side] = []
    for side, mapping in (("start", bound.start), ("end", bound.end)):
        agrees = False
        if type(mapping) is ServiceNowMapping:
            agrees = cast(ServiceNowOccurrence, source.occurrence).field == mapping.field
        elif type(mapping) is JiraMapping:
            cells = source.native_fields
            agrees = (
                cells["fieldId"].value == mapping.field_id
                and cells["from"] == mapping.from_value
                and cells["to"] == mapping.to
            )
        elif type(mapping) is PagerDutyMapping:
            agrees = source.native_fields["type"].value == mapping.event_type
        if agrees:
            matched.append(cast(Side, side))
    return matched


def _select(request: IncidentClockRequest, side: Side, candidates: list[SourceEvent], complete: bool) -> EventSelection:
    explicit = None if type(request) is ServiceNowRequest else getattr(request, side + "_occurrence")
    data: dict[str, Any] = {
        "state": "missing",
        "candidate_event_ids": [event.event_id for event in candidates],
        "selected_event_id": None,
        "explicit_occurrence": explicit,
        "source_literal": None,
        "utc_seconds": None,
    }
    if not complete:
        data["state"] = "incomplete"
    else:
        eligible = candidates if explicit is None else [event for event in candidates if event.occurrence == explicit]
        if not eligible:
            data["state"] = "missing" if explicit is None else "occurrence_not_found"
        elif len(eligible) > 1:
            data["state"] = "ambiguous"
        else:
            event = eligible[0]
            data["selected_event_id"] = event.event_id
            data["source_literal"] = event.timestamp.value
            data["state"] = event.timestamp.state
            if event.timestamp.state == "value":
                try:
                    data["utc_seconds"] = parse_instant(cast(str, event.timestamp.value), request.provider).to_decimal()
                    data["state"] = "selected"
                except ValueError:
                    data["state"] = "unsupported_timestamp"
    return EventSelection.model_validate(data)


def derive_clock(
    request: IncidentClockRequest,
    definition: PublishedClockDefinition,
    source_state: SourceState,
    events: list[SourceEvent],
) -> ClockOutcome:
    selected = validated_request(request)
    bound = published_definition(selected.provider, definition)
    if bound.clock_alias != selected.clock_alias:
        raise IncidentInputError("source_shape")
    if type(source_state) is not str or source_state not in ("complete", "incomplete", "unavailable"):
        raise IncidentInputError("source_shape")
    if type(events) is not list or len(events) > 10000:
        raise IncidentInputError("source_shape")
    rows = [SourceEvent.model_validate(event) for event in events]
    if len({row.event_id for row in rows}) != len(rows):
        raise IncidentInputError("source_shape")
    sides: dict[Side, list[SourceEvent]] = {"start": [], "end": []}
    for row in rows:
        if row.record_id != selected.record_id or row.event_id != event_identity(selected, row.occurrence):
            raise IncidentInputError("source_shape")
        matches = _matching_sides(bound, row)
        if matches != row.matches:
            raise IncidentInputError("source_shape")
        for side in matches:
            sides[side].append(row)
    start = _select(selected, "start", sides["start"], source_state == "complete")
    end = _select(selected, "end", sides["end"], source_state == "complete")
    state: Literal["computed", "unresolved_events", "reversed_order", "incomplete_source"] = "unresolved_events"
    elapsed = None
    if source_state != "complete":
        state = "incomplete_source"
    elif start.state == "selected" and end.state == "selected":
        elapsed = elapsed_seconds(
            parse_instant(cast(str, start.source_literal), selected.provider),
            parse_instant(cast(str, end.source_literal), selected.provider),
        )
        state = "reversed_order" if elapsed is None else "computed"
    return ClockOutcome(state=state, start=start, end=end, elapsed_seconds=elapsed)


_MODEL_TYPES += (
    Diagnostic,
    DeclaredPagination,
    SourceRead,
    SelectedRecordProjection,
    SourceEvent,
    EventSelection,
    ClockOutcome,
)


RunId = Annotated[str, Field(min_length=26, max_length=26, pattern=r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")]
VersionText = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[0-9][A-Za-z0-9.+_-]{0,63}$")]
SourceSystemId = Annotated[
    str, Field(min_length=84, max_length=90, pattern=r"^incident-clock:(servicenow|jira|pagerduty):[0-9a-f]{64}$")
]
CredentialValidity = Literal["expiry_checked", "expiry_unknown", "not_established"]
ClockState = Literal["computed", "unresolved_events", "reversed_order", "incomplete_source"]
_PUBLIC_CONFIG = ConfigDict(
    strict=True,
    extra="forbid",
    frozen=True,
    validate_default=True,
    revalidate_instances="always",
    use_enum_values=True,
    str_strip_whitespace=False,
    populate_by_name=False,
)


def _required_public_fields(model: type[BaseModel], value: object) -> object:
    data = _native(value)
    if type(data) is not dict or set(data) != {field.alias or name for name, field in model.model_fields.items()}:
        raise IncidentInputError("invalid_result")
    return data


class _PublicationModel(_WireModel):
    model_config = _PUBLIC_CONFIG

    @model_validator(mode="before")
    @classmethod
    def all_declared_fields(cls, value: object) -> object:
        return _required_public_fields(cls, value)

    @classmethod
    def model_validate_json(cls, json_data: str | bytes | bytearray, **kwargs: Any) -> Self:
        if type(json_data) is str:
            if len(json_data) > RESULT_BYTE_LIMIT:
                raise IncidentInputError("result_limit")
            try:
                content = json_data.encode("utf-8")
            except UnicodeError:
                raise IncidentInputError("invalid_result") from None
        elif type(json_data) is bytes:
            content = json_data
        else:
            raise IncidentInputError("invalid_result")
        if kwargs.get("strict") is False or kwargs.get("extra") not in (None, "forbid"):
            raise IncidentInputError("invalid_result")
        parse_result_json(content)
        kwargs.update(strict=True, extra="forbid")
        return super().model_validate_json(content, **kwargs)


class SelectionFilter(_PublicationModel):
    observation_scope: Literal["selected_incident_clock"]
    request: IncidentClockRequest
    profile_binding_sha256: Sha256
    definition_sha256: Sha256


def _filter_model(value: object) -> SelectionFilter:
    return SelectionFilter.model_validate(value)


def _filter_dict(value: object) -> dict[str, Any]:
    return cast(dict[str, Any], _native(_filter_model(value)))


SelectionFilterDict = Annotated[
    dict[str, Any],
    BeforeValidator(_filter_dict, json_schema_input_type=SelectionFilter),
    PlainSerializer(_filter_model, return_type=SelectionFilter, when_used="json"),
]


class IncidentClockContext(_PublicationModel, CollectionContext):
    model_config = _PUBLIC_CONFIG
    collector_id: Literal["incident-clock"]
    collector_version: VersionText
    run_id: RunId
    collected_at: UtcClock
    credential_identity: Literal["not-established"]
    source_system_id: SourceSystemId
    filter_applied: SelectionFilterDict
    pagination_context: None
    evidentia_version: VersionText


class IncidentClockCoverage(_PublicationModel, CoverageCount):
    model_config = _PUBLIC_CONFIG
    resource_type: Literal["selected_incident_clock"]
    scanned: int = Field(ge=0, le=1)
    matched_filter: int = Field(ge=0, le=1)
    collected: int = Field(ge=0, le=1)


def _coverage_models(value: object) -> list[IncidentClockCoverage]:
    if type(value) is not list or len(value) != 1:
        raise IncidentInputError("invalid_result")
    return [IncidentClockCoverage.model_validate(value[0])]


def _coverage_list(value: object) -> list[CoverageCount]:
    return list(_coverage_models(value))


CoverageList = Annotated[
    list[CoverageCount],
    Field(min_length=1, max_length=1),
    BeforeValidator(_coverage_list, json_schema_input_type=list[IncidentClockCoverage]),
    PlainSerializer(_coverage_models, return_type=list[IncidentClockCoverage], when_used="json"),
]


def _warning_values(value: object) -> list[str]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise IncidentInputError("invalid_result")
    if value not in (
        ["selected_scope_only", "workflow_mapping_only"],
        ["selected_scope_only", "workflow_mapping_only", "credential_expiry_unknown"],
    ):
        raise IncidentInputError("invalid_result")
    return list(value)


def _error_values(value: object) -> list[str]:
    if type(value) is not list or len(value) > 64 or any(type(item) is not str for item in value):
        raise IncidentInputError("invalid_result")
    if len(set(value)) != len(value) or any(item not in get_args(DiagnosticCode) for item in value):
        raise IncidentInputError("invalid_result")
    return list(value)


class IncidentClockManifest(_PublicationModel, CollectionManifest):
    model_config = _PUBLIC_CONFIG
    run_id: RunId
    collector_id: Literal["incident-clock"]
    collector_version: VersionText
    collection_started_at: UtcClock
    collection_finished_at: UtcClock
    source_system_ids: list[SourceSystemId] = Field(min_length=1, max_length=1)
    filters_applied: SelectionFilterDict
    coverage_counts: CoverageList
    total_findings: int = Field(ge=0, le=1)
    is_complete: bool
    incomplete_reason: Literal["selected_source_incomplete", "selected_source_unavailable"] | None
    empty_categories: list[str] = Field(max_length=0)
    warnings: Annotated[list[str], BeforeValidator(_warning_values), Field(min_length=2, max_length=3)]
    errors: Annotated[
        list[str], BeforeValidator(_error_values, json_schema_input_type=list[DiagnosticCode]), Field(max_length=64)
    ]
    evidentia_version: VersionText


class IncidentClockSummary(_PublicationModel):
    observation_scope: Literal["selected_incident_clock"]
    source_state: SourceState
    clock_state: ClockState
    elapsed_seconds: ElapsedSeconds | None
    start_event_id: EventId | None
    end_event_id: EventId | None
    start_occurrence: Occurrence | None
    end_occurrence: Occurrence | None
    definition_sha256: Sha256
    profile_binding_sha256: Sha256


class IncidentClockFinding(_PublicationModel, SecurityFinding):
    model_config = _PUBLIC_CONFIG
    id: str = Field(
        min_length=36, max_length=36, pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    title: Literal["Incident clock observation"]
    description: str = Field(min_length=1, max_length=256, pattern=r"^[ -~]{1,256}$")
    severity: Literal[Severity.INFORMATIONAL]
    status: Literal[FindingStatus.ACTIVE]
    compliance_status: Literal[ComplianceStatus.UNKNOWN]
    remediation: None
    source_system: Literal["incident-clock"]
    source_finding_id: None
    resource_type: Literal["selected_incident_clock"]
    resource_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    resource_region: None
    resource_account: None
    control_mappings: list[ControlMapping] = Field(max_length=0)
    collection_context: IncidentClockContext
    raw_data: IncidentClockSummary
    first_observed: UtcClock
    last_observed: UtcClock
    resolved_at: None

    @model_validator(mode="before")
    @classmethod
    def _derive_deterministic_id(cls, value: Any) -> Any:
        return _required_public_fields(cls, value)

    @model_validator(mode="before")
    @classmethod
    def _migrate_control_ids_kwarg(cls, value: Any) -> Any:
        return _required_public_fields(cls, value)


class IncidentClockResult(_PublicationModel):
    schema_version: Literal["1"]
    provider: Provider
    request: IncidentClockRequest
    run_id: RunId
    observation_scope: Literal["selected_incident_clock"]
    definition: PublishedClockDefinition
    source_state: SourceState
    clock: ClockOutcome
    events: list[SourceEvent] = Field(max_length=10000)
    record: SelectedRecordProjection | None
    source_reads: list[SourceRead] = Field(max_length=102)
    diagnostics: list[Diagnostic] = Field(max_length=64)
    findings: list[IncidentClockFinding] = Field(max_length=1)
    manifest: IncidentClockManifest
    profile_binding_sha256: Sha256
    credential_validity: CredentialValidity

    @model_validator(mode="after")
    def matching_scope(self) -> Self:
        if self.provider != self.request.provider or self.definition.clock_alias != self.request.clock_alias:
            raise IncidentInputError("invalid_result")
        if self.run_id != self.manifest.run_id or self.manifest.total_findings != len(self.findings):
            raise IncidentInputError("invalid_result")
        if self.manifest.is_complete != (self.source_state == "complete") or bool(self.findings) != (
            self.record is not None
        ):
            raise IncidentInputError("invalid_result")
        return self


class _RunSnapshot(_PublicationModel):
    request: IncidentClockRequest
    definition: PublishedClockDefinition
    profile_binding_sha256: Sha256
    run_id: RunId
    collector_version: VersionText
    core_version: VersionText
    started_at: UtcClock
    finished_at: UtcClock
    credential_validity: CredentialValidity
    reads: list[SourceRead] = Field(max_length=102)
    record: SelectedRecordProjection | None
    events: list[SourceEvent] = Field(max_length=10000)
    diagnostics: list[Diagnostic] = Field(max_length=55)


_MODEL_TYPES += (
    SelectionFilter,
    IncidentClockContext,
    IncidentClockCoverage,
    IncidentClockManifest,
    IncidentClockSummary,
    IncidentClockFinding,
    IncidentClockResult,
    _RunSnapshot,
)
_CLOCK_CODES = frozenset(
    (
        "timestamp_unsupported",
        "event_missing",
        "event_null",
        "event_empty",
        "event_ambiguous",
        "occurrence_not_found",
        "reversed_order",
    )
)


def _json_values(value: object) -> Any:
    data = _native(value)

    def convert(item: Any) -> Any:
        if type(item) is datetime:
            return _utc_json(item)
        if type(item) is list:
            return [convert(child) for child in item]
        if type(item) is dict:
            return {key: convert(child) for key, child in item.items()}
        return item

    return convert(data)


def projection_bytes(record: SelectedRecordProjection | None, events: list[SourceEvent]) -> bytes:
    content = result_json_bytes(_json_values({"record": record, "events": events}))
    if len(content) > PROJECTION_BYTE_LIMIT:
        raise IncidentInputError("result_limit")
    return content


def _diagnostic_key(item: Diagnostic) -> tuple[str, str | None, str | None]:
    return item.code, item.read_id, item.side


def _source_checks(snapshot: _RunSnapshot) -> SourceState:
    selected = snapshot.request
    if snapshot.definition.clock_alias != selected.clock_alias:
        raise IncidentInputError("invalid_result")
    published_definition(selected.provider, snapshot.definition)
    if snapshot.credential_validity == "expiry_unknown" and selected.provider != "pagerduty":
        raise IncidentInputError("invalid_result")
    reads = snapshot.reads
    if reads and snapshot.credential_validity == "not_established":
        raise IncidentInputError("invalid_result")
    keys = [_diagnostic_key(item) for item in snapshot.diagnostics]
    if len(set(keys)) != len(keys) or any(item.code in _CLOCK_CODES for item in snapshot.diagnostics):
        raise IncidentInputError("invalid_result")
    by_read: dict[str, SourceRead] = {}
    causal_codes: dict[str, list[str]] = {}
    for item in snapshot.diagnostics:
        if item.read_id is not None:
            codes = causal_codes.setdefault(item.read_id, [])
            if item.code not in codes:
                codes.append(item.code)
    if sum(read.body_bytes for read in reads) > 8388609 or sum(read.wire_bytes for read in reads) > 10485761:
        raise IncidentInputError("invalid_result")
    record_read: SourceRead | None = None
    history: list[SourceRead] = []
    expected_record = {"servicenow": "servicenow_record", "jira": "jira_issue", "pagerduty": "pagerduty_incident"}[
        selected.provider
    ]
    expected_history = "jira_changelog" if selected.provider == "jira" else "pagerduty_log_entries"
    for ordinal, read in enumerate(reads):
        if read.ordinal != ordinal or read.read_id != read_identity(selected, ordinal):
            raise IncidentInputError("invalid_result")
        if ordinal and not reads[ordinal - 1].accepted:
            raise IncidentInputError("invalid_result")
        if read.accepted == bool(causal_codes.get(read.read_id)):
            raise IncidentInputError("invalid_result")
        if read.diagnostic_codes != causal_codes.get(read.read_id, []):
            raise IncidentInputError("invalid_result")
        if selected.provider == "jira" and ordinal == 0:
            if read.template != "jira_accessible_resources":
                raise IncidentInputError("invalid_result")
        elif ordinal == (1 if selected.provider == "jira" else 0):
            if read.template != expected_record:
                raise IncidentInputError("invalid_result")
            if read.accepted:
                record_read = read
        elif selected.provider != "servicenow" and read.template == expected_history:
            history.append(read)
        else:
            raise IncidentInputError("invalid_result")
        by_read[read.read_id] = read
    if any(key not in by_read for key in causal_codes) or len(history) > 100:
        raise IncidentInputError("invalid_result")
    if bool(record_read) != (snapshot.record is not None):
        raise IncidentInputError("invalid_result")
    if snapshot.record is not None:
        record = snapshot.record
        if (
            record.provider != selected.provider
            or record.record_id != selected.record_id
            or record_read is None
            or record.read_id != record_read.read_id
        ):
            raise IncidentInputError("invalid_result")
        if selected.provider == "servicenow":
            expected_fields = {
                "sys_id",
                cast(ServiceNowMapping, snapshot.definition.start).field,
                cast(ServiceNowMapping, snapshot.definition.end).field,
            }
            if set(record.fields) != expected_fields:
                raise IncidentInputError("invalid_result")
    elif snapshot.events:
        raise IncidentInputError("invalid_result")
    counts: dict[str, int] = {}
    last_ordinal = -1
    for event in snapshot.events:
        if occurrence_provider(event.occurrence) != selected.provider:
            raise IncidentInputError("invalid_result")
        source = by_read.get(event.read_id)
        if source is None or not source.accepted or source.ordinal < last_ordinal:
            raise IncidentInputError("invalid_result")
        if source.kind != ("record" if selected.provider == "servicenow" else "history"):
            raise IncidentInputError("invalid_result")
        last_ordinal = source.ordinal
        counts[event.read_id] = counts.get(event.read_id, 0) + 1
        if selected.provider == "servicenow":
            occurrence = cast(ServiceNowOccurrence, event.occurrence)
            configured_fields = {
                cast(ServiceNowMapping, snapshot.definition.start).field,
                cast(ServiceNowMapping, snapshot.definition.end).field,
            }
            if (
                snapshot.record is None
                or occurrence.field not in configured_fields
                or event.timestamp != snapshot.record.fields[occurrence.field]
            ):
                raise IncidentInputError("invalid_result")
        elif selected.provider == "jira":
            allowed_fields = {
                cast(JiraMapping, snapshot.definition.start).field_id,
                cast(JiraMapping, snapshot.definition.end).field_id,
            }
            if event.native_fields["fieldId"].value not in allowed_fields:
                raise IncidentInputError("invalid_result")
        elif event.native_fields["type"].value not in get_args(PagerDutyEventType):
            raise IncidentInputError("invalid_result")
    for read in reads:
        if read.admitted_events != counts.get(read.read_id, 0):
            raise IncidentInputError("invalid_result")
        if read.accepted and read.kind == "history":
            if selected.provider == "pagerduty" and read.admitted_events != read.received_records:
                raise IncidentInputError("invalid_result")
            if selected.provider == "jira" and read.admitted_events > cast(int, read.received_records) * 256:
                raise IncidentInputError("invalid_result")
    if selected.provider == "servicenow" and snapshot.record is not None and len(snapshot.events) != 2:
        raise IncidentInputError("invalid_result")
    cursor, total, terminal = 0, None, False
    for read in history:
        if terminal:
            raise IncidentInputError("invalid_result")
        if not read.accepted:
            continue
        page = read.pagination
        if page is None or page.start != cursor or (total is not None and total != page.total):
            raise IncidentInputError("invalid_result")
        cursor, total, terminal = page.start + page.returned, page.total, page.terminal
    projection_bytes(snapshot.record, snapshot.events)
    if snapshot.record is None:
        return "unavailable"
    if snapshot.diagnostics or any(not read.accepted for read in reads):
        return "incomplete"
    return "complete" if selected.provider == "servicenow" or terminal else "incomplete"


def _clock_diagnostics(clock: ClockOutcome, events: list[SourceEvent]) -> list[Diagnostic]:
    output: list[Diagnostic] = []
    by_id = {event.event_id: event for event in events}
    codes: dict[str, DiagnosticCode] = {
        "missing": "event_missing",
        "null": "event_null",
        "empty": "event_empty",
        "unsupported_timestamp": "timestamp_unsupported",
        "ambiguous": "event_ambiguous",
        "occurrence_not_found": "occurrence_not_found",
    }
    if clock.state == "incomplete_source":
        # Report the first observed occurrence of each timestamp problem per side.
        seen: set[tuple[Side, DiagnosticCode]] = set()
        for observed in events:
            state = observed.timestamp.state
            code: DiagnosticCode | None = cast(DiagnosticCode | None, codes.get(state))
            if state == "value":
                try:
                    parse_instant(cast(str, observed.timestamp.value), occurrence_provider(observed.occurrence))
                except ValueError:
                    code = "timestamp_unsupported"
            if code is not None:
                for side in observed.matches:
                    key = side, code
                    if key not in seen:
                        output.append(Diagnostic(code=code, read_id=observed.read_id, side=side))
                        seen.add(key)
        output.append(Diagnostic(code="incomplete_source", read_id=None, side=None))
        return output
    for side, selected in (("start", clock.start), ("end", clock.end)):
        if selected.state in codes:
            event = by_id.get(selected.selected_event_id or "")
            output.append(
                Diagnostic(
                    code=codes[selected.state], read_id=None if event is None else event.read_id, side=cast(Side, side)
                )
            )
    if clock.state == "reversed_order":
        output.append(Diagnostic(code="reversed_order", read_id=None, side=None))
    return output


def _assemble_snapshot(snapshot: _RunSnapshot) -> dict[str, Any]:
    state = _source_checks(snapshot)
    request, definition = snapshot.request, snapshot.definition
    clock = derive_clock(request, definition, state, snapshot.events)
    diagnostics = list(snapshot.diagnostics)
    seen = {_diagnostic_key(item) for item in diagnostics}
    for item in _clock_diagnostics(clock, snapshot.events):
        if _diagnostic_key(item) not in seen:
            diagnostics.append(item)
            seen.add(_diagnostic_key(item))
    if len(diagnostics) > 64:
        raise IncidentInputError("result_limit")
    reads = []
    for source in snapshot.reads:
        codes: list[DiagnosticCode] = []
        for item in diagnostics:
            if item.read_id == source.read_id and item.code not in codes:
                codes.append(item.code)
        reads.append(source.model_copy(update={"diagnostic_codes": codes}))
    source_system_id = "incident-clock:" + request.provider + ":" + snapshot.profile_binding_sha256
    filters = {
        "observation_scope": "selected_incident_clock",
        "request": _native(request),
        "profile_binding_sha256": snapshot.profile_binding_sha256,
        "definition_sha256": definition.definition_sha256,
    }
    findings: list[dict[str, Any]] = []
    if snapshot.record is not None:
        observed = next(read.retrieved_at for read in reads if read.read_id == snapshot.record.read_id)
        by_id = {event.event_id: event for event in snapshot.events}
        first, last = by_id.get(clock.start.selected_event_id or ""), by_id.get(clock.end.selected_event_id or "")
        summary = {
            "observation_scope": "selected_incident_clock",
            "source_state": state,
            "clock_state": clock.state,
            "elapsed_seconds": clock.elapsed_seconds,
            "start_event_id": clock.start.selected_event_id,
            "end_event_id": clock.end.selected_event_id,
            "start_occurrence": None if first is None else _native(first.occurrence),
            "end_occurrence": None if last is None else _native(last.occurrence),
            "definition_sha256": definition.definition_sha256,
            "profile_binding_sha256": snapshot.profile_binding_sha256,
        }
        context = {
            "collector_id": "incident-clock",
            "collector_version": snapshot.collector_version,
            "run_id": snapshot.run_id,
            "collected_at": observed,
            "credential_identity": "not-established",
            "source_system_id": source_system_id,
            "filter_applied": filters,
            "pagination_context": None,
            "evidentia_version": snapshot.core_version,
        }
        findings.append(
            {
                "id": str(
                    uuid5(
                        NAMESPACE_URL,
                        "evidentia:incident-clock:" + request_identity(request) + ":" + snapshot.profile_binding_sha256,
                    )
                ),
                "title": "Incident clock observation",
                "description": f"Visible source is {state}; configured clock is {clock.state}.",
                "severity": "informational",
                "status": "active",
                "compliance_status": "unknown",
                "remediation": None,
                "source_system": "incident-clock",
                "source_finding_id": None,
                "resource_type": "selected_incident_clock",
                "resource_id": request.record_id,
                "resource_region": None,
                "resource_account": None,
                "control_mappings": [],
                "collection_context": context,
                "raw_data": summary,
                "first_observed": observed,
                "last_observed": observed,
                "resolved_at": None,
            }
        )
    warnings = ["selected_scope_only", "workflow_mapping_only"]
    if snapshot.credential_validity == "expiry_unknown":
        warnings.append("credential_expiry_unknown")
    errors = list(dict.fromkeys(item.code for item in snapshot.diagnostics)) if state != "complete" else []
    if state != "complete" and not errors:
        errors = ["incomplete_source"]
    count = len(findings)
    manifest = {
        "run_id": snapshot.run_id,
        "collector_id": "incident-clock",
        "collector_version": snapshot.collector_version,
        "collection_started_at": snapshot.started_at,
        "collection_finished_at": snapshot.finished_at,
        "source_system_ids": [source_system_id],
        "filters_applied": filters,
        "coverage_counts": [
            {"resource_type": "selected_incident_clock", "scanned": count, "matched_filter": count, "collected": count}
        ],
        "total_findings": count,
        "is_complete": state == "complete",
        "incomplete_reason": None if state == "complete" else "selected_source_" + state,
        "empty_categories": [],
        "warnings": warnings,
        "errors": errors,
        "evidentia_version": snapshot.core_version,
    }
    return {
        "schema_version": "1",
        "provider": request.provider,
        "request": _native(request),
        "run_id": snapshot.run_id,
        "observation_scope": "selected_incident_clock",
        "definition": _native(definition),
        "source_state": state,
        "clock": _native(clock),
        "events": _native(snapshot.events),
        "record": _native(snapshot.record),
        "source_reads": _native(reads),
        "diagnostics": _native(diagnostics),
        "findings": findings,
        "manifest": manifest,
        "profile_binding_sha256": snapshot.profile_binding_sha256,
        "credential_validity": snapshot.credential_validity,
    }


_RESULT_BINDINGS: dict[int, tuple[weakref.ReferenceType[IncidentClockResult], bytes, RunAuthority]] = {}


def make_result(authority: RunAuthority) -> IncidentClockResult:
    """Derive every published field from an issued immutable source snapshot."""
    from ._client import authority_snapshot

    try:
        snapshot = _RunSnapshot.model_validate_json(authority_snapshot(authority))
        authority_snapshot(authority)
        assembled = _assemble_snapshot(snapshot)
        authority_snapshot(authority)
        content = result_json_bytes(_json_values(assembled))
        authority_snapshot(authority)
        result = IncidentClockResult.model_validate_json(content)
        if result_json_bytes(_json_values(result)) != content:
            raise IncidentInputError("invalid_result")
        authority_snapshot(authority)
        identifier = id(result)
        reference = weakref.ref(result, lambda unused: _RESULT_BINDINGS.pop(identifier, None))
        _RESULT_BINDINGS[identifier] = (reference, content, authority)
        return result
    except (AttributeError, KeyError, TypeError, ValueError, RuntimeError, RecursionError):
        raise IncidentInputError("invalid_result") from None


def _result_authority(result: IncidentClockResult) -> RunAuthority:
    if type(result) is not IncidentClockResult:
        raise IncidentInputError("invalid_result")
    binding = _RESULT_BINDINGS.get(id(result))
    if binding is None or binding[0]() is not result:
        raise IncidentInputError("invalid_result")
    return binding[2]


def result_bytes(result: IncidentClockResult) -> bytes:
    """Refuse unissued, changed or late publications."""
    from ._client import authority_snapshot

    if type(result) is not IncidentClockResult:
        raise IncidentInputError("invalid_result")
    binding = _RESULT_BINDINGS.get(id(result))
    if binding is None or binding[0]() is not result:
        raise IncidentInputError("invalid_result")
    try:
        authority_snapshot(binding[2])
        observed = result_json_bytes(_json_values(result))
        if observed != binding[1]:
            raise IncidentInputError("invalid_result")
        authority_snapshot(binding[2])
        return observed
    except (AttributeError, TypeError, ValueError, RuntimeError, RecursionError):
        raise IncidentInputError("invalid_result") from None
