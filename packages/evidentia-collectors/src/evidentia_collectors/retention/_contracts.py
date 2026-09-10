"""Strict selected-resource contracts and factory-owned retention evidence."""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from importlib.metadata import version
from typing import Annotated, Any, Literal, Self, cast
from urllib.parse import quote

from evidentia_core.audit.provenance import CollectionContext, CollectionManifest, CoverageCount
from evidentia_core.models.common import NonBlankStr, Severity, current_version, deterministic_finding_id
from evidentia_core.models.finding import ComplianceStatus, FindingStatus, SecurityFinding
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    GetJsonSchemaHandler,
    PlainSerializer,
    RootModel,
    SerializerFunctionWrapHandler,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_serializer,
    model_validator,
)
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema

from ._parsing import JsonObject, ParsingError, canonical_json, checked_json, parse_strict_json

# A named native union preserves recursive JSON in serialization schemas too.
type StorageRetentionJsonValue = (
    bool | int | float | str | list[StorageRetentionJsonValue] | dict[str, StorageRetentionJsonValue] | None
)
type _WireJsonObject = dict[str, StorageRetentionJsonValue]

ProviderName = Literal["s3", "azure", "gcs"]
ComponentId = Literal[
    "s3-object-lock", "s3-versioning", "azure-account", "azure-blob-service", "azure-container", "gcs-bucket"
]
ResultStatus = Literal["complete", "partial", "unavailable"]
DiagnosticCode = Literal[
    "configuration_missing",
    "configuration_invalid",
    "credential_unavailable",
    "credential_rejected",
    "forbidden",
    "resource_not_found",
    "unsafe_destination",
    "offline_refused",
    "redirect_refused",
    "endpoint_mismatch",
    "timeout",
    "rate_limited",
    "upstream_error",
    "invalid_response",
    "source_identity_mismatch",
    "unsupported_source_value",
    "missing_source_detail",
    "projection_limit",
    "response_limit",
    "run_budget_exhausted",
    "internal_error",
    "cleanup_failed",
    "signing_unsupported",
    "retry_after_invalid",
]
COLLECTOR_ID = "storage-retention-scan"
SOURCE_SYSTEM = "storage-retention"
PROJECTION_VERSION: Literal["storage-retention-projection/v1"] = "storage-retention-projection/v1"
REQUEST_BYTE_LIMIT = 65_536
RESPONSE_BYTE_LIMIT = 1_048_576
RUN_BYTE_LIMIT = 16_777_216
PROJECTION_BYTE_LIMIT = 16_384
RUN_PROJECTION_BYTE_LIMIT = 1_048_576
RESULT_BYTE_LIMIT = 4_194_304
SAFE_INTEGER = 2**53 - 1
S3_REGIONS = frozenset(
    {
        "af-south-1",
        "ap-east-1",
        "ap-east-2",
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-northeast-3",
        "ap-south-1",
        "ap-south-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-3",
        "ap-southeast-4",
        "ap-southeast-5",
        "ap-southeast-6",
        "ap-southeast-7",
        "ca-central-1",
        "ca-west-1",
        "eu-central-1",
        "eu-central-2",
        "eu-north-1",
        "eu-south-1",
        "eu-south-2",
        "eu-west-1",
        "eu-west-2",
        "eu-west-3",
        "il-central-1",
        "me-central-1",
        "me-south-1",
        "mx-central-1",
        "sa-east-1",
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
    }
)
_COMPONENTS: dict[ProviderName, tuple[ComponentId, ...]] = {
    "s3": ("s3-object-lock", "s3-versioning"),
    "azure": ("azure-account", "azure-blob-service", "azure-container"),
    "gcs": ("gcs-bucket",),
}
_PROJECTION_CODES = frozenset(
    {"unsupported_source_value", "missing_source_detail", "cleanup_failed", "run_budget_exhausted"}
)
_DETAIL_CODES = frozenset({"unsupported_source_value", "missing_source_detail"})
_ALIAS = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
_END = r"(?![\s\S])"
_ALIAS_SCHEMA = "^" + _ALIAS + _END
_IP_FORM = r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
_S3_NAME = r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"
_S3_PREFIXES = ("xn--", "sthree-", "amzn-s3-demo-")
_S3_SUFFIXES = ("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")
_S3_SCHEMA = (
    r"^(?!xn--|sthree-|amzn-s3-demo-)(?!.*\.\.)(?!.*(?:-s3alias|--ol-s3|\.mrap|--x-s3|--table-s3)"
    + _END
    + ")(?!"
    + _IP_FORM
    + _END
    + ")"
    + _S3_NAME
    + _END
)
_UUID = r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
_STRICT = ConfigDict(
    strict=True, extra="forbid", str_strip_whitespace=False, validate_default=True, revalidate_instances="always"
)
Counter = Annotated[int, Field(ge=0, le=SAFE_INTEGER)]
HttpStatus = Annotated[int, Field(ge=100, le=599)]
ScopeLabel = Annotated[NonBlankStr, Field(max_length=64, json_schema_extra={"allOf": [{"pattern": _ALIAS_SCHEMA}]})]


class StorageRetentionInputError(ValueError):
    """A fixed diagnostic without input text or underlying exception details."""

    def __init__(
        self,
        code: Literal["invalid_request", "request_limit", "invalid_result", "projection_limit"] = "invalid_request",
    ) -> None:
        if code not in {"invalid_request", "request_limit", "invalid_result", "projection_limit"}:
            code = "invalid_request"
        self.code = code
        super().__init__(code)


def _clock(value: object, info: ValidationInfo) -> datetime:
    if info.mode == "json" and isinstance(value, str):
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z", value) is None:
            raise ValueError("invalid_clock")
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("invalid_clock") from None
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("invalid_clock")
    try:
        return value.astimezone(UTC)
    except (OverflowError, ValueError):
        raise ValueError("invalid_clock") from None


def clock_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


UtcClock = Annotated[datetime, BeforeValidator(_clock), PlainSerializer(clock_text, return_type=str, when_used="json")]


def _payload(model: BaseModel) -> dict[str, Any]:
    if not set(type(model).model_fields).issubset(model.__dict__):
        raise ValueError("invalid_constructed_model")
    return dict(model.__dict__)


def _declared_schema(schema: CoreSchema) -> CoreSchema:
    """Retain field schemas while removing the validation-only wrapper schema."""
    declared = dict(schema)
    declared.pop("serialization", None)
    child = declared.get("schema")
    if isinstance(child, dict):
        declared["schema"] = _declared_schema(cast(CoreSchema, child))
    return cast(CoreSchema, declared)


class _WireModel(BaseModel):
    model_config = _STRICT

    @classmethod
    def __get_pydantic_json_schema__(cls, schema: CoreSchema, handler: GetJsonSchemaHandler) -> JsonSchemaValue:
        # The serializer validates the same fields without changing their shape.
        if handler.mode == "serialization":
            return handler(_declared_schema(schema))
        return handler(schema)

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        data = _payload(self)
        if deep:
            data = copy.deepcopy(data)
        data.update(update or {})
        return type(self).model_validate(data)

    @model_serializer(mode="wrap")
    def checked_serialization(self, handler: SerializerFunctionWrapHandler) -> Any:
        return handler(type(self).model_validate(self))


class S3Target(_WireModel):
    bucket: Annotated[
        NonBlankStr, Field(min_length=3, max_length=63, json_schema_extra={"allOf": [{"pattern": _S3_SCHEMA}]})
    ]
    region: Annotated[NonBlankStr, Field(json_schema_extra={"enum": sorted(S3_REGIONS)})]
    expected_owner: (
        Annotated[str, Field(min_length=12, max_length=12, json_schema_extra={"pattern": "^[0-9]{12}" + _END})] | None
    ) = None

    @field_validator("bucket")
    @classmethod
    def bucket_name(cls, value: str) -> str:
        if (
            re.fullmatch(_S3_NAME, value) is None
            or ".." in value
            or re.fullmatch(_IP_FORM, value)
            or value.startswith(_S3_PREFIXES)
            or value.endswith(_S3_SUFFIXES)
        ):
            raise ValueError("invalid_bucket")
        return value

    @field_validator("region")
    @classmethod
    def known_region(cls, value: str) -> str:
        if value not in S3_REGIONS:
            raise ValueError("invalid_region")
        return value

    @field_validator("expected_owner")
    @classmethod
    def owner(cls, value: str | None) -> str | None:
        if value is not None and re.fullmatch(r"[0-9]{12}", value) is None:
            raise ValueError("invalid_expected_owner")
        return value


class AzureTarget(_WireModel):
    subscription_id: Annotated[
        NonBlankStr, Field(min_length=36, max_length=36, json_schema_extra={"allOf": [{"pattern": "^" + _UUID + _END}]})
    ]
    resource_group: Annotated[
        NonBlankStr,
        Field(
            max_length=90,
            json_schema_extra={"allOf": [{"pattern": r"^(?!.*\." + _END + r")[A-Za-z0-9_().-]{1,90}" + _END}]},
        ),
    ]
    account: Annotated[
        NonBlankStr,
        Field(min_length=3, max_length=24, json_schema_extra={"allOf": [{"pattern": "^[a-z0-9]{3,24}" + _END}]}),
    ]
    container: Annotated[
        NonBlankStr,
        Field(
            min_length=3,
            max_length=63,
            json_schema_extra={"allOf": [{"pattern": "^(?!.*--)[a-z0-9][a-z0-9-]{1,61}[a-z0-9]" + _END}]},
        ),
    ]

    @field_validator("subscription_id")
    @classmethod
    def subscription(cls, value: str) -> str:
        if re.fullmatch(_UUID, value) is None:
            raise ValueError("invalid_subscription")
        return value.lower()

    @field_validator("resource_group", "account", "container")
    @classmethod
    def names(cls, value: str, info: ValidationInfo) -> str:
        grammar = {
            "resource_group": r"[A-Za-z0-9_().-]{1,90}",
            "account": r"[a-z0-9]{3,24}",
            "container": r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]",
        }[info.field_name or ""]
        if (
            re.fullmatch(grammar, value) is None
            or (info.field_name == "resource_group" and value.endswith("."))
            or (info.field_name == "container" and "--" in value)
        ):
            raise ValueError("invalid_resource_name")
        return value


class GcsTarget(_WireModel):
    bucket: Annotated[
        NonBlankStr,
        Field(
            min_length=3,
            max_length=222,
            json_schema_extra={
                "allOf": [
                    {"pattern": "^(?!" + _IP_FORM + _END + r")[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]" + _END},
                    {"pattern": r"^[^.]{1,63}(?:\.[^.]{1,63})*" + _END},
                ]
            },
        ),
    ]

    @field_validator("bucket")
    @classmethod
    def bucket_name(cls, value: str) -> str:
        if (
            re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]", value) is None
            or re.fullmatch(_IP_FORM, value)
            or any(not 1 <= len(label) <= 63 for label in value.split("."))
        ):
            raise ValueError("invalid_bucket")
        return value


StorageTarget = S3Target | AzureTarget | GcsTarget


def _target(value: StorageTarget) -> StorageTarget:
    if type(value) not in {S3Target, AzureTarget, GcsTarget}:
        raise StorageRetentionInputError()
    try:
        return type(value).model_validate(value)
    except ValueError:
        raise StorageRetentionInputError() from None


def target_provider(target: StorageTarget) -> ProviderName:
    target = _target(target)
    if isinstance(target, S3Target):
        return "s3"
    if isinstance(target, AzureTarget):
        return "azure"
    return "gcs"


def _arm_account(target: AzureTarget, *, encoded: bool) -> str:
    group = quote(target.resource_group, safe="") if encoded else target.resource_group
    return (
        f"/subscriptions/{target.subscription_id}/resourceGroups/{group}"
        f"/providers/Microsoft.Storage/storageAccounts/{target.account}"
    )


def target_identity(target: StorageTarget) -> str:
    target = _target(target)
    if isinstance(target, S3Target):
        return f"s3:{target.region}:{target.bucket}"
    if isinstance(target, AzureTarget):
        return (
            "azure:"
            + (_arm_account(target, encoded=False) + f"/blobServices/default/containers/{target.container}").lower()
        )
    return f"gcs:{target.bucket}"


def component_ids(provider: ProviderName) -> tuple[ComponentId, ...]:
    if type(provider) is not str or provider not in _COMPONENTS:
        raise StorageRetentionInputError()
    return _COMPONENTS[provider]


def build_component_url(component_id: ComponentId, target: StorageTarget) -> str:
    target = _target(target)
    if component_id not in component_ids(target_provider(target)):
        raise StorageRetentionInputError()
    if isinstance(target, S3Target):
        query = "object-lock" if component_id == "s3-object-lock" else "versioning"
        return f"https://s3.{target.region}.amazonaws.com/{target.bucket}?{query}"
    if isinstance(target, AzureTarget):
        path = _arm_account(target, encoded=True)
        if component_id != "azure-account":
            path += "/blobServices/default"
        if component_id == "azure-container":
            path += "/containers/" + target.container
        return "https://management.azure.com" + path + "?api-version=2026-04-01"
    return f"https://storage.googleapis.com/storage/v1/b/{target.bucket}?projection=noAcl"


class _Request(_WireModel):
    scope_label: ScopeLabel

    @field_validator("scope_label")
    @classmethod
    def alias(cls, value: str) -> str:
        if re.fullmatch(_ALIAS, value) is None:
            raise ValueError("invalid_scope_label")
        return value

    @model_validator(mode="after")
    def unique_targets(self) -> Self:
        identities = [target_identity(target) for target in self.__dict__.get("targets", [])]
        if len(set(identities)) != len(identities):
            raise ValueError("duplicate_target")
        return self


class S3RetentionRequest(_Request):
    provider: Literal["s3"]
    targets: Annotated[list[S3Target], Field(min_length=1, max_length=20)]


class AzureRetentionRequest(_Request):
    provider: Literal["azure"]
    targets: Annotated[list[AzureTarget], Field(min_length=1, max_length=20)]


class GcsRetentionRequest(_Request):
    provider: Literal["gcs"]
    targets: Annotated[list[GcsTarget], Field(min_length=1, max_length=20)]


RequestBranch = Annotated[
    S3RetentionRequest | AzureRetentionRequest | GcsRetentionRequest, Field(discriminator="provider")
]


class StorageRetentionCollectRequest(RootModel[RequestBranch]):
    model_config = ConfigDict(strict=True, validate_default=True, revalidate_instances="always")

    @classmethod
    def __get_pydantic_json_schema__(cls, schema: CoreSchema, handler: GetJsonSchemaHandler) -> JsonSchemaValue:
        # The serializer validates the same fields without changing their shape.
        if handler.mode == "serialization":
            return handler(_declared_schema(schema))
        return handler(schema)

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        data = {"root": copy.deepcopy(self.root) if deep else self.root}
        data.update(update or {})
        if set(data) != {"root"}:
            raise ValueError("invalid_request")
        return type(self).model_validate(data["root"])

    @model_serializer(mode="wrap")
    def checked_serialization(self, handler: SerializerFunctionWrapHandler) -> Any:
        return handler(type(self).model_validate(self))


def validated_request(value: object) -> StorageRetentionCollectRequest:
    try:
        return StorageRetentionCollectRequest.model_validate(value)
    except (ValueError, TypeError, AttributeError):
        raise StorageRetentionInputError() from None


def parse_request(content: bytes) -> StorageRetentionCollectRequest:
    if type(content) is not bytes:
        raise StorageRetentionInputError()
    if len(content) > REQUEST_BYTE_LIMIT:
        raise StorageRetentionInputError("request_limit")
    try:
        value = parse_strict_json(content, max_bytes=REQUEST_BYTE_LIMIT)
    except ParsingError:
        raise StorageRetentionInputError() from None
    return validated_request(value)


class StorageRetentionDiagnostic(_WireModel):
    model_config = ConfigDict(**_STRICT, frozen=True)
    code: DiagnosticCode
    http_status: HttpStatus | None = None


def _diagnostics(values: tuple[StorageRetentionDiagnostic, ...]) -> tuple[StorageRetentionDiagnostic, ...]:
    if type(values) is not tuple:
        raise ValueError("invalid_diagnostics")
    checked = tuple(StorageRetentionDiagnostic.model_validate(item) for item in values)
    if len({(item.code, item.http_status) for item in checked}) != len(checked):
        raise ValueError("duplicate_diagnostic")
    return checked


class _Projection(_WireModel):
    api_version: Annotated[NonBlankStr, Field(max_length=128)]
    projection_version: Literal["storage-retention-projection/v1"] = PROJECTION_VERSION
    native_scope: Annotated[NonBlankStr, Field(max_length=256)]
    fields: _WireJsonObject
    source_etag: Annotated[str, Field(max_length=1024)] | None = None
    source_metageneration: Annotated[str, Field(max_length=128)] | None = None
    canonical_projection_sha256: Annotated[str, Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")]

    @field_validator("fields", mode="before")
    @classmethod
    def strict_fields(cls, value: object) -> JsonObject:
        checked = checked_json(value)
        if not isinstance(checked, dict):
            raise ValueError("invalid_projection")
        return checked

    @model_validator(mode="after")
    def digest(self) -> Self:
        data = {key: value for key, value in self.__dict__.items() if key != "canonical_projection_sha256"}
        payload = canonical_json(checked_json(data))
        if len(payload) > PROJECTION_BYTE_LIMIT:
            raise ValueError("projection_limit")
        if sha256(payload).hexdigest() != self.canonical_projection_sha256:
            raise ValueError("invalid_projection_digest")
        return self


@dataclass(frozen=True, init=False)
class ProjectedComponent:
    """An immutable selected-field snapshot, without runtime provenance."""

    api_version: str
    native_scope: str
    diagnostics: tuple[StorageRetentionDiagnostic, ...]
    source_etag: str | None
    source_metageneration: str | None
    _canonical: bytes

    def __init__(
        self,
        api_version: str,
        native_scope: str,
        fields: JsonObject,
        diagnostics: tuple[StorageRetentionDiagnostic, ...] = (),
        source_etag: str | None = None,
        source_metageneration: str | None = None,
    ) -> None:
        checked_diagnostics = _diagnostics(diagnostics)
        if any(item.code not in _DETAIL_CODES for item in checked_diagnostics):
            raise ValueError("invalid_projection_diagnostic")
        selected = checked_json(fields)
        if not isinstance(selected, dict):
            raise ValueError("invalid_projection")
        payload = canonical_json(
            checked_json(
                {
                    "api_version": api_version,
                    "projection_version": PROJECTION_VERSION,
                    "native_scope": native_scope,
                    "fields": selected,
                    "source_etag": source_etag,
                    "source_metageneration": source_metageneration,
                }
            )
        )
        if len(payload) > PROJECTION_BYTE_LIMIT:
            raise StorageRetentionInputError("projection_limit")
        data = parse_strict_json(payload, max_bytes=PROJECTION_BYTE_LIMIT)
        if not isinstance(data, dict):
            raise ValueError("invalid_projection")
        validated = _Projection.model_validate({**data, "canonical_projection_sha256": sha256(payload).hexdigest()})
        for name in ("api_version", "native_scope", "source_etag", "source_metageneration"):
            object.__setattr__(self, name, getattr(validated, name))
        object.__setattr__(self, "diagnostics", checked_diagnostics)
        object.__setattr__(self, "_canonical", payload)

    @property
    def fields(self) -> JsonObject:
        data = parse_strict_json(self._canonical, max_bytes=PROJECTION_BYTE_LIMIT)
        if not isinstance(data, dict) or not isinstance(data.get("fields"), dict):
            raise ValueError("invalid_projection")
        return cast(JsonObject, data["fields"])

    def _wire(self) -> _Projection:
        rebuilt = ProjectedComponent(
            self.api_version,
            self.native_scope,
            self.fields,
            self.diagnostics,
            self.source_etag,
            self.source_metageneration,
        )
        if rebuilt._canonical != self._canonical:
            raise ValueError("invalid_projection_snapshot")
        data = parse_strict_json(self._canonical, max_bytes=PROJECTION_BYTE_LIMIT)
        if not isinstance(data, dict):
            raise ValueError("invalid_projection")
        return _Projection.model_validate({**data, "canonical_projection_sha256": sha256(self._canonical).hexdigest()})


def projection_size(projection: ProjectedComponent) -> int:
    """Return full canonical content bytes, excluding the digest itself."""
    if type(projection) is not ProjectedComponent:
        raise ValueError("invalid_projection")
    projection._wire()
    return len(projection._canonical)


class StorageRetentionComponentResult(_WireModel):
    component_id: ComponentId
    canonical_resource_id: Annotated[NonBlankStr, Field(max_length=512)]
    status: ResultStatus
    attempts: Annotated[int, Field(ge=0, le=3)]
    raw_bytes: Counter
    decoded_bytes: Counter
    started_at: UtcClock | None
    finished_at: UtcClock | None
    http_status: HttpStatus | None
    diagnostics: list[StorageRetentionDiagnostic]
    projection: _Projection | None

    @model_validator(mode="after")
    def consistency(self) -> Self:
        _diagnostics(tuple(self.diagnostics))
        if self.attempts == 0:
            if (
                self.started_at is not None
                or self.finished_at is not None
                or self.raw_bytes
                or self.decoded_bytes
                or self.http_status is not None
                or self.projection is not None
            ):
                raise ValueError("invalid_unattempted_component")
        elif self.started_at is None or self.finished_at is None or self.finished_at < self.started_at:
            raise ValueError("invalid_component_clock")
        expected = "unavailable" if self.projection is None else "partial" if self.diagnostics else "complete"
        if self.status != expected or (self.projection is None and not self.diagnostics):
            raise ValueError("invalid_component_status")
        if self.projection is not None:
            if (
                self.raw_bytes > self.attempts * RESPONSE_BYTE_LIMIT
                or self.decoded_bytes > self.attempts * RESPONSE_BYTE_LIMIT
            ):
                raise ValueError("invalid_admitted_byte_count")
            if any(item.code not in _PROJECTION_CODES for item in self.diagnostics):
                raise ValueError("invalid_admitted_diagnostic")
            if self.http_status is None or not (
                self.http_status == 200 or (self.component_id == "s3-object-lock" and self.http_status == 404)
            ):
                raise ValueError("invalid_projection_http_status")
        return self


def make_component_result(
    component_id: ComponentId,
    target: StorageTarget,
    *,
    attempts: int,
    raw_bytes: int,
    decoded_bytes: int,
    started_at: datetime | None,
    finished_at: datetime | None,
    http_status: int | None,
    projection: ProjectedComponent | None,
    diagnostics: tuple[StorageRetentionDiagnostic, ...],
) -> StorageRetentionComponentResult:
    try:
        target = _target(target)
        if component_id not in component_ids(target_provider(target)):
            raise ValueError("invalid_component")
        merged = list(_diagnostics(diagnostics))
        if projection is not None:
            if type(projection) is not ProjectedComponent:
                raise ValueError("invalid_projection")
            for diagnostic in projection.diagnostics:
                if diagnostic not in merged:
                    merged.append(diagnostic)
        return StorageRetentionComponentResult(
            component_id=component_id,
            canonical_resource_id=target_identity(target),
            status="unavailable" if projection is None else "partial" if merged else "complete",
            attempts=attempts,
            raw_bytes=raw_bytes,
            decoded_bytes=decoded_bytes,
            started_at=started_at,
            finished_at=finished_at,
            http_status=http_status,
            diagnostics=merged,
            projection=projection._wire() if projection is not None else None,
        )
    except (ValueError, TypeError, AttributeError):
        raise StorageRetentionInputError("invalid_result") from None


class StorageRetentionResourceResult(_WireModel):
    target: StorageTarget
    canonical_resource_id: Annotated[NonBlankStr, Field(max_length=512)]
    status: ResultStatus
    components: list[StorageRetentionComponentResult]

    @model_validator(mode="after")
    def consistency(self) -> Self:
        identity = target_identity(self.target)
        if self.canonical_resource_id != identity or tuple(
            item.component_id for item in self.components
        ) != component_ids(target_provider(self.target)):
            raise ValueError("invalid_resource_identity")
        if any(item.canonical_resource_id != identity for item in self.components):
            raise ValueError("invalid_component_identity")
        if self.status != _resource_status(self.components):
            raise ValueError("invalid_resource_status")
        return self


def _resource_status(components: list[StorageRetentionComponentResult]) -> ResultStatus:
    if all(item.status == "complete" for item in components):
        return "complete"
    return "partial" if any(item.projection is not None for item in components) else "unavailable"


class _StrictContext(CollectionContext):
    model_config = _STRICT
    collected_at: UtcClock
    filter_applied: _WireJsonObject
    pagination_context: None = None

    @field_validator("filter_applied", mode="before")
    @classmethod
    def filters(cls, value: object) -> JsonObject:
        checked = checked_json(value)
        if not isinstance(checked, dict) or not checked:
            raise ValueError("invalid_filter")
        return checked


class _StrictCoverage(CoverageCount):
    model_config = _STRICT
    scanned: Counter
    matched_filter: Counter
    collected: Counter


class _StrictManifest(CollectionManifest):
    model_config = _STRICT
    collection_started_at: UtcClock
    collection_finished_at: UtcClock
    coverage_counts: list[CoverageCount]
    total_findings: Counter
    filters_applied: _WireJsonObject

    @field_validator("coverage_counts", mode="before", json_schema_input_type=list[_StrictCoverage])
    @classmethod
    def strict_counts(cls, value: object) -> list[_StrictCoverage]:
        if type(value) is not list:
            raise ValueError("invalid_coverage_counts")
        return [_StrictCoverage.model_validate(_core_payload(item)) for item in value]

    @field_serializer("coverage_counts")
    def serialized_counts(self, value: list[CoverageCount]) -> list[_StrictCoverage]:
        return [_StrictCoverage.model_validate(_core_payload(item)) for item in value]

    @field_validator("is_complete", mode="before")
    @classmethod
    def strict_bool(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("invalid_manifest_boolean")
        return value


class _StrictFinding(SecurityFinding):
    model_config = ConfigDict(**_STRICT, use_enum_values=False)
    raw_data: _WireJsonObject
    first_observed: UtcClock
    last_observed: UtcClock
    resolved_at: None = None
    collection_context: _StrictContext


def _limits() -> JsonObject:
    return {
        "max_targets": 20,
        "request_bytes": REQUEST_BYTE_LIMIT,
        "response_raw_bytes": RESPONSE_BYTE_LIMIT,
        "response_decoded_bytes": RESPONSE_BYTE_LIMIT,
        "run_raw_bytes": RUN_BYTE_LIMIT,
        "run_decoded_bytes": RUN_BYTE_LIMIT,
        "projection_bytes": PROJECTION_BYTE_LIMIT,
        "run_projection_bytes": RUN_PROJECTION_BYTE_LIMIT,
        "result_bytes": RESULT_BYTE_LIMIT,
        "max_attempts": 3,
        "run_seconds": 120,
    }


def _filters(provider: ProviderName, scope_label: str, resources: list[StorageRetentionResourceResult]) -> JsonObject:
    return cast(
        JsonObject,
        {
            "provider": provider,
            "scope_label": scope_label,
            "selected_targets": [resource.target.model_dump(mode="json") for resource in resources],
            "component_ids": list(component_ids(provider)),
            "observation_scope": "configuration",
            "coverage_scope": "selected_resources",
            "limits": _limits(),
        },
    )


def _core_payload(value: object) -> object:
    if isinstance(value, BaseModel):
        return _payload(value)
    return value


class StorageRetentionCollectResult(_WireModel):
    """Finite selected-read counts do not claim provider enumeration."""

    schema_version: Literal["storage-retention-collection/v1"] = "storage-retention-collection/v1"
    provider: ProviderName
    scope_label: ScopeLabel
    status: ResultStatus
    started_at: UtcClock
    finished_at: UtcClock
    observation_scope: Literal["configuration"] = "configuration"
    coverage_scope: Literal["selected_resources"] = "selected_resources"
    object_enforcement_assessed: Literal[False] = False
    recordset_completeness_assessed: Literal[False] = False
    identity_basis: Literal["operator-declared"] = "operator-declared"
    authenticated_identity_verified: Literal[False] = False
    requested_resources: Counter
    attempted_resources: Counter
    planned_components: Counter
    attempted_components: Counter
    completed_components: Counter
    resources: Annotated[list[StorageRetentionResourceResult], Field(min_length=1, max_length=20)]
    findings: list[_StrictFinding]
    diagnostics: list[StorageRetentionDiagnostic]
    manifest: _StrictManifest

    @field_validator("scope_label")
    @classmethod
    def alias(cls, value: str) -> str:
        return _Request.alias(value)

    @field_validator(
        "object_enforcement_assessed",
        "recordset_completeness_assessed",
        "authenticated_identity_verified",
        mode="before",
    )
    @classmethod
    def no_claim(cls, value: object) -> object:
        if value is not False:
            raise ValueError("invalid_assessment_claim")
        return value

    @field_validator("manifest", mode="before")
    @classmethod
    def manifest_data(cls, value: object) -> object:
        return _core_payload(value)

    @field_validator("findings", mode="before")
    @classmethod
    def finding_data(cls, value: object) -> object:
        if type(value) is not list:
            raise ValueError("invalid_findings")
        return [_core_payload(item) for item in value]

    @model_validator(mode="after")
    def consistency(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("invalid_result_clock")
        _diagnostics(tuple(self.diagnostics))
        identities = [item.canonical_resource_id for item in self.resources]
        if len(set(identities)) != len(identities) or any(
            target_provider(item.target) != self.provider for item in self.resources
        ):
            raise ValueError("invalid_result_resources")
        for resource in self.resources:
            for item in resource.components:
                if item.started_at is not None and (
                    item.started_at < self.started_at or item.finished_at is None or item.finished_at > self.finished_at
                ):
                    raise ValueError("invalid_result_interval")
        counts = _counts(self.resources)
        if any(getattr(self, name) != value for name, value in counts.items()):
            raise ValueError("invalid_result_counts")
        if self.status != _result_status(self.resources, self.diagnostics):
            raise ValueError("invalid_result_status")
        if self.status == "complete":
            components = [item for resource in self.resources for item in resource.components]
            if (
                sum(item.raw_bytes for item in components) > RUN_BYTE_LIMIT
                or sum(item.decoded_bytes for item in components) > RUN_BYTE_LIMIT
            ):
                raise ValueError("invalid_complete_byte_count")
        expected_findings, expected_manifest = _evidence(
            self.provider,
            self.scope_label,
            self.resources,
            self.diagnostics,
            self.status,
            self.started_at,
            self.finished_at,
            self.manifest.run_id,
            self.manifest.collector_version,
            self.manifest.evidentia_version,
        )
        if json_bytes([item.model_dump(mode="json", warnings="error") for item in self.findings]) != json_bytes(
            [item.model_dump(mode="json", warnings="error") for item in expected_findings]
        ) or json_bytes(self.manifest.model_dump(mode="json", warnings="error")) != json_bytes(
            expected_manifest.model_dump(mode="json", warnings="error")
        ):
            raise ValueError("invalid_factory_evidence")
        projected = sum(
            len(
                canonical_json(
                    checked_json(item.projection.model_dump(mode="json", exclude={"canonical_projection_sha256"}))
                )
            )
            for resource in self.resources
            for item in resource.components
            if item.projection is not None
        )
        if projected > RUN_PROJECTION_BYTE_LIMIT:
            raise ValueError("projection_limit")
        return self

    @model_serializer(mode="wrap")
    def checked_serialization(self, handler: SerializerFunctionWrapHandler) -> Any:
        checked = type(self).model_validate(self)
        data = handler(checked)
        if (
            isinstance(data, dict)
            and isinstance(data.get("started_at"), str)
            and len(json_bytes(data)) > RESULT_BYTE_LIMIT
        ):
            raise ValueError("result_limit")
        return data


def json_bytes(value: object) -> bytes:
    """Encode the complete validated wire result under its separate ceiling."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _counts(resources: list[StorageRetentionResourceResult]) -> dict[str, int]:
    components = [item for resource in resources for item in resource.components]
    return {
        "requested_resources": len(resources),
        "attempted_resources": sum(any(item.attempts for item in resource.components) for resource in resources),
        "planned_components": len(components),
        "attempted_components": sum(item.attempts > 0 for item in components),
        "completed_components": sum(item.status == "complete" for item in components),
    }


def _result_status(
    resources: list[StorageRetentionResourceResult], diagnostics: list[StorageRetentionDiagnostic]
) -> ResultStatus:
    if all(item.status == "complete" for item in resources) and not diagnostics:
        return "complete"
    return "partial" if any(item.status != "unavailable" for item in resources) else "unavailable"


def _evidence(
    provider: ProviderName,
    scope_label: str,
    resources: list[StorageRetentionResourceResult],
    diagnostics: list[StorageRetentionDiagnostic],
    status: ResultStatus,
    started_at: datetime,
    finished_at: datetime,
    run_id: str,
    collector_version: str,
    evidentia_version: str,
) -> tuple[list[_StrictFinding], _StrictManifest]:
    if type(run_id) is not str or re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", run_id) is None:
        raise ValueError("invalid_run_id")
    if any(
        type(item) is not str or re.fullmatch(r"[A-Za-z0-9.+_-]{1,128}", item) is None
        for item in (collector_version, evidentia_version)
    ):
        raise ValueError("invalid_version")
    filters = _filters(provider, scope_label, resources)
    findings: list[_StrictFinding] = []
    resource_type = {
        "s3": "AWS::S3::Bucket",
        "azure": "Microsoft.Storage/storageAccounts/blobServices/containers",
        "gcs": "storage.googleapis.com/Bucket",
    }[provider]
    for resource in resources:
        if resource.status == "unavailable":
            continue
        source_id = f"{provider}-retention-configuration:{resource.canonical_resource_id}"
        observations = [item for item in resource.components if item.projection is not None]
        first = min(item.started_at for item in observations if item.started_at is not None)
        last = max(item.finished_at for item in observations if item.finished_at is not None)
        finding_filters = {**filters, "canonical_resource_id": resource.canonical_resource_id}
        findings.append(
            _StrictFinding(
                id=deterministic_finding_id(SOURCE_SYSTEM, source_id),
                title="Selected storage retention configuration",
                description=(
                    "Configuration observed for an explicitly selected resource. "
                    "Object enforcement and recordset completeness were not assessed."
                ),
                severity=Severity.INFORMATIONAL,
                status=FindingStatus.ACTIVE,
                compliance_status=ComplianceStatus.UNKNOWN,
                remediation=None,
                source_system=SOURCE_SYSTEM,
                source_finding_id=source_id,
                resource_type=resource_type,
                resource_id=resource.canonical_resource_id,
                resource_region=resource.target.region if isinstance(resource.target, S3Target) else None,
                resource_account=None,
                control_mappings=[],
                collection_context=_StrictContext(
                    collector_id=COLLECTOR_ID,
                    collector_version=collector_version,
                    run_id=run_id,
                    collected_at=last,
                    credential_identity="operator-configured:identity-unverified",
                    source_system_id=resource.canonical_resource_id,
                    filter_applied=finding_filters,
                    pagination_context=None,
                    evidentia_version=evidentia_version,
                ),
                raw_data={
                    "resource": resource.model_dump(mode="json"),
                    "scope": filters,
                    "object_enforcement_assessed": False,
                    "recordset_completeness_assessed": False,
                    "identity_basis": "operator-declared",
                    "authenticated_identity_verified": False,
                },
                first_observed=first,
                last_observed=last,
                resolved_at=None,
            )
        )
    counts = _counts(resources)
    codes = sorted(
        {item.code for item in diagnostics}
        | {item.code for resource in resources for component in resource.components for item in component.diagnostics}
    )
    manifest = _StrictManifest(
        run_id=run_id,
        collector_id=COLLECTOR_ID,
        collector_version=collector_version,
        collection_started_at=started_at,
        collection_finished_at=finished_at,
        source_system_ids=[item.canonical_resource_id for item in resources],
        filters_applied=filters,
        coverage_counts=[
            _StrictCoverage(
                resource_type="requested-targets",
                scanned=counts["requested_resources"],
                matched_filter=counts["attempted_resources"],
                collected=len(findings),
            ),
            _StrictCoverage(
                resource_type="planned-components",
                scanned=counts["planned_components"],
                matched_filter=counts["attempted_components"],
                collected=counts["completed_components"],
            ),
        ],
        total_findings=len(findings),
        is_complete=status == "complete",
        incomplete_reason=None if status == "complete" else "Selected configuration reads are incomplete.",
        empty_categories=[],
        warnings=["Configuration observations do not establish object enforcement or recordset completeness."],
        errors=["storage-retention:" + code for code in codes],
        evidentia_version=evidentia_version,
    )
    return findings, manifest


def make_result(
    request: StorageRetentionCollectRequest,
    *,
    run_id: str,
    started_at: datetime,
    finished_at: datetime,
    components: dict[str, list[StorageRetentionComponentResult]],
    diagnostics: tuple[StorageRetentionDiagnostic, ...],
) -> StorageRetentionCollectResult:
    try:
        request = validated_request(request)
        targets = request.root.targets
        identities = [target_identity(target) for target in targets]
        if type(components) is not dict or list(components) != identities:
            raise ValueError("invalid_component_targets")
        resources = []
        for target, identity in zip(targets, identities, strict=True):
            items = components[identity]
            if type(items) is not list:
                raise ValueError("invalid_components")
            checked = [StorageRetentionComponentResult.model_validate(item) for item in items]
            resources.append(
                StorageRetentionResourceResult(
                    target=target, canonical_resource_id=identity, status=_resource_status(checked), components=checked
                )
            )
        run_diagnostics = list(_diagnostics(diagnostics))
        status = _result_status(resources, run_diagnostics)
        findings, manifest = _evidence(
            request.root.provider,
            request.root.scope_label,
            resources,
            run_diagnostics,
            status,
            started_at,
            finished_at,
            run_id,
            version("evidentia-collectors"),
            current_version(),
        )
        result = StorageRetentionCollectResult(
            provider=request.root.provider,
            scope_label=request.root.scope_label,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            resources=resources,
            findings=findings,
            diagnostics=run_diagnostics,
            manifest=manifest,
            **_counts(resources),
        )
        wire = result.model_dump_json(warnings="error")
        if len(wire.encode("utf-8")) > RESULT_BYTE_LIMIT:
            raise ValueError("result_limit")
        return StorageRetentionCollectResult.model_validate_json(wire)
    except (ValueError, TypeError, AttributeError, OverflowError):
        raise StorageRetentionInputError("invalid_result") from None
