"""Strict selected enterprise requests and bounded evidence contracts."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from types import MappingProxyType
from typing import Annotated, Any, Literal, NamedTuple, Self, cast

from evidentia_core.audit.provenance import CollectionContext, PaginationContext
from evidentia_core.models.common import ControlMapping, NonBlankStr, Severity, deterministic_finding_id
from evidentia_core.models.finding import ComplianceStatus, FindingStatus, SecurityFinding
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    GetJsonSchemaHandler,
    JsonValue,
    PlainSerializer,
    RootModel,
    SerializerFunctionWrapHandler,
    ValidationInfo,
    field_validator,
    model_serializer,
    model_validator,
)
from pydantic.config import ExtraValues
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema

from ._parsing import (
    JsonObject,
    ParsingError,
    canonical_json,
    checked_json,
    checked_result_json,
    parse_result_json,
    parse_strict_json,
    result_json_bytes,
)

type EnterpriseRetentionJsonValue = (
    bool | int | float | str | list[EnterpriseRetentionJsonValue] | dict[str, EnterpriseRetentionJsonValue] | None
)
ProviderName = Literal["google-vault", "splunk-enterprise", "elastic-ilm"]
REQUEST_BYTE_LIMIT = 65_536
RESPONSE_BYTE_LIMIT = 1_048_576
RUN_BYTE_LIMIT = 16_777_216
PROJECTION_BYTE_LIMIT = 65_536
RUN_PROJECTION_BYTE_LIMIT = 2_097_152
RESULT_BYTE_LIMIT = 4_194_304
MAX_COUNTER = 2**128 - 1
_END = r"(?![\s\S])"
_ALIAS = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
_VAULT_ID = r"[A-Za-z0-9_-]{1,128}"
_SPLUNK_ID = r"[A-Za-z0-9_][A-Za-z0-9_-]{0,79}"
_ELASTIC_ID = r"[a-z0-9.][a-z0-9_.-]{0,254}"
_POLICY_ID = r"[A-Za-z0-9_.-]{1,255}"
_STRICT = ConfigDict(
    strict=True,
    extra="forbid",
    str_strip_whitespace=False,
    validate_default=True,
    revalidate_instances="always",
)


def _schema(pattern: str) -> dict[str, Any]:
    return {"allOf": [{"pattern": "^" + pattern + _END}]}


ScopeLabel = Annotated[NonBlankStr, Field(min_length=1, max_length=64, json_schema_extra=_schema(_ALIAS))]
Counter = Annotated[int, Field(strict=True, ge=0, le=MAX_COUNTER)]
HttpStatus = Annotated[int, Field(strict=True, ge=100, le=599)]


class EnterpriseRetentionInputError(ValueError):
    """Expose a fixed diagnostic without retaining source values."""

    def __init__(
        self,
        code: Literal["invalid_request", "request_limit", "invalid_result", "projection_limit"] = "invalid_request",
    ) -> None:
        if type(code) is not str or code not in (
            "invalid_request",
            "request_limit",
            "invalid_result",
            "projection_limit",
        ):
            code = "invalid_request"
        self.code = code
        super().__init__(code)


def _request_wire_bytes(value: object) -> bytes:
    if type(value) is bytes:
        if len(value) > REQUEST_BYTE_LIMIT:
            raise EnterpriseRetentionInputError("request_limit")
        return value
    if type(value) is bytearray:
        with memoryview(value) as view:
            if view.nbytes > REQUEST_BYTE_LIMIT:
                raise EnterpriseRetentionInputError("request_limit")
            return bytes(view)
    if type(value) is not str:
        raise EnterpriseRetentionInputError()
    if len(value) > REQUEST_BYTE_LIMIT:
        raise EnterpriseRetentionInputError("request_limit")
    size = 0
    for char in value:
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            raise EnterpriseRetentionInputError()
        size += 1 if code < 0x80 else 2 if code < 0x800 else 3 if code < 0x10000 else 4
        if size > REQUEST_BYTE_LIMIT:
            raise EnterpriseRetentionInputError("request_limit")
    return value.encode("utf-8")


def _payload(model: BaseModel) -> dict[str, Any]:
    if not set(type(model).model_fields).issubset(model.__dict__):
        raise ValueError("invalid_constructed_model")
    return dict(model.__dict__)


def _declared_schema(schema: CoreSchema) -> CoreSchema:
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


class VaultMatterTarget(_WireModel):
    matter_id: Annotated[NonBlankStr, Field(min_length=1, max_length=128, json_schema_extra=_schema(_VAULT_ID))]

    @field_validator("matter_id")
    @classmethod
    def supported_identity(cls, value: str) -> str:
        if re.fullmatch(_VAULT_ID, value) is None:
            raise ValueError("invalid_target")
        return value


_SPLUNK_SCHEMA = r"(?!(?:_[nN][eE][wW]|_[rR][eE][lL][oO][aA][dD]|_[aA][lL][lL])" + _END + ")" + _SPLUNK_ID
_ELASTIC_SCHEMA = r"(?!\.{1,2}" + _END + ")" + _ELASTIC_ID


class SplunkIndexTarget(_WireModel):
    index: Annotated[NonBlankStr, Field(min_length=1, max_length=80, json_schema_extra=_schema(_SPLUNK_SCHEMA))]

    @field_validator("index")
    @classmethod
    def supported_identity(cls, value: str) -> str:
        if re.fullmatch(_SPLUNK_ID, value) is None or value.lower() in {"_new", "_reload", "_all"}:
            raise ValueError("invalid_target")
        return value


class ElasticIndexTarget(_WireModel):
    index: Annotated[NonBlankStr, Field(min_length=1, max_length=255, json_schema_extra=_schema(_ELASTIC_SCHEMA))]

    @field_validator("index")
    @classmethod
    def supported_identity(cls, value: str) -> str:
        if re.fullmatch(_ELASTIC_ID, value) is None or value in {".", ".."}:
            raise ValueError("invalid_target")
        return value


EnterpriseTarget = VaultMatterTarget | SplunkIndexTarget | ElasticIndexTarget


def target_identity(value: EnterpriseTarget) -> str:
    checked = type(value).model_validate(value)
    return checked.matter_id if isinstance(checked, VaultMatterTarget) else checked.index


def supported_policy(value: object) -> bool:
    return (
        type(value) is str
        and re.fullmatch(_POLICY_ID, value) is not None
        and value not in {".", ".."}
        and value.lower() != "_all"
    )


class _Request(_WireModel):
    profile_alias: ScopeLabel
    scope_label: ScopeLabel

    @field_validator("profile_alias", "scope_label")
    @classmethod
    def alias(cls, value: str) -> str:
        if re.fullmatch(_ALIAS, value) is None:
            raise ValueError("invalid_alias")
        return value

    @model_validator(mode="after")
    def unique_targets(self) -> Self:
        identities = [target_identity(target) for target in self.__dict__.get("targets", [])]
        if len(set(identities)) != len(identities):
            raise ValueError("duplicate_target")
        return self


class VaultRetentionRequest(_Request):
    provider: Literal["google-vault"]
    targets: Annotated[
        list[VaultMatterTarget], Field(min_length=1, max_length=20, json_schema_extra={"uniqueItems": True})
    ]


class SplunkRetentionRequest(_Request):
    provider: Literal["splunk-enterprise"]
    targets: Annotated[
        list[SplunkIndexTarget], Field(min_length=1, max_length=20, json_schema_extra={"uniqueItems": True})
    ]


class ElasticRetentionRequest(_Request):
    provider: Literal["elastic-ilm"]
    targets: Annotated[
        list[ElasticIndexTarget], Field(min_length=1, max_length=20, json_schema_extra={"uniqueItems": True})
    ]


RequestBranch = Annotated[
    VaultRetentionRequest | SplunkRetentionRequest | ElasticRetentionRequest, Field(discriminator="provider")
]


class EnterpriseRetentionCollectRequest(RootModel[RequestBranch]):
    model_config = ConfigDict(strict=True, validate_default=True, revalidate_instances="always")

    @classmethod
    def model_validate(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        from_attributes: bool | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        if strict is False or extra not in (None, "forbid") or from_attributes is True:
            raise EnterpriseRetentionInputError()
        return super().model_validate(
            _request_data(obj),
            strict=True,
            extra="forbid",
            from_attributes=from_attributes,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        if strict is False or extra not in (None, "forbid"):
            raise EnterpriseRetentionInputError()
        data = _request_wire_bytes(json_data)
        try:
            parse_strict_json(data, max_bytes=REQUEST_BYTE_LIMIT)
            return super().model_validate_json(
                data,
                strict=True,
                extra="forbid",
                context=context,
                by_alias=by_alias,
                by_name=by_name,
            )
        except (ValueError, TypeError):
            raise EnterpriseRetentionInputError() from None

    @classmethod
    def __get_pydantic_json_schema__(cls, schema: CoreSchema, handler: GetJsonSchemaHandler) -> JsonSchemaValue:
        if handler.mode == "serialization":
            return handler(_declared_schema(schema))
        return handler(schema)

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        data = {"root": type(self).model_validate(self).root}
        if update is not None:
            if type(update) is not dict:
                raise EnterpriseRetentionInputError()
            if update:
                data.update(_request_fields(update, frozenset({"root"})))
        if set(data) != {"root"}:
            raise ValueError("invalid_request")
        return type(self).model_validate(data["root"])

    @model_serializer(mode="wrap")
    def checked_serialization(self, handler: SerializerFunctionWrapHandler) -> Any:
        return handler(type(self).model_validate(self))


def _request_fields(value: object, names: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(names):
        raise EnterpriseRetentionInputError()
    copied: dict[str, Any] = {}
    for visits, (key, item) in enumerate(value.items(), 1):
        if visits > len(names) or type(key) is not str or key not in names:
            raise EnterpriseRetentionInputError()
        copied[key] = item
    if set(copied) != names:
        raise EnterpriseRetentionInputError()
    return copied


def _request_model_fields(value: BaseModel, names: frozenset[str]) -> dict[str, Any]:
    extra = value.__pydantic_extra__
    if extra is not None and (type(extra) is not dict or extra):
        raise EnterpriseRetentionInputError()
    return _request_fields(value.__dict__, names)


def _request_data(value: object) -> dict[str, Any]:
    """Admit only the finite request shape before union discriminator callbacks."""
    try:
        if type(value) is EnterpriseRetentionCollectRequest:
            value = _request_model_fields(value, frozenset({"root"}))["root"]
        branch: str | None = None
        if type(value) is VaultRetentionRequest:
            branch = "google-vault"
        elif type(value) is SplunkRetentionRequest:
            branch = "splunk-enterprise"
        elif type(value) is ElasticRetentionRequest:
            branch = "elastic-ilm"
        names = frozenset({"provider", "profile_alias", "scope_label", "targets"})
        data = (
            _request_model_fields(cast(BaseModel, value), names)
            if branch is not None
            else _request_fields(value, names)
        )
        provider = data["provider"]
        if type(provider) is not str or provider not in ("google-vault", "splunk-enterprise", "elastic-ilm"):
            raise EnterpriseRetentionInputError()
        if branch is not None and provider != branch:
            raise EnterpriseRetentionInputError()
        for name in ("profile_alias", "scope_label"):
            scalar = data[name]
            if type(scalar) is not str or not 1 <= len(scalar) <= 64:
                raise EnterpriseRetentionInputError()
        targets = data["targets"]
        if type(targets) is not list or not 1 <= len(targets) <= 20:
            raise EnterpriseRetentionInputError()
        identity = "matter_id" if provider == "google-vault" else "index"
        maximum = 128 if provider == "google-vault" else 80 if provider == "splunk-enterprise" else 255
        expected = (
            VaultMatterTarget
            if provider == "google-vault"
            else SplunkIndexTarget
            if provider == "splunk-enterprise"
            else ElasticIndexTarget
        )
        copied: list[dict[str, Any]] = []
        for target in targets:
            if len(copied) >= 20:
                raise EnterpriseRetentionInputError()
            item = (
                _request_model_fields(target, frozenset({identity}))
                if type(target) is expected
                else _request_fields(target, frozenset({identity}))
            )
            scalar = item[identity]
            if type(scalar) is not str or not 1 <= len(scalar) <= maximum:
                raise EnterpriseRetentionInputError()
            copied.append(item)
        if not copied:
            raise EnterpriseRetentionInputError()
        data["targets"] = copied
        return data
    except (ValueError, TypeError, AttributeError, RuntimeError):
        raise EnterpriseRetentionInputError() from None


def validated_request(value: object) -> EnterpriseRetentionCollectRequest:
    try:
        return EnterpriseRetentionCollectRequest.model_validate(value)
    except (ValueError, TypeError, AttributeError):
        raise EnterpriseRetentionInputError() from None


def parse_request(content: bytes) -> EnterpriseRetentionCollectRequest:
    if type(content) is not bytes:
        raise EnterpriseRetentionInputError()
    return EnterpriseRetentionCollectRequest.model_validate_json(content)


DiagnosticCode = Literal[
    "credential_missing",
    "credential_invalid",
    "credential_expired",
    "credential_resolution_failed",
    "credential_rejected",
    "offline_refused",
    "destination_refused",
    "dns_failed",
    "transport_failed",
    "timeout",
    "deadline_exceeded",
    "attempt_limit",
    "response_limit",
    "run_byte_limit",
    "invalid_encoding",
    "invalid_json",
    "invalid_response",
    "identity_mismatch",
    "redirect_refused",
    "http_denied",
    "http_not_found",
    "http_error",
    "retry_after_invalid",
    "page_limit",
    "record_limit",
    "token_invalid",
    "token_repeated",
    "projection_limit",
    "result_limit",
    "duplicate_conflict",
    "policy_reference_missing",
    "policy_reference_unsupported",
    "policy_unavailable",
    "upstream_error",
    "upstream_warning",
    "unsupported_source_value",
    "missing_source_detail",
    "cleanup_failed",
    "internal_error",
    "dependency_unavailable",
]

DiagnosticScope = Literal["run", "read", "resource", "observation"]
ResultStatus = Literal["complete", "partial", "unavailable"]
CoverageState = Literal["absent", "null", "known", "unknown"]
ReadKind = Literal["vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"]
ApiVersion = Literal["v1", "splunk-enterprise-10.4", "elastic-stack-ilm"]
_METHODS: dict[ReadKind, tuple[ProviderName, ApiVersion, str]] = {
    "vault-matter": ("google-vault", "v1", "vault.matters.get"),
    "vault-holds": ("google-vault", "v1", "vault.matters.holds.list"),
    "splunk-index": ("splunk-enterprise", "splunk-enterprise-10.4", "splunk.data.indexes.get"),
    "elastic-explain": ("elastic-ilm", "elastic-stack-ilm", "elastic.ilm.explain_lifecycle"),
    "elastic-policy": ("elastic-ilm", "elastic-stack-ilm", "elastic.ilm.get_lifecycle"),
    "elastic-status": ("elastic-ilm", "elastic-stack-ilm", "elastic.ilm.get_status"),
}
_CLOCK_PATTERN = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z"


def _clock(value: object, info: ValidationInfo) -> datetime:
    try:
        if info.mode == "json" and type(value) is str:
            if re.fullmatch(_CLOCK_PATTERN, value) is None:
                raise ValueError("invalid_clock")
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("invalid_clock")
        return value.astimezone(UTC)
    except (ValueError, OverflowError, TypeError):
        raise ValueError("invalid_clock") from None


def clock_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


UtcClock = Annotated[
    datetime,
    BeforeValidator(_clock),
    PlainSerializer(clock_text, return_type=str, when_used="json"),
    Field(json_schema_extra={"allOf": [{"pattern": "^" + _CLOCK_PATTERN + _END, "minLength": 27, "maxLength": 27}]}),
]
ReadIdentifier = Annotated[NonBlankStr, Field(max_length=384)]


class ReadKey(_WireModel):
    model_config = ConfigDict(**_STRICT, frozen=True)
    kind: ReadKind
    source_id: Annotated[NonBlankStr, Field(max_length=255, repr=False)]

    @model_validator(mode="after")
    def supported_source(self) -> Self:
        if self.kind in ("vault-matter", "vault-holds"):
            VaultMatterTarget(matter_id=self.source_id)
        elif self.kind == "splunk-index":
            SplunkIndexTarget(index=self.source_id)
        elif self.kind == "elastic-explain":
            ElasticIndexTarget(index=self.source_id)
        elif self.kind == "elastic-policy":
            if not supported_policy(self.source_id):
                raise ValueError("invalid_read_key")
        elif self.source_id != "service":
            raise ValueError("invalid_read_key")
        return self


def read_identifier(provider: ProviderName, profile_alias: str, key: ReadKey) -> str:
    checked = ReadKey.model_validate(key)
    if type(provider) is not str or provider != _METHODS[checked.kind][0]:
        raise ValueError("invalid_read_key")
    if type(profile_alias) is not str or re.fullmatch(_ALIAS, profile_alias) is None:
        raise ValueError("invalid_read_key")
    return f"enterprise-retention/{provider}/{profile_alias}/{checked.kind}/{checked.source_id}"


def parsed_read_identifier(value: object) -> tuple[ProviderName, str, ReadKey]:
    if type(value) is not str or not 1 <= len(value) <= 384 or not value.isascii():
        raise ValueError("invalid_read_id")
    pieces = value.split("/")
    if len(pieces) != 5 or pieces[0] != "enterprise-retention":
        raise ValueError("invalid_read_id")
    key = ReadKey.model_validate({"kind": pieces[3], "source_id": pieces[4]})
    provider = _METHODS[key.kind][0]
    if read_identifier(provider, pieces[2], key) != value:
        raise ValueError("invalid_read_id")
    return provider, pieces[2], key


# Scope, providers, read kinds, scheduling effect, terminal-reason permission.
DiagnosticRule = tuple[DiagnosticScope, tuple[ProviderName, ...], tuple[ReadKind, ...], str, bool]
_DIAGNOSTIC_RULES: dict[DiagnosticCode, tuple[DiagnosticRule, ...]] = {
    "credential_missing": (("run", ("google-vault", "splunk-enterprise", "elastic-ilm"), (), "stop_run", True),),
    "credential_invalid": (("run", ("google-vault", "splunk-enterprise", "elastic-ilm"), (), "stop_run", True),),
    "credential_expired": (("run", ("google-vault", "splunk-enterprise", "elastic-ilm"), (), "stop_run", True),),
    "credential_resolution_failed": (
        ("run", ("google-vault", "splunk-enterprise", "elastic-ilm"), (), "stop_run", True),
    ),
    "credential_rejected": (("run", ("google-vault", "splunk-enterprise", "elastic-ilm"), (), "stop_run", True),),
    "offline_refused": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "destination_refused": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "dns_failed": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "transport_failed": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "timeout": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "deadline_exceeded": (("run", ("google-vault", "splunk-enterprise", "elastic-ilm"), (), "stop_run", True),),
    "attempt_limit": (("run", ("google-vault", "splunk-enterprise", "elastic-ilm"), (), "stop_run", True),),
    "response_limit": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "run_byte_limit": (("run", ("google-vault", "splunk-enterprise", "elastic-ilm"), (), "stop_run", True),),
    "invalid_encoding": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "invalid_json": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "invalid_response": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "identity_mismatch": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "redirect_refused": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "http_denied": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "http_not_found": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "http_error": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "retry_after_invalid": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
    ),
    "page_limit": (("run", ("google-vault",), (), "stop_run", True),),
    "record_limit": (("run", ("google-vault",), (), "stop_run", True),),
    "token_invalid": (("read", ("google-vault",), ("vault-holds",), "end_read", True),),
    "token_repeated": (("read", ("google-vault",), ("vault-holds",), "end_read", True),),
    "projection_limit": (
        (
            "read",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "end_read",
            True,
        ),
        ("run", ("google-vault", "splunk-enterprise", "elastic-ilm"), (), "stop_run", True),
    ),
    "result_limit": (("run", ("google-vault", "splunk-enterprise", "elastic-ilm"), (), "stop_run", True),),
    "duplicate_conflict": (("read", ("google-vault",), ("vault-holds",), "continue_safe_enumeration", False),),
    "policy_reference_missing": (
        ("resource", ("elastic-ilm",), ("elastic-explain",), "no_unsupported_followup", False),
    ),
    "policy_reference_unsupported": (
        ("resource", ("elastic-ilm",), ("elastic-explain",), "no_unsupported_followup", False),
    ),
    "policy_unavailable": (("resource", ("elastic-ilm",), ("elastic-policy",), "no_unsupported_followup", False),),
    "upstream_error": (("read", ("splunk-enterprise",), ("splunk-index",), "end_read", True),),
    "upstream_warning": (("read", ("splunk-enterprise",), ("splunk-index",), "continue", False),),
    "unsupported_source_value": (
        ("read", ("splunk-enterprise",), ("splunk-index",), "continue", False),
        (
            "observation",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "continue",
            False,
        ),
    ),
    "missing_source_detail": (
        (
            "observation",
            ("google-vault", "splunk-enterprise", "elastic-ilm"),
            ("vault-matter", "vault-holds", "splunk-index", "elastic-explain", "elastic-policy", "elastic-status"),
            "continue",
            False,
        ),
    ),
    "cleanup_failed": (("run", ("google-vault", "splunk-enterprise", "elastic-ilm"), (), "stop_run", True),),
    "internal_error": (("run", ("google-vault", "splunk-enterprise", "elastic-ilm"), (), "stop_run", True),),
    "dependency_unavailable": (("run", ("google-vault", "splunk-enterprise", "elastic-ilm"), (), "stop_run", True),),
}
_DIAGNOSTIC_HTTP: dict[DiagnosticCode, str] = {
    "credential_missing": "none",
    "credential_invalid": "none",
    "credential_expired": "none",
    "credential_resolution_failed": "none",
    "credential_rejected": "401",
    "offline_refused": "none",
    "destination_refused": "none",
    "dns_failed": "none",
    "transport_failed": "observed",
    "timeout": "observed",
    "deadline_exceeded": "observed",
    "attempt_limit": "none",
    "response_limit": "observed",
    "run_byte_limit": "observed",
    "invalid_encoding": "observed",
    "invalid_json": "observed",
    "invalid_response": "observed",
    "identity_mismatch": "200",
    "redirect_refused": "3xx",
    "http_denied": "403",
    "http_not_found": "404",
    "http_error": "other_non_200",
    "retry_after_invalid": "retryable",
    "page_limit": "observed",
    "record_limit": "observed",
    "token_invalid": "200",
    "token_repeated": "200",
    "projection_limit": "observed",
    "result_limit": "observed",
    "duplicate_conflict": "200",
    "policy_reference_missing": "none",
    "policy_reference_unsupported": "none",
    "policy_unavailable": "none",
    "upstream_error": "200",
    "upstream_warning": "200",
    "unsupported_source_value": "200",
    "missing_source_detail": "200",
    "cleanup_failed": "observed",
    "internal_error": "none",
    "dependency_unavailable": "none",
}
DIAGNOSTIC_ORDER: tuple[DiagnosticCode, ...] = tuple(_DIAGNOSTIC_RULES)
_RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})


class EnterpriseRetentionDiagnostic(_WireModel):
    model_config = ConfigDict(**_STRICT, frozen=True)
    code: DiagnosticCode
    read_id: ReadIdentifier | None
    safe_http_status: HttpStatus | None

    @field_validator("read_id")
    @classmethod
    def valid_reference(cls, value: str | None) -> str | None:
        if value is not None:
            parsed_read_identifier(value)
        return value

    @model_validator(mode="after")
    def http_association(self) -> Self:
        association = _DIAGNOSTIC_HTTP[self.code]
        status = self.safe_http_status
        if association == "none" and status is not None:
            raise ValueError("invalid_diagnostic_status")
        if association in ("200", "401", "403", "404") and status != int(association):
            raise ValueError("invalid_diagnostic_status")
        if status is not None:
            if association == "3xx" and not 300 <= status <= 399:
                raise ValueError("invalid_diagnostic_status")
            if association == "retryable" and status not in _RETRYABLE_STATUS:
                raise ValueError("invalid_diagnostic_status")
            if association == "other_non_200" and (status in (200, 401, 403, 404) or 300 <= status <= 399):
                raise ValueError("invalid_diagnostic_status")
        return self


def _diagnostic_context(scope: DiagnosticScope, provider: ProviderName, kind: ReadKind | None) -> None:
    if type(scope) is not str or scope not in ("run", "read", "resource", "observation"):
        raise ValueError("invalid_diagnostic_scope")
    if type(provider) is not str or provider not in ("google-vault", "splunk-enterprise", "elastic-ilm"):
        raise ValueError("invalid_diagnostic_scope")
    if kind is not None and (type(kind) is not str or kind not in _METHODS or _METHODS[kind][0] != provider):
        raise ValueError("invalid_diagnostic_scope")
    if scope in ("read", "observation") and kind is None:
        raise ValueError("invalid_diagnostic_scope")


def diagnostic_rule(
    code: DiagnosticCode,
    scope: DiagnosticScope,
    provider: ProviderName,
    kind: ReadKind | None = None,
) -> DiagnosticRule:
    _diagnostic_context(scope, provider, kind)
    if type(code) is not str or code not in _DIAGNOSTIC_RULES:
        raise ValueError("invalid_diagnostic_scope")
    for rule in _DIAGNOSTIC_RULES[code]:
        if rule[0] == scope and provider in rule[1] and (not rule[2] or kind in rule[2]):
            return rule
    raise ValueError("invalid_diagnostic_scope")


def checked_diagnostics(
    values: object,
    *,
    scope: DiagnosticScope,
    provider: ProviderName,
    kind: ReadKind | None = None,
    owner_read_id: str | None = None,
) -> tuple[EnterpriseRetentionDiagnostic, ...]:
    _diagnostic_context(scope, provider, kind)
    if scope in ("read", "observation"):
        owner_provider, _, owner_key = parsed_read_identifier(owner_read_id)
        if owner_provider != provider or owner_key.kind != kind:
            raise ValueError("invalid_diagnostic_reference")
    elif owner_read_id is not None:
        raise ValueError("invalid_diagnostic_reference")
    if type(values) is not tuple and type(values) is not list:
        raise ValueError("invalid_diagnostics")
    if len(values) > len(DIAGNOSTIC_ORDER):
        raise ValueError("invalid_diagnostics")
    checked: list[EnterpriseRetentionDiagnostic] = []
    previous = -1
    for value in values:
        item = EnterpriseRetentionDiagnostic.model_validate(value)
        rule_kind = kind
        if item.read_id is not None:
            ref_provider, _, ref_key = parsed_read_identifier(item.read_id)
            if ref_provider != provider:
                raise ValueError("invalid_diagnostic_reference")
            if scope == "resource":
                if kind is not None and kind != ref_key.kind:
                    raise ValueError("invalid_diagnostic_reference")
                rule_kind = ref_key.kind
        diagnostic_rule(item.code, scope, provider, rule_kind)
        if scope in ("read", "observation") and (owner_read_id is None or item.read_id != owner_read_id):
            raise ValueError("invalid_diagnostic_reference")
        if scope == "resource" and item.read_id is None:
            raise ValueError("invalid_diagnostic_reference")
        order = DIAGNOSTIC_ORDER.index(item.code)
        if order <= previous:
            raise ValueError("invalid_diagnostic_order")
        previous = order
        checked.append(item)
    return tuple(checked)


class HttpStatusAccumulator:
    """Retain ambiguity after two distinct observed response statuses."""

    def __init__(self) -> None:
        self._status: int | None = None
        self._ambiguous = False

    def add(self, value: int | None) -> None:
        if value is None:
            return
        if type(value) is not int or not 100 <= value <= 599:
            raise ValueError("invalid_http_status")
        if not self._ambiguous:
            if self._status is None:
                self._status = value
            elif self._status != value:
                self._status = None
                self._ambiguous = True

    @property
    def value(self) -> int | None:
        return self._status


InterpretationCode = Literal["unsupported_source_value", "missing_source_detail"]
NativeKind = Literal["str", "int", "float", "bool", "null", "object", "list"]
Transform = Literal["literal", "selected_child_object", "selected_child_list", "archive_presence"]
ValidatorId = Literal[
    "exact_target_matter_id",
    "vault_matter_state",
    "nonblank_utf8_max_1024",
    "literal",
    "vault_corpus",
    "aware_rfc3339_text",
    "declared_shape",
    "exact_target_index",
    "splunk_datatype",
    "splunk_disabled",
    "splunk_nonnegative_setting",
    "archive_presence",
    "supported_policy_reference",
    "nonnegative_int",
    "timestamp_text_or_native_millis",
    "elastic_operation_mode",
    "nonblank",
    "voice_covered_data",
    "opaque_named_actions",
]
UnknownKeys = Literal["discard", "retain_exact_and_mark_unknown", "all_keys_are_dynamic_phase_entries"]


class ExpectedFields(NamedTuple):
    fields: JsonObject
    coverage: dict[str, CoverageState]
    diagnostics: tuple[InterpretationCode, ...]


class CorrespondenceError(ValueError):
    """Refuse a field mismatch without retaining source values or field paths."""

    def __init__(self) -> None:
        super().__init__("invalid_response")


@dataclass(frozen=True)
class SourceFieldRule:
    source_path: tuple[str, ...]
    output_path: tuple[str, ...]
    required: bool
    accepted_native_types: tuple[NativeKind, ...]
    transform: Transform
    validator: ValidatorId
    shape: str | None = None
    coverage_key: str | None = None
    protected: bool = False
    item_types: tuple[NativeKind, ...] = ()


@dataclass(frozen=True)
class ShapeDefinition:
    fields: tuple[SourceFieldRule, ...]
    unknown_keys: UnknownKeys
    value_shape: str | None = None
    value_types: tuple[NativeKind, ...] = ()


SHAPES: Mapping[str, ShapeDefinition] = MappingProxyType(
    {
        "vault_account": ShapeDefinition(
            (
                SourceFieldRule(
                    ("accountId",),
                    ("accountId",),
                    True,
                    ("str",),
                    "literal",
                    "nonblank",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("holdTime",),
                    ("holdTime",),
                    False,
                    ("str", "null"),
                    "literal",
                    "aware_rfc3339_text",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
            ),
            "discard",
            value_shape=None,
            value_types=(),
        ),
        "vault_org_unit": ShapeDefinition(
            (
                SourceFieldRule(
                    ("orgUnitId",),
                    ("orgUnitId",),
                    True,
                    ("str",),
                    "literal",
                    "nonblank",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("holdTime",),
                    ("holdTime",),
                    False,
                    ("str", "null"),
                    "literal",
                    "aware_rfc3339_text",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
            ),
            "discard",
            value_shape=None,
            value_types=(),
        ),
        "vault_drive_query": ShapeDefinition(
            (
                SourceFieldRule(
                    ("includeSharedDriveFiles",),
                    ("includeSharedDriveFiles",),
                    False,
                    ("bool", "null"),
                    "literal",
                    "literal",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("includeTeamDriveFiles",),
                    ("includeTeamDriveFiles",),
                    False,
                    ("bool", "null"),
                    "literal",
                    "literal",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
            ),
            "retain_exact_and_mark_unknown",
            value_shape=None,
            value_types=(),
        ),
        "vault_chat_query": ShapeDefinition(
            (
                SourceFieldRule(
                    ("includeRooms",),
                    ("includeRooms",),
                    False,
                    ("bool", "null"),
                    "literal",
                    "literal",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
            ),
            "retain_exact_and_mark_unknown",
            value_shape=None,
            value_types=(),
        ),
        "vault_mail_query": ShapeDefinition(
            (
                SourceFieldRule(
                    ("startTime",),
                    ("startTime",),
                    False,
                    ("str", "null"),
                    "literal",
                    "aware_rfc3339_text",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("endTime",),
                    ("endTime",),
                    False,
                    ("str", "null"),
                    "literal",
                    "aware_rfc3339_text",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("terms",),
                    ("terms",),
                    False,
                    ("str", "null"),
                    "literal",
                    "literal",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
            ),
            "retain_exact_and_mark_unknown",
            value_shape=None,
            value_types=(),
        ),
        "vault_groups_query": ShapeDefinition(
            (
                SourceFieldRule(
                    ("startTime",),
                    ("startTime",),
                    False,
                    ("str", "null"),
                    "literal",
                    "aware_rfc3339_text",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("endTime",),
                    ("endTime",),
                    False,
                    ("str", "null"),
                    "literal",
                    "aware_rfc3339_text",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("terms",),
                    ("terms",),
                    False,
                    ("str", "null"),
                    "literal",
                    "literal",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
            ),
            "retain_exact_and_mark_unknown",
            value_shape=None,
            value_types=(),
        ),
        "vault_voice_query": ShapeDefinition(
            (
                SourceFieldRule(
                    ("coveredData",),
                    ("coveredData",),
                    False,
                    ("list", "null"),
                    "literal",
                    "voice_covered_data",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=("str",),
                ),
            ),
            "retain_exact_and_mark_unknown",
            value_shape=None,
            value_types=(),
        ),
        "vault_empty_query": ShapeDefinition((), "retain_exact_and_mark_unknown", value_shape=None, value_types=()),
        "vault_query": ShapeDefinition(
            (
                SourceFieldRule(
                    ("driveQuery",),
                    ("driveQuery",),
                    False,
                    ("object", "null"),
                    "literal",
                    "declared_shape",
                    shape="vault_drive_query",
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("hangoutsChatQuery",),
                    ("hangoutsChatQuery",),
                    False,
                    ("object", "null"),
                    "literal",
                    "declared_shape",
                    shape="vault_chat_query",
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("mailQuery",),
                    ("mailQuery",),
                    False,
                    ("object", "null"),
                    "literal",
                    "declared_shape",
                    shape="vault_mail_query",
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("groupsQuery",),
                    ("groupsQuery",),
                    False,
                    ("object", "null"),
                    "literal",
                    "declared_shape",
                    shape="vault_groups_query",
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("voiceQuery",),
                    ("voiceQuery",),
                    False,
                    ("object", "null"),
                    "literal",
                    "declared_shape",
                    shape="vault_voice_query",
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("calendarQuery",),
                    ("calendarQuery",),
                    False,
                    ("object", "null"),
                    "literal",
                    "declared_shape",
                    shape="vault_empty_query",
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("geminiQuery",),
                    ("geminiQuery",),
                    False,
                    ("object", "null"),
                    "literal",
                    "declared_shape",
                    shape="vault_empty_query",
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
            ),
            "retain_exact_and_mark_unknown",
            value_shape=None,
            value_types=(),
        ),
        "elastic_phase_definition": ShapeDefinition(
            (
                SourceFieldRule(
                    ("min_age",),
                    ("min_age",),
                    False,
                    ("str", "null"),
                    "literal",
                    "literal",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("actions",),
                    ("actions",),
                    False,
                    ("object", "null"),
                    "literal",
                    "opaque_named_actions",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=("object", "list", "str", "int", "float", "bool", "null"),
                ),
            ),
            "retain_exact_and_mark_unknown",
            value_shape=None,
            value_types=(),
        ),
        "elastic_phases": ShapeDefinition(
            (),
            "all_keys_are_dynamic_phase_entries",
            value_shape="elastic_phase_definition",
            value_types=("object", "null"),
        ),
        "elastic_policy": ShapeDefinition(
            (
                SourceFieldRule(
                    ("phases",),
                    ("phases",),
                    False,
                    ("object", "null"),
                    "literal",
                    "declared_shape",
                    shape="elastic_phases",
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
            ),
            "discard",
            value_shape=None,
            value_types=(),
        ),
        "elastic_phase_execution": ShapeDefinition(
            (
                SourceFieldRule(
                    ("policy",),
                    ("policy",),
                    False,
                    ("str", "null"),
                    "literal",
                    "literal",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("version",),
                    ("version",),
                    False,
                    ("int", "null"),
                    "literal",
                    "nonnegative_int",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("modified_date_in_millis",),
                    ("modified_date_in_millis",),
                    False,
                    ("int", "null"),
                    "literal",
                    "nonnegative_int",
                    shape=None,
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
                SourceFieldRule(
                    ("phase_definition",),
                    ("phase_definition",),
                    False,
                    ("object", "null"),
                    "literal",
                    "declared_shape",
                    shape="elastic_phase_definition",
                    coverage_key=None,
                    protected=False,
                    item_types=(),
                ),
            ),
            "discard",
            value_shape=None,
            value_types=(),
        ),
    }
)
ROOT_RULES: Mapping[str, tuple[SourceFieldRule, ...]] = MappingProxyType(
    {
        "vault-matter": (
            SourceFieldRule(
                ("matterId",),
                ("matterId",),
                True,
                ("str",),
                "literal",
                "exact_target_matter_id",
                shape=None,
                coverage_key="matterId",
                protected=True,
                item_types=(),
            ),
            SourceFieldRule(
                ("state",),
                ("state",),
                False,
                ("str", "null"),
                "literal",
                "vault_matter_state",
                shape=None,
                coverage_key="state",
                protected=False,
                item_types=(),
            ),
        ),
        "vault-holds": (
            SourceFieldRule(
                ("holdId",),
                ("holdId",),
                True,
                ("str",),
                "literal",
                "nonblank_utf8_max_1024",
                shape=None,
                coverage_key="holdId",
                protected=True,
                item_types=(),
            ),
            SourceFieldRule(
                ("name",),
                ("name",),
                False,
                ("str", "null"),
                "literal",
                "literal",
                shape=None,
                coverage_key="name",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("corpus",),
                ("corpus",),
                False,
                ("str", "null"),
                "literal",
                "vault_corpus",
                shape=None,
                coverage_key="corpus",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("updateTime",),
                ("updateTime",),
                False,
                ("str", "null"),
                "literal",
                "aware_rfc3339_text",
                shape=None,
                coverage_key="updateTime",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("accounts",),
                ("accounts",),
                False,
                ("list", "null"),
                "selected_child_list",
                "declared_shape",
                shape="vault_account",
                coverage_key="accounts",
                protected=False,
                item_types=("object",),
            ),
            SourceFieldRule(
                ("orgUnit",),
                ("orgUnit",),
                False,
                ("object", "null"),
                "selected_child_object",
                "declared_shape",
                shape="vault_org_unit",
                coverage_key="orgUnit",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("query",),
                ("query",),
                False,
                ("object", "null"),
                "literal",
                "declared_shape",
                shape="vault_query",
                coverage_key="query",
                protected=False,
                item_types=(),
            ),
        ),
        "splunk-index": (
            SourceFieldRule(
                ("name",),
                ("name",),
                True,
                ("str",),
                "literal",
                "exact_target_index",
                shape=None,
                coverage_key="name",
                protected=True,
                item_types=(),
            ),
            SourceFieldRule(
                ("content", "datatype"),
                ("datatype",),
                False,
                ("str", "null"),
                "literal",
                "splunk_datatype",
                shape=None,
                coverage_key="datatype",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("content", "disabled"),
                ("disabled",),
                False,
                ("bool", "int", "str", "float", "null"),
                "literal",
                "splunk_disabled",
                shape=None,
                coverage_key="disabled",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("content", "frozenTimePeriodInSecs"),
                ("frozenTimePeriodInSecs",),
                False,
                ("int", "str", "float", "null"),
                "literal",
                "splunk_nonnegative_setting",
                shape=None,
                coverage_key="frozenTimePeriodInSecs",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("content", "maxTotalDataSizeMB"),
                ("maxTotalDataSizeMB",),
                False,
                ("int", "str", "float", "null"),
                "literal",
                "splunk_nonnegative_setting",
                shape=None,
                coverage_key="maxTotalDataSizeMB",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("content", "coldToFrozenDir"),
                ("coldToFrozenDirState",),
                False,
                ("str", "null"),
                "archive_presence",
                "archive_presence",
                shape=None,
                coverage_key="coldToFrozenDir",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("content", "coldToFrozenScript"),
                ("coldToFrozenScriptState",),
                False,
                ("str", "null"),
                "archive_presence",
                "archive_presence",
                shape=None,
                coverage_key="coldToFrozenScript",
                protected=False,
                item_types=(),
            ),
        ),
        "elastic-explain": (
            SourceFieldRule(
                ("index",),
                ("index",),
                True,
                ("str",),
                "literal",
                "exact_target_index",
                shape=None,
                coverage_key="index",
                protected=True,
                item_types=(),
            ),
            SourceFieldRule(
                ("managed",),
                ("managed",),
                True,
                ("bool",),
                "literal",
                "literal",
                shape=None,
                coverage_key="managed",
                protected=True,
                item_types=(),
            ),
            SourceFieldRule(
                ("policy",),
                ("policy",),
                False,
                ("str", "null"),
                "literal",
                "supported_policy_reference",
                shape=None,
                coverage_key="policy",
                protected=True,
                item_types=(),
            ),
            SourceFieldRule(
                ("phase",),
                ("phase",),
                False,
                ("str", "null"),
                "literal",
                "literal",
                shape=None,
                coverage_key="phase",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("action",),
                ("action",),
                False,
                ("str", "null"),
                "literal",
                "literal",
                shape=None,
                coverage_key="action",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("step",),
                ("step",),
                False,
                ("str", "null"),
                "literal",
                "literal",
                shape=None,
                coverage_key="step",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("failed_step",),
                ("failed_step",),
                False,
                ("str", "null"),
                "literal",
                "literal",
                shape=None,
                coverage_key="failed_step",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("index_creation_date_millis",),
                ("index_creation_date_millis",),
                False,
                ("int", "null"),
                "literal",
                "nonnegative_int",
                shape=None,
                coverage_key="index_creation_date_millis",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("lifecycle_date_millis",),
                ("lifecycle_date_millis",),
                False,
                ("int", "null"),
                "literal",
                "nonnegative_int",
                shape=None,
                coverage_key="lifecycle_date_millis",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("phase_time_millis",),
                ("phase_time_millis",),
                False,
                ("int", "null"),
                "literal",
                "nonnegative_int",
                shape=None,
                coverage_key="phase_time_millis",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("action_time_millis",),
                ("action_time_millis",),
                False,
                ("int", "null"),
                "literal",
                "nonnegative_int",
                shape=None,
                coverage_key="action_time_millis",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("step_time_millis",),
                ("step_time_millis",),
                False,
                ("int", "null"),
                "literal",
                "nonnegative_int",
                shape=None,
                coverage_key="step_time_millis",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("phase_execution",),
                ("phase_execution",),
                False,
                ("object", "null"),
                "selected_child_object",
                "declared_shape",
                shape="elastic_phase_execution",
                coverage_key="phase_execution",
                protected=False,
                item_types=(),
            ),
        ),
        "elastic-policy": (
            SourceFieldRule(
                ("version",),
                ("version",),
                False,
                ("int", "null"),
                "literal",
                "nonnegative_int",
                shape=None,
                coverage_key="version",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("modified_date",),
                ("modified_date",),
                False,
                ("str", "int", "null"),
                "literal",
                "timestamp_text_or_native_millis",
                shape=None,
                coverage_key="modified_date",
                protected=False,
                item_types=(),
            ),
            SourceFieldRule(
                ("policy",),
                ("policy",),
                False,
                ("object", "null"),
                "selected_child_object",
                "declared_shape",
                shape="elastic_policy",
                coverage_key="policy",
                protected=False,
                item_types=(),
            ),
        ),
        "elastic-status": (
            SourceFieldRule(
                ("operation_mode",),
                ("operation_mode",),
                False,
                ("str", "null"),
                "literal",
                "elastic_operation_mode",
                shape=None,
                coverage_key="operation_mode",
                protected=False,
                item_types=(),
            ),
        ),
    }
)
KNOWN_VALUES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "vault_matter_state": frozenset(("OPEN", "CLOSED", "DELETED")),
        "vault_corpus": frozenset(("DRIVE", "MAIL", "GROUPS", "HANGOUTS_CHAT", "VOICE", "CALENDAR", "GEMINI")),
        "voice_covered_data": frozenset(("TEXT_MESSAGES", "VOICEMAILS", "CALL_LOGS")),
        "splunk_datatype": frozenset(("event", "metric")),
        "elastic_operation_mode": frozenset(("RUNNING", "STOPPING", "STOPPED")),
    }
)


_MISSING = object()
_TIMESTAMP = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.[0-9]+)?(?:[Zz]|[+-]([0-9]{2}):([0-9]{2}))"
)
_POLICY = re.compile(r"[A-Za-z0-9_.-]{1,255}")


def _timestamp_known(value: str) -> bool:
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(match[index]) for index in range(1, 7))
    try:
        date(year, month, day)
    except ValueError:
        return False
    # Leap-second literals remain retained unknown detail; no leap-event model is asserted.
    return (
        hour <= 23
        and minute <= 59
        and second <= 59
        and (match[7] is None or (int(match[7]) <= 23 and int(match[8]) <= 59))
    )


def _kind(value: JsonValue) -> NativeKind:
    native = type(value)
    if value is None:
        return "null"
    if native is str:
        return "str"
    if native is bool:
        return "bool"
    if native is int:
        return "int"
    if native is float:
        return "float"
    if native is list:
        return "list"
    if native is dict:
        return "object"
    raise CorrespondenceError()


def _object(value: object) -> JsonObject:
    try:
        result = checked_json(value)
    except ParsingError:
        raise CorrespondenceError() from None
    if type(result) is not dict:
        raise CorrespondenceError()
    return result


def _read(source: JsonObject, path: tuple[str, ...]) -> object:
    current: JsonValue = source
    for key in path:
        if type(current) is not dict:
            raise CorrespondenceError()
        obj = current
        if key not in obj:
            return _MISSING
        current = obj[key]
    return current


def _assign(target: JsonObject, path: tuple[str, ...], value: JsonValue) -> None:
    for key in path[:-1]:
        if key not in target:
            target[key] = {}
        child = target[key]
        if type(child) is not dict:
            raise CorrespondenceError()
        target = child
    target[path[-1]] = value


def _semantic_known(validator: ValidatorId, value: JsonValue) -> bool:
    if validator in KNOWN_VALUES and validator != "voice_covered_data":
        return type(value) is str and value in KNOWN_VALUES[validator]
    if validator in {
        "literal",
        "exact_target_matter_id",
        "exact_target_index",
        "archive_presence",
        "opaque_named_actions",
    }:
        return True
    if validator in {"nonblank", "nonblank_utf8_max_1024"}:
        text = cast(str, value)
        if not text.strip() or (validator == "nonblank_utf8_max_1024" and len(text.encode("utf-8")) > 1024):
            raise CorrespondenceError()
        return True
    if validator == "nonnegative_int":
        if cast(int, value) < 0:
            raise CorrespondenceError()
        return True
    if validator == "splunk_disabled":
        return (
            type(value) is bool
            or (type(value) is int and value in (0, 1))
            or (type(value) is str and value in ("0", "1"))
        )
    if validator == "splunk_nonnegative_setting":
        return (type(value) is int and value >= 0) or (
            type(value) is str and bool(value) and all("0" <= char <= "9" for char in value)
        )
    if validator == "supported_policy_reference":
        text = cast(str, value)
        return _POLICY.fullmatch(text) is not None and text not in {".", ".."} and text.lower() != "_all"
    if validator == "aware_rfc3339_text":
        return _timestamp_known(cast(str, value))
    if validator == "timestamp_text_or_native_millis":
        return type(value) is int or _timestamp_known(cast(str, value))
    if validator == "voice_covered_data":
        return all(cast(str, item) in KNOWN_VALUES[validator] for item in cast(list[JsonValue], value))
    raise CorrespondenceError()


def _shape(source: JsonObject, shape_id: str) -> tuple[JsonObject, bool, bool]:
    shape = SHAPES[shape_id]
    if shape.value_shape is not None:
        dynamic: JsonObject = {}
        unknown = missing = False
        for key, value in source.items():
            if _kind(value) not in shape.value_types:
                raise CorrespondenceError()
            if value is None:
                dynamic[key] = None
                missing = True
            else:
                selected, child_unknown, child_missing = _shape(cast(JsonObject, value), shape.value_shape)
                dynamic[key] = selected
                unknown |= child_unknown
                missing |= child_missing
        return dynamic, unknown, missing
    open_shape = shape.unknown_keys == "retain_exact_and_mark_unknown"
    selected = dict(source) if open_shape else {}
    declared = {rule.source_path[0] for rule in shape.fields}
    unknown = open_shape and any(key not in declared for key in source)
    missing = False
    for rule in shape.fields:
        raw = _read(source, rule.source_path)
        output, coverage, child_missing = _field(rule, raw)
        if output is not _MISSING:
            _assign(selected, rule.output_path, cast(JsonValue, output))
        unknown |= coverage == "unknown"
        # Query branches are alternatives; absent alternatives are not missing detail.
        missing |= child_missing and not (shape_id == "vault_query" and raw is _MISSING)
    return selected, unknown, missing


def _field(rule: SourceFieldRule, raw: object) -> tuple[object, CoverageState, bool]:
    if raw is _MISSING:
        if rule.required:
            raise CorrespondenceError()
        return ("absent" if rule.transform == "archive_presence" else _MISSING), "absent", True
    value = cast(JsonValue, raw)
    if _kind(value) not in rule.accepted_native_types:
        raise CorrespondenceError()
    if value is None:
        return ("null" if rule.transform == "archive_presence" else None), "null", True
    if rule.transform == "archive_presence":
        return ("empty" if value == "" else "nonempty"), "known", False
    if rule.item_types:
        for item in value if type(value) is list else []:
            if _kind(item) not in rule.item_types:
                raise CorrespondenceError()
    if rule.shape is not None:
        if rule.transform == "selected_child_list":
            items: list[JsonValue] = []
            unknown = missing = False
            for item in cast(list[JsonValue], value):
                if type(item) is not dict:
                    raise CorrespondenceError()
                selected, child_unknown, child_missing = _shape(item, rule.shape)
                items.append(selected)
                unknown |= child_unknown
                missing |= child_missing
            return items, "unknown" if unknown else "known", missing
        selected, unknown, missing = _shape(cast(JsonObject, value), rule.shape)
        return selected, "unknown" if unknown else "known", missing
    known = _semantic_known(rule.validator, value)
    return value, "known" if known else "unknown", False


def expected_fields(kind: ReadKind, source: object) -> ExpectedFields:
    """Select one admitted occurrence; selected-target identity stays session-owned."""
    if type(kind) is not str or kind not in ROOT_RULES:
        raise CorrespondenceError()
    snapshot = _object(source)
    fields: JsonObject = {}
    coverage: dict[str, CoverageState] = {}
    unknown = missing = False
    for rule in ROOT_RULES[kind]:
        output, state, child_missing = _field(rule, _read(snapshot, rule.source_path))
        if output is not _MISSING:
            _assign(fields, rule.output_path, cast(JsonValue, output))
        assert rule.coverage_key is not None
        coverage[rule.coverage_key] = state
        unknown |= state == "unknown"
        missing |= child_missing
    if kind == "vault-holds" and fields.get("accounts") and type(fields.get("orgUnit")) is dict:
        unknown = True
    diagnostics: list[InterpretationCode] = []
    if unknown:
        diagnostics.append("unsupported_source_value")
    if missing:
        diagnostics.append("missing_source_detail")
    return ExpectedFields(_object(fields), coverage, tuple(diagnostics))


def validate_correspondence(kind: ReadKind, source: object, fields: object, coverage: object) -> None:
    """Bind exact selected values and finite root coverage to a detached occurrence."""
    expected = expected_fields(kind, source)
    selected, actual_coverage = _object(fields), _object(coverage)
    if canonical_json(selected) != canonical_json(expected.fields) or canonical_json(actual_coverage) != canonical_json(
        cast(JsonObject, expected.coverage)
    ):
        raise CorrespondenceError()


def _selected_expectation(kind: ReadKind, fields: object, coverage: object) -> ExpectedFields:
    """Check intrinsic projection shape; reconstructed source is not source attestation."""
    if type(kind) is not str or kind not in ROOT_RULES:
        raise CorrespondenceError()
    selected = _object(fields)
    reconstructed: JsonObject = {}
    for rule in ROOT_RULES[kind]:
        value = _read(selected, rule.output_path)
        if rule.transform == "archive_presence":
            if type(value) is not str:
                raise CorrespondenceError()
            if value == "absent":
                continue
            if value == "null":
                value = None
            elif value == "empty":
                value = ""
            elif value == "nonempty":
                value = "x"
            else:
                raise CorrespondenceError()
        elif value is _MISSING:
            continue
        _assign(reconstructed, rule.source_path, cast(JsonValue, value))
    validate_correspondence(kind, reconstructed, selected, coverage)
    return expected_fields(kind, reconstructed)


def validate_selected_fields(kind: ReadKind, fields: object, coverage: object) -> None:
    """Validate retained shape without attesting unretained source transport bytes."""
    _selected_expectation(kind, fields, coverage)


NativeScope = Literal["matter", "hold", "index", "policy", "service"]
MethodId = Literal[
    "vault.matters.get",
    "vault.matters.holds.list",
    "splunk.data.indexes.get",
    "elastic.ilm.explain_lifecycle",
    "elastic.ilm.get_lifecycle",
    "elastic.ilm.get_status",
]
InterpretationStatus = Literal["known", "limited"]
_SHA256 = r"[0-9a-f]{64}"
Digest = Annotated[NonBlankStr, Field(min_length=64, max_length=64, json_schema_extra=_schema(_SHA256))]
SourceIdentity = Annotated[NonBlankStr, Field(min_length=1, max_length=1024)]
_NATIVE_SCOPES: dict[ReadKind, NativeScope] = {
    "vault-matter": "matter",
    "vault-holds": "hold",
    "splunk-index": "index",
    "elastic-explain": "index",
    "elastic-policy": "policy",
    "elastic-status": "service",
}
_OBSERVATION_KINDS = {(_METHODS[kind][1], scope): kind for kind, scope in _NATIVE_SCOPES.items()}
_IDENTITY_FIELDS: dict[ReadKind, str | None] = {
    "vault-matter": "matterId",
    "vault-holds": "holdId",
    "splunk-index": "name",
    "elastic-explain": "index",
    "elastic-policy": None,
    "elastic-status": None,
}


def _digest(value: str) -> str:
    if type(value) is not str or re.fullmatch(_SHA256, value) is None:
        raise ValueError("invalid_digest")
    return value


def _source_identity(value: str) -> str:
    if type(value) is not str or not value.strip() or len(value.encode("utf-8")) > 1024:
        raise ValueError("invalid_source_identity")
    return value


def projection_digest(kind: ReadKind, source_identity: str, fields: JsonObject) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "projection_version": "enterprise-retention-projection/v1",
                "method_id": _METHODS[kind][2],
                "native_scope": _NATIVE_SCOPES[kind],
                "source_identity": source_identity,
                "fields": fields,
            }
        )
    ).hexdigest()


def _diagnostic_body(value: EnterpriseRetentionDiagnostic) -> JsonObject:
    return {"code": value.code, "read_id": value.read_id, "safe_http_status": value.safe_http_status}


class EnterpriseRetentionObservation(_WireModel):
    source_identity: SourceIdentity
    api_version: ApiVersion
    projection_version: Literal["enterprise-retention-projection/v1"]
    native_scope: NativeScope
    fields: dict[str, EnterpriseRetentionJsonValue]
    field_coverage: Annotated[dict[str, CoverageState], Field(max_length=33)]
    interpretation_status: InterpretationStatus
    diagnostics: Annotated[list[EnterpriseRetentionDiagnostic], Field(max_length=2)]
    canonical_projection_sha256: Digest

    @field_validator("source_identity")
    @classmethod
    def valid_identity(cls, value: str) -> str:
        return _source_identity(value)

    @field_validator("fields", mode="before")
    @classmethod
    def finite_fields(cls, value: object) -> JsonObject:
        checked = checked_json(value)
        if type(checked) is not dict:
            raise ValueError("invalid_projection")
        return checked

    @field_validator("canonical_projection_sha256")
    @classmethod
    def valid_digest(cls, value: str) -> str:
        return _digest(value)

    @property
    def kind(self) -> ReadKind:
        kind = _OBSERVATION_KINDS.get((self.api_version, self.native_scope))
        if kind is None:
            raise ValueError("invalid_projection_scope")
        return kind

    @model_validator(mode="after")
    def intrinsic_projection(self) -> Self:
        kind = self.kind
        fields = self.fields
        expected = _selected_expectation(kind, fields, self.field_coverage)
        identity_field = _IDENTITY_FIELDS[kind]
        if identity_field is not None and fields.get(identity_field) != self.source_identity:
            raise ValueError("invalid_projection_identity")
        if kind != "vault-holds":
            ReadKey(kind=kind, source_id=self.source_identity)
        if self.canonical_projection_sha256 != projection_digest(kind, self.source_identity, fields):
            raise ValueError("invalid_projection_digest")
        expected_status = "limited" if expected.diagnostics else "known"
        if self.interpretation_status != expected_status:
            raise ValueError("invalid_projection_interpretation")
        if tuple(item.code for item in self.diagnostics) != expected.diagnostics:
            raise ValueError("invalid_projection_diagnostics")
        if self.diagnostics:
            checked_diagnostics(
                self.diagnostics,
                scope="observation",
                provider=_METHODS[kind][0],
                kind=kind,
                owner_read_id=self.diagnostics[0].read_id,
            )
        if len(observation_bytes(self)) > PROJECTION_BYTE_LIMIT:
            raise ValueError("projection_limit")
        return self


def observation_body(value: EnterpriseRetentionObservation) -> JsonObject:
    return {
        "source_identity": value.source_identity,
        "api_version": value.api_version,
        "projection_version": value.projection_version,
        "native_scope": value.native_scope,
        "fields": value.fields,
        "field_coverage": cast(JsonObject, value.field_coverage),
        "interpretation_status": value.interpretation_status,
        "diagnostics": [_diagnostic_body(item) for item in value.diagnostics],
        "canonical_projection_sha256": value.canonical_projection_sha256,
    }


def observation_bytes(value: EnterpriseRetentionObservation) -> bytes:
    return canonical_json(observation_body(value))


def make_observation(
    key: ReadKey,
    *,
    profile_alias: str,
    source_identity: str,
    fields: JsonObject,
    coverage: dict[str, CoverageState],
) -> EnterpriseRetentionObservation:
    key = ReadKey.model_validate(key)
    expected = _selected_expectation(key.kind, fields, coverage)
    read_id = read_identifier(_METHODS[key.kind][0], profile_alias, key)
    return EnterpriseRetentionObservation(
        source_identity=source_identity,
        api_version=_METHODS[key.kind][1],
        projection_version="enterprise-retention-projection/v1",
        native_scope=_NATIVE_SCOPES[key.kind],
        fields=expected.fields,
        field_coverage=expected.coverage,
        interpretation_status="limited" if expected.diagnostics else "known",
        diagnostics=[
            EnterpriseRetentionDiagnostic(code=code, read_id=read_id, safe_http_status=200)
            for code in expected.diagnostics
        ],
        canonical_projection_sha256=projection_digest(key.kind, source_identity, expected.fields),
    )


_READ_COUNTERS = (
    "attempts",
    "responses_received",
    "pages_received",
    "pages_admitted",
    "records_received",
    "records_admitted",
    "duplicates_coalesced",
    "conflicts_quarantined",
    "raw_bytes",
    "decoded_bytes",
)


class EnterpriseRetentionReadResult(_WireModel):
    read_id: ReadIdentifier
    kind: ReadKind
    source_id: Annotated[NonBlankStr, Field(max_length=255)]
    method_id: MethodId
    status: ResultStatus
    attempts: Counter
    responses_received: Counter
    pages_received: Counter
    pages_admitted: Counter
    records_received: Counter
    records_admitted: Counter
    duplicates_coalesced: Counter
    conflicts_quarantined: Counter
    raw_bytes: Counter
    decoded_bytes: Counter
    started_at: UtcClock | None
    finished_at: UtcClock | None
    safe_http_status: HttpStatus | None
    terminal_reason: DiagnosticCode | None
    diagnostics: Annotated[list[EnterpriseRetentionDiagnostic], Field(max_length=40)]
    observations: Annotated[list[EnterpriseRetentionObservation], Field(max_length=2000)]

    @model_validator(mode="after")
    def ledger_consistency(self) -> Self:
        provider, _, key = parsed_read_identifier(self.read_id)
        if key.kind != self.kind or key.source_id != self.source_id or self.method_id != _METHODS[self.kind][2]:
            raise ValueError("invalid_read_identity")
        checked_diagnostics(
            self.diagnostics, scope="read", provider=provider, kind=self.kind, owner_read_id=self.read_id
        )
        if self.attempts == 0:
            if any(getattr(self, name) != 0 for name in _READ_COUNTERS) or self.observations:
                raise ValueError("invalid_unattempted_read")
            if self.started_at is not None or self.finished_at is not None or self.safe_http_status is not None:
                raise ValueError("invalid_unattempted_read")
        elif self.started_at is None or self.finished_at is None or self.started_at > self.finished_at:
            raise ValueError("invalid_read_clock")
        if not self.pages_admitted <= self.pages_received <= self.responses_received <= self.attempts:
            raise ValueError("invalid_read_counts")
        if (
            self.records_admitted != len(self.observations)
            or self.records_admitted + self.duplicates_coalesced > self.records_received
        ):
            raise ValueError("invalid_read_counts")
        if self.conflicts_quarantined * 2 > self.records_received:
            raise ValueError("invalid_read_counts")
        if self.responses_received == 0 and self.safe_http_status is not None:
            raise ValueError("invalid_read_status")
        if self.responses_received == 1 and self.safe_http_status is None:
            raise ValueError("invalid_read_status")
        if self.pages_received and self.safe_http_status is not None and self.safe_http_status != 200:
            raise ValueError("invalid_successful_response_status")
        if self.status == "complete" and (
            self.pages_received != self.pages_admitted
            or self.records_received != self.records_admitted + self.duplicates_coalesced
        ):
            raise ValueError("incomplete_source_accounting")
        if self.pages_admitted == 0 and (self.observations or self.status != "unavailable"):
            raise ValueError("invalid_read_status")
        if self.pages_admitted and self.status == "unavailable":
            raise ValueError("invalid_read_status")
        if self.kind != "vault-holds":
            if (
                self.pages_admitted > 1
                or self.records_admitted > 1
                or self.duplicates_coalesced
                or self.conflicts_quarantined
            ):
                raise ValueError("invalid_leaf_counts")
            if self.pages_admitted != self.records_admitted:
                raise ValueError("invalid_leaf_counts")
        codes = {item.code for item in self.diagnostics}
        if self.conflicts_quarantined and "duplicate_conflict" not in codes:
            raise ValueError("invalid_conflict_diagnostic")
        if not self.conflicts_quarantined and "duplicate_conflict" in codes:
            raise ValueError("invalid_conflict_diagnostic")
        if self.terminal_reason is not None:
            rules = _DIAGNOSTIC_RULES[self.terminal_reason]
            allowed = [
                rule
                for rule in rules
                if rule[4]
                and provider in rule[1]
                and (rule[0] == "run" or (rule[0] == "read" and self.kind in rule[2]))
            ]
            if not allowed or (all(rule[0] == "read" for rule in allowed) and self.terminal_reason not in codes):
                raise ValueError("invalid_terminal_reason")
        if (
            any(diagnostic_rule(item.code, "read", provider, self.kind)[4] for item in self.diagnostics)
            and self.terminal_reason is None
        ):
            raise ValueError("missing_terminal_reason")
        if self.status == "complete" and (self.terminal_reason is not None or self.conflicts_quarantined):
            raise ValueError("invalid_read_completeness")
        seen: set[str] = set()
        for item in self.observations:
            if item.kind != self.kind or (self.kind != "vault-holds" and item.source_identity != self.source_id):
                raise ValueError("invalid_observation_membership")
            if item.source_identity in seen:
                raise ValueError("duplicate_observation")
            seen.add(item.source_identity)
            checked_diagnostics(
                item.diagnostics, scope="observation", provider=provider, kind=self.kind, owner_read_id=self.read_id
            )
        return self


def empty_read(key: ReadKey, *, profile_alias: str) -> EnterpriseRetentionReadResult:
    key = ReadKey.model_validate(key)
    return EnterpriseRetentionReadResult(
        read_id=read_identifier(_METHODS[key.kind][0], profile_alias, key),
        kind=key.kind,
        source_id=key.source_id,
        method_id=cast(MethodId, _METHODS[key.kind][2]),
        status="unavailable",
        attempts=0,
        responses_received=0,
        pages_received=0,
        pages_admitted=0,
        records_received=0,
        records_admitted=0,
        duplicates_coalesced=0,
        conflicts_quarantined=0,
        raw_bytes=0,
        decoded_bytes=0,
        started_at=None,
        finished_at=None,
        safe_http_status=None,
        terminal_reason=None,
        diagnostics=[],
        observations=[],
    )


PolicyResolution = Literal["not_applicable", "resolved", "unresolved"]
_VERSION = r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}"
_RUN_ID = r"[0-7][0-9A-HJKMNP-TV-Z]{25}"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
Version = Annotated[NonBlankStr, Field(min_length=1, max_length=64, json_schema_extra=_schema(_VERSION))]
RunIdentifier = Annotated[NonBlankStr, Field(min_length=26, max_length=26, json_schema_extra=_schema(_RUN_ID))]
FindingIdentifier = Annotated[NonBlankStr, Field(min_length=36, max_length=36, json_schema_extra=_schema(_UUID))]


def _false_flag(value: object) -> Literal[False]:
    if value is not False:
        raise ValueError("invalid_assessment_flag")
    return False


FalseFlag = Annotated[Literal[False], BeforeValidator(_false_flag)]


_SELECTED_KINDS: dict[ProviderName, ReadKind] = {
    "google-vault": "vault-matter",
    "splunk-enterprise": "splunk-index",
    "elastic-ilm": "elastic-explain",
}


def resource_identifier(provider: ProviderName, profile_alias: str, source_id: str) -> str:
    kind = _SELECTED_KINDS[provider]
    key = ReadKey(kind=kind, source_id=source_id)
    read_identifier(provider, profile_alias, key)
    resource_kind = "matter" if provider == "google-vault" else "index"
    return f"enterprise-retention/{provider}/{profile_alias}/{resource_kind}/{source_id}"


def _resource_parts(value: str) -> tuple[ProviderName, str, str]:
    if type(value) is not str or len(value) > 384:
        raise ValueError("invalid_resource_id")
    parts = value.split("/")
    if (
        len(parts) != 5
        or parts[0] != "enterprise-retention"
        or parts[1] not in ("google-vault", "splunk-enterprise", "elastic-ilm")
    ):
        raise ValueError("invalid_resource_id")
    provider = cast(ProviderName, parts[1])
    if resource_identifier(provider, parts[2], parts[4]) != value:
        raise ValueError("invalid_resource_id")
    return provider, parts[2], parts[4]


class EnterpriseRetentionResourceResult[TargetT: (VaultMatterTarget, SplunkIndexTarget, ElasticIndexTarget)](
    _WireModel
):
    target: TargetT
    canonical_resource_id: ReadIdentifier
    status: ResultStatus
    read_ids: Annotated[
        list[ReadIdentifier], Field(min_length=1, max_length=3, json_schema_extra={"uniqueItems": True})
    ]
    policy_resolution: PolicyResolution
    diagnostics: Annotated[list[EnterpriseRetentionDiagnostic], Field(max_length=3)]

    @model_validator(mode="after")
    def references(self) -> Self:
        provider, alias, source_id = _resource_parts(self.canonical_resource_id)
        if source_id != target_identity(self.target) or len(set(self.read_ids)) != len(self.read_ids):
            raise ValueError("invalid_resource_identity")
        keys: list[ReadKey] = []
        for value in self.read_ids:
            read_provider, read_alias, key = parsed_read_identifier(value)
            if read_provider != provider or read_alias != alias:
                raise ValueError("invalid_resource_reference")
            keys.append(key)
        expected: list[ReadKey]
        if provider == "google-vault":
            expected = [
                ReadKey(kind="vault-matter", source_id=source_id),
                ReadKey(kind="vault-holds", source_id=source_id),
            ]
        elif provider == "splunk-enterprise":
            expected = [ReadKey(kind="splunk-index", source_id=source_id)]
        else:
            expected = [ReadKey(kind="elastic-explain", source_id=source_id)]
            if self.policy_resolution == "resolved":
                if len(keys) != 3 or keys[1].kind != "elastic-policy":
                    raise ValueError("invalid_policy_reference")
                expected.append(keys[1])
            expected.append(ReadKey(kind="elastic-status", source_id="service"))
        if keys != expected or (provider != "elastic-ilm" and self.policy_resolution != "not_applicable"):
            raise ValueError("invalid_resource_reference")
        checked_diagnostics(self.diagnostics, scope="resource", provider=provider)
        if any(item.read_id not in self.read_ids for item in self.diagnostics):
            raise ValueError("invalid_resource_diagnostic")
        return self


class CoverageCounts(_WireModel):
    absent: Counter
    null: Counter
    known: Counter
    unknown: Counter


CoverageTotals = Annotated[dict[str, CoverageCounts], Field(max_length=33)]


class _FindingRead(_WireModel):
    read_id: ReadIdentifier
    status: ResultStatus
    observations: Counter
    observation_digests_sha256: Digest

    @field_validator("read_id")
    @classmethod
    def valid_read_id(cls, value: str) -> str:
        parsed_read_identifier(value)
        return value

    @field_validator("observation_digests_sha256")
    @classmethod
    def valid_digest(cls, value: str) -> str:
        return _digest(value)


class _FindingData(_WireModel):
    target: EnterpriseTarget
    status: ResultStatus
    policy_resolution: PolicyResolution
    reads: Annotated[list[_FindingRead], Field(min_length=1, max_length=3)]
    field_coverage: CoverageTotals


class _SelectedFilter(_WireModel):
    provider: ProviderName
    profile_alias: ScopeLabel
    scope_label: ScopeLabel
    target: EnterpriseTarget
    observation_scope: Literal["configuration"]
    coverage_scope: Literal["selected_resources"]

    @field_validator("profile_alias", "scope_label")
    @classmethod
    def alias(cls, value: str) -> str:
        if re.fullmatch(_ALIAS, value) is None:
            raise ValueError("invalid_filter")
        return value


class _FindingPagination(_WireModel, PaginationContext):
    page_size: Literal[100] | None
    page_number: None
    total_pages: Counter
    continuation_token: None
    is_complete: Annotated[bool, Field(strict=True)]


class _FindingContext(_WireModel, CollectionContext):
    collector_id: Literal["enterprise-retention"]
    collector_version: Version
    run_id: RunIdentifier
    collected_at: UtcClock
    credential_identity: Literal["operator-configured:identity-unverified"]
    source_system_id: Annotated[NonBlankStr, Field(max_length=128)]
    filter_applied: Annotated[dict[str, Any], Field(min_length=6, max_length=6)]
    pagination_context: _FindingPagination
    evidentia_version: Version

    @field_validator("collector_version", "evidentia_version")
    @classmethod
    def version(cls, value: str) -> str:
        if re.fullmatch(_VERSION, value) is None:
            raise ValueError("invalid_version")
        return value

    @field_validator("run_id")
    @classmethod
    def run_identifier(cls, value: str) -> str:
        if re.fullmatch(_RUN_ID, value) is None:
            raise ValueError("invalid_run_id")
        return value

    @field_validator("filter_applied", mode="before")
    @classmethod
    def exact_filter(cls, value: object) -> dict[str, Any]:
        checked = checked_json(value)
        if type(checked) is not dict:
            raise ValueError("invalid_filter")
        parsed = _SelectedFilter.model_validate(checked)
        target = target_identity(parsed.target)
        kind = _SELECTED_KINDS[parsed.provider]
        ReadKey(kind=kind, source_id=target)
        return checked

    @model_validator(mode="after")
    def source_matches_filter(self) -> Self:
        if (
            self.source_system_id
            != f"enterprise-retention/{self.filter_applied['provider']}/{self.filter_applied['profile_alias']}"
        ):
            raise ValueError("invalid_source_system")
        return self


FindingTitle = Literal[
    "Google Vault matter and hold configuration",
    "Splunk Enterprise index retention configuration",
    "Elasticsearch ILM configuration",
]
FindingDescription = Literal[
    "Selected matter and hold configuration; retention rules and held-record coverage are unassessed.",
    "Selected index configuration; event coverage and archival execution are unassessed.",
    (
        "Selected index, service and current policy configuration; "
        "document coverage and lifecycle execution are unassessed."
    ),
]
FindingResourceType = Literal["GoogleVault::Matter", "SplunkEnterprise::Index", "ElasticsearchILM::Index"]
_FINDING_TEXT: dict[ProviderName, tuple[FindingTitle, FindingDescription, FindingResourceType]] = {
    "google-vault": (
        "Google Vault matter and hold configuration",
        "Selected matter and hold configuration; retention rules and held-record coverage are unassessed.",
        "GoogleVault::Matter",
    ),
    "splunk-enterprise": (
        "Splunk Enterprise index retention configuration",
        "Selected index configuration; event coverage and archival execution are unassessed.",
        "SplunkEnterprise::Index",
    ),
    "elastic-ilm": (
        "Elasticsearch ILM configuration",
        (
            "Selected index, service and current policy configuration; "
            "document coverage and lifecycle execution are unassessed."
        ),
        "ElasticsearchILM::Index",
    ),
}


class _EnterpriseFinding(_WireModel, SecurityFinding):
    id: FindingIdentifier
    title: FindingTitle
    description: FindingDescription
    severity: Literal[Severity.INFORMATIONAL]
    status: Literal[FindingStatus.ACTIVE]
    compliance_status: Literal[ComplianceStatus.UNKNOWN]
    remediation: None
    source_system: Literal["enterprise-retention"]
    source_finding_id: ReadIdentifier
    resource_type: FindingResourceType
    resource_id: ReadIdentifier
    resource_region: None
    resource_account: None
    control_mappings: Annotated[list[ControlMapping], Field(max_length=0)]
    collection_context: _FindingContext
    raw_data: _FindingData
    first_observed: UtcClock
    last_observed: UtcClock
    resolved_at: None

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        if re.fullmatch(_UUID, value) is None:
            raise ValueError("invalid_finding_id")
        return value

    @model_validator(mode="after")
    def canonical_identity(self) -> Self:
        provider, _, _ = _resource_parts(self.resource_id)
        if self.source_finding_id != self.resource_id or self.id != deterministic_finding_id(
            "enterprise-retention", self.resource_id
        ):
            raise ValueError("invalid_finding_identity")
        if (self.title, self.description, self.resource_type) != _FINDING_TEXT[provider]:
            raise ValueError("invalid_finding_description")
        return self


class EnterpriseRetentionManifest(_WireModel):
    schema_version: Literal["enterprise-retention-manifest/v1"]
    run_id: RunIdentifier
    collector_version: Version
    evidentia_version: Version
    status: ResultStatus
    resources_requested: Counter
    resources_attempted: Counter
    reads_planned: Counter
    reads_attempted: Counter
    reads_completed: Counter
    attempts: Counter
    responses_received: Counter
    pages_received: Counter
    pages_admitted: Counter
    records_received: Counter
    records_admitted: Counter
    duplicates_coalesced: Counter
    conflicts_quarantined: Counter
    raw_bytes: Counter
    decoded_bytes: Counter
    canonical_observation_bytes: Counter
    findings: Counter

    @field_validator("collector_version", "evidentia_version")
    @classmethod
    def version(cls, value: str) -> str:
        return _FindingContext.version(value)

    @field_validator("run_id")
    @classmethod
    def valid_run_id(cls, value: str) -> str:
        return _FindingContext.run_identifier(value)


class _ResultBranch(_WireModel):
    schema_version: Literal["enterprise-retention-collection/v1"]
    profile_alias: ScopeLabel
    scope_label: ScopeLabel
    status: ResultStatus
    started_at: UtcClock
    finished_at: UtcClock
    observation_scope: Literal["configuration"]
    coverage_scope: Literal["selected_resources"]
    identity_basis: Literal["operator-declared"]
    authenticated_identity_verified: FalseFlag
    object_enforcement_assessed: FalseFlag
    recordset_completeness_assessed: FalseFlag
    source_reads: Annotated[list[EnterpriseRetentionReadResult], Field(min_length=1, max_length=41)]
    findings: Annotated[list[_EnterpriseFinding], Field(max_length=20)]
    diagnostics: Annotated[list[EnterpriseRetentionDiagnostic], Field(max_length=40)]
    field_coverage: CoverageTotals
    manifest: EnterpriseRetentionManifest

    @field_validator("profile_alias", "scope_label")
    @classmethod
    def alias(cls, value: str) -> str:
        if re.fullmatch(_ALIAS, value) is None:
            raise ValueError("invalid_result_scope")
        return value

    @model_validator(mode="after")
    def ordered_clock(self) -> Self:
        if self.started_at > self.finished_at:
            raise ValueError("invalid_result_clock")
        return self


class VaultCollectResult(_ResultBranch):
    provider: Literal["google-vault"]
    resources: Annotated[list[EnterpriseRetentionResourceResult[VaultMatterTarget]], Field(min_length=1, max_length=20)]
    retention_rules_assessed: FalseFlag
    unassessed_surfaces: tuple[
        Literal["default_retention_rules"], Literal["custom_retention_rules"], Literal["held_record_coverage"]
    ]


class SplunkCollectResult(_ResultBranch):
    provider: Literal["splunk-enterprise"]
    resources: Annotated[list[EnterpriseRetentionResourceResult[SplunkIndexTarget]], Field(min_length=1, max_length=20)]
    unassessed_surfaces: tuple[
        Literal["event_coverage"],
        Literal["archive_execution_and_durability"],
        Literal["smartstore_and_volume_configuration"],
        Literal["cluster_wide_configuration"],
    ]


class ElasticCollectResult(_ResultBranch):
    provider: Literal["elastic-ilm"]
    resources: Annotated[
        list[EnterpriseRetentionResourceResult[ElasticIndexTarget]], Field(min_length=1, max_length=20)
    ]
    unassessed_surfaces: tuple[
        Literal["document_coverage"],
        Literal["lifecycle_execution_guarantees"],
        Literal["templates_and_unselected_indices"],
        Literal["atomic_provider_snapshot"],
    ]


ResultBranch = VaultCollectResult | SplunkCollectResult | ElasticCollectResult
_UNASSESSED: dict[ProviderName, tuple[str, ...]] = {
    "google-vault": ("default_retention_rules", "custom_retention_rules", "held_record_coverage"),
    "splunk-enterprise": (
        "event_coverage",
        "archive_execution_and_durability",
        "smartstore_and_volume_configuration",
        "cluster_wide_configuration",
    ),
    "elastic-ilm": (
        "document_coverage",
        "lifecycle_execution_guarantees",
        "templates_and_unselected_indices",
        "atomic_provider_snapshot",
    ),
}


_RESOURCE_TYPES: dict[ProviderName, type[BaseModel]] = {
    "google-vault": EnterpriseRetentionResourceResult[VaultMatterTarget],
    "splunk-enterprise": EnterpriseRetentionResourceResult[SplunkIndexTarget],
    "elastic-ilm": EnterpriseRetentionResourceResult[ElasticIndexTarget],
}
_RESULT_TYPES: dict[ProviderName, type[_ResultBranch]] = {
    "google-vault": VaultCollectResult,
    "splunk-enterprise": SplunkCollectResult,
    "elastic-ilm": ElasticCollectResult,
}
_WIRE_TYPES: tuple[type[BaseModel], ...] = (
    VaultMatterTarget,
    SplunkIndexTarget,
    ElasticIndexTarget,
    ReadKey,
    EnterpriseRetentionDiagnostic,
    EnterpriseRetentionObservation,
    EnterpriseRetentionReadResult,
    EnterpriseRetentionResourceResult,
    *_RESOURCE_TYPES.values(),
    CoverageCounts,
    _FindingRead,
    _FindingData,
    _SelectedFilter,
    _FindingPagination,
    _FindingContext,
    _EnterpriseFinding,
    EnterpriseRetentionManifest,
    VaultCollectResult,
    SplunkCollectResult,
    ElasticCollectResult,
)
_CLOCK_FIELDS = frozenset({"started_at", "finished_at", "collected_at", "first_observed", "last_observed"})


class _PublicationTree:
    """Bound a detached native tree before handing it to the JSON-mode contracts."""

    def __init__(self, *, native: bool) -> None:
        self.native = native
        self.nodes = 0
        self.size = 0

    def charge(self, amount: int) -> None:
        self.size += amount
        if self.size > RESULT_BYTE_LIMIT:
            raise EnterpriseRetentionInputError("invalid_result")

    def convert(self, value: object, depth: int = 0, *, field: str = "", source: bool = False) -> JsonValue:
        self.nodes += 1
        if self.nodes > 2_097_152 or depth > 20:
            raise EnterpriseRetentionInputError("invalid_result")
        value_type = type(value)
        if not source and value_type in _WIRE_TYPES:
            model = cast(BaseModel, value)
            if model.__pydantic_extra__:
                raise EnterpriseRetentionInputError("invalid_result")
            value = _payload(model)
            value_type = dict
        if not source and field in _CLOCK_FIELDS:
            if value_type is datetime:
                value = clock_text(_clock(value, _NATIVE_CLOCK_INFO))
                value_type = str
            elif value is not None and self.native:
                raise EnterpriseRetentionInputError("invalid_result")
        if not source and value_type in (Severity, FindingStatus, ComplianceStatus):
            value = cast(Severity | FindingStatus | ComplianceStatus, value).value
            value_type = str
        if value is None:
            self.charge(4)
            return None
        if value_type is bool:
            self.charge(4 if value else 5)
            return cast(bool, value)
        if value_type is int or value_type is float:
            checked = checked_json(value)
            self.charge(len(json.dumps(checked, allow_nan=False)))
            return checked
        if value_type is str:
            text = cast(str, value)
            if len(text) > 1_048_576:
                raise EnterpriseRetentionInputError("invalid_result")
            self.charge(len(json.dumps(text, ensure_ascii=False).encode("utf-8")))
            return text
        if value_type is tuple and not source:
            value_type = list
        if value_type is list:
            items = cast(list[object] | tuple[object, ...], value)
            self.charge(2 + max(len(items) - 1, 0))
            return [self.convert(item, depth + 1, source=source) for item in items]
        if value_type is dict:
            mapping = cast(dict[object, object], value)
            self.charge(2 + max(len(mapping) - 1, 0))
            output: JsonObject = {}
            for key, item in mapping.items():
                if type(key) is not str:
                    raise EnterpriseRetentionInputError("invalid_result")
                self.convert(key, depth + 1, source=True)
                self.charge(1)
                output[key] = self.convert(item, depth + 1, field=key, source=source or key == "fields")
            return output
        raise EnterpriseRetentionInputError("invalid_result")


class _NativeClockInfo:
    mode: Literal["python"] = "python"


_NATIVE_CLOCK_INFO = cast(ValidationInfo, _NativeClockInfo())


def _wire_object(value: object, *, native: bool = False) -> JsonObject:
    result = _PublicationTree(native=native).convert(value)
    return checked_result_json(result)


def _target_data(target: EnterpriseTarget) -> JsonObject:
    target = type(target).model_validate(target)
    if isinstance(target, VaultMatterTarget):
        return {"matter_id": target.matter_id}
    return {"index": target.index}


def initial_read_keys(request: EnterpriseRetentionCollectRequest) -> list[ReadKey]:
    request = EnterpriseRetentionCollectRequest.model_validate(request)
    result: list[ReadKey] = []
    if request.root.provider == "elastic-ilm":
        result.append(ReadKey(kind="elastic-status", source_id="service"))
    for target in request.root.targets:
        identity = target_identity(target)
        result.append(ReadKey(kind=_SELECTED_KINDS[request.root.provider], source_id=identity))
        if request.root.provider == "google-vault":
            result.append(ReadKey(kind="vault-holds", source_id=identity))
    return result


def _coverage(provider: ProviderName, reads: list[EnterpriseRetentionReadResult]) -> dict[str, CoverageCounts]:
    counts = {
        f"{kind}/{rule.coverage_key}": {"absent": 0, "null": 0, "known": 0, "unknown": 0}
        for kind in _METHODS
        if _METHODS[kind][0] == provider
        for rule in ROOT_RULES[kind]
    }
    for read in reads:
        for observation in read.observations:
            for path, state in observation.field_coverage.items():
                counts[f"{read.kind}/{path}"][state] += 1
    return {path: CoverageCounts.model_validate(value) for path, value in counts.items()}


def _relation(explain: EnterpriseRetentionReadResult) -> tuple[PolicyResolution, str | None, DiagnosticCode | None]:
    if not explain.observations:
        return "unresolved", None, None
    fields = explain.observations[0].fields
    if fields["managed"] is False:
        return "not_applicable", None, None
    policy = fields.get("policy")
    if policy is None or policy == "":
        return "unresolved", None, "policy_reference_missing"
    if not supported_policy(policy):
        return "unresolved", None, "policy_reference_unsupported"
    return "resolved", cast(str, policy), None


def _resource_data(
    request: EnterpriseRetentionCollectRequest,
    target: EnterpriseTarget,
    ledger: dict[str, EnterpriseRetentionReadResult],
) -> dict[str, Any]:
    provider, alias = request.root.provider, request.root.profile_alias
    identity = target_identity(target)
    selected_key = ReadKey(kind=_SELECTED_KINDS[provider], source_id=identity)
    selected_id = read_identifier(provider, alias, selected_key)
    reads = [ledger[selected_id]]
    resolution: PolicyResolution = "not_applicable"
    diagnostics: list[EnterpriseRetentionDiagnostic] = []
    if provider == "google-vault":
        reads.append(ledger[read_identifier(provider, alias, ReadKey(kind="vault-holds", source_id=identity))])
        if reads[1].attempts and not reads[0].pages_admitted:
            raise ValueError("unauthorized_holds_read")
    elif provider == "elastic-ilm":
        resolution, policy, code = _relation(reads[0])
        if policy is not None:
            policy_id = read_identifier(provider, alias, ReadKey(kind="elastic-policy", source_id=policy))
            reads.append(ledger[policy_id])
            if reads[-1].status == "unavailable":
                diagnostics.append(
                    EnterpriseRetentionDiagnostic(code="policy_unavailable", read_id=policy_id, safe_http_status=None)
                )
        elif code is not None:
            diagnostics.append(EnterpriseRetentionDiagnostic(code=code, read_id=selected_id, safe_http_status=None))
        reads.append(ledger[read_identifier(provider, alias, ReadKey(kind="elastic-status", source_id="service"))])
    status: ResultStatus = (
        "complete"
        if all(read.status == "complete" for read in reads) and resolution != "unresolved"
        else "partial"
        if any(read.pages_admitted for read in reads)
        else "unavailable"
    )
    return {
        "target": _target_data(target),
        "canonical_resource_id": resource_identifier(provider, alias, identity),
        "status": status,
        "read_ids": [read.read_id for read in reads],
        "policy_resolution": resolution,
        "diagnostics": diagnostics,
    }


def _finding(
    request: EnterpriseRetentionCollectRequest,
    resource: dict[str, Any],
    ledger: dict[str, EnterpriseRetentionReadResult],
    *,
    run_id: str,
    started_at: datetime,
    finished_at: datetime,
    collector_version: str,
    evidentia_version: str,
) -> _EnterpriseFinding | None:
    reads = [ledger[read_id] for read_id in resource["read_ids"]]
    if not any(read.pages_admitted for read in reads if read.kind not in ("elastic-status", "elastic-policy")):
        return None
    provider = request.root.provider
    title, description, resource_type = _FINDING_TEXT[provider]
    summaries = [
        _FindingRead(
            read_id=read.read_id,
            status=read.status,
            observations=len(read.observations),
            observation_digests_sha256=hashlib.sha256(
                canonical_json([item.canonical_projection_sha256 for item in read.observations])
            ).hexdigest(),
        )
        for read in reads
    ]
    context = _FindingContext(
        collector_id="enterprise-retention",
        collector_version=collector_version,
        run_id=run_id,
        collected_at=finished_at,
        credential_identity="operator-configured:identity-unverified",
        source_system_id=f"enterprise-retention/{provider}/{request.root.profile_alias}",
        filter_applied={
            "provider": provider,
            "profile_alias": request.root.profile_alias,
            "scope_label": request.root.scope_label,
            "target": resource["target"],
            "observation_scope": "configuration",
            "coverage_scope": "selected_resources",
        },
        pagination_context=_FindingPagination(
            page_size=100 if provider == "google-vault" else None,
            page_number=None,
            total_pages=sum(read.pages_admitted for read in reads),
            continuation_token=None,
            is_complete=resource["status"] == "complete",
        ),
        evidentia_version=evidentia_version,
    )
    return _EnterpriseFinding(
        id=deterministic_finding_id("enterprise-retention", resource["canonical_resource_id"]),
        title=title,
        description=description,
        severity=Severity.INFORMATIONAL,
        status=FindingStatus.ACTIVE,
        compliance_status=ComplianceStatus.UNKNOWN,
        remediation=None,
        source_system="enterprise-retention",
        source_finding_id=resource["canonical_resource_id"],
        resource_type=resource_type,
        resource_id=resource["canonical_resource_id"],
        resource_region=None,
        resource_account=None,
        control_mappings=[],
        collection_context=context,
        raw_data=_FindingData.model_validate(
            {
                "target": resource["target"],
                "status": resource["status"],
                "policy_resolution": resource["policy_resolution"],
                "reads": summaries,
                "field_coverage": _coverage(provider, reads),
            }
        ),
        first_observed=started_at,
        last_observed=finished_at,
        resolved_at=None,
    )


def _checked_read_plan(
    request: EnterpriseRetentionCollectRequest,
    reads: list[EnterpriseRetentionReadResult],
) -> dict[str, EnterpriseRetentionReadResult]:
    provider, alias = request.root.provider, request.root.profile_alias
    ledger = {read.read_id: read for read in reads}
    if len(ledger) != len(reads):
        raise ValueError("duplicate_read_id")
    keys = initial_read_keys(request)
    if provider == "elastic-ilm":
        policies: set[str] = set()
        for target in request.root.targets:
            explain_id = read_identifier(
                provider, alias, ReadKey(kind="elastic-explain", source_id=target_identity(target))
            )
            explain = ledger[explain_id]
            _, policy, _ = _relation(explain)
            if policy is not None and policy not in policies:
                policies.add(policy)
                keys.append(ReadKey(kind="elastic-policy", source_id=policy))
    expected_ids = [read_identifier(provider, alias, key) for key in keys]
    if list(ledger) != expected_ids:
        raise ValueError("invalid_read_plan")
    return ledger


def _assemble_result(
    request: EnterpriseRetentionCollectRequest,
    *,
    reads: list[EnterpriseRetentionReadResult],
    run_id: str,
    started_at: datetime,
    finished_at: datetime,
    diagnostics: list[EnterpriseRetentionDiagnostic],
    collector_version: str,
    evidentia_version: str,
) -> dict[str, Any]:
    request = EnterpriseRetentionCollectRequest.model_validate(request)
    provider, alias = request.root.provider, request.root.profile_alias
    reads = [EnterpriseRetentionReadResult.model_validate(read) for read in reads]
    ledger = _checked_read_plan(request, reads)
    checked = checked_diagnostics(diagnostics, scope="run", provider=provider)
    if any(item.read_id is not None and item.read_id not in ledger for item in checked):
        raise ValueError("invalid_run_reference")
    run_codes = {item.code for item in checked}
    for read in reads:
        if read.started_at is not None and (
            read.started_at < started_at or read.finished_at is None or read.finished_at > finished_at
        ):
            raise ValueError("read_outside_run_clock")
        if (
            read.terminal_reason is not None
            and any(rule[0] == "run" for rule in _DIAGNOSTIC_RULES[read.terminal_reason])
            and read.terminal_reason not in run_codes
            and read.terminal_reason not in {item.code for item in read.diagnostics}
        ):
            raise ValueError("missing_run_diagnostic")
    resources = [_resource_data(request, target, ledger) for target in request.root.targets]
    status: ResultStatus = (
        "complete"
        if all(item["status"] == "complete" for item in resources) and not checked
        else "partial"
        if any(read.pages_admitted for read in reads if read.kind not in ("elastic-status", "elastic-policy"))
        else "unavailable"
    )
    findings = [
        value
        for resource in resources
        if (
            value := _finding(
                request,
                resource,
                ledger,
                run_id=run_id,
                started_at=started_at,
                finished_at=finished_at,
                collector_version=collector_version,
                evidentia_version=evidentia_version,
            )
        )
        is not None
    ]
    totals = {name: sum(getattr(read, name) for read in reads) for name in _READ_COUNTERS}
    observation_total = sum(len(observation_bytes(item)) for read in reads for item in read.observations)
    if observation_total > RUN_PROJECTION_BYTE_LIMIT or totals["attempts"] > 100:
        raise ValueError("invalid_run_limits")
    if provider == "google-vault":
        holds = [read for read in reads if read.kind == "vault-holds"]
        if sum(read.pages_admitted for read in holds) > 20 or sum(read.records_admitted for read in holds) > 2000:
            raise ValueError("invalid_hold_admission")
    manifest = EnterpriseRetentionManifest.model_validate(
        {
            "schema_version": "enterprise-retention-manifest/v1",
            "run_id": run_id,
            "collector_version": collector_version,
            "evidentia_version": evidentia_version,
            "status": status,
            "resources_requested": len(resources),
            "resources_attempted": sum(
                ledger[
                    read_identifier(
                        provider, alias, ReadKey(kind=_SELECTED_KINDS[provider], source_id=target_identity(target))
                    )
                ].attempts
                > 0
                for target in request.root.targets
            ),
            "reads_planned": len(reads),
            "reads_attempted": sum(read.attempts > 0 for read in reads),
            "reads_completed": sum(read.status == "complete" for read in reads),
            **totals,
            "canonical_observation_bytes": observation_total,
            "findings": len(findings),
        }
    )
    body: dict[str, Any] = {
        "schema_version": "enterprise-retention-collection/v1",
        "provider": provider,
        "profile_alias": alias,
        "scope_label": request.root.scope_label,
        "status": status,
        "started_at": started_at,
        "finished_at": finished_at,
        "observation_scope": "configuration",
        "coverage_scope": "selected_resources",
        "identity_basis": "operator-declared",
        "authenticated_identity_verified": False,
        "object_enforcement_assessed": False,
        "recordset_completeness_assessed": False,
        "resources": resources,
        "source_reads": reads,
        "findings": findings,
        "diagnostics": list(checked),
        "field_coverage": _coverage(provider, reads),
        "manifest": manifest,
        "unassessed_surfaces": _UNASSESSED[provider],
    }
    if provider == "google-vault":
        body["retention_rules_assessed"] = False
    return body


def _validate_result(value: ResultBranch) -> None:
    request = EnterpriseRetentionCollectRequest.model_validate(
        {
            "provider": value.provider,
            "profile_alias": value.profile_alias,
            "scope_label": value.scope_label,
            "targets": [_target_data(item.target) for item in value.resources],
        }
    )
    expected = _assemble_result(
        request,
        reads=value.source_reads,
        run_id=value.manifest.run_id,
        started_at=value.started_at,
        finished_at=value.finished_at,
        diagnostics=value.diagnostics,
        collector_version=value.manifest.collector_version,
        evidentia_version=value.manifest.evidentia_version,
    )
    if result_json_bytes(_wire_object(value)) != result_json_bytes(_wire_object(expected)):
        raise ValueError("inconsistent_result")


class EnterpriseRetentionCollectResult(RootModel[Annotated[ResultBranch, Field(discriminator="provider")]]):
    model_config = ConfigDict(strict=True, revalidate_instances="always")

    @classmethod
    def __get_pydantic_json_schema__(cls, schema: CoreSchema, handler: GetJsonSchemaHandler) -> JsonSchemaValue:
        return handler(_declared_schema(schema)) if handler.mode == "serialization" else handler(schema)

    @model_validator(mode="after")
    def full_consistency(self) -> Self:
        _validate_result(self.root)
        return self

    @classmethod
    def model_validate(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        from_attributes: bool | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        if strict is False or extra not in (None, "forbid") or from_attributes is True:
            raise EnterpriseRetentionInputError("invalid_result")
        try:
            if type(obj) is cls:
                if obj.__pydantic_extra__:
                    raise ValueError("invalid_result")
                obj = obj.__dict__["root"]
            data = _wire_object(obj, native=True)
            return cls.model_validate_json(result_json_bytes(data), context=context, by_alias=by_alias, by_name=by_name)
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError, RuntimeError):
            raise EnterpriseRetentionInputError("invalid_result") from None

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        if strict is False or extra not in (None, "forbid"):
            raise EnterpriseRetentionInputError("invalid_result")
        try:
            if type(json_data) is bytes:
                data = json_data
            elif type(json_data) is bytearray:
                with memoryview(json_data) as view:
                    if view.nbytes > RESULT_BYTE_LIMIT:
                        raise ValueError("invalid_result")
                    data = bytes(view)
            elif type(json_data) is str:
                if len(json_data) > RESULT_BYTE_LIMIT:
                    raise ValueError("invalid_result")
                data = json_data.encode("utf-8")
            else:
                raise ValueError("invalid_result")
            parse_result_json(data)
            return super().model_validate_json(
                data, strict=True, extra="forbid", context=context, by_alias=by_alias, by_name=by_name
            )
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError, RuntimeError):
            raise EnterpriseRetentionInputError("invalid_result") from None

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        checked = type(self).model_validate(self)
        if update is None or (type(update) is dict and not update):
            return checked
        payload = _request_fields(update, frozenset({"root"}))
        return type(self).model_validate(payload["root"])

    @model_serializer(mode="wrap")
    def checked_serialization(self, handler: SerializerFunctionWrapHandler) -> Any:
        return handler(type(self).model_validate(self))

    def publication_bytes(self) -> bytes:
        checked = type(self).model_validate(self)
        return result_json_bytes(_wire_object(checked.root))


def make_result(
    request: EnterpriseRetentionCollectRequest,
    *,
    reads: list[EnterpriseRetentionReadResult],
    run_id: str,
    started_at: datetime,
    finished_at: datetime,
    diagnostics: list[EnterpriseRetentionDiagnostic],
    collector_version: str,
    evidentia_version: str,
) -> EnterpriseRetentionCollectResult:
    try:
        body = _assemble_result(
            request,
            reads=reads,
            run_id=run_id,
            started_at=started_at,
            finished_at=finished_at,
            diagnostics=diagnostics,
            collector_version=collector_version,
            evidentia_version=evidentia_version,
        )
        return EnterpriseRetentionCollectResult.model_validate(body)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError, RuntimeError):
        raise EnterpriseRetentionInputError("invalid_result") from None


_MANIFEST_COUNTERS = (
    "resources_requested",
    "resources_attempted",
    "reads_planned",
    "reads_attempted",
    "reads_completed",
    "attempts",
    "responses_received",
    "pages_received",
    "pages_admitted",
    "records_received",
    "records_admitted",
    "duplicates_coalesced",
    "conflicts_quarantined",
    "raw_bytes",
    "decoded_bytes",
    "canonical_observation_bytes",
    "findings",
)


class CapacityExceeded(ValueError):
    """Refuse new source admission while preserving the previously committed state."""

    def __init__(self, code: Literal["projection_limit", "result_limit"]) -> None:
        self.code = code
        super().__init__(code)


def _bound_diagnostics(
    scope: DiagnosticScope, provider: ProviderName, *, kind: ReadKind | None, read_id: str
) -> list[JsonValue]:
    return [
        {"code": code, "read_id": read_id, "safe_http_status": None}
        for code, rules in _DIAGNOSTIC_RULES.items()
        if any(rule[0] == scope and provider in rule[1] and (not rule[2] or kind in rule[2]) for rule in rules)
    ]


def _bounded_coverage(provider: ProviderName) -> JsonObject:
    return {
        f"{kind}/{rule.coverage_key}": {
            "absent": MAX_COUNTER,
            "null": MAX_COUNTER,
            "known": MAX_COUNTER,
            "unknown": MAX_COUNTER,
        }
        for kind in _METHODS
        if _METHODS[kind][0] == provider
        for rule in ROOT_RULES[kind]
    }


def _terminal_skeleton(request: EnterpriseRetentionCollectRequest) -> JsonObject:
    """Cover all finite metadata slots; the bounding object is not claimed evidence."""
    request = EnterpriseRetentionCollectRequest.model_validate(request)
    provider, alias = request.root.provider, request.root.profile_alias
    keys = initial_read_keys(request)
    future_policies: list[ReadKey] = []
    if provider == "elastic-ilm":
        future_policies = [
            ReadKey(kind="elastic-policy", source_id=f"p{index:02d}" + "x" * 252)
            for index in range(len(request.root.targets))
        ]
        keys.extend(future_policies)
    read_ids = [read_identifier(provider, alias, key) for key in keys]
    longest_id = max(read_ids, key=len)
    clock = "2000-01-01T00:00:00.000000Z"
    reads: list[JsonValue] = []
    for key, read_id in zip(keys, read_ids, strict=True):
        terminal_codes = [
            code
            for code, rules in _DIAGNOSTIC_RULES.items()
            if any(
                rule[4] and provider in rule[1] and (rule[0] == "run" or (rule[0] == "read" and key.kind in rule[2]))
                for rule in rules
            )
        ]
        read: JsonObject = {
            "read_id": read_id,
            "kind": key.kind,
            "source_id": key.source_id,
            "method_id": _METHODS[key.kind][2],
            "status": "unavailable",
            **{name: MAX_COUNTER for name in _READ_COUNTERS},
            "started_at": clock,
            "finished_at": clock,
            "safe_http_status": None,
            "terminal_reason": max(terminal_codes, key=len),
            "diagnostics": _bound_diagnostics("read", provider, kind=key.kind, read_id=read_id),
            "observations": [],
        }
        reads.append(read)
    resources: list[JsonValue] = []
    findings: list[JsonValue] = []
    bounded_targets: list[EnterpriseTarget] = []
    bounded_targets.extend(request.root.targets)
    for index, target in enumerate(bounded_targets):
        identity = target_identity(target)
        selected_id = read_identifier(provider, alias, ReadKey(kind=_SELECTED_KINDS[provider], source_id=identity))
        refs = [selected_id]
        if provider == "google-vault":
            refs.append(read_identifier(provider, alias, ReadKey(kind="vault-holds", source_id=identity)))
        elif provider == "elastic-ilm":
            refs.extend(
                [
                    read_identifier(provider, alias, future_policies[index]),
                    read_identifier(provider, alias, ReadKey(kind="elastic-status", source_id="service")),
                ]
            )
        resource_id = resource_identifier(provider, alias, identity)
        resource_diagnostics: list[JsonValue] = []
        if provider == "elastic-ilm":
            resource_diagnostics = [
                {"code": code, "read_id": longest_id, "safe_http_status": None}
                for code, rules in _DIAGNOSTIC_RULES.items()
                if any(rule[0] == "resource" and provider in rule[1] for rule in rules)
            ]
        resources.append(
            {
                "target": _target_data(target),
                "canonical_resource_id": resource_id,
                "status": "unavailable",
                "read_ids": list(refs),
                "policy_resolution": "not_applicable",
                "diagnostics": resource_diagnostics,
            }
        )
        title, description, resource_type = _FINDING_TEXT[provider]
        findings.append(
            {
                "id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "title": title,
                "description": description,
                "severity": "informational",
                "status": "active",
                "compliance_status": "unknown",
                "remediation": None,
                "source_system": "enterprise-retention",
                "source_finding_id": resource_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "resource_region": None,
                "resource_account": None,
                "control_mappings": [],
                "collection_context": {
                    "collector_id": "enterprise-retention",
                    "collector_version": "x" * 64,
                    "run_id": "7" + "Z" * 25,
                    "collected_at": clock,
                    "credential_identity": "operator-configured:identity-unverified",
                    "source_system_id": f"enterprise-retention/{provider}/{alias}",
                    "filter_applied": {
                        "provider": provider,
                        "profile_alias": alias,
                        "scope_label": request.root.scope_label,
                        "target": _target_data(target),
                        "observation_scope": "configuration",
                        "coverage_scope": "selected_resources",
                    },
                    "pagination_context": {
                        "page_size": None,
                        "page_number": None,
                        "total_pages": MAX_COUNTER,
                        "continuation_token": None,
                        "is_complete": False,
                    },
                    "evidentia_version": "x" * 64,
                },
                "raw_data": {
                    "target": _target_data(target),
                    "status": "unavailable",
                    "policy_resolution": "not_applicable",
                    "reads": [
                        {
                            "read_id": ref,
                            "status": "unavailable",
                            "observations": MAX_COUNTER,
                            "observation_digests_sha256": "f" * 64,
                        }
                        for ref in refs
                    ],
                    "field_coverage": _bounded_coverage(provider),
                },
                "first_observed": clock,
                "last_observed": clock,
                "resolved_at": None,
            }
        )
    manifest: JsonObject = {
        "schema_version": "enterprise-retention-manifest/v1",
        "run_id": "7" + "Z" * 25,
        "collector_version": "x" * 64,
        "evidentia_version": "x" * 64,
        "status": "unavailable",
        **{name: MAX_COUNTER for name in _MANIFEST_COUNTERS},
    }
    skeleton: JsonObject = {
        "schema_version": "enterprise-retention-collection/v1",
        "provider": provider,
        "profile_alias": alias,
        "scope_label": request.root.scope_label,
        "status": "unavailable",
        "started_at": clock,
        "finished_at": clock,
        "observation_scope": "configuration",
        "coverage_scope": "selected_resources",
        "identity_basis": "operator-declared",
        "authenticated_identity_verified": False,
        "object_enforcement_assessed": False,
        "recordset_completeness_assessed": False,
        "source_reads": reads,
        "resources": resources,
        "findings": findings,
        "diagnostics": _bound_diagnostics("run", provider, kind=None, read_id=longest_id),
        "field_coverage": _bounded_coverage(provider),
        "manifest": manifest,
        "unassessed_surfaces": list(_UNASSESSED[provider]),
    }
    if provider == "google-vault":
        skeleton["retention_rules_assessed"] = False
    _capacity_field_coverage(skeleton, provider)
    return skeleton


def _capacity_field_coverage(skeleton: JsonObject, provider: ProviderName) -> None:
    def exact(value: object, model: type[BaseModel]) -> None:
        if type(value) is not dict or set(value) != set(model.model_fields):
            raise ValueError("capacity_schema_changed")

    exact(skeleton, _RESULT_TYPES[provider])
    exact(skeleton["manifest"], EnterpriseRetentionManifest)
    for read in cast(list[JsonObject], skeleton["source_reads"]):
        exact(read, EnterpriseRetentionReadResult)
        for diagnostic in cast(list[JsonObject], read["diagnostics"]):
            exact(diagnostic, EnterpriseRetentionDiagnostic)
    target_types: dict[ProviderName, type[BaseModel]] = {
        "google-vault": VaultMatterTarget,
        "splunk-enterprise": SplunkIndexTarget,
        "elastic-ilm": ElasticIndexTarget,
    }
    target_type = target_types[provider]
    for resource in cast(list[JsonObject], skeleton["resources"]):
        exact(resource, _RESOURCE_TYPES[provider])
        exact(resource["target"], target_type)
    for finding in cast(list[JsonObject], skeleton["findings"]):
        exact(finding, _EnterpriseFinding)
        context = cast(JsonObject, finding["collection_context"])
        exact(context, _FindingContext)
        exact(context["filter_applied"], _SelectedFilter)
        exact(cast(JsonObject, context["filter_applied"])["target"], target_type)
        exact(context["pagination_context"], _FindingPagination)
        raw = cast(JsonObject, finding["raw_data"])
        exact(raw, _FindingData)
        exact(raw["target"], target_type)
        for read in cast(list[JsonObject], raw["reads"]):
            exact(read, _FindingRead)
        for count in cast(dict[str, JsonObject], raw["field_coverage"]).values():
            exact(count, CoverageCounts)
    if set(EnterpriseRetentionObservation.model_fields) != {
        "source_identity",
        "api_version",
        "projection_version",
        "native_scope",
        "fields",
        "field_coverage",
        "interpretation_status",
        "diagnostics",
        "canonical_projection_sha256",
    }:
        raise ValueError("capacity_schema_changed")


class CapacityPlan:
    """Reserve the bounded future metadata for one immutable selected request."""

    __slots__ = ("_limit", "_max_observations", "_metadata", "_request")
    _request: bytes
    _metadata: int
    _max_observations: int
    _limit: int

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("immutable_capacity_plan")

    def __init__(
        self, request: EnterpriseRetentionCollectRequest, *, _result_byte_limit: int = RESULT_BYTE_LIMIT
    ) -> None:
        request = EnterpriseRetentionCollectRequest.model_validate(request)
        if type(_result_byte_limit) is not int or not 0 < _result_byte_limit <= RESULT_BYTE_LIMIT:
            raise ValueError("invalid_capacity_limit")
        request_data: JsonObject = {
            "provider": request.root.provider,
            "profile_alias": request.root.profile_alias,
            "scope_label": request.root.scope_label,
            "targets": [_target_data(target) for target in request.root.targets],
        }
        object.__setattr__(self, "_request", canonical_json(request_data))
        object.__setattr__(self, "_metadata", len(result_json_bytes(_terminal_skeleton(request))))
        count = len(request.root.targets)
        object.__setattr__(
            self,
            "_max_observations",
            count + 2000
            if request.root.provider == "google-vault"
            else count
            if request.root.provider == "splunk-enterprise"
            else 2 * count + 1,
        )
        object.__setattr__(self, "_limit", _result_byte_limit)
        if self._metadata > self._limit:
            raise ValueError("terminal_metadata_limit")

    @property
    def metadata_bound_bytes(self) -> int:
        return self._metadata

    @property
    def maximum_result_bound_bytes(self) -> int:
        return self._metadata + RUN_PROJECTION_BYTE_LIMIT + self._max_observations

    def admission_bound(self, reads: list[EnterpriseRetentionReadResult]) -> int:
        if type(reads) is not list or len(reads) > 41:
            raise ValueError("invalid_capacity_state")
        checked = [EnterpriseRetentionReadResult.model_validate(read) for read in reads]
        try:
            _checked_read_plan(parse_request(self._request), checked)
        except (ValueError, KeyError):
            raise ValueError("invalid_capacity_state") from None
        count = sum(len(read.observations) for read in checked)
        size = sum(len(observation_bytes(item)) for read in checked for item in read.observations)
        if count > self._max_observations:
            raise ValueError("invalid_capacity_state")
        if size > RUN_PROJECTION_BYTE_LIMIT:
            raise CapacityExceeded("projection_limit")
        bound = self._metadata + size + count
        if bound > self._limit:
            raise CapacityExceeded("result_limit")
        return bound

    def validate_result(self, value: EnterpriseRetentionCollectResult) -> None:
        checked = EnterpriseRetentionCollectResult.model_validate(value)
        data: JsonObject = {
            "provider": checked.root.provider,
            "profile_alias": checked.root.profile_alias,
            "scope_label": checked.root.scope_label,
            "targets": [_target_data(resource.target) for resource in checked.root.resources],
        }
        if canonical_json(data) != self._request:
            raise ValueError("capacity_request_mismatch")
        bound = self.admission_bound(checked.root.source_reads)
        if len(checked.publication_bytes()) > bound:
            raise ValueError("capacity_bound_violated")
