"""Strict selected-query inputs and source-preserving registry evidence."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib.metadata import version
from types import UnionType
from typing import Annotated, Any, Literal, Self, Union, cast, get_args, get_origin

from evidentia_core.audit.provenance import CollectionContext, CollectionManifest, CoverageCount, new_run_id
from evidentia_core.models.common import (
    NON_BLANK_PATTERN,
    ControlMapping,
    Severity,
    current_version,
    deterministic_finding_id,
)
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
    OBSERVATION_BYTE_LIMIT,
    REQUEST_BYTE_LIMIT,
    RESULT_BYTE_LIMIT,
    canonical_json,
    checked_json,
    checked_result_json,
    parse_result_json,
    parse_strict_json,
    result_json_bytes,
)

type RegistryJsonValue = bool | int | float | str | list[RegistryJsonValue] | dict[str, RegistryJsonValue] | None

RegistryName = Literal[
    "tls",
    "rdap",
    "sam-entity",
    "sam-exclusions",
    "gleif",
    "fedramp",
    "cmvp",
    "fcc-covered-list",
    "incommon",
    "ssl-labs",
    "security-txt",
]
REGISTRIES: tuple[RegistryName, ...] = (
    "tls",
    "rdap",
    "sam-entity",
    "sam-exclusions",
    "gleif",
    "fedramp",
    "cmvp",
    "fcc-covered-list",
    "incommon",
    "ssl-labs",
    "security-txt",
)
_STRICT = ConfigDict(strict=True, extra="forbid", frozen=True, validate_default=True, revalidate_instances="always")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class RegistryInputError(ValueError):
    """Expose only a fixed input or invariant diagnostic."""

    def __init__(
        self, code: Literal["invalid_request", "invalid_result", "observation_limit"] = "invalid_request"
    ) -> None:
        if type(code) is not str or code not in {"invalid_request", "invalid_result", "observation_limit"}:
            code = "invalid_request"
        self.code: Literal["invalid_request", "invalid_result", "observation_limit"] = code
        super().__init__(code)


def _text(value: object, maximum: int, *, nonblank: bool = True) -> str:
    if type(value) is not str or len(value) > maximum:
        raise RegistryInputError()
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value):
        raise RegistryInputError()
    if len(value.encode("utf-8")) > maximum or (nonblank and not value.strip()):
        raise RegistryInputError()
    return value


def canonical_hostname(value: object) -> str:
    """Normalize DNS spelling without accepting URL or numeric-host syntax."""
    original = _text(value, 254)
    if not original.isascii():
        raise RegistryInputError()
    canonical = original.lower().removesuffix(".")
    if len(canonical) > 253 or not canonical:
        raise RegistryInputError()
    labels = canonical.split(".")
    if any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        raise RegistryInputError()
    if all(re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", label) is not None for label in labels):
        raise RegistryInputError()
    try:
        ipaddress.ip_address(canonical)
    except ValueError:
        return canonical
    raise RegistryInputError()


def normalized_organization_name(value: object) -> str:
    original = _text(value, 512)
    normalized = re.sub(" +", " ", unicodedata.normalize("NFC", original).casefold().strip(" "))
    return _text(normalized, 512)


def _declared_schema(schema: CoreSchema) -> CoreSchema:
    declared = dict(schema)
    declared.pop("serialization", None)
    child = declared.get("schema")
    if isinstance(child, dict):
        declared["schema"] = _declared_schema(cast(CoreSchema, child))
    return cast(CoreSchema, declared)


def _non_blank_schema(schema: JsonSchemaValue) -> None:
    """Publish non-blank admission while retaining narrower field patterns."""
    pattern = schema.get("pattern")
    if pattern is not None and pattern != NON_BLANK_PATTERN:
        schema["allOf"] = [*schema.get("allOf", []), {"type": "string", "pattern": pattern}]
    schema["pattern"] = NON_BLANK_PATTERN


class _WireModel(BaseModel):
    model_config = _STRICT

    @model_validator(mode="before")
    @classmethod
    def exact_request_leaves(cls, value: object) -> object:
        if any(cls is branch for branch in _BRANCHES.values()):
            return _request_data(value)
        if not any(cls is target for targets in _TARGETS.values() for target in targets):
            return value
        data = _model_fields(cast(BaseModel, value)) if type(value) is cls else value
        if type(data) is not dict or any(type(key) is not str or type(item) is not str for key, item in data.items()):
            raise RegistryInputError()
        if set(data) != set(cls.model_fields):
            raise RegistryInputError()
        return dict(data)

    @classmethod
    def __get_pydantic_json_schema__(cls, schema: CoreSchema, handler: GetJsonSchemaHandler) -> JsonSchemaValue:
        return handler(_declared_schema(schema)) if handler.mode == "serialization" else handler(schema)

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        if update is not None and type(update) is not dict:
            raise RegistryInputError()
        if update is not None and any(type(key) is not str for key in update):
            raise RegistryInputError()
        data = _model_fields(self)
        data.update(update or {})
        return type(self).model_validate(data)


class HostnameTarget(_WireModel):
    hostname: Annotated[str, Field(min_length=1, max_length=254, json_schema_extra=_non_blank_schema)]

    @field_validator("hostname")
    @classmethod
    def valid_host(cls, value: str) -> str:
        canonical_hostname(value)
        return value


class DomainTarget(_WireModel):
    domain: Annotated[str, Field(min_length=1, max_length=254, json_schema_extra=_non_blank_schema)]

    @field_validator("domain")
    @classmethod
    def valid_domain(cls, value: str) -> str:
        canonical_hostname(value)
        return value


class UEITarget(_WireModel):
    uei: Annotated[str, Field(min_length=12, max_length=12, pattern=r"^[A-Z0-9]{12}$")]

    @field_validator("uei")
    @classmethod
    def valid_uei(cls, value: str) -> str:
        if re.fullmatch(r"[A-Z0-9]{12}", value) is None:
            raise RegistryInputError()
        return value


class LEITarget(_WireModel):
    lei: Annotated[str, Field(min_length=20, max_length=20, pattern=r"^[A-Z0-9]{20}$")]

    @field_validator("lei")
    @classmethod
    def valid_lei(cls, value: str) -> str:
        if re.fullmatch(r"[A-Z0-9]{20}", value) is None:
            raise RegistryInputError()
        return value


class ProductTarget(_WireModel):
    product_id: Annotated[str, Field(min_length=1, max_length=128, json_schema_extra=_non_blank_schema)]

    @field_validator("product_id")
    @classmethod
    def valid_product(cls, value: str) -> str:
        return _text(value, 128)


class CertificateTarget(_WireModel):
    certificate_number: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[0-9]+$", json_schema_extra=_non_blank_schema)
    ]

    @field_validator("certificate_number")
    @classmethod
    def valid_number(cls, value: str) -> str:
        if re.fullmatch(r"[0-9]{1,128}", value) is None:
            raise RegistryInputError()
        return value


class EntityTarget(_WireModel):
    entity_id: Annotated[str, Field(min_length=1, max_length=2048, json_schema_extra=_non_blank_schema)]

    @field_validator("entity_id")
    @classmethod
    def valid_entity(cls, value: str) -> str:
        return _text(value, 2048)


class OrganizationTarget(_WireModel):
    organization_name: Annotated[str, Field(min_length=1, max_length=512, json_schema_extra=_non_blank_schema)]

    @field_validator("organization_name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        normalized_organization_name(value)
        return value


class SAMOrganizationTarget(OrganizationTarget):
    @field_validator("organization_name")
    @classmethod
    def supported_literal(cls, value: str) -> str:
        if re.fullmatch(r"[A-Za-z0-9 ',.\-]+", value) is None or re.search(r"[A-Za-z0-9]", value) is None:
            raise RegistryInputError()
        return value


class FCCOrganizationTarget(OrganizationTarget):
    query_scope: Literal["named_organization_entries"]


class EndpointTarget(HostnameTarget):
    endpoint_ip: Annotated[str, Field(min_length=1, max_length=45, json_schema_extra=_non_blank_schema)]

    @field_validator("endpoint_ip")
    @classmethod
    def valid_endpoint(cls, value: str) -> str:
        if "%" in value:
            raise RegistryInputError()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            raise RegistryInputError() from None
        if not address.is_global or address.is_multicast or address.is_unspecified:
            raise RegistryInputError()
        return value


class _Request(_WireModel):
    scope_label: Annotated[str, Field(min_length=1, max_length=128, json_schema_extra=_non_blank_schema)] | None = None

    @field_validator("scope_label")
    @classmethod
    def valid_scope(cls, value: str | None) -> str | None:
        return None if value is None else _text(value, 128)


class TLSRequest(_Request):
    registry: Literal["tls"]
    target: HostnameTarget


class RDAPRequest(_Request):
    registry: Literal["rdap"]
    target: DomainTarget


class SAMEntityRequest(_Request):
    registry: Literal["sam-entity"]
    target: UEITarget


class SAMExclusionsRequest(_Request):
    registry: Literal["sam-exclusions"]
    target: UEITarget | SAMOrganizationTarget


class GLEIFRequest(_Request):
    registry: Literal["gleif"]
    target: LEITarget


class FedRAMPRequest(_Request):
    registry: Literal["fedramp"]
    target: ProductTarget


class CMVPRequest(_Request):
    registry: Literal["cmvp"]
    target: CertificateTarget


class FCCRequest(_Request):
    registry: Literal["fcc-covered-list"]
    target: FCCOrganizationTarget


class InCommonRequest(_Request):
    registry: Literal["incommon"]
    target: EntityTarget


class SSLLabsRequest(_Request):
    registry: Literal["ssl-labs"]
    target: EndpointTarget


class SecurityTxtRequest(_Request):
    registry: Literal["security-txt"]
    target: HostnameTarget


RequestBranch = Annotated[
    TLSRequest
    | RDAPRequest
    | SAMEntityRequest
    | SAMExclusionsRequest
    | GLEIFRequest
    | FedRAMPRequest
    | CMVPRequest
    | FCCRequest
    | InCommonRequest
    | SSLLabsRequest
    | SecurityTxtRequest,
    Field(discriminator="registry"),
]
_BRANCHES: dict[str, type[_Request]] = dict(
    zip(
        REGISTRIES,
        (
            TLSRequest,
            RDAPRequest,
            SAMEntityRequest,
            SAMExclusionsRequest,
            GLEIFRequest,
            FedRAMPRequest,
            CMVPRequest,
            FCCRequest,
            InCommonRequest,
            SSLLabsRequest,
            SecurityTxtRequest,
        ),
        strict=True,
    )
)
_TARGETS: dict[str, tuple[type[_WireModel], ...]] = {
    "tls": (HostnameTarget,),
    "rdap": (DomainTarget,),
    "sam-entity": (UEITarget,),
    "sam-exclusions": (UEITarget, SAMOrganizationTarget),
    "gleif": (LEITarget,),
    "fedramp": (ProductTarget,),
    "cmvp": (CertificateTarget,),
    "fcc-covered-list": (FCCOrganizationTarget,),
    "incommon": (EntityTarget,),
    "ssl-labs": (EndpointTarget,),
    "security-txt": (HostnameTarget,),
}


def _model_fields(model: BaseModel) -> dict[str, Any]:
    extra = model.__pydantic_extra__
    data = model.__dict__
    if extra is not None and (type(extra) is not dict or extra):
        raise RegistryInputError()
    if type(data) is not dict or any(type(key) is not str for key in data):
        raise RegistryInputError()
    if set(data) != set(type(model).model_fields):
        raise RegistryInputError()
    return dict(data)


def _request_data(value: object) -> dict[str, Any]:
    try:
        if type(value) is RegistryLookupRequest:
            value = _model_fields(value)["root"]
        actual_branch: type[_Request] | None = None
        if any(type(value) is branch for branch in _BRANCHES.values()):
            actual_branch = cast(type[_Request], type(value))
            value = _model_fields(cast(BaseModel, value))
        if type(value) is not dict or any(type(key) is not str for key in value):
            raise RegistryInputError()
        if set(value) not in (
            {"registry", "target"},
            {"registry", "target", "scope_label"},
        ):
            raise RegistryInputError()
        data = dict(value)
        registry = data["registry"]
        if type(registry) is not str or registry not in _BRANCHES:
            raise RegistryInputError()
        if actual_branch is not None and actual_branch is not _BRANCHES[registry]:
            raise RegistryInputError()
        target = data["target"]
        if any(type(target) is target_type for target_type in _TARGETS[registry]):
            target = _model_fields(target)
        if type(target) is not dict or not target or len(target) > 2:
            raise RegistryInputError()
        copied: dict[str, str] = {}
        for key, item in target.items():
            if type(key) is not str or type(item) is not str or len(key) > 32 or len(item) > 2048:
                raise RegistryInputError()
            copied[key] = item
        if not any(set(copied) == set(target_type.model_fields) for target_type in _TARGETS[registry]):
            raise RegistryInputError()
        data["target"] = copied
        detached = checked_json(data)
        if type(detached) is not dict or len(canonical_json(detached)) > REQUEST_BYTE_LIMIT:
            raise RegistryInputError()
        return detached
    except (ValueError, TypeError, AttributeError, KeyError, RuntimeError, RecursionError):
        raise RegistryInputError() from None


class RegistryLookupRequest(RootModel[RequestBranch]):
    model_config = ConfigDict(strict=True, frozen=True, validate_default=True, revalidate_instances="always")

    @model_validator(mode="before")
    @classmethod
    def native_shape(cls, value: object, info: ValidationInfo) -> dict[str, Any]:
        if info.mode == "json":
            raise RegistryInputError()
        return _request_data(value)

    @classmethod
    def __get_pydantic_json_schema__(cls, schema: CoreSchema, handler: GetJsonSchemaHandler) -> JsonSchemaValue:
        return handler(_declared_schema(schema)) if handler.mode == "serialization" else handler(schema)

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
            raise RegistryInputError()
        try:
            return super().model_validate(
                _request_data(obj),
                strict=True,
                extra="forbid",
                from_attributes=False,
                context=context,
                by_alias=by_alias,
                by_name=by_name,
            )
        except (ValueError, TypeError, AttributeError):
            raise RegistryInputError() from None

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
            raise RegistryInputError()
        try:
            if (
                not any(type(json_data) is allowed for allowed in (str, bytes, bytearray))
                or len(json_data) > REQUEST_BYTE_LIMIT
            ):
                raise RegistryInputError()
            raw = json_data.encode("utf-8") if type(json_data) is str else bytes(cast(bytes | bytearray, json_data))
            return cls.model_validate(
                parse_strict_json(raw, max_bytes=REQUEST_BYTE_LIMIT),
                context=context,
                by_alias=by_alias,
                by_name=by_name,
            )
        except (ValueError, TypeError, UnicodeError):
            raise RegistryInputError() from None

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        checked = type(self).model_validate(self)
        if update is None or (type(update) is dict and not update):
            return checked
        if type(update) is not dict or any(type(key) is not str for key in update) or set(update) != {"root"}:
            raise RegistryInputError()
        return type(self).model_validate(update["root"])

    @model_serializer(mode="wrap")
    def checked_serialization(self, handler: SerializerFunctionWrapHandler) -> Any:
        return handler(type(self).model_validate(self))


def validated_request(value: object) -> RegistryLookupRequest:
    return RegistryLookupRequest.model_validate(value)


def parse_request(content: bytes) -> RegistryLookupRequest:
    if type(content) is not bytes:
        raise RegistryInputError()
    return RegistryLookupRequest.model_validate_json(content)


def request_identity(value: RegistryLookupRequest) -> str:
    target = validated_request(value).root.target
    if type(target) is EndpointTarget:
        return canonical_hostname(target.hostname) + "|" + str(ipaddress.ip_address(target.endpoint_ip))
    if type(target) is HostnameTarget:
        return canonical_hostname(target.hostname)
    if type(target) is DomainTarget:
        return canonical_hostname(target.domain)
    if isinstance(target, OrganizationTarget):
        return normalized_organization_name(target.organization_name)
    if type(target) is UEITarget:
        return target.uei
    if type(target) is LEITarget:
        return target.lei
    if type(target) is ProductTarget:
        return target.product_id
    if type(target) is CertificateTarget:
        return target.certificate_number
    if type(target) is EntityTarget:
        return target.entity_id
    raise RegistryInputError()


LookupOutcome = Literal["found", "not_found", "ambiguous", "unavailable"]
CollectionStatus = Literal["complete", "partial", "unavailable"]
Freshness = Literal["current_observation", "dated_snapshot", "stale", "unknown"]
MatchBasis = Literal["exact_identifier", "exact_normalized_name", "provider_candidate"]
CoverageState = Literal["present", "absent", "null", "unknown"]
DiagnosticCode = Literal[
    "offline_refused",
    "live_disabled",
    "missing_credential",
    "invalid_credential",
    "missing_extra",
    "dependency_failure",
    "destination_refused",
    "dns_failure",
    "tls_failure",
    "tls_certificate_verification_failed",
    "connection_failure",
    "timeout",
    "http_error",
    "redirect_refused",
    "retry_exhausted",
    "body_limit",
    "run_byte_limit",
    "invalid_response",
    "identity_mismatch",
    "source_terminal_unproven",
    "source_match_scope_limited",
    "traversal_incomplete",
    "page_limit",
    "record_limit",
    "attempt_limit",
    "read_limit",
    "diagnostic_limit",
    "observation_limit",
    "result_limit",
    "deadline_exceeded",
    "duplicate_conflict",
    "repeated_page",
    "total_changed",
    "projection_mismatch",
    "snapshot_missing",
    "snapshot_invalid",
    "signature_missing",
    "signature_invalid",
    "signature_unsupported",
    "signature_expired",
    "source_time_unsupported",
    "source_value_unknown",
    "source_name_conflict",
    "source_name_comparison_unsupported",
    "expired_source",
    "expiry_beyond_one_year",
    "syntax_invalid",
    "signature_unverified",
    "cache_miss",
    "category_applicability_not_assessed",
    "indirect_affiliate_applicability_not_assessed",
    "conditional_approval_applicability_not_assessed",
    "cleanup_failure",
]
_ADVISORY_CODES = frozenset(
    {
        "category_applicability_not_assessed",
        "indirect_affiliate_applicability_not_assessed",
        "conditional_approval_applicability_not_assessed",
        "source_time_unsupported",
        "source_value_unknown",
        "source_name_conflict",
        "source_name_comparison_unsupported",
        "expired_source",
        "expiry_beyond_one_year",
        "syntax_invalid",
        "signature_unverified",
    }
)
_COUNTER = Annotated[int, Field(strict=True, ge=0, le=50_000)]
_DIGEST = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)]
_RUN = Annotated[str, Field(pattern=r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$", min_length=26, max_length=26)]
_VERSION_TEXT = Annotated[
    str, Field(pattern=r"^[0-9A-Za-z.+-]{1,32}$", min_length=1, max_length=32, json_schema_extra=_non_blank_schema)
]


class _FrozenDict(dict[str, Any]):
    """Block ordinary mutation while keeping the core dictionary wire shape."""

    def _refuse(self, *args: Any, **kwargs: Any) -> Any:
        raise TypeError("immutable_registry_evidence")

    __setitem__ = _refuse
    __delitem__ = _refuse
    clear = _refuse
    pop = _refuse
    popitem = _refuse
    setdefault = _refuse
    update = _refuse
    __ior__ = _refuse


class _FrozenList(list[Any]):
    def _refuse(self, *args: Any, **kwargs: Any) -> Any:
        raise TypeError("immutable_registry_evidence")

    __setitem__ = _refuse
    __delitem__ = _refuse
    append = _refuse
    clear = _refuse
    extend = _refuse
    insert = _refuse
    pop = _refuse
    remove = _refuse
    reverse = _refuse
    sort = _refuse
    __iadd__ = _refuse
    __imul__ = _refuse


def _freeze(value: Any) -> Any:
    if type(value) is dict:
        return _FrozenDict({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return _FrozenList(_freeze(item) for item in value)
    return value


def clock_text(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise RegistryInputError("invalid_result")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _clock(value: object) -> datetime:
    if type(value) is datetime:
        clock_text(value)
        return value
    if (
        type(value) is not str
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z", value) is None
    ):
        raise RegistryInputError("invalid_result")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise RegistryInputError("invalid_result") from None
    if clock_text(parsed) != value:
        raise RegistryInputError("invalid_result")
    return parsed


UtcClock = Annotated[datetime, BeforeValidator(_clock), PlainSerializer(clock_text, return_type=str)]


class _PublicationTree:
    """Reject custom containers and bound native data before JSON allocation."""

    def __init__(self) -> None:
        self.nodes = 0
        self.size = 0

    def charge(self, amount: int) -> None:
        self.size += amount
        if self.size > RESULT_BYTE_LIMIT:
            raise RegistryInputError("invalid_result")

    def convert(self, value: object, depth: int = 0, *, source: bool = False) -> JsonValue:
        self.nodes += 1
        if self.nodes > 2_097_152 or depth > 20:
            raise RegistryInputError("invalid_result")
        kind = type(value)
        if not source and kind is RegistryLookupRequest:
            value = _request_data(value)
            kind = dict
        elif not source and any(kind is allowed for allowed in _RESULT_TYPES):
            value = _model_fields(cast(BaseModel, value))
            kind = dict
        elif not source and kind is datetime:
            value = clock_text(cast(datetime, value))
            kind = str
        elif not source and any(kind is allowed for allowed in (Severity, FindingStatus, ComplianceStatus)):
            value = cast(Severity | FindingStatus | ComplianceStatus, value).value
            kind = str
        if value is None:
            self.charge(4)
            return None
        if any(kind is allowed for allowed in (bool, int, float)):
            scalar = checked_json(value)
            self.charge(len(canonical_json(scalar)))
            return scalar
        if kind is str:
            literal = cast(str, value)
            if len(literal) > 1_048_576:
                raise RegistryInputError("invalid_result")
            encoded = json.dumps(literal, ensure_ascii=False).encode("utf-8")
            self.charge(len(encoded))
            return literal
        if any(kind is allowed for allowed in (list, _FrozenList, tuple)) and (kind is not tuple or not source):
            items = cast(list[object] | tuple[object, ...], value)
            self.charge(2 + max(len(items) - 1, 0))
            return [self.convert(item, depth + 1, source=source) for item in items]
        if kind is dict or kind is _FrozenDict:
            mapping = cast(dict[object, object], value)
            self.charge(2 + max(len(mapping) - 1, 0))
            output: dict[str, JsonValue] = {}
            for key, item in dict.items(mapping):
                if type(key) is not str:
                    raise RegistryInputError("invalid_result")
                self.convert(key, depth + 1, source=True)
                self.charge(1)
                output[key] = self.convert(
                    item, depth + 1, source=source or key in {"fields", "source_identity", "literal"}
                )
            return output
        raise RegistryInputError("invalid_result")


def _wire_object(value: object) -> dict[str, JsonValue]:
    try:
        return checked_result_json(_PublicationTree().convert(value))
    except (ValueError, TypeError, AttributeError, UnicodeError, RecursionError, RuntimeError):
        raise RegistryInputError("invalid_result") from None


def _strict_model_types(model: type[BaseModel], value: object) -> None:
    if model is RegistryLookupRequest:
        _request_data(value)
        return
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise RegistryInputError("invalid_result")
    if not set(value).issubset(model.model_fields):
        raise RegistryInputError("invalid_result")
    for name, item in value.items():
        if not _native_field_type(item, model.model_fields[name].annotation):
            raise RegistryInputError("invalid_result")


def _native_field_type(value: object, annotation: Any) -> bool:
    """Enforce exact scalar types before a caller can request lax validation."""
    if annotation is Any or annotation is JsonValue or annotation is RegistryJsonValue:
        return True
    if annotation is type(None):
        return value is None
    if annotation is datetime:
        try:
            _clock(value)
            return True
        except ValueError:
            return False
    if any(annotation is scalar for scalar in (str, int, float, bool)):
        return type(value) is annotation
    origin = get_origin(annotation)
    arguments = get_args(annotation)
    if origin is Annotated:
        return _native_field_type(value, arguments[0])
    if origin is Literal:
        for candidate in arguments:
            if any(type(candidate) is kind for kind in (Severity, FindingStatus, ComplianceStatus)):
                candidate = candidate.value
            if type(value) is type(candidate) and value == candidate:
                return True
        return False
    if origin is Union or origin is UnionType:
        return any(_native_field_type(value, candidate) for candidate in arguments)
    if origin is list:
        return type(value) is list and all(_native_field_type(item, arguments[0]) for item in value)
    if origin is dict:
        return type(value) is dict and all(
            _native_field_type(key, arguments[0]) and _native_field_type(item, arguments[1])
            for key, item in value.items()
        )
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        try:
            _strict_model_types(annotation, value)
            return True
        except ValueError:
            return False
    return False


class _ResultWire(_WireModel):
    @model_validator(mode="before")
    @classmethod
    def detached_shape(cls, value: object, info: ValidationInfo) -> dict[str, JsonValue]:
        if info.mode == "json":
            raise RegistryInputError("invalid_result")
        data = _wire_object(value)
        _strict_model_types(cls, data)
        return data

    @model_validator(mode="after")
    def freeze_containers(self) -> Self:
        for key, value in self.__dict__.items():
            object.__setattr__(self, key, _freeze(value))
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
            raise RegistryInputError("invalid_result")
        try:
            return super().model_validate(
                parse_result_json(result_json_bytes(_wire_object(obj))),
                strict=True,
                extra="forbid",
                context=context,
                by_alias=by_alias,
                by_name=by_name,
            )
        except (ValueError, TypeError, AttributeError):
            raise RegistryInputError("invalid_result") from None

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
            raise RegistryInputError("invalid_result")
        try:
            if (
                not any(type(json_data) is allowed for allowed in (str, bytes, bytearray))
                or len(json_data) > RESULT_BYTE_LIMIT
            ):
                raise RegistryInputError("invalid_result")
            raw = json_data.encode("utf-8") if type(json_data) is str else bytes(cast(bytes | bytearray, json_data))
            return cls.model_validate(parse_result_json(raw), context=context, by_alias=by_alias, by_name=by_name)
        except (ValueError, TypeError, UnicodeError):
            raise RegistryInputError("invalid_result") from None

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        data = _wire_object(type(self).model_validate(self))
        if update is not None:
            if type(update) is not dict or any(type(key) is not str for key in update):
                raise RegistryInputError("invalid_result")
            data.update(update)
        return type(self).model_validate(data)

    @model_serializer(mode="plain")
    def checked_serialization(self) -> dict[str, JsonValue]:
        return _wire_object(type(self).model_validate(self))


class RegistryDiagnostic(_ResultWire):
    code: DiagnosticCode
    source_read_id: Annotated[str, Field(pattern=r"^read-[0-9a-f]{64}$", min_length=69, max_length=69)] | None = None
    effect: Literal["advisory", "gap"]

    @model_validator(mode="after")
    def fixed_effect(self) -> Self:
        if self.effect != ("advisory" if self.code in _ADVISORY_CODES else "gap"):
            raise RegistryInputError("invalid_result")
        return self


def diagnostic(code: DiagnosticCode, read_id: str | None = None) -> RegistryDiagnostic:
    if type(code) is not str or code not in get_args(DiagnosticCode):
        raise RegistryInputError("invalid_result")
    return RegistryDiagnostic.model_validate(
        {
            "code": code,
            "source_read_id": read_id,
            "effect": "advisory" if code in _ADVISORY_CODES else "gap",
        }
    )


def normalized_source_time(
    value: object, representation: Literal["rfc3339", "unix_milliseconds", "source_text"] = "rfc3339"
) -> str | None:
    """Compare only exactly representable instants; retain every source literal."""
    if representation == "source_text":
        return None
    if representation == "unix_milliseconds":
        if type(value) is not int or abs(value) > 253_402_300_799_999:
            return None
        try:
            return clock_text(datetime(1970, 1, 1, tzinfo=UTC) + timedelta(milliseconds=value))
        except (OverflowError, ValueError):
            return None
    if type(value) is not str or len(value) > 512:
        return None
    match = re.fullmatch(
        r"([0-9]{4}-[0-9]{2}-[0-9]{2})[Tt]([0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?([Zz]|[+-][0-9]{2}:[0-9]{2})",
        value,
    )
    if match is None or match[4] == "-00:00":
        return None
    fraction = match[3] or ""
    if len(fraction) > 6 and any(char != "0" for char in fraction[6:]):
        return None
    zone = "+00:00" if match[4] in {"Z", "z"} else match[4]
    if zone[4:] > "59" or zone[1:3] > "23":
        return None
    try:
        instant = datetime.fromisoformat(match[1] + "T" + match[2] + "." + fraction[:6].ljust(6, "0") + zone)
        return clock_text(instant.astimezone(UTC))
    except (ValueError, OverflowError):
        return None


class SourceTime(_ResultWire):
    path: Annotated[str, Field(min_length=1, max_length=128, json_schema_extra=_non_blank_schema)]
    literal: str | int | float | None
    representation: Literal["rfc3339", "unix_milliseconds", "source_text"]
    normalized_utc: str | None

    @model_validator(mode="after")
    def exact_comparison(self) -> Self:
        if self.normalized_utc != normalized_source_time(self.literal, self.representation):
            raise RegistryInputError("invalid_result")
        return self


class ObservationTrust(_ResultWire):
    transport_verified: bool | None
    source_signature: Literal["verified", "unverified", "not_applicable"]


_INTERPRETATIONS: dict[RegistryName, str] = {
    "tls": "One verified TLS negotiation; other protocols and revocation are unassessed.",
    "rdap": "Selected domain registration evidence; resource ownership is unassessed.",
    "sam-entity": "Public registered-entity evidence; terminal coverage and eligibility are unassessed.",
    "sam-exclusions": "Selected active-firm exclusion evidence; eligibility is unassessed.",
    "gleif": "Selected LEI entity and registration evidence; compliance is unassessed.",
    "fedramp": "Dated selected product evidence; procurement and deployment are unassessed.",
    "cmvp": "Dated selected certificate evidence; deployment and configuration applicability are unassessed.",
    "fcc-covered-list": (
        "Dated named-entry evidence; category, indirect-affiliate and deployment applicability are unassessed."
    ),
    "incommon": "Signature-verified selected entity metadata; membership assessment is not performed.",
    "ssl-labs": "Selected cached Endpoint fields; live access is disabled and no assessment is initiated.",
    "security-txt": "Selected security.txt fields and syntax observations; permission to test is not established.",
}
_TITLES: dict[RegistryName, str] = {
    "tls": "TLS connection evidence",
    "rdap": "RDAP domain evidence",
    "sam-entity": "SAM entity registration evidence",
    "sam-exclusions": "SAM exclusion evidence",
    "gleif": "GLEIF entity evidence",
    "fedramp": "FedRAMP product snapshot evidence",
    "cmvp": "CMVP certificate snapshot evidence",
    "fcc-covered-list": "FCC named-entry snapshot evidence",
    "incommon": "InCommon entity metadata evidence",
    "ssl-labs": "SSL Labs cached endpoint evidence",
    "security-txt": "Security.txt publication evidence",
}


def observation_id(registry: RegistryName, source_identity: object, fields: object) -> str:
    return (
        "observation-"
        + hashlib.sha256(
            canonical_json(
                checked_json(
                    {
                        "registry": registry,
                        "source_identity": source_identity,
                        "fields": fields,
                    }
                )
            )
        ).hexdigest()
    )


class RegistryObservation(_ResultWire):
    registry: RegistryName
    observation_id: Annotated[str, Field(pattern=r"^observation-[0-9a-f]{64}$", min_length=76, max_length=76)]
    source_read_id: Annotated[str, Field(pattern=r"^read-[0-9a-f]{64}$", min_length=69, max_length=69)]
    source_identity: dict[str, RegistryJsonValue]
    matched_identity: Annotated[str, Field(min_length=1, max_length=2048, json_schema_extra=_non_blank_schema)]
    match_basis: MatchBasis
    fields: dict[str, RegistryJsonValue]
    field_coverage: Annotated[dict[str, CoverageState], Field(max_length=128)]
    source_times: Annotated[list[SourceTime], Field(max_length=64)]
    trust: ObservationTrust
    interpretation: Annotated[str, Field(max_length=256)]

    @model_validator(mode="after")
    def observation_invariants(self) -> Self:
        data = _wire_object(self)
        if len(canonical_json(checked_json(data))) > OBSERVATION_BYTE_LIMIT:
            raise RegistryInputError("observation_limit")
        if self.observation_id != observation_id(self.registry, data["source_identity"], data["fields"]):
            raise RegistryInputError("invalid_result")
        if self.interpretation != _INTERPRETATIONS[self.registry]:
            raise RegistryInputError("invalid_result")
        if self.registry == "incommon" and self.trust.source_signature != "verified":
            raise RegistryInputError("invalid_result")
        if self.registry != "incommon" and self.trust.source_signature == "verified":
            raise RegistryInputError("invalid_result")
        _text(self.matched_identity, 2048)
        if not self.source_identity:
            raise RegistryInputError("invalid_result")
        return self


def make_observation(
    registry: RegistryName,
    read_id: str,
    *,
    source_identity: dict[str, JsonValue],
    matched_identity: str,
    fields: dict[str, JsonValue],
    field_coverage: dict[str, CoverageState],
    match_basis: MatchBasis = "exact_identifier",
    source_times: list[SourceTime] | None = None,
    transport_verified: bool | None = True,
    source_signature: Literal["verified", "unverified", "not_applicable"] = "not_applicable",
) -> RegistryObservation:
    return RegistryObservation.model_validate(
        {
            "registry": registry,
            "observation_id": observation_id(registry, source_identity, fields),
            "source_read_id": read_id,
            "source_identity": source_identity,
            "matched_identity": matched_identity,
            "match_basis": match_basis,
            "fields": fields,
            "field_coverage": field_coverage,
            "source_times": [] if source_times is None else source_times,
            "trust": {"transport_verified": transport_verified, "source_signature": source_signature},
            "interpretation": _INTERPRETATIONS[registry],
        }
    )


_TEMPLATES: dict[RegistryName, str] = {
    "tls": "tls_leaf_443",
    "rdap": "rdap_selected_domain",
    "sam-entity": "sam_entity_v4",
    "sam-exclusions": "sam_exclusions_v4",
    "gleif": "gleif_lei_record_v1",
    "fedramp": "fedramp_snapshot",
    "cmvp": "cmvp_snapshot",
    "fcc-covered-list": "fcc_named_snapshot",
    "incommon": "incommon_mdq_entity",
    "ssl-labs": "ssl_labs_endpoint_live_disabled",
    "security-txt": "security_txt_well_known",
}
_SNAPSHOTS = frozenset({"fedramp", "cmvp", "fcc-covered-list"})


def read_identifier(request: RegistryLookupRequest, ordinal: int = 0) -> str:
    if type(ordinal) is not int or not 0 <= ordinal < 24:
        raise RegistryInputError("invalid_result")
    body = {"request": _request_data(request), "ordinal": ordinal}
    return "read-" + hashlib.sha256(canonical_json(checked_json(body))).hexdigest()


class SourceRead(_ResultWire):
    read_id: Annotated[str, Field(pattern=r"^read-[0-9a-f]{64}$", min_length=69, max_length=69)]
    registry: RegistryName
    ordinal: Annotated[int, Field(ge=0, lt=24)]
    method: Literal["GET", "TLS", "LOCAL", "DISABLED"]
    template: Annotated[str, Field(min_length=1, max_length=64, json_schema_extra=_non_blank_schema)]
    query_scope: RegistryLookupRequest
    transport_kind: Literal["https", "tls", "snapshot", "none"]
    status: CollectionStatus
    freshness: Freshness
    http_status: Annotated[int, Field(ge=100, le=599)] | None
    network_attempts: Annotated[int, Field(ge=0, le=64)]
    attempted_pages: Annotated[int, Field(ge=0, le=64)]
    accepted_pages: Annotated[int, Field(ge=0, le=20)]
    source_records: _COUNTER
    admitted_records: Annotated[int, Field(ge=0, le=100)]
    raw_bytes: Annotated[int, Field(ge=0, le=16_777_216)] | None
    decoded_bytes: Annotated[int, Field(ge=0, le=16_777_216)] | None
    body_complete: bool
    source_digest: _DIGEST | None
    retrieved_at: UtcClock
    publisher_date: Annotated[str, Field(max_length=512)] | None
    publisher_version: Annotated[str, Field(max_length=128)] | None
    snapshot_source: Annotated[str, Field(max_length=128)] | None
    cache_state: Literal["not_applicable", "cache_only", "unknown"]
    transport_verified: bool | None
    source_signature: Literal["verified", "unverified", "not_applicable"]

    @model_validator(mode="after")
    def read_invariants(self) -> Self:
        expected_kind = (
            "snapshot"
            if self.registry in _SNAPSHOTS
            else "tls"
            if self.registry == "tls"
            else "none"
            if self.registry == "ssl-labs"
            else "https"
        )
        expected_method = {"snapshot": "LOCAL", "tls": "TLS", "none": "DISABLED", "https": "GET"}[expected_kind]
        if (self.template, self.method, self.transport_kind) != (
            _TEMPLATES[self.registry],
            expected_method,
            expected_kind,
        ):
            raise RegistryInputError("invalid_result")
        if self.query_scope.root.registry != self.registry or self.read_id != read_identifier(
            self.query_scope, self.ordinal
        ):
            raise RegistryInputError("invalid_result")
        if self.accepted_pages > self.attempted_pages or self.admitted_records > self.source_records:
            raise RegistryInputError("invalid_result")
        if self.source_digest is not None and not self.body_complete:
            raise RegistryInputError("invalid_result")
        if self.transport_kind in {"tls", "none"} and (
            self.raw_bytes is not None or self.decoded_bytes is not None or self.http_status is not None
        ):
            raise RegistryInputError("invalid_result")
        if self.transport_kind in {"https", "snapshot"} and (self.raw_bytes is None or self.decoded_bytes is None):
            raise RegistryInputError("invalid_result")
        if self.transport_kind in {"snapshot", "none"} and (
            self.network_attempts or self.transport_verified is not None
        ):
            raise RegistryInputError("invalid_result")
        if self.registry == "ssl-labs" and (
            self.status != "unavailable" or self.admitted_records or self.accepted_pages
        ):
            raise RegistryInputError("invalid_result")
        if self.registry == "sam-entity" and self.status == "complete":
            raise RegistryInputError("invalid_result")
        if self.status == "unavailable" and self.admitted_records:
            raise RegistryInputError("invalid_result")
        if self.registry in _SNAPSHOTS and self.freshness not in {"dated_snapshot", "stale", "unknown"}:
            raise RegistryInputError("invalid_result")
        if self.registry == "incommon" and self.admitted_records and self.source_signature != "verified":
            raise RegistryInputError("invalid_result")
        return self


class RegistryContext(_ResultWire, CollectionContext):
    collector_id: Literal["public-registry"]
    collector_version: _VERSION_TEXT
    run_id: _RUN
    collected_at: UtcClock
    credential_identity: Literal["not-established"]
    source_system_id: Annotated[str, Field(min_length=1, max_length=64, json_schema_extra=_non_blank_schema)]
    filter_applied: dict[str, Any]
    pagination_context: None
    evidentia_version: _VERSION_TEXT


class RegistryCoverage(_ResultWire, CoverageCount):
    resource_type: Literal["selected_registry_query"]
    scanned: _COUNTER
    matched_filter: Annotated[int, Field(ge=0, le=100)]
    collected: Annotated[int, Field(ge=0, le=100)]


class RegistryManifest(_ResultWire, CollectionManifest):
    run_id: _RUN
    collector_id: Literal["public-registry"]
    collector_version: _VERSION_TEXT
    collection_started_at: UtcClock
    collection_finished_at: UtcClock
    source_system_ids: Annotated[list[str], Field(max_length=1)]
    filters_applied: dict[str, Any]
    coverage_counts: Annotated[list[CoverageCount], Field(min_length=1, max_length=1)]
    total_findings: Annotated[int, Field(ge=0, le=100)]
    is_complete: bool
    incomplete_reason: Literal["selected_query_incomplete"] | None
    empty_categories: Annotated[list[str], Field(max_length=1)]
    warnings: Annotated[list[str], Field(max_length=64)]
    errors: Annotated[list[str], Field(max_length=64)]
    evidentia_version: _VERSION_TEXT

    @field_validator("coverage_counts", mode="before")
    @classmethod
    def strict_coverage(cls, value: object) -> list[CoverageCount]:
        if type(value) is not list or len(value) != 1:
            raise RegistryInputError("invalid_result")
        return [RegistryCoverage.model_validate(value[0])]


class _FindingData(_ResultWire):
    observation: RegistryObservation


class RegistryFinding(_ResultWire, SecurityFinding):
    id: Annotated[str, Field(min_length=36, max_length=36)]
    title: Annotated[str, Field(min_length=1, max_length=128, json_schema_extra=_non_blank_schema)]
    description: Annotated[str, Field(min_length=1, max_length=256, json_schema_extra=_non_blank_schema)]
    severity: Literal[Severity.INFORMATIONAL]
    status: Literal[FindingStatus.ACTIVE]
    compliance_status: Literal[ComplianceStatus.UNKNOWN]
    remediation: None
    source_system: Literal["public-registry"]
    source_finding_id: Annotated[str, Field(min_length=76, max_length=76)]
    resource_type: Literal["selected_registry_query"]
    resource_id: Annotated[str, Field(min_length=1, max_length=2048, json_schema_extra=_non_blank_schema)]
    resource_region: None
    resource_account: None
    control_mappings: Annotated[list[ControlMapping], Field(max_length=0)]
    collection_context: RegistryContext
    raw_data: _FindingData
    first_observed: UtcClock
    last_observed: UtcClock
    resolved_at: None


class RegistryLookupResult(_ResultWire):
    schema_version: Literal["1"]
    registry: RegistryName
    request: RegistryLookupRequest
    run_id: _RUN
    observation_scope: Literal["selected_registry_query"]
    lookup_outcome: LookupOutcome
    collection_status: CollectionStatus
    freshness: Freshness
    observations: Annotated[list[RegistryObservation], Field(max_length=100)]
    source_reads: Annotated[list[SourceRead], Field(max_length=24)]
    findings: Annotated[list[RegistryFinding], Field(max_length=100)]
    diagnostics: Annotated[list[RegistryDiagnostic], Field(max_length=64)]
    manifest: RegistryManifest

    @model_validator(mode="after")
    def derived_views(self) -> Self:
        _validate_result(self)
        return self


_RESULT_TYPES: tuple[type[BaseModel], ...] = (
    RegistryDiagnostic,
    SourceTime,
    ObservationTrust,
    RegistryObservation,
    SourceRead,
    RegistryContext,
    RegistryCoverage,
    RegistryManifest,
    _FindingData,
    RegistryFinding,
    RegistryLookupResult,
)


def _filters(request: RegistryLookupRequest) -> dict[str, Any]:
    return {"request": _request_data(request), "observation_scope": "selected_registry_query"}


def _finding_body(
    observation: RegistryObservation,
    retrieved_at: datetime,
    request: RegistryLookupRequest,
    run_id: str,
    collector_version: str,
    core_version: str,
) -> dict[str, Any]:
    clock = clock_text(retrieved_at)
    return {
        "id": deterministic_finding_id("public-registry", observation.observation_id),
        "title": _TITLES[observation.registry],
        "description": _INTERPRETATIONS[observation.registry],
        "severity": "informational",
        "status": "active",
        "compliance_status": "unknown",
        "remediation": None,
        "source_system": "public-registry",
        "source_finding_id": observation.observation_id,
        "resource_type": "selected_registry_query",
        "resource_id": observation.matched_identity,
        "resource_region": None,
        "resource_account": None,
        "control_mappings": [],
        "collection_context": {
            "collector_id": "public-registry",
            "collector_version": collector_version,
            "run_id": run_id,
            "collected_at": clock,
            "credential_identity": "not-established",
            "source_system_id": "registry:" + observation.registry,
            "filter_applied": _filters(request),
            "pagination_context": None,
            "evidentia_version": core_version,
        },
        "raw_data": {"observation": _wire_object(observation)},
        "first_observed": clock,
        "last_observed": clock,
        "resolved_at": None,
    }


def _assemble_result(
    request: RegistryLookupRequest,
    run_id: str,
    started_at: datetime,
    finished_at: datetime,
    reads: list[SourceRead],
    observations: list[RegistryObservation],
    diagnostics: list[RegistryDiagnostic],
    collector_version: str,
    core_version: str,
) -> dict[str, Any]:
    gap = (
        not reads
        or any(read.status != "complete" for read in reads)
        or any(item.effect == "gap" for item in diagnostics)
    )
    complete = not gap
    outcome: LookupOutcome = (
        "ambiguous"
        if len({item.matched_identity for item in observations}) > 1
        else "found"
        if observations
        else "not_found"
        if complete
        else "unavailable"
    )
    status: CollectionStatus = "complete" if complete else "partial" if observations else "unavailable"
    fresh: Freshness = (
        "stale"
        if any(read.freshness == "stale" for read in reads)
        else "unknown"
        if not reads or any(read.freshness == "unknown" for read in reads)
        else "dated_snapshot"
        if any(read.freshness == "dated_snapshot" for read in reads)
        else "current_observation"
    )
    by_id = {read.read_id: read for read in reads}
    findings = [
        _finding_body(item, by_id[item.source_read_id].retrieved_at, request, run_id, collector_version, core_version)
        for item in observations
    ]
    return {
        "schema_version": "1",
        "registry": request.root.registry,
        "request": _request_data(request),
        "run_id": run_id,
        "observation_scope": "selected_registry_query",
        "lookup_outcome": outcome,
        "collection_status": status,
        "freshness": fresh,
        "observations": [_wire_object(item) for item in observations],
        "source_reads": [_wire_object(read) for read in reads],
        "findings": findings,
        "diagnostics": [_wire_object(item) for item in diagnostics],
        "manifest": {
            "run_id": run_id,
            "collector_id": "public-registry",
            "collector_version": collector_version,
            "collection_started_at": clock_text(started_at),
            "collection_finished_at": clock_text(finished_at),
            "source_system_ids": ["registry:" + request.root.registry] if reads else [],
            "filters_applied": _filters(request),
            "coverage_counts": [
                {
                    "resource_type": "selected_registry_query",
                    "scanned": sum(read.source_records for read in reads),
                    "matched_filter": len(observations),
                    "collected": len(findings),
                }
            ],
            "total_findings": len(findings),
            "is_complete": complete,
            "incomplete_reason": None if complete else "selected_query_incomplete",
            "empty_categories": ["selected_registry_query"] if outcome == "not_found" else [],
            "warnings": [item.code for item in diagnostics if item.effect == "advisory"],
            "errors": [item.code for item in diagnostics if item.effect == "gap"],
            "evidentia_version": core_version,
        },
    }


def _validate_result(value: RegistryLookupResult) -> None:
    if value.registry != value.request.root.registry:
        raise RegistryInputError("invalid_result")
    if value.manifest.collection_finished_at < value.manifest.collection_started_at:
        raise RegistryInputError("invalid_result")
    by_id = {read.read_id: read for read in value.source_reads}
    if len(by_id) != len(value.source_reads) or len({item.observation_id for item in value.observations}) != len(
        value.observations
    ):
        raise RegistryInputError("invalid_result")
    if [read.ordinal for read in value.source_reads] != list(range(len(value.source_reads))):
        raise RegistryInputError("invalid_result")
    if (
        sum(read.network_attempts for read in value.source_reads) > 64
        or sum(read.accepted_pages for read in value.source_reads) > 20
    ):
        raise RegistryInputError("invalid_result")
    if sum(read.admitted_records for read in value.source_reads) > 100:
        raise RegistryInputError("invalid_result")
    for field in ("raw_bytes", "decoded_bytes"):
        if sum(getattr(read, field) or 0 for read in value.source_reads if read.transport_kind == "https") > 8_388_608:
            raise RegistryInputError("invalid_result")
    if sum(len(canonical_json(checked_json(_wire_object(item)))) for item in value.observations) > 2_097_152:
        raise RegistryInputError("invalid_result")
    counts: dict[str, int] = {}
    for observation in value.observations:
        read = by_id.get(observation.source_read_id)
        if read is None or observation.registry != value.registry or read.registry != value.registry:
            raise RegistryInputError("invalid_result")
        if (observation.trust.transport_verified, observation.trust.source_signature) != (
            read.transport_verified,
            read.source_signature,
        ):
            raise RegistryInputError("invalid_result")
        counts[read.read_id] = counts.get(read.read_id, 0) + 1
    for read in value.source_reads:
        if (
            _request_data(read.query_scope) != _request_data(value.request)
            or counts.get(read.read_id, 0) != read.admitted_records
        ):
            raise RegistryInputError("invalid_result")
        if not value.manifest.collection_started_at <= read.retrieved_at <= value.manifest.collection_finished_at:
            raise RegistryInputError("invalid_result")
    for item in value.diagnostics:
        if item.source_read_id is not None and item.source_read_id not in by_id:
            raise RegistryInputError("invalid_result")
    if value.registry == "sam-entity" and not any(
        item.code == "source_terminal_unproven" for item in value.diagnostics
    ):
        raise RegistryInputError("invalid_result")
    if value.registry == "ssl-labs" and not any(item.code == "live_disabled" for item in value.diagnostics):
        raise RegistryInputError("invalid_result")
    if (
        value.registry == "sam-exclusions"
        and isinstance(value.request.root.target, SAMOrganizationTarget)
        and not value.observations
        and not any(item.code == "source_match_scope_limited" for item in value.diagnostics)
    ):
        raise RegistryInputError("invalid_result")
    expected = _assemble_result(
        value.request,
        value.run_id,
        value.manifest.collection_started_at,
        value.manifest.collection_finished_at,
        list(value.source_reads),
        list(value.observations),
        list(value.diagnostics),
        value.manifest.collector_version,
        value.manifest.evidentia_version,
    )
    if result_json_bytes(_wire_object(value)) != result_json_bytes(checked_result_json(expected)):
        raise RegistryInputError("invalid_result")


def make_result(
    request: RegistryLookupRequest,
    *,
    reads: list[SourceRead],
    observations: list[RegistryObservation],
    diagnostics: list[RegistryDiagnostic],
    started_at: datetime,
    finished_at: datetime,
    run_id: str | None = None,
) -> RegistryLookupResult:
    if any(type(items) is not list for items in (reads, observations, diagnostics)):
        raise RegistryInputError("invalid_result")
    checked_request = validated_request(request)
    checked_reads = [SourceRead.model_validate(read) for read in reads]
    checked_observations = [RegistryObservation.model_validate(item) for item in observations]
    checked_diagnostics = [RegistryDiagnostic.model_validate(item) for item in diagnostics]
    try:
        data = _assemble_result(
            checked_request,
            new_run_id() if run_id is None else run_id,
            started_at,
            finished_at,
            checked_reads,
            checked_observations,
            checked_diagnostics,
            version("evidentia-collectors"),
            current_version(),
        )
        return RegistryLookupResult.model_validate(data)
    except (ValueError, KeyError, TypeError, AttributeError):
        raise RegistryInputError("invalid_result") from None


def result_bytes(value: RegistryLookupResult) -> bytes:
    return result_json_bytes(_wire_object(RegistryLookupResult.model_validate(value)))


@dataclass(frozen=True)
class _CapacityLimits:
    observation_bytes: int = OBSERVATION_BYTE_LIMIT
    observations_bytes: int = 2_097_152
    result_bytes: int = RESULT_BYTE_LIMIT
    records: int = 100

    def __post_init__(self) -> None:
        for value, ceiling in (
            (self.observation_bytes, OBSERVATION_BYTE_LIMIT),
            (self.observations_bytes, 2_097_152),
            (self.result_bytes, RESULT_BYTE_LIMIT),
            (self.records, 100),
        ):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise RegistryInputError("invalid_result")


def _terminal_skeleton(request: RegistryLookupRequest, observations: list[RegistryObservation]) -> dict[str, Any]:
    """Reserve every metadata slot, including both complete observation copies."""
    registry = request.root.registry
    maximum_clock = datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC)
    clock = clock_text(maximum_clock)
    maximum_version = "9" * 32
    maximum_run = "7" + "Z" * 25
    maximum_diagnostic = max(get_args(DiagnosticCode), key=len)
    # Six escaped bytes per character bound every admitted JSON metadata string.
    escaped = chr(0)
    source_read = {
        "read_id": "read-" + "f" * 64,
        "registry": registry,
        "ordinal": 23,
        "method": "DISABLED",
        "template": _TEMPLATES[registry],
        "query_scope": _request_data(request),
        "transport_kind": "snapshot",
        "status": "unavailable",
        "freshness": "current_observation",
        "http_status": None,
        "network_attempts": 64,
        "attempted_pages": 64,
        "accepted_pages": 20,
        "source_records": 50_000,
        "admitted_records": 100,
        "raw_bytes": 16_777_216,
        "decoded_bytes": 16_777_216,
        "body_complete": False,
        "source_digest": "f" * 64,
        "retrieved_at": clock,
        "publisher_date": escaped * 512,
        "publisher_version": escaped * 128,
        "snapshot_source": escaped * 128,
        "cache_state": "not_applicable",
        "transport_verified": False,
        "source_signature": "not_applicable",
    }
    findings = [
        _finding_body(item, maximum_clock, request, maximum_run, maximum_version, maximum_version)
        for item in observations
    ]
    return {
        "schema_version": "1",
        "registry": registry,
        "request": _request_data(request),
        "run_id": maximum_run,
        "observation_scope": "selected_registry_query",
        "lookup_outcome": "unavailable",
        "collection_status": "unavailable",
        "freshness": "current_observation",
        "observations": [_wire_object(item) for item in observations],
        "source_reads": [dict(source_read) for _ in range(24)],
        "findings": findings,
        "diagnostics": [
            {"code": maximum_diagnostic, "source_read_id": "read-" + "f" * 64, "effect": "advisory"} for _ in range(64)
        ],
        "manifest": {
            "run_id": maximum_run,
            "collector_id": "public-registry",
            "collector_version": maximum_version,
            "collection_started_at": clock,
            "collection_finished_at": clock,
            "source_system_ids": ["registry:" + registry],
            "filters_applied": _filters(request),
            "coverage_counts": [
                {"resource_type": "selected_registry_query", "scanned": 50_000, "matched_filter": 100, "collected": 100}
            ],
            "total_findings": 100,
            "is_complete": False,
            "incomplete_reason": "selected_query_incomplete",
            "empty_categories": ["selected_registry_query"],
            "warnings": [maximum_diagnostic] * 64,
            "errors": [maximum_diagnostic] * 64,
            "evidentia_version": maximum_version,
        },
    }


class CapacityPlan:
    """Evaluate a whole candidate page without changing admitted evidence."""

    def __init__(self, request: RegistryLookupRequest, *, _limits: _CapacityLimits | None = None) -> None:
        if _limits is not None and type(_limits) is not _CapacityLimits:
            raise RegistryInputError("invalid_result")
        self._request = validated_request(request)
        self._limits = (
            _CapacityLimits()
            if _limits is None
            else _CapacityLimits(
                _limits.observation_bytes,
                _limits.observations_bytes,
                _limits.result_bytes,
                _limits.records,
            )
        )

    def _checked(self, observations: list[RegistryObservation]) -> list[RegistryObservation]:
        if type(observations) is not list or len(observations) > 100:
            raise RegistryInputError("invalid_result")
        checked = [RegistryObservation.model_validate(item) for item in observations]
        if any(item.registry != self._request.root.registry for item in checked):
            raise RegistryInputError("invalid_result")
        return checked

    def reserved_bytes(self, observations: list[RegistryObservation]) -> int:
        checked = self._checked(observations)
        sizes = [len(canonical_json(checked_json(_wire_object(item)))) for item in checked]
        if sum(sizes) > 2_097_152:
            raise RegistryInputError("observation_limit")
        body = _terminal_skeleton(self._request, checked)
        return len(
            json.dumps(body, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )

    def refusal(self, observations: list[RegistryObservation]) -> DiagnosticCode | None:
        if type(observations) is not list:
            raise RegistryInputError("invalid_result")
        if len(observations) > self._limits.records:
            return "record_limit"
        checked = self._checked(observations)
        sizes = [len(canonical_json(checked_json(_wire_object(item)))) for item in checked]
        if any(size > self._limits.observation_bytes for size in sizes) or sum(sizes) > self._limits.observations_bytes:
            return "observation_limit"
        if self.reserved_bytes(checked) > self._limits.result_bytes:
            return "result_limit"
        return None
