"""Closed native catalog values with immutable arrays and strict wire validation."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from types import UnionType
from typing import Annotated, Any, ClassVar, Literal, Self, Union, cast, get_args, get_origin

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    GetJsonSchemaHandler,
    ModelWrapValidatorHandler,
    ValidationInfo,
    field_validator,
    model_serializer,
    model_validator,
)
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema


class NativeSourceError(ValueError):
    """A fixed native-source refusal without source or host-path disclosure."""

    def __init__(self, code: str = "native_source_invalid") -> None:
        if type(code) is not str or code not in {
            "native_source_invalid",
            "native_source_unavailable",
            "catalog_generation_changed",
            "processing_deadline_exceeded",
        }:
            raise ValueError("native_source_invalid")
        self.code = code
        super().__init__(code)


class NativeBudget:
    """One real 60-second import clock, with a ten-second publication reserve."""

    __slots__ = ("_deadline", "_publication")

    def __init__(self) -> None:
        self._deadline = time.monotonic() + 60.0
        self._publication = False

    def check(self, *, publication: bool | None = None) -> None:
        allowed = self._publication if publication is None else publication
        if time.monotonic() >= self._deadline - (0.0 if allowed else 10.0):
            raise NativeSourceError("processing_deadline_exceeded")

    @contextmanager
    def publication(self) -> Iterator[None]:
        """Use the existing reserve only for captured-wire verification."""
        self.check()
        previous = self._publication
        self._publication = True
        try:
            yield
            self.check()
        finally:
            self._publication = previous


_ACTIVE_BUDGET: ContextVar[NativeBudget | None] = ContextVar("catalog_native_budget", default=None)
_VALIDATING: ContextVar[bool] = ContextVar("catalog_native_validating", default=False)


@contextmanager
def native_operation() -> Iterator[NativeBudget]:
    existing = _ACTIVE_BUDGET.get()
    if existing is not None:
        existing.check()
        yield existing
        return
    budget = NativeBudget()
    token = _ACTIVE_BUDGET.set(budget)
    try:
        yield budget
    finally:
        _ACTIVE_BUDGET.reset(token)


_JSON_ESCAPED = re.compile(r'["\\\x00-\x1f\x7f-\U0010ffff]')


def _json_string_bytes(value: str) -> int:
    size = len(value) + 2
    budget = _ACTIVE_BUDGET.get()
    for index, match in enumerate(_JSON_ESCAPED.finditer(value)):
        char = match[0]
        number = ord(char)
        if 0xD800 <= number <= 0xDFFF:
            raise NativeSourceError()
        size += 1 if char in '"\\\b\f\n\r\t' else 5 if number <= 0xFFFF else 11
        if index % 4096 == 0 and budget is not None:
            budget.check()
        if size > 16777216:
            raise NativeSourceError()
    return size


def _preflight(data: object) -> None:
    pending = [(data, 0)]
    seen: set[int] = set()
    count = 0
    text_bytes = 0
    wire_bytes = 0
    try:
        while pending:
            value, depth = pending.pop()
            count += type(value) is not dict
            if count > 262144 or depth > 64:
                raise NativeSourceError()
            if count % 256 == 0 and (budget := _ACTIVE_BUDGET.get()) is not None:
                budget.check()
            kind = type(value)
            if value is None:
                wire_bytes += 4
            elif kind is bool:
                wire_bytes += 4 if value else 5
            elif kind is int:
                if cast(int, value).bit_length() > 426:
                    raise NativeSourceError()
                spelling = str(value)
                if len(spelling) > 128:
                    raise NativeSourceError()
                wire_bytes += len(spelling)
            elif kind is str:
                wire_bytes += _json_string_bytes(cast(str, value))
            elif kind is dict or kind is list:
                length = len(cast(dict[str, Any] | list[Any], value))
                if length > (64 if kind is dict else 262144):
                    raise NativeSourceError()
                wire_bytes += 2 + max(length - 1, 0)
            if wire_bytes > 16777216:
                raise NativeSourceError()
            if value is None or kind is bool or kind is int:
                continue
            if kind is str:
                try:
                    size = len(cast(str, value).encode("utf8"))
                except UnicodeError:
                    raise NativeSourceError() from None
                text_bytes += size
                if size > 8388608 or text_bytes > 16777216:
                    raise NativeSourceError()
            elif kind is dict or kind is list:
                identity = id(value)
                if identity in seen:
                    raise NativeSourceError()
                seen.add(identity)
                if kind is dict:
                    for key, item in cast(dict[str, Any], value).items():
                        if type(key) is not str or len(key.encode("utf8")) > 1024:
                            raise NativeSourceError()
                        wire_bytes += _json_string_bytes(key) + 1
                        if wire_bytes > 16777216:
                            raise NativeSourceError()
                        text_bytes += len(key.encode("utf8"))
                        if text_bytes > 16777216:
                            raise NativeSourceError()
                        pending.append((item, depth + 1))
                else:
                    pending.extend((item, depth + 1) for item in cast(list[Any], value))
            else:
                raise NativeSourceError()
    finally:
        pending.clear()
        seen.clear()


class _NativeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, revalidate_instances="always")
    _list_fields: ClassVar[tuple[str, ...]] = ()
    _utf8_limits: ClassVar[dict[str, int]] = {}

    @model_validator(mode="wrap")
    @classmethod
    def _native_input(cls, data: Any, handler: ModelWrapValidatorHandler[Self], info: ValidationInfo) -> Self:
        if info.mode != "python" or type(data) is not dict or any(type(key) is not str for key in data):
            raise NativeSourceError()
        root = not _VALIDATING.get()
        prepared: dict[str, Any] = {}
        with native_operation() if root else nullcontext():
            token = _VALIDATING.set(True) if root else None
            try:
                if _MODEL_TYPES.get(id(cls)) is not cls:
                    raise NativeSourceError()
                if root:
                    _preflight(data)
                prepared = dict(data)
                rules = _NATIVE_FIELD_RULES[id(cls)]
                if len(prepared) != len(rules):
                    raise NativeSourceError()
                for name, value in prepared.items():
                    if type(name) is not str:
                        raise NativeSourceError()
                    rule = rules.get(name)
                    if rule is None or id(type(value)) not in rule[0]:
                        raise NativeSourceError()
                    item_types = rule[1]
                    if item_types is not None:
                        captured = tuple(value)
                        if any(id(type(item)) not in item_types for item in captured):
                            raise NativeSourceError()
                        prepared[name] = captured
                for name, limit in cls._utf8_limits.items():
                    value = prepared.get(name)
                    if value is not None and (type(value) is not str or len(value.encode("utf8")) > limit):
                        raise NativeSourceError()
                checked = handler(prepared)
                _validate_semantics(checked)
                return checked
            finally:
                prepared.clear()
                if token is not None:
                    _VALIDATING.reset(token)

    @model_serializer(mode="plain")
    def _validated_wire(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        with native_operation() as budget:
            try:
                data = native_value(self)
                type(self).model_validate(data)
                budget.check(publication=True)
                return data
            except BaseException:
                data.clear()
                raise

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        if update is not None and type(update) is not dict:
            raise NativeSourceError()
        if type(deep) is not bool:
            raise NativeSourceError()
        data: dict[str, Any] = {}
        with native_operation():
            try:
                data = native_value(self)
                if update is not None:
                    data.update(update)
                return type(self).model_validate(data)
            finally:
                data.clear()

    @classmethod
    def __get_pydantic_json_schema__(cls, schema: CoreSchema, handler: GetJsonSchemaHandler) -> JsonSchemaValue:
        if handler.mode == "serialization":
            copied = dict(schema)
            inner = copied.get("schema")
            if type(inner) is dict and inner.get("type") == "model":
                copied["schema"] = {name: value for name, value in inner.items() if name != "serialization"}
            else:
                copied.pop("serialization", None)
            return handler(cast(CoreSchema, copied))
        return handler(schema)


def native_value(value: object) -> dict[str, Any]:
    """Read owned model fields without invoking a caller serializer."""
    active: set[int] = set()
    owned: list[dict[str, Any] | list[Any]] = []
    nodes = 0
    with native_operation() as budget:

        def visit(item: Any, depth: int) -> Any:
            nonlocal nodes
            kind = type(item)
            nodes += kind is tuple or kind in (str, int, bool, type(None))
            if nodes > 262144 or depth > 64:
                raise NativeSourceError()
            if nodes % 256 == 0:
                budget.check()
            if item is None or kind is str or kind is int or kind is bool:
                return item
            identity = id(item)
            if identity in active:
                raise NativeSourceError()
            active.add(identity)
            try:
                if kind is tuple:
                    items: list[Any] = []
                    owned.append(items)
                    items.extend(visit(child, depth + 1) for child in item)
                    return items
                if _MODEL_TYPES.get(id(kind)) is not kind:
                    raise NativeSourceError()
                fields = kind.model_fields
                data = object.__getattribute__(item, "__dict__")
                if set(data) != set(fields):
                    raise NativeSourceError()
                result: dict[str, Any] = {}
                owned.append(result)
                for name in fields:
                    result[name] = visit(data[name], depth + 1)
                return result
            finally:
                active.remove(identity)

        try:
            result = visit(value, 0)
            if type(result) is not dict:
                raise NativeSourceError()
            budget.check()
            return cast(dict[str, Any], result)
        except BaseException:
            for container in owned:
                container.clear()
            raise
        finally:
            owned.clear()
            active.clear()


def native_compact(value: _NativeModel) -> bytes:
    """Ccompact over fixed declared field order, without untrusted callbacks."""
    with native_operation() as budget:
        data = native_value(value)
        text = ""
        encoded = b""
        try:
            _preflight(data)
            budget.check()
            text = json.dumps(data, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
            budget.check()
            encoded = text.encode("utf8")
            budget.check()
            return encoded
        finally:
            data.clear()
            text = ""
            encoded = b""


class CatalogNativeValueRef(_NativeModel):
    """Closed ValueRef value."""

    _utf8_limits = {"kind": 262144, "sha256": 262144}
    document_index: Annotated[int, Field(ge=0, le=15)]
    byte_start: Annotated[int, Field(ge=0, le=8388608)]
    byte_end: Annotated[int, Field(ge=0, le=8388608)]
    kind: Literal[
        "json_object",
        "json_array",
        "json_string",
        "json_number",
        "json_boolean",
        "json_null",
        "markdown_block",
        "utf8_text",
    ]
    sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class CatalogNativeFieldRef(_NativeModel):
    """Closed FieldRef value."""

    _utf8_limits = {"name": 1024}
    name: Annotated[str, Field(max_length=1024)]
    key: CatalogNativeValueRef
    value: CatalogNativeValueRef


class CatalogNativeAbsentSelection(_NativeModel):
    """Closed AbsentSelection value."""

    state: Literal["absent"]


class CatalogNativeNullSelection(_NativeModel):
    """Closed NullSelection value."""

    _list_fields = ("refs",)
    state: Literal["native_null"]
    refs: Annotated[tuple[CatalogNativeValueRef, ...], Field(max_length=1, min_length=1)]


class CatalogNativePresentSelection(_NativeModel):
    """Closed PresentSelection value."""

    _list_fields = ("refs",)
    state: Literal["present"]
    refs: Annotated[tuple[CatalogNativeValueRef, ...], Field(max_length=256, min_length=1)]


CatalogNativeFieldSelection = CatalogNativeAbsentSelection | CatalogNativeNullSelection | CatalogNativePresentSelection


class CatalogNativeSourceBinding(_NativeModel):
    """Closed SourceBinding value."""

    _utf8_limits = {
        "source_key": 64,
        "role": 262144,
        "media_type": 262144,
        "repository": 256,
        "commit": 262144,
        "upstream_path": 1024,
        "raw_sha256": 262144,
    }
    source_key: Annotated[str, Field(max_length=64)]
    role: Literal["authoritative", "reference", "license", "publication_context"]
    media_type: Literal["application/json", "text/markdown", "text/plain"]
    repository: Annotated[str, Field(max_length=256)]
    commit: Annotated[str, Field(pattern="^[0-9a-f]{40}$")]
    upstream_path: Annotated[str, Field(max_length=1024)]
    raw_bytes: Annotated[int, Field(ge=0, le=8388608)]
    raw_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class CatalogNativeSourceDocument(_NativeModel):
    """Closed SourceDocument value."""

    _utf8_limits = {"raw_utf8": 8388608}
    binding: CatalogNativeSourceBinding
    raw_utf8: Annotated[str, Field(max_length=8388608)]


class CatalogNativeSemanticSelection(_NativeModel):
    """Closed SemanticSelection value."""

    _utf8_limits = {"role": 262144}
    role: Literal[
        "native_id",
        "title",
        "class",
        "statement",
        "guidance",
        "parameter",
        "applicability",
        "essential_eight_applicability",
        "rationale",
        "note",
        "last_modified",
        "implementation",
        "criticality",
        "criticality_identity",
        "resources",
        "license_requirements",
        "badge",
        "nist_mapping",
        "mitre_mapping",
        "status",
        "publication_time",
        "native_version",
        "schema_version",
        "reference_record",
    ]
    value: CatalogNativeFieldSelection


class CatalogNativeOccurrence(_NativeModel):
    """Closed Occurrence value."""

    _list_fields = ("fields", "selections")
    _utf8_limits = {"kind": 262144}
    index: Annotated[int, Field(ge=0, le=4095)]
    kind: Literal[
        "catalog", "metadata", "group", "control", "principle", "section", "policy", "reference_policy", "context_block"
    ]
    parent_index: Annotated[int, Field(ge=0, le=4095)] | None
    sibling_ordinal: Annotated[int, Field(ge=0, le=4095)]
    source: CatalogNativeValueRef
    fields: Annotated[tuple[CatalogNativeFieldRef, ...], Field(max_length=64)]
    selections: Annotated[tuple[CatalogNativeSemanticSelection, ...], Field(max_length=32)]


class CatalogNativeControlSourceRef(_NativeModel):
    """Closed ControlSourceRef value."""

    _utf8_limits = {"bundle_sha256": 262144}
    bundle_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    occurrence_index: Annotated[int, Field(ge=0, le=4095)]


class CatalogNativeDiagnostic(_NativeModel):
    """Closed Diagnostic value."""

    _list_fields = ("refs",)
    _utf8_limits = {"code": 262144}
    code: Literal[
        "source_identity_conflict", "missing_reference_record", "source_reference_difference", "legacy_ids_retired"
    ]
    occurrence_index: Annotated[int, Field(ge=0, le=4095)] | None
    refs: Annotated[tuple[CatalogNativeValueRef, ...], Field(max_length=8)]


class CatalogNativeControlBinding(_NativeModel):
    """Closed ControlBinding value."""

    _utf8_limits = {"control_id": 128, "parent_control_id": 128, "admitted_criticality": 262144}
    control_id: Annotated[str, Field(max_length=128)]
    occurrence_index: Annotated[int, Field(ge=0, le=4095)]
    family_occurrence_index: Annotated[int, Field(ge=0, le=4095)] | None
    parent_control_id: Annotated[str, Field(max_length=128)] | None
    admitted_criticality: Literal["SHALL", "SHOULD"] | None


class CatalogNativeNativeData(_NativeModel):
    """Closed NativeData value."""

    _list_fields = ("documents", "occurrences", "control_bindings", "context_indices", "diagnostics")
    _utf8_limits = {"profile": 262144, "catalog_id": 262144, "converter_sha256": 262144}
    schema_version: Literal["catalog-native-v1"]
    profile: Literal["au-ism-2026.09.4", "cisa-scuba-m365-7ef9501d", "bsi-grundschutz-plus-plus-367d7750"]
    catalog_id: Literal["au-ism", "cisa-scuba", "bsi-grundschutz-plus-plus"]
    converter_id: Literal["evidentia-open-corpora-v1"]
    converter_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    documents: Annotated[tuple[CatalogNativeSourceDocument, ...], Field(max_length=16)]
    occurrences: Annotated[tuple[CatalogNativeOccurrence, ...], Field(max_length=4096)]
    control_bindings: Annotated[tuple[CatalogNativeControlBinding, ...], Field(max_length=2048)]
    context_indices: Annotated[tuple[Annotated[int, Field(ge=0, le=4095)], ...], Field(max_length=1024)]
    diagnostics: Annotated[tuple[CatalogNativeDiagnostic, ...], Field(max_length=512)]

    def _source_correspondence(self) -> Self:
        from evidentia_core.catalogs.open_corpora import validate_native_data

        validate_native_data(self)
        return self


class CatalogNativeNativeBundle(_NativeModel):
    """Closed NativeBundle value."""

    _utf8_limits = {"bundle_sha256": 262144}
    bundle_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    data: CatalogNativeNativeData

    def _bundle_digest(self) -> Self:
        encoded = native_compact(self.data)
        try:
            if len(encoded) + 92 > 12_058_624:
                raise NativeSourceError()
            with native_operation() as budget:
                digest = hashlib.sha256(b"evidentia.catalog-native.v1\x00")
                for offset in range(0, len(encoded), 4096):
                    budget.check()
                    digest.update(encoded[offset : offset + 4096])
                budget.check()
                if digest.hexdigest() != self.bundle_sha256:
                    raise NativeSourceError()
                return self
        finally:
            encoded = b""


class CatalogNativePackageRef(_NativeModel):
    """Closed PackageRef value."""

    _utf8_limits = {
        "profile": 262144,
        "source_manifest_path": 256,
        "source_manifest_sha256": 262144,
        "converter_sha256": 262144,
        "bundle_sha256": 262144,
        "projection_sha256": 262144,
    }
    schema_version: Literal["catalog-native-package-v1"]
    profile: Literal["au-ism-2026.09.4", "cisa-scuba-m365-7ef9501d", "bsi-grundschutz-plus-plus-367d7750"]
    source_manifest_path: Annotated[str, Field(max_length=256)]
    source_manifest_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    converter_id: Literal["evidentia-open-corpora-v1"]
    converter_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    bundle_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    projection_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class CatalogNativeSourceChunk(_NativeModel):
    """Closed SourceChunk value."""

    _utf8_limits = {"sha256": 262144, "raw_utf8": 1572864}
    schema_version: Literal["catalog-source-chunk-v1"]
    source_key: Literal["ism-catalog"]
    index: Annotated[int, Field(ge=0, le=1)]
    byte_start: Annotated[int, Field(ge=0, le=2677748)]
    byte_length: Annotated[int, Field(ge=1, le=1572864)]
    sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    raw_utf8: Annotated[str, Field(max_length=1572864)]


class CatalogNativeSourceUpload(_NativeModel):
    """Closed SourceUpload value."""

    _utf8_limits = {"source_key": 262144, "raw_utf8": 8388608}
    source_key: Literal["bsi-catalog", "bsi-license", "bsi-readme"]
    raw_utf8: Annotated[str, Field(max_length=8388608)]


class CatalogNativeExternalImportRequest(_NativeModel):
    """Closed ExternalImportRequest value."""

    _list_fields = ("documents",)
    profile: Literal["bsi-grundschutz-plus-plus-367d7750"]
    documents: Annotated[tuple[CatalogNativeSourceUpload, ...], Field(max_length=3, min_length=3)]

    @field_validator("documents")
    @classmethod
    def _upload_semantics(
        cls, documents: tuple[CatalogNativeSourceUpload, ...]
    ) -> tuple[CatalogNativeSourceUpload, ...]:
        with native_operation() as budget:
            if {document.source_key for document in documents} != {"bsi-catalog", "bsi-license", "bsi-readme"}:
                raise NativeSourceError()
            total = 0
            for document in documents:
                budget.check()
                total += len(document.raw_utf8.encode("utf8"))
                budget.check()
                if total > 8_388_608:
                    raise NativeSourceError()
        return documents


class CatalogNativeImportResult(_NativeModel):
    """Closed ImportResult value."""

    _list_fields = ("source_hashes",)
    _utf8_limits = {"bundle_sha256": 262144, "projection_sha256": 262144, "status": 262144}
    schema_version: Literal["catalog-native-import-result-v1"]
    catalog_id: Literal["bsi-grundschutz-plus-plus"]
    bundle_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    projection_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    status: Literal["imported", "already_present"]
    control_count: Literal[1000]
    storage: Literal["external"]
    source_hashes: Annotated[tuple[Annotated[str, Field(pattern="^[0-9a-f]{64}$")], ...], Field(max_length=3)]


class CatalogNativeNativeReadRequest(_NativeModel):
    """Closed NativeReadRequest value."""

    _utf8_limits = {"framework_id": 262144, "bundle_sha256": 262144}
    framework_id: Literal["au-ism", "cisa-scuba", "bsi-grundschutz-plus-plus"]
    bundle_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class CatalogNativeNativeReadError(_NativeModel):
    """Closed NativeReadError value."""

    _utf8_limits = {"code": 262144}
    code: Literal[
        "native_source_unavailable",
        "catalog_generation_changed",
        "native_source_invalid",
        "processing_deadline_exceeded",
    ]


class CatalogNativeStoredFile(_NativeModel):
    """Closed StoredFile value."""

    _utf8_limits = {"path": 256, "stored_sha256": 262144}
    kind: Literal["file"]
    path: Annotated[str, Field(max_length=256)]
    stored_bytes: Annotated[int, Field(ge=0, le=2097152)]
    stored_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class CatalogNativeStoredChunk(_NativeModel):
    """Closed StoredChunk value."""

    _utf8_limits = {"path": 256, "stored_sha256": 262144, "decoded_sha256": 262144}
    path: Annotated[str, Field(max_length=256)]
    stored_bytes: Annotated[int, Field(ge=0, le=2097152)]
    stored_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    index: Annotated[int, Field(ge=0, le=1)]
    byte_start: Annotated[int, Field(ge=0, le=2677748)]
    byte_length: Annotated[int, Field(ge=0, le=1572864)]
    decoded_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class CatalogNativeStoredChunks(_NativeModel):
    """Closed StoredChunks value."""

    _list_fields = ("parts",)
    kind: Literal["chunks"]
    parts: Annotated[tuple[CatalogNativeStoredChunk, ...], Field(max_length=2, min_length=2)]


class CatalogNativeSourceIndexEntry(_NativeModel):
    """Closed SourceIndexEntry value."""

    binding: CatalogNativeSourceBinding
    storage: CatalogNativeStoredFile | CatalogNativeStoredChunks


class CatalogNativePackagedIndex(_NativeModel):
    """Closed PackagedIndex value."""

    _list_fields = ("sources",)
    _utf8_limits = {"profile": 262144, "catalog_id": 262144, "converter_sha256": 262144}
    schema_version: Literal["catalog-source-index-v1"]
    profile: Literal["au-ism-2026.09.4", "cisa-scuba-m365-7ef9501d"]
    catalog_id: Literal["au-ism", "cisa-scuba"]
    converter_id: Literal["evidentia-open-corpora-v1"]
    converter_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    sources: Annotated[tuple[CatalogNativeSourceIndexEntry, ...], Field(max_length=16, min_length=1)]


class CatalogNativeExternalStoredFile(_NativeModel):
    """Closed ExternalStoredFile value."""

    _utf8_limits = {"path": 262144, "stored_sha256": 262144}
    kind: Literal["file"]
    path: Literal["Grundschutz++-resolved_catalog.json", "LICENSE.txt", "README.md"]
    stored_bytes: Annotated[int, Field(ge=0, le=8388608)]
    stored_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


class CatalogNativeExternalEntry(_NativeModel):
    """Closed ExternalEntry value."""

    binding: CatalogNativeSourceBinding
    storage: CatalogNativeExternalStoredFile


class CatalogNativeExternalIndex(_NativeModel):
    """Closed ExternalIndex value."""

    _list_fields = ("sources",)
    _utf8_limits = {"converter_sha256": 262144}
    schema_version: Literal["catalog-source-index-v1"]
    profile: Literal["bsi-grundschutz-plus-plus-367d7750"]
    catalog_id: Literal["bsi-grundschutz-plus-plus"]
    converter_id: Literal["evidentia-open-corpora-v1"]
    converter_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    sources: Annotated[tuple[CatalogNativeExternalEntry, ...], Field(max_length=3, min_length=3)]


class CatalogNativeCatalogPublicationObservation(_NativeModel):
    """Closed CatalogPublicationObservation value."""

    _list_fields = ("cleanup_errors",)
    schema_version: Literal["catalog-publication-observation-v1"]
    operation: Literal["native_import", "legacy_import", "remove", "compatibility_replace"]
    publication_state: Literal["not_attempted", "unchanged", "not_committed", "committed", "indeterminate"]
    prior_manifest_state: Literal["unread", "absent", "present"]
    prior_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")] | None
    proposed_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")] | None
    replace_outcome: Literal["not_called", "returned", "raised"]
    observed_manifest_state: Literal["not_observed", "absent", "present"]
    observed_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")] | None
    readback_result: Literal["not_attempted", "matches_prior", "matches_proposed", "other", "unavailable"]
    cleanup_state: Literal["not_started", "complete", "failed"]
    cleanup_errors: Annotated[
        tuple[Literal["temporary_cleanup_failed", "handle_close_failed", "lock_release_failed"], ...],
        Field(max_length=3, json_schema_extra={"uniqueItems": True}),
    ]
    failure_phase: Literal[
        None,
        "admission",
        "preparation",
        "lock",
        "manifest_read",
        "generation",
        "manifest_stage",
        "replace",
        "readback",
        "cleanup",
    ]
    primary_kind: Literal["none", "exception", "base_exception"]
    error_code: Literal[
        None,
        "catalog_transaction_conflict",
        "catalog_storage_unsupported",
        "catalog_manifest_invalid",
        "catalog_storage_limit_exceeded",
        "catalog_generation_conflict",
        "catalog_storage_failed",
        "catalog_publication_failed",
        "catalog_publication_indeterminate",
        "catalog_cleanup_failed",
        "processing_deadline_exceeded",
        "catalog_interrupted",
    ]

    def _publication_semantics(self) -> Self:
        if (self.prior_manifest_state == "present") != (self.prior_sha256 is not None):
            raise NativeSourceError()
        if (self.observed_manifest_state == "present") != (self.observed_sha256 is not None):
            raise NativeSourceError()
        if self.publication_state != "not_attempted" and self.proposed_sha256 is None:
            raise NativeSourceError()
        if self.publication_state in ("not_attempted", "unchanged") and self.replace_outcome != "not_called":
            raise NativeSourceError()
        if self.publication_state in ("not_committed", "indeterminate") and self.replace_outcome != "raised":
            raise NativeSourceError()
        if self.replace_outcome == "returned" and self.publication_state != "committed":
            raise NativeSourceError()
        same_prior = self.prior_manifest_state in ("absent", "present") and (
            self.observed_manifest_state,
            self.observed_sha256,
        ) == (self.prior_manifest_state, self.prior_sha256)
        same_proposed = self.observed_manifest_state == "present" and self.observed_sha256 == self.proposed_sha256
        if self.readback_result == "matches_prior" and not same_prior:
            raise NativeSourceError()
        if self.readback_result == "matches_proposed" and not same_proposed:
            raise NativeSourceError()
        if self.readback_result in ("unavailable", "not_attempted") and self.observed_manifest_state != "not_observed":
            raise NativeSourceError()
        if self.readback_result == "other" and (
            self.observed_manifest_state == "not_observed" or same_prior or same_proposed
        ):
            raise NativeSourceError()
        if self.publication_state == "unchanged" and (
            self.prior_manifest_state != "present"
            or self.prior_sha256 != self.proposed_sha256
            or self.readback_result != "matches_proposed"
        ):
            raise NativeSourceError()
        if self.publication_state == "not_committed" and (
            self.readback_result != "matches_prior" or self.prior_sha256 == self.proposed_sha256
        ):
            raise NativeSourceError()
        if self.publication_state == "committed" and (
            self.replace_outcome == "not_called"
            or (self.replace_outcome == "raised" and self.readback_result != "matches_proposed")
        ):
            raise NativeSourceError()
        if self.replace_outcome == "raised":
            expected_code = (
                "catalog_publication_indeterminate"
                if self.publication_state == "indeterminate"
                else "catalog_publication_failed"
            )
            if self.primary_kind == "none" or (self.primary_kind == "exception" and self.error_code != expected_code):
                raise NativeSourceError()
        if self.publication_state == "indeterminate" and self.readback_result not in (
            "unavailable",
            "not_attempted",
            "other",
        ):
            raise NativeSourceError()
        if (
            self.replace_outcome == "returned"
            and self.readback_result == "other"
            and self.primary_kind != "base_exception"
            and self.error_code != "catalog_generation_conflict"
        ):
            raise NativeSourceError()
        if self.error_code == "catalog_cleanup_failed" and (
            self.primary_kind != "exception"
            or self.failure_phase != "cleanup"
            or self.cleanup_state != "failed"
            or self.replace_outcome == "raised"
        ):
            raise NativeSourceError()
        if (self.cleanup_state == "failed") != bool(self.cleanup_errors):
            raise NativeSourceError()
        if (self.primary_kind == "base_exception") != (self.error_code == "catalog_interrupted"):
            raise NativeSourceError()
        if (self.primary_kind == "none") != (self.failure_phase is None):
            raise NativeSourceError()
        verified = (
            self.publication_state in ("committed", "unchanged")
            and self.readback_result == "matches_proposed"
            and self.primary_kind == "none"
            and self.failure_phase is None
            and self.cleanup_state == "complete"
            and not self.cleanup_errors
        )
        if (self.error_code is None) != verified:
            raise NativeSourceError()
        return self


class CatalogNativeCatalogStorageErrorEnvelope(_NativeModel):
    """Closed CatalogStorageErrorEnvelope value."""

    _utf8_limits = {"code": 262144}
    code: Literal[
        "catalog_transaction_conflict",
        "catalog_generation_conflict",
        "catalog_storage_unsupported",
        "catalog_manifest_invalid",
        "catalog_storage_limit_exceeded",
        "catalog_storage_failed",
        "catalog_publication_failed",
        "catalog_publication_indeterminate",
        "catalog_cleanup_failed",
        "processing_deadline_exceeded",
    ]
    publication: CatalogNativeCatalogPublicationObservation

    @field_validator("publication")
    @classmethod
    def _error_semantics(
        cls, publication: CatalogNativeCatalogPublicationObservation, info: ValidationInfo
    ) -> CatalogNativeCatalogPublicationObservation:
        if info.data.get("code") != publication.error_code:
            raise NativeSourceError()
        return publication


_MODEL_TYPES: dict[int, type[_NativeModel]] = {
    id(model): model
    for model in (
        CatalogNativeValueRef,
        CatalogNativeFieldRef,
        CatalogNativeAbsentSelection,
        CatalogNativeNullSelection,
        CatalogNativePresentSelection,
        CatalogNativeSourceBinding,
        CatalogNativeSourceDocument,
        CatalogNativeSemanticSelection,
        CatalogNativeOccurrence,
        CatalogNativeControlSourceRef,
        CatalogNativeDiagnostic,
        CatalogNativeControlBinding,
        CatalogNativeNativeData,
        CatalogNativeNativeBundle,
        CatalogNativePackageRef,
        CatalogNativeSourceChunk,
        CatalogNativeSourceUpload,
        CatalogNativeExternalImportRequest,
        CatalogNativeImportResult,
        CatalogNativeNativeReadRequest,
        CatalogNativeNativeReadError,
        CatalogNativeStoredFile,
        CatalogNativeStoredChunk,
        CatalogNativeStoredChunks,
        CatalogNativeSourceIndexEntry,
        CatalogNativePackagedIndex,
        CatalogNativeExternalStoredFile,
        CatalogNativeExternalEntry,
        CatalogNativeExternalIndex,
        CatalogNativeCatalogPublicationObservation,
        CatalogNativeCatalogStorageErrorEnvelope,
    )
}


def _native_type_ids(annotation: Any) -> frozenset[int]:
    """Compile exact native types from the closed, module-owned declarations."""
    if annotation is str or annotation is int or annotation is type(None):
        return frozenset((id(annotation),))
    origin = get_origin(annotation)
    arguments = get_args(annotation)
    if origin is Annotated:
        return _native_type_ids(arguments[0])
    if origin is Literal:
        return frozenset(id(type(value)) for value in arguments)
    if origin is Union or origin is UnionType:
        return frozenset[int]().union(*(_native_type_ids(item) for item in arguments))
    if origin is tuple:
        return frozenset((id(list),))
    if _MODEL_TYPES.get(id(annotation)) is annotation:
        return frozenset((id(dict),))
    raise RuntimeError("unsupported native field declaration")


def _native_field_rules(model: type[_NativeModel]) -> dict[str, tuple[frozenset[int], frozenset[int] | None]]:
    rules = {}
    for name, field in model.model_fields.items():
        if not field.is_required():
            raise RuntimeError("native fields must remain required")
        annotation = field.annotation
        item_types = _native_type_ids(get_args(annotation)[0]) if get_origin(annotation) is tuple else None
        if (item_types is not None) != (name in model._list_fields):
            raise RuntimeError("native array declaration mismatch")
        rules[name] = (_native_type_ids(annotation), item_types)
    return rules


_NATIVE_FIELD_RULES = {identity: _native_field_rules(model) for identity, model in _MODEL_TYPES.items()}

ValueRef = CatalogNativeValueRef
FieldRef = CatalogNativeFieldRef
FieldSelection = CatalogNativeFieldSelection
SourceBinding = CatalogNativeSourceBinding
SourceDocument = CatalogNativeSourceDocument
SemanticSelection = CatalogNativeSemanticSelection
Occurrence = CatalogNativeOccurrence
ControlSourceRef = CatalogNativeControlSourceRef
Diagnostic = CatalogNativeDiagnostic
ControlBinding = CatalogNativeControlBinding
NativeData = CatalogNativeNativeData
NativeBundle = CatalogNativeNativeBundle
PackageRef = CatalogNativePackageRef
SourceChunk = CatalogNativeSourceChunk
SourceUpload = CatalogNativeSourceUpload
ExternalImportRequest = CatalogNativeExternalImportRequest
ImportResult = CatalogNativeImportResult
NativeReadRequest = CatalogNativeNativeReadRequest
NativeReadError = CatalogNativeNativeReadError
StoredFile = CatalogNativeStoredFile
StoredChunk = CatalogNativeStoredChunk
StoredChunks = CatalogNativeStoredChunks
SourceIndexEntry = CatalogNativeSourceIndexEntry
PackagedIndex = CatalogNativePackagedIndex
ExternalStoredFile = CatalogNativeExternalStoredFile
ExternalEntry = CatalogNativeExternalEntry
ExternalIndex = CatalogNativeExternalIndex
CatalogPublicationObservation = CatalogNativeCatalogPublicationObservation
CatalogStorageErrorEnvelope = CatalogNativeCatalogStorageErrorEnvelope


def _validate_semantics(value: _NativeModel) -> None:
    kind = type(value)
    if kind is CatalogNativeCatalogPublicationObservation:
        errors = cast(CatalogNativeCatalogPublicationObservation, value).cleanup_errors
        if len(errors) != len(set(errors)):
            raise NativeSourceError()
        CatalogNativeCatalogPublicationObservation._publication_semantics(
            cast(CatalogNativeCatalogPublicationObservation, value)
        )
    elif kind is CatalogNativeValueRef:
        if cast(CatalogNativeValueRef, value).byte_start >= cast(CatalogNativeValueRef, value).byte_end:
            raise NativeSourceError()
    elif kind is CatalogNativeNullSelection:
        if cast(CatalogNativeNullSelection, value).refs[0].kind != "json_null":
            raise NativeSourceError()
    elif kind is CatalogNativePresentSelection:
        if any(ref.kind == "json_null" for ref in cast(CatalogNativePresentSelection, value).refs):
            raise NativeSourceError()
    elif kind is CatalogNativeSourceDocument:
        encoded = cast(CatalogNativeSourceDocument, value).raw_utf8.encode("utf-8")
        try:
            if (
                len(encoded) != cast(CatalogNativeSourceDocument, value).binding.raw_bytes
                or hashlib.sha256(encoded).hexdigest() != cast(CatalogNativeSourceDocument, value).binding.raw_sha256
            ):
                raise NativeSourceError()
        finally:
            encoded = b""
    elif kind is CatalogNativeSourceChunk:
        encoded = cast(CatalogNativeSourceChunk, value).raw_utf8.encode("utf-8")
        try:
            if (
                len(encoded) != cast(CatalogNativeSourceChunk, value).byte_length
                or hashlib.sha256(encoded).hexdigest() != cast(CatalogNativeSourceChunk, value).sha256
            ):
                raise NativeSourceError()
        finally:
            encoded = b""
    elif kind is CatalogNativeOccurrence:
        if len({item.role for item in cast(CatalogNativeOccurrence, value).selections}) != len(
            cast(CatalogNativeOccurrence, value).selections
        ):
            raise NativeSourceError()
        if cast(CatalogNativeOccurrence, value).source.kind == "json_object" and len(
            {item.name for item in cast(CatalogNativeOccurrence, value).fields}
        ) != len(cast(CatalogNativeOccurrence, value).fields):
            raise NativeSourceError()
        parent_index = cast(CatalogNativeOccurrence, value).parent_index
        if parent_index is not None and parent_index >= cast(CatalogNativeOccurrence, value).index:
            raise NativeSourceError()
    elif kind is CatalogNativeNativeData:
        CatalogNativeNativeData._source_correspondence(cast(CatalogNativeNativeData, value))
    elif kind is CatalogNativeNativeBundle:
        CatalogNativeNativeBundle._bundle_digest(cast(CatalogNativeNativeBundle, value))
