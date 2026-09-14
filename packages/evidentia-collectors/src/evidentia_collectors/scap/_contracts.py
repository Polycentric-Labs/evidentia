"""Closed SCAP models shared by collection, validation and public schemas.

Every field is required. Native source strings retain their exact decoded
values. Factory records are private and do not provide source authority.
"""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime
from functools import partial
from typing import Annotated, ClassVar, Literal, Self, cast

from evidentia_core.models.common import NON_BLANK_PATTERN
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, PlainSerializer, ValidationInfo, model_validator

from ._json import canonical_size, load_json
from ._limits import RESULT_LIMIT, ScapFailure, parse_utc, text_value, utc_text


def _exact(expected: type, value: object) -> object:
    if type(value) is not expected:
        raise ScapFailure()
    return value


def _literal(expected: object, value: object) -> object:
    if type(value) is not type(expected) or value != expected:
        raise ScapFailure()
    return value


def _sequence(minimum: int, maximum: int, value: object) -> object:
    if type(value) is not list or not minimum <= len(cast(list[object], value)) <= maximum:
        raise ScapFailure()
    return value


def _string(
    minimum: int,
    maximum: int,
    value: object,
    *,
    nonblank: bool = False,
    controls: bool = False,
    pattern: str | None = None,
) -> str:
    text = text_value(value, minimum, maximum, nonblank=nonblank, controls=controls)
    if pattern is not None and re.fullmatch(pattern, text) is None:
        raise ScapFailure()
    return text


def _integer(minimum: int, maximum: int, value: object) -> int:
    if type(value) is not int or not minimum <= cast(int, value) <= maximum:
        raise ScapFailure()
    return cast(int, value)


def _deadline(value: object) -> float:
    if type(value) is not float or not math.isfinite(cast(float, value)) or cast(float, value) < 0:
        raise ScapFailure()
    return cast(float, value)


def _raw(value: object) -> bytes:
    if type(value) is not bytes or not 1 <= len(cast(bytes, value)) <= 8_388_608:
        raise ScapFailure()
    return cast(bytes, value)


def _utc_runtime(value: object) -> datetime:
    if type(value) is not datetime or cast(datetime, value).tzinfo is not UTC:
        raise ScapFailure()
    return cast(datetime, value)


def _utc_string(value: object, *, canonical: bool) -> str:
    parse_utc(value, canonical=canonical)
    return cast(str, value)


def _xml_name(value: object, *, maximum: int, empty: bool = False, pi: bool = False) -> str:
    text = text_value(value, 0 if empty else 1, maximum)
    if not text:
        return text

    def start(character: str) -> bool:
        point = ord(character)
        return (
            character == "_"
            or (pi and character == ":")
            or 65 <= point <= 90
            or 97 <= point <= 122
            or 0xC0 <= point <= 0xD6
            or 0xD8 <= point <= 0xF6
            or 0xF8 <= point <= 0x2FF
            or 0x370 <= point <= 0x37D
            or 0x37F <= point <= 0x1FFF
            or 0x200C <= point <= 0x200D
            or 0x2070 <= point <= 0x218F
            or 0x2C00 <= point <= 0x2FEF
            or 0x3001 <= point <= 0xD7FF
            or 0xF900 <= point <= 0xFDCF
            or 0xFDF0 <= point <= 0xFFFD
            or 0x10000 <= point <= 0xEFFFF
        )

    if not start(text[0]) or (pi and text.lower() == "xml"):
        raise ScapFailure()
    for character in text[1:]:
        point = ord(character)
        if not (
            start(character)
            or character in "-."
            or 48 <= point <= 57
            or point == 0xB7
            or 0x300 <= point <= 0x36F
            or 0x203F <= point <= 0x2040
        ):
            raise ScapFailure()
    return text


def _object(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise ScapFailure()
    mapping = cast(dict[str, object], value)
    if any(type(key) is not str for key in mapping):
        raise ScapFailure()
    if "kind" in mapping and type(mapping["kind"]) is not str:
        raise ScapFailure()
    return mapping


class ClosedModel(BaseModel):
    """Admit exact native objects with every field present and no extra fields."""

    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, revalidate_instances="always", hide_input_in_errors=True
    )
    canonical_limit: ClassVar[int | None] = None

    @model_validator(mode="before")
    @classmethod
    def native_object(cls, value: object, info: ValidationInfo) -> dict[str, object]:
        if info.mode == "json":
            raise ScapFailure()
        mapping = _object(value)
        if mapping.keys() != cls.model_fields.keys():
            raise ScapFailure()
        return mapping

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        extra: Literal["allow", "ignore", "forbid"] | None = None,
        context: object = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        """Preflight complete JSON bytes before entering native model validation."""
        if cls.canonical_limit is None:
            raise ScapFailure()
        if type(json_data) is str:
            if len(json_data) > RESULT_LIMIT:
                raise ScapFailure("result_limit_exceeded")
            try:
                raw = json_data.encode("utf-8")
            except UnicodeError:
                raise ScapFailure() from None
        elif type(json_data) is bytes:
            raw = json_data
        else:
            raise ScapFailure()
        value = load_json(raw, RESULT_LIMIT)
        canonical_size(value, cls.canonical_limit)
        return cls.model_validate(
            value, strict=strict, extra=extra, context=context, by_alias=by_alias, by_name=by_name
        )


Boolean = Annotated[bool, BeforeValidator(partial(_exact, bool))]

RawBytes = Annotated[bytes, BeforeValidator(_raw), Field(min_length=1, max_length=8_388_608)]

MonotonicDeadline = Annotated[float, BeforeValidator(_deadline), Field(ge=0, allow_inf_nan=False)]

SourceText = Annotated[str, BeforeValidator(partial(_string, 0, 262144)), Field(min_length=0, max_length=262144)]

NamespaceUri = Annotated[str, BeforeValidator(partial(_string, 0, 2048)), Field(min_length=0, max_length=2048)]

LocalName = Annotated[
    str,
    BeforeValidator(partial(_string, 1, 256)),
    BeforeValidator(partial(_xml_name, maximum=256, empty=False, pi=False)),
    Field(max_length=256, json_schema_extra={"pattern": r"^[\s\S]+$"}),
]

NamespacePrefix = Annotated[
    str,
    BeforeValidator(partial(_string, 0, 128)),
    BeforeValidator(partial(_xml_name, maximum=128, empty=True, pi=False)),
    Field(min_length=0, max_length=128),
]

EncodingName = Annotated[
    str,
    BeforeValidator(partial(_string, 1, 32, pattern="^[Uu][Tt][Ff]-8$")),
    Field(min_length=1, max_length=32, pattern="^[Uu][Tt][Ff]-8$"),
]

PIName = Annotated[
    str,
    BeforeValidator(partial(_string, 1, 256)),
    BeforeValidator(partial(_xml_name, maximum=256, empty=False, pi=True)),
    Field(max_length=256, json_schema_extra={"pattern": r"^[\s\S]+$"}),
]

Sha256 = Annotated[
    str,
    BeforeValidator(partial(_string, 64, 64, pattern="^[0-9a-f]{64}$")),
    Field(min_length=64, max_length=64, pattern="^[0-9a-f]{64}$"),
]

Uuid5 = Annotated[
    str,
    BeforeValidator(
        partial(_string, 36, 36, pattern="^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    ),
    Field(
        min_length=36, max_length=36, pattern="^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    ),
]

RunId = Annotated[
    str,
    BeforeValidator(partial(_string, 26, 26, pattern="^[0-7][0-9A-HJKMNP-TV-Z]{25}$")),
    Field(min_length=26, max_length=26, pattern="^[0-7][0-9A-HJKMNP-TV-Z]{25}$"),
]

VersionLabel = Annotated[
    str,
    BeforeValidator(partial(_string, 1, 64, nonblank=True, controls=True)),
    Field(min_length=1, max_length=64, json_schema_extra={"pattern": NON_BLANK_PATTERN}),
]

ActorLabel = Annotated[
    str,
    BeforeValidator(partial(_string, 1, 128, nonblank=True, controls=True)),
    Field(min_length=1, max_length=128, json_schema_extra={"pattern": NON_BLANK_PATTERN}),
]

OperatorReference = Annotated[
    str,
    BeforeValidator(partial(_string, 1, 256, nonblank=True, controls=True)),
    Field(min_length=1, max_length=256, json_schema_extra={"pattern": NON_BLANK_PATTERN}),
]

CadenceSlug = Annotated[
    str,
    BeforeValidator(partial(_string, 1, 256, nonblank=True, controls=True)),
    Field(min_length=1, max_length=256, json_schema_extra={"pattern": NON_BLANK_PATTERN}),
]

UtcText = Annotated[
    str,
    BeforeValidator(
        partial(_string, 20, 27, pattern="^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$")
    ),
    BeforeValidator(partial(_utc_string, canonical=True)),
    Field(
        min_length=20, max_length=27, pattern="^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$"
    ),
]

UtcRuntime = Annotated[
    datetime, BeforeValidator(_utc_runtime), PlainSerializer(utc_text, return_type=str, when_used="json")
]

ClaimUtcText = Annotated[
    str,
    BeforeValidator(
        partial(_string, 20, 27, pattern="^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$")
    ),
    BeforeValidator(partial(_utc_string, canonical=False)),
    Field(
        min_length=20, max_length=27, pattern="^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$"
    ),
]

SourceSystemId = Annotated[
    str,
    BeforeValidator(partial(_string, 76, 76, pattern="^scap-source:[0-9a-f]{64}$")),
    Field(min_length=76, max_length=76, pattern="^scap-source:[0-9a-f]{64}$"),
]

SourceProfile = Annotated[
    Literal["xccdf-1.2-results", "oval-5.8-core-results", "oval-5.11.2-core-results", "oval-5.12.3-core-results"],
    BeforeValidator(partial(_exact, str)),
]

OvalProfile = Annotated[
    Literal["oval-5.8-core-results", "oval-5.11.2-core-results", "oval-5.12.3-core-results"],
    BeforeValidator(partial(_exact, str)),
]

UnitKind = Annotated[Literal["xccdf_test_result", "oval_system"], BeforeValidator(partial(_exact, str))]

SourceSystem = Annotated[Literal["scap-xccdf", "scap-oval"], BeforeValidator(partial(_exact, str))]

XccdfOutcome = Annotated[
    Literal["pass", "fail", "error", "unknown", "notapplicable", "informational", "fixed", "notchecked", "notselected"],
    BeforeValidator(partial(_exact, str)),
]

OvalOutcome = Annotated[
    Literal["true", "false", "unknown", "error", "not evaluated", "not applicable"],
    BeforeValidator(partial(_exact, str)),
]

NativeOutcome = Annotated[
    Literal[
        "pass",
        "fail",
        "error",
        "unknown",
        "notapplicable",
        "informational",
        "fixed",
        "notchecked",
        "notselected",
        "true",
        "false",
        "not evaluated",
        "not applicable",
    ],
    BeforeValidator(partial(_exact, str)),
]

OutcomeLevel = Annotated[
    Literal[
        "xccdf_rule_result",
        "oval_definition",
        "oval_criteria",
        "oval_criterion",
        "oval_extend_definition",
        "oval_test",
        "oval_tested_item",
    ],
    BeforeValidator(partial(_exact, str)),
]

TopOutcomeLevel = Annotated[
    Literal["xccdf_rule_result", "oval_definition", "oval_test"], BeforeValidator(partial(_exact, str))
]

OvalClass = Annotated[
    Literal["compliance", "inventory", "miscellaneous", "patch", "vulnerability"], BeforeValidator(partial(_exact, str))
]

NativeFlag = Annotated[
    Literal["error", "complete", "incomplete", "does not exist", "not collected", "not applicable"],
    BeforeValidator(partial(_exact, str)),
]

NativeStatus = Annotated[
    Literal["error", "exists", "does not exist", "not collected"], BeforeValidator(partial(_exact, str))
]

SourceRole = Annotated[
    Literal[
        "document_compilation",
        "assessment_start",
        "assessment_completion",
        "rule_completion",
        "override_time",
        "tailoring_version_time",
    ],
    BeforeValidator(partial(_exact, str)),
]

TimeNormalization = Annotated[
    Literal[
        "normalized", "timezone_missing", "precision_unsupported", "range_unsupported", "normalization_unsupported"
    ],
    BeforeValidator(partial(_exact, str)),
]

TimeScope = Annotated[
    Literal["document", "embedded_definitions", "selected_assessment", "system_characteristics"],
    BeforeValidator(partial(_exact, str)),
]

QualificationReason = Annotated[
    Literal[
        "native_completion_absent",
        "native_completion_timezone_missing",
        "native_completion_precision_unsupported",
        "native_completion_range_unsupported",
        "native_completion_normalization_unsupported",
        "native_completion_future",
        "native_start_unresolved",
        "native_completion_before_start",
    ],
    BeforeValidator(partial(_exact, str)),
]

CadenceReason = Annotated[
    Literal["no_selected_outcome_evidence", "selected_outcomes_not_evaluated"], BeforeValidator(partial(_exact, str))
]

CompletionState = Annotated[
    Literal["native_qualified", "operator_qualified", "unqualified"], BeforeValidator(partial(_exact, str))
]

CompletionBasis = Annotated[
    Literal["native_reported", "operator_asserted", "none"], BeforeValidator(partial(_exact, str))
]

DirectiveContent = Annotated[Literal["full", "thin"], BeforeValidator(partial(_exact, str))]

AssessmentTitle = Annotated[
    Literal["Imported XCCDF assessment", "Imported OVAL assessment"], BeforeValidator(partial(_exact, str))
]

FindingResourceType = Annotated[Literal["scap-assessment-occurrence"], BeforeValidator(partial(_exact, str))]

NodeIndex = Annotated[int, BeforeValidator(partial(_integer, 0, 32767)), Field(ge=0, le=32767)]

AttributeIndex = Annotated[int, BeforeValidator(partial(_integer, 0, 63)), Field(ge=0, le=63)]

AssessmentIndex = Annotated[int, BeforeValidator(partial(_integer, 0, 255)), Field(ge=0, le=255)]

UnitCount = Annotated[int, BeforeValidator(partial(_integer, 0, 256)), Field(ge=0, le=256)]

OutcomeIndex = Annotated[int, BeforeValidator(partial(_integer, 0, 9999)), Field(ge=0, le=9999)]

OutcomeCount = Annotated[int, BeforeValidator(partial(_integer, 0, 10000)), Field(ge=0, le=10000)]

NodeCount = Annotated[int, BeforeValidator(partial(_integer, 0, 32768)), Field(ge=0, le=32768)]

RawByteCount = Annotated[int, BeforeValidator(partial(_integer, 1, 8388608)), Field(ge=1, le=8388608)]

SourceTag = Annotated[Literal["scap", "xccdf", "oval"], BeforeValidator(partial(_exact, str))]

QualifiedBasis = Annotated[Literal["native_reported", "operator_asserted"], BeforeValidator(partial(_exact, str))]

ArtifactAvailabilityState = Annotated[Literal["available", "unavailable"], BeforeValidator(partial(_exact, str))]

CadenceState = Annotated[Literal["not_requested", "linked", "ineligible"], BeforeValidator(partial(_exact, str))]

ActorBasis = Annotated[Literal["caller_declared", "api_authenticated"], BeforeValidator(partial(_exact, str))]

ScapErrorCode = Annotated[
    Literal[
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
    ],
    BeforeValidator(partial(_exact, str)),
]

ScapErrorMessage = Annotated[
    Literal[
        "Invalid SCAP import options.",
        "Unsupported SCAP source profile.",
        "The selected assessment occurrence is unavailable.",
        "Invalid SCAP completion assertion.",
        "The completion assertion does not match the selected source.",
        "A completion assertion is not permitted for this source.",
        "The asserted completion time is not eligible.",
        "The XML input is not permitted.",
        "The XML input is malformed.",
        "The input does not satisfy the selected SCAP source contract.",
        "The complete source could not be read.",
        "The source exceeds a SCAP import limit.",
        "The complete result exceeds a SCAP publication limit.",
        "The source media type or encoding is not supported.",
        "The SCAP collector is unavailable.",
        "The optional SCAP XML support is unavailable.",
        "SCAP import support failed.",
        "The SCAP result could not be validated.",
        "The SCAP import deadline was exceeded.",
        "The complete SCAP result could not be published.",
        "No eligible evidence artifact is available for this import.",
    ],
    BeforeValidator(partial(_exact, str)),
]

DiagnosticCode = Annotated[
    Literal[
        "source_authenticity_unverified",
        "source_population_not_established",
        "complete_schema_validation_not_performed",
        "platform_validation_not_performed",
        "findings_are_summary_only",
        "signature_unverified",
        "partial_export_detail",
        "uninterpreted_content_preserved",
        "operator_completion_asserted",
        "native_completion_absent",
        "native_completion_timezone_missing",
        "native_completion_precision_unsupported",
        "native_completion_range_unsupported",
        "native_completion_normalization_unsupported",
        "native_completion_future",
        "native_start_unresolved",
        "native_completion_before_start",
        "no_selected_outcome_evidence",
        "selected_outcomes_not_evaluated",
    ],
    BeforeValidator(partial(_exact, str)),
]

DiagnosticMessage = Annotated[
    Literal[
        "Source authenticity was not verified.",
        "The source does not establish complete scanner population coverage.",
        "Complete schema validation was not performed.",
        "OVAL platform validation was not performed.",
        "The finding summarizes one selected assessment; native outcomes are retained separately.",
        "A source signature is present and was not verified.",
        "The declared OVAL export detail includes thin output.",
        "Native content outside the interpreted core is preserved.",
        "Assessment completion is an explicit operator assertion.",
        "No native assessment completion time is available.",
        "The native completion time has no timezone.",
        "The native completion precision cannot be represented exactly.",
        "The native completion time is outside the supported range.",
        "The native completion time cannot be normalized under the admitted policy.",
        "The native completion is later than the import start.",
        "The native assessment start cannot be compared exactly.",
        "The native completion precedes the native assessment start.",
        "The selected assessment contains no top-level outcome evidence.",
        "The selected assessment contains only unevaluated top-level outcomes.",
    ],
    BeforeValidator(partial(_exact, str)),
]

NativeValueSlot = Annotated[
    Literal["text", "attribute_value", "element_simple_content"], BeforeValidator(partial(_exact, str))
]


class ExpandedName(ClosedModel):
    canonical_limit: ClassVar[int | None] = 5242880
    namespace_uri: NamespaceUri
    local_name: LocalName


class NamespaceDeclaration(ClosedModel):
    canonical_limit: ClassVar[int | None] = 5242880
    prefix: NamespacePrefix
    namespace_uri: NamespaceUri


class XmlAttribute(ClosedModel):
    canonical_limit: ClassVar[int | None] = 5242880
    name: ExpandedName
    value: SourceText


class XmlDeclaration(ClosedModel):
    canonical_limit: ClassVar[int | None] = 5242880
    version: Annotated[Literal["1.0"], BeforeValidator(partial(_literal, "1.0"))]
    encoding: EncodingName | None
    standalone: Annotated[Literal["yes", "no"], BeforeValidator(partial(_exact, str))] | None


class XmlElement(ClosedModel):
    canonical_limit: ClassVar[int | None] = 5242880
    kind: Literal["element"]
    name: ExpandedName
    namespace_declarations: Annotated[
        list[NamespaceDeclaration], BeforeValidator(partial(_sequence, 0, 64)), Field(min_length=0, max_length=64)
    ]
    attributes: Annotated[
        list[XmlAttribute], BeforeValidator(partial(_sequence, 0, 64)), Field(min_length=0, max_length=64)
    ]
    text: SourceText | None
    tail: SourceText | None
    children: Annotated[
        list[NodeIndex], BeforeValidator(partial(_sequence, 0, 32768)), Field(min_length=0, max_length=32768)
    ]


class XmlComment(ClosedModel):
    canonical_limit: ClassVar[int | None] = 5242880
    kind: Literal["comment"]
    data: SourceText
    tail: SourceText | None


class XmlPI(ClosedModel):
    canonical_limit: ClassVar[int | None] = 5242880
    kind: Literal["processing_instruction"]
    target: PIName
    data: SourceText
    tail: SourceText | None


NativeNode = Annotated[XmlElement | XmlComment | XmlPI, Field(discriminator="kind"), BeforeValidator(_object)]


class NativeDocument(ClosedModel):
    canonical_limit: ClassVar[int | None] = 5242880
    declaration: XmlDeclaration | None
    text: SourceText | None
    children: Annotated[
        list[NodeIndex], BeforeValidator(partial(_sequence, 1, 32768)), Field(min_length=1, max_length=32768)
    ]
    nodes: Annotated[
        list[NativeNode], BeforeValidator(partial(_sequence, 1, 32768)), Field(min_length=1, max_length=32768)
    ]


class NativeValueRef(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    node_index: NodeIndex
    slot: NativeValueSlot
    attribute_index: AttributeIndex | None


class SourceBinding(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    sha256: Sha256
    bytes: RawByteCount
    profile: SourceProfile
    projection_version: Annotated[
        Literal["scap-native-document-v1"], BeforeValidator(partial(_literal, "scap-native-document-v1"))
    ]


class AssessmentUnit(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    assessment_index: AssessmentIndex
    unit_kind: UnitKind
    node_index: NodeIndex


class AssessmentSelection(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    assessment_index: AssessmentIndex
    unit_kind: UnitKind
    node_index: NodeIndex


class OutcomeOccurrence(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    unit_node_index: NodeIndex
    node_index: NodeIndex
    level: OutcomeLevel
    value_ref: NativeValueRef
    native_result: NativeOutcome


class NormalizedSourceTime(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    state: TimeNormalization
    utc: UtcText | None


class SourceTimeObservation(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    scope_node_index: NodeIndex
    scope: TimeScope
    role: SourceRole
    value_ref: NativeValueRef
    normalization: NormalizedSourceTime


class DefaultedBoolean(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    present: Boolean
    value_ref: NativeValueRef | None
    effective_value: Boolean


class DefaultedContent(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    present: Boolean
    value_ref: NativeValueRef | None
    effective_value: DirectiveContent


class DirectiveRule(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    node_index: NodeIndex
    outcome: OvalOutcome
    reported: DefaultedBoolean
    content: DefaultedContent


class ClassDirectives(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    node_index: NodeIndex
    class_ref: NativeValueRef
    definition_class: OvalClass
    rules: Annotated[list[DirectiveRule], BeforeValidator(partial(_sequence, 6, 6)), Field(min_length=6, max_length=6)]


class OvalDirectiveProjection(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    node_index: NodeIndex
    include_source_definitions: DefaultedBoolean
    embedded_definitions_node_index: NodeIndex | None
    default_rules: Annotated[
        list[DirectiveRule], BeforeValidator(partial(_sequence, 6, 6)), Field(min_length=6, max_length=6)
    ]
    class_rules: Annotated[
        list[ClassDirectives], BeforeValidator(partial(_sequence, 0, 5)), Field(min_length=0, max_length=5)
    ]


class NativeCollectionFlag(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    object_node_index: NodeIndex
    value_ref: NativeValueRef
    native_flag: NativeFlag


class OutcomeCountRow(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    level: OutcomeLevel
    native_result: NativeOutcome
    count: OutcomeCount


class CoverageProjection(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    scope: Annotated[
        Literal["selected_assessment_native_projection"],
        BeforeValidator(partial(_literal, "selected_assessment_native_projection")),
    ]
    selected_node_index: NodeIndex
    visible_unit_count: UnitCount
    selected_unit_count: Annotated[Literal[1], BeforeValidator(partial(_literal, 1))]
    unselected_unit_count: UnitCount
    visible_outcome_count: OutcomeCount
    selected_outcome_count: OutcomeCount
    top_level_outcome_count: OutcomeCount
    countable_top_level_outcome_count: OutcomeCount
    outcome_counts: Annotated[
        list[OutcomeCountRow], BeforeValidator(partial(_sequence, 9, 36)), Field(min_length=9, max_length=36)
    ]
    native_export_detail: Annotated[
        Literal["not_applicable", "full", "thin", "mixed", "no_reported_rules"], BeforeValidator(partial(_exact, str))
    ]
    oval_directives: OvalDirectiveProjection | None
    collection_flags: Annotated[
        list[NativeCollectionFlag], BeforeValidator(partial(_sequence, 0, 32768)), Field(min_length=0, max_length=32768)
    ]
    uninterpreted_node_count: NodeCount
    signature_node_indices: Annotated[
        list[NodeIndex], BeforeValidator(partial(_sequence, 0, 32768)), Field(min_length=0, max_length=32768)
    ]
    source_population_complete: Annotated[
        Literal["not_established"], BeforeValidator(partial(_literal, "not_established"))
    ]
    schema_validation: Annotated[
        Literal["bounded_core_profile_rules"], BeforeValidator(partial(_literal, "bounded_core_profile_rules"))
    ]
    complete_schema_validation: Annotated[Literal["not_performed"], BeforeValidator(partial(_literal, "not_performed"))]
    platform_validation: Annotated[Literal["not_performed"], BeforeValidator(partial(_literal, "not_performed"))]
    signature_verification: Annotated[Literal["not_performed"], BeforeValidator(partial(_literal, "not_performed"))]
    producer_interoperability: Annotated[
        Literal["not_established"], BeforeValidator(partial(_literal, "not_established"))
    ]
    cadence_evidence: Annotated[Literal["countable", "empty", "not_evaluated"], BeforeValidator(partial(_exact, str))]
    status_observations: Annotated[
        list[UnverifiedPlatformStatus],
        BeforeValidator(partial(_sequence, 0, 32768)),
        Field(min_length=0, max_length=32768),
    ]
    core_status_defaults: Annotated[
        list[CoreStatusDefault], BeforeValidator(partial(_sequence, 0, 32768)), Field(min_length=0, max_length=32768)
    ]


class ScapFindingIdentityFrame(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    schema_version: Annotated[
        Literal["scap-finding-identity-v1"], BeforeValidator(partial(_literal, "scap-finding-identity-v1"))
    ]
    source_sha256: Sha256
    source_profile: SourceProfile
    assessment_index: AssessmentIndex
    unit_node_index: NodeIndex
    mapping_rule_id: Annotated[
        Literal["scap-assessment-summary-v1"], BeforeValidator(partial(_literal, "scap-assessment-summary-v1"))
    ]


class FindingReference(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    node_index: NodeIndex
    mapping_rule_id: Annotated[
        Literal["scap-assessment-summary-v1"], BeforeValidator(partial(_literal, "scap-assessment-summary-v1"))
    ]
    source_key_sha256: Sha256
    finding_id: Uuid5


class AssessmentProjection(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    selection: AssessmentSelection
    units: Annotated[
        list[AssessmentUnit], BeforeValidator(partial(_sequence, 1, 256)), Field(min_length=1, max_length=256)
    ]
    outcomes: Annotated[
        list[OutcomeOccurrence], BeforeValidator(partial(_sequence, 0, 10000)), Field(min_length=0, max_length=10000)
    ]
    times: Annotated[
        list[SourceTimeObservation],
        BeforeValidator(partial(_sequence, 0, 10000)),
        Field(min_length=0, max_length=10000),
    ]
    coverage: CoverageProjection
    uninterpreted_roots: Annotated[
        list[NodeIndex], BeforeValidator(partial(_sequence, 0, 32768)), Field(min_length=0, max_length=32768)
    ]
    finding_refs: Annotated[
        list[FindingReference], BeforeValidator(partial(_sequence, 1, 1)), Field(min_length=1, max_length=1)
    ]


class CompletionAssertionInput(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2048
    schema_version: Annotated[
        Literal["scap-completion-assertion-v1"], BeforeValidator(partial(_literal, "scap-completion-assertion-v1"))
    ]
    source_sha256: Sha256
    source_profile: OvalProfile
    assessment_index: AssessmentIndex
    completed_at: ClaimUtcText
    reference: OperatorReference


class AssertionActor(ClosedModel):
    canonical_limit: ClassVar[int | None] = 4096
    basis: ActorBasis
    subject: ActorLabel
    provider: ActorLabel | None


class StableCompletionAssertion(ClosedModel):
    canonical_limit: ClassVar[int | None] = 4096
    schema_version: Annotated[
        Literal["scap-completion-assertion-v1"], BeforeValidator(partial(_literal, "scap-completion-assertion-v1"))
    ]
    source_sha256: Sha256
    source_profile: OvalProfile
    assessment_index: AssessmentIndex
    completed_at: ClaimUtcText
    reference: OperatorReference
    normalized_utc: UtcText
    basis: Annotated[Literal["operator_asserted"], BeforeValidator(partial(_literal, "operator_asserted"))]
    actor: AssertionActor


class CompletionProjection(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    state: CompletionState
    basis: CompletionBasis
    utc: UtcText | None
    native_ref: NativeValueRef | None
    assertion: StableCompletionAssertion | None
    qualification_reasons: Annotated[
        list[QualificationReason], BeforeValidator(partial(_sequence, 0, 8)), Field(min_length=0, max_length=8)
    ]


class StableArtifactCompletion(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    basis: QualifiedBasis
    utc: UtcText
    native_ref: NativeValueRef | None
    assertion: StableCompletionAssertion | None


class ArtifactAvailability(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    state: ArtifactAvailabilityState
    reasons: Annotated[
        list[QualificationReason], BeforeValidator(partial(_sequence, 0, 8)), Field(min_length=0, max_length=8)
    ]


class CadenceProjection(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    state: CadenceState
    requested_slug: CadenceSlug | None
    linked_slug: CadenceSlug | None
    reasons: Annotated[
        list[QualificationReason | CadenceReason],
        BeforeValidator(partial(_sequence, 0, 10)),
        Field(min_length=0, max_length=10),
    ]


class ScapImportRequest(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    source_profile: SourceProfile
    assessment_index: AssessmentIndex
    cadence_slug: CadenceSlug | None
    completion_assertion: CompletionAssertionInput | None


class RunMetadata(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    run_id: RunId
    collector_version: VersionLabel
    evidentia_version: VersionLabel
    finished_at: UtcRuntime


class FactoryInputs(ClosedModel):
    canonical_limit: ClassVar[int | None] = None
    raw: RawBytes
    request: ScapImportRequest
    native_document: NativeDocument
    assessment: AssessmentProjection
    imported_at: UtcRuntime
    deadline: MonotonicDeadline
    actor: AssertionActor | None
    run_metadata: RunMetadata


class ScapDiagnostic(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    code: DiagnosticCode
    severity: Annotated[Literal["advisory"], BeforeValidator(partial(_literal, "advisory"))]
    message: DiagnosticMessage
    node_index: Annotated[None, BeforeValidator(partial(_literal, None))]


Diagnostic = ScapDiagnostic


class ScapAssessmentSummary(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    schema_version: Annotated[
        Literal["scap-assessment-summary-v1"], BeforeValidator(partial(_literal, "scap-assessment-summary-v1"))
    ]
    source: SourceBinding
    selection: AssessmentSelection
    visible_unit_count: UnitCount
    selected_outcome_count: OutcomeCount
    top_level_outcome_count: OutcomeCount
    countable_top_level_outcome_count: OutcomeCount
    summary_only: Annotated[Literal[True], BeforeValidator(partial(_literal, True))]
    source_key_sha256: Sha256


class ScapImportFilter(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    source_profile: SourceProfile
    source_sha256: Sha256
    assessment_index: AssessmentIndex
    selected_node_index: NodeIndex
    scope: Annotated[
        Literal["selected_assessment_native_projection"],
        BeforeValidator(partial(_literal, "selected_assessment_native_projection")),
    ]
    time_basis: Annotated[
        Literal["file_import_observation"], BeforeValidator(partial(_literal, "file_import_observation"))
    ]


class ScapCollectionContext(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    collector_id: Annotated[Literal["scap"], BeforeValidator(partial(_literal, "scap"))]
    collector_version: VersionLabel
    run_id: RunId
    collected_at: UtcText
    credential_identity: Annotated[Literal["not-established"], BeforeValidator(partial(_literal, "not-established"))]
    source_system_id: SourceSystemId
    filter_applied: ScapImportFilter
    pagination_context: Annotated[None, BeforeValidator(partial(_literal, None))]
    evidentia_version: VersionLabel


CollectionContext = ScapCollectionContext


class ScapSecurityFinding(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    id: Uuid5
    title: AssessmentTitle
    description: Annotated[
        Literal[
            "One selected assessment was imported. Native outcomes remain in the full SCAP "
            "result and any evidence artifact; this summary makes no vulnerability or "
            "compliance conclusion."
        ],
        BeforeValidator(
            partial(
                _literal,
                "One selected assessment was imported. Native outcomes remain in the full SCAP "
                "result and any evidence artifact; this summary makes no vulnerability or "
                "compliance conclusion.",
            )
        ),
    ]
    severity: Annotated[Literal["informational"], BeforeValidator(partial(_literal, "informational"))]
    status: Annotated[Literal["active"], BeforeValidator(partial(_literal, "active"))]
    compliance_status: Annotated[Literal["unknown"], BeforeValidator(partial(_literal, "unknown"))]
    remediation: Annotated[None, BeforeValidator(partial(_literal, None))]
    source_system: SourceSystem
    source_finding_id: Annotated[None, BeforeValidator(partial(_literal, None))]
    resource_type: FindingResourceType
    resource_id: Annotated[None, BeforeValidator(partial(_literal, None))]
    resource_region: Annotated[None, BeforeValidator(partial(_literal, None))]
    resource_account: Annotated[None, BeforeValidator(partial(_literal, None))]
    control_mappings: Annotated[
        list[Annotated[None, BeforeValidator(partial(_literal, None))]],
        BeforeValidator(partial(_sequence, 0, 0)),
        Field(min_length=0, max_length=0),
    ]
    collection_context: CollectionContext
    raw_data: ScapAssessmentSummary
    first_observed: UtcText
    last_observed: UtcText
    resolved_at: Annotated[None, BeforeValidator(partial(_literal, None))]


SecurityFinding = ScapSecurityFinding


class ScapCoverageCount(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    resource_type: Annotated[
        Literal["scap-assessment-occurrence"], BeforeValidator(partial(_literal, "scap-assessment-occurrence"))
    ]
    scanned: UnitCount
    matched_filter: Annotated[Literal[1], BeforeValidator(partial(_literal, 1))]
    collected: Annotated[Literal[1], BeforeValidator(partial(_literal, 1))]


CoverageCount = ScapCoverageCount


class ScapCollectionManifest(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    run_id: RunId
    collector_id: Annotated[Literal["scap"], BeforeValidator(partial(_literal, "scap"))]
    collector_version: VersionLabel
    collection_started_at: UtcText
    collection_finished_at: UtcText
    source_system_ids: Annotated[
        list[SourceSystemId], BeforeValidator(partial(_sequence, 1, 1)), Field(min_length=1, max_length=1)
    ]
    filters_applied: ScapImportFilter
    coverage_counts: Annotated[
        list[CoverageCount], BeforeValidator(partial(_sequence, 1, 1)), Field(min_length=1, max_length=1)
    ]
    total_findings: Annotated[Literal[1], BeforeValidator(partial(_literal, 1))]
    is_complete: Annotated[Literal[True], BeforeValidator(partial(_literal, True))]
    incomplete_reason: Annotated[None, BeforeValidator(partial(_literal, None))]
    empty_categories: Annotated[
        list[Annotated[None, BeforeValidator(partial(_literal, None))]],
        BeforeValidator(partial(_sequence, 0, 0)),
        Field(min_length=0, max_length=0),
    ]
    warnings: Annotated[
        list[DiagnosticMessage], BeforeValidator(partial(_sequence, 0, 19)), Field(min_length=0, max_length=19)
    ]
    errors: Annotated[
        list[Annotated[None, BeforeValidator(partial(_literal, None))]],
        BeforeValidator(partial(_sequence, 0, 0)),
        Field(min_length=0, max_length=0),
    ]
    evidentia_version: VersionLabel


CollectionManifest = ScapCollectionManifest


class UnlinkedArtifactMetadata(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    scap_contract: Annotated[Literal["scap-evidence-v1"], BeforeValidator(partial(_literal, "scap-evidence-v1"))]
    source_sha256: Sha256
    source_profile: SourceProfile
    assessment_index: AssessmentIndex
    time_basis: QualifiedBasis


class LinkedArtifactMetadata(ClosedModel):
    canonical_limit: ClassVar[int | None] = 524288
    scap_contract: Annotated[Literal["scap-evidence-v1"], BeforeValidator(partial(_literal, "scap-evidence-v1"))]
    source_sha256: Sha256
    source_profile: SourceProfile
    assessment_index: AssessmentIndex
    time_basis: QualifiedBasis
    cadence_slug: CadenceSlug


ArtifactMetadata = UnlinkedArtifactMetadata | LinkedArtifactMetadata


class ScapEvidenceContent(ClosedModel):
    canonical_limit: ClassVar[int | None] = 16777216
    schema_version: Annotated[Literal["scap-evidence-v1"], BeforeValidator(partial(_literal, "scap-evidence-v1"))]
    source: SourceBinding
    native_document: NativeDocument
    assessment: AssessmentProjection
    completion: StableArtifactCompletion


class ScapEvidenceArtifact(ClosedModel):
    canonical_limit: ClassVar[int | None] = 16777216
    id: Uuid5
    title: AssessmentTitle
    description: Annotated[
        Literal[
            "Native source observations with disclosed completion provenance; no authenticity, "
            "completeness or compliance conclusion."
        ],
        BeforeValidator(
            partial(
                _literal,
                "Native source observations with disclosed completion provenance; no authenticity, "
                "completeness or compliance conclusion.",
            )
        ),
    ]
    evidence_type: Annotated[Literal["test_result"], BeforeValidator(partial(_literal, "test_result"))]
    source_system: SourceSystem
    collected_at: UtcText
    collected_by: Annotated[Literal["evidentia-scap-v1"], BeforeValidator(partial(_literal, "evidentia-scap-v1"))]
    content: ScapEvidenceContent
    content_hash: Sha256
    content_format: Annotated[Literal["json"], BeforeValidator(partial(_literal, "json"))]
    file_path: Annotated[None, BeforeValidator(partial(_literal, None))]
    file_size_bytes: Annotated[None, BeforeValidator(partial(_literal, None))]
    control_mappings: Annotated[
        list[Annotated[None, BeforeValidator(partial(_literal, None))]],
        BeforeValidator(partial(_sequence, 0, 0)),
        Field(min_length=0, max_length=0),
    ]
    sufficiency: Annotated[Literal["unknown"], BeforeValidator(partial(_literal, "unknown"))]
    sufficiency_rationale: Annotated[None, BeforeValidator(partial(_literal, None))]
    missing_elements: Annotated[
        list[Annotated[None, BeforeValidator(partial(_literal, None))]],
        BeforeValidator(partial(_sequence, 0, 0)),
        Field(min_length=0, max_length=0),
    ]
    validator_confidence: Annotated[None, BeforeValidator(partial(_literal, None))]
    validated_at: Annotated[None, BeforeValidator(partial(_literal, None))]
    validated_by: Annotated[None, BeforeValidator(partial(_literal, None))]
    expires_at: Annotated[None, BeforeValidator(partial(_literal, None))]
    tags: Annotated[list[SourceTag], BeforeValidator(partial(_sequence, 2, 2)), Field(min_length=2, max_length=2)]
    metadata: ArtifactMetadata
    version: Annotated[Literal[1], BeforeValidator(partial(_literal, 1))]
    lineage_id: Annotated[None, BeforeValidator(partial(_literal, None))]
    predecessor_id: Annotated[None, BeforeValidator(partial(_literal, None))]


EvidenceArtifact = ScapEvidenceArtifact


class ArtifactWithoutId(ClosedModel):
    canonical_limit: ClassVar[int | None] = 16777216
    title: AssessmentTitle
    description: Annotated[
        Literal[
            "Native source observations with disclosed completion provenance; no authenticity, "
            "completeness or compliance conclusion."
        ],
        BeforeValidator(
            partial(
                _literal,
                "Native source observations with disclosed completion provenance; no authenticity, "
                "completeness or compliance conclusion.",
            )
        ),
    ]
    evidence_type: Annotated[Literal["test_result"], BeforeValidator(partial(_literal, "test_result"))]
    source_system: SourceSystem
    collected_at: UtcText
    collected_by: Annotated[Literal["evidentia-scap-v1"], BeforeValidator(partial(_literal, "evidentia-scap-v1"))]
    content: ScapEvidenceContent
    content_hash: Sha256
    content_format: Annotated[Literal["json"], BeforeValidator(partial(_literal, "json"))]
    file_path: Annotated[None, BeforeValidator(partial(_literal, None))]
    file_size_bytes: Annotated[None, BeforeValidator(partial(_literal, None))]
    control_mappings: Annotated[
        list[Annotated[None, BeforeValidator(partial(_literal, None))]],
        BeforeValidator(partial(_sequence, 0, 0)),
        Field(min_length=0, max_length=0),
    ]
    sufficiency: Annotated[Literal["unknown"], BeforeValidator(partial(_literal, "unknown"))]
    sufficiency_rationale: Annotated[None, BeforeValidator(partial(_literal, None))]
    missing_elements: Annotated[
        list[Annotated[None, BeforeValidator(partial(_literal, None))]],
        BeforeValidator(partial(_sequence, 0, 0)),
        Field(min_length=0, max_length=0),
    ]
    validator_confidence: Annotated[None, BeforeValidator(partial(_literal, None))]
    validated_at: Annotated[None, BeforeValidator(partial(_literal, None))]
    validated_by: Annotated[None, BeforeValidator(partial(_literal, None))]
    expires_at: Annotated[None, BeforeValidator(partial(_literal, None))]
    tags: Annotated[list[SourceTag], BeforeValidator(partial(_sequence, 2, 2)), Field(min_length=2, max_length=2)]
    metadata: ArtifactMetadata
    version: Annotated[Literal[1], BeforeValidator(partial(_literal, 1))]
    lineage_id: Annotated[None, BeforeValidator(partial(_literal, None))]
    predecessor_id: Annotated[None, BeforeValidator(partial(_literal, None))]


class ScapArtifactIdentityFrame(ClosedModel):
    canonical_limit: ClassVar[int | None] = 16777216
    schema_version: Annotated[
        Literal["scap-artifact-identity-v1"], BeforeValidator(partial(_literal, "scap-artifact-identity-v1"))
    ]
    artifact_without_id: ArtifactWithoutId


class ScapCollectionResult(ClosedModel):
    canonical_limit: ClassVar[int | None] = 16777216
    schema_version: Annotated[Literal["scap-collection-v1"], BeforeValidator(partial(_literal, "scap-collection-v1"))]
    status: Annotated[Literal["imported"], BeforeValidator(partial(_literal, "imported"))]
    source: SourceBinding
    imported_at: UtcText
    native_document: NativeDocument
    assessment: AssessmentProjection
    findings: Annotated[
        list[SecurityFinding], BeforeValidator(partial(_sequence, 1, 1)), Field(min_length=1, max_length=1)
    ]
    manifest: CollectionManifest
    completion: CompletionProjection
    evidence_artifact: EvidenceArtifact | None
    artifact_availability: ArtifactAvailability
    cadence: CadenceProjection
    diagnostics: Annotated[
        list[Diagnostic], BeforeValidator(partial(_sequence, 0, 19)), Field(min_length=0, max_length=19)
    ]


class ScapError(ClosedModel):
    canonical_limit: ClassVar[int | None] = 65536
    schema_version: Annotated[Literal["scap-error-v1"], BeforeValidator(partial(_literal, "scap-error-v1"))]
    code: ScapErrorCode
    message: ScapErrorMessage


class UnverifiedPlatformStatus(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    node_index: NodeIndex
    scope: Annotated[
        Literal["direct_system_data_child", "nested_platform_position"], BeforeValidator(partial(_exact, str))
    ]
    value_ref: NativeValueRef
    interpretation: Annotated[
        Literal["unverified_platform_status"], BeforeValidator(partial(_literal, "unverified_platform_status"))
    ]
    effective_status: Annotated[None, BeforeValidator(partial(_literal, None))]


class CoreStatusDefault(ClosedModel):
    canonical_limit: ClassVar[int | None] = 2097152
    node_index: NodeIndex
    present: Boolean
    value_ref: NativeValueRef | None
    effective_status: NativeStatus
    interpretation: Annotated[
        Literal["reviewed_5_8_core_ip_address_status"],
        BeforeValidator(partial(_literal, "reviewed_5_8_core_ip_address_status")),
    ]


_MODELS = (
    ExpandedName,
    NamespaceDeclaration,
    XmlAttribute,
    XmlDeclaration,
    XmlElement,
    XmlComment,
    XmlPI,
    NativeDocument,
    NativeValueRef,
    SourceBinding,
    AssessmentUnit,
    AssessmentSelection,
    OutcomeOccurrence,
    NormalizedSourceTime,
    SourceTimeObservation,
    DefaultedBoolean,
    DefaultedContent,
    DirectiveRule,
    ClassDirectives,
    OvalDirectiveProjection,
    NativeCollectionFlag,
    OutcomeCountRow,
    CoverageProjection,
    ScapFindingIdentityFrame,
    FindingReference,
    AssessmentProjection,
    CompletionAssertionInput,
    AssertionActor,
    StableCompletionAssertion,
    CompletionProjection,
    StableArtifactCompletion,
    ArtifactAvailability,
    CadenceProjection,
    ScapImportRequest,
    RunMetadata,
    FactoryInputs,
    Diagnostic,
    ScapAssessmentSummary,
    ScapImportFilter,
    CollectionContext,
    SecurityFinding,
    CoverageCount,
    CollectionManifest,
    UnlinkedArtifactMetadata,
    LinkedArtifactMetadata,
    ScapEvidenceContent,
    EvidenceArtifact,
    ArtifactWithoutId,
    ScapArtifactIdentityFrame,
    ScapCollectionResult,
    ScapError,
    UnverifiedPlatformStatus,
    CoreStatusDefault,
)
for _model in _MODELS:
    _model.model_rebuild()
