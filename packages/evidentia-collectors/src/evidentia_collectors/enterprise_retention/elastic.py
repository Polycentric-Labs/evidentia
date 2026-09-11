"""Selected Elasticsearch ILM configuration without document or execution claims."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from typing import cast

from ._client import (
    AuthorityError,
    EnterpriseReadSession,
    ParsedResponse,
    ProjectedPage,
    ProjectedRecord,
    ReadSubject,
)
from ._contracts import (
    CoverageState,
    ElasticIndexTarget,
    EnterpriseRetentionResourceResult,
    InterpretationCode,
    NativeScope,
    ReadKind,
)
from ._parsing import JsonObject

_TEXT = (str, type(None))
_INTEGER = (int, type(None))
_OBJECT = (dict, type(None))
_POLICY_NAME = re.compile(r"[A-Za-z0-9_.-]{1,255}")
_SOURCE_TIME = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.[0-9]+)?(?:[Zz]|[+-]([0-9]{2}):([0-9]{2}))"
)


@dataclass
class _Selection:
    fields: JsonObject = field(default_factory=dict)
    coverage: dict[str, CoverageState] = field(default_factory=dict)
    unknown: bool = False
    missing: bool = False

    def copy(
        self,
        source: JsonObject,
        name: str,
        allowed: tuple[type[object], ...],
        *,
        required: bool = False,
        nonnegative: bool = False,
    ) -> None:
        if name not in source:
            if required:
                raise AuthorityError()
            self.coverage[name] = "absent"
            self.missing = True
            return
        value = source[name]
        if type(value) not in allowed or (nonnegative and type(value) is int and value < 0):
            raise AuthorityError()
        self.fields[name] = value
        self.coverage[name] = "null" if value is None else "known"
        self.missing |= value is None

    def mark_unknown(self, name: str) -> None:
        self.coverage[name] = "unknown"
        self.unknown = True

    def child(self, name: str, child: _Selection) -> None:
        self.fields[name] = child.fields
        self.coverage[name] = "unknown" if child.unknown else "known"
        self.unknown |= child.unknown
        self.missing |= child.missing


def _object(value: object) -> JsonObject:
    if type(value) is not dict:
        raise AuthorityError()
    return cast(JsonObject, value)


def _input(response: ParsedResponse, subject: ReadSubject, kind: ReadKind) -> JsonObject:
    if type(response) is not ParsedResponse or type(subject) is not ReadSubject:
        raise AuthorityError()
    checked = ReadSubject(subject.kind, subject.source_id)
    if checked.kind != kind or type(response.status) is not int or response.status != 200:
        raise AuthorityError()
    return response.data


def _page(selected: _Selection, subject: ReadSubject, scope: NativeScope) -> ProjectedPage:
    diagnostics: list[InterpretationCode] = []
    if selected.unknown:
        diagnostics.append("unsupported_source_value")
    if selected.missing:
        diagnostics.append("missing_source_detail")
    return ProjectedPage(
        (
            ProjectedRecord(
                0,
                subject.source_id,
                scope,
                selected.fields,
                selected.coverage,
                tuple(diagnostics),
            ),
        )
    )


def _phase_definition(source: JsonObject) -> _Selection:
    # The phase configuration is an open subtree. Its extensions remain literal.
    selected = _Selection(fields=dict(source), unknown=any(key not in ("min_age", "actions") for key in source))
    selected.copy(source, "min_age", _TEXT)
    selected.copy(source, "actions", _OBJECT)
    return selected


def _phase_execution(source: JsonObject) -> _Selection:
    selected = _Selection()
    selected.copy(source, "policy", _TEXT)
    selected.copy(source, "version", _INTEGER, nonnegative=True)
    selected.copy(source, "modified_date_in_millis", _INTEGER, nonnegative=True)
    selected.copy(source, "phase_definition", _OBJECT)
    definition = selected.fields.get("phase_definition")
    if definition is not None:
        selected.child("phase_definition", _phase_definition(_object(definition)))
    return selected


def _current_policy(source: JsonObject) -> _Selection:
    selected = _Selection()
    selected.copy(source, "phases", _OBJECT)
    phases = selected.fields.get("phases")
    if phases is not None:
        projected = _Selection()
        for name, value in _object(phases).items():
            if value is None:
                projected.fields[name] = None
                projected.missing = True
            else:
                phase = _phase_definition(_object(value))
                projected.fields[name] = phase.fields
                projected.unknown |= phase.unknown
                projected.missing |= phase.missing
        selected.child("phases", projected)
    return selected


def _known_source_time(value: str) -> bool:
    match = _SOURCE_TIME.fullmatch(value)
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(match[index]) for index in range(1, 7))
    try:
        date(year, month, day)
    except ValueError:
        return False
    return (
        hour <= 23
        and minute <= 59
        and second <= 59
        and (match[7] is None or (int(match[7]) <= 23 and int(match[8]) <= 59))
    )


def project_status(response: ParsedResponse, subject: ReadSubject) -> ProjectedPage:
    """Retain the literal service state without inferring index protection."""
    source = _input(response, subject, "elastic-status")
    selected = _Selection()
    selected.copy(source, "operation_mode", _TEXT)
    mode = selected.fields.get("operation_mode")
    if mode is not None and mode not in ("RUNNING", "STOPPING", "STOPPED"):
        selected.mark_unknown("operation_mode")
    return _page(selected, subject, "service")


def project_explain(response: ParsedResponse, subject: ReadSubject) -> ProjectedPage:
    """Select one exact index and its separately cached phase configuration."""
    data = _input(response, subject, "elastic-explain")
    indices = _object(data.get("indices"))
    if tuple(indices) != (subject.source_id,):
        raise AuthorityError("identity_mismatch")
    source = _object(indices[subject.source_id])
    if type(source.get("index")) is not str or source["index"] != subject.source_id:
        raise AuthorityError("identity_mismatch")
    selected = _Selection()
    selected.copy(source, "index", (str,), required=True)
    selected.copy(source, "managed", (bool,), required=True)
    for name in ("policy", "phase", "action", "step", "failed_step"):
        selected.copy(source, name, _TEXT)
    policy = selected.fields.get("policy")
    if isinstance(policy, str) and (
        _POLICY_NAME.fullmatch(policy) is None or policy in (".", "..") or policy.lower() == "_all"
    ):
        selected.mark_unknown("policy")
    for name in (
        "index_creation_date_millis",
        "lifecycle_date_millis",
        "phase_time_millis",
        "action_time_millis",
        "step_time_millis",
    ):
        selected.copy(source, name, _INTEGER, nonnegative=True)
    selected.copy(source, "phase_execution", _OBJECT)
    execution = selected.fields.get("phase_execution")
    if execution is not None:
        selected.child("phase_execution", _phase_execution(_object(execution)))
    return _page(selected, subject, "index")


def project_policy(response: ParsedResponse, subject: ReadSubject) -> ProjectedPage:
    """Select the authorized current policy, independently of cached explain data."""
    data = _input(response, subject, "elastic-policy")
    if tuple(data) != (subject.source_id,):
        raise AuthorityError("identity_mismatch")
    source = _object(data[subject.source_id])
    selected = _Selection()
    selected.copy(source, "version", _INTEGER, nonnegative=True)
    selected.copy(source, "modified_date", (str, int, type(None)))
    modified = selected.fields.get("modified_date")
    if isinstance(modified, str) and not _known_source_time(modified):
        selected.mark_unknown("modified_date")
    selected.copy(source, "policy", _OBJECT)
    policy = selected.fields.get("policy")
    if policy is not None:
        selected.child("policy", _current_policy(_object(policy)))
    return _page(selected, subject, "policy")


def read_elastic(
    target: ElasticIndexTarget, session: EnterpriseReadSession
) -> EnterpriseRetentionResourceResult[ElasticIndexTarget]:
    """Read selected ILM configuration through session-issued source handles."""
    status = session.read_elastic_status(project_status)
    explain = session.read_elastic_explain(target, project_explain)
    policy = session.read_elastic_policy(target, explain, project_policy)
    reads = (explain, status) if policy is None else (explain, policy, status)
    return cast(EnterpriseRetentionResourceResult[ElasticIndexTarget], session.finish_resource(target, reads=reads))
