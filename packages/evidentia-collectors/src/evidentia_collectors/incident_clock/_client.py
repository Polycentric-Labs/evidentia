"""Own incident read authority and retain immutable admitted source snapshots."""

from __future__ import annotations

import hashlib
import re
import time
import weakref
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.metadata import version
from typing import TYPE_CHECKING, Any, Literal, NamedTuple, Never, cast, get_args

from evidentia_core.audit.provenance import new_run_id

from . import _contracts as contract
from ._credentials import CredentialError, CredentialMaterial, resolve_material
from ._http import HTTPReceipt, TransferBudget, get_identity
from ._parsing import ParsingError, canonical_json, parse_strict_json, result_json_bytes
from ._profiles import AuthorizedSelection, _selection

if TYPE_CHECKING:
    from ._contracts import CredentialValidity, Diagnostic, SelectedRecordProjection, SourceEvent, SourceRead


class IncidentReadError(ValueError):
    def __init__(self) -> None:
        super().__init__("collector_failed")


class _RunSeed:
    __slots__ = ("__weakref__",)

    def __new__(cls) -> _RunSeed:
        raise IncidentReadError()

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("immutable_run_seed")

    def __repr__(self) -> str:
        return "RunSeed(<bound>)"

    def __reduce__(self) -> Never:
        raise TypeError("runtime_only_run")


class _SeedData(NamedTuple):
    selection: AuthorizedSelection
    run_id: str
    collector_version: str
    core_version: str
    started_at: datetime
    deadline: float


_SEEDS: weakref.WeakKeyDictionary[_RunSeed, _SeedData] = weakref.WeakKeyDictionary()


def _new_seed(selection: AuthorizedSelection) -> _RunSeed:
    _selection(selection)
    started = time.monotonic()
    started_at = datetime.now(UTC)
    collector_version, core_version = version("evidentia-collectors"), version("evidentia-core")
    run_id = new_run_id()
    if any(
        type(value) is not str or re.fullmatch(r"[0-9][A-Za-z0-9.+_-]{0,63}", value) is None
        for value in (collector_version, core_version)
    ):
        raise IncidentReadError()
    if type(run_id) is not str or re.fullmatch(r"[0-7][0-9A-HJKMNP-TV-Z]{25}", run_id) is None:
        raise IncidentReadError()
    seed = object.__new__(_RunSeed)
    _SEEDS[seed] = _SeedData(selection, run_id, collector_version, core_version, started_at, started + 60.0)
    return seed


def _seed(value: object) -> _SeedData:
    if type(value) is not _RunSeed:
        raise IncidentReadError()
    data = _SEEDS.get(value)
    if data is None:
        raise IncidentReadError()
    return data


class RunAuthority:
    """Identify a sealed source snapshot; caller values cannot construct one."""

    __slots__ = ("__weakref__",)

    def __new__(cls) -> RunAuthority:
        raise IncidentReadError()

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("immutable_run_authority")

    def __repr__(self) -> str:
        return "RunAuthority(<sealed>)"

    def __reduce__(self) -> Never:
        raise TypeError("runtime_only_authority")


_AUTHORITIES: weakref.WeakKeyDictionary[RunAuthority, tuple[bytes, float]] = weakref.WeakKeyDictionary()


def _issue_authority(
    seed: _RunSeed,
    *,
    credential_validity: CredentialValidity,
    reads: list[SourceRead],
    record: SelectedRecordProjection | None,
    events: list[SourceEvent],
    diagnostics: list[Diagnostic],
) -> RunAuthority:
    from ._contracts import _json_values, _RunSnapshot, _source_checks
    from ._parsing import result_json_bytes

    data = _seed(seed)
    if time.monotonic() >= data.deadline:
        raise IncidentReadError()
    selected = data.selection
    snapshot = _RunSnapshot.model_validate(
        {
            "request": selected.request,
            "definition": selected.definition,
            "profile_binding_sha256": selected.profile_binding_sha256,
            "run_id": data.run_id,
            "collector_version": data.collector_version,
            "core_version": data.core_version,
            "started_at": data.started_at,
            "finished_at": datetime.now(UTC),
            "credential_validity": credential_validity,
            "reads": reads,
            "record": record,
            "events": events,
            "diagnostics": diagnostics,
        }
    )
    _source_checks(snapshot)
    content = result_json_bytes(_json_values(snapshot))
    if time.monotonic() >= data.deadline:
        raise IncidentReadError()
    authority = object.__new__(RunAuthority)
    _AUTHORITIES[authority] = (content, data.deadline)
    return authority


def authority_snapshot(value: object) -> bytes:
    if type(value) is not RunAuthority:
        raise IncidentReadError()
    stored = _AUTHORITIES.get(value)
    if stored is None or time.monotonic() >= stored[1]:
        raise IncidentReadError()
    return stored[0]


# Leave time inside the 60-second run budget for source sealing and publication.
_PUBLICATION_RESERVE_SECONDS = 10.0


class _AdmissionFailure(ValueError):
    def __init__(self, code: contract.DiagnosticCode = "source_shape") -> None:
        self.code = code
        super().__init__(code)


@dataclass(slots=True)
class _SessionData:
    seed: _RunSeed
    material: CredentialMaterial | None
    validity: contract.CredentialValidity
    budget: TransferBudget = field(default_factory=TransferBudget)
    reads: list[contract.SourceRead] = field(default_factory=list)
    record: contract.SelectedRecordProjection | None = None
    events: list[contract.SourceEvent] = field(default_factory=list)
    diagnostics: list[contract.Diagnostic] = field(default_factory=list)
    occurrences: dict[str, bytes] = field(default_factory=dict)
    histories: dict[str, bytes] = field(default_factory=dict)
    cursor: int = 0
    total: int | None = None
    history_pages: int = 0
    history_records: int = 0
    record_attempted: bool = False
    terminal: bool = False
    stopped: bool = False
    closed: bool = False
    authority: RunAuthority | None = None


class _PageData(NamedTuple):
    accepted: bool
    terminal: bool
    next_start: int | None
    read_id: str | None


_PAGES: weakref.WeakKeyDictionary[AdmittedPage, _PageData] = weakref.WeakKeyDictionary()
_SESSIONS: weakref.WeakKeyDictionary[IncidentReadSession, _SessionData] = weakref.WeakKeyDictionary()


class AdmittedPage:
    """Expose traversal facts without granting an adapter source-write authority."""

    __slots__ = ("__weakref__",)

    def __new__(cls) -> AdmittedPage:
        raise IncidentReadError()

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("immutable_admitted_page")

    def __reduce__(self) -> Never:
        raise TypeError("runtime_only_page")

    @property
    def accepted(self) -> bool:
        return _page(self).accepted

    @property
    def terminal(self) -> bool:
        return _page(self).terminal

    @property
    def next_start(self) -> int | None:
        return _page(self).next_start

    @property
    def read_id(self) -> str | None:
        return _page(self).read_id


def _page(value: object) -> _PageData:
    if type(value) is not AdmittedPage:
        raise IncidentReadError()
    result = _PAGES.get(value)
    if result is None:
        raise IncidentReadError()
    return result


def _page_result(data: _SessionData, accepted: bool) -> AdmittedPage:
    page = object.__new__(AdmittedPage)
    _PAGES[page] = _PageData(
        accepted,
        data.terminal or data.stopped,
        data.cursor if accepted and not data.terminal and not data.stopped else None,
        data.reads[-1].read_id if data.reads else None,
    )
    return page


def _session(value: object) -> _SessionData:
    if type(value) is not IncidentReadSession:
        raise IncidentReadError()
    state = _SESSIONS.get(value)
    if state is None:
        raise IncidentReadError()
    return state


def _check_time(data: _SessionData, *, publishing: bool = False) -> None:
    cutoff = _seed(data.seed).deadline - (0.0 if publishing else _PUBLICATION_RESERVE_SECONDS)
    if time.monotonic() >= cutoff:
        raise _AdmissionFailure("deadline_exceeded")


def _diagnose(data: _SessionData, code: contract.DiagnosticCode, read_id: str | None = None) -> None:
    item = contract.Diagnostic(code=code, read_id=read_id, side=None)
    if item not in data.diagnostics:
        if len(data.diagnostics) >= 55:
            raise IncidentReadError()
        data.diagnostics.append(item)
    data.stopped = True


def _object(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise _AdmissionFailure()
    return cast(dict[str, Any], value)


def _array(value: Any) -> list[Any]:
    if type(value) is not list:
        raise _AdmissionFailure()
    return cast(list[Any], value)


def _opaque(value: Any) -> str:
    return contract.bounded_text(value, 256, nonblank=True)


def _container(payload: Any, template: contract.EndpointTemplate) -> Any:
    if template == "jira_accessible_resources":
        return payload
    key = {
        "servicenow_record": "result",
        "pagerduty_incident": "incident",
        "jira_changelog": "values",
        "pagerduty_log_entries": "log_entries",
    }.get(template)
    return payload if key is None else payload.get(key) if type(payload) is dict else None


def _received_count(container: Any, kind: str) -> int | None:
    if kind == "record":
        return 1 if type(container) is dict else None
    return len(container) if type(container) is list else None


def _site_grant(data: _SessionData, payload: Any) -> None:
    selected = _seed(data.seed).selection
    expected = selected.cloud_id
    grants: list[frozenset[str]] = []
    for item in _array(payload):
        _check_time(data)
        row = _object(item)
        identity = _opaque(row.get("id"))
        if identity != expected:
            continue
        scopes = _array(row.get("scopes"))
        if any(type(scope) is not str or not scope for scope in scopes) or len(scopes) != len(set(scopes)):
            raise _AdmissionFailure("site_grant_refused")
        jira_scopes = frozenset(scope for scope in scopes if ":jira" in scope)
        if jira_scopes:
            grants.append(jira_scopes)
    if not grants or any("read:jira-work" not in scopes or scopes != grants[0] for scopes in grants):
        raise _AdmissionFailure("site_grant_refused")


def _event(
    selected: AuthorizedSelection,
    read_id: str,
    occurrence: contract.Occurrence,
    native: dict[str, contract.NativeTextCell],
    time_key: str,
) -> contract.SourceEvent:
    request = selected.request
    candidate = contract.SourceEvent.model_validate(
        {
            "event_id": contract.event_identity(request, occurrence),
            "record_id": request.record_id,
            "read_id": read_id,
            "occurrence": occurrence,
            "timestamp": native[time_key],
            "native_fields": native,
            "matches": [],
        }
    )
    return candidate.model_copy(update={"matches": contract._matching_sides(selected.definition, candidate)})


def _record_projection(
    data: _SessionData, payload: Any, read_id: str
) -> tuple[contract.SelectedRecordProjection, list[contract.SourceEvent]]:
    selected = _seed(data.seed).selection
    request = selected.request
    row = _object(payload)
    identity = "sys_id" if request.provider == "servicenow" else "id"
    if type(row.get(identity)) is not str or row[identity] != request.record_id:
        raise _AdmissionFailure("record_mismatch")
    fields = {identity: contract.native_text_cell(row, identity, maximum=128)}
    events: list[contract.SourceEvent] = []
    if request.provider == "servicenow":
        definition = selected.definition
        for mapping in (definition.start, definition.end):
            field_name = cast(contract.ServiceNowMapping, mapping).field
            fields[field_name] = contract.native_text_cell(row, field_name, maximum=2048)
            events.append(
                _event(
                    selected,
                    read_id,
                    contract.ServiceNowOccurrence(field=field_name),
                    {"field": contract.NativeTextCell(state="value", value=field_name), "value": fields[field_name]},
                    "value",
                )
            )
    elif request.provider == "jira":
        fields["fields.created"] = contract.native_text_cell(_object(row.get("fields")), "created", maximum=2048)
    else:
        fields["created_at"] = contract.native_text_cell(row, "created_at", maximum=2048)
    record = contract.SelectedRecordProjection.model_validate(
        {"provider": request.provider, "record_id": request.record_id, "read_id": read_id, "fields": fields}
    )
    return record, events


def _pagination(data: _SessionData, payload: Any, count: int, start: int) -> contract.DeclaredPagination:
    row = _object(payload)
    provider = _seed(data.seed).selection.provider
    if provider == "jira":
        position, limit, terminal = row.get("startAt"), row.get("maxResults"), row.get("isLast")
    else:
        position, limit = row.get("offset"), row.get("limit")
        more = row.get("more")
        if type(more) is not bool:
            raise _AdmissionFailure("pagination_conflict")
        terminal = not more
    try:
        page = contract.DeclaredPagination.model_validate(
            {"start": position, "limit": limit, "total": row.get("total"), "terminal": terminal, "returned": count}
        )
    except ValueError:
        raise _AdmissionFailure("pagination_conflict") from None
    if page.start != start or (data.total is not None and page.total != data.total):
        raise _AdmissionFailure("pagination_conflict")
    return page


def _history_projection(
    data: _SessionData, payload: Any, read_id: str
) -> tuple[list[contract.SourceEvent], dict[str, bytes]]:
    selected = _seed(data.seed).selection
    request, definition = selected.request, selected.definition
    events: list[contract.SourceEvent] = []
    identities: dict[str, bytes] = {}
    for value in _array(payload):
        _check_time(data)
        row = _object(value)
        identity = _opaque(row.get("id"))
        fingerprint = hashlib.sha256(canonical_json(row)).digest()
        previous = identities.get(identity, data.histories.get(identity))
        if previous is not None:
            raise _AdmissionFailure("duplicate_occurrence" if previous == fingerprint else "source_conflict")
        identities[identity] = fingerprint
        if request.provider == "jira":
            items = _array(row.get("items"))
            if len(items) > 256:
                raise _AdmissionFailure("event_limit")
            timestamp = contract.native_text_cell(row, "created", maximum=2048)
            fields = {cast(contract.JiraMapping, mapping).field_id for mapping in (definition.start, definition.end)}
            for index, value in enumerate(items):
                _check_time(data)
                item = _object(value)
                field_id = _opaque(item.get("fieldId"))
                if field_id not in fields:
                    continue
                native = {name: contract.native_text_cell(item, name) for name in ("fieldId", "from", "to")}
                native["created"] = timestamp
                events.append(
                    _event(
                        selected,
                        read_id,
                        contract.JiraOccurrence(history_id=identity, item_index=index),
                        native,
                        "created",
                    )
                )
        else:
            if row.get("type") not in get_args(contract.PagerDutyEventType):
                raise _AdmissionFailure()
            incident = _object(row.get("incident"))
            if type(incident.get("id")) is not str or incident["id"] != request.record_id:
                raise _AdmissionFailure("record_mismatch")
            native = {name: contract.native_text_cell(row, name) for name in ("id", "type", "created_at")}
            native["incident.id"] = contract.native_text_cell(incident, "id", maximum=128)
            events.append(
                _event(selected, read_id, contract.PagerDutyOccurrence(event_id=identity), native, "created_at")
            )
        if len(events) + len(data.events) > 10000:
            raise _AdmissionFailure("event_limit")
    return events, identities


def _admit_read(data: _SessionData, template: contract.EndpointTemplate, start: int | None) -> bool:
    selected = _seed(data.seed).selection
    if data.material is None or data.stopped or data.closed or data.terminal:
        return False
    if len(data.reads) >= 102:
        _diagnose(data, "page_limit")
        return False
    try:
        _check_time(data)
    except _AdmissionFailure as error:
        _diagnose(data, error.code)
        return False
    ordinal = len(data.reads)
    read_id = contract.read_identity(selected.request, ordinal)
    kind: Literal["jira_access", "record", "history"] = (
        "jira_access" if template == "jira_accessible_resources" else "history" if start is not None else "record"
    )
    receipt = get_identity(
        selected,
        data.material,
        template,
        start,
        _seed(data.seed).deadline - _PUBLICATION_RESERVE_SECONDS,
        data.budget,
    )
    if type(receipt) is not HTTPReceipt:
        raise IncidentReadError()
    code = receipt.diagnostic
    received: int | None = None
    page: contract.DeclaredPagination | None = None
    record = data.record
    events: list[contract.SourceEvent] = []
    identities: dict[str, bytes] = {}
    occurrences: dict[str, bytes] = {}
    if code is None:
        try:
            _check_time(data)
            if receipt.body is None or receipt.http_status != 200:
                raise _AdmissionFailure()
            try:
                payload = parse_strict_json(receipt.body)
            except ParsingError:
                raise _AdmissionFailure("invalid_json") from None
            _check_time(data)
            container = _container(payload, template)
            received = _received_count(container, kind)
            if kind == "jira_access":
                _site_grant(data, container)
            elif kind == "record":
                record, events = _record_projection(data, container, read_id)
            else:
                rows = _array(container)
                if len(rows) > 100:
                    raise _AdmissionFailure("event_limit" if len(rows) > 10000 else "pagination_conflict")
                if len(rows) + data.history_records > 10000:
                    raise _AdmissionFailure("event_limit")
                page = _pagination(data, payload, len(rows), cast(int, start))
                events, identities = _history_projection(data, rows, read_id)
            for event in events:
                _check_time(data)
                fingerprint = result_json_bytes(contract._json_values(event))
                previous = occurrences.get(event.event_id, data.occurrences.get(event.event_id))
                if previous is not None:
                    raise _AdmissionFailure("duplicate_occurrence" if previous == fingerprint else "source_conflict")
                occurrences[event.event_id] = fingerprint
            contract.projection_bytes(record, data.events + events)
            _check_time(data)
        except _AdmissionFailure as error:
            code = error.code
        except contract.IncidentInputError as error:
            code = "result_limit" if error.code == "result_limit" else "source_shape"
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
            code = "source_shape"
    accepted = code is None
    if code is not None:
        _diagnose(data, code, read_id)
    read = contract.SourceRead.model_validate(
        {
            "read_id": read_id,
            "ordinal": ordinal,
            "kind": kind,
            "template": template,
            "state": "admitted" if accepted else "unavailable" if receipt.http_status is None else "rejected",
            "http_status": receipt.http_status,
            "retrieved_at": receipt.retrieved_at,
            "body_bytes": receipt.body_bytes,
            "body_complete": receipt.body_complete,
            "body_sha256": receipt.body_sha256,
            "accepted": accepted,
            "pagination": page if accepted else None,
            "received_records": received,
            "admitted_events": len(events) if accepted else 0,
            "diagnostic_codes": [] if code is None else [code],
            "wire_bytes": receipt.wire_bytes,
        }
    )
    data.reads.append(read)
    if accepted:
        data.record = record
        data.events.extend(events)
        data.histories.update(identities)
        data.occurrences.update(occurrences)
        if kind == "history" and page is not None:
            data.cursor, data.total, data.terminal = page.start + page.returned, page.total, page.terminal
            data.history_pages += 1
            data.history_records += cast(int, received)
        elif kind == "record" and selected.provider == "servicenow":
            data.terminal = True
    return accepted


class IncidentReadSession:
    """Own fixed GET traversal, page admission, credential lifetime and run sealing."""

    __slots__ = ("__weakref__",)

    def __init__(self, selection: AuthorizedSelection) -> None:
        if type(self) is not IncidentReadSession or self in _SESSIONS:
            raise IncidentReadError()
        seed = _new_seed(selection)
        state = _SessionData(seed, None, "not_established")
        _SESSIONS[self] = state
        try:
            _check_time(state)
            material = resolve_material(selection, datetime.now(UTC))
            state.material, state.validity = material, material.credential_validity
            _check_time(state)
        except CredentialError as error:
            _diagnose(state, error.code)
        except _AdmissionFailure as error:
            _diagnose(state, error.code)
        except BaseException:
            state.material = None
            state.stopped = True
            state.closed = True
            raise

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("owned_incident_session")

    def __repr__(self) -> str:
        return "IncidentReadSession(<owned>)"

    def __reduce__(self) -> Never:
        raise TypeError("runtime_only_session")

    @property
    def provider(self) -> str:
        return _seed(_session(self).seed).selection.provider

    def read_record(self) -> AdmittedPage:
        state = _session(self)
        try:
            if state.closed or state.record_attempted:
                raise IncidentReadError()
            state.record_attempted = True
            provider = _seed(state.seed).selection.provider
            if provider == "jira" and not _admit_read(state, "jira_accessible_resources", None):
                return _page_result(state, False)
            templates: dict[str, contract.EndpointTemplate] = {
                "servicenow": "servicenow_record",
                "jira": "jira_issue",
                "pagerduty": "pagerduty_incident",
            }
            template = templates[provider]
            return _page_result(state, _admit_read(state, template, None))
        except BaseException as error:
            if not isinstance(error, Exception):
                state.material = None
                state.stopped = True
                state.closed = True
            raise

    def read_history_page(self, start: int) -> AdmittedPage:
        state = _session(self)
        try:
            if state.closed or not state.record_attempted or state.record is None:
                raise IncidentReadError()
            if type(start) is not int or start != state.cursor or state.terminal or state.stopped:
                raise IncidentReadError()
            if state.history_pages >= 100:
                _diagnose(state, "page_limit")
                return _page_result(state, False)
            provider = _seed(state.seed).selection.provider
            if provider == "servicenow":
                raise IncidentReadError()
            template: contract.EndpointTemplate = "jira_changelog" if provider == "jira" else "pagerduty_log_entries"
            return _page_result(state, _admit_read(state, template, start))
        except BaseException as error:
            if not isinstance(error, Exception):
                state.material = None
                state.stopped = True
                state.closed = True
            raise

    def finish(self) -> RunAuthority:
        state = _session(self)
        if state.authority is not None:
            return state.authority
        if state.closed:
            raise IncidentReadError()
        try:
            _check_time(state, publishing=True)
            state.authority = _issue_authority(
                state.seed,
                credential_validity=state.validity,
                reads=state.reads,
                record=state.record,
                events=state.events,
                diagnostics=state.diagnostics,
            )
            _check_time(state, publishing=True)
            return state.authority
        finally:
            state.material = None
            state.closed = True

    def close(self) -> None:
        state = _session(self)
        state.material = None
        state.closed = True
