"""Read selected Google Vault matter and hold configuration without expanding scope."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date

from pydantic import JsonValue

from ._client import (
    AuthorityError,
    EnterpriseReadSession,
    ParsedResponse,
    ProjectedPage,
    ProjectedRecord,
    ReadSubject,
)
from ._contracts import CoverageState, EnterpriseRetentionResourceResult, InterpretationCode, VaultMatterTarget
from ._parsing import JsonObject

_STATES = frozenset(("OPEN", "CLOSED", "DELETED"))
_CORPORA = frozenset(("DRIVE", "MAIL", "GROUPS", "HANGOUTS_CHAT", "VOICE", "CALENDAR", "GEMINI"))
_VOICE_DATA = frozenset(("TEXT_MESSAGES", "VOICEMAILS", "CALL_LOGS"))
_TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.[0-9]+)?(?:[Zz]|[+-]([0-9]{2}):([0-9]{2}))"
)


@dataclass
class _Detail:
    unknown: bool = False
    missing: bool = False

    def include(self, child: _Detail) -> None:
        self.unknown |= child.unknown
        self.missing |= child.missing

    def diagnostics(self) -> tuple[InterpretationCode, ...]:
        codes: list[InterpretationCode] = []
        if self.unknown:
            codes.append("unsupported_source_value")
        if self.missing:
            codes.append("missing_source_detail")
        return tuple(codes)


_Check = Callable[[JsonValue, _Detail], JsonValue]


def _object(value: JsonValue) -> JsonObject:
    if type(value) is not dict:
        raise AuthorityError()
    return value


def _identity(source: JsonObject, name: str, *, max_bytes: int | None = None) -> str:
    value = source.get(name)
    if type(value) is not str or not value.strip():
        raise AuthorityError()
    if max_bytes is not None and len(value.encode("utf-8")) > max_bytes:
        raise AuthorityError()
    return value


def _optional(
    source: JsonObject,
    name: str,
    selected: JsonObject,
    detail: _Detail,
    check: _Check,
) -> CoverageState:
    if name not in source:
        detail.missing = True
        return "absent"
    value = source[name]
    if value is None:
        selected[name] = None
        detail.missing = True
        return "null"
    child = _Detail()
    selected[name] = check(value, child)
    detail.include(child)
    return "unknown" if child.unknown else "known"


def _text(value: JsonValue, _detail: _Detail) -> str:
    if type(value) is not str:
        raise AuthorityError()
    return value


def _state(value: JsonValue, detail: _Detail) -> str:
    text = _text(value, detail)
    detail.unknown = text not in _STATES
    return text


def _corpus(value: JsonValue, detail: _Detail) -> str:
    text = _text(value, detail)
    detail.unknown = text not in _CORPORA
    return text


def _timestamp(value: JsonValue, detail: _Detail) -> str:
    text = _text(value, detail)
    match = _TIME.fullmatch(text)
    known = match is not None
    if match is not None:
        try:
            date.fromisoformat(text[:10])
        except ValueError:
            known = False
        hour, minute, second = (int(match[i]) for i in (1, 2, 3))
        known &= hour < 24 and minute < 60 and second < 60
        if match[4] is not None:
            known &= int(match[4]) < 24 and int(match[5]) < 60
    # Validate the spelling without converting or rounding the source timestamp.
    detail.unknown = not known
    return text


def _boolean(value: JsonValue, _detail: _Detail) -> bool:
    if type(value) is not bool:
        raise AuthorityError()
    return value


def _voice_data(value: JsonValue, detail: _Detail) -> JsonValue:
    if type(value) is not list:
        raise AuthorityError()
    for item in value:
        if type(item) is not str:
            raise AuthorityError()
        if item not in _VOICE_DATA:
            detail.unknown = True
    return list(value)


def _accounts(value: JsonValue, detail: _Detail) -> JsonValue:
    if type(value) is not list:
        raise AuthorityError()
    selected: list[JsonValue] = []
    for item in value:
        source = _object(item)
        account: JsonObject = {"accountId": _identity(source, "accountId")}
        _optional(source, "holdTime", account, detail, _timestamp)
        selected.append(account)
    return selected


def _org_unit(value: JsonValue, detail: _Detail) -> JsonObject:
    source = _object(value)
    selected: JsonObject = {"orgUnitId": _identity(source, "orgUnitId")}
    _optional(source, "holdTime", selected, detail, _timestamp)
    return selected


_QUERY_FIELDS: dict[str, tuple[tuple[str, _Check], ...]] = {
    "driveQuery": (("includeSharedDriveFiles", _boolean), ("includeTeamDriveFiles", _boolean)),
    "hangoutsChatQuery": (("includeRooms", _boolean),),
    "mailQuery": (("startTime", _timestamp), ("endTime", _timestamp), ("terms", _text)),
    "groupsQuery": (("startTime", _timestamp), ("endTime", _timestamp), ("terms", _text)),
    "voiceQuery": (("coveredData", _voice_data),),
    "calendarQuery": (),
    "geminiQuery": (),
}


def _query(value: JsonValue, detail: _Detail) -> JsonObject:
    source = _object(value)
    selected = dict(source)
    # Only declared locations have typed leaves. Future configuration stays exact.
    for branch, raw in source.items():
        if branch not in _QUERY_FIELDS:
            detail.unknown = True
            continue
        if raw is None:
            detail.missing = True
            continue
        child = _object(raw)
        leaves = _QUERY_FIELDS[branch]
        declared = {name for name, _ in leaves}
        if any(name not in declared for name in child):
            detail.unknown = True
        output = dict(child)
        for name, check in leaves:
            _optional(child, name, output, detail, check)
        selected[branch] = output
    return selected


def project_matter(response: ParsedResponse, subject: ReadSubject) -> ProjectedPage:
    """Select the BASIC matter identity and literal state from one response."""
    if subject.kind != "vault-matter":
        raise AuthorityError()
    source = response.data
    identity = _identity(source, "matterId")
    if identity != subject.source_id:
        raise AuthorityError("identity_mismatch")
    fields: JsonObject = {"matterId": identity}
    detail = _Detail()
    coverage: dict[str, CoverageState] = {
        "matterId": "known",
        "state": _optional(source, "state", fields, detail, _state),
    }
    return ProjectedPage((ProjectedRecord(0, identity, "matter", fields, coverage, detail.diagnostics()),))


def project_holds(response: ParsedResponse, subject: ReadSubject) -> ProjectedPage:
    """Select every hold occurrence; the session owns continuation and admission."""
    if subject.kind != "vault-holds":
        raise AuthorityError()
    source = response.data
    if "holds" not in source:
        return ProjectedPage(())
    members = source["holds"]
    if type(members) is not list:
        raise AuthorityError()
    records: list[ProjectedRecord] = []
    for ordinal, item in enumerate(members):
        hold = _object(item)
        identity = _identity(hold, "holdId", max_bytes=1024)
        fields: JsonObject = {"holdId": identity}
        coverage: dict[str, CoverageState] = {"holdId": "known"}
        detail = _Detail()
        checks: tuple[tuple[str, _Check], ...] = (
            ("name", _text),
            ("corpus", _corpus),
            ("updateTime", _timestamp),
            ("accounts", _accounts),
            ("orgUnit", _org_unit),
            ("query", _query),
        )
        for name, check in checks:
            coverage[name] = _optional(hold, name, fields, detail, check)
        accounts = fields.get("accounts")
        if type(accounts) is list and len(accounts) > 0 and type(fields.get("orgUnit")) is dict:
            # Contradictory provider scope is retained without inventing a resolved scope.
            detail.unknown = True
        records.append(ProjectedRecord(ordinal, identity, "hold", fields, coverage, detail.diagnostics()))
    return ProjectedPage(tuple(records))


def read_vault(
    target: VaultMatterTarget, session: EnterpriseReadSession
) -> EnterpriseRetentionResourceResult[VaultMatterTarget]:
    """Read one selected matter and its holds through the bounded shared session."""
    matter = session.read_vault_matter(target, project_matter)
    holds = session.read_vault_holds(target, project_holds)
    return session.finish_resource(target, reads=(matter, holds))
