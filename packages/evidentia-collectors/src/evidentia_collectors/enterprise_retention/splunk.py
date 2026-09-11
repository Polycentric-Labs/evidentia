"""Selected Splunk Enterprise index configuration with literal source values."""

from pydantic import JsonValue

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
    EnterpriseRetentionResourceResult,
    InterpretationCode,
    SplunkIndexTarget,
)
from ._parsing import JsonObject


def _scalar_coverage(name: str, value: JsonValue) -> CoverageState:
    if value is None:
        return "null"
    if name == "datatype":
        if type(value) is not str:
            raise AuthorityError()
        return "known" if value in ("event", "metric") else "unknown"
    if name == "disabled":
        if type(value) is bool:
            return "known"
        if type(value) is int:
            return "known" if value in (0, 1) else "unknown"
        if type(value) is str:
            return "known" if value in ("0", "1") else "unknown"
        if type(value) is float:
            return "unknown"
        raise AuthorityError()
    if type(value) is int:
        return "known" if value >= 0 else "unknown"
    if type(value) is str:
        return "known" if value and all("0" <= character <= "9" for character in value) else "unknown"
    if type(value) is float:
        return "unknown"
    raise AuthorityError()


def project_index(response: ParsedResponse, subject: ReadSubject) -> ProjectedPage:
    """Project one selected index after the session admits its envelope.

    The session handles body ERROR and fixed message warnings before this
    callback. Archive settings describe presence only, without retaining paths
    or claiming successful archival. Optional detail limits interpretation.
    """
    if type(response) is not ParsedResponse or type(subject) is not ReadSubject or subject.kind != "splunk-index":
        raise AuthorityError()
    entries = response.data.get("entry")
    if type(entries) is not list or len(entries) != 1 or type(entries[0]) is not dict:
        raise AuthorityError()
    entry = entries[0]
    identity = entry.get("name")
    if type(identity) is not str or identity != subject.source_id:
        raise AuthorityError("identity_mismatch")
    content = entry.get("content")
    if type(content) is not dict:
        raise AuthorityError()

    fields: JsonObject = {"name": identity}
    coverage: dict[str, CoverageState] = {"name": "known"}
    for name in ("datatype", "disabled", "frozenTimePeriodInSecs", "maxTotalDataSizeMB"):
        if name not in content:
            coverage[name] = "absent"
            continue
        value = content[name]
        coverage[name] = _scalar_coverage(name, value)
        fields[name] = value

    for name in ("coldToFrozenDir", "coldToFrozenScript"):
        if name not in content:
            coverage[name] = "absent"
            fields[name + "State"] = "absent"
            continue
        value = content[name]
        if value is None:
            coverage[name] = "null"
            fields[name + "State"] = "null"
        elif type(value) is str:
            coverage[name] = "known"
            fields[name + "State"] = "nonempty" if value else "empty"
        else:
            raise AuthorityError()

    diagnostics: list[InterpretationCode] = []
    if "unknown" in coverage.values():
        diagnostics.append("unsupported_source_value")
    if any(state in ("absent", "null") for state in coverage.values()):
        diagnostics.append("missing_source_detail")
    record = ProjectedRecord(0, identity, "index", fields, coverage, tuple(diagnostics))
    return ProjectedPage((record,))


def read_splunk(
    target: SplunkIndexTarget, session: EnterpriseReadSession
) -> EnterpriseRetentionResourceResult[SplunkIndexTarget]:
    """Read the selected index through the shared session."""
    handle = session.read_splunk_index(target, project_index)
    return session.finish_resource(target, reads=(handle,))
