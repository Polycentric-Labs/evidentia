"""Project selected domain metadata without RDAP personal contacts."""

from __future__ import annotations

from typing import Any, cast

from ._client import RegistryReadSession
from ._contracts import RDAPRequest, RegistryInputError, RegistryLookupResult
from ._parsing import checked_json


def _select(value: object, names: tuple[str, ...]) -> dict[str, Any] | None:
    if value is None:
        return None
    if type(value) is not dict:
        raise ValueError("invalid RDAP projection shape")
    source = cast(dict[str, Any], value)
    return {name: source[name] for name in names if name in source}


def _objects(value: object, names: tuple[str, ...]) -> list[dict[str, Any] | None] | None:
    if value is None:
        return None
    if type(value) is not list:
        raise ValueError("invalid RDAP projection shape")
    return [_select(item, names) for item in value]


def project_rdap(source: dict[str, Any]) -> dict[str, Any]:
    """Preserve literal names, statuses, source dates and redaction metadata."""
    selected = _select(
        checked_json(source),
        ("objectClassName", "ldhName", "unicodeName", "status", "events", "notices", "rdapConformance", "redacted"),
    )
    if selected is None:
        raise ValueError("invalid RDAP projection shape")
    if "events" in selected:
        selected["events"] = _objects(selected["events"], ("eventAction", "eventDate"))
    if "notices" in selected:
        notices = _objects(selected["notices"], ("title", "description", "links", "type"))
        selected["notices"] = notices
        if notices is not None:
            for notice in notices:
                if notice is not None and "links" in notice:
                    notice["links"] = _objects(notice["links"], ("rel", "title", "media", "type", "hreflang"))
    if "redacted" in selected:
        redactions = _objects(
            selected["redacted"], ("name", "reason", "prePath", "postPath", "replacementPath", "pathLang", "method")
        )
        selected["redacted"] = redactions
        if redactions is not None:
            for redaction in redactions:
                if redaction is not None:
                    for name in ("name", "reason"):
                        if name in redaction:
                            redaction[name] = _select(redaction[name], ("type", "description"))
    return selected


def lookup(session: RegistryReadSession) -> RegistryLookupResult:
    """Read the selected domain through the session's packaged IANA discovery."""
    request = session.request.root
    if not isinstance(request, RDAPRequest):
        raise RegistryInputError()
    return session.read_rdap(request.target, project_rdap)
