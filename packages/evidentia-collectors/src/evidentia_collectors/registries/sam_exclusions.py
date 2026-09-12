"""Preserve selected firm-exclusion fields and ordered action occurrences."""

from __future__ import annotations

from typing import Any

from ._client import RegistryReadSession
from ._contracts import RegistryInputError, RegistryLookupResult, SAMExclusionsRequest
from ._source_fields import validate_fields

_DETAILS = ("classificationType", "exclusionType", "exclusionProgram", "excludingAgencyCode", "excludingAgencyName")
_IDENTIFICATION = ("ueiSAM", "entityName")
_ACTION = ("createDate", "updateDate", "activateDate", "terminationDate", "terminationType", "recordStatus")


def _object(value: object, names: tuple[str, ...]) -> dict[str, Any] | None:
    if value is None:
        return None
    if type(value) is not dict:
        raise ValueError("invalid_response")
    return {name: value[name] for name in names if name in value}


def _project(source: dict[str, Any]) -> dict[str, Any]:
    selected: dict[str, Any] = {}
    for section, names in (
        ("exclusionDetails", _DETAILS),
        ("exclusionIdentification", _IDENTIFICATION),
        ("exclusionOtherInformation", ("isFASCSAOrder",)),
    ):
        if section in source:
            selected[section] = _object(source[section], names)
    if "exclusionActions" in source:
        actions = _object(source["exclusionActions"], ("listOfActions",))
        if actions is not None and "listOfActions" in actions:
            values = actions["listOfActions"]
            if values is not None:
                if type(values) is not list:
                    raise ValueError("invalid_response")
                actions["listOfActions"] = [_object(value, _ACTION) for value in values]
        selected["exclusionActions"] = actions
    return validate_fields("sam-exclusions", "firm_exclusion_occurrence", selected)


def lookup(session: RegistryReadSession) -> RegistryLookupResult:
    """Read the fixed query while the session retains total and matching authority."""
    request = session.request.root
    if not isinstance(request, SAMExclusionsRequest):
        raise RegistryInputError()
    return session.read_sam_exclusions(request.target, _project)
