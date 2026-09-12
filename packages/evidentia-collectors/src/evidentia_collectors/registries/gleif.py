"""Project the selected identity, entity and registration fields of one LEI."""

from __future__ import annotations

from typing import Any, cast

from ._client import RegistryReadSession
from ._contracts import GLEIFRequest, RegistryInputError, RegistryLookupResult
from ._parsing import checked_json


def _select(value: object, names: tuple[str, ...]) -> dict[str, Any] | None:
    if value is None:
        return None
    if type(value) is not dict:
        raise ValueError("invalid GLEIF projection shape")
    source = cast(dict[str, Any], value)
    return {name: source[name] for name in names if name in source}


def project_gleif(source: dict[str, Any]) -> dict[str, Any]:
    """Preserve source absence, nulls and successor order without addresses."""
    selected = _select(checked_json(source), ("id", "type", "attributes"))
    if selected is None:
        raise ValueError("invalid GLEIF projection shape")
    if "attributes" in selected:
        attributes = _select(selected["attributes"], ("lei", "entity", "registration"))
        selected["attributes"] = attributes
        if attributes is not None:
            if "entity" in attributes:
                entity = _select(attributes["entity"], ("legalName", "status", "successorEntities"))
                attributes["entity"] = entity
                if entity is not None:
                    if "legalName" in entity:
                        entity["legalName"] = _select(entity["legalName"], ("name", "language"))
                    if "successorEntities" in entity and entity["successorEntities"] is not None:
                        successors = entity["successorEntities"]
                        if type(successors) is not list:
                            raise ValueError("invalid GLEIF projection shape")
                        entity["successorEntities"] = [_select(item, ("lei", "name")) for item in successors]
            if "registration" in attributes:
                attributes["registration"] = _select(
                    attributes["registration"],
                    ("initialRegistrationDate", "lastUpdateDate", "status", "nextRenewalDate"),
                )
    return selected


def lookup(session: RegistryReadSession) -> RegistryLookupResult:
    """Read the selected LEI through the session's fixed record endpoint."""
    request = session.request.root
    if not isinstance(request, GLEIFRequest):
        raise RegistryInputError()
    return session.read_gleif(request.target, project_gleif)
