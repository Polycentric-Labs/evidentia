"""Retain public registered-entity fields within the session's partial scope."""

from __future__ import annotations

from typing import Any

from ._client import RegistryReadSession
from ._contracts import RegistryInputError, RegistryLookupResult, SAMEntityRequest
from ._source_fields import validate_fields

_FIELDS = (
    "ueiSAM",
    "samRegistered",
    "entityEFTIndicator",
    "legalBusinessName",
    "registrationStatus",
    "registrationDate",
    "lastUpdateDate",
    "registrationExpirationDate",
    "activationDate",
)


def _project(source: dict[str, Any]) -> dict[str, Any]:
    selected = {name: source[name] for name in _FIELDS if name in source}
    return validate_fields("sam-entity", "registered_entity_occurrence", selected)


def lookup(session: RegistryReadSession) -> RegistryLookupResult:
    """Read one bounded registered-only page without claiming terminal coverage."""
    request = session.request.root
    if not isinstance(request, SAMEntityRequest):
        raise RegistryInputError()
    return session.read_sam_entity(request.target, _project)
