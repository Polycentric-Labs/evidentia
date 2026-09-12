"""Project selected fields only after the session verifies the signed XML root."""

from __future__ import annotations

from typing import Any

from ._client import RegistryReadSession
from ._contracts import InCommonRequest, RegistryInputError, RegistryLookupResult
from ._source_fields import validate_fields


def _project(source: dict[str, Any]) -> dict[str, Any]:
    selected: dict[str, Any] = {
        name: source[name] for name in ("entityID", "validUntil", "cacheDuration") if name in source
    }
    for name, children in (
        ("organization_names", ("value", "language")),
        ("organization_display_names", ("value", "language")),
        ("registration_info", ("registrationAuthority", "registrationInstant")),
    ):
        if name not in source:
            continue
        values = source[name]
        if type(values) is not list or any(type(value) is not dict for value in values):
            raise ValueError("invalid_response")
        selected[name] = [{key: value[key] for key in children if key in value} for value in values]
    if "role_descriptors" in source:
        if type(source["role_descriptors"]) is not list:
            raise ValueError("invalid_response")
        selected["role_descriptors"] = list(source["role_descriptors"])
    return validate_fields("incommon", "verified_entity_descriptor_adapter", selected)


def lookup(session: RegistryReadSession) -> RegistryLookupResult:
    """Return verified selected metadata with membership assessment unperformed."""
    request = session.request.root
    if not isinstance(request, InCommonRequest):
        raise RegistryInputError()
    return session.read_incommon(request.target, _project)
