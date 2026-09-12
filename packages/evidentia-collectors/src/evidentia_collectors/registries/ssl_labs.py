"""Keep live SSL Labs access disabled and parse only bounded cached Endpoint data."""

from __future__ import annotations

import ipaddress
from typing import Any

from ._client import ReadFault, RegistryReadSession
from ._contracts import RegistryInputError, RegistryLookupResult, SSLLabsRequest
from ._parsing import parse_strict_json
from ._source_fields import validate_fields

_FIELDS = (
    "ipAddress",
    "statusMessage",
    "statusDetails",
    "grade",
    "gradeTrustIgnored",
    "futureGrade",
    "hasWarnings",
    "isExceptional",
)


def _project(source: dict[str, Any]) -> dict[str, Any]:
    selected = {name: source[name] for name in _FIELDS if name in source}
    if "details" in source:
        details = source["details"]
        if details is None:
            selected["details"] = None
        elif type(details) is dict:
            selected["details"] = {"hostStartTime": details["hostStartTime"]} if "hostStartTime" in details else {}
        else:
            raise ValueError("invalid_response")
    return validate_fields("ssl-labs", "endpoint", selected)


def lookup(session: RegistryReadSession) -> RegistryLookupResult:
    """Return the shared live-disabled result before transport or projection."""
    request = session.request.root
    if not isinstance(request, SSLLabsRequest):
        raise RegistryInputError()
    return session.read_ssl_labs(request.target, _project)


def parse_endpoint(content: bytes, endpoint_ip: str) -> dict[str, Any]:
    """Parse injected cached bytes without enabling or initiating an assessment."""
    if type(endpoint_ip) is not str:
        raise ReadFault("identity_mismatch")
    try:
        requested = ipaddress.ip_address(endpoint_ip)
    except ValueError:
        raise ReadFault("identity_mismatch") from None
    if not requested.is_global or requested.is_multicast or "%" in endpoint_ip:
        raise ReadFault("identity_mismatch")
    source = parse_strict_json(content)
    if type(source) is not dict:
        raise ReadFault("invalid_response")
    if not source:
        raise ReadFault("cache_miss")
    actual = source.get("ipAddress")
    if type(actual) is not str or "%" in actual:
        raise ReadFault("identity_mismatch")
    try:
        same = ipaddress.ip_address(actual) == requested
    except ValueError:
        same = False
    if not same:
        raise ReadFault("identity_mismatch")
    return _project(source)
