"""Read exact CMVP certificate facts with their captured source memberships."""

from __future__ import annotations

from typing import Any

from ._client import RegistryReadSession
from ._contracts import RegistryInputError, RegistryLookupResult
from ._parsing import canonical_json, checked_json

TABLE_FIELDS: dict[str, Any] = {
    "Certificate Number": str,
    "Vendor Name": str,
    "Module Name": str,
    "Module Type": str,
    "Validation Date": str,
    "Status": str,
}
DETAIL_FIELDS: dict[str, Any] = {
    "Module Name": str,
    "Standard": str,
    "Status": str,
    "Sunset Date": str,
    "Caveat": str,
    "Module Type": str,
}
_CERTIFICATE: dict[str, Any] = {
    "certificate_number": str,
    "fields": TABLE_FIELDS,
    "status": {"basis": str, "value": str},
    "occurrences": [{"source_id": str, "table_id": str, "source_index": int, "query_status": str}],
    "detail": {"source_id": str, "source_index": int, "fields": DETAIL_FIELDS},
}


def _select(value: Any, schema: Any) -> Any:
    if type(schema) is dict:
        if type(value) is not dict:
            raise ValueError("invalid_snapshot_fields")
        return {key: _select(value[key], child) for key, child in schema.items() if key in value}
    if type(schema) is list:
        if type(value) is not list:
            raise ValueError("invalid_snapshot_fields")
        return [_select(item, schema[0]) for item in value]
    if type(value) is not schema or (schema is int and value < 0):
        raise ValueError("invalid_snapshot_fields")
    return value


def _project(source: object, schema: dict[str, Any]) -> dict[str, Any]:
    native = checked_json(source)
    selected: dict[str, Any] = _select(native, schema)
    if len(canonical_json(selected)) > 65_536:
        raise ValueError("invalid_snapshot_fields")
    return selected


def select_source_fields(table_id: str, source: object) -> dict[str, Any]:
    """Retain native captured text, including date order and line breaks."""
    if type(table_id) is not str or table_id not in {"active", "historical", "revoked", "certificate_5517_detail"}:
        raise ValueError("invalid_snapshot_fields")
    schema = DETAIL_FIELDS if table_id == "certificate_5517_detail" else TABLE_FIELDS
    return _project(source, schema)


def project_certificate(source: dict[str, Any]) -> dict[str, Any]:
    return _project(source, _CERTIFICATE)


def lookup(session: RegistryReadSession) -> RegistryLookupResult:
    request = session.request.root
    if request.registry != "cmvp":
        raise RegistryInputError()
    return session.read_snapshot(request.target, project_certificate)
