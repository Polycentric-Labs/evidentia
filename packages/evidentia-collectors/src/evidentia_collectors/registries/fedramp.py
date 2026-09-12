"""Read exact FedRAMP product facts from the dated packaged snapshot."""

from __future__ import annotations

from typing import Any

from ._client import RegistryReadSession
from ._contracts import RegistryInputError, RegistryLookupResult
from ._parsing import canonical_json, checked_json

PRODUCT_FIELDS: dict[str, Any] = {
    "id": str,
    "name": str,
    "csp": str,
    "cso": str,
    "status": str,
    "auth_date": str,
    "auth_type": str,
    "impact_level": str,
    "deployment_model": str,
    "uei": str,
    "service_model": [str],
}
HISTORY_FIELDS: dict[str, Any] = {
    "unique_id": str,
    "product_id": str,
    "cert_type": str,
    "cert_path": str,
    "cert_class": str,
    "from_status": str,
    "to_status": str,
    "transition_date": str,
    "recorded_date": str,
    "source": str,
}
PACKAGE_FIELDS: dict[str, Any] = {
    "serviceIdentification": {
        "fedRampPackageId": str,
        "providerName": str,
        "ueiNumber": str,
        "serviceName": str,
        "certificationType": str,
    },
    "ZD_frid_retro": str,
    "last_fetched_timestamp": str,
    "id_matches_expected": bool,
}
_PRODUCT: dict[str, Any] = {
    "source_index": int,
    "fields": PRODUCT_FIELDS,
    "history": [{"source_index": int, "fields": HISTORY_FIELDS}],
    "package_rows": [{"source_index": int, "fields": PACKAGE_FIELDS}],
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
    """Select the finite raw-source columns without deriving status or identity."""
    schemas = {"products": PRODUCT_FIELDS, "history": HISTORY_FIELDS, "packages": PACKAGE_FIELDS}
    if type(table_id) is not str or table_id not in schemas:
        raise ValueError("invalid_snapshot_fields")
    return _project(source, schemas[table_id])


def project_product(source: dict[str, Any]) -> dict[str, Any]:
    """Preserve source-order histories and separately established package joins."""
    return _project(source, _PRODUCT)


def lookup(session: RegistryReadSession) -> RegistryLookupResult:
    request = session.request.root
    if request.registry != "fedramp":
        raise RegistryInputError()
    return session.read_snapshot(request.target, project_product)
