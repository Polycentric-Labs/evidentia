"""Project selected GCS bucket configuration without object-level claims."""

from __future__ import annotations

import re
from datetime import date
from typing import Literal

from ._client import ClientFault, ComponentResponse, StorageReadSession
from ._contracts import (
    GcsTarget,
    ProjectedComponent,
    StorageRetentionComponentResult,
    StorageRetentionDiagnostic,
    StorageTarget,
)
from ._parsing import JsonObject

_FieldKind = Literal["unsigned", "timestamp", "boolean", "mode"]
_DetailCode = Literal["missing_source_detail", "unsupported_source_value"]
_UNSIGNED = re.compile(r"[0-9]{1,128}")
_TIMESTAMP = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.[0-9]+)?(?:[Zz]|[+-]([0-9]{2}):([0-9]{2}))"
)
_CONFIG_FIELDS: tuple[tuple[str, tuple[tuple[str, _FieldKind], ...]], ...] = (
    (
        "retentionPolicy",
        (("retentionPeriod", "unsigned"), ("effectiveTime", "timestamp"), ("isLocked", "boolean")),
    ),
    ("versioning", (("enabled", "boolean"),)),
    ("objectRetention", (("mode", "mode"),)),
)


def _detail(diagnostics: list[StorageRetentionDiagnostic], code: _DetailCode) -> None:
    diagnostic = StorageRetentionDiagnostic(code=code)
    if diagnostic not in diagnostics:
        diagnostics.append(diagnostic)


def _supported_timestamp(value: str) -> bool:
    """Check RFC3339 calendar and lexical bounds without changing the literal."""
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(match[index]) for index in range(1, 7))
    try:
        date(year, month, day)
    except ValueError:
        return False
    # Leap-event validation is outside this configuration reader; retain it as partial.
    if hour > 23 or minute > 59 or second > 59:
        return False
    return match[7] is None or (int(match[7]) <= 23 and int(match[8]) <= 59)


def _select_field(
    source: JsonObject,
    selected: JsonObject,
    name: str,
    kind: _FieldKind,
    diagnostics: list[StorageRetentionDiagnostic],
) -> None:
    if name not in source:
        _detail(diagnostics, "missing_source_detail")
        return
    value = source[name]
    if value is None:
        selected[name] = None
        _detail(diagnostics, "missing_source_detail")
        return
    if kind == "boolean":
        if type(value) is not bool:
            raise ClientFault("invalid_response", 200)
    else:
        if not isinstance(value, str):
            raise ClientFault("invalid_response", 200)
        if kind == "unsigned":
            if _UNSIGNED.fullmatch(value) is None:
                raise ClientFault("invalid_response", 200)
            # Compare exact integers only; keep the source representation in fields.
            if name == "retentionPeriod" and not 0 < int(value) < 3_155_760_000:
                _detail(diagnostics, "unsupported_source_value")
        elif (kind == "timestamp" and not _supported_timestamp(value)) or (kind == "mode" and value != "Enabled"):
            _detail(diagnostics, "unsupported_source_value")
    selected[name] = value


def _project_bucket(response: ComponentResponse, target: StorageTarget) -> ProjectedComponent:
    if not isinstance(target, GcsTarget) or response.component_id != "gcs-bucket" or response.http_status != 200:
        raise ClientFault("invalid_response", response.http_status)
    source = response.body
    if not isinstance(source, dict):
        raise ClientFault("invalid_response", 200)
    name = source.get("name")
    if not isinstance(name, str) or not name:
        raise ClientFault("invalid_response", 200)
    if name != target.bucket:
        raise ClientFault("source_identity_mismatch", 200)
    fields: JsonObject = {"name": name}
    diagnostics: list[StorageRetentionDiagnostic] = []
    _select_field(source, fields, "metageneration", "unsigned", diagnostics)
    for config_name, config_fields in _CONFIG_FIELDS:
        if config_name not in source:
            continue
        config = source[config_name]
        if config is None:
            fields[config_name] = None
            _detail(diagnostics, "missing_source_detail")
            continue
        if not isinstance(config, dict):
            raise ClientFault("invalid_response", 200)
        selected: JsonObject = {}
        for field_name, kind in config_fields:
            _select_field(config, selected, field_name, kind, diagnostics)
        fields[config_name] = selected
    generation = fields.get("metageneration")
    return ProjectedComponent(
        "v1",
        "bucket",
        fields,
        tuple(diagnostics),
        source_etag=response.source_etag,
        source_metageneration=generation if isinstance(generation, str) else None,
    )


def read_gcs(target: GcsTarget, session: StorageReadSession) -> list[StorageRetentionComponentResult]:
    """Read configuration for exactly one selected bucket through the shared session."""
    return [session.read_component("gcs-bucket", target, _project_bucket)]
