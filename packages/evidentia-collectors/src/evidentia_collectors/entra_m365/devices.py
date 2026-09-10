"""Intune device state observations with exact source-sync ages."""

from ._client import EntraM365GraphReader
from ._contracts import (
    KNOWN_ENUMS,
    EntraM365CapabilityRead,
    EntraM365CollectRequest,
    EntraM365DlpExport,
    EntraM365RunContext,
    JsonObject,
    JsonValue,
    _ExactSourceTimestamp,
    clock_text,
    parse_source_timestamp,
    source_age_seconds,
)


def _known_state(value: JsonValue, field: str) -> str:
    if isinstance(value, str) and value in KNOWN_ENUMS[("managed-devices", field)]:
        return value
    return "unknown"


def _sync_age(fields: JsonObject, end: _ExactSourceTimestamp) -> JsonObject:
    literal = fields.get("lastSyncDateTime")
    if literal is None:
        return {
            "state": "null" if "lastSyncDateTime" in fields else "absent",
            "source_timestamp": None,
            "age_seconds": None,
        }
    age = source_age_seconds(end, parse_source_timestamp(literal))
    return {
        "state": "future" if age is None else "known",
        "source_timestamp": literal,
        "age_seconds": age,
    }


def read_managed_devices(
    request: EntraM365CollectRequest,
    graph_reader: EntraM365GraphReader,
    run_context: EntraM365RunContext,
    dlp_export: EntraM365DlpExport | None = None,
) -> EntraM365CapabilityRead:
    """Preserve observed device states without a compliance or age threshold."""
    source = graph_reader.read_collection("managed-devices", request, run_context)
    end = parse_source_timestamp(clock_text(run_context.window_end))
    findings = [
        run_context.make_finding(
            source,
            "managed-device-state",
            source_id=record.source_id,
            raw_data={
                "compliance_state": _known_state(record.fields.get("complianceState"), "complianceState"),
                "management_state": _known_state(record.fields.get("managementState"), "managementState"),
                "last_sync": _sync_age(record.fields, end),
            },
        )
        for record in source.records
    ]
    return run_context.finish_read(source, findings=findings)
