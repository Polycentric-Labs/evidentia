"""Bounded DLP export preflight and configuration-only interpretation."""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
from typing import TYPE_CHECKING, Literal, cast

from pydantic import ValidationError

from ._contracts import (
    PAGE_MAX_BYTES,
    DiagnosticCode,
    DlpFormat,
    EntraM365CapabilityRead,
    EntraM365CollectRequest,
    EntraM365Diagnostic,
    EntraM365DlpExport,
    EntraM365InputError,
    EntraM365RunContext,
    JsonObject,
    JsonValue,
    clock_text,
    parse_source_timestamp,
    parse_strict_json,
    source_age_seconds,
)

if TYPE_CHECKING:
    from ._client import EntraM365GraphReader

_POLICY_FIELDS = ("Guid", "Name", "Mode", "DistributionStatus", "Workload", "Enabled", "IsValid")
_RULE_FIELDS = ("Guid", "Policy", "ParentPolicyName", "Mode", "Workload", "Disabled", "IsValid")
_TEST_MODES = ("TestWithNotifications", "TestWithoutNotifications")
type _ConfigurationState = Literal["disabled", "test", "configured_enforce", "unknown"]


def _provider_records(value: JsonValue, fields: tuple[str, ...]) -> list[JsonValue]:
    if not isinstance(value, list) or len(value) > 10_000:
        raise EntraM365InputError()
    result: list[JsonValue] = []
    for record in value:
        if not isinstance(record, dict) or not all(key in record for key in fields):
            raise EntraM365InputError()
        result.append({key: record[key] for key in fields})
    return result


def parse_dlp_export(content: str, *, format: DlpFormat) -> EntraM365DlpExport:
    """Validate the full export before credentials, transport, or item admission."""
    if not isinstance(content, str) or format not in ("evidentia-dlp-v1", "scubagear-provider-v1"):
        raise EntraM365InputError()
    if len(content) > PAGE_MAX_BYTES:
        raise EntraM365InputError("response_limit")
    try:
        data = content.encode("utf-8")
    except UnicodeEncodeError:
        raise EntraM365InputError("invalid_body") from None
    if len(data) > PAGE_MAX_BYTES:
        raise EntraM365InputError("response_limit")
    try:
        value = parse_strict_json(data)
    except ValueError:
        raise EntraM365InputError("invalid_body") from None
    if format == "scubagear-provider-v1":
        if not isinstance(value, dict):
            raise EntraM365InputError()
        value = {
            "schema_version": 1,
            "source": {
                "kind": "operator-export",
                "producer": "ScubaGear",
                "producer_version": None,
                "captured_at": None,
                "parent_sha256": sha256(data).hexdigest(),
                "source_uri": None,
                "sanitization": "operator-declared",
            },
            "policies": _provider_records(value.get("dlp_compliance_policies"), _POLICY_FIELDS),
            "rules": _provider_records(value.get("dlp_compliance_rules"), _RULE_FIELDS),
        }
    try:
        return EntraM365DlpExport.model_validate(value)
    except ValidationError:
        raise EntraM365InputError() from None


def _policy_state(fields: JsonObject, diagnostics: Counter[DiagnosticCode]) -> _ConfigurationState:
    mode, enabled = fields["Mode"], fields["Enabled"]
    expected = False if mode == "Disable" else True if mode == "Enable" or mode in _TEST_MODES else None
    conflict = expected is not None and enabled is not None and enabled is not expected
    if conflict:
        diagnostics["conflicting_state"] += 1
    if fields["IsValid"] is not True:
        diagnostics["source_validity_unknown"] += 1
        return "unknown"
    if conflict or expected is None or enabled is None:
        return "unknown"
    return "disabled" if mode == "Disable" else "configured_enforce" if mode == "Enable" else "test"


def _rule_state(
    fields: JsonObject, parent_state: _ConfigurationState, diagnostics: Counter[DiagnosticCode]
) -> _ConfigurationState:
    if fields["IsValid"] is not True:
        diagnostics["source_validity_unknown"] += 1
        return "unknown"
    if fields["Disabled"] is True:
        return "disabled"
    if parent_state in ("disabled", "test"):
        return parent_state
    if parent_state == "configured_enforce" and fields["Mode"] == "Enforce" and fields["Disabled"] is False:
        return "configured_enforce"
    return "unknown"


def read_dlp_export(
    request: EntraM365CollectRequest,
    graph_reader: EntraM365GraphReader,
    run_context: EntraM365RunContext,
    dlp_export: EntraM365DlpExport | None = None,
) -> EntraM365CapabilityRead:
    """Join and classify admitted export rows without a Graph or PowerShell call."""
    request = EntraM365CollectRequest.model_validate(request)
    if request != run_context.request or "dlp-export" not in request.capabilities:
        raise ValueError("invalid_collection_request")
    if dlp_export is None:
        reading = run_context.begin("dlp-export", None)
        reading.add_diagnostic("input_missing")
        return run_context.finish_read(reading.finish_source(), findings=[])
    export = EntraM365DlpExport.model_validate(dlp_export)
    source = run_context.admit_dlp_export(export)
    policies = {record.source_id: record for record in source.records if record.kind == "dlp-policy"}
    names = Counter(cast(str, record.fields["Name"]) for record in policies.values())
    diagnostics: Counter[DiagnosticCode] = Counter()
    states = {identifier: _policy_state(record.fields, diagnostics) for identifier, record in policies.items()}
    joined: dict[str, list[JsonValue]] = {identifier: [] for identifier in policies}
    findings = []
    unresolved = []
    metadata = cast(JsonObject, export.source.model_dump())
    captured = export.source.captured_at
    age = (
        source_age_seconds(parse_source_timestamp(clock_text(run_context.window_end)), parse_source_timestamp(captured))
        if captured is not None
        else None
    )
    for record in source.records:
        if record.kind != "dlp-rule":
            continue
        reference = record.fields["Policy"]
        parent = policies.get(reference) if isinstance(reference, str) else None
        name = record.fields["ParentPolicyName"]
        if parent is None or (name is not None and (name != parent.fields["Name"] or names[cast(str, name)] != 1)):
            diagnostics["unresolved_parent"] += 1
            if record.fields["IsValid"] is not True:
                diagnostics["source_validity_unknown"] += 1
            unresolved.append(record)
        else:
            joined[parent.source_id].append(
                {
                    "source": record.fields,
                    "configuration_state": _rule_state(record.fields, states[parent.source_id], diagnostics),
                }
            )
    for identifier, record in policies.items():
        findings.append(
            run_context.make_finding(
                source,
                "dlp-policy-configuration",
                source_id=identifier,
                raw_data={
                    "configuration_state": states[identifier],
                    "distribution_status": record.fields["DistributionStatus"],
                    "rules": joined[identifier],
                    "export_source": metadata,
                    "source_age_seconds": age,
                },
            )
        )
    for record in unresolved:
        findings.append(
            run_context.make_finding(
                source,
                "dlp-unresolved-rule",
                source_id=record.source_id,
                raw_data={
                    "configuration_state": "unknown",
                    "parent_resolution": "unresolved",
                    "export_source": metadata,
                    "source_age_seconds": age,
                },
            )
        )
    return run_context.finish_read(
        source,
        findings=findings,
        diagnostics=[
            EntraM365Diagnostic(code=code, count=count, http_status=None) for code, count in diagnostics.items()
        ],
    )
