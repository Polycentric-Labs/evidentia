"""Observed Entra policy, registration, sign-in and activated-role evidence."""

from collections import Counter
from typing import cast

from ._client import EntraM365GraphReader
from ._contracts import (
    KNOWN_ENUMS,
    EntraM365CapabilityRead,
    EntraM365CollectRequest,
    EntraM365DlpExport,
    EntraM365RunContext,
    EntraM365SourceRead,
    JsonObject,
    JsonValue,
    clock_text,
    parse_source_timestamp,
    source_age_seconds,
)


def read_conditional_access(
    request: EntraM365CollectRequest,
    graph_reader: EntraM365GraphReader,
    run_context: EntraM365RunContext,
    dlp_export: EntraM365DlpExport | None = None,
) -> EntraM365CapabilityRead:
    """Report policy configuration without evaluating effective coverage."""
    source = graph_reader.read_collection("conditional-access", request, run_context)
    classifications = {
        "enabled": "enabled",
        "disabled": "disabled",
        "enabledForReportingButNotEnforced": "report_only",
    }
    findings = []
    for record in source.records:
        state = record.fields.get("state")
        classification = classifications.get(state, "unknown") if isinstance(state, str) else "unknown"
        findings.append(
            run_context.make_finding(
                source,
                "conditional-access-policy",
                source_id=record.source_id,
                raw_data={"configuration_state": classification},
            )
        )
    return run_context.finish_read(source, findings=findings)


def _flag_counts(source: EntraM365SourceRead, field: str) -> JsonObject:
    counts = {"true": 0, "false": 0, "null": 0, "absent": 0, "unknown": 0}
    for record in source.records:
        value = record.fields.get(field)
        if field not in record.fields:
            category = "absent"
        elif value is None:
            category = "null"
        elif value is True:
            category = "true"
        elif value is False:
            category = "false"
        else:
            category = "unknown"
        counts[category] += 1
    return {key: value for key, value in counts.items()}


def _method_counts(source: EntraM365SourceRead) -> JsonObject:
    """Count each literal method once per final observed report record."""
    methods: Counter[str] = Counter()
    for record in source.records:
        value = record.fields.get("methodsRegistered")
        if value is not None:
            # The shared projection has already validated this string array.
            methods.update(set(cast(list[str], value)))
    coverage = source.capability.field_coverage["methodsRegistered"]
    counts: list[JsonValue] = [{"method": method, "records": methods[method]} for method in sorted(methods)]
    return {
        "absent": coverage.absent,
        "null": coverage.null,
        "known": coverage.known,
        "unknown": coverage.unknown,
        "counts": counts,
    }


def _update_ages(source: EntraM365SourceRead, run_context: EntraM365RunContext) -> JsonObject:
    """Group literal update times without retaining report-user identities."""
    timestamps: Counter[str] = Counter(
        cast(str, record.fields["lastUpdatedDateTime"])
        for record in source.records
        if record.fields.get("lastUpdatedDateTime") is not None
    )
    end = parse_source_timestamp(clock_text(run_context.window_end))
    values: list[JsonValue] = []
    future = 0
    for literal in sorted(timestamps):
        age = source_age_seconds(end, parse_source_timestamp(literal))
        count = timestamps[literal]
        if age is None:
            future += count
        values.append({"source_timestamp": literal, "age_seconds": age, "records": count})
    coverage = source.capability.field_coverage["lastUpdatedDateTime"]
    return {
        "absent": coverage.absent,
        "null": coverage.null,
        "known": coverage.known,
        "unknown": coverage.unknown,
        "future": future,
        "values": values,
    }


def read_authentication_registration(
    request: EntraM365CollectRequest,
    graph_reader: EntraM365GraphReader,
    run_context: EntraM365RunContext,
    dlp_export: EntraM365DlpExport | None = None,
) -> EntraM365CapabilityRead:
    """Summarize independent registration flags over observed report records."""
    source = graph_reader.read_collection("authentication-registration", request, run_context)
    findings = []
    if source.records:
        findings.append(
            run_context.make_finding(
                source,
                "authentication-registration-summary",
                source_id=None,
                raw_data={
                    "observed_records": len(source.records),
                    "is_mfa_registered": _flag_counts(source, "isMfaRegistered"),
                    "is_mfa_capable": _flag_counts(source, "isMfaCapable"),
                    "methods_registered": _method_counts(source),
                    "last_updated": _update_ages(source, run_context),
                },
            )
        )
    return run_context.finish_read(source, findings=findings)


def read_sign_ins(
    request: EntraM365CollectRequest,
    graph_reader: EntraM365GraphReader,
    run_context: EntraM365RunContext,
    dlp_export: EntraM365DlpExport | None = None,
) -> EntraM365CapabilityRead:
    """Describe final in-window events and the availability of policy detail."""
    source = graph_reader.read_collection("sign-ins", request, run_context)
    findings = []
    for record in source.records:
        status = record.fields.get("conditionalAccessStatus")
        observed_status = (
            status
            if isinstance(status, str) and status in KNOWN_ENUMS[("sign-ins", "conditionalAccessStatus")]
            else "unknown"
        )
        findings.append(
            run_context.make_finding(
                source,
                "sign-in-observation",
                source_id=record.source_id,
                raw_data={
                    "conditional_access_status": observed_status,
                    # The fixed v1.0 method does not establish this optional field.
                    "authentication_requirement": "unknown",
                    "conditional_access_detail": (
                        "available"
                        if record.fields.get("appliedConditionalAccessPolicies") is not None
                        else "unavailable"
                    ),
                },
            )
        )
    return run_context.finish_read(source, findings=findings)


def read_directory_roles(
    request: EntraM365CollectRequest,
    graph_reader: EntraM365GraphReader,
    run_context: EntraM365RunContext,
    dlp_export: EntraM365DlpExport | None = None,
) -> EntraM365CapabilityRead:
    """Inventory activated roles without assignments, membership or eligibility."""
    source = graph_reader.read_collection("directory-roles", request, run_context)
    findings = [
        run_context.make_finding(
            source,
            "directory-role-inventory",
            source_id=record.source_id,
            raw_data={
                "inventory_scope": "activated_roles",
                "assignments_assessed": False,
                "membership_assessed": False,
                "eligibility_assessed": False,
            },
        )
        for record in source.records
    ]
    return run_context.finish_read(source, findings=findings)
