"""Synthetic transport acceptance for observed Intune device states."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from evidentia_collectors.entra_m365._contracts import EntraM365CollectResult
from evidentia_collectors.entra_m365.devices import read_managed_devices

from .entra_m365._transport_support import DEVICE_PATH, NOW, ORIGIN, PRIMARY, Reply, assert_closed, codes, encode_page
from .entra_m365.conftest import make_run as make_run
from .entra_m365.conftest import runtime as runtime

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "entra_m365" / "devices" / "managed-devices.json"


def _read(make_run, rows, **options):
    run = make_run([Reply(encode_page(rows))], capabilities=["managed-devices"], **options)
    read = read_managed_devices(run.request, run.reader, run.context)
    return run, read


def _result(run, read):
    result = run.context.build_result([read])
    restored = EntraM365CollectResult.model_validate_json(result.model_dump_json())
    assert restored.model_dump_json() == result.model_dump_json()
    assert result.manifest.total_findings == read.capability.collected == len(read.findings)
    return result


def test_device_fixture_keeps_literal_state_and_exact_source_ages(make_run):
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert fixture["kind"] == "authored-synthetic"
    replies = [
        Reply(json.dumps(row["body"]).encode(), status=row["status"], headers=row["headers"])
        for row in fixture["exchanges"]
    ]
    run = make_run(replies, capabilities=["managed-devices"])
    read = read_managed_devices(run.request, run.reader, run.context)
    result = _result(run, read)
    assert read.capability.state == "complete"
    assert read.capability.scanned == read.capability.matched_filter == read.capability.collected == 6
    assert read.capability.pages_completed == read.capability.requests_attempted == 2
    assert len(run.scenario.requests) == len(fixture["exchanges"])
    for actual, expected in zip(run.scenario.requests, fixture["exchanges"], strict=True):
        assert actual.method == expected["method"]
        assert actual.url.host == "graph.microsoft.com"
        assert actual.url.path == expected["route"]
        assert actual.url.query.decode() == expected["query"]
        assert actual.headers["authorization"] == "Bearer " + PRIMARY
        assert "prefer" not in actual.headers
    assert run.provider.calls == ["primary"]
    assert read.findings[0].raw_data["source"] == {
        "id": " device-a ",
        "complianceState": "compliant",
        "managementState": "managed",
        "lastSyncDateTime": "2026-09-09t23:59:59.999999999999z",
    }
    assert [finding.raw_data["observation"] for finding in read.findings] == [
        {
            "compliance_state": "compliant",
            "management_state": "managed",
            "last_sync": {
                "state": "known",
                "source_timestamp": "2026-09-09t23:59:59.999999999999z",
                "age_seconds": "0.000000000001",
            },
        },
        {
            "compliance_state": "noncompliant",
            "management_state": "unhealthy",
            "last_sync": {"state": "known", "source_timestamp": "2026-08-01T00:00:00Z", "age_seconds": "3456000"},
        },
        {
            "compliance_state": "unknown",
            "management_state": "unknown",
            "last_sync": {
                "state": "future",
                "source_timestamp": "2026-09-10T00:00:00.000000000001Z",
                "age_seconds": None,
            },
        },
        {
            "compliance_state": "unknown",
            "management_state": "unknown",
            "last_sync": {"state": "null", "source_timestamp": None, "age_seconds": None},
        },
        {
            "compliance_state": "unknown",
            "management_state": "unknown",
            "last_sync": {"state": "absent", "source_timestamp": None, "age_seconds": None},
        },
        {
            "compliance_state": "configManager",
            "management_state": "retireCanceled",
            "last_sync": {"state": "known", "source_timestamp": "2026-09-10T00:00:00Z", "age_seconds": "0"},
        },
    ]
    assert [(item.code, item.count) for item in read.capability.diagnostics] == [("future_timestamp", 1)]
    for key in ("complianceState", "managementState"):
        assert read.capability.field_coverage[key].model_dump() == {"absent": 1, "null": 1, "known": 3, "unknown": 1}
    assert read.capability.field_coverage["lastSyncDateTime"].model_dump() == {
        "absent": 1,
        "null": 1,
        "known": 4,
        "unknown": 0,
    }
    for finding in read.findings:
        assert finding.compliance_status.value == "unknown"
        assert finding.severity.value == "informational"
        assert finding.status.value == "active"
        assert finding.first_observed == finding.last_observed == NOW
        assert finding.resolved_at is None
        assert finding.collection_context.run_id == run.context.run_id
        assert [mapping.control_id for mapping in finding.control_mappings] == ["CM-8", "CA-7"]
        assert {mapping.relationship for mapping in finding.control_mappings} == {"intersects-with"}
        assert "stale" not in finding.raw_data["observation"]
    assert read.findings[0].source_finding_id == "synthetic-reader:managed-devices: device-a "
    assert "SYNTHETIC-EXCLUDED-DEVICE" not in result.model_dump_json()
    assert read.capability.observed_first is read.capability.observed_last is None
    assert read.capability.requested_window_start is read.capability.requested_window_end is None
    assert result.manifest.is_complete
    assert result.full_surface_complete is False
    assert_closed(run)


def test_empty_device_collection_is_complete_and_visible_in_manifest(make_run):
    run, read = _read(make_run, [])
    result = _result(run, read)
    assert read.findings == ()
    assert read.capability.state == "complete"
    assert read.capability.pages_completed == 1
    assert read.capability.scanned == read.capability.matched_filter == read.capability.collected == 0
    assert result.manifest.empty_categories == ["managed-devices"]
    assert result.manifest.errors == []


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("id", " "),
        ("id", 1),
        ("id", "x" * 513),
        ("complianceState", False),
        ("complianceState", "x" * 129),
        ("managementState", []),
        ("lastSyncDateTime", True),
        ("lastSyncDateTime", 0),
        ("lastSyncDateTime", "2026-09-09T00:00:00"),
        ("lastSyncDateTime", "2026-02-30T00:00:00Z"),
        ("lastSyncDateTime", "0001-01-01T00:00:00+00:01"),
        ("lastSyncDateTime", "2026-09-09T00:00:60Z"),
    ],
)
def test_invalid_selected_device_field_rejects_whole_page(make_run, key, value):
    run, read = _read(make_run, [{"id": "valid", "complianceState": "compliant"}, {"id": "invalid", key: value}])
    _result(run, read)
    assert read.capability.state == "unavailable"
    assert read.capability.scanned == read.capability.matched_filter == read.capability.collected == 0
    assert read.findings == ()
    assert codes(read) == {"invalid_record"}
    assert_closed(run)


@pytest.mark.parametrize(
    ("field", "literal", "observed"),
    [
        ("complianceState", "compliant", "compliant"),
        ("complianceState", "inGracePeriod", "inGracePeriod"),
        ("complianceState", "unknown", "unknown"),
        ("complianceState", "Compliant", "unknown"),
        ("complianceState", "new-state", "unknown"),
        ("managementState", "retireCanceled", "retireCanceled"),
        ("managementState", "discovered", "discovered"),
        ("managementState", "unknownFutureValue", "unknown"),
        ("managementState", " managed ", "unknown"),
    ],
)
def test_device_enum_membership_is_exact_and_not_a_compliance_verdict(make_run, field, literal, observed):
    run, read = _read(make_run, [{"id": "device", field: literal}])
    _result(run, read)
    observation_key = "compliance_state" if field == "complianceState" else "management_state"
    assert read.findings[0].raw_data["observation"][observation_key] == observed
    assert read.findings[0].raw_data["source"][field] == literal
    assert read.findings[0].compliance_status.value == "unknown"
    assert read.capability.state == "complete"


def test_duplicate_and_conflicting_device_versions_do_not_leave_ages_or_future_counts(make_run):
    future = {"id": "conflict", "lastSyncDateTime": "2026-09-10T00:00:00.000000000001Z", "complianceState": "compliant"}
    survivor = {"id": "survivor", "lastSyncDateTime": "2026-09-09T23:59:59.9999999Z", "managementState": "managed"}
    run = make_run(
        [
            Reply(encode_page([future, survivor, survivor], ORIGIN + DEVICE_PATH + "?page=2")),
            Reply(encode_page([{**future, "complianceState": "noncompliant"}])),
        ],
        capabilities=["managed-devices"],
    )
    read = read_managed_devices(run.request, run.reader, run.context)
    _result(run, read)
    assert read.capability.state == "partial"
    assert read.capability.scanned == 4
    assert read.capability.duplicate_records == 1
    assert read.capability.matched_filter == read.capability.collected == 1
    assert codes(read) == {"conflicting_duplicate"}
    assert read.findings[0].resource_id == "survivor"
    assert read.findings[0].raw_data["observation"]["last_sync"]["age_seconds"] == "0.0000001"
    assert run.context.slots_used == 2


@pytest.mark.parametrize("stop_kind", ["terminal", "continuation", "over"])
def test_device_item_cap_preserves_only_admitted_observations(make_run, stop_kind):
    rows = [{"id": "one"}, {"id": "one"}, {"id": "two"}]
    if stop_kind == "over":
        rows.append({"id": "unadmitted"})
    continuation = ORIGIN + DEVICE_PATH + "?page=2" if stop_kind == "continuation" else None
    run = make_run(
        [Reply(encode_page(rows, continuation))],
        capabilities=["managed-devices"],
        request_fields={"max_items": 2},
    )
    read = read_managed_devices(run.request, run.reader, run.context)
    result = _result(run, read)
    assert [finding.resource_id for finding in read.findings] == ["one", "two"]
    assert read.capability.duplicate_records == 1
    assert read.capability.state == ("complete" if stop_kind == "terminal" else "partial")
    assert result.manifest.is_complete == (stop_kind == "terminal")
    assert len(run.scenario.requests) == 1


def test_device_page_failure_preserves_prior_findings_without_leaking_upstream_body(make_run, caplog):
    marker = "SYNTHETIC_DEVICE_ERROR_BODY"
    run = make_run(
        [
            Reply(encode_page([{"id": "prior", "complianceState": "noncompliant"}], ORIGIN + DEVICE_PATH + "?page=2")),
            Reply(marker.encode(), status=403),
        ],
        capabilities=["managed-devices"],
    )
    read = read_managed_devices(run.request, run.reader, run.context)
    result = _result(run, read)
    assert read.capability.state == "partial"
    assert read.capability.collected == read.capability.scanned == 1
    assert [(item.code, item.count, item.http_status) for item in read.capability.diagnostics] == [
        ("permission_denied", 1, 403)
    ]
    assert read.findings[0].raw_data["observation"]["compliance_state"] == "noncompliant"
    assert marker not in result.model_dump_json()
    assert marker not in caplog.text
    assert_closed(run)


def test_maximum_source_precision_produces_an_exact_age_string(make_run):
    timestamp = "2026-09-09T23:59:59." + "9" * 2027 + "Z"
    assert len(timestamp) == 2048
    run, read = _read(make_run, [{"id": "precise", "lastSyncDateTime": timestamp}])
    result = _result(run, read)
    assert read.findings[0].raw_data["source"]["lastSyncDateTime"] == timestamp
    assert read.findings[0].raw_data["observation"]["last_sync"]["age_seconds"] == "0." + "0" * 2026 + "1"
    assert result.manifest.is_complete


def test_overlong_source_precision_rejects_the_page(make_run):
    timestamp = "2026-09-09T23:59:59." + "9" * 2028 + "Z"
    run, read = _read(make_run, [{"id": "overlong", "lastSyncDateTime": timestamp}])
    _result(run, read)
    assert read.capability.state == "unavailable"
    assert read.findings == ()
    assert codes(read) == {"invalid_record"}


def test_device_snapshots_and_finding_ids_are_isolated_across_runs(make_run):
    row = {"id": "literal device ", "lastSyncDateTime": "2026-09-09T23:59:59-00:00"}
    first, read = _read(make_run, [row])
    result = _result(first, read)
    saved = deepcopy(result.findings[0].raw_data)
    read.findings[0].raw_data["observation"]["last_sync"]["age_seconds"] = "changed"
    assert result.findings[0].raw_data == saved
    second, other = _read(make_run, [row])
    _result(second, other)
    assert other.findings[0].raw_data == saved
    assert other.findings[0].id == result.findings[0].id
    assert other.findings[0].collection_context.run_id != result.findings[0].collection_context.run_id
