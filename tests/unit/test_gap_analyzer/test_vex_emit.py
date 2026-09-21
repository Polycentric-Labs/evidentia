"""VEX export contracts for literal control-gap observations in versions 1.6 and 1.7."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

import pytest
from evidentia_core.gap_analyzer import export_report, reporter
from evidentia_core.gap_analyzer.vex import gap_report_to_cyclonedx_vex
from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    GapStatus,
    ImplementationEffort,
)
from jsonschema import Draft7Validator, ValidationError
from referencing import Registry
from referencing.exceptions import Unresolvable


def _gap(
    control_id: str,
    severity: GapSeverity,
    implementation_status: str = "missing",
    status: GapStatus = GapStatus.OPEN,
    **kw: Any,
) -> ControlGap:
    return ControlGap(
        framework="nist-800-53-rev5",
        control_id=control_id,
        control_title=f"{control_id} title",
        control_description=f"{control_id} description",
        gap_severity=severity,
        implementation_status=implementation_status,
        gap_description=f"{control_id} is not implemented.",
        remediation_guidance=f"Implement {control_id}.",
        implementation_effort=ImplementationEffort.MEDIUM,
        status=status,
        **kw,
    )


def _report(gaps: list[ControlGap]) -> GapAnalysisReport:
    sev = [g.gap_severity for g in gaps]
    return GapAnalysisReport(
        organization="Acme",
        frameworks_analyzed=["nist-800-53-rev5"],
        total_controls_required=100,
        total_controls_in_inventory=80,
        total_gaps=len(gaps),
        critical_gaps=sum(1 for s in sev if s == GapSeverity.CRITICAL),
        high_gaps=sum(1 for s in sev if s == GapSeverity.HIGH),
        medium_gaps=sum(1 for s in sev if s == GapSeverity.MEDIUM),
        low_gaps=sum(1 for s in sev if s == GapSeverity.LOW),
        coverage_percentage=80.0,
        gaps=gaps,
        inventory_source="inventory.yaml",
    )


# ---------------------------------------------------------------------------
# Vector 1 - Minimal positive: envelope + per-gap vulnerability
# ---------------------------------------------------------------------------


def test_cyclonedx_vex_envelope_has_bom_format_and_spec_version() -> None:
    vex = gap_report_to_cyclonedx_vex(_report([_gap("AC-2", GapSeverity.HIGH)]))
    assert vex["bomFormat"] == "CycloneDX"
    assert vex["specVersion"] == "1.6"
    assert vex["version"] == 1
    assert UUID(vex["serialNumber"]).urn == vex["serialNumber"]


def test_metadata_tool_is_evidentia() -> None:
    vex = gap_report_to_cyclonedx_vex(_report([_gap("AC-2", GapSeverity.HIGH)]))
    tool = vex["metadata"]["tools"]["components"][0]
    assert tool["name"] == "Evidentia"
    assert tool["publisher"] == "Polycentric Labs"
    assert tool["type"] == "application"
    assert tool["version"]


def test_each_gap_becomes_one_vulnerability_entry() -> None:
    report = _report([_gap("AC-2", GapSeverity.HIGH), _gap("AC-3", GapSeverity.MEDIUM)])
    vex = gap_report_to_cyclonedx_vex(report)
    assert len(vex["vulnerabilities"]) == 2
    ids = {v["id"] for v in vex["vulnerabilities"]}
    assert ids == {report.gaps[0].id, report.gaps[1].id}


def test_severity_maps_to_cyclonedx_rating() -> None:
    report = _report(
        [
            _gap("C", GapSeverity.CRITICAL),
            _gap("H", GapSeverity.HIGH),
            _gap("M", GapSeverity.MEDIUM),
            _gap("L", GapSeverity.LOW),
            _gap("I", GapSeverity.INFORMATIONAL),
        ]
    )
    vex = gap_report_to_cyclonedx_vex(report)

    # EvidentiaModel uses use_enum_values=True so gap_severity comes
    # back as a plain str; unwrap defensively for the cross-key build.
    def _sev(g: ControlGap) -> str:
        return g.gap_severity.value if hasattr(g.gap_severity, "value") else str(g.gap_severity)

    by_gap_severity = {
        _sev(gap): vex["vulnerabilities"][i]["ratings"][0]["severity"] for i, gap in enumerate(report.gaps)
    }
    assert by_gap_severity == {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "info",
    }


def test_recommendation_carries_remediation_guidance() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH)
    gap.remediation_guidance = "Wire IAM federation to corporate SSO."
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["recommendation"] == "Wire IAM federation to corporate SSO."


def test_description_carries_framework_and_control() -> None:
    vex = gap_report_to_cyclonedx_vex(_report([_gap("AC-2", GapSeverity.HIGH)]))
    description = vex["vulnerabilities"][0]["description"]
    assert "nist-800-53-rev5" in description
    assert "AC-2" in description


def test_properties_carry_evidentia_metadata() -> None:
    """CycloneDX `properties` carries framework + control_id +
    implementation_status as name/value pairs for downstream consumers
    that re-key per control."""
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="partial")
    gap.cross_framework_value = ["soc2-tsc:CC6.1"]
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    props = {p["name"]: p["value"] for p in vex["vulnerabilities"][0]["properties"]}
    assert props["evidentia:framework"] == "nist-800-53-rev5"
    assert props["evidentia:control_id"] == "AC-2"
    assert props["evidentia:implementation_status"] == "partial"
    assert "evidentia:cross_framework_value" in props


# ---------------------------------------------------------------------------
# Literal observations retain the historical control-gap cases
# ---------------------------------------------------------------------------


def test_implemented_is_only_a_control_gap_observation() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="implemented")
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"] == {
        "detail": _detail(
            gap.implementation_status, gap.status.value if isinstance(gap.status, GapStatus) else gap.status
        )
    }


def test_missing_open_has_no_impact_verdict() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="missing")
    gap.status = GapStatus.OPEN
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"] == {
        "detail": _detail(
            gap.implementation_status, gap.status.value if isinstance(gap.status, GapStatus) else gap.status
        )
    }


def test_in_progress_has_no_impact_verdict() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="missing")
    gap.status = GapStatus.IN_PROGRESS
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"] == {
        "detail": _detail(
            gap.implementation_status, gap.status.value if isinstance(gap.status, GapStatus) else gap.status
        )
    }


def test_remediated_has_no_impact_verdict() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="missing")
    gap.status = GapStatus.REMEDIATED
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"] == {
        "detail": _detail(
            gap.implementation_status, gap.status.value if isinstance(gap.status, GapStatus) else gap.status
        )
    }


def test_risk_acceptance_has_no_code_reachability_justification() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="missing")
    gap.status = GapStatus.ACCEPTED
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"] == {
        "detail": _detail(
            gap.implementation_status, gap.status.value if isinstance(gap.status, GapStatus) else gap.status
        )
    }


def test_partial_has_no_impact_verdict() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="partial")
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"] == {
        "detail": _detail(
            gap.implementation_status, gap.status.value if isinstance(gap.status, GapStatus) else gap.status
        )
    }


def test_planned_has_no_impact_verdict() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="planned")
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"] == {
        "detail": _detail(
            gap.implementation_status, gap.status.value if isinstance(gap.status, GapStatus) else gap.status
        )
    }


def test_control_inapplicability_has_no_code_presence_justification() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="not_applicable")
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"] == {
        "detail": _detail(
            gap.implementation_status, gap.status.value if isinstance(gap.status, GapStatus) else gap.status
        )
    }


def test_justification_is_absent_from_control_gap_observation() -> None:
    """Control lifecycle alone cannot justify a vulnerability-impact assertion."""
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="missing")
    gap.status = GapStatus.OPEN
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert "justification" not in vex["vulnerabilities"][0]["analysis"]


def test_analysis_detail_carries_literal_observation() -> None:
    gap = _gap("AC-2", GapSeverity.HIGH, implementation_status="partial")
    vex = gap_report_to_cyclonedx_vex(_report([gap]))
    assert vex["vulnerabilities"][0]["analysis"] == {"detail": _detail("partial", "open")}


# ---------------------------------------------------------------------------
# Vector 2 - Empty inventory / zero-gap report
# ---------------------------------------------------------------------------


def test_empty_report_produces_empty_vulnerabilities_array() -> None:
    vex = gap_report_to_cyclonedx_vex(_report([]))
    assert vex["bomFormat"] == "CycloneDX"
    assert vex["vulnerabilities"] == []


# ---------------------------------------------------------------------------
# Vector 4 - Round-trip via the `export_report` dispatch
# ---------------------------------------------------------------------------


def test_export_report_writes_cyclonedx_vex_file(tmp_path: Path) -> None:
    """End-to-end via the public export_report dispatch: --format
    cyclonedx-vex writes a JSON document to disk that round-trips into
    a dict with the expected CycloneDX 1.6 VEX shape."""
    report = _report([_gap("AC-2", GapSeverity.CRITICAL), _gap("AC-3", GapSeverity.LOW)])
    output_path = tmp_path / "gaps.vex.json"

    returned_path = export_report(report, output_path, format="cyclonedx-vex")

    assert returned_path == output_path
    loaded = json.loads(output_path.read_text(encoding="utf-8"))
    assert loaded["bomFormat"] == "CycloneDX"
    assert loaded["specVersion"] == "1.6"
    assert len(loaded["vulnerabilities"]) == 2


# ---------------------------------------------------------------------------
# Vector 7 - Round-trip JSON validity + serial-number determinism
# ---------------------------------------------------------------------------


def test_serial_number_is_deterministic_for_same_report() -> None:
    """A re-emit of the same report produces the same `serialNumber`
    so VEX consumers can detect idempotent re-publishes."""
    report = _report([_gap("AC-2", GapSeverity.HIGH)])
    a = gap_report_to_cyclonedx_vex(report)
    b = gap_report_to_cyclonedx_vex(report)
    assert a["serialNumber"] == b["serialNumber"]


def test_all_vulnerabilities_have_required_cyclonedx_fields() -> None:
    """Every output record retains its source, rating and detail-only observation."""
    report = _report(
        [
            _gap("C", GapSeverity.CRITICAL),
            _gap("H", GapSeverity.HIGH, implementation_status="partial"),
            _gap("M", GapSeverity.MEDIUM, implementation_status="implemented"),
        ]
    )
    vex = gap_report_to_cyclonedx_vex(report)
    for vuln in vex["vulnerabilities"]:
        assert "id" in vuln
        assert "source" in vuln
        assert vuln["source"]["name"] == "Evidentia"
        assert "ratings" in vuln
        assert len(vuln["ratings"]) == 1
        assert "analysis" in vuln
        assert set(vuln["analysis"]) == {"detail"}


def _detail(implementation: str, lifecycle: str) -> str:
    return (
        "Control-gap lifecycle observation only. "
        f"implementation_status={implementation}; gap_status={lifecycle}. "
        "No component or service applicability, vulnerable-code presence or "
        "exploitability assessment is provided."
    )


def _fixed_report(gaps: list[ControlGap]) -> GapAnalysisReport:
    return _report(gaps).model_copy(
        update={"id": "vex-contract-report", "analyzed_at": datetime(2026, 1, 1, tzinfo=UTC)}
    )


@pytest.mark.parametrize("version", ["1.6", "1.7"])
def test_literal_versions_and_omitted_default(version: str, tmp_path: Path) -> None:
    report = _fixed_report([_gap("AC-2", GapSeverity.HIGH)])
    original = report.model_dump(mode="python")
    default = gap_report_to_cyclonedx_vex(report)
    assert default == gap_report_to_cyclonedx_vex(report, spec_version="1.6")
    selected = gap_report_to_cyclonedx_vex(report, spec_version=version)
    expected = copy.deepcopy(default)
    expected["specVersion"] = version
    assert selected == expected
    first = tmp_path / "omitted.json"
    second = tmp_path / "explicit.json"
    export_report(report, first, format="cyclonedx-vex")
    export_report(report, second, format="cyclonedx-vex", vex_spec_version="1.6")
    assert first.read_bytes() == second.read_bytes()
    export_report(report, second, format="cyclonedx-vex", vex_spec_version=version)
    assert json.loads(second.read_bytes()) == selected
    assert report.model_dump(mode="python") == original


class _VersionText(str):
    pass


@pytest.mark.parametrize("invalid", ["1.5", "1.8", " 1.7", "1.7 ", "", None, True, 1.7, [], {}, _VersionText("1.6")])
def test_invalid_native_selector_refuses_before_output(
    invalid: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = _fixed_report([])
    with pytest.raises(ValueError):
        gap_report_to_cyclonedx_vex(report, spec_version=invalid)
    calls: list[str] = []

    def forbidden(*args: Any, **kwargs: Any) -> Path:
        calls.append("exporter")
        raise AssertionError("invalid selection reached an exporter")

    monkeypatch.setattr(reporter, "_export_cyclonedx_vex", forbidden)
    target = tmp_path / "existing.json"
    target.write_bytes(b"preserve-existing-output")
    with pytest.raises(ValueError):
        export_report(report, target, format="cyclonedx-vex", vex_spec_version=invalid)
    assert target.read_bytes() == b"preserve-existing-output"
    assert calls == []


@pytest.mark.parametrize(
    "format_name,exporter_name",
    [
        ("json", "_export_json"),
        ("csv", "_export_csv"),
        ("markdown", "_export_markdown"),
        ("oscal-ar", "_export_oscal_ar"),
        ("sarif", "_export_sarif"),
        ("ocsf", "_export_ocsf"),
        ("ocsf-detection", "_export_ocsf_detection"),
    ],
)
def test_non_vex_omission_keeps_dispatch_and_explicit_presence_refuses(
    format_name: Any, exporter_name: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    target = tmp_path / "untouched"
    report = _fixed_report([])

    def capture(*args: Any, **kwargs: Any) -> Path:
        calls.append((args, kwargs))
        return target

    monkeypatch.setattr(reporter, exporter_name, capture)
    assert export_report(report, target, format=format_name) == target
    assert len(calls) == 1 and calls[0][0] == (report, target)
    assert "vex_spec_version" not in calls[0][1] and "spec_version" not in calls[0][1]
    calls.clear()
    for version in ["1.6", "1.7", None, False, "invalid"]:
        with pytest.raises(ValueError):
            export_report(
                report,
                target,
                format=format_name,
                vex_spec_version=version,
                gpg_key_id="synthetic-unused",
                sign_with_sigstore=True,
                key_sign_path="synthetic-unused",
            )
    assert calls == []
    assert not target.exists()


@pytest.mark.parametrize("version", ["1.6", "1.7"])
def test_uuid_uses_original_report_identity_and_timestamp_representation(version: str) -> None:
    report = _fixed_report([])
    before = report.model_dump(mode="python")
    expected = uuid5(
        NAMESPACE_URL, "https://github.com/Polycentric-Labs/evidentia#vex:vex-contract-report:2026-01-01T00:00:00+00:00"
    ).urn
    first = gap_report_to_cyclonedx_vex(report, spec_version=version)
    assert first["serialNumber"] == expected
    assert UUID(first["serialNumber"]).urn == first["serialNumber"]
    other_id = report.model_copy(update={"id": "other-vex-report"})
    assert gap_report_to_cyclonedx_vex(other_id, spec_version=version)["serialNumber"] != expected
    other_spelling = report.model_copy(update={"analyzed_at": datetime.fromisoformat("2026-01-01T01:00:00+01:00")})
    second = gap_report_to_cyclonedx_vex(other_spelling, spec_version=version)
    assert second["serialNumber"] != expected
    assert second["metadata"]["timestamp"] == first["metadata"]["timestamp"]
    assert report.model_dump(mode="python") == before


@pytest.mark.parametrize("version", ["1.6", "1.7"])
@pytest.mark.parametrize(
    "source,expected",
    [
        ("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00.000000Z"),
        ("2026-01-01T00:00:00+05:30", "2025-12-31T18:30:00.000000Z"),
        ("2026-01-01T00:00:00+00:00:30", "2025-12-31T23:59:30.000000Z"),
        ("2024-02-29T12:34:56.000789+00:00", "2024-02-29T12:34:56.000789Z"),
        ("0001-01-01T00:00:00+00:00", "0001-01-01T00:00:00.000000Z"),
        ("9999-12-31T23:59:59.999999+00:00", "9999-12-31T23:59:59.999999Z"),
    ],
)
def test_timestamp_same_instant_canonical_calendar(source: str, expected: str, version: str) -> None:
    instant = datetime.fromisoformat(source)
    report = _fixed_report([]).model_copy(update={"analyzed_at": instant})
    doc = gap_report_to_cyclonedx_vex(report, spec_version=version)
    assert doc["metadata"]["timestamp"] == expected
    assert datetime.fromisoformat(expected) == instant
    assert report.analyzed_at is instant
    _validate_document(doc, version)


class _UndefinedOffset(tzinfo):
    def utcoffset(self, dt: datetime | None) -> None:
        return None

    def dst(self, dt: datetime | None) -> None:
        return None

    def tzname(self, dt: datetime | None) -> None:
        return None


@pytest.mark.parametrize(
    "instant",
    [
        datetime(2026, 1, 1),
        datetime(2026, 1, 1, tzinfo=_UndefinedOffset()),
        datetime.fromisoformat("0001-01-01T00:00:00+01:00"),
        datetime.fromisoformat("9999-12-31T23:59:59.999999-01:00"),
    ],
)
@pytest.mark.parametrize("version", ["1.6", "1.7"])
def test_unusable_timestamp_refuses_without_touching_output(instant: datetime, version: str, tmp_path: Path) -> None:
    report = _fixed_report([]).model_copy(update={"analyzed_at": instant})
    target = tmp_path / "existing.json"
    target.write_bytes(b"old-output")
    with pytest.raises(ValueError):
        gap_report_to_cyclonedx_vex(report, spec_version=version)
    with pytest.raises(ValueError):
        export_report(report, target, format="cyclonedx-vex", vex_spec_version=version)
    assert target.read_bytes() == b"old-output"
    assert report.analyzed_at is instant


@pytest.mark.parametrize("version", ["1.6", "1.7"])
@pytest.mark.parametrize(
    "implementation", ["missing", "partial", "planned", "implemented", "not_applicable", "operator-defined; <tag>"]
)
@pytest.mark.parametrize("lifecycle", ["open", "in_progress", "remediated", "accepted", "not_applicable"])
def test_all_gap_states_preserve_exact_source_fields_without_impact_claims(
    version: str, implementation: str, lifecycle: str
) -> None:
    gap = _gap(
        "AC-2",
        GapSeverity.HIGH,
        implementation_status=implementation,
        status=GapStatus(lifecycle),
        priority_score=7.25,
        cross_framework_value=["soc2-tsc:CC6.1", "iso27001:A.8"],
    )
    report = _fixed_report([gap])
    before = report.model_dump(mode="python")
    doc = gap_report_to_cyclonedx_vex(report, spec_version=version)
    assert doc["vulnerabilities"] == [
        {
            "bom-ref": gap.id,
            "id": gap.id,
            "source": {"name": "Evidentia", "url": "https://github.com/Polycentric-Labs/evidentia"},
            "ratings": [{"source": {"name": "Evidentia"}, "severity": "high", "method": "other"}],
            "description": "nist-800-53-rev5 AC-2 (AC-2 title): AC-2 is not implemented.",
            "analysis": {"detail": _detail(implementation, lifecycle)},
            "recommendation": "Implement AC-2.",
            "properties": [
                {"name": "evidentia:framework", "value": "nist-800-53-rev5"},
                {"name": "evidentia:control_id", "value": "AC-2"},
                {"name": "evidentia:implementation_status", "value": implementation},
                {"name": "evidentia:gap_status", "value": lifecycle},
                {"name": "evidentia:priority_score", "value": "7.25"},
                {"name": "evidentia:cross_framework_value", "value": "soc2-tsc:CC6.1, iso27001:A.8"},
            ],
        }
    ]
    assert report.model_dump(mode="python") == before
    _validate_document(doc, version)


@pytest.mark.parametrize("version", ["1.6", "1.7"])
@pytest.mark.parametrize("count", [0, 2])
def test_empty_and_multiple_gap_order_and_empty_optional_fields(version: str, count: int) -> None:
    gaps = [_gap(f"AC-{index}", GapSeverity.LOW) for index in range(count)]
    for gap in gaps:
        gap.remediation_guidance = ""
    report = _fixed_report(gaps)
    doc = gap_report_to_cyclonedx_vex(report, spec_version=version)
    assert [row["id"] for row in doc["vulnerabilities"]] == [gap.id for gap in gaps]
    for row in doc["vulnerabilities"]:
        assert "recommendation" not in row and "affects" not in row
        assert [prop["name"] for prop in row["properties"]] == [
            "evidentia:framework",
            "evidentia:control_id",
            "evidentia:implementation_status",
            "evidentia:gap_status",
            "evidentia:priority_score",
        ]
    _validate_document(doc, version)


_SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "cyclonedx"
_SOURCE_HASHES = {
    "bom-1.6.schema.json": "4cb5659bb51fd3c52b90e3da325ea7998309bab0aeeef5cafaf75ccb12740ad2",
    "bom-1.7.schema.json": "04dfc1351f9c4b30777db4b7b4cef774993cad36c9d6ef482bcaa40f594a15aa",
    "source-index.json": "97747f3942230e22bb3ef301af12e2cc0911e47288bfe447d27ead4dbf26b4ba",
    "LICENSE-2.0.txt": "6c29f22a4a7385285c6f579ec9f33c5e989f00739d6b257243a0b082ec9447ae",
}


def _schema(version: str) -> dict[str, Any]:
    raw = (_SCHEMA_ROOT / f"bom-{version}.schema.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == _SOURCE_HASHES[f"bom-{version}.schema.json"]
    return dict(json.loads(raw))


def _validate_document(doc: dict[str, Any], version: str) -> None:
    assert doc["specVersion"] == version
    clock = doc["metadata"]["timestamp"]
    assert re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z", clock)
    assert datetime.fromisoformat(clock).utcoffset() == timedelta(0)
    # An explicit empty Registry has no retrieval callback; absent resources fail locally.
    Draft7Validator(_schema(version), registry=Registry()).validate(doc)


def test_all_four_source_files_match_reviewed_bytes() -> None:
    for name, expected in _SOURCE_HASHES.items():
        raw = (_SCHEMA_ROOT / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected
        assert b"\r" not in raw


@pytest.mark.parametrize("version", ["1.6", "1.7"])
@pytest.mark.parametrize("mutation", ["serial", "vendor"])
def test_old_invalid_serial_and_vendor_remain_schema_refusals(version: str, mutation: str) -> None:
    doc = gap_report_to_cyclonedx_vex(_fixed_report([]), spec_version=version)
    _validate_document(doc, version)
    if mutation == "serial":
        doc["serialNumber"] = "urn:uuid:evidentia-vex-0123456789abcdef"
    else:
        tool = doc["metadata"]["tools"]["components"][0]
        tool["vendor"] = tool.pop("publisher")
    with pytest.raises(ValidationError):
        Draft7Validator(_schema(version), registry=Registry()).validate(doc)


@pytest.mark.parametrize(
    "bad",
    [
        "2026-01-01T00:00:00",
        "2026-04-31T00:00:00.000000Z",
        "2026-01-01T00:00:60.000000Z",
        "2026-01-01T00:00:00.00000Z",
        "2026-01-01T00:00:00.000000Z\n",
        "0000-01-01T00:00:00.000000Z",
        "2026-01-01T00:00:00.000000z",
    ],
)
def test_canonical_calendar_guard_is_independent_of_optional_schema_formats(bad: str) -> None:
    doc = gap_report_to_cyclonedx_vex(_fixed_report([]))
    doc["metadata"]["timestamp"] = bad
    with pytest.raises((AssertionError, ValueError)):
        _validate_document(doc, "1.6")


def test_version_selection_is_checked_independently_of_schema() -> None:
    doc = gap_report_to_cyclonedx_vex(_fixed_report([]))
    doc["specVersion"] = "1.7"
    with pytest.raises(AssertionError):
        _validate_document(doc, "1.6")


def test_unresolved_external_schema_reference_fails_without_retrieval(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    network_calls: list[str] = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        network_calls.append("network")
        raise AssertionError("schema attempted network retrieval")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    schema = _schema("1.6")
    schema["allOf"] = [{"$ref": "https://schema.invalid/vex-unbundled-control.json"}]
    validator = Draft7Validator(schema, registry=Registry())
    with pytest.raises(Unresolvable):
        validator.validate(gap_report_to_cyclonedx_vex(_fixed_report([])))
    assert network_calls == []
