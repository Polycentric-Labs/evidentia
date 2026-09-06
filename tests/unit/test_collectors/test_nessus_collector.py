"""Tests for the v0.13 V13-05 Nessus scan-export ingestion collector."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

pytest.importorskip("defusedxml")

from evidentia_collectors.nessus import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    NessusIngestError,
    collect_nessus_file,
    collect_nessus_text,
    parse_nessus,
)
from evidentia_collectors.nessus.mapping import nessus_severity_to_severity
from evidentia_core.models.common import OLIRRelationship, Severity
from evidentia_core.models.evidence import EvidenceType
from evidentia_core.models.finding import ComplianceStatus

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "scans"
SAMPLE = FIXTURES / "nessus-sample.nessus"
HOSTILE = FIXTURES / "nessus-hostile-entity.nessus"


class TestParseNessus:
    """`parse_nessus` is a pure function; shape + timestamps only, no
    SecurityFinding mapping."""

    def test_parse_shape(self) -> None:
        parsed = parse_nessus(SAMPLE.read_bytes())
        assert parsed.report_name == "demo-scan"
        assert [h.name for h in parsed.hosts] == [
            "scanner-target-1",
            "scanner-target-2",
        ]
        assert len(parsed.items) == 5

    def test_host_start_end_parsed(self) -> None:
        parsed = parse_nessus(SAMPLE.read_bytes())
        host1 = parsed.hosts[0]
        assert host1.host_ip == "10.0.0.11"
        assert host1.host_start == datetime(2026, 9, 1, 10, 20, 0, tzinfo=UTC)
        assert host1.host_end == datetime(2026, 9, 1, 10, 22, 31, tzinfo=UTC)

    def test_missing_host_end_is_none(self) -> None:
        parsed = parse_nessus(SAMPLE.read_bytes())
        host2 = parsed.hosts[1]
        assert host2.host_ip == "10.0.0.12"
        assert host2.host_start is None
        assert host2.host_end is None

    def test_earliest_start_latest_end_ignore_hosts_with_none(self) -> None:
        parsed = parse_nessus(SAMPLE.read_bytes())
        assert parsed.earliest_host_start == datetime(2026, 9, 1, 10, 20, 0, tzinfo=UTC)
        assert parsed.latest_host_end == datetime(2026, 9, 1, 10, 22, 31, tzinfo=UTC)

    def test_two_cve_children_captured(self) -> None:
        parsed = parse_nessus(SAMPLE.read_bytes())
        critical_item = next(i for i in parsed.items if i.severity == 4)
        assert critical_item.cve == ["CVE-2026-12345", "CVE-2026-67890"]

    def test_plugin_output_over_4000_chars_at_parse_layer(self) -> None:
        """The parser itself does NOT trim; trimming is a mapping-layer
        concern (plugin_output_max_chars)."""
        parsed = parse_nessus(SAMPLE.read_bytes())
        critical_item = next(i for i in parsed.items if i.severity == 4)
        assert len(critical_item.plugin_output) > 4000

    def test_wrong_root_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.xml"
        bad.write_text("<NotNessus/>", encoding="utf-8")
        with pytest.raises(NessusIngestError, match="NessusClientData_v2"):
            parse_nessus(bad.read_bytes())

    def test_malformed_xml_raises(self) -> None:
        with pytest.raises(NessusIngestError, match="not valid XML"):
            parse_nessus(b"not xml at all <<<")

    def test_hostile_entity_declaration_refused(self) -> None:
        with pytest.raises(NessusIngestError, match="unsafe XML construct"):
            parse_nessus(HOSTILE.read_bytes())


class TestSeverityMapping:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (0, Severity.INFORMATIONAL),
            (1, Severity.LOW),
            (2, Severity.MEDIUM),
            (3, Severity.HIGH),
            (4, Severity.CRITICAL),
        ],
    )
    def test_exact_levels(self, value: int, expected: Severity) -> None:
        assert nessus_severity_to_severity(value) == expected

    def test_clamps_out_of_range(self) -> None:
        assert nessus_severity_to_severity(-5) == Severity.INFORMATIONAL
        assert nessus_severity_to_severity(99) == Severity.CRITICAL


class TestCollectNessusFile:
    def test_every_mapping_rule(self) -> None:
        findings, _manifest, _artifact = collect_nessus_file(SAMPLE)
        assert len(findings) == 5
        ssl_finding = next(f for f in findings if f.source_finding_id and "51192" in f.source_finding_id)
        assert ssl_finding.title == "SSL Certificate Cannot Be Trusted on scanner-target-1:443/tcp"
        assert ssl_finding.source_system == "nessus"
        assert ssl_finding.source_finding_id == "demo-scan:scanner-target-1:51192:443/tcp"
        assert ssl_finding.severity == Severity.MEDIUM
        # A vulnerability observation is not a control check; the default
        # ComplianceStatus is left alone.
        assert ssl_finding.compliance_status == ComplianceStatus.UNKNOWN
        assert ssl_finding.resource_type == "host"
        assert ssl_finding.resource_id == "10.0.0.11"
        assert ssl_finding.remediation == "Purchase or generate a proper certificate for this service."
        assert "cannot be trusted" in ssl_finding.description.lower()

        mapping_ids = {(m.framework, m.control_id) for m in ssl_finding.control_mappings}
        assert mapping_ids == {
            ("nist-800-53-rev5", "RA-5"),
            ("nist-800-53-rev5", "SI-2"),
        }
        for m in ssl_finding.control_mappings:
            assert m.relationship == OLIRRelationship.SUBSET_OF

        assert ssl_finding.raw_data["plugin_family"] == "General"
        assert ssl_finding.raw_data["risk_factor"] == "Medium"
        assert ssl_finding.raw_data["cve"] == []
        assert ssl_finding.raw_data["cvss3_base_score"] == 5.9

        assert ssl_finding.collection_context.collector_id == COLLECTOR_ID
        assert ssl_finding.collection_context.credential_identity == "file"
        assert ssl_finding.collection_context.source_system_id == "demo-scan"
        # host1 has a real HOST_END; every field derived from it agrees.
        expected_collected_at = datetime(2026, 9, 1, 10, 22, 31, tzinfo=UTC)
        assert ssl_finding.collection_context.collected_at == expected_collected_at
        assert ssl_finding.first_observed == expected_collected_at
        assert ssl_finding.last_observed == expected_collected_at

    def test_deterministic_ids_stable_across_two_parses(self) -> None:
        findings1, _, _ = collect_nessus_file(SAMPLE)
        findings2, _, _ = collect_nessus_file(SAMPLE)
        assert [f.id for f in findings1] == [f.id for f in findings2]
        assert len({f.id for f in findings1}) == 5

    def test_severity_zero_maps_to_informational(self) -> None:
        findings, _, _ = collect_nessus_file(SAMPLE)
        info_finding = next(f for f in findings if f.severity == Severity.INFORMATIONAL)
        assert "Nessus Scan Information" in info_finding.title

    def test_host_without_host_end_falls_back_to_now_and_warns(self) -> None:
        findings, manifest, _ = collect_nessus_file(SAMPLE)
        host2_finding = next(f for f in findings if "scanner-target-2" in (f.source_finding_id or ""))
        now = datetime.now(UTC)
        assert (now - host2_finding.collection_context.collected_at).total_seconds() < 30
        assert manifest.is_complete is False
        assert manifest.incomplete_reason is not None
        assert "1 of 2" in manifest.incomplete_reason
        assert any("scanner-target-2" in w and "HOST_END" in w for w in manifest.warnings)

    def test_manifest_coverage_and_completeness(self) -> None:
        _, manifest, _ = collect_nessus_file(SAMPLE)
        assert manifest.collector_id == COLLECTOR_ID
        assert manifest.run_id
        assert manifest.total_findings == 5
        counts = {c.resource_type: c for c in manifest.coverage_counts}
        assert counts["host"].scanned == 2
        assert counts["host"].collected == 2
        assert counts["report_item"].scanned == 5
        assert counts["report_item"].collected == 5
        assert manifest.empty_categories == []

    def test_empty_report_items_category_when_host_has_no_items(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.nessus"
        empty.write_text(
            '<NessusClientData_v2><Report name="r">'
            '<ReportHost name="h1"><HostProperties>'
            '<tag name="HOST_END">Tue Sep  1 10:22:31 2026</tag>'
            "</HostProperties></ReportHost>"
            "</Report></NessusClientData_v2>",
            encoding="utf-8",
        )
        findings, manifest, _ = collect_nessus_file(empty)
        assert findings == []
        assert manifest.empty_categories == ["report_items"]
        assert manifest.is_complete is True

    def test_plugin_output_trimmed_to_max_chars(self) -> None:
        findings, _, _ = collect_nessus_file(SAMPLE, plugin_output_max_chars=100)
        critical_finding = next(f for f in findings if f.severity == Severity.CRITICAL)
        assert len(critical_finding.raw_data["plugin_output"]) == 100

    def test_default_plugin_output_max_chars_is_4000(self) -> None:
        findings, _, _ = collect_nessus_file(SAMPLE)
        critical_finding = next(f for f in findings if f.severity == Severity.CRITICAL)
        assert len(critical_finding.raw_data["plugin_output"]) == 4000

    def test_artifact_metadata_and_hash(self) -> None:
        _, _, artifact = collect_nessus_file(SAMPLE, cadence_slug="pci-dss-11-6-1-weekly")
        assert artifact.title == "Nessus scan report: demo-scan"
        assert artifact.evidence_type == EvidenceType.TEST_RESULT
        assert artifact.source_system == "nessus"
        assert artifact.collected_by == COLLECTOR_ID
        assert artifact.collected_at == datetime(2026, 9, 1, 10, 22, 31, tzinfo=UTC)
        assert artifact.metadata["cadence_slug"] == "pci-dss-11-6-1-weekly"
        assert artifact.metadata["scanner"] == "nessus"
        assert artifact.metadata["report_name"] == "demo-scan"
        assert artifact.metadata["run_id"]
        assert artifact.content_format == "json"
        assert isinstance(artifact.content, dict)
        assert artifact.content["hosts_scanned"] == 2
        assert artifact.content["items_by_severity"]["critical"] == 1
        assert artifact.tags == ["vulnerability-scan", "nessus"]
        mapping_ids = {(m.framework, m.control_id) for m in artifact.control_mappings}
        assert mapping_ids == {
            ("nist-800-53-rev5", "RA-5"),
            ("nist-800-53-rev5", "SI-2"),
        }
        assert artifact.content_hash is not None
        assert len(artifact.content_hash) == 64

    def test_default_cadence_slug(self) -> None:
        _, _, artifact = collect_nessus_file(SAMPLE)
        assert artifact.metadata["cadence_slug"] == "fedramp-conmon-scans"

    def test_size_cap_rejects_oversized_input(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("evidentia_collectors.nessus.collector._MAX_INPUT_BYTES", 10)
        with pytest.raises(NessusIngestError, match="cap"):
            collect_nessus_file(SAMPLE)

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(NessusIngestError):
            collect_nessus_file(tmp_path / "does-not-exist.nessus")

    def test_hostile_fixture_refused(self) -> None:
        with pytest.raises(NessusIngestError):
            collect_nessus_file(HOSTILE)


class TestCollectNessusText:
    def test_matches_file_mode(self) -> None:
        text = SAMPLE.read_text(encoding="utf-8")
        findings, manifest, artifact = collect_nessus_text(text, source_name="inline")
        assert len(findings) == 5
        assert manifest.total_findings == 5
        assert artifact.source_system == "nessus"

    def test_size_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("evidentia_collectors.nessus.collector._MAX_INPUT_BYTES", 10)
        with pytest.raises(NessusIngestError, match="cap"):
            collect_nessus_text("<NessusClientData_v2/>", source_name="inline")


class TestBlindSpots:
    def test_shape(self) -> None:
        assert len(BLIND_SPOTS) == 4
        for entry in BLIND_SPOTS:
            assert set(entry.keys()) == {"id", "title", "description"}
            assert entry["id"].startswith("EVIDENTIA-NESSUS-")
