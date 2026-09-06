"""Tests for the v0.13 V13-05 Greenbone GMP report XML ingestion collector."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

pytest.importorskip("defusedxml")

from evidentia_collectors.greenbone import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    GreenboneIngestError,
    collect_greenbone_file,
    collect_greenbone_text,
    parse_greenbone,
)
from evidentia_collectors.greenbone.mapping import greenbone_severity_to_severity
from evidentia_core.models.common import OLIRRelationship, Severity
from evidentia_core.models.evidence import EvidenceType
from evidentia_core.models.finding import ComplianceStatus

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "scans"
SAMPLE = FIXTURES / "greenbone-sample.xml"
HOSTILE = FIXTURES / "greenbone-hostile-entity.xml"


class TestParseGreenbone:
    """`parse_greenbone` is a pure function: shape + timestamps only, no
    SecurityFinding mapping."""

    def test_parse_shape(self) -> None:
        parsed = parse_greenbone(SAMPLE.read_bytes())
        assert parsed.task_name == "Weekly external scan"
        assert len(parsed.results) == 5

    def test_report_id_from_inner_report_not_outer_wrapper(self) -> None:
        """The fixture's outer wrapper carries a deliberately different id
        ("outer-wrapper-id-999") from the inner report ("demo-gb-report");
        the parser must read the inner one."""
        parsed = parse_greenbone(SAMPLE.read_bytes())
        assert parsed.report_id == "demo-gb-report"

    def test_scan_start_end_parsed(self) -> None:
        parsed = parse_greenbone(SAMPLE.read_bytes())
        assert parsed.scan_start == datetime(2026, 6, 1, 9, 0, 0, tzinfo=UTC)
        assert parsed.scan_end == datetime(2026, 6, 1, 9, 45, 12, tzinfo=UTC)

    def test_two_hosts_one_with_hostname(self) -> None:
        parsed = parse_greenbone(SAMPLE.read_bytes())
        by_ip = {r.host_ip: r.hostname for r in parsed.results}
        assert by_ip["10.0.0.21"] == "target1.example.internal"
        assert by_ip["10.0.0.22"] is None

    def test_two_cve_refs_captured(self) -> None:
        parsed = parse_greenbone(SAMPLE.read_bytes())
        critical_result = next(r for r in parsed.results if r.threat == "Critical")
        assert critical_result.cve == ["CVE-2026-50001", "CVE-2026-50002"]

    def test_single_cve_ref_captured(self) -> None:
        parsed = parse_greenbone(SAMPLE.read_bytes())
        high_result = next(r for r in parsed.results if r.threat == "High")
        assert high_result.cve == ["CVE-2026-40010"]

    def test_description_over_4000_chars_at_parse_layer(self) -> None:
        """The parser itself does NOT trim: trimming is a mapping-layer
        concern (description_max_chars)."""
        parsed = parse_greenbone(SAMPLE.read_bytes())
        critical_result = next(r for r in parsed.results if r.threat == "Critical")
        assert len(critical_result.description) > 4000

    def test_critical_result_has_no_summary_tag(self) -> None:
        """Deliberate fixture property: the critical result carries no NVT
        `summary` tag, forcing the mapping layer's `<description>` fallback."""
        parsed = parse_greenbone(SAMPLE.read_bytes())
        critical_result = next(r for r in parsed.results if r.threat == "Critical")
        assert critical_result.summary == ""

    def test_log_result_has_no_severity_tag(self) -> None:
        """Deliberate fixture property: the Log-tier result carries no
        `<severity>` element, forcing the mapping layer's `<threat>`
        fallback."""
        parsed = parse_greenbone(SAMPLE.read_bytes())
        log_result = next(r for r in parsed.results if r.threat == "Log")
        assert log_result.severity is None

    def test_nvt_tags_parsed(self) -> None:
        parsed = parse_greenbone(SAMPLE.read_bytes())
        low_result = next(r for r in parsed.results if r.threat == "Low")
        assert low_result.cvss_base_vector == "AV:N/AC:L/Au:N/C:N/I:N/A:N"
        assert low_result.solution == ("Restrict access to the sitemap.xml file if it is not intended to be public.")
        assert low_result.solution_type == "Mitigation"
        assert low_result.cvss_base == 2.6

    def test_qod_parsed(self) -> None:
        parsed = parse_greenbone(SAMPLE.read_bytes())
        medium_result = next(r for r in parsed.results if r.threat == "Medium")
        assert medium_result.qod == 95

    def test_wrong_root_raises(self) -> None:
        with pytest.raises(GreenboneIngestError, match="expected 'report'"):
            parse_greenbone(b"<NotAReport/>")

    def test_malformed_xml_raises(self) -> None:
        with pytest.raises(GreenboneIngestError, match="not valid XML"):
            parse_greenbone(b"not xml at all <<<")

    def test_hostile_entity_declaration_refused(self) -> None:
        with pytest.raises(GreenboneIngestError, match="unsafe XML construct"):
            parse_greenbone(HOSTILE.read_bytes())

    def test_bare_inner_report_form_accepted(self) -> None:
        """No outer wrapper at all: just the inner <report> on its own."""
        bare = (
            b'<report id="bare-report">'
            b"<scan_start>2026-01-01T00:00:00Z</scan_start>"
            b"<task><name>Bare scan</name></task>"
            b"<results>"
            b'<result id="r1">'
            b"<name>Test</name>"
            b"<host>10.0.0.5</host>"
            b"<port>0/tcp</port>"
            b'<nvt oid="1.2.3"><name>Test NVT</name><family>General</family>'
            b"<tags>summary=hi</tags></nvt>"
            b"<threat>Low</threat><severity>1.0</severity>"
            b"<qod><value>70</value></qod>"
            b"<description>desc</description>"
            b"</result>"
            b"</results>"
            b"<scan_end>2026-01-01T01:00:00Z</scan_end>"
            b"</report>"
        )
        parsed = parse_greenbone(bare)
        assert parsed.report_id == "bare-report"
        assert parsed.task_name == "Bare scan"
        assert len(parsed.results) == 1
        assert parsed.results[0].host_ip == "10.0.0.5"

    def test_empty_results_element(self) -> None:
        parsed = parse_greenbone(b"<report><results></results></report>")
        assert parsed.results == []
        assert parsed.report_id == "unknown"
        assert parsed.task_name == ""

    def test_missing_results_element_entirely(self) -> None:
        parsed = parse_greenbone(b'<report id="r"></report>')
        assert parsed.results == []


class TestSeverityMapping:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (9.0, Severity.CRITICAL),
            (10.0, Severity.CRITICAL),
            (8.99, Severity.HIGH),
            (7.0, Severity.HIGH),
            (6.99, Severity.MEDIUM),
            (4.0, Severity.MEDIUM),
            (3.99, Severity.LOW),
            (0.1, Severity.LOW),
            (0.0, Severity.INFORMATIONAL),
        ],
    )
    def test_thresholds(self, value: float, expected: Severity) -> None:
        assert greenbone_severity_to_severity(value, "Medium") == expected

    @pytest.mark.parametrize(
        ("threat", "expected"),
        [
            ("Log", Severity.INFORMATIONAL),
            ("Low", Severity.LOW),
            ("Medium", Severity.MEDIUM),
            ("High", Severity.HIGH),
            ("Critical", Severity.CRITICAL),
            ("critical", Severity.CRITICAL),  # case-insensitive
        ],
    )
    def test_threat_fallback_when_severity_missing(self, threat: str, expected: Severity) -> None:
        assert greenbone_severity_to_severity(None, threat) == expected

    def test_unrecognized_threat_defaults_informational(self) -> None:
        assert greenbone_severity_to_severity(None, "Bogus") == Severity.INFORMATIONAL
        assert greenbone_severity_to_severity(None, "") == Severity.INFORMATIONAL


class TestCollectGreenboneFile:
    def test_every_mapping_rule(self) -> None:
        findings, _manifest, _artifact = collect_greenbone_file(SAMPLE)
        assert len(findings) == 5
        low_finding = next(f for f in findings if f.source_finding_id and "200001" in f.source_finding_id)
        assert low_finding.title == "Sitemap Detection on target1.example.internal:80/tcp"
        assert low_finding.source_system == "greenbone"
        assert low_finding.source_finding_id == "demo-gb-report:10.0.0.21:1.3.6.1.4.1.25623.1.0.200001:80/tcp"
        assert low_finding.severity == Severity.LOW
        # A vulnerability observation is not a control check; the default
        # ComplianceStatus is left alone.
        assert low_finding.compliance_status == ComplianceStatus.UNKNOWN
        assert low_finding.resource_type == "host"
        assert low_finding.resource_id == "10.0.0.21"
        assert low_finding.remediation == (
            "Restrict access to the sitemap.xml file if it is not intended to be public."
        )
        assert "sitemap.xml" in low_finding.description.lower()

        mapping_ids = {(m.framework, m.control_id) for m in low_finding.control_mappings}
        assert mapping_ids == {
            ("nist-800-53-rev5", "RA-5"),
            ("nist-800-53-rev5", "SI-2"),
        }
        for m in low_finding.control_mappings:
            assert m.relationship == OLIRRelationship.SUBSET_OF

        assert low_finding.raw_data["family"] == "General"
        assert low_finding.raw_data["cvss_base"] == 2.6
        assert low_finding.raw_data["cvss_base_vector"] == "AV:N/AC:L/Au:N/C:N/I:N/A:N"
        assert low_finding.raw_data["qod"] == 70
        assert low_finding.raw_data["cve"] == []
        assert low_finding.raw_data["solution_type"] == "Mitigation"

        assert low_finding.collection_context.collector_id == COLLECTOR_ID
        assert low_finding.collection_context.credential_identity == "file"
        assert low_finding.collection_context.source_system_id == "demo-gb-report"
        # Report-level scan_end: every finding shares the same collected_at.
        expected_collected_at = datetime(2026, 6, 1, 9, 45, 12, tzinfo=UTC)
        assert low_finding.collection_context.collected_at == expected_collected_at
        assert low_finding.first_observed == expected_collected_at
        assert low_finding.last_observed == expected_collected_at

    def test_title_uses_ip_when_no_hostname(self) -> None:
        findings, _, _ = collect_greenbone_file(SAMPLE)
        medium_finding = next(f for f in findings if f.severity == Severity.MEDIUM)
        assert medium_finding.title == "TLS/SSL Weak Cipher Suites on 10.0.0.22:443/tcp"
        assert medium_finding.resource_id == "10.0.0.22"

    def test_deterministic_ids_stable_across_two_parses(self) -> None:
        findings1, _, _ = collect_greenbone_file(SAMPLE)
        findings2, _, _ = collect_greenbone_file(SAMPLE)
        assert [f.id for f in findings1] == [f.id for f in findings2]
        assert len({f.id for f in findings1}) == 5

    def test_log_severity_via_threat_fallback_when_severity_tag_absent(self) -> None:
        findings, _, _ = collect_greenbone_file(SAMPLE)
        info_finding = next(f for f in findings if f.severity == Severity.INFORMATIONAL)
        assert "Host Summary" in info_finding.title
        # Confirms the raw <severity> tag really was absent for this result
        # (see TestParseGreenbone.test_log_result_has_no_severity_tag) and
        # the informational classification came from <threat>Log</threat>.
        assert info_finding.raw_data["cvss_base"] == 0.0

    def test_summary_tag_preferred_over_description_element(self) -> None:
        findings, _, _ = collect_greenbone_file(SAMPLE)
        info_finding = next(f for f in findings if f.severity == Severity.INFORMATIONAL)
        assert info_finding.description == "Host summary information collected during the scan."

    def test_description_element_fallback_when_summary_tag_absent(self) -> None:
        findings, _, _ = collect_greenbone_file(SAMPLE, description_max_chars=100)
        critical_finding = next(f for f in findings if f.severity == Severity.CRITICAL)
        assert critical_finding.description.startswith("OVERFLOW-PATTERN-DEADBEEF")

    def test_manifest_coverage_and_completeness(self) -> None:
        _, manifest, _ = collect_greenbone_file(SAMPLE)
        assert manifest.collector_id == COLLECTOR_ID
        assert manifest.run_id
        assert manifest.total_findings == 5
        assert manifest.is_complete is True
        assert manifest.incomplete_reason is None
        counts = {c.resource_type: c for c in manifest.coverage_counts}
        assert counts["host"].scanned == 2
        assert counts["host"].collected == 2
        assert counts["result"].scanned == 5
        assert counts["result"].collected == 5
        assert manifest.empty_categories == []
        assert manifest.warnings == []

    def test_empty_results_category_when_report_has_no_results(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.xml"
        empty.write_text(
            '<report id="empty-report">'
            "<task><name>Empty scan</name></task>"
            "<scan_start>2026-01-01T00:00:00Z</scan_start>"
            "<results></results>"
            "<scan_end>2026-01-01T00:05:00Z</scan_end>"
            "</report>",
            encoding="utf-8",
        )
        findings, manifest, _ = collect_greenbone_file(empty)
        assert findings == []
        assert manifest.empty_categories == ["results"]
        assert manifest.is_complete is True

    def test_scan_end_missing_falls_back_to_scan_start_and_warns(self, tmp_path: Path) -> None:
        partial = tmp_path / "partial.xml"
        partial.write_text(
            '<report id="partial-report"><scan_start>2026-02-01T00:00:00Z</scan_start><results></results></report>',
            encoding="utf-8",
        )
        _, manifest, artifact = collect_greenbone_file(partial)
        assert manifest.is_complete is False
        assert manifest.incomplete_reason == "report has no <scan_end> timestamp"
        assert any("scan_start" in w for w in manifest.warnings)
        assert artifact.collected_at == datetime(2026, 2, 1, 0, 0, 0, tzinfo=UTC)

    def test_both_timestamps_missing_falls_back_to_now_and_warns(self, tmp_path: Path) -> None:
        no_times = tmp_path / "no-times.xml"
        no_times.write_text('<report id="no-times-report"><results></results></report>', encoding="utf-8")
        _, manifest, artifact = collect_greenbone_file(no_times)
        assert manifest.is_complete is False
        now = datetime.now(UTC)
        assert (now - artifact.collected_at).total_seconds() < 30
        assert any("collection time" in w for w in manifest.warnings)

    def test_description_trimmed_to_max_chars(self) -> None:
        findings, _, _ = collect_greenbone_file(SAMPLE, description_max_chars=100)
        critical_finding = next(f for f in findings if f.severity == Severity.CRITICAL)
        assert len(critical_finding.description) == 100

    def test_default_description_max_chars_is_4000(self) -> None:
        findings, _, _ = collect_greenbone_file(SAMPLE)
        critical_finding = next(f for f in findings if f.severity == Severity.CRITICAL)
        assert len(critical_finding.description) == 4000

    def test_artifact_metadata_and_hash(self) -> None:
        _, _, artifact = collect_greenbone_file(SAMPLE, cadence_slug="pci-dss-11-6-1-weekly")
        assert artifact.title == "Greenbone scan report: Weekly external scan"
        assert artifact.evidence_type == EvidenceType.TEST_RESULT
        assert artifact.source_system == "greenbone"
        assert artifact.collected_by == COLLECTOR_ID
        assert artifact.collected_at == datetime(2026, 6, 1, 9, 45, 12, tzinfo=UTC)
        assert artifact.metadata["cadence_slug"] == "pci-dss-11-6-1-weekly"
        assert artifact.metadata["scanner"] == "greenbone"
        assert artifact.metadata["report_id"] == "demo-gb-report"
        assert artifact.metadata["task_name"] == "Weekly external scan"
        assert artifact.metadata["run_id"]
        assert artifact.content_format == "json"
        assert isinstance(artifact.content, dict)
        assert artifact.content["hosts_scanned"] == 2
        assert artifact.content["results_by_severity"]["critical"] == 1
        assert artifact.tags == ["vulnerability-scan", "greenbone"]
        mapping_ids = {(m.framework, m.control_id) for m in artifact.control_mappings}
        assert mapping_ids == {
            ("nist-800-53-rev5", "RA-5"),
            ("nist-800-53-rev5", "SI-2"),
        }
        assert artifact.content_hash is not None
        assert len(artifact.content_hash) == 64

    def test_default_cadence_slug(self) -> None:
        _, _, artifact = collect_greenbone_file(SAMPLE)
        assert artifact.metadata["cadence_slug"] == "fedramp-conmon-scans"

    def test_size_cap_rejects_oversized_input(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("evidentia_collectors.greenbone.collector._MAX_INPUT_BYTES", 10)
        with pytest.raises(GreenboneIngestError, match="cap"):
            collect_greenbone_file(SAMPLE)

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(GreenboneIngestError):
            collect_greenbone_file(tmp_path / "does-not-exist.xml")

    def test_hostile_fixture_refused(self) -> None:
        with pytest.raises(GreenboneIngestError):
            collect_greenbone_file(HOSTILE)


class TestCollectGreenboneText:
    def test_matches_file_mode(self) -> None:
        text = SAMPLE.read_text(encoding="utf-8")
        findings, manifest, artifact = collect_greenbone_text(text, source_name="inline")
        assert len(findings) == 5
        assert manifest.total_findings == 5
        assert artifact.source_system == "greenbone"

    def test_size_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("evidentia_collectors.greenbone.collector._MAX_INPUT_BYTES", 10)
        with pytest.raises(GreenboneIngestError, match="cap"):
            collect_greenbone_text("<report></report>", source_name="inline")


class TestBlindSpots:
    def test_shape(self) -> None:
        assert len(BLIND_SPOTS) == 4
        for entry in BLIND_SPOTS:
            assert set(entry.keys()) == {"id", "title", "description"}
            assert entry["id"].startswith("EVIDENTIA-GREENBONE-")
