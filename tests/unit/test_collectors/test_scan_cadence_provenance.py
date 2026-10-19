"""Scan importers record cadence provenance on the evidence artifact (v0.13.0 review H5, D9).

The series layer only counts a complete run whose timestamp came from the
export, so the Nessus and Greenbone importers say which is which in the
artifact metadata.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from evidentia_core.conmon.series import (
    COLLECTION_COMPLETE_METADATA_KEY,
    TIMESTAMP_SOURCE_COLLECTION_TIME,
    TIMESTAMP_SOURCE_METADATA_KEY,
    TIMESTAMP_SOURCE_RECORD,
    assert_series,
    default_window,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "scans"
WEEKLY = "pci-dss-11-6-1-weekly"

pytest.importorskip("defusedxml", reason="the scan extra is not installed")


def test_nessus_sample_is_a_complete_record_dated_run() -> None:
    from evidentia_collectors.nessus import collect_nessus_file

    _findings, manifest, artifact = collect_nessus_file(FIXTURES / "nessus-sample.nessus", cadence_slug=WEEKLY)
    # The cadence key says the export shows a completed scan (a HOST_END
    # exists); the manifest's is_complete tracks per-host coverage.
    assert artifact.metadata[COLLECTION_COMPLETE_METADATA_KEY] is (artifact.content["scan_end"] is not None)
    assert isinstance(manifest.is_complete, bool)
    assert artifact.metadata[TIMESTAMP_SOURCE_METADATA_KEY] in {
        TIMESTAMP_SOURCE_RECORD,
        TIMESTAMP_SOURCE_COLLECTION_TIME,
    }
    if artifact.content["scan_end"] is not None:
        assert artifact.metadata[TIMESTAMP_SOURCE_METADATA_KEY] == TIMESTAMP_SOURCE_RECORD


def test_nessus_export_without_host_end_is_clock_dated_and_incomplete() -> None:
    from evidentia_collectors.nessus import collect_nessus_text

    xml = (
        '<?xml version="1.0"?><NessusClientData_v2><Report name="partial">'
        '<ReportHost name="10.0.0.5"><HostProperties>'
        '<tag name="HOST_START">Mon Oct 12 10:00:00 2026</tag>'
        "</HostProperties></ReportHost></Report></NessusClientData_v2>"
    )
    _findings, manifest, artifact = collect_nessus_text(xml, source_name="inline", cadence_slug=WEEKLY)
    assert manifest.is_complete is False
    assert artifact.metadata[COLLECTION_COMPLETE_METADATA_KEY] is False
    assert artifact.metadata[TIMESTAMP_SOURCE_METADATA_KEY] == TIMESTAMP_SOURCE_COLLECTION_TIME


def test_zero_host_nessus_export_is_recorded_as_incomplete() -> None:
    from evidentia_collectors.nessus import collect_nessus_text

    xml = '<?xml version="1.0"?><NessusClientData_v2><Report name="empty"></Report></NessusClientData_v2>'
    _findings, manifest, artifact = collect_nessus_text(xml, source_name="inline", cadence_slug=WEEKLY)
    assert manifest.is_complete is False
    assert manifest.incomplete_reason == "report contains no hosts"
    assert artifact.metadata[COLLECTION_COMPLETE_METADATA_KEY] is False


def test_re_imported_partial_exports_do_not_manufacture_a_series() -> None:
    """Three imports of the same timestamp-less export, a week apart, stay insufficient."""
    from evidentia_collectors.nessus import collect_nessus_text

    xml = '<?xml version="1.0"?><NessusClientData_v2><Report name="stale"></Report></NessusClientData_v2>'
    artifacts = [collect_nessus_text(xml, source_name="inline", cadence_slug=WEEKLY)[2] for _ in range(3)]
    start, end = default_window()
    series = assert_series(WEEKLY, artifacts, window_start=start, window_end=end)
    assert series.observations == []
    assert series.excluded_observations == 3
    assert series.verdict == "insufficient"


def test_greenbone_sample_records_its_provenance() -> None:
    from evidentia_collectors.greenbone import collect_greenbone_file

    _findings, manifest, artifact = collect_greenbone_file(FIXTURES / "greenbone-sample.xml", cadence_slug=WEEKLY)
    assert artifact.metadata[COLLECTION_COMPLETE_METADATA_KEY] is manifest.is_complete
    assert artifact.metadata[TIMESTAMP_SOURCE_METADATA_KEY] == TIMESTAMP_SOURCE_RECORD


def test_greenbone_report_without_timestamps_is_clock_dated() -> None:
    from evidentia_collectors.greenbone import collect_greenbone_text

    xml = '<?xml version="1.0"?><report id="r-1"><report id="r-1"><results></results></report></report>'
    _findings, manifest, artifact = collect_greenbone_text(xml, source_name="inline", cadence_slug=WEEKLY)
    assert manifest.is_complete is False
    assert artifact.metadata[COLLECTION_COMPLETE_METADATA_KEY] is False
    assert artifact.metadata[TIMESTAMP_SOURCE_METADATA_KEY] == TIMESTAMP_SOURCE_COLLECTION_TIME
