"""Edge inputs to the scan importers end in a typed error (v0.13.0 review M7, D8)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("defusedxml", reason="the scan extra is not installed")


@pytest.mark.parametrize("pkg", ["nessus", "greenbone"])
def test_unpaired_surrogate_is_a_typed_ingest_error(pkg: str) -> None:
    """A lone surrogate used to escape as UnicodeEncodeError (HTTP 500 on the API)."""
    if pkg == "nessus":
        from evidentia_collectors.nessus import NessusIngestError as error
        from evidentia_collectors.nessus import collect_nessus_text as collect
    else:
        from evidentia_collectors.greenbone import GreenboneIngestError as error
        from evidentia_collectors.greenbone import collect_greenbone_text as collect
    with pytest.raises(error, match="not valid UTF-8 text"):
        collect("<report>\ud800</report>", source_name="inline")


@pytest.mark.skipif(os.name != "nt", reason="reserved device names exist on Windows only")
@pytest.mark.parametrize("pkg", ["nessus", "greenbone"])
@pytest.mark.parametrize("name", ["CON", "NUL", "COM1", "con.nessus"])
def test_reserved_device_names_are_refused_before_open(pkg: str, name: str, tmp_path: Path) -> None:
    if pkg == "nessus":
        from evidentia_collectors.nessus import NessusIngestError as error
        from evidentia_collectors.nessus import collect_nessus_file as collect
    else:
        from evidentia_collectors.greenbone import GreenboneIngestError as error
        from evidentia_collectors.greenbone import collect_greenbone_file as collect
    with pytest.raises(error, match="reserved device"):
        collect(tmp_path / name)


def test_greenbone_vhost_results_keep_distinct_identities() -> None:
    """Two results that share host_ip, NVT and port but differ by hostname are two findings."""
    from evidentia_collectors.greenbone import collect_greenbone_text

    def result(result_id: str, hostname: str) -> str:
        return (
            f'<result id="{result_id}"><name>Sitemap Detection</name>'
            f"<host>10.0.0.21<hostname>{hostname}</hostname></host><port>80/tcp</port>"
            '<nvt oid="1.3.6.1.4.1.25623.1.0.200001"><name>Sitemap Detection</name><family>General</family>'
            "<cvss_base>2.6</cvss_base></nvt><threat>Low</threat><severity>2.6</severity>"
            "<description>Sitemap found.</description></result>"
        )

    xml = (
        '<?xml version="1.0"?><report id="outer"><report id="demo-gb-report" type="scan">'
        "<scan_start>2026-06-01T09:00:00Z</scan_start><scan_end>2026-06-01T10:00:00Z</scan_end>"
        f'<results start="1" max="-1">{result("r-1", "a.example.internal")}{result("r-2", "b.example.internal")}</results>'
        "</report></report>"
    )
    findings, _manifest, _artifact = collect_greenbone_text(xml, source_name="inline")
    assert len(findings) == 2
    assert len({f.source_finding_id for f in findings}) == 2
    assert all("example.internal" in str(f.source_finding_id) for f in findings)


def test_reserved_name_helper_is_platform_aware(tmp_path: Path) -> None:
    from evidentia_collectors._paths import is_reserved_device_name

    expected = os.name == "nt"
    assert is_reserved_device_name(tmp_path / "CON") is expected
    assert is_reserved_device_name(tmp_path / "lpt3.xml") is expected
    assert is_reserved_device_name(tmp_path / "report.xml") is False
