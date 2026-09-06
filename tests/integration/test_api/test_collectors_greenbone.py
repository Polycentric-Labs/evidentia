"""Integration tests for `POST /api/collectors/greenbone/collect` (v0.13 V13-05).

Reuses the project-wide ``api_client`` fixture from conftest. Every test
that lets ``save_evidence`` reach its True default (or sets it explicitly)
redirects ``EVIDENTIA_EVIDENCE_STORE_DIR`` to ``tmp_path`` so the run never
touches the developer's real evidence store (mirrors
tests/integration/test_api/test_collectors_nessus.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_SAMPLE_GREENBONE_XML = """<?xml version="1.0" ?>
<report id="outer-wrapper" format_id="d5da9f67-8551-4e32-322c-c25a3d569742" extension="xml">
<report id="api-test-report">
<scan_start>2026-09-01T09:00:00Z</scan_start>
<task id="task-1"><name>API test scan</name></task>
<results>
<result id="result-1">
<name>Weak SSH Ciphers</name>
<host>10.0.0.50<hostname>api-test-host</hostname></host>
<port>22/tcp</port>
<nvt oid="1.3.6.1.4.1.25623.1.0.999001">
<name>Weak SSH Ciphers</name>
<family>General</family>
<cvss_base>5.3</cvss_base>
<tags>cvss_base_vector=AV:N/AC:L/Au:N/C:P/I:N/A:N|summary=The remote SSH server supports weak ciphers.|solution=Disable weak ciphers in sshd_config.|solution_type=Mitigation</tags>
<refs/>
</nvt>
<threat>Medium</threat>
<severity>5.3</severity>
<qod><value>80</value></qod>
<description>The remote SSH server is configured to allow weak ciphers.</description>
</result>
</results>
<scan_end>2026-09-01T09:05:00Z</scan_end>
</report>
</report>
"""


@pytest.mark.usefixtures("api_client")
class TestGreenboneCollectEndpoint:
    """v0.13 V13-05: /api/collectors/greenbone/collect (text-upload, no path/URL)."""

    def test_happy_path_returns_findings_manifest_and_evidence(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("defusedxml")
        monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path / "evidence"))
        r = api_client.post(
            "/api/collectors/greenbone/collect",
            json={"content": _SAMPLE_GREENBONE_XML},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["findings"]) == 1
        assert body["findings"][0]["title"] == "Weak SSH Ciphers on api-test-host:22/tcp"
        assert body["findings"][0]["source_system"] == "greenbone"
        assert body["manifest"]["is_complete"] is True
        assert body["manifest"]["total_findings"] == 1
        assert body["evidence"]["saved"] is True
        assert body["evidence"]["lineage_id"]

    def test_save_evidence_false_writes_nothing(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("defusedxml")
        store = tmp_path / "evidence"
        monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(store))
        r = api_client.post(
            "/api/collectors/greenbone/collect",
            json={"content": _SAMPLE_GREENBONE_XML, "save_evidence": False},
        )
        assert r.status_code == 200, r.text
        assert r.json()["evidence"]["saved"] is False
        assert not store.exists() or not any(store.iterdir())

    def test_saved_artifact_readable_from_configured_store(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("defusedxml")
        store = tmp_path / "evidence"
        monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(store))
        r = api_client.post(
            "/api/collectors/greenbone/collect",
            json={
                "content": _SAMPLE_GREENBONE_XML,
                "cadence_slug": "fedramp-conmon-scans",
            },
        )
        assert r.status_code == 200, r.text
        lineage_id = r.json()["evidence"]["lineage_id"]

        from evidentia_core.evidence_store import list_lineage

        versions = list_lineage(lineage_id, store)
        assert len(versions) == 1
        assert versions[0].metadata["cadence_slug"] == "fedramp-conmon-scans"
        assert versions[0].source_system == "greenbone"

    def test_missing_content_returns_400(self, api_client: TestClient) -> None:
        r = api_client.post("/api/collectors/greenbone/collect", json={})
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "content" in detail["message"].lower()

    def test_malformed_xml_returns_400(self, api_client: TestClient) -> None:
        pytest.importorskip("defusedxml")
        r = api_client.post(
            "/api/collectors/greenbone/collect",
            json={"content": "not xml at all <<<"},
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_body"

    def test_wrong_root_returns_400(self, api_client: TestClient) -> None:
        pytest.importorskip("defusedxml")
        r = api_client.post(
            "/api/collectors/greenbone/collect",
            json={"content": "<NotAReport/>"},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "report" in detail["message"]

    def test_hostile_entity_declaration_returns_400(self, api_client: TestClient) -> None:
        pytest.importorskip("defusedxml")
        hostile = (
            '<?xml version="1.0" ?>\n'
            "<!DOCTYPE report [\n"
            '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
            "]>\n"
            "<report>&xxe;</report>\n"
        )
        r = api_client.post(
            "/api/collectors/greenbone/collect",
            json={"content": hostile},
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_body"

    def test_unknown_cadence_slug_returns_400(self, api_client: TestClient) -> None:
        pytest.importorskip("defusedxml")
        r = api_client.post(
            "/api/collectors/greenbone/collect",
            json={
                "content": _SAMPLE_GREENBONE_XML,
                "cadence_slug": "not-a-real-cadence",
            },
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "not-a-real-cadence" in detail["message"]

    def test_content_over_cap_returns_400(self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """The 50 MB cap is exercised via a monkeypatched threshold; a real
        50 MB JSON round-trip would make this test needlessly slow, and the
        collector-unit tests already prove the real 50 MB constant."""
        pytest.importorskip("defusedxml")
        monkeypatch.setattr("evidentia_collectors.greenbone.collector._MAX_INPUT_BYTES", 100)
        r = api_client.post(
            "/api/collectors/greenbone/collect",
            json={"content": _SAMPLE_GREENBONE_XML},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "cap" in detail["message"].lower()

    def test_missing_scan_extra_returns_503(self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """``sys.modules[name] = None`` makes a subsequent ``import name``
        raise ImportError: the hermetic way to simulate the [scan] extra
        being absent (mirrors tests/unit/test_collectors/
        test_collector_ssrf_guard.py's driver-absent simulation)."""
        monkeypatch.setitem(sys.modules, "evidentia_collectors.greenbone", None)
        r = api_client.post(
            "/api/collectors/greenbone/collect",
            json={"content": _SAMPLE_GREENBONE_XML},
        )
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "feature_unavailable"

    def test_status_endpoint_includes_greenbone_entry(self, api_client: TestClient) -> None:
        r = api_client.get("/api/collectors/status")
        assert r.status_code == 200
        assert "greenbone" in r.json()
