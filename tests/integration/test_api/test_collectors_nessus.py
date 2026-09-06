"""Integration tests for `POST /api/collectors/nessus/collect` (v0.13 V13-05).

Reuses the project-wide ``api_client`` fixture from conftest. Every test
that lets ``save_evidence`` reach its True default (or sets it explicitly)
redirects ``EVIDENTIA_EVIDENCE_STORE_DIR`` to ``tmp_path`` so the run never
touches the developer's real evidence store (mirrors
tests/integration/test_api/test_evidence_router.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_SAMPLE_NESSUS_XML = """<?xml version="1.0" ?>
<NessusClientData_v2>
<Report name="api-test-scan">
<ReportHost name="10.0.0.50">
<HostProperties>
<tag name="host-ip">10.0.0.50</tag>
<tag name="HOST_START">Tue Sep  1 09:00:00 2026</tag>
<tag name="HOST_END">Tue Sep  1 09:05:00 2026</tag>
</HostProperties>
<ReportItem port="22" svc_name="ssh" protocol="tcp" severity="2" pluginID="12345" pluginName="Weak SSH Ciphers" pluginFamily="General">
<synopsis>The remote SSH server supports weak ciphers.</synopsis>
<description>The remote SSH server is configured to allow weak ciphers.</description>
<plugin_output>Weak ciphers: arcfour, arcfour128</plugin_output>
<risk_factor>Medium</risk_factor>
<cvss3_base_score>5.3</cvss3_base_score>
<solution>Disable weak ciphers in sshd_config.</solution>
</ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>
"""


@pytest.mark.usefixtures("api_client")
class TestNessusCollectEndpoint:
    """v0.13 V13-05: /api/collectors/nessus/collect (text-upload, no path/URL)."""

    def test_happy_path_returns_findings_manifest_and_evidence(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pytest.importorskip("defusedxml")
        monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path / "evidence"))
        r = api_client.post(
            "/api/collectors/nessus/collect",
            json={"content": _SAMPLE_NESSUS_XML},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["findings"]) == 1
        assert body["findings"][0]["title"] == "Weak SSH Ciphers on 10.0.0.50:22/tcp"
        assert body["findings"][0]["source_system"] == "nessus"
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
            "/api/collectors/nessus/collect",
            json={"content": _SAMPLE_NESSUS_XML, "save_evidence": False},
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
            "/api/collectors/nessus/collect",
            json={
                "content": _SAMPLE_NESSUS_XML,
                "cadence_slug": "fedramp-conmon-scans",
            },
        )
        assert r.status_code == 200, r.text
        lineage_id = r.json()["evidence"]["lineage_id"]

        from evidentia_core.evidence_store import list_lineage

        versions = list_lineage(lineage_id, store)
        assert len(versions) == 1
        assert versions[0].metadata["cadence_slug"] == "fedramp-conmon-scans"
        assert versions[0].source_system == "nessus"

    def test_missing_content_returns_400(self, api_client: TestClient) -> None:
        r = api_client.post("/api/collectors/nessus/collect", json={})
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "content" in detail["message"].lower()

    def test_malformed_xml_returns_400(self, api_client: TestClient) -> None:
        pytest.importorskip("defusedxml")
        r = api_client.post(
            "/api/collectors/nessus/collect",
            json={"content": "not xml at all <<<"},
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_body"

    def test_wrong_root_returns_400(self, api_client: TestClient) -> None:
        pytest.importorskip("defusedxml")
        r = api_client.post(
            "/api/collectors/nessus/collect",
            json={"content": "<NotNessus/>"},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "NessusClientData_v2" in detail["message"]

    def test_hostile_entity_declaration_returns_400(self, api_client: TestClient) -> None:
        pytest.importorskip("defusedxml")
        hostile = (
            '<?xml version="1.0" ?>\n'
            "<!DOCTYPE NessusClientData_v2 [\n"
            '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
            "]>\n"
            "<NessusClientData_v2>&xxe;</NessusClientData_v2>\n"
        )
        r = api_client.post(
            "/api/collectors/nessus/collect",
            json={"content": hostile},
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_body"

    def test_unknown_cadence_slug_returns_400(self, api_client: TestClient) -> None:
        pytest.importorskip("defusedxml")
        r = api_client.post(
            "/api/collectors/nessus/collect",
            json={
                "content": _SAMPLE_NESSUS_XML,
                "cadence_slug": "not-a-real-cadence",
            },
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "not-a-real-cadence" in detail["message"]

    def test_content_over_cap_returns_400(self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """The 50 MB cap is exercised via a monkeypatched threshold; a real
        50 MB JSON round-trip would make this test needlessly slow; the
        collector-unit tests already prove the real 50 MB constant."""
        pytest.importorskip("defusedxml")
        monkeypatch.setattr("evidentia_collectors.nessus.collector._MAX_INPUT_BYTES", 100)
        r = api_client.post(
            "/api/collectors/nessus/collect",
            json={"content": _SAMPLE_NESSUS_XML},
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
        monkeypatch.setitem(sys.modules, "evidentia_collectors.nessus", None)
        r = api_client.post(
            "/api/collectors/nessus/collect",
            json={"content": _SAMPLE_NESSUS_XML},
        )
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "feature_unavailable"

    def test_status_endpoint_includes_nessus_entry(self, api_client: TestClient) -> None:
        r = api_client.get("/api/collectors/status")
        assert r.status_code == 200
        assert "nessus" in r.json()
