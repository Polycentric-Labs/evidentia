"""Input bounds and error handling closed by the v0.13.0 review (API partition findings).

Unbounded dates and integers overflowed into 500s, blank or non-finite
values made records unloadable, and parse errors echoed server detail.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


class TestConmonBounds:
    def test_blank_entry_slug_is_422(self, api_client: TestClient) -> None:
        r = api_client.post("/api/conmon/check", json={"entries": [{"slug": " ", "last_completed": "2026-01-01"}]})
        assert r.status_code == 422, r.text

    def test_window_days_is_bounded(self, api_client: TestClient) -> None:
        body = {"entries": [{"slug": "pci-dss-11-6-1-weekly", "last_completed": "2026-01-01"}], "window_days": 99999999}
        assert api_client.post("/api/conmon/check", json=body).status_code == 422
        assert api_client.post("/api/conmon/health", json={"state": {}, "window_days": 99999999}).status_code == 422

    def test_far_future_last_completed_is_422_not_500(self, api_client: TestClient) -> None:
        body = {"entries": [{"slug": "pci-dss-11-6-1-weekly", "last_completed": "9999-12-31"}]}
        r = api_client.post("/api/conmon/check", json=body)
        assert r.status_code == 422, r.text

    def test_unregistered_slug_with_evidence_store_is_collected_not_500(
        self, api_client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path / "store"))
        (tmp_path / "store").mkdir()
        body = {
            "entries": [{"slug": "x" * 128, "last_completed": "2026-01-01"}],
            "use_evidence_store": True,
            "today": "2026-10-02",
        }
        r = api_client.post("/api/conmon/check", json=body)
        assert r.status_code == 200, r.text
        assert r.json()["unknown_slugs"] == ["x" * 128]

    def test_mark_completed_rejects_future_dates(
        self, api_client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_CONMON_STATE_FILE", str(tmp_path / "state.yaml"))
        future = (date.today() + timedelta(days=30)).isoformat()
        r = api_client.post("/api/conmon/mark-completed", json={"slug": "pci-dss-11-6-1-weekly", "when": future})
        assert r.status_code == 422, r.text
        assert not (tmp_path / "state.yaml").exists()


class TestGapAnalyzeErrors:
    def test_malformed_yaml_is_400_without_detail_echo(self, api_client: TestClient) -> None:
        r = api_client.post("/api/gap/analyze", json={"frameworks": ["soc2-tsc"], "inventory_content": "a: b: c"})
        assert r.status_code == 400, r.text
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "a: b: c" not in detail["message"]
        assert "tmp" not in detail["message"].lower()

    def test_unknown_framework_is_400(self, api_client: TestClient) -> None:
        fixture = Path(__file__).resolve().parents[2] / "fixtures" / "sample-inventory.yaml"
        inventory = fixture.read_text(encoding="utf-8")
        r = api_client.post(
            "/api/gap/analyze", json={"frameworks": ["no-such-framework"], "inventory_content": inventory}
        )
        assert r.status_code == 400, r.text
        assert r.json()["detail"]["field"] == "frameworks"

    def test_unpaired_surrogate_is_400(self, api_client: TestClient) -> None:
        # The JSON escape decodes to a lone surrogate that no UTF-8 writer accepts;
        # the test client cannot serialise it itself, so the body is sent raw.
        raw = b'{"frameworks": ["soc2-tsc"], "inventory_content": "a: \\ud800"}'
        r = api_client.post("/api/gap/analyze", content=raw, headers={"content-type": "application/json"})
        assert r.status_code == 400, r.text
        assert r.json()["detail"]["error"] == "invalid_body"

    def test_inline_inventory_is_capped(self, api_client: TestClient) -> None:
        r = api_client.post("/api/gap/analyze", json={"frameworks": ["soc2-tsc"], "inventory_content": "x" * 8_000_001})
        assert r.status_code == 422, r.text


class TestOscalVerifySemantics:
    def test_empty_document_is_not_valid(self, api_client: TestClient) -> None:
        r = api_client.post("/api/oscal/verify", json={"content": json.dumps({})})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["has_verification_surface"] is False
        assert body["overall_valid"] is False

    def test_identity_pins_need_a_bundle(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/oscal/verify",
            json={
                "content": json.dumps({}),
                "expected_sigstore_identity": "ci@example.com",
                "expected_sigstore_issuer": "https://token.actions.githubusercontent.com",
            },
        )
        assert r.status_code == 400, r.text
        assert "bundle" in r.json()["detail"]["message"]

    def test_inline_key_and_envelope_are_capped(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/oscal/verify",
            json={"content": json.dumps({}), "dsse_envelope": "{}", "verify_public_key": "k" * 20_001},
        )
        assert r.status_code == 422, r.text
