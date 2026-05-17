"""Integration tests for /api/ai-gov/* (v0.9.3 P2.5)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def isolated_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Per-test isolated AI registry; matches CLI test fixture."""
    registry_dir = tmp_path / "ai_registry"
    monkeypatch.setenv("EVIDENTIA_AI_REGISTRY_DIR", str(registry_dir))
    return registry_dir


class TestClassify:
    def test_classify_returns_high_for_annex_iii(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            "/api/ai-gov/classify",
            json={
                "name": "resume-screener",
                "purpose": "Score job applicants",
                "annex_iii_domain": "employment",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["eu_ai_act_tier"] == "high"

    def test_classify_returns_minimal_for_default(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            "/api/ai-gov/classify",
            json={"name": "spam-filter", "purpose": "Internal spam"},
        )
        assert resp.status_code == 200
        assert resp.json()["eu_ai_act_tier"] == "minimal"


class TestRegisterListGetDelete:
    def test_full_lifecycle(self, api_client: TestClient) -> None:
        # Register
        register = api_client.post(
            "/api/ai-gov/register",
            json={
                "descriptor": {
                    "name": "resume-screener",
                    "purpose": "Score job applicants",
                    "annex_iii_domain": "employment",
                },
                "provider": "acme-ai",
                "owner": "hr-team",
                "deployment_status": "pilot",
            },
        )
        assert register.status_code == 200
        system_id = register.json()["system_id"]

        # List
        listed = api_client.get("/api/ai-gov/systems")
        assert listed.status_code == 200
        assert len(listed.json()) == 1

        # Get
        got = api_client.get(f"/api/ai-gov/systems/{system_id}")
        assert got.status_code == 200
        assert got.json()["descriptor"]["name"] == "resume-screener"

        # Delete
        deleted = api_client.delete(f"/api/ai-gov/systems/{system_id}")
        assert deleted.status_code == 200
        assert deleted.json()["removed"] is True

        # Get after delete → 404
        gone = api_client.get(f"/api/ai-gov/systems/{system_id}")
        assert gone.status_code == 404

    def test_list_with_tier_filter(self, api_client: TestClient) -> None:
        api_client.post(
            "/api/ai-gov/register",
            json={
                "descriptor": {
                    "name": "high-risk",
                    "purpose": "x",
                    "annex_iii_domain": "employment",
                },
                "provider": "p",
                "owner": "o",
            },
        )
        api_client.post(
            "/api/ai-gov/register",
            json={
                "descriptor": {"name": "minimal", "purpose": "x"},
                "provider": "p",
                "owner": "o",
            },
        )

        high = api_client.get("/api/ai-gov/systems?tier=high")
        assert high.status_code == 200
        assert len(high.json()) == 1

        minimal = api_client.get("/api/ai-gov/systems?tier=minimal")
        assert minimal.status_code == 200
        assert len(minimal.json()) == 1

    def test_unknown_tier_returns_400(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.get("/api/ai-gov/systems?tier=bogus")
        assert resp.status_code == 400

    def test_invalid_uuid_returns_400(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.get("/api/ai-gov/systems/not-a-uuid")
        assert resp.status_code == 400

    def test_unknown_uuid_returns_404(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.get(
            "/api/ai-gov/systems/11111111-1111-4111-8111-111111111111"
        )
        assert resp.status_code == 404

    def test_delete_unknown_id_is_idempotent(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.delete(
            "/api/ai-gov/systems/11111111-1111-4111-8111-111111111111"
        )
        assert resp.status_code == 200
        assert resp.json()["removed"] is False
