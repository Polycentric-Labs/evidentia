"""Integration tests for /api/ai-gov/* (v0.9.3 P2.5)."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

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


# ── v0.9.4 P1.3: rate-limit + idempotency on register ───────────────


class TestIdempotency:
    """v0.9.4 P1.3 closes F-V93-S10 LOW (register has no duplicate-
    name detection). X-Idempotency-Key header lets clients retry
    safely without creating duplicates."""

    _SAMPLE_BODY: ClassVar[dict] = {
        "descriptor": {
            "name": "resume-screener",
            "purpose": "Score job applicants",
            "annex_iii_domain": "employment",
        },
        "provider": "acme-ai",
        "owner": "hr-team",
    }

    def test_same_key_same_body_returns_prior_system_id(
        self, api_client: TestClient
    ) -> None:
        """Idempotent replay: identical key + body returns the
        original system_id and the entry is NOT duplicated."""
        first = api_client.post(
            "/api/ai-gov/register",
            json=self._SAMPLE_BODY,
            headers={"X-Idempotency-Key": "test-key-1"},
        )
        assert first.status_code == 200
        first_id = first.json()["system_id"]
        assert first.json().get("idempotent_replay") is not True

        second = api_client.post(
            "/api/ai-gov/register",
            json=self._SAMPLE_BODY,
            headers={"X-Idempotency-Key": "test-key-1"},
        )
        assert second.status_code == 200
        assert second.json()["system_id"] == first_id
        assert second.json()["idempotent_replay"] is True

        # Confirm no duplicate created.
        listing = api_client.get("/api/ai-gov/systems")
        assert listing.status_code == 200
        assert len(listing.json()) == 1

    def test_same_key_different_body_returns_409(
        self, api_client: TestClient
    ) -> None:
        """Same key + different body = 409 Conflict (operator error
        signal). Prevents key-reuse bugs from silently creating
        wrong-data entries."""
        first = api_client.post(
            "/api/ai-gov/register",
            json=self._SAMPLE_BODY,
            headers={"X-Idempotency-Key": "test-key-2"},
        )
        assert first.status_code == 200

        different_body = {
            **self._SAMPLE_BODY,
            "owner": "different-team",
        }
        second = api_client.post(
            "/api/ai-gov/register",
            json=different_body,
            headers={"X-Idempotency-Key": "test-key-2"},
        )
        assert second.status_code == 409
        assert "test-key-2" in second.json()["detail"]

    def test_no_key_creates_fresh_entry_each_call(
        self, api_client: TestClient
    ) -> None:
        """Without X-Idempotency-Key, repeated POSTs create separate
        entries (legacy v0.9.3 behavior preserved)."""
        first = api_client.post(
            "/api/ai-gov/register", json=self._SAMPLE_BODY
        )
        second = api_client.post(
            "/api/ai-gov/register", json=self._SAMPLE_BODY
        )
        assert first.status_code == 200
        assert second.status_code == 200
        assert first.json()["system_id"] != second.json()["system_id"]


class TestRateLimit:
    """v0.9.4 P1.3 — token-bucket rate limit on POST /classify +
    POST /register. Default burst=10 + 60/min. Tests rely on TestClient
    setting a stable client.host (per Starlette's TestClient default,
    requests appear from 'testclient')."""

    _SAMPLE_CLASSIFY_BODY: ClassVar[dict] = {
        "name": "spam-filter",
        "purpose": "Internal spam",
    }

    def test_burst_then_throttle(self, api_client: TestClient) -> None:
        """Burst capacity of 10 → 10 succeed, 11th returns 429."""
        # First 10 should all succeed (burst).
        for i in range(10):
            resp = api_client.post(
                "/api/ai-gov/classify",
                json={
                    "name": f"item-{i}",
                    "purpose": "test",
                },
            )
            assert resp.status_code == 200, (
                f"burst {i} should be allowed but got {resp.status_code}"
            )
        # 11th hits empty bucket → 429.
        resp = api_client.post(
            "/api/ai-gov/classify", json=self._SAMPLE_CLASSIFY_BODY
        )
        assert resp.status_code == 429
        assert "Rate limit" in resp.json()["detail"]
        assert resp.headers.get("Retry-After") == "5"

    def test_get_endpoints_not_rate_limited(
        self, api_client: TestClient
    ) -> None:
        """GET endpoints (list/show) aren't on the allowlist —
        many calls in a row all succeed."""
        for _ in range(50):
            resp = api_client.get("/api/ai-gov/systems")
            assert resp.status_code == 200
