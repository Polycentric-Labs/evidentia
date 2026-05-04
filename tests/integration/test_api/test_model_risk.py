"""TestClient coverage for /api/model-risk/models/* endpoints (v0.7.10 P0.6).

Each test scopes the model store to ``tmp_path`` via the
``EVIDENTIA_MODEL_STORE_DIR`` env var so no state leaks across
tests or into the real user profile. Reuses the project-wide
``api_client`` fixture from conftest.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolated_model_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Point EVIDENTIA_MODEL_STORE_DIR at an isolated tmp for each test."""
    store = tmp_path / "model-store"
    monkeypatch.setenv("EVIDENTIA_MODEL_STORE_DIR", str(store))
    return store


def _make_payload(
    name: str = "FICO scorer v3",
    methodology: str = "ml",
    tier: str = "tier_1",
    vendor_or_internal: str = "internal",
) -> dict[str, object]:
    return {
        "name": name,
        "purpose": "Score consumer credit applications",
        "methodology": methodology,
        "vendor_or_internal": vendor_or_internal,
        "tier": tier,
        "owner": "ml-team@example.com",
    }


# ── POST /api/model-risk/models ────────────────────────────────────


class TestCreateModel:
    def test_minimal_create_returns_201_with_stamped_fields(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/model-risk/models", json=_make_payload()
        )
        assert r.status_code == 201, r.text
        body = r.json()
        # Server stamped these via Pydantic default_factory
        assert body["id"]
        assert body["created_at"]
        assert body["updated_at"]
        assert body["evidentia_version"]
        assert body["name"] == "FICO scorer v3"

    def test_create_auto_computes_next_validation_due(
        self, api_client: TestClient
    ) -> None:
        payload = _make_payload(tier="tier_1")
        payload["last_validation_date"] = "2025-06-15"
        r = api_client.post("/api/model-risk/models", json=payload)
        assert r.status_code == 201, r.text
        # tier_1 → annual cadence
        assert r.json()["next_validation_due"] == "2026-06-15"

    def test_create_with_explicit_next_validation_due(
        self, api_client: TestClient
    ) -> None:
        payload = _make_payload(tier="tier_1")
        payload["last_validation_date"] = "2025-06-15"
        payload["next_validation_due"] = "2025-12-01"
        r = api_client.post("/api/model-risk/models", json=payload)
        assert r.status_code == 201
        # operator override beats auto-cadence
        assert r.json()["next_validation_due"] == "2025-12-01"

    def test_invalid_enum_returns_422_via_pydantic(
        self, api_client: TestClient
    ) -> None:
        payload = _make_payload(methodology="telepathy")
        r = api_client.post("/api/model-risk/models", json=payload)
        assert r.status_code == 422

    def test_vendor_provenance_without_vendor_id_returns_422(
        self, api_client: TestClient
    ) -> None:
        payload = _make_payload(vendor_or_internal="vendor", methodology="llm")
        r = api_client.post("/api/model-risk/models", json=payload)
        assert r.status_code == 422

    def test_internal_provenance_with_vendor_id_returns_422(
        self, api_client: TestClient
    ) -> None:
        payload = _make_payload()
        payload["vendor_id"] = "aaaa1111-2222-3333-4444-555566667777"
        r = api_client.post("/api/model-risk/models", json=payload)
        assert r.status_code == 422


# ── GET /api/model-risk/models ─────────────────────────────────────


class TestListModels:
    def test_empty_list(self, api_client: TestClient) -> None:
        r = api_client.get("/api/model-risk/models")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 0
        assert body["models"] == []

    def test_list_with_pagination_envelope(
        self, api_client: TestClient
    ) -> None:
        for i in range(3):
            api_client.post(
                "/api/model-risk/models",
                json=_make_payload(name=f"Model {i}"),
            )
        r = api_client.get("/api/model-risk/models?skip=0&limit=2")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 3
        assert body["skip"] == 0
        assert body["limit"] == 2
        assert len(body["models"]) == 2

    def test_filter_by_tier(self, api_client: TestClient) -> None:
        api_client.post(
            "/api/model-risk/models", json=_make_payload(name="T1", tier="tier_1")
        )
        api_client.post(
            "/api/model-risk/models", json=_make_payload(name="T2", tier="tier_2")
        )
        r = api_client.get("/api/model-risk/models?tier=tier_1")
        body = r.json()
        assert body["total"] == 1
        assert body["models"][0]["name"] == "T1"

    def test_filter_by_methodology(self, api_client: TestClient) -> None:
        api_client.post(
            "/api/model-risk/models",
            json=_make_payload(name="ML", methodology="ml"),
        )
        api_client.post(
            "/api/model-risk/models",
            json=_make_payload(name="LLM", methodology="llm"),
        )
        r = api_client.get("/api/model-risk/models?methodology=llm")
        assert r.json()["total"] == 1

    def test_invalid_tier_filter_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.get("/api/model-risk/models?tier=tier_99")
        assert r.status_code == 400
        assert isinstance(r.json()["detail"], str)


# ── GET /api/model-risk/models/{id} ────────────────────────────────


class TestGetModel:
    def test_get_existing(self, api_client: TestClient) -> None:
        post = api_client.post(
            "/api/model-risk/models", json=_make_payload()
        )
        mid = post.json()["id"]
        r = api_client.get(f"/api/model-risk/models/{mid}")
        assert r.status_code == 200
        assert r.json()["id"] == mid

    def test_get_unknown_returns_404(self, api_client: TestClient) -> None:
        r = api_client.get(
            "/api/model-risk/models/00000000-0000-0000-0000-000000000000"
        )
        assert r.status_code == 404

    def test_get_invalid_id_shape_returns_404(
        self, api_client: TestClient
    ) -> None:
        # Path-traversal shape and non-uuid both normalize to 404
        r = api_client.get("/api/model-risk/models/not-a-uuid")
        assert r.status_code == 404


# ── PUT /api/model-risk/models/{id} ────────────────────────────────


class TestReplaceModel:
    def test_replace_preserves_id_and_created_at(
        self, api_client: TestClient
    ) -> None:
        post = api_client.post(
            "/api/model-risk/models", json=_make_payload()
        )
        original = post.json()
        mid = original["id"]
        # Client supplies a different id; server must ignore it
        new_payload = _make_payload(name="Renamed")
        new_payload["id"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        r = api_client.put(
            f"/api/model-risk/models/{mid}", json=new_payload
        )
        assert r.status_code == 200, r.text
        body = r.json()
        # path id wins
        assert body["id"] == mid
        assert body["created_at"] == original["created_at"]
        assert body["name"] == "Renamed"

    def test_replace_recomputes_next_validation_due(
        self, api_client: TestClient
    ) -> None:
        post = api_client.post(
            "/api/model-risk/models", json=_make_payload(tier="tier_2")
        )
        mid = post.json()["id"]
        update = _make_payload(tier="tier_2")
        update["last_validation_date"] = "2025-06-15"
        r = api_client.put(f"/api/model-risk/models/{mid}", json=update)
        assert r.status_code == 200
        # tier_2 → biennial → 2027-06-15
        assert r.json()["next_validation_due"] == "2027-06-15"

    def test_replace_explicit_override_wins(
        self, api_client: TestClient
    ) -> None:
        post = api_client.post(
            "/api/model-risk/models", json=_make_payload(tier="tier_1")
        )
        mid = post.json()["id"]
        update = _make_payload(tier="tier_1")
        update["last_validation_date"] = "2025-06-15"
        update["next_validation_due"] = "2025-12-31"
        r = api_client.put(f"/api/model-risk/models/{mid}", json=update)
        assert r.json()["next_validation_due"] == "2025-12-31"

    def test_replace_unknown_returns_404(
        self, api_client: TestClient
    ) -> None:
        r = api_client.put(
            "/api/model-risk/models/00000000-0000-0000-0000-000000000000",
            json=_make_payload(),
        )
        assert r.status_code == 404


# ── DELETE /api/model-risk/models/{id} ─────────────────────────────


class TestDeleteModel:
    def test_delete_returns_204(self, api_client: TestClient) -> None:
        post = api_client.post(
            "/api/model-risk/models", json=_make_payload()
        )
        mid = post.json()["id"]
        r = api_client.delete(f"/api/model-risk/models/{mid}")
        assert r.status_code == 204
        # confirm gone
        get_after = api_client.get(f"/api/model-risk/models/{mid}")
        assert get_after.status_code == 404

    def test_delete_unknown_returns_404(
        self, api_client: TestClient
    ) -> None:
        r = api_client.delete(
            "/api/model-risk/models/00000000-0000-0000-0000-000000000000"
        )
        assert r.status_code == 404

    def test_delete_invalid_id_shape_returns_404(
        self, api_client: TestClient
    ) -> None:
        r = api_client.delete("/api/model-risk/models/not-a-uuid")
        assert r.status_code == 404


# ── GET /api/model-risk/models/{id}/next-validation-due ────────────


class TestPreviewNextValidationDue:
    def test_preview_returns_computed_date(
        self, api_client: TestClient
    ) -> None:
        payload = _make_payload(tier="tier_1")
        payload["last_validation_date"] = "2025-06-15"
        post = api_client.post("/api/model-risk/models", json=payload)
        mid = post.json()["id"]
        r = api_client.get(
            f"/api/model-risk/models/{mid}/next-validation-due"
        )
        assert r.status_code == 200
        assert r.json() == {"next_validation_due": "2026-06-15"}

    def test_preview_returns_null_when_no_anchor(
        self, api_client: TestClient
    ) -> None:
        post = api_client.post(
            "/api/model-risk/models", json=_make_payload()
        )
        mid = post.json()["id"]
        r = api_client.get(
            f"/api/model-risk/models/{mid}/next-validation-due"
        )
        assert r.status_code == 200
        assert r.json() == {"next_validation_due": None}

    def test_preview_unknown_returns_404(
        self, api_client: TestClient
    ) -> None:
        r = api_client.get(
            "/api/model-risk/models/"
            "00000000-0000-0000-0000-000000000000/next-validation-due"
        )
        assert r.status_code == 404
