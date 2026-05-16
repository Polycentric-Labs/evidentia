"""TestClient coverage for /api/conmon/* endpoints (v0.9.1 P1).

CONMON REST router parity with the v0.9.0 CLI surface.
Reuses the project-wide ``api_client`` fixture from conftest.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestListCadences:
    """GET /api/conmon/cadences."""

    def test_list_all_returns_bundled(self, api_client: TestClient) -> None:
        resp = api_client.get("/api/conmon/cadences")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 7
        slugs = [c["slug"] for c in data]
        assert "nist-800-53-rev5-ca7" in slugs
        assert "fedramp-conmon-poam" in slugs

    def test_list_filter_by_framework(self, api_client: TestClient) -> None:
        resp = api_client.get(
            "/api/conmon/cadences", params={"framework": "fedramp-rev5-mod"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 3
        for item in data:
            assert item["framework"] == "fedramp-rev5-mod"

    def test_list_filter_unknown_framework_returns_empty(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.get(
            "/api/conmon/cadences", params={"framework": "nonexistent"}
        )
        assert resp.status_code == 200
        assert resp.json() == []

    def test_cadence_shape(self, api_client: TestClient) -> None:
        resp = api_client.get("/api/conmon/cadences")
        first = resp.json()[0]
        assert "slug" in first
        assert "framework" in first
        assert "activity" in first
        assert "frequency" in first
        assert "description" in first
        assert "citation" in first


class TestGetCadence:
    """GET /api/conmon/cadences/{slug}."""

    def test_get_known_slug(self, api_client: TestClient) -> None:
        resp = api_client.get("/api/conmon/cadences/nist-800-53-rev5-ca7")
        assert resp.status_code == 200
        data = resp.json()
        assert data["slug"] == "nist-800-53-rev5-ca7"
        assert data["framework"] == "nist-800-53-rev5"
        assert data["frequency"] == "monthly"

    def test_get_unknown_slug_returns_404(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.get("/api/conmon/cadences/nonexistent-slug")
        assert resp.status_code == 404


class TestNextDue:
    """POST /api/conmon/next."""

    def test_compute_monthly(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/next",
            json={
                "slug": "nist-800-53-rev5-ca7",
                "last_completed": "2026-04-15",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["slug"] == "nist-800-53-rev5-ca7"
        assert data["next_due"] == "2026-05-15"
        assert data["last_completed"] == "2026-04-15"

    def test_compute_annual(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/next",
            json={
                "slug": "fedramp-conmon-annual",
                "last_completed": "2025-06-01",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["next_due"] == "2026-06-01"

    def test_unknown_slug_returns_404(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/next",
            json={
                "slug": "no-such-cadence",
                "last_completed": "2026-01-01",
            },
        )
        assert resp.status_code == 404

    def test_last_day_clamping(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/next",
            json={
                "slug": "nist-800-53-rev5-ca7",
                "last_completed": "2026-01-31",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["next_due"] == "2026-02-28"


class TestCheck:
    """POST /api/conmon/check."""

    def test_overdue_detection(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={
                "entries": [
                    {
                        "slug": "nist-800-53-rev5-ca7",
                        "last_completed": "2026-01-01",
                    }
                ],
                "today": "2026-05-15",
                "window_days": 14,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["today"] == "2026-05-15"
        assert len(data["overdue"]) == 1
        assert data["overdue"][0]["slug"] == "nist-800-53-rev5-ca7"
        assert data["overdue"][0]["state"] == "overdue"

    def test_due_soon_detection(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={
                "entries": [
                    {
                        "slug": "nist-800-53-rev5-ca7",
                        "last_completed": "2026-05-01",
                    }
                ],
                "today": "2026-05-20",
                "window_days": 14,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["due_soon"]) == 1
        assert data["due_soon"][0]["state"] == "due_soon"

    def test_current_detection(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={
                "entries": [
                    {
                        "slug": "nist-800-53-rev5-ca7",
                        "last_completed": "2026-05-10",
                    }
                ],
                "today": "2026-05-15",
                "window_days": 14,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["current"]) == 1
        assert data["current"][0]["state"] == "current"

    def test_unknown_slugs_collected(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={
                "entries": [
                    {
                        "slug": "unknown-slug-xyz",
                        "last_completed": "2026-01-01",
                    },
                    {
                        "slug": "nist-800-53-rev5-ca7",
                        "last_completed": "2026-05-10",
                    },
                ],
                "today": "2026-05-15",
                "window_days": 14,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "unknown-slug-xyz" in data["unknown_slugs"]
        assert len(data["current"]) == 1

    def test_batch_multiple_cadences(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={
                "entries": [
                    {
                        "slug": "nist-800-53-rev5-ca7",
                        "last_completed": "2026-01-01",
                    },
                    {
                        "slug": "fedramp-conmon-poam",
                        "last_completed": "2026-05-01",
                    },
                    {
                        "slug": "fedramp-conmon-annual",
                        "last_completed": "2025-06-01",
                    },
                ],
                "today": "2026-05-15",
                "window_days": 14,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        total = (
            len(data["overdue"])
            + len(data["due_soon"])
            + len(data["current"])
        )
        assert total == 3

    def test_default_today_uses_real_date(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={
                "entries": [
                    {
                        "slug": "nist-800-53-rev5-ca7",
                        "last_completed": "2020-01-01",
                    }
                ],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["today"] is not None
        assert len(data["overdue"]) == 1

    def test_empty_entries_returns_422(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={"entries": []},
        )
        assert resp.status_code == 422

    def test_over_100_entries_returns_422(self, api_client: TestClient) -> None:
        entries = [
            {"slug": "nist-800-53-rev5-ca7", "last_completed": "2026-01-01"}
            for _ in range(101)
        ]
        resp = api_client.post(
            "/api/conmon/check",
            json={"entries": entries, "today": "2026-05-15"},
        )
        assert resp.status_code == 422
