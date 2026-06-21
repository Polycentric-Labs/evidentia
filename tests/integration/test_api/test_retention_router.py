"""TestClient coverage for /api/retention/* endpoints (v0.10.12 P?).

Surfaces the v0.7.11 retention data layer + lifecycle primitives over
HTTP. Each test scopes the retention store to ``tmp_path`` via
``EVIDENTIA_RETENTION_STORE_DIR`` so no state leaks across tests or
into the real user profile.

Mirrors tests/integration/test_api/test_poam.py in style. The
``api_client`` fixture is overridden locally here: the retention
router is wired onto a fresh FastAPI app under the ``/api`` prefix
(the same mount the app-layer controller will use). This keeps the
test hermetic + the router fully exercised WITHOUT editing app.py
(the router-mount integration is a separate, out-of-scope change).
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
from evidentia_core.rbac import RBACPolicy, Role
from evidentia_core.retention.metadata import (
    RetentionMetadata,
    default_retention_days,
)
from evidentia_core.retention_metadata_store import save_retention
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolated_retention_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Point EVIDENTIA_RETENTION_STORE_DIR at an isolated tmp per test."""
    store = tmp_path / "retention-store"
    monkeypatch.setenv("EVIDENTIA_RETENTION_STORE_DIR", str(store))
    return store


@pytest.fixture
def api_client() -> TestClient:
    """Fresh TestClient with the retention router mounted under /api.

    Overrides the conftest ``api_client`` so this suite exercises the
    new router even before app.py wires it (strict file scope: this
    test + the router are the only new files; app.py is untouched).
    """
    from evidentia_api.routers import retention as retention_router

    app = FastAPI()
    app.include_router(
        retention_router.router, prefix="/api", tags=["retention"]
    )
    return TestClient(app)


@pytest.fixture
def readonly_api_client() -> TestClient:
    """Retention TestClient under a restrictive read-only RBAC policy.

    The store dir is isolated by the autouse ``_isolated_retention_store``
    fixture. This app sets ``app.state.rbac_policy`` to a deny-by-default
    policy whose ``default_role`` is ``reader`` — an anonymous request
    (identity None) resolves to that role, so reads pass while the
    ``require_role("write")`` / ``require_role("admin")`` gates deny.
    Proves those gates actually bite (they are inert under the permissive
    DEFAULT_POLICY the other tests run with).
    """
    from evidentia_api.routers import retention as retention_router

    app = FastAPI()
    app.include_router(
        retention_router.router, prefix="/api", tags=["retention"]
    )
    app.state.rbac_policy = RBACPolicy(
        identities={}, default_role=Role.READER
    )
    return TestClient(app)


def _set_payload(
    classification: str = "sox-404",
    **overrides: object,
) -> dict[str, object]:
    payload: dict[str, object] = {"classification": classification}
    payload.update(overrides)
    return payload


def _seed(
    classification: str = "sox-404",
    **overrides: object,
) -> RetentionMetadata:
    """Persist a RetentionMetadata directly to the store + return it."""
    days = overrides.pop(
        "retention_period_days", default_retention_days(classification)
    )
    md = RetentionMetadata(
        classification=classification,  # type: ignore[arg-type]
        retention_period_days=days,  # type: ignore[arg-type]
        **overrides,  # type: ignore[arg-type]
    )
    save_retention(md)
    return md


# ── POST /api/retention (set) ──────────────────────────────────────


class TestSetRetention:
    def test_set_returns_201_with_computed_lock_until(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/retention",
            json=_set_payload("sox-404", record_pointer="s3://bucket/x"),
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["id"]
        assert body["classification"] == "sox-404"
        # default 7*365 days → lock_until computed by the validator
        assert body["lock_until"] is not None
        expected = (
            date.fromisoformat(body["created_at"][:10])
            + timedelta(days=7 * 365)
        ).isoformat()
        assert body["lock_until"] == expected
        assert body["retention_period_days"] == 7 * 365
        assert body["lifecycle_stage"] == "active"

    def test_set_uses_default_days_when_omitted(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post("/api/retention", json=_set_payload("pci-dss"))
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["retention_period_days"] == default_retention_days(
            "pci-dss"
        )

    def test_set_honors_explicit_days(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/retention",
            json=_set_payload("generic", retention_period_days=10),
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["retention_period_days"] == 10

    def test_set_unknown_classification_returns_422(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/retention", json=_set_payload("not-a-class")
        )
        assert r.status_code == 422


# ── GET /api/retention (list) ──────────────────────────────────────


class TestListRetention:
    def test_list_returns_envelope(self, api_client: TestClient) -> None:
        _seed("sox-404")
        _seed("pci-dss")
        r = api_client.get("/api/retention")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] == 2
        assert body["skip"] == 0
        assert body["limit"] >= 2
        assert len(body["items"]) == 2

    def test_list_filters_by_classification(
        self, api_client: TestClient
    ) -> None:
        _seed("sox-404")
        _seed("pci-dss")
        r = api_client.get("/api/retention?classification=pci-dss")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["classification"] == "pci-dss"

    def test_list_filters_by_lifecycle(
        self, api_client: TestClient
    ) -> None:
        _seed("sox-404")
        r = api_client.get("/api/retention?lifecycle=active")
        assert r.status_code == 200, r.text
        assert r.json()["total"] == 1
        r2 = api_client.get("/api/retention?lifecycle=purged")
        assert r2.status_code == 200, r2.text
        assert r2.json()["total"] == 0

    def test_list_unknown_classification_filter_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.get("/api/retention?classification=bogus")
        assert r.status_code == 400, r.text

    def test_list_unknown_lifecycle_filter_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.get("/api/retention?lifecycle=bogus")
        assert r.status_code == 400, r.text


# ── GET /api/retention/{id} (show) ─────────────────────────────────


class TestShowRetention:
    def test_show_returns_record(self, api_client: TestClient) -> None:
        md = _seed("hipaa")
        r = api_client.get(f"/api/retention/{md.id}")
        assert r.status_code == 200, r.text
        assert r.json()["id"] == md.id
        assert r.json()["classification"] == "hipaa"

    def test_show_missing_returns_404(self, api_client: TestClient) -> None:
        import uuid

        r = api_client.get(f"/api/retention/{uuid.uuid4()}")
        assert r.status_code == 404, r.text

    def test_show_invalid_id_returns_404(
        self, api_client: TestClient
    ) -> None:
        r = api_client.get("/api/retention/not-a-uuid")
        assert r.status_code == 404, r.text


# ── POST /api/retention/{id}/extend ────────────────────────────────


class TestExtendRetention:
    def test_extend_happy(self, api_client: TestClient) -> None:
        md = _seed("generic", retention_period_days=10)
        assert md.lock_until is not None
        new_lock = (md.lock_until + timedelta(days=30)).isoformat()
        r = api_client.post(
            f"/api/retention/{md.id}/extend",
            json={"new_lock_until": new_lock},
        )
        assert r.status_code == 200, r.text
        assert r.json()["lock_until"] == new_lock

    def test_extend_shorten_returns_400(
        self, api_client: TestClient
    ) -> None:
        md = _seed("generic", retention_period_days=100)
        assert md.lock_until is not None
        earlier = (md.lock_until - timedelta(days=30)).isoformat()
        r = api_client.post(
            f"/api/retention/{md.id}/extend",
            json={"new_lock_until": earlier},
        )
        assert r.status_code == 400, r.text

    def test_extend_missing_returns_404(
        self, api_client: TestClient
    ) -> None:
        import uuid

        r = api_client.post(
            f"/api/retention/{uuid.uuid4()}/extend",
            json={"new_lock_until": date.today().isoformat()},
        )
        assert r.status_code == 404, r.text


# ── POST /api/retention/{id}/transition ────────────────────────────


class TestTransitionRetention:
    def test_transition_active_to_preserved(
        self, api_client: TestClient
    ) -> None:
        md = _seed("sox-404")
        r = api_client.post(
            f"/api/retention/{md.id}/transition",
            json={"new_stage": "preserved"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["lifecycle_stage"] == "preserved"

    def test_illegal_transition_returns_400(
        self, api_client: TestClient
    ) -> None:
        # purged is terminal; purged → active is illegal.
        md = _seed("sox-404", lifecycle_stage="purged")
        r = api_client.post(
            f"/api/retention/{md.id}/transition",
            json={"new_stage": "active"},
        )
        assert r.status_code == 400, r.text

    def test_transition_missing_returns_404(
        self, api_client: TestClient
    ) -> None:
        import uuid

        r = api_client.post(
            f"/api/retention/{uuid.uuid4()}/transition",
            json={"new_stage": "preserved"},
        )
        assert r.status_code == 404, r.text


# ── DELETE /api/retention/{id} ─────────────────────────────────────


class TestDeleteRetention:
    def test_delete_returns_204(self, api_client: TestClient) -> None:
        md = _seed("glba")
        r = api_client.delete(f"/api/retention/{md.id}")
        assert r.status_code == 204, r.text
        # gone
        assert (
            api_client.get(f"/api/retention/{md.id}").status_code == 404
        )

    def test_delete_missing_returns_404(
        self, api_client: TestClient
    ) -> None:
        import uuid

        r = api_client.delete(f"/api/retention/{uuid.uuid4()}")
        assert r.status_code == 404, r.text

    def test_delete_invalid_id_returns_404(
        self, api_client: TestClient
    ) -> None:
        r = api_client.delete("/api/retention/not-a-uuid")
        assert r.status_code == 404, r.text


# ── GET /api/retention/report ──────────────────────────────────────


class TestRetentionReport:
    def test_report_returns_markdown(self, api_client: TestClient) -> None:
        _seed("sox-404")
        r = api_client.get("/api/retention/report")
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("text/plain")
        assert "# Retention Posture Report" in r.text

    def test_report_empty_inventory(self, api_client: TestClient) -> None:
        r = api_client.get("/api/retention/report")
        assert r.status_code == 200, r.text
        assert "# Retention Posture Report" in r.text

    def test_report_not_shadowed_by_id_route(
        self, api_client: TestClient
    ) -> None:
        # /retention/report must resolve to the report route, NOT the
        # /retention/{retention_id} param route (which would 404 on the
        # invalid 'report' id).
        r = api_client.get("/api/retention/report")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/plain")


# ── RBAC enforcement (proves the require_role gates bite) ──────────


class TestRetentionRBAC:
    """Under a read-only policy the write + admin gates must deny.

    The other tests run under the permissive DEFAULT_POLICY, where the
    ``require_role`` gates are inert. These install a deny-by-default
    (read-only) policy and prove a write (set) → 403, an admin DELETE →
    403, while a read (list) still returns 200.
    """

    def test_anonymous_set_denied_403(
        self, readonly_api_client: TestClient
    ) -> None:
        # POST /retention is gated on require_role("write").
        r = readonly_api_client.post(
            "/api/retention", json=_set_payload("sox-404")
        )
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "rbac_denied"

    def test_anonymous_delete_denied_403(
        self, readonly_api_client: TestClient
    ) -> None:
        # Seed directly (store dir isolated by the autouse fixture) so a
        # real record exists; the admin DELETE gate must still deny.
        md = _seed("glba")
        r = readonly_api_client.delete(f"/api/retention/{md.id}")
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "rbac_denied"

    def test_anonymous_list_allowed_200(
        self, readonly_api_client: TestClient
    ) -> None:
        # The list endpoint carries no require_role gate (reads are open),
        # so it returns 200 even under the read-only policy — proving the
        # policy is read-allowed, not blanket-deny.
        _seed("sox-404")
        r = readonly_api_client.get("/api/retention")
        assert r.status_code == 200, r.text
        assert r.json()["total"] == 1
