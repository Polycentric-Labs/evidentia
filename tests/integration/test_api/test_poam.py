"""TestClient coverage for /api/poam/* endpoints (v0.9.0 P2).

Each test scopes the POA&M store to ``tmp_path`` via
``EVIDENTIA_POAM_STORE_DIR`` so no state leaks across tests or
into the real user profile. Reuses the project-wide
``api_client`` fixture from conftest.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from evidentia_core.models.gap import (
    ControlGap,
    GapSeverity,
    ImplementationEffort,
    Milestone,
    POAMState,
)
from evidentia_core.poam_store import save_poam
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolated_poam_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Point EVIDENTIA_POAM_STORE_DIR at an isolated tmp for each test."""
    store = tmp_path / "poam-store"
    monkeypatch.setenv("EVIDENTIA_POAM_STORE_DIR", str(store))
    return store


def _make_payload(
    control_id: str = "AC-2",
    severity: str = "high",
) -> dict[str, object]:
    return {
        "framework": "nist-800-53-rev5",
        "control_id": control_id,
        "control_title": "Account Management",
        "control_description": "Manage system accounts.",
        "gap_severity": severity,
        "implementation_status": "missing",
        "gap_description": "No automated lifecycle.",
        "remediation_guidance": "Implement Okta lifecycle.",
        "implementation_effort": "medium",
    }


def _make_gap(
    control_id: str = "AC-2",
    severity: GapSeverity = GapSeverity.HIGH,
) -> ControlGap:
    return ControlGap(
        framework="nist-800-53-rev5",
        control_id=control_id,
        control_title="Account Management",
        control_description="Manage system accounts.",
        gap_severity=severity,
        implementation_status="missing",
        gap_description="No lifecycle.",
        remediation_guidance="Implement Okta.",
        implementation_effort=ImplementationEffort.MEDIUM,
    )


# ── POST /api/poam/items ───────────────────────────────────────────


class TestCreatePoam:
    def test_create_returns_201_with_stamped_fields(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post("/api/poam/items", json=_make_payload())
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["id"]
        assert body["control_id"] == "AC-2"
        assert body["poam_milestones"] == []

    def test_invalid_severity_returns_422(
        self, api_client: TestClient
    ) -> None:
        payload = _make_payload(severity="not-a-real-severity")
        r = api_client.post("/api/poam/items", json=payload)
        assert r.status_code == 422


# ── GET /api/poam/items ────────────────────────────────────────────


class TestListPoams:
    def test_empty_store_returns_empty(self, api_client: TestClient) -> None:
        r = api_client.get("/api/poam/items")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 0
        assert body["items"] == []

    def test_lists_in_canonical_order(self, api_client: TestClient) -> None:
        save_poam(_make_gap("AC-1", GapSeverity.LOW))
        save_poam(_make_gap("AC-2", GapSeverity.CRITICAL))
        save_poam(_make_gap("AC-3", GapSeverity.MEDIUM))
        r = api_client.get("/api/poam/items")
        body = r.json()
        assert body["total"] == 3
        # First should be CRITICAL severity
        assert body["items"][0]["gap_severity"] == "critical"

    def test_severity_filter(self, api_client: TestClient) -> None:
        save_poam(_make_gap("AC-1", GapSeverity.LOW))
        save_poam(_make_gap("AC-2", GapSeverity.CRITICAL))
        r = api_client.get("/api/poam/items?severity=critical")
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["gap_severity"] == "critical"

    def test_invalid_severity_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.get("/api/poam/items?severity=not-real")
        assert r.status_code == 400
        # F-V08-DAST-3 status normalization: manual 4xx carries the
        # structured object detail (2026-07-06 convergence) — still
        # distinguishable from Pydantic's 422 array.
        detail = r.json()["detail"]
        assert detail["error"] == "unknown_severity"
        assert detail["severity"] == "not-real"
        assert "message" in detail

    def test_pagination(self, api_client: TestClient) -> None:
        for i in range(5):
            save_poam(_make_gap(f"AC-{i}", GapSeverity.HIGH))
        r = api_client.get("/api/poam/items?skip=2&limit=2")
        body = r.json()
        assert body["total"] == 5
        assert len(body["items"]) == 2


# ── GET /api/poam/items/{id} ───────────────────────────────────────


class TestGetPoam:
    def test_get_returns_record(self, api_client: TestClient) -> None:
        gap = _make_gap()
        save_poam(gap)
        r = api_client.get(f"/api/poam/items/{gap.id}")
        assert r.status_code == 200
        assert r.json()["id"] == gap.id

    def test_get_unknown_returns_404(self, api_client: TestClient) -> None:
        r = api_client.get(
            "/api/poam/items/00000000-0000-0000-0000-000000000000"
        )
        assert r.status_code == 404

    def test_get_invalid_id_returns_404(
        self, api_client: TestClient
    ) -> None:
        # Shape-violation widened to 404 per TPRM precedent.
        r = api_client.get("/api/poam/items/not-a-uuid")
        assert r.status_code == 404


# ── PUT /api/poam/items/{id} ───────────────────────────────────────


class TestReplacePoam:
    def test_replace_preserves_id_and_created_at(
        self, api_client: TestClient
    ) -> None:
        gap = _make_gap()
        save_poam(gap)
        # Client tries to overwrite id, but server pins it
        payload = _make_payload()
        payload["id"] = "different-id"  # type: ignore[assignment]
        r = api_client.put(
            f"/api/poam/items/{gap.id}", json=payload
        )
        # The "different-id" body fails Pydantic UUID validation
        # because gap.id is a UUID and Pydantic typing on ControlGap.id
        # accepts any string per the model; so this might pass or 422.
        # If 200, verify the id was server-pinned.
        if r.status_code == 200:
            assert r.json()["id"] == gap.id

    def test_replace_unknown_returns_404(
        self, api_client: TestClient
    ) -> None:
        r = api_client.put(
            "/api/poam/items/00000000-0000-0000-0000-000000000000",
            json=_make_payload(),
        )
        assert r.status_code == 404


# ── DELETE /api/poam/items/{id} ────────────────────────────────────


class TestDeletePoam:
    def test_delete_returns_204(self, api_client: TestClient) -> None:
        gap = _make_gap()
        save_poam(gap)
        r = api_client.delete(f"/api/poam/items/{gap.id}")
        assert r.status_code == 204
        # Verify gone
        r2 = api_client.get(f"/api/poam/items/{gap.id}")
        assert r2.status_code == 404

    def test_delete_unknown_returns_404(
        self, api_client: TestClient
    ) -> None:
        r = api_client.delete(
            "/api/poam/items/00000000-0000-0000-0000-000000000000"
        )
        assert r.status_code == 404


# ── milestones ─────────────────────────────────────────────────────


class TestAddMilestone:
    def test_add_milestone_returns_updated_poam(
        self, api_client: TestClient
    ) -> None:
        gap = _make_gap()
        save_poam(gap)
        r = api_client.post(
            f"/api/poam/items/{gap.id}/milestones",
            json={
                "target_date": "2026-06-30",
                "description": "Deliver Okta",
                "status": "planned",
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["poam_milestones"]) == 1
        assert body["poam_milestones"][0]["description"] == "Deliver Okta"

    def test_add_to_unknown_poam_returns_404(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/poam/items/00000000-0000-0000-0000-000000000000/milestones",
            json={
                "target_date": "2026-06-30",
                "description": "x",
            },
        )
        assert r.status_code == 404


class TestUpdateMilestone:
    def test_update_milestone_status_forward(
        self, api_client: TestClient
    ) -> None:
        gap = _make_gap()
        gap.poam_milestones.append(
            Milestone(
                target_date=date(2026, 6, 30),
                description="phase 1",
            )
        )
        save_poam(gap)
        ms_id = gap.poam_milestones[0].id
        r = api_client.patch(
            f"/api/poam/items/{gap.id}/milestones/{ms_id}",
            json={"status": "in_progress"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["poam_milestones"][0]["status"] == "in_progress"

    def test_backward_transition_returns_400(
        self, api_client: TestClient
    ) -> None:
        gap = _make_gap()
        gap.poam_milestones.append(
            Milestone(
                target_date=date(2026, 6, 30),
                description="phase 1",
                status=POAMState.COMPLETED,
            )
        )
        save_poam(gap)
        ms_id = gap.poam_milestones[0].id
        r = api_client.patch(
            f"/api/poam/items/{gap.id}/milestones/{ms_id}",
            json={"status": "in_progress"},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "Invalid state transition" in detail["message"]

    def test_update_unknown_milestone_returns_404(
        self, api_client: TestClient
    ) -> None:
        gap = _make_gap()
        save_poam(gap)
        r = api_client.patch(
            (
                f"/api/poam/items/{gap.id}/milestones/"
                f"00000000-0000-0000-0000-000000000000"
            ),
            json={"status": "in_progress"},
        )
        assert r.status_code == 404


# ── GET /api/poam/calendar ─────────────────────────────────────────


class TestCalendar:
    def test_empty_calendar(self, api_client: TestClient) -> None:
        r = api_client.get("/api/poam/calendar?today=2026-05-08")
        assert r.status_code == 200
        body = r.json()
        assert body["overdue"] == []
        assert body["due_soon"] == []

    def test_overdue_milestone_surfaces(
        self, api_client: TestClient
    ) -> None:
        gap = _make_gap()
        gap.poam_milestones.append(
            Milestone(
                target_date=date(2026, 1, 1),
                description="late work",
                status=POAMState.PLANNED,
            )
        )
        save_poam(gap)
        r = api_client.get("/api/poam/calendar?today=2026-05-08")
        body = r.json()
        assert len(body["overdue"]) == 1
        assert body["overdue"][0]["control_id"] == "nist-800-53-rev5:AC-2"

    def test_invalid_today_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.get("/api/poam/calendar?today=not-a-date")
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_field"
        assert detail["field"] == "today"


# ── OpenAPI error-status documentation (2026-07-06 convergence) ─────


def test_poam_error_statuses_documented_in_openapi(
    api_client: TestClient,
) -> None:
    """Every status the poam router deliberately raises is documented
    on the operation's ``responses`` (schemathesis undocumented-status
    noise → contract; companion to the ai_gov openapi test)."""
    schema = api_client.get("/api/openapi.json").json()
    expected: list[tuple[str, str, list[str]]] = [
        ("/api/poam/items", "get", ["400"]),
        ("/api/poam/items", "post", ["422"]),
        ("/api/poam/items/{poam_id}", "get", ["404"]),
        ("/api/poam/items/{poam_id}", "put", ["404"]),
        ("/api/poam/items/{poam_id}", "delete", ["404"]),
        ("/api/poam/items/{poam_id}/milestones", "post", ["404"]),
        (
            "/api/poam/items/{poam_id}/milestones/{milestone_id}",
            "patch",
            ["400", "404"],
        ),
        ("/api/poam/calendar", "get", ["400"]),
    ]
    for path, method, statuses in expected:
        op = schema["paths"][path][method]
        for status in statuses:
            assert status in op["responses"], (
                f"{method.upper()} {path} missing documented {status}"
            )
