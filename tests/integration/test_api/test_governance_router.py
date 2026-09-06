"""TestClient coverage for /api/governance/* endpoints (v0.10.12).

Surfaces the governance CLI verbs (effective-challenge log, KRI/KPI/KGI
metrics, process-as-code workflows, 3LOD lines report) over HTTP.

Hermetic: a LOCAL ``FastAPI()`` app includes ONLY the governance router
under ``prefix="/api"`` (the router is NOT yet registered in
``evidentia_api.app.create_app``, so we cannot reuse the project-wide
``api_client`` fixture). All three persistence stores are isolated to
``tmp_path`` via their store-dir env vars
(``EVIDENTIA_CHALLENGE_STORE_DIR`` / ``EVIDENTIA_METRIC_STORE_DIR`` /
``EVIDENTIA_WORKFLOW_STORE_DIR``) so nothing leaks across tests or into
the real user-data dir. The lines-report endpoint is stateless (it
takes a posted owner list), so no store isolation is needed for it.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import date
from pathlib import Path

import pytest
from evidentia_core.effective_challenge_store import save_challenge
from evidentia_core.governance import (
    ChallengeOutcome,
    EffectiveChallenge,
    Metric,
    MetricDirection,
    MetricKind,
    MetricObservation,
    Workflow,
    WorkflowStep,
    WorkflowStepStatus,
)
from evidentia_core.metric_store import save_metric
from evidentia_core.rbac import RBACPolicy, Role
from evidentia_core.workflow_store import save_workflow
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def gov_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """A TestClient over a local app holding ONLY the governance router.

    Each of the three governance stores is redirected to an isolated
    tmp subdirectory so saved records never touch the developer's real
    user-data dir or leak across tests.
    """
    monkeypatch.setenv("EVIDENTIA_CHALLENGE_STORE_DIR", str(tmp_path / "challenge-store"))
    monkeypatch.setenv("EVIDENTIA_METRIC_STORE_DIR", str(tmp_path / "metric-store"))
    monkeypatch.setenv("EVIDENTIA_WORKFLOW_STORE_DIR", str(tmp_path / "workflow-store"))
    from evidentia_api.routers import governance as governance_router

    app = FastAPI()
    app.include_router(governance_router.router, prefix="/api")
    with TestClient(app) as client:
        yield client


@pytest.fixture
def gov_readonly_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """A governance TestClient under a restrictive read-only RBAC policy.

    Identical store isolation to ``gov_client``, but installs a
    deny-by-default policy whose ``default_role`` is ``reader``. An
    anonymous request (identity None) resolves to that role, so reads
    pass while ``require_role("write")`` / ``require_role("admin")``
    gates deny — proving those gates actually bite (they are inert under
    the permissive DEFAULT_POLICY the other tests run with).
    """
    monkeypatch.setenv("EVIDENTIA_CHALLENGE_STORE_DIR", str(tmp_path / "challenge-store"))
    monkeypatch.setenv("EVIDENTIA_METRIC_STORE_DIR", str(tmp_path / "metric-store"))
    monkeypatch.setenv("EVIDENTIA_WORKFLOW_STORE_DIR", str(tmp_path / "workflow-store"))
    from evidentia_api.routers import governance as governance_router

    app = FastAPI()
    app.include_router(governance_router.router, prefix="/api")
    app.state.rbac_policy = RBACPolicy(identities={}, default_role=Role.READER)
    with TestClient(app) as client:
        yield client


# ── fixtures: model + payload builders ─────────────────────────────


def _challenge_payload(
    subject_model_id: str = "11111111-1111-1111-1111-111111111111",
    topic: str = "Methodology — feature selection",
    outcome: str = "pending",
) -> dict[str, object]:
    return {
        "subject_model_id": subject_model_id,
        "challenger_email": "mrm@example.com",
        "challenger_role": "MRM Director",
        "challenge_date": "2026-05-01",
        "challenge_topic": topic,
        "challenge_substance": "Feature X lacks a documented rationale.",
        "outcome": outcome,
    }


def _make_challenge(
    subject_model_id: str = "11111111-1111-1111-1111-111111111111",
    outcome: ChallengeOutcome = ChallengeOutcome.PENDING,
) -> EffectiveChallenge:
    return EffectiveChallenge(
        subject_model_id=subject_model_id,
        challenger_email="mrm@example.com",
        challenger_role="MRM Director",
        challenge_date=date(2026, 5, 1),
        challenge_topic="Methodology",
        challenge_substance="Substance text.",
        outcome=outcome,
    )


def _metric_payload(
    name: str = "Failed-login rate",
    kind: str = "kri",
) -> dict[str, object]:
    return {
        "name": name,
        "description": "Failed logins per 1,000 attempts.",
        "kind": kind,
        "direction": "higher_is_worse",
        "unit": "per 1,000 logins",
        "warning_threshold": 3.0,
        "critical_threshold": 5.0,
    }


def _make_metric(
    name: str = "Failed-login rate",
    kind: MetricKind = MetricKind.KRI,
    observations: list[MetricObservation] | None = None,
) -> Metric:
    return Metric(
        name=name,
        description="Failed logins per 1,000 attempts.",
        kind=kind,
        direction=MetricDirection.HIGHER_IS_WORSE,
        unit="per 1,000 logins",
        warning_threshold=3.0,
        critical_threshold=5.0,
        observations=observations or [],
    )


def _workflow_payload(
    name: str = "Credit-model quarterly review",
) -> dict[str, object]:
    return {
        "name": name,
        "description": "Quarterly review of the credit-scoring model.",
        "initiator": "owner@example.com",
        "subject": "Model 80e8b404",
        "steps": [
            {
                "name": "Model owner self-review",
                "required_role": "1LOD model owner",
                "sla_days": 7,
            },
            {
                "name": "MRM 2nd-line review",
                "required_role": "MRM Director (2LOD)",
                "sla_days": 14,
            },
        ],
    }


def _make_workflow(name: str = "WF") -> Workflow:
    return Workflow(
        name=name,
        description="desc",
        initiator="owner@example.com",
        steps=[
            WorkflowStep(
                name="step 0",
                required_role="1LOD",
                status=WorkflowStepStatus.IN_PROGRESS,
            ),
            WorkflowStep(name="step 1", required_role="2LOD"),
        ],
    )


# ════════════════════════════════════════════════════════════════════
# Challenges
# ════════════════════════════════════════════════════════════════════


class TestCreateChallenge:
    def test_create_returns_201(self, gov_client: TestClient) -> None:
        r = gov_client.post("/api/governance/challenges", json=_challenge_payload())
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["id"]
        assert body["challenge_topic"] == "Methodology — feature selection"
        assert body["outcome"] == "pending"

    def test_invalid_outcome_returns_422(self, gov_client: TestClient) -> None:
        r = gov_client.post(
            "/api/governance/challenges",
            json=_challenge_payload(outcome="not-real"),
        )
        assert r.status_code == 422


class TestListChallenges:
    def test_empty_store(self, gov_client: TestClient) -> None:
        r = gov_client.get("/api/governance/challenges")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 0
        assert body["items"] == []

    def test_lists_records(self, gov_client: TestClient) -> None:
        save_challenge(_make_challenge())
        save_challenge(_make_challenge())
        r = gov_client.get("/api/governance/challenges")
        assert r.json()["total"] == 2

    def test_subject_model_id_filter(self, gov_client: TestClient) -> None:
        save_challenge(_make_challenge(subject_model_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
        save_challenge(_make_challenge(subject_model_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"))
        r = gov_client.get("/api/governance/challenges?subject_model_id=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["subject_model_id"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

    def test_outcome_filter(self, gov_client: TestClient) -> None:
        save_challenge(_make_challenge(outcome=ChallengeOutcome.ACCEPTED))
        save_challenge(_make_challenge(outcome=ChallengeOutcome.PENDING))
        r = gov_client.get("/api/governance/challenges?outcome=accepted")
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["outcome"] == "accepted"

    def test_invalid_outcome_filter_returns_400(self, gov_client: TestClient) -> None:
        r = gov_client.get("/api/governance/challenges?outcome=bogus")
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "unknown_outcome"
        assert detail["outcome"] == "bogus"
        assert "message" in detail


class TestGetChallenge:
    def test_get_returns_record(self, gov_client: TestClient) -> None:
        c = _make_challenge()
        save_challenge(c)
        r = gov_client.get(f"/api/governance/challenges/{c.id}")
        assert r.status_code == 200
        assert r.json()["id"] == c.id

    def test_unknown_returns_404(self, gov_client: TestClient) -> None:
        r = gov_client.get("/api/governance/challenges/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404
        detail = r.json()["detail"]
        assert detail["error"] == "not_found"
        assert detail["resource"] == "challenge"

    def test_invalid_id_returns_404(self, gov_client: TestClient) -> None:
        r = gov_client.get("/api/governance/challenges/not-a-uuid")
        assert r.status_code == 404


# ════════════════════════════════════════════════════════════════════
# Metrics
# ════════════════════════════════════════════════════════════════════


class TestCreateMetric:
    def test_create_returns_201(self, gov_client: TestClient) -> None:
        r = gov_client.post("/api/governance/metrics", json=_metric_payload())
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["id"]
        assert body["name"] == "Failed-login rate"

    def test_create_response_includes_computed_status(self, gov_client: TestClient) -> None:
        # Create must splice the computed status alongside the persisted
        # fields, consistent with list / show / observe. A freshly
        # created metric has no observations → status == "no_data".
        r = gov_client.post("/api/governance/metrics", json=_metric_payload())
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["status"] == "no_data"

    def test_invalid_kind_returns_422(self, gov_client: TestClient) -> None:
        r = gov_client.post("/api/governance/metrics", json=_metric_payload(kind="not-real"))
        assert r.status_code == 422


class TestObserveMetric:
    def test_observe_appends_and_recomputes_status(self, gov_client: TestClient) -> None:
        m = _make_metric()
        save_metric(m)
        r = gov_client.post(
            f"/api/governance/metrics/{m.id}/observations",
            json={"value": 6.0, "observed_at": "2026-05-10"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["observations"]) == 1
        assert body["observations"][0]["value"] == 6.0
        # 6.0 >= critical 5.0 → BREACH
        assert body["status"] == "breach"

    def test_observe_watch_status(self, gov_client: TestClient) -> None:
        m = _make_metric()
        save_metric(m)
        r = gov_client.post(
            f"/api/governance/metrics/{m.id}/observations",
            json={"value": 4.0, "observed_at": "2026-05-10", "note": "spike"},
        )
        body = r.json()
        # warn 3.0 <= 4.0 < crit 5.0 → WATCH
        assert body["status"] == "watch"

    def test_observe_unknown_returns_404(self, gov_client: TestClient) -> None:
        r = gov_client.post(
            "/api/governance/metrics/00000000-0000-0000-0000-000000000000/observations",
            json={"value": 1.0, "observed_at": "2026-05-10"},
        )
        assert r.status_code == 404


class TestListMetrics:
    def test_empty(self, gov_client: TestClient) -> None:
        r = gov_client.get("/api/governance/metrics")
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_lists_with_status(self, gov_client: TestClient) -> None:
        save_metric(_make_metric(observations=[MetricObservation(observed_at=date(2026, 5, 1), value=6.0)]))
        r = gov_client.get("/api/governance/metrics")
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["status"] == "breach"

    def test_no_data_status(self, gov_client: TestClient) -> None:
        save_metric(_make_metric())
        r = gov_client.get("/api/governance/metrics")
        assert r.json()["items"][0]["status"] == "no_data"

    def test_kind_filter(self, gov_client: TestClient) -> None:
        save_metric(_make_metric(name="a", kind=MetricKind.KRI))
        save_metric(_make_metric(name="b", kind=MetricKind.KPI))
        r = gov_client.get("/api/governance/metrics?kind=kpi")
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["kind"] == "kpi"

    def test_invalid_kind_returns_400(self, gov_client: TestClient) -> None:
        r = gov_client.get("/api/governance/metrics?kind=bogus")
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "unknown_kind"
        assert detail["kind"] == "bogus"
        assert "message" in detail


class TestMetricReportOrdering:
    """The static /report path MUST resolve before /{metric_id}."""

    def test_report_returns_markdown(self, gov_client: TestClient) -> None:
        save_metric(_make_metric(observations=[MetricObservation(observed_at=date(2026, 5, 1), value=6.0)]))
        r = gov_client.get("/api/governance/metrics/report")
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("text/plain")
        assert "# Governance Metrics Dashboard" in r.text

    def test_report_not_shadowed_by_id(self, gov_client: TestClient) -> None:
        # If /{metric_id} shadowed /report, "report" would be parsed as an
        # ID → InvalidMetricIdError → 404. A 200 proves correct ordering.
        r = gov_client.get("/api/governance/metrics/report")
        assert r.status_code == 200


class TestGetMetric:
    def test_get_returns_with_status(self, gov_client: TestClient) -> None:
        m = _make_metric(observations=[MetricObservation(observed_at=date(2026, 5, 1), value=1.0)])
        save_metric(m)
        r = gov_client.get(f"/api/governance/metrics/{m.id}")
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == m.id
        # 1.0 < warn 3.0 → COMFORTABLE
        assert body["status"] == "comfortable"

    def test_unknown_returns_404(self, gov_client: TestClient) -> None:
        r = gov_client.get("/api/governance/metrics/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404

    def test_invalid_id_returns_404(self, gov_client: TestClient) -> None:
        r = gov_client.get("/api/governance/metrics/not-a-uuid")
        assert r.status_code == 404


class TestDeleteMetric:
    def test_delete_returns_204(self, gov_client: TestClient) -> None:
        m = _make_metric()
        save_metric(m)
        r = gov_client.delete(f"/api/governance/metrics/{m.id}")
        assert r.status_code == 204
        r2 = gov_client.get(f"/api/governance/metrics/{m.id}")
        assert r2.status_code == 404

    def test_delete_unknown_returns_404(self, gov_client: TestClient) -> None:
        r = gov_client.delete("/api/governance/metrics/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404


# ════════════════════════════════════════════════════════════════════
# Workflows
# ════════════════════════════════════════════════════════════════════


class TestRunWorkflow:
    def test_run_auto_promotes_and_sets_status(self, gov_client: TestClient) -> None:
        r = gov_client.post("/api/governance/workflows", json=_workflow_payload())
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["id"]
        # Step 0 auto-promoted PENDING → IN_PROGRESS
        assert body["steps"][0]["status"] == "in_progress"
        # evaluate_workflow → IN_PROGRESS once step 0 is active
        assert body["status"] == "in_progress"

    def test_run_invalid_body_returns_422(self, gov_client: TestClient) -> None:
        # missing required 'initiator'
        r = gov_client.post(
            "/api/governance/workflows",
            json={"name": "x", "description": "d", "steps": []},
        )
        assert r.status_code == 422


class TestAdvanceWorkflow:
    def test_advance_happy_path(self, gov_client: TestClient) -> None:
        wf = _make_workflow()
        save_workflow(wf)
        r = gov_client.post(
            f"/api/governance/workflows/{wf.id}/advance",
            json={
                "step_index": 0,
                "new_status": "approved",
                "actor": "owner@example.com",
                "note": "looks good",
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["steps"][0]["status"] == "approved"
        # Next step auto-promoted
        assert body["steps"][1]["status"] == "in_progress"

    def test_advance_out_of_order_returns_400(self, gov_client: TestClient) -> None:
        wf = _make_workflow()
        save_workflow(wf)
        # Step 1 is not the active step (step 0 is) → WorkflowAdvanceError
        r = gov_client.post(
            f"/api/governance/workflows/{wf.id}/advance",
            json={
                "step_index": 1,
                "new_status": "approved",
                "actor": "x@example.com",
            },
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "active step" in detail["message"]

    def test_advance_unknown_workflow_returns_404(self, gov_client: TestClient) -> None:
        r = gov_client.post(
            "/api/governance/workflows/00000000-0000-0000-0000-000000000000/advance",
            json={
                "step_index": 0,
                "new_status": "approved",
                "actor": "x@example.com",
            },
        )
        assert r.status_code == 404


class TestGetWorkflow:
    def test_get_returns_record(self, gov_client: TestClient) -> None:
        wf = _make_workflow()
        save_workflow(wf)
        r = gov_client.get(f"/api/governance/workflows/{wf.id}")
        assert r.status_code == 200
        assert r.json()["id"] == wf.id

    def test_unknown_returns_404(self, gov_client: TestClient) -> None:
        r = gov_client.get("/api/governance/workflows/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404

    def test_invalid_id_returns_404(self, gov_client: TestClient) -> None:
        r = gov_client.get("/api/governance/workflows/not-a-uuid")
        assert r.status_code == 404


class TestListWorkflows:
    def test_empty(self, gov_client: TestClient) -> None:
        r = gov_client.get("/api/governance/workflows")
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_lists_records(self, gov_client: TestClient) -> None:
        save_workflow(_make_workflow("a"))
        save_workflow(_make_workflow("b"))
        r = gov_client.get("/api/governance/workflows")
        assert r.json()["total"] == 2


class TestWorkflowLog:
    def test_log_returns_markdown(self, gov_client: TestClient) -> None:
        wf = _make_workflow()
        save_workflow(wf)
        r = gov_client.get(f"/api/governance/workflows/{wf.id}/log")
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("text/plain")
        assert "# Workflow Audit Log" in r.text

    def test_log_unknown_returns_404(self, gov_client: TestClient) -> None:
        r = gov_client.get("/api/governance/workflows/00000000-0000-0000-0000-000000000000/log")
        assert r.status_code == 404


class TestDeleteWorkflow:
    def test_delete_returns_204(self, gov_client: TestClient) -> None:
        wf = _make_workflow()
        save_workflow(wf)
        r = gov_client.delete(f"/api/governance/workflows/{wf.id}")
        assert r.status_code == 204
        r2 = gov_client.get(f"/api/governance/workflows/{wf.id}")
        assert r2.status_code == 404

    def test_delete_unknown_returns_404(self, gov_client: TestClient) -> None:
        r = gov_client.delete("/api/governance/workflows/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404


# ════════════════════════════════════════════════════════════════════
# Lines report
# ════════════════════════════════════════════════════════════════════


class TestLinesReport:
    def test_returns_markdown_from_posted_owners(self, gov_client: TestClient) -> None:
        owners = [
            {
                "email": "alice@example.com",
                "line_of_defense": "first",
                "team": "Loan Origination",
            },
            {
                "email": "bob@example.com",
                "line_of_defense": "second",
                "team": "MRM",
            },
        ]
        r = gov_client.post("/api/governance/lines-report", json=owners)
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("text/plain")
        assert "# Three Lines of Defense Distribution" in r.text
        assert "alice@example.com" in r.text

    def test_empty_owner_list_returns_markdown(self, gov_client: TestClient) -> None:
        r = gov_client.post("/api/governance/lines-report", json=[])
        assert r.status_code == 200
        assert "# Three Lines of Defense Distribution" in r.text

    def test_invalid_owner_returns_422(self, gov_client: TestClient) -> None:
        r = gov_client.post(
            "/api/governance/lines-report",
            json=[{"email": "x@example.com", "line_of_defense": "bogus"}],
        )
        assert r.status_code == 422


# ════════════════════════════════════════════════════════════════════
# RBAC enforcement (proves the require_role gates bite)
# ════════════════════════════════════════════════════════════════════


class TestGovernanceRBAC:
    """Under a read-only policy the write + admin gates must deny.

    The other tests run under the permissive DEFAULT_POLICY, where the
    ``require_role`` gates are inert. These install a deny-by-default
    (read-only) policy and prove a write (create) → 403, an admin
    DELETE → 403, while a read (list) still returns 200.
    """

    def test_anonymous_create_metric_denied_403(self, gov_readonly_client: TestClient) -> None:
        # POST /governance/metrics is gated on require_role("write").
        r = gov_readonly_client.post("/api/governance/metrics", json=_metric_payload())
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "rbac_denied"

    def test_anonymous_delete_metric_denied_403(self, gov_readonly_client: TestClient) -> None:
        # Seed directly (store env vars are isolated by the fixture) so a
        # real record exists; the admin DELETE gate must still deny.
        m = _make_metric()
        save_metric(m)
        r = gov_readonly_client.delete(f"/api/governance/metrics/{m.id}")
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "rbac_denied"

    def test_anonymous_list_metrics_allowed_200(self, gov_readonly_client: TestClient) -> None:
        # The read endpoint carries no require_role gate (reads are open),
        # so it returns 200 even under the read-only policy — proving the
        # policy is read-allowed, not blanket-deny.
        save_metric(_make_metric())
        r = gov_readonly_client.get("/api/governance/metrics")
        assert r.status_code == 200, r.text
        assert r.json()["total"] == 1


class TestCreateEmptyIdReturns422:
    """F-V1012-S4-1: a client-supplied empty ``id`` on the create endpoints
    must return 422, not an unhandled 500. Pydantic accepts ``""`` as a valid
    str (the UUID default_factory only fires on an OMITTED id), and the store's
    id-shape validation then rejects it — the handler normalizes that to 422.
    The same guard lands on the poam / tprm / model-risk create endpoints."""

    def test_create_challenge_empty_id(self, gov_client: TestClient) -> None:
        r = gov_client.post(
            "/api/governance/challenges",
            json={**_challenge_payload(), "id": ""},
        )
        assert r.status_code == 422, r.text

    def test_create_metric_empty_id(self, gov_client: TestClient) -> None:
        r = gov_client.post(
            "/api/governance/metrics",
            json={**_metric_payload(), "id": ""},
        )
        assert r.status_code == 422, r.text

    def test_run_workflow_empty_id(self, gov_client: TestClient) -> None:
        r = gov_client.post(
            "/api/governance/workflows",
            json={**_workflow_payload(), "id": ""},
        )
        assert r.status_code == 422, r.text


# ════════════════════════════════════════════════════════════════════
# OpenAPI error documentation (2026-07-06 error-shape convergence)
# ════════════════════════════════════════════════════════════════════


class TestGovernanceOpenApiErrorDocs:
    """Every deliberate 4xx the governance router raises is documented
    on its OpenAPI operation (schemathesis undocumented-status noise →
    contract). Uses the project-wide app so the schema reflects the
    registered router."""

    def test_governance_error_statuses_documented_in_openapi(self, api_client: TestClient) -> None:
        schema = api_client.get("/api/openapi.json").json()
        expected: list[tuple[str, str, list[str]]] = [
            ("/api/governance/challenges", "post", ["403", "422"]),
            ("/api/governance/challenges", "get", ["400"]),
            ("/api/governance/challenges/{challenge_id}", "get", ["404"]),
            ("/api/governance/metrics", "post", ["403", "422"]),
            (
                "/api/governance/metrics/{metric_id}/observations",
                "post",
                ["403", "404"],
            ),
            ("/api/governance/metrics", "get", ["400"]),
            ("/api/governance/metrics/{metric_id}", "get", ["404"]),
            (
                "/api/governance/metrics/{metric_id}",
                "delete",
                ["403", "404"],
            ),
            ("/api/governance/workflows", "post", ["403", "422"]),
            (
                "/api/governance/workflows/{workflow_id}/advance",
                "post",
                ["400", "403", "404"],
            ),
            ("/api/governance/workflows/{workflow_id}", "get", ["404"]),
            (
                "/api/governance/workflows/{workflow_id}/log",
                "get",
                ["404"],
            ),
            (
                "/api/governance/workflows/{workflow_id}",
                "delete",
                ["403", "404"],
            ),
        ]
        for path, method, statuses in expected:
            responses = schema["paths"][path][method]["responses"]
            for status in statuses:
                assert status in responses, f"{method.upper()} {path} missing {status}"
