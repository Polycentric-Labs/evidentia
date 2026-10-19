"""Every mutating REST operation carries a role gate (v0.13.0 review H4, decision D8).

The default policy maps every identity to admin, so the gates are inert
for existing deployments. Under an operator policy the gates follow the
reader / writer / admin model the governance, retention and catalog
routers already use: ``admin`` for hard deletes and the project
configuration, ``write`` for creates, updates, outbound pushes, store
writes and paid LLM paths, ``read`` for compute-only operations.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

# Authorization for these two is enforced inside the handler by the
# release-cadence authority binding (``capture_authority(request).require``),
# which also records the policy provenance; they carry no route dependency.
HANDLER_ENFORCED = {
    ("POST", "/api/collect/release-cadence"),
    ("POST", "/api/conmon/release-series"),
}

EXPECTED_ROLES = {
    ("PUT", "/api/config"): "admin",
    ("DELETE", "/api/ai-gov/systems/{system_id}"): "admin",
    ("DELETE", "/api/model-risk/models/{model_id}"): "admin",
    ("DELETE", "/api/poam/items/{poam_id}"): "admin",
    ("DELETE", "/api/tprm/vendors/{vendor_id}"): "admin",
    ("POST", "/api/collectors/nessus/collect"): "write",
    ("POST", "/api/collectors/greenbone/collect"): "write",
    ("POST", "/api/integrations/tableau/publish/{report_key}"): "write",
    ("POST", "/api/integrations/powerbi/publish/{report_key}"): "write",
    ("POST", "/api/integrations/servicenow/push/{report_key}"): "write",
    ("POST", "/api/integrations/jira/push/{report_key}"): "write",
    ("POST", "/api/integrations/jira/sync/{report_key}"): "write",
    ("POST", "/api/gap/analyze"): "write",
    ("POST", "/api/risk/generate"): "write",
    ("POST", "/api/explain/{framework}/{control_id:path}"): "write",
    ("POST", "/api/conmon/series"): "read",
    ("POST", "/api/conmon/check"): "read",
    ("POST", "/api/conmon/health"): "read",
    ("POST", "/api/collectors/vanta/collect"): "read",
}


def _role_actions(route: APIRoute, inherited: list[Any]) -> set[str]:
    actions: set[str] = set()
    for dep in [*route.dependant.dependencies, *inherited]:
        call = getattr(dep, "call", None) or getattr(dep, "dependency", None)
        if call is None or "require_role" not in getattr(call, "__qualname__", ""):
            continue
        cells = dict(zip(call.__code__.co_freevars, call.__closure__ or (), strict=False))
        actions.add(cells["action"].cell_contents)
    return actions


def _operations(app: Any) -> Iterator[tuple[str, str, set[str]]]:
    """Yield ``(method, path, role_actions)`` for every API operation."""
    for route in app.routes:
        if isinstance(route, APIRoute):
            for method in route.methods - {"HEAD", "OPTIONS"}:
                yield method, route.path, _role_actions(route, [])
            continue
        # FastAPI includes routers lazily; unwrap the include record.
        inner = getattr(route, "original_router", None)
        context = getattr(route, "include_context", None)
        if inner is None or context is None:
            continue
        prefix = getattr(context, "prefix", "") or ""
        inherited = list(getattr(context, "dependencies", None) or [])
        for sub in inner.routes:
            if isinstance(sub, APIRoute):
                for method in sub.methods - {"HEAD", "OPTIONS"}:
                    yield method, prefix + sub.path, _role_actions(sub, inherited)


def test_every_mutating_operation_is_gated(api_client: TestClient) -> None:
    ops = {(m, p): roles for m, p, roles in _operations(api_client.app) if p.startswith("/api/")}
    assert len(ops) > 100, "route walk found too few operations; the include shape changed"
    ungated = sorted(
        f"{m} {p}" for (m, p), roles in ops.items() if m in MUTATING and not roles and (m, p) not in HANDLER_ENFORCED
    )
    assert ungated == [], f"mutating operations without a require_role gate: {ungated}"
    for key, role in EXPECTED_ROLES.items():
        assert key in ops, key
        assert ops[key] == {role}, (key, ops[key])


@pytest.fixture
def reader_client(api_client: TestClient) -> TestClient:
    from evidentia_core.rbac import RBACPolicy, Role

    api_client.app.state.rbac_policy = RBACPolicy(identities={}, default_role=Role.READER)  # type: ignore[attr-defined]
    return api_client


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "/api/integrations/tableau/publish/0123456789abcdef", {}),
        ("POST", "/api/integrations/powerbi/publish/0123456789abcdef", {}),
        ("POST", "/api/integrations/servicenow/push/0123456789abcdef", {}),
        ("POST", "/api/collectors/nessus/collect", {}),
        ("POST", "/api/collectors/greenbone/collect", {}),
        ("POST", "/api/poam/items", {}),
        ("POST", "/api/tprm/vendors", {}),
        ("POST", "/api/model-risk/models", {}),
        ("POST", "/api/ai-gov/register", {}),
        ("DELETE", "/api/ai-gov/systems/00000000-0000-4000-8000-000000000000", None),
        ("POST", "/api/gap/analyze", {}),
        ("POST", "/api/risk/generate", {}),
        ("POST", "/api/init/commit", {}),
        ("PUT", "/api/config", {}),
    ],
)
def test_reader_is_denied_before_validation(reader_client: TestClient, method: str, path: str, body: Any) -> None:
    """The gate runs before body validation, so even an empty body is a 403."""
    response = reader_client.request(method, path, json=body)
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["error"] == "rbac_denied"


@pytest.fixture
def denied_client(api_client: TestClient) -> TestClient:
    from evidentia_core.rbac import RBACPolicy, Role

    api_client.app.state.rbac_policy = RBACPolicy(identities={}, default_role=Role.DENY)  # type: ignore[attr-defined]
    return api_client


def test_denied_identity_never_reaches_a_credentialed_collector(
    denied_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The read gate on a credentialed collect route runs before the env read and before any egress."""
    monkeypatch.setenv("GOOGLE_WORKSPACE_ACCESS_TOKEN", "denied-must-not-trigger-this")
    response = denied_client.post("/api/collectors/google-workspace/collect", json={})
    assert response.status_code == 403, response.text
    assert "denied-must-not-trigger-this" not in response.text


def test_reader_keeps_compute_only_operations(reader_client: TestClient) -> None:
    response = reader_client.post(
        "/api/conmon/check",
        json={"entries": [{"slug": "pci-dss-11-6-1-weekly", "last_completed": "2026-10-01"}], "today": "2026-10-02"},
    )
    assert response.status_code == 200, response.text
    response = reader_client.post("/api/risk/quantify", json={})
    assert response.status_code != 403, response.text
