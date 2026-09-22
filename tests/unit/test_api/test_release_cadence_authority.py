"""Actual application policy provenance and pre-I/O release authority."""

from __future__ import annotations

import json

import pytest
from evidentia_api.app import create_app
from evidentia_core.plugins.auth import AuthProvider, AuthResult
from evidentia_core.rbac import RBACPolicy, TenantRBACPolicy
from fastapi.testclient import TestClient

POLL = "/api/collect/release-cadence"
SERIES = "/api/conmon/release-series"


class Provider(AuthProvider):
    def __init__(self, principal="alice", authenticated=True):
        self.principal = principal
        self.authenticated = authenticated

    def authenticate(self, *, authorization_header):
        return AuthResult(self.authenticated, self.principal, "synthetic authentication")

    def name(self):
        return "synthetic-release-test"


def request_value(*, persist=False, series=False):
    value = {
        "schema_version": "release-series-request-v1" if series else "release-poll-request-v1",
        "source_profile": "github-public-releases-2026-03-10",
        "owner": "Allen",
        "repository": "Example",
        "channel": "full_releases",
    }
    if series:
        value.update(
            window_start="2000-01-01T00:00:00.000000Z",
            window_end="2000-01-03T00:00:00.000000Z",
            interval_days=1,
            tolerance_days=0,
        )
    else:
        value["persist"] = persist
    return value


def make_app(monkeypatch, *, policy=None, provider=True, load_fail=False):
    import evidentia_core.rbac as rbac

    monkeypatch.delenv("EVIDENTIA_RBAC_POLICY_FILE", raising=False)
    if policy is not None or load_fail:
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", "synthetic-never-opened.yaml")

        def load(path):
            if load_fail:
                raise ValueError("synthetic invalid policy")
            return policy

        monkeypatch.setattr(rbac, "load_rbac_policy_auto", load)
    return create_app(auth_provider=Provider() if provider is True else None if provider is False else provider)


def forbid_io(monkeypatch):
    from evidentia_collectors.release_cadence import _http, _traversal
    from evidentia_core import evidence_store
    from evidentia_core.release_cadence import _store

    calls = []

    def forbidden(*args, **kwargs):
        calls.append("I/O")
        raise AssertionError("No provider or store operation is admitted.")

    monkeypatch.setattr(_http.HttpAttempt, "fetch", forbidden)
    monkeypatch.setattr(_traversal, "traverse", forbidden)
    monkeypatch.setattr(_store, "discover", forbidden)
    monkeypatch.setattr(evidence_store, "save_evidence_version_one", forbidden)
    return calls


@pytest.mark.parametrize("endpoint", [POLL, SERIES])
@pytest.mark.parametrize("provider", [False, Provider(""), Provider(" "), Provider(None)])
def test_authentication_required_before_body(monkeypatch, endpoint, provider):
    app = make_app(monkeypatch, provider=provider)
    calls = forbid_io(monkeypatch)
    read = []

    def body():
        read.append("body")
        yield b"not-json"

    result = TestClient(app).post(endpoint, content=body(), headers={"content-type": "application/json"})
    assert result.status_code == 403 and read == [] and calls == []


def test_existing_middleware_401_is_unchanged(monkeypatch):
    result = TestClient(make_app(monkeypatch, provider=Provider(authenticated=False))).post(POLL, content=b"bad")
    assert result.status_code == 401
    assert set(result.json()) == {"detail", "reason", "provider"}


@pytest.mark.parametrize("endpoint", [POLL, SERIES])
@pytest.mark.parametrize("mode", ["failed", "missing", "status", "substituted", "mutated", "unsupported"])
def test_policy_provenance_refuses_before_body(monkeypatch, endpoint, mode):
    policy = RBACPolicy(identities={"alice": "reader"}, default_role="deny")
    app = make_app(monkeypatch, policy=policy if mode != "unsupported" else object(), load_fail=mode == "failed")
    if mode == "missing":
        del app.state.release_cadence_policy_provenance
    elif mode == "status":
        app.state.release_cadence_policy_provenance = "loaded-again"
    elif mode == "substituted":
        app.state.rbac_policy = RBACPolicy(default_role="admin")
    elif mode == "mutated":
        app.state.rbac_policy.identities["alice"] = "admin"
    calls = forbid_io(monkeypatch)
    read = []

    def body():
        read.append("body")
        yield b"{}"

    result = TestClient(app).post(endpoint, content=body(), headers={"content-type": "application/json"})
    assert result.status_code == 503 and result.json()["code"] == "authority_unavailable"
    assert read == [] and calls == []


@pytest.mark.parametrize("endpoint", [POLL, SERIES])
def test_valid_read_deny_preserves_existing_shape(monkeypatch, endpoint):
    app = make_app(monkeypatch, policy=RBACPolicy(default_role="deny"))
    calls = forbid_io(monkeypatch)
    result = TestClient(app).post(endpoint, content=b"malformed")
    assert result.status_code == 403
    assert result.json()["detail"] == {
        "error": "rbac_denied",
        "action": "read",
        "identity": "alice",
        "message": "Identity does not have permission for this action. Operators configure RBAC via EVIDENTIA_RBAC_POLICY_FILE.",
    }
    assert calls == []


def test_write_denial_occurs_after_validation_before_provider_or_store(monkeypatch):
    app = make_app(monkeypatch, policy=RBACPolicy(default_role="reader"))
    calls = forbid_io(monkeypatch)
    client = TestClient(app)
    invalid = client.post(POLL, json={**request_value(persist=True), "unknown": 1})
    assert invalid.status_code == 422
    denied = client.post(POLL, json=request_value(persist=True))
    assert denied.status_code == 403 and denied.json()["detail"]["action"] == "write"
    assert calls == []


@pytest.mark.parametrize(
    "keys,default,principal",
    [
        (["Acme", "acme"], "Acme", "alice@@Acme"),
        (["Acme"], "acme", "alice"),
        (["Acme"], None, "alice"),
        (["Acme"], "Acme", "alice@@acme"),
        (["Acme\n"], "Acme\n", "alice"),
        (["Acme"], "Acme", "alice@@"),
        (["Acme"], "Acme", "@@Acme"),
    ],
)
def test_tenant_names_and_claims_are_exact(monkeypatch, keys, default, principal):
    policy = TenantRBACPolicy(tenants={key: RBACPolicy(default_role="admin") for key in keys}, default_tenant=default)
    object.__setattr__(policy, "tenants", {key: RBACPolicy(default_role="admin") for key in keys})
    object.__setattr__(policy, "default_tenant", default)
    app = make_app(monkeypatch, policy=policy, provider=Provider(principal))
    calls = forbid_io(monkeypatch)
    result = TestClient(app).post(POLL, json=request_value(persist=True))
    assert result.status_code == 503 and result.json()["code"] == "authority_unavailable"
    assert calls == []


@pytest.mark.parametrize("principal", ["alice@@Acme", "alice"])
def test_tenant_store_selection_uses_exact_authenticated_binding(monkeypatch, tmp_path, principal):
    from evidentia_collectors.release_cadence import _traversal
    from evidentia_core import evidence_store

    from tests.unit.test_collectors.release_cadence._helpers import encoded, pages, row

    monkeypatch.setattr(evidence_store, "_resolve_auto_mirror_backend", lambda: None)
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path))
    policy = TenantRBACPolicy(
        tenants={"Acme": RBACPolicy(default_role="admin"), "Other": RBACPolicy(default_role="admin")},
        default_tenant="Acme",
    )
    app = make_app(monkeypatch, policy=policy, provider=Provider(principal))
    pages(monkeypatch, _traversal, [(encoded([row()]), ())])
    result = TestClient(app).post(POLL, json=request_value(persist=True))
    assert result.status_code == 200 and result.json()["persistence"]["state"] == "complete"
    event = result.json()["events"][0]["event_id"]
    assert (tmp_path / "tenants" / "Acme" / event / "v1.json").is_file()
    assert not (tmp_path / "tenants" / "Other").exists()
    assert not (tmp_path / event).exists()


def test_differently_cased_existing_tenant_is_not_adopted(monkeypatch, tmp_path):
    from evidentia_collectors.release_cadence import _traversal

    from tests.unit.test_collectors.release_cadence._helpers import encoded, pages, row

    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path))
    (tmp_path / "tenants" / "acme").mkdir(parents=True)
    policy = TenantRBACPolicy(tenants={"Acme": RBACPolicy(default_role="admin")}, default_tenant="Acme")
    app = make_app(monkeypatch, policy=policy)
    pages(monkeypatch, _traversal, [(encoded([row()]), ())])
    result = TestClient(app).post(POLL, json=request_value(persist=True))
    assert result.status_code == 200
    assert result.json()["persistence"]["state"] == "not_started"
    assert result.json()["persistence"]["attempted_calls"] == 0
    assert list((tmp_path / "tenants" / "acme").iterdir()) == []
    assert [entry.name for entry in (tmp_path / "tenants").iterdir()] == ["acme"]


def test_tenant_observation_still_performs_no_store_operation(monkeypatch):
    from evidentia_collectors.release_cadence import _traversal
    from evidentia_core.release_cadence import _store

    from tests.unit.test_collectors.release_cadence._helpers import pages

    policy = TenantRBACPolicy(tenants={"Acme": RBACPolicy(default_role="reader")}, default_tenant="Acme")
    app = make_app(monkeypatch, policy=policy)
    pages(monkeypatch, _traversal, [(b"[]", ())])

    def forbidden(*args, **kwargs):
        raise AssertionError("Observation must not select, enumerate or open a store.")

    monkeypatch.setattr(_store, "lexical_store_root", forbidden)
    monkeypatch.setattr(_store, "discover", forbidden)
    result = TestClient(app).post(POLL, json=request_value())
    assert result.status_code == 200 and result.json()["discovery"]["status"] == "not_requested"


def test_policy_drift_while_body_is_read_refuses_before_provider(monkeypatch):
    app = make_app(monkeypatch, policy=RBACPolicy(default_role="admin"))
    calls = forbid_io(monkeypatch)

    def body():
        yield b" "
        app.state.rbac_policy.default_role = "reader"
        yield json.dumps(request_value(persist=True)).encode()

    result = TestClient(app).post(POLL, content=body(), headers={"content-type": "application/json"})
    assert result.status_code == 503 and result.json()["code"] == "authority_unavailable" and calls == []
