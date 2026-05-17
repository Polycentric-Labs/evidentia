"""TestClient coverage for /api/integrations/jira/* endpoints."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient


def _set_jira_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JIRA_BASE_URL", "https://acme.atlassian.net")
    monkeypatch.setenv("JIRA_EMAIL", "user@example.com")
    monkeypatch.setenv("JIRA_API_TOKEN", "secret-never-in-response")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")


def _unset_jira_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for v in ("JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"):
        monkeypatch.delenv(v, raising=False)


def _patch_client_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler: httpx.MockTransport,
) -> None:
    """Patch JiraClient.__init__ to inject a MockTransport-backed http client.

    Simpler than overriding the dep-injection surface in the API; we
    swap out the client's httpx.Client during construction.
    """
    from evidentia_integrations.jira import client as client_mod

    orig_init = client_mod.JiraClient.__init__

    def patched_init(self: Any, config: Any, *, http: Any = None) -> None:
        if http is None:
            http = httpx.Client(
                base_url=config.base_url,
                transport=handler,
                headers={"Authorization": "Basic x", "Accept": "application/json"},
            )
        orig_init(self, config, http=http)

    monkeypatch.setattr(client_mod.JiraClient, "__init__", patched_init)


# ── status ────────────────────────────────────────────────────────────────


class TestJiraStatus:
    def test_returns_unconfigured_when_env_missing(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _unset_jira_env(monkeypatch)
        r = api_client.get("/api/integrations/jira/status")
        assert r.status_code == 200
        payload = r.json()
        assert payload["configured"] is False
        # Error message is sanitized + correlated by request_id; the
        # specifics (which env var, exception class, etc.) live in the
        # server log only.
        assert payload["error"] == (
            "Jira configuration is incomplete or invalid."
        )
        assert len(payload["request_id"]) == 12
        # Critical: env-var name + secret-store hints must not leak.
        assert "JIRA_BASE_URL" not in r.text
        assert "JIRA_API_TOKEN" not in r.text

    def test_returns_configured_on_success(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_jira_env(monkeypatch)

        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("/myself"):
                return httpx.Response(
                    200,
                    json={"displayName": "Allen", "emailAddress": "a@example.com"},
                )
            if "/project/SEC" in req.url.path:
                return httpx.Response(200, json={"key": "SEC", "name": "Security"})
            return httpx.Response(404)

        _patch_client_transport(monkeypatch, httpx.MockTransport(handler))

        r = api_client.get("/api/integrations/jira/status")
        assert r.status_code == 200, r.text
        payload = r.json()
        assert payload["configured"] is True
        assert payload["project_key"] == "SEC"
        assert payload["project_name"] == "Security"
        assert payload["user"] == "Allen"
        # Critical: token value must never leak.
        assert "secret-never-in-response" not in r.text

    def test_returns_auth_error_when_credentials_reject(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_jira_env(monkeypatch)

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401, json={"errorMessages": ["Bad credentials"]}
            )

        _patch_client_transport(monkeypatch, httpx.MockTransport(handler))

        r = api_client.get("/api/integrations/jira/status")
        assert r.status_code == 200
        payload = r.json()
        assert payload["configured"] is False
        # Sanitized message + request-id correlation; upstream Jira
        # response codes + error text live in the server log only.
        assert payload["error"] == (
            "Jira API call failed; check server logs with the request_id."
        )
        assert len(payload["request_id"]) == 12
        # v0.9.4 P4.4: previously these asserted against r.text which
        # also covered the random 12-char request_id field; ~0.7% of
        # runs had the literal "401" as a substring of the random
        # request_id (root cause of the ubuntu-only flake seen on
        # v0.9.3 merge commit a5a6c02). Scope the substring check
        # to the user-visible error field — that's the actual
        # info-disclosure surface the test is guarding.
        assert "401" not in payload["error"]
        assert "Bad credentials" not in payload["error"]
        assert "secret-never-in-response" not in r.text


# ── status-map ────────────────────────────────────────────────────────────


class TestJiraStatusMap:
    def test_returns_both_directions(self, api_client: TestClient) -> None:
        r = api_client.get("/api/integrations/jira/status-map")
        assert r.status_code == 200
        payload = r.json()
        # Sanity check a few known entries.
        assert payload["gap_status_to_jira"]["open"] == "To Do"
        assert payload["gap_status_to_jira"]["remediated"] == "Done"
        assert payload["jira_status_to_gap"]["in progress"] == "in_progress"
        assert payload["jira_status_to_gap"]["won't do"] == "accepted"


# ── push / sync validation ────────────────────────────────────────────────


class TestJiraPushSyncValidation:
    def test_push_invalid_key_returns_400(self, api_client: TestClient) -> None:
        r = api_client.post("/api/integrations/jira/push/not-a-hex-key")
        assert r.status_code == 400

    def test_push_missing_report_returns_404(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_jira_env(monkeypatch)
        r = api_client.post("/api/integrations/jira/push/0123456789abcdef")
        assert r.status_code == 404

    def test_sync_invalid_key_returns_400(self, api_client: TestClient) -> None:
        r = api_client.post("/api/integrations/jira/sync/xxxxxxxxxxxxxxxx")
        assert r.status_code == 400

    def test_push_returns_503_when_jira_unconfigured_but_report_exists(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Create a report by running gap analyze first.
        from pathlib import Path

        fixture_root = Path(__file__).resolve().parents[3] / "examples" / "meridian-fintech-v2"
        inventory = (fixture_root / "my-controls.yaml").read_text(encoding="utf-8")
        r = api_client.post(
            "/api/gap/analyze",
            json={
                "frameworks": ["soc2-tsc"],
                "inventory_content": inventory,
                "inventory_format": "yaml",
            },
        )
        assert r.status_code == 200, r.text
        reports = api_client.get("/api/gap/reports").json()["reports"]
        key = reports[0]["key"]

        # Now unset Jira env vars — push should 503 with a clear error.
        _unset_jira_env(monkeypatch)
        r = api_client.post(f"/api/integrations/jira/push/{key}")
        assert r.status_code == 503
        assert "JIRA_BASE_URL" in r.json()["detail"]


# ── Tableau publish endpoint (v0.7.8 P1.1) ────────────────────────


class TestTableauPublishEndpoint:
    def test_invalid_key_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/integrations/tableau/publish/not-a-hex-key",
            json={"server_url": "https://example.tableau"},
        )
        assert r.status_code == 400

    def test_missing_server_url_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/integrations/tableau/publish/0123456789abcdef",
            json={},
        )
        assert r.status_code == 400
        assert "server_url" in r.json()["detail"]

    def test_invalid_risks_array_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/integrations/tableau/publish/0123456789abcdef",
            json={
                "server_url": "https://example.tableau.com",
                "risks": "not-a-list",
            },
        )
        assert r.status_code == 400


# ── Power BI publish endpoint (v0.7.8 P1.2) ───────────────────────


class TestPowerBIPublishEndpoint:
    def test_invalid_key_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/integrations/powerbi/publish/not-a-hex-key",
            json={
                "workspace_id": "ws-1",
                "tenant_id": "t-1",
                "client_id": "c-1",
            },
        )
        assert r.status_code == 400

    def test_missing_workspace_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/integrations/powerbi/publish/0123456789abcdef",
            json={"tenant_id": "t-1", "client_id": "c-1"},
        )
        assert r.status_code == 400
        assert "workspace_id" in r.json()["detail"]

    def test_missing_tenant_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/integrations/powerbi/publish/0123456789abcdef",
            json={"workspace_id": "ws-1", "client_id": "c-1"},
        )
        assert r.status_code == 400
        assert "tenant_id" in r.json()["detail"]

    def test_missing_client_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/integrations/powerbi/publish/0123456789abcdef",
            json={"workspace_id": "ws-1", "tenant_id": "t-1"},
        )
        assert r.status_code == 400
        assert "client_id" in r.json()["detail"]
