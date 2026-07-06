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
        assert r.json()["detail"]["error"] == "invalid_id"

    def test_push_missing_report_returns_404(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_jira_env(monkeypatch)
        r = api_client.post("/api/integrations/jira/push/0123456789abcdef")
        assert r.status_code == 404
        detail = r.json()["detail"]
        assert detail["error"] == "not_found"
        assert detail["resource"] == "gap_report"

    def test_sync_invalid_key_returns_400(self, api_client: TestClient) -> None:
        r = api_client.post("/api/integrations/jira/sync/xxxxxxxxxxxxxxxx")
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_id"

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
        detail = r.json()["detail"]
        assert detail["error"] == "credentials_missing"
        assert "JIRA_BASE_URL" in detail["message"]


# ── Tableau publish endpoint (v0.7.8 P1.1) ────────────────────────


class TestTableauPublishEndpoint:
    def test_guarded_server_url_returns_400(
        self, api_client: TestClient
    ) -> None:
        # The SSRF/offline guard on the body-controlled ``server_url``
        # deliberately fires BEFORE the report-key lookup, so this
        # request never reaches the invalid-key branch (which the
        # jira/servicenow/powerbi tests cover via ``error:
        # invalid_id``). The unresolvable host trips the guard → 400
        # ``invalid_field`` on ``server_url``.
        r = api_client.post(
            "/api/integrations/tableau/publish/not-a-hex-key",
            json={"server_url": "https://example.tableau"},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_field"
        assert detail["field"] == "server_url"

    def test_missing_server_url_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/integrations/tableau/publish/0123456789abcdef",
            json={},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "missing_field"
        assert detail["field"] == "server_url"
        assert "server_url" in detail["message"]

    def test_invalid_risks_array_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/integrations/tableau/publish/0123456789abcdef",
            json={
                "server_url": "https://example.tableau.com",
                "risks": "not-a-list",
                # Opt out of the SSRF guard so this test exercises the
                # risks-array validation rather than host resolution.
                "block_private_ips": False,
            },
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_field"

    def test_private_server_url_refused_ssrf(
        self, api_client: TestClient
    ) -> None:
        # SSRF guard: a body-controlled server_url pointing at a private /
        # cloud-metadata host (169.254.169.254 = link-local) must be refused
        # BEFORE any outbound, PAT-bearing request — the same network_guard
        # chokepoint every collector uses. Literal IP, so no DNS needed.
        r = api_client.post(
            "/api/integrations/tableau/publish/0123456789abcdef",
            json={"server_url": "https://169.254.169.254/"},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_field"
        assert detail["field"] == "server_url"
        assert "tableau" in detail["message"].lower()

    def test_http_server_url_refused_non_tls(
        self, api_client: TestClient
    ) -> None:
        # The PAT must never go over a plaintext channel: an http:// URL is
        # refused by the TableauConfig https field_validator. block_private
        # is opted out so the SSRF guard does not fire first, isolating the
        # scheme check.
        r = api_client.post(
            "/api/integrations/tableau/publish/0123456789abcdef",
            json={
                "server_url": "http://192.0.2.1/",
                "block_private_ips": False,
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
        assert r.json()["detail"]["error"] == "invalid_id"

    def test_missing_workspace_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/integrations/powerbi/publish/0123456789abcdef",
            json={"tenant_id": "t-1", "client_id": "c-1"},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "missing_field"
        assert detail["field"] == "workspace_id"
        assert "workspace_id" in detail["message"]

    def test_missing_tenant_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/integrations/powerbi/publish/0123456789abcdef",
            json={"workspace_id": "ws-1", "client_id": "c-1"},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "missing_field"
        assert detail["field"] == "tenant_id"
        assert "tenant_id" in detail["message"]

    def test_missing_client_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/integrations/powerbi/publish/0123456789abcdef",
            json={"workspace_id": "ws-1", "tenant_id": "t-1"},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "missing_field"
        assert detail["field"] == "client_id"
        assert "client_id" in detail["message"]


# ── ServiceNow helpers ─────────────────────────────────────────────────────


def _set_servicenow_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "EVIDENTIA_SERVICENOW_INSTANCE_URL", "https://acme.service-now.com"
    )
    monkeypatch.setenv("EVIDENTIA_SERVICENOW_USER", "svc-user")
    monkeypatch.setenv(
        "EVIDENTIA_SERVICENOW_PASSWORD", "sn-secret-never-in-response"
    )
    monkeypatch.setenv("EVIDENTIA_SERVICENOW_TABLE", "incident")


def _unset_servicenow_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for v in (
        "EVIDENTIA_SERVICENOW_INSTANCE_URL",
        "EVIDENTIA_SERVICENOW_USER",
        "EVIDENTIA_SERVICENOW_PASSWORD",
        "EVIDENTIA_SERVICENOW_TABLE",
    ):
        monkeypatch.delenv(v, raising=False)


def _patch_servicenow_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler: httpx.MockTransport,
) -> None:
    """Patch ServiceNowClient.__init__ to inject a MockTransport http client.

    Mirrors ``_patch_client_transport`` for Jira — swaps the client's
    real ``httpx.Client`` for a MockTransport-backed one during
    construction so no network call is ever made.
    """
    from evidentia_integrations.servicenow import client as sn_client_mod

    orig_init = sn_client_mod.ServiceNowClient.__init__

    def patched_init(self: Any, config: Any, *, http: Any = None) -> None:
        if http is None:
            http = httpx.Client(
                base_url=config.instance_url,
                transport=handler,
                headers={
                    "Authorization": "Basic x",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
        orig_init(self, config, http=http)

    monkeypatch.setattr(
        sn_client_mod.ServiceNowClient, "__init__", patched_init
    )


def _make_report(api_client: TestClient) -> str:
    """Create a saved GapAnalysisReport and return its gap-store key."""
    from pathlib import Path

    fixture_root = (
        Path(__file__).resolve().parents[3]
        / "examples"
        / "meridian-fintech-v2"
    )
    inventory = (fixture_root / "my-controls.yaml").read_text(
        encoding="utf-8"
    )
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
    return str(reports[0]["key"])


# ── ServiceNow status ──────────────────────────────────────────────────────


class TestServiceNowStatus:
    def test_returns_unconfigured_when_env_missing(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _unset_servicenow_env(monkeypatch)
        r = api_client.get("/api/integrations/servicenow/status")
        assert r.status_code == 200
        payload = r.json()
        assert payload["configured"] is False
        # Sanitized message + request-id correlation; env-var names /
        # secret-store hints live in the server log only.
        assert payload["error"] == (
            "ServiceNow configuration is incomplete or invalid."
        )
        assert len(payload["request_id"]) == 12
        assert "EVIDENTIA_SERVICENOW_INSTANCE_URL" not in r.text
        assert "EVIDENTIA_SERVICENOW_PASSWORD" not in r.text

    def test_returns_configured_on_success(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_servicenow_env(monkeypatch)

        def handler(req: httpx.Request) -> httpx.Response:
            # test_connection() probes GET /api/now/table/<table>
            if "/api/now/table/incident" in req.url.path:
                return httpx.Response(
                    200, json={"result": [{"sys_id": "abc123"}]}
                )
            return httpx.Response(404)

        _patch_servicenow_transport(
            monkeypatch, httpx.MockTransport(handler)
        )

        r = api_client.get("/api/integrations/servicenow/status")
        assert r.status_code == 200, r.text
        payload = r.json()
        assert payload["configured"] is True
        assert payload["instance_url"] == "https://acme.service-now.com"
        assert payload["table_name"] == "incident"
        assert payload["user"] == "svc-user"
        # Critical: password value must never leak.
        assert "sn-secret-never-in-response" not in r.text

    def test_returns_error_when_credentials_reject(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_servicenow_env(monkeypatch)

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401, json={"error": {"message": "User Not Authenticated"}}
            )

        _patch_servicenow_transport(
            monkeypatch, httpx.MockTransport(handler)
        )

        r = api_client.get("/api/integrations/servicenow/status")
        assert r.status_code == 200
        payload = r.json()
        assert payload["configured"] is False
        assert payload["error"] == (
            "ServiceNow API call failed; check server logs with the "
            "request_id."
        )
        assert len(payload["request_id"]) == 12
        # Upstream status code + error text must not leak to the wire.
        assert "401" not in payload["error"]
        assert "User Not Authenticated" not in payload["error"]
        assert "sn-secret-never-in-response" not in r.text


# ── ServiceNow push ────────────────────────────────────────────────────────


class TestServiceNowPush:
    def test_push_invalid_key_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/integrations/servicenow/push/not-a-hex-key"
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_id"

    def test_push_missing_report_returns_404(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_servicenow_env(monkeypatch)
        r = api_client.post(
            "/api/integrations/servicenow/push/0123456789abcdef"
        )
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "not_found"

    def test_push_returns_503_when_unconfigured_but_report_exists(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        key = _make_report(api_client)
        _unset_servicenow_env(monkeypatch)
        r = api_client.post(f"/api/integrations/servicenow/push/{key}")
        assert r.status_code == 503
        detail = r.json()["detail"]
        assert detail["error"] == "credentials_missing"
        assert "EVIDENTIA_SERVICENOW_INSTANCE_URL" in detail["message"]

    def test_push_valid_report_calls_client_and_returns_result(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        key = _make_report(api_client)
        _set_servicenow_env(monkeypatch)

        created: list[str] = []

        def handler(req: httpx.Request) -> httpx.Response:
            path = req.url.path
            # Idempotency lookup (find_existing_by_correlation): no match.
            if req.method == "GET" and "/api/now/table/incident" in path:
                return httpx.Response(200, json={"result": []})
            # Record creation.
            if req.method == "POST" and "/api/now/table/incident" in path:
                created.append("x")
                return httpx.Response(
                    201,
                    json={
                        "result": {
                            "sys_id": f"sys{len(created)}",
                            "number": f"INC001000{len(created)}",
                            "short_description": "gap",
                            "state": "1",
                        }
                    },
                )
            return httpx.Response(404)

        _patch_servicenow_transport(
            monkeypatch, httpx.MockTransport(handler)
        )

        r = api_client.post(f"/api/integrations/servicenow/push/{key}")
        assert r.status_code == 200, r.text
        payload = r.json()
        # Result shape mirrors the jira push response.
        assert "created" in payload
        assert "existing" in payload
        assert "skipped" in payload
        assert "errored" in payload
        assert "outcomes" in payload
        assert isinstance(payload["outcomes"], list)
        # The mocked client was actually exercised (records created).
        assert created, "expected the ServiceNow client to be called"
        assert payload["created"] >= 1
        # Critical: password value must never leak into the response.
        assert "sn-secret-never-in-response" not in r.text

    def test_push_never_reads_credentials_from_request_body(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A password supplied in the body must be ignored — creds are
        sourced server-side from env only. With env UNSET, even a body
        carrying credentials must 503 (the body password is never used).
        """
        key = _make_report(api_client)
        _unset_servicenow_env(monkeypatch)

        # Body carries would-be secrets; the endpoint must NOT honor them.
        r = api_client.post(
            f"/api/integrations/servicenow/push/{key}",
            json={
                "instance_url": "https://attacker.service-now.com",
                "user": "attacker",
                "password": "body-supplied-secret",
            },
        )
        assert r.status_code == 503, r.text
        # The 503 proves config came from (absent) env, not the body.
        detail = r.json()["detail"]
        assert detail["error"] == "credentials_missing"
        assert "EVIDENTIA_SERVICENOW_INSTANCE_URL" in detail["message"]


# ── OpenAPI error-status documentation (2026-07-06 convergence) ────────────


def test_integrations_error_statuses_documented_in_openapi(
    api_client: TestClient,
) -> None:
    """Every status the integrations routes deliberately raise is
    documented on the operation's ``responses`` in the OpenAPI schema
    (schemathesis undocumented-status noise → contract)."""
    schema = api_client.get("/api/openapi.json").json()
    expected = [
        (
            "/api/integrations/jira/push/{report_key}",
            "post",
            ["400", "404", "503"],
        ),
        (
            "/api/integrations/jira/sync/{report_key}",
            "post",
            ["400", "404", "503"],
        ),
        (
            "/api/integrations/tableau/publish/{report_key}",
            "post",
            ["400", "404", "500", "503"],
        ),
        (
            "/api/integrations/powerbi/publish/{report_key}",
            "post",
            ["400", "404", "500", "503"],
        ),
        (
            "/api/integrations/servicenow/push/{report_key}",
            "post",
            ["400", "404", "503"],
        ),
    ]
    for path, method, statuses in expected:
        responses = schema["paths"][path][method]["responses"]
        for status in statuses:
            assert status in responses, (path, method, status)
