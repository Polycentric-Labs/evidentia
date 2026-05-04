"""TestClient coverage for /api/collectors/* endpoints.

Smoke coverage only — full collector happy-paths are covered in
``tests/unit/test_collectors/``. Here we verify routing, validation,
and error-code mapping.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


class TestCollectorsStatus:
    def test_reports_packages_and_env(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_should_never_appear_in_response")
        r = api_client.get("/api/collectors/status")
        assert r.status_code == 200
        payload = r.json()
        assert "aws" in payload
        assert "github" in payload
        assert payload["github"]["token_configured"] is True
        assert payload["github"]["token_source"] == "env:GITHUB_TOKEN"
        # Token value must NEVER appear in the response.
        assert "should_never_appear_in_response" not in r.text

    def test_reports_github_unconfigured_when_env_missing(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        r = api_client.get("/api/collectors/status")
        payload = r.json()
        assert payload["github"]["token_configured"] is False
        assert payload["github"]["token_source"] is None


class TestGithubCollectEndpoint:
    def test_rejects_malformed_repo(self, api_client: TestClient) -> None:
        r = api_client.post("/api/collectors/github/collect", json={"repo": "notaformat"})
        # 400 (not 422) — runtime body-content validation; matches
        # OpenAPI `{detail: string}` shape (F-V08-DAST-3).
        assert r.status_code == 400
        assert "owner/repo" in r.json()["detail"]

    def test_missing_repo_returns_400(self, api_client: TestClient) -> None:
        r = api_client.post("/api/collectors/github/collect", json={})
        assert r.status_code == 400


class TestSQLiteCollectEndpointSafeRoot:
    """v0.7.7 Step 5.A — F-001 path-traversal containment.

    The REST endpoint must honor EVIDENTIA_SQLITE_SAFE_ROOT and refuse
    any database_path that resolves outside it (CWE-22 mitigation).
    """

    def test_rejects_path_outside_safe_root(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: object,
    ) -> None:
        from pathlib import Path as _P

        safe = _P(str(tmp_path)) / "safe"
        safe.mkdir()
        outside = _P(str(tmp_path)) / "outside.db"
        import sqlite3
        sqlite3.connect(str(outside)).close()

        monkeypatch.setenv("EVIDENTIA_SQLITE_SAFE_ROOT", str(safe))
        r = api_client.post(
            "/api/collectors/sql/sqlite/collect",
            json={"database_path": str(outside)},
        )
        # SQLiteCollectorError -> 503 with "outside safe_root" detail
        assert r.status_code == 503
        assert "outside safe_root" in r.json()["detail"]

    def test_accepts_path_inside_safe_root(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: object,
    ) -> None:
        from pathlib import Path as _P

        safe = _P(str(tmp_path)) / "safe"
        safe.mkdir()
        inside = safe / "app.db"
        import sqlite3
        sqlite3.connect(str(inside)).close()

        monkeypatch.setenv("EVIDENTIA_SQLITE_SAFE_ROOT", str(safe))
        r = api_client.post(
            "/api/collectors/sql/sqlite/collect",
            json={"database_path": str(inside)},
        )
        # Path inside safe_root is accepted; collection succeeds (200)
        # — even an empty DB produces file-ACL + integrity findings
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_no_safe_root_env_falls_back_to_unconstrained(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: object,
    ) -> None:
        """When EVIDENTIA_SQLITE_SAFE_ROOT is unset, any readable path
        is accepted (single-tenant trusted-perimeter posture)."""
        from pathlib import Path as _P

        db = _P(str(tmp_path)) / "app.db"
        import sqlite3
        sqlite3.connect(str(db)).close()

        monkeypatch.delenv("EVIDENTIA_SQLITE_SAFE_ROOT", raising=False)
        r = api_client.post(
            "/api/collectors/sql/sqlite/collect",
            json={"database_path": str(db)},
        )
        assert r.status_code == 200


class TestSnowflakeCollectEndpoint:
    """Smoke coverage for /api/collectors/snowflake/collect (v0.7.8 P0.2).

    No live Snowflake; we validate routing + body validation + secret-
    handling guarantees.
    """

    def test_missing_account_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/collectors/snowflake/collect",
            json={"user": "EVIDENTIA_AUDIT_RO"},
        )
        # 400 (not 422) — body-content validation. F-V08-DAST-3.
        assert r.status_code == 400
        assert "account" in r.json()["detail"]

    def test_missing_user_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/collectors/snowflake/collect",
            json={"account": "acme-prod"},
        )
        assert r.status_code == 400
        assert "user" in r.json()["detail"]

    def test_missing_password_env_returns_400(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Ensure neither default nor any custom env is set.
        monkeypatch.delenv("SNOWFLAKE_PASSWORD", raising=False)
        r = api_client.post(
            "/api/collectors/snowflake/collect",
            json={
                "account": "acme-prod",
                "user": "EVIDENTIA_AUDIT_RO",
            },
        )
        # 400 because the password env var resolves to nothing.
        assert r.status_code == 400
        assert "SNOWFLAKE_PASSWORD" in r.json()["detail"]

    def test_status_endpoint_includes_snowflake_entry(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(
            "SNOWFLAKE_PASSWORD",
            "fake-pwd-must-not-appear-in-response",
        )
        r = api_client.get("/api/collectors/status")
        assert r.status_code == 200
        payload = r.json()
        assert "snowflake" in payload
        assert payload["snowflake"]["default_password_env_configured"] is True
        # Secret value MUST NOT leak.
        assert "fake-pwd-must-not-appear-in-response" not in r.text


class TestSecurityScorecardCollectEndpointSSRFGuard:
    """v0.7.12 P0.6 / CodeQL #92 closure (CRITICAL py/partial-ssrf).

    The /api/collectors/securityscorecard/collect endpoint must
    reject portfolio_id values containing path-traversal segments
    BEFORE they flow into the f-string URL composition at
    ``_paginate_portfolio``. The collector itself also validates
    (defense-in-depth) but a 400 here gives the API consumer a
    sharper error than the collector's 503.
    """

    @pytest.mark.parametrize(
        "bad_portfolio_id",
        [
            "../admin",
            "portfolio/companies",
            "portfolio\\evil",
            "/leading-slash",
            "trailing-slash/",
            "portfolio?inject=1",
            "portfolio#frag",
            "portfolio with spaces",
            "portfolio\nnewline",
        ],
    )
    def test_rejects_unsafe_portfolio_id_with_400(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        bad_portfolio_id: str,
    ) -> None:
        # Provide a token so the env-var gate doesn't fail first
        monkeypatch.setenv("SECURITYSCORECARD_API_TOKEN", "ssc_test")
        r = api_client.post(
            "/api/collectors/securityscorecard/collect",
            json={"portfolio_id": bad_portfolio_id},
        )
        # 400 (not 422) — early-fail at the REST boundary; matches
        # the OpenAPI {detail: string} shape (F-V08-DAST-3 pattern).
        assert r.status_code == 400, (
            f"Expected 400 for portfolio_id={bad_portfolio_id!r}, "
            f"got {r.status_code}: {r.text}"
        )
        assert "portfolio_id" in r.json()["detail"].lower()
