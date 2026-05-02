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
        assert r.status_code == 422
        assert "owner/repo" in r.json()["detail"]

    def test_missing_repo_returns_422(self, api_client: TestClient) -> None:
        r = api_client.post("/api/collectors/github/collect", json={})
        assert r.status_code == 422


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
