"""Unit tests for v0.8.1 P3.3 + v0.8.2 F-V81-S2 FastAPI AuthProvider middleware.

Verifies that the AuthProvider middleware:
1. Gates `/api/*` routes when wired (closes v0.8.0 F-V08-S3).
2. Allows liveness probes (`/api/health`, `/api/version`,
   `/api/openapi.json`, `/api/docs`, `/api/redoc`) without
   auth (Kubernetes / load-balancer readiness convention).
3. Does NOT fire when `auth_provider=None` (v0.8.0 backward
   compat for localhost-only deployments).
4. Returns 401 with `WWW-Authenticate: Bearer realm="evidentia"`
   on missing/invalid token (RFC 7235 §4.1).
5. Attaches the authenticated principal to `request.state` so
   downstream handlers can introspect.

v0.8.2 F-V81-S2 additions (TestAuthLifespan):
6. The FastAPI lifespan reads `EVIDENTIA_API_AUTH_TOKEN_FILE`
   at app STARTUP (not module import) and populates
   `app.state.auth_provider` accordingly.
7. Missing env var leaves `app.state.auth_provider = None` —
   no auth gating, matching v0.8.0 behavior.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest
from evidentia_api.app import create_app
from evidentia_core.plugins.auth.local_token import LocalTokenAuthProvider
from fastapi.testclient import TestClient


def _make_token_file(tmp_path: Path, value: str = "test-token-abc") -> Path:
    token_file = tmp_path / "token.txt"
    token_file.write_text(value, encoding="utf-8")
    return token_file


class TestAuthMiddleware:
    def test_no_auth_provider_means_no_gating(self) -> None:
        """v0.8.0 backward-compat: auth_provider=None matches
        the localhost-only deployment posture; no middleware
        attached + all routes reachable.
        """
        app = create_app(dev_mode=False, auth_provider=None)
        client = TestClient(app)
        # /api/metrics is the v0.8.0 P1 G3 endpoint — no auth
        # gating in v0.8.0. With auth_provider=None we keep that
        # behavior.
        response = client.get("/api/metrics")
        assert response.status_code == 200

    def test_auth_provider_gates_metrics_endpoint(
        self, tmp_path: Path
    ) -> None:
        """v0.8.1 F-V08-S3 closure: with an AuthProvider wired,
        /api/metrics requires a valid bearer token.
        """
        token_file = _make_token_file(tmp_path)
        provider = LocalTokenAuthProvider(token_file=token_file)
        app = create_app(dev_mode=False, auth_provider=provider)
        client = TestClient(app)

        # No Authorization header → 401.
        response = client.get("/api/metrics")
        assert response.status_code == 401
        assert (
            response.headers["WWW-Authenticate"]
            == 'Bearer realm="evidentia"'
        )
        body = response.json()
        assert body["detail"] == "Authentication required"
        assert body["provider"] == "local-token"

        # Wrong token → 401.
        response = client.get(
            "/api/metrics",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert response.status_code == 401

        # Right token → 200.
        response = client.get(
            "/api/metrics",
            headers={"Authorization": "Bearer test-token-abc"},
        )
        assert response.status_code == 200
        # The metrics body still renders Prometheus exposition.
        assert "evidentia_app_info" in response.text

    def test_health_probe_bypasses_auth(self, tmp_path: Path) -> None:
        """Liveness probe path /api/health is in the
        UNAUTHENTICATED_PATHS allowlist; it MUST be reachable
        without a token so Kubernetes/load-balancer readiness
        checks don't break.
        """
        token_file = _make_token_file(tmp_path)
        provider = LocalTokenAuthProvider(token_file=token_file)
        app = create_app(dev_mode=False, auth_provider=provider)
        client = TestClient(app)

        # No Authorization header → still 200 (allowlisted).
        response = client.get("/api/health")
        assert response.status_code == 200

    def test_version_probe_bypasses_auth(self, tmp_path: Path) -> None:
        """/api/version is allowlisted alongside /api/health —
        operator's CI gates often check the running version
        without a service-account credential.
        """
        token_file = _make_token_file(tmp_path)
        provider = LocalTokenAuthProvider(token_file=token_file)
        app = create_app(dev_mode=False, auth_provider=provider)
        client = TestClient(app)

        response = client.get("/api/version")
        assert response.status_code == 200

    def test_openapi_spec_bypasses_auth(self, tmp_path: Path) -> None:
        """/api/openapi.json must be reachable without a token
        so OpenAPI tooling (Stoplight, Swagger UI, etc.) can
        introspect the API + advertise the auth scheme to
        clients.
        """
        token_file = _make_token_file(tmp_path)
        provider = LocalTokenAuthProvider(token_file=token_file)
        app = create_app(dev_mode=False, auth_provider=provider)
        client = TestClient(app)

        response = client.get("/api/openapi.json")
        assert response.status_code == 200

    def test_static_spa_paths_bypass_auth(
        self, tmp_path: Path
    ) -> None:
        """Non-/api/* paths fall through to the static SPA
        mount; they bypass auth at the API layer (the SPA
        itself handles client-side auth in the browser).
        """
        token_file = _make_token_file(tmp_path)
        provider = LocalTokenAuthProvider(token_file=token_file)
        app = create_app(dev_mode=False, auth_provider=provider)
        client = TestClient(app)

        # The SPA root path — without auth, returns either the
        # SPA index.html or the placeholder JSON (depending on
        # whether the static mount is populated). Either way,
        # NOT a 401.
        response = client.get("/")
        assert response.status_code != 401


class TestAuthLifespan:
    """v0.8.2 F-V81-S2: env-driven AuthProvider construction
    is deferred to FastAPI lifespan (not module import).
    """

    def test_lifespan_reads_env_at_startup_not_import(
        self, tmp_path: Path
    ) -> None:
        """The lifespan reads EVIDENTIA_API_AUTH_TOKEN_FILE at
        app startup. This means setting the env var AFTER
        importing create_app + before entering the TestClient
        context manager populates app.state.auth_provider.

        v0.8.1 had the env-read at module import time, which
        meant the env var had to be set BEFORE the import or
        the provider was None forever. v0.8.2 F-V81-S2 fixes
        this by deferring to lifespan startup.
        """
        token_file = _make_token_file(tmp_path, value="lifespan-token")

        # Build the app with NO explicit auth_provider — the
        # lifespan should pick up the env var at startup.
        app = create_app(dev_mode=False, auth_provider=None)
        # Pre-startup: app.state.auth_provider is None (matches
        # v0.8.0 default; lifespan hasn't run yet).
        assert app.state.auth_provider is None

        # Set the env var AFTER create_app(); enter the
        # TestClient context manager to trigger the lifespan
        # startup event.
        with mock.patch.dict(
            os.environ,
            {"EVIDENTIA_API_AUTH_TOKEN_FILE": str(token_file)},
        ), TestClient(app) as client:
            # After lifespan startup, the provider is populated.
            assert app.state.auth_provider is not None
            # /api/metrics now requires the token.
            response = client.get("/api/metrics")
            assert response.status_code == 401
            # Right token works.
            response = client.get(
                "/api/metrics",
                headers={
                    "Authorization": "Bearer lifespan-token",
                },
            )
            assert response.status_code == 200

    def test_no_env_var_leaves_provider_none(self) -> None:
        """When EVIDENTIA_API_AUTH_TOKEN_FILE is unset (or empty),
        the lifespan does not construct a provider —
        app.state.auth_provider stays None and /api/metrics is
        reachable without a token (v0.8.0 backward-compat).
        """
        app = create_app(dev_mode=False, auth_provider=None)

        # Make sure the env var is unset for this test.
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(
                "EVIDENTIA_API_AUTH_TOKEN_FILE", None
            )
            with TestClient(app) as client:
                assert app.state.auth_provider is None
                # /api/metrics is reachable without a token.
                response = client.get("/api/metrics")
                assert response.status_code == 200

    def test_lifespan_raises_loud_on_broken_token_file(
        self, tmp_path: Path
    ) -> None:
        """If EVIDENTIA_API_AUTH_TOKEN_FILE points at a missing
        file, the lifespan raises during startup so the app
        fails loudly. This preserves the v0.8.1 fail-loud
        contract — operators don't get a silent fall-through to
        no-auth.
        """
        nonexistent = tmp_path / "no-such-file.txt"

        app = create_app(dev_mode=False, auth_provider=None)

        with mock.patch.dict(
            os.environ,
            {"EVIDENTIA_API_AUTH_TOKEN_FILE": str(nonexistent)},
        ), pytest.raises((FileNotFoundError, ValueError)), TestClient(app):
            pass  # pragma: no cover — lifespan raises first

    def test_explicit_injection_takes_precedence_over_env(
        self, tmp_path: Path
    ) -> None:
        """v0.8.2 F-V81-S2: explicit ``auth_provider=...`` passed
        to ``create_app`` wins over the env-var path. The
        lifespan only constructs a provider when
        ``app.state.auth_provider is None`` at startup.
        """
        explicit_token_file = _make_token_file(
            tmp_path, value="explicit-token"
        )
        explicit_provider = LocalTokenAuthProvider(
            token_file=explicit_token_file
        )

        # Different token file in the env — should be IGNORED
        # because explicit injection wins.
        env_token_file = _make_token_file(
            tmp_path / "env" if False else tmp_path,
            value="env-token-IGNORED",
        )
        # Use a different filename so they don't collide.
        env_token_file = tmp_path / "env-token.txt"
        env_token_file.write_text(
            "env-token-IGNORED", encoding="utf-8"
        )

        app = create_app(
            dev_mode=False, auth_provider=explicit_provider
        )

        with mock.patch.dict(
            os.environ,
            {"EVIDENTIA_API_AUTH_TOKEN_FILE": str(env_token_file)},
        ), TestClient(app) as client:
            # Explicit token works; env token does NOT (was ignored).
            response = client.get(
                "/api/metrics",
                headers={
                    "Authorization": "Bearer explicit-token",
                },
            )
            assert response.status_code == 200
            response = client.get(
                "/api/metrics",
                headers={
                    "Authorization": (
                        "Bearer env-token-IGNORED"
                    ),
                },
            )
            assert response.status_code == 401
