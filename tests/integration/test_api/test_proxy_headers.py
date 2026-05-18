"""TestClient coverage for ProxyHeadersMiddleware auto-wire (v0.9.5 P1.6).

Verifies the v0.9.5 P1.6 trust-proxy-headers feature:

1. Off by default (no proxy-headers handling).
2. On when ``create_app(trust_proxy_headers=True)``.
3. On when env var ``EVIDENTIA_TRUST_PROXY_HEADERS=1``.
4. Off when env var is unset / any value other than ``"1"``.
5. Programmatic value overrides env var.
6. ``app.state.trust_proxy_headers`` reflects the resolved value.

The functional behavior of uvicorn's ProxyHeadersMiddleware
(replacing ``scope["client"]`` from ``X-Forwarded-For``) is
upstream-tested by uvicorn itself; these tests verify the
attachment + env-var resolution wiring, not the middleware's
implementation.
"""

from __future__ import annotations

import pytest
from evidentia_api.app import create_app
from fastapi.testclient import TestClient


class TestProxyHeadersWiring:
    def test_off_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("EVIDENTIA_TRUST_PROXY_HEADERS", raising=False)
        app = create_app()
        assert app.state.trust_proxy_headers is False

    def test_explicit_true(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("EVIDENTIA_TRUST_PROXY_HEADERS", raising=False)
        app = create_app(trust_proxy_headers=True)
        assert app.state.trust_proxy_headers is True

    def test_env_var_on(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EVIDENTIA_TRUST_PROXY_HEADERS", "1")
        app = create_app()
        assert app.state.trust_proxy_headers is True

    def test_env_var_off_for_non_one_value(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only ``"1"`` activates — ``"true"`` / ``"on"`` / ``"yes"``
        do NOT, matching the project-wide env-var convention used
        by EVIDENTIA_API_SECURITY_HEADERS."""
        monkeypatch.setenv("EVIDENTIA_TRUST_PROXY_HEADERS", "true")
        app = create_app()
        assert app.state.trust_proxy_headers is False

    def test_explicit_false_overrides_env_var(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Programmatic ``False`` overrides env var (matches the
        ``security_headers`` convention)."""
        monkeypatch.setenv("EVIDENTIA_TRUST_PROXY_HEADERS", "1")
        app = create_app(trust_proxy_headers=False)
        assert app.state.trust_proxy_headers is False

    def test_doesnt_break_existing_routes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Smoke test: attaching ProxyHeadersMiddleware does NOT
        break the request path."""
        monkeypatch.setenv("EVIDENTIA_TRUST_PROXY_HEADERS", "1")
        app = create_app(trust_proxy_headers=True)
        client = TestClient(app)
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_middleware_attached_when_enabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Inspect the middleware stack: ProxyHeadersMiddleware is
        present when ``trust_proxy_headers=True``."""
        monkeypatch.delenv("EVIDENTIA_TRUST_PROXY_HEADERS", raising=False)
        app = create_app(trust_proxy_headers=True)
        middleware_classes = [
            m.cls.__name__ for m in app.user_middleware
        ]
        assert "ProxyHeadersMiddleware" in middleware_classes

    def test_middleware_absent_when_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("EVIDENTIA_TRUST_PROXY_HEADERS", raising=False)
        app = create_app(trust_proxy_headers=False)
        middleware_classes = [
            m.cls.__name__ for m in app.user_middleware
        ]
        assert "ProxyHeadersMiddleware" not in middleware_classes
