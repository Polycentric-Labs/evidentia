"""TestClient coverage for SecurityHeadersMiddleware (v0.7.9 F-V08-DAST-2).

Verifies the middleware:
1. Off by default (no headers when ``security_headers=False``).
2. Attached when ``create_app(security_headers=True)``.
3. Attached when env var ``EVIDENTIA_API_SECURITY_HEADERS=1``.
4. NOT attached when env var is unset.
5. Each header carries the expected value.
6. Doesn't break existing routes (regression check).
7. ``should_enable_for_host`` auto-detect helper returns the right
   value for each canonical input.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from evidentia_api.app import create_app
from evidentia_api.security_headers import (
    SECURITY_HEADERS,
    should_enable_for_host,
)
from fastapi.testclient import TestClient


def _make_client(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    security_headers: bool | None = None,
    env_var: str | None = None,
) -> TestClient:
    """Fresh TestClient with ``create_app(security_headers=...)`` and
    optional ``EVIDENTIA_API_SECURITY_HEADERS`` env-var seeding.

    Avoids cross-test bleed by resetting the FrameworkRegistry singleton
    + the network guard + the config-loader cache, mirroring conftest.
    """
    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(tmp_path / "gap_store"))
    monkeypatch.chdir(tmp_path)

    from evidentia_core.catalogs.registry import FrameworkRegistry
    from evidentia_core.config import _load_config_cached
    from evidentia_core.network_guard import set_offline

    _load_config_cached.cache_clear()
    set_offline(False)
    FrameworkRegistry.reset_instance()

    if env_var is None:
        monkeypatch.delenv("EVIDENTIA_API_SECURITY_HEADERS", raising=False)
    else:
        monkeypatch.setenv("EVIDENTIA_API_SECURITY_HEADERS", env_var)

    return TestClient(create_app(security_headers=security_headers))


# ── activation policy ──────────────────────────────────────────────


class TestActivationPolicy:
    def test_off_by_default(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """No env var, no explicit kwarg → middleware not attached."""
        client = _make_client(monkeypatch, tmp_path)
        r = client.get("/api/health")
        for header in SECURITY_HEADERS:
            assert header not in r.headers, f"Expected {header} absent; default should be off."

    def test_explicit_true_attaches_middleware(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        client = _make_client(monkeypatch, tmp_path, security_headers=True)
        r = client.get("/api/health")
        for header, expected in SECURITY_HEADERS.items():
            assert r.headers.get(header) == expected, f"{header} should be {expected!r}; got {r.headers.get(header)!r}"

    def test_explicit_false_does_not_attach(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # Even with the env var set ON, an explicit False kwarg overrides.
        client = _make_client(monkeypatch, tmp_path, security_headers=False, env_var="1")
        r = client.get("/api/health")
        for header in SECURITY_HEADERS:
            assert header not in r.headers, (
                f"Explicit False kwarg should override env var ON. {header} should NOT be present."
            )

    def test_env_var_1_enables(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        client = _make_client(monkeypatch, tmp_path, env_var="1")
        r = client.get("/api/health")
        for header, expected in SECURITY_HEADERS.items():
            assert r.headers.get(header) == expected

    def test_env_var_0_does_not_enable(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # Anything other than literal "1" is treated as off.
        client = _make_client(monkeypatch, tmp_path, env_var="0")
        r = client.get("/api/health")
        for header in SECURITY_HEADERS:
            assert header not in r.headers


# ── per-header value pinning ───────────────────────────────────────


class TestHeaderValues:
    @pytest.fixture()
    def headers(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> object:
        # Return the raw Headers object (case-insensitive lookups);
        # ``dict(r.headers)`` would lowercase keys.
        client = _make_client(monkeypatch, tmp_path, security_headers=True)
        r = client.get("/api/health")
        return r.headers

    def test_csp_default_src_self(self, headers: object) -> None:
        csp = headers["Content-Security-Policy"]  # type: ignore[index]
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        # Must NOT contain unsafe-eval (allowing it would defeat much
        # of the CSP value)
        assert "unsafe-eval" not in csp

    def test_x_frame_options_deny(self, headers: object) -> None:
        assert headers["X-Frame-Options"] == "DENY"  # type: ignore[index]

    def test_x_content_type_options_nosniff(self, headers: object) -> None:
        assert (
            headers["X-Content-Type-Options"] == "nosniff"  # type: ignore[index]
        )

    def test_referrer_policy_strict_origin_xorigin(self, headers: object) -> None:
        assert (
            headers["Referrer-Policy"]  # type: ignore[index]
            == "strict-origin-when-cross-origin"
        )

    def test_hsts_one_year_with_subdomains(self, headers: object) -> None:
        sts = headers["Strict-Transport-Security"]  # type: ignore[index]
        assert "max-age=31536000" in sts
        assert "includeSubDomains" in sts

    def test_permissions_policy_blocks_sensitive_apis(self, headers: object) -> None:
        pp = headers["Permissions-Policy"]  # type: ignore[index]
        for api in ("camera", "microphone", "geolocation", "payment"):
            assert f"{api}=()" in pp


# ── regression: existing routes still work ─────────────────────────


class TestRegressionExistingRoutes:
    def test_health_endpoint_returns_200_with_middleware(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        client = _make_client(monkeypatch, tmp_path, security_headers=True)
        r = client.get("/api/health")
        assert r.status_code == 200
        # Body still parseable, middleware doesn't tamper with payload
        assert "version" in r.json() or "status" in r.json()


# ── auto-detect helper ─────────────────────────────────────────────


class TestShouldEnableForHost:
    @pytest.mark.parametrize(
        "host,expected",
        [
            ("127.0.0.1", False),
            ("localhost", False),
            ("::1", False),
            ("0.0.0.0", True),
            ("192.168.1.10", True),
            ("evidentia.example.com", True),
            ("10.0.0.5", True),
        ],
    )
    def test_should_enable_for_host(self, host: str, expected: bool) -> None:
        assert should_enable_for_host(host) is expected


# ── always-set semantic (security wins) ───────────────────────────


class TestAlwaysSetSemantic:
    def test_middleware_overrides_route_set_header(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Per the always-set semantic: security headers win over any
        route-level customization. A future route that genuinely needs
        looser CSP must opt out via a different mechanism (e.g., a
        path-allow-list passed to the middleware constructor)."""
        from evidentia_core.catalogs.registry import FrameworkRegistry
        from evidentia_core.config import _load_config_cached
        from evidentia_core.network_guard import set_offline
        from fastapi import APIRouter, Response

        monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(tmp_path / "gap_store"))
        monkeypatch.chdir(tmp_path)
        _load_config_cached.cache_clear()
        set_offline(False)
        FrameworkRegistry.reset_instance()

        app = create_app(security_headers=True)
        custom_router = APIRouter()

        @custom_router.get("/api/test/custom-header")
        def _custom(response: Response) -> dict[str, object]:
            # Route tries to set its own X-Frame-Options; middleware
            # should override.
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
            return {"ok": True}

        app.include_router(custom_router)
        client = TestClient(app)
        r = client.get("/api/test/custom-header")
        # Middleware DENY wins — security headers always set.
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in r.headers
