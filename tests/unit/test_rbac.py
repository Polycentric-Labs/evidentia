"""Unit tests for evidentia_core.rbac (v0.9.5 P3.3; v0.9.8 P1.4 multi-tenant FastAPI)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from evidentia_core.rbac import (
    DEFAULT_POLICY,
    RBACPolicy,
    Role,
    check_permission,
    load_policy_from_file,
)


class TestRoleHierarchy:
    def test_admin_outranks_editor(self) -> None:
        assert Role.ADMIN.outranks_or_equal(Role.EDITOR) is True

    def test_editor_outranks_reader(self) -> None:
        assert Role.EDITOR.outranks_or_equal(Role.READER) is True

    def test_reader_outranks_deny(self) -> None:
        assert Role.READER.outranks_or_equal(Role.DENY) is True

    def test_role_outranks_self(self) -> None:
        assert Role.EDITOR.outranks_or_equal(Role.EDITOR) is True

    def test_lower_role_does_not_outrank_higher(self) -> None:
        assert Role.READER.outranks_or_equal(Role.EDITOR) is False
        assert Role.READER.outranks_or_equal(Role.ADMIN) is False
        assert Role.EDITOR.outranks_or_equal(Role.ADMIN) is False


class TestRBACPolicyResolution:
    def test_role_for_known_identity(self) -> None:
        policy = RBACPolicy(
            identities={"alice@example.com": Role.ADMIN},
            default_role=Role.READER,
        )
        assert policy.role_for("alice@example.com") == Role.ADMIN

    def test_role_for_unknown_identity_returns_default(self) -> None:
        policy = RBACPolicy(default_role=Role.READER)
        assert policy.role_for("nobody@example.com") == Role.READER

    def test_role_for_none_identity_returns_default(self) -> None:
        policy = RBACPolicy(default_role=Role.EDITOR)
        assert policy.role_for(None) == Role.EDITOR

    def test_default_policy_is_permissive(self) -> None:
        """Default policy: everyone is admin (preserves v0.9.4 behavior)."""
        assert DEFAULT_POLICY.role_for("anyone") == Role.ADMIN
        assert DEFAULT_POLICY.role_for(None) == Role.ADMIN


class TestCheckPermission:
    def test_admin_can_do_all_actions(self) -> None:
        assert check_permission("alice", "read") is True
        assert check_permission("alice", "write") is True
        assert check_permission("alice", "admin") is True

    def test_reader_can_read_but_not_write(self) -> None:
        policy = RBACPolicy(
            identities={"reader@example.com": Role.READER},
            default_role=Role.DENY,
        )
        assert check_permission("reader@example.com", "read", policy=policy) is True
        assert check_permission("reader@example.com", "write", policy=policy) is False
        assert check_permission("reader@example.com", "admin", policy=policy) is False

    def test_editor_can_write_but_not_admin(self) -> None:
        policy = RBACPolicy(
            identities={"editor@example.com": Role.EDITOR},
            default_role=Role.DENY,
        )
        assert check_permission("editor@example.com", "read", policy=policy) is True
        assert check_permission("editor@example.com", "write", policy=policy) is True
        assert check_permission("editor@example.com", "admin", policy=policy) is False

    def test_deny_role_blocks_everything(self) -> None:
        policy = RBACPolicy(
            identities={"banned@example.com": Role.DENY},
            default_role=Role.READER,
        )
        assert check_permission("banned@example.com", "read", policy=policy) is False

    def test_deny_by_default_blocks_unknown(self) -> None:
        policy = RBACPolicy(default_role=Role.DENY)
        assert check_permission("unknown", "read", policy=policy) is False

    def test_unknown_action_raises(self) -> None:
        with pytest.raises(KeyError):
            check_permission("alice", "bogus")


class TestPolicyFileLoad:
    def test_loads_yaml_policy(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "rbac.yaml"
        policy_file.write_text(
            "identities:\n"
            "  alice@example.com: admin\n"
            "  bob@example.com: editor\n"
            "  charlie@example.com: reader\n"
            "default_role: reader\n",
            encoding="utf-8",
        )
        policy = load_policy_from_file(policy_file)
        assert policy.identities["alice@example.com"] == Role.ADMIN
        assert policy.identities["bob@example.com"] == Role.EDITOR
        assert policy.identities["charlie@example.com"] == Role.READER
        assert policy.default_role == Role.READER

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_policy_from_file(tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "rbac.yaml"
        policy_file.write_text("not a valid: dict: nested: bad", encoding="utf-8")
        with pytest.raises(ValueError):
            load_policy_from_file(policy_file)

    def test_invalid_role_value_raises(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "rbac.yaml"
        policy_file.write_text(
            "identities:\n  alice@example.com: superuser\ndefault_role: reader\n",
            encoding="utf-8",
        )
        # Pydantic validation rejects "superuser" as not in Role enum.
        with pytest.raises(ValueError):
            load_policy_from_file(policy_file)


class TestRBACDependency:
    """The require_role() FastAPI dependency factory."""

    def test_default_policy_allows_all(self) -> None:
        """No policy file + no env var → permissive default → all
        actions allowed for any identity."""
        from evidentia_api.app import create_app
        from fastapi.testclient import TestClient

        app = create_app()
        client = TestClient(app)
        # Hit a known-existing endpoint to confirm no 403 from RBAC.
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_deny_policy_returns_403_via_dependency(self, tmp_path: Path) -> None:
        """End-to-end: standalone FastAPI app w/ deny-by-default
        policy + require_role("write") dependency returns 403 for
        anonymous + unknown identities.

        Uses an isolated FastAPI app rather than create_app() to
        sidestep the SPA static-mount catch-all that lives at the
        tail of create_app().
        """
        from evidentia_api.rbac_dependency import require_role
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        policy_file = tmp_path / "rbac.yaml"
        policy_file.write_text(
            "identities:\n  alice@example.com: editor\ndefault_role: deny\n",
            encoding="utf-8",
        )
        policy = load_policy_from_file(policy_file)

        app = FastAPI()
        app.state.rbac_policy = policy

        @app.get("/gated-test", dependencies=[require_role("write")])
        def gated_endpoint() -> dict[str, str]:
            return {"ok": "yes"}

        client = TestClient(app)
        # No identity → anonymous → default role is deny → 403.
        resp = client.get("/gated-test")
        assert resp.status_code == 403
        body = resp.json()
        assert body["detail"]["error"] == "rbac_denied"
        assert body["detail"]["action"] == "write"


# ── v0.9.8 P1.4 — Multi-tenant RBAC FastAPI integration ──────────


class TestRBACDependencyMultiTenant:
    """v0.9.8 P1.4 multi-tenant dispatch closes F-V97-multi-tenant-claim-spoofing.

    The dependency reads identity from ``request.state.auth_principal``
    (set by :class:`AuthProviderMiddleware`). The principal's
    ``@@<tenant>`` suffix carries the tenant claim — provenance is
    end-to-end from authenticated credential to RBAC decision,
    bypassing any env-var / header injection.
    """

    def _build_multi_tenant_policy(self, tmp_path: Path) -> Any:
        from evidentia_core.rbac import load_multi_tenant_policy_from_file

        policy_file = tmp_path / "multi.yaml"
        policy_file.write_text(
            "tenants:\n"
            "  acme-corp:\n"
            "    identities:\n"
            "      alice@example.com: editor\n"
            "    default_role: deny\n"
            "  globex:\n"
            "    identities:\n"
            "      bob@example.com: editor\n"
            "    default_role: deny\n"
            "default_tenant: acme-corp\n",
            encoding="utf-8",
        )
        return load_multi_tenant_policy_from_file(policy_file)

    def _build_gated_app(self, policy: Any, principal: str | None) -> Any:
        """Standalone FastAPI app that stubs the auth principal.

        Inserts a lightweight middleware (rather than the real
        AuthProviderMiddleware) that sets ``request.state.auth_principal``
        to the supplied value. Keeps the test focused on the RBAC
        dispatch path; AuthProviderMiddleware itself has its own
        coverage.
        """
        from evidentia_api.rbac_dependency import require_role
        from fastapi import FastAPI, Request

        app = FastAPI()
        app.state.rbac_policy = policy

        @app.middleware("http")
        async def _inject_principal(request: Request, call_next: Any) -> Any:
            if principal is not None:
                request.state.auth_principal = principal
            return await call_next(request)

        @app.get("/gated", dependencies=[require_role("write")])
        def gated() -> dict[str, str]:
            return {"ok": "yes"}

        return app

    def test_authenticated_in_home_tenant_allowed(self, tmp_path: Path) -> None:
        """alice@example.com@@acme-corp (editor in acme-corp) → 200."""
        from fastapi.testclient import TestClient

        policy = self._build_multi_tenant_policy(tmp_path)
        app = self._build_gated_app(policy, principal="alice@example.com@@acme-corp")
        resp = TestClient(app).get("/gated")
        assert resp.status_code == 200

    def test_authenticated_in_wrong_tenant_denied(self, tmp_path: Path) -> None:
        """alice@example.com@@globex (not editor in globex) → 403."""
        from fastapi.testclient import TestClient

        policy = self._build_multi_tenant_policy(tmp_path)
        app = self._build_gated_app(policy, principal="alice@example.com@@globex")
        resp = TestClient(app).get("/gated")
        assert resp.status_code == 403
        body = resp.json()
        assert body["detail"]["error"] == "rbac_denied"
        # Identity from the principal lands in the error body so
        # operators triage from the response alone.
        assert body["detail"]["identity"] == "alice@example.com@@globex"

    def test_no_claim_falls_through_to_default_tenant(self, tmp_path: Path) -> None:
        """Principal w/o claim resolves to ``default_tenant`` (acme-corp)."""
        from fastapi.testclient import TestClient

        policy = self._build_multi_tenant_policy(tmp_path)
        # alice with NO claim → resolves to acme-corp (default_tenant)
        # → editor in acme-corp → 200.
        app = self._build_gated_app(policy, principal="alice@example.com")
        resp = TestClient(app).get("/gated")
        assert resp.status_code == 200

    def test_anonymous_denied_against_multi_tenant_policy(self, tmp_path: Path) -> None:
        """No auth principal → anonymous → default-tenant default_role=deny → 403."""
        from fastapi.testclient import TestClient

        policy = self._build_multi_tenant_policy(tmp_path)
        app = self._build_gated_app(policy, principal=None)
        resp = TestClient(app).get("/gated")
        assert resp.status_code == 403

    def test_tenant_claim_spoofing_via_header_ignored(self, tmp_path: Path) -> None:
        """Closes F-V97-multi-tenant-claim-spoofing.

        A request header claiming a tenant the principal doesn't
        actually hold is IGNORED — the dependency only reads
        ``request.state.auth_principal``, which the
        AuthProviderMiddleware populated from the validated
        credential. An attacker spoofing ``X-Tenant: acme-corp`` in
        the headers cannot escalate from a globex principal.
        """
        from fastapi.testclient import TestClient

        policy = self._build_multi_tenant_policy(tmp_path)
        # Principal: bob@globex (editor in globex). Header claims acme.
        app = self._build_gated_app(policy, principal="bob@example.com@@globex")
        client = TestClient(app)
        # Spoofing header is silently ignored — bob is editor in
        # globex, so request to write succeeds based on the principal.
        resp = client.get("/gated", headers={"X-Tenant": "acme-corp"})
        assert resp.status_code == 200
        # bob is NOT editor in acme-corp, but the spoof header is
        # ignored — the actual tenant is bob's authenticated claim
        # (globex), where bob IS editor.

    def test_single_tenant_policy_ignores_tenant_claims(self, tmp_path: Path) -> None:
        """Backward compat — single-tenant policy treats principal as plain string.

        A principal with ``@@<tenant>`` suffix against a single-tenant
        policy uses the entire string as the identity. The v0.9.5
        :func:`check_permission` looks up the FULL string in the
        identities map; misses → ``default_role``.
        """
        from evidentia_api.rbac_dependency import require_role
        from fastapi import FastAPI, Request
        from fastapi.testclient import TestClient

        policy_file = tmp_path / "single.yaml"
        # Single-tenant policy w/ alice as editor.
        policy_file.write_text(
            "identities:\n  alice@example.com: editor\ndefault_role: deny\n",
            encoding="utf-8",
        )
        policy = load_policy_from_file(policy_file)

        app = FastAPI()
        app.state.rbac_policy = policy

        @app.middleware("http")
        async def _inject(request: Request, call_next: Any) -> Any:
            # Principal w/ embedded tenant claim — single-tenant
            # dispatch treats the full string as identity → miss →
            # default_role=deny → 403.
            request.state.auth_principal = "alice@example.com@@acme-corp"
            return await call_next(request)

        @app.get("/gated", dependencies=[require_role("write")])
        def gated() -> dict[str, str]:
            return {"ok": "yes"}

        resp = TestClient(app).get("/gated")
        # Single-tenant policy doesn't strip ``@@<tenant>`` — the
        # principal "alice@example.com@@acme-corp" is treated as a
        # distinct identity from "alice@example.com" → deny.
        assert resp.status_code == 403


# ── v0.9.8 P1.4 — create_app multi-tenant policy auto-detection ───


class TestCreateAppPolicyAutoDetection:
    """F-V98-02: create_app() must auto-detect a multi-tenant policy file.

    Before the fix, app.py loaded the RBAC policy only via
    load_policy_from_file (always single-tenant), so a multi-tenant
    policy file silently degraded to single-tenant on the REST surface.
    """

    def test_multi_tenant_policy_file_loads_as_tenant_policy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from evidentia_api.app import create_app
        from evidentia_core.rbac import TenantRBACPolicy

        policy_file = tmp_path / "multi.yaml"
        policy_file.write_text(
            "tenants:\n"
            "  acme-corp:\n"
            "    identities:\n"
            "      alice@example.com: admin\n"
            "    default_role: deny\n"
            "default_tenant: acme-corp\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))
        app = create_app()
        assert isinstance(app.state.rbac_policy, TenantRBACPolicy)

    def test_single_tenant_policy_file_loads_as_rbac_policy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from evidentia_api.app import create_app
        from evidentia_core.rbac import RBACPolicy, TenantRBACPolicy

        policy_file = tmp_path / "single.yaml"
        policy_file.write_text(
            "identities:\n  alice@example.com: admin\ndefault_role: reader\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))
        app = create_app()
        assert isinstance(app.state.rbac_policy, RBACPolicy)
        assert not isinstance(app.state.rbac_policy, TenantRBACPolicy)
