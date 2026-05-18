"""Unit tests for evidentia_core.rbac (v0.9.5 P3.3)."""

from __future__ import annotations

from pathlib import Path

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
        assert check_permission(
            "reader@example.com", "read", policy=policy
        ) is True
        assert check_permission(
            "reader@example.com", "write", policy=policy
        ) is False
        assert check_permission(
            "reader@example.com", "admin", policy=policy
        ) is False

    def test_editor_can_write_but_not_admin(self) -> None:
        policy = RBACPolicy(
            identities={"editor@example.com": Role.EDITOR},
            default_role=Role.DENY,
        )
        assert check_permission(
            "editor@example.com", "read", policy=policy
        ) is True
        assert check_permission(
            "editor@example.com", "write", policy=policy
        ) is True
        assert check_permission(
            "editor@example.com", "admin", policy=policy
        ) is False

    def test_deny_role_blocks_everything(self) -> None:
        policy = RBACPolicy(
            identities={"banned@example.com": Role.DENY},
            default_role=Role.READER,
        )
        assert check_permission(
            "banned@example.com", "read", policy=policy
        ) is False

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
            "identities:\n"
            "  alice@example.com: superuser\n"
            "default_role: reader\n",
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

    def test_deny_policy_returns_403_via_dependency(
        self, tmp_path: Path
    ) -> None:
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
            "identities:\n"
            "  alice@example.com: editor\n"
            "default_role: deny\n",
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
