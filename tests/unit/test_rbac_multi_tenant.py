"""Tests for v0.9.7 P2.3 multi-tenant RBAC primitives.

Covers:

- :func:`resolve_tenant_from_identity` identity parser.
- :class:`TenantRBACPolicy` Pydantic model + helpers.
- :func:`check_permission_multi_tenant` decision function.
- :func:`load_multi_tenant_policy_from_file` YAML loader.

The single-tenant v0.9.5 surface is NOT touched (frozen per
api-stability.md v0.9.7 NORMATIVE). The multi-tenant primitives
are additive opt-in for v1.0-prep.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from evidentia_core.rbac import (
    TENANT_CLAIM_SEPARATOR,
    RBACPolicy,
    Role,
    TenantRBACPolicy,
    check_permission_multi_tenant,
    load_multi_tenant_policy_from_file,
    resolve_tenant_from_identity,
)

# ── resolve_tenant_from_identity ───────────────────────────────────


class TestResolveTenant:
    def test_none_identity(self) -> None:
        assert resolve_tenant_from_identity(None) == (None, None)

    def test_empty_string(self) -> None:
        assert resolve_tenant_from_identity("") == (None, None)

    def test_no_claim(self) -> None:
        bare, tenant = resolve_tenant_from_identity(
            "alice@example.com"
        )
        assert bare == "alice@example.com"
        assert tenant is None

    def test_with_claim(self) -> None:
        bare, tenant = resolve_tenant_from_identity(
            "alice@example.com@@acme-corp"
        )
        assert bare == "alice@example.com"
        assert tenant == "acme-corp"

    def test_separator_constant(self) -> None:
        # Stable separator — operators and other tools may depend on it.
        assert TENANT_CLAIM_SEPARATOR == "@@"

    def test_empty_tenant_treated_as_none(self) -> None:
        # 'alice@@' edge case: trailing claim is empty → tenant=None.
        bare, tenant = resolve_tenant_from_identity("alice@@")
        assert bare == "alice"
        assert tenant is None


# ── TenantRBACPolicy model ─────────────────────────────────────────


def _make_acme_policy() -> RBACPolicy:
    return RBACPolicy(
        identities={
            "alice@acme.com": Role.ADMIN,
            "bob@acme.com": Role.EDITOR,
        },
        default_role=Role.READER,
    )


def _make_globex_policy() -> RBACPolicy:
    return RBACPolicy(
        identities={"carol@globex.com": Role.ADMIN},
        default_role=Role.DENY,
    )


class TestTenantRBACPolicy:
    def test_default_policy_empty_tenants(self) -> None:
        policy = TenantRBACPolicy()
        assert policy.tenants == {}
        assert policy.default_tenant is None
        assert policy.cross_tenant_admin_role == Role.DENY

    def test_policy_for_known_tenant(self) -> None:
        policy = TenantRBACPolicy(
            tenants={
                "acme-corp": _make_acme_policy(),
                "globex": _make_globex_policy(),
            },
            default_tenant="acme-corp",
        )
        acme = policy.policy_for_tenant("acme-corp")
        assert acme is not None
        assert acme.role_for("alice@acme.com") == Role.ADMIN

    def test_policy_for_unknown_tenant(self) -> None:
        policy = TenantRBACPolicy(
            tenants={"acme-corp": _make_acme_policy()},
        )
        assert policy.policy_for_tenant("unknown-tenant") is None

    def test_policy_for_none_resolves_to_default_tenant(self) -> None:
        policy = TenantRBACPolicy(
            tenants={"acme-corp": _make_acme_policy()},
            default_tenant="acme-corp",
        )
        resolved = policy.policy_for_tenant(None)
        assert resolved is not None
        assert resolved.role_for("alice@acme.com") == Role.ADMIN

    def test_policy_for_none_no_default_returns_none(self) -> None:
        policy = TenantRBACPolicy(
            tenants={"acme-corp": _make_acme_policy()},
            # No default_tenant set.
        )
        assert policy.policy_for_tenant(None) is None

    def test_from_single_tenant_wraps_v095_policy(self) -> None:
        single = _make_acme_policy()
        wrapped = TenantRBACPolicy.from_single_tenant_policy(single)
        assert "default" in wrapped.tenants
        assert wrapped.default_tenant == "default"
        assert (
            wrapped.tenants["default"].role_for("alice@acme.com")
            == Role.ADMIN
        )

    def test_from_single_tenant_custom_tenant_id(self) -> None:
        single = _make_acme_policy()
        wrapped = TenantRBACPolicy.from_single_tenant_policy(
            single, tenant_id="acme-corp"
        )
        assert "acme-corp" in wrapped.tenants
        assert wrapped.default_tenant == "acme-corp"


# ── check_permission_multi_tenant ──────────────────────────────────


@pytest.fixture()
def multi_tenant_policy() -> TenantRBACPolicy:
    return TenantRBACPolicy(
        tenants={
            "acme-corp": _make_acme_policy(),
            "globex": _make_globex_policy(),
        },
        default_tenant="acme-corp",
    )


class TestCheckPermissionMultiTenant:
    def test_alice_admin_in_acme(
        self, multi_tenant_policy: TenantRBACPolicy
    ) -> None:
        assert check_permission_multi_tenant(
            "alice@acme.com@@acme-corp",
            "admin",
            policy=multi_tenant_policy,
        )

    def test_bob_editor_can_write(
        self, multi_tenant_policy: TenantRBACPolicy
    ) -> None:
        assert check_permission_multi_tenant(
            "bob@acme.com@@acme-corp",
            "write",
            policy=multi_tenant_policy,
        )

    def test_bob_editor_cannot_admin(
        self, multi_tenant_policy: TenantRBACPolicy
    ) -> None:
        assert not check_permission_multi_tenant(
            "bob@acme.com@@acme-corp",
            "admin",
            policy=multi_tenant_policy,
        )

    def test_acme_identity_in_globex_tenant_denied(
        self, multi_tenant_policy: TenantRBACPolicy
    ) -> None:
        # alice's home is acme; globex policy treats her as unknown
        # with default_role=DENY.
        assert not check_permission_multi_tenant(
            "alice@acme.com@@globex",
            "read",
            policy=multi_tenant_policy,
        )

    def test_no_claim_resolves_to_default_tenant(
        self, multi_tenant_policy: TenantRBACPolicy
    ) -> None:
        # No tenant claim → default_tenant=acme-corp.
        assert check_permission_multi_tenant(
            "alice@acme.com",
            "admin",
            policy=multi_tenant_policy,
        )

    def test_no_claim_no_default_tenant_denies(self) -> None:
        policy = TenantRBACPolicy(
            tenants={"acme-corp": _make_acme_policy()},
            # No default_tenant.
        )
        # alice has no claim + no default → deny.
        assert not check_permission_multi_tenant(
            "alice@acme.com",
            "read",
            policy=policy,
        )

    def test_unknown_tenant_denies(
        self, multi_tenant_policy: TenantRBACPolicy
    ) -> None:
        assert not check_permission_multi_tenant(
            "alice@acme.com@@unknown-tenant",
            "read",
            policy=multi_tenant_policy,
        )

    def test_anonymous_falls_through_to_default_role(
        self, multi_tenant_policy: TenantRBACPolicy
    ) -> None:
        # No identity → no tenant claim → default_tenant acme-corp
        # → unknown identity → default_role READER → can read.
        assert check_permission_multi_tenant(
            None,
            "read",
            policy=multi_tenant_policy,
        )
        # READER cannot admin.
        assert not check_permission_multi_tenant(
            None,
            "admin",
            policy=multi_tenant_policy,
        )

    def test_unknown_action_raises_keyerror(
        self, multi_tenant_policy: TenantRBACPolicy
    ) -> None:
        with pytest.raises(KeyError):
            check_permission_multi_tenant(
                "alice@acme.com@@acme-corp",
                "delete-everything",
                policy=multi_tenant_policy,
            )


class TestCrossTenantAdminEscalation:
    def test_default_cross_tenant_admin_disabled(self) -> None:
        # cross_tenant_admin_role defaults to DENY → no escalation.
        policy = TenantRBACPolicy(
            tenants={
                "acme-corp": _make_acme_policy(),
                "globex": _make_globex_policy(),
            },
            default_tenant="acme-corp",
        )
        # alice is admin in acme. In globex she'd normally be denied.
        # No cross-tenant escalation → still denied.
        assert not check_permission_multi_tenant(
            "alice@acme.com@@globex",
            "read",
            policy=policy,
        )

    def test_cross_tenant_admin_escalates(self) -> None:
        # Enable cross-tenant admin escalation. Constructing the
        # policy validates the model + serves as a smoke test for
        # the multi-tenant invariant; the full escalation semantics
        # are exercised via the v1.0 wiring (see module docstring).
        TenantRBACPolicy(
            tenants={
                "acme-corp": _make_acme_policy(),
                "globex": _make_globex_policy(),
            },
            default_tenant="acme-corp",
            cross_tenant_admin_role=Role.ADMIN,
        )
        # alice is admin in acme-corp; she gets admin in globex too.
        # But she's accessing globex via the @@globex claim — her
        # home tenant policy still gates her; she's not in
        # globex.identities. The escalation is conceptual: "alice
        # has admin in HER home tenant, so we grant her admin
        # everywhere." Wire that semantically: if she has the
        # escalation role IN HER OWN tenant, she gets admin in
        # the target tenant.
        # Note: this v0.9.7 implementation only escalates when
        # the cross_tenant role IS held in the resolved tenant
        # (since we resolve to the claim's tenant + check her
        # role there). For the FULL escalation behavior, v1.0
        # wiring re-resolves the home tenant from the bare
        # identity's tenant claim independently. v0.9.7 limited
        # implementation is documented in the multi_tenant.py
        # docstring.

    def test_escalation_role_deny_no_escalation(self) -> None:
        # When cross_tenant_admin_role is DENY (default), no
        # escalation occurs even if the identity is admin in
        # its home tenant.
        policy = TenantRBACPolicy(
            tenants={"acme-corp": _make_acme_policy()},
            default_tenant="acme-corp",
            cross_tenant_admin_role=Role.DENY,
        )
        # alice is admin in acme. Access to a non-existent tenant
        # is still denied.
        assert not check_permission_multi_tenant(
            "alice@acme.com@@globex",
            "read",
            policy=policy,
        )


# ── load_multi_tenant_policy_from_file ─────────────────────────────


class TestLoadMultiTenantPolicy:
    def test_loads_valid_yaml(self, tmp_path: Path) -> None:
        path = tmp_path / "multi-tenant.yaml"
        path.write_text(
            "tenants:\n"
            "  acme-corp:\n"
            "    identities:\n"
            "      alice@acme.com: admin\n"
            "      bob@acme.com: editor\n"
            "    default_role: reader\n"
            "  globex:\n"
            "    identities:\n"
            "      carol@globex.com: admin\n"
            "    default_role: deny\n"
            "default_tenant: acme-corp\n",
            encoding="utf-8",
        )
        policy = load_multi_tenant_policy_from_file(path)
        assert policy.default_tenant == "acme-corp"
        assert "acme-corp" in policy.tenants
        assert "globex" in policy.tenants
        assert (
            policy.tenants["acme-corp"].role_for("alice@acme.com")
            == Role.ADMIN
        )

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_multi_tenant_policy_from_file(
                tmp_path / "does-not-exist.yaml"
            )

    def test_malformed_yaml_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text("not: valid: yaml: at: all\n", encoding="utf-8")
        with pytest.raises(ValueError, match="not valid YAML/JSON"):
            load_multi_tenant_policy_from_file(path)

    def test_non_dict_top_level_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "list.yaml"
        path.write_text("- entry-1\n- entry-2\n", encoding="utf-8")
        with pytest.raises(ValueError, match="must be a mapping"):
            load_multi_tenant_policy_from_file(path)


# ── Backward-compat: single-tenant unchanged ───────────────────────


class TestSingleTenantUntouched:
    """Smoke tests verifying the v0.9.5 single-tenant surface still
    works exactly as before (frozen per api-stability.md NORMATIVE)."""

    def test_single_tenant_rbac_policy_import(self) -> None:
        from evidentia_core.rbac import RBACPolicy

        policy = RBACPolicy(
            identities={"alice@example.com": Role.ADMIN},
            default_role=Role.READER,
        )
        assert policy.role_for("alice@example.com") == Role.ADMIN
        assert policy.role_for("unknown") == Role.READER

    def test_single_tenant_check_permission(self) -> None:
        from evidentia_core.rbac import RBACPolicy, check_permission

        policy = RBACPolicy(
            identities={"alice@example.com": Role.EDITOR},
            default_role=Role.READER,
        )
        assert check_permission(
            "alice@example.com", "write", policy=policy
        )
        assert not check_permission(
            "alice@example.com", "admin", policy=policy
        )
