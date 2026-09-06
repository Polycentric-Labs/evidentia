"""Unit + smoke tests for the CLI RBAC mirror (v0.9.6 P1).

Coverage:

- :mod:`evidentia.cli._rbac_lifecycle` — process-lifetime singletons
  for policy + identity resolution.
- :mod:`evidentia.cli._rbac` — ``require_role_cli`` decorator
  behavior on allow / deny / unknown-action / env-var precedence.
- ``evidentia --rbac-identity`` global flag wiring through the
  Typer ``@app.callback()`` (smoke test via :class:`CliRunner`).
- ``conmon check`` flag normalization (``--state-file`` canonical;
  ``--last-completed-file`` deprecated with ``DeprecationWarning``).
"""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest
import typer
from evidentia_core.rbac import RBACPolicy, Role
from typer.testing import CliRunner


@pytest.fixture(autouse=True)
def _clean_rbac_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset the process-lifetime singletons + env vars per test.

    The ``_rbac_lifecycle`` module caches the loaded policy +
    identity override for the process lifetime. Tests that
    parameterize policy state need a clean slate per case.
    """
    monkeypatch.delenv("EVIDENTIA_RBAC_POLICY_FILE", raising=False)
    monkeypatch.delenv("EVIDENTIA_RBAC_IDENTITY", raising=False)
    monkeypatch.delenv("EVIDENTIA_RBAC_TENANT", raising=False)

    from evidentia.cli._rbac_lifecycle import _reset_rbac_cache

    _reset_rbac_cache()
    yield
    _reset_rbac_cache()


# ── lifecycle module ────────────────────────────────────────────────


class TestLifecyclePolicy:
    """Tests for :func:`get_rbac_policy` cache + env-var resolution."""

    def test_default_policy_when_env_unset(self) -> None:
        from evidentia.cli._rbac_lifecycle import (
            get_rbac_policy,
        )
        from evidentia_core.rbac import DEFAULT_POLICY

        assert get_rbac_policy() is DEFAULT_POLICY

    def test_loads_file_when_env_set(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "identities:\n  alice@example.com: admin\n  bob@example.com: editor\ndefault_role: reader\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))

        from evidentia.cli._rbac_lifecycle import get_rbac_policy

        policy = get_rbac_policy()
        assert isinstance(policy, RBACPolicy)
        assert policy.role_for("alice@example.com") == Role.ADMIN
        assert policy.role_for("bob@example.com") == Role.EDITOR
        assert policy.role_for("eve@example.com") == Role.READER

    def test_cache_returns_same_instance(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("identities: {}\ndefault_role: reader\n", encoding="utf-8")
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))

        from evidentia.cli._rbac_lifecycle import get_rbac_policy

        first = get_rbac_policy()
        # Mutate the underlying file; cached instance MUST be unchanged.
        policy_file.write_text("identities: {}\ndefault_role: admin\n", encoding="utf-8")
        second = get_rbac_policy()
        assert first is second
        assert second.default_role == Role.READER

    def test_missing_file_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setenv(
            "EVIDENTIA_RBAC_POLICY_FILE",
            str(tmp_path / "does-not-exist.yaml"),
        )

        from evidentia.cli._rbac_lifecycle import get_rbac_policy

        with pytest.raises(FileNotFoundError):
            get_rbac_policy()

    def test_malformed_file_raises_value_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("not: valid: yaml: at: all\n", encoding="utf-8")
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))

        from evidentia.cli._rbac_lifecycle import get_rbac_policy

        with pytest.raises(ValueError, match="not valid YAML/JSON"):
            get_rbac_policy()


class TestLifecycleIdentity:
    """Tests for :func:`get_rbac_identity` precedence rules."""

    def test_returns_none_when_unset(self) -> None:
        from evidentia.cli._rbac_lifecycle import get_rbac_identity

        assert get_rbac_identity() is None

    def test_returns_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "alice@example.com")

        from evidentia.cli._rbac_lifecycle import get_rbac_identity

        assert get_rbac_identity() == "alice@example.com"

    def test_override_wins_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "env-identity")

        from evidentia.cli._rbac_lifecycle import (
            get_rbac_identity,
            set_rbac_identity_override,
        )

        set_rbac_identity_override("flag-identity")
        assert get_rbac_identity() == "flag-identity"

    def test_override_none_falls_back_to_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "env-identity")

        from evidentia.cli._rbac_lifecycle import (
            get_rbac_identity,
            set_rbac_identity_override,
        )

        set_rbac_identity_override("flag-identity")
        assert get_rbac_identity() == "flag-identity"
        # Clearing the override exposes the env var again.
        set_rbac_identity_override(None)
        assert get_rbac_identity() == "env-identity"

    def test_empty_env_treated_as_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "")

        from evidentia.cli._rbac_lifecycle import get_rbac_identity

        assert get_rbac_identity() is None


# ── v0.9.8 P1.3 — Multi-tenant lifecycle + decision dispatch ──────


class TestLifecycleTenant:
    """v0.9.8 P1.3 tenant resolution mirrors the identity precedence rules."""

    def test_returns_none_when_unset(self) -> None:
        from evidentia.cli._rbac_lifecycle import get_rbac_tenant

        assert get_rbac_tenant() is None

    def test_returns_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EVIDENTIA_RBAC_TENANT", "acme-corp")

        from evidentia.cli._rbac_lifecycle import get_rbac_tenant

        assert get_rbac_tenant() == "acme-corp"

    def test_override_wins_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EVIDENTIA_RBAC_TENANT", "env-tenant")

        from evidentia.cli._rbac_lifecycle import (
            get_rbac_tenant,
            set_rbac_tenant_override,
        )

        set_rbac_tenant_override("flag-tenant")
        assert get_rbac_tenant() == "flag-tenant"

    def test_combined_identity_no_tenant_returns_identity(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No tenant override + plain identity → identity passes through."""
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "alice@example.com")

        from evidentia.cli._rbac_lifecycle import (
            get_rbac_identity_with_tenant_claim,
        )

        assert get_rbac_identity_with_tenant_claim() == "alice@example.com"

    def test_combined_identity_with_tenant_appends_claim(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Tenant override + plain identity → ``alice@example.com@@acme-corp``."""
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "alice@example.com")
        monkeypatch.setenv("EVIDENTIA_RBAC_TENANT", "acme-corp")

        from evidentia.cli._rbac_lifecycle import (
            get_rbac_identity_with_tenant_claim,
        )

        assert get_rbac_identity_with_tenant_claim() == "alice@example.com@@acme-corp"

    def test_combined_matching_embedded_and_override_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Embedded claim + override agree → passes through."""
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "alice@example.com@@acme-corp")
        monkeypatch.setenv("EVIDENTIA_RBAC_TENANT", "acme-corp")

        from evidentia.cli._rbac_lifecycle import (
            get_rbac_identity_with_tenant_claim,
        )

        assert get_rbac_identity_with_tenant_claim() == "alice@example.com@@acme-corp"

    def test_combined_conflicting_claims_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Embedded ``@@acme`` + override ``globex`` → ValueError."""
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "alice@example.com@@acme-corp")
        monkeypatch.setenv("EVIDENTIA_RBAC_TENANT", "globex")

        from evidentia.cli._rbac_lifecycle import (
            get_rbac_identity_with_tenant_claim,
        )

        with pytest.raises(ValueError, match="Conflicting tenant"):
            get_rbac_identity_with_tenant_claim()

    def test_combined_no_identity_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No identity + tenant set → still anonymous (None)."""
        monkeypatch.setenv("EVIDENTIA_RBAC_TENANT", "acme-corp")
        # No EVIDENTIA_RBAC_IDENTITY.

        from evidentia.cli._rbac_lifecycle import (
            get_rbac_identity_with_tenant_claim,
        )

        assert get_rbac_identity_with_tenant_claim() is None


class TestLifecycleMultiTenantPolicyDetection:
    """:func:`get_rbac_policy` auto-detects single vs multi-tenant YAML."""

    def test_single_tenant_yaml_loads_as_rbac_policy(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from evidentia_core.rbac import RBACPolicy

        policy_file = tmp_path / "single.yaml"
        policy_file.write_text(
            "identities:\n  alice@example.com: admin\ndefault_role: reader\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))

        from evidentia.cli._rbac_lifecycle import get_rbac_policy

        policy = get_rbac_policy()
        assert isinstance(policy, RBACPolicy)

    def test_multi_tenant_yaml_loads_as_tenant_policy(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from evidentia_core.rbac import TenantRBACPolicy

        policy_file = tmp_path / "multi.yaml"
        policy_file.write_text(
            "tenants:\n"
            "  acme-corp:\n"
            "    identities:\n"
            "      alice@example.com: admin\n"
            "    default_role: reader\n"
            "default_tenant: acme-corp\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))

        from evidentia.cli._rbac_lifecycle import get_rbac_policy

        policy = get_rbac_policy()
        assert isinstance(policy, TenantRBACPolicy)
        assert policy.default_tenant == "acme-corp"


class TestRequireRoleCLIMultiTenant:
    """``require_role_cli`` dispatches multi-tenant when policy demands."""

    def _wire_multi_tenant_policy(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        policy_file = tmp_path / "multi.yaml"
        policy_file.write_text(
            "tenants:\n"
            "  acme-corp:\n"
            "    identities:\n"
            "      alice@example.com: admin\n"
            "    default_role: deny\n"
            "  globex:\n"
            "    identities:\n"
            "      bob@example.com: editor\n"
            "    default_role: deny\n"
            "default_tenant: acme-corp\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))

    def test_alice_admin_in_acme_via_tenant_flag(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """alice@example.com w/ --rbac-tenant=acme-corp → admin granted."""
        self._wire_multi_tenant_policy(tmp_path, monkeypatch)
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "alice@example.com")
        monkeypatch.setenv("EVIDENTIA_RBAC_TENANT", "acme-corp")

        from evidentia.cli._rbac import require_role_cli

        called = []

        @require_role_cli("admin")
        def _action() -> str:
            called.append(1)
            return "ok"

        result = _action()
        assert result == "ok"
        assert called == [1]

    def test_alice_denied_in_globex_via_tenant_flag(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """alice@example.com w/ --rbac-tenant=globex → denied (not in globex)."""
        self._wire_multi_tenant_policy(tmp_path, monkeypatch)
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "alice@example.com")
        monkeypatch.setenv("EVIDENTIA_RBAC_TENANT", "globex")

        from evidentia.cli._rbac import require_role_cli

        @require_role_cli("write")
        def _action() -> str:
            return "ok"

        with pytest.raises(typer.Exit) as exc_info:
            _action()
        assert exc_info.value.exit_code == 77  # EXIT_CODE_RBAC_DENIED

    def test_embedded_claim_works_without_flag(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Identity-embedded claim works without --rbac-tenant."""
        self._wire_multi_tenant_policy(tmp_path, monkeypatch)
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "bob@example.com@@globex")

        from evidentia.cli._rbac import require_role_cli

        @require_role_cli("write")
        def _action() -> str:
            return "ok"

        # bob is editor in globex → write granted.
        assert _action() == "ok"

    def test_conflicting_claims_exit_with_config_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Embedded ``@@acme`` + ``--rbac-tenant globex`` exits 77."""
        self._wire_multi_tenant_policy(tmp_path, monkeypatch)
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "alice@example.com@@acme-corp")
        monkeypatch.setenv("EVIDENTIA_RBAC_TENANT", "globex")

        from evidentia.cli._rbac import require_role_cli

        @require_role_cli("read")
        def _action() -> str:
            return "ok"

        with pytest.raises(typer.Exit) as exc_info:
            _action()
        assert exc_info.value.exit_code == 77

    def test_single_tenant_policy_ignores_tenant_flag(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Single-tenant policy + --rbac-tenant set → v0.9.6 behavior."""
        policy_file = tmp_path / "single.yaml"
        policy_file.write_text(
            "identities:\n  alice@example.com: admin\ndefault_role: reader\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "alice@example.com")
        # Tenant flag is set but should be IGNORED — single-tenant policy
        # dispatches through the v0.9.5 check_permission path.
        monkeypatch.setenv("EVIDENTIA_RBAC_TENANT", "acme-corp")

        from evidentia.cli._rbac import require_role_cli

        @require_role_cli("admin")
        def _action() -> str:
            return "ok"

        # alice is admin in the single-tenant policy → granted.
        # The tenant flag has no effect.
        assert _action() == "ok"


class TestLifecycleReset:
    def test_reset_clears_cache(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("identities: {}\ndefault_role: reader\n", encoding="utf-8")
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))

        from evidentia.cli._rbac_lifecycle import (
            _reset_rbac_cache,
            get_rbac_policy,
        )

        first = get_rbac_policy()
        _reset_rbac_cache()
        # Rewrite file post-reset; second load picks up new contents.
        policy_file.write_text("identities: {}\ndefault_role: admin\n", encoding="utf-8")
        second = get_rbac_policy()
        assert first is not second
        assert second.default_role == Role.ADMIN

    def test_reset_clears_override(self) -> None:
        from evidentia.cli._rbac_lifecycle import (
            _reset_rbac_cache,
            get_rbac_identity,
            set_rbac_identity_override,
        )

        set_rbac_identity_override("temp")
        assert get_rbac_identity() == "temp"
        _reset_rbac_cache()
        assert get_rbac_identity() is None


# ── decorator module ────────────────────────────────────────────────


class TestDecoratorActionValidation:
    def test_unknown_action_raises_keyerror_at_decoration(self) -> None:
        from evidentia.cli._rbac import require_role_cli

        with pytest.raises(KeyError):
            require_role_cli("wirte")  # typo on purpose

    def test_known_actions_decorate_cleanly(self) -> None:
        from evidentia.cli._rbac import require_role_cli

        # No exception raised = pass.
        require_role_cli("read")
        require_role_cli("write")
        require_role_cli("admin")


class TestDecoratorAllowPath:
    def test_admin_default_allows_all_actions(self) -> None:
        from evidentia.cli._rbac import require_role_cli

        @require_role_cli("write")
        def cmd() -> str:
            return "ok"

        assert cmd() == "ok"

    def test_identity_via_env_allows(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "identities:\n  alice@example.com: editor\ndefault_role: deny\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "alice@example.com")

        from evidentia.cli._rbac import require_role_cli

        @require_role_cli("write")
        def cmd() -> int:
            return 42

        assert cmd() == 42

    def test_reader_can_read(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "identities:\n  bob@example.com: reader\ndefault_role: deny\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "bob@example.com")

        from evidentia.cli._rbac import require_role_cli

        @require_role_cli("read")
        def cmd() -> str:
            return "ok"

        assert cmd() == "ok"

    def test_wrapped_function_preserves_args_and_returns(self) -> None:
        from evidentia.cli._rbac import require_role_cli

        @require_role_cli("read")
        def add(a: int, b: int = 5) -> int:
            return a + b

        assert add(3) == 8
        assert add(3, b=7) == 10


class TestDecoratorDenyPath:
    def test_reader_denied_write(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "identities:\n  alice@example.com: reader\ndefault_role: deny\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "alice@example.com")

        from evidentia.cli._rbac import (
            EXIT_CODE_RBAC_DENIED,
            require_role_cli,
        )

        @require_role_cli("write")
        def cmd() -> None:
            raise AssertionError("must not be called")

        with pytest.raises(typer.Exit) as exc_info:
            cmd()
        assert exc_info.value.exit_code == EXIT_CODE_RBAC_DENIED

        captured = capsys.readouterr()
        # Permission-denied message goes to stderr, references the action
        # + identity, and gives a remediation hint.
        assert "Permission denied" in captured.err
        assert "write" in captured.err
        assert "alice@example.com" in captured.err
        assert "EVIDENTIA_RBAC_POLICY_FILE" in captured.err

    def test_anonymous_with_deny_default(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("identities: {}\ndefault_role: deny\n", encoding="utf-8")
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))
        # No EVIDENTIA_RBAC_IDENTITY set → anonymous.

        from evidentia.cli._rbac import (
            EXIT_CODE_RBAC_DENIED,
            require_role_cli,
        )

        @require_role_cli("read")
        def cmd() -> None:
            raise AssertionError("must not be called")

        with pytest.raises(typer.Exit) as exc_info:
            cmd()
        assert exc_info.value.exit_code == EXIT_CODE_RBAC_DENIED

        captured = capsys.readouterr()
        assert "anonymous" in captured.err

    def test_editor_denied_admin(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "identities:\n  carol@example.com: editor\ndefault_role: deny\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "carol@example.com")

        from evidentia.cli._rbac import (
            EXIT_CODE_RBAC_DENIED,
            require_role_cli,
        )

        @require_role_cli("admin")
        def cmd() -> None:
            raise AssertionError("must not be called")

        with pytest.raises(typer.Exit) as exc_info:
            cmd()
        assert exc_info.value.exit_code == EXIT_CODE_RBAC_DENIED


class TestDecoratorIdentityPrecedence:
    def test_override_wins_over_env(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "identities:\n  env-id: reader\n  flag-id: editor\ndefault_role: deny\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "env-id")

        from evidentia.cli._rbac import require_role_cli
        from evidentia.cli._rbac_lifecycle import (
            set_rbac_identity_override,
        )

        set_rbac_identity_override("flag-id")

        @require_role_cli("write")
        def cmd() -> str:
            return "ok"

        # flag-id (editor) > env-id (reader), so write is allowed.
        assert cmd() == "ok"


# ── CLI integration (CliRunner) ─────────────────────────────────────


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class TestGlobalRbacIdentityFlag:
    """Smoke tests for the ``--rbac-identity`` global flag wiring."""

    def test_global_flag_sets_override(self, runner: CliRunner) -> None:
        from evidentia.cli._rbac_lifecycle import _reset_rbac_cache
        from evidentia.cli.main import app

        _reset_rbac_cache()
        result = runner.invoke(app, ["--rbac-identity", "alice@example.com", "version"])
        assert result.exit_code == 0
        # The override is process-lifetime — observe it post-invoke.
        from evidentia.cli._rbac_lifecycle import get_rbac_identity

        assert get_rbac_identity() == "alice@example.com"

    def test_no_global_flag_leaves_override_none(self, runner: CliRunner) -> None:
        from evidentia.cli._rbac_lifecycle import (
            _reset_rbac_cache,
            get_rbac_identity,
        )
        from evidentia.cli.main import app

        _reset_rbac_cache()
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert get_rbac_identity() is None


# ── conmon check flag normalization ─────────────────────────────────


@pytest.fixture()
def state_file(tmp_path: Path) -> Path:
    """Minimal valid state file for `conmon check`."""
    sf = tmp_path / "state.yaml"
    sf.write_text("nist-800-53-rev5-ca7: 2026-04-01\n", encoding="utf-8")
    return sf


class TestConmonCheckFlagNormalization:
    def test_canonical_state_file_works(self, runner: CliRunner, state_file: Path) -> None:
        from evidentia.cli.main import app

        result = runner.invoke(app, ["conmon", "check", "--state-file", str(state_file)])
        # Exit 0 (or 1 if cycle overdue; check it's not the new exit-2
        # for "missing required flag" or "both flags set").
        assert result.exit_code in (0, 1), result.output

    def test_deprecated_flag_still_works(
        self,
        runner: CliRunner,
        state_file: Path,
    ) -> None:
        from evidentia.cli.main import app

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = runner.invoke(
                app,
                [
                    "conmon",
                    "check",
                    "--last-completed-file",
                    str(state_file),
                ],
            )
        assert result.exit_code in (0, 1), result.output
        # CliRunner may or may not surface warnings depending on
        # pytest warning filters. We confirm the flag is at least
        # accepted (didn't exit-2 with "missing required"). The
        # explicit DeprecationWarning emission is verified directly
        # via the function-call path in TestConmonCheckDeprecation.

    def test_both_flags_set_errors_exit_2(
        self,
        runner: CliRunner,
        state_file: Path,
    ) -> None:
        from evidentia.cli.main import app

        result = runner.invoke(
            app,
            [
                "conmon",
                "check",
                "--state-file",
                str(state_file),
                "--last-completed-file",
                str(state_file),
            ],
        )
        assert result.exit_code == 2
        assert "cannot specify both" in result.output.lower()

    def test_neither_flag_set_errors_exit_2(self, runner: CliRunner) -> None:
        from evidentia.cli.main import app

        result = runner.invoke(app, ["conmon", "check"])
        assert result.exit_code == 2
        assert "--state-file is required" in result.output.lower()


class TestConmonCheckDeprecation:
    """Direct-call test verifying the DeprecationWarning emission.

    CliRunner mediation can swallow warnings depending on pytest
    config. We call the underlying function directly so the
    warnings filter behaves predictably under ``pytest -W error``.
    """

    def test_deprecation_warning_emitted_with_old_flag(
        self,
        state_file: Path,
    ) -> None:
        from evidentia.cli.conmon import conmon_check

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                conmon_check(
                    state_file=None,
                    last_completed_file=state_file,
                    today_override="2026-05-18",
                    window_days=14,
                    output_json=True,
                    evidence_store=None,
                )
            except SystemExit:
                # Function may exit with audit-event-emit side effects
                # under some configurations; only the warning matters.
                pass
            except typer.Exit:
                pass

        dep_warns = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(dep_warns) >= 1
        assert "--last-completed-file is deprecated" in str(dep_warns[0].message)
