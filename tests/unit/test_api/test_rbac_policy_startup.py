"""The API fails closed when EVIDENTIA_RBAC_POLICY_FILE cannot be loaded (v0.13.0 review H1).

Before v0.13.0 an unloadable policy file logged one line and fell back to
the permissive default, which maps every identity to admin. The CLI
already refused to run in the same situation; the API now does too.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("EVIDENTIA_SKIP_FRONTEND_BUILD", "1")
    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(tmp_path / "gap_store"))
    monkeypatch.chdir(tmp_path)


def test_missing_policy_file_refuses_to_start(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(tmp_path / "missing-policy.yaml"))
    from evidentia_api.app import create_app

    with pytest.raises(RuntimeError, match="EVIDENTIA_RBAC_POLICY_FILE is set but the policy could not be loaded"):
        create_app()


def test_malformed_policy_file_refuses_to_start(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("identities: [not, a, mapping\n", encoding="utf-8")
    monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))
    from evidentia_api.app import create_app

    with pytest.raises(RuntimeError, match="could not be loaded"):
        create_app()


def test_valid_policy_file_is_honoured(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("identities: {}\ndefault_role: reader\n", encoding="utf-8")
    monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy_file))
    from evidentia_api.app import create_app
    from evidentia_core.rbac import RBACPolicy, Role

    app = create_app()
    policy = app.state.rbac_policy
    assert isinstance(policy, RBACPolicy)
    assert policy.default_role == Role.READER


def test_unset_variable_keeps_the_default_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("EVIDENTIA_RBAC_POLICY_FILE", raising=False)
    from evidentia_api.app import create_app
    from evidentia_core.rbac import DEFAULT_POLICY

    app = create_app()
    assert app.state.rbac_policy is DEFAULT_POLICY
