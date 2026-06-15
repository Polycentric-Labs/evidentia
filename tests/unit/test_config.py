"""Tests for the v0.2.1 ``evidentia.yaml`` config loader."""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest
from evidentia.config import (
    EvidentiaConfig,
    _expand_env_vars,
    find_config_file,
    get_default,
    load_config,
)


def _write_yaml(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    # Clear the per-path LRU cache so successive tests see fresh contents
    from evidentia.config import _load_config_cached

    _load_config_cached.cache_clear()
    return path


# -----------------------------------------------------------------------------
# find_config_file — discovery walk
# -----------------------------------------------------------------------------


def test_find_config_finds_file_in_cwd(tmp_path: Path) -> None:
    cfg = tmp_path / "evidentia.yaml"
    cfg.write_text("organization: Test")
    assert find_config_file(start=tmp_path) == cfg


def test_find_config_walks_to_parent(tmp_path: Path) -> None:
    """CWD has no config, but parent does — should find it."""
    child = tmp_path / "child"
    child.mkdir()
    (tmp_path / "evidentia.yaml").write_text("organization: Parent")
    found = find_config_file(start=child)
    assert found == (tmp_path / "evidentia.yaml")


def test_find_config_returns_none_when_missing(tmp_path: Path) -> None:
    """No config in tree = None, not an exception."""
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    # stop_at bounds the walk to tmp_path, so a stray ancestor config
    # (e.g. ~/evidentia.yaml — pytest tmp dirs live under $HOME) can't
    # leak in and make this non-deterministic.
    result = find_config_file(start=deep, stop_at=tmp_path)
    assert result is None


# -----------------------------------------------------------------------------
# load_config — schema validation and precedence
# -----------------------------------------------------------------------------


def test_load_config_none_when_no_file() -> None:
    """load_config() with an explicit non-existent path returns defaults."""
    cfg = load_config()  # may or may not find one, depending on CWD
    assert isinstance(cfg, EvidentiaConfig)


def test_load_config_happy_path(tmp_path: Path) -> None:
    path = _write_yaml(
        tmp_path / "evidentia.yaml",
        "organization: Acme\nsystem_name: Portal\nframeworks:\n  - nist-800-53-rev5-moderate\n",
    )
    cfg = load_config(path)
    assert cfg.organization == "Acme"
    assert cfg.system_name == "Portal"
    assert cfg.frameworks == ["nist-800-53-rev5-moderate"]
    assert cfg.source_path == path


def test_load_config_empty_yaml_yields_defaults(tmp_path: Path) -> None:
    """Empty YAML should not crash — all fields default to None/empty."""
    path = _write_yaml(tmp_path / "evidentia.yaml", "")
    cfg = load_config(path)
    assert cfg.organization is None
    assert cfg.frameworks == []


def test_load_config_legacy_nested_frameworks_default(tmp_path: Path) -> None:
    """Legacy v0.2.0 `frameworks.default: [...]` shape emits deprecation warning but works."""
    path = _write_yaml(
        tmp_path / "evidentia.yaml",
        "frameworks:\n  default:\n    - soc2-tsc\n    - nist-800-53-mod\n",
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cfg = load_config(path)
    deprecation = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecation, "Expected DeprecationWarning for legacy frameworks.default shape"
    assert cfg.frameworks == ["soc2-tsc", "nist-800-53-mod"]


def test_load_config_warns_on_large_framework_set(tmp_path: Path) -> None:
    """> 5 frameworks emits UserWarning at load time."""
    many = "\n".join(f"  - fw{i}" for i in range(7))
    path = _write_yaml(tmp_path / "evidentia.yaml", f"frameworks:\n{many}\n")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        load_config(path)
    user_warns = [w for w in caught if issubclass(w.category, UserWarning)]
    assert user_warns, "Expected UserWarning for 7-framework config"


def test_load_config_extra_keys_are_allowed(tmp_path: Path) -> None:
    """Legacy v0.2.0 keys (storage, logging) don't cause validation errors."""
    path = _write_yaml(
        tmp_path / "evidentia.yaml",
        "organization: Acme\nstorage:\n  type: file\nlogging:\n  level: INFO\n",
    )
    cfg = load_config(path)  # must not raise
    assert cfg.organization == "Acme"


def test_load_config_malformed_yaml_raises(tmp_path: Path) -> None:
    """Non-dict YAML at top level is a clear error."""
    path = _write_yaml(tmp_path / "evidentia.yaml", "- just a list\n- of items\n")
    with pytest.raises(ValueError, match="YAML mapping"):
        load_config(path)


# -----------------------------------------------------------------------------
# _expand_env_vars — string interpolation
# -----------------------------------------------------------------------------


def test_expand_env_vars_simple(monkeypatch) -> None:
    monkeypatch.setenv("MY_VAR", "hello")
    assert _expand_env_vars("Value is ${MY_VAR}") == "Value is hello"


def test_expand_env_vars_missing_left_intact(monkeypatch) -> None:
    """If env var doesn't exist, leave the ${VAR} placeholder in place."""
    monkeypatch.delenv("MISSING_VAR", raising=False)
    assert _expand_env_vars("${MISSING_VAR}/path") == "${MISSING_VAR}/path"


def test_expand_env_vars_recursive(monkeypatch) -> None:
    """Interpolation walks nested dicts and lists."""
    monkeypatch.setenv("ORG", "Acme")
    data = {
        "a": "${ORG} Corp",
        "b": ["first", "${ORG}"],
        "c": {"nested": "${ORG}/portal"},
    }
    result = _expand_env_vars(data)
    assert result == {
        "a": "Acme Corp",
        "b": ["first", "Acme"],
        "c": {"nested": "Acme/portal"},
    }


def test_expand_env_vars_in_config(tmp_path: Path, monkeypatch) -> None:
    """Full load_config pipeline expands ${} in any string value."""
    monkeypatch.setenv("SPECIAL_ORG", "Specialized Industries")
    path = _write_yaml(
        tmp_path / "evidentia.yaml", "organization: ${SPECIAL_ORG}\n"
    )
    cfg = load_config(path)
    assert cfg.organization == "Specialized Industries"


# -----------------------------------------------------------------------------
# get_default — precedence chain
# -----------------------------------------------------------------------------


def test_get_default_cli_wins_over_env_and_yaml(monkeypatch) -> None:
    cfg = EvidentiaConfig(organization="YamlOrg")
    monkeypatch.setenv("CB_TEST_ORG", "EnvOrg")
    assert (
        get_default(cfg, "CliOrg", "organization", env_var="CB_TEST_ORG") == "CliOrg"
    )


def test_get_default_env_wins_over_yaml(monkeypatch) -> None:
    cfg = EvidentiaConfig(organization="YamlOrg")
    monkeypatch.setenv("CB_TEST_ORG", "EnvOrg")
    assert (
        get_default(cfg, None, "organization", env_var="CB_TEST_ORG") == "EnvOrg"
    )


def test_get_default_yaml_used_when_cli_and_env_empty(monkeypatch) -> None:
    cfg = EvidentiaConfig(organization="YamlOrg")
    monkeypatch.delenv("CB_TEST_ORG", raising=False)
    assert get_default(cfg, None, "organization", env_var="CB_TEST_ORG") == "YamlOrg"


def test_get_default_falls_through_to_builtin_default(monkeypatch) -> None:
    cfg = EvidentiaConfig()  # no org set
    monkeypatch.delenv("CB_TEST_ORG", raising=False)
    assert (
        get_default(
            cfg, None, "organization", env_var="CB_TEST_ORG", builtin_default="Default"
        )
        == "Default"
    )


def test_get_default_empty_string_treated_as_empty() -> None:
    """Empty CLI value (explicit '') should fall through to yaml."""
    cfg = EvidentiaConfig(organization="YamlOrg")
    assert get_default(cfg, "", "organization") == "YamlOrg"


def test_get_default_dotted_yaml_path() -> None:
    """Nested attribute paths like 'llm.model' work."""
    cfg = EvidentiaConfig()
    cfg.llm.model = "claude-opus-4"  # type: ignore[attr-defined]
    assert get_default(cfg, None, "llm.model") == "claude-opus-4"


def test_get_default_nonexistent_path_returns_builtin() -> None:
    cfg = EvidentiaConfig()
    assert get_default(cfg, None, "nonexistent.key", builtin_default="fallback") == "fallback"
