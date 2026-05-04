"""Unit tests for `evidentia.cli._editor.resolve_editor_or_exit`
(v0.7.11 P3 closure of v0.7.10 F-V10-S2).
"""

from __future__ import annotations

from typing import Any

import pytest
import typer
from evidentia.cli._editor import resolve_editor_or_exit


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip the env vars this helper reads."""
    monkeypatch.delenv("EDITOR", raising=False)
    monkeypatch.delenv("EVIDENTIA_EDITOR_ALLOW_ANY", raising=False)


def _stub_which(*, mapping: dict[str, str | None]) -> Any:
    def _stub(cmd: str) -> str | None:
        return mapping.get(cmd)
    return _stub


# ── happy-path resolution ──────────────────────────────────────────


def test_default_vi_resolves_when_unset(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "evidentia.cli._editor.shutil.which",
        _stub_which(mapping={"vi": "/usr/bin/vi"}),
    )
    argv = resolve_editor_or_exit()
    assert argv == ["/usr/bin/vi"]


def test_simple_editor_resolves(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EDITOR", "vim")
    monkeypatch.setattr(
        "evidentia.cli._editor.shutil.which",
        _stub_which(mapping={"vim": "/usr/local/bin/vim"}),
    )
    argv = resolve_editor_or_exit()
    assert argv == ["/usr/local/bin/vim"]


def test_editor_with_args_split_correctly(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EDITOR", "code -w")
    monkeypatch.setattr(
        "evidentia.cli._editor.shutil.which",
        _stub_which(mapping={"code": "/usr/local/bin/code"}),
    )
    argv = resolve_editor_or_exit()
    assert argv == ["/usr/local/bin/code", "-w"]


def test_editor_with_quoted_args(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """shlex.split handles quoted-arg patterns correctly."""
    monkeypatch.setenv("EDITOR", 'vim "-u" "NONE"')
    monkeypatch.setattr(
        "evidentia.cli._editor.shutil.which",
        _stub_which(mapping={"vim": "/usr/bin/vim"}),
    )
    argv = resolve_editor_or_exit()
    assert argv == ["/usr/bin/vim", "-u", "NONE"]


def test_resolved_path_basename_used_for_allowlist_check(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If EDITOR='editor' but PATH resolves to /usr/bin/vim,
    the allowlist check uses the resolved basename ('vim')."""
    monkeypatch.setenv("EDITOR", "editor")
    # 'editor' isn't on the allowlist, but it resolves to /usr/bin/vim
    # which IS on the allowlist via the basename check.
    monkeypatch.setattr(
        "evidentia.cli._editor.shutil.which",
        _stub_which(mapping={"editor": "/usr/bin/vim"}),
    )
    argv = resolve_editor_or_exit()
    assert argv == ["/usr/bin/vim"]


# ── opt-out env var ────────────────────────────────────────────────


def test_opt_out_allows_any_editor(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EDITOR", "weirdeditor")
    monkeypatch.setenv("EVIDENTIA_EDITOR_ALLOW_ANY", "1")
    monkeypatch.setattr(
        "evidentia.cli._editor.shutil.which",
        _stub_which(mapping={"weirdeditor": "/opt/wei/weirdeditor"}),
    )
    argv = resolve_editor_or_exit()
    assert argv == ["/opt/wei/weirdeditor"]


def test_opt_out_truthy_string_only_one_passes(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Strict ``== "1"`` check — ``true`` / ``yes`` etc. don't bypass."""
    monkeypatch.setenv("EDITOR", "weirdeditor")
    monkeypatch.setenv("EVIDENTIA_EDITOR_ALLOW_ANY", "true")
    monkeypatch.setattr(
        "evidentia.cli._editor.shutil.which",
        _stub_which(mapping={"weirdeditor": "/opt/wei/weirdeditor"}),
    )
    with pytest.raises(typer.Exit):
        resolve_editor_or_exit()


# ── error paths ────────────────────────────────────────────────────


def test_empty_editor_exits(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EDITOR", "   ")
    with pytest.raises(typer.Exit):
        resolve_editor_or_exit()


def test_editor_not_on_path_exits(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EDITOR", "nonexistent")
    monkeypatch.setattr(
        "evidentia.cli._editor.shutil.which",
        _stub_which(mapping={}),
    )
    with pytest.raises(typer.Exit):
        resolve_editor_or_exit()


def test_editor_not_in_allowlist_exits(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EDITOR", "evil")
    # The binary IS on PATH, but its basename isn't allowlisted.
    monkeypatch.setattr(
        "evidentia.cli._editor.shutil.which",
        _stub_which(mapping={"evil": "/opt/evil/evil"}),
    )
    with pytest.raises(typer.Exit):
        resolve_editor_or_exit()


def test_unbalanced_quotes_in_editor_exits(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """shlex.split raises ValueError on unbalanced quotes; we
    catch and exit cleanly rather than crash."""
    monkeypatch.setenv("EDITOR", 'vim "unbalanced')
    with pytest.raises(typer.Exit):
        resolve_editor_or_exit()


def test_default_param_when_editor_unset(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "evidentia.cli._editor.shutil.which",
        _stub_which(mapping={"nano": "/usr/bin/nano"}),
    )
    argv = resolve_editor_or_exit(default="nano")
    assert argv == ["/usr/bin/nano"]


def test_custom_allowlist(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Caller can pass a tighter allowlist."""
    monkeypatch.setenv("EDITOR", "vim")
    monkeypatch.setattr(
        "evidentia.cli._editor.shutil.which",
        _stub_which(mapping={"vim": "/usr/bin/vim"}),
    )
    # vim NOT in {"vi"} — should exit
    with pytest.raises(typer.Exit):
        resolve_editor_or_exit(allowlist=frozenset({"vi"}))
