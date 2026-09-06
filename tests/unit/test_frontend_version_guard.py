"""Unit tests for the frontend hardcoded-version guard in
``scripts/check_version_consistency.py``.

The guard closes the gap where the ``packages/evidentia-ui`` tree is ``frozen``
wholesale (so never-skip exempts it) yet a hardcoded ``vX.Y.Z`` in JSX/code is a
real staleness bug — it shipped once as a stale ``v0.7.6`` sidebar label.
"""

from __future__ import annotations

import importlib.util
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECK_PATH = REPO_ROOT / "scripts" / "check_version_consistency.py"


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def check() -> Any:
    return _load_module("check_vc_frontend_guard", CHECK_PATH)


@pytest.fixture
def bump(check: Any) -> Any:
    return check._load_bump_module()


@pytest.fixture
def chdir_tmp(tmp_path: Path) -> Iterator[Path]:
    prev = Path.cwd()
    os.chdir(tmp_path)
    try:
        yield tmp_path
    finally:
        os.chdir(prev)


def _track(bump: Any, monkeypatch: pytest.MonkeyPatch, paths: list[str]) -> None:
    monkeypatch.setattr(bump, "tracked_files", lambda: [Path(p) for p in paths])


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_version_literal_in_comment_passes(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rel = "packages/evidentia-ui/src/App.tsx"
    _write(
        chdir_tmp,
        rel,
        "/*\n * v0.7.6: alpha.2 routing wired.\n */\nexport const App = () => null;\n",
    )
    _track(bump, monkeypatch, [rel])
    assert check.check_frontend_no_hardcoded_version(bump) == []


def test_hardcoded_version_in_jsx_fails(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rel = "packages/evidentia-ui/src/components/Foot.tsx"
    _write(
        chdir_tmp,
        rel,
        "export const Foot = () => <p>v0.7.6 (alpha.2 wired)</p>;\n",
    )
    _track(bump, monkeypatch, [rel])
    failures = check.check_frontend_no_hardcoded_version(bump)
    assert len(failures) == 1
    assert "v0.7.6" in failures[0]
    assert "Foot.tsx" in failures[0]


def test_test_files_are_excluded(check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rel = "packages/evidentia-ui/src/components/Foo.test.tsx"
    _write(chdir_tmp, rel, 'const mock = { evidentia_version: "0.10.7" };\n')
    _track(bump, monkeypatch, [rel])
    assert check.check_frontend_no_hardcoded_version(bump) == []


def test_real_repo_frontend_is_clean(check: Any, bump: Any) -> None:
    """The live repo must carry no hardcoded frontend project-version literal."""
    assert check.check_frontend_no_hardcoded_version(bump) == []
