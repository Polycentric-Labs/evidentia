"""Tests for ``scripts/check_python_ceiling.py`` — the self-lift watcher for
the ``requires-python<3.15`` cap (litellm currently declares
``requires_python "<3.15,>=3.10"``; when it relaxes past 3.15 the cap can
lift again).

Detect-and-nudge, fail-soft: a PyPI fetch failure or malformed payload must
never turn this sentinel red (mirrors ``check_workflow_liveness.py``). All
network access goes through an injected opener; no real network in unit
tests.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import urllib.error
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_python_ceiling.py"


@pytest.fixture(scope="module")
def cpc() -> Any:
    spec = importlib.util.spec_from_file_location("check_python_ceiling", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_python_ceiling"] = module
    spec.loader.exec_module(module)
    return module


# --- ceiling_allows ---------------------------------------------------------


def test_ceiling_allows_false_when_still_capped_below_target(cpc: Any) -> None:
    assert cpc.ceiling_allows("<3.15,>=3.10") is False


def test_ceiling_allows_true_when_relaxed_past_target(cpc: Any) -> None:
    assert cpc.ceiling_allows("<3.16,>=3.10") is True


def test_ceiling_allows_true_when_unbounded_above(cpc: Any) -> None:
    assert cpc.ceiling_allows(">=3.10") is True


def test_ceiling_allows_false_when_none(cpc: Any) -> None:
    assert cpc.ceiling_allows(None) is False


def test_ceiling_allows_false_when_empty_string(cpc: Any) -> None:
    assert cpc.ceiling_allows("") is False


def test_ceiling_allows_respects_custom_target(cpc: Any) -> None:
    assert cpc.ceiling_allows("<3.14,>=3.10", target="3.13.0") is True
    assert cpc.ceiling_allows("<3.14,>=3.10", target="3.14.0") is False


def test_ceiling_allows_false_on_malformed_specifier(cpc: Any) -> None:
    # An unexpected/non-spec PyPI value must not crash the sentinel (exit-0
    # detect-and-nudge doctrine) — "can't tell" means no nudge.
    assert cpc.ceiling_allows("not-a-specifier") is False


def test_ceiling_allows_false_on_malformed_target(cpc: Any) -> None:
    assert cpc.ceiling_allows("<3.14,>=3.10", target="garbage") is False


# --- fetch_requires_python ---------------------------------------------------


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _opener_returning(data: dict[str, Any]) -> Any:
    payload = json.dumps(data).encode("utf-8")

    def opener(req: Any, timeout: float = 30) -> _FakeResponse:
        del req, timeout
        return _FakeResponse(payload)

    return opener


def _opener_raising(exc: Exception) -> Any:
    def opener(req: Any, timeout: float = 30) -> _FakeResponse:
        del req, timeout
        raise exc

    return opener


def test_fetch_requires_python_parses_payload(cpc: Any) -> None:
    opener = _opener_returning({"info": {"requires_python": "<3.14,>=3.10"}})
    assert cpc.fetch_requires_python("litellm", opener=opener) == "<3.14,>=3.10"


def test_fetch_requires_python_handles_null_field(cpc: Any) -> None:
    opener = _opener_returning({"info": {"requires_python": None}})
    assert cpc.fetch_requires_python("litellm", opener=opener) is None


def test_fetch_requires_python_none_on_urlerror(cpc: Any) -> None:
    opener = _opener_raising(urllib.error.URLError("boom"))
    assert cpc.fetch_requires_python("litellm", opener=opener) is None


def test_fetch_requires_python_none_on_malformed_json(cpc: Any) -> None:
    def opener(req: Any, timeout: float = 30) -> _FakeResponse:
        del req, timeout
        return _FakeResponse(b"not json")

    assert cpc.fetch_requires_python("litellm", opener=opener) is None


def test_fetch_requires_python_none_on_missing_key(cpc: Any) -> None:
    opener = _opener_returning({"info": {}})
    assert cpc.fetch_requires_python("litellm", opener=opener) is None


def test_fetch_requires_python_none_on_missing_info(cpc: Any) -> None:
    opener = _opener_returning({})
    assert cpc.fetch_requires_python("litellm", opener=opener) is None


# --- main --------------------------------------------------------------------


def test_main_writes_nudge_when_ceiling_allows(
    cpc: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cpc, "fetch_requires_python", lambda package, opener=None: "<3.16,>=3.10")
    out = tmp_path / "ceiling-findings.md"
    rc = cpc.main(["--output", str(out)])
    assert rc == 0
    text = out.read_text(encoding="utf-8")
    assert text.strip() != ""
    assert "litellm" in text


def test_main_writes_empty_file_when_still_capped(
    cpc: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cpc, "fetch_requires_python", lambda package, opener=None: "<3.15,>=3.10")
    out = tmp_path / "ceiling-findings.md"
    rc = cpc.main(["--output", str(out)])
    assert rc == 0
    assert out.read_text(encoding="utf-8") == ""


def test_main_writes_empty_file_and_exit_0_when_fetch_none(
    cpc: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cpc, "fetch_requires_python", lambda package, opener=None: None)
    out = tmp_path / "ceiling-findings.md"
    rc = cpc.main(["--output", str(out)])
    assert rc == 0
    assert out.read_text(encoding="utf-8") == ""


def test_main_respects_package_and_target_args(
    cpc: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, str] = {}

    def fake_fetch(package: str, opener: Any = None) -> str:
        seen["package"] = package
        return "<3.99,>=3.10"

    monkeypatch.setattr(cpc, "fetch_requires_python", fake_fetch)
    out = tmp_path / "ceiling-findings.md"
    rc = cpc.main(
        ["--package", "somepkg", "--target", "3.20.0", "--output", str(out)]
    )
    assert rc == 0
    assert seen["package"] == "somepkg"
    assert "somepkg" in out.read_text(encoding="utf-8")
