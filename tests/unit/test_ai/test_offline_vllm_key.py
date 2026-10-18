"""The offline vLLM branch reads HOSTED_VLLM_API_KEY, never the cloud OPENAI_API_KEY (v0.13.0 review, CWE-522)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from evidentia_core.network_guard import set_offline

MESSAGES = [{"role": "user", "content": "hello"}]


@pytest.fixture()
def offline() -> Iterator[None]:
    set_offline(True)
    try:
        yield
    finally:
        set_offline(False)


def _prepare(model: str) -> dict[str, str]:
    from evidentia_ai._offline_completion import _prepare

    request = _prepare((), {"model": model, "messages": MESSAGES, "api_base": "http://127.0.0.1:8000"})
    return dict(request.headers)


def test_vllm_uses_its_own_key(offline: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-openai-value")
    monkeypatch.setenv("HOSTED_VLLM_API_KEY", "synthetic-vllm-value")
    headers = _prepare("hosted_vllm/local-model")
    assert headers.get("Authorization") == "Bearer synthetic-vllm-value"


def test_vllm_without_its_key_sends_no_authorization(offline: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-openai-value")
    monkeypatch.delenv("HOSTED_VLLM_API_KEY", raising=False)
    headers = _prepare("hosted_vllm/local-model")
    assert "Authorization" not in headers
    assert "synthetic-openai-value" not in str(headers)


def test_openai_compatible_server_still_reads_openai_key(offline: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-openai-value")
    monkeypatch.delenv("HOSTED_VLLM_API_KEY", raising=False)
    headers = _prepare("openai/local-model")
    assert headers.get("Authorization") == "Bearer synthetic-openai-value"
