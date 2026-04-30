"""Unit tests for ``evidentia_core.network_guard``.

Covers the host-classifier, URL guard, and LLM-config guard. No network
IO is performed; the guard is pure logic over strings and IPs.
"""

from __future__ import annotations

import pytest
from evidentia_core.network_guard import (
    LOCAL_LLM_PREFIXES,
    OfflineViolationError,
    check_llm_model,
    check_url,
    is_loopback_or_private,
    is_offline,
    offline_mode,
    set_offline,
)


@pytest.fixture(autouse=True)
def _reset_offline_state():
    """Make sure every test starts and ends with offline mode disabled."""
    set_offline(False)
    yield
    set_offline(False)


# ── is_loopback_or_private ───────────────────────────────────────────────


class TestIsLoopbackOrPrivate:
    @pytest.mark.parametrize(
        "host",
        [
            "localhost",
            "localhost.localdomain",
            "LOCALHOST",  # case-insensitive
            "127.0.0.1",
            "127.0.0.42",
            "::1",
            "[::1]",  # bracketed IPv6 (as urlparse returns)
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "169.254.1.1",  # link-local
            "fe80::1234",
            "fd00::1",  # unique-local
        ],
    )
    def test_allowed_hosts(self, host: str) -> None:
        assert is_loopback_or_private(host) is True

    @pytest.mark.parametrize(
        "host",
        [
            "8.8.8.8",
            "1.1.1.1",
            "api.openai.com",
            "github.com",
            "172.15.0.1",  # just outside 172.16/12
            "172.32.0.1",  # just outside 172.16/12
            "2001:4860:4860::8888",  # Google DNS IPv6
            "",
        ],
    )
    def test_rejected_hosts(self, host: str) -> None:
        assert is_loopback_or_private(host) is False


# ── offline-mode toggle ─────────────────────────────────────────────────


class TestOfflineToggle:
    def test_default_is_off(self) -> None:
        assert is_offline() is False

    def test_set_offline_toggles(self) -> None:
        set_offline(True)
        assert is_offline() is True
        set_offline(False)
        assert is_offline() is False

    def test_context_manager_enable(self) -> None:
        assert is_offline() is False
        with offline_mode():
            assert is_offline() is True
        assert is_offline() is False

    def test_context_manager_restores_on_exception(self) -> None:
        assert is_offline() is False
        with pytest.raises(RuntimeError), offline_mode():
            assert is_offline() is True
            raise RuntimeError("boom")
        assert is_offline() is False

    def test_context_manager_preserves_existing_state(self) -> None:
        set_offline(True)
        with offline_mode(False):
            assert is_offline() is False
        # Restored to the outer (True) state, not the default False.
        assert is_offline() is True


# ── check_url ───────────────────────────────────────────────────────────


class TestCheckUrl:
    def test_noop_when_offline_is_off(self) -> None:
        # Even a cloud host passes when offline is off.
        check_url("https://api.openai.com/v1/chat", subsystem="test")

    def test_allows_loopback_when_offline(self) -> None:
        with offline_mode():
            check_url("http://127.0.0.1:8080/", subsystem="test")
            check_url("http://localhost:11434/api/generate", subsystem="test")
            check_url("http://[::1]:8000/health", subsystem="test")

    def test_allows_rfc_1918_when_offline(self) -> None:
        with offline_mode():
            check_url("https://10.0.5.7/evidence", subsystem="test")
            check_url("https://192.168.1.100:8443/", subsystem="test")

    def test_rejects_cloud_host_when_offline(self) -> None:
        with offline_mode(), pytest.raises(OfflineViolationError) as excinfo:
            check_url("https://api.openai.com/v1/chat", subsystem="llm_client")
        err = excinfo.value
        assert err.subsystem == "llm_client"
        # Exact-string assertion (not substring) so this stays a
        # well-formed test — substring-on-URL is a CodeQL
        # py/incomplete-url-substring-sanitization smell even in tests.
        assert err.target == "https://api.openai.com/v1/chat"
        assert err.remediation

    def test_error_carries_remediation_hint(self) -> None:
        with offline_mode(), pytest.raises(OfflineViolationError) as excinfo:
            check_url(
                "https://raw.githubusercontent.com/usnistgov/oscal-content/main/catalog.json",
                subsystem="catalog_loader",
                remediation="Download the catalog locally and use --from-file instead.",
            )
        assert "Download the catalog locally" in excinfo.value.remediation


# ── check_llm_model ─────────────────────────────────────────────────────


class TestCheckLlmModel:
    def test_noop_when_offline_is_off(self) -> None:
        check_llm_model("gpt-4o")  # cloud model, offline off — should pass

    def test_rejects_cloud_model_when_offline(self) -> None:
        for cloud_model in ["gpt-4o", "claude-sonnet-4-6", "gemini-1.5-pro"]:
            with offline_mode(), pytest.raises(OfflineViolationError):
                check_llm_model(cloud_model)

    @pytest.mark.parametrize("prefix", LOCAL_LLM_PREFIXES)
    def test_allows_local_prefix(self, prefix: str) -> None:
        # Model after the prefix is arbitrary; only the prefix matters for
        # offline allowlisting.
        with offline_mode():
            check_llm_model(f"{prefix}llama3")

    def test_allows_custom_api_base_on_loopback(self) -> None:
        with offline_mode():
            check_llm_model(
                "gpt-4o", api_base="http://127.0.0.1:8080/v1"
            )  # self-hosted OpenAI-compatible
            check_llm_model(
                "custom-model",
                api_base="https://10.0.0.50:8443/v1",
            )

    def test_rejects_custom_api_base_on_cloud(self) -> None:
        with offline_mode(), pytest.raises(OfflineViolationError) as excinfo:
            check_llm_model("gpt-4o", api_base="https://api.openai.com/v1")
        # Exact-string assertion: the target field for model + api_base
        # cases is "<model> @ <api_base>". Substring-in-URL is the
        # same CodeQL smell flagged in test_rejects_cloud_host_when_offline
        # above.
        assert excinfo.value.target == "gpt-4o @ https://api.openai.com/v1"

    def test_case_insensitive_prefix_match(self) -> None:
        with offline_mode():
            check_llm_model("OLLAMA/llama3")
            check_llm_model("Ollama_Chat/Mistral")
