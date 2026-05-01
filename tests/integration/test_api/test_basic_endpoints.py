"""TestClient coverage for health, version, doctor, air-gap, llm-status.

These endpoints are dependency-light and form the "boot probe" surface —
the React UI calls them on load to confirm the backend is reachable.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


class TestHealth:
    def test_health_ok(self, api_client: TestClient) -> None:
        r = api_client.get("/api/health")
        assert r.status_code == 200
        payload = r.json()
        assert payload["status"] == "ok"
        assert "version" in payload

    def test_health_strict_shape(self, api_client: TestClient) -> None:
        # Pydantic ConfigDict(extra="forbid") on HealthResponse enforces
        # this server-side; we still assert it client-side so the contract
        # is visible to anyone reading the test file.
        r = api_client.get("/api/health")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/json")
        payload = r.json()
        assert set(payload.keys()) == {"status", "version"}
        assert payload["status"] == "ok"
        assert isinstance(payload["version"], str)
        assert payload["version"], "version was empty string"

    def test_health_path_matches_dockerfile_healthcheck(
        self, api_client: TestClient
    ) -> None:
        # The Dockerfile HEALTHCHECK at the repo root calls
        # http://localhost:8000/api/health — guard against a future
        # router-prefix refactor silently breaking the container's
        # liveness probe. /health (no prefix) would fall through to
        # the SPA fallback handler and return index.html with 200,
        # masking an actually-broken API.
        r_with_prefix = api_client.get("/api/health")
        assert r_with_prefix.status_code == 200
        assert r_with_prefix.json()["status"] == "ok"

    def test_version_shape(self, api_client: TestClient) -> None:
        r = api_client.get("/api/version")
        assert r.status_code == 200
        payload = r.json()
        assert set(payload.keys()) == {
            "api_version",
            "core_version",
            "ai_version",
            "python_version",
        }
        # All versions are non-empty strings.
        for k, v in payload.items():
            assert isinstance(v, str) and v, f"{k} was empty"


class TestDoctor:
    def test_doctor_lists_subsystems(self, api_client: TestClient) -> None:
        r = api_client.get("/api/doctor")
        assert r.status_code == 200
        payload = r.json()
        subsystems = payload["subsystems"]
        assert isinstance(subsystems, list)
        names = {s["name"] for s in subsystems}
        # Core packages must all appear.
        assert {"Python", "evidentia_core", "evidentia_api"} <= names

    def test_check_air_gap_default(self, api_client: TestClient) -> None:
        r = api_client.post("/api/doctor/check-air-gap")
        assert r.status_code == 200
        payload = r.json()
        assert "air_gapped" in payload
        assert isinstance(payload["checks"], list)
        # Known-stable subsystems should be present.
        subsystems = {c["subsystem"] for c in payload["checks"]}
        assert {"llm_client", "catalog_loader", "gap_store", "web_ui"} <= subsystems

    def test_check_air_gap_with_ollama_model_reports_ok(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_LLM_MODEL", "ollama/llama3")
        r = api_client.post("/api/doctor/check-air-gap")
        assert r.status_code == 200
        llm_check = next(
            c for c in r.json()["checks"] if c["subsystem"] == "llm_client"
        )
        assert llm_check["status"] == "ok"

    def test_check_air_gap_with_cloud_model_reports_would_leak(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("EVIDENTIA_LLM_MODEL", raising=False)
        monkeypatch.delenv("EVIDENTIA_LLM_API_BASE", raising=False)
        monkeypatch.delenv("OPENAI_API_BASE", raising=False)
        r = api_client.post("/api/doctor/check-air-gap")
        payload = r.json()
        llm_check = next(
            c for c in payload["checks"] if c["subsystem"] == "llm_client"
        )
        assert llm_check["status"] == "would_leak"
        assert payload["air_gapped"] is False


class TestLlmStatus:
    def test_returns_provider_map_without_key_values(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Set one key so we can verify we get the "configured" bool but not
        # the key value itself.
        monkeypatch.setenv("OPENAI_API_KEY", "sk-should-never-appear-in-response")
        r = api_client.get("/api/llm-status")
        assert r.status_code == 200
        payload = r.json()
        assert set(payload["providers"].keys()) >= {
            "openai",
            "anthropic",
            "google",
            "azure_openai",
            "ollama",
        }
        openai_state = payload["providers"]["openai"]
        assert openai_state["configured"] is True
        assert openai_state["source"] == "env:OPENAI_API_KEY"
        # Critical: the key value must NOT appear anywhere in the response.
        body = r.text
        assert "sk-should-never-appear" not in body

    def test_reports_unconfigured_providers_as_false(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for var in (
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GOOGLE_API_KEY",
            "AZURE_OPENAI_API_KEY",
        ):
            monkeypatch.delenv(var, raising=False)
        r = api_client.get("/api/llm-status")
        providers = r.json()["providers"]
        assert providers["openai"]["configured"] is False
        assert providers["openai"]["source"] is None
