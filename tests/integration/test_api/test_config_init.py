"""TestClient coverage for /api/config and /api/init/wizard."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient


class TestConfig:
    def test_get_default_when_no_yaml(self, api_client: TestClient) -> None:
        """No evidentia.yaml in tmp_path CWD -> returns defaults."""
        r = api_client.get("/api/config")
        assert r.status_code == 200
        payload = r.json()
        assert payload["organization"] is None
        assert payload["frameworks"] == []

    def test_put_then_get_roundtrip(
        self, api_client: TestClient, tmp_path: Path
    ) -> None:
        """PUT /api/config writes YAML; subsequent GET reflects it."""
        new_config = {
            "organization": "API Test Org",
            "system_name": "API Test System",
            "frameworks": ["soc2-tsc", "nist-800-53-rev5-moderate"],
            "llm": {"model": "claude-sonnet-4-6", "temperature": 0.2},
        }
        r = api_client.put("/api/config", json=new_config)
        assert r.status_code == 200, r.text
        persisted = r.json()
        assert persisted["organization"] == "API Test Org"
        assert persisted["system_name"] == "API Test System"
        assert persisted["frameworks"] == [
            "soc2-tsc",
            "nist-800-53-rev5-moderate",
        ]

        # File landed in the tmp_path cwd.
        target = tmp_path / "evidentia.yaml"
        assert target.is_file()
        text = target.read_text(encoding="utf-8")
        assert "API Test Org" in text
        assert "claude-sonnet-4-6" in text

        r2 = api_client.get("/api/config")
        assert r2.status_code == 200
        assert r2.json()["organization"] == "API Test Org"

    def test_put_rejects_invalid_temperature(
        self, api_client: TestClient
    ) -> None:
        bad = {
            "organization": "X",
            "frameworks": ["soc2-tsc"],
            "llm": {"model": "gpt-4o", "temperature": 99.0},
        }
        r = api_client.put("/api/config", json=bad)
        assert r.status_code == 422


class TestInitWizard:
    def test_returns_three_yamls_and_framework_recommendations(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/init/wizard",
            json={
                "organization": "Wizard Test Co",
                "system_name": "Wizard Platform",
                "industry": "healthtech",
                "hosting": "aws",
                "data_classification": ["PHI", "PII"],
                "regulatory_requirements": ["HIPAA"],
                "preset": "hipaa-starter",
            },
        )
        assert r.status_code == 200, r.text
        payload = r.json()
        assert "evidentia_yaml" in payload
        assert "my_controls_yaml" in payload
        assert "system_context_yaml" in payload
        # healthtech + PHI must get HIPAA recommendations.
        assert "hipaa-security" in payload["recommended_frameworks"]
        assert "hipaa-privacy" in payload["recommended_frameworks"]
        # Generated YAMLs mention the organization.
        assert "Wizard Test Co" in payload["evidentia_yaml"]
        assert "Wizard Test Co" in payload["my_controls_yaml"]

    def test_rejects_unknown_preset(self, api_client: TestClient) -> None:
        # The wizard validates the preset value at runtime; the
        # generator raises ValueError which the route normalizes to
        # 400 with `{detail: string}` shape (F-V08-DAST-3).
        r = api_client.post(
            "/api/init/wizard",
            json={
                "organization": "Test",
                "industry": "saas",
                "preset": "bogus-preset",
            },
        )
        assert r.status_code == 400


class TestInitCommit:
    """`POST /api/init/commit` writes the starter files to the server cwd."""

    _NAMES = ("evidentia.yaml", "my-controls.yaml", "system-context.yaml")

    def test_writes_three_starter_files(
        self, api_client: TestClient, tmp_path: Path
    ) -> None:
        r = api_client.post(
            "/api/init/commit",
            json={
                "organization": "Commit Co",
                "industry": "saas",
                "hosting": "aws",
                "preset": "nist-moderate-starter",
            },
        )
        assert r.status_code == 200, r.text
        payload = r.json()
        assert sorted(payload["created"]) == sorted(self._NAMES)
        assert payload["skipped"] == []
        for name in self._NAMES:
            assert (tmp_path / name).is_file()
        assert "Commit Co" in (tmp_path / "evidentia.yaml").read_text("utf-8")
        # Mirrors `evidentia init`: the storage dir is created too.
        assert (tmp_path / ".evidentia").is_dir()

    def test_skips_existing_without_overwrite(
        self, api_client: TestClient, tmp_path: Path
    ) -> None:
        (tmp_path / "evidentia.yaml").write_text("PRE-EXISTING", encoding="utf-8")
        r = api_client.post(
            "/api/init/commit",
            json={"organization": "Skip Co", "preset": "empty"},
        )
        assert r.status_code == 200, r.text
        payload = r.json()
        assert payload["skipped"] == ["evidentia.yaml"]
        assert sorted(payload["created"]) == [
            "my-controls.yaml",
            "system-context.yaml",
        ]
        # No silent clobber — the existing file is byte-for-byte untouched.
        assert (tmp_path / "evidentia.yaml").read_text("utf-8") == "PRE-EXISTING"

    def test_overwrite_true_replaces_existing(
        self, api_client: TestClient, tmp_path: Path
    ) -> None:
        (tmp_path / "evidentia.yaml").write_text("OLD", encoding="utf-8")
        r = api_client.post(
            "/api/init/commit",
            json={
                "organization": "Overwrite Co",
                "preset": "empty",
                "overwrite": True,
            },
        )
        assert r.status_code == 200, r.text
        assert "evidentia.yaml" in r.json()["created"]
        text = (tmp_path / "evidentia.yaml").read_text("utf-8")
        assert "OLD" not in text
        assert "Overwrite Co" in text

    def test_rejects_unknown_preset(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/init/commit",
            json={"organization": "Test", "preset": "bogus-preset"},
        )
        assert r.status_code == 400
