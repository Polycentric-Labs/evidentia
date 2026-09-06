"""Integration tests for `evidentia evidence` subcommands (v0.9.6 P2).

Covers:

- ``evidence save`` happy path + WORM-violation error path.
- ``evidence history`` listing + JSON output.
- ``evidence show --version N`` rendering + missing-version handling.
- RBAC gating: write denied for ``reader`` role; reads allowed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _normalize(s: str) -> str:
    return " ".join(_ANSI_RE.sub("", s).split())


@pytest.fixture(autouse=True)
def _clean_rbac_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset RBAC singletons per test."""
    monkeypatch.delenv("EVIDENTIA_RBAC_POLICY_FILE", raising=False)
    monkeypatch.delenv("EVIDENTIA_RBAC_IDENTITY", raising=False)

    from evidentia.cli._rbac_lifecycle import _reset_rbac_cache

    _reset_rbac_cache()
    yield
    _reset_rbac_cache()


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def store_dir(tmp_path: Path) -> Path:
    """Per-test evidence-store root."""
    return tmp_path / "evidence_store"


@pytest.fixture()
def artifact_yaml(tmp_path: Path) -> Path:
    """Write a minimal valid YAML artifact and return its path."""
    yaml_path = tmp_path / "artifact_v1.yaml"
    yaml_path.write_text(
        "title: 'S3 bucket policy snapshot'\n"
        "evidence_type: configuration\n"
        "source_system: aws\n"
        "collected_by: 'alice@example.com'\n"
        "content:\n"
        "  bucket: 'evidentia-prod'\n"
        "  policy: 'deny-all'\n",
        encoding="utf-8",
    )
    return yaml_path


# ── evidence save ──────────────────────────────────────────────────


class TestEvidenceSave:
    def test_saves_v1(
        self,
        runner: CliRunner,
        artifact_yaml: Path,
        store_dir: Path,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "evidence",
                "save",
                str(artifact_yaml),
                "--store-dir",
                str(store_dir),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Saved" in result.output
        assert "v1" in result.output

    def test_saves_with_json_output(
        self,
        runner: CliRunner,
        artifact_yaml: Path,
        store_dir: Path,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "evidence",
                "save",
                str(artifact_yaml),
                "--store-dir",
                str(store_dir),
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["version"] == 1
        assert "artifact_id" in payload
        assert "lineage_id" in payload
        assert payload["path"].endswith("v1.json")

    def test_missing_yaml_errors_exit_2(
        self,
        runner: CliRunner,
        tmp_path: Path,
        store_dir: Path,
    ) -> None:
        missing = tmp_path / "does-not-exist.yaml"
        result = runner.invoke(
            app,
            [
                "evidence",
                "save",
                str(missing),
                "--store-dir",
                str(store_dir),
            ],
        )
        assert result.exit_code == 2

    def test_invalid_yaml_errors_exit_2(
        self,
        runner: CliRunner,
        tmp_path: Path,
        store_dir: Path,
    ) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("not: valid: yaml: structure\n", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "evidence",
                "save",
                str(bad),
                "--store-dir",
                str(store_dir),
            ],
        )
        assert result.exit_code == 2

    def test_yaml_top_level_list_errors_exit_2(
        self,
        runner: CliRunner,
        tmp_path: Path,
        store_dir: Path,
    ) -> None:
        bad = tmp_path / "list.yaml"
        bad.write_text("- a\n- b\n", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "evidence",
                "save",
                str(bad),
                "--store-dir",
                str(store_dir),
            ],
        )
        assert result.exit_code == 2
        assert "mapping" in _normalize(result.output).lower()

    def test_schema_violation_errors_exit_2(
        self,
        runner: CliRunner,
        tmp_path: Path,
        store_dir: Path,
    ) -> None:
        bad = tmp_path / "schema-violation.yaml"
        # Missing required fields: title, evidence_type, source_system,
        # collected_by.
        bad.write_text("foo: bar\n", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "evidence",
                "save",
                str(bad),
                "--store-dir",
                str(store_dir),
            ],
        )
        assert result.exit_code == 2

    def test_worm_violation_when_resaving_same_id(
        self,
        runner: CliRunner,
        tmp_path: Path,
        store_dir: Path,
    ) -> None:
        # Write a YAML with an explicit id (so re-saves collide).
        from uuid import uuid4

        fixed_id = str(uuid4())
        yaml_path = tmp_path / "fixed.yaml"
        yaml_path.write_text(
            f"id: '{fixed_id}'\n"
            "title: 'fixed-id artifact'\n"
            "evidence_type: configuration\n"
            "source_system: aws\n"
            "collected_by: 'alice@example.com'\n",
            encoding="utf-8",
        )
        first = runner.invoke(
            app,
            [
                "evidence",
                "save",
                str(yaml_path),
                "--store-dir",
                str(store_dir),
            ],
        )
        assert first.exit_code == 0, first.output
        second = runner.invoke(
            app,
            [
                "evidence",
                "save",
                str(yaml_path),
                "--store-dir",
                str(store_dir),
            ],
        )
        assert second.exit_code == 1
        assert "WORM violation" in second.output


# ── evidence history ───────────────────────────────────────────────


class TestEvidenceHistory:
    def test_empty_lineage_returns_no_versions(
        self,
        runner: CliRunner,
        store_dir: Path,
    ) -> None:
        from uuid import uuid4

        result = runner.invoke(
            app,
            [
                "evidence",
                "history",
                str(uuid4()),
                "--store-dir",
                str(store_dir),
            ],
        )
        assert result.exit_code == 0
        assert "No versions found" in result.output

    def test_lineage_returns_one_version_after_save(
        self,
        runner: CliRunner,
        artifact_yaml: Path,
        store_dir: Path,
    ) -> None:
        save = runner.invoke(
            app,
            [
                "evidence",
                "save",
                str(artifact_yaml),
                "--store-dir",
                str(store_dir),
                "--json",
            ],
        )
        assert save.exit_code == 0
        payload = json.loads(save.output)
        lineage_id = payload["lineage_id"]

        history = runner.invoke(
            app,
            [
                "evidence",
                "history",
                lineage_id,
                "--store-dir",
                str(store_dir),
                "--json",
            ],
        )
        assert history.exit_code == 0, history.output
        versions = json.loads(history.output)
        assert len(versions) == 1
        assert versions[0]["version"] == 1

    def test_invalid_lineage_id_errors_exit_2(
        self,
        runner: CliRunner,
        store_dir: Path,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "evidence",
                "history",
                "not-a-uuid",
                "--store-dir",
                str(store_dir),
            ],
        )
        assert result.exit_code == 2


# ── evidence show ──────────────────────────────────────────────────


class TestEvidenceShow:
    def test_show_renders_saved_version(
        self,
        runner: CliRunner,
        artifact_yaml: Path,
        store_dir: Path,
    ) -> None:
        save = runner.invoke(
            app,
            [
                "evidence",
                "save",
                str(artifact_yaml),
                "--store-dir",
                str(store_dir),
                "--json",
            ],
        )
        lineage_id = json.loads(save.output)["lineage_id"]
        show = runner.invoke(
            app,
            [
                "evidence",
                "show",
                lineage_id,
                "--version",
                "1",
                "--store-dir",
                str(store_dir),
                "--json",
            ],
        )
        assert show.exit_code == 0, show.output
        artifact = json.loads(show.output)
        assert artifact["version"] == 1
        assert artifact["title"] == "S3 bucket policy snapshot"

    def test_missing_version_errors_exit_1(
        self,
        runner: CliRunner,
        artifact_yaml: Path,
        store_dir: Path,
    ) -> None:
        save = runner.invoke(
            app,
            [
                "evidence",
                "save",
                str(artifact_yaml),
                "--store-dir",
                str(store_dir),
                "--json",
            ],
        )
        lineage_id = json.loads(save.output)["lineage_id"]
        show = runner.invoke(
            app,
            [
                "evidence",
                "show",
                lineage_id,
                "--version",
                "5",
                "--store-dir",
                str(store_dir),
            ],
        )
        assert show.exit_code == 1
        assert "no v5 found" in show.output.lower()


# ── RBAC gating ────────────────────────────────────────────────────


@pytest.fixture()
def reader_policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(
        "identities:\n  alice@example.com: reader\ndefault_role: deny\n",
        encoding="utf-8",
    )
    return p


@pytest.fixture()
def editor_policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(
        "identities:\n  bob@example.com: editor\ndefault_role: deny\n",
        encoding="utf-8",
    )
    return p


class TestEvidenceRBAC:
    def test_reader_can_query_history(
        self,
        runner: CliRunner,
        store_dir: Path,
        reader_policy_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from uuid import uuid4

        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(reader_policy_file))
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "alice@example.com")
        result = runner.invoke(
            app,
            [
                "evidence",
                "history",
                str(uuid4()),
                "--store-dir",
                str(store_dir),
            ],
        )
        # Reader allowed for "read"; the lineage just doesn't exist.
        assert result.exit_code == 0

    def test_reader_denied_save(
        self,
        runner: CliRunner,
        artifact_yaml: Path,
        store_dir: Path,
        reader_policy_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(reader_policy_file))
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "alice@example.com")
        result = runner.invoke(
            app,
            [
                "evidence",
                "save",
                str(artifact_yaml),
                "--store-dir",
                str(store_dir),
            ],
        )
        assert result.exit_code == 77  # EX_NOPERM

    def test_editor_can_save(
        self,
        runner: CliRunner,
        artifact_yaml: Path,
        store_dir: Path,
        editor_policy_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(editor_policy_file))
        monkeypatch.setenv("EVIDENTIA_RBAC_IDENTITY", "bob@example.com")
        result = runner.invoke(
            app,
            [
                "evidence",
                "save",
                str(artifact_yaml),
                "--store-dir",
                str(store_dir),
            ],
        )
        assert result.exit_code == 0, result.output

    def test_anonymous_denied_under_deny_default(
        self,
        runner: CliRunner,
        artifact_yaml: Path,
        store_dir: Path,
        reader_policy_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(reader_policy_file))
        # No EVIDENTIA_RBAC_IDENTITY → anonymous.
        result = runner.invoke(
            app,
            [
                "evidence",
                "save",
                str(artifact_yaml),
                "--store-dir",
                str(store_dir),
            ],
        )
        assert result.exit_code == 77
