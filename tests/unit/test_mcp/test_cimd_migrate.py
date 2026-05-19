"""Tests for v0.9.7 P1.2 `evidentia mcp cimd-migrate` CLI verb.

Closes F-V96-conmon-mcp-cimd-migration: the v0.9.6 cycle added
4 new MCP tools (``conmon_*``) but pre-v0.9.6 CIMD registries
default-reject them. This verb adds the new tool names to each
client's scope so operators upgrading don't have to hand-edit
JSON.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def registry_file(tmp_path: Path) -> Path:
    """A CIMD registry with two clients, neither having conmon_* tools."""
    payload = {
        "version": 1,
        "clients": {
            "claude-desktop": {
                "client_id": "claude-desktop",
                "client_name": "Claude Desktop",
                "scope": (
                    "list_frameworks get_control gap_analyze gap_diff"
                ),
                "redirect_uris": [],
                "policy_uri": None,
                "tos_uri": None,
            },
            "readonly-agent": {
                "client_id": "readonly-agent",
                "client_name": "Read-Only Agent",
                "scope": "list_frameworks get_control",
                "redirect_uris": [],
                "policy_uri": None,
                "tos_uri": None,
            },
        },
    }
    p = tmp_path / "registry.json"
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return p


class TestCIMDMigrate:
    def test_dry_run_does_not_modify(
        self,
        runner: CliRunner,
        registry_file: Path,
    ) -> None:
        before = registry_file.read_text(encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "mcp",
                "cimd-migrate",
                str(registry_file),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "DRY RUN" in result.output
        assert "registry file NOT modified" in result.output
        # File unchanged.
        assert registry_file.read_text(encoding="utf-8") == before

    def test_apply_adds_conmon_tools_to_all_clients(
        self,
        runner: CliRunner,
        registry_file: Path,
    ) -> None:
        result = runner.invoke(
            app,
            ["mcp", "cimd-migrate", str(registry_file)],
        )
        assert result.exit_code == 0, result.output
        assert "Migration applied" in result.output

        updated = json.loads(registry_file.read_text(encoding="utf-8"))
        for cid in ("claude-desktop", "readonly-agent"):
            scope = updated["clients"][cid]["scope"].split()
            for tool in (
                "conmon_list_cadences",
                "conmon_next_due",
                "conmon_check_state",
                "conmon_health",
            ):
                assert tool in scope, (
                    f"{cid} missing {tool} after migration"
                )

    def test_apply_preserves_existing_scope(
        self,
        runner: CliRunner,
        registry_file: Path,
    ) -> None:
        result = runner.invoke(
            app,
            ["mcp", "cimd-migrate", str(registry_file)],
        )
        assert result.exit_code == 0, result.output
        updated = json.loads(registry_file.read_text(encoding="utf-8"))
        # claude-desktop kept its 4 original tools.
        scope = updated["clients"]["claude-desktop"]["scope"].split()
        for tool in (
            "list_frameworks",
            "get_control",
            "gap_analyze",
            "gap_diff",
        ):
            assert tool in scope

    def test_idempotent_second_run_no_change(
        self,
        runner: CliRunner,
        registry_file: Path,
    ) -> None:
        # First run applies the migration.
        runner.invoke(app, ["mcp", "cimd-migrate", str(registry_file)])
        # Second run is a no-op.
        result = runner.invoke(
            app,
            ["mcp", "cimd-migrate", str(registry_file)],
        )
        assert result.exit_code == 0
        assert "No changes required" in result.output

    def test_client_id_filter(
        self,
        runner: CliRunner,
        registry_file: Path,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "mcp",
                "cimd-migrate",
                str(registry_file),
                "--client-id",
                "readonly-agent",
            ],
        )
        assert result.exit_code == 0, result.output
        updated = json.loads(registry_file.read_text(encoding="utf-8"))
        # readonly-agent updated; claude-desktop UNCHANGED.
        assert (
            "conmon_list_cadences"
            in updated["clients"]["readonly-agent"]["scope"].split()
        )
        assert (
            "conmon_list_cadences"
            not in updated["clients"]["claude-desktop"]["scope"].split()
        )

    def test_unknown_client_id_exits_1(
        self,
        runner: CliRunner,
        registry_file: Path,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "mcp",
                "cimd-migrate",
                str(registry_file),
                "--client-id",
                "no-such-client",
            ],
        )
        assert result.exit_code == 1
        assert "not in registry" in result.output

    def test_custom_tools_override(
        self,
        runner: CliRunner,
        registry_file: Path,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "mcp",
                "cimd-migrate",
                str(registry_file),
                "--tools",
                "new_future_tool_a new_future_tool_b",
            ],
        )
        assert result.exit_code == 0, result.output
        updated = json.loads(registry_file.read_text(encoding="utf-8"))
        for cid in ("claude-desktop", "readonly-agent"):
            scope = updated["clients"][cid]["scope"].split()
            assert "new_future_tool_a" in scope
            assert "new_future_tool_b" in scope
            # conmon_* NOT added (operator overrode the default set)
            assert "conmon_list_cadences" not in scope

    def test_invalid_registry_exits_1(
        self,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{", encoding="utf-8")
        result = runner.invoke(
            app,
            ["mcp", "cimd-migrate", str(bad)],
        )
        assert result.exit_code == 1
        assert "Invalid JSON" in result.output

    def test_atomic_write_no_tmp_left(
        self,
        runner: CliRunner,
        registry_file: Path,
    ) -> None:
        result = runner.invoke(
            app,
            ["mcp", "cimd-migrate", str(registry_file)],
        )
        assert result.exit_code == 0
        # No .tmp file left in the directory.
        tmp_files = list(registry_file.parent.glob("*.tmp"))
        assert tmp_files == []
