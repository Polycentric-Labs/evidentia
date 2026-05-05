"""Unit + integration tests for evidentia-mcp (v0.8.0 P0.3).

Three test classes mirroring the three layers of the MCP package:

1. :class:`TestServerBuild` — server construction + tool
   registration (smoke-level; doesn't speak MCP protocol).
2. :class:`TestToolBehavior` — invoke each tool's underlying
   Python implementation directly via the FastMCP tool manager
   and validate the structured output. This is "library-level"
   testing — fast, deterministic, no subprocess.
3. :class:`TestCLI` — Typer CliRunner-driven tests of
   ``evidentia mcp doctor``. The ``serve`` verb is excluded
   (it blocks on stdin); operators validate it via the doctor
   command + an MCP client.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from evidentia_core.gap_analyzer.analyzer import GapAnalyzer
from evidentia_core.gap_analyzer.inventory import load_inventory
from evidentia_core.models.control import (
    ControlImplementation,
    ControlInventory,
    ControlStatus,
)
from evidentia_mcp.cli import app as mcp_cli_app
from evidentia_mcp.server import build_server
from typer.testing import CliRunner

# ── Test fixtures ──────────────────────────────────────────────────


@pytest.fixture
def tiny_inventory(tmp_path: Path) -> Path:
    """Write a minimal control inventory to disk + return the path."""
    inv = ControlInventory(
        organization="Test Org",
        system_name="test-system",
        controls=[
            ControlImplementation(
                id="AC-2",
                title="Account Management",
                description="Manage information system accounts.",
                status=ControlStatus.IMPLEMENTED,
                frameworks=["nist-800-53-rev5-moderate"],
            ),
            ControlImplementation(
                id="AC-3",
                title="Access Enforcement",
                description="Enforce approved authorizations.",
                status=ControlStatus.PLANNED,
                frameworks=["nist-800-53-rev5-moderate"],
            ),
        ],
    )
    path = tmp_path / "inventory.json"
    path.write_text(inv.model_dump_json(indent=2), encoding="utf-8")
    return path


@pytest.fixture
def tiny_report_paths(
    tiny_inventory: Path, tmp_path: Path
) -> tuple[Path, Path]:
    """Generate two GapAnalysisReport JSON files for diff testing."""
    inventory = load_inventory(tiny_inventory)
    analyzer = GapAnalyzer()
    base_report = analyzer.analyze(
        inventory=inventory,
        frameworks=["nist-800-53-rev5-moderate"],
        show_efficiency=False,
    )
    head_report = analyzer.analyze(
        inventory=inventory,
        frameworks=["nist-800-53-rev5-moderate"],
        show_efficiency=False,
    )
    base_path = tmp_path / "base-report.json"
    head_path = tmp_path / "head-report.json"
    base_path.write_text(base_report.model_dump_json(indent=2), encoding="utf-8")
    head_path.write_text(head_report.model_dump_json(indent=2), encoding="utf-8")
    return base_path, head_path


# ── 1. Server build ────────────────────────────────────────────────


class TestServerBuild:
    def test_build_server_returns_fastmcp_instance(self) -> None:
        from mcp.server.fastmcp import FastMCP

        server = build_server()
        assert isinstance(server, FastMCP)

    def test_server_name_is_evidentia(self) -> None:
        server = build_server()
        assert server.name == "evidentia"

    def test_four_core_tools_registered(self) -> None:
        server = build_server()
        # FastMCP exposes registered tools via _tool_manager._tools
        tools = set(server._tool_manager._tools.keys())
        assert {
            "list_frameworks",
            "get_control",
            "gap_analyze",
            "gap_diff",
        } <= tools

    def test_each_tool_has_a_description(self) -> None:
        """FastMCP renders the docstring as the MCP tool description."""
        server = build_server()
        for tool_name, tool_obj in server._tool_manager._tools.items():
            assert tool_obj.description, (
                f"Tool {tool_name!r} is missing a description; "
                f"FastMCP needs the function docstring populated."
            )


# ── 2. Tool behavior ───────────────────────────────────────────────


def _invoke_tool(server: Any, tool_name: str, **kwargs: Any) -> Any:
    """Call a registered tool's underlying Python function directly.

    FastMCP wraps the function in a ``Tool`` object. The original
    callable lives at ``tool.fn``.
    """
    tool = server._tool_manager._tools[tool_name]
    return tool.fn(**kwargs)


class TestListFrameworks:
    def test_returns_a_list_of_dicts(self) -> None:
        server = build_server()
        result = _invoke_tool(server, "list_frameworks")
        assert isinstance(result, list)
        assert len(result) > 0
        for entry in result:
            assert isinstance(entry, dict)
            for required_key in (
                "id",
                "name",
                "tier",
                "category",
            ):
                assert required_key in entry, (
                    f"framework metadata missing key {required_key!r}: {entry}"
                )

    def test_includes_nist_800_53_rev5(self) -> None:
        server = build_server()
        result = _invoke_tool(server, "list_frameworks")
        ids = {entry["id"] for entry in result}
        # nist-800-53-rev5-moderate ships in the bundled catalogs;
        # if this fails, the catalog registry has regressed.
        assert any(
            fid.startswith("nist-800-53-rev5") for fid in ids
        )


class TestGetControl:
    def test_returns_known_control(self) -> None:
        server = build_server()
        result = _invoke_tool(
            server,
            "get_control",
            framework_id="nist-800-53-rev5-moderate",
            control_id="AC-1",
        )
        assert isinstance(result, dict)
        assert result["id"] == "AC-1"
        assert "title" in result

    def test_unknown_control_raises_valueerror(self) -> None:
        server = build_server()
        with pytest.raises(ValueError, match="not found"):
            _invoke_tool(
                server,
                "get_control",
                framework_id="nist-800-53-rev5-moderate",
                control_id="ZZ-99999",
            )


class TestGapAnalyze:
    def test_runs_analysis_against_tiny_inventory(
        self, tiny_inventory: Path
    ) -> None:
        server = build_server()
        result = _invoke_tool(
            server,
            "gap_analyze",
            inventory_path=str(tiny_inventory),
            frameworks=["nist-800-53-rev5-moderate"],
        )
        assert isinstance(result, dict)
        # GapAnalysisReport always carries gaps + frameworks_analyzed fields.
        assert "gaps" in result
        assert "frameworks_analyzed" in result

    def test_missing_path_raises_filenotfound(
        self, tmp_path: Path
    ) -> None:
        server = build_server()
        with pytest.raises(FileNotFoundError):
            _invoke_tool(
                server,
                "gap_analyze",
                inventory_path=str(tmp_path / "does-not-exist.json"),
                frameworks=["nist-800-53-rev5-moderate"],
            )


class TestGapDiff:
    def test_diff_two_reports_returns_dict(
        self, tiny_report_paths: tuple[Path, Path]
    ) -> None:
        base_path, head_path = tiny_report_paths
        server = build_server()
        result = _invoke_tool(
            server,
            "gap_diff",
            base_report_path=str(base_path),
            head_report_path=str(head_path),
        )
        assert isinstance(result, dict)
        # GapDiff always carries summary + entries fields.
        assert "summary" in result or "entries" in result

    def test_missing_base_raises_filenotfound(
        self,
        tmp_path: Path,
        tiny_report_paths: tuple[Path, Path],
    ) -> None:
        _base, head_path = tiny_report_paths
        server = build_server()
        with pytest.raises(FileNotFoundError, match="Base report"):
            _invoke_tool(
                server,
                "gap_diff",
                base_report_path=str(tmp_path / "nonexistent.json"),
                head_report_path=str(head_path),
            )

    def test_unparseable_report_raises_valueerror(
        self,
        tmp_path: Path,
        tiny_report_paths: tuple[Path, Path],
    ) -> None:
        _base, head_path = tiny_report_paths
        broken = tmp_path / "broken.json"
        broken.write_text(json.dumps({"not": "a-report"}), encoding="utf-8")
        server = build_server()
        with pytest.raises(ValueError, match="cannot be parsed"):
            _invoke_tool(
                server,
                "gap_diff",
                base_report_path=str(broken),
                head_report_path=str(head_path),
            )


# ── 3. CLI doctor ──────────────────────────────────────────────────


class TestCLI:
    def test_doctor_returns_zero_on_pass(self) -> None:
        runner = CliRunner()
        result = runner.invoke(mcp_cli_app, ["doctor"])
        assert result.exit_code == 0
        assert "PASS" in result.stdout
        assert "MCP SDK" in result.stdout

    def test_serve_with_no_stdio_exits_2(self) -> None:
        """Operators trying to bypass stdio get a clear error."""
        runner = CliRunner()
        # We pass --no-stdio which the implementation rejects.
        result = runner.invoke(mcp_cli_app, ["serve", "--no-stdio"])
        assert result.exit_code == 2
