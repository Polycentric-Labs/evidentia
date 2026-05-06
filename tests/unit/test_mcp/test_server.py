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
import sys
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
from evidentia_core.security.paths import PathTraversalError
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
        # v0.8.1 F-V08-CR-4: use public list_tools() async API
        # rather than _tool_manager._tools private access.
        import asyncio

        server = build_server()
        tools = asyncio.run(server.list_tools())
        registered = {t.name for t in tools}
        assert {
            "list_frameworks",
            "get_control",
            "gap_analyze",
            "gap_diff",
        } <= registered

    def test_each_tool_has_a_description(self) -> None:
        """FastMCP renders the docstring as the MCP tool description."""
        # v0.8.1 F-V08-CR-4: public list_tools() API.
        import asyncio

        server = build_server()
        tools = asyncio.run(server.list_tools())
        for tool in tools:
            assert tool.description, (
                f"Tool {tool.name!r} is missing a description; "
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


# ── 2.5 v0.8.2 F-V81-S1 path-input gating ─────────────────────────


class TestGapAnalyzePathGating:
    """v0.8.2 F-V81-S1: file-path input gating via --allow-root.

    Mirrors the existing path-traversal patterns in
    ``tests/unit/test_security_paths.py`` to enforce the same
    rejections at the MCP tool boundary.
    """

    def test_allow_root_none_preserves_v081_behavior(
        self, tiny_inventory: Path
    ) -> None:
        """No --allow-root → file-path tools accept any readable path
        (backward-compat with v0.8.1 stdio default)."""
        server = build_server(allow_root=None)
        # tiny_inventory lives in pytest's tmp_path; with allow_root=None
        # the gating short-circuits and the call succeeds as before.
        result = _invoke_tool(
            server,
            "gap_analyze",
            inventory_path=str(tiny_inventory),
            frameworks=["nist-800-53-rev5-moderate"],
        )
        assert isinstance(result, dict)
        assert "gaps" in result

    def test_allow_root_accepts_inside(
        self, tiny_inventory: Path, tmp_path: Path
    ) -> None:
        """Inventory path inside --allow-root → call succeeds."""
        # tiny_inventory is created under tmp_path; bind allow_root to tmp_path.
        server = build_server(allow_root=tmp_path)
        result = _invoke_tool(
            server,
            "gap_analyze",
            inventory_path=str(tiny_inventory),
            frameworks=["nist-800-53-rev5-moderate"],
        )
        assert isinstance(result, dict)
        assert "gaps" in result

    def test_allow_root_rejects_dotdot_traversal(
        self, tmp_path: Path
    ) -> None:
        """``..`` segments escaping --allow-root → PathTraversalError."""
        safe_root = tmp_path / "store"
        safe_root.mkdir()
        sibling = tmp_path / "outside.json"
        sibling.write_text("{}", encoding="utf-8")
        candidate = safe_root / ".." / "outside.json"

        server = build_server(allow_root=safe_root)
        # PathTraversalError is a ValueError subclass; assert the
        # specific subclass to lock in the contract.
        with pytest.raises(PathTraversalError):
            _invoke_tool(
                server,
                "gap_analyze",
                inventory_path=str(candidate),
                frameworks=["nist-800-53-rev5-moderate"],
            )

    def test_allow_root_rejects_absolute_outside(
        self, tmp_path: Path
    ) -> None:
        """Absolute path outside --allow-root → PathTraversalError."""
        safe_root = tmp_path / "store"
        safe_root.mkdir()
        elsewhere = tmp_path / "elsewhere.json"
        elsewhere.write_text("{}", encoding="utf-8")

        server = build_server(allow_root=safe_root)
        with pytest.raises(PathTraversalError):
            _invoke_tool(
                server,
                "gap_analyze",
                inventory_path=str(elsewhere),
                frameworks=["nist-800-53-rev5-moderate"],
            )

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="symlink creation requires elevated privileges on Windows",
    )
    def test_allow_root_rejects_symlink_escape(
        self, tmp_path: Path
    ) -> None:
        """Symlink inside --allow-root pointing outside → rejected."""
        import os

        safe_root = tmp_path / "store"
        safe_root.mkdir()
        target = tmp_path / "outside.json"
        target.write_text("{}", encoding="utf-8")
        link = safe_root / "trojan.json"
        os.symlink(target, link)

        server = build_server(allow_root=safe_root)
        with pytest.raises(PathTraversalError):
            _invoke_tool(
                server,
                "gap_analyze",
                inventory_path=str(link),
                frameworks=["nist-800-53-rev5-moderate"],
            )


class TestGapDiffPathGating:
    """v0.8.2 F-V81-S1: gap_diff has 2 path inputs; both must gate."""

    def test_allow_root_rejects_base_outside(
        self,
        tmp_path: Path,
        tiny_report_paths: tuple[Path, Path],
    ) -> None:
        """base_report_path outside --allow-root → PathTraversalError."""
        _base, head_path = tiny_report_paths
        # Bind allow_root to a sub-directory that does NOT contain
        # the existing tiny_report_paths fixture.
        safe_root = tmp_path / "isolated"
        safe_root.mkdir()
        elsewhere = tmp_path / "elsewhere-base.json"
        elsewhere.write_text(json.dumps({}), encoding="utf-8")

        server = build_server(allow_root=safe_root)
        with pytest.raises(PathTraversalError):
            _invoke_tool(
                server,
                "gap_diff",
                base_report_path=str(elsewhere),
                head_report_path=str(head_path),
            )

    def test_allow_root_rejects_head_outside(
        self,
        tmp_path: Path,
        tiny_report_paths: tuple[Path, Path],
    ) -> None:
        """head_report_path outside --allow-root → PathTraversalError."""
        base_path, _head = tiny_report_paths
        safe_root = tmp_path / "isolated"
        safe_root.mkdir()
        elsewhere = tmp_path / "elsewhere-head.json"
        elsewhere.write_text(json.dumps({}), encoding="utf-8")

        server = build_server(allow_root=safe_root)
        with pytest.raises(PathTraversalError):
            _invoke_tool(
                server,
                "gap_diff",
                base_report_path=str(base_path),
                head_report_path=str(elsewhere),
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
        """Operators trying to bypass stdio without --transport
        get a clear error pointing at the new flag."""
        # CliRunner's mix_stderr=False keeps stderr separately
        # captured; without it, the err output is mixed into
        # stdout. Use mix_stderr=False so we can assert on the
        # error message specifically.
        runner = CliRunner(mix_stderr=False)
        # We pass --no-stdio which the implementation rejects
        # (with a hint to use --transport instead).
        result = runner.invoke(mcp_cli_app, ["serve", "--no-stdio"])
        assert result.exit_code == 2
        # The error message points at --transport.
        assert "--transport" in result.stderr

    def test_serve_help_shows_transport_choices(self) -> None:
        """v0.8.1 P3.1: --transport flag is documented + offers
        stdio/sse/http choices.

        Inspect the Typer command's underlying Click parameter
        metadata directly rather than the rendered help output.
        Help-output rendering goes through Rich and depends on
        terminal-width detection + ANSI styling, both of which
        vary unpredictably across local/CI/OS — checking the
        parameter declarations directly is deterministic.
        """
        import click
        from typer.main import get_command

        click_app = get_command(mcp_cli_app)
        # click_app is a Group; .get_command(ctx, name) walks
        # subcommands. Pass ctx=None — no command actually runs.
        assert isinstance(click_app, click.Group)
        serve_cmd = click_app.get_command(None, "serve")  # type: ignore[arg-type]
        assert serve_cmd is not None, "serve subcommand missing"

        opt_flags = {opt for p in serve_cmd.params for opt in p.opts}
        assert "--transport" in opt_flags

        # Locate the transport param + assert its Choice values.
        transport_param = next(
            p for p in serve_cmd.params if "--transport" in p.opts
        )
        # Typer renders enum-typed Options as click.Choice; the
        # choices are the enum's value strings.
        assert isinstance(transport_param.type, click.Choice)
        choice_values = set(transport_param.type.choices)
        assert {"stdio", "sse", "http"}.issubset(choice_values)

    def test_serve_help_shows_host_port(self) -> None:
        """v0.8.1 P3.1: --host + --port flags are documented."""
        import click
        from typer.main import get_command

        click_app = get_command(mcp_cli_app)
        assert isinstance(click_app, click.Group)
        serve_cmd = click_app.get_command(None, "serve")  # type: ignore[arg-type]
        assert serve_cmd is not None, "serve subcommand missing"

        opt_flags = {opt for p in serve_cmd.params for opt in p.opts}
        assert "--host" in opt_flags
        assert "--port" in opt_flags

    def test_serve_help_shows_allow_root(self) -> None:
        """v0.8.2 F-V81-S1: --allow-root flag is documented."""
        import click
        from typer.main import get_command

        click_app = get_command(mcp_cli_app)
        assert isinstance(click_app, click.Group)
        serve_cmd = click_app.get_command(None, "serve")  # type: ignore[arg-type]
        assert serve_cmd is not None, "serve subcommand missing"

        opt_flags = {opt for p in serve_cmd.params for opt in p.opts}
        assert "--allow-root" in opt_flags
