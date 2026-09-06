"""Unit tests for the v0.9.6 P4 CONMON MCP tools (first-mover wrap).

Tests the 4 new tools registered on the FastMCP server:

- ``conmon_list_cadences`` — bundled-cadence inventory.
- ``conmon_next_due`` — per-slug next-due computation.
- ``conmon_check_state`` — state-file → overdue / due_soon / current.
- ``conmon_health`` — wrapper around v0.9.5 ``health_from_state_file``.

Tests are library-level (direct tool function invocation via the
FastMCP tool manager), not subprocess-level. The MCP protocol layer
is exercised by the v0.8.0 test_server.py base suite.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from evidentia_core.evidence_store import save_evidence
from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType
from evidentia_core.security.paths import PathTraversalError
from evidentia_mcp.server import build_server


def _invoke_tool(server: Any, tool_name: str, **kwargs: Any) -> Any:
    """Call a registered tool's underlying Python function directly."""
    tool = server._tool_manager._tools[tool_name]
    return tool.fn(**kwargs)


def _save_artifact(
    store: Path,
    collected: datetime,
    slug: str = "pci-dss-11-6-1-weekly",
    source: str = "nessus",
) -> None:
    """Save one evidence artifact linked to ``slug`` at ``collected``."""
    artifact = EvidenceArtifact.model_validate(
        {
            "title": f"scan {collected.date().isoformat()}",
            "evidence_type": EvidenceType.TEST_RESULT,
            "source_system": source,
            "collected_by": "test-runner@example.com",
            "collected_at": collected,
            "content": {"ok": True},
            "metadata": {"cadence_slug": slug},
        }
    )
    save_evidence(artifact, evidence_store_dir=store)


# ── conmon_list_cadences ───────────────────────────────────────────


class TestListCadences:
    def test_returns_a_list_of_dicts(self) -> None:
        server = build_server()
        result = _invoke_tool(server, "conmon_list_cadences")
        assert isinstance(result, list)
        assert len(result) > 0
        for entry in result:
            assert isinstance(entry, dict)
            assert "slug" in entry
            assert "framework" in entry
            assert "frequency" in entry

    def test_includes_nist_ca7(self) -> None:
        server = build_server()
        result = _invoke_tool(server, "conmon_list_cadences")
        slugs = {entry["slug"] for entry in result}
        assert "nist-800-53-rev5-ca7" in slugs

    def test_framework_filter(self) -> None:
        server = build_server()
        result = _invoke_tool(
            server,
            "conmon_list_cadences",
            framework="fedramp-rev5-mod",
        )
        if result:
            for entry in result:
                assert entry["framework"] == "fedramp-rev5-mod"

    def test_unknown_framework_returns_empty(self) -> None:
        server = build_server()
        result = _invoke_tool(
            server,
            "conmon_list_cadences",
            framework="not-a-real-framework",
        )
        assert result == []


# ── conmon_next_due ────────────────────────────────────────────────


class TestNextDue:
    def test_happy_path(self) -> None:
        server = build_server()
        result = _invoke_tool(
            server,
            "conmon_next_due",
            slug="nist-800-53-rev5-ca7",
            last_completed="2026-04-01",
        )
        assert result["slug"] == "nist-800-53-rev5-ca7"
        assert result["last_completed"] == "2026-04-01"
        assert "next_due" in result
        # CA-7 monthly cadence → next_due should be after 2026-04-01.
        assert result["next_due"] > "2026-04-01"

    def test_unknown_slug_raises_value_error(self) -> None:
        server = build_server()
        with pytest.raises(ValueError, match="Unknown CONMON cadence"):
            _invoke_tool(
                server,
                "conmon_next_due",
                slug="not-a-real-slug",
                last_completed="2026-04-01",
            )

    def test_bad_date_raises_value_error(self) -> None:
        server = build_server()
        with pytest.raises(ValueError, match="ISO-8601 date"):
            _invoke_tool(
                server,
                "conmon_next_due",
                slug="nist-800-53-rev5-ca7",
                last_completed="not-a-date",
            )


# ── conmon_check_state ─────────────────────────────────────────────


@pytest.fixture()
def state_file(tmp_path: Path) -> Path:
    """A state-file with one overdue cadence + one current cadence."""
    p = tmp_path / "state.yaml"
    # CA-7 is monthly; 2025-01-01 → overdue under any 2026 today.
    p.write_text("nist-800-53-rev5-ca7: 2025-01-01\n", encoding="utf-8")
    return p


class TestCheckState:
    def test_returns_attention_buckets(self, state_file: Path) -> None:
        server = build_server()
        result = _invoke_tool(
            server,
            "conmon_check_state",
            state_file_path=str(state_file),
        )
        assert "overdue" in result
        assert "due_soon" in result
        assert "current" in result
        # CA-7 anchored 2025-01-01 → overdue today.
        assert len(result["overdue"]) >= 1

    def test_missing_state_file_raises(self, tmp_path: Path) -> None:
        server = build_server()
        with pytest.raises(FileNotFoundError):
            _invoke_tool(
                server,
                "conmon_check_state",
                state_file_path=str(tmp_path / "does-not-exist.yaml"),
            )

    def test_invalid_yaml_raises_value_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("not: valid: yaml\n", encoding="utf-8")
        server = build_server()
        with pytest.raises(ValueError):
            _invoke_tool(
                server,
                "conmon_check_state",
                state_file_path=str(bad),
            )

    def test_top_level_list_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "list.yaml"
        bad.write_text("- entry-1\n- entry-2\n", encoding="utf-8")
        server = build_server()
        with pytest.raises(ValueError, match="mapping"):
            _invoke_tool(
                server,
                "conmon_check_state",
                state_file_path=str(bad),
            )

    def test_unknown_slug_skipped(self, tmp_path: Path) -> None:
        state = tmp_path / "state.yaml"
        state.write_text(
            "not-a-real-cadence: 2026-04-01\nnist-800-53-rev5-ca7: 2026-04-01\n",
            encoding="utf-8",
        )
        server = build_server()
        result = _invoke_tool(
            server,
            "conmon_check_state",
            state_file_path=str(state),
        )
        # Unknown slug filtered silently; CA-7 surfaces in one bucket.
        all_slugs = (
            {e["slug"] for e in result["overdue"]}
            | {e["slug"] for e in result["due_soon"]}
            | {e["slug"] for e in result["current"]}
        )
        assert "nist-800-53-rev5-ca7" in all_slugs
        assert "not-a-real-cadence" not in all_slugs

    def test_window_days_respected(self, state_file: Path) -> None:
        server = build_server()
        # Far-future window should bucket the entry as overdue (it
        # is); just confirm no crash.
        result = _invoke_tool(
            server,
            "conmon_check_state",
            state_file_path=str(state_file),
            window_days=365,
        )
        assert result["window_days"] == 365


# ── conmon_health ──────────────────────────────────────────────────


class TestHealth:
    def test_returns_dict_report(self, state_file: Path) -> None:
        server = build_server()
        result = _invoke_tool(
            server,
            "conmon_health",
            state_file_path=str(state_file),
        )
        assert isinstance(result, dict)
        # Health report ships a posture summary; just confirm shape.

    def test_missing_state_file_raises(self, tmp_path: Path) -> None:
        server = build_server()
        with pytest.raises(FileNotFoundError):
            _invoke_tool(
                server,
                "conmon_health",
                state_file_path=str(tmp_path / "missing.yaml"),
            )


# ── conmon_series (v0.13, V13-01) ───────────────────────────────────


class TestSeries:
    """``conmon_series``: the cadence evidence series MCP tool."""

    def test_continuous_series_happy_path(self, tmp_path: Path) -> None:
        store = tmp_path / "store"
        start = datetime(2026, 6, 1, 9, tzinfo=UTC)
        for i in range(3):
            _save_artifact(store, start + timedelta(days=7 * i))

        server = build_server()
        result = _invoke_tool(
            server,
            "conmon_series",
            slug="pci-dss-11-6-1-weekly",
            evidence_store_dir=str(store),
            since="2026-06-01",
            until="2026-06-15",
        )
        assert result["series"]["slug"] == "pci-dss-11-6-1-weekly"
        assert result["series"]["verdict"] == "continuous"
        assert len(result["series"]["observations"]) == 3
        assert "evidence of cadence" in result["description"]

    def test_gapped_series(self, tmp_path: Path) -> None:
        store = tmp_path / "store"
        start = datetime(2026, 6, 1, 9, tzinfo=UTC)
        for offset in (0, 7, 21):  # day 14 missing -> one gap
            _save_artifact(store, start + timedelta(days=offset))

        server = build_server()
        result = _invoke_tool(
            server,
            "conmon_series",
            slug="pci-dss-11-6-1-weekly",
            evidence_store_dir=str(store),
            since="2026-06-01",
            until="2026-06-22",
        )
        assert result["series"]["verdict"] == "gapped"
        assert len(result["series"]["gaps"]) == 1

    def test_default_window_used_when_dates_omitted(self, tmp_path: Path) -> None:
        """No store contents + no explicit dates -> a valid (insufficient) result."""
        store = tmp_path / "store"
        server = build_server()
        result = _invoke_tool(
            server,
            "conmon_series",
            slug="nist-800-53-rev5-ca7",
            evidence_store_dir=str(store),
        )
        assert result["series"]["verdict"] == "insufficient"

    def test_unknown_slug_raises_value_error(self, tmp_path: Path) -> None:
        server = build_server()
        with pytest.raises(ValueError, match="Unknown CONMON cadence"):
            _invoke_tool(
                server,
                "conmon_series",
                slug="not-a-real-slug",
                evidence_store_dir=str(tmp_path),
            )

    def test_bad_date_raises_value_error(self, tmp_path: Path) -> None:
        server = build_server()
        with pytest.raises(ValueError, match="ISO-8601"):
            _invoke_tool(
                server,
                "conmon_series",
                slug="nist-800-53-rev5-ca7",
                evidence_store_dir=str(tmp_path),
                since="not-a-date",
            )

    def test_until_before_since_raises_value_error(self, tmp_path: Path) -> None:
        server = build_server()
        with pytest.raises(ValueError, match="before"):
            _invoke_tool(
                server,
                "conmon_series",
                slug="nist-800-53-rev5-ca7",
                evidence_store_dir=str(tmp_path),
                since="2026-06-15",
                until="2026-06-01",
            )

    def test_allow_root_rejects_path_outside_root(self, tmp_path: Path) -> None:
        safe_root = tmp_path / "safe"
        safe_root.mkdir()
        outside = tmp_path / "outside-store"
        outside.mkdir()

        server = build_server(allow_root=safe_root)
        with pytest.raises(PathTraversalError):
            _invoke_tool(
                server,
                "conmon_series",
                slug="nist-800-53-rev5-ca7",
                evidence_store_dir=str(outside),
            )

    def test_allow_root_accepts_path_inside_root(self, tmp_path: Path) -> None:
        safe_root = tmp_path / "safe"
        safe_root.mkdir()
        store = safe_root / "store"

        server = build_server(allow_root=safe_root)
        result = _invoke_tool(
            server,
            "conmon_series",
            slug="nist-800-53-rev5-ca7",
            evidence_store_dir=str(store),
            since="2026-06-01",
            until="2026-06-15",
        )
        assert result["series"]["verdict"] == "insufficient"

    def test_no_allow_root_accepts_any_path(self, tmp_path: Path) -> None:
        store = tmp_path / "store"
        server = build_server(allow_root=None)
        result = _invoke_tool(
            server,
            "conmon_series",
            slug="nist-800-53-rev5-ca7",
            evidence_store_dir=str(store),
            since="2026-06-01",
            until="2026-06-15",
        )
        assert result["series"]["verdict"] == "insufficient"


# ── tool registration ──────────────────────────────────────────────


class TestToolRegistration:
    def test_all_four_conmon_tools_registered(self) -> None:
        server = build_server()
        registered = set(server._tool_manager._tools.keys())
        expected = {
            "conmon_list_cadences",
            "conmon_next_due",
            "conmon_check_state",
            "conmon_health",
            "conmon_series",
        }
        assert expected.issubset(registered), f"Missing CONMON MCP tools: {expected - registered}"

    def test_each_conmon_tool_has_description(self) -> None:
        server = build_server()
        for tool_name in (
            "conmon_list_cadences",
            "conmon_next_due",
            "conmon_check_state",
            "conmon_health",
            "conmon_series",
        ):
            tool = server._tool_manager._tools[tool_name]
            assert tool.description, (
                f"CONMON tool {tool_name!r} has no description; "
                "operators using MCP tool-picker UIs need the "
                "docstring populated."
            )
