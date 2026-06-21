"""Tests for ``scripts/check_doc_counts.py`` (v0.10.12 Wave 0).

The README "capabilities at a glance" counts (framework catalogs, inter-framework
crosswalks, evidence collectors, MCP tools) must equal the code-derived truth.
This gate parses the README table + derives each count from the live registries /
schema and fails on any drift.

The PURE functions (``parse_readme_counts``, ``compare_counts``,
``count_crosswalk_files``, ``count_mcp_tools``, ``count_collector_endpoints``)
are pinned here against tiny in-memory fixtures so the tests stay fast and
filesystem-/network-free. ``scripts/`` has no ``__init__.py``; the repo root is
placed on ``sys.path`` so it resolves as a PEP 420 namespace package, matching
the ``from scripts import …`` import form used across the gate tooling.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import check_doc_counts as c  # noqa: E402

_README_FIXTURE = """\
# Evidentia

Some prose mentioning 95 bundled catalogs that must NOT be parsed as a count.

| Capability | Count |
|---|---|
| Framework catalogs | 95 |
| Inter-framework crosswalks | 15 |
| Evidence collectors | 14 |
| MCP tools | 13 |
"""


def test_parse_readme_counts_extracts_the_four_table_rows() -> None:
    counts = c.parse_readme_counts(_README_FIXTURE)
    assert counts == {
        "catalogs": 95,
        "crosswalks": 15,
        "collectors": 14,
        "mcp_tools": 13,
    }


def test_parse_readme_counts_ignores_prose_numbers() -> None:
    # The "95 bundled catalogs" prose line is not a table row; only the
    # pipe-delimited "| label | int |" rows count.
    text = "Prose says 999 catalogs.\n| Framework catalogs | 95 |\n"
    assert c.parse_readme_counts(text)["catalogs"] == 95


def test_compare_counts_clean_when_equal() -> None:
    code = {"catalogs": 95, "crosswalks": 15, "collectors": 14, "mcp_tools": 13}
    readme = dict(code)
    assert c.compare_counts(code, readme) == []


def test_compare_counts_flags_mismatch() -> None:
    code = {"catalogs": 95, "crosswalks": 15, "collectors": 14, "mcp_tools": 13}
    readme = {"catalogs": 92, "crosswalks": 15, "collectors": 14, "mcp_tools": 13}
    errs = c.compare_counts(code, readme)
    assert len(errs) == 1
    assert "catalogs" in errs[0]
    assert "92" in errs[0] and "95" in errs[0]


def test_compare_counts_flags_missing_readme_key() -> None:
    code = {"catalogs": 95, "crosswalks": 15, "collectors": 14, "mcp_tools": 13}
    readme = {"catalogs": 95, "crosswalks": 15, "collectors": 14}  # mcp_tools absent
    errs = c.compare_counts(code, readme)
    assert any("mcp_tools" in e for e in errs)


def test_count_catalogs_counts_manifest_entries(tmp_path: Path) -> None:
    manifest = tmp_path / "frameworks.yaml"
    manifest.write_text(
        "version: 1\nframeworks:\n- id: a\n- id: b\n- id: c\n", encoding="utf-8"
    )
    assert c.count_catalogs(manifest) == 3


def test_count_catalogs_empty_manifest_is_zero(tmp_path: Path) -> None:
    manifest = tmp_path / "frameworks.yaml"
    manifest.write_text("version: 1\nframeworks: []\n", encoding="utf-8")
    assert c.count_catalogs(manifest) == 0


def test_count_crosswalk_files_counts_json_only(tmp_path: Path) -> None:
    (tmp_path / "a.json").write_text("{}", encoding="utf-8")
    (tmp_path / "b.json").write_text("{}", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("x", encoding="utf-8")
    assert c.count_crosswalk_files(tmp_path) == 2


def test_count_mcp_tools_counts_decorators() -> None:
    text = (
        "@server.tool()\n"
        "def a(): ...\n"
        "@server.tool()\n"
        "def b(): ...\n"
        "# @server.tool()  <- a comment, still a registration marker? no\n"
    )
    # Two real decorators; the commented line shares the token but is on a
    # comment line — the counter matches the decorator at column 0.
    assert c.count_mcp_tools(text) == 2


def test_count_collector_endpoints_counts_collect_paths() -> None:
    openapi = {
        "paths": {
            "/api/collectors/aws/collect": {"post": {}},
            "/api/collectors/sql/postgres/collect": {"post": {}},
            "/api/collectors/status": {"get": {}},
            "/api/gap/analyze": {"post": {}},
        }
    }
    assert c.count_collector_endpoints(openapi) == 2


def test_count_collector_endpoints_excludes_ocsf_ingest() -> None:
    # The OCSF ingest path (added v0.10.12 to mirror `evidentia collect ocsf`)
    # shares the /collect verb but is an importer of already-collected OCSF,
    # not a credentialed collection agent — it is excluded from the count.
    openapi = {
        "paths": {
            "/api/collectors/aws/collect": {"post": {}},
            "/api/collectors/ocsf/collect": {"post": {}},
        }
    }
    assert c.count_collector_endpoints(openapi) == 1
