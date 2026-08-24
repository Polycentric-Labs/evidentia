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


# ── parity badge (v0.12.1) ────────────────────────────────────────────────

_BADGE = (
    '<a href="docs/parity-coverage.md"><img src="https://img.shields.io/badge/'
    'CLI%E2%86%94GUI%20parity-{pct}%25-brightgreen.svg" alt="CLI↔GUI parity"></a>'
)


def _patch_live_pct(monkeypatch, pct: float) -> None:
    """Stand in for the check_parity import so the test needs no manifest."""
    import types

    fake = types.SimpleNamespace(
        load_manifest=lambda *a, **k: {"commands": []},
        status_counts=lambda rows: {},
        coverage_pct=lambda counts: pct,
    )

    class _Loader:
        @staticmethod
        def exec_module(mod) -> None:
            mod.load_manifest = fake.load_manifest
            mod.status_counts = fake.status_counts
            mod.coverage_pct = fake.coverage_pct

    class _Spec:
        loader = _Loader()

    monkeypatch.setattr(
        c.importlib.util, "spec_from_file_location", lambda *a, **k: _Spec()
    )
    monkeypatch.setattr(
        c.importlib.util, "module_from_spec", lambda spec: types.SimpleNamespace()
    )


def test_parity_badge_passes_when_it_matches_live(monkeypatch) -> None:
    _patch_live_pct(monkeypatch, 100.0)
    assert c.check_parity_badge(_BADGE.format(pct=100)) == []


def test_parity_badge_fails_on_the_real_v0120_drift(monkeypatch) -> None:
    """The exact defect: badge frozen at 93 while parity reached 100.

    The badge was hardcoded during the pre-v0.11.0 claim sweep and nothing
    compared it to the live number, so it understated a shipped capability by
    seven points on the project's most public surface for a full release.
    """
    _patch_live_pct(monkeypatch, 100.0)
    errs = c.check_parity_badge(_BADGE.format(pct=93))
    assert len(errs) == 1
    assert "93%" in errs[0] and "100.0%" in errs[0]


def test_parity_badge_tolerates_rounding(monkeypatch) -> None:
    """A whole-percent badge may legally round a fractional coverage number."""
    _patch_live_pct(monkeypatch, 93.4)
    assert c.check_parity_badge(_BADGE.format(pct=93)) == []


def test_parity_badge_fails_when_the_badge_is_missing(monkeypatch) -> None:
    """A removed or reformatted badge must fail loudly, not silently pass."""
    _patch_live_pct(monkeypatch, 100.0)
    errs = c.check_parity_badge("# Evidentia\n\nNo badge here.\n")
    assert len(errs) == 1
    assert "no CLI<->GUI parity badge" in errs[0]
