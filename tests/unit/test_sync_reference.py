"""Tests for ``scripts/wiki/sync_reference.py`` (D6 Batch 2, v0.10.7).

The reference-page generator mechanically renders the wiki's
``4-reference/`` section (CLI, MCP tools, configuration, catalogs,
crosswalks) from the live Evidentia code/data. These tests pin the
non-trivial *extraction* logic — the AST parse of ``@server.tool()``
functions, the ``EVIDENTIA_*`` env-var scan, the ``evidentia.yaml``
Pydantic-schema parse, the ``frameworks.yaml`` manifest parse, and the
crosswalk-JSON parse — against tiny inline fixtures (no network, no full
project import), plus the ``--check`` drift comparison via ``tmp_path``.

Test plan:

1. ``collect_mcp_tools_ordered`` finds only ``@server.tool()`` functions,
   in source (registration) order, with rendered signature + first
   docstring line; ignores undecorated / differently-decorated functions.
2. ``_format_signature`` renders annotations + defaults correctly.
3. ``collect_env_vars`` extracts ``EVIDENTIA_*`` NAMES (sorted, de-duped)
   from .py source and ignores non-matching literals.
4. ``collect_yaml_schema`` pulls the Pydantic ``Field`` keys + types +
   descriptions, flattens ``llm.*``, and drops the ``source_path``
   internal field.
5. ``parse_frameworks_manifest`` + ``render_catalogs`` compute the
   headline count, per-family subtotals, and the text-depth summary from
   the data (not hardcoded).
6. ``parse_crosswalk`` handles both JSON shapes (with/without
   ``verification``) and counts ``mappings`` rows; with a
   ``CrosswalkResolution`` it renders the ``n/N (p%)`` display strings, and
   without one (or when a side has no bundled catalog) it renders
   ``"not bundled"``. ``render_crosswalks`` computes the total row sum and
   carries the two resolution columns. ``collect_crosswalks`` computes a
   resolution per file when a registry is given.
7. ``build_banner`` emits the HTML-comment marker + visible blockquote +
   H1 naming the generator.
8. ``compare`` (the pure ``--check`` comparison) returns no drift on a
   match, flags a mutated committed page, and reports a missing page.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GEN_PATH = REPO_ROOT / "scripts" / "wiki" / "sync_reference.py"


@pytest.fixture(scope="module")
def mod() -> Any:
    """Import scripts/wiki/sync_reference.py (no __init__.py).

    The module imports only stdlib + PyYAML at module scope (the Typer/Click
    imports are deferred into the CLI-collection functions), so it loads
    cleanly via importlib without putting ``scripts/wiki/`` on ``sys.path``
    and without requiring the full evidentia project to be installed.
    """
    spec = importlib.util.spec_from_file_location("sync_reference", GEN_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["sync_reference"] = module
    spec.loader.exec_module(module)
    return module


# --- MCP tool AST parse ----------------------------------------------------


MCP_FIXTURE = '''
def build_server():
    """Not a tool — undecorated."""

    @other.decorator()
    def not_a_tool():
        """Different decorator."""

    @server.tool()
    def list_things() -> list[dict[str, str]]:
        """List the things.

        Longer description on a later line.
        """

    @server.tool()
    def get_thing(thing_id: str, verbose: bool = True) -> dict[str, str]:
        """Return one thing by id."""
'''


def test_collect_mcp_tools_finds_only_tools_in_order(mod: Any) -> None:
    tools = mod.collect_mcp_tools_ordered(MCP_FIXTURE)
    names = [t["name"] for t in tools]
    # Only the two @server.tool() functions, in source order.
    assert names == ["list_things", "get_thing"]
    # First docstring line only (not the longer trailing description).
    assert tools[0]["summary"] == "List the things."
    assert tools[1]["summary"] == "Return one thing by id."


def test_collect_mcp_tools_renders_signatures(mod: Any) -> None:
    tools = mod.collect_mcp_tools_ordered(MCP_FIXTURE)
    assert tools[0]["signature"] == "list_things() -> list[dict[str, str]]"
    assert tools[1]["signature"] == "get_thing(thing_id: str, verbose: bool = True) -> dict[str, str]"


def test_format_signature_handles_no_return_and_no_annotation(mod: Any) -> None:
    import ast

    src = "def f(a, b: int, c=3):\n    pass\n"
    func = ast.parse(src).body[0]
    assert mod._format_signature(func) == "f(a, b: int, c = 3)"


# --- env-var scan ----------------------------------------------------------


def test_collect_env_vars_extracts_names_sorted_and_deduped(mod: Any, tmp_path: Path) -> None:
    pkg = tmp_path / "packages"
    (pkg / "a").mkdir(parents=True)
    (pkg / "b").mkdir(parents=True)
    (pkg / "a" / "x.py").write_text(
        'v = os.environ.get("EVIDENTIA_GAP_STORE_DIR")\n'
        'pw = os.getenv("EVIDENTIA_POSTGRES_PASSWORD")\n'
        # Non-matching literals are ignored.
        'other = os.environ.get("HOME")\n'
        'lower = "evidentia_not_matched"\n',
        encoding="utf-8",
    )
    # Duplicate in a second file -> de-duplicated in the result.
    (pkg / "b" / "y.py").write_text('again = os.environ["EVIDENTIA_GAP_STORE_DIR"]\n', encoding="utf-8")
    names = mod.collect_env_vars(pkg)
    assert names == ["EVIDENTIA_GAP_STORE_DIR", "EVIDENTIA_POSTGRES_PASSWORD"]


# --- evidentia.yaml schema parse -------------------------------------------


CONFIG_FIXTURE = """
from pydantic import BaseModel, Field


class LLMConfig(BaseModel):
    model: str | None = Field(default=None, description="Model name.")
    temperature: float | None = Field(default=None, description="Temp.")


class EvidentiaConfig(BaseModel):
    organization: str | None = Field(default=None, description="Org name.")
    frameworks: list[str] = Field(default_factory=list, description="Defaults.")
    llm: LLMConfig = Field(default_factory=LLMConfig, description="LLM block.")
    source_path: Path | None = Field(default=None, exclude=True, description="internal")
"""


def test_collect_yaml_schema_flattens_llm_and_drops_internal(mod: Any) -> None:
    schema = mod.collect_yaml_schema(CONFIG_FIXTURE)
    keys = [row["key"] for row in schema]
    # llm flattened into llm.model / llm.temperature; the nested `llm` field
    # itself is replaced; source_path (exclude=True) is dropped.
    assert "llm" not in keys
    assert "source_path" not in keys
    assert keys == ["organization", "frameworks", "llm.model", "llm.temperature"]
    by_key = {row["key"]: row for row in schema}
    assert by_key["organization"]["type"] == "str | None"
    assert by_key["organization"]["description"] == "Org name."
    assert by_key["frameworks"]["type"] == "list[str]"
    assert by_key["llm.temperature"]["description"] == "Temp."


# --- frameworks.yaml manifest parse + render -------------------------------


def test_parse_frameworks_manifest_and_render_counts(mod: Any) -> None:
    manifest = (
        "version: 1\n"
        "frameworks:\n"
        "- id: a-fed\n"
        "  name: A Fed\n"
        "  version: '1'\n"
        "  tier: A\n"
        "  category: control\n"
        "  path: us-federal/a-fed.json\n"
        "  text_depth: full\n"
        "- id: b-intl\n"
        "  name: B Intl\n"
        "  version: '2'\n"
        "  tier: C\n"
        "  category: control\n"
        "  path: international/b-intl.json\n"
        "  text_depth: headings\n"
        "- id: c-fed\n"
        "  name: C Fed\n"
        "  version: '3'\n"
        "  tier: A\n"
        "  category: control\n"
        "  path: us-federal/c-fed.json\n"
        "  text_depth: partial\n"
    )
    frameworks = mod.parse_frameworks_manifest(manifest)
    assert len(frameworks) == 3
    rendered = mod.render_catalogs(frameworks)
    # Headline count computed from the data.
    assert "ships **3** framework catalogs" in rendered
    # Per-family subtotal computed (2 us-federal, 1 international).
    assert "## US Federal (2)" in rendered
    assert "## International (1)" in rendered
    # Within a family, frameworks are sorted by id (a-fed before c-fed).
    assert rendered.index("a-fed") < rendered.index("c-fed")
    # Tier labels are license-only; they make no claim about text content.
    assert "Public-domain or open-licensed, redistributable verbatim" in rendered
    # Per-family rows carry the Text column with each entry's depth.
    assert "| `a-fed` | A Fed | 1 | A | full | control |" in rendered
    assert "| `b-intl` | B Intl | 2 | C | headings | control |" in rendered
    assert "| `c-fed` | C Fed | 3 | A | partial | control |" in rendered
    # The Text depth summary table counts one catalog per depth.
    assert "## Text depth" in rendered
    assert "| full | 1 |" in rendered
    assert "| partial | 1 |" in rendered
    assert "| headings | 1 |" in rendered


def test_render_catalogs_text_depth_defaults_to_dash_when_absent(mod: Any) -> None:
    manifest = (
        "version: 1\n"
        "frameworks:\n"
        "- id: legacy-fw\n"
        "  name: Legacy Framework\n"
        "  version: '1'\n"
        "  tier: A\n"
        "  category: control\n"
        "  path: us-federal/legacy-fw.json\n"
    )
    frameworks = mod.parse_frameworks_manifest(manifest)
    rendered = mod.render_catalogs(frameworks)
    # No text_depth key at all (an older manifest entry) renders "-", and
    # does not get counted in any of the three depth buckets.
    assert "| `legacy-fw` | Legacy Framework | 1 | A | - | control |" in rendered
    assert "| full | 0 |" in rendered
    assert "| partial | 0 |" in rendered
    assert "| headings | 0 |" in rendered


def test_parse_frameworks_manifest_rejects_bad_shape(mod: Any) -> None:
    with pytest.raises(ValueError, match="frameworks"):
        mod.parse_frameworks_manifest("just: a scalar mapping\n")


# --- crosswalk JSON parse + render -----------------------------------------


def test_parse_crosswalk_handles_both_shapes(mod: Any) -> None:
    # OSPS shape: carries `verification` + a 2-row mappings list.
    osps = {
        "source_framework": "osps-baseline-2026.02.19",
        "target_framework": "eu-cra",
        "verification": "self-attested-via-upstream",
        "mappings": [{"x": 1}, {"x": 2}],
    }
    row = mod.parse_crosswalk("osps-baseline_to_eu-cra.json", osps)
    assert row["source"] == "osps-baseline-2026.02.19"
    assert row["target"] == "eu-cra"
    assert row["verification"] == "self-attested-via-upstream"
    assert row["rows"] == 2
    # No resolution passed: both sides read "not bundled" since there is
    # nothing to measure either side against.
    assert row["source_resolved"] == "not bundled"
    assert row["target_resolved"] == "not bundled"

    # Hand-authored shape: no `verification`; verification falls back to "".
    authored = {
        "source_framework": "iso-27001-2022",
        "target_framework": "nist-800-53-mod",
        "mappings": [{"x": 1}],
    }
    row2 = mod.parse_crosswalk("iso.json", authored)
    assert row2["verification"] == ""
    assert row2["rows"] == 1


def test_parse_crosswalk_with_resolution_renders_percentages(mod: Any) -> None:
    from evidentia_core.catalogs.crosswalk import CrosswalkResolution

    payload = {
        "source_framework": "nist-csf-2.0",
        "target_framework": "nist-800-53-rev5",
        "mappings": [{"x": 1}, {"x": 2}, {"x": 3}, {"x": 4}],
    }
    resolution = CrosswalkResolution(
        file="nist-csf-2.0_to_nist-800-53-rev5.json",
        source_framework="nist-csf-2.0",
        target_framework="nist-800-53-rev5",
        rows=4,
        source_ids_known=True,
        target_ids_known=True,
        source_resolved=3,
        target_resolved=4,
        unresolved_source_ids=("GV.OC-99",),
        unresolved_target_ids=(),
    )
    row = mod.parse_crosswalk("nist-csf-2.0_to_nist-800-53-rev5.json", payload, resolution)
    assert row["source_resolved"] == "3/4 (75%)"
    assert row["target_resolved"] == "4/4 (100%)"


def test_parse_crosswalk_resolution_reports_not_bundled_per_side(mod: Any) -> None:
    from evidentia_core.catalogs.crosswalk import CrosswalkResolution

    payload = {
        "source_framework": "osps-baseline",
        "target_framework": "eu-cra",
        "mappings": [{"x": 1}, {"x": 2}],
    }
    # Source is bundled and fully resolves; target has no bundled catalog.
    resolution = CrosswalkResolution(
        file="osps-baseline_to_eu-cra.json",
        source_framework="osps-baseline",
        target_framework="eu-cra",
        rows=2,
        source_ids_known=True,
        target_ids_known=False,
        source_resolved=2,
        target_resolved=0,
        unresolved_source_ids=(),
        unresolved_target_ids=(),
    )
    row = mod.parse_crosswalk("osps-baseline_to_eu-cra.json", payload, resolution)
    assert row["source_resolved"] == "2/2 (100%)"
    assert row["target_resolved"] == "not bundled"


def test_render_crosswalks_computes_totals(mod: Any) -> None:
    rows = [
        {
            "file": "a.json",
            "source": "s1",
            "target": "t1",
            "verification": "self-attested-via-upstream",
            "rows": 100,
            "source_resolved": "100/100 (100%)",
            "target_resolved": "not bundled",
        },
        {
            "file": "b.json",
            "source": "s2",
            "target": "t2",
            "verification": "",
            "rows": 23,
            "source_resolved": "20/23 (87%)",
            "target_resolved": "23/23 (100%)",
        },
    ]
    rendered = mod.render_crosswalks(rows)
    # Count + total-row-sum both computed from the data.
    assert "bundles **2** framework crosswalks" in rendered
    assert "123 control-to-control mapping rows" in rendered
    # New columns are in the header and render each row's resolution.
    assert "Source ids resolved" in rendered
    assert "Target ids resolved" in rendered
    # Empty verification uses an ASCII placeholder; resolution values remain intact.
    placeholder = "-"
    assert f"| `b.json` | `s2` | `t2` | {placeholder} | 23 | 20/23 (87%) | 23/23 (100%) |" in rendered
    assert "| `a.json` | `s1` | `t1` | self-attested-via-upstream | 100 | 100/100 (100%) | not bundled |" in rendered


# --- collect_crosswalks (registry-aware resolution) -------------------------


class _StubRegistry:
    """Minimal stand-in for a FrameworkRegistry's ``control_ids_for``.

    Duck-typed: ``collect_crosswalks`` only ever calls this one method, so
    the tests do not need a real registry (which would pull in the whole
    bundled catalog set) to exercise the resolution wiring.
    """

    def __init__(self, known: dict[str, frozenset[str]]) -> None:
        self._known = known

    def control_ids_for(self, framework_id: str) -> frozenset[str] | None:
        return self._known.get(framework_id)


def test_collect_crosswalks_computes_resolution_when_registry_given(mod: Any, tmp_path: Path) -> None:
    mappings_dir = tmp_path / "mappings"
    mappings_dir.mkdir()
    payload = {
        "source_framework": "nist-csf-2.0",
        "target_framework": "eu-cra",
        "version": "1",
        "generated_at": "2026-01-01",
        "source": "test fixture",
        "mappings": [
            {"source_control_id": "GV.OC-01", "target_control_id": "AC-1", "relationship": "related"},
            {"source_control_id": "GV.OC-99", "target_control_id": "AC-2", "relationship": "related"},
        ],
    }
    (mappings_dir / "nist-csf-2.0_to_eu-cra.json").write_text(json.dumps(payload), encoding="utf-8")
    # nist-csf-2.0 is "bundled" (one of its two ids is known); eu-cra is not.
    registry = _StubRegistry({"nist-csf-2.0": frozenset({"GV.OC-01"})})
    rows = mod.collect_crosswalks(mappings_dir, registry=registry)
    assert len(rows) == 1
    assert rows[0]["source_resolved"] == "1/2 (50%)"
    assert rows[0]["target_resolved"] == "not bundled"


def test_collect_crosswalks_without_registry_reads_not_bundled(mod: Any, tmp_path: Path) -> None:
    mappings_dir = tmp_path / "mappings"
    mappings_dir.mkdir()
    payload = {
        "source_framework": "a",
        "target_framework": "b",
        "mappings": [{"x": 1}],
    }
    (mappings_dir / "a_to_b.json").write_text(json.dumps(payload), encoding="utf-8")
    # No registry: parse_crosswalk never receives a resolution, so both
    # sides read "not bundled" without needing evidentia_core at all.
    rows = mod.collect_crosswalks(mappings_dir)
    assert len(rows) == 1
    assert rows[0]["source_resolved"] == "not bundled"
    assert rows[0]["target_resolved"] == "not bundled"


# --- banner ----------------------------------------------------------------


def test_build_banner_contains_marker_h1_and_guidance(mod: Any) -> None:
    banner = mod.build_banner("CLI reference")
    assert banner.startswith("<!-- AUTO-GENERATED by scripts/wiki/sync_reference.py -- do not edit directly -->")
    assert "# CLI reference" in banner
    assert "> **Auto-generated page.**" in banner
    assert "scripts/wiki/sync_reference.py" in banner


# --- compare / --check idiom ----------------------------------------------


def test_compare_no_drift_when_committed_matches(mod: Any, tmp_path: Path) -> None:
    rendered = {
        "docs/wiki/4-reference/cli.md": "# CLI\nbody-a\n",
        "docs/wiki/4-reference/catalogs.md": "# Catalogs\nbody-b\n",
    }
    for rel, text in rendered.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert mod.compare(rendered, tmp_path) == []


def test_compare_detects_drift_on_mutated_page(mod: Any, tmp_path: Path) -> None:
    rendered = {
        "docs/wiki/4-reference/cli.md": "# CLI\nbody-a\n",
        "docs/wiki/4-reference/catalogs.md": "# Catalogs\nbody-b\n",
    }
    for rel, text in rendered.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (tmp_path / "docs/wiki/4-reference/cli.md").write_text("# CLI\nMUTATED\n", encoding="utf-8")
    drift = mod.compare(rendered, tmp_path)
    assert len(drift) == 1
    assert "docs/wiki/4-reference/cli.md" in drift[0]
    assert "catalogs" not in "".join(drift)


def test_compare_flags_missing_page(mod: Any, tmp_path: Path) -> None:
    rendered = {
        "docs/wiki/4-reference/cli.md": "# CLI\nbody-a\n",
        "docs/wiki/4-reference/catalogs.md": "# Catalogs\nbody-b\n",
    }
    present = "docs/wiki/4-reference/catalogs.md"
    path = tmp_path / present
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered[present], encoding="utf-8")
    drift = mod.compare(rendered, tmp_path)
    assert len(drift) == 1
    assert "docs/wiki/4-reference/cli.md" in drift[0]
    assert "missing" in drift[0]


def test_generate_crosswalks_ignores_user_catalog_imports(
    mod: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bundled reference rows cannot be changed by an operator's local import."""
    user_dir = tmp_path / "catalogs"
    user_dir.mkdir()
    monkeypatch.setenv("EVIDENTIA_CATALOG_DIR", str(user_dir))
    baseline = mod.generate_all()[mod.PAGE_CROSSWALKS]
    (user_dir / "soc2-tsc.json").write_text(
        json.dumps(
            {
                "framework_id": "soc2-tsc",
                "framework_name": "Imported fixture",
                "version": "1",
                "controls": [{"id": "LOCAL-1", "title": "Local control", "description": "Imported statement"}],
            }
        ),
        encoding="utf-8",
    )
    from evidentia_core.catalogs.loader import load_any_catalog
    from evidentia_core.catalogs.manifest import FrameworkManifest, load_manifest
    from evidentia_core.catalogs.user_dir import save_user_manifest

    bundled = load_manifest().get("soc2-tsc")
    assert bundled is not None
    imported = bundled.model_copy(update={"path": "soc2-tsc.json"})
    save_user_manifest(FrameworkManifest(version=1, frameworks=[imported]), user_dir)
    assert load_any_catalog("soc2-tsc").get_control("LOCAL-1") is not None
    assert mod.generate_all()[mod.PAGE_CROSSWALKS] == baseline
