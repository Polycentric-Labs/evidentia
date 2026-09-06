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
   headline count + per-family subtotals from the data (not hardcoded).
6. ``parse_crosswalk`` handles both JSON shapes (with/without
   ``verification``) and counts ``mappings`` rows; ``render_crosswalks``
   computes the total row sum.
7. ``build_banner`` emits the HTML-comment marker + visible blockquote +
   H1 naming the generator.
8. ``compare`` (the pure ``--check`` comparison) returns no drift on a
   match, flags a mutated committed page, and reports a missing page.
"""

from __future__ import annotations

import importlib.util
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
        "- id: b-intl\n"
        "  name: B Intl\n"
        "  version: '2'\n"
        "  tier: C\n"
        "  category: control\n"
        "  path: international/b-intl.json\n"
        "- id: c-fed\n"
        "  name: C Fed\n"
        "  version: '3'\n"
        "  tier: A\n"
        "  category: control\n"
        "  path: us-federal/c-fed.json\n"
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

    # Hand-authored shape: no `verification`; verification falls back to "".
    authored = {
        "source_framework": "iso-27001-2022",
        "target_framework": "nist-800-53-mod",
        "mappings": [{"x": 1}],
    }
    row2 = mod.parse_crosswalk("iso.json", authored)
    assert row2["verification"] == ""
    assert row2["rows"] == 1


def test_render_crosswalks_computes_totals(mod: Any) -> None:
    rows = [
        {
            "file": "a.json",
            "source": "s1",
            "target": "t1",
            "verification": "self-attested-via-upstream",
            "rows": 100,
        },
        {
            "file": "b.json",
            "source": "s2",
            "target": "t2",
            "verification": "",
            "rows": 23,
        },
    ]
    rendered = mod.render_crosswalks(rows)
    # Count + total-row-sum both computed from the data.
    assert "bundles **2** framework crosswalks" in rendered
    assert "123 control-to-control mapping rows" in rendered
    # Empty verification renders as the em-dash placeholder.
    assert "| `b.json` | `s2` | `t2` | — | 23 |" in rendered


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
