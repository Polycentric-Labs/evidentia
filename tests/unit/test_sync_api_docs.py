"""Tests for ``scripts/wiki/sync_api_docs.py`` (D6 Batch 2, v0.10.7).

The API-docs generator renders one concise public-surface index per Python
workspace package (Option B — NOT mkdocstrings HTML), all from static
AST/text extraction. These tests pin the non-trivial extraction logic — the
``__all__`` literal parse, the top-level public-name fallback scan, the
``pyproject.toml`` description read, the submodule/subpackage listing, and the
docstring-summary index — against tiny inline/``tmp_path`` fixtures (no
project import, no network), plus the ``--check`` drift comparison.

Test plan:

1. ``extract_all_list`` returns the literal ``__all__`` string list (list +
   tuple forms), and ``None`` when no ``__all__`` is declared.
2. ``extract_public_toplevel_names`` collects public defs/classes + imported
   names, dropping underscore + denylisted names.
3. ``read_description`` pulls ``[project].description`` from pyproject text.
4. ``list_public_submodules`` returns ``*.py`` stems + subpackage dirs (with
   ``__init__.py``), excluding underscore names + non-package dirs (e.g. a
   ``static/`` build dir).
5. ``build_symbol_docs`` pairs a symbol with the first docstring line of its
   defining module, and "" when undiscoverable.
6. ``render_package_page`` renders the ``__all__`` table when symbols exist,
   the thin-root message when they don't, and always the submodule list +
   pointers.
7. ``build_banner`` emits the marker + H1 + guidance.
8. ``compare`` (the ``--check`` comparison) detects match / drift / missing.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GEN_PATH = REPO_ROOT / "scripts" / "wiki" / "sync_api_docs.py"


@pytest.fixture(scope="module")
def mod() -> Any:
    """Import scripts/wiki/sync_api_docs.py (stdlib-only at module scope)."""
    spec = importlib.util.spec_from_file_location("sync_api_docs", GEN_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["sync_api_docs"] = module
    spec.loader.exec_module(module)
    return module


# --- __all__ extraction ----------------------------------------------------


def test_extract_all_list_reads_list_form(mod: Any) -> None:
    src = '__all__ = ["b_func", "A_Class", "c_const"]\n'
    assert mod.extract_all_list(src) == ["b_func", "A_Class", "c_const"]


def test_extract_all_list_reads_tuple_form(mod: Any) -> None:
    src = '__all__ = ("one", "two")\n'
    assert mod.extract_all_list(src) == ["one", "two"]


def test_extract_all_list_none_when_absent(mod: Any) -> None:
    src = "x = 1\ndef f():\n    pass\n"
    assert mod.extract_all_list(src) is None


# --- top-level public-name fallback ----------------------------------------


def test_extract_public_toplevel_names_collects_and_filters(mod: Any) -> None:
    src = (
        "from __future__ import annotations\n"
        "from importlib.metadata import PackageNotFoundError\n"
        "from foo.bar import Thing\n"
        "import os\n"
        "_private = 1\n"
        "PUBLIC = 2\n"
        "def helper():\n"
        "    pass\n"
        "class Widget:\n"
        "    pass\n"
    )
    names = mod.extract_public_toplevel_names(src)
    # Public defs/classes/assignments + imported `Thing`/`os`; underscore +
    # denylisted (annotations, PackageNotFoundError) dropped; sorted.
    assert names == ["PUBLIC", "Thing", "Widget", "helper", "os"]
    assert "PackageNotFoundError" not in names
    assert "annotations" not in names
    assert "_private" not in names


# --- pyproject description --------------------------------------------------


def test_read_description(mod: Any) -> None:
    text = '[project]\nname = "evidentia-core"\ndescription = "Core models and gap analysis"\nversion = "0.10.7"\n'
    assert mod.read_description(text) == "Core models and gap analysis"


def test_read_description_missing(mod: Any) -> None:
    assert mod.read_description('[project]\nname = "x"\n') == ""


# --- submodule listing ------------------------------------------------------


def test_list_public_submodules(mod: Any, tmp_path: Path) -> None:
    pkg = tmp_path / "evidentia_core"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "config.py").write_text("", encoding="utf-8")
    (pkg / "gap_diff.py").write_text("", encoding="utf-8")
    (pkg / "_private.py").write_text("", encoding="utf-8")  # excluded
    # A real subpackage (has __init__.py).
    (pkg / "catalogs").mkdir()
    (pkg / "catalogs" / "__init__.py").write_text("", encoding="utf-8")
    # A non-package dir (no __init__.py — e.g. a React build dir) is excluded.
    (pkg / "static").mkdir()
    (pkg / "static" / "index.html").write_text("", encoding="utf-8")
    # An underscore dir is excluded.
    (pkg / "__pycache__").mkdir()

    subs = mod.list_public_submodules(pkg)
    assert subs == ["catalogs", "config", "gap_diff"]
    assert "static" not in subs
    assert "_private" not in subs


# --- docstring-summary index ------------------------------------------------


def test_build_symbol_docs_pairs_first_docstring_line(mod: Any, tmp_path: Path) -> None:
    pkg = tmp_path / "evidentia_eval"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "harness.py").write_text(
        "class DFAHarness:\n"
        '    """Run the harness.\n\n    Longer detail.\n    """\n'
        "def helper():\n"
        '    """Help out."""\n',
        encoding="utf-8",
    )
    docs = mod.build_symbol_docs(pkg, ["DFAHarness", "helper", "Missing"])
    assert docs == [
        ("DFAHarness", "Run the harness."),
        ("helper", "Help out."),
        ("Missing", ""),  # undiscoverable -> empty summary
    ]


# --- rendering --------------------------------------------------------------


def test_render_package_page_with_symbols(mod: Any) -> None:
    page = mod.render_package_page(
        dist_name="evidentia-eval",
        module_name="evidentia_eval",
        description="DFAH harness.",
        symbol_docs=[("DFAHarness", "Run the harness."), ("hash_output", "")],
        has_explicit_all=True,
        submodules=["harness", "metrics"],
    )
    assert "# `evidentia-eval` API" in page
    assert "DFAH harness." in page
    assert "exported by `evidentia_eval.__all__`" in page
    assert "| `DFAHarness` | Run the harness. |" in page
    assert "| `hash_output` | — |" in page  # empty summary -> em-dash
    assert "- `evidentia_eval.harness`" in page
    assert "live API reference" in page


def test_render_package_page_thin_root(mod: Any) -> None:
    page = mod.render_package_page(
        dist_name="evidentia-core",
        module_name="evidentia_core",
        description="Core engine.",
        symbol_docs=[],  # thin root
        has_explicit_all=False,
        submodules=["catalogs", "models"],
    )
    assert "keeps a thin package root" in page
    assert "exposes only `__version__`" in page
    # Submodules still listed even with no public symbols.
    assert "- `evidentia_core.catalogs`" in page


def test_build_banner_contains_marker_h1_and_guidance(mod: Any) -> None:
    banner = mod.build_banner("evidentia-core")
    assert banner.startswith("<!-- AUTO-GENERATED by scripts/wiki/sync_api_docs.py -- do not edit directly -->")
    assert "# `evidentia-core` API" in banner
    assert "> **Auto-generated page.**" in banner
    assert "scripts/wiki/sync_api_docs.py" in banner


# --- compare / --check idiom ----------------------------------------------


def test_compare_no_drift_when_committed_matches(mod: Any, tmp_path: Path) -> None:
    rendered = {
        "docs/wiki/4-reference/api/evidentia-core.md": "# core\nbody-a\n",
        "docs/wiki/4-reference/api/evidentia-eval.md": "# eval\nbody-b\n",
    }
    for rel, text in rendered.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert mod.compare(rendered, tmp_path) == []


def test_compare_detects_drift_and_missing(mod: Any, tmp_path: Path) -> None:
    rendered = {
        "docs/wiki/4-reference/api/evidentia-core.md": "# core\nbody-a\n",
        "docs/wiki/4-reference/api/evidentia-eval.md": "# eval\nbody-b\n",
    }
    # Write core (mutated) + omit eval (missing).
    core = tmp_path / "docs/wiki/4-reference/api/evidentia-core.md"
    core.parent.mkdir(parents=True, exist_ok=True)
    core.write_text("# core\nMUTATED\n", encoding="utf-8")
    drift = mod.compare(rendered, tmp_path)
    assert len(drift) == 2
    joined = "\n".join(drift)
    assert "evidentia-core.md" in joined
    assert "evidentia-eval.md" in joined
    assert "missing" in joined


# --- package table sanity --------------------------------------------------


def test_packages_table_is_the_seven_python_packages(mod: Any) -> None:
    dist_names = [d for d, _m in mod.PACKAGES]
    assert len(mod.PACKAGES) == 7
    # The CLI meta-package + the TS frontend are intentionally NOT here.
    assert "evidentia" not in dist_names
    assert "evidentia-ui" not in dist_names
    # Every dist maps to its underscored import module.
    for dist, module in mod.PACKAGES:
        assert module == dist.replace("-", "_")
