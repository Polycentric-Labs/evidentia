"""Tests for ``scripts/wiki/sync_mirrors.py`` (D6, v0.10.7).

The wiki-mirror generator projects canonical docs (repo root / ``docs/``)
into ``docs/wiki/<section>/`` mirror pages: a provenance banner plus the
canonical body with relative links rewritten to absolute GitHub blob
URLs. These tests pin the *transformation* contract against tiny inline
fixtures (no real docs read, no network), plus the ``--check`` drift
comparison via ``tmp_path``.

Test plan:

1. ``rewrite_links`` rewrites a relative link from a ``docs/``-sourced doc
   to an absolute blob URL, correctly resolving both siblings and ``../``
   parents (repo-root climb).
2. ``rewrite_links`` rewrites a relative link from a ROOT-sourced doc.
3. ``rewrite_links`` passes through anchors / external / mailto / ftp /
   protocol-relative targets unchanged, and preserves a ``#fragment`` on a
   rewritten relative link.
4. ``rewrite_links`` does NOT rewrite image links (``![alt](src)``).
5. ``rewrite_links`` leaves a link untouched when ``..`` escapes the repo
   root (cannot form a valid in-repo blob URL).
6. ``build_banner`` emits the HTML-comment marker + a visible blockquote
   naming the canonical source + the "do not edit / re-run" guidance.
7. ``render_mirror`` = banner + link-rewritten body.
8. ``compare`` (the pure comparison the ``--check`` gate builds on)
   returns no drift on a match, flags a mutated committed mirror, and
   reports a missing committed mirror.
9. The 13 ``MIRRORS`` mappings are well-formed: unique mirror paths, each
   mirror under ``docs/wiki/{5-compliance,6-project}/``.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GEN_PATH = REPO_ROOT / "scripts" / "wiki" / "sync_mirrors.py"

FIXTURE_BASE = "https://github.com/Polycentric-Labs/evidentia/blob/main"


@pytest.fixture(scope="module")
def mod() -> Any:
    """Import scripts/wiki/sync_mirrors.py (no __init__.py).

    The module imports only stdlib at module scope, so it loads cleanly
    via importlib without putting ``scripts/wiki/`` on ``sys.path``.
    """
    spec = importlib.util.spec_from_file_location("sync_mirrors", GEN_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["sync_mirrors"] = module
    spec.loader.exec_module(module)
    return module


# --- link rewriting --------------------------------------------------------


def test_rewrite_relative_link_from_docs_sourced_doc(mod: Any) -> None:
    # A doc under docs/ links to a sibling (docs/x.md) and a repo-root
    # parent (../SECURITY.md). Both become absolute blob URLs.
    content = (
        "See [sibling](sibling.md) and [security](../SECURITY.md) for more."
    )
    out = mod.rewrite_links(content, "docs/ocsf-mapping.md", FIXTURE_BASE)
    assert f"[sibling]({FIXTURE_BASE}/docs/sibling.md)" in out
    assert f"[security]({FIXTURE_BASE}/SECURITY.md)" in out


def test_rewrite_relative_link_from_root_sourced_doc(mod: Any) -> None:
    # A root doc links to a docs/ child and a root sibling.
    content = "[overlay](docs/financial-sector-overlay.md) and [eol](EOL.md)."
    out = mod.rewrite_links(content, "CHANGELOG.md", FIXTURE_BASE)
    assert f"[overlay]({FIXTURE_BASE}/docs/financial-sector-overlay.md)" in out
    assert f"[eol]({FIXTURE_BASE}/EOL.md)" in out


def test_rewrite_passes_through_external_and_anchor_links(mod: Any) -> None:
    content = (
        "[ext](https://example.com/x) "
        "[anchor](#section) "
        "[mail](mailto:a@b.com) "
        "[ftp](ftp://host/f) "
        "[proto](//cdn.example.com/x)"
    )
    out = mod.rewrite_links(content, "docs/verification.md", FIXTURE_BASE)
    # Untouched -- no blob base injected for any of them.
    assert out == content


def test_rewrite_preserves_fragment_on_relative_link(mod: Any) -> None:
    content = "[api](api-stability.md#frozen-surface)"
    out = mod.rewrite_links(content, "docs/ocsf-mapping.md", FIXTURE_BASE)
    assert (
        f"[api]({FIXTURE_BASE}/docs/api-stability.md#frozen-surface)" in out
    )


def test_rewrite_does_not_touch_image_links(mod: Any) -> None:
    # Image links (![alt](src)) must NOT be rewritten -- a /blob/ URL is
    # an HTML page, not raw bytes, and would break rendering.
    content = "![diagram](assets/arch.png) and [doc](other.md)"
    out = mod.rewrite_links(content, "docs/architecture.md", FIXTURE_BASE)
    assert "![diagram](assets/arch.png)" in out  # image untouched
    assert f"[doc]({FIXTURE_BASE}/docs/other.md)" in out  # normal link rewritten


def test_rewrite_leaves_escaping_link_untouched(mod: Any) -> None:
    # ../../ from a docs/ doc escapes the repo root -> no valid in-repo
    # blob URL -> leave the link as-is rather than emit a bad URL.
    content = "[outside](../../etc/passwd)"
    out = mod.rewrite_links(content, "docs/verification.md", FIXTURE_BASE)
    assert out == content


# --- banner + render -------------------------------------------------------


def test_build_banner_contains_marker_and_guidance(mod: Any) -> None:
    banner = mod.build_banner("docs/verification.md")
    # HTML-comment provenance marker (machine-detectable; non-rendering).
    assert (
        "<!-- AUTO-GENERATED MIRROR of docs/verification.md "
        "-- do not edit directly -->" in banner
    )
    # Visible blockquote naming the canonical source + re-run guidance.
    assert "> **Auto-generated mirror.**" in banner
    assert "`docs/verification.md`" in banner
    assert "scripts/wiki/sync_mirrors.py" in banner


def test_render_mirror_is_banner_plus_rewritten_body(mod: Any) -> None:
    content = "# Title\n\n[security](../SECURITY.md)\n"
    out = mod.render_mirror(content, "docs/verification.md", FIXTURE_BASE)
    assert out.startswith("<!-- AUTO-GENERATED MIRROR of docs/verification.md")
    # The body's relative link was rewritten in the rendered output.
    assert f"[security]({FIXTURE_BASE}/SECURITY.md)" in out
    # The original heading survives verbatim.
    assert "# Title" in out


# --- compare / --check idiom ----------------------------------------------


def test_compare_no_drift_when_committed_matches(mod: Any, tmp_path: Path) -> None:
    # Build a small two-mapping rendered dict and write it as "committed".
    rendered = {
        "docs/wiki/6-project/eol.md": "# A\nbody-a\n",
        "docs/wiki/5-compliance/ocsf-mapping.md": "# B\nbody-b\n",
    }
    for rel, text in rendered.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert mod.compare(rendered, tmp_path) == []


def test_compare_detects_drift_on_mutated_committed_file(
    mod: Any, tmp_path: Path
) -> None:
    rendered = {
        "docs/wiki/6-project/eol.md": "# A\nbody-a\n",
        "docs/wiki/5-compliance/ocsf-mapping.md": "# B\nbody-b\n",
    }
    for rel, text in rendered.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    # Mutate ONE committed mirror so it diverges from rendered.
    (tmp_path / "docs/wiki/6-project/eol.md").write_text(
        "# A\nMUTATED\n", encoding="utf-8"
    )
    drift = mod.compare(rendered, tmp_path)
    assert len(drift) == 1
    assert "docs/wiki/6-project/eol.md" in drift[0]
    assert "ocsf-mapping" not in "".join(drift)


def test_compare_flags_missing_committed_file(mod: Any, tmp_path: Path) -> None:
    rendered = {
        "docs/wiki/6-project/eol.md": "# A\nbody-a\n",
        "docs/wiki/5-compliance/ocsf-mapping.md": "# B\nbody-b\n",
    }
    # Write only ONE of the two; the other is "missing".
    present = "docs/wiki/5-compliance/ocsf-mapping.md"
    path = tmp_path / present
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered[present], encoding="utf-8")
    drift = mod.compare(rendered, tmp_path)
    assert len(drift) == 1
    assert "docs/wiki/6-project/eol.md" in drift[0]
    assert "missing" in drift[0]


# --- mapping table sanity --------------------------------------------------


def test_mirror_mappings_are_well_formed(mod: Any) -> None:
    mirrors = mod.MIRRORS
    assert len(mirrors) == 13
    mirror_paths = [m.mirror for m in mirrors]
    # Unique mirror destinations.
    assert len(set(mirror_paths)) == 13
    # Every mirror lands under one of the two wiki sections.
    for m in mirrors:
        assert m.mirror.startswith(
            ("docs/wiki/6-project/", "docs/wiki/5-compliance/")
        ), m.mirror
        assert m.mirror.endswith(".md")
        # Source is a repo-relative path (no leading slash, no scheme).
        assert not m.source.startswith(("/", "http"))
    # 9 in 6-project, 4 in 5-compliance per the D6 spec.
    proj = sum(1 for m in mirrors if m.mirror.startswith("docs/wiki/6-project/"))
    comp = sum(
        1 for m in mirrors if m.mirror.startswith("docs/wiki/5-compliance/")
    )
    assert proj == 9
    assert comp == 4
