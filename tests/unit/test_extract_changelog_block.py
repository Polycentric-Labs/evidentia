"""Self-tests for ``scripts/extract_changelog_block.py``.

v0.7.13 P2.2.1 deliverable. The extraction script is wired into
``.github/workflows/release.yml`` and runs at every tag push. A
silent regression in the regex pattern would ship malformed
release bodies, so these tests pin the contract.

Test plan:

1. Every shipped release block (v0.7.0 → v0.7.12) extracts
   non-empty content + the heading line itself is excluded.
2. The ``[Unreleased]`` block extracts independently of any
   ``[X.Y.Z]`` block.
3. A non-existent version returns ``None``.
4. Edge cases: trailing whitespace, blocks adjacent to other
   ``## [`` headings, blocks with embedded ``[`` chars in
   markdown links.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# Load the script as a module without going through `python -m`.
# The script lives in `scripts/`, which isn't a package; this
# avoids needing to add an `__init__.py` there.
_SCRIPT_PATH = (
    Path(__file__).parent.parent.parent
    / "scripts"
    / "extract_changelog_block.py"
)
_spec = importlib.util.spec_from_file_location(
    "extract_changelog_block", _SCRIPT_PATH
)
assert _spec is not None
assert _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
sys.modules["extract_changelog_block"] = _mod
_spec.loader.exec_module(_mod)

extract_block = _mod.extract_block
render_release_body = _mod.render_release_body


_REPO_ROOT = Path(__file__).parent.parent.parent
_CHANGELOG = (_REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "version",
    [
        "0.7.0",
        "0.7.1",
        "0.7.2",
        "0.7.3",
        "0.7.4",
        "0.7.5",
        "0.7.6",
        "0.7.7",
        "0.7.7.1",
        "0.7.8",
        "0.7.9",
        "0.7.10",
        "0.7.11",
        "0.7.12",
    ],
)
def test_every_v0_7_block_extracts_non_empty(version: str) -> None:
    """Every shipped v0.7.x release block extracts as non-empty."""
    block = extract_block(_CHANGELOG, version)
    assert block is not None, (
        f"v{version} CHANGELOG block returned None — possible regex "
        "regression"
    )
    assert len(block) > 100, (
        f"v{version} CHANGELOG block is suspiciously short "
        f"({len(block)} chars) — extraction may be truncated"
    )


def test_extracted_block_excludes_heading_line() -> None:
    """The heading line itself ``## [X.Y.Z] - <date>`` is not in the
    extracted block — only the content beneath it."""
    block = extract_block(_CHANGELOG, "0.7.12")
    assert block is not None
    # The heading should NOT appear at the start of the extracted
    # block. The first non-empty line should be either content or
    # a sub-heading like `### Added`.
    first_line = block.lstrip().split("\n", 1)[0]
    assert not first_line.startswith("## [0.7.12]"), (
        f"Extracted block leaks heading line: {first_line!r}"
    )


def test_extracted_block_excludes_next_heading() -> None:
    """The block doesn't bleed into the next ``## [`` section."""
    block = extract_block(_CHANGELOG, "0.7.12")
    assert block is not None
    # No `## [` heading should appear inside the extracted block —
    # `## [0.7.11]` (the next-newer-then-older heading) marks the
    # block end.
    assert "## [0.7.11]" not in block, (
        "Extracted v0.7.12 block bleeds into v0.7.11"
    )
    assert "## [0.7.10]" not in block


def test_unreleased_block_extracts_independently() -> None:
    """The ``[Unreleased]`` block is its own thing; not confused with
    any ``[X.Y.Z]`` block."""
    block = extract_block(_CHANGELOG, "Unreleased")
    # The Unreleased block may legitimately be empty or near-empty
    # between releases; just verify the search matches without
    # crashing. The key is no false-match on a real version.
    if block is not None:
        # If non-empty, sanity-check it doesn't bleed into v0.7.12.
        assert "## [0.7.12]" not in block


def test_nonexistent_version_returns_none() -> None:
    """A version that doesn't exist in the CHANGELOG returns None."""
    block = extract_block(_CHANGELOG, "99.99.99")
    assert block is None


def test_dotted_prefix_does_not_match_longer_version() -> None:
    """``0.7.1`` must not match ``[0.7.10]`` or ``[0.7.11]`` etc."""
    # If extract_block had a buggy non-anchored regex, searching
    # for "0.7.1" would match the 0.7.10 heading first (wrong
    # block). Verify we get the correct block by checking unique
    # content.
    block_0_7_1 = extract_block(_CHANGELOG, "0.7.1")
    block_0_7_11 = extract_block(_CHANGELOG, "0.7.11")
    assert block_0_7_1 is not None
    assert block_0_7_11 is not None
    # They must differ in content (not the same block).
    assert block_0_7_1 != block_0_7_11
    # And they must not be substrings of each other (no overlap).
    assert block_0_7_1 not in block_0_7_11
    assert block_0_7_11 not in block_0_7_1


def test_render_release_body_includes_required_stanzas() -> None:
    """The rendered release body carries the canonical PEP 740 +
    CHANGELOG link stanzas needed by the body-substantiveness
    Step 7 check."""
    block = extract_block(_CHANGELOG, "0.7.12")
    assert block is not None
    body = render_release_body("0.7.12", block)
    # Required marker stanzas (from references/release-notes-checklist.md):
    assert "## Highlights" in body
    assert "pypi-attestations verify pypi" in body
    assert "evidentia==0.7.12" in body
    assert "CHANGELOG.md" in body
    # The CHANGELOG content must be embedded (not just templated).
    assert block in body
    # Sanity: rendered body is much longer than the canonical stub
    # body (~776 bytes pre-fix).
    assert len(body) > 1500


def test_render_release_body_handles_synthetic_block() -> None:
    """The renderer doesn't blow up on a minimal synthetic block."""
    synthetic_block = "### Added\n\n- One feature.\n\n### Fixed\n\n- One fix.\n"
    body = render_release_body("0.7.13", synthetic_block)
    assert "## Highlights" in body
    assert "0.7.13" in body
    assert synthetic_block in body
