"""Unit tests for ``scripts/gen_readme_releases.py`` (v0.10.7 E5a).

The generator turns the top-3 dated CHANGELOG blocks into the README
"Recent Releases" section, and (in ``--check`` mode) guards against the
block going stale relative to the project version.

These tests exercise the pure functions against inline fixtures — no
filesystem CHANGELOG/README and no network. The module is imported via
importlib and registered in ``sys.modules`` so its frozen ``@dataclass``
resolves its own ``__module__`` (CPython dataclass machinery requirement).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GEN_PATH = REPO_ROOT / "scripts" / "gen_readme_releases.py"


def _load_gen_module() -> Any:
    mod_name = "gen_readme_releases_under_test"
    spec = importlib.util.spec_from_file_location(mod_name, GEN_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register BEFORE exec so @dataclass(frozen=True) can resolve __module__.
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen() -> Any:
    return _load_gen_module()


# A 3-block inline CHANGELOG fixture in the real Evidentia house format,
# plus an [Unreleased] block (must be skipped) and an older 4th block.
CHANGELOG_FIXTURE = """\
# Changelog

## [Unreleased]

_No changes yet on the v9.9.9 development branch._

## [1.2.3] - 2026-06-01

**Theme**: *v1.2.3 — alpha feature + beta hardening (carried over) + hygiene*. Patch bump.

**Release summary**: Some prose here. **100 tests pass.**

### Added

- `evidentia thing do` (Phase 7): does the alpha thing for users. See commit `abc1234`.
- A second additive surface that should be summarized too.

### Fixed

- Some fix that should not lead the summary because Added exists.

## [1.2.2] - 2026-05-20

**Theme**: *v1.2.2 — beta-only theme*. Patch bump.

### Changed

- Changed-only cycle: no Added section, so summary comes from Changed.

## [1.2.1] - 2026-05-10

**Theme**: *v1.2.1 — gamma theme*. Patch bump.

### Added

- The gamma addition.

## [1.2.0] - 2026-05-01

**Theme**: *v1.2.0 — should not appear (4th newest)*. Minor bump.

### Added

- Old addition.
"""


class TestParseChangelogBlocks:
    def test_parses_dated_blocks_newest_first_skipping_unreleased(self, gen: Any) -> None:
        blocks = gen.parse_changelog_blocks(CHANGELOG_FIXTURE)
        versions = [b.version for b in blocks]
        # [Unreleased] is skipped (no date); dated blocks in document order.
        assert versions == ["1.2.3", "1.2.2", "1.2.1", "1.2.0"]
        assert blocks[0].date == "2026-06-01"

    def test_block_body_bounded_by_next_h2(self, gen: Any) -> None:
        blocks = gen.parse_changelog_blocks(CHANGELOG_FIXTURE)
        first = blocks[0]
        # The first block's body must contain its own bullets but NOT the
        # next release's theme.
        assert "alpha thing" in first.body
        assert "beta-only theme" not in first.body


class TestCondenseTheme:
    def test_strips_self_version_prefix(self, gen: Any) -> None:
        blocks = gen.parse_changelog_blocks(CHANGELOG_FIXTURE)
        theme = gen.condense_theme(blocks[0].body, blocks[0].version)
        # Leading "v1.2.3 — " prefix removed.
        assert not theme.startswith("v1.2.3")
        assert theme.startswith("alpha feature")

    def test_caps_clauses_and_drops_trailing_parenthetical(self, gen: Any) -> None:
        # "alpha feature + beta hardening (carried over) + hygiene" -> the
        # per-clause trailing parenthetical is dropped.
        theme = gen.condense_theme(CHANGELOG_FIXTURE.split("## [1.2.3]")[1], "1.2.3")
        assert "(carried over)" not in theme
        assert "beta hardening" in theme


class TestCondenseSummary:
    def test_summary_from_added_section(self, gen: Any) -> None:
        blocks = gen.parse_changelog_blocks(CHANGELOG_FIXTURE)
        summary = gen.condense_summary(blocks[0].body)
        assert "does the alpha thing" in summary
        # "See commit ..." tail stripped.
        assert "See commit" not in summary
        # The "(Phase 7):" label is collapsed (no raw "(Phase 7)").
        assert "(Phase 7)" not in summary

    def test_summary_falls_back_to_changed_when_no_added(self, gen: Any) -> None:
        blocks = gen.parse_changelog_blocks(CHANGELOG_FIXTURE)
        # 1.2.2 has only a Changed section.
        v122 = next(b for b in blocks if b.version == "1.2.2")
        summary = gen.condense_summary(v122.body)
        assert "Changed-only cycle" in summary


class TestRenderBlock:
    def test_three_entries_newest_first(self, gen: Any) -> None:
        blocks = gen.parse_changelog_blocks(CHANGELOG_FIXTURE)
        block = gen.render_block(blocks)
        entries = [ln for ln in block.splitlines() if ln.startswith("**v")]
        assert len(entries) == 3
        assert entries[0].startswith("**v1.2.3 (2026-06-01)**")
        assert entries[1].startswith("**v1.2.2 (2026-05-20)**")
        assert entries[2].startswith("**v1.2.1 (2026-05-10)**")
        # The 4th-newest must NOT appear.
        assert "1.2.0" not in block

    def test_entry_has_theme_and_summary_shape(self, gen: Any) -> None:
        blocks = gen.parse_changelog_blocks(CHANGELOG_FIXTURE)
        entry = gen.render_entry(blocks[0])
        # Shape: **vX.Y.Z (date)** — *theme*. summary.
        assert entry.startswith("**v1.2.3 (2026-06-01)** — *")
        assert entry.rstrip().endswith(".")


class TestSpliceIntoReadme:
    README_FIXTURE = (
        "# Project\n\n"
        "## Documentation\n\n"
        "Some docs.\n\n"
        "## Recent Releases\n\n"
        "**v0.0.1 (2020-01-01)** — *old*. old entry.\n\n"
        "Full release history: [CHANGELOG.md](CHANGELOG.md)\n\n"
        "## License\n\n"
        "MIT.\n"
    )

    def test_replaces_only_the_block(self, gen: Any) -> None:
        new_body = "**v1.2.3 (2026-06-01)** — *new*. new entry."
        updated = gen.splice_into_readme(self.README_FIXTURE, new_body)
        # Old entry gone, new entry present.
        assert "v0.0.1" not in updated
        assert "**v1.2.3 (2026-06-01)** — *new*. new entry." in updated
        # Surrounding sections untouched.
        assert "## Documentation\n\nSome docs." in updated
        assert "## License\n\nMIT." in updated
        # Exactly one blank line after the header (no double blank).
        assert "## Recent Releases\n\n**v1.2.3" in updated
        assert "## Recent Releases\n\n\n" not in updated
        # The 'Full release history:' pointer line is preserved.
        assert "Full release history: [CHANGELOG.md](CHANGELOG.md)" in updated

    def test_missing_header_raises(self, gen: Any) -> None:
        with pytest.raises(ValueError, match="Recent Releases"):
            gen.splice_into_readme("# No section here\n", "x")

    def test_missing_full_history_raises(self, gen: Any) -> None:
        text = "## Recent Releases\n\nsome entry\n\n## License\n"
        with pytest.raises(ValueError, match="Full release history"):
            gen.splice_into_readme(text, "x")


class TestCheckReadmeCurrent:
    def _readme_with_versions(self, versions: list[str]) -> str:
        entries = "\n\n".join(f"**v{v} (2026-01-01)** — *t*. s." for v in versions)
        return f"## Recent Releases\n\n{entries}\n\nFull release history: [CHANGELOG.md](CHANGELOG.md)\n"

    def test_passes_when_three_entries_newest_matches(self, gen: Any) -> None:
        readme = self._readme_with_versions(["0.10.7", "0.10.6", "0.10.5"])
        ok, msg = gen.check_readme_current(readme, "0.10.7")
        assert ok, msg

    def test_fails_when_newest_mismatch(self, gen: Any) -> None:
        readme = self._readme_with_versions(["0.10.6", "0.10.5", "0.10.4"])
        ok, msg = gen.check_readme_current(readme, "0.10.7")
        assert not ok
        assert "0.10.7" in msg

    def test_fails_when_wrong_count(self, gen: Any) -> None:
        readme = self._readme_with_versions(["0.10.7", "0.10.6"])
        ok, msg = gen.check_readme_current(readme, "0.10.7")
        assert not ok
        assert "expected exactly 3" in msg

    def test_extract_versions(self, gen: Any) -> None:
        readme = self._readme_with_versions(["0.10.7", "0.10.6", "0.10.5"])
        assert gen.extract_readme_block_versions(readme) == [
            "0.10.7",
            "0.10.6",
            "0.10.5",
        ]


class TestRealReadmeIsCurrent:
    """The shipped README block must satisfy the staleness guard against the
    real CHANGELOG + project version (the same assertion the pre-tag gate
    runs). This is the regression that catches a future stale README."""

    def test_real_readme_block_is_current(self, gen: Any) -> None:
        readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        current = gen.detect_current_version()
        ok, msg = gen.check_readme_current(readme_text, current)
        assert ok, msg

    def test_real_changelog_produces_three_entries(self, gen: Any) -> None:
        changelog_text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        blocks = gen.parse_changelog_blocks(changelog_text)
        assert len(blocks) >= 3
        rendered = gen.render_block(blocks)
        entries = [ln for ln in rendered.splitlines() if ln.startswith("**v")]
        assert len(entries) == 3
        # Newest rendered entry == current project version.
        assert entries[0].startswith(f"**v{gen.detect_current_version()} (")
