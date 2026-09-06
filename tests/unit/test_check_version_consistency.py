"""Unit tests for ``scripts/check_version_consistency.py`` (v0.10.7 E4).

The consistency-check is the "never-skip-a-version-reference" gate. It reads
``scripts/version_tracked_files.yaml`` and enforces:

  1. COVERAGE  — every tracked file holds the current version where expected.
  2. NEVER-SKIP — every git-tracked file carrying a project-version literal is
     classified (tracked OR frozen); an unclassified literal is a hard fail.

These tests build tiny temp "repos" (a dir + a fake ``git ls-files`` result
via monkeypatched ``tracked_files``) so no real git / network is touched. The
script's ``check_coverage`` / ``check_never_skip`` read files relative to the
process CWD, so tests chdir into the temp dir.
"""

from __future__ import annotations

import importlib.util
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECK_PATH = REPO_ROOT / "scripts" / "check_version_consistency.py"


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def check() -> Any:
    return _load_module("check_version_consistency_under_test", CHECK_PATH)


@pytest.fixture
def bump(check: Any) -> Any:
    """The bump_version module the check imports (for its helpers)."""
    return check._load_bump_module()


@pytest.fixture
def chdir_tmp(tmp_path: Path) -> Iterator[Path]:
    """Run the test body with CWD set to a temp dir (restored afterwards)."""
    prev = Path.cwd()
    os.chdir(tmp_path)
    try:
        yield tmp_path
    finally:
        os.chdir(prev)


def _make_bump_with_tracked(bump: Any, monkeypatch: pytest.MonkeyPatch, tracked: list[str], packages: list[str]) -> Any:
    """Monkeypatch the imported bump module so tracked_files() + workspace_packages()
    return controlled values, while keeping the real expand_manifest_path +
    replacements_for_kind."""
    monkeypatch.setattr(bump, "tracked_files", lambda: [Path(p) for p in tracked])
    monkeypatch.setattr(bump, "workspace_packages", lambda *a, **k: list(packages))
    return bump


# ── COVERAGE ───────────────────────────────────────────────────────────


def test_coverage_pass_when_tracked_file_current(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (chdir_tmp / "pyproject.toml").write_text('version = "0.10.7"\n', encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["pyproject.toml"], [])
    manifest = {
        "tracked": [{"path": "pyproject.toml", "kind": "python_version"}],
        "frozen": [],
    }
    assert check.check_coverage(bump, manifest, "0.10.7") == []


def test_coverage_fail_when_tracked_file_stale(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # File holds the OLD version; current is 0.10.7 -> stale -> FAIL.
    (chdir_tmp / "pyproject.toml").write_text('version = "0.10.6"\n', encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["pyproject.toml"], [])
    manifest = {
        "tracked": [{"path": "pyproject.toml", "kind": "python_version"}],
        "frozen": [],
    }
    failures = check.check_coverage(bump, manifest, "0.10.7")
    assert len(failures) == 1
    assert "stale tracked file pyproject.toml" in failures[0]
    assert "0.10.7" in failures[0]


def test_coverage_readme_container_tag_stale_fails(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale README container tag (the motivating bug) is caught."""
    (chdir_tmp / "README.md").write_text(
        "Container: `docker pull ghcr.io/polycentric-labs/evidentia:v0.10.6`\n",
        encoding="utf-8",
    )
    _make_bump_with_tracked(bump, monkeypatch, ["README.md"], [])
    manifest = {
        "tracked": [{"path": "README.md", "kind": "readme_container_tag"}],
        "frozen": [],
    }
    failures = check.check_coverage(bump, manifest, "0.10.7")
    assert len(failures) == 1
    assert "README.md" in failures[0]


def test_coverage_advisory_kinds_not_required(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pip_extra_pin / workspace_pins / cff_date are advisory — a file lacking
    the current version for one of those kinds does NOT fail coverage."""
    # requirements.in legitimately lags (last *published* release).
    (chdir_tmp / "requirements.in").write_text("evidentia[gui]==0.9.1\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["requirements.in"], [])
    manifest = {
        "tracked": [{"path": "requirements.in", "kind": "pip_extra_pin"}],
        "frozen": [],
    }
    assert check.check_coverage(bump, manifest, "0.10.7") == []


def test_coverage_missing_glob_target_fails(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tracked path/glob that matches no tracked file is a config error."""
    _make_bump_with_tracked(bump, monkeypatch, ["other.toml"], [])
    manifest = {
        "tracked": [{"path": "packages/*/pyproject.toml", "kind": "python_version"}],
        "frozen": [],
    }
    failures = check.check_coverage(bump, manifest, "0.10.7")
    assert len(failures) == 1
    assert "matched no git-tracked file" in failures[0]


# ── NEVER-SKIP ─────────────────────────────────────────────────────────


def test_never_skip_pass_when_literal_in_frozen(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A frozen file holding an OLD project version passes (historical)."""
    (chdir_tmp / "CHANGELOG.md").write_text("## [0.7.0] - 2026-01-01\nInitial.\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["CHANGELOG.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "CHANGELOG.md"}],
    }
    assert check.check_never_skip(bump, manifest) == []


def test_never_skip_fail_when_literal_unclassified(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unclassified file carrying a project-version literal hard-fails with
    the exact message the task specifies."""
    (chdir_tmp / "mystery.cfg").write_text("some_setting = v0.10.7\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["mystery.cfg"], [])
    manifest = {"tracked": [], "frozen": []}
    failures = check.check_never_skip(bump, manifest)
    assert len(failures) == 1
    assert failures[0] == (
        "untracked version reference in mystery.cfg — classify it in "
        "scripts/version_tracked_files.yaml (tracked or frozen)"
    )


def test_never_skip_classified_tracked_file_ok(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tracked file with the current literal is classified -> not flagged."""
    (chdir_tmp / "pyproject.toml").write_text('version = "0.10.7"\n', encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["pyproject.toml"], [])
    manifest = {
        "tracked": [{"path": "pyproject.toml", "kind": "python_version"}],
        "frozen": [],
    }
    assert check.check_never_skip(bump, manifest) == []


def test_never_skip_glob_classification(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``docs/**`` frozen glob classifies a nested doc carrying a literal."""
    (chdir_tmp / "docs").mkdir()
    (chdir_tmp / "docs" / "sub").mkdir()
    (chdir_tmp / "docs" / "sub" / "old-plan.md").write_text("Shipped in v0.8.0.\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["docs/sub/old-plan.md"], [])
    manifest = {"tracked": [], "frozen": [{"path": "docs/**"}]}
    assert check.check_never_skip(bump, manifest) == []


def test_never_skip_ignores_sub_project_versions(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Small third-party dep versions (0.1.x .. 0.6.x) are below the project
    family floor (>= 0.7) and do NOT trip the gate, so a file that ONLY
    carries such a version need not be classified."""
    (chdir_tmp / "unrelated.txt").write_text("annotated-types 0.6.0 and defusedxml 0.5.1\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["unrelated.txt"], [])
    manifest = {"tracked": [], "frozen": []}
    assert check.check_never_skip(bump, manifest) == []


def test_never_skip_binary_file_skipped(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-UTF-8 / binary tracked file cannot carry a text literal and is
    skipped rather than crashing."""
    (chdir_tmp / "blob.bin").write_bytes(b"\xff\xfe\x00\x01binary\x00")
    _make_bump_with_tracked(bump, monkeypatch, ["blob.bin"], [])
    manifest = {"tracked": [], "frozen": []}
    assert check.check_never_skip(bump, manifest) == []


# ── End-to-end against the REAL repo manifest ──────────────────────────


def test_real_repo_passes_clean(check: Any) -> None:
    """The committed manifest + working tree must pass both invariants.

    This is the live proof that ``frozen`` is seeded comprehensively enough
    that HEAD is green (the v0.10.7 E4 acceptance gate)."""
    bump = check._load_bump_module()
    manifest = bump.load_manifest()
    current = bump.detect_current_version()
    coverage = check.check_coverage(bump, manifest, current)
    never_skip = check.check_never_skip(bump, manifest)
    assert coverage == [], f"coverage failures: {coverage}"
    assert never_skip == [], f"never-skip failures: {never_skip}"


def test_project_version_regex_matches_expected_forms(check: Any) -> None:
    rx = check.PROJECT_VERSION_RE
    assert rx.search("v0.10.7")
    assert rx.search("0.10.7")
    assert rx.search("0.7.0")
    assert rx.search("0.7.7.1")  # hot-fix form
    assert rx.search("evidentia:v0.10.8 ")
    # Below the family floor (< 0.7) — not a project version.
    assert not rx.search("annotated-types 0.6.0")
    assert not rx.search("0.1.2")
    # Not a 0.x version at all.
    assert not rx.search("python 3.12.4")
    assert not rx.search("800.53.7")


# ── ANCHORS (v0.10.7 overlay: live-version lines inside frozen files) ──────


def test_anchor_coverage_passes_when_current(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An anchored line holding the CURRENT version passes; a historical literal
    on a DIFFERENT line does not affect the anchor check."""
    (chdir_tmp / "SECURITY.md").write_text(
        "Latest patched release: 0.10.7\n"  # current — OK
        "## CVE-2026-0001 (fixed in 0.9.3)\n",  # historical — ignored by anchor
        encoding="utf-8",
    )
    _make_bump_with_tracked(bump, monkeypatch, ["SECURITY.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "SECURITY.md"}],
        "anchors": [{"path": "SECURITY.md", "line_contains": "Latest patched release:"}],
    }
    assert check.check_anchors(bump, manifest, "0.10.7") == []


def test_anchor_coverage_fails_when_stale(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale anchored line (the live-in-frozen drift the whole mechanism
    guards) hard-fails with the spec'd message."""
    (chdir_tmp / "SECURITY.md").write_text("Latest patched release: 0.10.6\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["SECURITY.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "SECURITY.md"}],
        "anchors": [{"path": "SECURITY.md", "line_contains": "Latest patched release:"}],
    }
    failures = check.check_anchors(bump, manifest, "0.10.7")
    assert len(failures) == 1
    assert failures[0] == (
        "anchor stale in SECURITY.md: line containing 'Latest patched "
        "release:' shows 0.10.6 not 0.10.7; run scripts/bump_version.py"
    )


def test_anchor_coverage_stale_v_prefixed_reports_found(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The 'found' value in the failure message includes the literal as-written
    (preserving the v prefix)."""
    (chdir_tmp / "README.md").write_text("Pinned: v0.10.6 image\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["README.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "README.md"}],
        "anchors": [{"path": "README.md", "line_contains": "Pinned:"}],
    }
    failures = check.check_anchors(bump, manifest, "0.10.7")
    assert len(failures) == 1
    assert "shows v0.10.6 not 0.10.7" in failures[0]


def test_anchor_multi_line_marker_each_checked(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A marker matching 2 lines checks BOTH — one stale line fails even if the
    other is current."""
    (chdir_tmp / "doc.md").write_text("Release: 0.10.7\nRelease: 0.10.5\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["doc.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "doc.md"}],
        "anchors": [{"path": "doc.md", "line_contains": "Release:"}],
    }
    failures = check.check_anchors(bump, manifest, "0.10.7")
    # Only the second (0.10.5) line is stale.
    assert len(failures) == 1
    assert "shows 0.10.5 not 0.10.7" in failures[0]


def test_anchor_empty_list_passes(check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No anchors => no anchor failures (the default state)."""
    _make_bump_with_tracked(bump, monkeypatch, ["x.md"], [])
    manifest: dict[str, list[dict[str, str]]] = {
        "tracked": [],
        "frozen": [],
        "anchors": [],
    }
    assert check.check_anchors(bump, manifest, "0.10.7") == []


def test_anchor_guard_path_matches_no_file(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_bump_with_tracked(bump, monkeypatch, ["other.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "missing.md"}],
        "anchors": [{"path": "missing.md", "line_contains": "x"}],
    }
    failures = check.check_anchors(bump, manifest, "0.10.7")
    assert len(failures) == 1
    assert "matched no git-tracked file" in failures[0]


def test_anchor_guard_marker_matches_zero_lines(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (chdir_tmp / "doc.md").write_text("no marker here\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["doc.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "doc.md"}],
        "anchors": [{"path": "doc.md", "line_contains": "Latest release:"}],
    }
    failures = check.check_anchors(bump, manifest, "0.10.7")
    assert len(failures) == 1
    assert "matched 0 lines" in failures[0]


def test_anchor_guard_line_has_no_version(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An anchored line with the marker but no project-version literal fails."""
    (chdir_tmp / "doc.md").write_text("Latest release: TBD\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["doc.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "doc.md"}],
        "anchors": [{"path": "doc.md", "line_contains": "Latest release:"}],
    }
    failures = check.check_anchors(bump, manifest, "0.10.7")
    assert len(failures) == 1
    assert "no project-version literal" in failures[0]


def test_anchor_guard_unclassified_file(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An anchor file in NEITHER tracked NOR frozen fails — overlay, not a
    classification substitute."""
    (chdir_tmp / "doc.md").write_text("Latest release: 0.10.6\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["doc.md"], [])
    manifest: dict[str, list[dict[str, str]]] = {
        "tracked": [],
        "frozen": [],  # doc.md unclassified
        "anchors": [{"path": "doc.md", "line_contains": "Latest release:"}],
    }
    failures = check.check_anchors(bump, manifest, "0.10.7")
    assert len(failures) == 1
    assert "NEITHER tracked NOR frozen" in failures[0]


def test_anchor_classified_via_glob(check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A file classified by a frozen GLOB (not a literal path) satisfies the
    'must be classified' guard for its anchor overlay."""
    (chdir_tmp / "docs").mkdir()
    (chdir_tmp / "docs" / "status.md").write_text("Latest release: 0.10.7\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["docs/status.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "docs/**"}],  # glob classifies docs/status.md
        "anchors": [{"path": "docs/status.md", "line_contains": "Latest release:"}],
    }
    # Classified via glob => no 'unclassified' failure; line is current => pass.
    assert check.check_anchors(bump, manifest, "0.10.7") == []


# ── FIX-1: exactly-one-live-literal invariant on anchored lines ───────────


def test_anchor_ambiguous_two_project_literals_historical(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An anchored line carrying the current literal AND a second in-family
    PROJECT literal (a historical project version on the same line) is an
    ambiguous anchor — a HARD FAIL. The checker must NOT pass merely because
    the current token appears somewhere on the line."""
    (chdir_tmp / "doc.md").write_text("Latest: v0.10.7 (was v0.10.6)\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["doc.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "doc.md"}],
        "anchors": [{"path": "doc.md", "line_contains": "Latest:"}],
    }
    failures = check.check_anchors(bump, manifest, "0.10.7")
    assert len(failures) == 1
    assert "ambiguous anchor" in failures[0]
    assert "Latest:" in failures[0]
    assert "doc.md" in failures[0]
    assert "2 project-version literals" in failures[0]


def test_anchor_ambiguous_third_party_in_family_literal(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An anchored line carrying the current project literal AND a 3rd-party
    dependency literal in the >=0.7 project family on the SAME line is also
    ambiguous — a HARD FAIL (otherwise the gate could pass a stale live token
    that the bumper would have corrupted)."""
    (chdir_tmp / "doc.md").write_text("Pinned evidentia 0.10.7 with somedep 0.9.5 today\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["doc.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "doc.md"}],
        "anchors": [{"path": "doc.md", "line_contains": "Pinned evidentia"}],
    }
    failures = check.check_anchors(bump, manifest, "0.10.7")
    assert len(failures) == 1
    assert "ambiguous anchor" in failures[0]


def test_anchor_single_literal_must_equal_current_not_merely_present(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The SINGLE literal on an anchored line must EQUAL current — not merely
    'current appears somewhere'. A single STALE literal still fails (this is the
    plain-stale path, retained after the exactly-one tightening)."""
    (chdir_tmp / "doc.md").write_text("Latest patched release: v0.10.6\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["doc.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "doc.md"}],
        "anchors": [{"path": "doc.md", "line_contains": "Latest patched release:"}],
    }
    failures = check.check_anchors(bump, manifest, "0.10.7")
    assert len(failures) == 1
    assert "shows v0.10.6 not 0.10.7" in failures[0]


def test_anchor_single_literal_equal_current_passes(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exactly one live literal equal to current passes (happy path retained)."""
    (chdir_tmp / "doc.md").write_text("Latest release tag: v0.10.7\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["doc.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "doc.md"}],
        "anchors": [{"path": "doc.md", "line_contains": "Latest release tag:"}],
    }
    assert check.check_anchors(bump, manifest, "0.10.7") == []


# ── FIX-2 (M-1): malformed anchor entry → clean failure string, not KeyError ─


def test_anchor_malformed_missing_line_contains_clean_failure(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An anchor entry missing ``line_contains`` yields an appended failure
    string (NOT a raw KeyError)."""
    (chdir_tmp / "doc.md").write_text("Latest: 0.10.7\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["doc.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "doc.md"}],
        "anchors": [{"path": "doc.md"}],  # line_contains missing
    }
    failures = check.check_anchors(bump, manifest, "0.10.7")
    assert len(failures) == 1
    assert "line_contains" in failures[0]


def test_anchor_malformed_missing_path_clean_failure(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An anchor entry missing ``path`` yields an appended failure string (NOT
    a raw KeyError)."""
    _make_bump_with_tracked(bump, monkeypatch, ["doc.md"], [])
    manifest = {
        "tracked": [],
        "frozen": [{"path": "doc.md"}],
        "anchors": [{"line_contains": "Latest:"}],  # path missing
    }
    failures = check.check_anchors(bump, manifest, "0.10.7")
    assert len(failures) == 1
    assert "path" in failures[0]


# ── FIX-3 (M-2): never-skip routes through the shared classified_paths ────


def test_never_skip_uses_shared_classified_paths(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """check_never_skip routes classification through bump.classified_paths so
    there is ONE definition of the tracked∪frozen union. We assert that helper
    is actually consulted by spying on it."""
    (chdir_tmp / "CHANGELOG.md").write_text("## [0.7.0]\n", encoding="utf-8")
    _make_bump_with_tracked(bump, monkeypatch, ["CHANGELOG.md"], [])
    manifest = {"tracked": [], "frozen": [{"path": "CHANGELOG.md"}]}

    calls: list[Any] = []
    real = bump.classified_paths

    def _spy(m: Any, tracked: Any) -> set[str]:
        calls.append((m, tracked))
        return real(m, tracked)

    monkeypatch.setattr(bump, "classified_paths", _spy)
    assert check.check_never_skip(bump, manifest) == []
    assert calls, "check_never_skip must consult bump.classified_paths"


def test_never_skip_classified_set_identical_via_shared_helper(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The classified set check_never_skip relies on equals what the shared
    bump.classified_paths produces for the same manifest + tracked list (the
    'identical before/after the DRY refactor' guarantee)."""
    (chdir_tmp / "CHANGELOG.md").write_text("0.7.0\n", encoding="utf-8")
    (chdir_tmp / "pyproject.toml").write_text('version = "0.10.7"\n', encoding="utf-8")
    tracked = ["CHANGELOG.md", "pyproject.toml", "docs/old.md"]
    _make_bump_with_tracked(bump, monkeypatch, tracked, [])
    manifest = {
        "tracked": [{"path": "pyproject.toml", "kind": "python_version"}],
        "frozen": [{"path": "CHANGELOG.md"}, {"path": "docs/**"}],
    }
    expected = bump.classified_paths(manifest, bump.tracked_files())
    # docs/old.md is classified by the docs/** glob; both tracked + frozen
    # literals are present.
    assert "CHANGELOG.md" in expected
    assert "pyproject.toml" in expected
    assert "docs/old.md" in expected
    # And never-skip passes (every literal-bearing file is classified).
    assert check.check_never_skip(bump, manifest) == []


def test_real_repo_anchor_check_passes(check: Any) -> None:
    """The committed manifest's POPULATED anchors yield no anchor failures.

    Post-WS1-B the manifest anchors every live "current version" example inside
    an otherwise-frozen file; this is the live proof that each anchored line
    carries exactly one in-family literal equal to the current version (no
    stale/ambiguous/0-literal anchor at HEAD)."""
    bump = check._load_bump_module()
    manifest = bump.load_manifest()
    current = bump.detect_current_version()
    assert manifest["anchors"], "anchors should be populated post-WS1-B"
    assert check.check_anchors(bump, manifest, current) == []


# ── WS1-C: decisions-documented guard (every entry carries a rationale) ───────


def test_decisions_documented_all_with_desc_passes(check: Any) -> None:
    """Every tracked/frozen/anchor entry carrying a non-empty desc passes."""
    manifest = {
        "tracked": [{"path": "a", "kind": "python_version", "desc": "why a"}],
        "frozen": [{"path": "b", "desc": "why b"}],
        "anchors": [{"path": "c", "line_contains": "x", "desc": "why c"}],
    }
    assert check.check_decisions_documented(manifest) == []


def test_decisions_documented_missing_desc_fails(check: Any) -> None:
    """A manifest entry with no ``desc`` is an undocumented decision — hard fail."""
    manifest = {
        "tracked": [{"path": "a", "kind": "python_version"}],  # no desc
        "frozen": [],
        "anchors": [],
    }
    failures = check.check_decisions_documented(manifest)
    assert len(failures) == 1
    assert "undocumented tracked entry 'a'" in failures[0]


def test_decisions_documented_empty_desc_fails(check: Any) -> None:
    """A whitespace-only ``desc`` does not count as documentation."""
    manifest = {
        "tracked": [],
        "frozen": [{"path": "b", "desc": "   "}],
        "anchors": [],
    }
    failures = check.check_decisions_documented(manifest)
    assert len(failures) == 1
    assert "undocumented frozen entry 'b'" in failures[0]


def test_real_repo_decisions_documented_passes(check: Any) -> None:
    """Every entry in the committed manifest carries a rationale (no undocumented
    classification at HEAD)."""
    bump = check._load_bump_module()
    manifest = bump.load_manifest()
    assert check.check_decisions_documented(manifest) == []


# ── requires-python in-sync (member caps, 2026-07 closeout) ────────────────


def _write_pyproject(path: Path, requires_python: str) -> None:
    path.write_text(
        f'[project]\nname = "x"\nrequires-python = "{requires_python}"\n',
        encoding="utf-8",
    )


def test_requires_python_in_sync_passes_when_identical(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Root + every packages/*/pyproject.toml agreeing on requires-python
    passes cleanly."""
    _write_pyproject(chdir_tmp / "pyproject.toml", ">=3.12,<3.14")
    pkg_dir = chdir_tmp / "packages" / "evidentia-core"
    pkg_dir.mkdir(parents=True)
    _write_pyproject(pkg_dir / "pyproject.toml", ">=3.12,<3.14")
    monkeypatch.setattr(check, "REPO_ROOT", chdir_tmp)
    _make_bump_with_tracked(
        bump,
        monkeypatch,
        ["pyproject.toml", "packages/evidentia-core/pyproject.toml"],
        [],
    )
    assert check.check_requires_python_in_sync(bump) == []


def test_requires_python_in_sync_fails_naming_offending_file(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A member whose requires-python diverges from the root is a hard fail
    that NAMES the offending file (the observed-firing contract)."""
    _write_pyproject(chdir_tmp / "pyproject.toml", ">=3.12,<3.14")
    ok_dir = chdir_tmp / "packages" / "evidentia-core"
    ok_dir.mkdir(parents=True)
    _write_pyproject(ok_dir / "pyproject.toml", ">=3.12,<3.14")
    bad_dir = chdir_tmp / "packages" / "evidentia-mcp"
    bad_dir.mkdir(parents=True)
    _write_pyproject(bad_dir / "pyproject.toml", ">=3.12")  # open-ended -> mismatch
    monkeypatch.setattr(check, "REPO_ROOT", chdir_tmp)
    _make_bump_with_tracked(
        bump,
        monkeypatch,
        [
            "pyproject.toml",
            "packages/evidentia-core/pyproject.toml",
            "packages/evidentia-mcp/pyproject.toml",
        ],
        [],
    )
    failures = check.check_requires_python_in_sync(bump)
    assert len(failures) == 1
    assert "packages/evidentia-mcp/pyproject.toml" in failures[0]
    assert ">=3.12" in failures[0]
    assert ">=3.12,<3.14" in failures[0]


def test_requires_python_in_sync_fails_when_member_missing_field(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A member pyproject.toml with no requires-python at all is a clean
    failure, not a crash."""
    _write_pyproject(chdir_tmp / "pyproject.toml", ">=3.12,<3.14")
    bad_dir = chdir_tmp / "packages" / "evidentia-core"
    bad_dir.mkdir(parents=True)
    (bad_dir / "pyproject.toml").write_text('[project]\nname = "evidentia-core"\n', encoding="utf-8")
    monkeypatch.setattr(check, "REPO_ROOT", chdir_tmp)
    _make_bump_with_tracked(
        bump,
        monkeypatch,
        ["pyproject.toml", "packages/evidentia-core/pyproject.toml"],
        [],
    )
    failures = check.check_requires_python_in_sync(bump)
    assert len(failures) == 1
    assert "packages/evidentia-core/pyproject.toml" in failures[0]
    assert "missing" in failures[0]


def test_requires_python_in_sync_fails_when_no_members_found(
    check: Any, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No packages/*/pyproject.toml at all is a config error, not a silent
    pass."""
    _write_pyproject(chdir_tmp / "pyproject.toml", ">=3.12,<3.14")
    monkeypatch.setattr(check, "REPO_ROOT", chdir_tmp)
    _make_bump_with_tracked(bump, monkeypatch, ["pyproject.toml"], [])
    failures = check.check_requires_python_in_sync(bump)
    assert len(failures) == 1
    assert "no packages/*/pyproject.toml files found" in failures[0]


def test_real_repo_requires_python_in_sync_passes(check: Any) -> None:
    """The committed repo's root + all 8 member packages agree on
    requires-python (the v2026-07 member-caps closeout acceptance gate)."""
    bump = check._load_bump_module()
    assert check.check_requires_python_in_sync(bump) == []


# ── SIBLING PINS (v0.12.0) ─────────────────────────────────────────────


def _write_pkg(root: Path, rel: str, body: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_sibling_pins_pass_when_lower_bound_is_current(
    check: Any, bump: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_pkg(tmp_path, "pyproject.toml", '[project]\nname = "root"\n')
    _write_pkg(
        tmp_path,
        "packages/evidentia/pyproject.toml",
        "[project]\n"
        'dependencies = ["evidentia-core>=0.12.0,<0.13.0"]\n'
        "[project.optional-dependencies]\n"
        'worm-s3 = ["evidentia-core[worm-s3]>=0.12.0,<0.13.0"]\n',
    )
    monkeypatch.setattr(check, "REPO_ROOT", tmp_path)
    _make_bump_with_tracked(bump, monkeypatch, ["packages/evidentia/pyproject.toml"], ["evidentia-core"])
    assert check.check_sibling_pins_at_current(bump, "0.12.0") == []


def test_sibling_pins_fail_on_the_worm_extra_regression(
    check: Any, bump: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exact shape that shipped broken in v0.11.0 and v0.11.2.

    The base dependency moved with the release; the extra did not. Their
    ranges no longer intersect, so ``pip install "evidentia[worm-s3]"`` fails
    with ResolutionImpossible. ``bump_pin_range`` could not catch it because
    it searches for the version being bumped FROM, and this pin was already
    two minors behind, so it matched nothing.
    """
    _write_pkg(tmp_path, "pyproject.toml", '[project]\nname = "root"\n')
    _write_pkg(
        tmp_path,
        "packages/evidentia/pyproject.toml",
        "[project]\n"
        'dependencies = ["evidentia-core>=0.12.0,<0.13.0"]\n'
        "[project.optional-dependencies]\n"
        'worm-s3 = ["evidentia-core[worm-s3]>=0.10.0,<0.11.0"]\n',
    )
    monkeypatch.setattr(check, "REPO_ROOT", tmp_path)
    _make_bump_with_tracked(bump, monkeypatch, ["packages/evidentia/pyproject.toml"], ["evidentia-core"])
    failures = check.check_sibling_pins_at_current(bump, "0.12.0")
    assert len(failures) == 1
    assert "optional-dependencies.worm-s3" in failures[0]
    assert ">=0.10.0" in failures[0]


def test_sibling_pins_ignore_third_party_lookalikes(
    check: Any, bump: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A third-party dep sharing the range shape must not be flagged (F-V100-M1)."""
    _write_pkg(tmp_path, "pyproject.toml", '[project]\nname = "root"\n')
    _write_pkg(
        tmp_path,
        "packages/evidentia/pyproject.toml",
        '[project]\ndependencies = ["py-ocsf-models>=0.9.0,<0.10.0"]\n',
    )
    monkeypatch.setattr(check, "REPO_ROOT", tmp_path)
    _make_bump_with_tracked(bump, monkeypatch, ["packages/evidentia/pyproject.toml"], ["evidentia-core"])
    assert check.check_sibling_pins_at_current(bump, "0.12.0") == []


# Every one of these is legal PEP 508 and genuinely unsatisfiable against a
# 0.12.0 base. The first shape is the one that actually shipped broken; the
# rest are variants the FIRST version of this gate silently passed, found by
# the v0.12.0 pre-release security review.
_STALE_SHAPES = [
    ("house_style", "evidentia-core[worm-s3]>=0.10.0,<0.11.0"),
    ("space_before_op", "evidentia-core[worm-s3] >=0.10.0,<0.11.0"),
    ("space_after_op", "evidentia-core[worm-s3]>= 0.10.0,<0.11.0"),
    ("equality_pin", "evidentia-core==0.10.0"),
    ("compatible_release", "evidentia-core~=0.10.0"),
    ("underscore_name", "evidentia_core>=0.10.0,<0.11.0"),
    ("bare_lower_bound", "evidentia-core>=0.10.0"),
    ("environment_marker", 'evidentia-core>=0.10.0; python_version >= "3.12"'),
]

_ACCEPTABLE_SHAPES = [
    ("current_house_style", "evidentia-core[worm-s3]>=0.12.0,<0.13.0"),
    ("current_spaced", "evidentia-core >= 0.12.0, <0.13.0"),
    ("third_party_lookalike", "py-ocsf-models>=0.9.0,<0.10.0"),
]


@pytest.mark.parametrize("label,req", _STALE_SHAPES, ids=[s[0] for s in _STALE_SHAPES])
def test_sibling_pins_catch_every_stale_shape(
    label: str,
    req: str,
    check: Any,
    bump: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A gate that only knows the house style fails OPEN on legal variants."""
    _write_pkg(tmp_path, "pyproject.toml", '[project]\nname = "root"\n')
    _write_pkg(
        tmp_path,
        "packages/evidentia/pyproject.toml",
        f'[project]\ndependencies = ["{req}"]\n',
    )
    monkeypatch.setattr(check, "REPO_ROOT", tmp_path)
    _make_bump_with_tracked(bump, monkeypatch, ["packages/evidentia/pyproject.toml"], ["evidentia-core"])
    failures = check.check_sibling_pins_at_current(bump, "0.12.0")
    assert failures, f"{label}: stale pin {req!r} was NOT caught (gate failed open)"


@pytest.mark.parametrize("label,req", _ACCEPTABLE_SHAPES, ids=[s[0] for s in _ACCEPTABLE_SHAPES])
def test_sibling_pins_accept_current_and_third_party(
    label: str,
    req: str,
    check: Any,
    bump: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Widening the pattern must not make the gate cry wolf."""
    _write_pkg(tmp_path, "pyproject.toml", '[project]\nname = "root"\n')
    _write_pkg(
        tmp_path,
        "packages/evidentia/pyproject.toml",
        f'[project]\ndependencies = ["{req}"]\n',
    )
    monkeypatch.setattr(check, "REPO_ROOT", tmp_path)
    _make_bump_with_tracked(bump, monkeypatch, ["packages/evidentia/pyproject.toml"], ["evidentia-core"])
    assert check.check_sibling_pins_at_current(bump, "0.12.0") == [], label


def test_sibling_name_alternation_survives_re_escape() -> None:
    r"""PEP 503 separators become a class WITHOUT a stray escape.

    Substituting into an already-``re.escape``d name yields ``\[-_.]``, which
    turns the character class into a literal ``[`` and breaks every match.
    This asserts the alternation is built the other way round.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("cvc_alt", CHECK_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    alt = mod._sibling_name_alternation(["evidentia-core", "evidentia"])
    assert alt == "evidentia[-_.]core|evidentia"
    assert r"\[" not in alt
