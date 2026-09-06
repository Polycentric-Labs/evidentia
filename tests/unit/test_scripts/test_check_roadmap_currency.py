"""Tests for scripts/check_roadmap_currency.py (v0.11 cycle-open doc-currency gate).

The gate cross-checks docs/ROADMAP.md status headings against CHANGELOG.md's
shipped ``## [X.Y.Z]`` blocks (the source of truth a shallow CI checkout can
see — NOT git tags, which unpublished ghost tags and tagless checkouts both
betray). These tests pin the parser's leading-version-token / trailing-status
contract against the real heading shapes in the ROADMAP, and each assertion
(A0 single open cycle, A1 planned-never-shipped, A2 umbrella consistency,
A3 open-cycle plan doc, A4 advisory backfill) on synthetic fixtures.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_roadmap_currency.py"


@pytest.fixture(scope="module")
def rc() -> object:
    """Import scripts/check_roadmap_currency.py as a module (no __init__.py)."""
    spec = importlib.util.spec_from_file_location("check_roadmap_currency", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_roadmap_currency"] = module
    spec.loader.exec_module(module)
    return module


def changelog(*versions: str) -> str:
    """A minimal CHANGELOG with one shipped block per version."""
    blocks = "\n\n".join(f"## [{v}] - 2026-01-01\n\n- something." for v in versions)
    return f"# Changelog\n\n## [Unreleased]\n\n{blocks}\n"


# ── parser ──────────────────────────────────────────────────────────────────


def test_parser_requires_leading_version_token(rc) -> None:
    """Headings whose version appears mid-line only are NOT status headings."""
    text = (
        "## v0.10.x — Research line — PLANNED\n"
        "### Medical-device GRC feature line (v0.11 → v1.1+) — PLANNED\n"
        "### 1. Web UI — `evidentia serve` — SHIPPED (v0.4.1)\n"
        "### Planned for v0.4.2 polish:\n"
        "### Operator deep-dive — PLANNED (after the v0.10.x feature surface)\n"
    )
    headings, _ = rc.parse_roadmap(text)
    assert [h.version for h in headings] == ["0.10.x"]


def test_parser_skips_version_heading_without_status(rc) -> None:
    """`## v0.7.0+ — Quality signals, ...` has no status word — skipped."""
    headings, _ = rc.parse_roadmap("## v0.7.0+ — Quality signals, more integrations, UI polish\n")
    assert headings == []


def test_parser_accepts_status_with_trailing_note(rc) -> None:
    text = (
        "### v0.10.5 — OSS first-mover artifacts — PLANNED (added 2026-05-24)\n"
        "### v0.10.12 — Parity build-out — PLANNED (dedicated session)\n"
        "## v0.7.7 — SQL collectors — SHIPPED (+ v0.7.7.1 same-day hot-fix)\n"
    )
    headings, _ = rc.parse_roadmap(text)
    assert [(h.version, h.status) for h in headings] == [
        ("0.10.5", "PLANNED"),
        ("0.10.12", "PLANNED"),
        ("0.7.7", "SHIPPED"),
    ]


def test_parser_umbrella_vs_concrete_classification(rc) -> None:
    text = (
        "## v0.10.x — line — PLANNED\n"
        "## v0.11 — theme — PLANNED\n"
        "### v1.1+ — later — RESERVED\n"
        "## v1.0 — stability — RESERVED\n"
        "### v0.10.5 — artifacts — SHIPPED\n"
    )
    headings, _ = rc.parse_roadmap(text)
    by_version = {h.version: h for h in headings}
    assert by_version["0.10.x"].is_umbrella and by_version["0.10.x"].cycle == "0.10"
    assert by_version["0.11"].is_umbrella and by_version["0.11"].cycle == "0.11"
    assert by_version["1.1+"].is_umbrella and by_version["1.1+"].cycle == "1.1"
    assert by_version["1.0"].is_umbrella and by_version["1.0"].cycle == "1.0"
    assert not by_version["0.10.5"].is_umbrella
    assert by_version["0.10.5"].cycle == "0.10"


def test_parser_skips_fenced_code_blocks(rc) -> None:
    text = "## v0.11 — theme — PLANNED\n```\n## v0.12 — example inside a fence — SHIPPED\n```\n"
    headings, h2_lines = rc.parse_roadmap(text)
    assert [h.version for h in headings] == ["0.11"]
    assert h2_lines == [1]


def test_parser_h2_boundaries_include_statusless_h2(rc) -> None:
    """Every `## ` line is a section boundary, status-bearing or not."""
    text = "## v0.11 — theme — PLANNED\nbody\n## Deferred / rejected items\n"
    _, h2_lines = rc.parse_roadmap(text)
    assert h2_lines == [1, 3]


# ── A0 ──────────────────────────────────────────────────────────────────────


def test_a0_exactly_one_planned_h2(rc) -> None:
    one, _ = rc.parse_roadmap("## v0.11 — theme — PLANNED\n")
    assert rc.check_a0_single_open_cycle(one) == []

    none, _ = rc.parse_roadmap("## v0.10.x — line — SHIPPED\n")
    assert len(rc.check_a0_single_open_cycle(none)) == 1

    two, _ = rc.parse_roadmap("## v0.11 — theme — PLANNED\n## v0.12 — next — PLANNED\n")
    (failure,) = rc.check_a0_single_open_cycle(two)
    assert "2 PLANNED h2" in failure


def test_a0_planned_h3_does_not_count(rc) -> None:
    """Only h2 headings define the open cycle; PLANNED h3s are cycle content."""
    headings, _ = rc.parse_roadmap("## v0.11 — theme — PLANNED\n### v0.11.3 — later patch — PLANNED\n")
    assert rc.check_a0_single_open_cycle(headings) == []


# ── A1 ──────────────────────────────────────────────────────────────────────


def test_a1_concrete_planned_with_shipped_block_fires(rc) -> None:
    headings, _ = rc.parse_roadmap("### v0.10.5 — artifacts — PLANNED\n### v0.10.9 — debt — PLANNED\n")
    failures = rc.check_a1_planned_never_shipped(headings, ["0.10.5"])
    assert len(failures) == 1 and "[0.10.5]" in failures[0]


def test_a1_reserved_with_shipped_block_fires(rc) -> None:
    headings, _ = rc.parse_roadmap("## v1.0 — stability — RESERVED\n")
    assert rc.check_a1_planned_never_shipped(headings, ["1.0.0"]) != []


def test_a1_umbrella_planned_with_cycle_blocks_fires(rc) -> None:
    headings, _ = rc.parse_roadmap("## v0.10.x — line — PLANNED\n")
    failures = rc.check_a1_planned_never_shipped(headings, ["0.10.0", "0.10.5", "0.9.9"])
    assert len(failures) == 1 and "2 shipped" in failures[0]


def test_a1_umbrella_cycle_prefix_is_exact(rc) -> None:
    """A v0.1 umbrella must not match 0.10.x releases (prefix, not substring)."""
    headings, _ = rc.parse_roadmap("## v0.1 — ancient — RESERVED\n")
    assert rc.check_a1_planned_never_shipped(headings, ["0.10.5"]) == []


def test_a1_shipped_and_unshipped_planned_pass(rc) -> None:
    headings, _ = rc.parse_roadmap("### v0.10.6 — shipped fine — SHIPPED\n### v0.12.0 — future — PLANNED\n")
    assert rc.check_a1_planned_never_shipped(headings, ["0.10.6"]) == []


# ── A2 ──────────────────────────────────────────────────────────────────────


def test_a2_planned_umbrella_holding_shipped_entries_fires(rc) -> None:
    text = "## v0.10.x — line — PLANNED\n### v0.10.6 — a — SHIPPED\n### v0.10.9 — b — PLANNED\n"
    headings, h2_lines = rc.parse_roadmap(text)
    failures = rc.check_a2_planned_umbrella_pure(headings, h2_lines, 3)
    assert len(failures) == 1 and "v0.10.6" in failures[0]


def test_a2_section_is_bounded_by_the_next_h2(rc) -> None:
    """A SHIPPED entry after the next h2 belongs to that section, not the umbrella."""
    text = (
        "## v0.11 — theme — PLANNED\n"
        "### v0.11.9 — future patch — PLANNED\n"
        "## Deferred / rejected items\n"
        "### v0.10.6 — old — SHIPPED\n"
    )
    headings, h2_lines = rc.parse_roadmap(text)
    assert rc.check_a2_planned_umbrella_pure(headings, h2_lines, 4) == []


def test_a2_shipped_umbrella_with_planned_h3_passes(rc) -> None:
    """Mid-cycle shape: SHIPPED umbrella, future patches PLANNED inside it."""
    text = "## v0.10.x — line — SHIPPED\n### v0.10.9 — next — PLANNED\n"
    headings, h2_lines = rc.parse_roadmap(text)
    assert rc.check_a2_planned_umbrella_pure(headings, h2_lines, 2) == []


# ── A3 ──────────────────────────────────────────────────────────────────────


def _docs_tree(tmp_path: Path, *plan_names: str) -> Path:
    docs = tmp_path / "docs"
    (docs / "releases" / "plans").mkdir(parents=True)
    for name in plan_names:
        (docs / "releases" / "plans" / name).write_text("# plan\n", encoding="utf-8")
    return docs


def test_a3_open_cycle_without_plan_link_fires(rc, tmp_path: Path) -> None:
    text = "## v0.11 — theme — PLANNED\n\nNo plan link here.\n"
    headings, h2_lines = rc.parse_roadmap(text)
    failures = rc.check_a3_open_cycle_has_plan(headings, h2_lines, text.splitlines(), _docs_tree(tmp_path))
    assert len(failures) == 1 and "links no" in failures[0]


def test_a3_version_mismatched_plan_link_fires(rc, tmp_path: Path) -> None:
    text = "## v0.11 — theme — PLANNED\nFull plan: [old](releases/plans/v0.10.9-plan.md).\n"
    headings, h2_lines = rc.parse_roadmap(text)
    failures = rc.check_a3_open_cycle_has_plan(
        headings, h2_lines, text.splitlines(), _docs_tree(tmp_path, "v0.10.9-plan.md")
    )
    assert len(failures) == 1 and "does not match the cycle (v0.11)" in failures[0]


def test_a3_missing_plan_file_fires(rc, tmp_path: Path) -> None:
    text = "## v0.11 — theme — PLANNED\nFull plan: [plan](releases/plans/v0.11-plan.md).\n"
    headings, h2_lines = rc.parse_roadmap(text)
    failures = rc.check_a3_open_cycle_has_plan(headings, h2_lines, text.splitlines(), _docs_tree(tmp_path))
    assert len(failures) == 1 and "does not exist on disk" in failures[0]


def test_a3_matching_on_disk_plan_passes(rc, tmp_path: Path) -> None:
    text = (
        "## v0.11 — theme — PLANNED\nFull plan: [plan](releases/plans/v0.11-plan.md).\n## v1.0 — stability — RESERVED\n"
    )
    headings, h2_lines = rc.parse_roadmap(text)
    assert (
        rc.check_a3_open_cycle_has_plan(headings, h2_lines, text.splitlines(), _docs_tree(tmp_path, "v0.11-plan.md"))
        == []
    )


def test_a3_link_must_live_inside_the_open_cycle_section(rc, tmp_path: Path) -> None:
    """A plan link in a LATER section cannot satisfy the open cycle."""
    text = (
        "## v0.11 — theme — PLANNED\n"
        "No link in this section.\n"
        "## Release-runbook follow-ups\n"
        "See [plan](releases/plans/v0.11-plan.md).\n"
    )
    headings, h2_lines = rc.parse_roadmap(text)
    failures = rc.check_a3_open_cycle_has_plan(
        headings, h2_lines, text.splitlines(), _docs_tree(tmp_path, "v0.11-plan.md")
    )
    assert len(failures) == 1


def test_a3_is_intro_scoped_a_sub_entry_plan_link_does_not_count(rc, tmp_path: Path) -> None:
    """The exact v0.10.x shape: the PLANNED umbrella's own intro links no plan
    doc, while a sub-h3 body links an OLD per-patch plan — that must NOT
    satisfy the cycle-level claim."""
    text = (
        "## v0.10.x — research line — PLANNED\n"
        "Umbrella intro with no plan link.\n"
        "### v0.10.5 — artifacts — PLANNED\n"
        "Full plan at [v0.10.5-plan.md](releases/plans/v0.10.5-plan.md).\n"
    )
    headings, h2_lines = rc.parse_roadmap(text)
    failures = rc.check_a3_open_cycle_has_plan(
        headings, h2_lines, text.splitlines(), _docs_tree(tmp_path, "v0.10.5-plan.md")
    )
    assert len(failures) == 1 and "links no" in failures[0]


def test_a3_concrete_planned_h2_expects_full_version(rc, tmp_path: Path) -> None:
    text = "## v0.11.2 — hot patch — PLANNED\nFull plan: [plan](releases/plans/v0.11.2-plan.md).\n"
    headings, h2_lines = rc.parse_roadmap(text)
    assert (
        rc.check_a3_open_cycle_has_plan(
            headings,
            h2_lines,
            text.splitlines(),
            _docs_tree(tmp_path, "v0.11.2-plan.md"),
        )
        == []
    )


# ── A4 (advisory) ───────────────────────────────────────────────────────────


def test_a4_reports_missing_latest_cycle_entries_only(rc) -> None:
    headings, _ = rc.parse_roadmap("## v0.10.x — line — SHIPPED\n### v0.10.16 — a — SHIPPED\n")
    advisory = rc.check_a4_latest_cycle_backfilled(headings, ["0.9.9", "0.10.16", "0.10.17"])
    # 0.10.17 is missing; 0.9.9 is a PRIOR cycle (not checked); the umbrella
    # heading does not cover a concrete version.
    assert len(advisory) == 1 and "[0.10.17]" in advisory[0]


def test_a4_latest_cycle_is_numeric_not_lexicographic(rc) -> None:
    """0.10.16 > 0.10.9 numerically — the latest cycle must be 0.10, complete."""
    headings, _ = rc.parse_roadmap("### v0.10.9 — a — SHIPPED\n### v0.10.16 — b — SHIPPED\n")
    assert rc.check_a4_latest_cycle_backfilled(headings, ["0.10.9", "0.10.16"]) == []


def test_a4_is_advisory_never_a_failure(rc, tmp_path: Path) -> None:
    report = rc.run_checks(
        "## v0.11 — theme — PLANNED\nFull plan: [p](releases/plans/v0.11-plan.md).\n",
        changelog("0.10.17"),
        _docs_tree(tmp_path, "v0.11-plan.md"),
    )
    assert report.a4_advisory != []  # 0.10.17 has no SHIPPED heading
    assert report.failures == []  # ...and that does not fail the gate


# ── end-to-end shapes ───────────────────────────────────────────────────────


def test_broken_tree_shape_fires_a1_a2_a3(rc, tmp_path: Path) -> None:
    """The exact defect shape the v0.11 cycle-open found (miniaturized)."""
    roadmap = (
        "## v0.10.x — research line — PLANNED\n"
        "### v0.10.5 — artifacts — PLANNED (added 2026-05-24)\n"
        "Full plan at [v0.10.5-plan.md](releases/plans/v0.10.5-plan.md).\n"
        "### v0.10.6 — crosswalks — SHIPPED\n"
        "### v0.11 — federal theme — PLANNED (post-deep-dive)\n"
    )
    report = rc.run_checks(roadmap, changelog("0.10.5", "0.10.6"), _docs_tree(tmp_path, "v0.10.5-plan.md"))
    assert len(report.a1) == 2  # the PLANNED umbrella + the PLANNED v0.10.5
    assert len(report.a2) == 1  # SHIPPED v0.10.6 inside the PLANNED umbrella
    assert len(report.a3) == 1  # the cycle's own intro links no plan doc
    assert report.failures


def test_fixed_tree_shape_is_green(rc, tmp_path: Path) -> None:
    """The green shape is newest-first: h2 versions descend down the file (A5)."""
    roadmap = (
        "## v1.0 — stability — RESERVED\n"
        "## v0.11 — federal theme — PLANNED\n"
        "Full plan: [v0.11-plan.md](releases/plans/v0.11-plan.md).\n"
        "### v1.1+ — later — RESERVED\n"
        "## v0.10.x — research line — SHIPPED\n"
        "### v0.10.5 — artifacts — SHIPPED\n"
        "### v0.10.6 — crosswalks — SHIPPED\n"
    )
    report = rc.run_checks(roadmap, changelog("0.10.5", "0.10.6"), _docs_tree(tmp_path, "v0.11-plan.md"))
    assert report.failures == []
    assert report.a4_advisory == []


# ── A5 descending version order ─────────────────────────────────────────────


def test_a5_passes_on_descending_h2_order(rc) -> None:
    headings, _ = rc.parse_roadmap(
        "## v1.0 — stability — RESERVED\n## v0.12 — hardening — SHIPPED\n## v0.9.9 — hygiene — SHIPPED\n"
    )
    assert rc.check_a5_descending_version_order(headings) == []


def test_a5_fires_on_ascending_h2_order(rc) -> None:
    """The through-v0.11.2 shape: oldest at the top, which buried the open cycle
    2,300 lines down and left a stale wish list sitting below v1.0."""
    headings, _ = rc.parse_roadmap(
        "## v0.3.0 — first — SHIPPED\n## v0.9.0 — federal — SHIPPED\n## v1.0 — stability — PLANNED\n"
    )
    failures = rc.check_a5_descending_version_order(headings)
    assert len(failures) == 2
    assert "must sort BELOW" in failures[0]


def test_a5_tolerates_umbrella_and_plus_forms(rc) -> None:
    """``_numeric_key`` raises on ``x``; A5 carries its own key so ``v0.10.x``
    and ``v1.1+`` do not crash the gate."""
    headings, _ = rc.parse_roadmap(
        "## v1.1+ — later — RESERVED\n## v0.10.x — research line — SHIPPED\n## v0.10.5 — artifacts — SHIPPED\n"
    )
    assert rc.check_a5_descending_version_order(headings) == []


def test_a5_plus_form_ranks_above_its_bare_version(rc) -> None:
    """``v1.1+`` ("this version and beyond") ranks ABOVE plain ``v1.1``. The
    old key erased the ``+`` and treated the two as equal, so this valid
    layout wrongly failed the gate."""
    headings, _ = rc.parse_roadmap("## v1.1+ - beyond - RESERVED\n## v1.1 - cycle - SHIPPED\n")
    assert rc.check_a5_descending_version_order(headings) == []


def test_a5_fires_when_bare_version_sits_above_its_plus_form(rc) -> None:
    headings, _ = rc.parse_roadmap("## v1.1 - cycle - SHIPPED\n## v1.1+ - beyond - RESERVED\n")
    failures = rc.check_a5_descending_version_order(headings)
    assert len(failures) == 1
    assert "must sort BELOW" in failures[0]


def test_a5_bare_cycle_umbrella_ranks_above_its_concrete_releases(rc) -> None:
    """A bare cycle heading (``v0.11``) is an umbrella and ranks ABOVE its
    own concrete releases, exactly like the ``.x`` form, because that is how
    the file lays every cycle out: umbrella first, patches inside or below.
    The old key ranked a bare cycle BELOW its patches (patch = -1), the
    opposite of the layout, and its docstring asserted the wrong thing."""
    headings, _ = rc.parse_roadmap("## v0.11 - cycle - SHIPPED\n## v0.11.2 - patch - SHIPPED\n")
    assert rc.check_a5_descending_version_order(headings) == []


def test_a5_fires_on_equal_versions(rc) -> None:
    """The ``>=`` branch: two h2s carrying the SAME version are flagged as a
    violation, never tolerated as a tie."""
    headings, _ = rc.parse_roadmap("## v0.12 - one - SHIPPED\n## v0.12 - two - SHIPPED\n")
    failures = rc.check_a5_descending_version_order(headings)
    assert len(failures) == 1
    assert "must sort BELOW" in failures[0]


def test_a5_ignores_headings_without_version_token_or_status(rc) -> None:
    """Malformed and non-status headings never reach A5: no leading version
    token, or no trailing status word, means the heading is not tracked."""
    headings, _ = rc.parse_roadmap("## version notes\n## v1.0 - open - PLANNED\n## v0.9.x has no status word here\n")
    assert [h.version for h in headings] == ["1.0"]
    assert rc.check_a5_descending_version_order(headings) == []


def test_a5_counts_toward_gate_failure(rc, tmp_path: Path) -> None:
    """A5 is a failing assertion, not an advisory like A4."""
    report = rc.run_checks(
        "## v0.11 — theme — PLANNED\nFull plan: [p](releases/plans/v0.11-plan.md).\n## v1.0 — later — RESERVED\n",
        changelog("0.10.5"),
        _docs_tree(tmp_path, "v0.11-plan.md"),
    )
    assert report.a5
    assert report.failures


def test_real_repo_documents_parse(rc) -> None:
    """Structural smoke on the live docs: the parser sees the real shapes."""
    roadmap_text = (REPO_ROOT / "docs" / "ROADMAP.md").read_text(encoding="utf-8")
    changelog_text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    headings, h2_lines = rc.parse_roadmap(roadmap_text)
    assert len(headings) >= 40
    assert len(h2_lines) >= 30
    assert len(rc.parse_changelog_versions(changelog_text)) >= 40
