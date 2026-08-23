#!/usr/bin/env python3
"""Doc-currency gate: the ROADMAP must agree with the CHANGELOG about what shipped.

v0.11 cycle-open. Motivation: v0.10.17 shipped with four ROADMAP entries still
marked PLANNED although their releases had shipped (v0.10.5 / v0.10.9 /
v0.10.11 / v0.10.12), the shipped ``## v0.10.x`` cycle umbrella still marked
PLANNED, and four shipped patches with no ROADMAP entry at all — none of it
caught mechanically (engineering-practices lesson 11: a doc's currency claim
is a gate or it is a lie). The version-anchor overlay cannot express these
STRUCTURAL claims (a status word on a heading, a section that must exist), so
this dedicated gate covers them.

The source of truth for "shipped" is CHANGELOG.md's ``## [X.Y.Z]`` blocks —
deliberately NOT git tags: the CI checkout does not fetch tags (a tag-based
gate would pass locally and break in CI), and unpublished ghost tags exist
(v0.10.14 / v0.10.15) whose releases never published and therefore must NOT
demand ROADMAP entries; both have no CHANGELOG block, which is exactly right.

Headings parse as ``## / ### v<version> — <title> — <STATUS>[ (note)]``, keyed
off the LEADING version token and the TRAILING status word. Headings without a
leading version token are skipped (``### Medical-device GRC feature line
(v0.11 → v1.1+) — PLANNED`` and ``### 1. Web UI — … — SHIPPED (v0.4.1)`` carry
versions mid-line only), as are version headings with no status word
(``## v0.7.0+ — Quality signals, …``). A version is a cycle UMBRELLA when it
has no concrete patch part (``0.10.x`` / ``0.11`` / ``1.1+``), else CONCRETE.

Assertions:

  A0 — exactly ONE ``PLANNED`` h2 exists (the single open cycle).
  A1 — nothing marked ``PLANNED`` / ``RESERVED`` has shipped: a concrete
       heading must have no CHANGELOG ``## [X.Y.Z]`` block; an umbrella must
       have no ``## [X.Y.*]`` block at all. (The workhorse.)
  A2 — a ``PLANNED`` umbrella h2 contains no ``SHIPPED`` entry inside its own
       section (structural self-consistency, CHANGELOG-independent — the
       v0.10.x umbrella sat PLANNED over three SHIPPED h3s).
  A3 — the top ``PLANNED`` h2's INTRO (the text before its first sub-heading)
       links a ``releases/plans/v<x>-plan.md`` whose version matches its cycle
       and which EXISTS on disk (an open cycle without a plan doc is
       unratified work). Intro-scoped deliberately: an umbrella's h3 bodies
       legitimately link OLD per-patch plan docs, which must not satisfy the
       cycle-level claim.
  A4 — ADVISORY (reported, never failing): every CHANGELOG version in the
       LATEST shipped cycle has a concrete ``SHIPPED`` heading. Advisory-first
       per the wiring rule — a check that becomes required must be observed
       false-positive-free before it may block; harden once the backfill
       policy for pre-convention patches is settled.

Pure-filesystem: reads ``docs/ROADMAP.md`` + ``CHANGELOG.md`` and stats
plan-doc paths. No git, no workspace import — safe in shallow CI checkouts
and light installs, so it lives in the fast ``consistency`` gate scope.

Exit codes:
    0 — PASS (A0–A3 hold; A4 advisories do not fail the gate)
    1 — FAIL (at least one A0–A3 assertion failed)
    2 — usage / IO error

Usage:
    python scripts/check_roadmap_currency.py
    python scripts/check_roadmap_currency.py --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
ROADMAP_PATH = REPO_ROOT / "docs" / "ROADMAP.md"
CHANGELOG_PATH = REPO_ROOT / "CHANGELOG.md"
DOCS_DIR = REPO_ROOT / "docs"

# The LEADING version token right after the hashes: `## v0.10.x`, `### v0.11`,
# `## v1.1+`, `### v0.10.5`. The lookahead requires whitespace/EOL after the
# token so `v0.10.x` is one token (never `v0.10` + trailing `.x`) and a heading
# like `## version notes` cannot half-match.
_HEADING_RE = re.compile(r"^(?P<hashes>#{2,3})\s+v(?P<version>\d+\.\d+(?:\.(?:\d+|x))?\+?)(?=\s|$)")
_STATUS_RE = re.compile(r"\b(SHIPPED|PLANNED|RESERVED)\b")
_CHANGELOG_VERSION_RE = re.compile(r"^## \[(\d+\.\d+\.\d+(?:\.\d+)?)\]", re.MULTILINE)
# A markdown link target of the form `releases/plans/v<...>.md` (hrefs in the
# ROADMAP are docs/-relative).
_PLAN_LINK_RE = re.compile(r"\(((?:\./)?releases/plans/v[0-9][\w.+-]*\.md)\)")



def check_a5_descending_version_order(headings: list[Heading]) -> list[str]:
    """A5, h2 version headings appear in strictly DESCENDING version order.

    The roadmap reads newest-first: the open cycle and the most recent releases
    are at the top, the oldest at the bottom. Before v0.12.1 the file was
    ascending, which put a stale `v0.7.0+` wish list BELOW the v1.0 section and
    made the reader scroll 2,300 lines to find current work. Ordering is a
    structural claim like any other, so it is gated rather than trusted.

    Only h2 headings participate. h3 entries nest inside their cycle and are
    deliberately not constrained here.
    """
    def order_key(version: str) -> tuple[int, int, int]:
        """Sortable key tolerant of the umbrella forms `_numeric_key` rejects.

        `v0.10.x` (a whole line) sorts ABOVE its concrete patches; a bare cycle
        like `v0.11` sorts BELOW them, which is where the file already puts it.
        """
        core = version.rstrip("+")
        parts = core.split(".")
        major, minor = int(parts[0]), int(parts[1])
        if len(parts) < 3:
            patch = -1
        elif parts[2] == "x":
            patch = 10_000
        else:
            patch = int(parts[2])
        return (major, minor, patch)

    h2s = [h for h in headings if h.level == 2]
    failures: list[str] = []
    for earlier, later in zip(h2s, h2s[1:]):
        if order_key(later.version) >= order_key(earlier.version):
            failures.append(
                f"line {later.line_no}: v{later.version} must sort BELOW "
                f"v{earlier.version} (line {earlier.line_no}); the roadmap is "
                f"newest-first, so h2 versions descend down the file"
            )
    return failures


@dataclass(frozen=True)
class Heading:
    """One parsed ROADMAP status heading."""

    line_no: int  # 1-based
    level: int  # 2 (h2) or 3 (h3)
    version: str  # "0.10.x" | "0.11" | "1.1+" | "0.10.5" | ...
    status: str  # "SHIPPED" | "PLANNED" | "RESERVED"
    text: str  # the full heading line (for messages)

    @property
    def is_umbrella(self) -> bool:
        """A cycle umbrella (no concrete patch part) vs a concrete release."""
        if self.version.endswith("+") or self.version.endswith(".x"):
            return True
        return self.version.count(".") < 2

    @property
    def cycle(self) -> str:
        """The `X.Y` cycle prefix of this heading's version."""
        parts = self.version.rstrip("+").split(".")
        return ".".join(parts[:2])


def parse_roadmap(text: str) -> tuple[list[Heading], list[int]]:
    """Parse status headings + ALL h2 line numbers (section boundaries).

    Fenced code blocks are skipped so an example heading inside a ``` fence
    can never register. The h2 boundary list includes EVERY `## ` heading
    (status-bearing or not) — a section ends at the next h2, whatever it is.
    """
    headings: list[Heading] = []
    h2_lines: list[int] = []
    in_fence = False
    for idx, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if line.startswith("## ") and not line.startswith("###"):
            h2_lines.append(idx)
        m = _HEADING_RE.match(line)
        if m is None:
            continue
        rest = line[m.end() :]
        statuses = _STATUS_RE.findall(rest)
        if not statuses:
            continue  # a version heading with no status word is not tracked
        headings.append(
            Heading(
                line_no=idx,
                level=len(m.group("hashes")),
                version=m.group("version"),
                status=statuses[-1],
                text=line.strip(),
            )
        )
    return headings, h2_lines


def parse_changelog_versions(text: str) -> list[str]:
    """Every shipped `## [X.Y.Z]` version in CHANGELOG.md ([Unreleased] never matches)."""
    return _CHANGELOG_VERSION_RE.findall(text)


def _numeric_key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("."))


def _section_end(start_line: int, h2_lines: list[int], total_lines: int) -> int:
    """The last line (inclusive) of the h2 section starting at ``start_line``."""
    later = [ln for ln in h2_lines if ln > start_line]
    return (min(later) - 1) if later else total_lines


def check_a0_single_open_cycle(headings: list[Heading]) -> list[str]:
    """A0 — exactly one PLANNED h2 (the single open cycle)."""
    planned_h2 = [h for h in headings if h.level == 2 and h.status == "PLANNED"]
    if len(planned_h2) == 1:
        return []
    if not planned_h2:
        return [
            "no PLANNED h2 found — the roadmap must carry exactly one open "
            "cycle (`## v<x> — ... — PLANNED`)"
        ]
    listed = "; ".join(f"line {h.line_no}: {h.text}" for h in planned_h2)
    return [
        f"{len(planned_h2)} PLANNED h2 headings found (exactly one open cycle "
        f"allowed): {listed}"
    ]


def check_a1_planned_never_shipped(
    headings: list[Heading], shipped: list[str]
) -> list[str]:
    """A1 — nothing marked PLANNED/RESERVED has a shipped CHANGELOG block."""
    failures: list[str] = []
    shipped_set = set(shipped)
    for h in headings:
        if h.status not in ("PLANNED", "RESERVED"):
            continue
        if h.is_umbrella:
            cycle_hits = sorted(
                (v for v in shipped_set if v.startswith(h.cycle + ".")),
                key=_numeric_key,
            )
            if cycle_hits:
                failures.append(
                    f"line {h.line_no}: '{h.text}' is {h.status} but the "
                    f"v{h.cycle}.x cycle has {len(cycle_hits)} shipped "
                    f"CHANGELOG release(s) ({', '.join(cycle_hits[:4])}"
                    f"{', ...' if len(cycle_hits) > 4 else ''}) — mark the "
                    f"cycle SHIPPED or fix the heading"
                )
        elif h.version in shipped_set:
            failures.append(
                f"line {h.line_no}: '{h.text}' is {h.status} but CHANGELOG "
                f"has a shipped [{h.version}] block — mark it SHIPPED"
            )
    return failures


def check_a2_planned_umbrella_pure(
    headings: list[Heading], h2_lines: list[int], total_lines: int
) -> list[str]:
    """A2 — a PLANNED umbrella h2 contains no SHIPPED entry in its section."""
    failures: list[str] = []
    for h in headings:
        if not (h.level == 2 and h.status == "PLANNED" and h.is_umbrella):
            continue
        end = _section_end(h.line_no, h2_lines, total_lines)
        shipped_inside = [
            s
            for s in headings
            if h.line_no < s.line_no <= end and s.status == "SHIPPED"
        ]
        if shipped_inside:
            listed = ", ".join(f"v{s.version} (line {s.line_no})" for s in shipped_inside)
            failures.append(
                f"line {h.line_no}: PLANNED umbrella '{h.text}' contains "
                f"{len(shipped_inside)} SHIPPED entr(ies) inside its own "
                f"section ({listed}) — a cycle with shipped releases is not "
                f"PLANNED"
            )
    return failures


def _intro_end(start_line: int, roadmap_lines: list[str], section_end: int) -> int:
    """The last line (inclusive) of a heading's INTRO — up to its first
    sub-heading (any ``##``/``###`` line, status-bearing or not), fence-aware.
    """
    in_fence = False
    for idx in range(start_line + 1, section_end + 1):
        line = roadmap_lines[idx - 1]
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence and line.startswith("##"):
            return idx - 1
    return section_end


def check_a3_open_cycle_has_plan(
    headings: list[Heading],
    h2_lines: list[int],
    roadmap_lines: list[str],
    docs_dir: Path,
) -> list[str]:
    """A3 — the top PLANNED h2's intro links an on-disk, version-matching plan doc."""
    planned_h2 = [h for h in headings if h.level == 2 and h.status == "PLANNED"]
    if not planned_h2:
        return [
            "no PLANNED h2 exists to carry the current-cycle plan link "
            "(see the A0 failure)"
        ]
    top = min(planned_h2, key=lambda h: h.line_no)
    section_end = _section_end(top.line_no, h2_lines, len(roadmap_lines))
    end = _intro_end(top.line_no, roadmap_lines, section_end)
    intro = "\n".join(roadmap_lines[top.line_no - 1 : end])
    links = _PLAN_LINK_RE.findall(intro)
    if not links:
        return [
            f"line {top.line_no}: the open cycle '{top.text}' links no "
            f"releases/plans/v<x>-plan.md in its intro (before the first "
            f"sub-heading) — the current cycle must link its plan doc"
        ]
    expected = f"v{top.version if not top.is_umbrella else top.cycle}"
    problems: list[str] = []
    for link in links:
        name = Path(link).name
        rest = name[len(expected) :] if name.startswith(expected) else None
        if rest is None or rest[:1] not in (".", "-"):
            problems.append(f"'{link}' does not match the cycle ({expected})")
            continue
        if not (docs_dir / link).is_file():
            problems.append(f"'{link}' does not exist on disk under docs/")
            continue
        return []  # one version-matching, on-disk plan link satisfies A3
    return [
        f"line {top.line_no}: the open cycle '{top.text}' has no satisfying "
        f"plan link — " + "; ".join(problems)
    ]


def check_a4_latest_cycle_backfilled(
    headings: list[Heading], shipped: list[str]
) -> list[str]:
    """A4 (ADVISORY) — every shipped version in the latest cycle has a SHIPPED heading."""
    if not shipped:
        return []
    latest = max(shipped, key=_numeric_key)
    cycle_prefix = ".".join(latest.split(".")[:2]) + "."
    members = sorted(
        (v for v in shipped if v.startswith(cycle_prefix)), key=_numeric_key
    )
    covered = {
        h.version for h in headings if h.status == "SHIPPED" and not h.is_umbrella
    }
    return [
        f"shipped [{v}] has no `SHIPPED` roadmap heading — backfill a "
        f"`### v{v} — ... — SHIPPED` entry"
        for v in members
        if v not in covered
    ]


@dataclass
class Report:
    """The per-assertion findings of one gate run."""

    a0: list[str]
    a1: list[str]
    a2: list[str]
    a3: list[str]
    a4_advisory: list[str]
    a5: list[str]
    heading_count: int
    shipped_count: int

    @property
    def failures(self) -> list[str]:
        return self.a0 + self.a1 + self.a2 + self.a3 + self.a5


def run_checks(roadmap_text: str, changelog_text: str, docs_dir: Path) -> Report:
    """Run every assertion against the given documents."""
    headings, h2_lines = parse_roadmap(roadmap_text)
    roadmap_lines = roadmap_text.splitlines()
    shipped = parse_changelog_versions(changelog_text)
    return Report(
        a0=check_a0_single_open_cycle(headings),
        a1=check_a1_planned_never_shipped(headings, shipped),
        a2=check_a2_planned_umbrella_pure(headings, h2_lines, len(roadmap_lines)),
        a3=check_a3_open_cycle_has_plan(headings, h2_lines, roadmap_lines, docs_dir),
        a4_advisory=check_a4_latest_cycle_backfilled(headings, shipped),
        a5=check_a5_descending_version_order(headings),
        heading_count=len(headings),
        shipped_count=len(shipped),
    )


_SECTIONS = (
    ("a0", "A0 single-open-cycle", "exactly one PLANNED h2."),
    ("a1", "A1 planned-never-shipped", "no PLANNED/RESERVED heading has shipped."),
    ("a2", "A2 umbrella-consistency", "no PLANNED umbrella holds SHIPPED entries."),
    ("a3", "A3 open-cycle-plan-doc", "the open cycle links an on-disk plan doc."),
    ("a5", "A5 descending-version-order", "h2 versions descend down the file (newest first)."),
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="emit a machine-readable JSON report"
    )
    args = parser.parse_args(argv)

    try:
        roadmap_text = ROADMAP_PATH.read_text(encoding="utf-8")
        changelog_text = CHANGELOG_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"check_roadmap_currency: cannot read input: {exc}", file=sys.stderr)
        return 2

    report = run_checks(roadmap_text, changelog_text, DOCS_DIR)

    if args.json:
        print(
            json.dumps(
                {
                    "ok": not report.failures,
                    "a0_failures": report.a0,
                    "a1_failures": report.a1,
                    "a2_failures": report.a2,
                    "a3_failures": report.a3,
                    "a5_failures": report.a5,
                    "a4_advisory": report.a4_advisory,
                },
                indent=2,
            )
        )
        return 0 if not report.failures else 1

    print(
        f"check_roadmap_currency: {report.heading_count} status heading(s), "
        f"{report.shipped_count} shipped CHANGELOG version(s)"
    )
    for attr, label, pass_text in _SECTIONS:
        findings: list[str] = getattr(report, attr)
        if findings:
            print()
            print(f"{label} FAILURES ({len(findings)}):")
            for f in findings:
                print(f"  - {f}")
        else:
            print(f"  {label}: PASS — {pass_text}")

    if report.a4_advisory:
        print()
        print(f"A4 latest-cycle-backfill ADVISORY ({len(report.a4_advisory)} — does not fail the gate):")
        for f in report.a4_advisory:
            print(f"  - {f}")
    else:
        print("  A4 latest-cycle-backfill: clean — every shipped release in the latest cycle has its entry.")

    print()
    if report.failures:
        print(
            f"check_roadmap_currency: FAIL ({len(report.failures)} issue(s)). "
            "The ROADMAP's status headings disagree with the CHANGELOG."
        )
        return 1
    print("check_roadmap_currency: PASS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
