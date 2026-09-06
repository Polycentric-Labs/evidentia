#!/usr/bin/env python3
"""Generate the README "Recent Releases" block from CHANGELOG.md.

Evidentia v0.10.7 Phase E5a. The README's ``## Recent Releases`` section
is a hand-maintained mirror of the newest CHANGELOG entries; it drifted
stale across the v0.10.x line (e.g. shipping v0.10.7 while the README
still listed v0.10.6/5/4). This script makes the block a *generated*
artifact so it can never lag the project version again.

THE CONTRACT (CHANGELOG -> README)
==================================

CHANGELOG.md is the source of truth. It carries one block per release:

    ## [X.Y.Z] - YYYY-MM-DD

    **Theme**: *<theme phrase>*. <prose...>

    **Release summary**: <prose...>

    ### Added
    - <bullet>
    ...

This generator:

  1. Parses every ``## [X.Y.Z] - YYYY-MM-DD`` heading (newest first as they
     appear top-to-bottom; the ``[Unreleased]`` block has no date and is
     skipped).
  2. Takes the top 3 dated blocks.
  3. For each, emits ONE README entry in the existing house style::

         **vX.Y.Z (YYYY-MM-DD)** — *<condensed theme>*. <condensed summary>.

     - the *theme* comes from the block's ``**Theme**:`` line, stripped of
       its leading ``vX.Y.Z —`` self-prefix and normalized (em dashes ->
       commas; trailing period dropped).
     - the *summary* is condensed from the block's leading ``### Added``
       bullets (their first sentence each), capped to keep the entry to the
       ~1-3 sentence length of the surrounding entries.
  4. Replaces ONLY the text between the ``## Recent Releases`` header line
     and the ``Full release history:`` line in README.md. Everything else
     in the README is left byte-for-byte untouched.

``--check`` MODE (the pre-tag staleness guard)
==============================================

``gen_readme_releases.py --check`` exits non-zero unless the README
Recent-Releases block has EXACTLY 3 entries AND the newest entry's version
equals the current project version (read from
``packages/evidentia-core/pyproject.toml``). This is wired into the
``check_docs_health.py`` ``readme_recent_releases_current`` invariant so a
release can't ship with a stale README releases list.

Deterministic, stdlib-only. The auto-condensed prose is intended to be
README-quality on its own; if a particular release's CHANGELOG phrasing
condenses awkwardly, hand-edit the generated block and (optionally) tighten
the condensation heuristics here — the ``--check`` guard only asserts count
+ newest-version, not exact prose, so hand-polish survives re-runs as long
as the count and newest version stay correct.

Exit codes:
    0 — write mode: block written (or already current). check mode: PASS.
    1 — check mode: block is stale (wrong count or newest != current).
    2 — IO / parse error (CHANGELOG or README missing/malformed).

Usage:
    python scripts/gen_readme_releases.py            # rewrite README block
    python scripts/gen_readme_releases.py --check     # staleness guard
    python scripts/gen_readme_releases.py --print      # print block to stdout
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent

CHANGELOG_PATH = REPO_ROOT / "CHANGELOG.md"
README_PATH = REPO_ROOT / "README.md"
CORE_PYPROJECT_PATH = REPO_ROOT / "packages" / "evidentia-core" / "pyproject.toml"

TOP_N = 3

# The README block lives between this header line and the "Full release
# history:" pointer line. The header pattern deliberately does NOT consume
# the trailing newline (no ``\s*$``) so ``.end()`` lands immediately after
# the header text; the splice then re-adds exactly one blank line. The
# trailing ``[^\S\n]*`` tolerates trailing spaces on the header line itself.
RECENT_HEADER_RE = re.compile(r"^## Recent Releases[^\S\n]*", re.MULTILINE)
FULL_HISTORY_RE = re.compile(r"^Full release history:", re.MULTILINE)

# A dated CHANGELOG release heading: `## [X.Y.Z] - YYYY-MM-DD`.
CHANGELOG_HEADING_RE = re.compile(
    r"^## \[(?P<version>\d+\.\d+\.\d+(?:\.\d+)?)\]\s*-\s*(?P<date>\d{4}-\d{2}-\d{2})\s*$",
    re.MULTILINE,
)

# The `**Theme**: *<phrase>*. ...` line inside a block.
THEME_RE = re.compile(r"\*\*Theme\*\*:\s*\*(?P<theme>.+?)\*\.?", re.DOTALL)

# A README recent-releases entry's leading version token: `**vX.Y.Z (date)**`.
README_ENTRY_RE = re.compile(
    r"^\*\*v(?P<version>\d+\.\d+\.\d+(?:\.\d+)?)\s*\(",
    re.MULTILINE,
)

# Max characters of condensed-summary prose appended after the theme. Keeps
# each entry to the ~1-3 sentence length of the surrounding house style.
SUMMARY_CHAR_BUDGET = 300

# Max number of `` + ``-joined clauses kept from a CHANGELOG theme. The
# house-style README themes run ~2-3 short clauses (e.g. "OCSF symmetry
# loop close + CHANGELOG pre-tag CI gate"); CHANGELOG themes are often
# longer and parenthetical, so we keep the leading clauses + drop trailing
# ones past this cap.
THEME_CLAUSE_CAP = 3


@dataclass(frozen=True)
class ReleaseBlock:
    """One parsed CHANGELOG release block."""

    version: str
    date: str
    body: str  # text between this heading and the next `## ` heading


def detect_current_version() -> str:
    """Read evidentia-core's pyproject.toml ``version`` — the source of truth.

    Mirrors ``bump_version.detect_current_version`` (kept inline so this
    script stays stdlib-only and import-free).
    """
    if not CORE_PYPROJECT_PATH.exists():
        raise FileNotFoundError(f"cannot detect current version: {CORE_PYPROJECT_PATH} missing")
    for line in CORE_PYPROJECT_PATH.read_text(encoding="utf-8").splitlines():
        m = re.match(r'\s*version\s*=\s*"(\d+\.\d+\.\d+(?:\.\d+)?)"', line)
        if m:
            return m.group(1)
    raise ValueError("cannot find version field in evidentia-core/pyproject.toml")


def parse_changelog_blocks(changelog_text: str) -> list[ReleaseBlock]:
    """Return every dated ``## [X.Y.Z] - DATE`` block, in document order.

    The document lists releases newest-first, so the returned list is also
    newest-first. The ``[Unreleased]`` block (no date) is skipped by the
    date-requiring heading regex.
    """
    matches = list(CHANGELOG_HEADING_RE.finditer(changelog_text))
    blocks: list[ReleaseBlock] = []
    # Generic next-`## ` heading finder to bound each block's body.
    next_h2_re = re.compile(r"^## ", re.MULTILINE)
    for m in matches:
        body_start = m.end()
        # The block body runs to the next `## ` heading after this one.
        nxt = next_h2_re.search(changelog_text, pos=body_start)
        body_end = nxt.start() if nxt else len(changelog_text)
        blocks.append(
            ReleaseBlock(
                version=m.group("version"),
                date=m.group("date"),
                body=changelog_text[body_start:body_end],
            )
        )
    return blocks


def _strip_trailing_refs(text: str) -> str:
    """Drop trailing CHANGELOG bookkeeping fragments from a bullet lead.

    Removes ``See commit(s) ...`` / ``See [..](..)`` tails and any trailing
    ``(...)`` parenthetical (commit hashes, phase labels, "(was N ...)"),
    which read as noise in a README one-liner.
    """
    # Drop a "See commit(s) ..." / "See [text](url) ..." tail.
    text = re.split(r"\s+See (?:commit|commits|\[)", text)[0]
    # Drop one trailing parenthetical group (e.g. "(Phase 7)", "(class_uid 2004)").
    text = re.sub(r"\s*\([^()]*\)\s*$", "", text)
    return text.strip()


def _normalize_inline(text: str) -> str:
    """Collapse whitespace + soft-normalize punctuation for a one-liner.

    - join hard-wrapped CHANGELOG lines into a single line
    - em dash / en dash between words -> comma (matches the repo's
      em-dash-free prose preference and the surrounding entry voice)
    - drop a trailing period (the caller re-adds sentence punctuation)
    """
    one_line = re.sub(r"\s+", " ", text).strip()
    # Em/en dash used as a clause separator -> ", ".
    one_line = re.sub(r"\s*[—–]\s*", ", ", one_line)
    return one_line.rstrip(". ").strip()


def _cap_theme_clauses(theme: str) -> str:
    """Keep at most ``THEME_CLAUSE_CAP`` leading `` + ``-joined clauses.

    Each kept clause is itself trimmed of a trailing parenthetical aside
    (e.g. "(carried from v0.10.5 deferred Phases 1-5)") so the theme reads
    like the short house-style README themes.
    """
    clauses = [c.strip() for c in theme.split(" + ") if c.strip()]
    trimmed: list[str] = []
    for clause in clauses[:THEME_CLAUSE_CAP]:
        clause = re.sub(r"\s*\([^()]*\)\s*$", "", clause).strip()
        if clause:
            trimmed.append(clause)
    return " + ".join(trimmed)


def condense_theme(body: str, version: str) -> str:
    """Extract + condense the block's theme phrase.

    The CHANGELOG theme phrase usually self-prefixes with ``vX.Y.Z —``;
    that prefix is stripped (the README entry already shows the version in
    its bold lead). Em/en dashes inside the phrase are normalized, the
    phrase is capped to the leading clauses, and trailing parenthetical
    asides are dropped — yielding the short house-style README theme.
    """
    m = THEME_RE.search(body)
    if not m:
        return ""
    theme = m.group("theme").strip()
    # Strip a leading `vX.Y.Z` self-reference and the dash/space after it.
    theme = re.sub(rf"^v?{re.escape(version)}\s*[—–-]\s*", "", theme).strip()
    # Collapse internal whitespace WITHOUT turning ` + ` clause separators
    # into commas (clause capping below relies on the ` + ` delimiter).
    theme = re.sub(r"\s+", " ", theme).rstrip(". ").strip()
    return _cap_theme_clauses(theme)


def _split_sentences(text: str) -> list[str]:
    """Naive sentence split on `. ` boundaries (good enough for bullets)."""
    # Protect common abbreviations / decimals are rare in these bullets; a
    # simple split is sufficient and deterministic.
    parts = re.split(r"(?<=[.])\s+", text.strip())
    return [p.strip() for p in parts if p.strip()]


def _extract_added_bullets(body: str) -> list[str]:
    """Return the first-sentence lead of each top-level ``### Added`` bullet.

    Falls back to ``### Changed`` / ``### Fixed`` / ``### Docs`` /
    ``### Security`` (in that order) if there is no ``### Added`` section, so
    hardening/doc-only cycles (which have no Added section) still produce a
    summary.
    """
    section_order = ["Added", "Changed", "Fixed", "Docs", "Security"]
    section_re = {name: re.compile(rf"^### {name}\s*$", re.MULTILINE) for name in section_order}
    next_h3_re = re.compile(r"^#{2,3} ", re.MULTILINE)

    for name in section_order:
        m = section_re[name].search(body)
        if not m:
            continue
        sec_start = m.end()
        nxt = next_h3_re.search(body, pos=sec_start)
        sec_end = nxt.start() if nxt else len(body)
        section = body[sec_start:sec_end]
        bullets = _parse_top_level_bullets(section)
        if bullets:
            return bullets
    return []


def _parse_top_level_bullets(section: str) -> list[str]:
    """Split a markdown section into its top-level (``- ``) bullets.

    Continuation lines (indented, or wrapped) are folded into the bullet
    they belong to. Nested sub-bullets are folded too (we only summarize at
    the top level). Returns the first sentence of each bullet.
    """
    raw_bullets: list[str] = []
    current: list[str] = []
    for line in section.splitlines():
        if re.match(r"^- ", line):
            if current:
                raw_bullets.append(" ".join(current))
            current = [line[2:].strip()]
        elif current and (line.startswith((" ", "\t")) or not line.strip()):
            # continuation / wrapped line / blank inside the bullet
            if line.strip():
                current.append(line.strip())
        elif current and line.strip():
            # a non-indented continuation (CHANGELOG wraps bullets without
            # indentation in several places) — fold it in.
            current.append(line.strip())
    if current:
        raw_bullets.append(" ".join(current))

    leads: list[str] = []
    for b in raw_bullets:
        normalized = _normalize_inline(b)
        if not normalized:
            continue
        sentences = _split_sentences(normalized + ".")
        lead = sentences[0] if sentences else normalized
        lead = _strip_trailing_refs(lead.rstrip("."))
        # Drop a leading "(Phase N): " label some bullets carry after their
        # bold code token, e.g. "`x --format y` (Phase 7): emits ...".
        lead = re.sub(r"^(.*?)\s*\(Phase \d+\):\s*", r"\1: ", lead).strip()
        if lead:
            leads.append(lead)
    return leads


def condense_summary(body: str) -> str:
    """Build a short summary sentence from the block's leading bullets.

    Joins the first-sentence leads of the top bullets with "; " until the
    character budget is hit, so the entry matches the ~1-3 sentence length
    of the surrounding README entries.
    """
    leads = _extract_added_bullets(body)
    if not leads:
        return ""
    picked: list[str] = []
    running = 0
    for lead in leads:
        # +2 for the "; " join cost.
        cost = len(lead) + (2 if picked else 0)
        if picked and running + cost > SUMMARY_CHAR_BUDGET:
            break
        picked.append(lead)
        running += cost
    return "; ".join(picked)


def render_entry(block: ReleaseBlock) -> str:
    """Render ONE README recent-releases entry for a release block."""
    theme = condense_theme(block.body, block.version)
    summary = condense_summary(block.body)
    head = f"**v{block.version} ({block.date})**"
    if theme:
        head += f" — *{theme}*"
    if summary:
        return f"{head}. {summary}."
    return f"{head}."


def render_block(blocks: list[ReleaseBlock]) -> str:
    """Render the top-N entries as the README block body (between header and
    the 'Full release history:' line). Entries are blank-line separated."""
    top = blocks[:TOP_N]
    return "\n\n".join(render_entry(b) for b in top)


def splice_into_readme(readme_text: str, new_block_body: str) -> str:
    """Replace the text between the ``## Recent Releases`` header and the
    ``Full release history:`` line with ``new_block_body``.

    Preserves the header line, the blank lines framing the block, and
    everything outside the block byte-for-byte.
    """
    header_m = RECENT_HEADER_RE.search(readme_text)
    if header_m is None:
        raise ValueError("README has no '## Recent Releases' header")
    full_m = FULL_HISTORY_RE.search(readme_text, pos=header_m.end())
    if full_m is None:
        raise ValueError("README has no 'Full release history:' line after the '## Recent Releases' header")
    prefix = readme_text[: header_m.end()]
    suffix = readme_text[full_m.start() :]
    # One blank line after the header, the block, then one blank line before
    # the 'Full release history:' line — matching the existing layout.
    return f"{prefix}\n\n{new_block_body}\n\n{suffix}"


def extract_readme_block_versions(readme_text: str) -> list[str]:
    """Return the versions of the entries currently in the README block."""
    header_m = RECENT_HEADER_RE.search(readme_text)
    if header_m is None:
        return []
    full_m = FULL_HISTORY_RE.search(readme_text, pos=header_m.end())
    end = full_m.start() if full_m else len(readme_text)
    block = readme_text[header_m.end() : end]
    return [m.group("version") for m in README_ENTRY_RE.finditer(block)]


def check_readme_current(readme_text: str, current_version: str) -> tuple[bool, str]:
    """Return (ok, message) for the staleness guard.

    OK iff the README block has EXACTLY ``TOP_N`` entries AND the newest
    (first) entry's version == ``current_version``.
    """
    versions = extract_readme_block_versions(readme_text)
    if len(versions) != TOP_N:
        return False, (
            f"README Recent-Releases block has {len(versions)} entr(ies), expected exactly {TOP_N}: {versions}"
        )
    if versions[0] != current_version:
        return False, (
            f"README newest release entry is v{versions[0]} but current "
            f"project version is {current_version} — regenerate with "
            f"`python scripts/gen_readme_releases.py`"
        )
    return True, (
        f"README Recent-Releases block is current: {TOP_N} entries, newest v{versions[0]} == project {current_version}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help=(
            "Staleness guard: exit 1 unless the README block has exactly "
            f"{TOP_N} entries and the newest == the current project version."
        ),
    )
    mode.add_argument(
        "--print",
        action="store_true",
        help="Print the generated block to stdout (do not write README).",
    )
    args = parser.parse_args(argv)

    try:
        changelog_text = CHANGELOG_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read {CHANGELOG_PATH}: {exc}", file=sys.stderr)
        return 2

    blocks = parse_changelog_blocks(changelog_text)
    if len(blocks) < TOP_N:
        print(
            f"error: CHANGELOG has only {len(blocks)} dated release block(s); need at least {TOP_N}",
            file=sys.stderr,
        )
        return 2

    if args.print:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")  # cp1252-safe on Windows
        print(render_block(blocks))
        return 0

    try:
        readme_text = README_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read {README_PATH}: {exc}", file=sys.stderr)
        return 2

    if args.check:
        try:
            current = detect_current_version()
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        ok, message = check_readme_current(readme_text, current)
        print(("PASS: " if ok else "FAIL: ") + message)
        return 0 if ok else 1

    # Write mode: regenerate the block and splice it in.
    new_body = render_block(blocks)
    try:
        updated = splice_into_readme(readme_text, new_body)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if updated == readme_text:
        print("README Recent-Releases block already up to date; no change.")
        return 0

    README_PATH.write_text(updated, encoding="utf-8")
    print(
        "README Recent-Releases block regenerated "
        f"({TOP_N} entries: {', '.join('v' + b.version for b in blocks[:TOP_N])})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
