#!/usr/bin/env python3
"""Comprehensive doc-health check for Evidentia.

Run BEFORE any version-update push. Invoked by `/pre-release-review`
Step 5.D.3 in --strict mode (blocks tag if FAIL); also runnable in
--advisory mode (default) during development.

10 checks total (7 doc + 3 publicly-facing-surface):

DOC HEALTH (always runs):

1. **parse_validity**       — every tracked .md loads as valid UTF-8.
2. **cross_link_resolve**   — every relative markdown link in every
                              tracked .md resolves to a tracked file
                              (or a real directory, for the wiki's
                              section-index pattern).
3. **readme_size_guard**    — README.md is at or below the
                              ``--readme-max`` byte budget (default
                              11,000; canonical OSS benchmark ~6-8KB).
4. **private_path_leak**    — no tracked public .md file links to a
                              ``private/`` path (the gitignored
                              strategy directory).
5. **readme_header_titlecase** — every README ``##``/``###`` header is
                              Title Case (stop-words lowercase except
                              first; acronyms + "Evidentia" preserved).
                              Added v0.10.7 E5c.
6. **readme_recent_releases_current** — the README "Recent Releases"
                              block has exactly 3 entries and its newest
                              entry's version == the current project
                              version (replicates
                              ``gen_readme_releases.py --check``; can't
                              ship a stale releases list). Added E5c.

PHRASE AUDIT (config-driven; layered base + private overlay):

7. **phrase_audit**         — no forbidden phrases (per the layered phrase
                              config) in tracked public files outside the
                              per-file allowlist. This includes the committed
                              base's reclaimable-vendor-host patterns
                              (*.vercel.app / *.netlify.app / *.pages.dev / …)
                              plus any private-overlay phrases.
8. **commit_msg_audit**     — same forbidden-phrase set, applied to
                              commit messages in the range
                              ``cutoff..HEAD`` (cutoff loaded from
                              config; everything before is allowlisted
                              as immutable history).
9. **tag_msg_audit**        — same forbidden-phrase set, applied to
                              annotated tag bodies. Tags listed in the
                              config's tag_allowlist are skipped
                              (immutable; force-update would break
                              cosign signatures bound to those SHAs).
10. **release_body_audit**  — uses ``gh api`` to inspect the latest
                              GitHub Release body. Advisory mode
                              (gracefully WARNs if gh is unauthenticated
                              or returns empty).

Config (layered, docs-airtightness A1.5):
  * ``check-docs-health-patterns.yaml`` (repo root) — the committed, PUBLIC
    base. Ships the reclaimable-vendor-host patterns so that grep runs in
    EVERY environment (CI, fresh clones).
  * ``private/check-docs-health-patterns.yaml`` (gitignored) — the PRIVATE
    overlay: the sensitive phrase set + audit-scoping keys
    (``commit_cutoff_sha``, ``tag_allowlist``, …). Merged on top of the base;
    it WINS / EXTENDS.
If the private overlay is absent, the commit/tag/release-body audits emit an
advisory WARN and skip (no ``commit_cutoff_sha``), but the base vendor-host
grep + the 6 always-on doc-health checks still run. If NEITHER layer is
present, all phrase checks skip with one WARN. See ``private/README.md`` for
the private-overlay schema + setup.

SPECIAL MODE for the commit-msg git hook:

    python scripts/check_docs_health.py --check-commit-msg <file>

    Reads the message file and runs TWO checks before letting
    ``git commit`` complete:

    1. **capitalized-subject** — the commit subject (first non-blank,
       non-``#`` line) must be capitalized: for a conventional-commit
       subject (``type(scope)!: description``) the DESCRIPTION must start
       uppercase; for a non-conventional subject the FIRST WORD must.
       git-generated subjects (``Merge``/``Revert``/``fixup!``/...) and
       code-identifier-leading descriptions (containing ``_``/``.`` or
       backtick-wrapped, e.g. ``check_secrets``) are exempt. This check
       ALWAYS runs — it does NOT depend on the phrase config.

    2. **forbidden-phrase** — applies the loaded forbidden-phrase set;
       exits 2 if any pattern matches. If the phrase config is absent,
       THIS check passes silently (no enforcement) but the cap-check in
       (1) still runs.

    Exits 2 if either check fails. The .githooks/commit-msg hook invokes
    this before letting ``git commit`` complete; its env-var bypass
    short-circuits the whole hook (covering both checks).

Exit codes:

- 0 = PASS (or PASS-with-warnings; --strict treats WARN as PASS too)
- 2 = FAIL (one or more FAIL findings; --strict blocks here)

Usage:

    uv run python scripts/check_docs_health.py                  # advisory
    uv run python scripts/check_docs_health.py --strict         # blocking
    uv run python scripts/check_docs_health.py --json           # machine-readable
    uv run python scripts/check_docs_health.py --check-commit-msg <file>
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

REPO_ROOT = Path.cwd().resolve()
# Layered phrase config (docs-airtightness A1.5):
#   * BASE_CONFIG_PATH — committed, PUBLIC, non-sensitive layer. Ships in the
#     repo so the reclaimable-vendor-host grep runs in EVERY environment (CI,
#     fresh clones), never only where the private overlay happens to exist.
#   * PHRASE_CONFIG_PATH — the gitignored PRIVATE overlay. Merged on top of the
#     base when present; it WINS/EXTENDS (its patterns append, its scalar/list
#     keys override the base's). Absent for fresh clones / collaborators.
BASE_CONFIG_PATH = Path("check-docs-health-patterns.yaml")
PHRASE_CONFIG_PATH = Path("private/check-docs-health-patterns.yaml")

# ── README header Title-Case invariant (v0.10.7 E5c) ───────────────────────
# Stop-words kept lowercase UNLESS they are the first word of the header.
# Mirrors the one-time Title-Casing applied in E5b. Conservative on purpose:
# a tight stop-word set + an acronym/proper-noun allowlist avoid mangling
# "What is Evidentia?" or acronym-bearing headers.
#
# The core set is the E5b-named articles/conjunctions/short-prepositions
# (a/an/the/of/in/on/for/and/to/vs). It is widened with the standard short
# function words English title-case also keeps lowercase — notably the
# copula "is" (so the canonical "What is Evidentia?" header is NOT flagged),
# plus common short prepositions/conjunctions. Kept deliberately small so an
# obviously-lowercase PRINCIPAL word (e.g. "new" in "## new thing") still
# FAILS.
TITLECASE_STOPWORDS: frozenset[str] = frozenset(
    {
        # E5b-named:
        "a", "an", "the", "of", "in", "on", "for", "and", "to", "vs",
        # standard title-case lowercase function words:
        "is", "as", "at", "by", "or", "nor", "but", "via", "with", "from",
    }
)
# Tokens whose exact casing is preserved (acronyms + the project proper noun).
# Compared case-INSENSITIVELY; the value is the canonical casing to expect.
TITLECASE_PRESERVE: dict[str, str] = {
    "ai": "AI",
    "oscal": "OSCAL",
    "osps": "OSPS",
    "cli": "CLI",
    "mcp": "MCP",
    "api": "API",
    "sbom": "SBOM",
    "grc": "GRC",
    "oidc": "OIDC",
    "evidentia": "Evidentia",
}

# Per-line cross-link allowlist. False-positives that aren't worth the
# complexity of inline-code-aware regex skipping (the fenced-code-aware
# skip in find_code_block_ranges handles ``` blocks; this catches inline
# `code` cases on a per-line basis).
CROSS_LINK_LINE_ALLOWLIST: dict[str, set[int]] = {
    # release-checklist line 284 illustrates the link syntax to check
    # for: "every `[link](other.md)` points at an existing file". (Line
    # shifted from 271 -> 284 in v0.10.7 D4.4 when the Step 5 test-gate
    # block gained the audit_workflow_permissions.py --strict check.)
    "docs/release-checklist.md": {284},
}

# Files exempt from cross-link broken-target FAILs:
# - CHANGELOG.md has known link-rot from the prior file-relocation
#   cleanup; historical entries are not edited per append-only convention.
# - security-review-v*.md docs use a `file.py:42`-style annotation that
#   looks like a broken markdown link to the resolver but is in fact a
#   security review's evidence pointer (audit-trail; not actionable).
CROSS_LINK_FILE_ALLOWLIST_GLOBS: list[str] = [
    "CHANGELOG.md",
    "docs/security-review-v[0-9]*.md",
]


@dataclass
class PhraseConfig:
    """Loaded forbidden-phrase config (or empty placeholder if absent)."""

    forbidden_patterns: list[tuple[str, re.Pattern[str]]]
    file_allowlist_globs: list[str]
    line_allowlist: dict[str, set[int]]
    tag_allowlist: set[str]
    commit_cutoff_sha: str
    is_loaded: bool  # False if config file absent / unreadable

    @classmethod
    def empty(cls) -> PhraseConfig:
        return cls(
            forbidden_patterns=[],
            file_allowlist_globs=[],
            line_allowlist={},
            tag_allowlist=set(),
            commit_cutoff_sha="",
            is_loaded=False,
        )


def _parse_config_file(config_path: Path) -> tuple[dict | None, str | None]:
    """Parse one YAML config file into a raw dict.

    Returns ``(data, error)``. ``data`` is ``None`` (with a populated
    ``error``) when the file is absent, PyYAML is unavailable, the file is
    unparseable, or its top level is not a mapping. Pure — no compilation or
    merging happens here (that is :func:`load_phrase_config`'s job).
    """
    if not config_path.exists():
        return None, f"config not found at {config_path.as_posix()}"

    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return None, (
            "PyYAML not available; phrase checks disabled "
            "(install with `uv sync --all-groups`)"
        )

    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as e:
        return None, f"config at {config_path.as_posix()} unparseable: {e}"

    if not isinstance(data, dict):
        return None, f"config at {config_path.as_posix()} not a dict"

    return data, None


def _compile_patterns(raw_patterns: object) -> list[tuple[str, re.Pattern[str]]]:
    """Compile a raw ``forbidden_patterns`` list into ``(name, pattern)`` pairs.

    Each entry is a mapping with ``name`` + ``regex`` (and optional ``flags`` /
    ``reason``; ``reason`` is documentation-only and ignored here). Malformed
    entries and uncompilable regexes are skipped, matching the prior behavior.
    """
    compiled: list[tuple[str, re.Pattern[str]]] = []
    if not isinstance(raw_patterns, list):
        return compiled
    for entry in raw_patterns:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        regex = entry.get("regex")
        if not name or not regex:
            continue
        flags = 0
        for flag_name in entry.get("flags", []) or []:
            flags |= getattr(re, flag_name, 0)
        try:
            compiled.append((name, re.compile(regex, flags)))
        except re.error:
            continue
    return compiled


def _parse_line_allowlist(raw_line_allow: object) -> dict[str, set[int]]:
    """Parse a raw ``line_allowlist`` mapping into ``{path: {line, ...}}``."""
    line_allow: dict[str, set[int]] = {}
    if isinstance(raw_line_allow, dict):
        for path_key, lines in raw_line_allow.items():
            if isinstance(lines, list):
                line_allow[str(path_key)] = {int(n) for n in lines if isinstance(n, int)}
    return line_allow


def load_phrase_config() -> tuple[PhraseConfig, str | None]:
    """Load the layered doc-health phrase config (base + private overlay).

    Two layers (docs-airtightness A1.5):

      * The committed, public BASE at :data:`BASE_CONFIG_PATH` — ships the
        reclaimable-vendor-host patterns so that check runs in every
        environment.
      * The gitignored PRIVATE overlay at :data:`PHRASE_CONFIG_PATH` — the
        sensitive phrase set + audit-scoping keys.

    The private overlay WINS / EXTENDS: its ``forbidden_patterns`` are appended
    to the base's, and its scalar/list keys (``commit_cutoff_sha``,
    ``tag_allowlist``, ``file_allowlist``, ``line_allowlist``) override or
    extend the base's. ``is_loaded`` is True if EITHER layer parsed, so the
    doc-health run treats the config as present whenever the committed base
    ships (which it always does in-repo).

    Returns ``(config, error_message)``. ``error_message`` is populated only
    when NEITHER layer could be loaded (so phrase checks are fully disabled) —
    it describes why. When the base loads but the private overlay is absent,
    the config is returned with ``error_message=None`` and the commit/tag/
    release-body audits degrade to their own advisory WARNs (missing
    ``commit_cutoff_sha`` etc.), while the base vendor-host grep still runs.
    """
    # The per-file parse errors are intentionally discarded: a missing/
    # unparseable single layer is not itself an error as long as the OTHER
    # layer loaded (handled below); only the both-absent case surfaces a
    # message, and it builds its own.
    base_data, _base_err = _parse_config_file(REPO_ROOT / BASE_CONFIG_PATH)
    priv_data, _priv_err = _parse_config_file(REPO_ROOT / PHRASE_CONFIG_PATH)

    if base_data is None and priv_data is None:
        # Neither layer available: phrase checks fully disabled. Surface the
        # private-overlay reason (the historical message) so setup guidance is
        # unchanged for the common "no config at all" case.
        return PhraseConfig.empty(), (
            f"phrase config not found at {PHRASE_CONFIG_PATH.as_posix()} "
            f"or {BASE_CONFIG_PATH.as_posix()}; phrase checks disabled "
            f"(see private/README.md for setup)"
        )

    base_data = base_data or {}
    priv_data = priv_data or {}

    # forbidden_patterns: base first, then private appended (private extends).
    compiled = _compile_patterns(base_data.get("forbidden_patterns", []) or [])
    compiled += _compile_patterns(priv_data.get("forbidden_patterns", []) or [])

    # file_allowlist: union (either layer may exempt a path).
    file_allow = list(base_data.get("file_allowlist", []) or []) + list(
        priv_data.get("file_allowlist", []) or []
    )

    # line_allowlist: merge; private wins on a path collision.
    line_allow = _parse_line_allowlist(base_data.get("line_allowlist", {}) or {})
    line_allow.update(_parse_line_allowlist(priv_data.get("line_allowlist", {}) or {}))

    # tag_allowlist: union.
    tag_allow = set(base_data.get("tag_allowlist", []) or []) | set(
        priv_data.get("tag_allowlist", []) or []
    )

    # commit_cutoff_sha: private wins (base leaves it empty).
    cutoff = str(
        priv_data.get("commit_cutoff_sha", "")
        or base_data.get("commit_cutoff_sha", "")
    )

    return PhraseConfig(
        forbidden_patterns=compiled,
        file_allowlist_globs=file_allow,
        line_allowlist=line_allow,
        tag_allowlist=tag_allow,
        commit_cutoff_sha=cutoff,
        is_loaded=True,
    ), None


def matches_allowlist(path: Path, globs: list[str]) -> bool:
    """Return True if path matches any glob in the allowlist."""
    posix = path.as_posix()
    return any(Path(posix).match(g) for g in globs)


class Severity(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class Finding:
    severity: Severity
    check: str
    path: str
    line: int | None
    message: str

    def to_dict(self) -> dict[str, str | int | None]:
        return {
            "severity": self.severity.value,
            "check": self.check,
            "path": self.path,
            "line": self.line,
            "message": self.message,
        }


@dataclass
class CheckResult:
    findings: list[Finding] = field(default_factory=list)
    files_checked: int = 0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def fail_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.FAIL)

    @property
    def warn_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARN)


def list_tracked_files(suffix: str | None = None) -> set[Path]:
    """Return all files tracked by git, as Path objects relative to repo root."""
    args = ["git", "ls-files"]
    if suffix is not None:
        args.append(f"*{suffix}")
    result = subprocess.run(args, capture_output=True, text=True, check=True)
    return {Path(p) for p in (result.stdout or "").splitlines() if p}


def check_parse_validity(md_paths: list[Path], result: CheckResult) -> None:
    for path in md_paths:
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError as e:
            result.add(Finding(
                Severity.FAIL, "parse_validity", path.as_posix(), None,
                f"file is not valid UTF-8: {e}",
            ))
        except OSError as e:
            result.add(Finding(
                Severity.FAIL, "parse_validity", path.as_posix(), None,
                f"file unreadable: {e}",
            ))


def find_code_block_ranges(content: str) -> list[tuple[int, int]]:
    """Return (start, end) char ranges of fenced code blocks (```...```).

    Used to skip markdown-link extraction inside code blocks (code
    examples often contain literal `[text](URL)` strings that look like
    broken markdown links to the resolver but are illustrative code).
    """
    ranges: list[tuple[int, int]] = []
    in_block = False
    block_start = 0
    pos = 0
    for line in content.splitlines(keepends=True):
        if line.lstrip().startswith("```"):
            if in_block:
                ranges.append((block_start, pos + len(line)))
                in_block = False
            else:
                block_start = pos
                in_block = True
        pos += len(line)
    if in_block:
        ranges.append((block_start, len(content)))
    return ranges


def is_in_code_block(pos: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= pos < end for start, end in ranges)


def check_cross_link_resolve(
    md_paths: list[Path],
    all_tracked: set[Path],
    result: CheckResult,
) -> None:
    link_re = re.compile(r"(?<!\!)\[([^\]\n]+)\]\(([^)\n]+)\)")
    for path in md_paths:
        if matches_allowlist(path, CROSS_LINK_FILE_ALLOWLIST_GLOBS):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        code_ranges = find_code_block_ranges(content)
        line_allow = CROSS_LINK_LINE_ALLOWLIST.get(path.as_posix(), set())
        for match in link_re.finditer(content):
            if is_in_code_block(match.start(), code_ranges):
                continue
            line = content[:match.start()].count("\n") + 1
            if line in line_allow:
                continue
            target = match.group(2).strip()
            if target.startswith(("http://", "https://", "mailto:", "ftp://", "#")):
                continue
            target = target.split("#", 1)[0].rstrip("/")
            if not target:
                continue
            if target.endswith("/"):
                target = target + "index.md"
            try:
                abs_target = (path.parent / target).resolve()
            except (ValueError, OSError):
                result.add(Finding(
                    Severity.WARN, "cross_link_resolve", path.as_posix(), line,
                    f"link target outside repo or unresolvable: {target}",
                ))
                continue
            if abs_target.is_dir():
                candidate = abs_target / "index.md"
                if candidate.exists():
                    abs_target = candidate
            try:
                rel_to_repo = abs_target.relative_to(REPO_ROOT)
            except ValueError:
                result.add(Finding(
                    Severity.WARN, "cross_link_resolve", path.as_posix(), line,
                    f"link target outside repo or unresolvable: {target}",
                ))
                continue
            if abs_target.is_dir():
                continue
            if rel_to_repo not in all_tracked:
                # A broken relative link always FAILs (docs-airtightness A1.3).
                # Historically broken links under docs/wiki/ were DOWNGRADED to
                # WARN on the rationale that the wiki was "scaffolded" in v0.10.7
                # with per-page stubs filling in over later cycles. The wiki is
                # now content-complete, so that rationale is dead — a broken
                # wiki-internal link is real link-rot and must block --strict in
                # required CI (previously it slipped through to be caught only
                # post-merge by the Pages `mkdocs build --strict`; A1.4 also
                # adds a PR-scoped strict build as a second layer).
                result.add(Finding(
                    Severity.FAIL, "cross_link_resolve", path.as_posix(), line,
                    f"broken link to {rel_to_repo.as_posix()}",
                ))


def check_readme_size_guard(max_bytes: int, result: CheckResult) -> None:
    readme = Path("README.md")
    if not readme.exists():
        result.add(Finding(
            Severity.FAIL, "readme_size_guard", "README.md", None,
            "README.md not found at repo root",
        ))
        return
    size = readme.stat().st_size
    if size > max_bytes:
        result.add(Finding(
            Severity.FAIL, "readme_size_guard", "README.md", None,
            f"README size {size} bytes exceeds budget {max_bytes}",
        ))
    elif size > max_bytes * 0.9:
        result.add(Finding(
            Severity.WARN, "readme_size_guard", "README.md", None,
            f"README size {size} bytes is within 10% of budget {max_bytes}",
        ))


def check_private_path_leak(md_paths: list[Path], result: CheckResult) -> None:
    private_re = re.compile(r"\[([^\]\n]+)\]\(([^)\n]*\bprivate/[^)\n]*)\)")
    for path in md_paths:
        if path.parts[0] == "private":
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for match in private_re.finditer(content):
            target = match.group(2)
            if "/private/" not in target and not target.startswith("private/"):
                continue
            line = content[:match.start()].count("\n") + 1
            result.add(Finding(
                Severity.FAIL, "private_path_leak", path.as_posix(), line,
                f"public file links to private/ path: {target}",
            ))


def _titlecase_violations(header_text: str) -> list[str]:
    """Return the words in a header that violate the Title-Case rule.

    Rules (mirroring E5b):
      * The FIRST word is always capitalized (even a stop-word).
      * Stop-words (TITLECASE_STOPWORDS) after the first word stay lowercase.
      * Acronyms / the "Evidentia" proper noun (TITLECASE_PRESERVE) must use
        their canonical casing.
      * Every other ("principal") word must start with an uppercase letter.

    Conservative to avoid false positives: a token is only flagged when it is
    UNAMBIGUOUSLY wrong. A token is skipped (never flagged) when its leading
    alphabetic run is empty (starts with a digit/symbol, e.g. ``(60``) or
    already contains an uppercase letter somewhere in that run other than the
    expected position (e.g. ``POA&M``, ``OSCAL/OSPS`` compound tokens).
    """
    words = header_text.split()
    violations: list[str] = []
    for idx, raw in enumerate(words):
        # Isolate the leading alphabetic run (handles "Box)", "What's",
        # "(60" -> empty run -> skipped). We judge casing on that run only.
        m = re.match(r"^[^\w]*([A-Za-z]+)", raw)
        if not m:
            continue  # no leading alpha run (pure digits/symbols) — skip
        word_alpha = m.group(1)
        lower = word_alpha.lower()

        # Acronym / proper-noun preservation (case-insensitive key).
        if lower in TITLECASE_PRESERVE:
            expected = TITLECASE_PRESERVE[lower]
            if word_alpha != expected:
                violations.append(f"{raw!r} (expected {expected})")
            continue

        # A token whose alpha run has an interior uppercase letter (e.g.
        # "OSCAL", "VEX", "POA" in "POA&M", a CamelCase compound) is treated
        # as an intentional special token and skipped — Title-Case only
        # governs the first-letter of ordinary words.
        if word_alpha[1:] != word_alpha[1:].lower():
            continue

        is_first = idx == 0
        if not is_first and lower in TITLECASE_STOPWORDS:
            # Stop-word after first position: must be lowercase.
            if word_alpha[0].isupper():
                violations.append(f"{raw!r} (stop-word should be lowercase)")
            continue

        # Principal word (or first word): must start uppercase.
        if not word_alpha[0].isupper():
            violations.append(f"{raw!r} (should be capitalized)")
    return violations


def check_readme_header_titlecase(result: CheckResult) -> None:
    """Every README ``##``/``###`` header must be Title Case (E5c).

    Headers inside fenced code blocks (the quickstart's ``# 1. ...`` bash
    comments) are skipped via the same fenced-code-aware logic the
    cross-link check uses.
    """
    readme = Path("README.md")
    if not readme.exists():
        result.add(Finding(
            Severity.FAIL, "readme_header_titlecase", "README.md", None,
            "README.md not found at repo root",
        ))
        return
    try:
        content = readme.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as e:
        result.add(Finding(
            Severity.FAIL, "readme_header_titlecase", "README.md", None,
            f"README.md unreadable: {e}",
        ))
        return

    code_ranges = find_code_block_ranges(content)
    header_re = re.compile(r"^(#{2,3})\s+(.+?)\s*$", re.MULTILINE)
    for match in header_re.finditer(content):
        if is_in_code_block(match.start(), code_ranges):
            continue
        line = content[: match.start()].count("\n") + 1
        header_text = match.group(2)
        violations = _titlecase_violations(header_text)
        if violations:
            result.add(Finding(
                Severity.FAIL, "readme_header_titlecase", "README.md", line,
                f"header {header_text!r} is not Title Case: "
                f"{'; '.join(violations)}",
            ))


def check_readme_recent_releases_current(result: CheckResult) -> None:
    """README Recent-Releases block must be current (E5c).

    Replicates ``gen_readme_releases.py --check``: the block must have
    exactly 3 entries AND its newest entry's version must equal the current
    project version. Imports the generator module (stdlib-only sibling) so
    the assertion logic lives in exactly one place.
    """
    gen_path = Path(__file__).resolve().parent / "gen_readme_releases.py"
    if not gen_path.exists():
        result.add(Finding(
            Severity.WARN, "readme_recent_releases_current", "<scripts>", None,
            "gen_readme_releases.py not found; check skipped",
        ))
        return
    try:
        mod_name = "gen_readme_releases_for_docs_health"
        spec = importlib.util.spec_from_file_location(mod_name, gen_path)
        if spec is None or spec.loader is None:
            raise ImportError("cannot build import spec")
        gen = importlib.util.module_from_spec(spec)
        # Register BEFORE exec so @dataclass(frozen=True) in the module can
        # resolve its own ``__module__`` via sys.modules (CPython's dataclass
        # machinery looks the module up there; an unregistered module yields
        # None and raises AttributeError during class processing).
        sys.modules[mod_name] = gen
        spec.loader.exec_module(gen)
    except (ImportError, OSError, SyntaxError) as e:
        result.add(Finding(
            Severity.WARN, "readme_recent_releases_current", "<scripts>", None,
            f"could not import gen_readme_releases.py: {e}",
        ))
        return

    readme = Path("README.md")
    if not readme.exists():
        result.add(Finding(
            Severity.FAIL, "readme_recent_releases_current", "README.md", None,
            "README.md not found at repo root",
        ))
        return
    try:
        readme_text = readme.read_text(encoding="utf-8")
        current = gen.detect_current_version()
    except (FileNotFoundError, ValueError, OSError) as e:
        result.add(Finding(
            Severity.WARN, "readme_recent_releases_current", "README.md", None,
            f"could not evaluate current version: {e}",
        ))
        return

    ok, message = gen.check_readme_current(readme_text, current)
    if not ok:
        result.add(Finding(
            Severity.FAIL, "readme_recent_releases_current", "README.md", None,
            message,
        ))


def _scan_text_for_forbidden(
    text: str,
    source: str,
    config: PhraseConfig,
    check_prefix: str = "phrase_audit",
) -> list[Finding]:
    """Apply the loaded forbidden-pattern set to a blob of text."""
    findings: list[Finding] = []
    for pattern_name, pattern in config.forbidden_patterns:
        for match in pattern.finditer(text):
            line = text[: match.start()].count("\n") + 1
            findings.append(Finding(
                Severity.FAIL, f"{check_prefix}:{pattern_name}",
                source, line,
                f"forbidden phrase match (pattern {pattern_name}): "
                f"{match.group(0)!r}",
            ))
    return findings


def check_phrase_audit(
    md_paths: list[Path], config: PhraseConfig, result: CheckResult
) -> None:
    """Scan tracked .md files for forbidden phrases (config-driven)."""
    for path in md_paths:
        if matches_allowlist(path, config.file_allowlist_globs):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        line_allow = config.line_allowlist.get(path.as_posix(), set())
        for pattern_name, pattern in config.forbidden_patterns:
            for match in pattern.finditer(content):
                line = content[:match.start()].count("\n") + 1
                if line in line_allow:
                    continue
                result.add(Finding(
                    Severity.FAIL, f"phrase_audit:{pattern_name}",
                    path.as_posix(), line,
                    f"forbidden phrase match (pattern {pattern_name}): "
                    f"{match.group(0)!r}",
                ))


def check_git_commit_message_audit(
    config: PhraseConfig, result: CheckResult
) -> None:
    """Scan commit messages for forbidden phrases in cutoff..HEAD."""
    cutoff = config.commit_cutoff_sha
    if not cutoff:
        result.add(Finding(
            Severity.WARN, "commit_msg_audit", "<config>", None,
            "no commit_cutoff_sha in phrase config; check skipped",
        ))
        return

    rev_parse = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", cutoff],
        capture_output=True, text=True, check=False,
    )
    if rev_parse.returncode != 0:
        result.add(Finding(
            Severity.WARN, "commit_msg_audit", "<git>", None,
            f"cutoff SHA {cutoff!r} not found in repo; check skipped",
        ))
        return

    log = subprocess.run(
        [
            "git", "log",
            "--format=__COMMIT__%n%H%n%B%n__END__",
            f"{cutoff}..HEAD",
        ],
        capture_output=True, text=True, check=False,
        # SF-8: commit bodies are UTF-8; without an explicit encoding the
        # Windows default (cp1252) raises UnicodeDecodeError on non-Latin-1
        # bytes. errors="replace" keeps the audit running on odd bytes.
        encoding="utf-8", errors="replace",
    )
    if log.returncode != 0:
        result.add(Finding(
            Severity.WARN, "commit_msg_audit", "<git>", None,
            f"git log failed: {(log.stderr or '').strip()}",
        ))
        return

    blocks = (log.stdout or "").split("__COMMIT__\n")
    for block in blocks:
        if not block.strip():
            continue
        lines = block.split("\n", 1)
        if len(lines) < 2:
            continue
        sha = lines[0].strip()
        body = lines[1].rsplit("__END__", 1)[0]
        findings = _scan_text_for_forbidden(
            body, source=f"commit:{sha[:7]}", config=config,
            check_prefix="commit_msg_audit",
        )
        for f in findings:
            result.add(f)


def check_git_tag_message_audit(
    config: PhraseConfig, result: CheckResult
) -> None:
    """Scan annotated tag messages for forbidden phrases."""
    tag_list = subprocess.run(
        ["git", "tag", "-l"],
        capture_output=True, text=True, check=False,
        encoding="utf-8", errors="replace",  # SF-8: cp1252-safe on Windows
    )
    if tag_list.returncode != 0:
        result.add(Finding(
            Severity.WARN, "tag_msg_audit", "<git>", None,
            "git tag -l failed; tag check skipped",
        ))
        return

    tags = [t.strip() for t in (tag_list.stdout or "").splitlines() if t.strip()]
    for tag in tags:
        if tag in config.tag_allowlist:
            continue
        body = subprocess.run(
            ["git", "tag", "-l", "--format=%(contents)", tag],
            capture_output=True, text=True, check=False,
            encoding="utf-8", errors="replace",  # SF-8: cp1252-safe on Windows
        )
        body_text = (body.stdout or "").strip()
        if body.returncode != 0 or not body_text:
            continue
        findings = _scan_text_for_forbidden(
            body_text, source=f"tag:{tag}", config=config,
            check_prefix="tag_msg_audit",
        )
        for f in findings:
            result.add(f)


def check_github_release_body_audit(
    config: PhraseConfig, result: CheckResult
) -> None:
    """Scan the latest GitHub Release body for forbidden phrases.

    Uses ``gh api``. Advisory: WARNs if gh is unavailable/unauthenticated
    or the release body is empty.
    """
    auth_status = subprocess.run(
        ["gh", "auth", "status"],
        capture_output=True, text=True, check=False,
        encoding="utf-8", errors="replace",  # SF-8: cp1252-safe on Windows
    )
    if auth_status.returncode != 0:
        result.add(Finding(
            Severity.WARN, "release_body_audit", "<gh>", None,
            "gh CLI not available or unauthenticated; check skipped",
        ))
        return

    latest = subprocess.run(
        ["gh", "release", "view", "--json", "tagName,body"],
        capture_output=True, text=True, check=False,
        encoding="utf-8", errors="replace",  # SF-8: cp1252-safe on Windows
    )
    if latest.returncode != 0:
        result.add(Finding(
            Severity.WARN, "release_body_audit", "<gh>", None,
            f"gh release view failed: {(latest.stderr or '').strip()[:200]}",
        ))
        return

    stdout_text = latest.stdout or ""
    if not stdout_text.strip():
        result.add(Finding(
            Severity.WARN, "release_body_audit", "<gh>", None,
            "gh release view returned empty output",
        ))
        return

    try:
        data = json.loads(stdout_text)
        tag = data.get("tagName", "<unknown>")
        body = data.get("body", "")
    except json.JSONDecodeError:
        result.add(Finding(
            Severity.WARN, "release_body_audit", "<gh>", None,
            "gh release view returned invalid JSON",
        ))
        return

    findings = _scan_text_for_forbidden(
        body, source=f"release:{tag}", config=config,
        check_prefix="release_body_audit",
    )
    for f in findings:
        result.add(f)


def render_findings_text(result: CheckResult) -> str:
    if not result.findings:
        return "All docs-health checks PASS."
    grouped: dict[Severity, list[Finding]] = {
        Severity.FAIL: [], Severity.WARN: [], Severity.PASS: [],
    }
    for f in result.findings:
        grouped[f.severity].append(f)
    lines = []
    for severity in (Severity.FAIL, Severity.WARN):
        items = grouped[severity]
        if not items:
            continue
        lines.append(f"\n=== {severity.value} ({len(items)}) ===")
        for f in items:
            loc = f"{f.path}:{f.line}" if f.line is not None else f.path
            lines.append(f"  [{f.check}] {loc} — {f.message}")
    lines.append(
        f"\nTotal: {result.fail_count} FAIL, {result.warn_count} WARN; "
        f"{result.files_checked} files checked."
    )
    return "\n".join(lines)


# ── Capitalized-subject convention (commit-msg gate) ──────────────────────
#
# Git-generated / special subjects that carry their own fixed casing and
# must never be re-cased.
_SUBJECT_SPECIAL_PREFIXES = (
    "Merge ",
    "Revert ",
    "fixup! ",
    "squash! ",
    "amend! ",
)

# A conventional-commit subject: `type` or `type(scope)`, optional `!`,
# then `: ` and the description. Type is lowercase letters (per the repo's
# convention); scope is anything but `()`.
_CONVENTIONAL_RE = re.compile(
    r"^(?P<type>[a-z]+)(?P<scope>\([^)]*\))?(?P<bang>!)?: (?P<desc>.*)$"
)

# Characters we skip past at the start of a description before locating the
# first "word": opening backtick / quotes / paren.
_LEADING_SKIP = "`'\"("


def _leading_word_is_code_identifier(text: str) -> bool:
    """True if the first token of ``text`` is a code identifier we must
    NOT force-capitalize (capitalizing a symbol would corrupt it).

    A code identifier here means the leading word is backtick-wrapped, or
    its bare token contains ``_`` or ``.`` (e.g. ``check_secrets``,
    ``bump_version.py``, ``gap_report_to_oscal_poam()``).
    """
    stripped = text.lstrip()
    if stripped.startswith("`"):
        return True
    # The first whitespace-delimited token.
    token = stripped.split(maxsplit=1)[0] if stripped else ""
    return "_" in token or "." in token


def check_subject_capitalized(subject: str) -> str | None:
    """Return an error message if ``subject`` violates the capitalized-
    subject convention, else ``None`` (pass / exempt).

    Rules:

    * git-generated/special subjects (``Merge ``, ``Revert ``, ``fixup! ``,
      ``squash! ``, ``amend! ``) are exempt.
    * conventional-commit subjects (``type(scope)!: description``): the
      DESCRIPTION must start with an uppercase letter.
    * non-conventional subjects: the FIRST WORD must start uppercase.
    * a description/subject whose leading word is a code identifier
      (contains ``_`` or ``.``, or is backtick-wrapped) is exempt —
      capitalizing a symbol would corrupt it.
    * a leading non-alpha token (digit/quote/paren) is not flagged; we
      skip opening ``` ` ``` ``'`` ``"`` ``(`` and only require capitalization
      when the first real word leads with a lowercase letter.
    """
    subject = subject.strip()
    if not subject:
        return None
    if subject.startswith(_SUBJECT_SPECIAL_PREFIXES):
        return None

    m = _CONVENTIONAL_RE.match(subject)
    if m is not None:
        target = m.group("desc")
        label = "conventional-commit description"
    else:
        target = subject
        label = "commit subject"

    if not target.strip():
        return None

    # Code-identifier-leading text is exempt (would corrupt the symbol).
    if _leading_word_is_code_identifier(target):
        return None

    # Skip opening punctuation to find the first real character.
    idx = 0
    while idx < len(target) and target[idx] in _LEADING_SKIP:
        idx += 1
    if idx >= len(target):
        return None
    first = target[idx]

    # Only alphabetic leading chars are subject to the rule; a leading
    # digit / symbol is not flagged.
    if not first.isalpha():
        return None
    if first.isupper():
        return None

    word = target[idx:].split(maxsplit=1)[0]
    return (
        f"{label} must start with a capital letter "
        f"(got {word!r}; capitalize the first word, e.g. {word.capitalize()!r})"
    )


def _subject_from_message(text: str) -> str:
    """The subject = the first non-blank, non-comment (``#``) line."""
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("#"):
            continue
        return line
    return ""


def run_commit_msg_hook_check(message_file: str) -> int:
    """Hook mode: read a single message file, enforce the gate.

    Invoked by .githooks/commit-msg as
    ``python scripts/check_docs_health.py --check-commit-msg "$1"``.

    Runs TWO checks, in order:

    1. **capitalized-subject** — ALWAYS runs (independent of the phrase
       config; the subject convention is public and config-free). Blocks
       (exit 2) on violation.
    2. **forbidden-phrase** — only if the private phrase config is loaded;
       absent config means no phrase enforcement (silent pass for that
       check, matching the audit script's full-run WARN behavior).

    The ``.githooks/commit-msg`` env-var bypass short-circuits the whole
    hook before this function runs, so it covers BOTH checks — no separate
    bypass is needed for the cap-check.

    Exits 0 if clean (or if only the phrase config is absent), 2 if either
    check fails.
    """
    try:
        text = Path(message_file).read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as e:
        print(f"check_commit_msg: cannot read {message_file}: {e}", file=sys.stderr)
        return 2

    # ── Check 1: capitalized subject (always runs) ───────────────────────
    subject = _subject_from_message(text)
    cap_error = check_subject_capitalized(subject)
    if cap_error is not None:
        print(
            "\n*** commit-msg hook BLOCKED: subject not capitalized ***\n",
            file=sys.stderr,
        )
        print(f"  subject: {subject!r}", file=sys.stderr)
        print(f"  {cap_error}", file=sys.stderr)
        print(
            "\nFix: capitalize the description (conventional commits) or the\n"
            "first word (non-conventional). Code identifiers (with _ or .) and\n"
            "git-generated subjects (Merge/Revert/fixup!/...) are exempt.\n"
            "Bypass (rare; use sparingly): "
            "EVIDENTIA_ALLOW_PHRASE_BYPASS=1 git commit ...\n",
            file=sys.stderr,
        )
        return 2

    # ── Check 2: forbidden phrase (config-gated) ─────────────────────────
    config, _err = load_phrase_config()
    if not config.is_loaded:
        # No config = no phrase enforcement. Silent pass (the audit
        # script's full run emits the WARN; hook mode stays quiet to avoid
        # spamming git's commit flow). The cap-check above already ran.
        return 0

    # Strip git's commented lines (lines starting with # are not part of the message)
    text_no_comments = "\n".join(
        line for line in text.splitlines() if not line.startswith("#")
    )

    findings = _scan_text_for_forbidden(
        text_no_comments, source=message_file, config=config,
        check_prefix="commit_msg_hook",
    )
    if not findings:
        return 0

    print(
        "\n*** commit-msg hook BLOCKED: forbidden phrase in commit message ***\n",
        file=sys.stderr,
    )
    for f in findings:
        print(f"  [{f.check}] line {f.line}: {f.message}", file=sys.stderr)
    print(
        "\nFix: rephrase the commit message obliquely. See private/README.md\n"
        "for the standing rule on publicly-facing surfaces.\n"
        "Bypass (rare; use sparingly): "
        "EVIDENTIA_ALLOW_PHRASE_BYPASS=1 git commit ...\n",
        file=sys.stderr,
    )
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evidentia comprehensive doc-health check."
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit 2 on any FAIL (used by /pre-release-review pre-tag).",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit findings as JSON (machine-readable).",
    )
    parser.add_argument(
        "--readme-max", type=int, default=11_000,
        help="README.md max byte budget (default 11000; canonical OSS ~6-8KB).",
    )
    parser.add_argument(
        "--check-commit-msg", metavar="FILE",
        help=(
            "Hook mode: scan a single message file. Used by "
            ".githooks/commit-msg before letting git commit complete. "
            "Exits 0 if clean OR if phrase config is absent, 2 if matched."
        ),
    )
    parser.add_argument(
        "--skip-release-body", action="store_true",
        help="Skip the gh-api release-body check (faster; for local dev).",
    )
    args = parser.parse_args()

    # Hook mode: short-circuit the full check; just scan the one file.
    if args.check_commit_msg:
        return run_commit_msg_hook_check(args.check_commit_msg)

    # Load phrase config (may be absent for fresh clones / collaborators
    # without it; the 4 doc-health checks still run regardless).
    config, config_err = load_phrase_config()

    md_paths = sorted(list_tracked_files(suffix=".md"))
    all_tracked = list_tracked_files()
    result = CheckResult(files_checked=len(md_paths))

    # Doc-health checks (always run)
    check_parse_validity(md_paths, result)
    check_cross_link_resolve(md_paths, all_tracked, result)
    check_readme_size_guard(args.readme_max, result)
    check_private_path_leak(md_paths, result)
    check_readme_header_titlecase(result)
    check_readme_recent_releases_current(result)

    # Phrase-audit checks (config-gated)
    if config.is_loaded:
        check_phrase_audit(md_paths, config, result)
        check_git_commit_message_audit(config, result)
        check_git_tag_message_audit(config, result)
        if not args.skip_release_body:
            check_github_release_body_audit(config, result)
    elif config_err:
        result.add(Finding(
            Severity.WARN, "phrase_config", "<config>", None,
            config_err,
        ))

    if args.json:
        print(json.dumps({
            "files_checked": result.files_checked,
            "fail_count": result.fail_count,
            "warn_count": result.warn_count,
            "phrase_config_loaded": config.is_loaded,
            "findings": [f.to_dict() for f in result.findings],
        }, indent=2))
    else:
        print(render_findings_text(result))

    if args.strict and result.fail_count > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
