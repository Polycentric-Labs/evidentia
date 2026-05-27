#!/usr/bin/env python3
"""Comprehensive doc-health check for Evidentia.

Run BEFORE any version-update push. Invoked by `/pre-release-review`
Step 5.D.3 in --strict mode (blocks tag if FAIL); also runnable in
--advisory mode (default) during development.

5 core checks (v0.10.7 MVP):

1. **parse_validity**     — every tracked .md loads as valid UTF-8.
2. **cross_link_resolve** — every relative markdown link in every
                            tracked .md resolves to a tracked file
                            (or a real directory, for the wiki's
                            section-index pattern).
3. **readme_size_guard**  — README.md is at or below the
                            ``--readme-max`` byte budget (default
                            10,000; canonical OSS benchmark ~6-8KB).
4. **tier_vocab_audit**   — no Pro/Enterprise/Federal commercial-tier
                            vocabulary leaks into tracked public files
                            outside the per-line allowlist.
5. **private_path_leak**  — no tracked public .md file links to a
                            ``private/`` path (the gitignored
                            commercial-strategy directory).

Exit codes:

- 0 = PASS (or PASS-with-warnings; --strict treats WARN as PASS too)
- 2 = FAIL (one or more FAIL findings; --strict blocks here)

Usage:

    uv run python scripts/check_docs_health.py                # advisory
    uv run python scripts/check_docs_health.py --strict       # blocking
    uv run python scripts/check_docs_health.py --json         # machine-readable
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

REPO_ROOT = Path.cwd().resolve()

# Forbidden tier-vocab regex patterns. Per the v0.10.7 audit, these are
# the specific phrases that leak Evidentia paid-plan specifics into
# public docs. The intentionally narrow set; competitor-pricing
# references in market research are LEGITIMATE and not caught here
# (they're news/comparison content, not Evidentia's own tiers).
TIER_VOCAB_FORBIDDEN: list[tuple[str, re.Pattern[str]]] = [
    ("paid-commercial-tier", re.compile(r"\bpaid\s+(?:commercial|services)\b", re.IGNORECASE)),
    ("commercial-tier-phrase", re.compile(r"\bcommercial[- ]tier(?!s\b)", re.IGNORECASE)),
    ("pro-federal-pair", re.compile(r"\b[Pp]ro\s*/\s*[Ff]ederal\b")),
    ("pro-enterprise-pair", re.compile(r"\b[Pp]ro\s*/\s*[Ee]nterprise\b")),
    ("federal-tier-candidate", re.compile(r"\bfederal[- ]tier\s+candidate\b", re.IGNORECASE)),
    ("enterprise-tier-candidate", re.compile(r"\benterprise[- ]tier\s+candidate\b", re.IGNORECASE)),
]

# Per-line allowlist (file:line). Use sparingly + with inline rationale.
TIER_VOCAB_LINE_ALLOWLIST: dict[str, set[int]] = {
    # No active per-line exceptions; file-glob allowlist below covers
    # legitimate cases.
}

# Per-line cross-link allowlist. False-positives that aren't worth the
# complexity of inline-code-aware regex skipping (the fenced-code-aware
# skip in find_code_block_ranges handles ``` blocks; this catches inline
# `code` cases on a per-line basis).
CROSS_LINK_LINE_ALLOWLIST: dict[str, set[int]] = {
    # release-checklist line 271 illustrates the link syntax to check
    # for: "every `[link](other.md)` points at an existing file".
    "docs/release-checklist.md": {271},
}

# Files exempt from cross-link broken-target FAILs:
# - CHANGELOG.md has known link-rot from the v0.10.6 design-partner-program.md
#   move; historical entries are not edited per append-only convention.
# - security-review-v*.md docs use a `file.py:42`-style annotation that looks
#   like a broken markdown link to the resolver but is in fact a security
#   review's evidence pointer (audit-trail; not actionable).
CROSS_LINK_FILE_ALLOWLIST_GLOBS: list[str] = [
    "CHANGELOG.md",
    "docs/security-review-v[0-9]*.md",
]

# File globs exempt from tier_vocab_audit. These are:
# 1. Research/landscape docs where tier vocabulary refers to market
#    segmentation, NOT Evidentia's paid plans.
# 2. Historical per-cycle records (plan docs, security reviews,
#    marketplace decision-logs) that pre-date the v0.10.6+ tier-
#    erasure directive and remain as factual history.
TIER_VOCAB_FILE_ALLOWLIST_GLOBS: list[str] = [
    "docs/positioning-and-value.md",
    "docs/integration-survey.md",
    "docs/capability-matrix.md",
    "docs/threat-model.md",
    "docs/financial-sector-overlay.md",
    "docs/enterprise-grade.md",
    "docs/enterprise-grade-accepted-findings.md",
    "docs/dfah-faithfulness.md",
    "docs/v1.0-transition.md",
    "docs/hf-eval-suite-scaffolding.md",
    "docs/walkthrough-*.md",
    "docs/governance-metrics.md",      # KRI market-pricing comparison
    "docs/quickstart.md",              # Vanta/Drata cost comparison
    "docs/risk-quantification.md",     # RiskLens/ProcessUnity comparison
    "CHANGELOG.md",
    "docs/v[0-9]*-plan.md",
    "docs/v[0-9]*-implementation-plan.md",
    "docs/v[0-9]*-shipped.md",
    "docs/v[0-9]*-marketplace.md",
    "docs/v[0-9]*.x-retrospective.md",
    "docs/security-review-v[0-9]*.md",
]


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
    return {Path(p) for p in result.stdout.splitlines() if p}


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
            try:
                abs_target = (path.parent / target).resolve()
                rel_to_repo = abs_target.relative_to(REPO_ROOT)
            except (ValueError, OSError):
                line = content[:match.start()].count("\n") + 1
                result.add(Finding(
                    Severity.WARN, "cross_link_resolve", path.as_posix(), line,
                    f"link target outside repo or unresolvable: {target}",
                ))
                continue
            if abs_target.is_dir():
                continue
            if rel_to_repo not in all_tracked:
                line = content[:match.start()].count("\n") + 1
                # Downgrade to WARN for any broken link under docs/wiki/.
                # The wiki is scaffolded in v0.10.7; per-page files fill
                # in over upcoming cycles. Section indexes legitimately
                # reference future stubs (including reference/api/ subdir
                # entries that don't have parent dirs yet).
                under_wiki = rel_to_repo.parts[:2] == ("docs", "wiki")
                severity = Severity.WARN if under_wiki else Severity.FAIL
                result.add(Finding(
                    severity, "cross_link_resolve", path.as_posix(), line,
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


def check_tier_vocab_audit(md_paths: list[Path], result: CheckResult) -> None:
    for path in md_paths:
        posix = path.as_posix()
        if matches_allowlist(path, TIER_VOCAB_FILE_ALLOWLIST_GLOBS):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        line_allow = TIER_VOCAB_LINE_ALLOWLIST.get(posix, set())
        for check_name, pattern in TIER_VOCAB_FORBIDDEN:
            for match in pattern.finditer(content):
                line = content[:match.start()].count("\n") + 1
                if line in line_allow:
                    continue
                result.add(Finding(
                    Severity.FAIL, f"tier_vocab_audit:{check_name}", posix, line,
                    f"forbidden tier vocabulary: {match.group(0)!r}",
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


def render_findings_text(result: CheckResult) -> str:
    if not result.findings:
        return "All docs-health checks PASS."
    grouped: dict[Severity, list[Finding]] = {Severity.FAIL: [], Severity.WARN: [], Severity.PASS: []}
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
    lines.append(f"\nTotal: {result.fail_count} FAIL, {result.warn_count} WARN; {result.files_checked} files checked.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evidentia comprehensive doc-health check.")
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit 2 on any FAIL finding (used by /pre-release-review Step 5.D.3 pre-tag).",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit findings as JSON (machine-readable).",
    )
    parser.add_argument(
        "--readme-max", type=int, default=10_000,
        help="README.md max byte budget (default 10000; canonical OSS ~6-8KB).",
    )
    args = parser.parse_args()

    md_paths = sorted(list_tracked_files(suffix=".md"))
    all_tracked = list_tracked_files()
    result = CheckResult(files_checked=len(md_paths))

    check_parse_validity(md_paths, result)
    check_cross_link_resolve(md_paths, all_tracked, result)
    check_readme_size_guard(args.readme_max, result)
    check_tier_vocab_audit(md_paths, result)
    check_private_path_leak(md_paths, result)

    if args.json:
        print(json.dumps({
            "files_checked": result.files_checked,
            "fail_count": result.fail_count,
            "warn_count": result.warn_count,
            "findings": [f.to_dict() for f in result.findings],
        }, indent=2))
    else:
        print(render_findings_text(result))

    if args.strict and result.fail_count > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
