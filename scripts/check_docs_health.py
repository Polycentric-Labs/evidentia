#!/usr/bin/env python3
"""Comprehensive doc-health check for Evidentia.

Run BEFORE any version-update push. Invoked by `/pre-release-review`
Step 5.D.3 (doc-health) + 5.D.4 (commit-message audit) in --strict
mode (blocks tag if FAIL); also runnable in --advisory mode (default)
during development.

8 checks total (5 doc + 3 publicly-facing-surface):

DOC HEALTH (--strict gates these on FAIL):

1. **parse_validity**       — every tracked .md loads as valid UTF-8.
2. **cross_link_resolve**   — every relative markdown link in every
                              tracked .md resolves to a tracked file
                              (or a real directory, for the wiki's
                              section-index pattern).
3. **readme_size_guard**    — README.md is at or below the
                              ``--readme-max`` byte budget (default
                              10,000; canonical OSS benchmark ~6-8KB).
4. **tier_vocab_audit**     — no Pro/Enterprise/Federal commercial-tier
                              vocabulary leaks into tracked public files
                              outside the per-line allowlist.
5. **private_path_leak**    — no tracked public .md file links to a
                              ``private/`` path (the gitignored
                              commercial-strategy directory).

PUBLICLY-FACING SURFACES (Allen 2026-05-27 directive):

6. **commit_msg_audit**     — no tier vocabulary in commit messages
                              AFTER the allowlist cutoff SHA (default
                              ``32df7fa``; everything before is
                              accepted as immutable historical).
                              `git log <cutoff>..HEAD` is the scan range.
7. **tag_msg_audit**        — no tier vocabulary in annotated tag
                              messages for tags created AFTER the
                              cutoff. v0.10.5 + earlier tags are
                              allowlisted (immutable; force-update
                              would break cosign signatures).
8. **release_body_audit**   — no tier vocabulary in the latest
                              GitHub Release body (uses ``gh api``;
                              requires gh auth in the env).

SPECIAL MODE for the commit-msg git hook:

    python scripts/check_docs_health.py --check-commit-msg <file>

    Reads the message file, runs ONLY the tier-vocab regex set, exits
    2 if any forbidden phrase matches. The .githooks/commit-msg hook
    invokes this before letting `git commit` complete.

Exit codes:

- 0 = PASS (or PASS-with-warnings; --strict treats WARN as PASS too)
- 2 = FAIL (one or more FAIL findings; --strict blocks here)

Usage:

    uv run python scripts/check_docs_health.py                       # advisory
    uv run python scripts/check_docs_health.py --strict              # blocking
    uv run python scripts/check_docs_health.py --json                # machine-readable
    uv run python scripts/check_docs_health.py --commit-cutoff <sha> # explicit cutoff
    uv run python scripts/check_docs_health.py --check-commit-msg <file>  # hook mode
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

# Default commit-message allowlist cutoff: everything up to + including
# this SHA is treated as immutable history (Allen 2026-05-27 decision).
# Per the historical audit, the leaked-commit-message remediation is
# accept + prevent-future because the cosign chain + PEP 740 attestations
# + the awesome-oscal PR URL are bound to specific commit SHAs.
DEFAULT_COMMIT_CUTOFF = "32df7fa"

# Tag names allowlisted (immutable per convention; force-update would
# break cosign signatures + GitHub Release bindings).
TAG_AUDIT_ALLOWLIST: set[str] = {
    "v0.10.5",  # contains "commercial-tier hiring" reference
    # v0.10.4 + earlier predate the tier-erasure directive
    "v0.10.4", "v0.10.3", "v0.10.2", "v0.10.1", "v0.10.0",
    "v0.9.9", "v0.9.8", "v0.9.7", "v0.9.6", "v0.9.5", "v0.9.4",
    "v0.9.3", "v0.9.2", "v0.9.1", "v0.9.0",
    # Older v0.7.x / v0.8.x tags also predate the directive
}

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


def _scan_text_for_tier_vocab(
    text: str, source: str, line_offset: int = 0
) -> list[Finding]:
    """Apply TIER_VOCAB_FORBIDDEN regex set to a blob of text.

    Returns Finding records with check name prefixed by 'commit_msg_audit',
    'tag_msg_audit', or 'release_body_audit' based on caller.
    """
    findings: list[Finding] = []
    for check_name, pattern in TIER_VOCAB_FORBIDDEN:
        for match in pattern.finditer(text):
            line = text[: match.start()].count("\n") + 1 + line_offset
            findings.append(Finding(
                Severity.FAIL, f"tier_vocab:{check_name}", source, line,
                f"forbidden tier vocabulary: {match.group(0)!r}",
            ))
    return findings


def check_git_commit_message_audit(
    cutoff_sha: str, result: CheckResult
) -> None:
    """Scan commit messages for tier vocab in the range cutoff_sha..HEAD.

    Commits up to + including cutoff_sha are treated as immutable
    historical (Allen 2026-05-27 decision). Commits after the cutoff
    are subject to the tier-vocab regex set.
    """
    # First, confirm the cutoff SHA exists. If not, fail open (skip the
    # check rather than reporting noise).
    rev_parse = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", cutoff_sha],
        capture_output=True, text=True, check=False,
    )
    if rev_parse.returncode != 0:
        result.add(Finding(
            Severity.WARN, "commit_msg_audit", "<git>", None,
            f"cutoff SHA {cutoff_sha!r} not found in repo; check skipped",
        ))
        return

    # Get commits in (cutoff..HEAD] with their full messages.
    log = subprocess.run(
        [
            "git", "log",
            "--format=__COMMIT__%n%H%n%B%n__END__",
            f"{cutoff_sha}..HEAD",
        ],
        capture_output=True, text=True, check=False,
    )
    if log.returncode != 0:
        result.add(Finding(
            Severity.WARN, "commit_msg_audit", "<git>", None,
            f"git log failed: {log.stderr.strip()}",
        ))
        return

    # Parse out (sha, message) per commit.
    blocks = log.stdout.split("__COMMIT__\n")
    for block in blocks:
        if not block.strip():
            continue
        lines = block.split("\n", 1)
        if len(lines) < 2:
            continue
        sha = lines[0].strip()
        body = lines[1].rsplit("__END__", 1)[0]
        findings = _scan_text_for_tier_vocab(body, source=f"commit:{sha[:7]}")
        for f in findings:
            # Re-tag with commit_msg_audit prefix
            f.check = f.check.replace("tier_vocab:", "commit_msg_audit:")
            result.add(f)


def check_git_tag_message_audit(result: CheckResult) -> None:
    """Scan annotated tag messages for tier vocab.

    Tags in TAG_AUDIT_ALLOWLIST are skipped (immutable; force-update
    would break cosign chain + GitHub Release binding).
    """
    tag_list = subprocess.run(
        ["git", "tag", "-l"],
        capture_output=True, text=True, check=False,
    )
    if tag_list.returncode != 0:
        result.add(Finding(
            Severity.WARN, "tag_msg_audit", "<git>", None,
            "git tag -l failed; tag check skipped",
        ))
        return

    tags = [t.strip() for t in tag_list.stdout.splitlines() if t.strip()]
    for tag in tags:
        if tag in TAG_AUDIT_ALLOWLIST:
            continue
        body = subprocess.run(
            ["git", "tag", "-l", "--format=%(contents)", tag],
            capture_output=True, text=True, check=False,
        )
        body_text = (body.stdout or "").strip()
        if body.returncode != 0 or not body_text:
            continue
        findings = _scan_text_for_tier_vocab(body_text, source=f"tag:{tag}")
        for f in findings:
            f.check = f.check.replace("tier_vocab:", "tag_msg_audit:")
            result.add(f)


def check_github_release_body_audit(result: CheckResult) -> None:
    """Scan the latest GitHub Release body for tier vocab.

    Uses `gh api`. If gh is unavailable or unauthenticated, the check
    emits a single WARN finding and moves on (doesn't block --strict).
    """
    # Check gh is on PATH + authenticated
    auth_status = subprocess.run(
        ["gh", "auth", "status"],
        capture_output=True, text=True, check=False,
    )
    if auth_status.returncode != 0:
        result.add(Finding(
            Severity.WARN, "release_body_audit", "<gh>", None,
            "gh CLI not available or unauthenticated; check skipped",
        ))
        return

    # Get the latest release body
    latest = subprocess.run(
        ["gh", "release", "view", "--json", "tagName,body"],
        capture_output=True, text=True, check=False,
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

    findings = _scan_text_for_tier_vocab(body, source=f"release:{tag}")
    for f in findings:
        f.check = f.check.replace("tier_vocab:", "release_body_audit:")
        result.add(f)


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


def run_commit_msg_hook_check(message_file: str) -> int:
    """Hook mode: read a single message file, scan for tier vocab.

    Invoked by .githooks/commit-msg as
    `python scripts/check_docs_health.py --check-commit-msg "$1"`.
    Exits 0 if clean, 2 if forbidden vocab found.
    """
    try:
        text = Path(message_file).read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as e:
        print(f"check_commit_msg: cannot read {message_file}: {e}", file=sys.stderr)
        return 2

    # Strip git's commented lines (lines starting with # are not part of the message)
    text_no_comments = "\n".join(
        line for line in text.splitlines() if not line.startswith("#")
    )

    findings = _scan_text_for_tier_vocab(text_no_comments, source=message_file)
    if not findings:
        return 0

    print(
        "\n*** commit-msg hook BLOCKED: forbidden tier vocabulary in commit message ***\n",
        file=sys.stderr,
    )
    for f in findings:
        print(f"  [{f.check}] line {f.line}: {f.message}", file=sys.stderr)
    print(
        "\nFix: rephrase the commit message obliquely "
        "(e.g., 'removed tier-strategy phrasing' instead of naming specific tiers).\n"
        "Bypass (rare; use sparingly): "
        "EVIDENTIA_ALLOW_TIER_VOCAB_IN_COMMIT=1 git commit ...\n",
        file=sys.stderr,
    )
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Evidentia comprehensive doc-health check.")
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit 2 on any FAIL finding (used by /pre-release-review Step 5.D.3 + 5.D.4 pre-tag).",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit findings as JSON (machine-readable).",
    )
    parser.add_argument(
        "--readme-max", type=int, default=10_000,
        help="README.md max byte budget (default 10000; canonical OSS ~6-8KB).",
    )
    parser.add_argument(
        "--commit-cutoff", default=DEFAULT_COMMIT_CUTOFF,
        help=(
            "Allowlist cutoff SHA for commit_msg_audit. Commits up to + "
            f"including this SHA are treated as immutable historical. "
            f"Default: {DEFAULT_COMMIT_CUTOFF} (Allen 2026-05-27 decision)."
        ),
    )
    parser.add_argument(
        "--check-commit-msg", metavar="FILE",
        help=(
            "Hook mode: scan a single message file for tier vocab. Used by "
            ".githooks/commit-msg before letting git commit complete. "
            "Exits 0 if clean, 2 if forbidden vocab found."
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

    md_paths = sorted(list_tracked_files(suffix=".md"))
    all_tracked = list_tracked_files()
    result = CheckResult(files_checked=len(md_paths))

    check_parse_validity(md_paths, result)
    check_cross_link_resolve(md_paths, all_tracked, result)
    check_readme_size_guard(args.readme_max, result)
    check_tier_vocab_audit(md_paths, result)
    check_private_path_leak(md_paths, result)
    check_git_commit_message_audit(args.commit_cutoff, result)
    check_git_tag_message_audit(result)
    if not args.skip_release_body:
        check_github_release_body_audit(result)

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
