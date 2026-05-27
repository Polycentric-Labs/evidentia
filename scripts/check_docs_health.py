#!/usr/bin/env python3
"""Comprehensive doc-health check for Evidentia.

Run BEFORE any version-update push. Invoked by `/pre-release-review`
Step 5.D.3 in --strict mode (blocks tag if FAIL); also runnable in
--advisory mode (default) during development.

8 checks total (5 doc + 3 publicly-facing-surface):

DOC HEALTH (always runs):

1. **parse_validity**       — every tracked .md loads as valid UTF-8.
2. **cross_link_resolve**   — every relative markdown link in every
                              tracked .md resolves to a tracked file
                              (or a real directory, for the wiki's
                              section-index pattern).
3. **readme_size_guard**    — README.md is at or below the
                              ``--readme-max`` byte budget (default
                              10,000; canonical OSS benchmark ~6-8KB).
4. **private_path_leak**    — no tracked public .md file links to a
                              ``private/`` path (the gitignored
                              strategy directory).

PHRASE AUDIT (config-driven; runs only if private config present):

5. **phrase_audit**         — no forbidden phrases (per the project's
                              private phrase config) in tracked public
                              files outside the per-file allowlist.
6. **commit_msg_audit**     — same forbidden-phrase set, applied to
                              commit messages in the range
                              ``cutoff..HEAD`` (cutoff loaded from
                              config; everything before is allowlisted
                              as immutable history).
7. **tag_msg_audit**        — same forbidden-phrase set, applied to
                              annotated tag bodies. Tags listed in the
                              config's tag_allowlist are skipped
                              (immutable; force-update would break
                              cosign signatures bound to those SHAs).
8. **release_body_audit**   — uses ``gh api`` to inspect the latest
                              GitHub Release body. Advisory mode
                              (gracefully WARNs if gh is unauthenticated
                              or returns empty).

Config: ``private/check-docs-health-patterns.yaml`` (gitignored).
If absent, the 4 phrase-related checks emit one WARN and skip; the
4 doc-health checks still run. See ``private/README.md`` for the
config schema + setup.

SPECIAL MODE for the commit-msg git hook:

    python scripts/check_docs_health.py --check-commit-msg <file>

    Reads the message file, applies the loaded forbidden-phrase set,
    exits 2 if any pattern matches. If the phrase config is absent,
    the hook passes silently (no enforcement). The .githooks/commit-msg
    hook invokes this before letting ``git commit`` complete.

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
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

REPO_ROOT = Path.cwd().resolve()
PHRASE_CONFIG_PATH = Path("private/check-docs-health-patterns.yaml")

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


def load_phrase_config() -> tuple[PhraseConfig, str | None]:
    """Load the private phrase-audit config.

    Returns (config, error_message). If config is absent or unparseable,
    the returned config is the empty placeholder and error_message
    describes why phrase checks are disabled.
    """
    config_path = REPO_ROOT / PHRASE_CONFIG_PATH
    if not config_path.exists():
        return PhraseConfig.empty(), (
            f"phrase config not found at {PHRASE_CONFIG_PATH.as_posix()}; "
            f"phrase checks disabled (see private/README.md for setup)"
        )

    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return PhraseConfig.empty(), (
            "PyYAML not available; phrase checks disabled "
            "(install with `uv sync --all-groups`)"
        )

    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as e:
        return PhraseConfig.empty(), (
            f"phrase config at {PHRASE_CONFIG_PATH.as_posix()} unparseable: {e}"
        )

    if not isinstance(data, dict):
        return PhraseConfig.empty(), (
            f"phrase config at {PHRASE_CONFIG_PATH.as_posix()} not a dict"
        )

    raw_patterns = data.get("forbidden_patterns", []) or []
    compiled: list[tuple[str, re.Pattern[str]]] = []
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

    raw_line_allow = data.get("line_allowlist", {}) or {}
    line_allow: dict[str, set[int]] = {}
    if isinstance(raw_line_allow, dict):
        for path_key, lines in raw_line_allow.items():
            if isinstance(lines, list):
                line_allow[str(path_key)] = {int(n) for n in lines if isinstance(n, int)}

    return PhraseConfig(
        forbidden_patterns=compiled,
        file_allowlist_globs=list(data.get("file_allowlist", []) or []),
        line_allowlist=line_allow,
        tag_allowlist=set(data.get("tag_allowlist", []) or []),
        commit_cutoff_sha=str(data.get("commit_cutoff_sha", "")),
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
                # Downgrade to WARN for any broken link under docs/wiki/.
                # The wiki is scaffolded in v0.10.7; per-page files fill
                # in over upcoming cycles. Section indexes legitimately
                # reference future stubs.
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


def run_commit_msg_hook_check(message_file: str) -> int:
    """Hook mode: read a single message file, apply the phrase set.

    Invoked by .githooks/commit-msg as
    ``python scripts/check_docs_health.py --check-commit-msg "$1"``.
    Exits 0 if clean (or if phrase config is absent), 2 if matched.
    """
    config, _err = load_phrase_config()
    if not config.is_loaded:
        # No config = no enforcement. Silent pass (the audit script's
        # full run emits the WARN; hook mode stays quiet to avoid
        # spamming git's commit flow).
        return 0

    try:
        text = Path(message_file).read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as e:
        print(f"check_commit_msg: cannot read {message_file}: {e}", file=sys.stderr)
        return 2

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
        "--readme-max", type=int, default=10_000,
        help="README.md max byte budget (default 10000; canonical OSS ~6-8KB).",
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
