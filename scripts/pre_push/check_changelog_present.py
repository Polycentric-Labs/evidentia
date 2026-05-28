#!/usr/bin/env python3
"""Pre-push gate L2 check: CHANGELOG-block presence on a version bump.

If any tracked ``pyproject.toml``'s ``version = "X.Y.Z"`` field CHANGED in
the push range, this check verifies that ``CHANGELOG.md`` contains a
``## [X.Y.Z]`` block for the new version. BLOCK (exit 1) if a version was
bumped without a matching CHANGELOG block.

This is the local pre-push twin of ``.github/workflows/verify-changelog.yml``
(the v0.10.4 P5 lesson): the CI gate runs the same logic on push/PR to
``main``, but pre-push catches the omission BEFORE the push so the TAG
push (which fires the irreversible PyPI publish) is never blocked by a
late-discovered missing block.

Range selection (positional args, supplied by the orchestrator):

    check_changelog_present.py <range_base_sha> <range_tip_sha>

When the base is empty / all-zeros (new branch) or the range cannot be
resolved, the check falls back to comparing the working-tree pyproject
versions against ``origin/main`` (or, failing that, SKIPs — there is no
"old" side to diff a bump against).

Exit codes:
    0 — PASS (no version bump in range, or every bumped version has a block)
    1 — BLOCK (a version bumped with no matching ``## [X.Y.Z]`` block)
    2 — usage / IO error
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ZERO_SHA = "0" * 40

# Matches a ``## [X.Y.Z]`` heading (optionally ``## [X.Y.Z] - date`` or a
# link-reference ``## [X.Y.Z](...)``). Anchored to the start of a line.
_VERSION_RE = re.compile(r'^version\s*=\s*["\']([^"\']+)["\']', re.MULTILINE)


def _run_git(args: list[str], repo_root: Path) -> subprocess.CompletedProcess[str]:
    """Run a git command (argument list; no shell) rooted at ``repo_root``."""
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def changelog_has_block(changelog_text: str, version: str) -> bool:
    """True if ``CHANGELOG.md`` text has a ``## [<version>]`` heading.

    Accepts the three shipped forms: ``## [X.Y.Z]``, ``## [X.Y.Z] - date``,
    and ``## [X.Y.Z](link)``. The version string is matched literally
    (escaped) so a ``0.10.7`` version does not spuriously match ``0.10.70``.
    """
    pattern = re.compile(
        r"^##\s*\[" + re.escape(version) + r"\]",
        re.MULTILINE,
    )
    return pattern.search(changelog_text) is not None


def extract_versions(pyproject_text: str) -> list[str]:
    """Return every ``version = "..."`` value in a pyproject.toml blob.

    A pyproject can carry a ``[project] version`` plus (rarely) others;
    the regex collects all top-level-ish ``version =`` assignments. The
    primary signal is the ``[project].version`` parsed via tomllib; the
    regex is the fallback used when diffing a raw git blob where a full
    TOML parse of a partial/older revision could fail.
    """
    return _VERSION_RE.findall(pyproject_text)


def project_version(pyproject_text: str) -> str | None:
    """Return ``[project].version`` via a real TOML parse, or None."""
    try:
        data = tomllib.loads(pyproject_text)
    except tomllib.TOMLDecodeError:
        return None
    project = data.get("project")
    if isinstance(project, dict):
        version = project.get("version")
        if isinstance(version, str):
            return version
    return None


def _changed_pyprojects(
    base: str, tip: str, repo_root: Path
) -> list[str]:
    """Return repo-relative paths of pyproject.toml files changed in range."""
    proc = _run_git(
        ["diff", "--name-only", "--diff-filter=ACMR", base, tip],
        repo_root,
    )
    if proc.returncode != 0:
        return []
    out: list[str] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.endswith("pyproject.toml"):
            out.append(line)
    return out


def _git_show(rev: str, path: str, repo_root: Path) -> str | None:
    """Return the contents of ``path`` at ``rev``, or None if absent."""
    proc = _run_git(["show", f"{rev}:{path}"], repo_root)
    if proc.returncode != 0:
        return None
    return proc.stdout


def bumped_versions(
    base: str, tip: str, repo_root: Path
) -> set[str]:
    """Return the set of NEW versions introduced by a bump in the range.

    For each pyproject.toml changed between ``base`` and ``tip``, compares
    the ``[project].version`` (falling back to any ``version =`` literal)
    at ``tip`` against ``base``. A version that exists at ``tip`` but
    differs from / is absent at ``base`` is a "bump" and must have a
    CHANGELOG block.
    """
    new_versions: set[str] = set()
    for path in _changed_pyprojects(base, tip, repo_root):
        tip_text = _git_show(tip, path, repo_root)
        if tip_text is None:
            continue
        base_text = _git_show(base, path, repo_root)

        tip_versions = set(extract_versions(tip_text))
        base_versions = set(extract_versions(base_text)) if base_text else set()

        # Any version literal present at tip but not at base is newly
        # introduced in this range.
        for v in tip_versions - base_versions:
            new_versions.add(v)
    return new_versions


def resolve_range(
    base_arg: str | None, tip_arg: str | None, repo_root: Path
) -> tuple[str, str] | None:
    """Resolve the (base, tip) commit range to diff for bumps.

    Returns None when there is no usable range (caller should SKIP).
    Falls back to ``origin/main..HEAD`` when the supplied base is empty /
    all-zeros / unresolvable.
    """
    tip = tip_arg or "HEAD"
    if (
        base_arg
        and base_arg != ZERO_SHA
        and _run_git(["rev-parse", "--verify", "--quiet", f"{base_arg}^{{commit}}"], repo_root).returncode
        == 0
    ):
        return (base_arg, tip)

    # Fallback: diff against origin/main if it exists.
    if _run_git(["rev-parse", "--verify", "--quiet", "origin/main^{commit}"], repo_root).returncode == 0:
        return ("origin/main", tip)

    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", nargs="?", default=None, help="range base SHA")
    parser.add_argument("tip", nargs="?", default=None, help="range tip SHA")
    parser.add_argument(
        "--changelog",
        type=Path,
        default=None,
        help="path to CHANGELOG.md (default: <repo-root>/CHANGELOG.md)",
    )
    args = parser.parse_args(argv)

    proc = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print("ERROR check_changelog_present: not in a git repo", file=sys.stderr)
        return 2
    repo_root = Path(proc.stdout.strip())

    rng = resolve_range(args.base, args.tip, repo_root)
    if rng is None:
        print("SKIP check_changelog_present (no range to diff a bump against)")
        return 0

    base, tip = rng
    new_versions = bumped_versions(base, tip, repo_root)
    if not new_versions:
        print("PASS check_changelog_present (no pyproject version bump in range)")
        return 0

    changelog_path = args.changelog or (repo_root / "CHANGELOG.md")
    try:
        changelog_text = changelog_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"ERROR check_changelog_present: cannot read {changelog_path}: {exc}", file=sys.stderr)
        return 2

    missing = sorted(v for v in new_versions if not changelog_has_block(changelog_text, v))
    if missing:
        for v in missing:
            print(
                f"BLOCK check_changelog_present: version bumped to [{v}] "
                f"but no '## [{v}]' block in {changelog_path.name}",
                file=sys.stderr,
            )
        print(
            "\nAdd a '## [X.Y.Z] - YYYY-MM-DD' block to CHANGELOG.md for each "
            "bumped version before pushing. This mirrors verify-changelog.yml; "
            "see docs/pre-push-gate.md and the v0.10.3 ship incident.",
            file=sys.stderr,
        )
        print("BLOCK check_changelog_present")
        return 1

    bumped_list = ", ".join(sorted(new_versions))
    print(f"PASS check_changelog_present (bumped {bumped_list}; CHANGELOG block(s) present)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
