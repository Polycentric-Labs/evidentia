#!/usr/bin/env python3
"""Advisory diff: commit subjects since the last tag vs the CHANGELOG block (#18).

The changelog-presence gate (verify-changelog.yml / release.yml) proves a
``## [X.Y.Z]`` block EXISTS and is non-trivial; nothing checks it is
COMPLETE. This advisory closes that narrow gap at release-prep time: when
the workspace version X.Y.Z is bumped but not yet tagged, it lists every
commit landed since the previous release tag whose PR number (the
``(#NNN)`` suffix every merge-queue squash subject carries) is not
mentioned anywhere in the ``[X.Y.Z]`` CHANGELOG block — the shape of a
shipped-but-undocumented change.

PURELY ADVISORY (elite-practice scan #18): always exits 0 on findings —
a hand-curated CHANGELOG legitimately folds several PRs into one bullet
or omits mechanical ones (Dependabot bumps), so a hard gate here would
either lie or nag. The value is the visible checklist in the release-prep
PR's CI log. Deliberately NOT a Conventional-Commits/git-cliff adoption:
release orchestration stays with the atomic tag-driven design.

Fail-soft (lesson 2): no tags visible (shallow clone), no git, an
already-tagged version (nothing being prepped), or a missing block (the
presence gate's job) all mean "nothing to compare" — exit 0 with a note.
Exit 1 only on internal errors.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - py<3.11 unsupported anyway
    sys.exit("python >= 3.11 required (tomllib)")

REPO_ROOT = Path(__file__).resolve().parents[1]

_PR_REF_RE = re.compile(r"\(#(\d+)\)")
_BLOCK_HEADING_RE = "## ["


def workspace_version(pyproject_path: Path) -> str | None:
    """The root [project] version — what the next tag will publish."""
    try:
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        version = data["project"]["version"]
    except (OSError, tomllib.TOMLDecodeError, KeyError):
        return None
    return version if isinstance(version, str) else None


def changelog_block(changelog_text: str, version: str) -> str | None:
    """The ``## [version]`` block's text (to the next ``## [`` heading)."""
    heading = f"## [{version}]"
    start = changelog_text.find(heading)
    if start == -1:
        return None
    end = changelog_text.find(_BLOCK_HEADING_RE, start + len(heading))
    return changelog_text[start : end if end != -1 else len(changelog_text)]


def pr_number(subject: str) -> str | None:
    """The trailing ``(#NNN)`` PR ref of a squash-merge subject, if any."""
    matches = _PR_REF_RE.findall(subject)
    return matches[-1] if matches else None


def compare(subjects: list[str], block: str) -> tuple[list[str], list[str]]:
    """Return (subjects whose PR ref is absent from the block,
    subjects carrying no PR ref at all)."""
    missing: list[str] = []
    unreferenced: list[str] = []
    for subject in subjects:
        pr = pr_number(subject)
        if pr is None:
            unreferenced.append(subject)
        elif f"#{pr}" not in block:
            missing.append(subject)
    return missing, unreferenced


def _git(*args: str) -> str | None:
    """Run git in the repo root; None on any failure (fail-soft)."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args(argv)

    version = workspace_version(REPO_ROOT / "pyproject.toml")
    if version is None:
        print("WARN: could not read the workspace version — skipping", file=sys.stderr)
        return 0

    if (_git("tag", "-l", f"v{version}") or "").strip():
        print(
            f"check_changelog_vs_commits: v{version} is already tagged — "
            "no release being prepped, nothing to compare."
        )
        return 0

    base = (_git("describe", "--tags", "--abbrev=0", "HEAD") or "").strip()
    if not base:
        print(
            "WARN: no reachable release tag (shallow clone or no tags) — "
            "skipping the advisory diff",
            file=sys.stderr,
        )
        return 0

    log = _git("log", "--format=%s", f"{base}..HEAD")
    if log is None:
        print(f"WARN: git log {base}..HEAD failed — skipping", file=sys.stderr)
        return 0
    subjects = [s for s in log.splitlines() if s.strip()]

    try:
        changelog_text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    except OSError as exc:
        print(f"WARN: cannot read CHANGELOG.md ({exc}) — skipping", file=sys.stderr)
        return 0
    block = changelog_block(changelog_text, version)
    if block is None:
        print(
            f"check_changelog_vs_commits: no [{version}] block yet — the "
            "changelog-presence gate owns that failure; nothing to compare."
        )
        return 0

    missing, unreferenced = compare(subjects, block)
    print(
        f"check_changelog_vs_commits: {len(subjects)} commit(s) in "
        f"{base}..HEAD vs the [{version}] block:"
    )
    for subject in missing:
        print(f"  ADVISORY: PR not mentioned in [{version}]: {subject}")
    for subject in unreferenced:
        print(f"  note (no PR ref, direct commit?): {subject}")
    if not missing and not unreferenced:
        print("  every commit's PR ref appears in the block.")
    else:
        print(
            f"  {len(missing)} PR(s) unmentioned, {len(unreferenced)} "
            "subject(s) without a PR ref. ADVISORY ONLY — a curated block "
            "may fold or omit deliberately; review, don't chase zero."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
