#!/usr/bin/env python3
"""Atomically bump version + inter-package pin ranges across the Evidentia monorepo.

Replaces the deprecated scripts/_bump_version.py (which was hardcoded
0.5 -> 0.6). This one is general: pass --from X.Y.Z --to A.B.C (or just
--to A.B.C and it auto-detects current).

Updates three patterns across tracked .toml + .json files:
  - version = "X.Y.Z"            (pyproject.toml)
  - "version": "X.Y.Z"           (package.json)
  - >=X.Y.Z,<X.(Y+1).0           (inter-package pins; widens to next minor)

Skips lockfiles (uv.lock, package-lock.json) - those are regenerated
by `uv sync --all-packages` after running this script.

Usage:
  ./scripts/bump_version.py --to 0.8.0
  ./scripts/bump_version.py --from 0.7.0 --to 0.7.1
  ./scripts/bump_version.py --to 0.7.1 --dry-run  # show what would change

Per the publishing-authority protocol (~/.claude/CLAUDE.md), this script
NEVER pushes, tags, or publishes. It only edits files. Use git status
afterward + commit explicitly. Tag creation requires explicit user
approval per the global protocol.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Matches X.Y.Z and X.Y.Z.W (hot-fix versions per the v0.7.4 / v0.7.7.1
# precedent: same-day patches that need to ride atop a tagged minor +
# don't earn a fresh patch number).
VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:\.\d+)?")


def tracked_files() -> list[Path]:
    """All git-tracked files (so we never touch generated/ignored content)."""
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout
    return [Path(p) for p in out.splitlines() if p]


def detect_current_version() -> str:
    """Read evidentia-core's pyproject.toml as the source of truth."""
    p = Path("packages/evidentia-core/pyproject.toml")
    if not p.exists():
        sys.exit(
            "Cannot detect current version: "
            "packages/evidentia-core/pyproject.toml missing"
        )
    for line in p.read_text(encoding="utf-8").splitlines():
        m = re.match(r'\s*version\s*=\s*"(\d+\.\d+\.\d+)"', line)
        if m:
            return m.group(1)
    sys.exit("Cannot find version field in evidentia-core/pyproject.toml")


def cur_parts_str(version: str) -> str:
    """Return `major.minor` slice of a version for display purposes."""
    parts = version.split(".")
    return f"{parts[0]}.{parts[1]}"


def bump_pin_range(current: str, target: str) -> tuple[str, str]:
    """Return (current-range-regex, next-range-replacement) for inter-package pin updates.

    Pin convention (v0.7.12+): `>={target},<{M}.{m+1}.0` — tightens
    the LOWER bound to the current release version, not the minor's
    `.0`. This closes the v0.7.11 propagation foot-gun where pip
    could resolve a cached `evidentia-core==0.7.10` against a
    freshly-published `evidentia==0.7.11` because the loose
    `>=0.7.0,<0.8.0` pin permitted ANY patch.

    The regex pattern matches any prior pin in the current
    major.minor range — `>=0.7.\\d+(?:\\.\\d+)?,<0.8.0` — so the
    fix also rewrites legacy `>=0.7.0,<0.8.0` pins on the first
    post-fix bump.

    Hot-fix versions (X.Y.Z.W per the v0.7.4 / v0.7.7.1
    precedent) ride the major.minor of their parent release.
    """
    cur_parts = current.split(".")
    tgt_parts = target.split(".")
    cur_maj, cur_min = cur_parts[0], cur_parts[1]
    tgt_maj, tgt_min = tgt_parts[0], tgt_parts[1]
    # Cross-minor bump: match anything in the OLD minor range. Same-minor
    # bump: also match anything in the current minor (catches both
    # already-tightened pins and legacy loose ones).
    cur_range = (
        rf">={cur_maj}\.{cur_min}\.\d+(?:\.\d+)?,"
        rf"<{cur_maj}\.{int(cur_min)+1}\.0"
    )
    tgt_range = f">={target},<{tgt_maj}.{int(tgt_min)+1}.0"
    return cur_range, tgt_range


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--from",
        dest="frm",
        help="current version (auto-detected from evidentia-core if omitted)",
    )
    ap.add_argument("--to", required=True, help="target version, e.g. 0.7.1")
    ap.add_argument(
        "--dry-run", action="store_true", help="print changes without writing"
    )
    ap.add_argument(
        "--regenerate-requirements",
        action="store_true",
        help=(
            "v0.7.14 P1.5 preview: also regenerate "
            "docker/requirements.txt via pip-compile --generate-hashes "
            "against evidentia[gui]==<--to>. The Dockerfile install "
            "line continues to use exact-version pinning for now; the "
            "switch to pip install --require-hashes -r requirements.txt "
            "lands in v0.8.0 G4 (reproducible-build verification). "
            "Until then, the regenerated file ships as v0.8.0 "
            "foundation + can be inspected by operators planning their "
            "own hash-pinned image builds. Requires pip-tools "
            "installed (pip install pip-tools)."
        ),
    )
    args = ap.parse_args()

    if not VERSION_RE.fullmatch(args.to):
        sys.exit(f"--to must be X.Y.Z, got {args.to!r}")
    current = args.frm or detect_current_version()
    if not VERSION_RE.fullmatch(current):
        sys.exit(f"--from must be X.Y.Z, got {current!r}")
    if current == args.to:
        print(f"Already at {args.to} - nothing to do.")
        return 0

    cur_pin_pattern, tgt_pin = bump_pin_range(current, args.to)
    # Replacements are (regex_pattern, replacement_text). Using regex
    # with negative-lookaheads avoids substring traps like "0.7.7"
    # matching inside "0.7.7.1" when bumping a hot-fix.
    cur_re = re.escape(current)
    nla = r"(?!\.\d)"  # negative-lookahead: not followed by .digit
    replacements: list[tuple[str, str]] = [
        (rf'version = "{cur_re}"{nla}', f'version = "{args.to}"'),
        (rf'"version": "{cur_re}"{nla}', f'"version": "{args.to}"'),
        # v0.7.12 P0.5 closure: tighten inter-package pin lower bound
        # to the current release version (not just the minor's .0).
        # Closes the v0.7.11 PyPI propagation foot-gun where pip
        # could resolve a cached `evidentia-core==<previous-patch>`
        # against a freshly-published `evidentia==<this-patch>`
        # because the loose `>=0.7.0,<0.8.0` pin permitted ANY patch.
        (cur_pin_pattern, tgt_pin),
        # v0.7.7.1 trap: Dockerfile pinned to the current release as a
        # hardcoded literal. Without this replacement, the published
        # ghcr.io image installs the previous version inside even
        # though the image is tagged with the new version. Surfaced
        # by the v0.7.7 pre-release-review Step 7.5 container smoke.
        (rf'evidentia\[gui\]=={cur_re}{nla}', f'evidentia[gui]=={args.to}'),
    ]

    print(f"Bump plan: {current} -> {args.to}")
    print(f"  Inter-package pins: <prior-range-in-{cur_parts_str(current)}> -> {tgt_pin}")
    print()

    files_changed = 0
    total_subs = 0
    # File-type allowlist: text-based config files that may carry
    # version literals or pin ranges. Includes Dockerfile (no
    # extension) per the v0.7.7.1 hot-fix precedent.
    text_suffixes = {".toml", ".json"}
    text_names = {"Dockerfile"}
    for p in tracked_files():
        if not (p.suffix.lower() in text_suffixes or p.name in text_names):
            continue
        if p.name in {"uv.lock", "package-lock.json"}:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except Exception:
            continue
        new_text = text
        file_subs = 0
        for pattern, new in replacements:
            new_text, n = re.subn(pattern, new, new_text)
            file_subs += n
        if file_subs:
            print(f"  {p}: {file_subs} substitution(s)")
            if not args.dry_run:
                p.write_text(new_text, encoding="utf-8")
            files_changed += 1
            total_subs += file_subs

    print()
    suffix = " [DRY RUN]" if args.dry_run else ""
    print(
        f"Summary: {files_changed} file(s), {total_subs} substitution(s){suffix}"
    )

    # v0.7.14 P1.5: optional regeneration of docker/requirements.txt
    # via pip-compile. Runs AFTER the version-bump substitutions so
    # the requirements.in pin is updated to the new version before
    # pip-compile resolves the transitive closure.
    if args.regenerate_requirements:
        print()
        print("Regenerating docker/requirements.txt (P1.5 preview)...")
        if args.dry_run:
            print("  (dry run; would have run pip-compile)")
        else:
            import subprocess
            from pathlib import Path

            repo_root = Path(__file__).resolve().parent.parent
            docker_dir = repo_root / "docker"
            req_in = docker_dir / "requirements.in"
            req_out = docker_dir / "requirements.txt"
            if not req_in.exists():
                docker_dir.mkdir(exist_ok=True)
                req_in.write_text(
                    f"evidentia[gui]=={args.to}\n",
                    encoding="utf-8",
                )
            else:
                # Update the pin in requirements.in to match the
                # new version (single-line file).
                req_in.write_text(
                    f"evidentia[gui]=={args.to}\n",
                    encoding="utf-8",
                )
            try:
                result = subprocess.run(
                    [
                        "pip-compile",
                        "--generate-hashes",
                        "--output-file",
                        str(req_out),
                        str(req_in),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode != 0:
                    print(
                        "  pip-compile FAILED; check output:",
                        result.stderr[-500:],
                    )
                    print(
                        "  (regeneration skipped; install pip-tools "
                        "via `pip install pip-tools` then re-run)"
                    )
                else:
                    pkg_count = sum(
                        1
                        for line in req_out.read_text(
                            encoding="utf-8"
                        ).splitlines()
                        if line and line[0].isalpha()
                    )
                    print(
                        f"  docker/requirements.txt regenerated: "
                        f"{pkg_count} packages with SHA256 hashes"
                    )
            except FileNotFoundError:
                print(
                    "  pip-compile not found; install via "
                    "`pip install pip-tools` (regeneration skipped)"
                )

    if not args.dry_run and files_changed > 0:
        print()
        print("Next steps (per the publishing-authority protocol, do these manually):")
        print(f"  1. uv sync --all-packages   # regenerate uv.lock at {args.to}")
        print("  2. Run pytest + mypy + ruff to confirm nothing broke")
        print(
            f"  3. git add -p && git commit -m 'chore(release): bump to {args.to}'"
        )
        print(f"  4. (When ready, with explicit approval) push to main + tag v{args.to}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
