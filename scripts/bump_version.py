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
            "v0.7.14 P1.5 (foundation) → v0.8.2 (staged) → v0.8.3 G4 "
            "(activated): regenerate docker/requirements.txt with "
            "SHA256 hashes that match release.yml's reproducible "
            "uv build output. Wraps `uv build --all-packages` (with "
            "SOURCE_DATE_EPOCH from HEAD's commit timestamp) → "
            "pip-compile --find-links=./dist/ against the locally-"
            "built wheels for evidentia[gui]==<--to>. Requires "
            "pip-tools (`pip install pip-tools`) + uv installed. "
            "F-V82-S1 (v0.8.3 LOW): host platform auto-detection "
            "— on non-Linux hosts, pip-compile runs inside the "
            "pinned python:3.14-slim base image so Linux-only "
            "transitives (uvloop) resolve correctly. See "
            "docs/dockerfile-pinning.md for the full regeneration "
            "narrative."
        ),
    )
    args = ap.parse_args()

    if not VERSION_RE.fullmatch(args.to):
        sys.exit(f"--to must be X.Y.Z, got {args.to!r}")
    current = args.frm or detect_current_version()
    if not VERSION_RE.fullmatch(current):
        sys.exit(f"--from must be X.Y.Z, got {current!r}")
    if current == args.to:
        if args.regenerate_requirements:
            # v0.8.3 G4: allow --regenerate-requirements to fire
            # even when the version doesn't change. Operators may
            # want to refresh requirements.txt hashes after a
            # transitive-dep CVE OR to test the regeneration
            # pipeline without bumping. Skip the substitution loop
            # but proceed to the regeneration block below.
            print(
                f"Already at {args.to} — skipping version "
                "substitutions; proceeding with "
                "--regenerate-requirements."
            )
        else:
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

    # v0.7.14 P1.5 (foundation) → v0.8.2 (production-staged) → v0.8.3 G4
    # (production-activated): regenerate docker/requirements.txt with
    # SHA256 hashes that match what release.yml will upload to PyPI.
    #
    # v0.8.3 G4 path — local-wheels via SOURCE_DATE_EPOCH:
    #
    #   1. Build local wheels with SOURCE_DATE_EPOCH derived from the
    #      target version's intended tag commit. Same env var is used
    #      by release.yml when it builds wheels for PyPI publish, so
    #      the wheels are byte-identical → SHA256 hashes match → the
    #      requirements.txt's hashes match what pip downloads from
    #      PyPI at container-build time.
    #   2. Run pip-compile --find-links=./dist/ so the resolver sees
    #      the locally-built wheels for evidentia[gui]==X.Y.Z (which
    #      isn't on PyPI yet because we haven't tagged).
    #   3. The output has hashes for the local wheels; release.yml
    #      will upload those exact bytes to PyPI; pip downloads them
    #      at container-build time + verifies hashes match.
    #
    # F-V82-S1 (v0.8.3 LOW): when host platform != Linux + the user
    # explicitly opts in to --regenerate-requirements, auto-invoke
    # pip-compile inside Docker so Linux-only transitives (uvloop)
    # resolve correctly. Still uses --find-links pointed at the
    # locally-built dist/.
    if args.regenerate_requirements:
        print()
        print("Regenerating docker/requirements.txt (v0.8.3 G4)...")
        if args.dry_run:
            print("  (dry run; would have run uv build + pip-compile)")
        else:
            import os
            import subprocess
            from pathlib import Path

            repo_root = Path(__file__).resolve().parent.parent
            docker_dir = repo_root / "docker"
            dist_dir = repo_root / "dist"
            req_in = docker_dir / "requirements.in"
            req_out = docker_dir / "requirements.txt"

            # Ensure requirements.in pins the new version.
            docker_dir.mkdir(exist_ok=True)
            req_in.write_text(
                f"evidentia[gui]=={args.to}\n",
                encoding="utf-8",
            )

            # Step 1 — build local wheels with SOURCE_DATE_EPOCH
            # derived from HEAD's commit timestamp. Matches the
            # release.yml step in v0.8.3 G4.
            sde_proc = subprocess.run(
                ["git", "log", "-1", "--format=%ct", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            )
            source_date_epoch = sde_proc.stdout.strip()
            print(
                f"  SOURCE_DATE_EPOCH={source_date_epoch} "
                "(from HEAD commit timestamp)"
            )

            # Clean dist/ so we don't pull in stale wheels from a
            # prior bump.
            if dist_dir.exists():
                import shutil

                shutil.rmtree(dist_dir)

            build_env = os.environ.copy()
            build_env["SOURCE_DATE_EPOCH"] = source_date_epoch
            build_proc = subprocess.run(
                ["uv", "build", "--all-packages"],
                capture_output=True,
                text=True,
                env=build_env,
                check=False,
            )
            if build_proc.returncode != 0:
                print(
                    "  uv build FAILED:",
                    build_proc.stderr[-500:],
                )
                print(
                    "  (regeneration skipped; ensure `uv` is "
                    "installed + the workspace builds cleanly)"
                )
                # Continue with version-bump completion; just skip
                # the regeneration. Operator can re-run.
            else:
                wheel_count = len(list(dist_dir.glob("*.whl")))
                print(
                    f"  uv build OK: {wheel_count} wheels in dist/"
                )

                # Step 2 — invoke pip-compile against local wheels
                # via --find-links. Auto-detect host platform: on
                # non-Linux, run inside Docker so Linux-only deps
                # (uvloop) resolve.
                is_linux_host = sys.platform.startswith("linux")
                if is_linux_host:
                    print(
                        "  Host is Linux; running pip-compile "
                        "directly"
                    )
                    # --no-emit-find-links keeps the local-wheels
                    # path out of the generated requirements.txt
                    # so the file is portable to environments
                    # that don't have dist/ available (the
                    # production container, downstream
                    # consumers).
                    compile_cmd = [
                        "pip-compile",
                        "--generate-hashes",
                        f"--find-links={dist_dir}",
                        "--no-emit-find-links",
                        "--output-file",
                        str(req_out),
                        str(req_in),
                    ]
                    compile_proc = subprocess.run(
                        compile_cmd,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                else:
                    # F-V82-S1: invoke pip-compile inside the
                    # pinned Linux base image.
                    print(
                        f"  Host is {sys.platform}; invoking "
                        "pip-compile inside Docker (Linux base)"
                    )
                    base_image = (
                        "python:3.14-slim@sha256:"
                        "5b3879b6f3cb77e712644d50262d05a7c"
                        "146b7312d784a18eff7ff5462e77033"
                    )
                    docker_path = subprocess.run(
                        ["pwd", "-W"],
                        capture_output=True,
                        text=True,
                        check=False,
                    ).stdout.strip() or str(repo_root)
                    compile_cmd = [
                        "docker",
                        "run",
                        "--rm",
                        "-v",
                        f"{docker_path}/docker:/work",
                        "-v",
                        f"{docker_path}/dist:/wheels",
                        "-w",
                        "//work",
                        base_image,
                        "sh",
                        "-c",
                        (
                            "pip install -q pip-tools && "
                            "pip-compile --generate-hashes "
                            "--find-links=/wheels "
                            "--no-emit-find-links "
                            "--output-file=requirements.txt "
                            "requirements.in"
                        ),
                    ]
                    compile_proc = subprocess.run(
                        compile_cmd,
                        capture_output=True,
                        text=True,
                        check=False,
                    )

                if compile_proc.returncode != 0:
                    print(
                        "  pip-compile FAILED:",
                        compile_proc.stderr[-500:],
                    )
                    print(
                        "  (regeneration skipped; verify pip-tools "
                        "+ Docker (if non-Linux host) installed)"
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
