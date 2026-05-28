#!/usr/bin/env python3
"""Pre-push gate L2 check: third-party pin drift alongside a workspace bump.

Guards against the v0.10.0 ``F-V100-M1`` failure mode: a workspace-package
version bump (e.g. ``bump_version.py --to 0.10.7``) must NOT drag any
THIRD-PARTY (non-workspace) package's pinned version in ``uv.lock``. The
v0.10.0 incident was a buggy bump tool over-bumping ``py-ocsf-models``'s
pin; this check is the structural backstop.

Trigger condition (all must hold, else SKIP):

  1. ``uv.lock`` changed in the push range, AND
  2. at least one of the 8 workspace packages' versions moved between the
     base and tip ``uv.lock``.

When triggered, the check diffs the THIRD-PARTY package versions (those
whose ``uv.lock`` ``source`` is a registry, i.e. NOT ``editable`` /
``virtual``, and whose name is not one of the workspace members) between
base and tip. Any third-party version that moved BLOCKS the push.

Range selection (positional args, supplied by the orchestrator):

    check_uv_lock_pin_drift.py <range_base_sha> <range_tip_sha>

Fallbacks: when the base is empty / all-zeros / unresolvable, the
working-tree ``uv.lock`` is compared against ``git show origin/main:uv.lock``.

Exit codes:
    0 — PASS / SKIP (no workspace bump, or no third-party drift)
    1 — BLOCK (third-party pin moved alongside a workspace bump)
    2 — usage / IO error
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ZERO_SHA = "0" * 40

# The 8 workspace packages (per the v0.10.7 plan + pyproject [tool.uv.sources]).
# evidentia-workspace (the virtual root) is intentionally included so a root
# meta-package bump also counts as a workspace bump.
WORKSPACE_PACKAGES: frozenset[str] = frozenset(
    {
        "evidentia",
        "evidentia-ai",
        "evidentia-api",
        "evidentia-collectors",
        "evidentia-core",
        "evidentia-eval",
        "evidentia-integrations",
        "evidentia-mcp",
        "evidentia-workspace",
    }
)

_NAME_RE = re.compile(r'^name\s*=\s*"([^"]+)"')
_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"')
_SOURCE_RE = re.compile(r"^source\s*=\s*\{\s*(\w+)\s*=")


def parse_lock(text: str) -> dict[str, tuple[str, str]]:
    """Parse a ``uv.lock`` into ``{package_name: (version, source_kind)}``.

    ``source_kind`` is the first key of the ``source = { <kind> = ... }``
    inline table: ``registry`` for PyPI third-party packages, ``editable``
    / ``virtual`` for workspace members, ``git`` / ``directory`` / ``url``
    for other source kinds. A package with no parsed source defaults to
    ``""`` (treated as third-party-unknown for safety only if it is not a
    known workspace member).

    Parsing is line-oriented (not a full TOML parse) so it works on an
    older/partial lock blob from ``git show`` without choking, and is
    resilient to the lock's large size. Each ``[[package]]`` block is a
    name + version + (optional) source on its own lines.
    """
    packages: dict[str, tuple[str, str]] = {}
    cur_name: str | None = None
    cur_version: str | None = None
    cur_source: str = ""
    in_package = False

    def _flush() -> None:
        nonlocal cur_name, cur_version, cur_source
        if cur_name is not None and cur_version is not None:
            packages[cur_name] = (cur_version, cur_source)
        cur_name = None
        cur_version = None
        cur_source = ""

    for line in text.splitlines():
        if line.strip() == "[[package]]":
            _flush()
            in_package = True
            continue
        if not in_package:
            continue
        # A new top-level table other than [[package]] ends the section.
        if line.startswith("[") and line.strip() != "[[package]]":
            _flush()
            in_package = False
            continue

        m = _NAME_RE.match(line)
        if m and cur_name is None:
            cur_name = m.group(1)
            continue
        m = _VERSION_RE.match(line)
        if m and cur_version is None:
            cur_version = m.group(1)
            continue
        m = _SOURCE_RE.match(line)
        if m and not cur_source:
            cur_source = m.group(1)
            continue

    _flush()
    return packages


def workspace_bumped(
    base: dict[str, tuple[str, str]],
    tip: dict[str, tuple[str, str]],
) -> list[tuple[str, str, str]]:
    """Return ``[(name, base_version, tip_version)]`` for bumped workspace pkgs.

    A workspace package is one in :data:`WORKSPACE_PACKAGES` OR whose
    source kind is ``editable`` / ``virtual`` (covers the case where the
    name set drifts but the source still marks it a workspace member).
    """
    bumped: list[tuple[str, str, str]] = []
    names = set(base) | set(tip)
    for name in sorted(names):
        b = base.get(name)
        t = tip.get(name)
        is_ws = name in WORKSPACE_PACKAGES or (
            (b is not None and b[1] in {"editable", "virtual"})
            or (t is not None and t[1] in {"editable", "virtual"})
        )
        if not is_ws:
            continue
        b_ver = b[0] if b else ""
        t_ver = t[0] if t else ""
        if b_ver and t_ver and b_ver != t_ver:
            bumped.append((name, b_ver, t_ver))
    return bumped


def third_party_drift(
    base: dict[str, tuple[str, str]],
    tip: dict[str, tuple[str, str]],
) -> list[tuple[str, str, str]]:
    """Return ``[(name, base_version, tip_version)]`` for moved third-party pins.

    Third-party = present in BOTH base and tip, NOT a workspace member,
    and version changed. Packages added/removed entirely are NOT flagged
    here (a genuine dependency add/remove is a legitimate, separate change;
    this check targets *version movement* of an existing pin, which is the
    F-V100-M1 signature). Source kind ``editable``/``virtual`` is excluded.
    """
    drift: list[tuple[str, str, str]] = []
    for name in sorted(set(base) & set(tip)):
        if name in WORKSPACE_PACKAGES:
            continue
        b_ver, b_src = base[name]
        t_ver, t_src = tip[name]
        if b_src in {"editable", "virtual"} or t_src in {"editable", "virtual"}:
            continue
        if b_ver != t_ver:
            drift.append((name, b_ver, t_ver))
    return drift


def _run_git(args: list[str], repo_root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _lock_changed_in_range(base: str, tip: str, repo_root: Path) -> bool:
    proc = _run_git(["diff", "--name-only", base, tip, "--", "uv.lock"], repo_root)
    return proc.returncode == 0 and bool(proc.stdout.strip())


def _git_show(rev: str, path: str, repo_root: Path) -> str | None:
    proc = _run_git(["show", f"{rev}:{path}"], repo_root)
    if proc.returncode != 0:
        return None
    return proc.stdout


def resolve_base(base_arg: str | None, repo_root: Path) -> str | None:
    """Resolve the base revision to diff uv.lock against (or None to SKIP)."""
    if (
        base_arg
        and base_arg != ZERO_SHA
        and _run_git(["rev-parse", "--verify", "--quiet", f"{base_arg}^{{commit}}"], repo_root).returncode
        == 0
    ):
        return base_arg
    if _run_git(["rev-parse", "--verify", "--quiet", "origin/main^{commit}"], repo_root).returncode == 0:
        return "origin/main"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", nargs="?", default=None, help="range base SHA")
    parser.add_argument("tip", nargs="?", default=None, help="range tip SHA")
    args = parser.parse_args(argv)

    proc = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print("ERROR check_uv_lock_pin_drift: not in a git repo", file=sys.stderr)
        return 2
    repo_root = Path(proc.stdout.strip())

    base = resolve_base(args.base, repo_root)
    if base is None:
        print("SKIP check_uv_lock_pin_drift (no base revision to diff uv.lock against)")
        return 0

    tip = args.tip or "HEAD"

    # When diffing against a real tip commit, gate on the lock actually
    # changing in range. When tip is the working tree (HEAD fallback), the
    # range diff still uses HEAD; the working-tree lock is read below.
    using_worktree = args.tip is None and base == "origin/main"
    if not using_worktree and not _lock_changed_in_range(base, tip, repo_root):
        print("SKIP check_uv_lock_pin_drift (uv.lock unchanged in range)")
        return 0

    base_text = _git_show(base, "uv.lock", repo_root)
    if base_text is None:
        print("SKIP check_uv_lock_pin_drift (no base uv.lock to compare)")
        return 0

    if using_worktree:
        try:
            tip_text: str | None = (repo_root / "uv.lock").read_text(encoding="utf-8")
        except OSError:
            tip_text = None
    else:
        tip_text = _git_show(tip, "uv.lock", repo_root)
    if tip_text is None:
        print("SKIP check_uv_lock_pin_drift (no tip uv.lock to compare)")
        return 0

    base_pkgs = parse_lock(base_text)
    tip_pkgs = parse_lock(tip_text)

    bumped = workspace_bumped(base_pkgs, tip_pkgs)
    if not bumped:
        print("PASS check_uv_lock_pin_drift (no workspace version bump in uv.lock)")
        return 0

    drift = third_party_drift(base_pkgs, tip_pkgs)
    if drift:
        ws_summary = ", ".join(f"{n} {b}->{t}" for n, b, t in bumped)
        print(
            f"BLOCK check_uv_lock_pin_drift: workspace bump ({ws_summary}) "
            f"moved {len(drift)} third-party pin(s):",
            file=sys.stderr,
        )
        for name, b_ver, t_ver in drift:
            print(f"  - {name}: {b_ver} -> {t_ver}", file=sys.stderr)
        print(
            "\nA workspace version bump must not drag third-party pins (the "
            "v0.10.0 F-V100-M1 pattern). If the dependency change is "
            "intentional, commit it separately from the version bump. "
            "See docs/pre-push-gate.md.",
            file=sys.stderr,
        )
        print("BLOCK check_uv_lock_pin_drift")
        return 1

    ws_summary = ", ".join(f"{n} {b}->{t}" for n, b, t in bumped)
    print(f"PASS check_uv_lock_pin_drift (workspace bump {ws_summary}; no third-party drift)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
