#!/usr/bin/env python3
"""Pre-push check: every commit being pushed must carry a signature.

Evidentia v0.10.7 follow-up (closes F-V107-1). Branch protection on ``main``
requires verified signatures, but ``enforce_admins=False`` (the deliberate
direct-push pattern) lets an admin *bypass* that rule — which is exactly how
three unsigned commits (``eedde81`` / ``5f44982`` / ``458a94c``) reached
``main`` at the v0.10.7 push, only flagged by GitHub *after the fact*. This
local gate catches an unsigned (or bad-signature) commit BEFORE it leaves the
machine, so the admin-bypass path can't silently admit one again.

Decision rule — block on ``git log %G?`` of:
  * ``N`` — no signature at all (the failure mode that slipped through)
  * ``B`` — a bad / forged signature
and PASS:
  * ``G`` — good, verified signature
  * ``U`` — good signature whose signer isn't in the *local* allowed-signers
            file (the commit IS signed; GitHub verifies the registered key)
  * ``E`` — signature unverifiable locally (e.g. no allowed-signers configured)
so a fresh clone without ``gpg.ssh.allowedSignersFile`` set does not spuriously
fail on otherwise-signed commits.

Usage:
    check_commit_signatures.py <base> <tip>

``<base>`` empty  -> fall back to ``origin/main`` if it exists, else check only
the tip commit (a brand-new branch with no shared base).

Exit codes:
    0 — every commit in range is signed (or locally-unverifiable-but-signed).
    1 — one or more commits have no signature / a bad signature (BLOCK).
    2 — git invocation error.
"""

from __future__ import annotations

import subprocess
import sys

# %G? statuses that mean "this commit is not acceptably signed".
BLOCK_STATUSES = {"N", "B"}


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _resolve_range(base: str, tip: str) -> list[str]:
    """Return the ``git log`` revision args for the push range."""
    if base:
        return [f"{base}..{tip}"]
    # No base handed in (new branch / unhelpful stdin): prefer origin/main as
    # the comparison point, else fall back to just the tip commit.
    probe = _git("rev-parse", "--verify", "--quiet", "origin/main^{commit}")
    if probe.returncode == 0:
        return [f"origin/main..{tip}"]
    return ["-1", tip]


def main(argv: list[str]) -> int:
    base = argv[1].strip() if len(argv) > 1 else ""
    tip = (argv[2].strip() if len(argv) > 2 else "") or "HEAD"

    rev_args = _resolve_range(base, tip)
    result = _git("log", "--no-color", "--format=%H %G? %s", *rev_args)
    if result.returncode != 0:
        print(
            f"check_commit_signatures: git log failed: {result.stderr.strip()}",
            file=sys.stderr,
        )
        return 2

    lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
    bad: list[tuple[str, str, str]] = []
    for line in lines:
        parts = line.split(" ", 2)
        sha = parts[0]
        status = parts[1] if len(parts) > 1 else "?"
        subject = parts[2] if len(parts) > 2 else ""
        if status in BLOCK_STATUSES:
            bad.append((sha[:9], status, subject))

    print(f"check_commit_signatures: {len(lines)} commit(s) in range; {len(bad)} unsigned/bad.")
    if bad:
        print("  Commits with no valid signature (N = none, B = bad):")
        for sha, status, subject in bad:
            print(f"    {sha} [{status}] {subject}")
        print("  These are UNPUSHED — sign them before pushing. With commit.gpgsign=true + a registered key:")
        print(f"    git rebase --exec 'git commit --amend --no-edit -S' {base or 'origin/main'}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
