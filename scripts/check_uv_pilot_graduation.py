#!/usr/bin/env python3
"""Pilot-graduation watcher for ``uv audit`` / ``UV_MALWARE_CHECK`` (H5).

Both uv features run in this repo as OBSERVE-FIRST pilots (test.yml
``uv-audit`` + ``uv-malware-check`` jobs, continue-on-error, plus the
advisory pre-commit hook) because Astral ships them as preview
(astral.sh blog, 2026-06-08: "Both of these features are in preview for
now"). The graduation plan is written into the pilots' own comments —
"Graduate to fail-closed ... once the feature is GA + observed stable" —
but nothing WATCHED for GA. A pilot that never graduates is noise; this
sentinel mechanizes the exit condition (same doctrine as
``check_python_ceiling.py``: detect-and-nudge, never a gate).

Two probes, deliberately different mechanisms:

1. FUNCTIONAL (audit): run ``uv audit --locked`` WITHOUT
   ``--preview-features audit``. Today uv emits ``warning: `uv audit` is
   experimental and may change without warning`` (observed on uv 0.11.6).
   When that warning disappears while the command still runs, audit has
   graduated -> nudge.
2. TEXTUAL (malware-check + audit backstop): scan uv's CHANGELOG for
   stabilization language near "audit" / "malware". The malware-check
   path cannot be probed functionally — ``UV_MALWARE_CHECK=1`` without
   its preview flag is silently ignored on a dry-run sync (observed), so
   only Astral's own release notes reliably announce its graduation.

Fail-soft (lesson 2 — a chronically-red sentinel trains people to ignore
it): a network failure, a missing uv binary, or unclassifiable output is
"can't tell yet, don't nudge" on that probe; the script still exits 0.
Exit 1 only on internal errors.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

UV_CHANGELOG_URL = "https://raw.githubusercontent.com/astral-sh/uv/main/CHANGELOG.md"

# Stabilization phrasing near the feature name, on one changelog line
# (either order — lookaheads). Kept deliberately loose: release-notes
# wording is not an API. A false nudge costs one human look; a missed
# nudge costs a stale pilot.
_STABILIZE = (
    r"(?:stabiliz\w*|no longer (?:in )?preview|no longer experimental|"
    r"out of preview|now stable|is stable)"
)
# Feature names matched as substrings (no \b): `UV_MALWARE_CHECK` has no
# word boundary around "malware" (underscores are word chars), and the
# stabilization-phrasing co-occurrence already filters noise.
_GRADUATION_RE = re.compile(rf"(?im)^(?=.*(?:audit|malware))(?=.*{_STABILIZE}).*$")

_PREVIEW_MARKERS = ("experimental", "preview")


def classify_audit_probe(returncode: int, stdout: str, stderr: str) -> str:
    """Classify a no-preview-flag ``uv audit --locked`` run.

    Returns one of:
      - ``"preview"``    — ran, still carries the experimental/preview warning.
      - ``"graduated"``  — ran (audit output present), no preview warning.
      - ``"indeterminate"`` — could not tell (didn't run / unrecognized shape).

    ``uv audit`` exits non-zero when advisories exist, so the exit code is
    NOT the ran/didn't-run signal — the output shape is.
    """
    combined = f"{stdout}\n{stderr}".lower()
    ran = "resolved" in combined or "known vulnerabilit" in combined
    if not ran:
        return "indeterminate"
    if any(marker in combined for marker in _PREVIEW_MARKERS):
        return "preview"
    return "graduated"


def run_audit_probe() -> str:
    """Execute the functional audit probe. Fail-soft to ``indeterminate``."""
    if shutil.which("uv") is None:
        print("WARN: uv not on PATH — audit probe skipped", file=sys.stderr)
        return "indeterminate"
    try:
        proc = subprocess.run(
            ["uv", "audit", "--locked"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"WARN: audit probe failed to run: {exc}", file=sys.stderr)
        return "indeterminate"
    return classify_audit_probe(proc.returncode, proc.stdout or "", proc.stderr or "")


def changelog_graduation_hits(text: str) -> list[str]:
    """Changelog lines that read like an audit/malware stabilization note."""
    hits: list[str] = []
    for match in _GRADUATION_RE.finditer(text):
        line = match.group(0).strip()
        if line and line not in hits:
            hits.append(line)
    return hits


def fetch_changelog(
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> str | None:
    """GET uv's CHANGELOG.md. FAIL-SOFT: any error returns None."""
    req = urllib.request.Request(UV_CHANGELOG_URL, headers={"Accept": "text/plain"})
    try:
        # Fixed https host (raw.githubusercontent.com); 30s covers connect,
        # read-phase stalls raise bare TimeoutError — caught as OSError.
        with opener(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (OSError, ValueError) as exc:
        print(f"WARN: uv changelog fetch failed: {exc}", file=sys.stderr)
        return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", required=True, help="nudge markdown path")
    ap.add_argument(
        "--skip-probe",
        action="store_true",
        help="skip the functional uv-audit probe (tests/offline use)",
    )
    ap.add_argument(
        "--skip-fetch",
        action="store_true",
        help="skip the changelog fetch (tests/offline use)",
    )
    args = ap.parse_args(argv)

    findings: list[str] = []

    if not args.skip_probe:
        status = run_audit_probe()
        print(f"functional audit probe: {status}")
        if status == "graduated":
            findings.append(
                "- **`uv audit` ran clean WITHOUT `--preview-features audit`** "
                "(the experimental warning is gone) — the audit pilot can "
                "graduate: drop the preview flag in test.yml's `uv-audit` job "
                "and .pre-commit-config.yaml, and decide whether the job "
                "leaves continue-on-error."
            )

    if not args.skip_fetch:
        changelog = fetch_changelog()
        if changelog is not None:
            hits = changelog_graduation_hits(changelog)
            for hit in hits[:5]:
                findings.append(
                    f"- **uv CHANGELOG stabilization note**: `{hit}` — check "
                    "whether `uv audit` / `UV_MALWARE_CHECK` graduated; if so, "
                    "promote the test.yml pilots (drop preview flags; decide "
                    "fail-closed malware-check on the required sync steps)."
                )
            if not hits:
                print("changelog probe: no stabilization language found")

    Path(args.output).write_text("\n".join(findings) + ("\n" if findings else ""), encoding="utf-8")
    for line in findings:
        print(line)
    print(f"check_uv_pilot_graduation: {len(findings)} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
