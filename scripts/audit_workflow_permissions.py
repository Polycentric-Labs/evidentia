#!/usr/bin/env python3
"""Audit .github/workflows/*.yml for missing/loose `permissions:` blocks.

BLOCKING in v0.10.7 when invoked with ``--strict`` (the
``verify-workflow-perms.yml`` CI gate passes ``--strict``). Default
invocation (no flag) stays ADVISORY — prints a report to stdout and
exits 0 — preserving the v0.10.6 behavior for ad-hoc local runs.

A workflow whose top-level ``permissions:`` block grants a ``write``
scope is a FAIL. Some workflows legitimately need a write scope (a bot
that opens an issue, a composite-action smoke test that posts a PR
comment). Such a workflow may carry a ``# JUSTIFIED: <reason>`` comment
on the line IMMEDIATELY ABOVE its top-level ``permissions:`` key, which
downgrades the FAIL to a separately-counted ``JUSTIFIED`` status. Under
``--strict`` a JUSTIFIED workflow does NOT cause a non-zero exit (it is
an accepted, documented exception); only un-justified FAIL / ERROR do.

Association rule (chosen for robustness): the ``# JUSTIFIED:`` comment
MUST appear on the first non-blank line directly preceding the
top-level (column-0) ``permissions:`` key. PyYAML's ``safe_load``
discards all comments, so the annotation is recovered by a separate
raw-text scan rather than from the parsed mapping. The
"line-immediately-above" rule is unambiguous and needs no comment-to-
block line-range tracking (which the "anywhere within the block"
alternative would require).

Closes OSPS-AC-04.01/02 (the audit existence requirement PLUS the
least-privilege enforcement gate via ``--strict``).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

WORKFLOWS_DIR = Path(__file__).parent.parent / ".github" / "workflows"

# Matches a top-level (column-0, unindented) `permissions:` key. Indented
# job-scoped `permissions:` keys are intentionally NOT matched — the
# JUSTIFIED annotation governs the top-level block only.
_TOP_LEVEL_PERMISSIONS_RE = re.compile(r"^permissions\s*:")
# Matches `# JUSTIFIED: <reason>` (any leading whitespace; reason is the
# remainder of the line after the colon).
_JUSTIFIED_RE = re.compile(r"^\s*#\s*JUSTIFIED\s*:\s*(?P<reason>.+?)\s*$")


def find_justification(text: str) -> str | None:
    """Return the JUSTIFIED reason for a workflow, or None.

    The reason is read from a ``# JUSTIFIED: <reason>`` comment on the
    first non-blank line directly above the top-level ``permissions:``
    key. Returns ``None`` when there is no top-level ``permissions:``
    key or no qualifying comment precedes it.
    """
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if not _TOP_LEVEL_PERMISSIONS_RE.match(line):
            continue
        # Walk upward past blank lines to the first non-blank line.
        j = idx - 1
        while j >= 0 and not lines[j].strip():
            j -= 1
        if j >= 0:
            m = _JUSTIFIED_RE.match(lines[j])
            if m:
                return m.group("reason")
        # Only the first top-level permissions key is considered.
        return None
    return None


def audit_workflow(path: Path) -> tuple[str, str]:
    """Return (status, detail) per workflow file.

    Status is one of OK / WARN / FAIL / JUSTIFIED / ERROR. A FAIL is
    downgraded to JUSTIFIED when the file carries a ``# JUSTIFIED:``
    comment per :func:`find_justification`.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return ("ERROR", f"read failed: {exc}")

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return ("ERROR", f"YAML parse: {exc}")

    # yaml.safe_load returns None for empty files / comment-only files,
    # and a non-dict for a top-level list or scalar. A non-mapping
    # top-level would AttributeError on the subsequent .get(); guard
    # explicitly so the audit surfaces a clear error message. This also
    # catches top-level lists/scalars, not just empty files.
    if not isinstance(data, dict):
        return ("ERROR", f"top-level not a YAML mapping (got {type(data).__name__})")

    top_level_perms = data.get("permissions")
    if top_level_perms is None:
        # Check per-job
        jobs = data.get("jobs", {})
        jobs_with_perms = sum(
            1 for j in jobs.values()
            if isinstance(j, dict) and "permissions" in j
        )
        if jobs_with_perms == len(jobs) and jobs_with_perms > 0:
            return ("OK", "all jobs declare explicit permissions")
        return ("WARN", "no top-level permissions and not all jobs declare permissions")

    if top_level_perms == "write-all" or (
        isinstance(top_level_perms, dict)
        and any(v == "write" for v in top_level_perms.values())
    ):
        reason = find_justification(text)
        if reason is not None:
            return (
                "JUSTIFIED",
                f"top-level permissions={top_level_perms} grants write; "
                f"JUSTIFIED: {reason}",
            )
        return (
            "FAIL",
            f"top-level permissions={top_level_perms} grants write — review needed",
        )

    return ("OK", f"top-level permissions={top_level_perms}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--strict",
        action="store_true",
        help=(
            "exit 2 if any un-justified FAIL (or ERROR) remains; exit 0 "
            "when clean. JUSTIFIED workflows are accepted exceptions and "
            "do NOT trigger a non-zero exit. Default (omitted) stays "
            "advisory (exit 0 always) for backward-compatible local runs."
        ),
    )
    ap.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help=(
            "emit machine-readable {workflow: {status, detail}, ...} plus "
            "a summary to stdout for per-run audit-trail integration. "
            "Composes with --strict (json output, strict exit code)."
        ),
    )
    args = ap.parse_args()

    if not WORKFLOWS_DIR.exists():
        print(f"No .github/workflows/ dir found at {WORKFLOWS_DIR}", file=sys.stderr)
        return 1

    workflows = sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(WORKFLOWS_DIR.glob("*.yaml"))

    by_status: dict[str, list[tuple[str, str]]] = {
        "OK": [], "WARN": [], "FAIL": [], "JUSTIFIED": [], "ERROR": [],
    }
    results: dict[str, dict[str, str]] = {}
    for wf in workflows:
        status, detail = audit_workflow(wf)
        by_status[status].append((wf.name, detail))
        results[wf.name] = {"status": status, "detail": detail}

    # Under --strict, only un-justified FAIL and ERROR block the build.
    blocking = len(by_status["FAIL"]) + len(by_status["ERROR"])

    if args.as_json:
        summary = {
            "total": len(workflows),
            "ok": len(by_status["OK"]),
            "warn": len(by_status["WARN"]),
            "fail": len(by_status["FAIL"]),
            "justified": len(by_status["JUSTIFIED"]),
            "error": len(by_status["ERROR"]),
            "strict": args.strict,
            "blocking": blocking,
        }
        print(json.dumps({"workflows": results, "summary": summary}, indent=2))
    else:
        print(f"Auditing {len(workflows)} workflow files in .github/workflows/:\n")
        for status in ("FAIL", "ERROR", "WARN", "JUSTIFIED", "OK"):
            if by_status[status]:
                print(f"\n=== {status} ({len(by_status[status])}) ===")
                for name, detail in by_status[status]:
                    print(f"  {name}: {detail}")
        print(f"\nTotal: {len(workflows)} workflows audited.")
        if args.strict:
            if blocking:
                print(
                    f"STRICT: {blocking} blocking issue(s) "
                    f"({len(by_status['FAIL'])} FAIL, {len(by_status['ERROR'])} ERROR). "
                    f"{len(by_status['JUSTIFIED'])} JUSTIFIED exception(s) accepted."
                )
            else:
                print(
                    "STRICT: PASS — 0 un-justified FAIL/ERROR "
                    f"({len(by_status['JUSTIFIED'])} JUSTIFIED exception(s) accepted)."
                )
        else:
            print("Advisory mode. Pass --strict to make FAIL/ERROR blocking.")

    if args.strict and blocking:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
