#!/usr/bin/env python3
"""Audit .github/workflows/*.yml for missing/loose `permissions:` blocks.

ADVISORY ONLY in v0.10.6 — prints a report to stdout without failing
the build. The v0.10.7 CI gate will promote this to a blocking check
once all existing workflows pass.

Closes OSPS-AC-04.01/02 partial (the audit existence requirement;
full closure needs the least-privilege enforcement, deferred to v0.10.7).
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

WORKFLOWS_DIR = Path(__file__).parent.parent / ".github" / "workflows"


def audit_workflow(path: Path) -> tuple[str, str]:
    """Return (status, detail) per workflow file."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return ("ERROR", f"YAML parse: {exc}")

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
        return (
            "FAIL",
            f"top-level permissions={top_level_perms} grants write — review needed",
        )

    return ("OK", f"top-level permissions={top_level_perms}")


def main() -> int:
    if not WORKFLOWS_DIR.exists():
        print(f"No .github/workflows/ dir found at {WORKFLOWS_DIR}", file=sys.stderr)
        return 1

    workflows = sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(WORKFLOWS_DIR.glob("*.yaml"))
    print(f"Auditing {len(workflows)} workflow files in .github/workflows/:\n")

    by_status: dict[str, list[tuple[str, str]]] = {
        "OK": [], "WARN": [], "FAIL": [], "ERROR": [],
    }
    for wf in workflows:
        status, detail = audit_workflow(wf)
        by_status[status].append((wf.name, detail))

    for status in ("FAIL", "ERROR", "WARN", "OK"):
        if by_status[status]:
            print(f"\n=== {status} ({len(by_status[status])}) ===")
            for name, detail in by_status[status]:
                print(f"  {name}: {detail}")

    print(f"\nTotal: {sum(len(v) for v in by_status.values())} workflows audited.")
    print("Advisory mode (v0.10.6). v0.10.7 will promote FAIL + WARN to blocking.")
    return 0  # advisory


if __name__ == "__main__":
    sys.exit(main())
