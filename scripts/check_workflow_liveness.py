#!/usr/bin/env python3
"""G10 workflow-liveness detector (engineering-practices lesson 9).

Rule (i) — statically dead TRIGGER EVENTS: flag any declared trigger event
that can never fire given how this repo emits it. v1 rule: ``release:`` —
Releases here are created exclusively by release.yml using GITHUB_TOKEN, and
GITHUB_TOKEN-created events never trigger workflows (GitHub anti-recursion).
The rule targets EVENTS, not workflows: a workflow with a live
``workflow_dispatch`` and a dead ``release:`` still has a dead trigger
(exactly how post-publish-smoke sat un-fired for its whole lifetime).

Rule (ii) — never-fired automatic triggers: for each ACTIVE workflow, for
each declared trigger event other than workflow_dispatch/workflow_call, flag
the event if the workflow has ZERO runs of that event type — but only after a
30-day grace window anchored on the NEWER of the workflow's created_at and
the last commit touching its file (an edited workflow gets fresh grace, so a
just-added trigger is not flagged before it has had a chance to fire).

Posture: detect-and-nudge. Findings are written as markdown for the calling
job to post as a tracking issue; this script exits 0 on findings (the
sentinel must not go chronically red — lesson 2). Rule (ii) is fail-soft on
API errors (skipped with a warning); rule (i) always runs. Exit 1 only on
internal errors.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

GRACE_DAYS = 30
# Events that are manual/callee-side and never expected to self-fire.
EXEMPT_EVENTS = {"workflow_dispatch", "workflow_call"}

DEAD_TRIGGER_RULES: dict[str, str] = {
    "release": (
        "Releases in this repo are created by release.yml using GITHUB_TOKEN; "
        "GITHUB_TOKEN-created events never trigger workflows (GitHub "
        "anti-recursion), so a `release:` trigger here can never fire. Use "
        "`workflow_run` on the release workflow instead."
    ),
}


def workflow_triggers(text: str) -> set[str]:
    """Declared trigger event names. NB: PyYAML parses bare `on:` as True."""
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        return set()
    on = data.get("on", data.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(e) for e in on}
    if isinstance(on, dict):
        return {str(e) for e in on}
    return set()


def check_dead_triggers(triggers_by_file: dict[str, set[str]]) -> list[str]:
    findings: list[str] = []
    for name in sorted(triggers_by_file):
        for event in sorted(triggers_by_file[name] & set(DEAD_TRIGGER_RULES)):
            findings.append(
                f"- **`{name}`** declares a structurally dead `on: {event}` "
                f"trigger: {DEAD_TRIGGER_RULES[event]}"
            )
    return findings
