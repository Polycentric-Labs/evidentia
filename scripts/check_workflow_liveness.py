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

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
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


def _parse_gh_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class GitHubAPI:
    """Tiny REST client. Paths are RELATIVE to /repos/{repo} (e.g.
    ``/actions/workflows``); auth via GITHUB_TOKEN/GH_TOKEN."""

    def __init__(self, repo: str, token: str | None) -> None:
        self.base = f"https://api.github.com/repos/{repo}"
        self.token = token

    def get(self, path: str, params: dict[str, str] | None = None) -> object:
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
            },
        )
        # Fixed https host (api.github.com); 30s covers connect, but a
        # read-phase stall raises bare TimeoutError — callers catch OSError.
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))


def check_never_fired(
    api: GitHubAPI, triggers_by_path: dict[str, set[str]], now: datetime
) -> list[str]:
    findings: list[str] = []
    listing = api.get("/actions/workflows", params={"per_page": "100"})
    if not isinstance(listing, dict):
        raise ValueError("unexpected /actions/workflows response shape")
    for wf in listing.get("workflows", []):
        if wf.get("state") != "active":
            continue
        path = wf.get("path", "")
        triggers = triggers_by_path.get(path)
        if not triggers:
            continue  # not a local top-level workflow file we parsed
        anchor = _parse_gh_datetime(wf["created_at"])
        commits = api.get("/commits", params={"path": path, "per_page": "1"})
        if isinstance(commits, list) and commits:
            touched = _parse_gh_datetime(commits[0]["commit"]["committer"]["date"])
            anchor = max(anchor, touched)
        age = now - anchor
        if age < timedelta(days=GRACE_DAYS):
            continue
        for event in sorted(triggers - EXEMPT_EVENTS):
            runs = api.get(
                f"/actions/workflows/{wf['id']}/runs",
                params={"event": event, "per_page": "1"},
            )
            if not isinstance(runs, dict):
                raise ValueError(f"unexpected runs response shape for {path}")
            if runs.get("total_count", 0) == 0:
                findings.append(
                    f"- **`{Path(path).name}`** trigger `on: {event}` has ZERO "
                    f"runs ever in {age.days}d (grace window {GRACE_DAYS}d) — "
                    f"a never-fired gate is a dead gate (lesson 9)."
                )
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True, help="OWNER/NAME")
    ap.add_argument("--output", required=True, help="findings markdown path")
    ap.add_argument(
        "--skip-api",
        action="store_true",
        help="rule (i) only — no network (local/test use)",
    )
    args = ap.parse_args(argv)

    triggers_by_path: dict[str, set[str]] = {}
    for path in sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(
        WORKFLOWS_DIR.glob("*.yaml")
    ):
        try:
            triggers_by_path[f".github/workflows/{path.name}"] = workflow_triggers(
                path.read_text(encoding="utf-8")
            )
        except yaml.YAMLError as exc:
            print(f"WARN: could not parse {path.name}: {exc}", file=sys.stderr)

    findings = check_dead_triggers(
        {Path(p).name: t for p, t in triggers_by_path.items()}
    )
    if not args.skip_api:
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        api = GitHubAPI(args.repo, token)
        try:
            findings += check_never_fired(api, triggers_by_path, datetime.now(UTC))
        except (OSError, ValueError, KeyError) as exc:
            # Fail-soft (lesson 2: a chronically-red sentinel trains people to
            # ignore it). OSError covers URLError/HTTPError/read-phase
            # TimeoutError; ValueError covers JSONDecodeError + shape checks.
            # Rule (i) findings above still stand.
            print(f"WARN: runs-API check skipped: {exc}", file=sys.stderr)

    Path(args.output).write_text(
        "\n".join(findings) + ("\n" if findings else ""), encoding="utf-8"
    )
    for line in findings:
        print(line)
    print(f"check_workflow_liveness: {len(findings)} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
