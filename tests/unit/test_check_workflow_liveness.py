"""Tests for ``scripts/check_workflow_liveness.py`` (G10; lesson 9 —
"a gate is not real until it has been observed firing").

Rule (i): statically dead trigger EVENTS (a ``release:`` trigger in a repo
whose Releases are created with GITHUB_TOKEN can never fire).
Rule (ii): declared automatic trigger events with ZERO runs ever, after a
30-day grace window anchored on the newer of workflow created_at / last
commit touching the file (so freshly-edited workflows get fresh grace).

All API access goes through an injected fake; no network in unit tests.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_workflow_liveness.py"


@pytest.fixture(scope="module")
def cwl() -> Any:
    spec = importlib.util.spec_from_file_location("check_workflow_liveness", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_workflow_liveness"] = module
    spec.loader.exec_module(module)
    return module


def test_on_key_parsed_despite_yaml_true_gotcha(cwl: Any) -> None:
    # PyYAML parses bare `on:` as boolean True (YAML 1.1) — must still work.
    text = "name: x\non:\n  release:\n    types: [published]\n  workflow_dispatch: {}\njobs: {}\n"
    assert cwl.workflow_triggers(text) == {"release", "workflow_dispatch"}


def test_on_as_string_and_list(cwl: Any) -> None:
    assert cwl.workflow_triggers("on: push\njobs: {}\n") == {"push"}
    assert cwl.workflow_triggers("on: [push, pull_request]\njobs: {}\n") == {
        "push",
        "pull_request",
    }


def test_dead_release_trigger_flagged_even_with_dispatch(cwl: Any) -> None:
    findings = cwl.check_dead_triggers(
        {"post-publish-smoke.yml": {"release", "workflow_dispatch"}}
    )
    assert len(findings) == 1
    assert "release" in findings[0] and "post-publish-smoke.yml" in findings[0]


def test_no_dead_trigger_no_finding(cwl: Any) -> None:
    assert cwl.check_dead_triggers({"test.yml": {"push", "pull_request"}}) == []


class FakeAPI:
    """Minimal stand-in for GitHubAPI.get keyed on (path, frozen params)."""

    def __init__(self, responses: dict[tuple[str, str], Any]) -> None:
        self.responses = responses

    def get(self, path: str, params: dict[str, str] | None = None) -> Any:
        key = (path, json.dumps(params or {}, sort_keys=True))
        return self.responses[key]


NOW = datetime(2026, 7, 2, tzinfo=UTC)
OLD = "2026-01-01T00:00:00Z"
RECENT = "2026-06-25T00:00:00Z"


def _api(created: str, touched: str, total: int) -> FakeAPI:
    wf_path = ".github/workflows/w.yml"
    return FakeAPI(
        {
            ("/actions/workflows", json.dumps({"per_page": "100"}, sort_keys=True)): {
                "total_count": 1,
                "workflows": [
                    {"id": 7, "path": wf_path, "state": "active", "created_at": created}
                ],
            },
            (
                "/commits",
                json.dumps({"path": wf_path, "per_page": "1"}, sort_keys=True),
            ): [{"commit": {"committer": {"date": touched}}}],
            (
                "/actions/workflows/7/runs",
                json.dumps({"event": "schedule", "per_page": "1"}, sort_keys=True),
            ): {"total_count": total},
        }
    )


def test_zero_runs_past_grace_flagged(cwl: Any) -> None:
    findings = cwl.check_never_fired(
        _api(OLD, OLD, 0), {".github/workflows/w.yml": {"schedule"}}, NOW
    )
    assert len(findings) == 1 and "schedule" in findings[0]


def test_recently_touched_file_gets_fresh_grace(cwl: Any) -> None:
    findings = cwl.check_never_fired(
        _api(OLD, RECENT, 0), {".github/workflows/w.yml": {"schedule"}}, NOW
    )
    assert findings == []


def test_nonzero_runs_not_flagged(cwl: Any) -> None:
    findings = cwl.check_never_fired(
        _api(OLD, OLD, 3), {".github/workflows/w.yml": {"schedule"}}, NOW
    )
    assert findings == []


def test_dispatch_and_call_events_exempt(cwl: Any) -> None:
    findings = cwl.check_never_fired(
        _api(OLD, OLD, 0),
        {".github/workflows/w.yml": {"workflow_dispatch", "workflow_call"}},
        NOW,
    )
    assert findings == []
