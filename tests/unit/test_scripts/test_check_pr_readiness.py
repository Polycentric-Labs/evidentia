"""Exercise admission with synthetic GitHub evidence and no network requests."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch
from urllib.parse import parse_qs

import pytest

ROOT = Path(__file__).resolve().parents[3]
HEAD = "a" * 40
BASE = "b" * 40
MERGE = "c" * 40
PR = 7
BRANCH = "feat/example-change"
START = "2020-01-01T00:00:00Z"
END = "2020-01-01T00:00:10Z"
REPORT_END = "2020-01-01T00:00:12Z"
ROW = dict[str, Any]


@pytest.fixture(scope="module")
def checker() -> Any:
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.syspath_prepend(str(ROOT / "scripts"))
        spec = importlib.util.spec_from_file_location("readiness_test", ROOT / "scripts/check_pr_readiness.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


@pytest.fixture
def policy(checker: Any) -> Any:
    return copy.deepcopy(checker.load_policy())


def completed(name: str) -> ROW:
    return {"name": name, "status": "completed", "conclusion": "success", "started_at": START, "completed_at": END}


def synthetic_snapshot(checker: Any, policy: Any) -> ROW:
    """Author API envelopes from public policy names, without recorded responses."""
    files = [{"filename": path, "status": "modified", "sha": "d" * 40} for path in policy["workflow_sources"]]
    files.append({"filename": "Dockerfile", "status": "modified", "sha": "d" * 40})
    pr = {
        "number": PR,
        "state": "open",
        "draft": False,
        "merged": False,
        "mergeable": True,
        "mergeable_state": "clean",
        "merge_commit_sha": MERGE,
        "user": {"login": "contributor"},
        "changed_files": len(files),
        "head": {"sha": HEAD, "ref": BRANCH, "repo": {"full_name": checker.REPO}},
        "base": {"sha": BASE, "ref": "main", "repo": {"full_name": checker.REPO}},
    }
    rules = [
        {
            "type": "required_status_checks",
            "parameters": {
                "required_status_checks": [
                    {"context": row["context"], "integration_id": row["integration_id"]} for row in policy["baseline"]
                ]
            },
        },
        {"type": "merge_queue", "parameters": {"grouping_strategy": "ALLGREEN"}},
    ]
    snapshot: ROW = {
        "pr_start": pr,
        "pr_end": copy.deepcopy(pr),
        "files": files,
        "rules": rules,
        "checks": [],
        "runs": [],
        "jobs": {},
        "suite_ids": [],
        "collection_complete": True,
        "status_sha": HEAD,
        "statuses": [{"id": 9000, "context": "example/validation", "state": "success"}],
        "codspeed_commit_resolutions": {HEAD[:7]: HEAD, BASE[:7]: BASE},
    }
    next_job = 3000
    for index, workflow in enumerate(sorted(policy["workflow_sources"])):
        run_id, suite_id = 1000 + index, 2000 + index
        run = {
            **completed(workflow),
            "id": run_id,
            "path": workflow,
            "workflow_id": 100 + index,
            "run_number": 1,
            "run_attempt": 1,
            "check_suite_id": suite_id,
            "head_sha": HEAD,
            "event": "pull_request",
            "repository": {"full_name": checker.REPO},
            "head_repository": {"full_name": checker.REPO},
            "updated_at": END,
            "pull_requests": [
                {
                    "number": PR,
                    "head": {"sha": HEAD, "repo": {"url": checker.API_REPO}},
                    "base": {"sha": BASE, "ref": "main", "repo": {"url": checker.API_REPO}},
                }
            ],
        }
        jobs = []
        for requirement in policy["workflow_jobs"]:
            if requirement["workflow"] != workflow:
                continue
            job = {
                **completed(requirement["context"]),
                "id": next_job,
                "run_id": run_id,
                "run_attempt": 1,
                "head_sha": HEAD,
                "check_run_url": checker.API_REPO + f"/check-runs/{next_job}",
                "steps": [{**completed(name), "number": number} for number, name in enumerate(requirement["steps"], 1)],
            }
            if requirement.get("allow_non_dependabot_skip"):
                job.update(conclusion="skipped", steps=[])
                run["conclusion"] = "skipped"
            elif workflow == checker.TEST and requirement["context"].startswith("pytest ("):
                inactive = (
                    {checker.NONLINUX} if "ubuntu" in requirement["context"] else {checker.LINUX, checker.CODECOV}
                )
                for step in job["steps"]:
                    if step["name"] in inactive:
                        step["conclusion"] = "skipped"
            elif workflow == checker.MERIDIAN:
                next(step for step in job["steps"] if step["name"] == checker.CACHE_SEED)["conclusion"] = "skipped"
            check = {
                **completed(job["name"]),
                "id": next_job,
                "head_sha": HEAD,
                "conclusion": job["conclusion"],
                "app": {"id": checker.ACTIONS},
                "check_suite": {"id": suite_id},
            }
            jobs.append(job)
            snapshot["checks"].append(check)
            next_job += 1
        snapshot["runs"].append(run)
        snapshot["jobs"][f"{run_id}:1"] = jobs
        snapshot["suite_ids"].append(suite_id)
    snapshot["checks"].append(
        {
            **completed("CodSpeed Performance Analysis"),
            "id": 8000,
            "head_sha": HEAD,
            "app": {"id": 257293},
            "check_suite": {"id": 8001},
            "external_id": "",
            "completed_at": REPORT_END,
            "output": {
                "title": "Performance Gate Passed",
                "summary": (
                    f"<sub>Comparing <code>{BRANCH}</code> ({HEAD[:7]}) with <code>main</code> ({BASE[:7]})</sub>"
                ),
            },
        }
    )
    snapshot["suite_ids"].append(8001)
    snapshot["check_suites"] = []
    for suite_id in snapshot["suite_ids"]:
        children = [row for row in snapshot["checks"] if row["check_suite"]["id"] == suite_id]
        snapshot["check_suites"].append(
            {
                "id": suite_id,
                "head_sha": HEAD,
                "app": {"id": children[0]["app"]["id"]},
                "repository": {"full_name": checker.REPO},
                "status": "completed",
                "conclusion": "neutral" if all(row["conclusion"] == "skipped" for row in children) else "success",
                "latest_check_runs_count": len(children),
                "check_runs_url": checker.API_REPO + f"/check-suites/{suite_id}/check-runs",
                "created_at": START,
                "updated_at": END,
            }
        )
    snapshot["status_pages"] = [{"page": 1, "per_page": 100, "sha": HEAD, "repository": checker.REPO, "total_count": 1}]
    return snapshot


@pytest.fixture
def snapshot(checker: Any, policy: Any) -> ROW:
    return synthetic_snapshot(checker, policy)


def job(snapshot: ROW, name: str) -> ROW:
    return next(row for rows in snapshot["jobs"].values() for row in rows if row["name"] == name)


def step(snapshot: ROW, name: str, step_name: str) -> ROW:
    return next(row for row in job(snapshot, name)["steps"] if row["name"] == step_name)


def external(snapshot: ROW) -> ROW:
    return next(row for row in snapshot["checks"] if row["name"] == "CodSpeed Performance Analysis")


def required(snapshot: ROW) -> list[ROW]:
    return cast(
        list[ROW],
        next(row for row in snapshot["rules"] if row["type"] == "required_status_checks")["parameters"][
            "required_status_checks"
        ],
    )


def change_files(snapshot: ROW, files: list[ROW]) -> None:
    snapshot["files"] = files
    for name in ("pr_start", "pr_end"):
        snapshot[name]["changed_files"] = len(files)


def omit_workflow(snapshot: ROW, path: str) -> None:
    run = next(row for row in snapshot["runs"] if row["path"] == path)
    ids = {row["id"] for row in snapshot["jobs"].pop(f"{run['id']}:{run['run_attempt']}")}
    snapshot["runs"].remove(run)
    snapshot["checks"] = [row for row in snapshot["checks"] if row["id"] not in ids]
    snapshot["suite_ids"] = sorted({row["check_suite"]["id"] for row in snapshot["checks"]})
    snapshot["check_suites"] = [row for row in snapshot["check_suites"] if row["id"] in snapshot["suite_ids"]]


def reject(checker: Any, policy: Any, snapshot: ROW, contains: str) -> None:
    result = checker.assess_pair(snapshot, copy.deepcopy(snapshot), policy, PR, HEAD)
    assert result["ready"] is False, result
    assert any(contains in error for error in result["errors"]), result["errors"]


def test_complete_synthetic_evidence_preserves_both_snapshots(checker: Any, policy: Any, snapshot: ROW) -> None:
    assert len(policy["baseline"]) == 25
    result = checker.assess_pair(snapshot, copy.deepcopy(snapshot), policy, PR, HEAD)
    assert result["ready"], result["errors"]
    assert len(result["bindings"]) == len(policy["workflow_jobs"])
    assert result["snapshots"] == [checker.normalized(snapshot)] * 2
    assert result["snapshot_sha256"] == [checker.digest(item) for item in result["snapshots"]]


@pytest.mark.parametrize(
    "field,value", [("draft", True), ("mergeable", False), ("mergeable", None), ("merged", True), ("state", "closed")]
)
def test_ineligible_pr_rejects(checker: Any, policy: Any, snapshot: ROW, field: str, value: object) -> None:
    snapshot["pr_end"][field] = value
    reject(checker, policy, snapshot, "confirmed mergeable")


@pytest.mark.parametrize(
    "side,field,value",
    [
        ("head", "sha", "e" * 40),
        ("base", "ref", "release"),
        ("base", "sha", "e" * 40),
    ],
)
def test_pr_identity_changes_reject(
    checker: Any, policy: Any, snapshot: ROW, side: str, field: str, value: str
) -> None:
    snapshot["pr_end"][side][field] = value
    reject(checker, policy, snapshot, "eligibility changed")


def test_replacing_baseline_context_without_changing_count_rejects(checker: Any, policy: Any, snapshot: ROW) -> None:
    required(snapshot)[0]["context"] = "Substitute validation"
    reject(checker, policy, snapshot, "removed or changed")


@pytest.mark.parametrize("app", [None, 999, "15368"])
def test_baseline_application_pin_cannot_change(checker: Any, policy: Any, snapshot: ROW, app: object) -> None:
    required(snapshot)[0]["integration_id"] = app
    reject(checker, policy, snapshot, "removed or changed")


def test_merge_queue_presence_is_required(checker: Any, policy: Any, snapshot: ROW) -> None:
    snapshot["rules"] = [row for row in snapshot["rules"] if row["type"] != "merge_queue"]
    reject(checker, policy, snapshot, "Merge queue")


@pytest.mark.parametrize(
    "name,value", [("head_sha", "e" * 40), ("event", "push"), ("path", ".github/workflows/other.yml")]
)
def test_workflow_identity_rejects(checker: Any, policy: Any, snapshot: ROW, name: str, value: str) -> None:
    next(row for row in snapshot["runs"] if row["path"] == checker.TEST)[name] = value
    reject(checker, policy, snapshot, "workflow" if name == "path" else "Workflow")


def test_workflow_association_cannot_reuse_another_pr(checker: Any, policy: Any, snapshot: ROW) -> None:
    snapshot["runs"][0]["pull_requests"][0]["number"] = PR + 1
    reject(checker, policy, snapshot, "PR association")


@pytest.mark.parametrize(
    "field,value",
    [("run_id", 0), ("run_attempt", 2), ("head_sha", "e" * 40), ("check_run_url", "https://example.com/check")],
)
def test_job_binding_rejects(checker: Any, policy: Any, snapshot: ROW, field: str, value: object) -> None:
    job(snapshot, "ruff")[field] = value
    reject(checker, policy, snapshot, "binding failed")


def test_disconnected_check_suite_rejects(checker: Any, policy: Any, snapshot: ROW) -> None:
    next(row for row in snapshot["checks"] if row["name"] == "ruff")["check_suite"]["id"] += 10000
    reject(checker, policy, snapshot, "binding failed")


@pytest.mark.parametrize("outcome", ["failure", "cancelled", "skipped", "neutral", None])
def test_successful_job_cannot_hide_invalid_step(checker: Any, policy: Any, snapshot: ROW, outcome: object) -> None:
    step(snapshot, "frontend (typecheck + build)", "Vitest unit tests")["conclusion"] = outcome
    reject(checker, policy, snapshot, "Mandatory step not successful")


def test_missing_mypy_execution_rejects(checker: Any, policy: Any, snapshot: ROW) -> None:
    row = job(snapshot, "mypy")
    row["steps"] = [item for item in row["steps"] if item["name"] != "Run mypy"]
    reject(checker, policy, snapshot, "mypy / Run mypy")


def test_each_reviewed_job_and_mandatory_step_is_required(checker: Any, policy: Any) -> None:
    for requirement in policy["workflow_jobs"]:
        snapshot = synthetic_snapshot(checker, policy)
        missing = job(snapshot, requirement["context"])
        snapshot["jobs"][f"{missing['run_id']}:1"].remove(missing)
        snapshot["checks"] = [row for row in snapshot["checks"] if row["id"] != missing["id"]]
        reject(checker, policy, snapshot, requirement["context"])
        if requirement.get("allow_non_dependabot_skip"):
            continue
        for name in requirement["mandatory_steps"]:
            snapshot = synthetic_snapshot(checker, policy)
            row = job(snapshot, requirement["context"])
            row["steps"] = [item for item in row["steps"] if item["name"] != name]
            reject(checker, policy, snapshot, "Mandatory step")


def test_complete_applicable_lane_omissions_reject(checker: Any, policy: Any) -> None:
    for workflow in policy["workflow_sources"]:
        snapshot = synthetic_snapshot(checker, policy)
        omit_workflow(snapshot, workflow)
        reject(checker, policy, snapshot, "Expected workflow/application check")


@pytest.mark.parametrize("status", ["removed", "renamed"])
def test_catalog_path_origin_requires_meridian(checker: Any, policy: Any, snapshot: ROW, status: str) -> None:
    original = "packages/evidentia-core/src/evidentia_core/catalogs/data/example.json"
    row = {"filename": original, "status": status}
    if status == "renamed":
        row.update(filename="docs/example.json", previous_filename=original)
    change_files(snapshot, [row])
    omit_workflow(snapshot, checker.MERIDIAN)
    reject(checker, policy, snapshot, "Meridian gap diff")


@pytest.mark.parametrize(
    "path", ["packages/demo/data/example.json", "packages/demo/pyproject.toml", "pyproject.toml", "uv.lock"]
)
def test_data_and_dependency_changes_require_fuzzing(checker: Any, policy: Any, snapshot: ROW, path: str) -> None:
    change_files(snapshot, [{"filename": path, "status": "modified"}])
    omit_workflow(snapshot, ".github/workflows/cflite-pr.yml")
    reject(checker, policy, snapshot, "fuzzing")


@pytest.mark.parametrize(
    "workflow,name",
    [
        (".github/workflows/cflite-pr.yml", "fuzzing"),
        (".github/workflows/evidentia.yml", "Meridian gap diff"),
        (".github/workflows/dast.yml", "DAST (Schemathesis + Playwright)"),
    ],
)
def test_live_required_conditional_job_overrides_paths(
    checker: Any, policy: Any, snapshot: ROW, workflow: str, name: str
) -> None:
    identity = next(row for row in policy["workflow_jobs"] if row["workflow"] == workflow)
    name = identity["context"]
    change_files(snapshot, [{"filename": "docs/example.md", "status": "modified"}])
    required(snapshot).append({"context": name, "integration_id": checker.ACTIONS})
    assert checker.assess_pair(snapshot, copy.deepcopy(snapshot), policy, PR, HEAD)["ready"]
    omit_workflow(snapshot, workflow)
    reject(checker, policy, snapshot, name)


def test_unknown_live_check_cannot_be_ignored(checker: Any, policy: Any, snapshot: ROW) -> None:
    required(snapshot).append({"context": "New validation", "integration_id": checker.ACTIONS})
    reject(checker, policy, snapshot, "Unreviewed required")


def test_ambiguous_live_workflow_mapping_rejects(checker: Any, policy: Any) -> None:
    policy["extra"].append(
        {"context": "fuzzing", "integration_id": checker.ACTIONS, "workflow": ".github/workflows/other.yml"}
    )
    with pytest.raises(checker.AdmissionError, match="ambiguous"):
        checker.expected_requirements(policy, set(), [("fuzzing", checker.ACTIONS)])


def test_newer_failed_attempt_is_not_replaced_with_old_success(checker: Any, policy: Any, snapshot: ROW) -> None:
    run = next(row for row in snapshot["runs"] if row["path"] == checker.TEST)
    newer = copy.deepcopy(run)
    newer.update(id=run["id"] + 10000, run_number=2, conclusion="failure")
    snapshot["runs"].append(newer)
    snapshot["jobs"][f"{newer['id']}:1"] = []
    reject(checker, policy, snapshot, "Workflow attempt not successful")


def test_old_codspeed_result_cannot_cover_successful_rerun(checker: Any, policy: Any, snapshot: ROW) -> None:
    run = next(row for row in snapshot["runs"] if row["path"] == ".github/workflows/codspeed.yml")
    jobs = snapshot["jobs"].pop(f"{run['id']}:1")
    run["run_attempt"] = 2
    for row in jobs:
        check = next(item for item in snapshot["checks"] if item["id"] == row["id"])
        row["id"] += 10000
        row["run_attempt"] = 2
        row["check_run_url"] = checker.API_REPO + f"/check-runs/{row['id']}"
        check["id"] = row["id"]
        for item in [row, check, *row["steps"]]:
            item.update(started_at="2020-01-01T00:01:00Z", completed_at="2020-01-01T00:01:10Z")
    snapshot["jobs"][f"{run['id']}:2"] = jobs
    reject(checker, policy, snapshot, "CodSpeed linkage rejected")


@pytest.mark.parametrize(
    "alteration", ["head", "base", "branch", "duplicate", "missing", "unresolved", "wrong-resolution"]
)
def test_codspeed_comparison_must_resolve_exact_commits(
    checker: Any, policy: Any, snapshot: ROW, alteration: str
) -> None:
    row = external(snapshot)
    summary = row["output"]["summary"]
    if alteration == "head":
        summary = summary.replace(HEAD[:7], "ddddddd")
    elif alteration == "base":
        summary = summary.replace(BASE[:7], "ddddddd")
    elif alteration == "branch":
        summary = summary.replace(BRANCH, "feat/other-change")
    elif alteration == "duplicate":
        summary += summary
    elif alteration == "missing":
        summary = "Performance Gate Passed"
    elif alteration == "unresolved":
        snapshot["codspeed_commit_resolutions"] = {}
    else:
        snapshot["codspeed_commit_resolutions"][BASE[:7]] = "d" * 40
    row["output"]["summary"] = summary
    reject(checker, policy, snapshot, "CodSpeed linkage rejected")


@pytest.mark.parametrize("value", [None, "invalid", "2020-01-01T00:00:12", START, END, "9999-01-01T00:00:00Z"])
def test_codspeed_report_times_fail_closed(checker: Any, policy: Any, snapshot: ROW, value: object) -> None:
    external(snapshot)["completed_at"] = value
    reject(checker, policy, snapshot, "CodSpeed linkage rejected")


def test_codspeed_prefix_floor_comes_from_policy(checker: Any, policy: Any, snapshot: ROW) -> None:
    policy["codspeed_linkage"]["minimum_commit_prefix_length"] = 8
    reject(checker, policy, snapshot, "shorter than policy")


@pytest.mark.parametrize("target", ["checks", "rules", "runs", "files", "statuses"])
def test_changed_evidence_between_captures_rejects(checker: Any, policy: Any, snapshot: ROW, target: str) -> None:
    second = copy.deepcopy(snapshot)
    if target == "checks":
        external(second)["output"]["title"] = "Updated analysis"
    elif target == "rules":
        second["rules"][1]["parameters"]["grouping_strategy"] = "HEADGREEN"
    elif target == "runs":
        second["runs"][0]["updated_at"] = REPORT_END
    elif target == "files":
        second["files"][0]["sha"] = "e" * 40
    else:
        second["statuses"][0]["id"] += 1
    result = checker.assess_pair(snapshot, second, policy, PR, HEAD)
    assert not result["ready"]
    assert "Normalized evidence changed between complete snapshots" in result["errors"]


def test_api_order_is_not_an_evidence_change(checker: Any, policy: Any, snapshot: ROW) -> None:
    second = copy.deepcopy(snapshot)
    for name in ("checks", "rules", "runs", "files", "statuses", "suite_ids", "check_suites"):
        second[name].reverse()
    assert checker.assess_pair(snapshot, second, policy, PR, HEAD)["ready"]


@pytest.mark.parametrize("state", ["pending", "failure", "error"])
def test_commit_status_failure_blocks(checker: Any, policy: Any, snapshot: ROW, state: str) -> None:
    snapshot["statuses"][0]["state"] = state
    reject(checker, policy, snapshot, "Commit status not successful")


@pytest.mark.parametrize("change", ["short", "ceiling", "missing-origin", "unknown-status"])
def test_changed_file_completeness_rejects(checker: Any, policy: Any, snapshot: ROW, change: str) -> None:
    if change == "short":
        snapshot["files"].pop()
    elif change == "ceiling":
        change_files(snapshot, [{"filename": f"docs/{i}.md", "status": "modified"} for i in range(3000)])
    elif change == "missing-origin":
        snapshot["files"][0]["status"] = "renamed"
    else:
        snapshot["files"][0]["status"] = "mystery"
    reject(checker, policy, snapshot, "file" if change in {"short", "ceiling"} else "evidence")


def test_skipped_dependabot_job_requires_exact_actor_and_empty_steps(checker: Any, policy: Any, snapshot: ROW) -> None:
    for name in ("pr_start", "pr_end"):
        snapshot[name]["user"]["login"] = "dependabot[bot]"
    reject(checker, policy, snapshot, "not successful")


def test_container_skip_requires_irrelevant_files_and_successful_classifier(
    checker: Any, policy: Any, snapshot: ROW
) -> None:
    change_files(snapshot, [{"filename": "docs/example.md", "status": "modified"}])
    for row in job(snapshot, "Build + smoke test")["steps"]:
        if row["name"] in checker.CONTAINER_STEPS:
            row["conclusion"] = "skipped"
    assert checker.assess_pair(snapshot, copy.deepcopy(snapshot), policy, PR, HEAD)["ready"]
    change_files(snapshot, [{"filename": "Dockerfile", "status": "removed"}])
    reject(checker, policy, snapshot, "Mandatory step")


class FakeTransport:
    """Serve fully authored REST responses while recording each requested endpoint."""

    def __init__(self, snapshot: ROW) -> None:
        self.snapshot = snapshot
        self.calls: list[str] = []

    def __call__(self, path: str) -> Any:
        self.calls.append(path)
        route, _, raw_query = path.partition("?")
        query = parse_qs(raw_query)
        snapshot = self.snapshot
        if route == f"pulls/{PR}":
            return copy.deepcopy(snapshot["pr_start"])
        if route == "rules/branches/main":
            return copy.deepcopy(snapshot["rules"])
        if route == f"pulls/{PR}/files":
            return self.page(snapshot["files"], query)
        if route == f"commits/{HEAD}/check-runs":
            return {"total_count": len(snapshot["checks"]), "check_runs": self.page(snapshot["checks"], query)}
        if route == f"commits/{HEAD}/check-suites":
            rows = snapshot["check_suites"]
            return {"total_count": len(rows), "check_suites": self.page(rows, query)}
        if route == f"commits/{HEAD}/status":
            return {
                "sha": HEAD,
                "repository": copy.deepcopy(snapshot["pr_start"]["base"]["repo"]),
                "total_count": len(snapshot["statuses"]),
                "statuses": self.page(snapshot["statuses"], query),
            }
        if route == "actions/runs":
            assert query["head_sha"] == [HEAD]
            return {"total_count": len(snapshot["runs"]), "workflow_runs": self.page(snapshot["runs"], query)}
        if route.startswith("actions/runs/"):
            parts = route.split("/")
            assert len(parts) == 6 and parts[3] == "attempts" and parts[5] == "jobs"
            rows = snapshot["jobs"][f"{parts[2]}:{parts[4]}"]
            return {"total_count": len(rows), "jobs": self.page(rows, query)}
        if route.startswith("commits/"):
            return {"sha": snapshot["codspeed_commit_resolutions"][route.split("/")[1]]}
        raise AssertionError("Unexpected request: " + path)

    @staticmethod
    def page(rows: list[ROW], query: dict[str, list[str]]) -> list[ROW]:
        count = int(query.get("per_page", ["100"])[0])
        page = int(query.get("page", ["1"])[0])
        return copy.deepcopy(rows[(page - 1) * count : page * count])


def test_capture_uses_exact_attempt_endpoints_and_commit_resolution(
    checker: Any, policy: Any, snapshot: ROW, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = FakeTransport(snapshot)
    monkeypatch.setattr(checker, "api", transport)
    first = checker.capture(PR, HEAD, policy)
    second = checker.capture(PR, HEAD, policy)
    result = checker.assess_pair(first, second, policy, PR, HEAD)
    assert result["ready"], result["errors"]
    for run in snapshot["runs"]:
        assert sum(f"actions/runs/{run['id']}/attempts/1/jobs?" in path for path in transport.calls) == 2
    assert transport.calls.count(f"commits/{HEAD[:7]}") == 2
    assert transport.calls.count(f"commits/{BASE[:7]}") == 2


@pytest.mark.parametrize(
    "payload",
    [
        {"total_count": 2, "rows": [{"id": 1}]},
        {"total_count": 1000, "rows": []},
        {"total_count": 2, "rows": [{"id": 1}, {"id": 1}]},
        {"total_count": 1, "rows": ["invalid"]},
    ],
)
def test_pagination_truncation_duplicates_and_malformed_rows_reject(
    checker: Any, monkeypatch: pytest.MonkeyPatch, payload: ROW
) -> None:
    monkeypatch.setattr(checker, "api", lambda path: payload)
    with pytest.raises(checker.AdmissionError):
        checker.paged("example", "rows", cap=1000)


def test_pagination_crosses_page_boundary(checker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def query(path: str) -> ROW:
        calls.append(path)
        rows = (
            [{"id": number} for number in range(100)]
            if parse_qs(path.partition("?")[2])["page"] == ["1"]
            else [{"id": 100}]
        )
        return {"total_count": 101, "rows": rows}

    monkeypatch.setattr(checker, "api", query)
    assert len(checker.paged("example", "rows")) == 101
    assert len(calls) == 2


def test_api_is_explicit_read_only_and_rejects_ambiguous_json(checker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert kwargs["timeout"] == 55
        return subprocess.CompletedProcess(command, 0, '{"value":1,"value":2}', "")

    monkeypatch.setattr(checker.subprocess, "run", run)
    with pytest.raises(checker.policy_module.PolicyError, match="Duplicate"):
        checker.api("pulls/7")
    assert calls[0][calls[0].index("--method") + 1] == "GET"
    assert calls[0][calls[0].index("--hostname") + 1] == "github.com"
    assert calls[0][-1] == "repos/" + checker.REPO + "/pulls/7"


def test_main_always_recollects_and_writes_unique_receipt(
    checker: Any, policy: Any, snapshot: ROW, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = FakeTransport(snapshot)
    monkeypatch.setattr(checker, "api", transport)
    path = tmp_path / "receipt.json"
    args = ["--pr", str(PR), "--head", HEAD, "--output", str(path)]
    assert checker.main(args) == 0
    first = json.loads(path.read_text(encoding="ascii"))
    assert checker.main(args) == 0
    second = json.loads(path.read_text(encoding="ascii"))
    assert first["invocation_id"] != second["invocation_id"]
    assert len(second["snapshots"]) == 2
    assert second["remote_mutations"] is False
    assert transport.calls.count(f"pulls/{PR}") == 8
    assert b"\r" not in path.read_bytes()


def test_failed_collection_replaces_old_success_with_fresh_failure(
    checker: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "receipt.json"
    path.write_text('{"ready":true,"invocation_id":"old"}', encoding="ascii")

    def fail(path: str) -> None:
        raise checker.AdmissionError("Synthetic network failure")

    monkeypatch.setattr(checker, "api", fail)
    assert checker.main(["--pr", str(PR), "--head", HEAD, "--output", str(path)]) == 1
    receipt = json.loads(path.read_text(encoding="ascii"))
    assert receipt["ready"] is False and receipt["invocation_id"] != "old"
    assert receipt["expires_at"] > receipt["completed_at"]


@pytest.mark.parametrize("head", ["short", "0" * 39, "Z" * 40])
def test_invalid_cli_head_never_queries_github(
    checker: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, head: str
) -> None:
    def unexpected(path: str) -> None:
        raise AssertionError("Network was not expected")

    monkeypatch.setattr(checker, "api", unexpected)
    assert checker.main(["--pr", str(PR), "--head", head, "--output", str(tmp_path / "receipt.json")]) == 1


def test_receipt_cannot_overwrite_policy_by_equal_path_or_hardlink(checker: Any, tmp_path: Path) -> None:
    source = tmp_path / "policy.json"
    source.write_bytes(b"protected")
    for output in (source, tmp_path / "alias.json"):
        if output != source:
            os.link(source, output)
        with pytest.raises(checker.AdmissionError, match="protected"):
            checker.write_receipt(output, {"ready": False}, (source,))
        assert source.read_bytes() == b"protected"


def test_failed_atomic_replace_preserves_existing_receipt(checker: Any, tmp_path: Path) -> None:
    target = tmp_path / "receipt.json"
    target.write_bytes(b"original")
    with (
        patch.object(checker.os, "replace", side_effect=OSError("Synthetic failure")),
        pytest.raises(OSError, match="Synthetic"),
    ):
        checker.write_receipt(target, {"ready": False})
    assert target.read_bytes() == b"original"
    assert list(tmp_path.iterdir()) == [target]


def test_unreviewed_policy_fails_before_collection(
    checker: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "policy.json"
    path.write_bytes(checker.policy_module.POLICY_PATH.read_bytes() + b" ")

    def unexpected(path: str) -> None:
        raise AssertionError("Network was not expected")

    monkeypatch.setattr(checker, "api", unexpected)
    assert (
        checker.main(
            ["--pr", str(PR), "--head", HEAD, "--policy", str(path), "--output", str(tmp_path / "receipt.json")]
        )
        == 1
    )


@pytest.mark.parametrize(
    "outcome", ["failure", "cancelled", "timed_out", "action_required", "skipped", "neutral", None]
)
def test_visible_check_failure_is_never_ignored(checker: Any, policy: Any, snapshot: ROW, outcome: object) -> None:
    external(snapshot)["conclusion"] = outcome
    reject(checker, policy, snapshot, "Check not successful")


@pytest.mark.parametrize("outcome", ["skipped", "neutral", None])
def test_unknown_nonexecuting_step_rejects(checker: Any, policy: Any, snapshot: ROW, outcome: object) -> None:
    job(snapshot, "ruff")["steps"].append({**completed("Unreviewed validation"), "conclusion": outcome})
    reject(checker, policy, snapshot, "Step not successful")


def test_pending_step_does_not_inherit_success_from_job(checker: Any, policy: Any, snapshot: ROW) -> None:
    step(snapshot, "ruff", "Run ruff")["status"] = "in_progress"
    reject(checker, policy, snapshot, "Mandatory step")


def test_duplicate_step_and_check_identities_reject(checker: Any, policy: Any, snapshot: ROW) -> None:
    job(snapshot, "ruff")["steps"].append(copy.deepcopy(step(snapshot, "ruff", "Run ruff")))
    reject(checker, policy, snapshot, "duplicate steps")
    snapshot = synthetic_snapshot(checker, policy)
    snapshot["checks"].append(copy.deepcopy(external(snapshot)))
    reject(checker, policy, snapshot, "Duplicate check")


@pytest.mark.parametrize("name,value", [("head_sha", "e" * 40), ("app", {"id": 999})])
def test_external_analysis_exact_head_and_application_required(
    checker: Any, policy: Any, snapshot: ROW, name: str, value: object
) -> None:
    external(snapshot)[name] = value
    reject(checker, policy, snapshot, "Stale check" if name == "head_sha" else "CodSpeed")


def test_absent_and_truncated_suite_inventory_reject(checker: Any, policy: Any, snapshot: ROW) -> None:
    snapshot["suite_ids"] = []
    reject(checker, policy, snapshot, "Check-suite evidence")
    snapshot["suite_ids"] = list(range(1000))
    reject(checker, policy, snapshot, "Check-suite evidence")


def test_managed_codeql_cannot_replace_required_repository_workflow(checker: Any, policy: Any, snapshot: ROW) -> None:
    run = next(row for row in snapshot["runs"] if row["path"] == ".github/workflows/codeql.yml")
    run.update(path=checker.MANAGED, event="dynamic", pull_requests=[])
    reject(checker, policy, snapshot, "Expected workflow/application")


def test_capture_binds_rerun_jobs_to_selected_attempt(
    checker: Any, policy: Any, snapshot: ROW, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = next(row for row in snapshot["runs"] if row["path"] == checker.TEST)
    old_key = f"{run['id']}:1"
    rows = snapshot["jobs"].pop(old_key)
    run["run_attempt"] = 2
    for row in rows:
        check = next(item for item in snapshot["checks"] if item["id"] == row["id"])
        row["id"] += 10000
        row["run_attempt"] = 2
        row["check_run_url"] = checker.API_REPO + f"/check-runs/{row['id']}"
        check["id"] = row["id"]
    snapshot["jobs"][f"{run['id']}:2"] = rows
    transport = FakeTransport(snapshot)
    monkeypatch.setattr(checker, "api", transport)
    first = checker.capture(PR, HEAD, policy)
    second = checker.capture(PR, HEAD, policy)
    assert checker.assess_pair(first, second, policy, PR, HEAD)["ready"]
    assert sum(f"actions/runs/{run['id']}/attempts/2/jobs?" in path for path in transport.calls) == 2
    assert not any(f"actions/runs/{run['id']}/attempts/1/jobs?" in path for path in transport.calls)


def test_changed_pagination_total_rejects(checker: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def query(path: str) -> ROW:
        nonlocal calls
        calls += 1
        return {"total_count": 101 if calls == 1 else 102, "rows": [{"id": value} for value in range(100)]}

    monkeypatch.setattr(checker, "api", query)
    with pytest.raises(checker.AdmissionError, match="count changed"):
        checker.paged("example", "rows")


def test_malformed_capture_is_a_fresh_rejection(checker: Any, policy: Any, snapshot: ROW) -> None:
    snapshot["checks"][0]["app"] = None
    result = checker.assess_pair(snapshot, copy.deepcopy(snapshot), policy, PR, HEAD)
    assert not result["ready"]
    assert any("Malformed" in error for error in result["errors"])


def test_live_failure_receipt_retains_rejected_snapshots(
    checker: Any, policy: Any, snapshot: ROW, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    step(snapshot, "ruff", "Run ruff")["conclusion"] = "failure"
    monkeypatch.setattr(checker, "api", FakeTransport(snapshot))
    path = tmp_path / "receipt.json"
    assert checker.main(["--pr", str(PR), "--head", HEAD, "--output", str(path)]) == 1
    receipt = json.loads(path.read_text(encoding="ascii"))
    assert not receipt["ready"] and len(receipt["snapshots"]) == 2
    assert receipt["snapshot_sha256"] == [checker.digest(item) for item in receipt["snapshots"]]


def test_cli_policy_alias_is_protected_even_after_successful_collection(
    checker: Any, policy: Any, snapshot: ROW, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "policy.json"
    source.write_bytes(checker.policy_module.POLICY_PATH.read_bytes())
    output = tmp_path / "output.json"
    os.link(source, output)
    before = source.read_bytes()
    monkeypatch.setattr(checker, "api", FakeTransport(snapshot))
    assert checker.main(["--pr", str(PR), "--head", HEAD, "--policy", str(source), "--output", str(output)]) == 2
    assert source.read_bytes() == before


def test_exclusive_temporary_creation_preserves_existing_file(checker: Any, tmp_path: Path) -> None:
    target = tmp_path / "receipt.json"
    identifier = checker.uuid.UUID("00000000-0000-0000-0000-000000000001")
    temporary = target.with_name(target.name + "." + identifier.hex + ".tmp")
    temporary.write_bytes(b"existing")
    with patch.object(checker.uuid, "uuid4", return_value=identifier), pytest.raises(FileExistsError):
        checker.write_receipt(target, {"ready": False})
    assert temporary.read_bytes() == b"existing"
    assert not target.exists()


def capture_result(checker: Any, policy: Any, snapshot: ROW, monkeypatch: pytest.MonkeyPatch, transform: Any) -> ROW:
    transport = FakeTransport(snapshot)

    def query(path: str) -> Any:
        return transform(path, transport(path))

    monkeypatch.setattr(checker, "api", query)
    first = checker.capture(PR, HEAD, policy)
    second = checker.capture(PR, HEAD, policy)
    return cast(ROW, checker.assess_pair(first, second, policy, PR, HEAD))


@pytest.mark.parametrize("value", [None, True, False, -1, 0.0, 36.0, "36", "missing"])
def test_all_keyed_transport_envelopes_require_integer_totals(
    checker: Any, policy: Any, snapshot: ROW, monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    def transform(path: str, payload: Any) -> Any:
        if isinstance(payload, dict) and "total_count" in payload:
            if value == "missing":
                del payload["total_count"]
            else:
                payload["total_count"] = value
        return payload

    with pytest.raises(checker.AdmissionError, match="nonnegative integer"):
        capture_result(checker, policy, snapshot, monkeypatch, transform)


@pytest.mark.parametrize(
    "field,value",
    [
        ("sha", "d" * 40),
        ("sha", None),
        ("sha", "missing"),
        ("repository", {"full_name": "example/wrong-repository"}),
        ("repository", {}),
        ("total_count", None),
        ("total_count", True),
        ("total_count", 1.0),
    ],
)
def test_every_status_page_binds_head_repository_and_count(
    checker: Any, policy: Any, snapshot: ROW, monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    def transform(path: str, payload: Any) -> Any:
        if "/status?" in path and "per_page=100" in path:
            if value == "missing":
                payload.pop(field)
            else:
                payload[field] = value
        return payload

    with pytest.raises(checker.AdmissionError):
        capture_result(checker, policy, snapshot, monkeypatch, transform)


def test_later_status_page_cannot_change_head(
    checker: Any, policy: Any, snapshot: ROW, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot["statuses"] = [
        {"id": 10000 + number, "context": f"example/{number}", "state": "success"} for number in range(101)
    ]

    def transform(path: str, payload: Any) -> Any:
        if "/status?" in path and parse_qs(path.partition("?")[2]).get("page") == ["2"]:
            payload["sha"] = "d" * 40
        return payload

    with pytest.raises(checker.AdmissionError, match="another head"):
        capture_result(checker, policy, snapshot, monkeypatch, transform)


def test_empty_status_inventory_has_complete_bound_envelopes(
    checker: Any, policy: Any, snapshot: ROW, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot["statuses"] = []
    result = capture_result(checker, policy, snapshot, monkeypatch, lambda path, payload: payload)
    assert result["ready"], result["errors"]
    assert all(row["total_count"] == 0 and row["sha"] == HEAD for row in result["snapshots"][0]["status_pages"])


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "queued", "conclusion": None},
        {"status": "in_progress", "conclusion": None},
        {"status": "completed", "conclusion": "failure"},
        {"status": "completed", "conclusion": "neutral"},
        {"status": "completed", "conclusion": None},
        {"head_sha": "d" * 40},
        {"app": {"id": 999999}},
        {"latest_check_runs_count": 2},
        {"latest_check_runs_count": 0, "status": "queued", "conclusion": None},
    ],
)
def test_suite_envelope_cannot_contradict_old_successful_child(
    checker: Any, policy: Any, snapshot: ROW, monkeypatch: pytest.MonkeyPatch, changes: ROW
) -> None:
    def transform(path: str, payload: Any) -> Any:
        if "/check-suites?" in path:
            next(row for row in payload["check_suites"] if row["id"] == 8001).update(changes)
        return payload

    if "head_sha" in changes:
        with pytest.raises(checker.AdmissionError, match="Suite head"):
            capture_result(checker, policy, snapshot, monkeypatch, transform)
    else:
        result = capture_result(checker, policy, snapshot, monkeypatch, transform)
        assert not result["ready"] and any("Suite" in error for error in result["errors"]), result


def test_suite_rerequest_after_first_capture_is_retained_and_rejects(
    checker: Any, policy: Any, snapshot: ROW, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0

    def transform(path: str, payload: Any) -> Any:
        nonlocal calls
        if "/check-suites?" in path:
            calls += 1
            if calls == 2:
                next(row for row in payload["check_suites"] if row["id"] == 8001).update(
                    status="queued", conclusion=None
                )
        return payload

    result = capture_result(checker, policy, snapshot, monkeypatch, transform)
    assert not result["ready"]
    assert "Normalized evidence changed between complete snapshots" in result["errors"]
    first = next(row for row in result["snapshots"][0]["check_suites"] if row["id"] == 8001)
    second = next(row for row in result["snapshots"][1]["check_suites"] if row["id"] == 8001)
    assert first["status"] == "completed" and second["status"] == "queued"


def empty_suite(checker: Any) -> ROW:
    return {
        "id": 987654,
        "head_sha": HEAD,
        "app": {"id": 999999},
        "repository": {"full_name": checker.REPO},
        "status": "queued",
        "conclusion": None,
        "latest_check_runs_count": 0,
        "check_runs_url": checker.API_REPO + "/check-suites/987654/check-runs",
        "created_at": START,
        "updated_at": END,
    }


def test_automatic_empty_queued_suite_is_retained_without_granting_a_check(
    checker: Any, policy: Any, snapshot: ROW, monkeypatch: pytest.MonkeyPatch
) -> None:
    def transform(path: str, payload: Any) -> Any:
        if "/check-suites?" in path:
            payload["check_suites"].append(empty_suite(checker))
            payload["total_count"] += 1
        return payload

    result = capture_result(checker, policy, snapshot, monkeypatch, transform)
    assert result["ready"], result["errors"]
    assert result["empty_queued_suites"] == [987654]
    assert next(row for row in result["snapshots"][0]["check_suites"] if row["id"] == 987654)["status"] == "queued"
    snapshot["checks"].remove(external(snapshot))
    result = capture_result(checker, policy, snapshot, monkeypatch, transform)
    assert not result["ready"] and any("CodSpeed" in error for error in result["errors"])


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "in_progress"},
        {"status": "completed", "conclusion": "failure"},
        {"conclusion": "failure"},
        {"status": "completed", "conclusion": "neutral"},
        {"latest_check_runs_count": 1},
    ],
)
def test_nonidle_empty_suite_is_not_discarded(
    checker: Any, policy: Any, snapshot: ROW, monkeypatch: pytest.MonkeyPatch, changes: ROW
) -> None:
    def transform(path: str, payload: Any) -> Any:
        if "/check-suites?" in path:
            suite = empty_suite(checker)
            suite.update(changes)
            payload["check_suites"].append(suite)
            payload["total_count"] += 1
        return payload

    result = capture_result(checker, policy, snapshot, monkeypatch, transform)
    assert not result["ready"] and any("Suite" in error for error in result["errors"])


@pytest.mark.parametrize(
    "changes",
    [
        {"head_sha": "d" * 40},
        {"app": None},
        {"app": {"id": True}},
        {"latest_check_runs_count": False},
        {"latest_check_runs_count": 0.0},
        {"latest_check_runs_count": -1},
        {"repository": {"full_name": "example/wrong"}},
        {"check_runs_url": "https://example.com/invalid"},
    ],
)
def test_malformed_empty_suite_cannot_use_the_idle_classification(
    checker: Any, policy: Any, snapshot: ROW, monkeypatch: pytest.MonkeyPatch, changes: ROW
) -> None:
    def transform(path: str, payload: Any) -> Any:
        if "/check-suites?" in path:
            suite = empty_suite(checker)
            suite.update(changes)
            payload["check_suites"].append(suite)
            payload["total_count"] += 1
        return payload

    with pytest.raises(checker.AdmissionError):
        capture_result(checker, policy, snapshot, monkeypatch, transform)


def test_suite_bound_to_selected_run_cannot_be_an_idle_container(checker: Any, policy: Any, snapshot: ROW) -> None:
    run = next(row for row in snapshot["runs"] if row["path"] == checker.TEST)
    snapshot["check_suites"].append(empty_suite(checker))
    snapshot["suite_ids"].append(987654)
    run["check_suite_id"] = 987654
    reject(checker, policy, snapshot, "Suite is not")
