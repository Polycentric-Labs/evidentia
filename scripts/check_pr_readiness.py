"""Local, read-only, point-in-time PR admission; never a remote policy guarantee."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import subprocess
import uuid
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NotRequired, TypedDict, cast

import verification_policy as policy_module

JsonObject = dict[str, Any]


class SuiteApp(TypedDict):
    id: int


class SuiteRepository(TypedDict):
    full_name: str


class CheckSuite(TypedDict):
    """The suite envelope that binds child checks and exposes rerun state."""

    id: int
    head_sha: str
    app: SuiteApp
    repository: SuiteRepository
    status: str
    conclusion: str | None
    latest_check_runs_count: int
    check_runs_url: str
    created_at: NotRequired[str | None]
    updated_at: NotRequired[str | None]


class Snapshot(TypedDict):
    """Collected API evidence; nested provider fields are checked before admission."""

    codspeed_commit_resolutions: dict[str, str]
    pr_start: JsonObject
    pr_end: JsonObject
    rules: list[JsonObject]
    files: list[JsonObject]
    checks: list[JsonObject]
    status_sha: str
    statuses: list[JsonObject]
    runs: list[JsonObject]
    jobs: dict[str, list[JsonObject]]
    suite_ids: list[int]
    check_suites: list[CheckSuite]
    status_pages: list[JsonObject]
    collection_complete: bool


class AdmissionResult(TypedDict):
    """A decision and the evidence retained for its independent verification."""

    ready: bool
    errors: list[str]
    allowed_skips: list[str]
    empty_queued_suites: list[int]
    bindings: list[JsonObject]
    snapshots: NotRequired[list[JsonObject]]
    snapshot_sha256: NotRequired[list[str]]


REPO = "Polycentric-Labs/evidentia"
API_REPO = "https://api.github.com/repos/" + REPO
ACTIONS = 15368
MANAGED = "dynamic/github-code-quality/codeql"
DEPENDABOT = ".github/workflows/dependabot-auto-merge.yml"
DEPENDABOT_JOB = "Enable auto-merge (Dependabot patch)"
CONTAINER = ".github/workflows/container-build.yml"
TEST = ".github/workflows/test.yml"
MERIDIAN = ".github/workflows/evidentia.yml"
CONTAINER_STEPS = {
    "Set up Docker Buildx",
    "Determine latest published evidentia version (from PyPI)",
    "Wait for PyPI propagation",
    "Regenerate hash-pinned requirements.txt against PyPI",
    "Install osv-scanner (v2.4.0, checksum-verified)",
    "osv-scan regenerated container requirements",
    "Build image (load into local Docker, not pushed)",
    "Smoke test \u2014 `evidentia version`",
    "Smoke test \u2014 `evidentia catalog list`",
    "Smoke test \u2014 image labels",
    "Smoke test \u2014 non-root execution",
}
LINUX = "Run tests (with coverage on Linux)"
NONLINUX = "Run tests (no coverage on non-Linux)"
CODECOV = "Upload coverage to Codecov"
CACHE_SEED = "Seed baseline on cache miss (first run ever or key bump)"
MERIDIAN_REQUIRED = {
    "Analyze head",
    "Restore baseline",
    "Gap diff (markdown for PR comment)",
    "Gate on regressions",
}
LIMITS = [
    "Point-in-time local admission only; evidence can change after the final read.",
    "GitHub enforces required checks at the protected merge; this receipt does not authorize a merge.",
    "No merge-queue candidate validation or remote policy enforcement is claimed.",
    "Workflow source digests are provenance; step conclusions do not verify commands or action implementations.",
    "Required context/application identities and merge-queue presence are compared. Other protections need review.",
    "CodSpeed uses resolved commits and step/report times. The provider does not attest a GitHub run/attempt ID.",
    "Shell failure masking (for example || true) cannot be recovered from successful API step conclusions.",
    "An action's internal suppressed failures or continue-on-error outcome may require independent logs/source review.",
    "Current-head Actions checks must bind to selected attempts; ambiguous historical duplicates withhold admission.",
    "GitHub check listing can omit suites beyond its documented 1000-suite ceiling; ceiling evidence is rejected.",
]


class AdmissionError(RuntimeError):
    pass


def digest(value: object) -> str:
    """Hash a canonical JSON value without accepting non-JSON numeric constants."""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    ).hexdigest()


def load_policy(path: Path = policy_module.POLICY_PATH) -> policy_module.VerificationPolicy:
    policy = policy_module.load_policy(path)
    if len(policy["baseline"]) != 25:
        raise AdmissionError("Unexpected reviewed baseline size")
    return policy


def api(path: str) -> Any:
    result = subprocess.run(
        [
            "gh",
            "api",
            "--method",
            "GET",
            "--hostname",
            "github.com",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            f"repos/{REPO}/{path}",
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=55,
    )
    if result.returncode:
        raise AdmissionError("Read-only GitHub query failed: " + path.split("?")[0])
    return policy_module.strict_json(result.stdout)


def nonnegative_integer(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise AdmissionError(label + " must be a nonnegative integer")
    return value


def status_identity(payload: JsonObject, head: str) -> JsonObject:
    """Bind every combined-status envelope to the requested commit and repository."""
    total = nonnegative_integer(payload.get("total_count"), "Status total_count")
    if payload.get("sha") != head or payload.get("repository", {}).get("full_name") != REPO:
        raise AdmissionError("Status page belongs to another head or repository")
    return {"sha": head, "repository": REPO, "total_count": total}


def paged(
    path: str,
    field: str | None,
    cap: int = 10000,
    expected: int | None = None,
    *,
    status_head: str | None = None,
    page_evidence: list[JsonObject] | None = None,
) -> list[JsonObject]:
    rows: list[JsonObject] = []
    total = nonnegative_integer(expected, "Expected page count") if expected is not None else None
    if total is not None and total >= cap:
        raise AdmissionError("API pagination ceiling reached")
    for page in range(1, cap // 100 + 2):
        payload = api(path + ("&" if "?" in path else "?") + f"per_page=100&page={page}")
        if field is not None:
            if not isinstance(payload, dict):
                raise AdmissionError("Unexpected paginated envelope")
            reported = nonnegative_integer(payload.get("total_count"), "Pagination total_count")
            if total is not None and total != reported:
                raise AdmissionError("Pagination count changed")
            total = reported
            if total >= cap:
                raise AdmissionError("API pagination ceiling reached")
            if status_head is not None:
                identity = status_identity(payload, status_head)
                if page_evidence is not None:
                    page_evidence.append({"page": page, "per_page": 100, **identity})
            batch = payload.get(field)
        else:
            batch = payload
        if not isinstance(batch, list) or len(batch) > 100 or any(not isinstance(row, dict) for row in batch):
            raise AdmissionError("Unexpected paginated response")
        rows.extend(batch)
        if len(rows) >= cap:
            raise AdmissionError("API pagination ceiling reached")
        if total is not None and len(rows) > total:
            raise AdmissionError("Pagination rows exceed reported total")
        if len(batch) < 100:
            if total is not None and len(rows) != total:
                raise AdmissionError("Incomplete paginated evidence")
            ids = [row.get("id", row.get("filename")) for row in rows]
            if len(ids) != len(set(ids)):
                raise AdmissionError("Duplicate paginated evidence")
            return rows
    raise AdmissionError("Pagination did not terminate")


def suite_identity(row: JsonObject, head: str) -> CheckSuite:
    """Require the native suite identity and child-count envelope before using it."""
    suite_id = nonnegative_integer(row.get("id"), "Suite ID")
    app = row.get("app")
    repository = row.get("repository")
    if not isinstance(app, dict) or not isinstance(repository, dict):
        raise AdmissionError("Suite application or repository is malformed")
    app_id = nonnegative_integer(app.get("id"), "Suite App ID")
    count = nonnegative_integer(row.get("latest_check_runs_count"), "Suite latest_check_runs_count")
    if (
        suite_id == 0
        or app_id == 0
        or row.get("head_sha") != head
        or repository.get("full_name") != REPO
        or row.get("check_runs_url") != API_REPO + f"/check-suites/{suite_id}/check-runs"
        or not isinstance(row.get("status"), str)
        or "conclusion" not in row
        or (row["conclusion"] is not None and not isinstance(row["conclusion"], str))
    ):
        raise AdmissionError("Suite head, application, repository or state identity is invalid")
    return CheckSuite(
        id=suite_id,
        head_sha=head,
        app={"id": app_id},
        repository={"full_name": REPO},
        status=row["status"],
        conclusion=row["conclusion"],
        latest_check_runs_count=count,
        check_runs_url=row["check_runs_url"],
        created_at=row.get("created_at"),
        updated_at=row.get("updated_at"),
    )


def selected_runs(runs: list[JsonObject]) -> list[JsonObject]:
    groups: dict[str, list[JsonObject]] = defaultdict(list)
    for run in runs:
        groups[run["path"]].append(run)
    selected = []
    for path, rows in groups.items():
        if len({row["workflow_id"] for row in rows}) != 1:
            raise AdmissionError("Ambiguous workflow identity: " + path)
        # Select by GitHub sequence/attempt identity, never by a favorable conclusion.
        selected.append(max(rows, key=lambda row: (row["run_number"], row["id"], row["run_attempt"])))
    return sorted(selected, key=lambda row: row["path"])


def capture(pr_number: int, head: str, policy: policy_module.VerificationPolicy) -> Snapshot:
    before = api(f"pulls/{pr_number}")
    rules = api("rules/branches/main")
    files = paged(f"pulls/{pr_number}/files", None, 3000, before["changed_files"])
    checks = paged(f"commits/{head}/check-runs?filter=latest", "check_runs")
    # Enumerate suites independently so the check endpoint's suite limit is visible.
    suites = [suite_identity(row, head) for row in paged(f"commits/{head}/check-suites", "check_suites", 1000)]
    status = api(f"commits/{head}/status?per_page=1")
    status_pages = [{"page": 1, "per_page": 1, **status_identity(status, head)}]
    statuses = paged(
        f"commits/{head}/status",
        "statuses",
        expected=status["total_count"],
        status_head=head,
        page_evidence=status_pages,
    )
    runs = paged(f"actions/runs?head_sha={head}", "workflow_runs", 1000)
    jobs: dict[str, list[JsonObject]] = {}
    for run in selected_runs(runs):
        key = f"{run['id']}:{run['run_attempt']}"
        jobs[key] = paged(f"actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", "jobs")
    resolutions: dict[str, str] = {}
    for check in checks:
        if check["name"] == "CodSpeed Performance Analysis" and check["app"]["id"] == 257293:
            _, head_prefix, _, base_prefix = codspeed_comparison(check, policy)
            for prefix in (head_prefix, base_prefix):
                resolutions[prefix] = api(f"commits/{prefix}")["sha"]
    return {
        "codspeed_commit_resolutions": resolutions,
        "pr_start": before,
        "pr_end": api(f"pulls/{pr_number}"),
        "rules": rules,
        "files": files,
        "checks": checks,
        "status_sha": status["sha"],
        "statuses": statuses,
        "runs": runs,
        "jobs": jobs,
        "suite_ids": sorted(row["id"] for row in suites),
        "check_suites": suites,
        "status_pages": status_pages,
        "collection_complete": True,
    }


def pr_identity(pr: JsonObject) -> JsonObject:
    return {
        "number": pr["number"],
        "state": pr["state"],
        "draft": pr["draft"],
        "merged": pr["merged"],
        "mergeable": pr["mergeable"],
        "mergeable_state": pr.get("mergeable_state"),
        "merge_commit_sha": pr["merge_commit_sha"],
        "author": pr["user"]["login"],
        "changed_files": pr["changed_files"],
        "head": {
            "sha": pr["head"]["sha"],
            "ref": pr["head"]["ref"],
            "repo": pr["head"]["repo"]["full_name"],
        },
        "base": {
            "sha": pr["base"]["sha"],
            "ref": pr["base"]["ref"],
            "repo": pr["base"]["repo"]["full_name"],
        },
    }


def paths_for(files: list[JsonObject]) -> set[str]:
    paths = set()
    allowed = {
        "added",
        "removed",
        "modified",
        "renamed",
        "copied",
        "changed",
        "unchanged",
    }
    for row in files:
        if row["status"] not in allowed or not row.get("filename"):
            raise AdmissionError("Unknown changed-file metadata")
        paths.add(row["filename"])
        if row["status"] == "renamed" and not row.get("previous_filename"):
            raise AdmissionError("Renamed path lacks its original filename")
        if row.get("previous_filename"):
            paths.add(row["previous_filename"])
    return paths


def path_matches(path: str, pattern: str) -> bool:
    expression = re.escape(pattern).replace(r"\*\*/", "(?:.*/)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return re.fullmatch(expression, path) is not None


def expected_requirements(
    policy: policy_module.VerificationPolicy,
    paths: set[str],
    live_required: Iterable[tuple[str, int | None]] = (),
) -> list[policy_module.CheckIdentity]:
    rows: list[policy_module.CheckIdentity] = [*policy["baseline"], *policy["extra"]]
    rows += [
        row
        for row in policy["workflow_jobs"]
        if row["paths"] is None or any(path_matches(path, pattern) for path in paths for pattern in row["paths"])
    ]
    reviewed: list[policy_module.CheckIdentity] = [*policy["baseline"], *policy["extra"], *policy["workflow_jobs"]]
    for context, application in sorted(live_required, key=lambda pair: pair[0]):
        mappings = [row for row in reviewed if row["context"] == context and row["integration_id"] == application]
        if len({row["workflow"] for row in mappings}) != 1:
            raise AdmissionError("Live required check has missing or ambiguous reviewed workflow identity: " + context)
        # Server-required evidence takes precedence over ordinary path relevance.
        rows.append(mappings[-1])
    return list({(row["context"], row["integration_id"], row["workflow"]): row for row in rows}.values())


def codspeed_comparison(check: JsonObject, policy: policy_module.VerificationPolicy) -> tuple[str, str, str, str]:
    summary = check["output"]["summary"]
    pattern = (
        r"<sub>\s*Comparing <code>([^<]+)</code> \(([0-9a-f]{7,40})\) "
        r"with <code>([^<]+)</code> \(([0-9a-f]{7,40})\)\s*</sub>"
    )
    matches = re.findall(pattern, summary)
    if len(matches) != 1 or len(re.findall("Comparing", summary, re.IGNORECASE)) != 1:
        raise AdmissionError("CodSpeed comparison is missing, unparseable or ambiguous")
    match = matches[0]
    minimum = policy["codspeed_linkage"]["minimum_commit_prefix_length"]
    if len(match[1]) < minimum or len(match[3]) < minimum:
        raise AdmissionError("CodSpeed comparison commit prefix is shorter than policy permits")
    return html.unescape(match[0]), match[1], html.unescape(match[2]), match[3]


def timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise AdmissionError("Timestamp is missing or not text")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise AdmissionError("Timestamp lacks a timezone")
    return result


def check_codspeed_linkage(
    snapshot: Snapshot,
    selected: list[JsonObject],
    before: JsonObject,
    head: str,
    errors: list[str],
    policy: policy_module.VerificationPolicy,
) -> None:
    try:
        checks = [
            row
            for row in snapshot["checks"]
            if row["name"] == "CodSpeed Performance Analysis" and row["app"]["id"] == 257293
        ]
        runs = [row for row in selected if row["path"] == ".github/workflows/codspeed.yml"]
        if len(checks) != 1 or len(runs) != 1:
            raise AdmissionError("CodSpeed external/run identity is missing or ambiguous")
        external, run = checks[0], runs[0]
        jobs = snapshot["jobs"][f"{run['id']}:{run['run_attempt']}"]
        benchmarks = [
            step
            for job in jobs
            if job["name"] == "codspeed benchmarks (pilot, non-blocking)"
            for step in job["steps"]
            if step["name"] == "Run CodSpeed benchmarks"
        ]
        if len(benchmarks) != 1 or not success(benchmarks[0]):
            raise AdmissionError("CodSpeed benchmark step is missing or not successful")
        start, end = (
            timestamp(benchmarks[0]["started_at"]),
            timestamp(benchmarks[0]["completed_at"]),
        )
        external_end = timestamp(external["completed_at"])
        if not start <= end < external_end <= datetime.now(UTC):
            raise AdmissionError("CodSpeed external completion predates the selected benchmark or has invalid times")
        head_ref, head_prefix, base_ref, base_prefix = codspeed_comparison(external, policy)
        resolutions = snapshot["codspeed_commit_resolutions"]
        if (
            head_ref != before["head"]["ref"]
            or base_ref != before["base"]["ref"]
            or not head.startswith(head_prefix)
            or not before["base"]["sha"].startswith(base_prefix)
            or resolutions.get(head_prefix) != head
            or resolutions.get(base_prefix) != before["base"]["sha"]
        ):
            raise AdmissionError("CodSpeed comparison does not resolve to the reviewed head and current base")
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, OverflowError, AdmissionError) as exc:
        errors.append("CodSpeed linkage rejected: " + str(exc))


def container_relevant(paths: set[str]) -> bool:
    return any(path == "Dockerfile" or path.startswith("docker/") or path == CONTAINER for path in paths)


def success(row: Mapping[str, object]) -> bool:
    return row.get("status") == "completed" and row.get("conclusion") == "success"


def check_steps(
    job: JsonObject,
    run: JsonObject,
    paths: set[str],
    policy: policy_module.VerificationPolicy,
    errors: list[str],
    allowed: list[str],
) -> None:
    steps = job["steps"]
    by_name = {row["name"]: row for row in steps}
    if len(by_name) != len(steps) or not steps:
        errors.append("Missing or duplicate steps: " + job["name"])
    requirements = [
        row for row in policy["workflow_jobs"] if row["workflow"] == run["path"] and row["context"] == job["name"]
    ]
    required: set[str] = set()
    if run["path"] != MANAGED:
        if len(requirements) != 1:
            errors.append("Unreviewed repository workflow/job identity: " + job["name"])
        else:
            required = set(requirements[0]["mandatory_steps"])
            if not set(requirements[0]["steps"]) <= by_name.keys():
                errors.append("Missing source workflow step identities: " + job["name"])
    skipped: set[str] = set()
    if run["path"] == TEST and job["name"].startswith("pytest ("):
        match = re.fullmatch(r"pytest \((ubuntu|macos|windows)-latest, Python 3\.(12|14)\)", job["name"])
        if not match:
            errors.append("Unreviewed pytest matrix: " + job["name"])
        elif match[1] == "ubuntu":
            required |= {LINUX, CODECOV}
            skipped.add(NONLINUX)
        else:
            required.add(NONLINUX)
            skipped |= {LINUX, CODECOV}
        if not {LINUX, NONLINUX, CODECOV} <= by_name.keys():
            errors.append("Missing pytest branch evidence: " + job["name"])
    if run["path"] == TEST and job["name"] == "pytest no-extras (collector SSRF guard fidelity)":
        required.add("SSRF guard holds with zero drivers")
    if run["path"] == CONTAINER and job["name"] == "Build + smoke test":
        relevance = "Determine whether container-relevant paths changed"
        required.add(relevance)
        if not by_name.keys() >= CONTAINER_STEPS:
            errors.append("Missing container step evidence")
        if container_relevant(paths):
            required |= CONTAINER_STEPS
        elif success(by_name.get(relevance, {})):
            skipped |= CONTAINER_STEPS
    if run["path"] == MERIDIAN and job["name"] == "Meridian gap diff":
        required |= MERIDIAN_REQUIRED
        if all(success(by_name.get(name, {})) for name in MERIDIAN_REQUIRED):
            skipped.add(CACHE_SEED)
    for name in sorted(required):
        if not success(by_name.get(name, {})):
            errors.append("Mandatory step not successful: " + job["name"] + " / " + name)
    for step in steps:
        if success(step):
            continue
        if (
            step.get("status") == "completed"
            and step.get("conclusion") == "skipped"
            and step["name"] in skipped
            and step["name"] not in required
        ):
            allowed.append(job["name"] + " / " + step["name"])
        else:
            errors.append(
                "Step not successful: " + job["name"] + " / " + step["name"] + " = " + str(step.get("conclusion"))
            )


def check_suite_evidence(
    snapshot: Snapshot,
    selected: list[JsonObject],
    action_jobs: dict[int, tuple[str, bool]],
    head: str,
    errors: list[str],
) -> list[int]:
    """Keep empty automatic containers distinct from executed or rerequested suites."""
    suites = [suite_identity(cast(JsonObject, row), head) for row in snapshot["check_suites"]]
    suite_ids = [row["id"] for row in suites]
    if len(suite_ids) != len(set(suite_ids)) or sorted(suite_ids) != sorted(snapshot["suite_ids"]):
        errors.append("Check-suite identity inventory is incomplete or duplicated")
    selected_ids = {row["check_suite_id"] for row in selected}
    if not selected_ids <= set(suite_ids):
        errors.append("Selected workflow has no matching suite")
    idle: list[int] = []
    for suite in suites:
        suite_id = suite["id"]
        children = [row for row in snapshot["checks"] if row["check_suite"]["id"] == suite_id]
        if len(children) != suite["latest_check_runs_count"]:
            errors.append(f"Suite child count disagrees with current checks: {suite_id}")
        if any(row["head_sha"] != head or row["app"]["id"] != suite["app"]["id"] for row in children):
            errors.append(f"Suite child head/application binding failed: {suite_id}")
        if suite_id in selected_ids and suite["app"]["id"] != ACTIONS:
            errors.append(f"Selected workflow suite is not owned by Actions: {suite_id}")
        # GitHub creates suites before Apps create runs. This grants no required check.
        if (
            suite["status"] == "queued"
            and suite["conclusion"] is None
            and suite["latest_check_runs_count"] == 0
            and not children
            and suite_id not in selected_ids
        ):
            idle.append(suite_id)
            continue
        skipped_children = bool(children) and all(
            row["status"] == "completed"
            and row["conclusion"] == "skipped"
            and action_jobs.get(row["id"], ("", False))[1]
            for row in children
        )
        if not (
            suite["status"] == "completed"
            and children
            and (
                suite["conclusion"] == "success" or (skipped_children and suite["conclusion"] in {"neutral", "skipped"})
            )
        ):
            errors.append(f"Suite is not a successful or reviewed skipped execution: {suite_id}")
    return sorted(idle)


def evaluate(
    snapshot: Snapshot, policy: policy_module.VerificationPolicy, pr_number: int, head: str
) -> AdmissionResult:
    errors: list[str] = []
    allowed: list[str] = []
    bindings: list[JsonObject] = []
    empty_queued_suites: list[int] = []
    try:
        before, after = snapshot["pr_start"], snapshot["pr_end"]
        for pr in (before, after):
            ident = pr_identity(pr)
            if ident["number"] != pr_number or ident["head"]["sha"] != head:
                errors.append("PR number or reviewed head changed")
            if (
                ident["state"] != "open"
                or ident["draft"] is not False
                or ident["merged"] is not False
                or ident["mergeable"] is not True
            ):
                errors.append("PR is not open, nondraft, unmerged and confirmed mergeable")
            if (
                ident["base"]["ref"] != "main"
                or ident["base"]["repo"] != REPO
                or not re.fullmatch(r"[0-9a-f]{40}", ident["merge_commit_sha"] or "")
            ):
                errors.append("Invalid PR base or candidate merge identity")
        if pr_identity(before) != pr_identity(after):
            errors.append("PR eligibility changed during evidence collection")
        if (
            snapshot.get("collection_complete") is not True
            or len(snapshot["files"]) != before["changed_files"]
            or len(snapshot["files"]) >= 3000
        ):
            errors.append("Changed-file evidence is incomplete or truncated")
        paths = paths_for(snapshot["files"])
        rules = snapshot["rules"]
        live = {
            (row["context"], row.get("integration_id"))
            for rule in rules
            if rule["type"] == "required_status_checks"
            for row in rule["parameters"]["required_status_checks"]
        }
        baseline = {(row["context"], row["integration_id"]) for row in policy["baseline"]}
        if not baseline <= live:
            errors.append("Reviewed required context/application identities were removed or changed")
        known = {
            (row["context"], row["integration_id"])
            for row in [*policy["baseline"], *policy["extra"], *policy["workflow_jobs"]]
        }
        if live - known:
            errors.append("Unreviewed required context/application identities need policy review")
        if not any(rule["type"] == "merge_queue" for rule in rules):
            errors.append("Merge queue rule missing")
        expected = expected_requirements(policy, paths, live)
        checks = snapshot["checks"]
        if not checks or not snapshot["runs"]:
            errors.append("Current-head validation evidence is empty")
        by_id = {row["id"]: row for row in checks}
        if len(by_id) != len(checks):
            errors.append("Duplicate check identities")
        if len(snapshot["suite_ids"]) >= 1000 or not {row["check_suite"]["id"] for row in checks} <= set(
            snapshot["suite_ids"]
        ):
            errors.append("Check-suite evidence incomplete or truncated")
        selected = selected_runs(snapshot["runs"])
        action_jobs: dict[int, tuple[str, bool]] = {}
        for run in selected:
            path = run["path"]
            if (
                run["head_sha"] != head
                or run["repository"]["full_name"] != REPO
                or run["head_repository"]["full_name"] != before["head"]["repo"]["full_name"]
            ):
                errors.append("Workflow head/repository mismatch: " + path)
            managed = path == MANAGED and run["event"] == "dynamic" and run["pull_requests"] == []
            if not managed:
                matches = [
                    pr
                    for pr in run["pull_requests"]
                    if pr["number"] == pr_number
                    and pr["head"]["sha"] == head
                    and pr["head"]["repo"]["url"] == API_REPO
                    and pr["base"]["repo"]["url"] == API_REPO
                    and pr["base"]["sha"] == before["base"]["sha"]
                    and pr["base"]["ref"] == "main"
                ]
                if run["event"] != "pull_request" or len(matches) != 1:
                    errors.append("Workflow lacks the intended PR association: " + path)
            jobs = snapshot["jobs"][f"{run['id']}:{run['run_attempt']}"]
            bot_skip = (
                path == DEPENDABOT
                and before["user"]["login"] != "dependabot[bot]"
                and len(jobs) == 1
                and jobs[0]["name"] == DEPENDABOT_JOB
                and jobs[0]["conclusion"] == "skipped"
                and jobs[0]["status"] == "completed"
                and jobs[0]["steps"] == []
            )
            if not success(run) and not (bot_skip and run["status"] == "completed" and run["conclusion"] == "skipped"):
                errors.append("Workflow attempt not successful: " + path)
            if not jobs:
                errors.append("Workflow attempt has no job evidence: " + path)
            for job in jobs:
                check = by_id.get(job["id"])
                valid = (
                    check is not None
                    and job["id"] not in action_jobs
                    and job["run_id"] == run["id"]
                    and job["run_attempt"] == run["run_attempt"]
                    and job["head_sha"] == head
                    and job["check_run_url"] == API_REPO + f"/check-runs/{job['id']}"
                    and check["app"]["id"] == ACTIONS
                    and check["name"] == job["name"]
                    and check["check_suite"]["id"] == run["check_suite_id"]
                    and check["status"] == job["status"]
                    and check["conclusion"] == job["conclusion"]
                )
                if not valid:
                    errors.append("Job/check/run/attempt/suite binding failed: " + job["name"])
                    continue
                action_jobs[job["id"]] = (path, bot_skip)
                bindings.append(
                    {
                        "check_id": job["id"],
                        "name": job["name"],
                        "workflow": path,
                        "run_id": run["id"],
                        "attempt": run["run_attempt"],
                        "suite_id": run["check_suite_id"],
                    }
                )
                if bot_skip:
                    allowed.append(path + " / " + job["name"])
                else:
                    if not success(job):
                        errors.append("Job not successful: " + job["name"])
                    check_steps(job, run, paths, policy, errors, allowed)
        for check in checks:
            if check["head_sha"] != head:
                errors.append("Stale check head: " + check["name"])
            binding = action_jobs.get(check["id"])
            if check["app"]["id"] == ACTIONS and binding is None:
                errors.append("Actions check lacks a selected attempt binding: " + check["name"])
            if not success(check) and not (
                binding and binding[1] and check["conclusion"] == "skipped" and check["status"] == "completed"
            ):
                errors.append("Check not successful: " + check["name"])
        empty_queued_suites = check_suite_evidence(snapshot, selected, action_jobs, head, errors)
        for requirement in expected:
            matches = [
                check
                for check in checks
                if check["name"] == requirement["context"]
                and check["app"]["id"] == requirement["integration_id"]
                and (
                    requirement["workflow"] is None
                    or action_jobs.get(check["id"], (None,))[0] == requirement["workflow"]
                )
            ]
            accepted = len(matches) == 1 and (
                success(matches[0])
                or (
                    requirement.get("allow_non_dependabot_skip") is True
                    and action_jobs.get(matches[0]["id"], (None, False))[1]
                )
            )
            if not accepted:
                errors.append(
                    "Expected workflow/application check missing, ambiguous or not successful: "
                    + requirement["context"]
                )
        check_codspeed_linkage(snapshot, selected, before, head, errors, policy)
        if snapshot["status_sha"] != head:
            errors.append("Commit status aggregate belongs to another head")
        if not snapshot["status_pages"] or any(
            row.get("sha") != head
            or row.get("repository") != REPO
            or nonnegative_integer(row.get("total_count"), "Status page total_count") != len(snapshot["statuses"])
            for row in snapshot["status_pages"]
        ):
            errors.append("Status page envelope evidence is incomplete or inconsistent")
        contexts = [row["context"] for row in snapshot["statuses"]]
        if len(contexts) != len(set(contexts)):
            errors.append("Duplicate commit status contexts")
        for status in snapshot["statuses"]:
            if status["state"] != "success":
                errors.append("Commit status not successful: " + status["context"])
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, OverflowError, AdmissionError) as exc:
        errors.append("Malformed or incomplete evidence: " + type(exc).__name__ + " " + str(exc))
    return {
        "ready": not errors,
        "errors": sorted(set(errors)),
        "allowed_skips": sorted(allowed),
        "empty_queued_suites": empty_queued_suites,
        "bindings": bindings,
    }


def normalized(snapshot: Snapshot) -> JsonObject:
    # Retain all security-relevant raw check/run/job fields while dropping bulky,
    # unrelated provider presentation metadata. Sorting removes API order noise.
    def pick(row: JsonObject, keys: Iterable[str]) -> JsonObject:
        return {key: row.get(key) for key in keys}

    checks = [
        dict(
            pick(
                row,
                (
                    "id",
                    "name",
                    "head_sha",
                    "status",
                    "conclusion",
                    "started_at",
                    "completed_at",
                    "output",
                ),
            ),
            app_id=row["app"]["id"],
            suite_id=row["check_suite"]["id"],
        )
        for row in snapshot["checks"]
    ]
    run_keys = (
        "id",
        "path",
        "workflow_id",
        "run_number",
        "run_attempt",
        "check_suite_id",
        "head_sha",
        "event",
        "status",
        "conclusion",
        "updated_at",
        "pull_requests",
    )
    runs = [
        dict(
            pick(row, run_keys),
            repository=row["repository"]["full_name"],
            head_repository=row["head_repository"]["full_name"],
        )
        for row in snapshot["runs"]
    ]
    jobs = {
        key: sorted(
            [
                pick(
                    row,
                    (
                        "id",
                        "name",
                        "run_id",
                        "run_attempt",
                        "head_sha",
                        "status",
                        "conclusion",
                        "check_run_url",
                        "started_at",
                        "completed_at",
                        "steps",
                    ),
                )
                for row in values
            ],
            key=lambda row: row["id"],
        )
        for key, values in snapshot["jobs"].items()
    }
    return {
        "codspeed_commit_resolutions": snapshot["codspeed_commit_resolutions"],
        "pr_start": pr_identity(snapshot["pr_start"]),
        "pr_end": pr_identity(snapshot["pr_end"]),
        "rules": sorted(snapshot["rules"], key=digest),
        "files": sorted(
            [pick(row, ("filename", "previous_filename", "status", "sha")) for row in snapshot["files"]],
            key=lambda row: row["filename"],
        ),
        "checks": sorted(checks, key=lambda row: row["id"]),
        "status_sha": snapshot["status_sha"],
        "statuses": sorted(
            [pick(row, ("id", "context", "state", "created_at", "updated_at")) for row in snapshot["statuses"]],
            key=lambda row: row["id"],
        ),
        "runs": sorted(runs, key=lambda row: row["id"]),
        "jobs": jobs,
        "suite_ids": sorted(snapshot["suite_ids"]),
        "check_suites": sorted(snapshot["check_suites"], key=lambda row: row["id"]),
        "status_pages": snapshot["status_pages"],
        "collection_complete": snapshot["collection_complete"],
    }


def assess_pair(
    first: Snapshot, second: Snapshot, policy: policy_module.VerificationPolicy, pr_number: int, head: str
) -> AdmissionResult:
    result = evaluate(first, policy, pr_number, head)
    other = evaluate(second, policy, pr_number, head)
    result["errors"] += other["errors"]
    try:
        snapshots = [normalized(item) for item in (first, second)]
        hashes = [digest(item) for item in snapshots]
        result["snapshot_sha256"] = hashes
        result["snapshots"] = snapshots
        if hashes[0] != hashes[1]:
            result["errors"].append("Normalized evidence changed between complete snapshots")
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, OverflowError) as exc:
        result["errors"].append("Snapshot normalization failed: " + type(exc).__name__)
    result["errors"] = sorted(set(result["errors"]))
    result["ready"] = not result["errors"]
    return result


def write_receipt(path: Path, receipt: JsonObject, protected: Iterable[Path] = ()) -> None:
    """Replace the chosen receipt atomically without writing through source aliases."""
    for source in protected:
        if path.resolve() == source.resolve() or (path.exists() and source.exists() and os.path.samefile(path, source)):
            raise AdmissionError("Receipt would overwrite a protected source")
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    created = False
    try:
        with temporary.open("x", encoding="ascii", newline="\n") as handle:
            created = True
            handle.write(json.dumps(receipt, indent=2, ensure_ascii=True, allow_nan=False) + "\n")
        os.replace(temporary, path)
    finally:
        if created and temporary.exists():
            temporary.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--head", required=True)
    parser.add_argument("--policy", type=Path, default=policy_module.POLICY_PATH)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    started = datetime.now(UTC)
    receipt: JsonObject = {
        "version": 2,
        "invocation_id": str(uuid.uuid4()),
        "repository": REPO,
        "pr": args.pr,
        "expected_head": args.head,
        "started_at": started.isoformat(),
        "ready": False,
        "errors": [],
        "policy_sha256": policy_module.POLICY_SHA256,
        "checker_sha256": hashlib.sha256(policy_module.normalized_bytes(Path(__file__).read_bytes())).hexdigest(),
        "limits": LIMITS,
        "remote_mutations": False,
    }
    try:
        if args.pr <= 0 or not re.fullmatch(r"[0-9a-f]{40}", args.head):
            raise AdmissionError("Invalid PR number or full reviewed head SHA")
        policy = load_policy(args.policy)
        first = capture(args.pr, args.head, policy)
        second = capture(args.pr, args.head, policy)
        receipt.update(assess_pair(first, second, policy, args.pr, args.head))
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        IndexError,
        OverflowError,
        AdmissionError,
        subprocess.SubprocessError,
    ) as exc:
        receipt["ready"] = False
        receipt["errors"].append("Admission collection failed: " + type(exc).__name__ + " " + str(exc))
    completed = datetime.now(UTC)
    receipt["completed_at"] = completed.isoformat()
    receipt["expires_at"] = (completed + timedelta(seconds=120)).isoformat()
    try:
        write_receipt(
            args.output,
            receipt,
            (args.policy, policy_module.POLICY_PATH, Path(policy_module.__file__), Path(__file__)),
        )
    except (OSError, ValueError, AdmissionError) as exc:
        print(
            json.dumps(
                {
                    "ready": False,
                    "invocation_id": receipt["invocation_id"],
                    "error": "Receipt write failed: " + str(exc),
                },
                ensure_ascii=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "ready": receipt["ready"],
                "invocation_id": receipt["invocation_id"],
                "errors": receipt["errors"],
            },
            ensure_ascii=True,
        )
    )
    return 0 if receipt["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
