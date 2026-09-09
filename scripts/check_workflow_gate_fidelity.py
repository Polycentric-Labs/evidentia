"""Check reviewed workflow identities and the execution rules of enforced gates."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import re
import shlex
import sys
from pathlib import Path
from typing import cast

import yaml
from verification_policy import (
    PolicyError,
    VerificationPolicy,
    WorkflowJob,
    load_policy,
    normalized_bytes,
    validate_policy,
)
from yaml.events import AliasEvent
from yaml.nodes import MappingNode

ROOT = Path(__file__).resolve().parents[1]

TEST_WORKFLOW = ".github/workflows/test.yml"
CONTAINER_WORKFLOW = ".github/workflows/container-build.yml"
REFRESH_WORKFLOW = ".github/workflows/catalog-refresh.yml"
DEPENDABOT_WORKFLOW = ".github/workflows/dependabot-auto-merge.yml"
PR_ONLY = {".github/workflows/codspeed.yml", ".github/workflows/cflite-pr.yml"}
MATRIX_EXPRESSION = re.compile(r"\$\{\{\s*matrix\.([a-zA-Z_][a-zA-Z0-9_-]*)\s*\}\}")
DEPENDABOT_JOB_IF = "github.event.pull_request.user.login == 'dependabot[bot]'"
DEPENDABOT_STEP_IF = (
    "steps.meta.outputs.update-type == 'version-update:semver-patch' "
    "&& steps.meta.outputs.dependency-group != '' "
    "&& steps.meta.outputs.dependency-group != 'python-frameworks' "
    "&& (steps.meta.outputs.package-ecosystem == 'uv' "
    "|| steps.meta.outputs.package-ecosystem == 'pip' "
    "|| steps.meta.outputs.package-ecosystem == 'npm')"
)


class WorkflowFidelityError(ValueError):
    """A workflow cannot be matched to its reviewed execution contract."""


class _WorkflowLoader(yaml.SafeLoader):
    """Keep the Actions event name 'on' a string without weakening booleans."""


_WorkflowLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:bool"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"), list("tTfF")
)


def _unique_mapping(loader: yaml.SafeLoader, node: MappingNode) -> dict[str, object]:
    result: dict[str, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise WorkflowFidelityError("YAML has a duplicate or non-string mapping key")
        result[key] = loader.construct_object(value_node)
    return result


_WorkflowLoader.add_constructor("tag:yaml.org,2002:map", _unique_mapping)


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise WorkflowFidelityError(label + " must be a mapping")
    return cast(dict[str, object], value)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WorkflowFidelityError(label + " must be a nonblank string")
    return value


def _fields(value: dict[str, object], allowed: set[str], label: str) -> None:
    unknown = value.keys() - allowed
    if unknown:
        raise WorkflowFidelityError("Unsupported " + label + " fields: " + ", ".join(sorted(unknown)))


def _execution_controls(value: dict[str, object]) -> None:
    if "if" in value and (not isinstance(value["if"], str) or not value["if"].strip()):
        raise WorkflowFidelityError("Invalid conditional execution field")
    if "continue-on-error" in value and type(value["continue-on-error"]) is not bool:
        raise WorkflowFidelityError("Invalid failure suppression field")


def parse_workflow(raw: bytes) -> dict[str, object]:
    """Reject YAML ambiguity before interpreting GitHub-specific fields."""
    try:
        if any(isinstance(event, AliasEvent) for event in yaml.parse(raw)):
            raise WorkflowFidelityError("YAML aliases require explicit review")
        document: object = yaml.load(raw, Loader=_WorkflowLoader)
    except (yaml.YAMLError, UnicodeError, RecursionError, ValueError) as exc:
        raise WorkflowFidelityError("Invalid workflow YAML: " + str(exc)) from exc
    workflow = _mapping(document, "workflow")
    _fields(workflow, {"name", "run-name", "on", "permissions", "env", "defaults", "concurrency", "jobs"}, "workflow")
    return workflow


def _events(workflow: dict[str, object]) -> dict[str, object]:
    value = workflow.get("on")
    if isinstance(value, str):
        return {_text(value, "event"): None}
    if isinstance(value, list):
        names = [_text(item, "event") for item in value]
        if not names or len(names) != len(set(names)):
            raise WorkflowFidelityError("Duplicate or empty event coverage")
        return dict.fromkeys(names)
    return _mapping(value, "event coverage")


def _render(value: object, matrix: dict[str, str], label: str) -> str:
    text = _text(value, label)

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in matrix:
            raise WorkflowFidelityError("Unknown matrix expression in " + label)
        return matrix[key]

    text = MATRIX_EXPRESSION.sub(replace, text)
    if "${{" in text or "}}" in text:
        raise WorkflowFidelityError("Unsupported expression in " + label)
    return text


def _matrices(job: dict[str, object]) -> list[dict[str, str]]:
    if "strategy" not in job:
        return [{}]
    strategy = _mapping(job["strategy"], "matrix strategy")
    if strategy.keys() - {"matrix", "fail-fast", "max-parallel"}:
        raise WorkflowFidelityError("Unsupported matrix strategy")
    if "fail-fast" in strategy and strategy["fail-fast"] is not False:
        raise WorkflowFidelityError("matrix fail-fast can cancel reviewed checks")
    if "max-parallel" in strategy and (
        type(strategy["max-parallel"]) is not int or cast(int, strategy["max-parallel"]) < 1
    ):
        raise WorkflowFidelityError("Unsupported matrix max-parallel")
    dimensions = _mapping(strategy.get("matrix"), "matrix")
    if not dimensions or dimensions.keys() & {"include", "exclude"}:
        raise WorkflowFidelityError("Empty or unsupported matrix include/exclude")
    values: list[list[str]] = []
    count = 1
    for key, choices in dimensions.items():
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]*", key) or not isinstance(choices, list) or not choices:
            raise WorkflowFidelityError("Invalid matrix dimension")
        names = [_render(item, {}, "matrix value") for item in choices]
        if len(names) != len(set(names)):
            raise WorkflowFidelityError("Duplicate matrix value")
        count *= len(names)
        if count > 256:
            raise WorkflowFidelityError("matrix exceeds the supported 256 job bound")
        values.append(names)
    return [dict(zip(dimensions, combination, strict=True)) for combination in itertools.product(*values)]


def _condition(value: object) -> str | None:
    if value is None:
        return None
    expression = _text(value, "conditional expression").strip()
    if expression.startswith("${{") and expression.endswith("}}"):
        expression = expression[3:-2].strip()
    return " ".join(expression.split())


def _step_condition(path: str, job_id: str, name: str, index: int) -> str | None:
    if path == CONTAINER_WORKFLOW and job_id == "build" and index >= 2:
        return "steps.relevant.outputs.relevant == 'true'"
    if path == TEST_WORKFLOW and job_id == "test":
        return {
            "Run tests (with coverage on Linux)": "matrix.os == 'ubuntu-latest'",
            "Run tests (no coverage on non-Linux)": "matrix.os != 'ubuntu-latest'",
            "Upload coverage to Codecov": "matrix.os == 'ubuntu-latest'",
        }.get(name)
    if (
        path == DEPENDABOT_WORKFLOW
        and job_id == "auto-merge"
        and name == "Enable auto-merge for in-scope patch updates"
    ):
        return DEPENDABOT_STEP_IF
    if path == ".github/workflows/evidentia.yml" and job_id == "compliance":
        return {
            "Seed baseline on cache miss (first run ever or key bump)": "steps.baseline.outputs.cache-hit != 'true'",
            "Gap diff (markdown for PR comment)": "github.event_name == 'pull_request'",
            "Post PR comment": "always() && github.event_name == 'pull_request'",
            "Gate on regressions": "github.event_name == 'pull_request'",
        }.get(name)
    return None


def _suppression(value: object, *, allowed: bool, label: str) -> None:
    if value is False or value is None:
        return
    if value is True and allowed:
        return
    raise WorkflowFidelityError("Unreviewed failure suppression in " + label)


def _effective_run_setting(
    workflow: dict[str, object], job: dict[str, object], step: dict[str, object], key: str
) -> object:
    result: object = None
    for owner in (workflow, job):
        defaults = _mapping(owner.get("defaults", {}), "run defaults")
        run_defaults = _mapping(defaults.get("run", {}), "run defaults")
        result = run_defaults.get(key, result)
    return step.get(key, result)


def _commands(value: object) -> list[str]:
    return [
        line.strip()
        for line in _text(value, "run command").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _vitest(workflow: dict[str, object], job: dict[str, object], step: dict[str, object]) -> None:
    lines = _commands(step.get("run"))
    try:
        tokens = shlex.split(lines[0]) if len(lines) == 1 else []
    except ValueError as exc:
        raise WorkflowFidelityError("Invalid Vitest command") from exc
    if tokens != ["npm", "run", "test", "--", "--run"]:
        raise WorkflowFidelityError("Vitest must run directly with its reviewed arguments")
    if _effective_run_setting(workflow, job, step, "shell") not in {None, "bash", "sh"}:
        raise WorkflowFidelityError("Unreviewed Vitest shell can hide failure")
    if _effective_run_setting(workflow, job, step, "working-directory") != "packages/evidentia-ui":
        raise WorkflowFidelityError("Vitest must run in the frontend directory")
    if _render(job.get("runs-on"), {}, "Vitest runner") != "ubuntu-latest":
        raise WorkflowFidelityError("Unreviewed Vitest runner")


def _container_catalog(workflow: dict[str, object], job: dict[str, object], step: dict[str, object]) -> None:
    expected = [
        'output="${RUNNER_TEMP:?RUNNER_TEMP is required}/evidentia-catalog-smoke.txt"',
        "trap 'rm -f \"$output\"' EXIT",
        'docker run --rm evidentia:smoke catalog list > "$output"',
        'test -s "$output"',
        'head -n 10 "$output"',
    ]
    if _commands(step.get("run")) != expected or _effective_run_setting(workflow, job, step, "shell") != "bash":
        raise WorkflowFidelityError("Container catalog must enforce capture, nonempty output, and display in Bash")


def _catalog_refresh(workflow: dict[str, object]) -> None:
    jobs = _mapping(workflow.get("jobs"), "catalog refresh jobs")
    job = _mapping(jobs.get("refresh"), "catalog refresh job")
    if "if" in job or "needs" in job:
        raise WorkflowFidelityError("Unreviewed catalog refresh conditional")
    _suppression(job.get("continue-on-error"), allowed=False, label="catalog refresh")
    steps = job.get("steps")
    if not isinstance(steps, list):
        raise WorkflowFidelityError("Missing catalog refresh steps")
    matches = [
        _mapping(step, "catalog refresh step")
        for step in steps
        if isinstance(step, dict) and step.get("name") == "Regenerate manifest from disk"
    ]
    if len(matches) != 1:
        raise WorkflowFidelityError("Missing or duplicate catalog refresh producer")
    step = matches[0]
    _suppression(step.get("continue-on-error"), allowed=False, label="catalog refresh")
    if "if" in step or "uses" in step:
        raise WorkflowFidelityError("Unreviewed catalog refresh conditional or action")
    commands = _commands(step.get("run"))
    if _effective_run_setting(workflow, job, step, "shell") != "bash" or commands[:2] != [
        "set -euo pipefail",
        "uv run --locked python scripts/catalogs/regenerate_manifest.py | tee regen.out",
    ]:
        raise WorkflowFidelityError("Catalog refresh must enforce Bash pipefail before the generator pipeline")


def _coverage(path: str, events: dict[str, object], rows: list[WorkflowJob], required: bool) -> None:
    if "pull_request" not in events or (required and "merge_group" not in events):
        raise WorkflowFidelityError(path + ": missing PR or merge_group coverage")
    if path in PR_ONLY and "merge_group" in events:
        raise WorkflowFidelityError(path + ": this assurance remains PR-only")
    if "pull_request_target" in events:
        raise WorkflowFidelityError(path + ": unsupported PR target coverage")
    expected_paths = rows[0]["paths"]
    if any(row["paths"] != expected_paths for row in rows):
        raise WorkflowFidelityError(path + ": conflicting reviewed paths")
    for event in ("pull_request", "merge_group"):
        if event not in events:
            continue
        config = _mapping({} if events[event] is None else events[event], event + " coverage")
        if config.keys() - {"branches", "paths", "types"}:
            raise WorkflowFidelityError(path + ": unsupported event coverage filters")
        if "branches" in config and config["branches"] != ["main"]:
            raise WorkflowFidelityError(path + ": event coverage excludes the reviewed main branch")
        expected = expected_paths if event == "pull_request" else None
        if config.get("paths") != expected or (required and expected is not None):
            raise WorkflowFidelityError(path + ": event paths differ from reviewed coverage")
        if "types" in config:
            types = config["types"]
            needed = {"opened", "synchronize", "reopened"} if event == "pull_request" else {"checks_requested"}
            if not isinstance(types, list) or any(not isinstance(item, str) for item in types) or set(types) != needed:
                raise WorkflowFidelityError(path + ": unsupported event type coverage")


def _check_job(
    path: str, job_id: str, job: dict[str, object], workflow: dict[str, object], rows: list[WorkflowJob]
) -> None:
    _fields(
        job,
        {
            "name",
            "runs-on",
            "permissions",
            "environment",
            "concurrency",
            "outputs",
            "env",
            "defaults",
            "steps",
            "timeout-minutes",
            "strategy",
            "continue-on-error",
            "container",
            "services",
            "if",
            "needs",
            "uses",
            "with",
            "secrets",
        },
        "job",
    )
    _execution_controls(job)
    if "uses" in job or "needs" in job:
        raise WorkflowFidelityError(path + ": unsupported reusable or dependent job")
    expected_if = DEPENDABOT_JOB_IF if path == DEPENDABOT_WORKFLOW and job_id == "auto-merge" else None
    if _condition(job.get("if")) != expected_if:
        raise WorkflowFidelityError(path + ": unreviewed job conditional")
    _suppression(
        job.get("continue-on-error"),
        allowed=path == TEST_WORKFLOW and job_id in {"uv-audit", "uv-malware-check"},
        label=job_id,
    )
    steps_value = job.get("steps")
    if not isinstance(steps_value, list) or not steps_value:
        raise WorkflowFidelityError(path + ": missing job steps")
    steps = [_mapping(step, "step") for step in steps_value]
    ids: set[str] = set()
    for step in steps:
        _fields(
            step,
            {
                "name",
                "id",
                "if",
                "uses",
                "run",
                "shell",
                "working-directory",
                "with",
                "env",
                "continue-on-error",
                "timeout-minutes",
            },
            "step",
        )
        _execution_controls(step)
        if ("uses" in step) == ("run" in step):
            raise WorkflowFidelityError(path + ": step must select exactly one run or uses")
        _text(step.get("uses") if "uses" in step else step.get("run"), "step action or command")
        if "id" in step:
            step_id = _text(step["id"], "step id")
            if step_id in ids or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]*", step_id):
                raise WorkflowFidelityError(path + ": duplicate or invalid step id")
            ids.add(step_id)
    contexts: set[str] = set()
    for matrix in _matrices(job):
        context = _render(job.get("name", job_id), matrix, "job context")
        if context in contexts:
            raise WorkflowFidelityError(path + ": ambiguous matrix job context")
        contexts.add(context)
        matches = [row for row in rows if row["context"] == context]
        if len(matches) != 1:
            raise WorkflowFidelityError(path + ": unreviewed job context " + context)
        _render(job.get("runs-on"), matrix, "job runner")
        names = []
        for step in steps:
            default_name = "Run " + _text(step["uses"], "step uses") if "uses" in step else None
            names.append(_render(step.get("name", default_name), matrix, "step name"))
        if len(names) != len(set(names)) or names != matches[0]["steps"]:
            raise WorkflowFidelityError(path + ": ordered step identities differ in " + context)
        for index, (name, step) in enumerate(zip(names, steps, strict=True)):
            if _condition(step.get("if")) != _step_condition(path, job_id, name, index):
                raise WorkflowFidelityError(path + ": unreviewed step conditional in " + name)
            advisory = (
                path == ".github/workflows/codspeed.yml"
                and job_id == "benchmarks"
                and name == "Run CodSpeed benchmarks"
            ) or (
                path == ".github/workflows/evidentia.yml"
                and job_id == "compliance"
                and name == "Gap diff (markdown for PR comment)"
            )
            _suppression(step.get("continue-on-error"), allowed=advisory, label=name)
            if path == TEST_WORKFLOW and job_id == "frontend-test" and name == "Vitest unit tests":
                _vitest(workflow, job, step)
            if (
                path == CONTAINER_WORKFLOW
                and job_id == "build"
                and name == "Smoke test \u2014 `evidentia catalog list`"
            ):
                _container_catalog(workflow, job, step)
    if contexts != {row["context"] for row in rows}:
        raise WorkflowFidelityError(path + ": missing reviewed matrix job contexts")


def validate_workflows(root: Path, policy: VerificationPolicy) -> None:
    """Compare local sources with the reviewed policy without contacting GitHub."""
    policy = validate_policy(policy)
    source_paths = set(policy["workflow_sources"])
    if not (root / REFRESH_WORKFLOW).is_file():
        raise WorkflowFidelityError("Missing catalog refresh workflow")
    for path in sorted(source_paths):
        source = root / path
        if not source.is_file():
            raise WorkflowFidelityError("Missing reviewed workflow: " + path)
        if hashlib.sha256(normalized_bytes(source.read_bytes())).hexdigest() != policy["workflow_sources"][path]:
            raise WorkflowFidelityError("Workflow source digest differs from review: " + path)
    required = {row["workflow"] for row in policy["baseline"] if row["workflow"] is not None}
    seen_names: set[str] = set()
    for source in sorted((root / ".github/workflows").iterdir()):
        if source.suffix not in {".yml", ".yaml"}:
            continue
        path = source.relative_to(root).as_posix()
        workflow = parse_workflow(source.read_bytes())
        events = _events(workflow)
        if path == REFRESH_WORKFLOW:
            _catalog_refresh(workflow)
        if path not in source_paths:
            if events.keys() & {"pull_request", "pull_request_target", "merge_group"}:
                raise WorkflowFidelityError("Unreviewed pre-merge workflow: " + path)
            continue
        name = _render(workflow.get("name"), {}, "workflow name")
        if name in seen_names:
            raise WorkflowFidelityError("Duplicate workflow name: " + name)
        seen_names.add(name)
        rows = [row for row in policy["workflow_jobs"] if row["workflow"] == path]
        _coverage(path, events, rows, path in required)
        jobs = _mapping(workflow.get("jobs"), "workflow jobs")
        if set(jobs) != {row["job_id"] for row in rows}:
            raise WorkflowFidelityError(path + ": complete job identities differ from review")
        for job_id, job in jobs.items():
            _check_job(path, job_id, _mapping(job, "job"), workflow, [row for row in rows if row["job_id"] == job_id])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        validate_workflows(args.root.resolve(), load_policy())
    except (WorkflowFidelityError, PolicyError, OSError) as exc:
        print("Workflow gate fidelity failed: " + str(exc), file=sys.stderr)
        return 1
    print("Workflow gate fidelity passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
