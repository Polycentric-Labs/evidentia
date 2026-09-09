"""Exercise workflow semantics after fixture source hashes have been reviewed."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
FRONTEND = ".github/workflows/test.yml"


@pytest.fixture(scope="module")
def guard() -> Any:
    spec = importlib.util.spec_from_file_location(
        "workflow_fidelity_test", ROOT / "scripts/check_workflow_gate_fidelity.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with pytest.MonkeyPatch.context() as patch:
        patch.syspath_prepend(str(ROOT / "scripts"))
        spec.loader.exec_module(module)
    return module


@pytest.fixture
def checkout(tmp_path: Path, guard: Any) -> tuple[Path, dict[str, Any]]:
    policy = copy.deepcopy(guard.load_policy())
    target = tmp_path / ".github/workflows"
    target.mkdir(parents=True)
    for source in (ROOT / ".github/workflows").iterdir():
        if source.suffix in {".yml", ".yaml"}:
            (target / source.name).write_bytes(source.read_bytes())
    return tmp_path, policy


def write_workflow(checkout: tuple[Path, dict[str, Any]], path: str, value: object) -> None:
    root, policy = checkout
    raw = yaml.safe_dump(value, sort_keys=False, allow_unicode=True).encode("utf-8")
    (root / path).write_bytes(raw)
    if path in policy["workflow_sources"]:
        policy["workflow_sources"][path] = hashlib.sha256(raw).hexdigest()


def frontend(checkout: tuple[Path, dict[str, Any]], guard: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    workflow = guard.parse_workflow((checkout[0] / FRONTEND).read_bytes())
    job = workflow["jobs"]["frontend-test"]
    return workflow, job


def test_reviewed_workflows_pass(guard: Any) -> None:
    guard.validate_workflows(ROOT, guard.load_policy())


def test_crlf_does_not_change_source_identity(checkout: tuple[Path, dict[str, Any]], guard: Any) -> None:
    path = checkout[0] / FRONTEND
    path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    guard.validate_workflows(*checkout)


def test_unreviewed_source_bytes_reject(checkout: tuple[Path, dict[str, Any]], guard: Any) -> None:
    path = checkout[0] / FRONTEND
    path.write_bytes(path.read_bytes() + b"\n# Unreviewed change\n")
    with pytest.raises(guard.WorkflowFidelityError, match="digest"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize(
    "command",
    [
        "npm run test -- --run || true",
        "npm run test -- --run; exit 0",
        "npm run test -- --run\necho done",
        "set +e\nnpm run test -- --run",
        "if npm run test -- --run; then echo done; fi",
        "npm run test -- --run | cat",
        "echo npm run test -- --run",
        "npm run test -- --run &",
        "npm run test -- --run --passWithNoTests",
    ],
)
def test_vitest_shell_masking_rejects_after_rehash(
    checkout: tuple[Path, dict[str, Any]], guard: Any, command: str
) -> None:
    workflow, job = frontend(checkout, guard)
    next(step for step in job["steps"] if step["name"] == "Vitest unit tests")["run"] = command
    write_workflow(checkout, FRONTEND, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match="Vitest"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize("level", ["job", "step"])
@pytest.mark.parametrize("field,value", [("continue-on-error", True), ("if", "false"), ("if", "always()")])
def test_frontend_skip_and_suppression_reject(
    checkout: tuple[Path, dict[str, Any]], guard: Any, level: str, field: str, value: object
) -> None:
    workflow, job = frontend(checkout, guard)
    target = job if level == "job" else next(step for step in job["steps"] if step["name"] == "Vitest unit tests")
    target[field] = value
    write_workflow(checkout, FRONTEND, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match=r"conditional|suppression"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize("level", ["workflow", "job", "step"])
def test_custom_vitest_shell_cannot_swallow_exit(checkout: tuple[Path, dict[str, Any]], guard: Any, level: str) -> None:
    workflow, job = frontend(checkout, guard)
    if level == "step":
        next(step for step in job["steps"] if step["name"] == "Vitest unit tests")["shell"] = "bash {0}; exit 0"
    else:
        (workflow if level == "workflow" else job)["defaults"] = {"run": {"shell": "bash {0}; exit 0"}}
    write_workflow(checkout, FRONTEND, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match="shell"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize("event", ["pull_request", "merge_group"])
def test_required_events_cannot_disappear(checkout: tuple[Path, dict[str, Any]], guard: Any, event: str) -> None:
    workflow, _ = frontend(checkout, guard)
    del workflow["on"][event]
    write_workflow(checkout, FRONTEND, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match="coverage"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize(
    "filters",
    [{"paths": ["docs/**"]}, {"paths-ignore": ["**"]}, {"branches": ["other"]}, {"types": ["closed"]}],
)
def test_required_pr_event_cannot_filter_out_checks(
    checkout: tuple[Path, dict[str, Any]], guard: Any, filters: dict[str, object]
) -> None:
    workflow, _ = frontend(checkout, guard)
    workflow["on"]["pull_request"] = filters
    write_workflow(checkout, FRONTEND, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match=r"coverage|paths"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize("path", [".github/workflows/codspeed.yml", ".github/workflows/cflite-pr.yml"])
def test_unsupported_queue_assurance_is_not_invented(
    checkout: tuple[Path, dict[str, Any]], guard: Any, path: str
) -> None:
    workflow = guard.parse_workflow((checkout[0] / path).read_bytes())
    workflow["on"]["merge_group"] = None
    write_workflow(checkout, path, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match="PR-only"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize("mutation", ["extra", "missing", "rename", "duplicate"])
def test_complete_job_identities_are_enforced(checkout: tuple[Path, dict[str, Any]], guard: Any, mutation: str) -> None:
    workflow, job = frontend(checkout, guard)
    if mutation == "extra":
        workflow["jobs"]["extra"] = {"name": "Other check", "runs-on": "ubuntu-latest", "steps": [{"run": "true"}]}
    elif mutation == "missing":
        del workflow["jobs"]["frontend-test"]
    elif mutation == "rename":
        job["name"] = "Other frontend"
    else:
        workflow["jobs"]["extra"] = copy.deepcopy(job)
    write_workflow(checkout, FRONTEND, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match=r"job|context"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize("mutation", ["remove", "duplicate", "reverse", "blank", "expression"])
def test_complete_step_identities_are_enforced(
    checkout: tuple[Path, dict[str, Any]], guard: Any, mutation: str
) -> None:
    workflow, job = frontend(checkout, guard)
    if mutation == "remove":
        job["steps"].pop(0)
    elif mutation == "duplicate":
        job["steps"].append(copy.deepcopy(job["steps"][0]))
    elif mutation == "reverse":
        job["steps"].reverse()
    else:
        job["steps"][0]["name"] = "" if mutation == "blank" else "${{ github.actor }}"
    write_workflow(checkout, FRONTEND, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match=r"step|expression"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize(
    "matrix",
    [
        "${{ fromJSON(needs.prepare.outputs.matrix) }}",
        {"os": ["ubuntu-latest", "ubuntu-latest"]},
        {"os": []},
        {"os": ["ubuntu-latest"], "include": [{"os": "other"}]},
        {"os": ["ubuntu-latest"], "exclude": [{"os": "ubuntu-latest"}]},
        {"os": ["ubuntu-latest"], "python-version": [3.12]},
    ],
)
def test_unsupported_or_ambiguous_matrix_fails_closed(
    checkout: tuple[Path, dict[str, Any]], guard: Any, matrix: object
) -> None:
    workflow, _ = frontend(checkout, guard)
    workflow["jobs"]["test"]["strategy"]["matrix"] = matrix
    write_workflow(checkout, FRONTEND, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match="matrix"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize(
    "raw",
    [
        b"name: One\nname: Two\non: pull_request\njobs: {}\n",
        b"name: Test\non: pull_request\non: merge_group\njobs: {}\n",
        b"name: Test\non: pull_request\njobs:\n  test: {}\n  test: {}\n",
        b"name: Test\non: pull_request\njobs:\n  test:\n    name: A\n    name: B\n",
        b"name: Test\non: pull_request\njobs: [broken\n",
        b"name: Test\non: pull_request\njobs: !custom {}\n",
        b"name: Test\non: pull_request\njobs: &a {copy: *a}\n",
        b"name: Test\non: pull_request\njobs: {}\n---\nname: Other\n",
        b"[]\n",
    ],
)
def test_malformed_yaml_rejects(raw: bytes, guard: Any) -> None:
    with pytest.raises(guard.WorkflowFidelityError, match=r"YAML|workflow"):
        guard.parse_workflow(raw)


def test_missing_source_fails_closed(checkout: tuple[Path, dict[str, Any]], guard: Any) -> None:
    (checkout[0] / FRONTEND).unlink()
    with pytest.raises(guard.WorkflowFidelityError, match="Missing"):
        guard.validate_workflows(*checkout)


def test_new_pr_workflow_requires_policy_review(checkout: tuple[Path, dict[str, Any]], guard: Any) -> None:
    write_workflow(checkout, ".github/workflows/other.yml", {"name": "Other", "on": ["pull_request"], "jobs": {}})
    with pytest.raises(guard.WorkflowFidelityError, match="Unreviewed"):
        guard.validate_workflows(*checkout)


def test_path_policy_must_match_source(checkout: tuple[Path, dict[str, Any]], guard: Any) -> None:
    path = ".github/workflows/cflite-pr.yml"
    workflow = guard.parse_workflow((checkout[0] / path).read_bytes())
    workflow["on"]["pull_request"]["paths"] = ["tests/fuzz/**"]
    write_workflow(checkout, path, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match="paths"):
        guard.validate_workflows(*checkout)


def test_reviewed_condition_cannot_move_to_vitest(checkout: tuple[Path, dict[str, Any]], guard: Any) -> None:
    workflow, job = frontend(checkout, guard)
    next(step for step in job["steps"] if step["name"] == "Vitest unit tests")["if"] = "matrix.os == 'ubuntu-latest'"
    write_workflow(checkout, FRONTEND, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match="conditional"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize("level", ["workflow", "job", "step"])
def test_unknown_execution_fields_reject(checkout: tuple[Path, dict[str, Any]], guard: Any, level: str) -> None:
    workflow, job = frontend(checkout, guard)
    targets = {"workflow": workflow, "job": job, "step": job["steps"][0]}
    targets[level]["continue_on_error"] = True
    write_workflow(checkout, FRONTEND, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match="Unsupported"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize("level", ["job", "step"])
@pytest.mark.parametrize("field", ["if", "continue-on-error"])
def test_null_execution_controls_reject(
    checkout: tuple[Path, dict[str, Any]], guard: Any, level: str, field: str
) -> None:
    workflow, job = frontend(checkout, guard)
    target = job if level == "job" else job["steps"][0]
    target[field] = None
    write_workflow(checkout, FRONTEND, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match="Invalid"):
        guard.validate_workflows(*checkout)


def test_cli_reports_source_failure(checkout: tuple[Path, dict[str, Any]], guard: Any, capsys: Any) -> None:
    (checkout[0] / FRONTEND).unlink()
    assert guard.main(["--root", str(checkout[0])]) == 1
    assert "Missing" in capsys.readouterr().err


def test_accepted_vitest_command_propagates_actual_shell_failure(guard: Any, tmp_path: Path) -> None:
    workflow = guard.parse_workflow((ROOT / FRONTEND).read_bytes())
    job = workflow["jobs"]["frontend-test"]
    step = next(step for step in job["steps"] if step["name"] == "Vitest unit tests")
    guard.validate_workflows(ROOT, guard.load_policy())
    bash = shutil.which("bash")
    assert bash is not None, "The supported CI platforms provide Bash"
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", "npm() { return 23; }\n" + step["run"]],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 23


@pytest.mark.parametrize("event_value", [False, 0, "", []])
def test_malformed_event_config_rejects(checkout: tuple[Path, dict[str, Any]], guard: Any, event_value: object) -> None:
    workflow, _ = frontend(checkout, guard)
    workflow["on"]["pull_request"] = event_value
    write_workflow(checkout, FRONTEND, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match="coverage"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize("mutation", ["pipeline", "empty", "shell", "suppression"])
def test_container_capture_cannot_mask_failure(
    checkout: tuple[Path, dict[str, Any]], guard: Any, mutation: str
) -> None:
    path = ".github/workflows/container-build.yml"
    workflow = guard.parse_workflow((checkout[0] / path).read_bytes())
    step = next(
        step
        for step in workflow["jobs"]["build"]["steps"]
        if step["name"] == "Smoke test \u2014 `evidentia catalog list`"
    )
    if mutation == "pipeline":
        step["run"] = "docker run --rm evidentia:smoke catalog list | head -n 10"
    elif mutation == "empty":
        step["run"] = step["run"].replace('test -s "$output"', ":")
    elif mutation == "shell":
        step["shell"] = "bash {0}; exit 0"
    else:
        step["continue-on-error"] = True
    write_workflow(checkout, path, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match=r"Container catalog|suppression"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize("mutation", ["pipefail", "shell", "suppression", "conditional", "missing"])
def test_scheduled_refresh_producer_failure_cannot_be_hidden(
    checkout: tuple[Path, dict[str, Any]], guard: Any, mutation: str
) -> None:
    path = ".github/workflows/catalog-refresh.yml"
    workflow = guard.parse_workflow((checkout[0] / path).read_bytes())
    job = workflow["jobs"]["refresh"]
    step = next(step for step in job["steps"] if step.get("name") == "Regenerate manifest from disk")
    if mutation == "pipefail":
        step["run"] = step["run"].replace("set -euo pipefail", "set -eu")
    elif mutation == "shell":
        step["shell"] = "sh"
    elif mutation == "suppression":
        step["continue-on-error"] = True
    elif mutation == "conditional":
        step["if"] = "false"
    else:
        job["steps"].remove(step)
    write_workflow(checkout, path, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match=r"[Rr]efresh"):
        guard.validate_workflows(*checkout)


PROTECTED_STEPS = [
    (FRONTEND, "frontend-test", "Vitest unit tests"),
    (".github/workflows/container-build.yml", "build", "Smoke test \u2014 `evidentia catalog list`"),
    (".github/workflows/catalog-refresh.yml", "refresh", "Regenerate manifest from disk"),
]
NON_BASH_SEPARATORS = ["\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]


@pytest.mark.parametrize("path,job_id,step_name", PROTECTED_STEPS)
def test_actions_interpolation_cannot_hide_in_run_comments(
    checkout: tuple[Path, dict[str, Any]], guard: Any, path: str, job_id: str, step_name: str
) -> None:
    workflow = guard.parse_workflow((checkout[0] / path).read_bytes())
    step = next(step for step in workflow["jobs"][job_id]["steps"] if step.get("name") == step_name)
    step["run"] = "# ${{ github.event.pull_request.title }}\n" + step["run"]
    write_workflow(checkout, path, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match="interpolation"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize("path,job_id,step_name", PROTECTED_STEPS)
@pytest.mark.parametrize("separator", NON_BASH_SEPARATORS)
def test_non_bash_separators_cannot_hide_protected_commands(
    checkout: tuple[Path, dict[str, Any]], guard: Any, path: str, job_id: str, step_name: str, separator: str
) -> None:
    workflow = guard.parse_workflow((checkout[0] / path).read_bytes())
    step = next(step for step in workflow["jobs"][job_id]["steps"] if step.get("name") == step_name)
    body = "# hidden command" + separator + step["run"].replace("\n", separator)
    step["run"] = body
    # ASCII escapes retain the separator in a quoted YAML scalar exactly.
    raw = yaml.safe_dump(workflow, sort_keys=False, allow_unicode=False).encode("utf-8")
    (checkout[0] / path).write_bytes(raw)
    if path in checkout[1]["workflow_sources"]:
        checkout[1]["workflow_sources"][path] = hashlib.sha256(raw).hexdigest()
    parsed = guard.parse_workflow(raw)
    assert next(step for step in parsed["jobs"][job_id]["steps"] if step.get("name") == step_name)["run"] == body
    with pytest.raises(guard.WorkflowFidelityError, match="separator"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize("whitespace", ["\u00a0", "\u202f", "\u3000"])
@pytest.mark.parametrize("position", ["prefix", "suffix"])
def test_unicode_whitespace_cannot_change_vitest_arguments(
    checkout: tuple[Path, dict[str, Any]], guard: Any, whitespace: str, position: str
) -> None:
    workflow, job = frontend(checkout, guard)
    step = next(step for step in job["steps"] if step["name"] == "Vitest unit tests")
    step["run"] = (
        whitespace + step["run"].strip(" \t\n") if position == "prefix" else step["run"].strip(" \t\n") + whitespace
    )
    write_workflow(checkout, FRONTEND, workflow)
    with pytest.raises(guard.WorkflowFidelityError, match="Vitest"):
        guard.validate_workflows(*checkout)


@pytest.mark.parametrize("separator", ["\n", *NON_BASH_SEPARATORS])
def test_bash_comment_ends_only_at_lf(separator: str, tmp_path: Path) -> None:
    bash = shutil.which("bash")
    assert bash is not None, "The supported CI platforms provide Bash"
    command = "npm() { printf 'called'; return 23; }\n# comment" + separator + "npm run test -- --run"
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", command],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    assert result.returncode == (23 if separator == "\n" else 0)
    assert result.stdout == (b"called" if separator == "\n" else b"")


@pytest.mark.parametrize("path,job_id,step_name", PROTECTED_STEPS)
@pytest.mark.parametrize("line_ending", [b"\n", b"\r\n"])
def test_protected_commands_accept_ordinary_yaml_line_endings(
    checkout: tuple[Path, dict[str, Any]], guard: Any, path: str, job_id: str, step_name: str, line_ending: bytes
) -> None:
    source = checkout[0] / path
    source.write_bytes(source.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", line_ending))
    workflow = guard.parse_workflow(source.read_bytes())
    body = next(step for step in workflow["jobs"][job_id]["steps"] if step.get("name") == step_name)["run"]
    assert "\r" not in body
    guard.validate_workflows(*checkout)
