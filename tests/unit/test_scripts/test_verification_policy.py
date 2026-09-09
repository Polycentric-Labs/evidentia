"""Reject malformed or unreviewed verification policies before gate execution."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def seam() -> Any:
    spec = importlib.util.spec_from_file_location("verification_policy_test", ROOT / "scripts/verification_policy.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def policy(seam: Any) -> dict[str, Any]:
    return copy.deepcopy(seam.load_policy())


def test_reviewed_policy_loads_with_required_docs(seam: Any) -> None:
    policy = seam.load_policy()
    assert len(policy["baseline"]) == 25
    assert any(row["context"] == "docs build (strict)" and row["integration_id"] == 15368 for row in policy["baseline"])


def test_lf_and_crlf_checkouts_have_same_identity(seam: Any, tmp_path: Path) -> None:
    raw = seam.POLICY_PATH.read_bytes().replace(b"\r\n", b"\n")
    path = tmp_path / "policy.json"
    path.write_bytes(raw.replace(b"\n", b"\r\n"))
    assert seam.load_policy(path) == seam.load_policy()


def test_unreviewed_bytes_reject_even_if_valid_json(seam: Any, tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_bytes(seam.POLICY_PATH.read_bytes() + b" ")
    with pytest.raises(seam.PolicyError, match="reviewed"):
        seam.load_policy(path)


def test_duplicate_json_keys_are_not_silently_overwritten(seam: Any) -> None:
    with pytest.raises(seam.PolicyError, match="Duplicate"):
        seam.strict_json('{"version":2,"version":1}')


@pytest.mark.parametrize(
    "field",
    [
        "version",
        "repository",
        "baseline",
        "extra",
        "workflow_jobs",
        "workflow_sources",
        "mandatory_steps",
        "codspeed_linkage",
    ],
)
def test_missing_top_level_fields_reject(seam: Any, policy: dict[str, Any], field: str) -> None:
    del policy[field]
    with pytest.raises(seam.PolicyError):
        seam.validate_policy(policy)


def test_unknown_field_rejects_typo(seam: Any, policy: dict[str, Any]) -> None:
    policy["mandatory_step"] = policy["mandatory_steps"]
    with pytest.raises(seam.PolicyError):
        seam.validate_policy(policy)


@pytest.mark.parametrize("identity", [True, "15368", None, 0])
def test_application_identity_is_strict(seam: Any, policy: dict[str, Any], identity: object) -> None:
    policy["baseline"][0]["integration_id"] = identity
    with pytest.raises(seam.PolicyError):
        seam.validate_policy(policy)


def test_duplicate_check_identity_rejects(seam: Any, policy: dict[str, Any]) -> None:
    policy["extra"].append(copy.deepcopy(policy["baseline"][0]))
    with pytest.raises(seam.PolicyError, match="Duplicate"):
        seam.validate_policy(policy)


def test_workflow_path_cannot_escape_the_repository_scope(seam: Any, policy: dict[str, Any]) -> None:
    policy["baseline"][0]["workflow"] = "../outside.yml"
    with pytest.raises(seam.PolicyError, match="workflow path"):
        seam.validate_policy(policy)


def test_required_check_needs_a_workflow_job(seam: Any, policy: dict[str, Any]) -> None:
    identity = policy["baseline"][0]
    policy["workflow_jobs"] = [
        row
        for row in policy["workflow_jobs"]
        if not (row["context"] == identity["context"] and row["workflow"] == identity["workflow"])
    ]
    with pytest.raises(seam.PolicyError, match="no reviewed job"):
        seam.validate_policy(policy)


def test_mandatory_step_must_be_in_source_job(seam: Any, policy: dict[str, Any]) -> None:
    policy["workflow_jobs"][0]["mandatory_steps"].append("Missing validation")
    with pytest.raises(seam.PolicyError, match="not present"):
        seam.validate_policy(policy)


def test_duplicate_step_maps_cannot_disagree(seam: Any, policy: dict[str, Any]) -> None:
    job = policy["workflow_jobs"][0]
    policy["mandatory_steps"][job["context"]] = ["Other validation"]
    with pytest.raises(seam.PolicyError, match="disagree"):
        seam.validate_policy(policy)


def test_unattested_provider_linkage_cannot_be_claimed(seam: Any, policy: dict[str, Any]) -> None:
    policy["codspeed_linkage"]["provider_run_id_attested"] = True
    with pytest.raises(seam.PolicyError, match="Unsupported"):
        seam.validate_policy(policy)


def test_missing_source_identity_rejects(seam: Any, policy: dict[str, Any]) -> None:
    del policy["workflow_sources"][policy["workflow_jobs"][0]["workflow"]]
    with pytest.raises(seam.PolicyError, match="missing workflow source"):
        seam.validate_policy(policy)


@pytest.mark.parametrize("value", [True, False, "same_time", None])
def test_temporal_linkage_requires_the_reviewed_strict_order(seam: Any, policy: dict[str, Any], value: object) -> None:
    policy["codspeed_linkage"]["require_completed_after_benchmark"] = value
    with pytest.raises(seam.PolicyError, match="Unsupported"):
        seam.validate_policy(policy)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_json_numeric_constants_reject(seam: Any, constant: str) -> None:
    with pytest.raises(seam.PolicyError, match="Non-JSON"):
        seam.strict_json('{"value":' + constant + "}")


def test_actions_check_cannot_discard_its_workflow(seam: Any, policy: dict[str, Any]) -> None:
    policy["baseline"][0]["workflow"] = None
    with pytest.raises(seam.PolicyError, match="Actions checks"):
        seam.validate_policy(policy)


def test_workflow_check_cannot_claim_an_external_application(seam: Any, policy: dict[str, Any]) -> None:
    policy["baseline"][0]["integration_id"] = 999
    with pytest.raises(seam.PolicyError, match="Actions checks"):
        seam.validate_policy(policy)


def test_skip_exception_cannot_be_transferred_to_another_job(seam: Any, policy: dict[str, Any]) -> None:
    policy["workflow_jobs"][0]["allow_non_dependabot_skip"] = True
    with pytest.raises(seam.PolicyError, match="restricted"):
        seam.validate_policy(policy)


@pytest.mark.parametrize("field,value", [("job_id", "other-job"), ("context", "other-context")])
def test_skip_exception_requires_exact_dependabot_identity(
    seam: Any, policy: dict[str, Any], field: str, value: str
) -> None:
    job = next(row for row in policy["workflow_jobs"] if row.get("allow_non_dependabot_skip"))
    job[field] = value
    with pytest.raises(seam.PolicyError, match="restricted"):
        seam.validate_policy(policy)


def test_context_and_application_cannot_bind_two_workflows(seam: Any, policy: dict[str, Any]) -> None:
    job = copy.deepcopy(policy["workflow_jobs"][0])
    job["workflow"] = next(path for path in policy["workflow_sources"] if path != job["workflow"])
    policy["workflow_jobs"].append(job)
    with pytest.raises(seam.PolicyError, match="Ambiguous"):
        seam.validate_policy(policy)


def test_workflow_source_cannot_lose_all_its_jobs(seam: Any, policy: dict[str, Any]) -> None:
    target = ".github/workflows/evidentia.yml"
    removed = {row["context"] for row in policy["workflow_jobs"] if row["workflow"] == target}
    assert removed
    policy["workflow_jobs"] = [row for row in policy["workflow_jobs"] if row["workflow"] != target]
    policy["mandatory_steps"] = {key: value for key, value in policy["mandatory_steps"].items() if key not in removed}
    with pytest.raises(seam.PolicyError, match="no reviewed jobs"):
        seam.validate_policy(policy)


def test_step_map_cannot_contain_an_unused_context(seam: Any, policy: dict[str, Any]) -> None:
    policy["mandatory_steps"]["Unused validation"] = ["Unknown step"]
    with pytest.raises(seam.PolicyError, match="Orphan"):
        seam.validate_policy(policy)


@pytest.mark.parametrize("pattern", ["!**", "../outside", "/absolute", "dir\\file", "*.jsx?", "[ab].py", "a+.py"])
def test_unsupported_path_patterns_reject(seam: Any, policy: dict[str, Any], pattern: str) -> None:
    policy["workflow_jobs"][0]["paths"] = [pattern]
    with pytest.raises(seam.PolicyError, match="Unsupported path"):
        seam.validate_policy(policy)
