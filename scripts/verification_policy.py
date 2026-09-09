"""Read the reviewed verification policy without accepting silent schema drift."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Literal, NotRequired, TypedDict, cast

POLICY_PATH = Path(__file__).resolve().parents[1] / ".github" / "verification-policy.json"
POLICY_SHA256 = "b11bc4f606e91460efff5bd2910429f03d9c9e858d07c65d07a453223caad66d"


class CheckIdentity(TypedDict):
    context: str
    integration_id: int
    workflow: str | None


class WorkflowJob(CheckIdentity):
    job_id: str
    paths: list[str] | None
    steps: list[str]
    mandatory_steps: list[str]
    allow_non_dependabot_skip: NotRequired[bool]


class CodSpeedLinkage(TypedDict):
    minimum_commit_prefix_length: int
    require_git_resolution: bool
    require_completed_after_benchmark: Literal["strictly_later"]
    provider_run_id_attested: bool


class VerificationPolicy(TypedDict):
    version: int
    repository: str
    baseline: list[CheckIdentity]
    extra: list[CheckIdentity]
    mandatory_steps: dict[str, list[str]]
    workflow_jobs: list[WorkflowJob]
    workflow_sources: dict[str, str]
    codspeed_linkage: CodSpeedLinkage


class PolicyError(ValueError):
    """A policy changed without review or no longer meets its schema."""


def normalized_bytes(raw: bytes) -> bytes:
    """Normalize Git checkout line endings before checking content identity."""
    return raw.replace(b"\r\n", b"\n")


def strict_json(raw: str | bytes) -> object:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise PolicyError("Duplicate policy key: " + key)
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise PolicyError("Non-JSON numeric constant: " + value)

    try:
        return json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyError("Invalid policy JSON") from exc


def _object(value: object, required: set[str], optional: set[str] | None = None) -> dict[str, object]:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - (optional or set()):
        raise PolicyError("Unknown or missing policy fields")
    return cast(dict[str, object], value)


def _strings(value: object, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(v, str) or not v.strip() for v in value):
        raise PolicyError("Expected nonblank string list")
    if len(value) != len(set(value)) or (nonempty and not value):
        raise PolicyError("Empty or duplicate policy list")
    return cast(list[str], value)


def _workflow(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"\.github/workflows/[a-z0-9-]+\.yml", value):
        raise PolicyError("Invalid workflow path")
    return value


def _identity(value: object, *, job: bool = False) -> dict[str, object]:
    fields = {"context", "integration_id", "workflow"}
    if job:
        fields |= {"job_id", "paths", "steps", "mandatory_steps"}
    row = _object(value, fields, {"allow_non_dependabot_skip"} if job else set())
    if not isinstance(row["context"], str) or not row["context"].strip():
        raise PolicyError("Blank check context")
    if type(row["integration_id"]) is not int or row["integration_id"] <= 0:
        raise PolicyError("Invalid check application identity")
    if (row["integration_id"] == 15368) != (row["workflow"] is not None):
        raise PolicyError("Actions checks require a workflow and workflow checks require Actions")
    if row["workflow"] is not None or job:
        _workflow(row["workflow"])
    if job:
        if not isinstance(row["job_id"], str) or not row["job_id"].strip():
            raise PolicyError("Blank job identity")
        if row["paths"] is not None:
            patterns = _strings(row["paths"], nonempty=True)
            if any(
                pattern.startswith(("!", "/"))
                or "\\" in pattern
                or ".." in pattern.split("/")
                or any(char in pattern for char in "?[]+")
                for pattern in patterns
            ):
                raise PolicyError("Unsupported path policy syntax")
        steps = _strings(row["steps"], nonempty=True)
        mandatory = _strings(row["mandatory_steps"], nonempty=True)
        if not set(mandatory) <= set(steps):
            raise PolicyError("Mandatory step is not present in its job")
        if "allow_non_dependabot_skip" in row and type(row["allow_non_dependabot_skip"]) is not bool:
            raise PolicyError("Invalid conditional skip flag")
        if row.get("allow_non_dependabot_skip") is True and (
            row["workflow"],
            row["job_id"],
            row["context"],
            row["integration_id"],
        ) != (
            ".github/workflows/dependabot-auto-merge.yml",
            "auto-merge",
            "Enable auto-merge (Dependabot patch)",
            15368,
        ):
            raise PolicyError("Conditional skip is restricted to the reviewed Dependabot job")
    return row


def validate_policy(value: object) -> VerificationPolicy:
    data = _object(value, set(VerificationPolicy.__required_keys__))
    if data["version"] != 2 or type(data["version"]) is not int or data["repository"] != "Polycentric-Labs/evidentia":
        raise PolicyError("Unexpected policy version or repository")
    identities: set[tuple[object, object]] = set()
    for field in ("baseline", "extra"):
        rows = data[field]
        if not isinstance(rows, list) or not rows:
            raise PolicyError("Missing check identities")
        for item in rows:
            row = _identity(item)
            key = (row["context"], row["integration_id"])
            if key in identities:
                raise PolicyError("Duplicate check identity")
            identities.add(key)
    source_map = data["workflow_sources"]
    if not isinstance(source_map, dict) or not source_map:
        raise PolicyError("Missing workflow source identities")
    for path, sha in source_map.items():
        _workflow(path)
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise PolicyError("Invalid workflow source digest")
    jobs = data["workflow_jobs"]
    if not isinstance(jobs, list) or not jobs:
        raise PolicyError("Missing workflow jobs")
    seen: set[tuple[object, object, object]] = set()
    bindings: dict[tuple[object, object], object] = {}
    for item in jobs:
        row = _identity(item, job=True)
        job_key = (row["workflow"], row["context"], row["integration_id"])
        if job_key in seen or row["workflow"] not in source_map:
            raise PolicyError("Duplicate job or missing workflow source")
        identity_key = (row["context"], row["integration_id"])
        if identity_key in bindings and bindings[identity_key] != row["workflow"]:
            raise PolicyError("Ambiguous check workflow identity")
        bindings[identity_key] = row["workflow"]
        seen.add(job_key)
    for field in ("baseline", "extra"):
        for check_row in cast(list[CheckIdentity], data[field]):
            if (
                check_row["workflow"] is not None
                and (check_row["workflow"], check_row["context"], check_row["integration_id"]) not in seen
            ):
                raise PolicyError("Required check has no reviewed job")
    if set(source_map) != {row["workflow"] for row in cast(list[WorkflowJob], jobs)}:
        raise PolicyError("Workflow source has no reviewed jobs")
    step_map = data["mandatory_steps"]
    if not isinstance(step_map, dict):
        raise PolicyError("Missing mandatory step map")
    for context, steps in step_map.items():
        if not isinstance(context, str) or not context.strip():
            raise PolicyError("Blank mandatory-step context")
        _strings(steps, nonempty=True)
    for job_row in cast(list[WorkflowJob], jobs):
        if step_map.get(job_row["context"]) != job_row["mandatory_steps"]:
            raise PolicyError("Mandatory step maps disagree")
    if set(step_map) != {row["context"] for row in cast(list[WorkflowJob], jobs)}:
        raise PolicyError("Orphan mandatory-step context")
    link = _object(data["codspeed_linkage"], set(CodSpeedLinkage.__required_keys__))
    if type(link["minimum_commit_prefix_length"]) is not int or not 7 <= link["minimum_commit_prefix_length"] <= 40:
        raise PolicyError("Invalid comparison commit prefix floor")
    for flag in ("require_git_resolution", "provider_run_id_attested"):
        if type(link[flag]) is not bool:
            raise PolicyError("Invalid comparison linkage flag")
    if (
        not link["require_git_resolution"]
        or link["require_completed_after_benchmark"] != "strictly_later"
        or link["provider_run_id_attested"]
    ):
        raise PolicyError("Unsupported performance evidence contract")
    return cast(VerificationPolicy, data)


def load_policy(path: Path = POLICY_PATH) -> VerificationPolicy:
    raw = normalized_bytes(path.read_bytes())
    if hashlib.sha256(raw).hexdigest() != POLICY_SHA256:
        raise PolicyError("Policy content differs from the reviewed version")
    return validate_policy(strict_json(raw))
