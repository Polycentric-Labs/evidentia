"""Keep registry authentication separate from container publication authority."""

from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
LOGIN = "Log in to Docker Hardened Images"


def workflow(name: str) -> dict[str, Any]:
    return yaml.load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


@pytest.mark.parametrize(
    "name,build_step,condition",
    [
        (
            "container-build.yml",
            "Build image (load into local Docker, not pushed)",
            "steps.relevant.outputs.relevant == 'true'",
        ),
        ("release.yml", "Build container image from local wheels (load, not pushed)", None),
    ],
)
def test_dhi_login_is_read_scoped_and_adjacent_to_the_build(name: str, build_step: str, condition: str | None) -> None:
    source = workflow(name)
    job = source["jobs"]["build"]
    steps = job["steps"]
    names = [step.get("name") for step in steps]
    assert names.count(LOGIN) == 1
    assert names.index(LOGIN) + 1 == names.index(build_step)
    login = steps[names.index(LOGIN)]
    assert login["uses"] == "docker/login-action@dbcb813823bdd20940b903addbd779551569679f"
    assert login.get("if") == condition
    assert login.get("continue-on-error") in (None, "false")
    assert login["with"] == {
        "registry": "dhi.io",
        "username": "${{ secrets.DHI_USERNAME }}",
        "password": "${{ secrets.DHI_READ_TOKEN }}",
        "logout": "true",
    }
    assert "pull_request_target" not in source["on"]
    assert job.get("permissions", source.get("permissions")) == {"contents": "read"}
    assert "environment" not in job
    assert steps[names.index(build_step)]["with"]["push"] == "false"


def test_registry_read_access_does_not_change_release_publication_gates() -> None:
    jobs = workflow("release.yml")["jobs"]
    for name, environment in (("publish-pypi", "pypi"), ("publish-container", "ghcr")):
        job = jobs[name]
        assert "github.event_name == 'push'" in job["if"]
        assert "needs.tag-guard.outputs.publishable == 'true'" in job["if"]
        assert job["environment"]["name"] == environment
    assert "workflow_dispatch" in workflow("release.yml")["on"]
