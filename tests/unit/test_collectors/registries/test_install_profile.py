"""Guard the declared installation boundary before artifact-specific checks."""

from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[4]


def _requirements(extra: str | None = None) -> dict[str, Requirement]:
    with (ROOT / "packages/evidentia-collectors/pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)["project"]
    declarations = project["dependencies"] if extra is None else project["optional-dependencies"][extra]
    requirements = [Requirement(value) for value in declarations]
    assert len(requirements) == len({requirement.name for requirement in requirements})
    return {requirement.name: requirement for requirement in requirements}


def test_base_metadata_declares_owned_http_dependency_without_xml_extra() -> None:
    base = _requirements()
    assert str(base["httpcore"].specifier) == "==1.0.9"
    assert "httpx" in base
    assert {"defusedxml", "signxml", "lxml"}.isdisjoint(base)
    assert not base["httpcore"].extras and base["httpcore"].marker is None


def test_registry_extra_keeps_exact_verifier_and_parser_requirements() -> None:
    extra = _requirements("registries")
    assert set(extra) == {"defusedxml", "signxml"}
    assert str(extra["defusedxml"].specifier) == ">=0.7.1"
    assert str(extra["signxml"].specifier) == "==5.1.0"
    assert all(requirement.marker is None and not requirement.extras for requirement in extra.values())


def test_all_extra_contains_the_same_reviewed_registry_requirements() -> None:
    combined = _requirements("all")
    for name, requirement in _requirements("registries").items():
        assert str(combined[name]) == str(requirement)
