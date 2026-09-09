"""Run the CI-pinned Gitleaks history scan without exposing scanner output."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import cast

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = Path(".github/workflows/secret-scan.yml")
SCAN_ARGS = ("git", ".", "--config", ".gitleaks.toml", "--redact", "--no-banner")
INSTALL_NAME = "Install gitleaks (pinned binary, SHA256-verified)"
SCAN_NAME = "Run gitleaks (scan git history)"
VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
DOWNLOAD_LINE = (
    'curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${VER}/'
    'gitleaks_${VER}_linux_x64.tar.gz" -o /tmp/gitleaks.tar.gz'
)


class GateError(ValueError):
    """A fixed, value-free explanation of an unmet scan requirement."""


class _WorkflowLoader(yaml.SafeLoader):
    """Keep the Actions event key 'on' a string and reject ambiguous mappings."""


_WorkflowLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in values if tag != "tag:yaml.org,2002:bool"]
    for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"), list("tTfF")
)


def _unique_mapping(loader: yaml.SafeLoader, node: MappingNode) -> dict[str, object]:
    result: dict[str, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise GateError("CI workflow has ambiguous mapping keys")
        result[key] = loader.construct_object(value_node)
    return result


_WorkflowLoader.add_constructor("tag:yaml.org,2002:map", _unique_mapping)


def _mapping(value: object, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GateError("CI scan contract has unsupported or missing fields")
    return cast(dict[str, object], value)


def _lines(value: object) -> list[str]:
    if not isinstance(value, str):
        raise GateError("CI scan command must be literal text")
    if "${{" in value:
        raise GateError("CI run commands and comments must not contain Actions expressions")
    # Bash separates commands at LF, not at Unicode or other control separators.
    lines = [line.strip(" \t") for line in value.split("\n")]
    return [line for line in lines if line and not line.startswith("#")]


def pinned_version(raw: bytes) -> str:
    """Validate the supported CI install and scan shape, then return its version."""
    try:
        if any(isinstance(event, AliasEvent) for event in yaml.parse(raw)):
            raise GateError("CI workflow aliases require review")
        document: object = yaml.load(raw, Loader=_WorkflowLoader)
    except (yaml.YAMLError, UnicodeError, RecursionError, ValueError) as exc:
        raise GateError("CI workflow is invalid or ambiguous") from exc
    workflow = _mapping(document, {"name", "on", "permissions", "concurrency", "jobs"})
    jobs = _mapping(workflow["jobs"], {"gitleaks"})
    job = _mapping(jobs["gitleaks"], {"name", "runs-on", "steps"})
    if job["name"] != "gitleaks (default ruleset + allowlist)" or job["runs-on"] != "ubuntu-latest":
        raise GateError("CI Gitleaks job identity changed")
    steps = job["steps"]
    if not isinstance(steps, list) or len(steps) != 3:
        raise GateError("CI scan requires its reviewed three steps")
    checkout = _mapping(steps[0], {"name", "uses", "with"})
    action = checkout["uses"]
    if (
        checkout["name"] != "Checkout"
        or not isinstance(action, str)
        or re.fullmatch(r"actions/checkout@[0-9a-f]{40}", action) is None
    ):
        raise GateError("CI checkout must use a pinned action")
    checkout_options = _mapping(checkout["with"], {"fetch-depth", "persist-credentials"})
    depth = checkout_options["fetch-depth"]
    if type(depth) is not int or depth != 0 or checkout_options["persist-credentials"] is not False:
        raise GateError("CI checkout must retain full history without persisted credentials")
    install = _mapping(steps[1], {"name", "run"})
    scan = _mapping(steps[2], {"name", "run"})
    if install["name"] != INSTALL_NAME or scan["name"] != SCAN_NAME:
        raise GateError("CI install or scan step identity changed")
    lines = _lines(install["run"])
    if len(lines) != 6 or not lines[0].startswith("VER="):
        raise GateError("CI must pin one literal Gitleaks version")
    version = lines[0][4:]
    if VERSION_PATTERN.fullmatch(version) is None:
        raise GateError("CI must pin one literal Gitleaks version")
    if (
        lines[1] != DOWNLOAD_LINE
        or re.fullmatch(r'echo "[0-9a-f]{64}  /tmp/gitleaks\.tar\.gz" \| sha256sum -c -', lines[2]) is None
        or lines[3:]
        != [
            "tar -xzf /tmp/gitleaks.tar.gz -C /tmp gitleaks",
            "sudo mv /tmp/gitleaks /usr/local/bin/gitleaks",
            "gitleaks version",
        ]
    ):
        raise GateError("CI binary installation or checksum verification changed")
    if _lines(scan["run"]) != ["gitleaks " + " ".join(SCAN_ARGS)]:
        raise GateError("CI history scan arguments changed")
    return version


def _child_environment() -> dict[str, str]:
    # Repository and scanner overrides must not redirect this fixed scan.
    return {key: value for key, value in os.environ.items() if not key.upper().startswith(("GIT_", "GITLEAKS_"))}


def _binary(name: str, environment: dict[str, str]) -> str:
    located = shutil.which(name, path=environment.get("PATH", ""))
    if located is None:
        raise GateError("Required Git or Gitleaks binary is not installed on PATH")
    path = Path(located).resolve()
    if not path.is_file() or path.suffix.lower() in {".bat", ".cmd", ".ps1", ".sh"}:
        raise GateError("Required Git or Gitleaks executable is not a supported binary")
    return str(path)


def _probe(args: list[str], root: Path, environment: dict[str, str]) -> str:
    try:
        result = subprocess.run(
            args,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            errors="strict",
            shell=False,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise GateError("Git or Gitleaks preflight could not complete") from exc
    if result.returncode != 0:
        raise GateError("Git or Gitleaks preflight failed")
    return result.stdout


def check(root: Path) -> None:
    """Require the CI contract and full local history before running a fixed scan."""
    root = root.resolve()
    workflow = root / WORKFLOW
    config = root / ".gitleaks.toml"
    if not workflow.is_file() or not config.is_file():
        raise GateError("CI workflow or repository Gitleaks configuration is missing")
    if not workflow.resolve().is_relative_to(root) or not config.resolve().is_relative_to(root):
        raise GateError("CI workflow and Gitleaks configuration must be inside the repository")
    try:
        version = pinned_version(workflow.read_bytes())
    except OSError as exc:
        raise GateError("CI workflow could not be read") from exc
    environment = _child_environment()
    scanner = _binary("gitleaks", environment)
    git = _binary("git", environment)
    repository = _probe(
        [git, "-C", str(root), "rev-parse", "--show-toplevel", "--is-shallow-repository"], root, environment
    )
    lines = repository.splitlines()
    if len(lines) != 2 or Path(lines[0]).resolve() != root or lines[1] != "false":
        raise GateError("Scan requires the actual repository root and complete Git history")
    if _probe([scanner, "version"], root, environment).strip() != version:
        raise GateError("Installed Gitleaks version does not match the CI pin")
    try:
        result = subprocess.run(
            [scanner, *SCAN_ARGS],
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            check=False,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError("Gitleaks history scan could not complete; scanner output withheld") from exc
    if result.returncode != 0:
        raise GateError("Gitleaks history scan failed; scanner output withheld")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        check(ROOT)
    except GateError as exc:
        # GateError messages are fixed descriptions, never tool or file content.
        print("BLOCK check_gitleaks: " + str(exc))
        return 1
    except (OSError, ValueError):
        print("BLOCK check_gitleaks: scan preflight failed; scanner output withheld")
        return 1
    print("PASS check_gitleaks: CI-pinned history scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
