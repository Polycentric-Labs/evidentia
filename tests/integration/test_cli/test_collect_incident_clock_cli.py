"""Check incident CLI authorization, complete output and failure preservation."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from click import unstyle
from evidentia.cli import _incident_clock_io, _rbac
from evidentia.cli.main import app
from evidentia_collectors.incident_clock import IncidentClockCollector
from evidentia_collectors.incident_clock import _client as source_client
from evidentia_collectors.incident_clock._contracts import result_bytes
from evidentia_core.rbac import RBACPolicy, Role
from typer import rich_utils
from typer.testing import CliRunner, Result

from ..test_api.test_collectors_incident_clock import CONFIG, VALID, actual_result, configuration, install_transport


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path, Path]:
    for name in (
        "EVIDENTIA_RBAC_POLICY_FILE",
        "EVIDENTIA_RBAC_IDENTITY",
        "EVIDENTIA_RBAC_TENANT",
        "EVIDENTIA_INCIDENT_CLOCK_PROFILES_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "settings.yaml"
    config.write_text("{}\n", encoding="utf-8")
    source = tmp_path / "request.json"
    source.write_bytes(json.dumps(VALID).encode())
    profiles = tmp_path / "profiles.json"
    profiles.write_bytes(json.dumps(CONFIG).encode())
    monkeypatch.setattr(_rbac, "get_rbac_policy", lambda: RBACPolicy(default_role=Role.READER))
    monkeypatch.setattr(_rbac, "get_rbac_identity", lambda: "synthetic-reader")
    return config, source, profiles


def invoke(
    settings: tuple[Path, Path, Path],
    *,
    provider: str = "servicenow",
    output: Path | None = None,
    explicit_profiles: bool = True,
) -> Result:
    config, source, profiles = settings
    args = ["--config", str(config), "collect", "incident-clock", "--provider", provider, "--request-file", str(source)]
    if explicit_profiles:
        args += ["--profiles-file", str(profiles)]
    if output is not None:
        args += ["--output", str(output)]
    return CliRunner().invoke(app, args)


def test_read_role_precedes_input_metadata(settings: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_rbac, "get_rbac_policy", lambda: RBACPolicy(default_role=Role.DENY))
    read = Mock(side_effect=AssertionError("early input"))
    monkeypatch.setattr(_incident_clock_io, "read_request_file", read)
    outcome = invoke(settings)
    assert outcome.exit_code == 77 and outcome.stdout == ""
    read.assert_not_called()


def test_selector_disagreement_precedes_profile_read(
    settings: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    read = Mock(side_effect=AssertionError("early profile read"))
    monkeypatch.setattr(_incident_clock_io, "read_profile_file", read)
    outcome = invoke(settings, provider="jira")
    assert outcome.exit_code == 2 and outcome.stdout == ""
    read.assert_not_called()


@pytest.mark.parametrize("provider", ["servicenow", "jira", "pagerduty"])
def test_actual_provider_collection(
    settings: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch, provider: str
) -> None:
    request, configured = configuration(provider)
    settings[1].write_bytes(json.dumps(request).encode())
    settings[2].write_bytes(json.dumps(configured).encode())
    calls = install_transport(monkeypatch, provider)
    outcome = invoke(settings, provider=provider)
    assert outcome.exit_code == 0, outcome.output
    observed = json.loads(outcome.stdout)
    assert observed["provider"] == provider and observed["clock"]["elapsed_seconds"] == "1" and calls


@pytest.mark.parametrize(
    "mode,provider",
    [
        ("complete", "servicenow"),
        ("unresolved", "servicenow"),
        ("reversed", "servicenow"),
        ("unavailable", "servicenow"),
        ("incomplete", "jira"),
    ],
)
@pytest.mark.parametrize("to_file", [False, True])
def test_full_exact_output_and_source_exit_status(
    settings: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: str,
    provider: str,
    to_file: bool,
) -> None:
    observed = actual_result(monkeypatch, provider, mode)
    raw = result_bytes(observed)
    request, configured = configuration(provider)
    settings[1].write_bytes(json.dumps(request).encode())
    settings[2].write_bytes(json.dumps(configured).encode())
    monkeypatch.setattr(IncidentClockCollector, "collect_v2", lambda self, selected: observed)
    destination = tmp_path / "result.json" if to_file else None
    outcome = invoke(settings, provider=provider, output=destination)
    assert outcome.exit_code == (0 if observed.source_state == "complete" else 1), outcome.output
    assert (destination.read_bytes() if destination else outcome.stdout.encode()) == raw
    if destination:
        assert outcome.stdout == ""


@pytest.mark.parametrize("body", [b"{", b"[]", b" " * 16385])
def test_invalid_input_is_two(settings: tuple[Path, Path, Path], body: bytes) -> None:
    settings[1].write_bytes(body)
    outcome = invoke(settings)
    assert outcome.exit_code == 2 and outcome.stdout == ""


@pytest.mark.parametrize(
    "mode", ["malformed", "oversized", "no-local-grant", "wrong-record", "absent-file", "absent-configuration"]
)
def test_profile_refusals_are_uniform_and_precede_credentials(
    settings: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    if mode == "malformed":
        settings[2].write_bytes(b"{")
    elif mode == "oversized":
        settings[2].write_bytes(b" " * 65537)
    elif mode in {"no-local-grant", "wrong-record"}:
        configured = json.loads(settings[2].read_bytes())
        configured["profiles"][0]["allow_local_cli" if mode == "no-local-grant" else "record_ids"] = (
            False if mode == "no-local-grant" else ["2" * 32]
        )
        settings[2].write_bytes(json.dumps(configured).encode())
    elif mode == "absent-file":
        settings[2].unlink()
    credentials = Mock(side_effect=AssertionError("early credentials"))
    monkeypatch.setattr(source_client, "resolve_material", credentials)
    outcome = invoke(settings, explicit_profiles=mode != "absent-configuration")
    assert outcome.exit_code == 77 and outcome.stdout == ""
    assert outcome.stderr.strip() == "The selected collection profile is unavailable."
    credentials.assert_not_called()


def test_profile_environment_and_explicit_override(
    settings: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EVIDENTIA_INCIDENT_CLOCK_PROFILES_FILE", str(settings[2]))
    install_transport(monkeypatch)
    assert invoke(settings, explicit_profiles=False).exit_code == 0
    monkeypatch.setenv("EVIDENTIA_INCIDENT_CLOCK_PROFILES_FILE", "absent.json")
    install_transport(monkeypatch)
    assert invoke(settings).exit_code == 0


@pytest.mark.parametrize("index", [1, 2])
@pytest.mark.parametrize("hardlink", [False, True])
def test_both_input_files_are_protected_from_output_alias(
    settings: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch, index: int, hardlink: bool
) -> None:
    target = settings[index]
    before = target.read_bytes()
    destination = target.with_name("alias.json") if hardlink else target
    if hardlink:
        os.link(target, destination)
    worker = Mock(side_effect=AssertionError("early collection"))
    monkeypatch.setattr(IncidentClockCollector, "collect_v2", worker)
    outcome = invoke(settings, output=destination)
    assert outcome.exit_code == (77 if hardlink and index == 2 else 2)
    assert target.read_bytes() == before and outcome.stdout == ""
    worker.assert_not_called()


@pytest.mark.parametrize("mode", ["exception", "mutated-result", "wrong-request", "replace-failure"])
def test_failures_preserve_existing_output(
    settings: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    result = actual_result(monkeypatch, "jira" if mode == "wrong-request" else "servicenow")
    if mode == "mutated-result":
        result.events.clear()

    def collect(self: Any, selected: Any) -> Any:
        if mode == "exception":
            raise RuntimeError("synthetic-private-failure")
        return result

    monkeypatch.setattr(IncidentClockCollector, "collect_v2", collect)
    if mode == "replace-failure":

        def fail(*args: Any) -> Any:
            raise OSError("synthetic-private-path")

        monkeypatch.setattr(_incident_clock_io.os, "replace", fail)
    output = tmp_path / "result.json"
    output.write_bytes(b"preserved result")
    outcome = invoke(settings, output=output)
    assert outcome.exit_code == 1 and output.read_bytes() == b"preserved result" and outcome.stdout == ""
    assert "synthetic-private" not in outcome.stderr
    assert list(tmp_path.glob(".evidentia-incident-clock-*.tmp")) == []


@pytest.mark.parametrize("width", [80, 200])
@pytest.mark.parametrize("colored", [False, True])
def test_help_describes_request_and_profile_boundaries(
    settings: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch, width: int, colored: bool
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("COLUMNS", str(width))
    monkeypatch.setattr(rich_utils, "FORCE_TERMINAL", colored)
    monkeypatch.setattr(rich_utils, "COLOR_SYSTEM", "standard" if colored else None)
    monkeypatch.setattr(rich_utils, "MAX_WIDTH", width)
    outcome = CliRunner().invoke(
        app, ["--config", str(settings[0]), "collect", "incident-clock", "--help"], color=colored
    )
    assert outcome.exit_code == 0
    visible = unstyle(outcome.stdout)
    assert all(word in visible for word in ("--provider", "--request-file", "--profiles-file", "--output", "16384"))
    assert all(word not in visible for word in ("--token", "--base-url", "--allow-private-ips"))
