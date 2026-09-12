"""Exercise registry CLI authorization, exact output and safe file handling."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from click import unstyle
from evidentia.cli import _rbac, _retention_io
from evidentia.cli.main import app
from evidentia_collectors.registries import RegistryCollector
from evidentia_collectors.registries._contracts import result_bytes
from evidentia_core.rbac import RBACPolicy, Role
from typer import rich_utils
from typer.testing import CliRunner, Result

from ..test_api.test_collectors_registry import VALID, actual_result
from ..test_api.test_collectors_registry_stream import demo_results


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
    for name in ("EVIDENTIA_RBAC_POLICY_FILE", "EVIDENTIA_RBAC_IDENTITY", "EVIDENTIA_RBAC_TENANT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "settings.yaml"
    config.write_text("{}\n", encoding="utf-8")
    source = tmp_path / "request.json"
    source.write_bytes(json.dumps(VALID).encode())
    monkeypatch.setattr(_rbac, "get_rbac_policy", lambda: RBACPolicy(default_role=Role.READER))
    monkeypatch.setattr(_rbac, "get_rbac_identity", lambda: "synthetic-reader")
    monkeypatch.setattr(RegistryCollector, "collect_v2", lambda self, request: actual_result(request))
    return config, source


def invoke(settings: tuple[Path, Path], *, selector: str = "ssl-labs", output: Path | None = None) -> Result:
    config, source = settings
    args = ["--config", str(config), "collect", "registry", "--registry", selector, "--request-file", str(source)]
    if output is not None:
        args += ["--output", str(output)]
    return CliRunner().invoke(app, args)


def test_read_role_precedes_input_and_path_conversion(
    settings: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_rbac, "get_rbac_policy", lambda: RBACPolicy(default_role=Role.DENY))
    read = Mock(side_effect=AssertionError("early input"))
    monkeypatch.setattr(_retention_io, "read_request_file", read)
    outcome = invoke(settings)
    assert outcome.exit_code == 77 and outcome.stdout == ""
    read.assert_not_called()


def test_discriminator_disagreement_precedes_reservation(
    settings: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    reserve = Mock(side_effect=AssertionError("early reservation"))
    monkeypatch.setattr(_retention_io, "ReservedOutput", reserve)
    outcome = invoke(settings, selector="tls")
    assert outcome.exit_code == 2 and outcome.stdout == ""
    reserve.assert_not_called()


@pytest.mark.parametrize("to_file", [False, True])
def test_full_exact_unavailable_output(
    settings: tuple[Path, Path], to_file: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = actual_result()
    monkeypatch.setattr(RegistryCollector, "collect_v2", lambda self, request: result)
    destination = tmp_path / "result.json" if to_file else None
    outcome = invoke(settings, output=destination)
    assert outcome.exit_code == 1, outcome.output
    assert (destination.read_bytes() if destination else outcome.stdout.encode()) == result_bytes(result)
    assert "scope" in outcome.stderr.lower()


@pytest.mark.parametrize("body", [b"{", b"[]", b" " * 65537], ids=["malformed", "array", "oversized"])
def test_invalid_input(settings: tuple[Path, Path], body: bytes) -> None:
    settings[1].write_bytes(body)
    outcome = invoke(settings)
    assert outcome.exit_code == 2 and outcome.stdout == ""


@pytest.mark.parametrize("alias", ["same", "hardlink"])
def test_output_alias_refuses_before_collection(
    settings: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, alias: str
) -> None:
    source = settings[1]
    destination = source if alias == "same" else source.with_name("hardlink.json")
    if alias == "hardlink":
        os.link(source, destination)
    before = source.read_bytes()
    collect = Mock(side_effect=AssertionError("early collection"))
    monkeypatch.setattr(RegistryCollector, "collect_v2", collect)
    outcome = invoke(settings, output=destination)
    assert outcome.exit_code == 2 and source.read_bytes() == before
    collect.assert_not_called()


def test_mutated_worker_argument_cannot_rebind_output(
    settings: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    def worker(self: object, request: Any) -> Any:
        object.__setattr__(request.root.target, "hostname", "different.example.org")
        return actual_result(request)

    monkeypatch.setattr(RegistryCollector, "collect_v2", worker)
    outcome = invoke(settings)
    assert outcome.exit_code == 1 and outcome.stdout == ""
    assert "different.example.org" not in outcome.stderr


@pytest.mark.parametrize("name,result,raw", demo_results(), ids=[item[0] for item in demo_results()])
def test_all_selector_exit_and_json_parity(
    settings: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, name: str, result: Any, raw: bytes
) -> None:
    settings[1].write_bytes(result.request.model_dump_json().encode())
    monkeypatch.setattr(RegistryCollector, "collect_v2", lambda self, request: result)
    outcome = invoke(settings, selector=result.registry)
    success = (
        result.collection_status == "complete"
        and result.lookup_outcome in {"found", "not_found"}
        and result.freshness in {"current_observation", "dated_snapshot"}
    )
    assert outcome.exit_code == (0 if success else 1), name
    assert outcome.stdout.encode() == raw, name


@pytest.mark.parametrize("width", [80, 200])
@pytest.mark.parametrize("colored", [False, True])
def test_help_is_safe_and_readable(
    settings: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, width: int, colored: bool
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("COLUMNS", str(width))
    monkeypatch.setattr(rich_utils, "FORCE_TERMINAL", colored)
    monkeypatch.setattr(rich_utils, "COLOR_SYSTEM", "standard" if colored else None)
    monkeypatch.setattr(rich_utils, "MAX_WIDTH", width)
    result = CliRunner().invoke(app, ["--config", str(settings[0]), "collect", "registry", "--help"], color=colored)
    assert result.exit_code == 0
    visible = unstyle(result.stdout)
    for word in ("--registry", "--request-file", "--output", "65536"):
        assert word in visible
    for word in ("--token", "--base-url", "--allow-private-ips", "--enable"):
        assert word not in visible
