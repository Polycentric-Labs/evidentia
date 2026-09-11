"""Real CLI authorization, profile grants and atomic full-result publication."""

from __future__ import annotations

import builtins
import json
import os
import socket
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, Self
from unittest.mock import DEFAULT, Mock

import pytest
from click import unstyle
from evidentia.cli import _rbac
from evidentia.cli import _retention_io as file_io
from evidentia.cli.main import app
from evidentia_collectors.enterprise_retention import _contracts as contracts
from evidentia_collectors.enterprise_retention import _profiles as profiles
from evidentia_collectors.enterprise_retention import collector as feature
from evidentia_core.rbac import RBACPolicy, Role
from typer import rich_utils
from typer.testing import CliRunner, Result

from ..test_api.test_collectors_enterprise_retention import VALID, full_result, registry, selection

Request = contracts.EnterpriseRetentionCollectRequest
CollectionResult = contracts.EnterpriseRetentionCollectResult
MARKER = "synthetic-private-path-or-value"


@dataclass
class State:
    config: Path
    events: list[str] = field(default_factory=list)
    requests: list[Request] = field(default_factory=list)
    result_factory: Callable[[Request], CollectionResult] = lambda request: full_result()
    construct: Callable[[], None] | None = None
    closing: Callable[[], None] | None = None

    def invoke(self, source: Path | str, output: Path | str | None = None, *, stdin: str | None = None) -> Result:
        args = ["--config", str(self.config), "collect", "enterprise-retention", "--request-file", str(source)]
        if output is not None:
            args.extend(["--output", str(output)])
        return CliRunner().invoke(app, args, input=stdin)


@pytest.fixture
def state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[State]:
    for name in ("EVIDENTIA_RBAC_POLICY_FILE", "EVIDENTIA_RBAC_IDENTITY", "EVIDENTIA_RBAC_TENANT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE", str(tmp_path / "synthetic-profiles.json"))
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "empty.yaml"
    config.write_text("{}\n", encoding="utf-8", newline="\n")
    result = State(config)
    monkeypatch.setattr(_rbac, "get_rbac_policy", lambda: RBACPolicy(default_role=Role.READER))
    monkeypatch.setattr(_rbac, "get_rbac_identity", lambda: "synthetic-reader")
    monkeypatch.setattr(profiles, "load_profile_registry", lambda path: registry(local=True))
    refuse = Mock(side_effect=AssertionError("unexpected provider connection"))
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)

    class Collector:
        def __init__(self, *, profile: profiles.AuthorizedProfile) -> None:
            assert type(profile) is profiles.AuthorizedProfile
            assert profile.profile.allow_local_cli is True
            result.events.append("construct")
            if result.construct is not None:
                result.construct()

        def __enter__(self) -> Self:
            result.events.append("enter")
            return self

        def collect_v2(self, request: Request) -> CollectionResult:
            result.events.append("collect")
            result.requests.append(request)
            return result.result_factory(request)

        def __exit__(
            self, kind: type[BaseException] | None, error: BaseException | None, trace: TracebackType | None
        ) -> None:
            result.events.append("close")
            if result.closing is not None:
                result.closing()

    monkeypatch.setattr(feature, "EnterpriseRetentionCollector", Collector)
    yield result


@pytest.fixture
def source(tmp_path: Path) -> Path:
    path = tmp_path / "request.json"
    path.write_bytes(json.dumps(VALID).encode())
    return path


@pytest.mark.parametrize("status", ["complete", "partial", "unavailable"])
@pytest.mark.parametrize("to_file", [False, True])
def test_full_statuses_preserve_exact_canonical_bytes(
    state: State, source: Path, tmp_path: Path, status: str, to_file: bool
) -> None:
    result = full_result(status)
    source.write_bytes(json.dumps(selection(status)).encode())
    state.result_factory = lambda request: result
    output = tmp_path / "result.json" if to_file else None
    outcome = state.invoke(source, output)
    assert outcome.exit_code == (0 if status == "complete" else 1), outcome.output
    raw = output.read_bytes() if output is not None else outcome.stdout.encode()
    assert raw == result.publication_bytes()
    assert CollectionResult.model_validate_json(raw).root.status == status
    assert not raw.endswith(b"\n")
    assert state.events == ["construct", "enter", "collect", "close"]
    if status != "unavailable":
        assert b"9007199254740993" in raw and b'"00042"' in raw
    if to_file:
        assert outcome.stdout == ""


@pytest.mark.parametrize("width", [80, 200])
@pytest.mark.parametrize("colored", [False, True])
def test_real_help_at_both_widths_and_color_modes(
    state: State, monkeypatch: pytest.MonkeyPatch, width: int, colored: bool
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("LINES", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("COLUMNS", str(width))
    monkeypatch.setattr(rich_utils, "FORCE_TERMINAL", colored)
    monkeypatch.setattr(rich_utils, "COLOR_SYSTEM", "standard" if colored else None)
    monkeypatch.setattr(rich_utils, "MAX_WIDTH", width)
    outcome = CliRunner().invoke(
        app, ["--config", str(state.config), "collect", "enterprise-retention", "--help"], color=colored
    )
    assert outcome.exit_code == 0 and ("\x1b[" in outcome.stdout) is colored
    visible = unstyle(outcome.stdout)
    for word in ("--request-file", "--output", "65536", "EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE"):
        assert word in visible
    assert "--token" not in visible and "--base-url" not in visible and state.events == []


def test_read_role_precedes_paths_profile_loading_and_collector(
    state: State, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = source.with_name("output.json")
    watched = {str(source), str(output)}
    metadata: list[str] = []

    def observe(path: object, *args: object, **kwargs: object) -> object:
        if isinstance(path, (str, bytes, os.PathLike)) and os.fsdecode(path) in watched:
            metadata.append(os.fsdecode(path))
        return DEFAULT

    monkeypatch.setattr(os, "stat", Mock(wraps=os.stat, side_effect=observe))
    monkeypatch.setattr(_rbac, "get_rbac_policy", lambda: RBACPolicy(default_role=Role.DENY))
    read = Mock(side_effect=AssertionError("read before role"))
    load = Mock(side_effect=AssertionError("profile load before role"))
    monkeypatch.setattr(file_io, "read_request_file", read)
    monkeypatch.setattr(profiles, "load_profile_registry", load)
    outcome = state.invoke(source, output)
    assert outcome.exit_code == 77 and outcome.stdout == "" and metadata == [] and state.events == []
    read.assert_not_called()
    load.assert_not_called()


@pytest.mark.parametrize("mode", ["absent", "api-only", "unknown", "wrong-provider", "empty"])
def test_cli_requires_its_own_explicit_profile_grant(
    state: State, source: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    if mode == "absent":
        monkeypatch.delenv("EVIDENTIA_ENTERPRISE_RETENTION_PROFILES_FILE")
    elif mode == "api-only":
        monkeypatch.setattr(profiles, "load_profile_registry", lambda path: registry(local=False))
    elif mode == "empty":
        monkeypatch.setattr(profiles, "load_profile_registry", lambda path: profiles.ProfileRegistry())
    else:
        change = {"profile_alias": "unknown"} if mode == "unknown" else {"provider": "elastic-ilm"}
        source.write_bytes(json.dumps({**VALID, **change}).encode())
    outcome = state.invoke(source)
    assert outcome.exit_code == 77 and outcome.stdout == "" and state.events == []
    assert outcome.stderr == "The selected collection profile is unavailable.\n"


def test_profile_configuration_errors_are_sanitized(
    state: State, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(profiles, "load_profile_registry", Mock(side_effect=ValueError(MARKER)))
    outcome = state.invoke(source)
    assert outcome.exit_code == 1 and state.events == [] and MARKER not in outcome.output


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{",
        b"[]",
        b"null",
        b"false",
        b"1",
        b"provider: splunk",
        b"\xef\xbb\xbf{}",
        b'{"provider":"splunk-enterprise","provider":"elastic-ilm"}',
        b'{"x":NaN}',
        b'{"x":"\\ud800"}',
        b'{"x":"\xff"}',
        b" " * 65537,
    ],
    ids=lambda raw: f"input-{len(raw)}-bytes",
)
def test_invalid_input_is_refused_before_profiles(
    state: State, source: Path, monkeypatch: pytest.MonkeyPatch, raw: bytes
) -> None:
    source.write_bytes(raw)
    load = Mock(side_effect=AssertionError("invalid input read a profile"))
    monkeypatch.setattr(profiles, "load_profile_registry", load)
    outcome = state.invoke(source)
    assert outcome.exit_code == 2 and outcome.stdout == "" and state.events == []
    assert outcome.stderr == "Invalid enterprise retention request.\n"
    load.assert_not_called()


@pytest.mark.parametrize("size", [65536, 65537])
def test_actual_file_byte_limit(state: State, source: Path, size: int) -> None:
    raw = json.dumps(VALID).encode()
    source.write_bytes(raw + b" " * (size - len(raw)))
    outcome = state.invoke(source)
    assert outcome.exit_code == (0 if size == 65536 else 2), outcome.output
    assert bool(state.events) is (size == 65536)


@pytest.mark.parametrize(
    "mode",
    [
        "missing",
        "directory",
        "stdin",
        "symlink",
        "parent-symlink",
        "parent-symlink-dotdot",
        "hardlink",
        "device",
        "ads",
    ],
)
def test_named_regular_unlinked_input_only(state: State, source: Path, tmp_path: Path, mode: str) -> None:
    candidate: Path | str = source
    if mode == "missing":
        candidate = tmp_path / MARKER
    elif mode == "directory":
        candidate = tmp_path
    elif mode == "stdin":
        candidate = "-"
    elif mode == "symlink":
        candidate = tmp_path / "input-link.json"
        candidate.symlink_to(source)
    elif mode.startswith("parent-symlink"):
        parent = tmp_path / "input-parent"
        parent.symlink_to(tmp_path, target_is_directory=True)
        candidate = parent / (".." if mode.endswith("dotdot") else ".") / source.name
    elif mode == "hardlink":
        candidate = tmp_path / "input-hardlink.json"
        os.link(source, candidate)
    elif mode == "device":
        candidate = "NUL"
    else:
        candidate = str(source) + ":stream"
    before = source.read_bytes()
    outcome = state.invoke(candidate, stdin=json.dumps(VALID))
    assert outcome.exit_code == 2 and outcome.stdout == "" and state.events == []
    assert source.read_bytes() == before and MARKER not in outcome.output


@pytest.mark.parametrize("mode", ["same", "hardlink", "symlink", "parent-symlink"])
def test_input_output_aliases_never_collect(state: State, source: Path, tmp_path: Path, mode: str) -> None:
    output = source
    if mode == "hardlink":
        output = tmp_path / "output.json"
        os.link(source, output)
    elif mode == "symlink":
        output = tmp_path / "output.json"
        output.symlink_to(source)
    elif mode == "parent-symlink":
        parent = tmp_path / "output-parent"
        parent.symlink_to(tmp_path, target_is_directory=True)
        output = parent / source.name
    before = source.read_bytes()
    outcome = state.invoke(source, output)
    assert outcome.exit_code in {1, 2} and outcome.stdout == "" and state.events == []
    assert source.read_bytes() == output.read_bytes() == before


@pytest.mark.parametrize("alias", [True, False])
def test_editor_save_keeps_original_selection_and_protects_new_input(
    state: State, source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, alias: bool
) -> None:
    original_read = file_io.read_request_file
    edited = json.dumps({**VALID, "scope_label": "edited"}).encode()

    def saved(path: Path) -> file_io.InputSnapshot:
        snapshot = original_read(path)
        replacement = tmp_path / "editor.json"
        replacement.write_bytes(edited)
        os.replace(replacement, source)
        return snapshot

    monkeypatch.setattr(file_io, "read_request_file", saved)
    output = source if alias else tmp_path / "output.json"
    outcome = state.invoke(source, output)
    assert source.read_bytes() == edited
    if alias:
        assert outcome.exit_code == 2 and state.events == []
    else:
        assert outcome.exit_code == 0, outcome.output
        assert CollectionResult.model_validate_json(output.read_bytes()).root.scope_label == "synthetic"


def test_exclusive_output_reservation_precedes_collection(state: State, source: Path, tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    output.write_bytes(b"previous output")

    def reserved() -> None:
        files = list(tmp_path.glob(".evidentia-retention-*.tmp"))
        assert len(files) == 1 and files[0].stat().st_nlink == 1
        assert output.read_bytes() == b"previous output"

    state.construct = reserved
    outcome = state.invoke(source, output)
    assert outcome.exit_code == 0, outcome.output
    assert list(tmp_path.glob(".evidentia-retention-*.tmp")) == []


def test_reservation_failure_never_constructs_collector(
    state: State, source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "mkstemp", Mock(side_effect=OSError(MARKER)))
    outcome = state.invoke(source, tmp_path / "result.json")
    assert outcome.exit_code == 1 and outcome.stdout == "" and state.events == [] and MARKER not in outcome.output


@pytest.mark.parametrize("stage", ["construct", "collect", "close", "serialize"])
def test_failures_preserve_old_output_and_close_owned_resources(
    state: State, source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    output = tmp_path / "result.json"
    output.write_bytes(b"previous output")
    fail = Mock(side_effect=RuntimeError(MARKER))
    if stage == "construct":
        state.construct = fail
    elif stage == "close":
        state.closing = fail
    elif stage == "collect":
        state.result_factory = fail
    else:
        result = full_result()
        state.result_factory = lambda request: result
        monkeypatch.setattr(CollectionResult, "publication_bytes", fail)
    outcome = state.invoke(source, output)
    assert outcome.exit_code == 1 and outcome.stdout == "" and MARKER not in outcome.output
    assert output.read_bytes() == b"previous output" and list(tmp_path.glob(".evidentia-retention-*.tmp")) == []
    if stage != "construct":
        assert state.events[-1] == "close"


@pytest.mark.parametrize("operation", ["fsync", "replace", "write", "flush"])
def test_atomic_output_faults_preserve_existing_file(
    state: State, source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    output = tmp_path / "result.json"
    output.write_bytes(b"previous output")
    if operation in {"fsync", "replace"}:
        monkeypatch.setattr(os, operation, Mock(side_effect=OSError(MARKER)))
    else:
        original = os.fdopen

        def opened(fd: int, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            stream = original(fd, mode, *args, **kwargs)
            if mode == "w+b":

                class FaultedStream:
                    def __getattr__(self, name: str) -> Any:
                        if name == operation:
                            return Mock(side_effect=OSError(MARKER))
                        return getattr(stream, name)

                return FaultedStream()
            return stream

        monkeypatch.setattr(os, "fdopen", opened)
    outcome = state.invoke(source, output)
    assert outcome.exit_code == 1 and outcome.stdout == "" and MARKER not in outcome.output
    assert output.read_bytes() == b"previous output" and list(tmp_path.glob(".evidentia-retention-*.tmp")) == []


@pytest.mark.parametrize("change", ["created", "edited", "symlink", "hardlink"])
def test_concurrently_changed_output_is_preserved(state: State, source: Path, tmp_path: Path, change: str) -> None:
    output = tmp_path / "result.json"
    if change == "edited":
        output.write_bytes(b"previous output")

    def changed() -> None:
        if change == "symlink":
            output.symlink_to(source)
        elif change == "hardlink":
            os.link(source, output)
        else:
            output.write_bytes(b"concurrent output")

    state.closing = changed
    before = source.read_bytes()
    outcome = state.invoke(source, output)
    assert outcome.exit_code in {1, 2} and outcome.stdout == "" and source.read_bytes() == before
    assert output.read_bytes() == (before if change in {"symlink", "hardlink"} else b"concurrent output")


@pytest.mark.parametrize(
    "field,changed", [("profile_alias", "other"), ("scope_label", "other"), ("targets", [{"index": "other"}])]
)
@pytest.mark.parametrize("mutate", [False, True])
def test_result_is_bound_to_original_request(
    state: State,
    source: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    changed: object,
    mutate: bool,
) -> None:
    source.write_bytes(json.dumps({**VALID, field: changed}).encode())
    if field == "profile_alias":
        original = registry(local=True)
        configured = original.profiles[0]
        from dataclasses import replace

        monkeypatch.setattr(
            profiles,
            "load_profile_registry",
            lambda path: profiles.ProfileRegistry((replace(configured, alias="other"),), original.resolver),
        )

    def response(request: Request) -> CollectionResult:
        if mutate:
            request.root = contracts.validated_request(VALID).root
        return full_result()

    state.result_factory = response
    output = tmp_path / "result.json"
    output.write_bytes(b"previous output")
    outcome = state.invoke(source, output)
    assert outcome.exit_code == 1 and output.read_bytes() == b"previous output" and state.events[-1] == "close"


@pytest.mark.parametrize(
    "missing,absent",
    [
        ("evidentia_collectors", True),
        ("evidentia_collectors.enterprise_retention", True),
        ("evidentia_collectors.enterprise_retention._contracts", False),
        ("unrelated_transitive_dependency", False),
    ],
)
def test_only_exact_missing_optional_package_is_absence(
    state: State, source: Path, monkeypatch: pytest.MonkeyPatch, missing: str, absent: bool
) -> None:
    original = builtins.__import__

    def importing(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "evidentia_collectors.enterprise_retention._contracts":
            raise ModuleNotFoundError(MARKER, name=missing)
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", importing)
    outcome = state.invoke(source)
    assert outcome.exit_code == 1 and state.events == [] and MARKER not in outcome.output
    assert outcome.stderr == (
        "Enterprise retention collection is not installed.\n"
        if absent
        else "Enterprise retention collection could not be loaded.\n"
    )
