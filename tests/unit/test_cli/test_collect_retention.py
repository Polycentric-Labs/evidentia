"""Storage retention CLI authorization, file boundaries and full result output."""

from __future__ import annotations

import builtins
import json
import os
import socket
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Self
from unittest.mock import DEFAULT, Mock

import httpx
import pytest
from click import unstyle
from evidentia.cli import _rbac
from evidentia.cli import _retention_io as file_io
from evidentia.cli.main import app
from evidentia_collectors.retention import _contracts as contracts
from evidentia_collectors.retention import collector as feature
from evidentia_collectors.retention._credentials import BearerCredentials, CredentialResolution
from evidentia_collectors.retention.collector import StorageRetentionCollector as RealCollector
from evidentia_core.rbac import RBACPolicy, Role
from typer import rich_utils
from typer.testing import CliRunner, Result

Request = contracts.StorageRetentionCollectRequest
CollectionResult = contracts.StorageRetentionCollectResult
NOW = datetime(2025, 2, 3, 4, 5, 6, 789012, tzinfo=UTC)
VALID = {
    "provider": "gcs",
    "scope_label": "synthetic-scope",
    "targets": [{"bucket": "synthetic-one"}, {"bucket": "synthetic-two"}],
}
MARKER = "synthetic-private-path-or-value"


def make_result(request: Request, status: str = "complete") -> CollectionResult:
    components: dict[str, list[contracts.StorageRetentionComponentResult]] = {}
    for index, target in enumerate(request.root.targets):
        assert isinstance(target, (contracts.S3Target, contracts.AzureTarget, contracts.GcsTarget))
        admitted = status == "complete" or (status == "partial" and index == 0)
        diagnostics = () if admitted else (contracts.StorageRetentionDiagnostic(code="forbidden", http_status=403),)
        parts = [
            contracts.make_component_result(
                name,
                target,
                attempts=1,
                raw_bytes=2,
                decoded_bytes=2,
                started_at=NOW,
                finished_at=NOW,
                http_status=200 if admitted else 403,
                projection=contracts.ProjectedComponent("synthetic-v1", "configuration", {"observed": True})
                if admitted
                else None,
                diagnostics=diagnostics,
            )
            for name in contracts.component_ids(request.root.provider)
        ]
        components[contracts.target_identity(target)] = parts
    return contracts.make_result(
        request,
        run_id="synthetic-cli-run",
        started_at=NOW,
        finished_at=NOW,
        components=components,
        diagnostics=(),
    )


@dataclass
class State:
    events: list[str] = field(default_factory=list)
    requests: list[Request] = field(default_factory=list)
    result_factory: Callable[[Request], CollectionResult] = make_result
    construct: Callable[[], None] | None = None
    closing: Callable[[], None] | None = None
    config: Path = Path()

    def invoke(self, source: Path | str, output: Path | None = None, *, stdin: str | None = None) -> Result:
        args = ["--config", str(self.config), "collect", "retention", "--request-file", str(source)]
        if output is not None:
            args.extend(["--output", str(output)])
        return CliRunner().invoke(app, args, input=stdin)


@pytest.fixture
def state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[State]:
    for name in (
        "EVIDENTIA_RBAC_POLICY_FILE",
        "EVIDENTIA_RBAC_IDENTITY",
        "EVIDENTIA_RBAC_TENANT",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "STORAGE_RETENTION_AZURE_ACCESS_TOKEN",
        "STORAGE_RETENTION_GCS_ACCESS_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "empty.yaml"
    config.write_text("{}\n", encoding="utf-8", newline="\n")
    result = State(config=config)
    monkeypatch.setattr(_rbac, "get_rbac_policy", lambda: RBACPolicy(default_role=Role.READER))
    monkeypatch.setattr(_rbac, "get_rbac_identity", lambda: "synthetic-reader")

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("Provider and socket access are forbidden")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)

    class Collector:
        def __init__(self) -> None:
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

        def close(self) -> None:
            result.events.append("close")
            if result.closing is not None:
                result.closing()

        def __exit__(
            self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
        ) -> None:
            self.close()

    monkeypatch.setattr(feature, "StorageRetentionCollector", Collector)
    yield result


@pytest.fixture
def source(tmp_path: Path) -> Path:
    path = tmp_path / "request.json"
    path.write_text(json.dumps(VALID), encoding="utf-8", newline="\n")
    return path


@pytest.mark.parametrize("status", ["complete", "partial", "unavailable"])
@pytest.mark.parametrize("to_file", [False, True])
def test_all_statuses_retain_full_result_and_exit_code(
    state: State, source: Path, tmp_path: Path, status: str, to_file: bool
) -> None:
    state.result_factory = lambda request: make_result(request, status)
    output = tmp_path / "result.json" if to_file else None
    outcome = state.invoke(source, output)
    assert outcome.exit_code == (0 if status == "complete" else 1), outcome.output
    text = output.read_text(encoding="utf-8") if output is not None else outcome.stdout
    restored = CollectionResult.model_validate_json(text)
    assert restored.status == status
    assert len(restored.resources) == 2 and restored.requested_resources == 2
    assert restored.manifest.is_complete is (status == "complete")
    assert text.endswith("\n") and "\r" not in text
    assert state.events == ["construct", "enter", "collect", "close"]
    assert outcome.stderr == "" if status == "complete" else "incomplete" in outcome.stderr.lower()
    if to_file:
        assert outcome.stdout == ""


@pytest.mark.parametrize("width", [80, 200])
@pytest.mark.parametrize("colored", [False, True])
def test_real_help_keeps_all_options_and_fixed_credential_references(
    state: State, monkeypatch: pytest.MonkeyPatch, width: int, colored: bool
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("LINES", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("COLUMNS", str(width))
    monkeypatch.setattr(rich_utils, "FORCE_TERMINAL", colored)
    monkeypatch.setattr(rich_utils, "COLOR_SYSTEM", "standard" if colored else None)
    monkeypatch.setattr(rich_utils, "MAX_WIDTH", width)
    outcome = CliRunner().invoke(app, ["--config", str(state.config), "collect", "retention", "--help"], color=colored)
    assert outcome.exit_code == 0
    assert ("\x1b[" in outcome.stdout) is colored
    text = unstyle(outcome.stdout)
    assert max(map(len, text.splitlines())) == width
    for word in (
        "--request-file",
        "--output",
        "65536",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "STORAGE_RETENTION_AZURE_ACCESS_TOKEN",
        "STORAGE_RETENTION_GCS_ACCESS_TOKEN",
    ):
        assert word in text
    assert "--token" not in text and "--base-url" not in text
    assert state.events == []


def test_actual_read_role_denies_before_file_and_feature_work(
    state: State, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_rbac, "get_rbac_policy", lambda: RBACPolicy(default_role=Role.DENY))
    read = Mock(side_effect=AssertionError("Request file opened before authorization"))
    reserve = Mock(side_effect=AssertionError("Output opened before authorization"))
    monkeypatch.setattr(file_io, "read_request_file", read)
    monkeypatch.setattr(file_io, "ReservedOutput", reserve)
    outcome = state.invoke(source, source.with_name("output.json"))
    assert outcome.exit_code == 77 and outcome.stdout == ""
    assert state.events == [] and read.call_count == reserve.call_count == 0


@pytest.mark.parametrize("output_unreadable", [False, True])
def test_read_role_precedes_request_and_output_metadata_access(
    state: State, source: Path, monkeypatch: pytest.MonkeyPatch, output_unreadable: bool
) -> None:
    output = source.with_name("output.json")
    output.write_bytes(b"previous output")
    events: list[str] = []
    watched = {str(source): "input", str(output): "output"}

    def label(path: object) -> str | None:
        return watched.get(os.fsdecode(path)) if isinstance(path, (str, bytes, os.PathLike)) else None

    def observed_stat(path: object, *args: object, **kwargs: object) -> object:
        if name := label(path):
            events.append("stat-" + name)
        return DEFAULT

    def observed_access(path: object, *args: object, **kwargs: object) -> object:
        if name := label(path):
            events.append("access-" + name)
            if output_unreadable and name == "output":
                return False
        return DEFAULT

    def denied() -> RBACPolicy:
        events.append("role-denied")
        return RBACPolicy(default_role=Role.DENY)

    monkeypatch.setattr(os, "stat", Mock(wraps=os.stat, side_effect=observed_stat))
    monkeypatch.setattr(os, "access", Mock(wraps=os.access, side_effect=observed_access))
    monkeypatch.setattr(_rbac, "get_rbac_policy", denied)
    outcome = state.invoke(source, output)
    assert outcome.exit_code == 77 and outcome.stdout == ""
    assert events == ["role-denied"] and state.events == []
    assert str(output) not in outcome.stderr


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"{",
        b"[]",
        b"null",
        b"false",
        b"1",
        b"provider: gcs",
        b"\xef\xbb\xbf{}",
        b'{"provider":"gcs","provider":"s3"}',
        b'{"scope_label":NaN}',
        b'{"scope_label":"\\ud800"}',
        b'{"scope_label":"\xff"}',
        b" " * 65537,
    ],
    ids=[
        "empty",
        "syntax",
        "array",
        "null",
        "bool",
        "integer",
        "yaml",
        "bom",
        "duplicate",
        "nonfinite",
        "surrogate",
        "utf8",
        "size",
    ],
)
def test_invalid_json_never_constructs_collector(state: State, source: Path, content: bytes) -> None:
    source.write_bytes(content)
    outcome = state.invoke(source)
    assert outcome.exit_code == 2 and outcome.stdout == ""
    assert outcome.stderr == "Invalid storage retention request.\n"
    assert state.events == []


def test_unknown_request_fields_do_not_escape_in_errors(state: State, source: Path) -> None:
    source.write_text(json.dumps({**VALID, MARKER: MARKER}), encoding="utf-8", newline="\n")
    outcome = state.invoke(source)
    assert outcome.exit_code == 2 and outcome.stdout == ""
    assert MARKER not in outcome.output and str(source) not in outcome.output
    assert state.events == []


@pytest.mark.parametrize("size,accepted", [(65536, True), (65537, False)])
def test_actual_raw_byte_limit(state: State, source: Path, size: int, accepted: bool) -> None:
    content = json.dumps(VALID).encode()
    source.write_bytes(content + b" " * (size - len(content)))
    outcome = state.invoke(source)
    assert outcome.exit_code == (0 if accepted else 2)
    assert bool(state.events) is accepted


@pytest.mark.parametrize(
    "mode", ["missing", "directory", "stdin", "symlink", "parent-symlink", "parent-symlink-dotdot", "hardlink"]
)
def test_named_regular_unlinked_request_only(state: State, source: Path, tmp_path: Path, mode: str) -> None:
    candidate: Path | str = source
    if mode == "missing":
        candidate = tmp_path / MARKER
    elif mode == "directory":
        candidate = tmp_path
    elif mode == "stdin":
        candidate = "-"
    elif mode == "symlink":
        candidate = tmp_path / "link.json"
        candidate.symlink_to(source)
    elif mode in {"parent-symlink", "parent-symlink-dotdot"}:
        parent = tmp_path / "linked-parent"
        parent.symlink_to(tmp_path, target_is_directory=True)
        candidate = parent / (".." if mode == "parent-symlink-dotdot" else ".") / source.name
    else:
        candidate = tmp_path / "hardlink.json"
        os.link(source, candidate)
    before = source.read_bytes()
    outcome = state.invoke(candidate, stdin=json.dumps(VALID))
    assert outcome.exit_code == 2 and outcome.stdout == ""
    assert MARKER not in outcome.output and state.events == []
    assert source.read_bytes() == before


@pytest.mark.parametrize("mode", ["same", "hardlink", "symlink", "parent-symlink"])
def test_input_output_aliases_preserve_request_and_never_collect(
    state: State, source: Path, tmp_path: Path, mode: str
) -> None:
    output = source
    if mode == "hardlink":
        output = tmp_path / "output.json"
        os.link(source, output)
    elif mode == "symlink":
        output = tmp_path / "output.json"
        output.symlink_to(source)
    elif mode == "parent-symlink":
        parent = tmp_path / "link"
        parent.symlink_to(tmp_path, target_is_directory=True)
        output = parent / source.name
    before = source.read_bytes()
    outcome = state.invoke(source, output)
    assert outcome.exit_code in {1, 2} and outcome.stdout == ""
    assert source.read_bytes() == before and output.read_bytes() == before
    assert state.events == []


@pytest.mark.parametrize("spelling", ["input-parent", "output-parent", "unrelated"])
def test_atomic_editor_save_does_not_allow_output_to_replace_request(
    state: State, source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spelling: str
) -> None:
    child = tmp_path / "child"
    child.mkdir()
    alias = child / ".." / source.name
    source_arg = alias if spelling == "input-parent" else source
    output = source if spelling == "input-parent" else alias
    if spelling == "unrelated":
        output = tmp_path / "result.json"
    editor_bytes = json.dumps({**VALID, "scope_label": "edited-scope"}).encode("utf-8")
    original_read = file_io.read_request_file

    def saved(path: Path) -> file_io.InputSnapshot:
        snapshot = original_read(path)
        replacement = tmp_path / "editor-save.json"
        replacement.write_bytes(editor_bytes)
        os.replace(replacement, source)
        assert (source.stat().st_dev, source.stat().st_ino) != snapshot.identity
        return snapshot

    monkeypatch.setattr(file_io, "read_request_file", saved)
    outcome = state.invoke(source_arg, output)
    assert source.read_bytes() == editor_bytes
    assert outcome.stdout == ""
    if spelling == "unrelated":
        assert outcome.exit_code == 0, outcome.output
        result = CollectionResult.model_validate_json(output.read_bytes())
        assert result.scope_label == VALID["scope_label"]
        assert len(result.resources) == 2
    else:
        assert outcome.exit_code == 2 and state.events == []


@pytest.mark.parametrize(
    "mode",
    ["directory", "missing-parent", "symlink", "parent-symlink", "parent-symlink-dotdot", "hardlink", "readonly"],
)
def test_invalid_output_fails_before_collector_and_preserves_existing_bytes(
    state: State, source: Path, tmp_path: Path, mode: str
) -> None:
    existing = tmp_path / "existing.json"
    existing.write_bytes(b"previous output")
    output = tmp_path / "output.json"
    if mode == "directory":
        output.mkdir()
    elif mode == "missing-parent":
        output = tmp_path / "missing" / "result.json"
    elif mode == "symlink":
        output.symlink_to(existing)
    elif mode in {"parent-symlink", "parent-symlink-dotdot"}:
        parent = tmp_path / "linked-output"
        parent.symlink_to(tmp_path, target_is_directory=True)
        output = parent / (".." if mode == "parent-symlink-dotdot" else ".") / "result.json"
    elif mode == "hardlink":
        os.link(existing, output)
    else:
        output = existing
        output.chmod(0o444)
    try:
        outcome = state.invoke(source, output)
        assert outcome.exit_code == 1 and outcome.stdout == ""
        assert state.events == [] and existing.read_bytes() == b"previous output"
    finally:
        existing.chmod(0o600)


def test_exclusive_reservation_exists_before_collection_and_cleans_after_publish(
    state: State, source: Path, tmp_path: Path
) -> None:
    output = tmp_path / "result.json"
    output.write_bytes(b"old")
    collision = tmp_path / "result.json.tmp"
    collision.write_bytes(b"unrelated")

    def before() -> None:
        reserved = list(tmp_path.glob(".evidentia-retention-*.tmp"))
        assert len(reserved) == 1 and reserved[0].is_file()
        assert reserved[0].stat().st_nlink == 1
        assert output.read_bytes() == b"old"

    state.construct = before
    outcome = state.invoke(source, output)
    assert outcome.exit_code == 0, outcome.output
    assert state.events == ["construct", "enter", "collect", "close"]
    assert list(tmp_path.glob(".evidentia-retention-*.tmp")) == []
    assert collision.read_bytes() == b"unrelated"


def test_reservation_failure_does_no_provider_work(
    state: State, source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refused(*args: object, **kwargs: object) -> None:
        raise OSError(MARKER)

    monkeypatch.setattr(tempfile, "mkstemp", refused)
    outcome = state.invoke(source, tmp_path / "result.json")
    assert outcome.exit_code == 1 and outcome.stdout == ""
    assert state.events == [] and MARKER not in outcome.output


@pytest.mark.parametrize("stage", ["construct", "collect", "close"])
def test_collector_failure_closes_and_preserves_old_output(
    state: State, source: Path, tmp_path: Path, stage: str
) -> None:
    output = tmp_path / "result.json"
    output.write_bytes(b"old bytes")

    def failure() -> None:
        raise RuntimeError(MARKER)

    if stage == "construct":
        state.construct = failure
    elif stage == "close":
        state.closing = failure
    else:

        def fail_collect(request: Request) -> CollectionResult:
            raise RuntimeError(MARKER)

        state.result_factory = fail_collect
    outcome = state.invoke(source, output)
    assert outcome.exit_code == 1 and outcome.stdout == "" and MARKER not in outcome.output
    assert output.read_bytes() == b"old bytes"
    assert list(tmp_path.glob(".evidentia-retention-*.tmp")) == []
    if stage != "construct":
        assert state.events[-1] == "close"


@pytest.mark.parametrize(
    "failure",
    [
        "invalid-result",
        "different-request",
        "different-provider",
        "different-target",
        "different-order",
        "mutated-request",
    ],
)
def test_revalidation_precedes_every_output(state: State, source: Path, tmp_path: Path, failure: str) -> None:
    output = tmp_path / "result.json"
    output.write_bytes(b"old bytes")

    def response(request: Request) -> CollectionResult:
        if failure == "different-request":
            alternate = contracts.validated_request({**VALID, "scope_label": "different"})
            return make_result(alternate)
        if failure == "different-provider":
            return make_result(
                contracts.validated_request(
                    {
                        "provider": "s3",
                        "scope_label": "synthetic-scope",
                        "targets": [{"bucket": "synthetic-one", "region": "us-east-1"}],
                    }
                )
            )
        if failure == "different-target":
            return make_result(contracts.validated_request({**VALID, "targets": [{"bucket": "different-bucket"}]}))
        if failure == "different-order":
            return make_result(
                contracts.validated_request(
                    {**VALID, "targets": [{"bucket": "synthetic-two"}, {"bucket": "synthetic-one"}]}
                )
            )
        if failure == "mutated-request":
            request.root.scope_label = "different"
            return make_result(request)
        result = make_result(request)
        result.__dict__["object_enforcement_assessed"] = 0
        return result

    state.result_factory = response
    outcome = state.invoke(source, output)
    assert outcome.exit_code == 1 and outcome.stdout == ""
    assert output.read_bytes() == b"old bytes"
    assert state.events[-1] == "close"
    assert list(tmp_path.glob(".evidentia-retention-*.tmp")) == []


@pytest.mark.parametrize("operation", ["fsync", "replace"])
def test_atomic_write_failures_preserve_old_output(
    state: State, source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    output = tmp_path / "result.json"
    output.write_bytes(b"old bytes")

    def failure(*args: object, **kwargs: object) -> None:
        raise OSError(MARKER)

    monkeypatch.setattr(os, operation, failure)
    outcome = state.invoke(source, output)
    assert outcome.exit_code == 1 and outcome.stdout == "" and MARKER not in outcome.output
    assert output.read_bytes() == b"old bytes"
    assert list(tmp_path.glob(".evidentia-retention-*.tmp")) == []


@pytest.mark.parametrize("change", ["new-file", "symlink", "hardlink", "same-file-edited"])
def test_changed_output_is_refused_after_collection(state: State, source: Path, tmp_path: Path, change: str) -> None:
    output = tmp_path / "result.json"
    if change == "same-file-edited":
        output.write_bytes(b"old bytes")

    def mutate() -> None:
        if change == "symlink":
            output.symlink_to(source)
        elif change == "hardlink":
            os.link(source, output)
        else:
            output.write_bytes(b"concurrent bytes")

    state.closing = mutate
    before = source.read_bytes()
    outcome = state.invoke(source, output)
    assert outcome.exit_code in {1, 2} and outcome.stdout == ""
    assert source.read_bytes() == before
    assert output.read_bytes() == (before if change in {"symlink", "hardlink"} else b"concurrent bytes")
    assert list(tmp_path.glob(".evidentia-retention-*.tmp")) == []


def test_changed_request_between_open_and_read_is_refused(
    state: State, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_open = os.open

    def replace_after_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o600,
        *,
        dir_fd: int | None = None,
    ) -> int:
        is_source = Path(os.fsdecode(path)) == source
        if is_source:
            assert flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND) == 0
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if is_source:
            source.write_text(json.dumps({**VALID, "scope_label": "changed"}), encoding="utf-8", newline="\n")
        return descriptor

    monkeypatch.setattr(os, "open", replace_after_open)
    outcome = state.invoke(source)
    assert outcome.exit_code == 2 and outcome.stdout == "" and state.events == []


@pytest.mark.parametrize("name,optional", [("botocore", True), ("defusedxml", True), ("broken_dependency", False)])
def test_optional_s3_dependency_is_distinct_from_broken_transitive_import(
    state: State, source: Path, name: str, optional: bool
) -> None:
    source.write_text(
        json.dumps(
            {
                "provider": "s3",
                "scope_label": "synthetic-scope",
                "targets": [{"bucket": "example-bucket", "region": "us-east-1"}],
            }
        ),
        encoding="utf-8",
        newline="\n",
    )

    def failed(request: Request) -> CollectionResult:
        raise ModuleNotFoundError(MARKER, name=name)

    state.result_factory = failed
    outcome = state.invoke(source)
    assert outcome.exit_code == 1 and outcome.stdout == "" and MARKER not in outcome.output
    assert ("not installed" in outcome.stderr) is optional
    assert state.events[-1] == "close"


@pytest.mark.parametrize("original_s3", [False, True])
def test_optional_dependency_diagnostic_uses_original_provider(state: State, source: Path, original_s3: bool) -> None:
    s3 = {
        "provider": "s3",
        "scope_label": "synthetic-scope",
        "targets": [{"bucket": "example-bucket", "region": "us-east-1"}],
    }
    source.write_text(json.dumps(s3 if original_s3 else VALID), encoding="utf-8", newline="\n")

    def failed(request: Request) -> CollectionResult:
        request.root = contracts.validated_request(VALID if original_s3 else s3).root
        raise ModuleNotFoundError(MARKER, name="botocore")

    state.result_factory = failed
    outcome = state.invoke(source)
    assert outcome.exit_code == 1 and outcome.stdout == ""
    assert ("S3 support is not installed" in outcome.stderr) is original_s3
    assert MARKER not in outcome.stderr and state.events[-1] == "close"


@pytest.mark.parametrize("missing", ["evidentia_collectors", "evidentia_collectors.retention", "broken_dependency"])
def test_lazy_feature_import_is_sanitized_and_precedes_input_reads(
    state: State, source: Path, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    original_import = builtins.__import__

    def fail_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "evidentia_collectors.retention._contracts":
            raise ModuleNotFoundError(MARKER, name=missing)
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_import)
    read = Mock(side_effect=AssertionError("unexpected file read"))
    monkeypatch.setattr(file_io, "read_request_file", read)
    outcome = state.invoke(source)
    assert outcome.exit_code == 1 and outcome.stdout == "" and MARKER not in outcome.output
    assert ("not installed" in outcome.stderr) is (missing != "broken_dependency")
    assert read.call_count == 0 and state.events == []


def test_valid_request_with_distinct_creation_and_write_times_is_read(state: State, source: Path) -> None:
    os.utime(source, ns=(1_500_000_000_000_000_000, 1_500_000_000_000_000_000))
    outcome = state.invoke(source)
    assert outcome.exit_code == 0, outcome.output
    assert len(state.requests) == 1


def test_growing_request_is_bounded_by_bytes_actually_read(
    state: State, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_read = os.read
    total = 0
    calls = 0

    def growing(descriptor: int, size: int) -> bytes:
        nonlocal total, calls
        chunk = original_read(descriptor, size)
        total += len(chunk)
        calls += 1
        if calls == 1:
            with source.open("ab") as handle:
                handle.write(b" " * 65537)
        return chunk

    monkeypatch.setattr(os, "read", growing)
    outcome = state.invoke(source)
    assert outcome.exit_code == 2 and outcome.stdout == "" and state.events == []
    assert total == 65537


def test_source_edit_after_last_read_is_refused(state: State, source: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original_read = os.read

    def changed(descriptor: int, size: int) -> bytes:
        chunk = original_read(descriptor, size)
        if not chunk:
            with source.open("ab") as handle:
                handle.write(b" ")
        return chunk

    monkeypatch.setattr(os, "read", changed)
    outcome = state.invoke(source)
    assert outcome.exit_code == 2 and outcome.stdout == "" and state.events == []


@pytest.mark.parametrize("change", ["overwrite", "append"])
def test_written_reservation_bytes_must_match_validated_result(
    state: State, source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    output = tmp_path / "result.json"
    output.write_bytes(b"old bytes")
    original_sync = os.fsync

    def corrupt(descriptor: int) -> None:
        original_sync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET if change == "overwrite" else os.SEEK_END)
        os.write(descriptor, b"!")

    monkeypatch.setattr(os, "fsync", corrupt)
    outcome = state.invoke(source, output)
    assert outcome.exit_code == 1 and outcome.stdout == ""
    assert output.read_bytes() == b"old bytes"
    assert list(tmp_path.glob(".evidentia-retention-*.tmp")) == []


def test_new_hardlink_to_reserved_file_refuses_output_and_cleans_owned_name(
    state: State, source: Path, tmp_path: Path
) -> None:
    output = tmp_path / "result.json"
    output.write_bytes(b"old bytes")
    alias = tmp_path / "unexpected-link"

    def link_reservation() -> None:
        reserved = list(tmp_path.glob(".evidentia-retention-*.tmp"))
        assert len(reserved) == 1
        os.link(reserved[0], alias)

    state.construct = link_reservation
    outcome = state.invoke(source, output)
    assert outcome.exit_code == 1 and outcome.stdout == ""
    assert output.read_bytes() == b"old bytes" and alias.read_bytes() == b""
    assert list(tmp_path.glob(".evidentia-retention-*.tmp")) == []


def test_fd_wrapper_failure_closes_descriptor_and_removes_reservation(
    state: State, source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptors: list[int] = []

    def failed(descriptor: int, mode: str) -> None:
        descriptors.append(descriptor)
        raise OSError(MARKER)

    monkeypatch.setattr(os, "fdopen", failed)
    outcome = state.invoke(source, tmp_path / "result.json")
    assert outcome.exit_code == 1 and outcome.stdout == "" and state.events == []
    assert MARKER not in outcome.output and len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert list(tmp_path.glob(".evidentia-retention-*.tmp")) == []


def test_cancellation_closes_collector_and_preserves_old_file(state: State, source: Path, tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    output.write_bytes(b"old bytes")

    def cancelled(request: Request) -> CollectionResult:
        raise KeyboardInterrupt()

    state.result_factory = cancelled
    outcome = state.invoke(source, output)
    assert outcome.exit_code != 0 and outcome.stdout == ""
    assert state.events[-1] == "close" and output.read_bytes() == b"old bytes"
    assert list(tmp_path.glob(".evidentia-retention-*.tmp")) == []


@pytest.mark.parametrize(
    "statuses,expected", [([200, 200], "complete"), ([200, 403], "partial"), ([401], "unavailable")]
)
def test_real_collector_session_and_domain_are_wired_to_cli(
    state: State, source: Path, monkeypatch: pytest.MonkeyPatch, statuses: list[int], expected: str
) -> None:
    from evidentia_core import network_guard

    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", network_guard._GETADDRINFO_DELEGATE)
    monkeypatch.setattr(network_guard, "_offline_enabled", False)
    monkeypatch.setattr(network_guard, "enforce_public_host", lambda *args, **kwargs: ["8.8.8.8"])
    resolved: list[str] = []

    class Credentials:
        def resolve(self, provider: str) -> CredentialResolution:
            resolved.append(provider)
            return CredentialResolution(BearerCredentials("synthetic-bearer"), None)

    class Wire(httpx.BaseTransport):
        def __init__(self) -> None:
            self.paths: list[bytes] = []
            self.closed = 0

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            assert {str(item[4][0]) for item in socket.getaddrinfo(request.url.host, 443)} == {"8.8.8.8"}
            code = statuses[len(self.paths)]
            self.paths.append(request.url.raw_path)
            name = request.url.path.rsplit("/", 1)[-1]
            body = json.dumps({"name": name, "metageneration": "2", "versioning": {"enabled": False}}).encode()
            return httpx.Response(code, stream=httpx.ByteStream(body))

        def close(self) -> None:
            self.closed += 1

    wire = Wire()
    actual = RealCollector(
        credentials=Credentials(),
        transport_factory=lambda: wire,
        utc_clock=lambda: NOW,
        monotonic_clock=lambda: 0.0,
        run_id_factory=lambda: "synthetic-real-cli-run",
    )
    monkeypatch.setattr(feature, "StorageRetentionCollector", lambda: actual)
    outcome = state.invoke(source)
    assert outcome.exit_code == (0 if expected == "complete" else 1), outcome.output
    result = CollectionResult.model_validate_json(outcome.stdout)
    assert result.status == expected and len(result.resources) == 2
    assert len(wire.paths) == len(statuses) and wire.closed == 1 and resolved == ["gcs"]
    assert wire.paths[0] == b"/storage/v1/b/synthetic-one?projection=noAcl"
    if expected == "unavailable":
        assert result.resources[1].components[0].attempts == 0
    with pytest.raises(ValueError, match="collector_closed"):
        actual.collect_v2(contracts.validated_request(VALID))


@pytest.mark.parametrize("name", ["invalid*.json", "invalid?.json", "CON", "result.json.", "result.json "])
def test_platform_invalid_output_names_are_refused_before_collection(
    state: State, source: Path, tmp_path: Path, name: str
) -> None:
    output = tmp_path / name
    outcome = state.invoke(source, output)
    if os.name == "nt":
        assert outcome.exit_code == 1 and outcome.stdout == "" and state.events == []
        assert list(tmp_path.glob(".evidentia-retention-*.tmp")) == []
    else:
        assert outcome.exit_code == 0
        assert CollectionResult.model_validate_json(output.read_bytes()).status == "complete"
