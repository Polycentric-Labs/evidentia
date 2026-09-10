"""CLI evidence output, input preservation and read authorization."""

from __future__ import annotations

import builtins
import json
import os
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import Mock

import pytest
from click import unstyle
from evidentia.cli import collect as cli
from evidentia.cli._rbac_lifecycle import _reset_rbac_cache
from evidentia.cli.main import app
from evidentia_collectors import entra_m365 as feature
from typer import rich_utils
from typer.testing import CliRunner

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "entra_m365" / "purview" / "cisa-dlp-recorded.json"
_BASE = ["collect", "entra-m365", "--tenant-label", "fixture", "--capability", "dlp-export"]


@pytest.fixture(autouse=True)
def isolated_operator(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    for name in (
        "EVIDENTIA_RBAC_POLICY_FILE",
        "EVIDENTIA_RBAC_IDENTITY",
        "EVIDENTIA_RBAC_TENANT",
        "ENTRA_M365_ACCESS_TOKEN",
        "ENTRA_M365_RETENTION_ACCESS_TOKEN",
        "ENTRA_M365_AUTH_MODE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    _reset_rbac_cache()
    yield
    _reset_rbac_cache()


@pytest.fixture
def no_graph(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    from evidentia_collectors.entra_m365 import _client

    credentials = Mock(side_effect=AssertionError("unexpected credential access"))
    graph = Mock(side_effect=AssertionError("unexpected Graph read"))
    monkeypatch.setattr(_client._EnvironmentCredentials, "resolve", credentials)
    monkeypatch.setattr(_client.EntraM365GraphReader, "read_collection", graph)
    yield
    assert credentials.call_count == 0
    assert graph.call_count == 0


@pytest.mark.usefixtures("no_graph")
class TestLocalCollection:
    @pytest.mark.parametrize("colored", [False, True], ids=["plain", "colored"])
    @pytest.mark.parametrize("width", [80, 200])
    def test_registered_help_has_every_bounded_option(
        self, monkeypatch: pytest.MonkeyPatch, colored: bool, width: int
    ) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("LINES", raising=False)
        monkeypatch.setenv("TERM", "xterm-256color")
        monkeypatch.setenv("COLUMNS", str(width))
        monkeypatch.setattr(rich_utils, "FORCE_TERMINAL", colored)
        monkeypatch.setattr(rich_utils, "COLOR_SYSTEM", "standard" if colored else None)
        monkeypatch.setattr(rich_utils, "MAX_WIDTH", width)
        result = CliRunner().invoke(app, ["collect", "entra-m365", "--help"], color=colored)
        assert result.exit_code == 0
        assert ("\x1b[" in result.stdout) is colored
        help_text = unstyle(result.stdout)
        assert max(map(len, help_text.splitlines())) == width
        for name in (
            "tenant-label",
            "capability",
            "lookback-days",
            "max-items",
            "max-pages",
            "dlp-export",
            "dlp-format",
            "output",
        ):
            assert "--" + name in help_text
        for reference in (
            "ENTRA_M365_ACCESS_TOKEN",
            "ENTRA_M365_RETENTION_ACCESS_TOKEN",
            "ENTRA_M365_AUTH_MODE",
        ):
            assert reference in help_text
        assert "--access-token" not in help_text
        assert "--base-url" not in help_text

    def test_recorded_dlp_writes_full_json_only_to_stdout(self) -> None:
        result = CliRunner().invoke(app, [*_BASE, "--dlp-export", str(_FIXTURE)])
        assert result.exit_code == 0, result.output
        value = json.loads(result.stdout)
        assert value["schema_version"] == "entra-m365-collection/v1"
        assert value["status"] == "complete"
        assert value["full_surface_complete"] is False
        assert len(value["capabilities"]) == 9
        assert len(value["findings"]) == 11
        assert value["manifest"]["is_complete"] is True
        assert result.stderr == ""

    @pytest.mark.parametrize("to_file", [False, True])
    def test_missing_export_is_a_full_unavailable_result(self, tmp_path: Path, to_file: bool) -> None:
        output = tmp_path / "result.json"
        result = CliRunner().invoke(app, [*_BASE, *(["--output", str(output)] if to_file else [])])
        assert result.exit_code == 1, result.output
        value = json.loads(output.read_text(encoding="utf-8") if to_file else result.stdout)
        assert value["status"] == "unavailable"
        assert value["findings"] == []
        assert len(value["capabilities"]) == 9
        assert value["manifest"]["is_complete"] is False
        assert "incomplete" in result.stderr.lower()
        if to_file:
            assert result.stdout == ""

    @pytest.mark.parametrize("mode", ["same", "hardlink", "symlink", "parent-symlink"])
    def test_refuses_actual_input_output_aliases(self, tmp_path: Path, mode: str) -> None:
        source = tmp_path / "source.json"
        original = _FIXTURE.read_bytes()
        source.write_bytes(original)
        destination = source
        if mode == "hardlink":
            destination = tmp_path / "hardlink.json"
            os.link(source, destination)
        elif mode == "symlink":
            destination = tmp_path / "symlink.json"
            destination.symlink_to(source)
        elif mode == "parent-symlink":
            parent_alias = tmp_path / "parent-alias"
            parent_alias.symlink_to(tmp_path, target_is_directory=True)
            destination = parent_alias / source.name
        result = CliRunner().invoke(app, [*_BASE, "--dlp-export", str(source), "--output", str(destination)])
        assert result.exit_code == 2, result.output
        assert source.read_bytes() == original
        assert destination.read_bytes() == original
        assert result.stdout == ""

    def test_unique_temporary_file_preserves_old_suffix_collisions(self, tmp_path: Path) -> None:
        source = tmp_path / "result.json.tmp"
        original = _FIXTURE.read_bytes()
        source.write_bytes(original)
        destination = tmp_path / "result.json"
        destination.write_bytes(b"previous output")
        unrelated = tmp_path / "result.tmp"
        unrelated.write_bytes(b"unrelated file")
        result = CliRunner().invoke(app, [*_BASE, "--dlp-export", str(source), "--output", str(destination)])
        assert result.exit_code == 0, result.output
        assert source.read_bytes() == original
        assert unrelated.read_bytes() == b"unrelated file"
        assert json.loads(destination.read_text(encoding="utf-8"))["status"] == "complete"
        assert result.stdout == ""
        assert sorted(p.name for p in tmp_path.iterdir()) == ["result.json", "result.json.tmp", "result.tmp"]

    @pytest.mark.parametrize(
        "body",
        [
            b"{",
            b'{"schema_version":1,"schema_version":1}',
            b"\xff",
            b"[]",
            b"x" * (4_194_304 + 1),
        ],
        ids=["invalid-json", "duplicate-key", "invalid-utf8", "not-object", "over-byte-limit"],
    )
    def test_invalid_export_precedes_graph_and_preserves_output(self, tmp_path: Path, body: bytes) -> None:
        source = tmp_path / "input.json"
        destination = tmp_path / "output.json"
        source.write_bytes(body)
        destination.write_bytes(b"previous output")
        result = CliRunner().invoke(
            app,
            [
                *_BASE,
                "--capability",
                "directory-roles",
                "--dlp-export",
                str(source),
                "--output",
                str(destination),
            ],
        )
        assert result.exit_code == 2, result.output
        assert source.read_bytes() == body
        assert destination.read_bytes() == b"previous output"
        assert result.stdout == ""
        assert "Traceback" not in result.stderr
        assert not list(tmp_path.glob(".output.json.*"))

    @pytest.mark.parametrize(
        "args",
        [
            ["--dlp-format", "evidentia-dlp-v1"],
            ["--capability", "dlp-export"],
            ["--capability", "unknown"],
            ["--lookback-days", "31"],
            ["--max-pages", "101"],
            ["--max-items", "0"],
            ["--tenant-label", "invalid alias"],
            ["--access-token", "synthetic-marker"],
        ],
    )
    def test_invalid_request_is_exit_two(self, args: list[str]) -> None:
        result = CliRunner().invoke(app, [*_BASE, *args])
        assert result.exit_code == 2
        assert result.stdout == ""

    def test_output_preflight_fails_before_graph(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            app,
            [
                *_BASE,
                "--capability",
                "directory-roles",
                "--output",
                str(tmp_path / "missing" / "result.json"),
            ],
        )
        assert result.exit_code == 1, result.output
        assert result.stdout == ""
        assert not (tmp_path / "missing").exists()

    def test_read_deny_precedes_file_read_and_collection(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        policy = tmp_path / "deny.json"
        policy.write_text('{"identities": {}, "default_role": "deny"}', encoding="utf-8")
        monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy))
        result = CliRunner().invoke(app, [*_BASE, "--dlp-export", str(tmp_path / "does-not-exist.json")])
        assert result.exit_code == 77, result.output
        assert result.stdout == ""


def test_unrelated_output_symlink_is_refused_before_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_graph: None
) -> None:
    import evidentia_collectors.entra_m365 as feature

    constructor = Mock(side_effect=AssertionError("unexpected collector construction"))
    monkeypatch.setattr(feature, "EntraM365Collector", constructor)
    target = tmp_path / "existing.json"
    target.write_bytes(b"preserved existing bytes")
    link = tmp_path / "output.json"
    link.symlink_to(target)
    result = CliRunner().invoke(app, [*_BASE, "--dlp-export", str(_FIXTURE), "--output", str(link)])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert link.is_symlink()
    assert target.read_bytes() == b"preserved existing bytes"
    assert constructor.call_count == 0
    assert not list(tmp_path.glob(".evidentia-entra-*.tmp"))


BASE = ["collect", "entra-m365", "--tenant-label", "independent", "--capability", "dlp-export"]


LIMIT = 4_194_304


EMPTY = {
    "schema_version": 1,
    "source": {
        "kind": "authored-synthetic",
        "producer": "independent-cli",
        "producer_version": None,
        "captured_at": None,
        "parent_sha256": None,
        "source_uri": None,
        "sanitization": "synthetic",
    },
    "policies": [],
    "rules": [],
}


BODY = json.dumps(EMPTY, separators=(",", ":")).encode("utf-8")


def invoke(source=None, output=None, extra=None):
    args = list(BASE)
    if source is not None:
        args.extend(["--dlp-export", str(source)])
    if output is not None:
        args.extend(["--output", str(output)])
    return CliRunner().invoke(app, [*args, *(extra or [])])


@pytest.mark.usefixtures("no_graph")
@pytest.mark.parametrize("dangling", [False, True])
def test_unrelated_output_symlink_is_not_silently_replaced(tmp_path, monkeypatch, dangling):
    source = tmp_path / "input.json"
    target = tmp_path / "target.json"
    output = tmp_path / "result-link.json"
    source.write_bytes(BODY)
    if not dangling:
        target.write_bytes(b"previous target bytes")
    output.symlink_to(target)
    constructor = Mock(wraps=feature.EntraM365Collector)
    monkeypatch.setattr(feature, "EntraM365Collector", constructor)
    result = invoke(source, output)
    assert source.read_bytes() == BODY
    assert output.is_symlink(), "The accepted output silently replaced its unrelated symlink"
    if result.exit_code == 0:
        assert json.loads(target.read_text(encoding="utf-8"))["status"] == "complete"
    else:
        assert result.exit_code == 1
        assert constructor.call_count == 0
        if dangling:
            assert not target.exists()
        else:
            assert target.read_bytes() == b"previous target bytes"


@pytest.mark.usefixtures("no_graph")
@pytest.mark.parametrize("multibyte", [False, True])
@pytest.mark.parametrize("extra_byte", [False, True])
def test_exact_binary_limit_and_multibyte_boundary(tmp_path, multibyte, extra_byte):
    value = json.loads(BODY)
    if multibyte:
        value["source"]["producer"] = "synthetic-\u00e9"
    body = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    padded = body + b" " * (LIMIT - len(body) + int(extra_byte))
    source = tmp_path / "input.json"
    source.write_bytes(padded)
    result = invoke(source)
    assert result.exit_code == (2 if extra_byte else 0), result.output
    if not extra_byte:
        assert json.loads(result.stdout)["status"] == "complete"
    else:
        assert result.stdout == ""
    assert source.read_bytes() == padded


@pytest.mark.usefixtures("no_graph")
def test_input_growing_during_bounded_reads_is_refused(tmp_path, monkeypatch):
    source = tmp_path / "growing.json"
    source.write_bytes(BODY)
    original_open = Path.open
    reads = []

    class Growing:
        def __init__(self, stream):
            self.stream = stream
            self.grown = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def read(self, size):
            assert 0 < size <= 65_536
            reads.append(size)
            result = self.stream.read(size)
            if not self.grown:
                with original_open(source, "ab") as append:
                    append.write(b" " * (LIMIT + 1 - len(BODY)))
                self.grown = True
            return result

    def open_file(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        return Growing(stream) if path == source and args == ("rb",) else stream

    monkeypatch.setattr(Path, "open", open_file)
    result = invoke(source)
    assert result.exit_code == 2
    assert result.stdout == ""
    assert len(reads) > 1 and max(reads) <= 65_536


@pytest.mark.usefixtures("no_graph")
@pytest.mark.parametrize("failure", ["reserve", "fdopen", "replace", "serialize"])
def test_output_failures_preserve_original_and_own_descriptor(tmp_path, monkeypatch, failure):
    source = tmp_path / "input.json"
    output = tmp_path / "result.json"
    source.write_bytes(BODY)
    output.write_bytes(b"previous output")
    descriptors = []
    original_mkstemp = cli.tempfile.mkstemp

    def reserve(*args, **kwargs):
        descriptor, name = original_mkstemp(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor, name

    marker = "SYNTHETIC_PRIVATE_FAILURE"
    if failure == "reserve":
        monkeypatch.setattr(cli.tempfile, "mkstemp", Mock(side_effect=OSError(marker)))
        constructor = Mock(side_effect=AssertionError("collection began after reservation failure"))
        monkeypatch.setattr(feature, "EntraM365Collector", constructor)
    else:
        monkeypatch.setattr(cli.tempfile, "mkstemp", reserve)
    if failure == "fdopen":
        monkeypatch.setattr(cli.os, "fdopen", Mock(side_effect=OSError(marker)))
    elif failure == "replace":
        monkeypatch.setattr(cli.os, "replace", Mock(side_effect=OSError(marker)))
    elif failure == "serialize":
        monkeypatch.setattr(feature.EntraM365CollectResult, "model_dump_json", Mock(side_effect=ValueError(marker)))
    result = invoke(source, output)
    assert result.exit_code == 1
    assert result.stdout == ""
    assert marker not in result.stderr
    assert source.read_bytes() == BODY
    assert output.read_bytes() == b"previous output"
    assert not list(tmp_path.glob(".evidentia-entra-*.tmp"))
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    if failure == "reserve":
        assert constructor.call_count == 0


@pytest.mark.usefixtures("no_graph")
@pytest.mark.parametrize(
    "missing,expected",
    [
        ("evidentia_collectors", "not installed"),
        ("evidentia_collectors.entra_m365", "not installed"),
        ("evidentia_collectors.entra_m365._contracts", "could not be loaded"),
        ("unrelated_dependency", "could not be loaded"),
    ],
)
def test_exact_missing_import_classification_without_error_echo(monkeypatch, missing, expected):
    original = builtins.__import__

    def imported(name, *args, **kwargs):
        if name == "evidentia_collectors.entra_m365":
            raise ModuleNotFoundError("SYNTHETIC_PRIVATE_IMPORT", name=missing)
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", imported)
    result = invoke()
    assert result.exit_code == 1
    assert expected in result.stderr
    assert "SYNTHETIC_PRIVATE_IMPORT" not in result.output
    assert result.stdout == ""
    help_result = CliRunner().invoke(app, ["collect", "entra-m365", "--help"])
    assert help_result.exit_code == 0


@pytest.mark.usefixtures("no_graph")
def test_wrong_typed_dlp_with_graph_stops_real_orchestration(tmp_path):
    value = json.loads(BODY)
    value["policies"] = [
        {
            "Guid": "policy",
            "Name": "policy",
            "Mode": "Enable",
            "DistributionStatus": "Pending",
            "Workload": None,
            "Enabled": 1,
            "IsValid": True,
        }
    ]
    source = tmp_path / "typed.json"
    source.write_text(json.dumps(value), encoding="utf-8")
    result = invoke(source, extra=["--capability", "directory-roles"])
    assert result.exit_code == 2
    assert result.stdout == ""


@pytest.mark.usefixtures("no_graph")
def test_default_capabilities_and_format_are_genuinely_omitted(monkeypatch):
    capture = Mock(side_effect=RuntimeError("SYNTHETIC_AFTER_REQUEST_CAPTURE"))
    monkeypatch.setattr(feature.EntraM365Collector, "collect_v2", capture)
    result = CliRunner().invoke(app, ["collect", "entra-m365", "--tenant-label", "independent"])
    assert result.exit_code == 1
    assert capture.call_count == 1
    request = capture.call_args.args[0]
    assert request.capabilities == [
        "conditional-access",
        "authentication-registration",
        "sign-ins",
        "directory-roles",
        "managed-devices",
        "retention-labels",
        "dlp-export",
        "defender-alerts",
        "defender-incidents",
    ]
    assert "capabilities" not in request.model_fields_set
    assert "dlp_format" not in request.model_fields_set
    assert "dlp_content" not in request.model_fields_set
    assert "SYNTHETIC_AFTER_REQUEST_CAPTURE" not in result.output


@pytest.mark.usefixtures("no_graph")
def test_unrelated_parent_symlink_preserves_intended_destination(tmp_path):
    actual_parent = tmp_path / "actual"
    actual_parent.mkdir()
    parent_alias = tmp_path / "parent-alias"
    parent_alias.symlink_to(actual_parent, target_is_directory=True)
    source = tmp_path / "input.json"
    source.write_bytes(BODY)
    result = invoke(source, parent_alias / "output.json")
    assert result.exit_code == 0, result.output
    assert parent_alias.is_symlink()
    assert json.loads((actual_parent / "output.json").read_text(encoding="utf-8"))["status"] == "complete"
    assert source.read_bytes() == BODY


@pytest.mark.usefixtures("no_graph")
def test_late_output_symlink_preserves_link_and_target(tmp_path, monkeypatch):
    source = tmp_path / "input.json"
    output = tmp_path / "result.json"
    target = tmp_path / "late-target.json"
    source.write_bytes(BODY)
    target.write_bytes(b"late target bytes")
    original = feature.EntraM365Collector.collect_v2

    def collect_and_swap(self, request):
        result = original(self, request)
        output.symlink_to(target)
        return result

    monkeypatch.setattr(feature.EntraM365Collector, "collect_v2", collect_and_swap)
    result = invoke(source, output)
    assert result.exit_code == 1
    assert result.stdout == ""
    assert output.is_symlink()
    assert target.read_bytes() == b"late target bytes"
    assert not list(tmp_path.glob(".evidentia-entra-*.tmp"))


@pytest.mark.usefixtures("no_graph")
@pytest.mark.parametrize("stage", ["write", "flush", "fsync", "close"])
def test_descriptor_failures_preserve_existing_output(tmp_path, monkeypatch, stage):
    source = tmp_path / "input.json"
    output = tmp_path / "output.json"
    source.write_bytes(BODY)
    output.write_bytes(b"existing bytes")
    original = cli.os.fdopen
    streams = []

    class FaultingStream:
        def __init__(self, stream):
            self.stream = stream
            streams.append(stream)

        @property
        def closed(self):
            return self.stream.closed

        def fileno(self):
            return self.stream.fileno()

        def write(self, content):
            if stage == "write":
                self.stream.write(content[:9])
                raise OSError("SYNTHETIC_PRIVATE_WRITE")
            return self.stream.write(content)

        def flush(self):
            if stage == "flush":
                raise OSError("SYNTHETIC_PRIVATE_FLUSH")
            self.stream.flush()

        def close(self):
            self.stream.close()
            if stage == "close":
                raise OSError("SYNTHETIC_PRIVATE_CLOSE")

    monkeypatch.setattr(cli.os, "fdopen", lambda descriptor, mode: FaultingStream(original(descriptor, mode)))
    if stage == "fsync":
        monkeypatch.setattr(cli.os, "fsync", Mock(side_effect=OSError("SYNTHETIC_PRIVATE_FSYNC")))
    result = invoke(source, output)
    assert result.exit_code == 1
    assert result.stdout == ""
    assert "SYNTHETIC_PRIVATE" not in result.stderr
    assert output.read_bytes() == b"existing bytes"
    assert source.read_bytes() == BODY
    assert streams and all(stream.closed for stream in streams)
    assert not list(tmp_path.glob(".evidentia-entra-*.tmp"))


@pytest.mark.usefixtures("no_graph")
def test_cleanup_failure_does_not_mask_input_error_or_touch_foreign_temp(tmp_path, monkeypatch):
    source = tmp_path / "invalid.json"
    output = tmp_path / "output.json"
    foreign = tmp_path / ".evidentia-entra-foreign.tmp"
    source.write_bytes(b"{")
    output.write_bytes(b"existing bytes")
    foreign.write_bytes(b"foreign bytes")
    original = Path.unlink

    def fail_owned(path, *args, **kwargs):
        if path.name.startswith(".evidentia-entra-") and path != foreign:
            raise OSError("SYNTHETIC_PRIVATE_CLEANUP")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_owned)
    result = invoke(source, output)
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "SYNTHETIC_PRIVATE_CLEANUP" not in result.stderr
    assert source.read_bytes() == b"{"
    assert output.read_bytes() == b"existing bytes"
    assert foreign.read_bytes() == b"foreign bytes"
    assert len(list(tmp_path.glob(".evidentia-entra-*.tmp"))) == 2


@pytest.mark.usefixtures("no_graph")
@pytest.mark.parametrize(
    "claim,tenant_label,allowed",
    [
        ("allowed", "unrelated-alias", True),
        ("blocked", "allowed", False),
        ("unknown", "allowed", False),
    ],
)
def test_actual_tenant_read_gate_does_not_use_collection_alias(tmp_path, monkeypatch, claim, tenant_label, allowed):
    source = tmp_path / "input.json"
    source.write_bytes(BODY)
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "tenants": {
                    "allowed": {"identities": {"synthetic-reader": "reader"}, "default_role": "deny"},
                    "blocked": {"identities": {}, "default_role": "deny"},
                },
                "default_tenant": None,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("EVIDENTIA_RBAC_POLICY_FILE", str(policy))
    read = Mock(wraps=cli._read_entra_export)
    constructor = Mock(wraps=feature.EntraM365Collector)
    monkeypatch.setattr(cli, "_read_entra_export", read)
    monkeypatch.setattr(feature, "EntraM365Collector", constructor)
    result = CliRunner().invoke(
        app,
        [
            "--rbac-identity",
            "synthetic-reader",
            "--rbac-tenant",
            claim,
            *BASE,
            "--tenant-label",
            tenant_label,
            "--dlp-export",
            str(source),
        ],
    )
    assert result.exit_code == (0 if allowed else 77), result.output
    assert read.call_count == constructor.call_count == int(allowed)
    if allowed:
        assert json.loads(result.stdout)["provenance"]["tenant_label"] == tenant_label
    else:
        assert result.stdout == ""
