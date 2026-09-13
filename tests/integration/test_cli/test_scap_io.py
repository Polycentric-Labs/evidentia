"""Exercise SCAP CLI file admission and exact accepted-byte publication."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import BinaryIO
from unittest.mock import Mock

import pytest
import typer
from evidentia_collectors.scap import _files, _json, collector
from evidentia_collectors.scap._limits import Budget, ScapFailure, start_budget

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "scap"
PROFILES = (
    ("xccdf-1.2-results", "xccdf-1.2-native.xml"),
    ("oval-5.8-core-results", "oval-5.8-native.xml"),
    ("oval-5.11.2-core-results", "oval-5.11.2-native.xml"),
    ("oval-5.12.3-core-results", "oval-5.12.3-native.xml"),
)


def source_bytes(filename: str) -> bytes:
    return (FIXTURES / filename).read_bytes().replace(b"\r\n", b"\n")


def assertion_bytes(raw: bytes, profile: str = "oval-5.8-core-results", **changes: object) -> bytes:
    return json.dumps(
        {
            "schema_version": "scap-completion-assertion-v1",
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "source_profile": profile,
            "assessment_index": 0,
            "completed_at": "2024-03-01T00:00:00Z",
            "reference": "Synthetic reviewed completion",
            **changes,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")


@pytest.fixture(autouse=True)
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("SCAP surface checks must not contact a network")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


@pytest.mark.parametrize("profile,filename", PROFILES)
def test_actual_result_stdout_is_the_accepted_wire(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
    filename: str,
) -> None:
    from evidentia.cli._scap_io import run_scap

    source = tmp_path / "source.xml"
    raw = source_bytes(filename)
    source.write_bytes(raw)
    original = collector._Accepted.output_bytes
    accepted: list[bytes] = []

    def capture(self: collector._Accepted, view: str = "result") -> bytes:
        wire = original(self, view)
        accepted.append(wire)
        return wire

    monkeypatch.setattr(collector._Accepted, "output_bytes", capture)
    run_scap(source=source, source_profile=profile, assessment_index=0)
    output = capsysbinary.readouterr()
    assert output.err == b"" and len(accepted) == 1 and output.out == accepted[0]
    result = json.loads(output.out)
    assert result["source"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["source"]["profile"] == profile
    assert len(result["findings"]) == 1
    assert (result["evidence_artifact"] is None) == profile.startswith("oval-")
    assert list(tmp_path.iterdir()) == [source]


@pytest.mark.parametrize("existing", [False, True])
def test_null_artifact_refuses_before_any_output_open(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
    monkeypatch: pytest.MonkeyPatch,
    existing: bool,
) -> None:
    from evidentia.cli._scap_io import run_scap

    source, target = tmp_path / "source.xml", tmp_path / "artifact.json"
    source.write_bytes(source_bytes("oval-5.8-native.xml"))
    if existing:
        target.write_bytes(b"original output")
    publish = Mock(side_effect=AssertionError("No output preparation for a null artifact"))
    monkeypatch.setattr(_files, "publish_file", publish)
    with pytest.raises(typer.Exit) as error:
        run_scap(
            source=source,
            source_profile="oval-5.8-core-results",
            assessment_index=0,
            output=target,
            output_view="artifact",
        )
    assert error.value.exit_code == 2
    output = capsysbinary.readouterr()
    assert output.out == b"" and output.err.decode().strip() == ScapFailure("artifact_unavailable").message
    publish.assert_not_called()
    assert target.read_bytes() == b"original output" if existing else not target.exists()


@pytest.mark.parametrize("alias", ["source-output", "source-claim", "claim-output", "hardlink-output"])
def test_all_input_aliases_refuse_before_parsing(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
    monkeypatch: pytest.MonkeyPatch,
    alias: str,
) -> None:
    from evidentia.cli._scap_io import run_scap

    source, claim, target = tmp_path / "source.xml", tmp_path / "claim.json", tmp_path / "output.json"
    raw = source_bytes("oval-5.8-native.xml")
    source.write_bytes(raw)
    claim.write_bytes(assertion_bytes(raw))
    if alias == "source-output":
        target = source
    elif alias == "source-claim":
        claim = source
    elif alias == "claim-output":
        target = claim
    else:
        os.link(source, target)
    parse = Mock(side_effect=AssertionError("An alias reached authoritative parsing"))
    monkeypatch.setattr(collector, "parse_xml", parse)
    with pytest.raises(typer.Exit) as error:
        run_scap(
            source=source,
            source_profile="oval-5.8-core-results",
            assessment_index=0,
            completion_assertion=claim,
            asserted_by="Synthetic operator",
            output=target,
        )
    assert error.value.exit_code == 2
    assert capsysbinary.readouterr().out == b""
    parse.assert_not_called()
    assert source.read_bytes() == raw


@pytest.mark.parametrize("view", ["result", "artifact"])
def test_complete_file_replaces_only_with_exact_selected_bytes(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
    monkeypatch: pytest.MonkeyPatch,
    view: str,
) -> None:
    from evidentia.cli._scap_io import run_scap

    source, target = tmp_path / "source.xml", tmp_path / "output.json"
    source.write_bytes(source_bytes("xccdf-1.2-native.xml"))
    target.write_bytes(b"old")
    original = collector._Accepted.output_bytes
    accepted: list[bytes] = []

    def capture(self: collector._Accepted, selected: str = "result") -> bytes:
        wire = original(self, selected)
        accepted.append(wire)
        return wire

    monkeypatch.setattr(collector._Accepted, "output_bytes", capture)
    run_scap(source=source, source_profile="xccdf-1.2-results", assessment_index=0, output=target, output_view=view)
    assert target.read_bytes() == accepted[0]
    assert capsysbinary.readouterr().out == b""
    assert set(tmp_path.iterdir()) == {source, target}


def test_one_original_clock_spans_sidecar_source_and_stdout(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidentia.cli._scap_io import run_scap

    source, claim = tmp_path / "source.xml", tmp_path / "claim.json"
    raw = source_bytes("oval-5.8-native.xml")
    source.write_bytes(raw)
    claim.write_bytes(assertion_bytes(raw))
    started: list[float] = []
    seen: list[tuple[str, float]] = []
    original_start = start_budget
    original_claim, original_source, original_publish = _files.read_claim, _files.read_source, _files.publish_stdout

    def start() -> Budget:
        budget = original_start()
        started.append(budget.deadline)
        return budget

    def read_claim(path: object, budget: Budget) -> bytes:
        seen.append(("claim", budget.deadline))
        return original_claim(path, budget)

    def read_source(path: object, budget: Budget) -> bytes:
        seen.append(("source", budget.deadline))
        return original_source(path, budget)

    def publish(stream: BinaryIO, wire: bytes, budget: Budget) -> None:
        seen.append(("stdout", budget.deadline))
        original_publish(stream, wire, budget)

    monkeypatch.setattr(collector, "start_budget", start)
    monkeypatch.setattr(_files, "read_claim", read_claim)
    monkeypatch.setattr(_files, "read_source", read_source)
    monkeypatch.setattr(_files, "publish_stdout", publish)
    run_scap(
        source=source,
        source_profile="oval-5.8-core-results",
        assessment_index=0,
        completion_assertion=claim,
        asserted_by="Synthetic operator",
    )
    assert len(started) == 1 and seen == [(stage, started[0]) for stage in ("claim", "source", "stdout")]
    assert json.loads(capsysbinary.readouterr().out)["evidence_artifact"] is not None


@pytest.mark.parametrize("during_json", [False, True])
def test_sidecar_expiry_keeps_deadline_error_and_never_reads_xml(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
    monkeypatch: pytest.MonkeyPatch,
    during_json: bool,
) -> None:
    from evidentia.cli._scap_io import run_scap

    source, claim = tmp_path / "source.xml", tmp_path / "claim.json"
    raw = source_bytes("oval-5.8-native.xml")
    source.write_bytes(raw)
    claim.write_bytes(assertion_bytes(raw))
    original = _files.read_claim
    deadline: list[float] = []

    def read(path: object, budget: Budget) -> bytes:
        value = original(path, budget)
        deadline.append(budget.deadline)
        if not during_json:
            monkeypatch.setattr(time, "monotonic", lambda: budget.deadline + 1.0)
        return value

    def invalid_json(*args: object, **kwargs: object) -> object:
        monkeypatch.setattr(time, "monotonic", lambda: deadline[0] + 1.0)
        raise ScapFailure()

    parse = Mock(side_effect=AssertionError("Expired claim reached source parsing"))
    monkeypatch.setattr(_files, "read_claim", read)
    monkeypatch.setattr(collector, "parse_xml", parse)
    if during_json:
        monkeypatch.setattr(_json, "load_json", invalid_json)
    with pytest.raises(typer.Exit) as error:
        run_scap(
            source=source,
            source_profile="oval-5.8-core-results",
            assessment_index=0,
            completion_assertion=claim,
            asserted_by="Synthetic operator",
        )
    assert error.value.exit_code == 1
    output = capsysbinary.readouterr()
    assert output.out == b"" and output.err.decode().strip() == ScapFailure("processing_deadline_exceeded").message
    parse.assert_not_called()


@pytest.mark.parametrize("mode", ["late-success", "short-write", "write-error", "flush-error"])
def test_stdout_admission_has_no_retry_or_false_rollback(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    from evidentia.cli._scap_io import run_scap

    source = tmp_path / "source.xml"
    source.write_bytes(source_bytes("xccdf-1.2-native.xml"))
    calls: list[str] = []
    delivered = bytearray()
    selected: list[bytes] = []
    original = collector._Accepted.output_bytes

    def capture(self: collector._Accepted, view: str = "result") -> bytes:
        wire = original(self, view)
        selected.append(wire)
        return wire

    class Stream:
        def write(self, wire: bytes) -> int:
            calls.append("write")
            delivered.extend(wire[:7] if mode in {"short-write", "write-error"} else wire)
            if mode == "write-error":
                raise OSError("Synthetic sensitive output detail")
            if mode == "late-success":
                monkeypatch.setattr(time, "monotonic", lambda: float("inf"))
            return 7 if mode == "short-write" else len(wire)

        def flush(self) -> None:
            calls.append("flush")
            if mode == "flush-error":
                raise OSError("Synthetic sensitive output detail")

    monkeypatch.setattr(collector._Accepted, "output_bytes", capture)
    with monkeypatch.context() as output_patch:
        output_patch.setattr(sys, "stdout", SimpleNamespace(buffer=Stream()))
        if mode == "late-success":
            run_scap(source=source, source_profile="xccdf-1.2-results", assessment_index=0)
        else:
            with pytest.raises(typer.Exit) as error:
                run_scap(source=source, source_profile="xccdf-1.2-results", assessment_index=0)
            assert error.value.exit_code == 1
    output = capsysbinary.readouterr()
    assert calls == (["write"] if mode in {"short-write", "write-error"} else ["write", "flush"])
    assert bytes(delivered) == (selected[0][:7] if mode in {"short-write", "write-error"} else selected[0])
    assert output.err == (
        b"" if mode == "late-success" else (ScapFailure("publication_failed").message + "\n").encode()
    )


@pytest.mark.parametrize("slot", ["source", "claim", "output"])
def test_unc_paths_are_refused_before_parsing_or_remote_metadata(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
    monkeypatch: pytest.MonkeyPatch,
    slot: str,
) -> None:
    from evidentia.cli._scap_io import run_scap

    source, claim, output = tmp_path / "source.xml", tmp_path / "claim.json", tmp_path / "result.json"
    raw = source_bytes("oval-5.8-native.xml")
    source.write_bytes(raw)
    claim.write_bytes(assertion_bytes(raw))
    unc = Path(r"\\synthetic-scap.invalid\share\input.xml")
    parse = Mock(side_effect=AssertionError("UNC reached parsing"))
    monkeypatch.setattr(collector, "parse_xml", parse)
    with pytest.raises(typer.Exit) as error:
        run_scap(
            source=unc if slot == "source" else source,
            source_profile="oval-5.8-core-results",
            assessment_index=0,
            completion_assertion=unc if slot == "claim" else claim,
            asserted_by="Synthetic operator",
            output=unc if slot == "output" else output,
        )
    assert error.value.exit_code == 2 and capsysbinary.readouterr().out == b""
    parse.assert_not_called()
    assert not output.exists()
