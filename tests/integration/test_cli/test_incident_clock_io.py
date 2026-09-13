"""Verify incident input limits and atomic output preservation on native files."""

from __future__ import annotations

import io
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from evidentia.cli import _incident_clock_io as output


def request(tmp_path: Path) -> output.InputSnapshot:
    source = tmp_path / "request.json"
    source.write_bytes(b"{}")
    return output.read_request_file(source)


@pytest.mark.parametrize("profile,limit", [(False, 16384), (True, 65536)])
def test_native_input_limit_and_one_extra_byte(tmp_path: Path, profile: bool, limit: int) -> None:
    source = tmp_path / "bounded.json"
    source.write_bytes(b" " * limit)
    reader = output.read_profile_file if profile else output.read_request_file
    assert len(reader(source).content) == limit
    source.write_bytes(b" " * (limit + 1))
    with pytest.raises(output.InputFailure, match="invalid_input"):
        reader(source)


def test_output_preserves_exact_utf8_and_supports_the_16_mib_result_cap(tmp_path: Path) -> None:
    snapshot = request(tmp_path)
    destination = tmp_path / "result.json"
    destination.write_bytes(b"previous")
    data = b'{"value":"' + chr(0xE9).encode() * 100 + b'"}'
    with output.ReservedOutput(snapshot, destination) as reserved:
        assert destination.read_bytes() == b"previous"
        reserved.publish(data)
    assert destination.read_bytes() == data
    maximum = b" " * 16777216
    with output.ReservedOutput(snapshot, destination) as reserved:
        reserved.publish(maximum)
    assert destination.read_bytes() == maximum
    assert not list(tmp_path.glob(".evidentia-incident-clock-*"))


def test_output_oversize_or_invalid_type_leaves_destination_unchanged(tmp_path: Path) -> None:
    snapshot = request(tmp_path)
    destination = tmp_path / "result.json"
    destination.write_bytes(b"previous")
    for value in (b"x" * 16777217, bytearray(b"changed"), "changed"):
        with pytest.raises(output.OutputFailure), output.ReservedOutput(snapshot, destination) as reserved:
            reserved.publish(value)
        assert destination.read_bytes() == b"previous"
        assert not list(tmp_path.glob(".evidentia-incident-clock-*"))


@pytest.mark.parametrize("kind", ["request", "profile", "hardlink", "directory", "dash"])
def test_input_aliases_and_nonfiles_refuse_before_output_reservation(tmp_path: Path, kind: str) -> None:
    snapshot = request(tmp_path)
    profile_path = tmp_path / "profiles.json"
    profile_path.write_bytes(b"{}")
    profile = output.read_profile_file(profile_path)
    if kind == "request":
        destination = snapshot.path
    elif kind == "profile":
        destination = profile_path
    elif kind == "hardlink":
        destination = tmp_path / "linked.json"
        os.link(snapshot.path, destination)
    elif kind == "directory":
        destination = tmp_path
    else:
        destination = Path("-")
    with (
        pytest.raises((output.InputFailure, output.OutputFailure)),
        output.ReservedOutput(snapshot, destination, protected_inputs=(profile,)),
    ):
        pytest.fail("an aliased or non-file destination was reserved")
    assert snapshot.path.read_bytes() == b"{}" and profile_path.read_bytes() == b"{}"
    assert not list(tmp_path.glob(".evidentia-incident-clock-*"))


def test_hardlinked_input_is_refused_without_reading_it(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(b"{}")
    os.link(source, tmp_path / "alias.json")
    with pytest.raises(output.InputFailure):
        output.read_request_file(source)


@pytest.mark.parametrize("stage", ["fsync", "replace", "flush", "write", "readback"])
def test_output_failures_keep_original_file_and_remove_owned_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    snapshot = request(tmp_path)
    destination = tmp_path / "result.json"
    destination.write_bytes(b"previous")

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise OSError("synthetic file failure")

    with pytest.raises(output.OutputFailure), output.ReservedOutput(snapshot, destination) as reserved:
        if stage in ("fsync", "replace"):
            monkeypatch.setattr(output.os, stage, fail)
        else:
            assert reserved.stream is not None
            original = reserved.stream

            class Stream:
                def __getattr__(self, name: str) -> Any:
                    return getattr(original, name)

                def write(self, content: bytes) -> int:
                    return len(content) - 1 if stage == "write" else original.write(content)

                def read(self, length: int) -> bytes:
                    return b"changed" if stage == "readback" else original.read(length)

                def flush(self) -> None:
                    if stage == "flush":
                        fail()
                    original.flush()

            reserved.stream = Stream()
        reserved.publish(b'{"state":"complete"}')
    assert destination.read_bytes() == b"previous"
    assert not list(tmp_path.glob(".evidentia-incident-clock-*"))


def test_changed_destination_is_preserved_instead_of_overwritten(tmp_path: Path) -> None:
    snapshot = request(tmp_path)
    destination = tmp_path / "result.json"
    destination.write_bytes(b"previous")
    with pytest.raises(output.OutputFailure), output.ReservedOutput(snapshot, destination) as reserved:
        destination.write_bytes(b"edited while collecting")
        reserved.publish(b"result")
    assert destination.read_bytes() == b"edited while collecting"
    assert not list(tmp_path.glob(".evidentia-incident-clock-*"))


def test_failure_before_publication_and_cancellation_preserve_the_destination(tmp_path: Path) -> None:
    snapshot = request(tmp_path)
    destination = tmp_path / "result.json"
    destination.write_bytes(b"previous")
    for exception in (ValueError, KeyboardInterrupt):
        with pytest.raises(exception), output.ReservedOutput(snapshot, destination):
            raise exception()
        assert destination.read_bytes() == b"previous"
        assert not list(tmp_path.glob(".evidentia-incident-clock-*"))


def test_stdout_receives_original_bytes_without_reencoding_or_extra_newline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = request(tmp_path)
    target = io.BytesIO()
    monkeypatch.setattr(output.sys, "stdout", SimpleNamespace(buffer=target))
    content = b'{"value":"' + chr(0xE9).encode() + b'"}'
    with output.ReservedOutput(snapshot, None) as reserved:
        reserved.publish(content)
    assert target.getvalue() == content


def test_input_change_during_read_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "request.json"
    source.write_bytes(b"{}")
    original = output.os.read
    changed = False

    def read(descriptor: int, length: int) -> bytes:
        nonlocal changed
        content = original(descriptor, length)
        if not changed:
            changed = True
            source.write_bytes(b'{"changed":true}')
        return content

    monkeypatch.setattr(output.os, "read", read)
    with pytest.raises(output.InputFailure):
        output.read_request_file(source)


def test_replaced_reservation_is_neither_published_nor_deleted(tmp_path: Path) -> None:
    snapshot = request(tmp_path)
    destination = tmp_path / "result.json"
    destination.write_bytes(b"previous")
    with pytest.raises(output.OutputFailure), output.ReservedOutput(snapshot, destination) as reserved:
        assert reserved.stream is not None and reserved.temporary is not None
        reserved.stream.close()
        original_name = reserved.temporary
        original_name.rename(tmp_path / "owned-moved.tmp")
        original_name.write_bytes(b"different owner")
        reserved.publish(b"result")
    assert destination.read_bytes() == b"previous"
    assert original_name.read_bytes() == b"different owner"


@pytest.mark.parametrize("kind", ["ordinary", "device", "forward-slash"])
@pytest.mark.parametrize("surface", ["request", "profile", "output"])
def test_windows_network_paths_refuse_before_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: str, surface: str
) -> None:
    from pathlib import PureWindowsPath
    from typing import cast

    snapshot = request(tmp_path)
    forms = {
        "ordinary": chr(92) * 2 + chr(92).join(("source.example.org", "share", "input.json")),
        "device": "//?/UNC/source.example.org/share/input.json",
        "forward-slash": "//source.example.org/share/input.json",
    }
    candidate = Path(forms[kind]) if os.name == "nt" else cast(Path, PureWindowsPath(forms[kind]))
    observed: list[str] = []

    def metadata(*args: Any, **kwargs: Any) -> Any:
        observed.append("metadata")
        raise AssertionError("nonlocal path reached metadata")

    monkeypatch.setattr(output, "_file", metadata)
    monkeypatch.setattr(output, "os", SimpleNamespace(name="nt", fspath=os.fspath))
    with pytest.raises((output.InputFailure, output.OutputFailure), match=r"invalid_(path|input)"):
        if surface == "output":
            with output.ReservedOutput(snapshot, candidate):
                pytest.fail("nonlocal output was reserved")
        else:
            reader = output.read_profile_file if surface == "profile" else output.read_request_file
            reader(candidate)
    assert observed == []
