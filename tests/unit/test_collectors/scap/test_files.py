"""File snapshots, atomic file output and truthful stdout publication boundaries."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from evidentia_collectors.scap import _files, collector
from evidentia_collectors.scap._limits import CLAIM_LIMIT, RAW_LIMIT, Budget, ScapFailure, start_budget

_FIXTURE = Path(__file__).resolve().parents[3] / "fixtures" / "scap" / "xccdf-1.2-native.xml"


def test_source_file_exact_bytes_and_same_result_as_bytes_core(tmp_path):
    source = tmp_path.resolve() / "source.xml"
    raw = _FIXTURE.read_bytes().replace(b"\r\n", b"\n")
    source.write_bytes(raw)
    assert _files.read_source(source, start_budget()) == raw
    actual = collector.collect_scap_file(source, source_profile="xccdf-1.2-results", assessment_index=0)
    expected = collector.collect_scap_bytes(raw, source_profile="xccdf-1.2-results", assessment_index=0)
    assert actual.evidence_artifact.model_dump() == expected.evidence_artifact.model_dump()


@pytest.mark.parametrize("size,accepted", [(RAW_LIMIT, True), (RAW_LIMIT + 1, False)])
def test_bounded_source_snapshot_size(tmp_path, size, accepted):
    source = tmp_path.resolve() / "size.xml"
    source.write_bytes(b" " * size)
    if accepted:
        assert len(_files.read_source(source, start_budget())) == size
    else:
        with pytest.raises(ScapFailure) as raised:
            _files.read_source(source, start_budget())
        assert raised.value.code == "source_limit_exceeded"


@pytest.mark.parametrize("size", [CLAIM_LIMIT, CLAIM_LIMIT + 1])
def test_sidecar_has_its_own_smaller_bound(tmp_path, size):
    source = tmp_path.resolve() / "claim.json"
    source.write_bytes(b" " * size)
    if size == CLAIM_LIMIT:
        assert len(_files.read_claim(source, start_budget())) == size
    else:
        with pytest.raises(ScapFailure) as raised:
            _files.read_claim(source, start_budget())
        assert raised.value.code == "source_limit_exceeded"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "//synthetic-host/share/file.xml",
        "\\\\synthetic-host\\share\\file.xml",
        "https://example.invalid/source.xml",
        "x\x00y",
        b"path",
    ],
)
def test_network_and_non_native_paths_refuse_before_file_access(monkeypatch, value):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError

    monkeypatch.setattr(_files.os, "open", forbidden)
    with pytest.raises(ScapFailure) as raised:
        _files.read_source(value, start_budget())
    assert raised.value.code == "invalid_request"
    assert calls == []


def test_path_protocol_and_string_subclasses_are_not_invoked():
    events = []

    class PathProtocol:
        def __fspath__(self):
            events.append("fspath")
            raise AssertionError

    class Text(str):
        def __str__(self):
            events.append("str")
            raise AssertionError

    for value in (PathProtocol(), Text("source.xml")):
        with pytest.raises(ScapFailure):
            _files.local_path(value)
    assert events == []


def test_directory_and_hardlinks_refuse(tmp_path):
    directory = tmp_path.resolve()
    source, alias = directory / "source.xml", directory / "alias.xml"
    source.write_bytes(b"<source/>")
    with pytest.raises(ScapFailure):
        _files.read_source(directory, start_budget())
    os.link(source, alias)
    for target in (source, alias):
        with pytest.raises(ScapFailure) as raised:
            _files.read_source(target, start_budget())
        assert raised.value.code == "invalid_request"


def test_symlink_source_and_parent_refuse(tmp_path):
    directory = tmp_path.resolve()
    source, link = directory / "source.xml", directory / "alias.xml"
    source.write_bytes(b"<source/>")
    try:
        link.symlink_to(source)
    except OSError as error:
        if os.name == "nt" and getattr(error, "winerror", None) == 1314:
            pytest.skip("Native symlink creation privilege is unavailable on this Windows host")
        raise
    with pytest.raises(ScapFailure):
        _files.read_source(link, start_budget())
    parent = directory / "linked-parent"
    parent.symlink_to(directory, target_is_directory=True)
    with pytest.raises(ScapFailure):
        _files.read_source(parent / "source.xml", start_budget())


@pytest.mark.parametrize("alias", ["source", "claim"])
def test_source_claim_output_aliases_refuse(tmp_path, alias):
    directory = tmp_path.resolve()
    source, claim = directory / "source.xml", directory / "claim.json"
    source.write_bytes(b"<source/>")
    claim.write_bytes(b"{}")
    output = source if alias == "source" else claim
    with pytest.raises(ScapFailure) as raised:
        _files.check_paths(source, claim, output)
    assert raised.value.code == "invalid_request"
    with pytest.raises(ScapFailure):
        _files.check_paths(source, source)


def test_mutation_during_source_read_refuses(tmp_path, monkeypatch):
    source = tmp_path.resolve() / "source.xml"
    source.write_bytes(b"<source>before</source>")
    original = _files.os.read
    changed = False

    def read(descriptor, size):
        nonlocal changed
        value = original(descriptor, size)
        if value and not changed:
            changed = True
            with source.open("ab") as stream:
                stream.write(b" ")
        return value

    monkeypatch.setattr(_files.os, "read", read)
    with pytest.raises(ScapFailure) as raised:
        _files.read_source(source, start_budget())
    assert raised.value.code == "source_read_failed"


def test_read_cancellation_survives_descriptor_cleanup_failure(tmp_path, monkeypatch):
    source = tmp_path.resolve() / "source.xml"
    source.write_bytes(b"<source/>")
    signal = KeyboardInterrupt("Synthetic cancellation")
    original_close = _files.os.close

    def cancel(*args):
        raise signal

    def close(descriptor):
        original_close(descriptor)
        raise OSError("Synthetic close failure")

    monkeypatch.setattr(_files.os, "read", cancel)
    monkeypatch.setattr(_files.os, "close", close)
    with pytest.raises(KeyboardInterrupt) as raised:
        _files.read_source(source, start_budget())
    assert raised.value is signal
    assert signal.__notes__ == ["SCAP source descriptor cleanup also failed."]


def test_successful_output_replaces_with_exact_complete_bytes_and_no_temp(tmp_path):
    target = tmp_path.resolve() / "result.json"
    target.write_bytes(b"previous")
    wire = b'{"result":"complete"}'
    _files.publish_file(target, wire, start_budget())
    assert target.read_bytes() == wire
    assert list(tmp_path.glob(".scap-output-*.tmp")) == []


@pytest.mark.parametrize("stage", ["fdopen", "write", "flush", "read", "growth", "close", "replace"])
def test_output_failure_preserves_previous_file_and_owned_temp_cleanup(tmp_path, monkeypatch, stage):
    target = tmp_path.resolve() / "result.json"
    target.write_bytes(b"previous")
    original_fdopen, original_replace = _files.os.fdopen, _files.os.replace

    class Stream:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, value):
            if stage == "write":
                raise OSError("Synthetic write failure")
            return self.stream.write(value)

        def flush(self):
            if stage == "flush":
                raise OSError("Synthetic flush failure")
            return self.stream.flush()

        def read(self, size):
            if stage == "read":
                raise OSError("Synthetic readback failure")
            if stage == "growth":
                return b"X" * size
            return self.stream.read(size)

        def close(self):
            self.stream.close()
            if stage == "close":
                raise OSError("Synthetic close failure")

    def fdopen(descriptor, mode):
        if stage == "fdopen":
            raise OSError("Synthetic fdopen failure")
        return Stream(original_fdopen(descriptor, mode))

    def replace(*args):
        if stage == "replace":
            raise OSError("Synthetic replace failure")
        return original_replace(*args)

    monkeypatch.setattr(_files.os, "fdopen", fdopen)
    monkeypatch.setattr(_files.os, "replace", replace)
    with pytest.raises(ScapFailure) as raised:
        _files.publish_file(target, b"complete", start_budget())
    assert raised.value.code == "publication_failed"
    assert target.read_bytes() == b"previous"
    assert list(tmp_path.glob(".scap-output-*.tmp")) == []


def test_output_cancellation_survives_stream_close_failure(tmp_path, monkeypatch):
    target = tmp_path.resolve() / "result.json"
    target.write_bytes(b"previous")
    signal = KeyboardInterrupt("Synthetic output cancellation")
    original = _files.os.fdopen

    class Stream:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def write(self, value):
            raise signal

        def close(self):
            self.wrapped.close()
            raise OSError("Synthetic close failure")

    monkeypatch.setattr(_files.os, "fdopen", lambda descriptor, mode: Stream(original(descriptor, mode)))
    with pytest.raises(KeyboardInterrupt) as raised:
        _files.publish_file(target, b"complete", start_budget())
    assert raised.value is signal
    assert target.read_bytes() == b"previous"
    assert list(tmp_path.glob(".scap-output-*.tmp")) == []


def test_expired_output_budget_refuses_before_temp_creation(tmp_path, monkeypatch):
    target = tmp_path.resolve() / "result.json"
    target.write_bytes(b"previous")

    def forbidden(*args, **kwargs):
        raise AssertionError("No output may be opened")

    monkeypatch.setattr(_files.tempfile, "mkstemp", forbidden)
    with pytest.raises(ScapFailure) as raised:
        _files.publish_file(target, b"complete", Budget(time.monotonic() - 1.0))
    assert raised.value.code == "processing_deadline_exceeded"
    assert target.read_bytes() == b"previous"


@pytest.mark.parametrize("stage", ["after_readback", "after_parents"])
@pytest.mark.parametrize("same_size", [False, True])
def test_mutation_after_candidate_readback_never_replaces_previous_output(tmp_path, monkeypatch, stage, same_size):
    target = tmp_path.resolve() / "result.json"
    previous, wire = b"previous", b"complete"
    target.write_bytes(previous)
    names = []
    original_create = _files.tempfile.mkstemp

    def create(*args, **kwargs):
        pair = original_create(*args, **kwargs)
        names.append(Path(pair[1]))
        return pair

    def change():
        with names[0].open("r+b") as stream:
            if same_size:
                stream.write(b"Z" * len(wire))
            else:
                stream.seek(0, 2)
                stream.write(b"X")

    monkeypatch.setattr(_files.tempfile, "mkstemp", create)
    if stage == "after_parents":
        original_parents = _files._parents_unchanged

        def parents(rows):
            change()
            return original_parents(rows)

        monkeypatch.setattr(_files, "_parents_unchanged", parents)
    else:
        original_open = _files.os.fdopen

        class Stream:
            def __init__(self, stream):
                self.stream = stream
                self.done = False

            def __getattr__(self, name):
                return getattr(self.stream, name)

            def read(self, size):
                chunk = self.stream.read(size)
                self.done = not chunk
                return chunk

            def fileno(self):
                if self.done:
                    change()
                    self.done = False
                return self.stream.fileno()

        monkeypatch.setattr(_files.os, "fdopen", lambda *args: Stream(original_open(*args)))
    with pytest.raises(ScapFailure) as raised:
        _files.publish_file(target, wire, start_budget())
    assert raised.value.code == "publication_failed"
    assert target.read_bytes() == previous
    assert list(tmp_path.glob(".scap-output-*.tmp")) == []


@pytest.mark.parametrize("surface", ["source", "output"])
def test_first_cancellation_from_close_preserves_its_identity(tmp_path, monkeypatch, surface):
    class Cancel(BaseException):
        pass

    signal = Cancel()
    target = tmp_path.resolve() / "result.json"
    target.write_bytes(b"previous")
    if surface == "source":
        original_close = _files.os.close

        def close(descriptor):
            original_close(descriptor)
            raise signal

        monkeypatch.setattr(_files.os, "close", close)

        def operation():
            return _files.read_source(target, start_budget())
    else:
        original_open = _files.os.fdopen

        class Stream:
            def __init__(self, stream):
                self.stream = stream

            def __getattr__(self, name):
                return getattr(self.stream, name)

            def close(self):
                self.stream.close()
                raise signal

        monkeypatch.setattr(_files.os, "fdopen", lambda *args: Stream(original_open(*args)))

        def operation():
            return _files.publish_file(target, b"complete", start_budget())

    with pytest.raises(Cancel) as raised:
        operation()
    assert raised.value is signal
    assert target.read_bytes() == b"previous"
    assert list(tmp_path.glob(".scap-output-*.tmp")) == []


@pytest.mark.parametrize("reverse", [False, True])
def test_ambiguous_stacked_mounts_refuse_network_in_either_order(monkeypatch, reverse):
    import io
    import posixpath
    from pathlib import PurePosixPath
    from types import SimpleNamespace

    rows = [b"20 1 8:1 / /owned rw - ext4 /dev/synthetic rw\n", b"21 1 8:2 / /owned rw - nfs4 synthetic rw\n"]
    if reverse:
        rows.reverse()
    monkeypatch.setattr(_files, "open", lambda *args: io.BytesIO(b"".join(rows)), raising=False)
    monkeypatch.setattr(_files, "os", SimpleNamespace(path=posixpath))
    with pytest.raises(ScapFailure) as raised:
        _files._linux_local_mount(PurePosixPath("/owned/source"))
    assert raised.value.code == "invalid_request"


@pytest.mark.parametrize("machine,symbol", [("arm64", "statfs"), ("x86_64", "statfs64")])
def test_darwin_architecture_selects_the_declared_64_bit_symbol(tmp_path, monkeypatch, machine, symbol):
    import ctypes
    from types import SimpleNamespace

    observed = []

    class Function:
        def __call__(self, source, pointer):
            structure = pointer._obj
            assert ctypes.sizeof(type(structure)) == 2168
            assert type(structure).flags.offset == 64
            structure.flags = 0x1000
            observed.append(symbol)
            return 0

    monkeypatch.setattr(_files.platform, "machine", lambda: machine)
    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace(**{symbol: Function()}))
    _files._darwin_local_mount(tmp_path.resolve() / "missing")
    assert observed == [symbol]


def test_stdout_exact_bytes_and_caller_ownership():
    import io

    stream = io.BytesIO()
    wire = b'{"synthetic":true}'
    _files.publish_stdout(stream, wire, start_budget())
    assert stream.getvalue() == wire
    assert not stream.closed


@pytest.mark.parametrize("kind", ["text", "mutable", "subclass", "empty", "oversized"])
def test_stdout_rejects_invalid_wire_before_sink_access(kind):
    class BytesChild(bytes):
        pass

    class ForbiddenSink:
        def __getattribute__(self, name):
            raise AssertionError("Invalid wire must not reach the sink")

    values = {"text": "{}", "mutable": bytearray(b"{}"), "subclass": BytesChild(b"{}"), "empty": b""}
    wire = b"x" * (_files.RESULT_LIMIT + 1) if kind == "oversized" else values[kind]
    with pytest.raises(ScapFailure) as raised:
        _files.publish_stdout(ForbiddenSink(), wire, start_budget())
    assert raised.value.code == "invalid_internal_result"


@pytest.mark.parametrize("count", [0, 1, None, False, True, 2.0, "2"])
def test_stdout_short_or_non_native_count_never_retries_or_flushes(count):
    calls = []
    delivered = bytearray()

    class Sink:
        def write(self, wire):
            calls.append("write")
            delivered.extend(wire[:1])
            return count

        def flush(self):
            calls.append("flush")

    with pytest.raises(ScapFailure) as raised:
        _files.publish_stdout(Sink(), b"{}", start_budget())
    assert raised.value.code == "publication_failed"
    assert calls == ["write"]
    assert delivered == b"{"


def test_stdout_integer_subclass_count_is_not_accepted():
    class Count(int):
        pass

    class Sink:
        def write(self, wire):
            return Count(len(wire))

        def flush(self):
            raise AssertionError("A refused count must not trigger flush")

    with pytest.raises(ScapFailure) as raised:
        _files.publish_stdout(Sink(), b"{}", start_budget())
    assert raised.value.code == "publication_failed"


@pytest.mark.parametrize("stage", ["write", "flush"])
@pytest.mark.parametrize(
    "error_kind", [OSError, ValueError, RuntimeError, KeyboardInterrupt, SystemExit, GeneratorExit]
)
def test_stdout_failures_do_not_retry_close_or_replace_primary(stage, error_kind):
    calls = []
    fault = error_kind("Synthetic stdout failure")

    class Sink:
        def write(self, wire):
            calls.append("write")
            if stage == "write":
                raise fault
            return len(wire)

        def flush(self):
            calls.append("flush")
            if stage == "flush":
                raise fault

        def close(self):
            calls.append("close")

    expected = ScapFailure if isinstance(fault, Exception) else error_kind
    with pytest.raises(expected) as raised:
        _files.publish_stdout(Sink(), b"{}", start_budget())
    if isinstance(fault, Exception):
        assert raised.value.code == "publication_failed"
        assert "Synthetic stdout failure" not in str(raised.value)
    else:
        assert raised.value is fault
    assert calls == (["write"] if stage == "write" else ["write", "flush"])


def test_stdout_expired_admission_performs_no_io():
    class ForbiddenSink:
        def __getattribute__(self, name):
            raise AssertionError("Expired admission must not reach the sink")

    with pytest.raises(ScapFailure) as raised:
        _files.publish_stdout(ForbiddenSink(), b"{}", Budget(time.monotonic() - 1.0))
    assert raised.value.code == "processing_deadline_exceeded"


def test_stdout_admission_cancellation_preserves_identity(monkeypatch):
    fault = KeyboardInterrupt("Synthetic admission cancellation")

    def cancelled(self, *, publication=False):
        assert publication is True
        raise fault

    class ForbiddenSink:
        def __getattribute__(self, name):
            raise AssertionError("Cancelled admission must not reach the sink")

    monkeypatch.setattr(Budget, "check", cancelled)
    with pytest.raises(KeyboardInterrupt) as raised:
        _files.publish_stdout(ForbiddenSink(), b"{}", start_budget())
    assert raised.value is fault


def test_stdout_success_after_admitted_write_crosses_real_deadline():
    calls = []
    budget = Budget(time.monotonic() + 1.0)

    class Sink:
        def write(self, wire):
            calls.append(wire)
            time.sleep(max(0.0, budget.deadline - time.monotonic()) + 0.01)
            return len(wire)

        def flush(self):
            calls.append("flush")

    _files.publish_stdout(Sink(), b"{}", budget)
    assert time.monotonic() >= budget.deadline
    assert calls == [b"{}", "flush"]


def test_file_success_after_admitted_replace_crosses_real_deadline(tmp_path, monkeypatch):
    destination = tmp_path / "admitted.json"
    destination.write_bytes(b"previous")
    budget = Budget(time.monotonic() + 1.0)
    replace = os.replace
    replacements = []

    def delayed(source, target):
        replacements.append((source, target))
        time.sleep(max(0.0, budget.deadline - time.monotonic()) + 0.01)
        replace(source, target)

    monkeypatch.setattr(os, "replace", delayed)
    _files.publish_file(destination, b'{"complete":true}', budget)
    assert time.monotonic() >= budget.deadline
    assert destination.read_bytes() == b'{"complete":true}'
    assert len(replacements) == 1
    assert list(tmp_path.iterdir()) == [destination]
