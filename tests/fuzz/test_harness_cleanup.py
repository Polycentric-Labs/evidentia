"""Exercise actual fuzz callback bodies with local file and parser seams."""

from __future__ import annotations

import ast
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from evidentia_core.oscal.profile import ProfileResolutionError
from pydantic import ValidationError

_HARNESSES = {
    "fuzz_catalog_import.py": (
        "_load_catalog_data",
        "load_oscal_catalog",
        "load_evidentia_catalog",
        "load_non_control_catalog",
    ),
    "fuzz_oscal_profile.py": ("_load_oscal_json", "resolve_profile"),
}


class StopInput(BaseException):
    """Represent cancellation without intercepting a real process signal."""


class InputBytes:
    def __init__(self, data):
        self.data = data

    def ConsumeIntInRange(self, low, high):
        assert (low, high) == (0, 2)
        return 0

    def remaining_bytes(self):
        return len(self.data)

    def ConsumeBytes(self, size):
        assert size == len(self.data)
        return self.data


def _load_callback(name, parser_error=None, error_at=0, cleanup_error=None):
    source = Path(__file__).with_name(name)
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    selected = [
        node
        for node in tree.body
        if (isinstance(node, ast.FunctionDef) and node.name == "TestOneInput")
        or (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id in {"_EXPECTED", "_EXTS"} for target in node.targets)
        )
    ]
    assert len([node for node in selected if isinstance(node, ast.FunctionDef)]) == 1
    calls = []
    filenames = []
    writes = []
    unlinks = []

    class Output(io.StringIO):
        def write(self, body):
            writes.append(body)
            return super().write(body)

    def mkstemp(*, suffix):
        filenames.append(suffix)
        return 17, "controlled-input" + suffix

    def fdopen(fd, mode, *, encoding):
        assert (fd, mode, encoding) == (17, "w", "utf-8")
        return Output()

    def unlink(filename):
        unlinks.append(filename)
        if cleanup_error is not None:
            raise cleanup_error

    def make_parser(index, callback_name):
        def parser(filename):
            assert filename == Path("controlled-input.json")
            calls.append(callback_name)
            if parser_error is not None and index == error_at:
                raise parser_error

        return parser

    namespace = {
        "Path": Path,
        "json": json,
        "yaml": yaml,
        "ValidationError": ValidationError,
        "ProfileResolutionError": ProfileResolutionError,
        "os": SimpleNamespace(fdopen=fdopen, unlink=unlink),
        "tempfile": SimpleNamespace(mkstemp=mkstemp),
        "atheris": SimpleNamespace(FuzzedDataProvider=InputBytes),
        "to_text": lambda data: data.decode("utf-8"),
    }
    namespace.update({name: make_parser(index, name) for index, name in enumerate(_HARNESSES[name])})
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), "exec"), namespace)
    return SimpleNamespace(
        run=namespace["TestOneInput"],
        expected=namespace["_EXPECTED"],
        calls=calls,
        filenames=filenames,
        writes=writes,
        unlinks=unlinks,
    )


def _declared_error(error_type):
    if error_type is json.JSONDecodeError:
        return error_type("controlled malformed input", "?", 0)
    if error_type is ValidationError:
        return error_type.from_exception_data("controlled input", [])
    return error_type("controlled malformed input")


def _file_calls(state):
    assert state.filenames == [".json"]
    assert state.writes == ["payload"]
    assert state.unlinks == ["controlled-input.json"]


@pytest.mark.parametrize("name", _HARNESSES)
@pytest.mark.parametrize("cleanup_type", [None, FileNotFoundError, PermissionError, OSError])
def test_success_cleanup(name, cleanup_type):
    error = cleanup_type("controlled cleanup") if cleanup_type else None
    state = _load_callback(name, cleanup_error=error)
    if cleanup_type in (PermissionError, OSError):
        with pytest.raises(cleanup_type) as caught:
            state.run(b"payload")
        assert caught.value is error
    else:
        state.run(b"payload")
    assert state.calls == list(_HARNESSES[name])
    _file_calls(state)


@pytest.mark.parametrize("name", _HARNESSES)
@pytest.mark.parametrize("cleanup_type", [None, FileNotFoundError, PermissionError, OSError])
def test_each_declared_rejection_continues_and_checks_cleanup(name, cleanup_type):
    expected = _load_callback(name).expected
    assert len(expected) == 6
    for index in range(len(_HARNESSES[name])):
        for error_type in expected:
            error = cleanup_type("controlled cleanup") if cleanup_type else None
            state = _load_callback(name, _declared_error(error_type), index, cleanup_error=error)
            if cleanup_type in (PermissionError, OSError):
                with pytest.raises(cleanup_type) as caught:
                    state.run(b"payload")
                assert caught.value is error
            else:
                state.run(b"payload")
            assert state.calls == list(_HARNESSES[name])
            _file_calls(state)


@pytest.mark.parametrize("name", _HARNESSES)
@pytest.mark.parametrize("primary_type", [RuntimeError, StopInput])
@pytest.mark.parametrize("cleanup_type", [None, FileNotFoundError, PermissionError, OSError])
def test_escaping_primary_survives_oserror_cleanup(name, primary_type, cleanup_type):
    for index in range(len(_HARNESSES[name])):
        primary = primary_type("controlled primary")
        cleanup = cleanup_type("controlled cleanup") if cleanup_type else None
        state = _load_callback(name, primary, index, cleanup)
        with pytest.raises(primary_type) as caught:
            state.run(b"payload")
        assert caught.value is primary
        assert state.calls == list(_HARNESSES[name][: index + 1])
        _file_calls(state)


@pytest.mark.parametrize("name", _HARNESSES)
def test_caller_exception_does_not_hide_cleanup_failure(name):
    cleanup = PermissionError("controlled cleanup")
    state = _load_callback(name, cleanup_error=cleanup)
    try:
        raise RuntimeError("ambient handled error")
    except RuntimeError:
        with pytest.raises(PermissionError) as caught:
            state.run(b"payload")
    assert caught.value is cleanup
    assert state.calls == list(_HARNESSES[name])
    _file_calls(state)


@pytest.mark.parametrize("name", _HARNESSES)
def test_empty_input_has_no_file_or_parser_calls(name):
    state = _load_callback(name)
    state.run(b"")
    assert (state.calls, state.filenames, state.writes, state.unlinks) == ([], [], [], [])


@pytest.mark.parametrize("name", _HARNESSES)
@pytest.mark.parametrize("primary_type", [None, RuntimeError, StopInput])
@pytest.mark.parametrize("cleanup_type", [RuntimeError, StopInput])
def test_non_oserror_cleanup_precedence_is_unchanged(name, primary_type, cleanup_type):
    primary = primary_type("controlled primary") if primary_type else None
    cleanup = cleanup_type("controlled cleanup")
    state = _load_callback(name, primary, cleanup_error=cleanup)
    with pytest.raises(cleanup_type) as caught:
        state.run(b"payload")
    assert caught.value is cleanup
    assert state.calls == list(_HARNESSES[name][:1] if primary else _HARNESSES[name])
    _file_calls(state)
