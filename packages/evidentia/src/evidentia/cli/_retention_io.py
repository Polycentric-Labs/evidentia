"""Bounded request reads and reserved atomic retention-result output."""

from __future__ import annotations

import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Self

import typer

_REQUEST_BYTES = 65_536
_RESULT_BYTES = 4_194_304


class InputFailure(ValueError):
    """A fixed local request error without source values or operator paths."""


class OutputFailure(OSError):
    """A fixed output error without filesystem exception text."""


@dataclass(frozen=True)
class InputSnapshot:
    path: Path
    content: bytes
    identity: tuple[int, int]


Failure = type[InputFailure] | type[OutputFailure]


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _windows_component(part: str) -> bool:
    base = part.partition(".")[0].rstrip(" ").upper()
    return (
        part.endswith((" ", "."))
        or any(character in '<>:"|?*' or ord(character) < 32 for character in part)
        or base in {"CON", "PRN", "AUX", "NUL"}
        or (len(base) == 4 and base[:3] in {"COM", "LPT"} and base[3] in "123456789\u00b9\u00b2\u00b3")
    )


def _path(path: Path, failure: Failure) -> Path:
    text = os.fspath(path)
    if text == "-" or "\x00" in text:
        raise failure("invalid_path")
    if os.name == "nt" and (
        text.startswith(("\\\\?\\", "\\\\.\\"))
        or (path.drive and not path.root)
        or any(_windows_component(part) for part in path.parts if part not in {path.anchor, ".", ".."})
    ):
        raise failure("invalid_path")
    # Keep parent components visible until every ancestor has been checked.
    return path if path.is_absolute() else Path.cwd() / path


def _parents(path: Path, failure: Failure) -> None:
    try:
        for parent in reversed(path.parents):
            info = parent.lstat()
            if _reparse(info) or not stat.S_ISDIR(info.st_mode):
                raise failure("invalid_path")
    except OSError:
        raise failure("invalid_path") from None


def _file(path: Path, failure: Failure, *, absent: bool = False) -> os.stat_result | None:
    _parents(path, failure)
    try:
        info = path.lstat()
    except FileNotFoundError:
        if absent:
            return None
        raise failure("invalid_file") from None
    except OSError:
        raise failure("invalid_file") from None
    if _reparse(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise failure("invalid_file")
    return info


def read_request_file(source: Path) -> InputSnapshot:
    """Read at most one extra byte from a regular file with one hard link."""
    descriptor: int | None = None
    try:
        path = _path(source, InputFailure)
        before = _file(path, InputFailure)
        if before is None or before.st_size > _REQUEST_BYTES:
            raise InputFailure("invalid_input")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        # Compare ctime only within one API; Windows stat views can differ.
        opened = os.fstat(descriptor)
        current = _file(path, InputFailure)
        if (
            current is None
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _fingerprint(opened)[:4] != _fingerprint(before)[:4]
            or _fingerprint(current) != _fingerprint(before)
        ):
            raise InputFailure("changed_input")
        content = bytearray()
        while chunk := os.read(descriptor, min(8192, _REQUEST_BYTES + 1 - len(content))):
            content.extend(chunk)
            if len(content) > _REQUEST_BYTES:
                raise InputFailure("request_limit")
        final = os.fstat(descriptor)
        current = _file(path, InputFailure)
        if (
            current is None
            or _fingerprint(final) != _fingerprint(opened)
            or _fingerprint(current) != _fingerprint(before)
            or final.st_nlink != 1
        ):
            raise InputFailure("changed_input")
        return InputSnapshot(path, bytes(content), _identity(opened))
    except (OSError, ValueError):
        raise InputFailure("invalid_input") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise InputFailure("input_close_failed") from None


class ReservedOutput:
    """Reserve a unique sibling before collection and replace only after validation."""

    def __init__(self, source: InputSnapshot, output: Path | None) -> None:
        self.source = source
        self.output = _path(output, OutputFailure) if output is not None else None
        self.temporary: Path | None = None
        self.stream: BinaryIO | None = None
        self._original: os.stat_result | None = None
        self._reserved: tuple[int, int] | None = None
        self._entered = False
        self._published = False

    def _destination(self, *, initial: bool = False) -> None:
        if self.output is None:
            return
        info = _file(self.output, OutputFailure, absent=True)
        current_source = _file(self.source.path, InputFailure, absent=True)
        # Normalize spelling only after inspecting the actual ancestors, including '..'.
        if os.path.normcase(os.path.abspath(self.output)) == os.path.normcase(os.path.abspath(self.source.path)):
            raise InputFailure("input_output_alias")
        if info is not None:
            if _identity(info) == self.source.identity or (
                current_source is not None and _identity(info) == _identity(current_source)
            ):
                raise InputFailure("input_output_alias")
            if not info.st_mode & stat.S_IWRITE or not os.access(self.output, os.W_OK):
                raise OutputFailure("invalid_output")
        if initial:
            self._original = info
        elif (info is None) != (self._original is None) or (
            info is not None and self._original is not None and _fingerprint(info) != _fingerprint(self._original)
        ):
            raise OutputFailure("changed_output")

    def __enter__(self) -> Self:
        if self._entered or self._published:
            raise OutputFailure("output_already_reserved")
        self._entered = True
        descriptor: int | None = None
        try:
            self._destination(initial=True)
            if self.output is not None:
                descriptor, name = tempfile.mkstemp(
                    prefix=".evidentia-retention-", suffix=".tmp", dir=self.output.parent
                )
                self.temporary = Path(name)
                self._reserved = _identity(os.fstat(descriptor))
                self.stream = os.fdopen(descriptor, "w+b")
                descriptor = None
                self._check_reserved()
            return self
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            self._cleanup()
            raise

    def _check_reserved(self) -> None:
        if self.temporary is None or self._reserved is None:
            raise OutputFailure("output_not_reserved")
        info = _file(self.temporary, OutputFailure)
        if info is None or _identity(info) != self._reserved:
            raise OutputFailure("changed_reservation")
        if self.stream is not None and not self.stream.closed:
            opened = os.fstat(self.stream.fileno())
            if _identity(opened) != self._reserved or opened.st_nlink != 1 or not stat.S_ISREG(opened.st_mode):
                raise OutputFailure("changed_reservation")

    def publish(self, content: bytes) -> None:
        if not self._entered or self._published or type(content) is not bytes or len(content) > _RESULT_BYTES:
            raise OutputFailure("invalid_output")
        try:
            if self.output is None:
                typer.echo(content.decode("utf-8"), nl=False)
                self._published = True
                return
            if self.stream is None or self.temporary is None:
                raise OutputFailure("output_not_reserved")
            self._destination()
            self._check_reserved()
            if self.stream.write(content) != len(content):
                raise OutputFailure("output_write_failed")
            self.stream.flush()
            os.fsync(self.stream.fileno())
            self.stream.seek(0)
            if self.stream.read(len(content) + 1) != content:
                raise OutputFailure("changed_output_bytes")
            self._check_reserved()
            self.stream.close()
            self._check_reserved()
            self._destination()
            os.replace(self.temporary, self.output)
            self.temporary = None
            self._published = True
        except (OSError, UnicodeError, ValueError):
            raise OutputFailure("output_failed") from None

    def _cleanup(self) -> bool:
        failed = False
        if self.stream is not None and not self.stream.closed:
            try:
                self.stream.close()
            except OSError:
                failed = True
        if self.temporary is not None:
            try:
                _parents(self.temporary, OutputFailure)
                try:
                    info = self.temporary.lstat()
                except FileNotFoundError:
                    info = None
                if info is not None:
                    if _reparse(info) or not stat.S_ISREG(info.st_mode) or _identity(info) != self._reserved:
                        raise OutputFailure("changed_reservation")
                    # Unlink only the owned name, even if another hard link was added.
                    self.temporary.unlink()
                self.temporary = None
            except OSError:
                failed = True
        return not failed

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._entered = False
        if not self._cleanup() and exc is None:
            raise OutputFailure("output_cleanup_failed")
