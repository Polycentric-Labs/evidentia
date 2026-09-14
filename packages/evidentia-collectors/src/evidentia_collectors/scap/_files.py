"""Bounded local file snapshots and atomic publication of accepted SCAP bytes."""

from __future__ import annotations

import hashlib
import os
import platform
import stat
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import BinaryIO, cast

from ._limits import CLAIM_LIMIT, FEED_LIMIT, RAW_LIMIT, RESULT_LIMIT, Budget, ScapFailure

_PATH_TYPE = type(Path())
_REPARSE = 0x400
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def local_path(value: object) -> Path:
    """Admit a native local path without invoking a user path protocol."""
    if type(value) is str:
        text = cast(str, value)
    elif type(value) is _PATH_TYPE:
        text = str(value)
    else:
        raise ScapFailure("invalid_request")
    if not text or "://" in text or "\x00" in text or text.startswith(("//", "\\\\")):
        raise ScapFailure("invalid_request")
    target = Path(os.path.abspath(text))
    if sys.platform == "win32":
        for part in target.parts[1:]:
            if ":" in part or part.rstrip(" .") != part or part.split(".", 1)[0].upper() in _RESERVED:
                raise ScapFailure("invalid_request")
        import ctypes

        drive_type = ctypes.windll.kernel32.GetDriveTypeW(str(target.anchor))
        if drive_type not in (2, 3, 5, 6):
            raise ScapFailure("invalid_request")
    elif sys.platform == "linux":
        _linux_local_mount(target)
    elif sys.platform == "darwin":
        _darwin_local_mount(target)
    else:
        raise ScapFailure("invalid_request")
    return target


def _identity(info: os.stat_result) -> tuple[int, int, int]:
    return info.st_dev, info.st_ino, info.st_mode


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (*_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _same_snapshot(path_info: os.stat_result, descriptor_info: os.stat_result) -> bool:
    # Windows path and descriptor ctime can represent different timestamp kinds.
    # Each is still compared with its own original snapshot after the read.
    def common(info: os.stat_result) -> tuple[int, ...]:
        return (*_identity(info), info.st_size, info.st_mtime_ns, info.st_nlink, getattr(info, "st_birthtime_ns", 0))

    return common(path_info) == common(descriptor_info) and (
        os.name == "nt" or path_info.st_ctime_ns == descriptor_info.st_ctime_ns
    )


def _reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE)


def _parents(target: Path) -> tuple[tuple[Path, tuple[int, int, int]], ...]:
    rows = []
    for parent in reversed(target.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or _reparse(info):
            raise ScapFailure("invalid_request")
        rows.append((parent, _identity(info)))
    return tuple(rows)


def _parents_unchanged(rows: tuple[tuple[Path, tuple[int, int, int]], ...]) -> None:
    for parent, identity in rows:
        current = parent.lstat()
        if _identity(current) != identity or _reparse(current):
            raise ScapFailure("source_read_failed")


def _regular(target: Path, *, optional: bool = False) -> os.stat_result | None:
    try:
        info = target.lstat()
    except FileNotFoundError:
        if optional:
            return None
        raise
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or _reparse(info):
        raise ScapFailure("invalid_request")
    return info


def check_paths(source: object, claim: object = None, output: object = None) -> tuple[Path, Path | None, Path | None]:
    """Reject source, sidecar and output aliases before source parsing or output creation."""
    targets = [
        local_path(source),
        None if claim is None else local_path(claim),
        None if output is None else local_path(output),
    ]
    present: list[tuple[Path, os.stat_result | None]] = []
    try:
        for index, target in enumerate(targets):
            if target is None:
                continue
            _parents(target)
            info = _regular(target, optional=index == 2)
            for earlier, previous in present:
                if os.path.normcase(str(earlier)) == os.path.normcase(str(target)):
                    raise ScapFailure("invalid_request")
                if (
                    info is not None
                    and previous is not None
                    and (info.st_dev, info.st_ino) == (previous.st_dev, previous.st_ino)
                ):
                    raise ScapFailure("invalid_request")
            present.append((target, info))
    except OSError:
        raise ScapFailure("source_read_failed") from None
    return cast(Path, targets[0]), targets[1], targets[2]


def _handle_path(descriptor: int, expected: Path) -> None:
    if sys.platform != "win32":
        return
    import ctypes
    import msvcrt
    from ctypes import wintypes

    function = ctypes.windll.kernel32.GetFinalPathNameByHandleW
    function.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    function.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    size = function(msvcrt.get_osfhandle(descriptor), buffer, len(buffer), 0)
    if size == 0 or size >= len(buffer):
        raise ScapFailure("source_read_failed")
    final = buffer.value
    if final.startswith("\\\\?\\"):
        final = final[4:]
    if os.path.normcase(os.path.normpath(final)) != os.path.normcase(str(expected)):
        raise ScapFailure("source_read_failed")


def _read(path: object, maximum: int, budget: Budget, *, publication: bool = False) -> bytes:
    target = local_path(path)
    descriptor: int | None = None
    primary: BaseException | None = None
    parts: list[bytes] = []
    try:
        budget.check(publication=publication)
        parents = _parents(target)
        before = _regular(target)
        if before is None:
            raise ScapFailure("source_read_failed")
        if before.st_size > maximum:
            raise ScapFailure("source_limit_exceeded")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(target, flags)
        opened = os.fstat(descriptor)
        _handle_path(descriptor, target)
        if not _same_snapshot(before, opened):
            raise ScapFailure("source_read_failed")
        total = 0
        while True:
            budget.check(publication=publication)
            part = os.read(descriptor, min(FEED_LIMIT, maximum + 1 - total))
            budget.check(publication=publication)
            if not part:
                break
            total += len(part)
            if total > maximum:
                raise ScapFailure("source_limit_exceeded")
            parts.append(part)
        if total != opened.st_size or _fingerprint(os.fstat(descriptor)) != _fingerprint(opened):
            raise ScapFailure("source_read_failed")
        after = _regular(target)
        if after is None or _fingerprint(after) != _fingerprint(before):
            raise ScapFailure("source_read_failed")
        _parents_unchanged(parents)
        budget.check(publication=publication)
        raw = b"".join(parts)
        budget.check(publication=publication)
        return raw
    except BaseException as error:
        primary = error
        if isinstance(error, OSError):
            primary = ScapFailure("source_read_failed")
            raise primary from None
        raise
    finally:
        parts.clear()
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as cleanup_error:
                if primary is None:
                    if not isinstance(cleanup_error, Exception):
                        raise
                    raise ScapFailure("source_read_failed") from None
                with suppress(BaseException):
                    primary.add_note("SCAP source descriptor cleanup also failed.")


def read_source(path: object, budget: Budget) -> bytes:
    return _read(path, RAW_LIMIT, budget)


def read_claim(path: object, budget: Budget) -> bytes:
    return _read(path, CLAIM_LIMIT, budget)


def publish_file(path: object, wire: bytes, budget: Budget) -> None:
    """Replace one output only after its complete private candidate passes readback."""
    if type(wire) is not bytes or not 0 < len(wire) <= RESULT_LIMIT:
        raise ScapFailure()
    target = local_path(path)
    temporary: str | None = None
    descriptor_owner: list[int | None] = [None]
    committed = False
    primary: BaseException | None = None
    try:
        budget.check(publication=True)
        parents = _parents(target)
        previous = _regular(target, optional=True)
        descriptor_owner[0], temporary = tempfile.mkstemp(prefix=".scap-output-", suffix=".tmp", dir=target.parent)
        candidate = os.fstat(cast(int, descriptor_owner[0]))
        _handle_path(cast(int, descriptor_owner[0]), Path(temporary))
        with _owned_stream(descriptor_owner) as stream:
            for start in range(0, len(wire), FEED_LIMIT):
                budget.check(publication=True)
                if stream.write(wire[start : start + FEED_LIMIT]) != len(wire[start : start + FEED_LIMIT]):
                    raise ScapFailure("publication_failed")
            stream.flush()
            budget.check(publication=True)
            written = os.fstat(stream.fileno())
            written_path = _regular(Path(temporary))
            if (
                _identity(written) != _identity(candidate)
                or written.st_size != len(wire)
                or written_path is None
                or not _same_snapshot(written_path, written)
            ):
                raise ScapFailure("publication_failed")
            stream.seek(0)
            digest, size = hashlib.sha256(), 0
            while chunk := stream.read(FEED_LIMIT):
                budget.check(publication=True)
                size += len(chunk)
                if size > len(wire):
                    raise ScapFailure("publication_failed")
                digest.update(chunk)
            if size != len(wire) or digest.digest() != hashlib.sha256(wire).digest():
                raise ScapFailure("publication_failed")
            if _fingerprint(os.fstat(stream.fileno())) != _fingerprint(written):
                raise ScapFailure("publication_failed")
        _parents_unchanged(parents)
        current = _regular(target, optional=True)
        if (previous is None) != (current is None) or (
            previous is not None and current is not None and _fingerprint(previous) != _fingerprint(current)
        ):
            raise ScapFailure("publication_failed")
        temporary_info = _regular(Path(temporary))
        if temporary_info is None or _fingerprint(temporary_info) != _fingerprint(written_path):
            raise ScapFailure("publication_failed")
        # A final descriptor read also detects same-size changes hidden by timestamp granularity.
        try:
            readback = _read(Path(temporary), len(wire), budget, publication=True)
        except ScapFailure as error:
            if error.code == "processing_deadline_exceeded":
                raise
            raise ScapFailure("publication_failed") from None
        if readback != wire:
            raise ScapFailure("publication_failed")
        budget.check(publication=True)
        os.replace(temporary, target)
        committed = True
    except BaseException as error:
        primary = error
        if isinstance(error, OSError):
            primary = ScapFailure("publication_failed")
            raise primary from None
        raise
    finally:
        for cleanup in (
            (lambda: os.close(cast(int, descriptor_owner[0]))) if descriptor_owner[0] is not None else None,
            (lambda: os.unlink(temporary)) if temporary is not None and not committed else None,
        ):
            if cleanup is None:
                continue
            try:
                cleanup()
            except BaseException:
                if primary is not None:
                    with suppress(BaseException):
                        primary.add_note("SCAP temporary-file cleanup also failed.")
                elif not committed:
                    raise ScapFailure("publication_failed") from None


@contextmanager
def _owned_stream(owner: list[int | None]) -> Iterator[BinaryIO]:
    descriptor = owner[0]
    if descriptor is None:
        raise ScapFailure()
    stream: BinaryIO | None = None
    primary: BaseException | None = None
    try:
        owner[0] = None
        stream = os.fdopen(descriptor, "w+b")
        yield stream
    except BaseException as error:
        primary = error
        raise
    finally:
        if owner[0] is None:
            try:
                if stream is None:
                    os.close(descriptor)
                else:
                    stream.close()
            except BaseException as cleanup_error:
                if primary is None:
                    if not isinstance(cleanup_error, Exception):
                        raise
                    raise ScapFailure("publication_failed") from None
                with suppress(BaseException):
                    primary.add_note("SCAP output stream cleanup also failed.")


def _mount_text(value: str) -> str:
    for encoded, decoded in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(encoded, decoded)
    return value


def _linux_local_mount(target: Path) -> None:
    with open("/proc/self/mountinfo", "rb") as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ScapFailure("invalid_request")
    selected_length = -1
    selected_types: set[str] = set()
    for line in raw.decode("utf-8", errors="surrogateescape").splitlines():
        left, separator, right = line.partition(" - ")
        fields, filesystem = left.split(), right.split()
        if not separator or len(fields) < 6 or len(filesystem) < 3:
            raise ScapFailure("invalid_request")
        mount = _mount_text(fields[4])
        if os.path.commonpath((str(target), mount)) == mount:
            if len(mount) > selected_length:
                selected_length = len(mount)
                selected_types = {filesystem[0]}
            elif len(mount) == selected_length:
                selected_types.add(filesystem[0])
    local = {
        "ext2",
        "ext3",
        "ext4",
        "xfs",
        "btrfs",
        "overlay",
        "tmpfs",
        "ramfs",
        "bcachefs",
        "f2fs",
        "zfs",
        "jfs",
        "reiserfs",
        "ufs",
        "vfat",
        "msdos",
        "exfat",
        "ntfs",
        "ntfs3",
        "iso9660",
        "udf",
        "hfs",
        "hfsplus",
        "fuseblk",
    }
    # Ambiguous stacked mounts cannot depend on mountinfo line ordering.
    if not selected_types or not selected_types <= local:
        raise ScapFailure("invalid_request")


def _darwin_local_mount(target: Path) -> None:
    import ctypes

    class MountInfo(ctypes.Structure):
        _fields_ = [
            ("block_size", ctypes.c_uint32),
            ("io_size", ctypes.c_int32),
            ("block_counts", ctypes.c_uint64 * 5),
            ("filesystem_id", ctypes.c_int32 * 2),
            ("owner", ctypes.c_uint32),
            ("filesystem_type", ctypes.c_uint32),
            ("flags", ctypes.c_uint32),
            ("subtype", ctypes.c_uint32),
            ("type_name", ctypes.c_char * 16),
            ("mount_point", ctypes.c_char * 1024),
            ("mount_source", ctypes.c_char * 1024),
            ("extended_flags", ctypes.c_uint32),
            ("reserved", ctypes.c_uint32 * 7),
        ]

    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    machine = platform.machine().lower()
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ScapFailure("invalid_request")
    if machine in {"arm64", "aarch64"}:
        function = library.statfs
    elif machine in {"x86_64", "amd64"}:
        function = library.statfs64
    else:
        raise ScapFailure("invalid_request")
    function.argtypes = [ctypes.c_char_p, ctypes.POINTER(MountInfo)]
    function.restype = ctypes.c_int
    info = MountInfo()
    probe = target if target.exists() else target.parent
    if function(os.fsencode(probe), ctypes.byref(info)) != 0 or not info.flags & 0x1000:
        raise ScapFailure("invalid_request")


def publish_stdout(stream: BinaryIO, wire: bytes, budget: Budget) -> None:
    """Admit one stdout write; delivery after admission cannot be rolled back."""
    if type(wire) is not bytes or not 0 < len(wire) <= RESULT_LIMIT:
        raise ScapFailure()
    budget.check(publication=True)
    try:
        count = stream.write(wire)
        if type(count) is not int or count != len(wire):
            raise ScapFailure("publication_failed")
        stream.flush()
    except Exception:
        raise ScapFailure("publication_failed") from None
