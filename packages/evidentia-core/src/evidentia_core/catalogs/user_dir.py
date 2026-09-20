"""User-imported catalog directory management.

v0.2.0 introduces a user-writable catalog directory so organizations
can load their own licensed copies of Tier-C stubs (ISO 27001, SOC 2,
PCI DSS, HITRUST, etc.) without touching the installed package. The
directory location follows platform conventions via ``platformdirs``:

- Windows:  ``%APPDATA%\\Evidentia\\catalogs\\``
- macOS:    ``~/Library/Application Support/evidentia/catalogs/``
- Linux:    ``~/.local/share/evidentia/catalogs/``

Override with the ``EVIDENTIA_CATALOG_DIR`` environment variable
or the ``--catalog-dir`` CLI flag (passed through to callers).

User-dir catalogs **shadow bundled catalogs of the same framework_id**
— precedence is user > bundled. This lets a user import, e.g., a real
AICPA TSC JSON and have ``evidentia catalog show soc2-tsc CC6.1``
render their licensed text instead of the stub.
"""

from __future__ import annotations

import errno
import hashlib
import io
import json
import logging
import os
import stat
import sys
import threading
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from platformdirs import user_data_dir

from evidentia_core.catalogs.manifest import (
    FrameworkManifest,
    FrameworkManifestEntry,
)
from evidentia_core.models.catalog import ControlCatalog
from evidentia_core.models.open_corpora import (
    CatalogPublicationObservation,
    ExternalIndex,
    ImportResult,
    NativeBudget,
    NativeSourceError,
    native_operation,
)

logger = logging.getLogger(__name__)

CATALOG_DIR_ENV_VAR = "EVIDENTIA_CATALOG_DIR"
USER_MANIFEST_FILENAME = "frameworks.yaml"
_MANIFEST_LIMIT = 4_194_304
_ENTRY_LIMIT = 4096
_CATALOG_LIMIT = 16_777_216
_BSI_ID = "bsi-grundschutz-plus-plus"
_BSI_PROFILE = "bsi-grundschutz-plus-plus-367d7750"
_BSI_FILES = ("Grundschutz++-resolved_catalog.json", "LICENSE.txt", "README.md", "source-index.json", "catalog.json")
_LOCK_NAME = "frameworks.yaml.lock"


class CatalogStorageError(ValueError):
    """A fixed storage classification; publication facts remain on the transaction."""

    def __init__(self, code: str) -> None:
        if code not in {
            "catalog_transaction_conflict",
            "catalog_storage_unsupported",
            "catalog_manifest_invalid",
            "catalog_storage_limit_exceeded",
            "catalog_generation_conflict",
            "catalog_storage_failed",
            "catalog_publication_failed",
            "catalog_publication_indeterminate",
            "catalog_cleanup_failed",
        }:
            raise ValueError("catalog_storage_failed")
        self.code = code
        super().__init__(code)


def _configured_user_dir(override: Path | None) -> Path:
    # Preserve the spelling until every original component has been checked.
    if override is not None:
        return Path(override).expanduser()
    if value := os.environ.get(CATALOG_DIR_ENV_VAR):
        return Path(value).expanduser()
    return Path(user_data_dir("evidentia", "Evidentia")) / "catalogs"


def _directory(path: Path, *, create: bool = False, budget: NativeBudget | None = None) -> Path:
    if ".." in path.parts or str(path).startswith(("\\\\", "//")):
        raise CatalogStorageError("catalog_storage_unsupported")
    absolute = path.absolute()
    for part in (*reversed(absolute.parents), absolute):
        if budget is not None:
            budget.check()
        try:
            info = part.lstat()
        except FileNotFoundError:
            if not create:
                raise
            if budget is not None:
                budget.check()
            with suppress(FileExistsError):
                part.mkdir()
            if budget is not None:
                budget.check()
            info = part.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 1024
        ):
            raise CatalogStorageError("catalog_storage_unsupported")
    if budget is not None:
        budget.check()
    return absolute


def _parent_identity(path: Path, budget: NativeBudget | None = None) -> tuple[tuple[Path, int, int], ...]:
    _directory(path, budget=budget)
    result = []
    for part in (*path.parents, path):
        if budget is not None:
            budget.check()
        info = part.lstat()
        result.append((part, info.st_dev, info.st_ino))
    return tuple(result)


def _check_parents(identities: tuple[tuple[Path, int, int], ...], budget: NativeBudget | None = None) -> None:
    for path, device, inode in identities:
        if budget is not None:
            budget.check()
        info = path.lstat()
        if (
            (info.st_dev, info.st_ino) != (device, inode)
            or not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 1024
        ):
            raise CatalogStorageError("catalog_storage_unsupported")


def _linux_filesystem_type(descriptor: int, budget: NativeBudget) -> int:
    """Admit the reviewed GNU libc x86-64 LP64 ext-family storage ABI."""
    import ctypes
    import platform

    budget.check()
    if (
        sys.platform != "linux"
        or platform.machine().lower() not in ("x86_64", "amd64")
        or ctypes.sizeof(ctypes.c_void_p) != 8
        or ctypes.sizeof(ctypes.c_long) != 8
        or ctypes.sizeof(ctypes.c_int) != 4
    ):
        raise CatalogStorageError("catalog_storage_unsupported")

    class StatFs(ctypes.Structure):
        _fields_ = [
            ("f_type", ctypes.c_long),
            ("f_bsize", ctypes.c_long),
            ("f_blocks", ctypes.c_ulong),
            ("f_bfree", ctypes.c_ulong),
            ("f_bavail", ctypes.c_ulong),
            ("f_files", ctypes.c_ulong),
            ("f_ffree", ctypes.c_ulong),
            ("f_fsid", ctypes.c_int * 2),
            ("f_namelen", ctypes.c_long),
            ("f_frsize", ctypes.c_long),
            ("f_flags", ctypes.c_long),
            ("f_spare", ctypes.c_long * 4),
        ]

    offsets = (0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88)
    if (
        ctypes.sizeof(StatFs) != 120
        or ctypes.alignment(StatFs) != 8
        or any(
            getattr(StatFs, name).offset != offset for (name, _), offset in zip(StatFs._fields_, offsets, strict=True)
        )
    ):
        raise CatalogStorageError("catalog_storage_unsupported")
    try:
        library = ctypes.CDLL(None, use_errno=True)
        if not callable(library.gnu_get_libc_version):
            raise CatalogStorageError("catalog_storage_unsupported")
        query = library.fstatfs
    except (AttributeError, OSError) as error:
        raise CatalogStorageError("catalog_storage_unsupported") from error
    query.argtypes = [ctypes.c_int, ctypes.POINTER(StatFs)]
    query.restype = ctypes.c_int
    value = StatFs()
    budget.check()
    try:
        result = query(descriptor, ctypes.byref(value))
    except Exception as error:
        raise CatalogStorageError("catalog_storage_unsupported") from error
    budget.check()
    if result != 0:
        raise CatalogStorageError("catalog_storage_unsupported") from OSError(ctypes.get_errno(), "fstatfs")
    # Linux assigns the same published magic to ext2, ext3 and ext4.
    if value.f_type != 0xEF53:
        raise CatalogStorageError("catalog_storage_unsupported")
    return int(value.f_type)


def _windows_local_drive(path: Path, budget: NativeBudget) -> None:
    """Refuse mapped remote or unsupported drives before creating storage."""
    import ctypes
    from ctypes import wintypes

    budget.check()
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    query = api.GetDriveTypeW
    query.argtypes = [wintypes.LPCWSTR]
    query.restype = wintypes.UINT
    budget.check()
    drive_type = query(path.absolute().anchor)
    budget.check()
    if drive_type not in (2, 3, 6):
        raise CatalogStorageError("catalog_storage_unsupported")


def _bounded_read(path: Path, limit: int, budget: NativeBudget, *, absent: bool = False) -> bytes | None:
    from evidentia_core.catalogs.loader import _read_native_catalog

    budget.check()
    try:
        size = path.lstat().st_size
    except FileNotFoundError:
        if absent:
            return None
        raise
    if size > limit:
        raise CatalogStorageError("catalog_storage_limit_exceeded")
    return _read_native_catalog(path, limit, budget)


class _ManifestLoader(yaml.SafeLoader):
    """Bounded YAML without duplicate keys or shared object aliases."""

    def __init__(self, stream: str, budget: NativeBudget) -> None:
        super().__init__(stream)
        self._budget = budget
        self._depth = 0
        self._nodes = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        self._nodes += 1
        self._depth += 1
        try:
            if self._depth > 64 or self._nodes > _MANIFEST_LIMIT:
                raise CatalogStorageError("catalog_storage_limit_exceeded")
            if self._nodes % 128 == 0:
                self._budget.check()
            event = self.peek_event()
            if isinstance(event, yaml.AliasEvent):
                raise CatalogStorageError("catalog_manifest_invalid")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if type(key) is not str or key in result:
                raise CatalogStorageError("catalog_manifest_invalid")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _parse_manifest(raw: bytes | None, budget: NativeBudget) -> FrameworkManifest:
    if raw is None:
        return FrameworkManifest(version=1, frameworks=[])
    if len(raw) > _MANIFEST_LIMIT:
        raise CatalogStorageError("catalog_storage_limit_exceeded")
    loader: _ManifestLoader | None = None
    try:
        budget.check()
        loader = _ManifestLoader(raw.decode("utf-8"), budget)
        data = loader.get_single_data()
        if data is None:
            data = {}
        if type(data) is not dict:
            raise CatalogStorageError("catalog_manifest_invalid")
        data.setdefault("version", 1)
        data.setdefault("frameworks", [])
        if type(data["frameworks"]) is not list or len(data["frameworks"]) > _ENTRY_LIMIT:
            raise CatalogStorageError("catalog_storage_limit_exceeded")
        result = FrameworkManifest.model_validate(data)
        ids = [entry.id for entry in result.frameworks]
        if len(ids) != len(set(ids)):
            raise CatalogStorageError("catalog_manifest_invalid")
        budget.check()
        return result
    except (yaml.YAMLError, UnicodeError, ValueError) as error:
        if isinstance(error, (CatalogStorageError, NativeSourceError)):
            raise
        raise CatalogStorageError("catalog_manifest_invalid") from error
    finally:
        if loader is not None:
            loader.dispose()


class _BoundedYaml(io.StringIO):
    def __init__(self, budget: NativeBudget) -> None:
        super().__init__()
        self._bytes = 0
        self._budget = budget

    def write(self, text: str) -> int:
        self._bytes += len(text.encode("utf-8"))
        if self._bytes > _MANIFEST_LIMIT:
            raise CatalogStorageError("catalog_storage_limit_exceeded")
        self._budget.check()
        return super().write(text)


def _manifest_bytes(manifest: FrameworkManifest, budget: NativeBudget) -> bytes:
    if type(manifest) is not FrameworkManifest or len(manifest.frameworks) > _ENTRY_LIMIT:
        raise CatalogStorageError("catalog_storage_limit_exceeded")
    # Re-enter native instance admission before serialization can omit forged keys.
    captured = FrameworkManifest(version=manifest.version, frameworks=list(manifest.frameworks))
    payload = FrameworkManifest.model_dump(captured, mode="json", exclude_none=True)
    captured = FrameworkManifest.model_validate(payload)
    ids = [entry.id for entry in captured.frameworks]
    if len(ids) != len(set(ids)):
        raise CatalogStorageError("catalog_manifest_invalid")
    with _BoundedYaml(budget) as stream:
        yaml.safe_dump(payload, stream, sort_keys=False, default_flow_style=False)
        encoded = stream.getvalue().encode("utf-8")
    budget.check()
    return encoded


class _NativeLock:
    """One independent native lock owner; the empty lock pathname is permanent."""

    def __init__(self, directory: Path, budget: NativeBudget | None = None) -> None:
        self.directory = directory
        self.parents = _parent_identity(directory, budget)
        self.directory_fd: int | None = None
        self.descriptor: int | None = None
        self.handle: Any = None
        self.parent_handle: Any = None
        self.api: Any = None
        self.overlapped: Any = None
        self.locked = False
        self.cleanup_failures: list[tuple[str, BaseException]] = []

    def acquire(self, budget: NativeBudget) -> None:
        budget.check()
        if os.name == "nt":
            self._windows_acquire(budget)
        elif os.name == "posix":
            self._posix_acquire(budget)
        else:
            raise CatalogStorageError("catalog_storage_unsupported")
        _check_parents(self.parents, budget)
        budget.check()

    def _posix_acquire(self, budget: NativeBudget) -> None:
        import fcntl

        native_fcntl: Any = fcntl
        native_os: Any = os
        required = ("O_CLOEXEC", "O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")
        if any(not hasattr(os, name) for name in required) or os.open not in os.supports_dir_fd:
            raise CatalogStorageError("catalog_storage_unsupported")
        flags = {name: getattr(os, name) for name in required}
        budget.check()
        self.directory_fd = os.open(
            self.directory, os.O_RDONLY | flags["O_DIRECTORY"] | flags["O_CLOEXEC"] | flags["O_NOFOLLOW"]
        )
        budget.check()
        opened_directory = os.fstat(self.directory_fd)
        budget.check()
        path_directory = self.directory.lstat()
        budget.check()
        if (opened_directory.st_dev, opened_directory.st_ino) != (path_directory.st_dev, path_directory.st_ino):
            raise CatalogStorageError("catalog_storage_unsupported")
        if sys.platform == "linux":
            _linux_filesystem_type(self.directory_fd, budget)
        if hasattr(os, "ST_LOCAL"):
            budget.check()
            local_flags = native_os.fstatvfs(self.directory_fd).f_flag
            budget.check()
            if not local_flags & os.ST_LOCAL:
                raise CatalogStorageError("catalog_storage_unsupported")
        budget.check()
        self.descriptor = os.open(
            _LOCK_NAME,
            os.O_RDWR | os.O_CREAT | flags["O_CLOEXEC"] | flags["O_NOFOLLOW"] | flags["O_NONBLOCK"],
            0o600,
            dir_fd=self.directory_fd,
        )
        budget.check()
        opened = os.fstat(self.descriptor)
        budget.check()
        observed = os.stat(_LOCK_NAME, dir_fd=self.directory_fd, follow_symlinks=False)
        budget.check()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != 0
            or opened.st_nlink != 1
            or opened.st_dev != opened_directory.st_dev
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise CatalogStorageError("catalog_storage_unsupported")
        for descriptor in (self.descriptor, self.directory_fd):
            budget.check()
            inheritable = os.get_inheritable(descriptor)
            budget.check()
            if inheritable:
                raise CatalogStorageError("catalog_storage_unsupported")
        budget.check()
        try:
            native_fcntl.flock(self.descriptor, native_fcntl.LOCK_EX | native_fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN):
                raise CatalogStorageError("catalog_transaction_conflict") from error
            raise
        self.locked = True
        budget.check()

    def _windows_acquire(self, budget: NativeBudget) -> None:
        import ctypes
        from ctypes import wintypes

        class AttributeTag(ctypes.Structure):
            _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]

        class Standard(ctypes.Structure):
            _fields_ = [
                ("allocation", ctypes.c_longlong),
                ("size", ctypes.c_longlong),
                ("links", wintypes.DWORD),
                ("delete_pending", ctypes.c_ubyte),
                ("directory", ctypes.c_ubyte),
            ]

        class FileIdentity(ctypes.Structure):
            _fields_ = [("volume", ctypes.c_ulonglong), ("identifier", ctypes.c_ubyte * 16)]

        class Overlapped(ctypes.Structure):
            _fields_ = [
                ("internal", ctypes.c_size_t),
                ("internal_high", ctypes.c_size_t),
                ("offset", wintypes.DWORD),
                ("offset_high", wintypes.DWORD),
                ("event", wintypes.HANDLE),
            ]

        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        api.CreateFileW.restype = wintypes.HANDLE
        api.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        api.GetFileInformationByHandleEx.restype = wintypes.BOOL
        api.GetFileType.argtypes = [wintypes.HANDLE]
        api.GetFileType.restype = wintypes.DWORD
        api.LockFileEx.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(Overlapped),
        ]
        api.LockFileEx.restype = wintypes.BOOL
        api.UnlockFileEx.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(Overlapped),
        ]
        api.UnlockFileEx.restype = wintypes.BOOL
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        api.CloseHandle.restype = wintypes.BOOL
        self.api = api
        self.overlapped = Overlapped()
        _windows_local_drive(self.directory, budget)

        def open_handle(path: Path, access: int, disposition: int, flags: int) -> Any:
            budget.check()
            handle = api.CreateFileW(str(path), access, 3, None, disposition, flags, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            return handle

        def identity(handle: Any, *, directory: bool) -> tuple[int, bytes]:
            attrs, standard, identifier = AttributeTag(), Standard(), FileIdentity()
            for info_class, value in ((9, attrs), (1, standard), (18, identifier)):
                budget.check()
                if not api.GetFileInformationByHandleEx(handle, info_class, ctypes.byref(value), ctypes.sizeof(value)):
                    raise ctypes.WinError(ctypes.get_last_error())
                budget.check()
            budget.check()
            file_type = api.GetFileType(handle)
            budget.check()
            if (
                file_type != 1
                or attrs.attributes & 1024
                or standard.delete_pending
                or bool(standard.directory) != directory
                or (not directory and (standard.size != 0 or standard.links != 1))
            ):
                raise CatalogStorageError("catalog_storage_unsupported")
            return identifier.volume, bytes(identifier.identifier)

        self.parent_handle = open_handle(self.directory, 0x80000000, 3, 0x02200000)
        budget.check()
        parent_identity = identity(self.parent_handle, directory=True)
        # Holding this parent without SHARE_DELETE prevents cooperative replacement.
        if not parent_identity[1]:
            raise CatalogStorageError("catalog_storage_unsupported")
        self.handle = open_handle(self.directory / _LOCK_NAME, 0xC0000000, 4, 0x00200000)
        budget.check()
        locked_identity = identity(self.handle, directory=False)
        check_handle = open_handle(self.directory / _LOCK_NAME, 0x80000000, 3, 0x00200000)
        primary: BaseException | None = None
        try:
            budget.check()
            if identity(check_handle, directory=False) != locked_identity:
                raise CatalogStorageError("catalog_storage_unsupported")
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                if not api.CloseHandle(check_handle):
                    raise ctypes.WinError(ctypes.get_last_error())
            except BaseException as cleanup:
                self.cleanup_failures.append(("handle_close_failed", cleanup))
                if primary is not None:
                    raise primary from cleanup
                raise
        budget.check()
        if not api.LockFileEx(self.handle, 3, 0, 1, 0, ctypes.byref(self.overlapped)):
            code = ctypes.get_last_error()
            if code == 33:
                raise CatalogStorageError("catalog_transaction_conflict")
            raise ctypes.WinError(code)
        self.locked = True
        budget.check()

    def close(self) -> list[tuple[str, BaseException]]:
        failures = self.cleanup_failures[:]
        self.cleanup_failures.clear()
        if os.name == "nt":
            import ctypes

            if self.locked:
                try:
                    if not self.api.UnlockFileEx(self.handle, 0, 1, 0, ctypes.byref(self.overlapped)):
                        raise ctypes.WinError(ctypes.get_last_error())
                except BaseException as error:
                    failures.append(("lock_release_failed", error))
                self.locked = False
            for name in ("handle", "parent_handle"):
                handle = getattr(self, name)
                if handle is not None:
                    setattr(self, name, None)
                    try:
                        if not self.api.CloseHandle(handle):
                            raise ctypes.WinError(ctypes.get_last_error())
                    except BaseException as error:
                        failures.append(("handle_close_failed", error))
        else:
            if self.locked and self.descriptor is not None:
                import fcntl

                native_fcntl: Any = fcntl
                try:
                    native_fcntl.flock(self.descriptor, native_fcntl.LOCK_UN)
                except BaseException as error:
                    failures.append(("lock_release_failed", error))
                self.locked = False
            for name in ("descriptor", "directory_fd"):
                descriptor = getattr(self, name)
                if descriptor is not None:
                    setattr(self, name, None)
                    try:
                        os.close(descriptor)
                    except BaseException as error:
                        failures.append(("handle_close_failed", error))
        return failures


@dataclass(frozen=True, slots=True)
class CatalogMutationIntent:
    """An operation request; commit captures its values before preparing storage."""

    operation: Literal["native_import", "legacy_import", "remove"]
    framework_id: str
    entry: object = None
    catalog_bytes: object = None
    sources: object = None
    force: bool = False
    expected_entry_sha256: str | None = None

    def __post_init__(self) -> None:
        if type(self.operation) is not str or self.operation not in ("native_import", "legacy_import", "remove"):
            raise CatalogStorageError("catalog_manifest_invalid")

    @classmethod
    def remove(cls, framework_id: str, *, expected_entry_sha256: str | None = None) -> CatalogMutationIntent:
        return cls("remove", framework_id, expected_entry_sha256=expected_entry_sha256)

    @classmethod
    def legacy(
        cls, entry: FrameworkManifestEntry, catalog_bytes: bytes, *, force: bool = False
    ) -> CatalogMutationIntent:
        return cls("legacy_import", entry.id, entry=entry, catalog_bytes=catalog_bytes, force=force)

    @classmethod
    def native(cls, sources: object) -> CatalogMutationIntent:
        return cls("native_import", _BSI_ID, sources=sources)


def catalog_entry_sha256(entry: FrameworkManifestEntry) -> str:
    """Bind the exact manifest value shown before an interactive confirmation."""
    if type(entry) is not FrameworkManifestEntry:
        raise CatalogStorageError("catalog_manifest_invalid")
    captured = FrameworkManifestEntry.model_validate(entry)
    data = FrameworkManifestEntry.model_dump(captured, mode="json", exclude_none=True)
    FrameworkManifestEntry.model_validate(data)
    return hashlib.sha256(
        json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _closed_names(
    directory: Path,
    expected: tuple[str, ...],
    budget: NativeBudget,
    cleanup_failures: list[tuple[str, BaseException]] | None = None,
) -> None:
    budget.check()
    _directory(directory, budget=budget)
    names: set[str] = set()
    budget.check()
    entries = os.scandir(directory)
    primary: BaseException | None = None
    try:
        while True:
            budget.check()
            try:
                entry = next(entries)
            except StopIteration:
                break
            budget.check()
            if entry.name not in expected or entry.name in names:
                raise CatalogStorageError("catalog_generation_conflict")
            # Windows DirEntry metadata can omit link count and file identity.
            info = (directory / entry.name).lstat()
            budget.check()
            if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 1024 or info.st_nlink != 1:
                raise CatalogStorageError("catalog_generation_conflict")
            names.add(entry.name)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            entries.close()
        except BaseException as cleanup:
            if cleanup_failures is not None:
                cleanup_failures.append(("handle_close_failed", cleanup))
            if primary is not None:
                raise primary from cleanup
            raise
    budget.check()
    if names != set(expected):
        raise CatalogStorageError("catalog_generation_conflict")


def _same_generation(
    directory: Path,
    files: tuple[tuple[str, bytes], ...],
    budget: NativeBudget,
    cleanup_failures: list[tuple[str, BaseException]] | None = None,
) -> None:
    _closed_names(directory, tuple(name for name, _ in files), budget, cleanup_failures)
    for name, expected in files:
        if _bounded_read(directory / name, len(expected), budget) != expected:
            raise CatalogStorageError("catalog_generation_conflict")
    _closed_names(directory, tuple(name for name, _ in files), budget, cleanup_failures)


def _rename_generation(source: Path, target: Path) -> None:
    """Publish a closed directory with the platform's no-replacement operation."""
    if os.name == "nt":
        os.rename(source, target)
        return
    import ctypes
    import sys

    api = ctypes.CDLL(None, use_errno=True)
    result: int
    if sys.platform.startswith("linux") and hasattr(api, "renameat2"):
        function = api.renameat2
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(-100, os.fsencode(source), -100, os.fsencode(target), 1)
    elif sys.platform == "darwin" and hasattr(api, "renamex_np"):
        function = api.renamex_np
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(os.fsencode(source), os.fsencode(target), 4)
    else:
        raise CatalogStorageError("catalog_storage_unsupported")
    if result:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


def _native_files(
    sources: object, budget: NativeBudget
) -> tuple[FrameworkManifestEntry, tuple[tuple[str, bytes], ...], dict[str, Any]]:
    from evidentia_core.catalogs.open_corpora import _restore_catalog_capture, derive_native_catalog

    if type(sources) is not dict or any(
        type(key) is not str or type(value) is not bytes for key, value in sources.items()
    ):
        raise NativeSourceError()
    captured = dict(sources)
    if (
        set(captured) != {"Grundschutz++-resolved_catalog.json", "LICENSE", "README.md"}
        or sum(map(len, captured.values())) > 8_388_608
    ):
        raise NativeSourceError()
    # Only this operation's newly derived immutable bytes use the captured view.
    snapshot = derive_native_catalog(_BSI_PROFILE, captured)
    data = _restore_catalog_capture(snapshot.wire)
    try:
        native = data["native_source"]["data"]
        rows = []
        for document, filename in zip(native["documents"], _BSI_FILES[:3], strict=True):
            binding = document["binding"]
            rows.append(
                {
                    "binding": binding,
                    "storage": {
                        "kind": "file",
                        "path": filename,
                        "stored_bytes": binding["raw_bytes"],
                        "stored_sha256": binding["raw_sha256"],
                    },
                }
            )
        index = ExternalIndex.model_validate(
            {
                "schema_version": "catalog-source-index-v1",
                "profile": _BSI_PROFILE,
                "catalog_id": _BSI_ID,
                "converter_id": "evidentia-open-corpora-v1",
                "converter_sha256": native["converter_sha256"],
                "sources": rows,
            }
        )
        index_bytes = index.model_dump_json().encode("utf-8") + b"\n"
        if len(index_bytes) > 65_536:
            raise CatalogStorageError("catalog_storage_limit_exceeded")
        entry = FrameworkManifestEntry.model_validate(
            {
                "id": _BSI_ID,
                "name": data["framework_name"],
                "version": data["version"],
                "tier": "C",
                "category": "control",
                "path": f"native/{_BSI_ID}/{snapshot.bundle_sha256}/catalog.json",
                "native_registration": {
                    "format": "evidentia.catalog-native.v1",
                    "profile": _BSI_PROFILE,
                    "bundle_sha256": snapshot.bundle_sha256,
                },
            }
        )
        result = {
            "schema_version": "catalog-native-import-result-v1",
            "catalog_id": _BSI_ID,
            "bundle_sha256": snapshot.bundle_sha256,
            "projection_sha256": snapshot.projection_sha256,
            "status": "imported",
            "control_count": 1000,
            "storage": "external",
            "source_hashes": [row["binding"]["raw_sha256"] for row in rows],
        }
        ImportResult.model_validate(result)
        budget.check()
        return (
            entry,
            (
                (_BSI_FILES[0], captured[_BSI_FILES[0]]),
                (_BSI_FILES[1], captured["LICENSE"]),
                (_BSI_FILES[2], captured["README.md"]),
                (_BSI_FILES[3], index_bytes),
                (_BSI_FILES[4], snapshot.wire + b"\n"),
            ),
            result,
        )
    finally:
        data.clear()
        captured.clear()


class CatalogManifestTransaction:
    """Single-use read-modify-publish ownership with a frozen terminal observation."""

    def __init__(self, override: Path | None = None) -> None:
        self._override = override
        self._use_guard = threading.Lock()
        self._used = False
        self._observation: CatalogPublicationObservation | None = None
        self._terminal: tuple[tuple[str, Any], ...] | None = None
        self._files: list[Path] = []
        self._directories: list[Path] = []
        self._descriptors: list[int] = []
        self._cleanup_failures: list[tuple[str, BaseException]] = []
        self._lock: _NativeLock | None = None
        self._result: dict[str, Any] | None = None
        self._result_json: bytes | None = None
        self._storage_device: int | None = None

    @property
    def observation(self) -> CatalogPublicationObservation | None:
        if self._observation is None and self._terminal is not None:
            ledger = dict(self._terminal)
            ledger["cleanup_errors"] = list(ledger["cleanup_errors"])
            self._observation = CatalogPublicationObservation.model_validate(ledger)
        return self._observation

    @property
    def result_json(self) -> bytes | None:
        """Return prepared native result bytes only after verified success."""
        if self._observation is None or self._observation.error_code is not None:
            return None
        return self._result_json

    def commit(self, intent: CatalogMutationIntent) -> Path | ImportResult:
        if type(intent) is not CatalogMutationIntent:
            raise CatalogStorageError("catalog_manifest_invalid")
        return self._commit(intent, None)

    def _replace_complete(self, manifest: FrameworkManifest) -> Path:
        result = self._commit(None, manifest)
        if not isinstance(result, Path):
            raise CatalogStorageError("catalog_storage_failed")
        return result

    def _check_local_directory(self, path: Path, budget: NativeBudget) -> None:
        budget.check()
        required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
        if any(not hasattr(os, name) for name in required):
            raise CatalogStorageError("catalog_storage_unsupported")
        flags = os.O_RDONLY
        for name in required:
            flags |= getattr(os, name)
        descriptor = os.open(path, flags)
        self._descriptors.append(descriptor)
        primary: BaseException | None = None
        try:
            budget.check()
            opened = os.fstat(descriptor)
            budget.check()
            observed = path.lstat()
            budget.check()
            if (
                not stat.S_ISDIR(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
                or os.get_inheritable(descriptor)
                or (self._storage_device is not None and opened.st_dev != self._storage_device)
            ):
                raise CatalogStorageError("catalog_storage_unsupported")
            if sys.platform == "darwin":
                native_os: Any = os
                if not hasattr(os, "ST_LOCAL") or not callable(getattr(os, "fstatvfs", None)):
                    raise CatalogStorageError("catalog_storage_unsupported")
                budget.check()
                local_flags = native_os.fstatvfs(descriptor).f_flag
                budget.check()
                if not local_flags & os.ST_LOCAL:
                    raise CatalogStorageError("catalog_storage_unsupported")
            else:
                _linux_filesystem_type(descriptor, budget)
            self._storage_device = opened.st_dev
        except BaseException as error:
            primary = error
            raise
        finally:
            self._descriptors.remove(descriptor)
            try:
                os.close(descriptor)
            except BaseException as cleanup:
                self._cleanup_failures.append(("handle_close_failed", cleanup))
                if primary is not None:
                    raise primary from cleanup
                raise

    def _storage_directory(self, path: Path, budget: NativeBudget, *, create: bool = False) -> Path:
        budget.check()
        if sys.platform not in ("linux", "darwin"):
            if os.name == "nt":
                _windows_local_drive(path, budget)
            result = _directory(path, create=create, budget=budget)
            budget.check()
            return result
        if ".." in path.parts or str(path).startswith(("\\\\", "//")):
            raise CatalogStorageError("catalog_storage_unsupported")
        absolute = path.absolute()
        existing = absolute
        missing: list[Path] = []
        while True:
            budget.check()
            try:
                existing.lstat()
            except FileNotFoundError:
                if not create or existing == existing.parent:
                    raise
                missing.append(existing)
                existing = existing.parent
            else:
                break
        _directory(existing, budget=budget)
        self._check_local_directory(existing, budget)
        for part in reversed(missing):
            budget.check()
            with suppress(FileExistsError):
                part.mkdir()
            budget.check()
            _directory(part, budget=budget)
            self._check_local_directory(part, budget)
        budget.check()
        return absolute

    def _write(self, path: Path, raw: bytes, budget: NativeBudget) -> None:
        budget.check()
        self._storage_directory(path.parent, budget)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags, 0o600)
        self._descriptors.append(descriptor)
        self._files.append(path)
        budget.check()
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or os.get_inheritable(descriptor)
            or (self._storage_device is not None and opened.st_dev != self._storage_device)
        ):
            raise CatalogStorageError("catalog_storage_unsupported")
        offset = 0
        while offset < len(raw):
            budget.check()
            written = os.write(descriptor, raw[offset : offset + 65_536])
            if type(written) is not int or written <= 0:
                raise CatalogStorageError("catalog_storage_failed")
            offset += written
            budget.check()
        os.fsync(descriptor)
        budget.check()
        self._descriptors.remove(descriptor)
        try:
            os.close(descriptor)
        except BaseException as error:
            self._cleanup_failures.append(("handle_close_failed", error))
            raise
        budget.check()

    def _stage(self, directory: Path, files: tuple[tuple[str, bytes], ...], budget: NativeBudget) -> Path:
        budget.check()
        self._storage_directory(directory, budget)
        stage = directory / (".catalog-stage-" + uuid.uuid4().hex)
        budget.check()
        stage.mkdir(mode=0o700)
        self._directories.append(stage)
        for name, raw in files:
            self._write(stage / name, raw, budget)
        _same_generation(stage, files, budget, self._cleanup_failures)
        return stage

    def _finish_generation(
        self, stage: Path, target: Path, files: tuple[tuple[str, bytes], ...], budget: NativeBudget
    ) -> None:
        budget.check()
        self._storage_directory(target.parent, budget, create=True)
        try:
            target.lstat()
        except FileNotFoundError:
            pass
        else:
            self._storage_directory(target, budget)
        budget.check()
        try:
            _rename_generation(stage, target)
        except FileExistsError:
            _same_generation(target, files, budget, self._cleanup_failures)
            return
        self._directories.remove(stage)
        self._files[:] = [path for path in self._files if path.parent != stage]
        budget.check()
        _same_generation(target, files, budget, self._cleanup_failures)

    def _cleanup(self, budget: NativeBudget) -> None:
        # Mandatory release never visits a new path, even after clock expiry.
        for descriptor in self._descriptors:
            try:
                os.close(descriptor)
            except BaseException as error:
                self._cleanup_failures.append(("handle_close_failed", error))
        self._descriptors.clear()
        for path in (*reversed(self._files), *reversed(self._directories)):
            try:
                budget.check(publication=True)
                if path in self._directories:
                    path.rmdir()
                else:
                    path.unlink(missing_ok=True)
                budget.check(publication=True)
            except BaseException as error:
                self._cleanup_failures.append(("temporary_cleanup_failed", error))
        self._files.clear()
        self._directories.clear()
        if self._lock is not None:
            self._cleanup_failures.extend(self._lock.close())

    def _commit(
        self, intent: CatalogMutationIntent | None, replacement: FrameworkManifest | None
    ) -> Path | ImportResult:
        with self._use_guard:
            if self._used:
                raise CatalogStorageError("catalog_transaction_conflict")
            self._used = True
        if intent is not None:
            intent = CatalogMutationIntent(
                **{name: object.__getattribute__(intent, name) for name in CatalogMutationIntent.__dataclass_fields__}
            )
        operation = intent.operation if intent is not None else "compatibility_replace"
        ledger: dict[str, Any] = {
            "schema_version": "catalog-publication-observation-v1",
            "operation": operation,
            "publication_state": "not_attempted",
            "prior_manifest_state": "unread",
            "prior_sha256": None,
            "proposed_sha256": None,
            "replace_outcome": "not_called",
            "observed_manifest_state": "not_observed",
            "observed_sha256": None,
            "readback_result": "not_attempted",
            "cleanup_state": "not_started",
            "cleanup_errors": [],
            "failure_phase": None,
            "primary_kind": "none",
            "error_code": None,
        }
        primary: BaseException | None = None
        phase = "admission"
        output = Path()
        prepared_result: ImportResult | None = None
        prepared_observation: CatalogPublicationObservation | None = None
        prepared_terminal: tuple[tuple[str, Any], ...] | None = None
        try:
            with native_operation() as budget:
                try:
                    budget.check()
                    entry, files = self._prepare(intent, replacement, budget)
                    replacement_bytes = _manifest_bytes(replacement, budget) if replacement is not None else None
                    phase = "preparation"
                    directory = self._storage_directory(_configured_user_dir(self._override), budget, create=True)
                    output = directory / USER_MANIFEST_FILENAME
                    stage = self._stage(directory, files, budget) if files else None
                    if intent is not None and intent.operation == "legacy_import":
                        from evidentia_core.catalogs.loader import load_any_catalog

                        if stage is None:
                            raise CatalogStorageError("catalog_storage_failed")
                        load_any_catalog(intent.framework_id, stage / "catalog.json")
                        budget.check()
                    phase = "lock"
                    self._lock = _NativeLock(directory, budget)
                    self._lock.acquire(budget)
                    phase = "manifest_read"
                    prior = _bounded_read(output, _MANIFEST_LIMIT, budget, absent=True)
                    ledger["prior_manifest_state"] = "absent" if prior is None else "present"
                    ledger["prior_sha256"] = None if prior is None else hashlib.sha256(prior).hexdigest()
                    current = _parse_manifest(prior, budget)
                    proposed = self._next_manifest(current, intent, replacement_bytes, entry, budget)
                    ledger["proposed_sha256"] = hashlib.sha256(proposed).hexdigest()
                    # Validate the fixed success values before any publication.
                    success = dict(ledger)
                    success.update(
                        publication_state="unchanged" if proposed == prior else "committed",
                        replace_outcome="not_called" if proposed == prior else "returned",
                        observed_manifest_state="present",
                        observed_sha256=ledger["proposed_sha256"],
                        readback_result="matches_proposed",
                        cleanup_state="complete",
                    )
                    prepared_observation = CatalogPublicationObservation.model_validate(success)
                    success["cleanup_errors"] = tuple(success["cleanup_errors"])
                    prepared_terminal = tuple(success.items())
                    if self._result is not None:
                        prepared_result = ImportResult.model_validate(self._result)
                        self._result_json = prepared_result.model_dump_json().encode("utf-8")
                    budget.check()
                    # This is the only transition into the existing ten-second reserve.
                    with budget.publication():
                        phase = "generation"
                        if stage is not None and entry is not None:
                            target = directory / entry.path
                            self._finish_generation(stage, target.parent, files, budget)
                            output_result = target
                        else:
                            output_result = output
                        if proposed == prior:
                            ledger.update(
                                publication_state="unchanged",
                                observed_manifest_state="present",
                                observed_sha256=ledger["prior_sha256"],
                                readback_result="matches_proposed",
                            )
                        else:
                            phase = "manifest_stage"
                            temporary = directory / (".frameworks-" + uuid.uuid4().hex + ".yaml")
                            self._write(temporary, proposed, budget)
                            _check_parents(self._lock.parents, budget)
                            self._storage_directory(directory, budget)
                            budget.check()
                            phase = "replace"
                            ledger["replace_outcome"] = "raised"
                            try:
                                os.replace(temporary, output)
                            except BaseException as error:
                                primary = error
                                ledger["failure_phase"] = phase
                            else:
                                ledger["replace_outcome"] = "returned"
                                ledger["publication_state"] = "committed"
                                self._files.remove(temporary)
                            phase = "readback"
                            self._readback(output, prior, proposed, ledger, budget, primary)
                            if primary is not None:
                                raise primary
                        budget.check()
                    output = output_result
                except BaseException as error:
                    primary = error if primary is None else primary
                    if ledger["failure_phase"] is None:
                        ledger["failure_phase"] = phase
                finally:
                    self._cleanup(budget)
                    ledger["cleanup_errors"] = list(dict.fromkeys(code for code, _ in self._cleanup_failures))
                    ledger["cleanup_state"] = "failed" if self._cleanup_failures else "complete"
                    if primary is None and self._cleanup_failures:
                        primary = self._cleanup_failures[0][1]
                        ledger["failure_phase"] = "cleanup"
                    try:
                        budget.check(publication=True)
                    except BaseException as error:
                        if primary is None:
                            primary = error
                            ledger["failure_phase"] = "cleanup"
        except BaseException as error:
            if primary is None:
                primary = error
                ledger["failure_phase"] = phase
        if primary is not None:
            ledger["primary_kind"] = "exception" if isinstance(primary, Exception) else "base_exception"
            ledger["error_code"] = self._error_code(primary, ledger)
        ledger["cleanup_errors"] = tuple(ledger["cleanup_errors"])
        self._terminal = tuple(ledger.items())
        self._cleanup_failures.clear()
        if primary is not None:
            self._result_json = None
            raise primary
        # The observed terminal facts must match the prevalidated success value.
        if prepared_observation is None or self._terminal != prepared_terminal:
            self._result_json = None
            raise CatalogStorageError("catalog_publication_indeterminate")
        self._observation = prepared_observation
        if prepared_result is not None:
            return prepared_result
        return output

    def _prepare(
        self, intent: CatalogMutationIntent | None, replacement: FrameworkManifest | None, budget: NativeBudget
    ) -> tuple[FrameworkManifestEntry | None, tuple[tuple[str, bytes], ...]]:
        if intent is None:
            if type(replacement) is not FrameworkManifest:
                raise CatalogStorageError("catalog_manifest_invalid")
            return None, ()
        if (
            intent.operation not in ("native_import", "legacy_import", "remove")
            or type(intent.framework_id) is not str
            or not intent.framework_id
            or type(intent.force) is not bool
            or (
                intent.expected_entry_sha256 is not None
                and (
                    type(intent.expected_entry_sha256) is not str
                    or len(intent.expected_entry_sha256) != 64
                    or any(c not in "0123456789abcdef" for c in intent.expected_entry_sha256)
                )
            )
        ):
            raise CatalogStorageError("catalog_manifest_invalid")
        if intent.operation == "remove":
            if (
                intent.entry is not None
                or intent.catalog_bytes is not None
                or intent.sources is not None
                or intent.force
            ):
                raise CatalogStorageError("catalog_manifest_invalid")
            return None, ()
        if intent.operation == "native_import":
            if (
                intent.framework_id != _BSI_ID
                or intent.entry is not None
                or intent.catalog_bytes is not None
                or intent.force
                or intent.expected_entry_sha256 is not None
            ):
                raise NativeSourceError()
            entry, files, self._result = _native_files(intent.sources, budget)
            return entry, files
        if (
            type(intent.entry) is not FrameworkManifestEntry
            or type(intent.catalog_bytes) is not bytes
            or intent.sources is not None
            or intent.expected_entry_sha256 is not None
        ):
            raise CatalogStorageError("catalog_manifest_invalid")
        raw = intent.catalog_bytes
        if len(raw) > _CATALOG_LIMIT:
            raise CatalogStorageError("catalog_storage_limit_exceeded")
        values = FrameworkManifestEntry.model_dump(intent.entry, mode="json", exclude_none=True)
        entry = FrameworkManifestEntry.model_validate(values)
        if entry.native_registration is not None or entry.id != intent.framework_id:
            raise CatalogStorageError("catalog_manifest_invalid")
        values["path"] = "legacy/" + hashlib.sha256(raw).hexdigest() + "/catalog.json"
        return FrameworkManifestEntry.model_validate(values), (("catalog.json", raw),)

    def _next_manifest(
        self,
        current: FrameworkManifest,
        intent: CatalogMutationIntent | None,
        replacement: bytes | None,
        entry: FrameworkManifestEntry | None,
        budget: NativeBudget,
    ) -> bytes:
        if intent is None:
            if replacement is None:
                raise CatalogStorageError("catalog_manifest_invalid")
            return replacement
        previous = current.get(intent.framework_id)
        if intent.expected_entry_sha256 is not None and (
            previous is None or catalog_entry_sha256(previous) != intent.expected_entry_sha256
        ):
            raise CatalogStorageError("catalog_transaction_conflict")
        if intent.operation == "remove":
            if previous is None:
                raise ValueError("Framework is not registered in the user catalog directory")
            entries = [item for item in current.frameworks if item.id != intent.framework_id]
        else:
            if entry is None:
                raise CatalogStorageError("catalog_manifest_invalid")
            if previous is not None:
                if intent.operation == "legacy_import" and not intent.force:
                    raise ValueError("Framework is already registered; use force to replace it")
                if intent.operation == "native_import":
                    if previous.native_registration != entry.native_registration or previous.path != entry.path:
                        raise CatalogStorageError("catalog_generation_conflict")
                    # Preserve the already registered complete entry, including operator metadata.
                    entry = previous
                    if self._result is None:
                        raise CatalogStorageError("catalog_storage_failed")
                    self._result["status"] = "already_present"
            entries = [entry if item.id == intent.framework_id else item for item in current.frameworks]
            if previous is None:
                entries.append(entry)
        return _manifest_bytes(FrameworkManifest(version=current.version, frameworks=entries), budget)

    def _readback(
        self,
        output: Path,
        prior: bytes | None,
        proposed: bytes,
        ledger: dict[str, Any],
        budget: NativeBudget,
        primary: BaseException | None,
    ) -> None:
        try:
            budget.check(publication=True)
            observed = _bounded_read(output, _MANIFEST_LIMIT, budget, absent=True)
            ledger["observed_manifest_state"] = "absent" if observed is None else "present"
            ledger["observed_sha256"] = None if observed is None else hashlib.sha256(observed).hexdigest()
            ledger["readback_result"] = (
                "matches_proposed" if observed == proposed else "matches_prior" if observed == prior else "other"
            )
            if ledger["replace_outcome"] == "raised":
                ledger["publication_state"] = (
                    "committed" if observed == proposed else "not_committed" if observed == prior else "indeterminate"
                )
            if observed != proposed and primary is None:
                raise CatalogStorageError("catalog_generation_conflict")
        except BaseException:
            if ledger["observed_manifest_state"] == "not_observed":
                ledger["readback_result"] = "unavailable"
            if ledger["replace_outcome"] == "raised" and ledger["publication_state"] == "not_attempted":
                ledger["publication_state"] = "indeterminate"
            raise

    @staticmethod
    def _error_code(primary: BaseException, ledger: dict[str, Any]) -> str:
        if not isinstance(primary, Exception):
            return "catalog_interrupted"
        if ledger["replace_outcome"] == "raised":
            return (
                "catalog_publication_indeterminate"
                if ledger["publication_state"] == "indeterminate"
                else "catalog_publication_failed"
            )
        if isinstance(primary, NativeSourceError) and primary.code == "processing_deadline_exceeded":
            return primary.code
        if ledger["failure_phase"] == "cleanup":
            return "catalog_cleanup_failed"
        if isinstance(primary, CatalogStorageError):
            return primary.code
        if ledger["failure_phase"] == "manifest_read":
            return "catalog_manifest_invalid"
        return "catalog_storage_failed"


def get_user_catalog_dir(override: Path | None = None) -> Path:
    """Resolve the user catalog directory.

    Precedence:
    1. Explicit ``override`` argument (CLI flag)
    2. ``EVIDENTIA_CATALOG_DIR`` environment variable
    3. Platform default from ``platformdirs.user_data_dir``
    """
    if override is not None:
        return Path(override).expanduser().resolve()
    env = os.environ.get(CATALOG_DIR_ENV_VAR)
    if env:
        return Path(env).expanduser().resolve()
    # "evidentia" = app name, "Evidentia" = app author
    return Path(user_data_dir("evidentia", "Evidentia")) / "catalogs"


def ensure_user_dir(override: Path | None = None) -> Path:
    """Get the user catalog directory, creating it if it doesn't exist."""
    path = get_user_catalog_dir(override)
    path.mkdir(parents=True, exist_ok=True)
    return path


def user_manifest_path(override: Path | None = None) -> Path:
    """Path to the user-dir ``frameworks.yaml`` (may not yet exist)."""
    return get_user_catalog_dir(override) / USER_MANIFEST_FILENAME


def load_user_manifest(override: Path | None = None) -> FrameworkManifest:
    """Load the user-dir manifest, or return an empty one if it doesn't exist.

    A missing manifest is not an error — most users won't have imported
    anything yet. Returns a manifest with empty ``frameworks`` list.
    """
    with native_operation() as budget:
        try:
            directory = _directory(_configured_user_dir(override), budget=budget)
        except FileNotFoundError:
            return FrameworkManifest(version=1, frameworks=[])
        return _parse_manifest(
            _bounded_read(directory / USER_MANIFEST_FILENAME, _MANIFEST_LIMIT, budget, absent=True), budget
        )


def save_user_manifest(manifest: FrameworkManifest, override: Path | None = None) -> Path:
    """Atomically replace the complete manifest; callers must avoid stale read-modify-write."""
    transaction = CatalogManifestTransaction(override)
    return transaction._replace_complete(manifest)


def load_registered_native_catalog(
    framework_id: str,
    *,
    bundle_sha256: str | None = None,
    user_dir_override: Path | None = None,
) -> ControlCatalog | None:
    """Read one explicitly registered external generation under its original clock."""
    from evidentia_core.catalogs.loader import _load_catalog_data, load_native_wire_catalog
    from evidentia_core.catalogs.open_corpora import _compact, catalog_model_data, converter_sha256, source_manifest

    if type(framework_id) is not str or not framework_id:
        raise NativeSourceError()
    if bundle_sha256 is not None and (
        type(bundle_sha256) is not str
        or len(bundle_sha256) != 64
        or any(c not in "0123456789abcdef" for c in bundle_sha256)
    ):
        raise NativeSourceError()
    with native_operation() as budget:
        try:
            try:
                user_directory = _directory(_configured_user_dir(user_dir_override), budget=budget)
            except FileNotFoundError:
                return None
            manifest = _parse_manifest(
                _bounded_read(user_directory / USER_MANIFEST_FILENAME, _MANIFEST_LIMIT, budget, absent=True), budget
            )
            entry = manifest.get(framework_id)
            if entry is None or entry.native_registration is None:
                return None
            registration = entry.native_registration
            if bundle_sha256 is not None and bundle_sha256 != registration.bundle_sha256:
                raise NativeSourceError("catalog_generation_changed")
            directory = user_directory / "native" / _BSI_ID / registration.bundle_sha256
            _closed_names(directory, _BSI_FILES, budget)
            index_bytes = _bounded_read(directory / "source-index.json", 65_536, budget)
            if index_bytes is None:
                raise NativeSourceError()
            parsed = _load_catalog_data(None, raw_bytes=index_bytes, mode="wire_json")
            index = ExternalIndex.model_validate(parsed.data)
            if index.model_dump_json().encode("utf-8") + b"\n" != index_bytes:
                raise NativeSourceError()
            expected_converter = converter_sha256()
            if index.converter_sha256 != expected_converter:
                raise NativeSourceError("catalog_generation_changed")
            expected_sources = next(
                row["sources"] for row in source_manifest()["profiles"] if row["profile"] == _BSI_PROFILE
            )
            raw_sources: list[bytes] = []
            total = 0
            for row, expected, filename in zip(index.sources, expected_sources, _BSI_FILES[:3], strict=True):
                binding, storage = row.binding, row.storage
                if (
                    storage.path != filename
                    or storage.stored_bytes != expected["raw_bytes"]
                    or storage.stored_sha256 != expected["raw_sha256"]
                    or binding.raw_bytes != storage.stored_bytes
                    or binding.raw_sha256 != storage.stored_sha256
                    or binding.repository != expected["repository"]
                    or binding.commit != expected["commit"]
                    or binding.upstream_path != expected["upstream_path"]
                ):
                    raise NativeSourceError()
                raw = _bounded_read(directory / filename, storage.stored_bytes, budget)
                if (
                    raw is None
                    or len(raw) != storage.stored_bytes
                    or hashlib.sha256(raw).hexdigest() != storage.stored_sha256
                ):
                    raise NativeSourceError()
                total += len(raw)
                if total > 8_388_608:
                    raise NativeSourceError()
                raw_sources.append(raw)
            catalog = load_native_wire_catalog(directory / "catalog.json")
            bundle = catalog.native_source
            if (
                bundle is None
                or bundle.bundle_sha256 != registration.bundle_sha256
                or bundle.data.profile != _BSI_PROFILE
                or bundle.data.converter_sha256 != expected_converter
            ):
                raise NativeSourceError("catalog_generation_changed")
            for document, row, raw in zip(bundle.data.documents, index.sources, raw_sources, strict=True):
                if document.binding != row.binding or document.raw_utf8.encode("utf-8") != raw:
                    raise NativeSourceError()
            # The explicit F1 loader has just reconstructed this operation-owned
            # model from the pinned sources. Compare its deterministic spelling
            # before returning or caching any model; caller models never enter here.
            captured_model = catalog_model_data(catalog)
            try:
                expected_wire = _compact(captured_model, budget) + b"\n"
                if _bounded_read(directory / "catalog.json", _CATALOG_LIMIT, budget) != expected_wire:
                    raise NativeSourceError()
            finally:
                captured_model.clear()
            _closed_names(directory, _BSI_FILES, budget)
            if converter_sha256() != expected_converter:
                raise NativeSourceError("catalog_generation_changed")
            budget.check()
            return catalog
        except CatalogStorageError as error:
            raise NativeSourceError() from error
        except OSError as error:
            raise NativeSourceError("native_source_unavailable") from error
        except ValueError as error:
            if isinstance(error, NativeSourceError):
                raise
            budget.check()
            raise NativeSourceError() from error


def resolve_catalog_path(
    framework_id: str,
    bundled_manifest: FrameworkManifest,
    user_manifest: FrameworkManifest | None = None,
    user_dir_override: Path | None = None,
    bundled_data_dir: Path | None = None,
) -> tuple[Path, FrameworkManifestEntry, str]:
    """Resolve a framework ID to a catalog path, respecting user-dir precedence.

    Returns ``(path, entry, source)`` where ``source`` is ``"user"`` or
    ``"bundled"``. Raises ``ValueError`` if the framework isn't found in
    either manifest.
    """
    # User manifest wins if the framework is declared there
    if user_manifest is None:
        user_manifest = load_user_manifest(user_dir_override)
    user_entry = user_manifest.get(framework_id)
    if user_entry is not None:
        user_dir = get_user_catalog_dir(user_dir_override)
        path = user_dir / user_entry.path
        # Defense-in-depth path containment (CWE-22): a user-manifest path must
        # resolve INSIDE the user catalog dir. The API import endpoint only ever
        # writes a validated ``{framework_id}.json`` (no separators, no ``..``),
        # but a hand-edited manifest could carry an escaping path — assert
        # containment so a traversal can never reach the file loader.
        #
        # Resolve ONCE and RETURN the resolved, containment-checked path (not the
        # raw join). Returning the value the ``is_relative_to`` guard actually
        # checked is what lets CodeQL's built-in ``py/path-injection`` barrier
        # recognize the guard — previously the check ran on ``path.resolve()``
        # but the *unchecked* ``path`` was returned, so the loader's
        # ``read_text`` was flagged (alert #164). The returned value is the
        # containment-checked path; CodeQL's py/path-injection does not
        # recognize the guard (it ignores the MaD barrier model), so the
        # finding is a dismissed false positive.
        resolved = path.resolve()
        if not resolved.is_relative_to(user_dir.resolve()):
            raise ValueError(
                f"User catalog path for {framework_id!r} escapes the user catalog directory; refusing to load."
            )
        # %r (repr) escapes control chars in user-controlled framework_id
        # + path — closes CodeQL py/log-injection alert #81 (CWE-117)
        # per v0.7.8 P0.5 S2. framework_id comes from CLI/API arg;
        # path derives from user_entry which is loaded from user-supplied
        # manifest YAML.
        logger.info(
            "Framework %r resolved from user dir (%r) — shadows bundled catalog"
            if bundled_manifest.get(framework_id)
            else "Framework %r resolved from user dir (%r)",
            framework_id,
            resolved,
        )
        return resolved, user_entry, "user"

    # Fall back to bundled
    bundled_entry = bundled_manifest.get(framework_id)
    if bundled_entry is None:
        all_ids = sorted({fw.id for fw in bundled_manifest.frameworks} | {fw.id for fw in user_manifest.frameworks})
        raise ValueError(f"Unknown framework '{framework_id}'. Available: {', '.join(all_ids)}")

    if bundled_data_dir is None:
        from evidentia_core.catalogs.loader import DATA_DIR

        bundled_data_dir = DATA_DIR
    # Resolve the bundled path too so resolve_catalog_path uniformly returns a
    # resolved absolute path. Bundled entries come from the trusted package
    # manifest (not user input), but returning a single sanitized shape keeps
    # the choke-point's output consistent for both branches + the QL sanitizer.
    return (bundled_data_dir / bundled_entry.path).resolve(), bundled_entry, "bundled"
