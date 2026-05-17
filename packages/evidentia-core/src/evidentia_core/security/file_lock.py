"""Cross-platform exclusive file locking (v0.9.4 P1.1).

Provides advisory file locks for use with state-file read-modify-write
cycles in long-lived daemons + concurrent CLI tools.

Closes v0.9.3 F-V93-Q3 HIGH: previously, ``conmon.daemon.mark_completed``
and ``conmon.alerting.AlertDeduper.mark_dispatched`` did non-atomic
``load → mutate → save`` on the state file. ``os.replace`` made the
final write atomic, but the read-modify cycle was not. Concurrent
invocations could clobber each other (last-writer-wins) silently.
v0.9.4 adds opt-in file-locking via this module.

Backend selection:

- POSIX (Linux/macOS): ``fcntl.flock`` with ``LOCK_EX | LOCK_NB``
- Windows: ``msvcrt.locking`` with ``LK_NBLCK``

Both backends do *advisory* locking — cooperating callers respect
the lock; rogue processes ignoring it can still write. This matches
PostgreSQL's ``pg_lock_file`` + git's ``index.lock`` conventions.

The lock file is created if missing. It is NOT removed on release
(deliberate: removing it races with the next acquirer). Operators
wanting periodic cleanup should rely on ``rm /path/*.lock`` from
their service-manager maintenance hook, OR just leave them — they're
0-byte sidecar files.

Lock-file location convention: same directory as the state file,
with a ``.lock`` suffix appended (e.g., ``state.yaml.lock``).
Callers MUST pass the lock-file path explicitly; this module does
not derive it from a state-file path so callers retain control over
where the lock lives (useful for tmpfs-backed locks in containerized
deployments).
"""

from __future__ import annotations

import contextlib
import sys
import time
from pathlib import Path
from types import TracebackType
from typing import IO


class FileLockTimeout(TimeoutError):
    """Raised when the lock cannot be acquired within the timeout window."""


class FileLock:
    """Cross-platform exclusive file-lock context manager.

    Example::

        from evidentia_core.security.file_lock import FileLock

        lock_path = state_file.with_suffix(state_file.suffix + ".lock")
        with FileLock(lock_path, timeout_seconds=5.0):
            # critical section — exactly one process inside at a time
            data = load_state(state_file)
            data[key] = value
            save_state(state_file, data)

    Args:
        path: Path to the lock file. Created if missing. Parent
            directory must exist OR be creatable (auto-mkdir on
            enter; ``OSError`` propagates if not creatable).
        timeout_seconds: Maximum time to wait for the lock. Default
            5.0s matches the operator's psychological "this isn't
            stuck" threshold for CLI tools. Raises
            :class:`FileLockTimeout` if exceeded.
        poll_interval_seconds: How frequently to retry the
            ``LOCK_NB`` attempt while waiting. Default 0.05s
            (20Hz) — fast enough that ``FileLockTimeout`` is rare
            even under heavy contention; low enough that the
            polling overhead is negligible.

    Raises (at ``__enter__``):
        FileLockTimeout: lock not acquired within ``timeout_seconds``.
        OSError: lock-file directory not creatable, or file-open
            failed for non-contention reasons.
    """

    def __init__(
        self,
        path: Path,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
    ) -> None:
        self._path = Path(path)
        self._timeout = timeout_seconds
        self._poll_interval = poll_interval_seconds
        self._fd: IO[bytes] | None = None

    def __enter__(self) -> FileLock:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Append-binary mode: don't truncate; create if missing.
        fd: IO[bytes] = self._path.open("a+b")
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                self._acquire(fd)
                self._fd = fd
                return self
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    fd.close()
                    raise FileLockTimeout(
                        f"could not acquire lock on {self._path} within "
                        f"{self._timeout}s"
                    ) from None
                time.sleep(self._poll_interval)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._fd is not None:
            try:
                self._release(self._fd)
            finally:
                self._fd.close()
                self._fd = None

    # ── platform-specific backends ────────────────────────────────

    if sys.platform == "win32":

        @staticmethod
        def _acquire(fd: IO[bytes]) -> None:
            import msvcrt

            # msvcrt.locking operates on the current file pointer +
            # the specified byte range. Lock 1 byte at offset 0; we
            # don't actually write to the lock file (operators rely
            # on the file's existence + the OS-level lock state).
            fd.seek(0)
            try:
                msvcrt.locking(fd.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                # Windows raises OSError(errno=EACCES/EDEADLK) on
                # contention; remap to BlockingIOError so the polling
                # loop in __enter__ handles it uniformly.
                raise BlockingIOError(
                    f"lock contention on {fd.name}: {exc}"
                ) from exc

        @staticmethod
        def _release(fd: IO[bytes]) -> None:
            import msvcrt

            # Unlock-of-released-lock is harmless; ignore.
            with contextlib.suppress(OSError):
                fd.seek(0)
                msvcrt.locking(fd.fileno(), msvcrt.LK_UNLCK, 1)

    else:

        @staticmethod
        def _acquire(fd: IO[bytes]) -> None:
            import fcntl

            fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

        @staticmethod
        def _release(fd: IO[bytes]) -> None:
            import fcntl

            # Best-effort release; close() also drops the lock.
            with contextlib.suppress(OSError):
                fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
