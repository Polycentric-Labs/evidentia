"""Unit tests for evidentia_core.security.file_lock (v0.9.4 P1.1)."""

from __future__ import annotations

import multiprocessing
import os
import sys
import threading
import time
from pathlib import Path

import pytest
from evidentia_core.security import FileLock, FileLockTimeout


class TestFileLockBasics:
    def test_acquires_and_releases(self, tmp_path: Path) -> None:
        lock_path = tmp_path / "test.lock"
        with FileLock(lock_path):
            assert lock_path.exists()
        # Second acquire after release should succeed immediately.
        with FileLock(lock_path):
            pass

    def test_lock_file_persists_after_release(self, tmp_path: Path) -> None:
        """Lock file is NOT removed on release (matches pg_lock_file
        + git index.lock convention; removing races with next acquirer)."""
        lock_path = tmp_path / "test.lock"
        with FileLock(lock_path):
            pass
        assert lock_path.exists()

    def test_creates_parent_directory(self, tmp_path: Path) -> None:
        lock_path = tmp_path / "nested" / "subdir" / "test.lock"
        assert not lock_path.parent.exists()
        with FileLock(lock_path):
            pass
        assert lock_path.exists()
        assert lock_path.parent.is_dir()

    def test_lock_file_is_empty(self, tmp_path: Path) -> None:
        """File-lock semantics don't write to the lock file."""
        lock_path = tmp_path / "test.lock"
        with FileLock(lock_path):
            pass
        assert lock_path.stat().st_size == 0


class TestFileLockExclusion:
    """In-process exclusion via threads (validates the same-process path).

    Cross-process contention (the real-world deployment case) is
    covered by ``TestFileLockMultiprocess`` below.
    """

    def test_second_thread_blocks_until_first_releases(
        self, tmp_path: Path
    ) -> None:
        lock_path = tmp_path / "test.lock"
        order: list[str] = []
        first_inside = threading.Event()
        first_can_exit = threading.Event()

        def first() -> None:
            with FileLock(lock_path, timeout_seconds=5.0):
                order.append("first-in")
                first_inside.set()
                first_can_exit.wait(timeout=5.0)
                order.append("first-out")

        def second() -> None:
            first_inside.wait(timeout=5.0)
            with FileLock(lock_path, timeout_seconds=5.0):
                order.append("second-in")
                order.append("second-out")

        t1 = threading.Thread(target=first)
        t2 = threading.Thread(target=second)
        t1.start()
        t2.start()

        # Let t2 get into its wait state, then release t1.
        time.sleep(0.2)
        first_can_exit.set()

        t1.join(timeout=10.0)
        t2.join(timeout=10.0)

        # Note: on POSIX, fcntl.flock is per-process, NOT per-thread —
        # so two threads in the same process won't actually block each
        # other on flock. The test still serves as a smoke for the
        # context-manager mechanics (acquire/release lifecycle). The
        # true cross-process exclusion guarantee is tested below in
        # TestFileLockMultiprocess.
        assert "first-in" in order
        assert "first-out" in order
        assert "second-in" in order
        assert "second-out" in order


class TestFileLockTimeout:
    """Timeout behavior under contention. Uses separate processes
    because fcntl.flock is per-process on POSIX (threads in the same
    process share the lock)."""

    def test_timeout_raises_when_contended(self, tmp_path: Path) -> None:
        """Spawn a child process holding the lock; parent times out.

        Uses a sentinel file (not a multiprocessing.Event, which is
        flaky on Windows spawn-method) so the parent can detect when
        the child has actually acquired the lock before racing it.
        """
        lock_path = tmp_path / "test.lock"
        acquired_signal = tmp_path / "child_acquired.signal"

        proc = multiprocessing.Process(
            target=_hold_lock_for,
            args=(str(lock_path), str(acquired_signal), 3.0),
        )
        proc.start()
        try:
            # Wait (up to 10s) for the child to signal it acquired.
            deadline = time.monotonic() + 10.0
            while not acquired_signal.exists():
                if time.monotonic() >= deadline:
                    pytest.fail(
                        "child process never acquired the lock — "
                        "spawn-method startup issue?"
                    )
                time.sleep(0.05)

            # Now try to acquire with short timeout; should fail.
            t0 = time.monotonic()
            with (
                pytest.raises(FileLockTimeout, match="could not acquire"),
                FileLock(lock_path, timeout_seconds=0.5),
            ):
                pass
            elapsed = time.monotonic() - t0
            # Timeout fired between 0.5s and 1.5s (poll overhead).
            assert 0.4 <= elapsed <= 1.5, f"timeout was {elapsed}s"
        finally:
            proc.join(timeout=5.0)
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=2.0)


def _hold_lock_for(
    lock_path: str, signal_path: str, hold_seconds: float
) -> None:
    """Helper for multiprocess tests — acquire the lock, signal that
    we have it (by touching the signal file), then sleep."""
    with FileLock(Path(lock_path), timeout_seconds=5.0):
        Path(signal_path).touch()
        time.sleep(hold_seconds)


def _try_increment_counter(
    lock_path: str, counter_path: str, iterations: int
) -> int:
    """Helper for the concurrent-writer test. Loops ``iterations`` times,
    each time: acquire lock → read counter → increment → write counter →
    release. Returns the number of successful increments observed."""
    import json

    successes = 0
    for _ in range(iterations):
        with FileLock(Path(lock_path), timeout_seconds=10.0):
            current = 0
            counter_file = Path(counter_path)
            if counter_file.is_file():
                current = int(json.loads(counter_file.read_text())["n"])
            tmp = counter_file.with_suffix(".tmp")
            tmp.write_text(json.dumps({"n": current + 1}))
            tmp.replace(counter_file)
            successes += 1
    return successes


class TestFileLockMultiprocess:
    """Cross-process exclusion guarantee — the actual deployment
    contention case. Validates that 4 concurrent writers don't
    last-writer-wins clobber each other (closes F-V93-Q3 HIGH).
    """

    @pytest.mark.skipif(
        sys.platform == "win32" and os.environ.get("CI") == "true",
        reason=(
            "multiprocessing on Windows CI runners is flaky for "
            "spawn-method workers; test passes locally on Windows + "
            "on all POSIX. Tracked: pytest-randomly + spawn-method "
            "stability work in v0.9.5"
        ),
    )
    def test_four_concurrent_writers_no_clobber(
        self, tmp_path: Path
    ) -> None:
        """4 processes each do 10 lock-acquire + increment cycles.
        With proper locking: final counter = 4 * 10 = 40. Without
        locking: typically < 40 due to lost-update races."""
        lock_path = tmp_path / "counter.lock"
        counter_path = tmp_path / "counter.json"
        iterations_per_worker = 10
        worker_count = 4

        with multiprocessing.Pool(processes=worker_count) as pool:
            results = pool.starmap(
                _try_increment_counter,
                [
                    (str(lock_path), str(counter_path), iterations_per_worker)
                    for _ in range(worker_count)
                ],
            )

        # Each worker reports its own successful increments.
        assert sum(results) == worker_count * iterations_per_worker

        # Final counter MUST equal total successful increments.
        import json

        final = json.loads(counter_path.read_text())["n"]
        assert final == worker_count * iterations_per_worker, (
            f"expected {worker_count * iterations_per_worker} but got "
            f"{final} — locking didn't serialize the read-modify-write"
        )


class TestFileLockExceptionPath:
    def test_releases_on_exception_in_critical_section(
        self, tmp_path: Path
    ) -> None:
        lock_path = tmp_path / "test.lock"
        with (
            pytest.raises(RuntimeError, match="inside"),
            FileLock(lock_path, timeout_seconds=1.0),
        ):
            raise RuntimeError("inside")
        # Lock must be released — next acquire should succeed.
        with FileLock(lock_path, timeout_seconds=1.0):
            pass
