"""Atomic text-file write helper (v0.9.5 P1.5).

Closes v0.9.4 F-V94-Q3 follow-up: lifts the inline
``write-tmp → os.replace → cleanup-on-OSError`` pattern that v0.9.4
applied at 4 call sites (``write_daemon_status``, ``save_state_file``,
``AlertDeduper._save_state``, ``_save_idempotency_store``) into a
single helper so future atomic-write sites get the cleanup behavior
for free.

The pattern matters: ``Path.write_text`` is atomic only at the OS
``os.replace`` level. The naive ``path.write_text(data)`` truncates
the destination BEFORE writing the new content, so a crash during the
write leaves the file zero-length or partially-written. The
``write-to-.tmp-then-replace`` pattern is the standard fix; cleaning
up the orphaned ``.tmp`` file on the ``OSError`` exception path
(disk-full, permission-denied) avoids accumulating sidecar artifacts
over time.

Example::

    from evidentia_core.security.atomic_write import atomic_write_text

    atomic_write_text(
        path=state_file,
        data=json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

Design notes:

- The helper is **synchronous + non-locking**. Callers that need
  exclusive write coordination (e.g., conmon daemon writing the
  state file from multiple processes) MUST wrap the call in a
  :class:`evidentia_core.security.file_lock.FileLock` themselves.
  Atomicity + serialization are orthogonal concerns; the helper
  handles atomicity, ``FileLock`` handles serialization.

- The parent directory is created if missing (``mkdir(parents=True,
  exist_ok=True)``) — matches the v0.9.4 inline patterns. Callers
  that want a strict "directory must pre-exist" check should
  validate before calling.

- The ``.tmp`` suffix is fixed (``path.suffix + ".tmp"``) — the
  v0.9.4 inline patterns used the same convention. Lock-file
  scanners in operator tooling can rely on the ``.tmp`` extension
  to identify orphaned artifacts.

- The helper is **text-only** (UTF-8 by default). Binary atomic
  writes are uncommon in Evidentia's call sites; a sibling
  ``atomic_write_bytes`` can be added later if a clear need
  emerges. Keeping the surface small avoids YAGNI proliferation.
"""

from __future__ import annotations

import contextlib
from pathlib import Path


def atomic_write_text(
    path: Path,
    data: str,
    *,
    encoding: str = "utf-8",
) -> None:
    """Atomically write ``data`` to ``path``.

    Implementation:

    1. Ensure parent directory exists.
    2. Write the new content to ``{path}.tmp``.
    3. ``os.replace`` the temp file over the destination (atomic
       on the same filesystem; documented POSIX + Windows behavior).
    4. On any ``OSError`` during steps 2-3, delete the orphaned
       ``.tmp`` file (best-effort; suppresses secondary OSError
       from the cleanup itself) and re-raise the original
       exception.

    Args:
        path: Destination file path.
        data: Text content to write.
        encoding: Text encoding for the file write. Default
            ``"utf-8"`` matches every existing call site.

    Raises:
        OSError: If the write or replace fails (e.g., disk full,
            permission denied, cross-filesystem replace). The
            ``.tmp`` sidecar is cleaned up before the exception
            propagates.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(data, encoding=encoding)
        tmp.replace(path)
    except OSError:
        # Clean up orphaned .tmp on write failure so disk-full /
        # permission errors don't accumulate sidecar artifacts
        # over time.
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise
