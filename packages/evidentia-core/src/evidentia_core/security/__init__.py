"""Security primitives shared across the Evidentia stack.

The package collects defensive-coding helpers that protect Evidentia's
trust boundaries. As of v0.9.5 the package houses three modules:

- :mod:`paths` — path-traversal-safe filesystem helpers wrapping the
  ``pathlib`` resolution dance behind a single predicate, so call
  sites at API + CLI + collector boundaries can reject directory-
  traversal attempts uniformly.
- :mod:`file_lock` — cross-platform advisory file-locking
  (``fcntl.flock`` on POSIX, ``msvcrt.locking`` on Windows) for
  concurrent state-file read-modify-write coordination. Closes
  v0.9.3 F-V93-Q3 HIGH (race-condition on conmon state files).
- :mod:`atomic_write` (v0.9.5) — ``atomic_write_text`` helper that
  consolidates the ``write-tmp → os.replace → cleanup-on-OSError``
  pattern v0.9.4 applied inline at 4 call sites (daemon-status,
  conmon-state, dedup-state, idempotency-store). Future atomic-
  write sites get the cleanup behavior for free.

Future modules in this package may include input-sanitization helpers
for other surfaces (URL hosts, regex sources, archive extraction
entries, etc.). The package import keeps the namespace small;
prefer ``from evidentia_core.security.<mod> import <name>``
over deep aliasing through this ``__init__``.
"""

from evidentia_core.security.atomic_write import atomic_write_text
from evidentia_core.security.file_lock import FileLock, FileLockTimeout
from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)

__all__ = [
    "FileLock",
    "FileLockTimeout",
    "PathTraversalError",
    "atomic_write_text",
    "validate_within",
]
