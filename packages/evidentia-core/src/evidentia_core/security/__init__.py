"""Security primitives shared across the Evidentia stack.

The package collects defensive-coding helpers that protect Evidentia's
trust boundaries. As of v0.9.4 the package houses two modules:

- :mod:`paths` — path-traversal-safe filesystem helpers wrapping the
  ``pathlib`` resolution dance behind a single predicate, so call
  sites at API + CLI + collector boundaries can reject directory-
  traversal attempts uniformly.
- :mod:`file_lock` — cross-platform advisory file-locking
  (``fcntl.flock`` on POSIX, ``msvcrt.locking`` on Windows) for
  concurrent state-file read-modify-write coordination. Closes
  v0.9.3 F-V93-Q3 HIGH (race-condition on conmon state files).

Future modules in this package may include input-sanitization helpers
for other surfaces (URL hosts, regex sources, archive extraction
entries, etc.). The package import keeps the namespace small;
prefer ``from evidentia_core.security.<mod> import <name>``
over deep aliasing through this ``__init__``.
"""

from evidentia_core.security.file_lock import FileLock, FileLockTimeout
from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)

__all__ = [
    "FileLock",
    "FileLockTimeout",
    "PathTraversalError",
    "validate_within",
]
