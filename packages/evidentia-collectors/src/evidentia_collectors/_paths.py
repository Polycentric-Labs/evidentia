"""Path checks shared by the file-ingest collectors."""

from __future__ import annotations

import os
from pathlib import Path

_RESERVED_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
)


def is_reserved_device_name(path: Path) -> bool:
    """True on Windows when ``path`` names a console or port device (``CON``, ``NUL``, ``COM1`` and so on).

    Opening such a name blocks on the device instead of reading a file;
    the SCAP, retention and registry importers already refuse them, and
    the scan importers do the same (v0.13.0 review, probe finding D8).
    """
    if os.name != "nt":
        return False
    stem = path.name.split(".", 1)[0].strip().upper()
    return stem in _RESERVED_DEVICE_NAMES
