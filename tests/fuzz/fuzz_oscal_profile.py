"""Atheris harness: OSCAL profile loading / resolution.

Target source entry point
-------------------------
``evidentia_core.oscal.profile`` — ``_load_oscal_json`` parses an OSCAL
profile document (``json.load`` + top-level-object validation) and
``resolve_profile`` walks ``profile.imports`` / ``back-matter.resources``
to resolve an imported catalog and apply profile alterations.

This is an untrusted-input surface: ``evidentia catalog import`` with an
OSCAL *profile* source, and any ``oscal``-subcommand path that resolves
a profile, parses an operator-supplied profile JSON document.

Strategy
--------
The fuzz bytes are written to a temp ``.json`` file. ``_load_oscal_json``
is the pure parse + dict-root check. ``resolve_profile`` is then driven
on the same file to exercise the import/back-matter traversal; almost
all malformed inputs resolve to a declared ``ProfileResolutionError``
(missing imports, missing href, non-object root). The resolver only
reads the one supplied file plus any *fragment* (``#uuid``) back-matter
references that point back into the same document, so it does not chase
arbitrary filesystem paths from fuzz input in this harness (a
filesystem ``href`` simply yields ``FileNotFoundError`` /
``ProfileResolutionError``, both caught).

Declared/expected exceptions (caught): ``ProfileResolutionError``,
``json.JSONDecodeError``, ``FileNotFoundError``, ``ValueError``,
``KeyError``, ``TypeError``. Anything else is a finding.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import atheris
from _harness_util import to_text

with atheris.instrument_imports():
    from evidentia_core.oscal.profile import (
        ProfileResolutionError,
        _load_oscal_json,
        resolve_profile,
    )

_EXPECTED = (
    ProfileResolutionError,
    json.JSONDecodeError,
    FileNotFoundError,
    ValueError,
    KeyError,
    TypeError,
)


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    body = to_text(data)
    fd, path_str = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        path = Path(path_str)
        try:
            _load_oscal_json(path)
        except _EXPECTED:
            pass
        try:
            resolve_profile(path)
        except _EXPECTED:
            pass
    finally:
        try:
            os.unlink(path_str)
        except OSError:
            pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
