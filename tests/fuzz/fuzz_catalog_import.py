"""Atheris harness: catalog import (JSON / YAML loader).

Target source entry point
-------------------------
``evidentia_core.catalogs.loader`` — the v0.10.4 choke-point invariant
routes every catalog file read through ``_load_catalog_data``, which
dispatches on file extension (``.json`` -> ``json.loads``,
``.yaml`` / ``.yml`` -> ``yaml.safe_load``) and rejects non-mapping
roots. Downstream typed loaders (``load_oscal_catalog``,
``load_evidentia_catalog``, ``load_non_control_catalog``) build Pydantic
models from the parsed dict.

This is an untrusted-input surface: ``evidentia catalog import <file>``
ingests an operator- or third-party-supplied catalog document.

Strategy
--------
A leading mode byte selects the file extension so a single corpus
exercises the JSON branch, the YAML branch, and each downstream typed
loader. The remaining bytes are written to a temp file with that
extension and fed to the loaders by path (the public API is
path-based).

Declared/expected exceptions (caught): ``ValueError`` (bad extension /
non-mapping root), ``json.JSONDecodeError``, ``yaml.YAMLError``,
``pydantic.ValidationError``, ``KeyError`` / ``TypeError`` from
downstream dict navigation. Anything else is an unexpected crash =
a finding.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import atheris
import yaml
from _harness_util import to_text
from pydantic import ValidationError

with atheris.instrument_imports():
    from evidentia_core.catalogs.loader import (
        _load_catalog_data,
        load_evidentia_catalog,
        load_non_control_catalog,
        load_oscal_catalog,
    )

_EXTS = (".json", ".yaml", ".yml")
_EXPECTED = (
    ValueError,
    json.JSONDecodeError,
    yaml.YAMLError,
    ValidationError,
    KeyError,
    TypeError,
)


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    fdp = atheris.FuzzedDataProvider(data)
    ext = _EXTS[fdp.ConsumeIntInRange(0, len(_EXTS) - 1)]
    body = to_text(fdp.ConsumeBytes(fdp.remaining_bytes()))

    fd, path_str = tempfile.mkstemp(suffix=ext)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        path = Path(path_str)
        # Choke-point parser: extension dispatch + non-mapping rejection.
        try:
            _load_catalog_data(path)
        except _EXPECTED:
            pass
        # Downstream typed loaders build Pydantic models from the dict.
        for loader in (
            load_oscal_catalog,
            load_evidentia_catalog,
            load_non_control_catalog,
        ):
            try:
                loader(path)
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
