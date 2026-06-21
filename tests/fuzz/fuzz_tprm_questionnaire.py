"""Atheris harness: TPRM completed-questionnaire ingest (JSON / CSV).

Target source entry point
-------------------------
``evidentia_core.tprm.questionnaire.parse_completed_questionnaire`` — the
extension-dispatched parser for a vendor's *completed* due-diligence
questionnaire (DDQ). ``.json`` -> ``_parse_completed_json`` (``json.loads``
+ shape checks); ``.csv`` -> ``_parse_completed_csv`` (``csv.reader`` over
the flat sentinel-header format). The ``.xlsx`` branch is a thin wrapper
over ``openpyxl.load_workbook`` and is intentionally NOT fuzzed here —
it is a different (binary) input format and the parse logic lives in
openpyxl, not Evidentia (per the "one format per harness" rule).

This is an untrusted-input surface: ``evidentia tprm`` ingests a
questionnaire returned by a third-party vendor.

Strategy
--------
A leading mode byte picks ``.json`` or ``.csv``; the remaining bytes are
written to a temp file with that extension and parsed via the public
dispatcher (and the matching sub-parser directly, for tighter coverage).

Declared/expected exceptions (caught): ``ValueError`` (bad extension /
malformed JSON shape), ``json.JSONDecodeError``, ``csv.Error``,
``UnicodeDecodeError``, ``KeyError`` / ``TypeError`` from row navigation,
``pydantic.ValidationError`` from ``CompletedQuestionnaire`` construction.
Anything else is a finding.
"""

from __future__ import annotations

import csv
import json
import os
import sys
import tempfile
from pathlib import Path

import atheris
from _harness_util import to_text
from pydantic import ValidationError

with atheris.instrument_imports():
    from evidentia_core.tprm.questionnaire import (
        _parse_completed_csv,
        _parse_completed_json,
        parse_completed_questionnaire,
    )

_EXTS = ((".json", _parse_completed_json), (".csv", _parse_completed_csv))
_EXPECTED = (
    ValueError,
    json.JSONDecodeError,
    csv.Error,
    UnicodeDecodeError,
    KeyError,
    TypeError,
    ValidationError,
)


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    fdp = atheris.FuzzedDataProvider(data)
    ext, sub_parser = _EXTS[fdp.ConsumeIntInRange(0, len(_EXTS) - 1)]
    body = to_text(fdp.ConsumeBytes(fdp.remaining_bytes()))

    fd, path_str = tempfile.mkstemp(suffix=ext)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        path = Path(path_str)
        try:
            parse_completed_questionnaire(path)
        except _EXPECTED:
            pass
        try:
            sub_parser(path)
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
