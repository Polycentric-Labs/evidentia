"""Atheris harness: gap-analysis report loader.

Target source entry point
-------------------------
``evidentia_core.models.gap.GapAnalysisReport.model_validate_json`` — the
pure-parse core invoked by ``evidentia_core.gap_store.load_report_by_key``
/ ``load_latest_report`` when a previously-saved gap report is read back
from the gap store (``report.read_text(...)`` -> ``model_validate_json``).

This is an untrusted-input surface: a gap report JSON file on disk is
reloaded; a tampered or corrupted store file flows straight into Pydantic
deserialization.

Strategy
--------
Feed the fuzz bytes as the JSON string. Pydantic v2's
``model_validate_json`` raises ``pydantic.ValidationError`` for BOTH
JSON-syntax errors and schema violations, so a single catch covers the
declared failure modes. The gap-store wrapper additionally enforces a
hex report-key + path-traversal guard before reaching this call; those
are covered by their own unit tests and are not re-fuzzed here (this
harness targets the deserialization core).

Declared/expected exceptions (caught): ``pydantic.ValidationError``,
``ValueError`` (defensive — some custom validators raise plain
``ValueError`` which Pydantic re-wraps, but a direct raise is possible).
Anything else is a finding.
"""

from __future__ import annotations

import sys

import atheris
from _harness_util import to_text
from pydantic import ValidationError

with atheris.instrument_imports():
    from evidentia_core.models.gap import GapAnalysisReport

_EXPECTED = (ValidationError, ValueError)


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    raw = to_text(data)
    try:
        GapAnalysisReport.model_validate_json(raw)
    except _EXPECTED:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
