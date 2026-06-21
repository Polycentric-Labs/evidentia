"""Atheris harness: OCSF JSON ingest.

Target source entry point
-------------------------
``evidentia_collectors.ocsf.collector._convert_ocsf_payload(raw, source=...)``
— the pure-parse core of ``evidentia collect ocsf --input <file-or-url>``.
It ``json.loads`` the raw OCSF document, validates the root is an object
or a list of objects, and dispatches each item by ``class_uid`` to
``evidentia_core.ocsf.finding_from_ocsf`` (Compliance Finding 2003, with
``trust_unmapped=False``) or ``finding_from_ocsf_detection`` (Detection
Finding 2004). Both re-validate via ``py_ocsf_models`` (the optional
``ocsf`` extra), so this harness requires that extra to be installed
(ClusterFuzzLite's build.sh installs it).

This is the canonical third-party untrusted-input surface — Prowler /
AWS Security Hub OCSF exports ingested from a file or HTTPS URL.

Strategy
--------
Feed the fuzz bytes as the raw JSON string directly (the function takes
``str``). ``_convert_ocsf_payload`` wraps every declared malformed-input
condition — invalid JSON, wrong root type, non-object list entries,
unsupported ``class_uid``, and any underlying ``OCSFMappingError`` /
Pydantic validation failure — into a single ``OCSFIngestError``. The
mapping path itself is also reached through the dispatcher, so the
Pydantic model_validate of the OCSF schema is fuzzed end to end.

Declared/expected exception (caught): ``OCSFIngestError``. Anything else
is an unexpected crash = a finding.
"""

from __future__ import annotations

import sys

import atheris
from _harness_util import to_text

with atheris.instrument_imports():
    from evidentia_collectors.ocsf.collector import (
        OCSFIngestError,
        _convert_ocsf_payload,
    )


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    raw = to_text(data)
    try:
        _convert_ocsf_payload(raw, source="fuzz-input")
    except OCSFIngestError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
