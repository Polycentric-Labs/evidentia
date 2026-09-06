"""Atheris harness: OSCAL verify (Assessment-Results digest check).

Target source entry point
-------------------------
``evidentia_core.oscal.verify.verify_digests(ar_doc: dict)`` — the core
of ``evidentia oscal verify``. It walks the top-level OSCAL model's
``back-matter.resources[]``, base64-decodes each embedded ``base64``
content block, re-hashes it (SHA-256), and compares to the stored
``rlinks`` digest. ``verify_ar_file`` is the file/signature wrapper;
``verify_digests`` is the pure-parse core that consumes an
already-decoded JSON dict.

This is an untrusted-input surface: an operator runs ``oscal verify`` on
a third-party-supplied signed OSCAL Assessment-Results / profile / POA&M
document.

Strategy
--------
The harness ``json.loads`` the fuzz bytes itself (the function takes a
parsed dict), keeps only ``dict`` roots, and calls ``verify_digests``.
This drives the back-matter traversal, the base64 decode (already
guarded for ``ValueError`` / ``TypeError`` in source), and the digest
comparison against arbitrary resource shapes.

Declared/expected exceptions (caught): ``json.JSONDecodeError`` /
``UnicodeDecodeError`` (harness-side parse), and ``ValueError`` /
``TypeError`` / ``KeyError`` from malformed resource shapes. Anything
else — e.g. an unhandled ``AttributeError`` from a resource that is a
string rather than a dict — is an unexpected crash = a finding.

KNOWN FINDING (WS-D Q1): this harness is EXPECTED to crash quickly on
the current source — ``verify_digests`` raises an undeclared
``AttributeError`` when ``back-matter.resources`` holds a non-dict entry
(verify.py:168). The Hypothesis complement marks the same finding xfail
(see ``test_parser_robustness.test_oscal_verify_digests_robustness``).
Once the source is hardened (guard ``isinstance(resource, dict)`` +
coerce ``resources`` to a list), this harness keeps fuzzing the deeper
digest/base64 logic.
"""

from __future__ import annotations

import json
import sys

import atheris
from _harness_util import to_text

with atheris.instrument_imports():
    from evidentia_core.oscal.verify import verify_digests


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    try:
        doc = json.loads(to_text(data))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return
    if not isinstance(doc, dict):
        return
    # verify_digests must NEVER raise on a parsed-JSON document — it returns a
    # list of DigestCheck verdicts (CWE-248 robustness invariant). We do NOT
    # swallow any exception: an uncaught raise IS the bug atheris should flag.
    # (F-V1012-2: the prior ``except (ValueError, TypeError, KeyError)`` masked
    # exactly the TypeError class that F-V1012-1 fixed.)
    verify_digests(doc)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
