"""Post-v0.13.0 CodeQL close-out: category-only verify errors (CWE-209), escaped log values (CWE-117)."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from evidentia_api.routers.oscal import _public_text
from evidentia_api.routers.risks import _warn_malformed_context


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Malformed JSON: Expecting value: line 1 column 1 (char 0)", "Malformed JSON"),
        ("AR file not found: /srv/tmp/ar.json", "AR file not found"),
        ("DSSE verification failed: signature mismatch for key abc", "DSSE verification failed"),
        (
            "DSSE envelope found (/srv/tmp/ar.dsse.json) but no --verify-key supplied; "
            "key-based DSSE verification requires a pinned public key (fail-closed).",
            "DSSE envelope found",
        ),
        ("Sigstore verification rejected: identity did not match", "Sigstore verification rejected"),
        ("Signature required but none found: a.sig, b.sigstore, or c.dsse", "Signature required but none found"),
        ("Plain category", "Plain category"),
    ],
)
def test_public_text_keeps_the_category_only(message: str, expected: str) -> None:
    assert _public_text(message) == expected


def test_malformed_context_warning_escapes_control_characters(caplog: pytest.LogCaptureFixture) -> None:
    detail = "line one" + chr(10) + "WARNING forged record" + chr(13) + "tail"
    path = Path("ctx" + chr(10) + "forged.yaml")
    with caplog.at_level(logging.WARNING, logger="evidentia_api.routers.risks"):
        _warn_malformed_context(path, ValueError(detail))
    messages = [record.getMessage() for record in caplog.records]
    assert len(messages) == 1
    assert chr(10) not in messages[0]
    assert chr(13) not in messages[0]
    assert repr(detail) in messages[0]
    assert repr(str(path)) in messages[0]
