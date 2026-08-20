"""Unit tests for the RFC 8594 deprecation-header helper (v0.12.0).

`docs/deprecation-calendar.md` § How removals are sequenced requires
every announced REST deprecation to carry a machine-readable
`Deprecation: true` header. These tests pin the header-construction
rules independently of any router that uses them.

Reference: RFC 8594, "The Deprecation HTTP Header Field" — §2 the
`Deprecation` header, §3 the `Sunset` header, §4 the
`successor-version` link relation.
"""

from __future__ import annotations

from datetime import date

import pytest
from evidentia_api.deprecation import deprecation_headers


def test_deprecation_header_is_always_present() -> None:
    """RFC 8594 §2 — the bare signal needs no other metadata."""
    headers = deprecation_headers()
    assert headers["Deprecation"] == "true"


def test_no_link_header_without_a_successor() -> None:
    """A `Link` with nothing to point at would be noise."""
    headers = deprecation_headers()
    assert "Link" not in headers


def test_successor_is_advertised_as_a_link_relation() -> None:
    """RFC 8594 §4 — `rel="successor-version"` names the replacement."""
    headers = deprecation_headers(successor="/api/thing/v2")
    assert headers["Link"] == '</api/thing/v2>; rel="successor-version"'


def test_no_sunset_header_without_a_date() -> None:
    """`Sunset` (RFC 8594 §3 → RFC 8594bis/RFC 8594 §3) states a DATE.

    Evidentia's calendar commits to a removal *release*, not a
    calendar date. Emitting a guessed timestamp would be a false
    machine-readable promise, so the header is omitted entirely
    until a real date is committed.
    """
    headers = deprecation_headers(successor="/api/thing/v2")
    assert "Sunset" not in headers


def test_sunset_is_an_imf_fixdate_when_a_date_is_committed() -> None:
    """RFC 8594 §3 requires the HTTP-date (IMF-fixdate) production."""
    headers = deprecation_headers(sunset=date(2027, 1, 15))
    assert headers["Sunset"] == "Fri, 15 Jan 2027 00:00:00 GMT"


def test_headers_are_a_fresh_mapping_per_call() -> None:
    """Callers mutate the result (merging into exception headers)."""
    first = deprecation_headers(successor="/api/thing/v2")
    first["X-Scratch"] = "mutated"
    second = deprecation_headers(successor="/api/thing/v2")
    assert "X-Scratch" not in second


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_successor_is_rejected(blank: str) -> None:
    """A blank successor is a caller bug, not an empty advertisement."""
    with pytest.raises(ValueError):
        deprecation_headers(successor=blank)
