"""Regressions for byte accounting and literal HTTP-date boundaries."""

import gzip
from datetime import UTC, datetime

import httpx
import pytest
from evidentia_collectors.entra_m365 import _client as client

from ._transport_support import Stream


@pytest.mark.parametrize("chunks", [[b"x" * 65], [b"x" * 64, b"x"], [b"x" * 4194304, b"x"]])
def test_identity_overflow_charges_every_received_byte(chunks):
    limit = 4194304 if sum(map(len, chunks)) > 65 else 64
    stream = Stream(chunks)
    response = httpx.Response(200, stream=stream)
    counts = [0, 0]

    def consume(raw, decoded):
        counts[0] += raw
        counts[1] += decoded

    with pytest.raises(ValueError, match="response_limit"):
        client.read_bounded_body(response, consume=consume, max_bytes=limit)
    assert counts == [sum(map(len, chunks))] * 2
    assert stream.closed == 1


@pytest.mark.parametrize("padding", [b"\xa0", b"\x85"])
def test_non_http_whitespace_does_not_normalize_encoding(padding):
    response = httpx.Response(
        200, headers=[(b"content-encoding", padding + b"gzip" + padding)], stream=Stream([gzip.compress(b"x")])
    )
    with pytest.raises(ValueError, match="invalid_envelope"):
        client.read_bounded_body(response, consume=lambda raw, decoded: None)
    assert response.is_closed


@pytest.mark.parametrize(
    "header",
    [
        "Thu, 01 Jan 0099 00:00:05 GMT",
        "Thu Jan  1 00:00:05 0099",
        "Sun, 01 Jan 0068 00:00:00 GMT",
        "Sun Jan  1 00:00:00 0068",
    ],
)
def test_literal_four_digit_year_stays_in_its_century(header):
    assert client.retry_delay(header, attempt=1, now=datetime(1999, 1, 1, tzinfo=UTC), remaining=10) == 0


@pytest.mark.parametrize("header", ["Sat, 01 Jan 0000 00:00:00 GMT", "Sat Jan  1 00:00:00 0000"])
def test_year_zero_is_not_remapped_to_2000(header):
    with pytest.raises(ValueError, match="retry_after_invalid"):
        client.retry_delay(header, attempt=1, now=datetime(2000, 1, 1, tzinfo=UTC), remaining=10)


def test_rfc850_pivot_includes_leap_second_calendar_rollover():
    assert (
        client.retry_delay(
            "Friday, 31-Dec-76 23:59:60 GMT",
            attempt=1,
            now=datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC),
            remaining=10,
        )
        == 0
    )
