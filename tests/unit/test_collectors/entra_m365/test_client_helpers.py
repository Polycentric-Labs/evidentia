"""Synthetic URL and HTTP stream boundary cases."""

import gzip
from datetime import UTC, datetime

import httpx
import pytest
from evidentia_collectors.entra_m365 import _client as client

from ._transport_support import Stream

URL = "https://graph.microsoft.com/v1.0/security/incidents"


@pytest.mark.parametrize(
    "url",
    [
        "http://graph.microsoft.com/v1.0/security/incidents",
        "https://graph.microsoft.com.evil.example/v1.0/security/incidents",
        "https://graph.microsoft.com:444/v1.0/security/incidents",
        "https://user@graph.microsoft.com/v1.0/security/incidents",
        URL + "#",
        URL + "#fragment",
        URL + "/../incidents",
        URL.replace("/security/", "/security%2f"),
        URL.replace("v1.0", "beta"),
        URL.replace("incidents", "alerts_v2"),
        URL + "?%24expand=anything",
        URL + "?$EXPAND=anything",
        URL + "?%2524expand=anything",
        URL + "?x=1&%78=2",
        URL + "?x=bad%2",
        URL + "?=value",
        URL + "?x=raw space",
        URL + "?x=\\anything",
        URL + "?x=\nanything",
        URL + "?x=" + "a" * 16400,
    ],
)
def test_refused_destination(url):
    validate = client.validate_destination
    with pytest.raises(ValueError, match="unsafe_destination"):
        validate("defender-incidents", url)


def test_opaque_query_bytes_and_default_port():
    validate = client.validate_destination
    query = "?$skiptoken=OPAQUE%2f%2F+a%20b%26$expand%3Dyes&future_paging.key=opaque"
    for base in [URL, URL.replace(".com/", ".com:443/")]:
        result = validate("defender-incidents", base + query)
        assert result.raw_path == (b"/v1.0/security/incidents" + query.encode())


def body(chunks, encoding=None, limit=64):
    read = client.read_bounded_body
    stream = Stream(chunks)
    response = httpx.Response(200, headers={} if encoding is None else {"Content-Encoding": encoding}, stream=stream)
    counts = []
    try:
        return (
            read(response, consume=lambda raw, decoded: counts.append((raw, decoded)), max_bytes=limit),
            stream,
            counts,
        )
    except Exception:
        assert stream.closed == 1
        raise


@pytest.mark.parametrize("encoding", [None, "identity", "gzip", "GZIP"])
def test_valid_encodings_and_accounting(encoding):
    raw = b"x" * 64
    encoded = gzip.compress(raw, mtime=0) if encoding and encoding.lower() == "gzip" else raw
    data, stream, counts = body([encoded], encoding)
    assert data == raw and stream.closed == 1
    assert sum(r for r, d in counts) == len(encoded) and sum(d for r, d in counts) == 64


@pytest.mark.parametrize("encoding", ["br", "gzip, gzip", "identity, gzip", "deflate"])
def test_encoding_refused(encoding):
    with pytest.raises(ValueError, match="invalid_envelope"):
        body([b"{}"], encoding)


@pytest.mark.parametrize("kind", ["overflow", "truncated", "trailing", "concatenated", "bad_crc"])
def test_invalid_gzip(kind):
    encoded = gzip.compress(b"x" * (65 if kind == "overflow" else 32), mtime=0)
    if kind == "truncated":
        encoded = encoded[:-4]
    if kind == "trailing":
        encoded += b"extra"
    if kind == "concatenated":
        encoded += gzip.compress(b"extra", mtime=0)
    if kind == "bad_crc":
        encoded = encoded[:-8] + bytes([encoded[-8] ^ 1]) + encoded[-7:]
    with pytest.raises(ValueError, match="response_limit" if kind == "overflow" else "invalid_envelope"):
        body([encoded], "gzip")


def test_partitioned_gzip_and_identity_overflow():
    encoded = gzip.compress(b"x" * 64, mtime=0)
    assert body([bytes([item]) for item in encoded], "gzip")[0] == b"x" * 64
    with pytest.raises(ValueError, match="response_limit"):
        body([b"x" * 65])


def test_budget_refusal_before_advancing_stream():
    read = client.read_bounded_body
    stream = Stream([b"x", b"y"])
    response = httpx.Response(200, stream=stream)

    def consume(raw, decoded):
        if stream.reads == 1 and raw == decoded == 0:
            raise ValueError("capability_budget")

    with pytest.raises(ValueError, match="capability_budget"):
        read(response, consume=consume)
    assert stream.reads == 1 and stream.closed == 1


@pytest.mark.parametrize(
    "header,expected",
    [
        (None, 1),
        ("0", 0),
        ("10", 10),
        ("0001", 1),
        ("Sun, 06 Nov 1994 08:49:37 GMT", 5),
        ("Sunday, 06-Nov-94 08:49:37 GMT", 5),
        ("Sun Nov  6 08:49:37 1994", 5),
        ("Sun, 06 Nov 1994 08:49:30 GMT", 0),
    ],
)
def test_retry_delay(header, expected):
    delay = client.retry_delay
    assert delay(header, attempt=1, now=datetime(1994, 11, 6, 8, 49, 32, tzinfo=UTC), remaining=20) == expected


@pytest.mark.parametrize(
    "header,code",
    [
        ("11", "retry_after_budget"),
        ("-1", "retry_after_invalid"),
        ("0.5", "retry_after_invalid"),
        ("", "retry_after_invalid"),
        ("NaN", "retry_after_invalid"),
        ("1, 2", "retry_after_invalid"),
        ("Sun, 06 Nov 1994 08:49:37 PST", "retry_after_invalid"),
    ],
)
def test_invalid_retry_delay(header, code):
    delay = client.retry_delay
    with pytest.raises(ValueError, match=code):
        delay(header, attempt=1, now=datetime(1994, 11, 6, 8, 49, 32, tzinfo=UTC), remaining=20)


def test_default_delay_and_budget():
    delay = client.retry_delay
    assert delay(None, attempt=2, now=datetime(2000, 1, 1, tzinfo=UTC), remaining=10) == 2
    with pytest.raises(ValueError, match="retry_after_budget"):
        delay("10", attempt=1, now=datetime(2000, 1, 1, tzinfo=UTC), remaining=9)
