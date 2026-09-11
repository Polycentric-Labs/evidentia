"""Authored in-memory response controls; no provider or network access."""

from __future__ import annotations

import gzip
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from evidentia_collectors.enterprise_retention import _client as a
from evidentia_collectors.retention import _client as frozen

LIMIT = 1048576
NOW = datetime(2026, 9, 10, 12, 0, 0, tzinfo=UTC)


class Chunks(httpx.SyncByteStream):
    def __init__(self, *parts: bytes) -> None:
        self.parts = parts
        self.yielded = 0
        self.closed = 0
        self.failure: BaseException | None = None
        self.close_failure: BaseException | None = None

    def __iter__(self) -> Iterator[bytes]:
        for part in self.parts:
            self.yielded += 1
            yield part
        if self.failure is not None:
            raise self.failure

    def close(self) -> None:
        self.closed += 1
        if self.close_failure is not None:
            raise self.close_failure


def response(stream: Chunks, headers: Any = None) -> httpx.Response:
    return httpx.Response(200, headers=headers, stream=stream)


def test_identity_exact_limit_preserves_checkpoint_and_both_counts() -> None:
    stream = Chunks(b"a" * (LIMIT // 2), b"b" * (LIMIT // 2))
    selected = response(stream)
    counts: list[tuple[int, int]] = []
    try:
        result = a.read_enterprise_body(selected, consume=lambda raw, decoded: counts.append((raw, decoded)))
        assert result == b"a" * (LIMIT // 2) + b"b" * (LIMIT // 2)
        assert counts == [(0, 0), (LIMIT // 2, LIMIT // 2), (0, 0), (LIMIT // 2, LIMIT // 2), (0, 0), (0, 0)]
        assert selected.is_closed
    finally:
        selected.close()
    assert stream.closed == 1


def test_duplicate_encoding_is_refused_before_body_or_consumer() -> None:
    stream = Chunks(b"synthetic")
    selected = response(stream, [("Content-Encoding", "identity"), ("content-encoding", "identity")])
    counts: list[tuple[int, int]] = []
    try:
        with pytest.raises(a.BodyRetryError, match=r"^invalid_encoding$"):
            a.read_enterprise_body(selected, consume=lambda raw, decoded: counts.append((raw, decoded)))
        assert stream.yielded == 0 and (not selected.is_closed)
        assert counts == []
    finally:
        selected.close()
    assert stream.closed == 1


def test_gzip_result_and_separate_raw_decoded_counts() -> None:
    expected = b"synthetic" * 1000
    encoded = gzip.compress(expected, mtime=0)
    stream = Chunks(encoded[:11], encoded[11:])
    selected = response(stream, {"Content-Encoding": "gzip"})
    counts: list[tuple[int, int]] = []
    try:
        assert a.read_enterprise_body(selected, consume=lambda raw, decoded: counts.append((raw, decoded))) == expected
        assert sum((raw for raw, decoded in counts)) == len(encoded)
        assert sum((decoded for raw, decoded in counts)) == len(expected)
    finally:
        selected.close()
    assert stream.closed == 1


def test_consume_clientfault_is_propagated_without_adapter_rewriting() -> None:
    primary = frozen.ClientFault("invalid_response")
    stream = Chunks(b"{}")
    selected = response(stream)

    def consume(raw: int, decoded: int) -> None:
        raise primary

    try:
        with pytest.raises(frozen.ClientFault) as result:
            a.read_enterprise_body(selected, consume=consume)
        assert result.value is primary
        assert not selected.is_closed and stream.yielded == 0
    finally:
        selected.close()


def test_retry_server_delay_above_ten_is_invalid_even_with_time_remaining() -> None:
    selected = httpx.Response(503, headers={"Retry-After": "11"})
    with pytest.raises(a.BodyRetryError, match=r"^retry_after_invalid$"):
        a.enterprise_retry_delay(selected, attempt=1, now=NOW, remaining=100.0)


def test_missing_retry_header_keeps_second_default_delay() -> None:
    assert a.enterprise_retry_delay(httpx.Response(503), attempt=2, now=NOW, remaining=20.0) == 2.0


@pytest.mark.parametrize("headers", [None, {"Content-Encoding": "identity"}, {"Content-Encoding": " IDENTITY\t"}])
def test_identity_header_forms_preserve_bytes(headers: Any) -> None:
    stream = Chunks(b"\x00\xff{}", b"")
    selected = response(stream, headers)
    try:
        assert a.read_enterprise_body(selected, consume=lambda raw, decoded: None) == b"\x00\xff{}"
    finally:
        selected.close()


@pytest.mark.parametrize(
    "value",
    ["gzip, identity", "identity,gzip", "gzip,gzip", "", "br", "deflate", "x-gzip", "identity\n", "gzip;level=1"],
)
def test_invalid_encoding_never_iterates_stream(value: str) -> None:
    stream = Chunks(b"synthetic")
    selected = response(stream, {"Content-Encoding": value})
    try:
        with pytest.raises(a.BodyRetryError, match=r"^invalid_encoding$"):
            a.read_enterprise_body(selected, consume=lambda raw, decoded: pytest.fail("unexpected checkpoint"))
        assert stream.yielded == 0 and stream.closed == 0
    finally:
        selected.close()


@pytest.mark.parametrize(
    "headers",
    [
        [("Content-Encoding", "gzip"), ("Content-Encoding", "gzip")],
        [("Content-Encoding", "gzip"), ("CONTENT-ENCODING", "identity")],
        [("Content-Encoding", "identity"), ("Content-Encoding", "")],
    ],
)
def test_encoding_multiplicity_cannot_be_normalized_away(headers: Any) -> None:
    selected = response(Chunks(b"{}"), headers)
    try:
        with pytest.raises(a.BodyRetryError, match=r"^invalid_encoding$"):
            a.read_enterprise_body(selected, consume=lambda raw, decoded: None)
    finally:
        selected.close()


@pytest.mark.parametrize("parts", [(b"x" * (LIMIT + 37),), (b"x" * LIMIT, b"y" * 37)])
def test_identity_refused_chunk_is_charged_in_full_before_response_limit(parts: tuple[bytes, ...]) -> None:
    stream = Chunks(*parts)
    selected = response(stream)
    counts: list[tuple[int, int]] = []
    try:
        with pytest.raises(a.BodyRetryError, match=r"^response_limit$"):
            a.read_enterprise_body(selected, consume=lambda raw, decoded: counts.append((raw, decoded)))
        assert sum((raw for raw, decoded in counts)) == LIMIT + 37
        assert sum((decoded for raw, decoded in counts)) == LIMIT + 37
        assert stream.closed == 0
    finally:
        selected.close()
    assert stream.closed == 1


@pytest.mark.parametrize("expected", [b"", b"x" * LIMIT], ids=["empty", "decoded-exact-limit"])
def test_gzip_decoded_exact_limit_and_empty_member(expected: bytes) -> None:
    encoded = gzip.compress(expected, mtime=0)
    stream = Chunks(encoded)
    selected = response(stream, {"Content-Encoding": "\tGZIP "})
    counts: list[tuple[int, int]] = []
    try:
        assert a.read_enterprise_body(selected, consume=lambda raw, decoded: counts.append((raw, decoded))) == expected
        assert sum((raw for raw, decoded in counts)) == len(encoded)
        assert sum((decoded for raw, decoded in counts)) == len(expected)
        assert stream.closed == 1
    finally:
        selected.close()


def stored_gzip(payload: bytes) -> bytes:
    import struct
    import zlib

    pieces = [payload[i : i + 65535] for i in range(0, len(payload), 65535)] or [b""]
    data = bytearray(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff")
    for index, piece in enumerate(pieces):
        data.append(1 if index == len(pieces) - 1 else 0)
        data.extend(struct.pack("<HH", len(piece), len(piece) ^ 65535))
        data.extend(piece)
    data.extend(struct.pack("<II", zlib.crc32(payload), len(payload) & 4294967295))
    return bytes(data)


@pytest.mark.parametrize("overshoot", [0, 1])
def test_gzip_raw_exact_boundary_is_independent_of_decoded_size(overshoot: int) -> None:
    expected = b"x" * (LIMIT - 98 + overshoot)
    encoded = stored_gzip(expected)
    assert len(encoded) == LIMIT + overshoot
    stream = Chunks(encoded)
    selected = response(stream, {"Content-Encoding": "gzip"})
    counts: list[tuple[int, int]] = []
    try:
        if overshoot:
            with pytest.raises(a.BodyRetryError, match=r"^response_limit$"):
                a.read_enterprise_body(selected, consume=lambda raw, decoded: counts.append((raw, decoded)))
            assert sum((decoded for raw, decoded in counts)) == 0
        else:
            assert (
                a.read_enterprise_body(selected, consume=lambda raw, decoded: counts.append((raw, decoded))) == expected
            )
            assert sum((decoded for raw, decoded in counts)) == len(expected)
        assert sum((raw for raw, decoded in counts)) == len(encoded)
    finally:
        selected.close()


def test_gzip_expansion_charges_produced_plus_one_without_unbounded_decode() -> None:
    encoded = gzip.compress(b"x" * (LIMIT * 8), mtime=0)
    selected = response(Chunks(encoded), {"Content-Encoding": "gzip"})
    counts: list[tuple[int, int]] = []
    try:
        with pytest.raises(a.BodyRetryError, match=r"^response_limit$"):
            a.read_enterprise_body(selected, consume=lambda raw, decoded: counts.append((raw, decoded)))
        assert sum((raw for raw, decoded in counts)) == len(encoded)
        assert sum((decoded for raw, decoded in counts)) == LIMIT + 1
        assert max((decoded for raw, decoded in counts)) <= 65536
    finally:
        selected.close()


@pytest.mark.parametrize("split_tail", [True, False])
@pytest.mark.parametrize("tail", [b"\x00", b"trailing", gzip.compress(b"second", mtime=0), gzip.compress(b"", mtime=0)])
def test_gzip_trailing_and_concatenated_members_rejected_after_full_raw_charge(split_tail: bool, tail: bytes) -> None:
    encoded = gzip.compress(b"first", mtime=0)
    parts = (encoded, tail) if split_tail else (encoded + tail,)
    stream = Chunks(*parts)
    selected = response(stream, {"Content-Encoding": "gzip"})
    counts: list[tuple[int, int]] = []
    try:
        with pytest.raises(a.BodyRetryError, match=r"^invalid_encoding$"):
            a.read_enterprise_body(selected, consume=lambda raw, decoded: counts.append((raw, decoded)))
        assert sum((raw for raw, decoded in counts)) == len(encoded) + len(tail)
        assert sum((decoded for raw, decoded in counts)) == len(b"first")
        assert not selected.is_closed
    finally:
        selected.close()


@pytest.mark.parametrize("length", [0, 1, 10, -1, -8])
def test_gzip_truncation_is_invalid_and_httpx_eof_close_is_retained(length: int) -> None:
    encoded = gzip.compress(b"synthetic", mtime=0)[:length]
    stream = Chunks(encoded)
    selected = response(stream, {"Content-Encoding": "gzip"})
    try:
        with pytest.raises(a.BodyRetryError, match=r"^invalid_encoding$"):
            a.read_enterprise_body(selected, consume=lambda raw, decoded: None)
        assert selected.is_closed and stream.closed == 1
    finally:
        selected.close()
    assert stream.closed == 1


@pytest.mark.parametrize("encoded", [b"not-gzip", b"\x1f\x8b\x00", gzip.compress(b"synthetic", mtime=0)[:-1] + b"\xff"])
def test_gzip_format_or_footer_corruption_has_fixed_encoding_error(encoded: bytes) -> None:
    selected = response(Chunks(encoded), {"Content-Encoding": "gzip"})
    try:
        with pytest.raises(a.BodyRetryError, match=r"^invalid_encoding$") as result:
            a.read_enterprise_body(selected, consume=lambda raw, decoded: None)
        assert result.value.args == ("invalid_encoding",)
        assert result.value.__suppress_context__
    finally:
        selected.close()


@pytest.mark.parametrize("phase", ["checkpoint", "raw", "decoded"])
@pytest.mark.parametrize("code", ["invalid_response", "response_limit", "run_budget_exhausted"])
def test_consumer_native_fault_identity_and_completed_accounting_are_retained(phase: str, code: str) -> None:
    primary = frozen.ClientFault(code)
    payload = b"synthetic"
    encoded = gzip.compress(payload, mtime=0)
    stream = Chunks(encoded)
    selected = response(stream, {"Content-Encoding": "gzip"})
    counts: list[tuple[int, int]] = []

    def consume(raw: int, decoded: int) -> None:
        counts.append((raw, decoded))
        if (
            (phase == "checkpoint" and raw == decoded == 0)
            or (phase == "raw" and raw)
            or (phase == "decoded" and decoded)
        ):
            raise primary

    try:
        with pytest.raises(frozen.ClientFault) as result:
            a.read_enterprise_body(selected, consume=consume)
        assert result.value is primary
        assert stream.closed == 0
        if phase == "checkpoint":
            assert stream.yielded == 0
        if phase == "raw":
            assert sum((raw for raw, decoded in counts)) == len(encoded)
        if phase == "decoded":
            assert sum((decoded for raw, decoded in counts)) == len(payload)
    finally:
        selected.close()


@pytest.mark.parametrize(
    "primary",
    [RuntimeError("synthetic-consumer"), KeyboardInterrupt("synthetic-cancel"), httpx.ReadError("synthetic-read")],
)
def test_other_consumer_exceptions_propagate_without_conversion(primary: BaseException) -> None:
    stream = Chunks(b"{}")
    selected = response(stream)

    def consume(raw: int, decoded: int) -> None:
        raise primary

    try:
        with pytest.raises(type(primary)) as result:
            a.read_enterprise_body(selected, consume=consume)
        assert result.value is primary
        assert not selected.is_closed
    finally:
        selected.close()


@pytest.mark.parametrize(
    "primary",
    [
        frozen.ClientFault("invalid_response"),
        frozen.ClientFault("response_limit"),
        httpx.ReadTimeout("synthetic-timeout"),
        httpx.ReadError("synthetic-read"),
        KeyboardInterrupt("synthetic-cancel"),
    ],
)
def test_stream_fault_identity_is_not_mistaken_for_helper_origin(primary: BaseException) -> None:
    stream = Chunks(b"{}")
    stream.failure = primary
    selected = response(stream)
    counts: list[tuple[int, int]] = []
    try:
        with pytest.raises(type(primary)) as result:
            a.read_enterprise_body(selected, consume=lambda raw, decoded: counts.append((raw, decoded)))
        assert result.value is primary
        assert counts == [(0, 0), (2, 2), (0, 0)]
        assert stream.closed == 0
    finally:
        selected.close()


def test_httpx_eof_close_failure_is_not_rewritten() -> None:
    primary = frozen.ClientFault("invalid_response")
    stream = Chunks(b"{}")
    stream.close_failure = primary
    selected = response(stream)
    with pytest.raises(frozen.ClientFault) as result:
        a.read_enterprise_body(selected, consume=lambda raw, decoded: None)
    assert result.value is primary
    assert selected.is_closed and stream.closed == 1
    selected.close()
    assert stream.closed == 1


def test_inherited_default_bound_and_empty_checkpoints_are_exact() -> None:
    import inspect

    assert a.RESPONSE_MAX_BYTES == frozen.RESPONSE_MAX_BYTES == LIMIT
    assert inspect.signature(frozen.read_bounded_body).parameters["max_bytes"].default == LIMIT
    selected = response(Chunks())
    calls: list[tuple[int, int]] = []
    try:
        assert a.read_enterprise_body(selected, consume=lambda raw, decoded: calls.append((raw, decoded))) == b""
        assert calls == [(0, 0), (0, 0)]
    finally:
        selected.close()


@pytest.mark.parametrize(
    "header,expected",
    [
        (None, 1.0),
        ("0", 0.0),
        ("1", 1.0),
        ("2", 2.0),
        ("10", 10.0),
        ("000000000000000000010", 10.0),
        (" \t2\t ", 2.0),
        ("0" * 126 + "10", 10.0),
        (" " * 127 + "1", 1.0),
        ("Thu, 10 Sep 2026 12:00:05 GMT", 5.0),
        ("Thursday, 10-Sep-26 12:00:05 GMT", 5.0),
        ("Thu Sep 10 12:00:05 2026", 5.0),
        ("Thu, 10 Sep 2026 11:59:59 GMT", 0.0),
        ("Thu, 10 Sep 2026 12:00:10 GMT", 10.0),
    ],
)
def test_retry_numeric_and_three_fixed_date_forms(header: str | None, expected: float) -> None:
    stream = Chunks(b"not-consumed")
    headers = {} if header is None else {"Retry-After": header}
    selected = response(stream, headers)
    original = list(selected.headers.raw)
    try:
        assert a.enterprise_retry_delay(selected, attempt=1, now=NOW, remaining=20.0) == expected
        assert selected.headers.raw == original
        assert stream.yielded == stream.closed == 0
    finally:
        selected.close()


@pytest.mark.parametrize(
    "header",
    [
        "",
        " ",
        "\t",
        "11",
        "30",
        "31",
        "999",
        "0" * 129,
        " " * 128 + "1",
        "+1",
        "-1",
        "1.0",
        "1e0",
        "NaN",
        "inf",
        "1,2",
        "1\r",
        "1\n",
        "1\x00",
        b"\xff",
        "Thu, 10 Sep 2026 12:00:11 GMT",
        "Thu, 10 Sep 2026 12:00:05 UTC",
        "Thu, 10 Sep 2026 12:00:05 +0000",
        "Thu, 10 Sep 2026 12:00:05 gmt",
        "Thu, 10 XXX 2026 12:00:05 GMT",
        "Thu, 31 Feb 2026 12:00:05 GMT",
        "Thu, 10 Sep 2026 24:00:05 GMT",
        "Thu, 10 Sep 2026 12:00:61 GMT",
        "Thu, 10 Sep 10000 12:00:05 GMT",
        "Thu, 10 Sep 2026 12:00:05 GMT, Thu, 10 Sep 2026 12:00:06 GMT",
    ],
)
def test_invalid_or_over_ten_retry_values_are_fixed_refusals(header: Any) -> None:
    selected = httpx.Response(503, headers=[("Retry-After", header)])
    with pytest.raises(a.BodyRetryError, match=r"^retry_after_invalid$") as result:
        a.enterprise_retry_delay(selected, attempt=1, now=NOW, remaining=100.0)
    assert result.value.args == ("retry_after_invalid",)


@pytest.mark.parametrize("values", [("1", "1"), ("1", "2"), ("", "1"), ("Thu, 10 Sep 2026 12:00:05 GMT", "5")])
def test_duplicate_retry_after_is_refused_even_when_identical(values: tuple[str, str]) -> None:
    selected = httpx.Response(503, headers=[("Retry-After", values[0]), ("RETRY-AFTER", values[1])])
    with pytest.raises(a.BodyRetryError, match=r"^retry_after_invalid$"):
        a.enterprise_retry_delay(selected, attempt=1, now=NOW, remaining=20.0)


@pytest.mark.parametrize(
    "header,attempt,remaining",
    [("10", 1, 9.999999), ("1", 1, 0.5), (None, 1, 0.999), (None, 2, 1.999), ("0", 1, 0.0), ("0", 1, -1.0)],
)
def test_valid_delay_without_sufficient_remaining_budget_is_deadline_exceeded(
    header: str | None, attempt: int, remaining: float
) -> None:
    selected = httpx.Response(503, headers={} if header is None else {"Retry-After": header})
    with pytest.raises(a.BodyRetryError, match=r"^deadline_exceeded$"):
        a.enterprise_retry_delay(selected, attempt=attempt, now=NOW, remaining=remaining)


@pytest.mark.parametrize("header,remaining,expected", [("10", 10.0, 10.0), ("1", 1.0, 1.0), ("0", 1e-05, 0.0)])
def test_exact_remaining_boundary_does_not_shorten_server_delay(header: str, remaining: float, expected: float) -> None:
    assert (
        a.enterprise_retry_delay(
            httpx.Response(503, headers={"Retry-After": header}), attempt=1, now=NOW, remaining=remaining
        )
        == expected
    )


def test_over_limit_server_delay_is_invalid_before_remaining_budget_classification() -> None:
    with pytest.raises(a.BodyRetryError, match=r"^retry_after_invalid$"):
        a.enterprise_retry_delay(httpx.Response(503, headers={"Retry-After": "11"}), attempt=1, now=NOW, remaining=1.0)


@pytest.mark.parametrize("attempt", [0, 3, -1, True, False, 1.0, "1", None])
def test_retry_attempt_requires_exact_native_first_or_second_attempt(attempt: Any) -> None:
    with pytest.raises(a.BodyRetryError, match=r"^internal_error$"):
        a.enterprise_retry_delay(httpx.Response(503), attempt=attempt, now=NOW, remaining=20.0)


@pytest.mark.parametrize("remaining", [None, True, False, "10", float("nan"), float("inf"), float("-inf"), 10**400])
def test_retry_budget_rejects_non_native_or_nonfinite_inputs(remaining: Any) -> None:
    with pytest.raises(a.BodyRetryError, match=r"^internal_error$"):
        a.enterprise_retry_delay(httpx.Response(503), attempt=1, now=NOW, remaining=remaining)


def test_retry_aware_offset_and_fraction_remain_exact() -> None:
    from datetime import timedelta, timezone

    local_now = NOW.replace(tzinfo=timezone(timedelta(hours=1))) + timedelta(hours=1, microseconds=500000)
    selected = httpx.Response(503, headers={"Retry-After": "Thu, 10 Sep 2026 12:00:05 GMT"})
    assert a.enterprise_retry_delay(selected, attempt=1, now=local_now, remaining=20.0) == 4.5


@pytest.mark.parametrize("now", [None, NOW.replace(tzinfo=None), "2026-09-10", NOW.date()])
def test_retry_now_requires_native_aware_datetime(now: Any) -> None:
    with pytest.raises(a.BodyRetryError, match=r"^internal_error$"):
        a.enterprise_retry_delay(httpx.Response(503), attempt=1, now=now, remaining=20.0)


def test_retry_offset_underflow_and_datetime_subclass_are_fixed_native_failures() -> None:
    from datetime import timedelta, timezone

    class OtherDatetime(datetime):
        pass

    for now in (datetime.min.replace(tzinfo=timezone(timedelta(hours=1))), OtherDatetime(2026, 9, 10, tzinfo=UTC)):
        with pytest.raises(a.BodyRetryError, match=r"^internal_error$"):
            a.enterprise_retry_delay(httpx.Response(503), attempt=1, now=now, remaining=20.0)


def test_frozen_retry_helper_keeps_its_thirty_second_behavior() -> None:
    assert frozen.retry_delay("30", attempt=1, now=NOW, remaining=100.0) == 30.0
    with pytest.raises(a.BodyRetryError, match=r"^retry_after_invalid$"):
        a.enterprise_retry_delay(
            httpx.Response(503, headers={"Retry-After": "30"}), attempt=1, now=NOW, remaining=100.0
        )


@pytest.mark.parametrize("selected", [None, {}, 200, object()])
def test_response_boundary_rejects_unrelated_native_objects(selected: Any) -> None:
    with pytest.raises(a.BodyRetryError, match=r"^internal_error$"):
        a.read_enterprise_body(selected, consume=lambda raw, decoded: None)
    with pytest.raises(a.BodyRetryError, match=r"^internal_error$"):
        a.enterprise_retry_delay(selected, attempt=1, now=NOW, remaining=20.0)


class OpaqueClientFault(frozen.ClientFault):
    def __str__(self) -> str:
        raise AssertionError("native error text must not be formatted")


@pytest.mark.parametrize("origin", ["consumer", "stream", "close"])
def test_clientfault_subclass_identity_is_preserved_without_formatting(origin: str) -> None:
    primary = OpaqueClientFault("invalid_response")
    stream = Chunks(b"{}")
    selected = response(stream)
    if origin == "stream":
        stream.failure = primary
    if origin == "close":
        stream.close_failure = primary

    def consume(raw: int, decoded: int) -> None:
        if origin == "consumer":
            raise primary

    try:
        with pytest.raises(OpaqueClientFault) as result:
            a.read_enterprise_body(selected, consume=consume)
        assert result.value is primary
    finally:
        stream.close_failure = None
        selected.close()


def test_response_subclasses_are_not_the_owned_native_response_boundary() -> None:

    class OtherResponse(httpx.Response):
        pass

    selected = OtherResponse(200)
    with pytest.raises(a.BodyRetryError, match=r"^internal_error$"):
        a.read_enterprise_body(selected, consume=lambda raw, decoded: None)
    with pytest.raises(a.BodyRetryError, match=r"^internal_error$"):
        a.enterprise_retry_delay(selected, attempt=1, now=NOW, remaining=20.0)


@pytest.mark.parametrize("origin", ["stream", "close"])
def test_preexisting_helper_fault_transport_is_not_reclassified(origin: str) -> None:
    inner = response(Chunks(b"invalid-gzip"), {"Content-Encoding": "gzip"})
    try:
        with pytest.raises(frozen.ClientFault) as captured:
            frozen.read_bounded_body(inner, consume=lambda raw, decoded: None)
        primary = captured.value
    finally:
        inner.close()
    stream = Chunks(b"{}")
    if origin == "stream":
        stream.failure = primary
    else:
        stream.close_failure = primary
    selected = response(stream)
    try:
        with pytest.raises(frozen.ClientFault) as result:
            a.read_enterprise_body(selected, consume=lambda raw, decoded: None)
        assert result.value is primary
    finally:
        stream.close_failure = None
        selected.close()
