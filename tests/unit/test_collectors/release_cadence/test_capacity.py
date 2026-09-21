"""Reachable selected-source and complete poll capacity with real deadlines."""

from __future__ import annotations

import json
import time

import pytest
from evidentia_collectors.release_cadence import _traversal, collector

from ._helpers import encoded, pages, request, row
from .test_http import link


def _compact(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sized_row(identifier, size):
    value = row(identifier, name="")
    remaining = size - len(_compact(value))
    # Escape-sensitive native scalars are retained exactly, without normalization.
    pattern = '\x00"\\\U0001f642'
    cost = len(_compact(pattern)) - 2
    value["name"] = pattern * (remaining // cost) + "a" * (remaining % cost)
    assert len(_compact(value)) == size
    return value


@pytest.mark.parametrize("excess", [0, 1])
def test_capacity_selected_row_exact_and_one_over(monkeypatch, excess, record_property):
    source = sized_row(1, 16_384 + excess)
    pages(monkeypatch, _traversal, [(encoded([source]), ())])
    started = time.monotonic()
    wire = collector.poll_release_bytes(request())
    elapsed = time.monotonic() - started
    value = json.loads(wire)
    if excess:
        assert value["terminal_reason"] == "selected_limit" and value["rows"] == []
    else:
        assert value["collection_state"] == "complete"
        assert value["rows"][0]["selected"] == source
        assert value["counters"]["selected_ccompact_bytes_admitted"] == 16_384
    assert elapsed < 60
    record_property("capacity_seconds", elapsed)


@pytest.mark.parametrize("excess", [0, 1])
def test_capacity_thousand_rows_selected_8mib_and_one_over(monkeypatch, excess, record_property):
    total = 8_388_608 + excess
    sources = [sized_row(i + 1, total // 1000 + (i < total % 1000)) for i in range(1000)]
    assert sum(len(_compact(value)) for value in sources) == total
    entries = [
        (encoded(sources[i : i + 100]), (link(str(i // 100 + 2)),) if i < 900 else ()) for i in range(0, 1000, 100)
    ]
    calls = pages(monkeypatch, _traversal, entries)
    started = time.monotonic()
    wire = collector.poll_release_bytes(request())
    elapsed = time.monotonic() - started
    value = json.loads(wire)
    assert len(calls) == 10 and len(value["pages"]) == 10
    if excess:
        assert value["terminal_reason"] == "selected_limit" and len(value["rows"]) == 900
    else:
        assert value["collection_state"] == "complete" and len(value["rows"]) == 1000
        assert value["counters"]["selected_ccompact_bytes_admitted"] == 8_388_608
        assert [record["selected"] for record in value["rows"]] == sources
    assert len(wire) <= 14_637_101 and elapsed < 60
    record_property("capacity_seconds", elapsed)
    record_property("wire_bytes", len(wire))
    record_property("rows_admitted", len(value["rows"]))


@pytest.mark.parametrize("gzip_mode", [False, True])
def test_capacity_shared_raw_and_decoded_run_totals(monkeypatch, gzip_mode, record_property):
    import gzip

    from evidentia_collectors.release_cadence import _http
    from evidentia_core.release_cadence._limits import ReleaseFailure, start_budget

    from .test_http import Stream, install

    payload = b" " * 4194304
    page_wire = gzip.compress(payload, mtime=0) if gzip_mode else payload
    headers = [(b"content-type", b"application/json")]
    if gzip_mode:
        headers.append((b"content-encoding", b"gzip"))
    totals = _http.EntityTotals()
    budget = start_budget()
    started = time.monotonic()
    expected_raw = 0
    for number in range(1, 6):
        current = (gzip.compress(b"x", mtime=0) if gzip_mode else b"x") if number == 5 else page_wire
        stream = Stream([current[pos : pos + 65536] for pos in range(0, len(current), 65536)])
        install(monkeypatch, stream, headers)
        attempt = _http.HttpAttempt()
        expected_raw += len(current)
        if number == 5:
            with pytest.raises(ReleaseFailure) as found:
                attempt.fetch("example", "synthetic", number, budget=budget, totals=totals)
            assert found.value.reason == ("decoded_limit" if gzip_mode else "raw_limit")
            assert not attempt.body_complete
        else:
            assert attempt.fetch("example", "synthetic", number, budget=budget, totals=totals) == payload
            assert attempt.body_complete
        assert totals.raw == expected_raw
        assert totals.decoded == min(number, 4) * 4194304 + (number == 5)
        assert stream.closed == 1
    elapsed = time.monotonic() - started
    assert elapsed < 60
    record_property("capacity_seconds", elapsed)
    record_property("raw_observed", totals.raw)
    record_property("decoded_observed", totals.decoded)


@pytest.mark.parametrize("boundary", ["occurrences", "depth"])
@pytest.mark.parametrize("excess", [0, 1])
def test_capacity_ignored_source_structure_is_charged(monkeypatch, boundary, excess, record_property):
    source = row()
    if boundary == "occurrences":
        # Root list + source object + every key/value + ignored key/list + leaves.
        existing = 2 + len(source) * 2 + 2
        source["ignored"] = [0] * (131072 + excess - existing)
    else:
        ignored = 0
        for _ in range(61 + excess):
            ignored = [ignored]
        source["ignored"] = ignored
    pages(monkeypatch, _traversal, [(encoded([source]), ())])
    started = time.monotonic()
    wire = collector.poll_release_bytes(request())
    elapsed = time.monotonic() - started
    value = json.loads(wire)
    assert elapsed < 60
    record_property("capacity_seconds", elapsed)
    if excess:
        assert value["collection_state"] == "unavailable" and value["rows"] == []
        assert value["terminal_reason"] == ("json_count" if boundary == "occurrences" else "json_depth")
    else:
        assert value["collection_state"] == "complete" and len(value["rows"]) == 1
        assert "ignored" not in value["rows"][0]["selected"]
        key = "json_value_key_occurrences" if boundary == "occurrences" else "json_depth_observed"
        assert value["pages"][0][key] == (131072 if boundary == "occurrences" else 64)
