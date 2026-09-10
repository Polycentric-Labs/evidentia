"""Synthetic acceptance of the Graph reader transport contract."""

import gzip
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import httpx
import pytest
from evidentia_collectors.entra_m365 import _contracts as contracts

from ._transport_support import (
    CA_PATH,
    DEVICE_PATH,
    NOW,
    OPAQUE,
    ORIGIN,
    PAGE_LIMIT,
    PRIMARY,
    RETENTION,
    RETENTION_PATH,
    SIGN_PATH,
    SOURCE_MARKER,
    Clock,
    Provider,
    Reply,
    Scenario,
    assert_closed,
    assert_safe,
    assert_summary,
    codes,
    encode_page,
    sign_in,
)


def test_empty_success_uses_real_request_guards_and_borrowed_lifetime(make_run, runtime):
    run = make_run([Reply()])
    assert run.provider.calls == []
    source = run.read()
    assert_summary(source, state="complete", pages=1, attempts=1, scanned=0, ids=[])
    request = run.scenario.requests[0]
    assert request.url == httpx.URL(ORIGIN + CA_PATH)
    assert request.headers["authorization"] == "Bearer " + PRIMARY
    assert request.extensions["timeout"] == {"connect": 5.0, "pool": 5.0, "read": 20.0, "write": 20.0}
    assert run.provider.calls == ["primary"]
    kinds = [kind for kind, value in runtime[0].calls]
    assert kinds.index("offline") < kinds.index("send")
    assert kinds.index("public") < kinds.index("send")
    assert kinds.count("pin_enter") == kinds.count("pin_exit") == 1
    run.reader.close()
    assert_closed(run)


def test_opaque_continuation_ignores_all_borrowed_defaults(make_run):
    continuation = ORIGIN + SIGN_PATH + "?$skiptoken=" + OPAQUE + "&future.key=next"
    run = make_run(
        [Reply(encode_page([sign_in("a")], continuation)), Reply(encode_page([sign_in("b")]))],
        capabilities=["sign-ins"],
        request_fields={"lookback_days": 1},
        defaults={
            "params": {"inherited": "forbidden"},
            "headers": {"X-Inherited": SOURCE_MARKER},
            "cookies": {"inherited": SOURCE_MARKER},
            "auth": ("synthetic-user", "synthetic-password"),
            "follow_redirects": True,
            "timeout": 999,
        },
    )
    source = run.read()
    assert_summary(source, state="complete", pages=2, attempts=2, scanned=2, ids=["a", "b"])
    first, second = run.scenario.requests
    assert list(first.url.params) == ["$filter"]
    assert first.url.params["$filter"] == (
        "createdDateTime ge 2026-09-09T00:00:00.000000Z and createdDateTime le 2026-09-10T00:00:00.000000Z"
    )
    assert second.url.raw_path == (SIGN_PATH + "?" + continuation.split("?", 1)[1]).encode()
    for request in (first, second):
        assert request.headers["authorization"] == "Bearer " + PRIMARY
        assert "x-inherited" not in request.headers
        assert "cookie" not in request.headers
        assert "inherited" not in request.url.params
    assert run.provider.calls == ["primary"]
    assert_closed(run)


@pytest.mark.parametrize("bad", [None, 0, True, [], {"id": None}, {"id": 3}])
def test_bad_record_rejects_whole_first_page(make_run, bad):
    source = make_run([Reply(encode_page([{"id": "a"}, bad]))]).read()
    assert_summary(source, state="unavailable", pages=0, attempts=1, scanned=0, ids=[])
    assert "invalid_record" in codes(source)


def test_rejected_later_page_cannot_quarantine_accepted_id(make_run):
    first = {"id": "a", "conditions": {"number": 1}}
    conflict = {"id": "a", "conditions": {"number": 1.0}}
    run = make_run(
        [
            Reply(encode_page([first], ORIGIN + CA_PATH + "?page=2")),
            Reply(encode_page([conflict, {"id": 0}])),
        ]
    )
    source = run.read()
    assert_summary(source, state="partial", pages=1, attempts=2, scanned=1, ids=["a"])
    assert source.records[0].fields["conditions"] == {"number": 1}
    assert "invalid_record" in codes(source)
    assert "conflicting_duplicate" not in codes(source)
    assert_closed(run)


def test_empty_accepted_page_then_invalid_json_is_partial(make_run):
    run = make_run([Reply(encode_page([], ORIGIN + CA_PATH + "?page=2")), Reply(b'{"value":[')])
    source = run.read()
    assert_summary(source, state="partial", pages=1, attempts=2, scanned=0, ids=[])
    assert "invalid_envelope" in codes(source)


@pytest.mark.parametrize(
    "continuation",
    [
        "",
        0,
        False,
        [],
        {},
        "https://refused.example/v1.0/identity/conditionalAccess/policies",
        ORIGIN + CA_PATH + "?%24expand=members",
        ORIGIN + DEVICE_PATH + "?page=2",
        ORIGIN + "/beta/identity/conditionalAccess/policies?page=2",
    ],
)
def test_invalid_continuation_rejects_its_page_before_next_send(make_run, continuation):
    run = make_run([Reply(encode_page([{"id": "a"}], continuation, include_next=True))])
    source = run.read()
    assert_summary(source, state="unavailable", pages=0, attempts=1, scanned=0, ids=[])
    assert codes(source) & {"continuation_invalid", "unsafe_destination"}
    assert len(run.scenario.requests) == 1
    assert_closed(run)


@pytest.mark.parametrize("continuation", ["", 0, ORIGIN + "/v1.0/directoryRoles?page=2"])
def test_roles_cannot_page_even_with_a_valid_graph_url(make_run, continuation):
    run = make_run(
        [Reply(encode_page([{"id": "role-a"}], continuation, include_next=True))],
        capabilities=["directory-roles"],
    )
    source = run.read()
    assert_summary(source, state="unavailable", pages=0, attempts=1, scanned=0, ids=[])
    assert "continuation_invalid" in codes(source)


@pytest.mark.parametrize("include_next", [False, True])
def test_missing_or_null_continuation_completes(make_run, include_next):
    run = make_run([Reply(encode_page([], include_next=include_next))])
    assert run.read().capability.state == "complete"


@pytest.mark.parametrize("length", [2, 3])
def test_repeated_and_alternating_loops_reject_closing_page(make_run, length):
    base = ORIGIN + CA_PATH
    replies = [Reply(encode_page([{"id": "a"}], base + "?page=1"))]
    if length == 3:
        replies.append(Reply(encode_page([{"id": "b"}], base + "?page=2")))
    replies.append(Reply(encode_page([{"id": "closing"}], base if length == 2 else base + "?page=1")))
    run = make_run(replies)
    source = run.read()
    assert_summary(
        source,
        state="partial",
        pages=length - 1,
        attempts=length,
        scanned=length - 1,
        ids=["a"] if length == 2 else ["a", "b"],
    )
    assert "continuation_loop" in codes(source)
    assert len(run.scenario.requests) == length


def test_cap_admission_still_checks_later_conflict(make_run):
    rows = [
        {"id": "a", "conditions": {"flag": False}},
        {"id": "new-unadmitted"},
        {"id": "a", "conditions": {"flag": 0}},
    ]
    run = make_run([Reply(encode_page(rows))], request_fields={"max_items": 1})
    source = run.read()
    assert_summary(source, state="partial", pages=1, attempts=1, scanned=3, ids=[])
    assert codes(source) == {"item_limit", "conflicting_duplicate"}
    assert source.capability.duplicate_records == 0


@pytest.mark.parametrize("continuation", [None, ORIGIN + CA_PATH + "?page=2"])
def test_exact_unique_cap_counts_duplicates_without_extra_request(make_run, continuation):
    run = make_run(
        [Reply(encode_page([{"id": "a"}, {"id": "a"}, {"id": "b"}], continuation))],
        request_fields={"max_items": 2},
    )
    source = run.read()
    assert_summary(
        source,
        state="complete" if continuation is None else "partial",
        pages=1,
        attempts=1,
        scanned=3,
        ids=["a", "b"],
    )
    assert source.capability.duplicate_records == 1
    assert ("item_limit" in codes(source)) == (continuation is not None)


def test_empty_page_limit_stops_without_prefetch(make_run):
    run = make_run(
        [Reply(encode_page([], ORIGIN + CA_PATH + "?page=2"))],
        request_fields={"max_pages": 1},
    )
    source = run.read()
    assert_summary(source, state="partial", pages=1, attempts=1, scanned=0, ids=[])
    assert "page_limit" in codes(source)


def test_conflict_recomputes_exact_extrema_and_denominators(make_run):
    a = sign_in("a", "2026-09-09T00:00:00.0000000001Z")
    b = sign_in("b", "2026-09-09T00:00:00.000000001Z")
    run = make_run(
        [
            Reply(encode_page([a, b, a], ORIGIN + SIGN_PATH + "?page=2")),
            Reply(encode_page([sign_in("a", "2026-09-09T00:00:00.1Z"), a])),
        ],
        capabilities=["sign-ins"],
    )
    source = run.read()
    assert_summary(source, state="partial", pages=2, attempts=2, scanned=5, ids=["b"])
    assert source.capability.duplicate_records == 2
    assert source.capability.observed_first == source.capability.observed_last == b["createdDateTime"]
    assert all(sum(value.model_dump().values()) == 1 for value in source.capability.field_coverage.values())
    assert [(item.code, item.count) for item in source.capability.diagnostics] == [("conflicting_duplicate", 1)]


def test_event_window_end_stays_fixed_after_wall_clock_moves(make_run):
    rows = [
        sign_in("start", "2026-09-09T00:00:00Z"),
        sign_in("end", "2026-09-10T00:00:00Z"),
        sign_in("future", "2026-09-10T00:00:00.000000000001Z"),
        sign_in("old", "2026-09-08T23:59:59.999999999999Z"),
    ]
    reply = Reply(encode_page(rows))
    run = make_run([reply], capabilities=["sign-ins"], request_fields={"lookback_days": 1})
    reply.on_send = lambda request: setattr(run.clock, "wall", NOW + timedelta(days=1))
    source = run.read()
    assert_summary(source, state="complete", pages=1, attempts=1, scanned=4, ids=["start", "end"])
    assert source.capability.requested_window_end == NOW
    assert source.capability.requested_window_start == NOW - timedelta(days=1)
    assert [(item.code, item.count) for item in source.capability.diagnostics] == [("future_timestamp", 1)]


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_retryable_status_then_success_has_exact_attempts_and_wait(make_run, status):
    run = make_run([Reply(SOURCE_MARKER.encode(), status=status), Reply()])
    source = run.read()
    assert_summary(source, state="complete", pages=1, attempts=2, scanned=0, ids=[])
    assert run.clock.sleeps == [1]
    assert_closed(run)
    assert_safe(source)


def test_three_failed_attempts_have_no_fourth_request_or_final_sleep(make_run):
    run = make_run([Reply(status=503), Reply(status=503), Reply(status=503)])
    source = run.read()
    assert_summary(source, state="unavailable", pages=0, attempts=3, scanned=0, ids=[])
    assert run.clock.sleeps == [1, 2]
    assert "retry_exhausted" in codes(source)
    assert len(run.scenario.requests) == 3
    assert_closed(run)


@pytest.mark.parametrize(
    "kind",
    [
        httpx.ConnectError,
        httpx.ConnectTimeout,
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.PoolTimeout,
    ],
)
def test_retryable_transport_exception_then_success_is_sanitized(make_run, caplog, kind):
    caplog.set_level(logging.DEBUG)
    run = make_run([kind(SOURCE_MARKER + " " + PRIMARY), Reply()])
    source = run.read()
    assert_summary(source, state="complete", pages=1, attempts=2, scanned=0, ids=[])
    assert run.clock.sleeps == [1]
    assert_safe(source, caplog)


@pytest.mark.parametrize("status", [400, 401, 403, 404, 408, 409, 422, 501])
def test_other_statuses_never_retry(make_run, status):
    run = make_run([Reply(SOURCE_MARKER.encode(), status=status)])
    source = run.read()
    assert_summary(source, state="unavailable", pages=0, attempts=1, scanned=0, ids=[])
    assert run.clock.sleeps == []
    assert len(run.scenario.requests) == 1
    assert all(item.http_status in {None, status} for item in source.capability.diagnostics)
    assert_safe(source)


@pytest.mark.parametrize("status", [300, 301, 302, 303, 304, 307, 308])
def test_returned_redirects_are_refused_even_with_hostile_client_default(make_run, status):
    run = make_run(
        [Reply(status=status, headers={"Location": "http://169.254.169.254/"})],
        defaults={"follow_redirects": True},
    )
    source = run.read()
    assert "redirect_refused" in codes(source)
    assert len(run.scenario.requests) == 1
    assert run.clock.sleeps == []
    assert_closed(run)


def test_malformed_location_is_nonretryable_sanitized_protocol_failure(make_run, caplog):
    caplog.set_level(logging.DEBUG)
    run = make_run(
        [Reply(status=302, headers={"Location": "https://graph.microsoft.com:invalid-port/"})],
        defaults={"follow_redirects": True},
    )
    source = run.read()
    assert_summary(source, state="unavailable", pages=0, attempts=1, scanned=0, ids=[])
    assert "upstream_error" in codes(source)
    assert run.clock.sleeps == []
    assert_safe(source, caplog)
    assert_closed(run)


@pytest.mark.parametrize(
    "header,expected",
    [
        ("0", 0),
        ("10", 10),
        ("Thu, 10 Sep 2026 00:00:05 GMT", 5),
        ("Thursday, 10-Sep-26 00:00:05 GMT", 5),
        ("Thu Sep 10 00:00:05 2026", 5),
        ("Wed, 09 Sep 2026 00:00:00 GMT", 0),
    ],
)
def test_retry_after_is_honored_in_real_reader(make_run, header, expected):
    run = make_run([Reply(status=429, headers={"Retry-After": header}), Reply()])
    source = run.read()
    assert source.capability.state == "complete"
    assert source.capability.requests_attempted == 2
    assert sum(run.clock.sleeps) == expected
    assert all(value == expected for value in run.clock.sleeps)


@pytest.mark.parametrize(
    "headers,code",
    [
        ({"Retry-After": "11"}, "retry_after_budget"),
        ({"Retry-After": "-1"}, "retry_after_invalid"),
        ({"Retry-After": "0.5"}, "retry_after_invalid"),
        ({"Retry-After": ""}, "retry_after_invalid"),
        ([(b"retry-after", b"1"), (b"retry-after", b"1")], "retry_after_invalid"),
    ],
)
def test_invalid_or_excessive_retry_after_stops_before_retry(make_run, headers, code):
    run = make_run([Reply(status=429, headers=headers)])
    source = run.read()
    assert code in codes(source)
    assert source.capability.state == "unavailable"
    assert len(run.scenario.requests) == 1
    assert run.clock.sleeps == []
    assert_closed(run)


def test_wait_larger_than_remaining_capability_budget_never_sleeps(make_run):
    reply = Reply(status=503, headers={"Retry-After": "2"})
    run = make_run([reply])
    reply.on_send = lambda request: run.clock.advance(59)
    source = run.read()
    assert "retry_after_budget" in codes(source)
    assert run.clock.sleeps == []
    assert len(run.scenario.requests) == 1


@pytest.mark.parametrize("refusal", ["offline", "private"])
def test_network_guards_apply_to_injected_client_without_credential_resolution(make_run, runtime, caplog, refusal):
    caplog.set_level(logging.DEBUG)
    run = make_run([])
    runtime[0].refusal = refusal
    source = run.read()
    assert_summary(source, state="unavailable", pages=0, attempts=0, scanned=0, ids=[])
    assert source.capability.diagnostics
    assert run.scenario.requests == []
    assert run.provider.calls == []
    assert_safe(source, caplog)


def test_retention_only_resolves_only_retention_group(make_run):
    run = make_run([Reply(encode_page([{"id": "label-a"}]))], capabilities=["retention-labels"])
    source = run.read()
    assert source.capability.state == "complete"
    assert source.capability.declared_auth_mode == "delegated"
    assert run.provider.calls == ["retention"]
    assert run.scenario.requests[0].headers["authorization"] == "Bearer " + RETENTION


def test_primary_401_latches_later_primary_but_preserves_retention(make_run):
    run = make_run(
        [Reply(status=401), Reply()],
        capabilities=["conditional-access", "managed-devices", "retention-labels"],
    )
    first = run.read("conditional-access")
    suppressed = run.read("managed-devices")
    independent = run.read("retention-labels")
    assert "authentication_failed" in codes(first)
    assert_summary(suppressed, state="unavailable", pages=0, attempts=0, scanned=0, ids=[])
    assert "authentication_failed" in codes(suppressed)
    assert independent.capability.state == "complete"
    assert [request.url.path for request in run.scenario.requests] == [CA_PATH, RETENTION_PATH]
    assert run.provider.calls == ["primary", "retention"]
    assert [request.headers["authorization"] for request in run.scenario.requests] == [
        "Bearer " + PRIMARY,
        "Bearer " + RETENTION,
    ]


def test_primary_403_does_not_suppress_unrelated_capability(make_run):
    run = make_run([Reply(status=403), Reply()], capabilities=["conditional-access", "managed-devices"])
    first = run.read("conditional-access")
    later = run.read("managed-devices")
    assert "permission_denied" in codes(first)
    assert later.capability.state == "complete"
    assert run.provider.calls == ["primary"]
    assert len(run.scenario.requests) == 2


def test_configuration_failure_is_group_local_and_never_falls_back(make_run, runtime):
    target = runtime[1]
    values = {
        "primary": target._CredentialResolution(
            token=None, declared_auth_mode=None, diagnostic="configuration_invalid"
        ),
        "retention": target._CredentialResolution(token=RETENTION, declared_auth_mode="delegated"),
    }
    run = make_run(
        [Reply()],
        capabilities=["conditional-access", "managed-devices", "retention-labels"],
        values=values,
    )
    for name in ("conditional-access", "managed-devices"):
        result = run.read(name)
        assert result.capability.state == "unavailable"
        assert "configuration_invalid" in codes(result)
        assert result.capability.requests_attempted == 0
    assert run.read("retention-labels").capability.state == "complete"
    assert run.provider.calls == ["primary", "retention"]
    assert [request.url.path for request in run.scenario.requests] == [RETENTION_PATH]


def test_new_reader_does_not_inherit_prior_run_401_or_returned_mutation(make_run):
    old = make_run([Reply(status=401)])
    assert "authentication_failed" in codes(old.read())
    fresh = make_run([Reply(encode_page([{"id": "new", "conditions": {"x": 1}}]))])
    result = fresh.read()
    assert result.capability.state == "complete"
    result.records[0].fields["conditions"]["x"] = 999
    later = make_run([Reply(encode_page([{"id": "new", "conditions": {"x": 1}}]))])
    assert later.read().records[0].fields["conditions"]["x"] == 1
    assert fresh.provider.calls == later.provider.calls == ["primary"]


def test_two_overlapping_runs_keep_credentials_results_and_logs_separate(make_run, runtime, caplog):
    caplog.set_level(logging.DEBUG)
    target = runtime[1]
    barrier = threading.Barrier(2)
    replies = [Reply(encode_page([{"id": label}])) for label in ("one", "two")]
    runs = []
    for label, reply in zip(("one", "two"), replies, strict=True):
        reply.on_send = lambda request: barrier.wait(timeout=5)
        values = {
            "primary": target._CredentialResolution(token=PRIMARY + label, declared_auth_mode="application"),
            "retention": target._CredentialResolution(token=RETENTION, declared_auth_mode="delegated"),
        }
        runs.append(make_run([reply], values=values))
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run.read) for run in runs]
        results = [future.result(timeout=10) for future in futures]
    assert [source.records[0].source_id for source in results] == ["one", "two"]
    assert [run.scenario.requests[0].headers["authorization"] for run in runs] == [
        "Bearer " + PRIMARY + "one",
        "Bearer " + PRIMARY + "two",
    ]
    for source in results:
        assert_safe(source, caplog)


def test_elapsed_run_budget_prevents_new_capability_and_token_lookup(make_run):
    run = make_run([])
    run.clock.advance(300)
    source = run.read()
    assert_summary(source, state="unavailable", pages=0, attempts=0, scanned=0, ids=[])
    assert "run_budget" in codes(source)
    assert source.capability.started_at is None
    assert run.provider.calls == []
    assert run.scenario.requests == []


def test_slow_first_chunk_closes_without_reading_or_retrying_more(make_run):
    reply = Reply(chunks=[b'{"value":', b"[]}"])
    run = make_run([reply])
    reply.before_chunk = lambda number: run.clock.advance(60) if number == 1 else None
    source = run.read()
    assert_summary(source, state="unavailable", pages=0, attempts=1, scanned=0, ids=[])
    assert "capability_budget" in codes(source)
    assert run.scenario.streams[0].reads == 1
    assert run.clock.sleeps == []
    assert_closed(run)


def test_next_request_timeout_is_reduced_to_remaining_budget(make_run):
    first = Reply(encode_page([{"id": "a"}], ORIGIN + CA_PATH + "?page=2"))
    second = Reply(encode_page([{"id": "b"}]))
    run = make_run([first, second])
    first.on_send = lambda request: run.clock.advance(59)
    second.before_chunk = lambda number: run.clock.advance(2)
    source = run.read()
    assert_summary(source, state="partial", pages=1, attempts=2, scanned=1, ids=["a"])
    assert run.scenario.requests[1].extensions["timeout"] == {"connect": 1.0, "pool": 1.0, "read": 1.0, "write": 1.0}
    assert "capability_budget" in codes(source)


@pytest.mark.parametrize("encoding", ["identity", "gzip"])
def test_real_reader_rejects_decoded_page_overflow_without_retry(make_run, encoding):
    body = b"x" * (PAGE_LIMIT + 1)
    if encoding == "gzip":
        body = gzip.compress(body, mtime=0)
    run = make_run([Reply(body, headers={"Content-Encoding": encoding})])
    source = run.read()
    assert_summary(source, state="unavailable", pages=0, attempts=1, scanned=0, ids=[])
    assert "response_limit" in codes(source)
    assert run.clock.sleeps == []
    assert_closed(run)


def test_failed_body_bytes_count_toward_real_capability_aggregate(make_run):
    replies = []
    for number in range(1, 8):
        prefix = encode_page([], ORIGIN + CA_PATH + "?page=" + str(number))
        replies.append(Reply(chunks=[prefix, b" " * (PAGE_LIMIT - len(prefix))]))
    failed = b'{"value":[]}' + b" " * (PAGE_LIMIT - 1 - len(b'{"value":[]}'))
    replies.append(Reply(chunks=[failed], failure=httpx.ReadTimeout(SOURCE_MARKER)))
    replies.append(Reply())
    run = make_run(replies)
    source = run.read()
    assert_summary(source, state="partial", pages=7, attempts=9, scanned=0, ids=[])
    assert "byte_limit" in codes(source)
    assert run.clock.sleeps == [1]
    assert len(run.scenario.requests) == 9
    assert_closed(run)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"value":[],"value":[]}',
        b'{"value":[{"id":"a","conditions":{"x":1,"x":2}}]}',
        b'{"value":[{"id":"a","conditions":{"x":NaN}}]}',
        b'{"value":[{"id":"a","conditions":{"x":1e9999}}]}',
        b'{"value":[{"id":"a"}]}\xff',
    ],
)
def test_strict_json_errors_reject_page_and_do_not_retry(make_run, payload):
    run = make_run([Reply(payload)])
    source = run.read()
    assert_summary(source, state="unavailable", pages=0, attempts=1, scanned=0, ids=[])
    assert "invalid_envelope" in codes(source)
    assert run.clock.sleeps == []


@pytest.mark.parametrize(
    "failure",
    [
        httpx.RemoteProtocolError(SOURCE_MARKER),
        RuntimeError(SOURCE_MARKER),
    ],
)
def test_nonretryable_exception_is_fixed_and_never_logged_raw(make_run, caplog, failure):
    caplog.set_level(logging.DEBUG)
    run = make_run([failure])
    source = run.read()
    assert_summary(source, state="unavailable", pages=0, attempts=1, scanned=0, ids=[])
    expected = "upstream_error" if isinstance(failure, httpx.RemoteProtocolError) else "internal_error"
    assert expected in codes(source)
    assert run.clock.sleeps == []
    assert_safe(source, caplog)


def test_current_reader_scope_covers_opaque_queries_body_and_cleanup_logs(make_run, caplog):
    caplog.set_level(logging.DEBUG)
    continuation = ORIGIN + CA_PATH + "?$skiptoken=" + OPAQUE
    run = make_run(
        [
            Reply(encode_page([{"id": "a", "discarded": SOURCE_MARKER}], continuation)),
            Reply(encode_page([{"id": "b"}])),
        ]
    )
    source = run.read()
    assert_summary(source, state="complete", pages=2, attempts=2, scanned=2, ids=["a", "b"])
    assert "discarded" not in source.records[0].fields
    assert_safe(source, caplog)
    assert_closed(run)


def test_response_close_failure_cannot_become_complete_or_leak(make_run, caplog):
    caplog.set_level(logging.DEBUG)
    run = make_run([Reply(close_failure=True)])
    source = run.read()
    assert_summary(source, state="unavailable", pages=0, attempts=1, scanned=0, ids=[])
    assert "internal_error" in codes(source)
    assert_safe(source, caplog)
    assert run.scenario.streams[0].closed == 1


def test_owned_client_uses_safe_defaults_and_closes(runtime, monkeypatch):
    guards, target, ledger = runtime
    guards.reset()
    original = httpx.Client
    scenario = Scenario(guards, [Reply()])
    created = []

    class SyntheticOwnedClient(original):
        def __init__(self, *args, **kwargs):
            assert kwargs.get("trust_env") is False
            assert kwargs.get("http2", False) is False
            unused_transport = kwargs.get("transport")
            if unused_transport is not None:
                unused_transport.close()
            kwargs["transport"] = httpx.MockTransport(scenario.handle)
            super().__init__(*args, **kwargs)
            created.append(self)

    monkeypatch.setattr(httpx, "Client", SyntheticOwnedClient)
    request = contracts.EntraM365CollectRequest(tenant_label="synthetic-owned", capabilities=["conditional-access"])
    clock = Clock()
    context = ledger.EntraM365RunContext.start(
        request,
        utc_clock=clock.utc,
        monotonic_clock=clock.monotonic,
        sleep=clock.sleep,
        run_id_factory=lambda: "synthetic-owned-run",
    )
    provider = Provider(target)
    reader = target.EntraM365GraphReader(credentials=provider, client=None)
    try:
        source = reader.read_collection("conditional-access", request, context)
        assert source.capability.state == "complete"
    finally:
        reader.close()
    assert len(created) == 1
    assert created[0].is_closed
    assert all(stream.closed == 1 for stream in scenario.streams)


def test_credential_resolution_repr_does_not_expose_token(runtime):
    target = runtime[1]
    value = target._CredentialResolution(token=PRIMARY, declared_auth_mode="application")
    assert PRIMARY not in repr(value)
