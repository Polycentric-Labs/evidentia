"""Canonical byte counts, coercion refusals and finite JSON input handling."""

import json
import math

import pytest
from evidentia_collectors.scap._json import canonical_bytes, canonical_size, detached, load_json
from evidentia_collectors.scap._limits import Budget, ScapFailure


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        0,
        -1,
        3.25,
        -0.0,
        "",
        '"\\\n\t',
        "caf\u00e9",
        "\U0001f642",
        "\x7f",
        {"z": [None, False], "a": "\u2028"},
    ],
)
def test_count_is_exact_for_all_json_value_kinds(value: object) -> None:
    expected = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    assert canonical_size(value, len(expected)) == len(expected)
    assert canonical_bytes(value, len(expected)) == expected
    with pytest.raises(ScapFailure, match="publication limit"):
        canonical_bytes(value, len(expected) - 1)


@pytest.mark.parametrize(
    "value", [math.nan, math.inf, -math.inf, 2**53, -(2**53), b"source", (1, 2), {1: "value"}, "\ud800", "\udfff"]
)
def test_non_native_or_nonrepresentable_values_refuse(value: object) -> None:
    with pytest.raises(ScapFailure):
        canonical_bytes(value)


def test_subclass_callbacks_never_execute() -> None:
    calls = []

    class TrapDict(dict):
        def items(self):
            calls.append("items")
            raise AssertionError("A source callback must not execute")

    class TrapList(list):
        def __iter__(self):
            calls.append("iter")
            raise AssertionError("A source callback must not execute")

    class TrapString(str):
        def encode(self, *args, **kwargs):
            calls.append("encode")
            raise AssertionError("A source callback must not execute")

    for value in [TrapDict(a=1), TrapList([1]), TrapString("text"), {TrapString("key"): 1}]:
        with pytest.raises(ScapFailure):
            canonical_bytes(value)
    assert calls == []


def test_cycles_refuse_and_acyclic_aliases_are_charged_and_detached() -> None:
    shared = {"source": ["\U0001f642"]}
    original = [shared, shared]
    expected = json.dumps(original, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    assert canonical_size(original, len(expected)) == len(expected)
    copied = detached(original, len(expected))
    assert copied == original
    assert copied[0] is not copied[1]
    shared["source"].append("later change")
    assert copied == [{"source": ["\U0001f642"]}, {"source": ["\U0001f642"]}]
    shared["cycle"] = shared
    with pytest.raises(ScapFailure):
        canonical_bytes(shared)


def test_limit_is_checked_before_escape_allocation(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_collectors.scap import _json

    def forbidden(*args, **kwargs):
        raise AssertionError("Full JSON allocation must not run after a failed count")

    monkeypatch.setattr(_json.json, "dumps", forbidden)
    with pytest.raises(ScapFailure, match="publication limit"):
        canonical_bytes("\U0001f642" * 1000, 12001)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a": 1, "a": 2}',
        b'{"a": {"b": 1, "b": 2}}',
        b'{"a": NaN}',
        b'{"a": 1e999}',
        b'"\\ud800"',
        b'{"a": 9007199254740992}',
        b'"unterminated',
        b"{} {}",
        b"\xef\xbb\xbf{}",
        b'"\xff"',
    ],
)
def test_invalid_json_never_becomes_a_usable_native_value(raw: bytes) -> None:
    with pytest.raises(ScapFailure):
        load_json(raw, 4096)


def test_utf8_and_encoded_duplicate_keys_preserve_exact_text() -> None:
    assert load_json('{"name": "  caf\u00e9  "}'.encode(), 4096) == {"name": "  caf\u00e9  "}
    with pytest.raises(ScapFailure):
        load_json(b'{"a": 1, "\\u0061": 2}', 4096)


def test_nested_json_refuses_before_decoder(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_collectors.scap import _json

    def forbidden(*args, **kwargs):
        raise AssertionError("Excessive depth must refuse before decoding")

    monkeypatch.setattr(_json.json, "loads", forbidden)
    with pytest.raises(ScapFailure):
        load_json(b"[" * 129 + b"0" + b"]" * 129, 4096)


def test_original_deadline_is_checked_before_and_after_encoding(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_collectors.scap import _json, _limits

    current = [5.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: current[0])
    budget = Budget(20.0)
    encode = _json.json.dumps

    def late(*args, **kwargs):
        result = encode(*args, **kwargs)
        current[0] = 20.0
        return result

    monkeypatch.setattr(_json.json, "dumps", late)
    with pytest.raises(ScapFailure, match="deadline"):
        canonical_bytes({"value": "complete"}, 4096, budget, publication=True)
    with pytest.raises(ScapFailure, match="deadline"):
        canonical_size({}, 4096, budget)


@pytest.mark.parametrize("change", ["custom", "oversize", "cycle"])
@pytest.mark.parametrize("operation", ["detach", "serialize"])
def test_each_occurrence_is_checked_after_prior_stage_mutation(
    monkeypatch: pytest.MonkeyPatch, change: str, operation: str
) -> None:
    from evidentia_collectors.scap import _json

    calls = []

    class TrapDict(dict):
        def items(self):
            calls.append("items")
            raise AssertionError("A later-inserted callback must not execute")

    original = ["trigger", {"a": "b"}]
    count_string = _json._string_size
    changed = []

    def change_next(value, *args, **kwargs):
        measured = count_string(value, *args, **kwargs)
        if value == "trigger" and not changed:
            changed.append(True)
            if change == "custom":
                original[1] = TrapDict(a="b")
            elif change == "oversize":
                original[1] = "x" * 500
            else:
                original[1] = original
        return measured

    monkeypatch.setattr(_json, "_string_size", change_next)
    with pytest.raises(ScapFailure):
        if operation == "detach":
            detached(original, 200)
        else:
            canonical_bytes(original, 200)
    assert changed == [True]
    assert calls == []


@pytest.mark.parametrize("operation", ["detach", "serialize"])
def test_completed_snapshot_has_no_later_caller_aliases(monkeypatch: pytest.MonkeyPatch, operation: str) -> None:
    from evidentia_collectors.scap import _json

    calls = []

    class TrapDict(dict):
        def items(self):
            calls.append("items")
            raise AssertionError("Serialization must use only the captured snapshot")

    original = [{"a": "b"}]
    walk = _json._walk

    def after_capture(*args, **kwargs):
        captured = walk(*args, **kwargs)
        original[0] = TrapDict(a="b")
        return captured

    monkeypatch.setattr(_json, "_walk", after_capture)
    if operation == "detach":
        assert detached(original, 200) == [{"a": "b"}]
    else:
        assert canonical_bytes(original, 200) == b'[{"a":"b"}]'
    assert calls == []


@pytest.mark.parametrize("stage", ["walk", "encode", "deadline"])
def test_owned_snapshots_clear_without_changing_source_or_cancellation(monkeypatch, stage):
    from evidentia_collectors.scap import _json, _limits

    class Cancelled(BaseException):
        pass

    primary = Cancelled()
    source = {"a": [{"value": "preserved"}, {"cancel_here": "later"}]}
    expected = {"a": [{"value": "preserved"}, {"cancel_here": "later"}]}
    snapshots = []
    count = _json._string_size
    encode = _json.json.dumps
    clock = [1.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: clock[0])

    def observed_size(value, *args, **kwargs):
        result = count(value, *args, **kwargs)
        if stage == "walk" and value == "cancel_here":
            raise primary
        return result

    def observed_encode(value, *args, **kwargs):
        snapshots.append(value)
        if stage == "encode":
            raise primary
        result = encode(value, *args, **kwargs)
        if stage == "deadline":
            clock[0] = 60.0
        return result

    monkeypatch.setattr(_json, "_string_size", observed_size)
    monkeypatch.setattr(_json.json, "dumps", observed_encode)
    with pytest.raises(ScapFailure if stage == "deadline" else Cancelled) as raised:
        canonical_bytes(source, 4096, Budget(60.0), publication=True)
    if stage != "deadline":
        assert raised.value is primary
    trace = raised.value.__traceback__
    while trace is not None:
        frame = trace.tb_frame
        if frame.f_code.co_name == "canonical_bytes":
            assert frame.f_locals["encoded"] == b""
        if frame.f_code.co_name == "_walk":
            assert not frame.f_locals["frames"]
            assert not frame.f_locals["string_sizes"]
            assert not frame.f_locals["result"]
        trace = trace.tb_next
    assert all(not snapshot for snapshot in snapshots)
    assert source == expected


def test_successful_encoder_releases_its_private_snapshot(monkeypatch):
    from evidentia_collectors.scap import _json

    snapshots = []
    encode = _json.json.dumps

    def observed(value, *args, **kwargs):
        snapshots.append(value)
        return encode(value, *args, **kwargs)

    monkeypatch.setattr(_json.json, "dumps", observed)
    source = {"values": [{"a": 1}]}
    assert canonical_bytes(source) == b'{"values":[{"a":1}]}'
    assert source == {"values": [{"a": 1}]}
    assert all(not snapshot for snapshot in snapshots)


def test_repeated_native_strings_remain_charged_for_every_occurrence() -> None:
    shared = {"repeated": ["repeated", "repeated"]}
    source = [shared] * 300
    expected = json.dumps(source, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    assert canonical_size(source, len(expected)) == len(expected)
    assert canonical_bytes(source, len(expected)) == expected
    copied = detached(source, len(expected))
    assert copied == source
    assert copied[0] is not copied[1]
    for operation in (canonical_size, canonical_bytes, detached):
        with pytest.raises(ScapFailure, match="publication limit"):
            operation(source, len(expected) - 1)


def test_repeated_string_subclass_is_refused_before_hashing() -> None:
    calls = []

    class TrapString(str):
        def __hash__(self):
            calls.append("hash")
            raise AssertionError("A source hash callback must not execute")

        def __eq__(self, other):
            calls.append("equality")
            raise AssertionError("A source equality callback must not execute")

    for operation in (canonical_size, canonical_bytes, detached):
        with pytest.raises(ScapFailure):
            operation(["repeated", TrapString("repeated")], 4096)
    assert calls == []


def test_repeated_ascii_values_do_not_skip_the_original_deadline(monkeypatch) -> None:
    from evidentia_collectors.scap import _limits

    calls = []

    def clock():
        calls.append(True)
        return 1.0 if len(calls) == 1 else 60.0

    monkeypatch.setattr(_limits.time, "monotonic", clock)
    with pytest.raises(ScapFailure) as error:
        canonical_bytes(["repeated"] * 1024, 16384, Budget(60.0), publication=True)
    assert error.value.code == "processing_deadline_exceeded"
    assert len(calls) == 2


def test_short_string_size_cache_is_bounded_per_walk(monkeypatch):
    from collections import Counter

    from evidentia_collectors.scap import _json

    values = [f"entry-{index:03d}" for index in range(513)]
    source = [*values, values[0], values[-1]]
    expected = _json.json.dumps(source, separators=(",", ":")).encode("ascii")
    calls = Counter()
    original = _json._string_size

    def observed(value, *args, **kwargs):
        calls[value] += 1
        return original(value, *args, **kwargs)

    monkeypatch.setattr(_json, "_string_size", observed)
    assert canonical_bytes(source, len(expected)) == expected
    assert calls[values[0]] == 1
    assert calls[values[-1]] == 2
    assert len(calls) == 513
    assert canonical_bytes(source, len(expected)) == expected
    assert calls[values[0]] == 2
    assert calls[values[-1]] == 4


@pytest.mark.parametrize(("length", "expected_calls"), [(64, 1), (65, 2)])
def test_short_string_cache_length_boundary(monkeypatch, length, expected_calls):
    from evidentia_collectors.scap import _json

    value = "a" * length
    source = [value, value]
    expected = _json.json.dumps(source, separators=(",", ":")).encode("ascii")
    calls = []
    original = _json._string_size

    def observed(item, *args, **kwargs):
        calls.append(item)
        return original(item, *args, **kwargs)

    monkeypatch.setattr(_json, "_string_size", observed)
    assert canonical_bytes(source, len(expected)) == expected
    assert calls == [value] * expected_calls
