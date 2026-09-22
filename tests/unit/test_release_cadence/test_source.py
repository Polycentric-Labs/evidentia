"""Literal source projection and independent ingress boundaries."""

import pytest
from evidentia_core.release_cadence._json import canonical_bytes, detach, load_json
from evidentia_core.release_cadence._limits import ReleaseFailure
from evidentia_core.release_cadence._source import canonical_repository, selected_facts


def row():
    return {
        "id": 101,
        "node_id": "synthetic",
        "url": "inert://literal",
        "html_url": "",
        "tag_name": "synthetic-v1",
        "target_commitish": "main",
        "name": None,
        "draft": False,
        "prerelease": False,
        "created_at": "",
        "published_at": None,
    }


@pytest.mark.parametrize(
    "owner,repo,expected",
    [
        ("Example", "Synthetic", ("example", "synthetic")),
        ("a--b", "x.y-z_0", ("a--b", "x.y-z_0")),
    ],
)
def test_repository_canonicalization(owner, repo, expected):
    assert canonical_repository(owner, repo) == expected


@pytest.mark.parametrize(
    "owner,repo",
    [
        ("-a", "x"),
        ("a-", "x"),
        ("a", "."),
        ("a", ".."),
        ("a", "x.GIT"),
        (" a", "x"),
        ("a", "x/y"),
        ("a", "x%2fy"),
        ("é", "x"),
        (True, "x"),
    ],
)
def test_repository_refuses_before_coercion(owner, repo):
    with pytest.raises(ReleaseFailure):
        canonical_repository(owner, repo)


def test_projection_preserves_absence_and_inert_source_strings():
    original = row()
    original["ignored"] = {"nested": [123]}
    actual = selected_facts(original)
    assert actual == row()
    assert "immutable" not in actual and "updated_at" not in actual
    original["name"] = "changed"
    assert actual["name"] is None
    assert selected_facts({**row(), "immutable": False, "updated_at": None}) != actual


@pytest.mark.parametrize(
    "change",
    [
        {"id": True},
        {"id": 1.0},
        {"id": 0},
        {"id": 9007199254740992},
        {"draft": 0},
        {"immutable": None},
        {"updated_at": False},
        {"published_at": "é" * 65},
        {"tag_name": "x" * 16385},
    ],
)
def test_selected_native_types(change):
    with pytest.raises(ReleaseFailure):
        selected_facts({**row(), **change})


def test_aliases_are_boundary_specific_and_occurrence_charged():
    shared = {"x": 1}
    aliased = [shared, shared]
    with pytest.raises(ReleaseFailure):
        detach(aliased, 1024)
    detached = detach(aliased, 1024, allow_aliases=True)
    assert detached == [{"x": 1}, {"x": 1}]
    assert detached[0] is not detached[1]
    with pytest.raises(ReleaseFailure):
        detach(aliased, 1024, allow_aliases=True, max_values=6)
    assert detach(aliased, 1024, allow_aliases=True, max_values=7) == detached
    shared["cycle"] = aliased
    with pytest.raises(ReleaseFailure):
        detach(aliased, 1024, allow_aliases=True)


def test_unknown_finite_numbers_do_not_coerce_selected_id():
    unknown = load_json(b'{"unknown":123456789012345678901234567890,"id":1e0}', 1024)
    assert unknown["unknown"] == 123456789012345678901234567890
    with pytest.raises(ReleaseFailure):
        selected_facts({**row(), "id": unknown["id"]})


@pytest.mark.parametrize(
    "raw",
    [
        b'{"ignored":{"x":1,"x":2}}',
        b"[] []",
        b"\xef\xbb\xbf[]",
        b'{"x":NaN}',
        b'{"x":1e999}',
        b'{"x":01}',
        b'{"x":1.}',
        b'{"x":"\\ud800"}',
        b'{"x":' + b"1" * 129 + b"}",
    ],
)
def test_strict_json_refusals(raw):
    with pytest.raises(ReleaseFailure):
        load_json(raw, 1024)


def test_preflight_depth_count_and_canonical_unicode():
    assert load_json(b"[" * 63 + b"0" + b"]" * 63, 1024) == detach(load_json(b"[" * 63 + b"0" + b"]" * 63, 1024), 1024)
    with pytest.raises(ReleaseFailure):
        load_json(b"[" * 64 + b"0" + b"]" * 64, 1024)
    assert load_json(b'{"x":1}', 1024, max_values=3) == {"x": 1}
    with pytest.raises(ReleaseFailure):
        load_json(b'{"x":1}', 1024, max_values=2)
    assert canonical_bytes({"x": "é😀"}, 1024) == b'{"x":"\\u00e9\\ud83d\\ude00"}'
    with pytest.raises(ReleaseFailure):
        canonical_bytes({"x": "é😀"}, 25)


def test_callbacks_and_metaclass_equality_are_never_admitted():
    class EvilMeta(type):
        def __eq__(self, other):
            raise AssertionError("type equality callback")

        def __hash__(self):
            raise AssertionError("type hash callback")

    class Evil(metaclass=EvilMeta):
        pass

    class EvilDict(dict):
        def items(self):
            raise AssertionError("items callback")

    for value in (Evil(), EvilDict(x=1)):
        with pytest.raises(ReleaseFailure):
            detach(value, 1024)


@pytest.mark.parametrize("text", [chr(value) for value in range(128)] + ["é", "😀", "\u2028"])
def test_canonical_scalar_size_matches_exact_standard_encoding(text):
    import json

    expected = json.dumps(
        {"x": text}, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()
    assert canonical_bytes({"x": text}, len(expected)) == expected
    with pytest.raises(ReleaseFailure):
        canonical_bytes({"x": text}, len(expected) - 1)


def test_serializer_cleanup_cannot_replace_primary(monkeypatch):
    from evidentia_core.release_cadence import _json
    from evidentia_core.release_cadence._limits import Budget

    class Primary(BaseException):
        pass

    primary = Primary()
    calls = 0

    def interrupt(budget):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise primary

    def cleanup_failure(value):
        raise RuntimeError("secondary cleanup")

    monkeypatch.setattr(_json, "check_budget", interrupt)
    monkeypatch.setattr(_json, "_discard", cleanup_failure)
    with pytest.raises(Primary) as raised:
        canonical_bytes({"x": "value"}, 1024, budget=Budget(1.0))
    assert raised.value is primary


@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 4095, 4096, 4097, 8193])
@pytest.mark.parametrize("unit", ["a", "\x00", '"', "\\", "\x7f", "\u0800", "\U0010ffff"])
def test_bounded_scalar_encoder_exact_independent_size(size, unit):
    import json

    from evidentia_core.release_cadence._json import _string_size
    from evidentia_core.release_cadence._limits import ReleaseFailure

    value = unit * size
    utf8 = len(value.encode("utf-8"))
    expected = len(json.dumps(value, ensure_ascii=True).encode("ascii"))
    assert _string_size(value, utf8, None) == expected
    if utf8:
        with pytest.raises(ReleaseFailure) as found:
            _string_size(value, utf8 - 1, None)
        assert found.value.reason == "json_scalar"


@pytest.mark.parametrize("point", [0xD800, 0xDBFF, 0xDC00, 0xDFFF])
@pytest.mark.parametrize("prefix", [0, 4095, 4096])
def test_bounded_scalar_encoder_refuses_surrogates_at_chunk_edges(point, prefix):
    from evidentia_core.release_cadence._json import _string_size
    from evidentia_core.release_cadence._limits import ReleaseFailure

    with pytest.raises(ReleaseFailure) as found:
        _string_size("a" * prefix + chr(point), prefix + 4, None)
    assert found.value.reason == "json_scalar"


def test_bounded_scalar_polling_and_encoder_temporaries(monkeypatch):
    from evidentia_core.release_cadence import _json

    polls = []
    chunks = []
    original_encoder = _json.json.encoder.encode_basestring_ascii
    primary = KeyboardInterrupt()

    def poll(budget):
        polls.append(True)
        if len(polls) == 3:
            raise primary

    def encode(value):
        assert type(value) is str and len(value) <= 4096
        encoded = original_encoder(value)
        assert len(value.encode("utf-8")) <= 16384
        assert len(encoded) <= 49154 and encoded.isascii()
        chunks.append((len(value), len(encoded)))
        return encoded

    monkeypatch.setattr(_json, "check_budget", poll)
    monkeypatch.setattr(_json.json.encoder, "encode_basestring_ascii", encode)
    with pytest.raises(KeyboardInterrupt) as found:
        _json._string_size("\U0010ffff" * 8193, 32772, None)
    assert found.value is primary and len(polls) == 3
    assert chunks == [(4096, 49154), (4096, 49154)]


def test_serializer_drops_owned_wire_on_late_cancellation(monkeypatch):
    from evidentia_core.release_cadence import _json

    primary = KeyboardInterrupt("Synthetic interruption after encoding.")
    encoded = []
    original = _json.json.dumps

    def encode(*args, **kwargs):
        value = original(*args, **kwargs)
        encoded.append(True)
        return value

    def check(budget):
        if encoded:
            raise primary

    monkeypatch.setattr(_json.json, "dumps", encode)
    monkeypatch.setattr(_json, "check_budget", check)
    with pytest.raises(KeyboardInterrupt) as found:
        _json.canonical_bytes({"payload": "x" * 1024}, 2048)
    assert found.value is primary
    trace = found.value.__traceback__
    frames = []
    while trace is not None:
        if trace.tb_frame.f_code is _json.canonical_bytes.__code__:
            frames.append(trace.tb_frame.f_locals)
        trace = trace.tb_next
    assert len(frames) == 1
    assert frames[0].get("snapshot") is None
    assert frames[0].get("raw") is None


@pytest.mark.parametrize("key", ["", "k", "k" * 64, "k" * 65, "k" * 256, '\u0001"\\', "\u00e9\U0001f600"])
@pytest.mark.parametrize("spaced", [False, True])
def test_repeated_key_sizes_match_exact_wire_and_limit(key, spaced):
    import json

    from evidentia_core.release_cadence._json import canonical_bytes
    from evidentia_core.release_cadence._limits import ReleaseFailure

    value = [{key: "same"} for _ in range(8)]
    separators = (", ", ": ") if spaced else (",", ":")
    expected = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=separators).encode("utf-8")
    assert canonical_bytes(value, len(expected), spaced=spaced) == expected
    with pytest.raises(ReleaseFailure) as found:
        canonical_bytes(value, len(expected) - 1, spaced=spaced)
    assert found.value.reason == "result_limit_exceeded"


def test_key_size_cache_is_bounded_and_cleared_per_walk(monkeypatch):
    import sys

    from evidentia_core.release_cadence import _json

    original = _json._string_size
    caches = []
    seen_sizes = []
    value = [{"key_" + str(index): index} for index in range(514)]
    value.extend({"key_0": index} for index in range(4))

    def observe(*args, **kwargs):
        frame = sys._getframe(1)
        if frame.f_code.co_name == "_snapshot":
            cache = frame.f_locals["cache"]
            caches.append(cache)
            seen_sizes.append(len(cache))
        return original(*args, **kwargs)

    monkeypatch.setattr(_json, "_string_size", observe)
    for _ in range(2):
        wire = _json.canonical_bytes(value, 100000)
        assert _json.load_json(wire, 100000) == value
    assert max(seen_sizes) == 512 and all(size <= 512 for size in seen_sizes)
    assert all(cache == {} for cache in caches)
    assert len({id(cache) for cache in caches}) == 2


@pytest.mark.parametrize("maximum", [0, 1, 3, 4])
def test_key_cache_cannot_relax_smaller_value_limits(maximum):
    from evidentia_core.release_cadence._json import detach
    from evidentia_core.release_cadence._limits import ReleaseFailure

    value = {"same": "same"}
    if maximum < 4:
        with pytest.raises(ReleaseFailure) as found:
            detach(value, 100, max_string_bytes=maximum)
        assert found.value.reason == "json_scalar"
    else:
        assert detach(value, 100, max_string_bytes=maximum) == value


def test_repeated_key_hit_preserves_cancellation_and_owned_cleanup(monkeypatch):
    import sys

    from evidentia_core.release_cadence import _json

    original = _json.check_budget
    primary = KeyboardInterrupt("synthetic key-hit interruption")
    value = [{"same": "value"} for _ in range(3)]
    hits = []

    def interrupt(budget):
        frame = sys._getframe(1)
        state = frame.f_locals
        if frame.f_code.co_name == "_snapshot" and state.get("item_key") == "same" and state.get("count") == 6:
            assert "same" in state["cache"]
            hits.append("same")
            raise primary
        return original(budget)

    monkeypatch.setattr(_json, "check_budget", interrupt)
    with pytest.raises(KeyboardInterrupt) as found:
        _json.canonical_bytes(value, 1000)
    assert found.value is primary and hits == ["same"]
    trace = found.value.__traceback__
    while trace is not None and trace.tb_frame.f_code.co_name != "_snapshot":
        trace = trace.tb_next
    assert trace is not None
    state = trace.tb_frame.f_locals
    assert state["cache"] == {} and state["frames"] == state["holder"] == []
    assert state["source"] is state["parent"] is state["item"] is state["item_key"] is None
    assert value == [{"same": "value"} for _ in range(3)]


@pytest.mark.parametrize("unit,count", [("a", 256), ("é", 128), ("😀", 64)])
def test_raw_parser_key_utf8_exact_and_one_over(unit, count):
    import json

    key = unit * count
    assert len(key.encode("utf-8")) == 256
    raw = json.dumps({key: 0}, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    assert load_json(raw, 4096) == {key: 0}
    excess = key + "a"
    assert len(excess.encode("utf-8")) == 257
    raw_excess = json.dumps({excess: 0}, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(ReleaseFailure):
        load_json(raw_excess, 4096)


@pytest.mark.parametrize(
    "token,expected",
    [
        (b"1" * 128, int("1" * 128)),
        (b"-" + b"1" * 127, -int("1" * 127)),
        (b"0." + b"1" * 126, float("0." + "1" * 126)),
        (b"1e+" + b"0" * 124 + b"1", 10.0),
    ],
)
def test_raw_parser_finite_number_token_exact_and_one_over(token, expected):
    assert len(token) == 128
    actual = load_json(b'{"ignored":' + token + b"}", 1024)["ignored"]
    assert type(actual) is type(expected) and actual == expected
    excess = token + b"0"
    assert len(excess) == 129
    with pytest.raises(ReleaseFailure):
        load_json(b'{"ignored":' + excess + b"}", 1024)


@pytest.mark.parametrize("identifier", [1, 9007199254740991, "1"])
def test_selected_id_exact_native_endpoints(identifier):
    expected = {**row(), "id": identifier}
    if type(identifier) is str:
        with pytest.raises(ReleaseFailure) as found:
            selected_facts(expected)
        assert found.value.reason == "source_field"
    else:
        assert selected_facts(expected) == expected


def test_optional_empty_literals_do_not_become_absence_or_null():
    expected = {**row(), "name": "", "immutable": False, "updated_at": ""}
    actual = selected_facts(expected)
    assert actual == expected and set(actual) == set(expected)
    assert actual != selected_facts(row())
    assert actual != selected_facts({**row(), "name": "", "immutable": False, "updated_at": None})


def test_json_spelling_and_unicode_normalization_have_distinct_hash_domains():
    import hashlib
    import json

    from evidentia_core.release_cadence._identity import fact_digest

    native = {**row(), "name": "\u00e9"}
    literal = json.dumps(native, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    escaped = json.dumps(native, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    left, right = selected_facts(load_json(literal, 16384)), selected_facts(load_json(escaped, 16384))
    expected = hashlib.sha256(
        json.dumps(
            ["evidentia.release-selected-facts.v1", native], sort_keys=True, ensure_ascii=True, separators=(",", ":")
        ).encode("ascii")
    ).hexdigest()
    assert literal != escaped and hashlib.sha256(literal).digest() != hashlib.sha256(escaped).digest()
    assert left == right == native and fact_digest(left) == fact_digest(right) == expected
    decomposed = {**native, "name": "e\u0301"}
    assert selected_facts(decomposed)["name"] == "e\u0301"
    assert fact_digest(decomposed) != expected
