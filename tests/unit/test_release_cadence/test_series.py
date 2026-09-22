"""Hand-derived series boundaries over synthetic temporary store records."""

from __future__ import annotations

import copy
import hashlib

import pytest
from evidentia_core.release_cadence._contracts import native_model
from evidentia_core.release_cadence._identity import build_observation, build_publication
from evidentia_core.release_cadence._json import canonical_bytes
from evidentia_core.release_cadence._series import evaluate_release_series

from ._helpers import artifact, series_request, write_artifact


@pytest.mark.parametrize("count", [0, 1])
def test_zero_and_one_are_insufficient(tmp_path, count):
    if count:
        write_artifact(tmp_path, artifact())
    result = native_model(evaluate_release_series(series_request(), evidence_store_dir=tmp_path))
    assert result["state"] == "insufficient"
    assert result["reasons"] == ["insufficient_events"]
    assert result["gaps"] == []
    assert len(result["events"]) == count


def test_two_publications_equal_threshold_all_boundaries(tmp_path):
    first = write_artifact(tmp_path, artifact())
    second = write_artifact(tmp_path, artifact("publication-102"))
    request = series_request()
    result = native_model(evaluate_release_series(request, evidence_store_dir=tmp_path))
    assert result["state"] == "continuous"
    assert result["reasons"] == []
    assert result["request"] == request
    assert result["request_sha256"] == hashlib.sha256(canonical_bytes(request, 4096)).hexdigest()
    assert [row["boundary"] for row in result["gaps"]] == ["start", "between", "end"]
    assert [row["elapsed_microseconds"] for row in result["gaps"]] == [86_400_000_000] * 3
    assert [row["allowed_microseconds"] for row in result["gaps"]] == [86_400_000_000] * 3
    assert [row["exceeds_allowed"] for row in result["gaps"]] == [False] * 3
    assert [(row["left_event_index"], row["right_event_index"]) for row in result["gaps"]] == [
        (None, 0),
        (0, 1),
        (1, None),
    ]
    assert [row["release_id"] for row in result["events"]] == [101, 102]
    assert [row["stored_file_sha256"] for row in result["records"]] == [
        hashlib.sha256(first.read_bytes()).hexdigest(),
        hashlib.sha256(second.read_bytes()).hexdigest(),
    ]


def test_one_microsecond_excess_is_a_gap(tmp_path):
    write_artifact(tmp_path, artifact())
    write_artifact(tmp_path, artifact("publication-102"))
    result = native_model(
        evaluate_release_series(series_request(window_start="1999-12-30T23:59:59.999999Z"), evidence_store_dir=tmp_path)
    )
    assert result["state"] == "gapped"
    assert result["reasons"] == ["gap_exceeds_allowed"]
    assert result["gaps"][0]["elapsed_microseconds"] == 86_400_000_001
    assert result["gaps"][0]["exceeds_allowed"] is True


@pytest.mark.parametrize(
    "channel,eligibility,reasons",
    [
        ("all_published", "eligible", []),
        ("full_releases", "channel_excluded", ["prerelease_excluded"]),
    ],
)
def test_coherent_prerelease_has_exact_ratified_reason(tmp_path, channel, eligibility, reasons):
    write_artifact(tmp_path, artifact("publication-103-prerelease"))
    result = native_model(evaluate_release_series(series_request(channel=channel), evidence_store_dir=tmp_path))
    assert result["events"][0]["eligibility"] == eligibility
    assert result["events"][0]["reasons"] == reasons
    assert result["state"] == "insufficient"


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"node_id": "different"}, "node_id_changed"),
        ({"published_at": "2000-01-02T00:00:00Z"}, "publication_instant_changed"),
        ({"published_at": None}, "publication_time_unqualified"),
        ({"draft": True}, "draft_changed_to_true"),
    ],
)
def test_material_conflict_outside_window_still_wins(tmp_path, change, reason):
    parent = artifact()
    facts = copy.deepcopy(parent["content"]["selected_facts"])
    facts.update(change)
    first = artifact("observation-101")["content"]["first_observation"]
    observation = build_observation(facts, first, parent)
    write_artifact(tmp_path, parent)
    write_artifact(tmp_path, observation)
    result = native_model(
        evaluate_release_series(
            series_request(window_start="2000-02-01T00:00:00Z", window_end="2000-02-02T00:00:00Z"),
            evidence_store_dir=tmp_path,
        )
    )
    assert result["discovery"]["status"] == "complete"
    assert result["state"] == "conflict"
    assert result["reasons"] == ["source_conflict"]
    assert result["events"][0]["in_window"] is False
    assert result["events"][0]["reasons"] == [reason]
    assert result["gaps"] == []


@pytest.mark.parametrize("channel,expected", [("all_published", "eligible"), ("full_releases", "conflict")])
def test_prerelease_flip_is_channel_specific(tmp_path, channel, expected):
    parent = artifact()
    facts = copy.deepcopy(parent["content"]["selected_facts"])
    facts["prerelease"] = True
    write_artifact(tmp_path, parent)
    write_artifact(
        tmp_path, build_observation(facts, artifact("observation-101")["content"]["first_observation"], parent)
    )
    result = native_model(evaluate_release_series(series_request(channel=channel), evidence_store_dir=tmp_path))
    assert result["events"][0]["eligibility"] == expected
    assert result["events"][0]["reasons"] == ([] if channel == "all_published" else ["prerelease_changed"])


def test_distinct_release_ids_at_equal_instants_count_twice(tmp_path):
    first = artifact()
    second = artifact("publication-102")
    facts = second["content"]["selected_facts"]
    facts["published_at"] = first["content"]["selected_facts"]["published_at"]
    equal = build_publication(facts, second["content"]["first_observation"])
    write_artifact(tmp_path, first)
    write_artifact(tmp_path, equal)
    result = native_model(
        evaluate_release_series(
            series_request(window_start="2000-01-01T00:00:00Z", window_end="2000-01-02T00:00:00Z"),
            evidence_store_dir=tmp_path,
        )
    )
    assert result["state"] == "continuous"
    assert len(result["events"]) == 2
    assert [row["elapsed_microseconds"] for row in result["gaps"]] == [0, 0, 86_400_000_000]


def test_unqualified_store_has_no_partial_tables(tmp_path):
    write_artifact(tmp_path, artifact())
    broken = tmp_path / artifact("publication-102")["id"] / "v1.json"
    broken.parent.mkdir()
    broken.write_bytes(b'{"bad":')
    result = native_model(evaluate_release_series(series_request(), evidence_store_dir=tmp_path))
    assert result["state"] == "unavailable"
    assert result["reasons"] == ["store_record_invalid"]
    assert result["events"] == result["records"] == result["gaps"] == []


def test_no_bundled_registry_or_legacy_discovery(tmp_path, monkeypatch):
    from evidentia_core import evidence_store
    from evidentia_core.conmon import calendar, series

    def forbidden(*args, **kwargs):
        raise AssertionError("Unbounded or registry seam used")

    monkeypatch.setattr(calendar, "get_cadence", forbidden)
    monkeypatch.setattr(series, "get_cadence", forbidden)
    monkeypatch.setattr(evidence_store, "iter_artifacts", forbidden)
    monkeypatch.setattr(evidence_store, "list_lineage", forbidden)
    result = native_model(evaluate_release_series(series_request(), evidence_store_dir=tmp_path))
    assert result["state"] == "insufficient"


def test_final_model_validation_remains_inside_original_budget(tmp_path, monkeypatch):
    from evidentia_core.release_cadence import _series
    from evidentia_core.release_cadence._contracts import ReleaseSeriesResult
    from evidentia_core.release_cadence._limits import ReleaseFailure

    original_start = _series.start_budget
    original_validate = ReleaseSeriesResult.model_validate_json
    budgets = []

    def capture_budget():
        value = original_start()
        budgets.append(value)
        return value

    def drift(cls, raw, **kwargs):
        checked = original_validate(raw, **kwargs)
        object.__setattr__(budgets[0], "deadline", budgets[0].deadline + 100.0)
        return checked

    monkeypatch.setattr(_series, "start_budget", capture_budget)
    monkeypatch.setattr(ReleaseSeriesResult, "model_validate_json", classmethod(drift))
    with pytest.raises(ReleaseFailure, match="release"):
        evaluate_release_series(series_request(), evidence_store_dir=tmp_path)
    assert len(budgets) == 1


def test_wire_mutation_cannot_override_retained_record_authority(tmp_path, monkeypatch):
    from evidentia_core.release_cadence import _series
    from evidentia_core.release_cadence._limits import ReleaseFailure

    write_artifact(tmp_path, artifact())
    original = _series._series_value
    calls = 0

    def mutate(*args, **kwargs):
        nonlocal calls
        value = original(*args, **kwargs)
        calls += 1
        if calls == 1:
            value["records"][0]["stored_file_sha256"] = "0" * 64
        return value

    monkeypatch.setattr(_series, "_series_value", mutate)
    with pytest.raises(ReleaseFailure):
        evaluate_release_series(series_request(), evidence_store_dir=tmp_path)
    assert calls == 2


# SR1-SR7: immutable validated captures remain local to one series operation.
def test_series_reuses_only_its_owned_validated_bytes(tmp_path, monkeypatch):
    import hashlib

    from evidentia_core.release_cadence import _series

    source = artifact()
    target = write_artifact(tmp_path, source)
    validate, reconstruct = _series.validate_artifact, _series._series_value
    validations, callbacks, phases = [], [], []

    def observed(*args, **kwargs):
        validations.append(args[0]["id"])
        return validate(*args, **kwargs)

    def rebuilt(*args, **kwargs):
        callbacks.append(kwargs["artifact_from_source"])
        phases.append(args[2])
        return reconstruct(*args, **kwargs)

    monkeypatch.setattr(_series, "validate_artifact", observed)
    monkeypatch.setattr(_series, "_series_value", rebuilt)
    for _ in range(2):
        result = native_model(evaluate_release_series(series_request(), evidence_store_dir=tmp_path))
        assert result["state"] == "insufficient" and result["gaps"] == []
        assert result["events"][0]["event_id"] == source["id"]
        assert result["records"][0]["stored_file_sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
        assert result["records"][0]["content_sha256"] == source["content_hash"]
        assert result["records"][0]["selected_facts_sha256"] == source["content"]["selected_facts_sha256"]
    assert validations == [source["id"], source["id"]]
    assert len(phases) == 4 and all(phase == phases[0] for phase in phases)
    assert callbacks[0] is callbacks[1] and callbacks[2] is callbacks[3] and callbacks[0] is not callbacks[2]
    for callback in callbacks:
        cells = dict(zip(callback.__code__.co_freevars, callback.__closure__, strict=True))
        assert cells["retained"].cell_contents == {}


@pytest.mark.parametrize("when", ["before_build", "after_build"])
def test_mutable_artifact_lent_to_first_reconstruction_cannot_change_authority(tmp_path, monkeypatch, when):
    from evidentia_core.release_cadence import _series
    from evidentia_core.release_cadence._limits import ReleaseFailure

    source = artifact()
    write_artifact(tmp_path, source)
    original = _series._series_value
    calls = 0
    lent = []

    def reconstructed(*args, **kwargs):
        nonlocal calls
        calls += 1
        resolver = kwargs["artifact_from_source"]

        def borrowed(relative, raw):
            value = resolver(relative, raw)
            lent.append(value)
            if calls == 1 and when == "before_build":
                value["content"]["selected_facts_sha256"] = "0" * 64
            return value

        kwargs["artifact_from_source"] = borrowed
        result = original(*args, **kwargs)
        if calls == 1 and when == "after_build":
            lent[0]["content"]["selected_facts_sha256"] = "0" * 64
        return result

    monkeypatch.setattr(_series, "_series_value", reconstructed)
    if when == "before_build":
        with pytest.raises(ReleaseFailure):
            evaluate_release_series(series_request(), evidence_store_dir=tmp_path)
    else:
        result = native_model(evaluate_release_series(series_request(), evidence_store_dir=tmp_path))
        assert result["records"][0]["selected_facts_sha256"] == source["content"]["selected_facts_sha256"]
    assert calls == 2 and lent[0] is not lent[1]
    assert lent[1]["content"]["selected_facts_sha256"] == source["content"]["selected_facts_sha256"]


@pytest.mark.parametrize("change", ["formatting", "malformed", "path", "raw_subclass", "path_subclass"])
def test_second_series_source_changes_cannot_use_cached_validation(tmp_path, monkeypatch, change):
    from evidentia_core.release_cadence import _series
    from evidentia_core.release_cadence._limits import ReleaseFailure

    write_artifact(tmp_path, artifact())
    original, validate = _series._series_value, _series.validate_artifact
    calls, validations = 0, 0
    callbacks = []

    class RawTrap(bytes):
        def __eq__(self, other):
            callbacks.append("bytes equality")
            raise AssertionError("untrusted equality")

    class PathTrap(str):
        def __hash__(self):
            callbacks.append("path hash")
            raise AssertionError("untrusted hash")

    def observed(*args, **kwargs):
        nonlocal validations
        validations += 1
        return validate(*args, **kwargs)

    def changed(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            updated = list(args)
            relative, raw = updated[2][0]
            if change == "formatting":
                raw += b" "
            elif change == "malformed":
                raw = b'{"incomplete"'
            elif change == "path":
                relative = "11111111-1111-5111-8111-111111111111/v1.json"
            elif change == "raw_subclass":
                raw = RawTrap(raw)
            else:
                relative = PathTrap(relative)
            updated[2] = ((relative, raw),)
            args = tuple(updated)
        return original(*args, **kwargs)

    monkeypatch.setattr(_series, "validate_artifact", observed)
    monkeypatch.setattr(_series, "_series_value", changed)
    with pytest.raises(ReleaseFailure):
        evaluate_release_series(series_request(), evidence_store_dir=tmp_path)
    assert calls == 2 and callbacks == []
    assert validations == (2 if change in {"formatting", "path"} else 1)


@pytest.mark.parametrize("phase", ["first_validate", "first_capture", "second_restore"])
def test_series_capture_cancellation_preserves_primary_and_clears_owned_values(tmp_path, monkeypatch, phase):
    import sys

    from evidentia_core.release_cadence import _series
    from evidentia_core.release_cadence._limits import Budget

    write_artifact(tmp_path, artifact())
    validate, encode, loads, check = (
        _series.validate_artifact,
        _series.canonical_bytes,
        _series.json.loads,
        Budget.check,
    )
    primary = KeyboardInterrupt("synthetic series capture cancellation")
    restored = False
    owned = []

    def fail_validation(*args, **kwargs):
        if phase == "first_validate":
            raise primary
        return validate(*args, **kwargs)

    def fail_capture(*args, **kwargs):
        result = encode(*args, **kwargs)
        if phase == "first_capture" and sys._getframe(1).f_code.co_name == "artifact_from_source":
            owned.append(args[0])
            raise primary
        return result

    def observe_restore(*args, **kwargs):
        nonlocal restored
        value = loads(*args, **kwargs)
        if phase == "second_restore" and sys._getframe(1).f_code.co_name == "artifact_from_source":
            restored = True
            owned.append(value)
        return value

    def fail_after_restore(self, reserve=0):
        if restored:
            raise primary
        return check(self, reserve)

    monkeypatch.setattr(_series, "validate_artifact", fail_validation)
    monkeypatch.setattr(_series, "canonical_bytes", fail_capture)
    monkeypatch.setattr(_series.json, "loads", observe_restore)
    monkeypatch.setattr(Budget, "check", fail_after_restore)
    with pytest.raises(KeyboardInterrupt) as found:
        evaluate_release_series(series_request(), evidence_store_dir=tmp_path)
    assert found.value is primary
    frames = {}
    trace = found.value.__traceback__
    while trace is not None:
        if trace.tb_frame.f_code.co_name in {"artifact_from_source", "_evaluate_wire"}:
            frames[trace.tb_frame.f_code.co_name] = trace.tb_frame.f_locals
        trace = trace.tb_next
    state = frames["artifact_from_source"]
    assert state["cached"] is state["encoded"] is state["artifact"] is None and state["raw"] == b""
    assert frames["_evaluate_wire"]["retained"] == {}
    assert all(value == {} for value in owned)


# PC1-PC8: parent relationships use operation-owned immutable artifact captures.
def test_every_parent_relation_remains_in_all_three_phases(tmp_path, monkeypatch):
    from evidentia_core.release_cadence import _series, _store

    write_artifact(tmp_path, artifact())
    write_artifact(tmp_path, artifact("observation-101"))
    validations, relations = [], []
    for module, label in ((_store, "discovery"), (_series, "series")):
        original_validate, original_relation = module.validate_artifact, module._parent_relations

        def validate(*args, _original=original_validate, _label=label, **kwargs):
            validations.append(_label)
            return _original(*args, **kwargs)

        def relation(*args, _original=original_relation, _label=label, **kwargs):
            relations.append(_label)
            return _original(*args, **kwargs)

        monkeypatch.setattr(module, "validate_artifact", validate)
        monkeypatch.setattr(module, "_parent_relations", relation)
    result = native_model(evaluate_release_series(series_request(), evidence_store_dir=tmp_path))
    assert result["state"] == "insufficient" and len(result["records"]) == 2
    assert validations == ["discovery", "discovery", "series", "series"]
    assert relations == ["discovery", "series", "series"]
    assert result["events"][0]["observation_count"] == 1


@pytest.mark.parametrize("side", ["child", "parent"])
@pytest.mark.parametrize("change", ["raw", "canonical", "path", "raw_subclass", "canonical_subclass", "path_subclass"])
def test_discovery_parent_guard_refuses_forged_record_capture(tmp_path, monkeypatch, side, change):
    import sys
    from dataclasses import replace

    from evidentia_core.release_cadence import _store
    from evidentia_core.release_cadence._limits import ReleaseFailure

    write_artifact(tmp_path, artifact())
    write_artifact(tmp_path, artifact("observation-101"))
    original = _store._inventory_pass
    calls, callback_calls = [], []

    class BytesTrap(bytes):
        def __eq__(self, other):
            callback_calls.append("bytes equality")
            raise AssertionError("Foreign bytes equality")

    class PathTrap(str):
        def __hash__(self):
            callback_calls.append("path hash")
            raise AssertionError("Foreign path hash")

    def inventory(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(True)
        if len(calls) == 2:
            check_pair = sys._getframe(1).f_locals["check_record_parent"]
            records = result[1]
            parent = next(
                record for record in records if record.native()["content"]["record_kind"] == "release_publication"
            )
            child = next(record for record in records if record is not parent)
            target = child if side == "child" else parent
            field, value = {
                "raw": ("raw", target.raw + b" "),
                "canonical": ("artifact_bytes", b"{}"),
                "path": ("relative_path", "11111111-1111-5111-8111-111111111111/v1.json"),
                "raw_subclass": ("raw", BytesTrap(target.raw)),
                "canonical_subclass": ("artifact_bytes", BytesTrap(target.artifact_bytes)),
                "path_subclass": ("relative_path", PathTrap(target.relative_path)),
            }[change]
            forged = replace(target, **{field: value})
            with pytest.raises(ReleaseFailure):
                check_pair(forged if side == "child" else child, forged if side == "parent" else parent)
        return result

    monkeypatch.setattr(_store, "_inventory_pass", inventory)
    result = native_model(evaluate_release_series(series_request(), evidence_store_dir=tmp_path))
    assert result["state"] == "insufficient" and callback_calls == [] and len(calls) == 2


@pytest.mark.parametrize("side", ["child", "parent"])
@pytest.mark.parametrize("change", ["raw", "path", "raw_subclass", "path_subclass"])
def test_series_parent_guard_refuses_forged_raw_binding(tmp_path, monkeypatch, side, change):
    import json

    from evidentia_core.release_cadence import _series
    from evidentia_core.release_cadence._limits import ReleaseFailure

    parent_value, child_value = artifact(), artifact("observation-101")
    write_artifact(tmp_path, parent_value)
    write_artifact(tmp_path, child_value)
    original, calls, callbacks = _series._series_value, [], []

    class BytesTrap(bytes):
        def __eq__(self, other):
            callbacks.append("bytes equality")
            raise AssertionError("Foreign equality")

    class PathTrap(str):
        def __hash__(self):
            callbacks.append("path hash")
            raise AssertionError("Foreign hash")

    def reconstruct(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(True)
        if len(calls) == 1:
            records = {json.loads(raw)["id"]: (relative, raw) for relative, raw in args[2]}
            child_path, child_raw = records[child_value["id"]]
            parent_path, parent_raw = records[parent_value["id"]]
            values = [child_path, child_raw, parent_path, parent_raw]
            offset = 0 if side == "child" else 2
            if change == "raw":
                values[offset + 1] += b" "
            elif change == "path":
                values[offset] = "11111111-1111-5111-8111-111111111111/v1.json"
            elif change == "raw_subclass":
                values[offset + 1] = BytesTrap(values[offset + 1])
            else:
                values[offset] = PathTrap(values[offset])
            with pytest.raises(ReleaseFailure):
                kwargs["parent_from_source"](*values)
        return result

    monkeypatch.setattr(_series, "_series_value", reconstruct)
    result = native_model(evaluate_release_series(series_request(), evidence_store_dir=tmp_path))
    assert result["state"] == "insufficient" and callbacks == [] and len(calls) == 2


@pytest.mark.parametrize("owner", ["discovery", "series"])
def test_detached_pair_mutation_cannot_change_published_source(tmp_path, monkeypatch, owner):
    from evidentia_core.release_cadence import _series, _store

    parent, child = artifact(), artifact("observation-101")
    write_artifact(tmp_path, parent)
    write_artifact(tmp_path, child)
    module = _store if owner == "discovery" else _series
    original, borrowed = module._parent_relations, []

    def detached_pair(left, right):
        original(left, right)
        borrowed.extend([left, right])
        left["content"]["selected_facts"]["name"] = "Harmless detached change"
        right["content"]["selected_facts"]["name"] = "Harmless detached change"

    monkeypatch.setattr(module, "_parent_relations", detached_pair)
    result = native_model(evaluate_release_series(series_request(), evidence_store_dir=tmp_path))
    assert {row["selected_facts_sha256"] for row in result["records"]} == {
        parent["content"]["selected_facts_sha256"],
        child["content"]["selected_facts_sha256"],
    }
    assert all(value == {} for value in borrowed)


@pytest.mark.parametrize("owner", ["discovery", "series"])
@pytest.mark.parametrize(
    "phase", ["before_child_restore", "child_restore", "before_parent_restore", "parent_restore", "relation"]
)
@pytest.mark.parametrize("exception", [KeyboardInterrupt, RuntimeError])
def test_parent_capture_interruption_clears_owned_values(tmp_path, monkeypatch, owner, phase, exception):
    import sys

    from evidentia_core.release_cadence import _series, _store
    from evidentia_core.release_cadence._limits import Budget

    write_artifact(tmp_path, artifact())
    write_artifact(tmp_path, artifact("observation-101"))
    module = _store if owner == "discovery" else _series
    function_name = "check_record_parent" if owner == "discovery" else "parent_from_source"
    original_loads, original_check, original_relation = module.json.loads, Budget.check, module._parent_relations
    primary, owned, armed = exception("Synthetic parent-boundary interruption"), [], [False]

    def restored(*args, **kwargs):
        value = original_loads(*args, **kwargs)
        if sys._getframe(1).f_code.co_name == function_name:
            owned.append(value)
            armed[0] = (phase == "child_restore" and len(owned) == 1) or (phase == "parent_restore" and len(owned) == 2)
        return value

    def check(self, reserve=0):
        frame = sys._getframe(1)
        while frame is not None and frame.f_code.co_name != function_name:
            frame = frame.f_back
        if frame is not None and phase.startswith("before_"):
            state = frame.f_locals
            is_parent = (
                (state["record"] is state["parent_record"])
                if owner == "discovery"
                else (state["relative"] == state["parent_path"])
            )
            if (phase == "before_child_restore" and not is_parent and not owned) or (
                phase == "before_parent_restore" and is_parent and len(owned) == 1
            ):
                raise primary
        if armed[0]:
            raise primary
        return original_check(self, reserve)

    def relation(*args, **kwargs):
        if phase == "relation":
            raise primary
        return original_relation(*args, **kwargs)

    monkeypatch.setattr(module.json, "loads", restored)
    monkeypatch.setattr(Budget, "check", check)
    monkeypatch.setattr(module, "_parent_relations", relation)
    with pytest.raises(exception) as caught:
        evaluate_release_series(series_request(), evidence_store_dir=tmp_path)
    assert caught.value is primary and all(value == {} for value in owned)
    assert (
        len(owned)
        == {
            "before_child_restore": 0,
            "child_restore": 1,
            "before_parent_restore": 1,
            "parent_restore": 2,
            "relation": 2,
        }[phase]
    )
    frames = {}
    trace = caught.value.__traceback__
    while trace is not None:
        frames[trace.tb_frame.f_code.co_name] = trace.tb_frame.f_locals
        trace = trace.tb_next
    state = frames[function_name]
    assert state["restored"] == [] and state["native"] is state["cached"] is None
    if owner == "discovery":
        assert state["child_record"] is state["parent_record"] is state["record"] is None
        assert frames["discover"]["retained"] == {}
    else:
        assert state["raw"] == state["child_raw"] == state["parent_raw"] == b""
        assert frames["_evaluate_wire"]["retained"] == {}


@pytest.mark.parametrize("owner", ["discovery", "series"])
def test_parent_cleanup_fault_preserves_primary_and_attempts_other_cleanup(tmp_path, monkeypatch, owner):
    from evidentia_core.release_cadence import _series, _store

    write_artifact(tmp_path, artifact())
    write_artifact(tmp_path, artifact("observation-101"))
    module = _store if owner == "discovery" else _series
    original_discard = module._discard
    primary, secondary = KeyboardInterrupt("Synthetic primary"), RuntimeError("Synthetic cleanup fault")
    calls = []

    def fail_relation(*args, **kwargs):
        raise primary

    def discard(value):
        calls.append(type(value))
        if type(value) is list:
            raise secondary
        return original_discard(value)

    monkeypatch.setattr(module, "_parent_relations", fail_relation)
    monkeypatch.setattr(module, "_discard", discard)
    with pytest.raises(KeyboardInterrupt) as caught:
        evaluate_release_series(series_request(), evidence_store_dir=tmp_path)
    assert caught.value is primary and calls == [list, dict]
    # A deliberately failing discard does not support an unconditional zeroization claim.


@pytest.mark.parametrize("owner", ["discovery", "series"])
@pytest.mark.parametrize("change", ["expiry", "reader_drift"])
def test_parent_capture_cannot_extend_original_deadline(tmp_path, monkeypatch, owner, change):
    import sys

    from evidentia_core.release_cadence import _limits, _series, _store
    from evidentia_core.release_cadence._limits import Budget, ReleaseFailure

    write_artifact(tmp_path, artifact())
    write_artifact(tmp_path, artifact("observation-101"))
    module = _store if owner == "discovery" else _series
    function_name = "check_record_parent" if owner == "discovery" else "parent_from_source"
    original_loads, native_clock, original_check = module.json.loads, _limits.time.monotonic, Budget.check
    offset, ready, changed = [0.0], [False], []
    invocation = _limits._start_invocation()
    original_deadline = invocation.budget.deadline

    def restored(*args, **kwargs):
        value = original_loads(*args, **kwargs)
        if sys._getframe(1).f_code.co_name == function_name:
            ready[0] = True
            if change == "expiry":
                offset[0] = 61.0
        return value

    def check(self, reserve=0):
        if ready[0] and change == "reader_drift" and not changed:
            object.__setattr__(invocation.budget, "deadline", original_deadline + 1.0)
            changed.append(True)
        return original_check(self, reserve)

    monkeypatch.setattr(_limits.time, "monotonic", lambda: native_clock() + offset[0])
    monkeypatch.setattr(module.json, "loads", restored)
    monkeypatch.setattr(Budget, "check", check)
    with pytest.raises(ReleaseFailure):
        _series._evaluate_wire(series_request(), tmp_path, _clock=invocation)
    assert ready[0] and (changed == [True] if change == "reader_drift" else offset[0] == 61.0)


def test_disposable_parent_guard_clone_cannot_replace_original_clock(tmp_path, monkeypatch):
    import sys

    from evidentia_core.release_cadence import _limits, _series
    from evidentia_core.release_cadence._limits import Budget, ReleaseFailure

    write_artifact(tmp_path, artifact())
    write_artifact(tmp_path, artifact("observation-101"))
    invocation = _limits._start_invocation()
    original_deadline = invocation.budget.deadline
    original_loads, native_clock, original_check = _series.json.loads, _limits.time.monotonic, Budget.check
    offset, ready, altered = [0.0], [False], []

    def restored(*args, **kwargs):
        value = original_loads(*args, **kwargs)
        if sys._getframe(1).f_code.co_name == "parent_from_source":
            ready[0] = True
        return value

    def check(self, reserve=0):
        if ready[0] and not altered:
            assert self is not invocation.budget
            object.__setattr__(self, "deadline", self.deadline + 120.0)
            altered.append(True)
            offset[0] = 61.0
        return original_check(self, reserve)

    monkeypatch.setattr(_series.json, "loads", restored)
    monkeypatch.setattr(_limits.time, "monotonic", lambda: native_clock() + offset[0])
    monkeypatch.setattr(Budget, "check", check)
    with pytest.raises(ReleaseFailure) as caught:
        _series._evaluate_wire(series_request(), tmp_path, _clock=invocation)
    assert caught.value.reason == "deadline_exceeded"
    assert altered == [True] and invocation.budget.deadline == original_deadline


def test_forty_seven_hours_fifty_nine_minutes_is_a_real_series_gap(tmp_path):
    write_artifact(tmp_path, artifact())
    write_artifact(tmp_path, artifact("publication-102"))
    result = native_model(
        evaluate_release_series(series_request(window_start="1999-12-30T00:00:01Z"), evidence_store_dir=tmp_path)
    )
    assert result["state"] == "gapped"
    assert result["reasons"] == ["gap_exceeds_allowed"]
    assert [row["boundary"] for row in result["gaps"]] == ["start", "between", "end"]
    assert [row["elapsed_microseconds"] for row in result["gaps"]] == [172_799_000_000, 86_400_000_000, 86_400_000_000]
    assert [row["allowed_microseconds"] for row in result["gaps"]] == [86_400_000_000] * 3
    assert [row["exceeds_allowed"] for row in result["gaps"]] == [True, False, False]


@pytest.mark.parametrize(
    "field,value,missing",
    [
        ("interval_days", 0, False),
        ("interval_days", -1, False),
        ("interval_days", 3661, False),
        ("interval_days", True, False),
        ("interval_days", 1.0, False),
        ("interval_days", "1", False),
        ("interval_days", None, True),
        ("tolerance_days", -1, False),
        ("tolerance_days", 3661, False),
        ("tolerance_days", True, False),
        ("tolerance_days", 0.0, False),
        ("tolerance_days", "0", False),
        ("tolerance_days", None, True),
    ],
)
def test_actual_series_policy_refuses_before_discovery(monkeypatch, tmp_path, field, value, missing):
    from evidentia_core.release_cadence import _series
    from evidentia_core.release_cadence._limits import ReleaseFailure

    request, calls = series_request(), []
    if missing:
        del request[field]
    else:
        request[field] = value

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("Invalid policy reached store discovery.")

    monkeypatch.setattr(_series, "discover", forbidden)
    with pytest.raises(ReleaseFailure) as caught:
        evaluate_release_series(request, evidence_store_dir=tmp_path)
    assert caught.value.reason == "invalid_request" and calls == []


@pytest.mark.parametrize("interval,tolerance", [(1, 0), (1, 3660), (3660, 0), (3660, 3660)])
def test_actual_series_policy_endpoints_use_local_cadence(monkeypatch, tmp_path, interval, tolerance):
    from evidentia_core.conmon import calendar
    from evidentia_core.release_cadence import _series

    write_artifact(tmp_path, artifact())
    write_artifact(tmp_path, artifact("publication-102"))
    original_interval, original_allowed = _series.interval_days_for, _series.allowed_gap_days
    intervals, allowances = [], []

    def capture_interval(cadence):
        intervals.append(cadence)
        return original_interval(cadence)

    def capture_allowed(cadence, when, permitted):
        allowances.append((cadence, permitted))
        return original_allowed(cadence, when, permitted)

    def forbidden(*args, **kwargs):
        raise AssertionError("Operator policy touched the shared cadence registry.")

    monkeypatch.setattr(calendar, "get_cadence", forbidden)
    monkeypatch.setattr(calendar, "register_cadence", forbidden)
    monkeypatch.setattr(_series, "interval_days_for", capture_interval)
    monkeypatch.setattr(_series, "allowed_gap_days", capture_allowed)
    result = native_model(
        evaluate_release_series(
            series_request(interval_days=interval, tolerance_days=tolerance), evidence_store_dir=tmp_path
        )
    )
    assert result["state"] == "continuous" and len(result["gaps"]) == 3
    assert [gap["allowed_microseconds"] for gap in result["gaps"]] == [(interval + tolerance) * 86_400_000_000] * 3
    assert intervals and allowances
    for cadence in intervals:
        assert cadence.slug == cadence.activity == "upstream-release-publication"
        assert cadence.framework == "operator-policy" and cadence.citation is None
        assert cadence.frequency == "custom" and cadence.interval_days == interval
    assert all(permitted == tolerance for _, permitted in allowances)


@pytest.mark.parametrize("case", ["equal", "reversed", "future", "exact_36600_days", "one_microsecond_over"])
def test_actual_series_window_boundaries(tmp_path, monkeypatch, case):
    from datetime import UTC, datetime, timedelta

    from evidentia_core.release_cadence import _series
    from evidentia_core.release_cadence._limits import ReleaseFailure

    start = datetime(1900, 1, 1, tzinfo=UTC)
    end = start + timedelta(days=36600)
    if case == "one_microsecond_over":
        end += timedelta(microseconds=1)
    if case == "equal":
        end = start
    if case == "reversed":
        end = start - timedelta(microseconds=1)
    if case == "future":
        start, end = datetime(9999, 1, 1, tzinfo=UTC), datetime(9999, 1, 3, tzinfo=UTC)
    request = series_request(
        window_start=start.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        window_end=end.isoformat(timespec="microseconds").replace("+00:00", "Z"),
    )
    if case == "exact_36600_days":
        write_artifact(tmp_path, artifact())
        write_artifact(tmp_path, artifact("publication-102"))
        result = native_model(evaluate_release_series(request, evidence_store_dir=tmp_path))
        assert result["state"] == "gapped" and len(result["gaps"]) == 3
        assert sum(gap["elapsed_microseconds"] for gap in result["gaps"]) == 3_162_240_000_000_000
    else:
        calls = []

        def forbidden(*args, **kwargs):
            calls.append(True)
            raise AssertionError("Invalid window reached discovery.")

        monkeypatch.setattr(_series, "discover", forbidden)
        with pytest.raises(ReleaseFailure) as caught:
            evaluate_release_series(request, evidence_store_dir=tmp_path)
        assert caught.value.reason == "invalid_request" and calls == []


def test_both_series_window_endpoints_are_inclusive(tmp_path):
    write_artifact(tmp_path, artifact())
    write_artifact(tmp_path, artifact("publication-102"))
    result = native_model(
        evaluate_release_series(
            series_request(window_start="2000-01-01T00:00:00Z", window_end="2000-01-02T00:00:00Z"),
            evidence_store_dir=tmp_path,
        )
    )
    assert result["state"] == "continuous"
    assert [event["in_window"] for event in result["events"]] == [True, True]
    assert [gap["elapsed_microseconds"] for gap in result["gaps"]] == [0, 86_400_000_000, 0]
    assert [gap["exceeds_allowed"] for gap in result["gaps"]] == [False] * 3


def test_two_simultaneous_operator_policies_do_not_share_or_mutate_registry(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from evidentia_core.conmon import calendar

    before = {key: value.model_dump(mode="json") for key, value in calendar._REGISTRY.items()}
    roots = [tmp_path / "one", tmp_path / "two"]
    for root in roots:
        write_artifact(root, artifact())
        write_artifact(root, artifact("publication-102"))

    def forbidden(*args, **kwargs):
        raise AssertionError("Concurrent local policy touched shared registry.")

    monkeypatch.setattr(calendar, "get_cadence", forbidden)
    monkeypatch.setattr(calendar, "register_cadence", forbidden)
    ready = Barrier(2)

    def execute(index):
        ready.wait(timeout=10)
        return native_model(
            evaluate_release_series(
                series_request(interval_days=index + 1, tolerance_days=index, window_start="1999-12-30T00:00:01Z"),
                evidence_store_dir=roots[index],
            )
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(execute, [0, 1]))
    assert [value["state"] for value in results] == ["gapped", "continuous"]
    assert [value["gaps"][0]["allowed_microseconds"] for value in results] == [86_400_000_000, 259_200_000_000]
    assert {key: value.model_dump(mode="json") for key, value in calendar._REGISTRY.items()} == before
