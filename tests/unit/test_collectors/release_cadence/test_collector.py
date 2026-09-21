"""Complete poll lifecycle over synthetic pages and temporary evidence stores."""

from datetime import UTC, datetime

import pytest
from evidentia_collectors.release_cadence import _traversal, collector
from evidentia_core.release_cadence._json import load_json
from evidentia_core.release_cadence._limits import ReleaseFailure

from ._helpers import encoded, pages, request, row

NOW = datetime(2001, 1, 1, tzinfo=UTC)


@pytest.fixture(autouse=True)
def local_only(monkeypatch):
    import evidentia_core.evidence_store as store

    monkeypatch.setattr(store, "_resolve_auto_mirror_backend", lambda: None)
    monkeypatch.setattr(collector, "_utc_now", lambda: NOW)
    monkeypatch.setattr(_traversal, "_utc_now", lambda: NOW)


def test_observation_never_touches_store(monkeypatch):
    calls = pages(monkeypatch, _traversal, [(encoded([row()]), ())])

    class Forbidden:
        def __str__(self):
            raise AssertionError("store path callback")

        def __fspath__(self):
            raise AssertionError("store path callback")

    value = load_json(collector.poll_release_bytes(request(), evidence_store_dir=Forbidden()), 16_777_216)
    assert len(calls) == 1 and value["collection_state"] == "complete"
    assert value["persistence"]["state"] == "not_requested"
    assert value["discovery"]["status"] == "not_requested"
    assert value["outcomes"] == [] and value["counters"]["total_store_raw_bytes_observed"] == 0


def test_null_empty_complete_and_requested_empty_store(monkeypatch, tmp_path):
    pages(monkeypatch, _traversal, [(b"[]", ())])
    value = load_json(collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path), 16_777_216)
    assert value["collection_state"] == "complete" and value["rows"] == []
    assert value["persistence"]["state"] == "complete" and value["persistence"]["attempted_calls"] == 0
    assert value["discovery"]["status"] == "complete"
    assert list(tmp_path.iterdir()) == []


def test_full_channel_preserves_excluded_and_unknown_time_rows(monkeypatch):
    pages(
        monkeypatch,
        _traversal,
        [
            (
                encoded(
                    [
                        row(1, prerelease=True),
                        row(2, draft=True),
                        row(3, published_at=None),
                        row(4, published_at="2002-01-01T00:00:00Z"),
                        row(5, published_at="not-time"),
                    ]
                ),
                (),
            )
        ],
    )
    value = load_json(collector.poll_release_bytes(request()), 16_777_216)
    assert [r["metadata"]["eligibility_reasons"] for r in value["rows"]] == [
        ["prerelease_excluded"],
        ["draft"],
        ["publication_time_absent"],
        ["publication_time_future"],
        ["publication_time_unsupported"],
    ]
    assert all(not r["metadata"]["initial_publication_eligible"] for r in value["rows"])


def test_partial_source_has_no_clock_or_store(monkeypatch):
    from .test_http import link

    pages(monkeypatch, _traversal, [(encoded([row()]), (link("2"),)), ReleaseFailure("upstream_not_found")])
    value = load_json(collector.poll_release_bytes(request(persist=True), evidence_store_dir=object()), 16_777_216)
    assert value["collection_state"] == "partial"
    assert value["clocks"]["traversal_completed_at"] is None
    assert value["rows"][0]["metadata"]["eligibility_reasons"] == []
    assert value["rows"][0]["metadata"]["initial_publication_eligible"] is False
    assert value["persistence"]["state"] == "not_started" and value["persistence"]["attempted_calls"] == 0
    assert value["discovery"]["status"] == "not_started"


def test_create_then_unchanged_repeat_preserves_first_receipt(monkeypatch, tmp_path):
    pages(monkeypatch, _traversal, [(encoded([row()]), ())])
    first = load_json(collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path), 16_777_216)
    assert first["persistence"]["state"] == "complete"
    assert [o["outcome"] for o in first["outcomes"]] == ["created", "not_applicable"]
    publication_id = first["events"][0]["event_id"]
    before = (tmp_path / publication_id / "v1.json").read_bytes()
    second = load_json(collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path), 16_777_216)
    assert second["persistence"]["state"] == "complete" and second["persistence"]["attempted_calls"] == 0
    assert [o["outcome"] for o in second["outcomes"]] == ["already_saved", "not_applicable"]
    assert (tmp_path / publication_id / "v1.json").read_bytes() == before
    assert second["outcomes"][0]["verified_record"]["first_observation_poll_id"] == first["clocks"]["poll_id"]


def test_changed_known_parent_records_observation_even_when_now_draft(monkeypatch, tmp_path):
    pages(monkeypatch, _traversal, [(encoded([row()]), ())])
    first = load_json(collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path), 16_777_216)
    pages(monkeypatch, _traversal, [(encoded([row(draft=True, published_at=None)]), ())])
    changed = load_json(collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path), 16_777_216)
    assert changed["persistence"]["state"] == "complete"
    assert [o["outcome"] for o in changed["outcomes"]] == ["already_saved", "created"]
    assert changed["events"][0]["event_id"] == first["events"][0]["event_id"]
    assert changed["events"][0]["blocks_all_published"] is True
    assert changed["rows"][0]["metadata"]["initial_publication_eligible"] is False


def test_prepared_invocation_is_single_use_and_uses_original_budget(monkeypatch):
    calls = pages(monkeypatch, _traversal, [(b"[]", ())])
    prepared = collector._prepare_poll()
    operation = prepared.begin(request())
    assert load_json(operation.output_bytes(), 16_777_216)["collection_state"] == "complete"
    with pytest.raises(ReleaseFailure):
        prepared.begin(request())
    assert len(calls) == 1


def test_request_alias_and_callbacks_refuse_before_transport(monkeypatch):
    calls = pages(monkeypatch, _traversal, [(b"[]", ())])

    class Callback(str):
        def lower(self):
            raise AssertionError("source callback")

    with pytest.raises((ReleaseFailure, ValueError)):
        collector.poll_release_bytes({**request(), "owner": Callback("allen")})
    assert calls == []


def test_reader_deadline_mutation_is_not_authority(monkeypatch):
    calls = pages(monkeypatch, _traversal, [(b"[]", ())])
    prepared = collector._prepare_poll()
    object.__setattr__(prepared.budget, "deadline", prepared.budget.deadline + 60.0)
    with pytest.raises(ReleaseFailure) as found:
        prepared.begin(request())
    assert found.value.reason == "clock_invalid" and calls == []


def test_renderer_cannot_replace_retained_source(monkeypatch):
    import hashlib
    import json

    from evidentia_core.release_cadence._identity import fact_digest

    pages(monkeypatch, _traversal, [(encoded([row()]), ())])
    original = collector._render

    def forged(*args, **kwargs):
        value = original(*args, **kwargs)
        selected = value["rows"][0]["selected"]
        selected["name"] = "forged source"
        value["rows"][0]["metadata"]["selected_facts_sha256"] = fact_digest(selected)
        value["counters"]["selected_ccompact_bytes_admitted"] = len(
            json.dumps(selected, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
        )
        assert hashlib.sha256(b"unchanged raw source").hexdigest() != value["pages"][0]["decoded_body_sha256"]
        return value

    monkeypatch.setattr(collector, "_render", forged)
    with pytest.raises(ReleaseFailure):
        collector.poll_release_bytes(request())


def test_factory_cannot_save_replacement_source(monkeypatch, tmp_path):
    pages(monkeypatch, _traversal, [(encoded([row()]), ())])
    original = collector.build_publication

    def forged(selected, first, *, budget):
        selected["name"] = "forged source"
        return original(selected, first, budget=budget)

    monkeypatch.setattr(collector, "build_publication", forged)
    with pytest.raises((ReleaseFailure, ValueError)):
        collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path)
    assert list(tmp_path.iterdir()) == [], "Source binding must refuse before the local save."


def test_first_save_rechecks_fifteen_seconds_after_preparation(monkeypatch, tmp_path):
    import time

    from evidentia_core import evidence_store
    from evidentia_core.release_cadence import _limits, _store

    pages(monkeypatch, _traversal, [(encoded([row()]), ())])
    native_clock = time.monotonic
    offset = [0.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: native_clock() + offset[0])
    original_target = _store.admit_save_target
    calls = []

    def consume_reserve(*args, **kwargs):
        original_target(*args, **kwargs)
        offset[0] = 46.0

    monkeypatch.setattr(_store, "admit_save_target", consume_reserve)
    monkeypatch.setattr(evidence_store, "save_evidence_version_one", lambda *a, **k: calls.append("save"))
    result = load_json(collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path), 16_777_216)
    assert calls == [], "The first irreversible seam requires at least fifteen seconds at that call."
    assert result["persistence"]["state"] == "not_started"
    assert result["persistence"]["stop_reason"] == "deadline_exceeded"


@pytest.mark.parametrize("after_write", [False, True])
def test_ordinary_save_failure_keeps_exact_presence_and_stops(monkeypatch, tmp_path, after_write):
    from evidentia_core import evidence_store

    pages(monkeypatch, _traversal, [(encoded([row(1), row(2)]), ())])
    original = evidence_store.save_evidence_version_one
    calls = []

    def fail(artifact, evidence_store_dir):
        calls.append(artifact.id)
        if after_write:
            original(artifact, evidence_store_dir=evidence_store_dir)
        raise OSError("synthetic save refusal")

    monkeypatch.setattr(evidence_store, "save_evidence_version_one", fail)
    result = load_json(collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path), 16_777_216)
    assert len(calls) == 1 and result["persistence"]["state"] == "partial"
    assert result["outcomes"][0]["save_call"] == "raised"
    assert result["outcomes"][0]["outcome"] == ("present_after_uncertain_save" if after_write else "failed")
    assert all(value["outcome"] == "not_attempted" for value in result["outcomes"][1:])
    assert result["persistence"]["stop_reason"] == "save_failed"
    assert (tmp_path / calls[0] / "v1.json").exists() == after_write


def test_cancellation_after_local_publication_propagates_same_object(monkeypatch, tmp_path):
    from evidentia_core import evidence_store

    pages(monkeypatch, _traversal, [(encoded([row()]), ())])
    original = evidence_store.save_evidence_version_one
    primary = KeyboardInterrupt()
    paths = []

    def cancel(artifact, evidence_store_dir):
        returned = original(artifact, evidence_store_dir=evidence_store_dir)
        paths.append(returned.path)
        raise primary

    monkeypatch.setattr(evidence_store, "save_evidence_version_one", cancel)
    with pytest.raises(KeyboardInterrupt) as found:
        collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path)
    assert found.value is primary and len(paths) == 1 and paths[0].is_file()


def test_unavailable_readback_is_indeterminate_and_no_later_save(monkeypatch, tmp_path):
    from evidentia_core import evidence_store
    from evidentia_core.release_cadence import _store

    pages(monkeypatch, _traversal, [(encoded([row(1), row(2)]), ())])
    original = evidence_store.save_evidence_version_one
    calls = []

    def save(artifact, evidence_store_dir):
        calls.append(artifact.id)
        return original(artifact, evidence_store_dir=evidence_store_dir)

    def unreadable(*args, **kwargs):
        raise ReleaseFailure("store_unavailable")

    monkeypatch.setattr(evidence_store, "save_evidence_version_one", save)
    monkeypatch.setattr(_store, "readback", unreadable)
    result = load_json(collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path), 16_777_216)
    assert len(calls) == 1 and result["persistence"]["state"] == "indeterminate"
    assert result["outcomes"][0]["local_state"] == "local_indeterminate"
    assert all(value["outcome"] == "not_attempted" for value in result["outcomes"][1:])
    assert (tmp_path / calls[0] / "v1.json").is_file()


@pytest.mark.parametrize("state", ["created", "collided", "raised"])
def test_expiry_preserves_prior_slots_and_call_observations(monkeypatch, tmp_path, state):
    import json

    from evidentia_core import evidence_store
    from evidentia_core.release_cadence import _limits, _store

    native_clock = _limits.time.monotonic
    offset = [0.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: native_clock() + offset[0])
    pages(monkeypatch, _traversal, [(encoded([row(1), row(2), row(3)]), ())])
    saved = []
    read = []
    original_save = evidence_store.save_evidence_version_one
    original_read = _store.readback
    primary = OSError("Synthetic second-call failure.")

    def save(artifact, evidence_store_dir):
        saved.append(artifact.id)
        if len(saved) == 1:
            return original_save(artifact, evidence_store_dir=evidence_store_dir)
        if state == "raised":
            offset[0] = 61.0
            raise primary
        value = original_save(artifact, evidence_store_dir=evidence_store_dir)
        if state == "collided":
            value = original_save(artifact, evidence_store_dir=evidence_store_dir)
        offset[0] = 61.0
        return value

    def readback(*args, **kwargs):
        assert offset[0] == 0.0
        read.append(True)
        return original_read(*args, **kwargs)

    monkeypatch.setattr(evidence_store, "save_evidence_version_one", save)
    monkeypatch.setattr(_store, "readback", readback)
    with pytest.raises(_limits._PersistenceExpiry) as found:
        collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path)
    failure = found.value
    assert len(saved) == 2 and len(read) == 1
    assert failure.original_failure.reason == "deadline_exceeded"
    assert failure.save_observations == (
        (0, "returned_created"),
        (2, "raised" if state == "raised" else "returned_" + state),
    )
    assert type(failure.captured_outcomes) is tuple and len(failure.captured_outcomes) == 6
    assert all(type(value) is bytes for value in failure.captured_outcomes)
    retained = [json.loads(value) for value in failure.captured_outcomes]
    assert retained[0]["outcome"] == "created" and retained[0]["local_state"] == "local_verified"
    assert retained[1]["outcome"] == "not_applicable"
    assert all(value["save_call"] == "not_called" for value in retained[2:])
    assert failure.save_failures == ((primary,) if state == "raised" else ())


@pytest.mark.parametrize("primary", [KeyboardInterrupt(), SystemExit(), GeneratorExit()])
def test_expiry_does_not_convert_cancellation_identity(monkeypatch, tmp_path, primary):
    from evidentia_core import evidence_store
    from evidentia_core.release_cadence import _limits

    native_clock = _limits.time.monotonic
    offset = [0.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: native_clock() + offset[0])
    pages(monkeypatch, _traversal, [(encoded([row(1), row(2)]), ())])
    calls = []

    def cancel(*args, **kwargs):
        calls.append(True)
        offset[0] = 61.0
        raise primary

    monkeypatch.setattr(evidence_store, "save_evidence_version_one", cancel)
    with pytest.raises(type(primary)) as found:
        collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path)
    assert found.value is primary and len(calls) == 1


def test_expiry_before_first_save_has_no_persistence_authority(monkeypatch, tmp_path):
    from evidentia_core import evidence_store
    from evidentia_core.release_cadence import _limits, _store

    native_clock = _limits.time.monotonic
    offset = [0.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: native_clock() + offset[0])
    pages(monkeypatch, _traversal, [(encoded([row()]), ())])
    calls = []
    original = _store.admit_save_target

    def expire(*args, **kwargs):
        original(*args, **kwargs)
        offset[0] = 61.0

    monkeypatch.setattr(_store, "admit_save_target", expire)
    monkeypatch.setattr(evidence_store, "save_evidence_version_one", lambda *a, **k: calls.append(True))
    with pytest.raises(ReleaseFailure) as found:
        collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path)
    assert found.value.code == "operation_failed" and calls == []


@pytest.mark.parametrize("phase", ["before_wire", "after_wire", "after_validated_copy", "final_check"])
@pytest.mark.parametrize("replacement", ["s", "changed-source-length"])
def test_final_wire_never_publishes_mutated_working_source(monkeypatch, phase, replacement):
    import json

    from evidentia_core.release_cadence._identity import fact_digest

    source = row(name="o")
    pages(monkeypatch, _traversal, [(encoded([source]), ())])
    original_encode = collector.canonical_bytes
    saved = []
    hits = []
    full_calls = 0

    def mutate(value):
        facts = value["rows"][0]["selected"]
        facts["name"] = replacement
        value["rows"][0]["metadata"]["selected_facts_sha256"] = fact_digest(facts)
        value["counters"]["selected_ccompact_bytes_admitted"] = len(
            json.dumps(facts, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
        )
        hits.append(True)

    def encode(value, *args, **kwargs):
        nonlocal full_calls
        complete = type(value) is dict and value.get("schema_version") == "release-poll-result-v1"
        if complete:
            full_calls += 1
            # The first result-shaped encoding captures _base. The second captures the final wire.
            if full_calls == 2 and phase == "before_wire":
                mutate(value)
        wire = original_encode(value, *args, **kwargs)
        if complete and full_calls == 2:
            saved.append(wire)
            if phase == "after_wire":
                mutate(value)
        elif complete and full_calls == 3 and phase == "after_validated_copy":
            mutate(value)
        return wire

    monkeypatch.setattr(collector, "canonical_bytes", encode)
    original_seal = collector._seal_result

    def seal(base, state, completed, budget, check):
        if phase != "final_check":
            return original_seal(base, state, completed, budget, check)
        calls = 0

        def final_check(reserve):
            nonlocal calls
            check(reserve)
            calls += 1
            if calls == 2:
                # The returned wire is immutable even if unrelated retained work is changed late.
                source["name"] = replacement
                hits.append(True)

        return original_seal(base, state, completed, budget, final_check)

    monkeypatch.setattr(collector, "_seal_result", seal)
    try:
        wire = collector.poll_release_bytes(request())
    except (ReleaseFailure, ValueError):
        assert phase in {"before_wire", "after_validated_copy"}
    else:
        value = json.loads(wire)
        assert value["rows"][0]["selected"]["name"] == "o"
        assert value["rows"][0]["metadata"]["selected_facts_sha256"] == fact_digest(row(name="o"))
        assert value["request"] == request() and wire in saved
    assert hits == [True]


@pytest.mark.parametrize("reason", ["deadline_exceeded", "store_record_invalid"])
def test_failed_planning_never_fabricates_unstarted_discovery(monkeypatch, tmp_path, reason):
    import json
    from uuid import uuid4

    from evidentia_core import evidence_store
    from evidentia_core.models.evidence import EvidenceArtifact
    from evidentia_core.release_cadence import _limits

    identifier = str(uuid4())
    ordinary = EvidenceArtifact(
        id=identifier,
        lineage_id=identifier,
        title="Synthetic prewrite discovery",
        evidence_type="repository_metadata",
        source_system="synthetic",
        collected_by="synthetic test",
    )
    directory = tmp_path / identifier
    directory.mkdir()
    raw = ordinary.model_dump_json().encode()
    (directory / "v1.json").write_bytes(raw)
    pages(monkeypatch, _traversal, [(encoded([row()]), ())])
    original_monotonic = _limits.time.monotonic
    elapsed = [0.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: original_monotonic() + elapsed[0])
    calls = []

    def refuse(*args, **kwargs):
        if reason == "deadline_exceeded":
            elapsed[0] = 46.0
        raise ReleaseFailure(reason)

    monkeypatch.setattr(collector, "_prepare_plans", refuse)
    monkeypatch.setattr(evidence_store, "save_evidence_version_one", lambda *args, **kwargs: calls.append(True))
    if reason == "deadline_exceeded":
        result = json.loads(collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path))
        assert result["discovery"]["status"] == "complete" and result["discovery"]["passes"] == 2
        assert result["discovery"]["canonical_files_read"] == 2
        assert result["counters"]["total_store_raw_bytes_observed"] == 2 * len(raw)
        assert result["persistence"]["state"] == "not_started"
        assert result["persistence"]["attempted_calls"] == 0
        assert result["persistence"]["stop_reason"] == reason
        assert result["events"][0]["stored_state"] == "unavailable"
    else:
        with pytest.raises(ReleaseFailure) as found:
            collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path)
        assert found.value.code == "operation_failed" and found.value.reason == reason
    assert calls == []


@pytest.mark.parametrize("kind", ["publication", "observation"])
@pytest.mark.parametrize("position", [0, 1])
@pytest.mark.parametrize("mode", ["raised_absent", "raised_present", "returned_absent", "unreadable"])
def test_each_save_kind_and_position_preserves_prior_effects(monkeypatch, tmp_path, kind, position, mode):
    import copy
    import json

    from evidentia_core import evidence_store
    from evidentia_core.release_cadence import _store

    from tests.unit.test_release_cadence._helpers import artifact, write_artifact

    parents = [artifact("publication-101"), artifact("publication-102")]
    sources = [copy.deepcopy(parent["content"]["selected_facts"]) for parent in parents]
    if kind == "observation":
        for parent, selected in zip(parents, sources, strict=True):
            write_artifact(tmp_path, parent)
            selected["name"] = "Synthetic current source change"
    pages(monkeypatch, _traversal, [(encoded(sources), ())])
    original_save = evidence_store.save_evidence_version_one
    original_readback = _store.readback
    saved = []
    primary = OSError("Synthetic save boundary refusal.")
    target_id = []

    def save(candidate, evidence_store_dir):
        current = len(saved)
        saved.append(candidate.id)
        if current != position:
            return original_save(candidate, evidence_store_dir=evidence_store_dir)
        target_id.append(candidate.id)
        if mode == "raised_absent":
            raise primary
        if mode == "returned_absent":
            return evidence_store.EvidenceVersionOneSaveResult(
                state="created", path=evidence_store_dir / candidate.id / "v1.json"
            )
        returned = original_save(candidate, evidence_store_dir=evidence_store_dir)
        if mode == "raised_present":
            raise primary
        return returned

    def readback(binding, identifier, *args, **kwargs):
        if mode == "unreadable" and target_id == [identifier]:
            raise ReleaseFailure("store_unavailable")
        return original_readback(binding, identifier, *args, **kwargs)

    monkeypatch.setattr(evidence_store, "save_evidence_version_one", save)
    monkeypatch.setattr(_store, "readback", readback)
    selected_request = {**request(persist=True), "owner": "Example", "repository": "Synthetic"}
    value = json.loads(collector.poll_release_bytes(selected_request, evidence_store_dir=tmp_path))
    slot = position * 2 + (kind == "observation")
    outcome = value["outcomes"][slot]
    expected = {
        "raised_absent": ("failed", "local_absent", "save_failed"),
        "raised_present": ("present_after_uncertain_save", "local_verified", "save_failed"),
        "returned_absent": ("conflict", "local_conflict", "save_readback_mismatch"),
        "unreadable": ("indeterminate", "local_indeterminate", "store_unavailable"),
    }[mode]
    assert (outcome["outcome"], outcome["local_state"], outcome["reason"]) == expected
    assert value["persistence"]["state"] == ("indeterminate" if mode == "unreadable" else "partial")
    assert value["persistence"]["attempted_calls"] == position + 1 and len(saved) == position + 1
    assert value["persistence"]["last_attempted_slot"] == slot
    assert value["persistence"]["stop_reason"] == expected[2]
    if position:
        earlier = 1 if kind == "observation" else 0
        assert value["outcomes"][earlier]["outcome"] == "created"
        assert (tmp_path / saved[0] / "v1.json").is_file()
    for later in value["outcomes"][slot + 1 :]:
        assert later["save_call"] == "not_called"
    assert (tmp_path / target_id[0] / "v1.json").exists() == (mode in {"raised_present", "unreadable"})


@pytest.mark.parametrize("different", [False, True])
def test_raced_publication_winner_is_verified_before_conditional_observation(monkeypatch, tmp_path, different):
    import copy
    import json

    from evidentia_core import evidence_store

    from tests.unit.test_release_cadence._helpers import artifact, write_artifact

    winner = artifact("publication-101")
    selected = copy.deepcopy(winner["content"]["selected_facts"])
    if different:
        selected["name"] = "Current facts differ from the raced winner"
    pages(monkeypatch, _traversal, [(encoded([selected]), ())])
    original = evidence_store.save_evidence_version_one
    calls = []
    winner_raw = []

    def race(candidate, evidence_store_dir):
        calls.append(candidate.id)
        if len(calls) == 1:
            winner_raw.append(write_artifact(evidence_store_dir, winner).read_bytes())
        return original(candidate, evidence_store_dir=evidence_store_dir)

    monkeypatch.setattr(evidence_store, "save_evidence_version_one", race)
    selected_request = {**request(persist=True), "owner": "Example", "repository": "Synthetic"}
    value = json.loads(collector.poll_release_bytes(selected_request, evidence_store_dir=tmp_path))
    publication, observation = value["outcomes"]
    assert publication["save_call"] == "returned_collided"
    assert publication["outcome"] == ("existing_different_facts" if different else "already_saved")
    assert (
        publication["verified_record"]["first_observation_poll_id"] == winner["content"]["first_observation"]["poll_id"]
    )
    assert (tmp_path / winner["id"] / "v1.json").read_bytes() == winner_raw[0]
    assert observation["outcome"] == ("created" if different else "not_applicable")
    assert len(calls) == (2 if different else 1)
    assert value["persistence"]["state"] == "complete"
    if different:
        stored = json.loads((tmp_path / calls[1] / "v1.json").read_bytes())
        assert stored["content"]["selected_facts"] == selected
        assert stored["content"]["parent_publication"]["content_sha256"] == winner["content_hash"]


@pytest.mark.parametrize(
    "owner,repository,admitted",
    [
        ("a", "x", True),
        ("a" * 39, "r" * 100, True),
        ("MiXeD", "Case", True),
        ("a" * 40, "x", False),
        ("-a", "x", False),
        ("a-", "x", False),
        ("a", "r" * 101, False),
        ("a", "x.git", False),
        ("a", "x%2Fy", False),
        ("a", "é", False),
    ],
)
def test_declared_repository_endpoints_refuse_before_transport(monkeypatch, owner, repository, admitted):
    calls = pages(monkeypatch, _traversal, [(b"[]", ())])
    selected_request = {**request(), "owner": owner, "repository": repository}
    if admitted:
        value = load_json(collector.poll_release_bytes(selected_request), 16_777_216)
        assert value["request"] == selected_request and value["collection_state"] == "complete"
        assert len(calls) == 1 and calls[0][:2] == (owner.lower(), repository.lower())
    else:
        with pytest.raises(ReleaseFailure) as found:
            collector.poll_release_bytes(selected_request)
        assert found.value.code == "invalid_request" and calls == []


@pytest.mark.parametrize("field", ["created_at", "published_at", "updated_at"])
@pytest.mark.parametrize("size", [128, 129])
def test_each_selected_timestamp_scalar_endpoint(monkeypatch, field, size):
    source = row(**{field: "x" * size})
    pages(monkeypatch, _traversal, [(encoded([source]), ())])
    value = load_json(collector.poll_release_bytes(request()), 16_777_216)
    if size == 128:
        assert value["collection_state"] == "complete" and value["rows"][0]["selected"] == source
        if field == "published_at":
            assert value["rows"][0]["metadata"]["eligibility_reasons"] == ["publication_time_unsupported"]
    else:
        assert value["collection_state"] == "unavailable" and value["terminal_reason"] == "source_field"
        assert value["rows"] == [] and not value["pages"][0]["admitted"]


@pytest.mark.parametrize("fraction,eligible", [("000000", True), ("000001", False)])
def test_publication_equal_completion_and_next_microsecond(monkeypatch, fraction, eligible):
    source = row(published_at="2001-01-01T00:00:00." + fraction + "Z")
    pages(monkeypatch, _traversal, [(encoded([source]), ())])
    value = load_json(collector.poll_release_bytes(request()), 16_777_216)
    assert value["clocks"]["traversal_completed_at"] == "2001-01-01T00:00:00.000000Z"
    metadata = value["rows"][0]["metadata"]
    assert metadata["source_time"]["classification"] == "normalized"
    assert metadata["initial_publication_eligible"] is eligible
    assert metadata["eligibility_reasons"] == ([] if eligible else ["publication_time_future"])


def test_original_budget_expiry_before_begin_starts_no_transport(monkeypatch):
    from evidentia_core.release_cadence import _limits

    now = [100.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: now[0])
    calls = pages(monkeypatch, _traversal, [(b"[]", ())])
    prepared = collector._prepare_poll()
    assert prepared.budget.deadline == 160.0
    now[0] = 145.000001
    # The work cutoff passed, but the original output deadline still has time.
    value = load_json(prepared.begin(request()).output_bytes(), 16_777_216)
    assert prepared.budget.deadline == 160.0 and calls == []
    assert value["collection_state"] == "unavailable"
    assert value["terminal_reason"] == "deadline_exceeded"
    assert value["clocks"]["traversal_completed_at"] is None
    assert value["counters"]["attempts"] == 0 and value["pages"] == value["rows"] == []
    assert value["persistence"]["state"] == "not_requested"
    assert value["persistence"]["attempted_calls"] == 0


@pytest.mark.parametrize("stage", ["fetch", "parse"])
def test_work_expiry_keeps_prior_page_and_starts_no_store(monkeypatch, stage):
    from evidentia_core import evidence_store
    from evidentia_core.release_cadence import _limits

    from .test_http import link

    now = [100.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: now[0])
    calls = pages(monkeypatch, _traversal, [(encoded([row(1)]), (link("2"),)), (encoded([row(2)]), ())])
    original_fetch = _traversal.HttpAttempt.fetch
    original_parse = _traversal.preflight
    parsed = []
    stores = []

    def fetch(attempt, owner, repository, number, **kwargs):
        result = original_fetch(attempt, owner, repository, number, **kwargs)
        if stage == "fetch" and number == 2:
            now[0] = 145.000001
        return result

    def parse(*args, **kwargs):
        result = original_parse(*args, **kwargs)
        parsed.append(True)
        if stage == "parse" and len(parsed) == 2:
            now[0] = 145.000001
        return result

    monkeypatch.setattr(_traversal.HttpAttempt, "fetch", fetch)
    monkeypatch.setattr(_traversal, "preflight", parse)
    monkeypatch.setattr(evidence_store, "save_evidence_version_one", lambda *args, **kwargs: stores.append(True))
    value = load_json(collector.poll_release_bytes(request(persist=True), evidence_store_dir=object()), 16_777_216)
    assert value["collection_state"] == "partial" and value["terminal_reason"] == "deadline_exceeded"
    assert [item["selected"]["id"] for item in value["rows"]] == [1]
    assert len(calls) == 2 and value["pages"][1]["raw_body_complete"]
    assert not value["pages"][1]["admitted"] and value["clocks"]["traversal_completed_at"] is None
    assert value["persistence"]["state"] == "not_started" and stores == []


@pytest.mark.parametrize("elapsed,admitted", [(45.0, True), (45.000001, False)])
def test_exact_fifteen_second_first_save_admission(monkeypatch, tmp_path, elapsed, admitted):
    from evidentia_core import evidence_store
    from evidentia_core.release_cadence import _limits, _store

    now = [100.0]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: now[0])
    pages(monkeypatch, _traversal, [(encoded([row()]), ())])
    original_target = _store.admit_save_target
    original_save = evidence_store.save_evidence_version_one
    calls = []

    def target(*args, **kwargs):
        result = original_target(*args, **kwargs)
        now[0] = 100.0 + elapsed
        return result

    def save(*args, **kwargs):
        calls.append(now[0])
        return original_save(*args, **kwargs)

    monkeypatch.setattr(_store, "admit_save_target", target)
    monkeypatch.setattr(evidence_store, "save_evidence_version_one", save)
    value = load_json(collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path), 16_777_216)
    assert value["persistence"]["attempted_calls"] == int(admitted)
    if admitted:
        assert calls == [145.0] and value["persistence"]["state"] == "complete"
        assert value["outcomes"][0]["outcome"] == "created"
    else:
        assert calls == [] and value["persistence"]["state"] == "not_started"
        assert value["persistence"]["stop_reason"] == "deadline_exceeded"
        assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("prior", [False, True])
@pytest.mark.parametrize(
    "status,reason",
    [
        (403, "upstream_forbidden"),
        (404, "upstream_not_found"),
        (429, "upstream_rate_limited"),
        (503, "upstream_server_error"),
    ],
)
def test_declared_http_errors_preserve_zero_or_one_prior_page(monkeypatch, prior, status, reason):
    from evidentia_collectors.release_cadence import _http

    from .test_http import Stream, install, link

    original_fetch = _http.HttpAttempt.fetch
    calls, streams = [], []

    def fetch(attempt, owner, repository, number, **kwargs):
        calls.append(number)
        first = prior and number == 1
        stream = Stream([encoded([row()]) if first else b"uninterpreted refusal body"])
        streams.append(stream)
        headers = [(b"content-type", b"application/json")]
        if first:
            headers.append((b"link", link("2")))
        install(monkeypatch, stream, headers, status=200 if first else status)
        return original_fetch(attempt, owner, repository, number, **kwargs)

    monkeypatch.setattr(_http.HttpAttempt, "fetch", fetch)
    value = load_json(collector.poll_release_bytes(request(persist=True), evidence_store_dir=object()), 16_777_216)
    assert value["collection_state"] == ("partial" if prior else "unavailable")
    assert value["terminal_reason"] == reason and len(value["rows"]) == int(prior)
    assert calls == ([1, 2] if prior else [1]) and value["pages"][-1]["http_status"] == status
    assert streams[-1].reads == 0 and all(stream.closed == 1 for stream in streams)
    assert value["persistence"]["state"] == "not_started" and value["persistence"]["attempted_calls"] == 0


def test_complete_poll_wire_matches_independent_hand_derived_projection(monkeypatch):
    from datetime import UTC, datetime
    from uuid import UUID

    from tests.unit.test_release_cadence.test_output import compact, hand_poll

    expected = hand_poll()
    source = expected["rows"][0]["selected"]
    calls = pages(monkeypatch, _traversal, [(compact([source]), ())])
    operation_clocks = iter([datetime(2001, 1, 1, tzinfo=UTC), datetime(2001, 1, 1, microsecond=2, tzinfo=UTC)])
    receipt_clocks = iter([datetime(2001, 1, 1, microsecond=1, tzinfo=UTC)] * 2)
    monkeypatch.setattr(collector, "_utc_now", lambda: next(operation_clocks))
    monkeypatch.setattr(_traversal, "_utc_now", lambda: next(receipt_clocks))
    monkeypatch.setattr(collector.uuid, "uuid4", lambda: UUID("00000000-0000-4000-8000-000000000001"))
    wire = collector.poll_release_bytes(expected["request"])
    assert wire == compact(expected) and len(calls) == 1


def test_worst_escaped_unsupported_timestamp_never_falls_back(monkeypatch):
    from evidentia_core.release_cadence._contracts import SourcePublicationTime

    literal = "\x01" * 128
    source = row(published_at=literal, created_at="2000-01-01T00:00:00Z", updated_at="2000-01-02T00:00:00Z")
    pages(monkeypatch, _traversal, [(encoded([source]), ())])
    value = load_json(collector.poll_release_bytes(request()), 16_777_216)
    selected = value["rows"][0]
    assert selected["selected"] == source
    assert selected["metadata"]["source_time"] == {"classification": "unsupported_syntax", "normalized_utc": None}
    assert selected["metadata"]["initial_publication_eligible"] is False and value["outcomes"] == []
    assert (
        SourcePublicationTime.model_validate(
            {"source_literal": literal, "classification": "unsupported_syntax", "normalized_utc": None}
        ).source_literal
        == literal
    )


def test_repeat_preserves_winner_under_new_case_channel_page_and_raw_spelling(monkeypatch, tmp_path):
    import json

    source = row(name="\u00e9")
    pages(monkeypatch, _traversal, [(encoded([source]), ())])
    first = json.loads(collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path))
    identifier = first["events"][0]["event_id"]
    target = tmp_path / identifier / "v1.json"
    original = target.read_bytes()
    link = (b"<https://api.github.com/repos/allen/example/releases?page=2&per_page=100>; rel=next",)
    next_rows = [row(202, draft=True), source]
    escaped = json.dumps(next_rows, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    pages(monkeypatch, _traversal, [(b"[]", link), (escaped, ())])
    changed_request = {**request(persist=True, channel="all_published"), "owner": "ALLEN", "repository": "EXAMPLE"}
    second = json.loads(collector.poll_release_bytes(changed_request, evidence_store_dir=tmp_path))
    outcome = next(item for item in second["outcomes"] if item["candidate_id"] == identifier)
    assert target.read_bytes() == original
    assert second["persistence"]["attempted_calls"] == 0 and outcome["outcome"] == "already_saved"
    assert outcome["verified_record"]["first_observation_poll_id"] == first["clocks"]["poll_id"]
    assert second["clocks"]["poll_id"] != first["clocks"]["poll_id"]
    assert second["request_sha256"] != first["request_sha256"]
    assert second["rows"][1]["metadata"]["page_index"] == second["rows"][1]["metadata"]["record_index"] == 1
    assert second["pages"][1]["raw_body_sha256"] != first["pages"][0]["raw_body_sha256"]


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("url", "inert://changed"),
        ("html_url", "changed"),
        ("tag_name", "v2"),
        ("target_commitish", "other"),
        ("name", ""),
        ("created_at", "changed"),
        ("immutable", False),
        ("updated_at", None),
    ],
)
def test_each_non_cadence_edit_has_its_own_observation(monkeypatch, tmp_path, field, replacement):
    import hashlib
    import json
    import uuid

    def compact(native):
        return json.dumps(native, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")

    original_source = row()
    pages(monkeypatch, _traversal, [(encoded([original_source]), ())])
    first = json.loads(collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path))
    source = {**original_source, field: replacement}
    pages(monkeypatch, _traversal, [(encoded([source]), ())])
    result = json.loads(collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path))
    fact_sha = hashlib.sha256(compact(["evidentia.release-selected-facts.v1", source])).hexdigest()
    event_tuple = ["evidentia.release-publication.v1", "api.github.com", "allen", "example", "101"]
    expected_id = str(
        uuid.uuid5(
            uuid.UUID("5b09e574-978a-5490-8446-a914e8a9dadf"),
            compact(["evidentia.release-source-observation.v1", event_tuple, fact_sha]).decode("ascii"),
        )
    )
    event = result["events"][0]
    assert event["event_id"] == first["events"][0]["event_id"]
    assert event["current_vs_parent"]["changed_fields"] == [field]
    assert event["stored_union_change_codes"] == ["non_cadence_facts_changed"]
    assert event["blocks_full_releases"] is event["blocks_all_published"] is False
    assert [item["outcome"] for item in result["outcomes"]] == ["already_saved", "created"]
    stored = json.loads((tmp_path / expected_id / "v1.json").read_bytes())
    assert stored["id"] == expected_id and stored["content"]["selected_facts"] == source
    assert stored["content"]["selected_facts_sha256"] == fact_sha
    assert stored["content"]["parent_publication"]["artifact_id"] == event["event_id"]


@pytest.mark.parametrize("collision", ["publication_uuid", "observation_uuid"])
def test_forced_uuid_collision_compares_native_identity_before_saving(monkeypatch, tmp_path, collision):
    import copy
    import uuid

    from evidentia_core import evidence_store
    from evidentia_core.release_cadence import _identity

    from tests.unit.test_release_cadence._helpers import artifact, write_artifact

    parent = artifact()
    paths = [write_artifact(tmp_path, parent)]
    child = artifact("observation-101")
    if collision == "observation_uuid":
        paths.append(write_artifact(tmp_path, child))
    before = {target: target.read_bytes() for target in paths}
    original_uuid5 = _identity.uuid.uuid5

    def collide(namespace, spelling):
        if collision == "publication_uuid" and namespace == uuid.NAMESPACE_URL:
            return uuid.UUID(parent["id"])
        if collision == "observation_uuid" and namespace == _identity.OBSERVATION_NAMESPACE:
            return uuid.UUID(child["id"])
        return original_uuid5(namespace, spelling)

    monkeypatch.setattr(_identity.uuid, "uuid5", collide)
    selected = copy.deepcopy(parent["content"]["selected_facts"])
    selected.update({"id": 102} if collision == "publication_uuid" else {"name": "Unequal colliding observation"})
    assert selected != parent["content"]["selected_facts"]
    assert collision != "observation_uuid" or selected != child["content"]["selected_facts"]
    pages(monkeypatch, _traversal, [(encoded([selected]), ())])
    calls = []
    monkeypatch.setattr(evidence_store, "save_evidence_version_one", lambda *a, **k: calls.append(True))
    with pytest.raises(ReleaseFailure) as caught:
        collector.poll_release_bytes(
            {**request(persist=True), "owner": "Example", "repository": "Synthetic"}, evidence_store_dir=tmp_path
        )
    assert caught.value.reason == (
        "store_identity_conflict" if collision == "publication_uuid" else "store_digest_conflict"
    )
    assert calls == [] and {target: target.read_bytes() for target in paths} == before
    assert set(tmp_path.iterdir()) == {target.parent for target in paths}


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"prerelease": True}, "prerelease_changed"),
        ({"node_id": "changed-node"}, "node_id_changed"),
        ({"published_at": "unsupported"}, "publication_time_unqualified"),
    ],
)
def test_conflicting_observation_survives_current_exclusion_and_later_reversion(monkeypatch, tmp_path, change, reason):
    import json

    from evidentia_core.release_cadence._contracts import native_model
    from evidentia_core.release_cadence._series import evaluate_release_series

    from tests.unit.test_release_cadence._helpers import series_request

    selected_request = {**request(persist=True), "owner": "Example", "repository": "Synthetic"}
    source = row()
    pages(monkeypatch, _traversal, [(encoded([source]), ())])
    collector.poll_release_bytes(selected_request, evidence_store_dir=tmp_path)
    pages(monkeypatch, _traversal, [(encoded([{**source, **change}]), ())])
    changed = json.loads(collector.poll_release_bytes(selected_request, evidence_store_dir=tmp_path))
    assert changed["outcomes"][1]["outcome"] == "created"
    if "prerelease" in change:
        assert changed["rows"][0]["metadata"]["initial_publication_eligible"] is False
    pages(monkeypatch, _traversal, [(encoded([source]), ())])
    reverted = json.loads(collector.poll_release_bytes(selected_request, evidence_store_dir=tmp_path))
    assert reverted["persistence"]["attempted_calls"] == 0
    value = native_model(evaluate_release_series(series_request(channel="full_releases"), evidence_store_dir=tmp_path))
    assert value["state"] == "conflict" and value["reasons"] == ["source_conflict"]
    assert value["events"][0]["reasons"] == [reason]


def test_complete_result_cap_refusal_precedes_every_save(monkeypatch, tmp_path):
    from evidentia_core import evidence_store

    pages(monkeypatch, _traversal, [(encoded([row()]), ())])
    calls = []

    def refuse(*args, **kwargs):
        raise ReleaseFailure("result_limit_exceeded")

    monkeypatch.setattr(collector, "_seal_result", refuse)
    monkeypatch.setattr(evidence_store, "save_evidence_version_one", lambda *a, **k: calls.append(True))
    with pytest.raises(ReleaseFailure) as caught:
        collector.poll_release_bytes(request(persist=True), evidence_store_dir=tmp_path)
    assert caught.value.reason == "result_limit_exceeded" and calls == [] and list(tmp_path.iterdir()) == []


def test_refused_first_save_retains_only_discovery_publication_reuse(monkeypatch, tmp_path):
    import copy
    import json

    from evidentia_core import evidence_store
    from evidentia_core.release_cadence import _limits, _store

    from tests.unit.test_release_cadence._helpers import artifact, write_artifact

    parent = artifact()
    target = write_artifact(tmp_path, parent)
    before = target.read_bytes()
    source = copy.deepcopy(parent["content"]["selected_facts"])
    pages(monkeypatch, _traversal, [(encoded([source, row(102)]), ())])
    real_clock, offset, calls = _limits.time.monotonic, [0.0], []
    monkeypatch.setattr(_limits.time, "monotonic", lambda: real_clock() + offset[0])
    original = _store.admit_save_target

    def expire_first_save(*args, **kwargs):
        original(*args, **kwargs)
        offset[0] = 46.0

    monkeypatch.setattr(_store, "admit_save_target", expire_first_save)
    monkeypatch.setattr(evidence_store, "save_evidence_version_one", lambda *a, **k: calls.append(True))
    result = json.loads(
        collector.poll_release_bytes(
            {**request(persist=True), "owner": "Example", "repository": "Synthetic"}, evidence_store_dir=tmp_path
        )
    )
    assert result["persistence"]["state"] == "not_started"
    assert result["persistence"]["stop_reason"] == "deadline_exceeded"
    assert result["persistence"]["attempted_calls"] == 0 and calls == []
    assert result["counters"]["targeted_record_reads"] == 0
    reused = result["outcomes"][0]
    assert reused["planned_action"] == "reuse_publication" and reused["save_call"] == "not_called"
    assert reused["outcome"] == "already_saved" and reused["local_state"] == "local_verified"
    assert reused["verified_record"]["first_observation_poll_id"] == parent["content"]["first_observation"]["poll_id"]
    assert target.read_bytes() == before


def test_same_instant_literal_change_stores_observation_without_redating_parent(monkeypatch, tmp_path):
    import json

    from evidentia_core.release_cadence._contracts import native_model
    from evidentia_core.release_cadence._series import evaluate_release_series

    from tests.unit.test_release_cadence._helpers import series_request

    selected_request = {**request(persist=True), "owner": "Example", "repository": "Synthetic"}
    original = row()
    pages(monkeypatch, _traversal, [(encoded([original]), ())])
    first = json.loads(collector.poll_release_bytes(selected_request, evidence_store_dir=tmp_path))
    parent_path = tmp_path / first["events"][0]["event_id"] / "v1.json"
    parent_bytes = parent_path.read_bytes()
    changed = {**original, "published_at": "2000-01-01t00:00:00-00:00"}
    pages(monkeypatch, _traversal, [(encoded([changed]), ())])
    second = json.loads(collector.poll_release_bytes(selected_request, evidence_store_dir=tmp_path))
    assert parent_path.read_bytes() == parent_bytes
    assert second["events"][0]["current_vs_parent"] == {
        "changed_fields": ["published_at"],
        "change_codes": ["publication_literal_changed"],
        "blocks_full_releases": False,
        "blocks_all_published": False,
    }
    outcome = second["outcomes"][1]
    assert outcome["outcome"] == "created"
    child = json.loads((tmp_path / outcome["candidate_id"] / "v1.json").read_bytes())
    assert child["content"]["selected_facts"]["published_at"] == changed["published_at"]
    assert child["content"]["publication_time"]["normalized_utc"] == "2000-01-01T00:00:00.000000Z"
    series = native_model(evaluate_release_series(series_request(), evidence_store_dir=tmp_path))
    assert series["state"] == "insufficient" and len(series["events"]) == 1
    assert series["events"][0]["published_at"] == "2000-01-01T00:00:00.000000Z"


def test_persisted_projection_matches_all_62_declared_provenance_fields(monkeypatch, tmp_path):
    import copy
    import hashlib
    import json
    import uuid
    from datetime import UTC, datetime

    def compact(value):
        return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode(
            "ascii"
        )

    def digest(value):
        return hashlib.sha256(compact(value)).hexdigest()

    def utc(literal):
        return (
            datetime.fromisoformat(literal.replace("Z", "+00:00"))
            .astimezone(UTC)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )

    original = row(immutable=False, updated_at=None)
    changed = {**original, "name": "Changed synthetic \u00e9"}
    selected_request = request(persist=True)
    before = datetime.now(UTC)
    polls = []
    for source in (original, changed):
        pages(monkeypatch, _traversal, [(encoded([source]), ())])
        polls.append(json.loads(collector.poll_release_bytes(selected_request, evidence_store_dir=tmp_path)))
    after = datetime.now(UTC)
    event_tuple = ["evidentia.release-publication.v1", "api.github.com", "allen", "example", "101"]
    event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, compact(event_tuple).decode("ascii")))
    parent_raw = (tmp_path / event_id / "v1.json").read_bytes()
    parent = json.loads(parent_raw)
    references = []
    for poll, source, slot, kind, action in (
        (polls[0], original, 0, "release_publication", "create_publication"),
        (polls[1], changed, 1, "release_source_observation", "create_observation"),
    ):
        outcome = poll["outcomes"][slot]
        fact_sha = digest(["evidentia.release-selected-facts.v1", source])
        identifier = (
            event_id
            if slot == 0
            else str(
                uuid.uuid5(
                    uuid.UUID("5b09e574-978a-5490-8446-a914e8a9dadf"),
                    compact(["evidentia.release-source-observation.v1", event_tuple, fact_sha]).decode("ascii"),
                )
            )
        )
        raw = (tmp_path / identifier / "v1.json").read_bytes()
        stored = json.loads(raw)
        content = stored["content"]
        first = content["first_observation"]
        row_value, page = poll["rows"][0], poll["pages"][0]
        assert set(source) == {
            "id",
            "node_id",
            "url",
            "html_url",
            "tag_name",
            "target_commitish",
            "name",
            "draft",
            "prerelease",
            "immutable",
            "created_at",
            "published_at",
            "updated_at",
        }
        assert row_value["selected"] == content["selected_facts"] == source
        assert poll["request"] == selected_request and poll["request_sha256"] == digest(selected_request)
        assert content["event_key"] == {
            "identity_version": event_tuple[0],
            "source_host": event_tuple[1],
            "canonical_owner": "allen",
            "canonical_repository": "example",
            "release_id": 101,
        }
        assert content["event_key_sha256"] == digest(event_tuple) and content["event_id"] == event_id
        assert content["publication_time"] == {
            "source_literal": source["published_at"],
            "classification": "normalized",
            "normalized_utc": "2000-01-01T00:00:00.000000Z",
        }
        assert row_value["metadata"]["source_time"] == {
            "classification": "normalized",
            "normalized_utc": "2000-01-01T00:00:00.000000Z",
        }
        source_sha = hashlib.sha256(encoded([source])).hexdigest()
        assert page["raw_body_sha256"] == page["decoded_body_sha256"] == source_sha
        assert first == {
            "poll_id": poll["clocks"]["poll_id"],
            "request_sha256": digest(selected_request),
            "requested_owner": "Allen",
            "requested_repository": "Example",
            "channel": "full_releases",
            "page_ordinal": 1,
            "page_number": 1,
            "record_index": 0,
            "retrieved_at": page["retrieved_at"],
            "traversal_completed_at": poll["clocks"]["traversal_completed_at"],
            "response_raw_sha256": source_sha,
            "response_decoded_sha256": source_sha,
        }
        assert row_value["metadata"]["page_index"] == row_value["metadata"]["record_index"] == 0
        assert page["page_ordinal"] == page["page_number"] == 1
        assert (
            stored["content_hash"]
            == hashlib.sha256(
                json.dumps(content, sort_keys=True, ensure_ascii=True, separators=(", ", ": "), allow_nan=False).encode(
                    "ascii"
                )
            ).hexdigest()
        )
        reference = outcome["verified_record"]
        verified = datetime.fromisoformat(reference["verified_at"].replace("Z", "+00:00"))
        assert before <= verified <= after
        semantic = copy.deepcopy(stored)
        semantic["collected_at"] = utc(stored["collected_at"])
        expected_reference = {
            "record_kind": kind,
            "artifact_id": identifier,
            "event_id": event_id,
            "version": 1,
            "relative_path": identifier + "/v1.json",
            "content_sha256": stored["content_hash"],
            "selected_facts_sha256": fact_sha,
            "artifact_semantic_sha256": digest(["evidentia.release-artifact.v1", semantic]),
            "stored_file_sha256": hashlib.sha256(raw).hexdigest(),
            "stored_file_bytes": len(raw),
            "collected_at": utc(stored["collected_at"]),
            "first_observation_poll_id": first["poll_id"],
            "verified_at": reference["verified_at"],
            "first_observed_at": first["retrieved_at"],
        }
        assert reference == expected_reference
        references.append(expected_reference)
        assert outcome == {
            "record_kind": kind,
            "event_id": event_id,
            "candidate_id": identifier,
            "candidate_selected_facts_sha256": fact_sha,
            "planned_action": action,
            "save_call": "returned_created",
            "outcome": "created",
            "local_state": "local_verified",
            "verified_record": expected_reference,
            "mirror_outcome": "unobserved",
            "reason": None,
        }
        if slot:
            assert content["parent_publication"] == {
                "event_key_sha256": digest(event_tuple),
                "content_sha256": parent["content_hash"],
                "selected_facts_sha256": digest(["evidentia.release-selected-facts.v1", original]),
                "artifact_id": event_id,
            }
            publication = poll["outcomes"][poll["events"][0]["publication_outcome_index"]]["verified_record"]
            assert publication["artifact_id"] == event_id
            assert publication["content_sha256"] == parent["content_hash"]
            assert publication["selected_facts_sha256"] == digest(["evidentia.release-selected-facts.v1", original])
    assert references[0]["first_observation_poll_id"] != references[1]["first_observation_poll_id"]
