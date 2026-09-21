"""Strict discovery over isolated synthetic stores, without glob fallback."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path

import pytest
from evidentia_core.models.evidence import EvidenceArtifact
from evidentia_core.release_cadence._limits import start_budget
from evidentia_core.release_cadence._store import discover

FIXTURES = Path(__file__).parents[2] / "fixtures" / "release_cadence"


def publication():
    return json.loads((FIXTURES / "publication-v1.json").read_bytes())


def write_record(root, artifact, *, version=1):
    directory = root / artifact["id"]
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"v{version}.json"
    destination.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    return destination


def test_complete_two_pass_scope_and_byte_accounting(tmp_path):
    artifact = publication()
    target = write_record(tmp_path, artifact)
    raw = target.read_bytes()
    snapshot = discover(tmp_path, "Example", "Synthetic", start_budget())
    summary = snapshot.summary()
    assert summary["status"] == "complete"
    assert summary["passes"] == 2
    assert summary["canonical_files_read"] == 2
    assert summary["release_records_observed"] == 2
    assert summary["raw_file_bytes_observed"] == 2 * len(raw)
    assert len(snapshot.records) == 1
    assert snapshot.records[0].native() == artifact
    assert snapshot.records[0].stored_file_sha256 == hashlib.sha256(raw).hexdigest()
    assert len(summary["inventory_sha256"]) == 64


def test_missing_root_is_empty_without_creation(tmp_path):
    root = tmp_path / "absent" / "store"
    snapshot = discover(root, "Example", "Synthetic", start_budget())
    assert snapshot.summary()["status"] == "complete"
    assert snapshot.records == ()
    assert not root.exists()


def test_unrelated_valid_ordinary_record_is_counted_and_excluded(tmp_path):
    identifier = str(uuid.uuid4())
    ordinary = EvidenceArtifact(
        id=identifier,
        title="Synthetic ordinary record",
        evidence_type="repository_metadata",
        source_system="test",
        collected_by="synthetic test",
        lineage_id=identifier,
    ).model_dump(mode="json")
    write_record(tmp_path, ordinary)
    snapshot = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert snapshot.summary()["status"] == "complete"
    assert snapshot.summary()["canonical_files_read"] == 2
    assert snapshot.summary()["release_records_observed"] == 0
    assert snapshot.records == ()


@pytest.mark.parametrize("case", ["duplicate", "malformed", "metadata", "scope", "id", "unknown-schema", "version-two"])
def test_unclassifiable_or_conflicting_release_blocks_discovery(tmp_path, case):
    artifact = publication()
    if case == "metadata":
        artifact["metadata"]["event_id"] = "15a1055c-d426-536c-93cb-a444dc0e6b5d"
    if case == "scope":
        artifact["metadata"]["canonical_repository"] = "other"
    if case == "id":
        artifact["id"] = "15a1055c-d426-536c-93cb-a444dc0e6b5d"
    if case == "unknown-schema":
        artifact["content"]["schema_version"] = "unknown"
    if case == "version-two":
        artifact["version"] = 2
    target = write_record(tmp_path, artifact, version=2 if case == "version-two" else 1)
    if case == "duplicate":
        target.write_bytes(b'{"title":"a","title":"b"}')
    if case == "malformed":
        target.write_bytes(b'{"not complete"')
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert result.summary()["status"] in {"record_invalid", "identity_conflict"}
    assert result.records == ()


def test_missing_parent_observation_is_not_filtered_by_date(tmp_path):
    artifact = json.loads((FIXTURES / "observation-v1.json").read_bytes())
    write_record(tmp_path, artifact)
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert result.summary()["status"] == "identity_conflict"
    assert result.records == ()


@pytest.mark.parametrize("name", ["v0.json", "v01.json", "V1.json", "v1.json.tmp", ".v1.json.owned.tmp"])
def test_malformed_version_and_owned_temporary_refuse(tmp_path, name):
    root = tmp_path / str(uuid.uuid4())
    root.mkdir()
    (root / name).write_bytes(b"{}")
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert result.summary()["status"] == "unavailable"


def test_nested_directory_and_noncanonical_lineage_refuse(tmp_path):
    nested = tmp_path / str(uuid.uuid4()) / "nested"
    nested.mkdir(parents=True)
    assert discover(tmp_path, "Example", "Synthetic", start_budget()).summary()["status"] == "unavailable"
    other = tmp_path / "second"
    other.mkdir()
    (other / str(uuid.uuid4()).upper()).mkdir()
    assert discover(other, "Example", "Synthetic", start_budget()).summary()["status"] == "unavailable"


def test_permission_failure_is_not_a_partial_glob_success(tmp_path, monkeypatch):
    from evidentia_core.release_cadence import _store

    original = os.scandir

    def denied(path):
        if Path(path) == tmp_path:
            raise PermissionError("synthetic denied enumeration")
        return original(path)

    monkeypatch.setattr(_store.os, "scandir", denied)
    monkeypatch.setattr(Path, "rglob", lambda *a, **k: (_ for _ in ()).throw(AssertionError("rglob used")))
    monkeypatch.setattr(Path, "glob", lambda *a, **k: (_ for _ in ()).throw(AssertionError("glob used")))
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert result.summary()["status"] == "unavailable"
    assert result.summary()["passes"] == 0
    assert result.records == ()


def test_file_mutation_between_passes_refuses_without_retry(tmp_path, monkeypatch):
    from evidentia_core.release_cadence import _store

    target = write_record(tmp_path, publication())
    original = _store._inventory_pass
    calls = 0

    def changed(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 1:
            target.write_bytes(target.read_bytes() + b" ")
        return result

    monkeypatch.setattr(_store, "_inventory_pass", changed)
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert result.summary()["status"] == "changed"
    assert result.summary()["passes"] == 2
    assert calls == 2
    assert result.records == ()


def test_symlink_refusal_when_native_creation_is_available(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    root = tmp_path / "linked"
    try:
        root.symlink_to(target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Native symlink privilege unavailable: {type(error).__name__}")
    result = discover(root, "Example", "Synthetic", start_budget())
    assert result.summary()["status"] == "unavailable"


@pytest.mark.parametrize(
    "name",
    [
        "v0.json",
        "v01.json",
        "V1.json",
        "v-1.json",
        "v+1.json",
        "v.1.json",
        "v1.txt",
        "v1.json.tmp",
        "v1.JSON",
        "v9007199254740992.json",
        "version.json",
        ".v1.json.abc.tmp",
        ".v01.json.abc.tmp",
        ".V01.JSON.abc.tmp",
        ".v-1.json.other",
    ],
)
def test_ratified_version_refusal_precedes_body_read(tmp_path, monkeypatch, name):
    from evidentia_core.release_cadence import _store

    lineage = tmp_path / str(uuid.uuid4())
    lineage.mkdir()
    (lineage / name).write_bytes(b"not read")
    reads = []

    def forbidden_read(*args, **kwargs):
        reads.append(args)
        raise AssertionError("A refused filename reached file-body reading")

    monkeypatch.setattr(_store, "read_regular", forbidden_read)
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert result.summary()["status"] == "unavailable"
    assert result.summary()["child_entries_observed"] == 1
    assert reads == []


@pytest.mark.parametrize("name", ["notes.txt", "version-notes.txt", "readme.json"])
def test_ordinary_names_are_counted_in_both_passes_without_parsing(tmp_path, monkeypatch, name):
    from evidentia_core.release_cadence import _store

    lineage = tmp_path / str(uuid.uuid4())
    lineage.mkdir()
    (lineage / name).write_bytes(b"not JSON")

    def forbidden_read(*args, **kwargs):
        raise AssertionError("An ordinary filename reached file-body reading")

    monkeypatch.setattr(_store, "read_regular", forbidden_read)
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert result.summary()["status"] == "complete"
    assert result.summary()["root_entries_observed"] == 2
    assert result.summary()["child_entries_observed"] == 2
    assert result.summary()["canonical_files_read"] == 0


@pytest.mark.parametrize("version", [1, 9_007_199_254_740_991])
def test_canonical_safe_integer_endpoints_are_classified(tmp_path, version):
    identifier = str(uuid.uuid4())
    ordinary = EvidenceArtifact(
        id=identifier,
        title="Synthetic ordinary record",
        evidence_type="repository_metadata",
        source_system="test",
        collected_by="synthetic test",
        lineage_id=identifier,
        version=version,
    ).model_dump(mode="json")
    write_record(tmp_path, ordinary, version=version)
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert result.summary()["status"] == "complete"
    assert result.summary()["canonical_files_read"] == 2


def test_unreadable_child_entry_refuses_complete_inventory(tmp_path, monkeypatch):
    child = tmp_path / str(uuid.uuid4())
    child.mkdir()
    original = Path.lstat

    def denied(self, *args, **kwargs):
        if self == child:
            raise PermissionError("synthetic unreadable child")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", denied)
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert result.summary()["status"] == "unavailable"
    assert result.summary()["passes"] == 0
    assert result.summary()["root_entries_observed"] == 1
    assert result.records == ()


def test_verified_other_repository_observation_is_scope_isolated(tmp_path):
    artifact = json.loads((FIXTURES / "observation-v1.json").read_bytes())
    write_record(tmp_path, artifact)
    result = discover(tmp_path, "Other", "Repository", start_budget())
    assert result.summary()["status"] == "complete"
    assert result.summary()["release_records_observed"] == 2
    assert result.records == ()


@pytest.mark.parametrize(
    "observation,remaining,admitted",
    [
        (False, 131072, False),
        (False, 131073, True),
        (True, 262145, False),
        (True, 262146, True),
    ],
)
def test_shared_readback_reservation_endpoints(observation, remaining, admitted):
    from evidentia_core.release_cadence._limits import STORE_TOTAL_BYTES, ReleaseFailure
    from evidentia_core.release_cadence._store import StoreReadBudget

    ledger = StoreReadBudget(consumed=STORE_TOTAL_BYTES - remaining)
    if admitted:
        ledger.reserve_readback(observation=observation)
        assert ledger.reserved == remaining
        ledger.charge(12)
        ledger.finish_readback()
        assert ledger.consumed == STORE_TOTAL_BYTES - remaining + 12
        assert ledger.reserved == 0
    else:
        with pytest.raises(ReleaseFailure) as raised:
            ledger.reserve_readback(observation=observation)
        assert raised.value.reason == "store_limit_exceeded"
        assert ledger.consumed == STORE_TOTAL_BYTES - remaining
        assert ledger.reserved == 0


def test_descriptor_read_closes_and_preserves_primary_cancellation(tmp_path, monkeypatch):
    from evidentia_core.release_cadence import _store

    target = tmp_path / "plain"
    target.write_bytes(b"synthetic")
    primary = KeyboardInterrupt("synthetic primary")
    secondary = SystemExit("synthetic close interruption")
    closed = []
    real_close = os.close

    def cancel_read(*args):
        raise primary

    def close_then_interrupt(fd):
        real_close(fd)
        closed.append(fd)
        raise secondary

    monkeypatch.setattr(_store.os, "read", cancel_read)
    monkeypatch.setattr(_store.os, "close", close_then_interrupt)
    with pytest.raises(KeyboardInterrupt) as raised:
        _store.read_regular(target, 128, _store.StoreReadBudget(), start_budget())
    assert raised.value is primary
    assert len(closed) == 1
    with pytest.raises(OSError):
        os.fstat(closed[0])


def test_returned_read_bytes_are_charged_before_later_failure(tmp_path, monkeypatch):
    from evidentia_core.release_cadence import _store

    target = tmp_path / "plain"
    target.write_bytes(b"synthetic")
    ledger = _store.StoreReadBudget()
    real_read = os.read
    reads = 0

    def first_then_cancel(fd, size):
        nonlocal reads
        reads += 1
        if reads == 1:
            return real_read(fd, min(size, 3))
        raise KeyboardInterrupt("synthetic interrupted read")

    monkeypatch.setattr(_store.os, "read", first_then_cancel)
    with pytest.raises(KeyboardInterrupt):
        _store.read_regular(target, 128, ledger, start_budget())
    assert ledger.consumed == 3


def test_descriptor_replacement_is_refused(tmp_path, monkeypatch):
    from evidentia_core.release_cadence import _store
    from evidentia_core.release_cadence._limits import ReleaseFailure

    target = tmp_path / "plain"
    target.write_bytes(b"synthetic")
    real_open = os.open

    def replace_then_open(path, flags):
        if Path(path) == target:
            target.unlink()
            target.write_bytes(b"other")
        return real_open(path, flags)

    monkeypatch.setattr(_store.os, "open", replace_then_open)
    with pytest.raises(ReleaseFailure) as raised:
        _store.read_regular(target, 128, _store.StoreReadBudget(), start_budget())
    assert raised.value.reason == "store_changed"


def test_targeted_readback_absence_presence_and_parent(tmp_path):
    from evidentia_core.release_cadence import _store

    from ._helpers import artifact

    budget = start_budget()
    binding = _store.admit_root(tmp_path, budget, reserve=0)
    ledger = _store.StoreReadBudget()
    parent = artifact()
    child = artifact("observation-101")
    assert _store.readback(binding, parent["id"], ledger, budget) is None
    parent_path = write_record(tmp_path, parent)
    child_path = write_record(tmp_path, child)
    result = _store.readback(binding, child["id"], ledger, budget)
    assert result.native() == child
    reference = _store.record_reference(result)
    assert reference["artifact_id"] == child["id"]
    assert reference["stored_file_sha256"] == hashlib.sha256(child_path.read_bytes()).hexdigest()
    assert reference["first_observed_at"] == child["content"]["first_observation"]["retrieved_at"]
    assert ledger.targeted_reads == 3
    assert ledger.consumed == len(parent_path.read_bytes()) + len(child_path.read_bytes())


def test_targeted_readback_parent_change_cannot_be_a_normal_source_edit(tmp_path):
    from evidentia_core.release_cadence import _store
    from evidentia_core.release_cadence._json import canonical_bytes
    from evidentia_core.release_cadence._limits import ReleaseFailure

    from ._helpers import artifact

    parent = artifact()
    child = artifact("observation-101")
    write_record(tmp_path, parent)
    write_record(tmp_path, child)
    budget = start_budget()
    binding = _store.admit_root(tmp_path, budget, reserve=0)
    wrong = dict(parent)
    wrong["title"] = "different expected authority"
    with pytest.raises(ReleaseFailure) as raised:
        _store.readback(
            binding, child["id"], _store.StoreReadBudget(), budget, expected_parent_bytes=canonical_bytes(wrong, 65536)
        )
    assert raised.value.reason == "store_changed"


# DC1-DC7: equal bytes may reuse semantic validation only inside one discovery.
def test_discovery_reuse_keeps_physical_reads_counters_and_fresh_values(tmp_path, monkeypatch):
    from evidentia_core.release_cadence import _store

    source = publication()
    target = write_record(tmp_path, source)
    raw = target.read_bytes()
    classify, read, inventory = _store._classify, _store.read_regular, _store._inventory_pass
    classifications, reads, passes = [], [], []

    def observe_classify(*args, **kwargs):
        classifications.append((args[0], args[1], args[2]))
        return classify(*args, **kwargs)

    def observe_read(*args, **kwargs):
        result = read(*args, **kwargs)
        reads.append(result)
        return result

    def observe_inventory(*args, **kwargs):
        result = inventory(*args, **kwargs)
        passes.append(result)
        return result

    monkeypatch.setattr(_store, "_classify", observe_classify)
    monkeypatch.setattr(_store, "read_regular", observe_read)
    monkeypatch.setattr(_store, "_inventory_pass", observe_inventory)
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    summary = result.summary()
    assert summary["status"] == "complete"
    assert len(classifications) == 1 and len(reads) == 2 and len(passes) == 2
    assert summary["release_records_observed"] == summary["canonical_files_read"] == 2
    assert summary["raw_file_bytes_observed"] == len(raw) * 2
    first, second = passes[0][1][0], result.records[0]
    assert second is not first and second.physical == reads[1][1]
    assert second.verified_at >= first.verified_at
    assert second.raw == first.raw == raw and second.native() == source
    assert second.artifact_bytes is first.artifact_bytes
    # A later discovery must not inherit the first invocation's validation authority.
    again = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert again.summary()["status"] == "complete" and len(classifications) == 2 and len(reads) == 4


@pytest.mark.parametrize("change", ["selected_facts", "formatting", "malformed", "version", "path"])
def test_changed_second_read_never_reuses_first_validation(tmp_path, monkeypatch, change):
    from evidentia_core.release_cadence import _store

    from .test_capacity import capacity_publication

    value = publication()
    target = write_record(tmp_path, value)
    inventory, classify = _store._inventory_pass, _store._classify
    calls, classified = 0, []

    def observed(*args, **kwargs):
        classified.append(args[0])
        return classify(*args, **kwargs)

    def changed(*args, **kwargs):
        nonlocal calls
        result = inventory(*args, **kwargs)
        calls += 1
        if calls == 1:
            if change == "selected_facts":
                value["content"]["selected_facts"]["name"] = "Changed synthetic release"
                replacement = capacity_publication(value, value["content"]["event_key"]["release_id"])
                target.write_bytes(json.dumps(replacement).encode("utf-8"))
            elif change == "formatting":
                target.write_bytes(target.read_bytes() + b" ")
            elif change == "malformed":
                target.write_bytes(b'{"incomplete"')
            elif change == "version":
                target.rename(target.with_name("v2.json"))
            else:
                target.parent.rename(tmp_path / "11111111-1111-5111-8111-111111111111")
        return result

    monkeypatch.setattr(_store, "_classify", observed)
    monkeypatch.setattr(_store, "_inventory_pass", changed)
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert len(classified) == 2
    assert result.summary()["status"] in {"changed", "record_invalid", "identity_conflict"}
    assert result.summary()["canonical_files_read"] == 2 and result.records == ()


@pytest.mark.parametrize("field", ["artifact_bytes", "raw", "relative_path"])
def test_returned_first_pass_values_are_not_cache_authority(tmp_path, monkeypatch, field):
    from dataclasses import replace

    from evidentia_core.release_cadence import _store

    source = publication()
    write_record(tmp_path, source)
    inventory = _store._inventory_pass
    calls = 0

    def forged(*args, **kwargs):
        nonlocal calls
        rows, records = inventory(*args, **kwargs)
        calls += 1
        if calls == 1:
            replacements = {"artifact_bytes": b'{"forged":true}', "raw": b"forged", "relative_path": "forged/v1.json"}
            records = (replace(records[0], **{field: replacements[field]}),)
        return rows, records

    monkeypatch.setattr(_store, "_inventory_pass", forged)
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    if field == "artifact_bytes":
        assert result.summary()["status"] == "complete" and result.records[0].native() == source
    else:
        assert result.summary()["status"] == "changed" and result.records == ()


@pytest.mark.parametrize("cancellation", [False, True])
def test_second_descriptor_failure_preserves_observed_bytes_and_primary(tmp_path, monkeypatch, cancellation):
    from evidentia_core.release_cadence import _store

    target = write_record(tmp_path, publication())
    length = target.stat().st_size
    real_read = os.read
    calls = 0
    primary = (
        KeyboardInterrupt("synthetic second-read cancellation") if cancellation else OSError("synthetic read failure")
    )
    ledger = _store.StoreReadBudget()

    def interrupted(fd, size):
        nonlocal calls
        calls += 1
        if calls == 3:
            return real_read(fd, 3)
        if calls == 4:
            raise primary
        return real_read(fd, size)

    monkeypatch.setattr(_store.os, "read", interrupted)
    if cancellation:
        with pytest.raises(KeyboardInterrupt) as found:
            discover(tmp_path, "Example", "Synthetic", start_budget(), ledger=ledger)
        assert found.value is primary
    else:
        result = discover(tmp_path, "Example", "Synthetic", start_budget(), ledger=ledger)
        summary = result.summary()
        assert summary["status"] == "unavailable" and summary["passes"] == 1
        assert summary["canonical_files_read"] == 2 and summary["release_records_observed"] == 1
        assert result.records == ()
    assert calls == 4 and ledger.consumed == length + 3


def test_full_raw_comparison_refuses_changed_bytes_even_with_forged_inventory(tmp_path, monkeypatch):
    from evidentia_core.release_cadence import _store

    target = write_record(tmp_path, publication())
    inventory, classify = _store._inventory_pass, _store._classify
    first = None
    classifications = 0

    def observed(*args, **kwargs):
        nonlocal classifications
        classifications += 1
        return classify(*args, **kwargs)

    def forged(*args, **kwargs):
        nonlocal first
        rows, records = inventory(*args, **kwargs)
        if first is None:
            first = rows
            target.write_bytes(target.read_bytes() + b" ")
        return first, records

    monkeypatch.setattr(_store, "_inventory_pass", forged)
    monkeypatch.setattr(_store, "_classify", observed)
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert classifications == 2 and result.summary()["status"] == "changed"
    assert result.summary()["passes"] == 2 and result.records == ()


@pytest.mark.parametrize("phase", ["cache_hit", "pass_return", "classification_encoding"])
def test_discovery_releases_new_local_buffers_after_cancellation(tmp_path, monkeypatch, phase):
    import sys

    from evidentia_core.release_cadence import _store

    target = write_record(tmp_path, publication())
    length = target.stat().st_size
    work, encode = _store._work, _store.canonical_bytes
    primary = KeyboardInterrupt("synthetic discovery interruption")

    def interrupt(budget, reserve):
        caller = sys._getframe(1)
        state = caller.f_locals
        if phase == "cache_hit" and caller.f_code.co_name == "classify_record" and state.get("cached") is not None:
            raise primary
        if phase == "pass_return" and caller.f_code.co_name == "_inventory_pass" and len(state.get("records", ())) == 1:
            raise primary
        return work(budget, reserve)

    def interrupt_encoding(*args, **kwargs):
        result = encode(*args, **kwargs)
        if phase == "classification_encoding" and sys._getframe(1).f_code.co_name == "classify_record":
            raise primary
        return result

    monkeypatch.setattr(_store, "_work", interrupt)
    monkeypatch.setattr(_store, "canonical_bytes", interrupt_encoding)
    with pytest.raises(KeyboardInterrupt) as found:
        discover(tmp_path, "Example", "Synthetic", start_budget())
    assert found.value is primary
    frames = {}
    trace = found.value.__traceback__
    while trace is not None:
        if Path(trace.tb_frame.f_code.co_filename) == Path(_store.__file__):
            frames[trace.tb_frame.f_code.co_name] = trace.tb_frame.f_locals
        trace = trace.tb_next
    state = frames["discover"]
    assert state["counts"].ledger.consumed == length * (2 if phase == "cache_hit" else 1)
    assert state["retained"] == {}
    assert state["first_records"] == state["first_record_bytes"] == state["second_records"] == ()
    state = frames["_inventory_pass"]
    assert state["inventory"] == state["records"] == [] and state["raw"] == b""
    assert state["artifact_bytes"] is None
    if phase != "pass_return":
        state = frames["classify_record"]
        assert state["raw"] == b""
        assert state["cached"] is state["artifact"] is state["encoded"] is None


@pytest.mark.parametrize("kind", ["raw", "relative", "version"])
def test_discovery_classifier_refuses_callback_types_before_lookup(tmp_path, monkeypatch, kind):
    from evidentia_core.release_cadence import _store
    from evidentia_core.release_cadence._limits import ReleaseFailure

    target = write_record(tmp_path, publication())
    original = _store._inventory_pass
    calls = 0
    callbacks = []

    class BytesTrap(bytes):
        def __eq__(self, other):
            callbacks.append("bytes equality")
            raise AssertionError("untrusted equality")

    class StringTrap(str):
        def __hash__(self):
            callbacks.append("string hash")
            raise AssertionError("untrusted hash")

    def check(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            classify = args[4]
            raw, relative, version = target.read_bytes(), target.parent.name + "/v1.json", 1
            if kind == "raw":
                raw = BytesTrap(raw)
            elif kind == "relative":
                relative = StringTrap(relative)
            else:
                version = True
            with pytest.raises(ReleaseFailure) as found:
                classify(raw, relative, version)
            assert found.value.reason == "store_record_invalid"
        return original(*args, **kwargs)

    monkeypatch.setattr(_store, "_inventory_pass", check)
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert result.summary()["status"] == "complete" and callbacks == []
    assert result.summary()["release_records_observed"] == 2


def test_discovery_reuse_checks_each_release_occurrence_limit(tmp_path, monkeypatch):
    from evidentia_core.release_cadence import _store

    target = write_record(tmp_path, publication())
    original = _store._inventory_pass
    calls = 0

    def boundary(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            args[1].releases = 2048
        return original(*args, **kwargs)

    monkeypatch.setattr(_store, "_inventory_pass", boundary)
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    summary = result.summary()
    assert summary["status"] == "limit_exceeded" and result.records == ()
    assert summary["release_records_observed"] == 2049 and summary["passes"] == 1
    assert summary["canonical_files_read"] == 2 and summary["raw_file_bytes_observed"] == target.stat().st_size * 2


@pytest.mark.parametrize("choice", ["explicit", "environment", "platform"])
def test_lexical_store_precedence_is_captured_before_resolution(tmp_path, monkeypatch, choice):
    from evidentia_core.release_cadence import _store

    platform_calls = []
    explicit, environment, platform = tmp_path / "explicit", tmp_path / "environment", tmp_path / "platform"

    def platform_root(application, author):
        platform_calls.append((application, author))
        return str(platform)

    monkeypatch.setattr(_store, "user_data_dir", platform_root)
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(environment))
    if choice == "platform":
        monkeypatch.delenv("EVIDENTIA_EVIDENCE_STORE_DIR")
    selected = _store.lexical_store_root(explicit if choice == "explicit" else None)
    assert (
        selected == {"explicit": explicit, "environment": environment, "platform": platform / "evidence_store"}[choice]
    )
    assert platform_calls == ([("evidentia", "Evidentia")] if choice == "platform" else [])
    assert not selected.exists()
    binding = _store.admit_root(selected, start_budget())
    assert binding.path == selected and not selected.exists()


@pytest.mark.parametrize(
    "spelling",
    [
        "..",
        "../outside",
        "\\\\server\\share",
        "\\\\?\\C:\\synthetic",
        "\\\\.\\pipe\\synthetic",
        "child:stream",
        "CON",
        "COM1.txt",
        "LPT9",
        "ending.",
        "ending ",
        "x://synthetic",
        "nul\x00inside",
    ],
)
def test_windows_lexical_refusal_precedes_enumeration(tmp_path, monkeypatch, spelling):
    import sys

    from evidentia_core.release_cadence import _store

    if sys.platform != "win32":
        pytest.skip("This case exercises the native Windows lexical branch.")
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("Unsafe root reached enumeration or opening.")

    monkeypatch.setattr(_store.os, "scandir", forbidden)
    monkeypatch.setattr(_store.os, "open", forbidden)
    value = spelling if spelling.startswith(("\\\\", "x:")) else str(tmp_path / spelling)
    result = discover(value, "Example", "Synthetic", start_budget())
    assert result.summary()["status"] == "unavailable" and result.records == ()
    assert calls == []


def test_native_hardlink_alias_refuses_descriptor_admission(tmp_path):
    from evidentia_core.release_cadence import _store
    from evidentia_core.release_cadence._limits import ReleaseFailure

    target, alias = tmp_path / "ordinary", tmp_path / "alias"
    target.write_bytes(b"authored synthetic bytes")
    os.link(target, alias)
    assert target.stat().st_nlink == 2
    ledger = _store.StoreReadBudget()
    with pytest.raises(ReleaseFailure) as caught:
        _store.read_regular(target, 128, ledger, start_budget())
    assert caught.value.reason == "store_unavailable" and ledger.consumed == 0
    assert target.read_bytes() == alias.read_bytes() == b"authored synthetic bytes"


@pytest.mark.parametrize("change", ["appearance", "disappearance"])
def test_entry_appearance_or_disappearance_between_passes_refuses(tmp_path, monkeypatch, change):
    from evidentia_core.release_cadence import _store

    ordinary = tmp_path / "ordinary.txt"
    if change == "disappearance":
        ordinary.write_bytes(b"authored unrelated root entry")
    original, calls = _store._inventory_pass, []

    def altered(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(True)
        if len(calls) == 1:
            if change == "appearance":
                ordinary.write_bytes(b"authored unrelated root entry")
            else:
                ordinary.unlink()
        return result

    monkeypatch.setattr(_store, "_inventory_pass", altered)
    result = discover(tmp_path, "Example", "Synthetic", start_budget())
    assert result.summary()["status"] == "changed" and result.records == () and len(calls) == 2


def test_captured_root_identity_replacement_refuses(tmp_path):
    from evidentia_core.release_cadence import _store
    from evidentia_core.release_cadence._limits import ReleaseFailure

    root, old = tmp_path / "root", tmp_path / "old-root"
    root.mkdir()
    binding = _store.admit_root(root, start_budget())
    root.rename(old)
    root.mkdir()
    assert old.is_dir() and root.is_dir()
    with pytest.raises(ReleaseFailure) as caught:
        binding.verify()
    assert caught.value.reason == "store_changed"


@pytest.mark.parametrize("count,status", [(4096, "complete"), (4097, "limit_exceeded")])
def test_tenant_parent_limit_keeps_fixed_discovery_status_and_closes_iterator(tmp_path, monkeypatch, count, status):
    from types import SimpleNamespace

    from evidentia_core.release_cadence import _store

    parent = tmp_path / "tenants"
    selected_root = parent / "Example"
    selected_root.mkdir(parents=True)
    original = _store.os.scandir
    streams = []

    class Entries:
        def __init__(self):
            self.position = 0
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            if self.position == count:
                raise StopIteration
            self.position += 1
            return SimpleNamespace(name=f"Unrelated{self.position}")

        def close(self):
            self.closed = True

    def bounded_entries(target):
        if Path(target) == parent:
            stream = Entries()
            streams.append(stream)
            return stream
        return original(target)

    monkeypatch.setattr(_store.os, "scandir", bounded_entries)
    budget = start_budget()
    deadline = budget.deadline
    selected = _store.lexical_store_root(str(tmp_path), tenant="Example")
    result = _store.discover(selected, "Example", "Synthetic", budget)
    assert result.summary()["status"] == status and result.records == ()
    assert streams and all(stream.closed and stream.position == count for stream in streams)
    assert budget.deadline == deadline and list(selected_root.iterdir()) == []
    if count == 4097:
        assert len(streams) == 1


@pytest.mark.parametrize("stage", ["original", "home_expanded"])
@pytest.mark.parametrize("position", ["leaf", "intermediate"])
@pytest.mark.parametrize("component", ["ending.", "ending ", "child:stream", "CON.txt"])
def test_windows_component_admission_precedes_normalization(tmp_path, monkeypatch, stage, position, component):
    import sys

    from evidentia_core.release_cadence import _store
    from evidentia_core.release_cadence._limits import ReleaseFailure

    if sys.platform != "win32":
        pytest.skip("This case exercises the native Windows lexical branch.")
    unsafe = tmp_path / component
    source = str(unsafe / "child" if position == "intermediate" else unsafe)
    if stage == "home_expanded":
        source = "~/child" if position == "intermediate" else "~"
    original_expand = _store.os.path.expanduser
    calls = []

    def expand(value):
        calls.append("expanduser")
        return original_expand(value)

    def forbidden(*args, **kwargs):
        calls.append("forbidden")
        raise AssertionError("Unsafe Windows spelling reached normalization or I/O.")

    with monkeypatch.context() as guard:
        guard.setenv("USERPROFILE", str(unsafe))
        guard.setattr(_store.os.path, "expanduser", expand)
        guard.setattr(_store.os.path, "abspath", forbidden)
        guard.setattr(_store.os, "scandir", forbidden)
        guard.setattr(_store.os, "open", forbidden)
        with pytest.raises(ReleaseFailure) as caught:
            _store.local_path(source)
    assert caught.value.reason == "store_unavailable"
    assert calls == (["expanduser"] if stage == "home_expanded" else [])


@pytest.mark.parametrize("home_kind", ["unc", "parent_component"])
def test_windows_expanded_home_cannot_introduce_unsafe_root(tmp_path, monkeypatch, home_kind):
    import sys

    from evidentia_core.release_cadence import _store
    from evidentia_core.release_cadence._limits import ReleaseFailure

    if sys.platform != "win32":
        pytest.skip("This case exercises the native Windows lexical branch.")
    home = r"\\server\share" if home_kind == "unc" else str(tmp_path / "parent" / ".." / "other")
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("Unsafe expanded home reached normalization or I/O.")

    with monkeypatch.context() as guard:
        guard.setenv("USERPROFILE", home)
        guard.setattr(_store.os.path, "abspath", forbidden)
        guard.setattr(_store.os, "scandir", forbidden)
        guard.setattr(_store.os, "open", forbidden)
        with pytest.raises(ReleaseFailure) as caught:
            _store.local_path("~/child")
    assert caught.value.reason == "store_unavailable" and calls == []


@pytest.mark.parametrize(
    "spelling", ["absolute", "relative", "dot_relative", "home", "drive_root", "current_directory"]
)
def test_windows_safe_spellings_preserve_native_local_path(tmp_path, monkeypatch, spelling):
    import sys

    from evidentia_core.release_cadence import _store

    if sys.platform != "win32":
        pytest.skip("This case exercises the native Windows lexical branch.")
    home = tmp_path / "home"
    values = {
        "absolute": (str(tmp_path / "safe"), tmp_path / "safe"),
        "relative": ("relative/child", tmp_path / "relative" / "child"),
        "dot_relative": ("./relative/child", tmp_path / "relative" / "child"),
        "home": ("~/child", home / "child"),
        "drive_root": (tmp_path.anchor, Path(tmp_path.anchor)),
        "current_directory": (".", tmp_path),
    }
    value, expected = values[spelling]
    with monkeypatch.context() as guard:
        guard.chdir(tmp_path)
        guard.setenv("USERPROFILE", str(home))
        actual = _store.local_path(value)
    assert actual == expected and not home.exists()
