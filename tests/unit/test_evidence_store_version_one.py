"""Version-one creation and collision do not enumerate lineage history."""

from __future__ import annotations

import errno
import json
import multiprocessing
import os
from pathlib import Path
from queue import Empty
from uuid import uuid4

import evidentia_core.evidence_store as store
import pytest
from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType


def artifact(identifier: str | None = None, payload: str = "first") -> EvidenceArtifact:
    identifier = identifier or str(uuid4())
    return EvidenceArtifact(
        id=identifier,
        lineage_id=identifier,
        version=1,
        predecessor_id=None,
        title="Synthetic release store boundary",
        evidence_type=EvidenceType.API_RESPONSE,
        source_system="synthetic",
        collected_by="test",
        content={"payload": payload},
    )


@pytest.fixture(autouse=True)
def no_ambient_mirror(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(store.EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR, raising=False)
    monkeypatch.delenv(store.EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR, raising=False)


def test_created_then_collision_without_history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*args: object, **kwargs: object) -> None:
        raise AssertionError("Version-one save must not enumerate history")

    monkeypatch.setattr(store, "_chain_head_version", denied)
    monkeypatch.setattr(store, "list_lineage", denied)
    monkeypatch.setattr(store, "list_lineages", denied)
    monkeypatch.setattr(Path, "glob", denied)
    value = artifact()
    expected = value.model_dump_json(indent=2).replace("\n", os.linesep).encode("utf-8")
    first = store.save_evidence_version_one(value, tmp_path)
    assert first.state == "created"
    assert first.path == tmp_path / value.id / "v1.json"
    assert first.path.read_bytes() == expected
    second = store.save_evidence_version_one(artifact(value.id, "different"), tmp_path)
    assert second.state == "collided"
    assert second.path == first.path
    assert second.path.read_bytes() == expected


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", 2),
        ("version", True),
        ("version", 1.0),
        ("lineage_id", None),
        ("lineage_id", "other"),
        ("predecessor_id", "other"),
        ("id", "../../outside"),
    ],
)
def test_exact_root_identity_before_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    candidate = artifact()
    candidate.__dict__[field] = value
    calls = []
    monkeypatch.setattr(store, "get_evidence_store_dir", lambda *args: calls.append(args))
    with pytest.raises(ValueError):
        store.save_evidence_version_one(candidate, tmp_path)
    assert calls == []


def test_subclass_refused_before_dump(tmp_path: Path) -> None:
    class Child(EvidenceArtifact):
        def model_dump_json(self, *args: object, **kwargs: object) -> str:
            raise AssertionError("Callback must not run")

    child = Child.model_validate(artifact().model_dump())
    with pytest.raises(ValueError):
        store.save_evidence_version_one(child, tmp_path)


def test_raced_collision_does_not_mirror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = artifact()
    winner = artifact(candidate.id, "winner").model_dump_json(indent=2).encode()
    out = tmp_path / candidate.id / "v1.json"
    mirror_calls = []

    def collide(source: Path, target: Path) -> None:
        assert target == out
        target.write_bytes(winner)
        raise FileExistsError

    monkeypatch.setattr(store.os, "link", collide)
    monkeypatch.setattr(store, "_resolve_auto_mirror_backend", lambda: mirror_calls.append(True))
    result = store.save_evidence_version_one(candidate, tmp_path)
    assert result.state == "collided"
    assert out.read_bytes() == winner
    assert mirror_calls == []
    assert list(out.parent.iterdir()) == [out]


def test_mirror_resolution_only_after_complete_created(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = artifact()
    out = tmp_path / candidate.id / "v1.json"
    primary = KeyboardInterrupt("synthetic mirror interruption")

    def mirror() -> None:
        assert json.loads(out.read_bytes())["id"] == candidate.id
        assert list(out.parent.iterdir()) == [out]
        raise primary

    monkeypatch.setattr(store, "_resolve_auto_mirror_backend", mirror)
    with pytest.raises(KeyboardInterrupt) as raised:
        store.save_evidence_version_one(candidate, tmp_path)
    assert raised.value is primary
    assert out.exists()


def test_unsupported_storage_preserves_unrelated_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = artifact()
    lineage = tmp_path / candidate.id
    lineage.mkdir()
    other = lineage / ".other-writer.tmp"
    other.write_bytes(b"unchanged")

    def no_link(*args: object) -> None:
        raise OSError(errno.ENOTSUP, "synthetic unsupported link")

    monkeypatch.setattr(store.os, "link", no_link)
    with pytest.raises(OSError) as raised:
        store.save_evidence_version_one(candidate, tmp_path)
    assert raised.value.errno == errno.ENOTSUP
    assert list(lineage.iterdir()) == [other]
    assert other.read_bytes() == b"unchanged"


def test_raced_legacy_collision_retains_primary_during_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = artifact()
    primary = store.EvidenceWORMViolation(candidate.id, 1, 9)
    unlinked = []
    real_unlink = store.os.unlink

    def collide(*args: object) -> None:
        raise FileExistsError

    def head(*args: object) -> int:
        raise primary

    def unlink(name: str) -> None:
        unlinked.append(name)
        real_unlink(name)
        raise KeyboardInterrupt("synthetic later cleanup")

    monkeypatch.setattr(store.os, "link", collide)
    monkeypatch.setattr(store, "_chain_head_version", head)
    monkeypatch.setattr(store.os, "unlink", unlink)
    with pytest.raises(store.EvidenceWORMViolation) as raised:
        store.save_evidence(candidate, tmp_path)
    assert raised.value is primary
    assert len(unlinked) == 1
    assert list((tmp_path / candidate.id).iterdir()) == []


def _version_one_writer(root: str, identifier: str, payload: str, start: object, results: object) -> None:
    import os

    os.environ.pop(store.EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR, None)
    os.environ.pop(store.EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR, None)
    start.wait(15)  # type: ignore[attr-defined]
    try:
        result = store.save_evidence_version_one(artifact(identifier, payload), Path(root))
        results.put((result.state, str(result.path)))  # type: ignore[attr-defined]
    except BaseException as error:
        results.put((type(error).__name__, "failed"))  # type: ignore[attr-defined]


@pytest.mark.parametrize("second", ["first", "different"])
def test_multiprocess_complete_no_replace(tmp_path: Path, second: str) -> None:
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    identifier = str(uuid4())
    processes = [
        context.Process(target=_version_one_writer, args=(str(tmp_path), identifier, value, start, results))
        for value in ("first", second)
    ]
    try:
        for process in processes:
            process.start()
        start.set()
        statuses = [results.get(timeout=30) for _ in processes]
        assert sorted(status for status, _ in statuses) == ["collided", "created"]
        raw = (tmp_path / identifier / "v1.json").read_bytes()
        stored = json.loads(raw)
        assert stored["id"] == identifier
        assert stored["content"]["payload"] in {"first", second}
        assert list((tmp_path / identifier).iterdir()) == [tmp_path / identifier / "v1.json"]
    except Empty:
        pytest.fail("Native writer failed to report")
    finally:
        for process in processes:
            if process.pid is not None:
                process.join(timeout=30)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=10)
        results.close()
        results.join_thread()
    assert all(process.exitcode == 0 for process in processes)
