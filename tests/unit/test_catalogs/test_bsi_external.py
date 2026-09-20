"""Synthetic external generations; no publisher text is distributed by these tests."""

from __future__ import annotations

import hashlib
import json

import pytest
from evidentia_core.catalogs import open_corpora, user_dir
from evidentia_core.models.open_corpora import NativeSourceError


@pytest.fixture
def synthetic_sources(monkeypatch):
    """Author all 160 groups/1,000 controls, retaining the profile's fixed shape."""
    groups = []
    control_index = 0
    for group_index in range(160):
        controls = []
        for _ in range(7 if group_index < 40 else 6):
            controls.append(
                {
                    "id": f"synthetic-{control_index}",
                    "title": "Synthetic control",
                    "parts": [{"name": "statement", "prose": "Synthetic statement."}],
                }
            )
            control_index += 1
        groups.append({"id": f"group-{group_index}", "title": "Synthetic group", "controls": controls})
    assert control_index == 1000
    raw = json.dumps(
        {
            "catalog": {
                "metadata": {"title": "Synthetic external catalog", "version": "test-v1", "oscal-version": "1.1.2"},
                "groups": groups,
            }
        },
        separators=(",", ":"),
    ).encode()
    sources = {
        "Grundschutz++-resolved_catalog.json": raw,
        "LICENSE": b"Synthetic license fixture.\n",
        "README.md": b"Synthetic publication context.\n",
    }
    profile = "bsi-grundschutz-plus-plus-367d7750"
    declarations = tuple(
        row._replace(
            repository="synthetic/local",
            commit="1" * 40,
            upstream=row.name,
            size=len(sources[row.name]),
            digest=hashlib.sha256(sources[row.name]).hexdigest(),
        )
        for row in open_corpora._SOURCES[profile]
    )
    monkeypatch.setitem(open_corpora._SOURCES, profile, declarations)
    return sources


def test_external_complete_generation_repeat_and_actual_reader(tmp_path, synthetic_sources) -> None:
    transaction = user_dir.CatalogManifestTransaction(tmp_path)
    result = transaction.commit(user_dir.CatalogMutationIntent.native(synthetic_sources))
    assert result.status == "imported"
    assert result.control_count == 1000
    assert result.source_hashes == tuple(hashlib.sha256(raw).hexdigest() for raw in synthetic_sources.values())
    generation = tmp_path / "native" / "bsi-grundschutz-plus-plus" / result.bundle_sha256
    assert {path.name for path in generation.iterdir()} == {
        "Grundschutz++-resolved_catalog.json",
        "LICENSE.txt",
        "README.md",
        "source-index.json",
        "catalog.json",
    }
    for source, stored in (
        ("Grundschutz++-resolved_catalog.json", "Grundschutz++-resolved_catalog.json"),
        ("LICENSE", "LICENSE.txt"),
        ("README.md", "README.md"),
    ):
        assert (generation / stored).read_bytes() == synthetic_sources[source]
    for leaf in ("source-index.json", "catalog.json"):
        persisted = (generation / leaf).read_bytes()
        assert persisted.endswith(b"}\n")
        assert not persisted.endswith(b"\n\n")
    before = (tmp_path / "frameworks.yaml").read_bytes()
    again = user_dir.CatalogManifestTransaction(tmp_path)
    repeated = again.commit(user_dir.CatalogMutationIntent.native(synthetic_sources))
    assert repeated.status == "already_present"
    assert repeated.bundle_sha256 == result.bundle_sha256
    assert (tmp_path / "frameworks.yaml").read_bytes() == before
    assert again.observation.publication_state == "unchanged"
    loaded = user_dir.load_registered_native_catalog(
        "bsi-grundschutz-plus-plus", bundle_sha256=result.bundle_sha256, user_dir_override=tmp_path
    )
    assert loaded.framework_name == "Synthetic external catalog"
    assert loaded.version == "test-v1"
    assert len(loaded.controls) == 1000
    assert [control.id for control in loaded.controls] == [f"synthetic-{index}" for index in range(1000)]
    assert loaded.native_source.bundle_sha256 == result.bundle_sha256
    assert [document.raw_utf8.encode() for document in loaded.native_source.data.documents] == list(
        synthetic_sources.values()
    )


@pytest.mark.parametrize(
    "leaf", ["Grundschutz++-resolved_catalog.json", "LICENSE.txt", "README.md", "source-index.json", "catalog.json"]
)
def test_external_reader_refuses_each_changed_leaf(tmp_path, synthetic_sources, leaf) -> None:
    result = user_dir.CatalogManifestTransaction(tmp_path).commit(
        user_dir.CatalogMutationIntent.native(synthetic_sources)
    )
    generation = tmp_path / "native" / "bsi-grundschutz-plus-plus" / result.bundle_sha256
    before = (tmp_path / "frameworks.yaml").read_bytes()
    target = generation / leaf
    raw = target.read_bytes()
    target.write_bytes(b"!" + raw[1:])
    with pytest.raises(ValueError):
        user_dir.load_registered_native_catalog("bsi-grundschutz-plus-plus", user_dir_override=tmp_path)
    assert (tmp_path / "frameworks.yaml").read_bytes() == before


def test_external_extra_leaf_and_wrong_requested_generation_refuse(tmp_path, synthetic_sources, monkeypatch) -> None:
    result = user_dir.CatalogManifestTransaction(tmp_path).commit(
        user_dir.CatalogMutationIntent.native(synthetic_sources)
    )
    generation = tmp_path / "native" / "bsi-grundschutz-plus-plus" / result.bundle_sha256
    (generation / "unexpected.txt").write_bytes(b"inert")
    with pytest.raises(NativeSourceError):
        user_dir.load_registered_native_catalog("bsi-grundschutz-plus-plus", user_dir_override=tmp_path)
    calls = []
    original = user_dir._closed_names

    def names(*args):
        calls.append(1)
        return original(*args)

    monkeypatch.setattr(user_dir, "_closed_names", names)
    with pytest.raises(NativeSourceError, match="catalog_generation_changed"):
        user_dir.load_registered_native_catalog(
            "bsi-grundschutz-plus-plus", bundle_sha256="0" * 64, user_dir_override=tmp_path
        )
    assert calls == []


def test_external_same_name_different_generation_bytes_never_overwrite(tmp_path, synthetic_sources) -> None:
    result = user_dir.CatalogManifestTransaction(tmp_path).commit(
        user_dir.CatalogMutationIntent.native(synthetic_sources)
    )
    generation = tmp_path / "native" / "bsi-grundschutz-plus-plus" / result.bundle_sha256
    target = generation / "README.md"
    target.write_bytes(b"changed retained bytes")
    manifest = (tmp_path / "frameworks.yaml").read_bytes()
    with pytest.raises(
        user_dir.CatalogStorageError, match=r"catalog_generation_conflict|catalog_storage_limit_exceeded"
    ):
        user_dir.CatalogManifestTransaction(tmp_path).commit(user_dir.CatalogMutationIntent.native(synthetic_sources))
    assert target.read_bytes() == b"changed retained bytes"
    assert (tmp_path / "frameworks.yaml").read_bytes() == manifest


def test_external_partial_or_unregistered_directory_has_no_registration_authority(tmp_path) -> None:
    directory = tmp_path / "native" / "bsi-grundschutz-plus-plus" / ("0" * 64)
    directory.mkdir(parents=True)
    (directory / "catalog.json").write_bytes(b"{}")
    assert user_dir.load_registered_native_catalog("bsi-grundschutz-plus-plus", user_dir_override=tmp_path) is None


def test_external_invalid_registration_refuses_before_generation_read(tmp_path, monkeypatch) -> None:
    (tmp_path / "frameworks.yaml").write_text(
        "version: 1\nframeworks:\n- id: bsi-grundschutz-plus-plus\n  name: synthetic\n  version: x\n  tier: C\n  category: control\n  path: old.json\n  native_registration:\n    format: evidentia.catalog-native.v1\n    profile: bsi-grundschutz-plus-plus-367d7750\n    bundle_sha256: '"
        + "0" * 64
        + "'\n",
        encoding="utf8",
    )
    calls = []
    monkeypatch.setattr(user_dir, "_closed_names", lambda *args: calls.append(args))
    with pytest.raises(NativeSourceError):
        user_dir.load_registered_native_catalog("bsi-grundschutz-plus-plus", user_dir_override=tmp_path)
    assert calls == []


@pytest.mark.parametrize("leaf", ["source-index.json", "catalog.json"])
@pytest.mark.parametrize("mutation", ["whitespace", "key_order"])
def test_external_generated_json_requires_exact_converter_spelling(tmp_path, synthetic_sources, leaf, mutation) -> None:
    result = user_dir.CatalogManifestTransaction(tmp_path).commit(
        user_dir.CatalogMutationIntent.native(synthetic_sources)
    )
    target = tmp_path / "native" / "bsi-grundschutz-plus-plus" / result.bundle_sha256 / leaf
    previous = target.read_bytes()
    if mutation == "whitespace":
        changed = previous + b"\n"
    else:
        value = json.loads(previous)
        changed = json.dumps(dict(reversed(tuple(value.items()))), separators=(",", ":")).encode() + b"\n"
    assert changed != previous
    target.write_bytes(changed)
    with pytest.raises(NativeSourceError):
        user_dir.load_registered_native_catalog("bsi-grundschutz-plus-plus", user_dir_override=tmp_path)
    assert target.read_bytes() == changed


@pytest.mark.parametrize("leaf", ["source-index.json", "catalog.json"])
@pytest.mark.parametrize("lf_count", [0, 1, 2])
def test_external_persisted_json_requires_one_lf(tmp_path, synthetic_sources, leaf, lf_count) -> None:
    result = user_dir.CatalogManifestTransaction(tmp_path).commit(
        user_dir.CatalogMutationIntent.native(synthetic_sources)
    )
    directory = tmp_path / "native" / "bsi-grundschutz-plus-plus" / result.bundle_sha256
    target = directory / leaf
    content = target.read_bytes().rstrip(b"\n")
    assert content.endswith(b"}")
    changed = content + b"\n" * lf_count
    target.write_bytes(changed)
    manifest = (tmp_path / "frameworks.yaml").read_bytes()
    if lf_count == 1:
        loaded = user_dir.load_registered_native_catalog("bsi-grundschutz-plus-plus", user_dir_override=tmp_path)
        assert loaded.native_source.bundle_sha256 == result.bundle_sha256
        repeated = user_dir.CatalogManifestTransaction(tmp_path).commit(
            user_dir.CatalogMutationIntent.native(synthetic_sources)
        )
        assert repeated.status == "already_present"
        assert repeated.bundle_sha256 == result.bundle_sha256
        assert repeated.projection_sha256 == result.projection_sha256
    else:
        with pytest.raises(NativeSourceError):
            user_dir.load_registered_native_catalog("bsi-grundschutz-plus-plus", user_dir_override=tmp_path)
        with pytest.raises(
            user_dir.CatalogStorageError, match=r"catalog_generation_conflict|catalog_storage_limit_exceeded"
        ):
            user_dir.CatalogManifestTransaction(tmp_path).commit(
                user_dir.CatalogMutationIntent.native(synthetic_sources)
            )
    assert target.read_bytes() == changed
    assert (tmp_path / "frameworks.yaml").read_bytes() == manifest
    for original, stored in (
        ("Grundschutz++-resolved_catalog.json", "Grundschutz++-resolved_catalog.json"),
        ("LICENSE", "LICENSE.txt"),
        ("README.md", "README.md"),
    ):
        assert (directory / stored).read_bytes() == synthetic_sources[original]


def test_external_native_import_rereads_an_actual_legacy_writer(tmp_path, synthetic_sources, monkeypatch) -> None:
    from evidentia_core.catalogs.manifest import FrameworkManifestEntry

    entry = FrameworkManifestEntry(
        id="synthetic-legacy", name="Synthetic legacy", version="one", tier="C", path="ignored.json"
    )
    raw = b'{"framework_id":"synthetic-legacy","framework_name":"Synthetic legacy","version":"one","source":"synthetic","controls":[]}'
    outer = user_dir.CatalogManifestTransaction(tmp_path)
    original = user_dir.CatalogManifestTransaction._stage
    inner_targets = []

    def stage(transaction, directory, files, budget):
        staged = original(transaction, directory, files, budget)
        if transaction is outer:
            inner_targets.append(
                user_dir.CatalogManifestTransaction(tmp_path).commit(user_dir.CatalogMutationIntent.legacy(entry, raw))
            )
        return staged

    monkeypatch.setattr(user_dir.CatalogManifestTransaction, "_stage", stage)
    result = outer.commit(user_dir.CatalogMutationIntent.native(synthetic_sources))
    assert result.status == "imported" and result.control_count == 1000
    manifest = user_dir.load_user_manifest(tmp_path)
    assert [value.id for value in manifest.frameworks] == ["synthetic-legacy", "bsi-grundschutz-plus-plus"]
    assert len(inner_targets) == 1 and inner_targets[0].read_bytes() == raw
    assert tmp_path / manifest.frameworks[0].path == inner_targets[0]
    loaded = user_dir.load_registered_native_catalog("bsi-grundschutz-plus-plus", user_dir_override=tmp_path)
    assert loaded.native_source.bundle_sha256 == result.bundle_sha256
    assert [value.id for value in loaded.controls] == [f"synthetic-{index}" for index in range(1000)]
    assert [document.raw_utf8.encode() for document in loaded.native_source.data.documents] == list(
        synthetic_sources.values()
    )
    assert outer.observation.publication_state == "committed"


@pytest.mark.parametrize("previous_kind", ["legacy", "different_native"])
def test_external_native_import_refuses_conflicting_current_registration(
    tmp_path, synthetic_sources, previous_kind
) -> None:
    from evidentia_core.catalogs.manifest import FrameworkManifest, FrameworkManifestEntry

    data = {
        "id": "bsi-grundschutz-plus-plus",
        "name": "Synthetic previous registration",
        "version": "old",
        "tier": "C",
        "category": "control",
        "path": "missing-old.json",
    }
    if previous_kind == "different_native":
        data["path"] = "native/bsi-grundschutz-plus-plus/" + "0" * 64 + "/catalog.json"
        data["native_registration"] = {
            "format": "evidentia.catalog-native.v1",
            "profile": "bsi-grundschutz-plus-plus-367d7750",
            "bundle_sha256": "0" * 64,
        }
    entry = FrameworkManifestEntry.model_validate(data)
    user_dir.save_user_manifest(FrameworkManifest(version=1, frameworks=[entry]), tmp_path)
    previous = (tmp_path / "frameworks.yaml").read_bytes()
    transaction = user_dir.CatalogManifestTransaction(tmp_path)
    with pytest.raises(user_dir.CatalogStorageError, match="catalog_generation_conflict"):
        transaction.commit(user_dir.CatalogMutationIntent.native(synthetic_sources))
    assert (tmp_path / "frameworks.yaml").read_bytes() == previous
    assert not (tmp_path / "native").exists()
    assert not (tmp_path / "missing-old.json").exists()
    assert not list(tmp_path.glob(".catalog-stage-*"))
    assert transaction.observation.publication_state == "not_attempted"
    assert transaction.observation.replace_outcome == "not_called"


@pytest.mark.parametrize("remaining", [5.0, -1.0])
def test_native_terminal_result_uses_original_publication_clock(tmp_path, synthetic_sources, monkeypatch, remaining):
    import time

    from evidentia_core.models.open_corpora import native_operation

    transaction = user_dir.CatalogManifestTransaction(tmp_path)
    original = user_dir.os.replace
    with native_operation() as budget:

        def replace(src, dst):
            original(src, dst)
            if dst.name == "frameworks.yaml":
                budget._deadline = time.monotonic() + remaining

        monkeypatch.setattr(user_dir.os, "replace", replace)
        if remaining > 0:
            result = transaction.commit(user_dir.CatalogMutationIntent.native(synthetic_sources))
            assert result.status == "imported"
            assert json.loads(transaction.result_json)["bundle_sha256"] == result.bundle_sha256
            assert transaction.observation.error_code is None
        else:
            with pytest.raises(NativeSourceError, match="processing_deadline_exceeded"):
                transaction.commit(user_dir.CatalogMutationIntent.native(synthetic_sources))
            assert transaction.result_json is None
    observation = transaction.observation
    assert observation.publication_state == "committed"
    assert observation.readback_result == ("matches_proposed" if remaining > 0 else "unavailable")
    assert observation.error_code == (None if remaining > 0 else "processing_deadline_exceeded")
    assert user_dir.load_user_manifest(tmp_path).get("bsi-grundschutz-plus-plus") is not None


@pytest.mark.parametrize("surface", ["api", "cli"])
@pytest.mark.parametrize("remaining", [5.0, -1.0])
def test_native_consumers_preserve_committed_state_at_clock_boundary(
    tmp_path, synthetic_sources, monkeypatch, surface, remaining
):
    import asyncio
    import time

    from evidentia_core.models import open_corpora as models

    directory = tmp_path / "catalogs"
    monkeypatch.setenv("EVIDENTIA_CATALOG_DIR", str(directory))
    original = user_dir.os.replace
    budgets = []

    def replace(src, dst):
        original(src, dst)
        if dst.name == "frameworks.yaml":
            budget = models._ACTIVE_BUDGET.get()
            assert budget is not None
            budgets.append(budget)
            budget._deadline = time.monotonic() + remaining

    monkeypatch.setattr(user_dir.os, "replace", replace)
    if surface == "api":
        from evidentia_api.routers import catalog as api
        from starlette.requests import Request

        names = ("bsi-catalog", "bsi-license", "bsi-readme")
        body = json.dumps(
            {
                "profile": "bsi-grundschutz-plus-plus-367d7750",
                "documents": [
                    {"source_key": key, "raw_utf8": raw.decode()}
                    for key, raw in zip(names, synthetic_sources.values(), strict=True)
                ],
            }
        ).encode()

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        request = Request({"type": "http", "headers": [(b"content-type", b"application/json")]}, receive)
        response = asyncio.run(api.import_native_catalog(request))
        assert response.status_code == (201 if remaining > 0 else 503)
        data = json.loads(response.body)
        if remaining > 0:
            assert data["status"] == "imported"
        else:
            envelope = models.CatalogStorageErrorEnvelope.model_validate(data)
            assert envelope.code == envelope.publication.error_code == "processing_deadline_exceeded"
            assert envelope.publication.publication_state == "committed"
            assert envelope.publication.readback_result == "unavailable"
    else:
        from evidentia.cli.catalog import app
        from typer.testing import CliRunner

        source = tmp_path / "sources"
        source.mkdir()
        for name, raw in synthetic_sources.items():
            (source / name).write_bytes(raw)
        response = CliRunner().invoke(
            app, ["import", "--native-profile", "bsi-grundschutz-plus-plus-367d7750", "--source-dir", str(source)]
        )
        assert response.exit_code == (0 if remaining > 0 else 1), response.output
        if remaining > 0:
            assert json.loads(response.output)["status"] == "imported"
        else:
            assert "processing_deadline_exceeded" in response.output
            assert '"publication_state": "committed"' in response.output
            assert '"status": "imported"' not in response.output
    assert len(budgets) == 1
    assert models._ACTIVE_BUDGET.get() is None
    assert user_dir.load_user_manifest(directory).get("bsi-grundschutz-plus-plus") is not None


def test_native_result_serialization_failure_cannot_publish(tmp_path, synthetic_sources, monkeypatch):
    from evidentia_core.models.open_corpora import ImportResult

    calls = []

    def refuse(*args, **kwargs):
        raise OSError("synthetic result serialization failure")

    monkeypatch.setattr(ImportResult, "model_dump_json", refuse)
    monkeypatch.setattr(user_dir.os, "replace", lambda *args: calls.append(args))
    transaction = user_dir.CatalogManifestTransaction(tmp_path)
    with pytest.raises(OSError, match="synthetic result serialization failure"):
        transaction.commit(user_dir.CatalogMutationIntent.native(synthetic_sources))
    assert calls == []
    assert transaction.result_json is None
    assert transaction.observation.publication_state == "not_attempted"
    assert not (tmp_path / "frameworks.yaml").exists()


def test_native_clock_expiry_preserves_primary_interruption(tmp_path, synthetic_sources, monkeypatch):
    import time

    from evidentia_core.models import open_corpora as models

    transaction = user_dir.CatalogManifestTransaction(tmp_path)
    primary = KeyboardInterrupt("synthetic interruption")
    original = user_dir.os.replace

    def replace(src, dst):
        original(src, dst)
        if dst.name == "frameworks.yaml":
            models._ACTIVE_BUDGET.get()._deadline = time.monotonic() - 1.0
            raise primary

    monkeypatch.setattr(user_dir.os, "replace", replace)
    with models.native_operation(), pytest.raises(KeyboardInterrupt) as caught:
        transaction.commit(user_dir.CatalogMutationIntent.native(synthetic_sources))
    assert caught.value is primary
    assert transaction.result_json is None
    observation = transaction.observation
    assert observation.primary_kind == "base_exception"
    assert observation.error_code == "catalog_interrupted"
    assert observation.replace_outcome == "raised"
    assert observation.publication_state == "indeterminate"
    assert observation.readback_result == "unavailable"
    assert user_dir.load_user_manifest(tmp_path).get("bsi-grundschutz-plus-plus") is not None


def test_native_observed_terminal_must_match_prevalidated_success(tmp_path, synthetic_sources, monkeypatch):
    original = user_dir.CatalogManifestTransaction._readback

    def readback(transaction, output, prior, proposed, ledger, budget, primary):
        original(transaction, output, prior, proposed, ledger, budget, primary)
        ledger["readback_result"] = "unavailable"
        ledger["observed_manifest_state"] = "not_observed"
        ledger["observed_sha256"] = None

    monkeypatch.setattr(user_dir.CatalogManifestTransaction, "_readback", readback)
    transaction = user_dir.CatalogManifestTransaction(tmp_path)
    with pytest.raises(user_dir.CatalogStorageError, match="catalog_publication_indeterminate"):
        transaction.commit(user_dir.CatalogMutationIntent.native(synthetic_sources))
    assert transaction.result_json is None
