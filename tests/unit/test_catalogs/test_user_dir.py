"""Tests for the user-catalog directory facility (catalogs/user_dir.py)."""

from __future__ import annotations

import json

import pytest
from evidentia_core.catalogs.manifest import (
    FrameworkManifest,
    FrameworkManifestEntry,
    load_manifest,
)
from evidentia_core.catalogs.user_dir import (
    get_user_catalog_dir,
    load_user_manifest,
    resolve_catalog_path,
    save_user_manifest,
    user_manifest_path,
)


def test_default_user_dir_under_platform_dirs(tmp_path, monkeypatch) -> None:
    """Without override, the user dir falls under platformdirs' app dir."""
    monkeypatch.delenv("EVIDENTIA_CATALOG_DIR", raising=False)
    path = get_user_catalog_dir()
    # We don't hardcode the exact path (varies by OS) — just sanity check
    # it ends with our app folder
    assert "evidentia" in str(path).lower() or "Evidentia" in str(path)


def test_env_override_wins(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("EVIDENTIA_CATALOG_DIR", str(tmp_path))
    assert get_user_catalog_dir() == tmp_path.resolve()


def test_explicit_override_wins_over_env(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("EVIDENTIA_CATALOG_DIR", str(tmp_path / "env"))
    override = tmp_path / "explicit"
    assert get_user_catalog_dir(override) == override.resolve()


def test_missing_user_manifest_returns_empty(tmp_path) -> None:
    manifest = load_user_manifest(tmp_path)
    assert manifest.version == 1
    assert manifest.frameworks == []


def test_roundtrip_user_manifest(tmp_path) -> None:
    entry = FrameworkManifestEntry(
        id="my-iso27001",
        name="ISO 27001:2022 (licensed copy)",
        version="2022",
        tier="C",
        category="control",
        path="my-iso27001.json",
        license="Copyright ISO/IEC — licensed copy",
        placeholder=False,
    )
    saved = save_user_manifest(FrameworkManifest(version=1, frameworks=[entry]), tmp_path)
    assert saved == user_manifest_path(tmp_path)
    assert saved.exists()

    reloaded = load_user_manifest(tmp_path)
    assert len(reloaded.frameworks) == 1
    assert reloaded.frameworks[0].id == "my-iso27001"
    assert reloaded.frameworks[0].tier == "C"


def test_user_entry_shadows_bundled(tmp_path) -> None:
    """A user-dir catalog with the same ID as a bundled one wins."""
    bundled = load_manifest()
    assert bundled.get("nist-800-53-mod") is not None

    # Drop a fake user catalog for nist-800-53-mod
    fake_json = tmp_path / "nist-800-53-mod.json"
    fake_json.write_text(
        json.dumps(
            {
                "framework_id": "nist-800-53-mod",
                "framework_name": "Custom NIST 800-53 Moderate",
                "version": "custom",
                "source": "user override",
                "controls": [],
            }
        )
    )
    save_user_manifest(
        FrameworkManifest(
            version=1,
            frameworks=[
                FrameworkManifestEntry(
                    id="nist-800-53-mod",
                    name="Custom NIST 800-53 Moderate",
                    version="custom",
                    tier="A",
                    category="control",
                    path="nist-800-53-mod.json",
                )
            ],
        ),
        tmp_path,
    )

    path, _entry, source = resolve_catalog_path(
        "nist-800-53-mod",
        bundled_manifest=bundled,
        user_dir_override=tmp_path,
    )
    assert source == "user"
    # resolve_catalog_path returns the RESOLVED, containment-checked path
    # (the value its is_relative_to guard checked) so CodeQL's path-injection
    # barrier recognizes the guard; compare against the resolved fixture path.
    assert path == fake_json.resolve()


def test_resolve_falls_through_to_bundled(tmp_path) -> None:
    bundled = load_manifest()
    path, _entry, source = resolve_catalog_path(
        "nist-800-53-mod",
        bundled_manifest=bundled,
        user_dir_override=tmp_path,
    )
    assert source == "bundled"
    assert path.name == "nist-800-53-mod.json"


def test_resolve_unknown_framework_raises(tmp_path) -> None:
    bundled = load_manifest()
    with pytest.raises(ValueError, match="Unknown framework"):
        resolve_catalog_path(
            "not-a-framework",
            bundled_manifest=bundled,
            user_dir_override=tmp_path,
        )


def test_resolve_rejects_user_path_escaping_user_dir(tmp_path) -> None:
    """A user-manifest entry whose path escapes the user dir is refused
    (defense-in-depth path containment, CWE-22). The API import endpoint never
    writes such a path (``framework_id`` is regex-validated), but a hand-edited
    or otherwise-tampered manifest could carry one — it must never reach the
    file loader. The manifest model itself does not validate the path, so this
    containment check in ``resolve_catalog_path`` is the guard.
    """
    bundled = load_manifest()
    save_user_manifest(
        FrameworkManifest(
            version=1,
            frameworks=[
                FrameworkManifestEntry(
                    id="evil",
                    name="Escaping catalog",
                    version="x",
                    tier="A",
                    category="control",
                    path="../../escape.json",
                )
            ],
        ),
        tmp_path,
    )
    with pytest.raises(ValueError, match="escapes the user"):
        resolve_catalog_path(
            "evil",
            bundled_manifest=bundled,
            user_dir_override=tmp_path,
        )


def _native_entry_data() -> dict:
    digest = "a" * 64
    return {
        "id": "bsi-grundschutz-plus-plus",
        "name": "Synthetic native catalog",
        "version": "synthetic",
        "tier": "C",
        "category": "control",
        "path": f"native/bsi-grundschutz-plus-plus/{digest}/catalog.json",
        "native_registration": {
            "format": "evidentia.catalog-native.v1",
            "profile": "bsi-grundschutz-plus-plus-367d7750",
            "bundle_sha256": digest,
        },
    }


def test_f2_native_registration_is_closed_and_legacy_null_is_omitted() -> None:
    entry = FrameworkManifestEntry.model_validate(_native_entry_data())
    assert entry.native_registration.bundle_sha256 == "a" * 64
    legacy = _native_entry_data()
    legacy.pop("native_registration")
    assert "native_registration" not in FrameworkManifestEntry.model_validate(legacy).model_dump(exclude_none=True)


@pytest.mark.parametrize("field", ["id", "category", "path"])
def test_f2_registration_checks_raw_cross_fields_before_stripping(field) -> None:
    data = _native_entry_data()
    data[field] = " " + data[field]
    with pytest.raises(ValueError):
        FrameworkManifestEntry.model_validate(data)


def test_f2_failed_manifest_serialization_preserves_exact_previous_bytes(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module

    previous = b"version: 1\nframeworks: []\n"
    target = tmp_path / "frameworks.yaml"
    target.write_bytes(previous)
    primary = RuntimeError("synthetic serializer failure")

    def refuse(*args, **kwargs):
        raise primary

    monkeypatch.setattr(module.yaml, "safe_dump", refuse)
    with pytest.raises(RuntimeError) as caught:
        save_user_manifest(FrameworkManifest(version=1, frameworks=[]), tmp_path)
    assert caught.value is primary
    assert target.read_bytes() == previous


def test_f2_manifest_save_replaces_one_complete_file(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module

    original = module.os.replace
    calls = []

    def observed(source, target):
        from pathlib import Path

        body = Path(source).read_bytes()
        assert body.startswith(b"version: 1\n")
        assert b"frameworks: []" in body
        calls.append((Path(source), Path(target)))
        return original(source, target)

    monkeypatch.setattr(module.os, "replace", observed)
    save_user_manifest(FrameworkManifest(version=1, frameworks=[]), tmp_path)
    assert len(calls) == 1
    assert calls[0][0] != calls[0][1]


@pytest.mark.parametrize(
    "raw",
    [
        b"version: 1\nversion: 2\nframeworks: []\n",
        b"version: 1\nframeworks: &a []\nother: *a\n",
        b"version: 1\nframeworks: []\nframeworks: []\n",
    ],
)
def test_f2_manifest_rejects_duplicate_or_alias_state_without_rewrite(tmp_path, raw) -> None:
    path = tmp_path / "frameworks.yaml"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        load_user_manifest(tmp_path)
    assert path.read_bytes() == raw


def test_f2_transaction_consumes_an_intent_once_even_after_failure(tmp_path) -> None:
    import evidentia_core.catalogs.user_dir as module

    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(ValueError):
        transaction.commit(module.CatalogMutationIntent.remove("missing"))
    observation = transaction.observation
    assert observation.publication_state == "not_attempted"
    with pytest.raises(ValueError):
        transaction.commit(module.CatalogMutationIntent.remove("missing"))
    assert transaction.observation is observation


def _legacy_import(version="one"):
    import evidentia_core.catalogs.user_dir as module

    entry = FrameworkManifestEntry(id="local", name="Local", version=version, tier="C", path="ignored.json")
    raw = json.dumps(
        {"framework_id": "local", "framework_name": "Local", "version": version, "source": "synthetic", "controls": []}
    ).encode()
    return module.CatalogMutationIntent.legacy(entry, raw), raw


def test_f2_legacy_generations_retain_prior_and_remove_does_not_open_payload(tmp_path, monkeypatch) -> None:
    import hashlib

    import evidentia_core.catalogs.user_dir as module

    first, raw = _legacy_import()
    target = module.CatalogManifestTransaction(tmp_path).commit(first)
    assert target == tmp_path / "legacy" / hashlib.sha256(raw).hexdigest() / "catalog.json"
    assert target.read_bytes() == raw
    before = (tmp_path / "frameworks.yaml").read_bytes()
    other, second_raw = _legacy_import("two")
    with pytest.raises(ValueError, match="already registered"):
        module.CatalogManifestTransaction(tmp_path).commit(other)
    assert (tmp_path / "frameworks.yaml").read_bytes() == before
    second = module.CatalogManifestTransaction(tmp_path).commit(
        module.CatalogMutationIntent.legacy(other.entry, second_raw, force=True)
    )
    assert target.read_bytes() == raw
    assert second.read_bytes() == second_raw
    current = load_user_manifest(tmp_path)
    digest = module.catalog_entry_sha256(current.frameworks[0])
    with pytest.raises(module.CatalogStorageError, match="transaction_conflict"):
        module.CatalogManifestTransaction(tmp_path).commit(
            module.CatalogMutationIntent.remove("local", expected_entry_sha256="0" * 64)
        )
    reads = []
    original = module._bounded_read

    def read(path, *args, **kwargs):
        reads.append(path.name)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(module, "_bounded_read", read)
    transaction = module.CatalogManifestTransaction(tmp_path)
    transaction.commit(module.CatalogMutationIntent.remove("local", expected_entry_sha256=digest))
    assert reads == ["frameworks.yaml", "frameworks.yaml"]
    assert load_user_manifest(tmp_path).frameworks == []
    assert target.read_bytes() == raw and second.read_bytes() == second_raw
    assert transaction.observation.publication_state == "committed"


def test_f2_unregistered_flat_file_does_not_require_force(tmp_path) -> None:
    import evidentia_core.catalogs.user_dir as module

    old = tmp_path / "local.json"
    old.write_bytes(b"unregistered old data")
    intent, _ = _legacy_import()
    module.CatalogManifestTransaction(tmp_path).commit(intent)
    assert old.read_bytes() == b"unregistered old data"


@pytest.mark.parametrize(
    "mode,state,readback,code",
    [
        ("prior", "not_committed", "matches_prior", "catalog_publication_failed"),
        ("proposed", "committed", "matches_proposed", "catalog_publication_failed"),
        ("other", "indeterminate", "other", "catalog_publication_indeterminate"),
        ("unavailable", "indeterminate", "unavailable", "catalog_publication_indeterminate"),
    ],
)
def test_f2_replace_exception_reports_exact_observed_state(tmp_path, monkeypatch, mode, state, readback, code) -> None:
    import evidentia_core.catalogs.user_dir as module

    old = b"version: 1\nframeworks: []\n"
    (tmp_path / "frameworks.yaml").write_bytes(old)
    primary = RuntimeError("synthetic replace boundary")
    original = module.os.replace
    original_read = module._bounded_read
    attempted = False

    def replace(source, target):
        nonlocal attempted
        attempted = True
        if mode == "proposed":
            original(source, target)
        elif mode == "other":
            target.write_bytes(b"version: 99\nframeworks: []\n")
        raise primary

    def read(path, *args, **kwargs):
        if attempted and mode == "unavailable":
            raise OSError("synthetic unavailable")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(module.os, "replace", replace)
    monkeypatch.setattr(module, "_bounded_read", read)
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(RuntimeError) as caught:
        transaction._replace_complete(FrameworkManifest(version=2, frameworks=[]))
    assert caught.value is primary
    observed = transaction.observation
    assert observed.publication_state == state
    assert observed.readback_result == readback
    assert observed.error_code == code
    assert observed.replace_outcome == "raised"
    assert observed.cleanup_state == "complete"
    assert len(observed.model_dump_json().encode()) <= 4096


@pytest.mark.parametrize("primary_type", [RuntimeError, KeyboardInterrupt])
def test_f2_cleanup_cannot_replace_primary(tmp_path, monkeypatch, primary_type) -> None:
    import evidentia_core.catalogs.user_dir as module

    primary = primary_type("synthetic primary")
    cleanup = SystemExit("synthetic cleanup")
    original_close = module._NativeLock.close

    def refuse(*args):
        raise primary

    def close(self):
        assert original_close(self) == []
        return [("lock_release_failed", cleanup), ("handle_close_failed", cleanup)]

    monkeypatch.setattr(module.os, "replace", refuse)
    monkeypatch.setattr(module._NativeLock, "close", close)
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(primary_type) as caught:
        transaction._replace_complete(FrameworkManifest(version=1, frameworks=[]))
    assert caught.value is primary
    assert transaction.observation.cleanup_errors == ("lock_release_failed", "handle_close_failed")
    assert transaction.observation.primary_kind == ("exception" if primary_type is RuntimeError else "base_exception")


def test_f2_success_path_cleanup_failure_is_visible_after_commit(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module

    primary = RuntimeError("synthetic close failure")
    original_close = module._NativeLock.close

    def close(self):
        assert original_close(self) == []
        return [("handle_close_failed", primary)]

    monkeypatch.setattr(module._NativeLock, "close", close)
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(RuntimeError) as caught:
        transaction._replace_complete(FrameworkManifest(version=1, frameworks=[]))
    assert caught.value is primary
    assert (tmp_path / "frameworks.yaml").read_bytes() == b"version: 1\nframeworks: []\n"
    assert transaction.observation.publication_state == "committed"
    assert transaction.observation.error_code == "catalog_cleanup_failed"


def test_f2_expiry_after_replace_does_no_new_read_or_path_cleanup(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module
    import evidentia_core.models.open_corpora as models

    clock = [100.0]
    monkeypatch.setattr(models.time, "monotonic", lambda: clock[0])
    original_replace = module.os.replace
    original_read = module._bounded_read
    reads = []

    def replace(source, target):
        original_replace(source, target)
        clock[0] = 161.0

    def read(*args, **kwargs):
        reads.append(clock[0])
        return original_read(*args, **kwargs)

    monkeypatch.setattr(module.os, "replace", replace)
    monkeypatch.setattr(module, "_bounded_read", read)
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(models.NativeSourceError, match="processing_deadline_exceeded"):
        transaction._replace_complete(FrameworkManifest(version=1, frameworks=[]))
    assert reads == [100.0]
    assert transaction.observation.publication_state == "committed"
    assert transaction.observation.readback_result == "unavailable"
    assert transaction.observation.error_code == "processing_deadline_exceeded"
    assert transaction.observation.cleanup_state == "complete"
    # The stable lock remains empty and can be acquired by a fresh owner.
    assert (tmp_path / "frameworks.yaml.lock").read_bytes() == b""
    assert len(transaction.observation.model_dump_json().encode()) <= 4096


def test_f2_expired_ambient_budget_is_never_reset(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module
    import evidentia_core.models.open_corpora as models

    clock = [100.0]
    monkeypatch.setattr(models.time, "monotonic", lambda: clock[0])
    transaction = module.CatalogManifestTransaction(tmp_path)
    with models.native_operation() as original:
        clock[0] = 161.0
        with pytest.raises(models.NativeSourceError) as caught:
            transaction.commit(module.CatalogMutationIntent.remove("absent"))
        primary = caught.value
        assert primary.code == "processing_deadline_exceeded"
        assert models._ACTIVE_BUDGET.get() is original
        with pytest.raises(ValueError, match="processing_deadline_exceeded"):
            _ = transaction.observation
        assert list(tmp_path.iterdir()) == []
    assert transaction.observation.publication_state == "not_attempted"
    assert transaction.observation.error_code == primary.code


def test_f2_stable_lock_busy_is_one_nonblocking_attempt(tmp_path) -> None:
    import evidentia_core.catalogs.user_dir as module
    from evidentia_core.models.open_corpora import native_operation

    first = module._NativeLock(tmp_path)
    with native_operation() as budget:
        first.acquire(budget)
        try:
            transaction = module.CatalogManifestTransaction(tmp_path)
            with pytest.raises(module.CatalogStorageError, match="catalog_transaction_conflict"):
                transaction._replace_complete(FrameworkManifest(version=1, frameworks=[]))
            assert transaction.observation.publication_state == "not_attempted"
            assert not (tmp_path / "frameworks.yaml").exists()
        finally:
            assert first.close() == []
    assert (tmp_path / "frameworks.yaml.lock").read_bytes() == b""


def test_f2_invalid_manifest_is_not_repaired(tmp_path) -> None:
    import evidentia_core.catalogs.user_dir as module

    raw = b"version: 1\nversion: 2\nframeworks: []\n"
    (tmp_path / "frameworks.yaml").write_bytes(raw)
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(module.CatalogStorageError, match="catalog_manifest_invalid"):
        transaction._replace_complete(FrameworkManifest(version=1, frameworks=[]))
    assert (tmp_path / "frameworks.yaml").read_bytes() == raw
    assert transaction.observation.publication_state == "not_attempted"


@pytest.mark.parametrize("mutation", ["extra", "upper_digest", "false", "missing_category", "wrong_path"])
def test_f2_native_registration_cannot_be_relaxed_by_model_options(mutation) -> None:
    data = _native_entry_data()
    if mutation == "extra":
        data["native_registration"]["extra"] = "inert"
    elif mutation == "upper_digest":
        data["native_registration"]["bundle_sha256"] = "A" * 64
    elif mutation == "false":
        data["native_registration"] = False
    elif mutation == "missing_category":
        del data["category"]
    else:
        data["path"] = "old.json"
    with pytest.raises(ValueError):
        FrameworkManifestEntry.model_validate(data, strict=False, extra="ignore")


def test_f2_native_registration_json_mode_refuses_lost_duplicate_evidence() -> None:
    with pytest.raises(ValueError):
        FrameworkManifestEntry.model_validate_json(json.dumps(_native_entry_data()))


@pytest.mark.parametrize("kind", ["mapping", "attributes"])
def test_f2_native_raw_cross_fields_cannot_bypass_checks_through_outer_objects(kind) -> None:
    from collections import UserDict
    from types import SimpleNamespace

    data = _native_entry_data()
    data["id"] = " " + data["id"]
    value = UserDict(data) if kind == "mapping" else SimpleNamespace(**data)
    with pytest.raises(ValueError):
        FrameworkManifestEntry.model_validate(value, from_attributes=True)


@pytest.mark.parametrize("kind", ["mapping", "attributes"])
def test_f2_legacy_outer_objects_keep_existing_stripping_behavior(kind) -> None:
    from collections import UserDict
    from types import SimpleNamespace

    data = _native_entry_data()
    data.pop("native_registration")
    data["id"] = " synthetic-legacy "
    value = UserDict(data) if kind == "mapping" else SimpleNamespace(**data)
    assert FrameworkManifestEntry.model_validate(value, from_attributes=True).id == "synthetic-legacy"


def test_f2_native_model_instances_are_recaptured_before_manifest_use() -> None:
    entry = FrameworkManifestEntry.model_validate(_native_entry_data())
    manifest = FrameworkManifest(version=1, frameworks=[entry])
    assert manifest.frameworks[0] is not entry
    assert manifest.frameworks[0].model_dump() == entry.model_dump()
    entry.id = " " + entry.id
    with pytest.raises(ValueError):
        FrameworkManifestEntry.model_validate(entry)
    with pytest.raises(ValueError):
        FrameworkManifest(version=1, frameworks=[entry])


@pytest.mark.parametrize("mutation", ["parent_extra", "nested_extra", "wrong_format", "constructed_raw_id"])
def test_f2_forged_native_models_do_not_lose_admission_evidence(mutation) -> None:
    entry = FrameworkManifestEntry.model_validate(_native_entry_data())
    if mutation == "parent_extra":
        entry.__dict__["unexpected"] = "preserve for refusal"
    elif mutation == "nested_extra":
        entry.native_registration.__dict__["unexpected"] = "preserve for refusal"
    elif mutation == "wrong_format":
        object.__setattr__(entry.native_registration, "format", "other")
    else:
        raw = _native_entry_data()
        raw["id"] = " " + raw["id"]
        entry = FrameworkManifestEntry.model_construct(**raw)
    with pytest.raises(ValueError):
        FrameworkManifestEntry.model_validate(entry, strict=False, extra="ignore")


def test_f2_linux_unknown_abi_refuses_before_any_storage_write(tmp_path, monkeypatch) -> None:
    import ctypes
    import platform
    import sys

    from evidentia_core.catalogs import user_dir

    assert ctypes.sizeof(ctypes.c_int) > 0
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(platform, "machine", lambda: "unsupported-abi")
    destination = tmp_path / "absent" / "catalogs"
    with pytest.raises(user_dir.CatalogStorageError, match="catalog_storage_unsupported"):
        user_dir.save_user_manifest(FrameworkManifest(version=1, frameworks=[]), destination)
    assert not destination.parent.exists()


def test_f2_remove_can_unregister_a_missing_or_escaping_payload(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module

    entry = FrameworkManifestEntry(id="bad", name="bad", version="one", tier="C", path="../../missing.json")
    save_user_manifest(FrameworkManifest(version=1, frameworks=[entry]), tmp_path)
    reads = []
    original = module._bounded_read

    def read(path, *args, **kwargs):
        reads.append(path.name)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(module, "_bounded_read", read)
    module.CatalogManifestTransaction(tmp_path).commit(module.CatalogMutationIntent.remove("bad"))
    assert reads == ["frameworks.yaml", "frameworks.yaml"]


def test_f2_fresh_manifest_preserves_a_writer_before_lock_acquisition(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module

    original = module.CatalogManifestTransaction._stage
    injected = False

    def stage(self, directory, files, budget):
        nonlocal injected
        result = original(self, directory, files, budget)
        if not injected:
            injected = True
            entry = FrameworkManifestEntry(id="other", name="other", version="one", tier="C", path="old.json")
            save_user_manifest(FrameworkManifest(version=1, frameworks=[entry]), tmp_path)
        return result

    monkeypatch.setattr(module.CatalogManifestTransaction, "_stage", stage)
    intent, _ = _legacy_import()
    module.CatalogManifestTransaction(tmp_path).commit(intent)
    assert [entry.id for entry in load_user_manifest(tmp_path).frameworks] == ["other", "local"]


def test_f2_captured_entry_cannot_change_during_storage_preparation(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module

    original = module.CatalogManifestTransaction._stage
    intent, _ = _legacy_import()

    def stage(self, directory, files, budget):
        intent.entry.name = "mutated caller value"
        object.__setattr__(intent, "framework_id", "other")
        return original(self, directory, files, budget)

    monkeypatch.setattr(module.CatalogManifestTransaction, "_stage", stage)
    module.CatalogManifestTransaction(tmp_path).commit(intent)
    entry = load_user_manifest(tmp_path).frameworks[0]
    assert entry.id == "local"
    assert entry.name == "Local"


@pytest.mark.parametrize("phase", ["fsync", "write"])
def test_f2_prepublication_io_failures_preserve_primary_and_prior(tmp_path, monkeypatch, phase) -> None:
    import evidentia_core.catalogs.user_dir as module

    prior = b"version: 1\nframeworks: []\n"
    (tmp_path / "frameworks.yaml").write_bytes(prior)
    primary = KeyboardInterrupt("synthetic storage interruption")

    def refuse(*args):
        raise primary

    monkeypatch.setattr(module.os, phase, refuse)
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(KeyboardInterrupt) as caught:
        transaction._replace_complete(FrameworkManifest(version=2, frameworks=[]))
    assert caught.value is primary
    assert transaction.observation.replace_outcome == "not_called"
    assert transaction.observation.publication_state == "not_attempted"
    assert (tmp_path / "frameworks.yaml").read_bytes() == prior
    assert {path.name for path in tmp_path.iterdir()} == {"frameworks.yaml", "frameworks.yaml.lock"}


def test_f2_expired_cleanup_retains_temp_without_path_visit(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module
    import evidentia_core.models.open_corpora as models

    clock = [100.0]
    monkeypatch.setattr(models.time, "monotonic", lambda: clock[0])
    primary = KeyboardInterrupt("synthetic expired replace")

    def refuse(*args):
        clock[0] = 161.0
        raise primary

    monkeypatch.setattr(module.os, "replace", refuse)
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(KeyboardInterrupt) as caught:
        transaction._replace_complete(FrameworkManifest(version=1, frameworks=[]))
    assert caught.value is primary
    assert transaction.observation.cleanup_errors == ("temporary_cleanup_failed",)
    assert transaction.observation.publication_state == "indeterminate"
    assert transaction.observation.error_code == "catalog_interrupted"
    assert len([path for path in tmp_path.iterdir() if path.name.startswith(".frameworks-")]) == 1
    assert not (tmp_path / "frameworks.yaml").exists()


def test_f2_terminal_diagnostic_failure_never_replaces_primary(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module

    primary = RuntimeError("synthetic missing entry")
    diagnostic = SystemExit("synthetic diagnostic failure")

    def prepare(*args):
        raise primary

    def validate(*args, **kwargs):
        raise diagnostic

    monkeypatch.setattr(module.CatalogManifestTransaction, "_prepare", prepare)
    monkeypatch.setattr(module.CatalogPublicationObservation, "model_validate", validate)
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(RuntimeError) as caught:
        transaction.commit(module.CatalogMutationIntent.remove("absent"))
    assert caught.value is primary
    assert list(tmp_path.iterdir()) == []


def test_f2_same_transaction_concurrent_begin_is_refused(tmp_path, monkeypatch) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    import evidentia_core.catalogs.user_dir as module

    entered, release = Event(), Event()
    original = module.CatalogManifestTransaction._prepare

    def prepare(*args):
        entered.set()
        assert release.wait(10)
        return original(*args)

    monkeypatch.setattr(module.CatalogManifestTransaction, "_prepare", prepare)
    transaction = module.CatalogManifestTransaction(tmp_path)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(transaction._replace_complete, FrameworkManifest(version=1, frameworks=[]))
        try:
            assert entered.wait(10)
            with pytest.raises(module.CatalogStorageError, match="transaction_conflict"):
                transaction.commit(module.CatalogMutationIntent.remove("absent"))
        finally:
            release.set()
        pending.result(timeout=10)
    assert transaction.observation.publication_state == "committed"


def test_f2_nonempty_and_hardlinked_lock_targets_are_refused(tmp_path) -> None:
    import os

    import evidentia_core.catalogs.user_dir as module

    lock = tmp_path / "frameworks.yaml.lock"
    lock.write_bytes(b"nonempty")
    with pytest.raises(module.CatalogStorageError, match="storage_unsupported"):
        save_user_manifest(FrameworkManifest(version=1, frameworks=[]), tmp_path)
    assert lock.read_bytes() == b"nonempty"
    lock.write_bytes(b"")
    os.link(lock, tmp_path / "second-link")
    with pytest.raises(module.CatalogStorageError, match="storage_unsupported"):
        save_user_manifest(FrameworkManifest(version=1, frameworks=[]), tmp_path)
    assert not (tmp_path / "frameworks.yaml").exists()


def test_f2_closed_generation_enumeration_propagates_errors(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module
    from evidentia_core.models.open_corpora import native_operation

    primary = PermissionError("synthetic unreadable directory")

    def refuse(*args):
        raise primary

    monkeypatch.setattr(module.os, "scandir", refuse)
    with native_operation() as budget, pytest.raises(PermissionError) as caught:
        module._closed_names(tmp_path, ("catalog.json",), budget)
    assert caught.value is primary


def _fake_linux_statfs(monkeypatch, magic=0xEF53, result=0, primary=None, after=None):
    import ctypes
    import platform
    import sys
    from types import SimpleNamespace

    calls = []

    class Query:
        def __call__(self, descriptor, pointer):
            value = pointer._obj
            calls.append(
                (
                    descriptor,
                    ctypes.sizeof(value),
                    ctypes.alignment(value),
                    tuple(getattr(type(value), name).offset for name, _ in value._fields_),
                )
            )
            if primary is not None:
                raise primary
            value.f_type = magic
            if after is not None:
                after()
            return result

    library = SimpleNamespace(fstatfs=Query(), gnu_get_libc_version=lambda: b"2.39")
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(ctypes, "c_long", ctypes.c_int64)
    monkeypatch.setattr(ctypes, "c_ulong", ctypes.c_uint64)
    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: library)
    return calls, library


@pytest.mark.parametrize("magic", [0xEF53, 0x01021994, 0x6969, 0xFF534D42, 0xFE534D42, 0x794C7630, 0x65735546, 0x1234])
def test_f2_linux_fd_query_admits_only_ratified_ext_family(monkeypatch, magic) -> None:
    from evidentia_core.catalogs import user_dir
    from evidentia_core.models.open_corpora import NativeBudget

    calls, library = _fake_linux_statfs(monkeypatch, magic)
    if magic == 0xEF53:
        assert user_dir._linux_filesystem_type(71, NativeBudget()) == magic
    else:
        with pytest.raises(user_dir.CatalogStorageError, match="catalog_storage_unsupported"):
            user_dir._linux_filesystem_type(71, NativeBudget())
    assert calls == [(71, 120, 8, (0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88))]
    assert len(library.fstatfs.argtypes) == 2


@pytest.mark.parametrize("failure", ["missing_query", "missing_glibc", "error_return", "os_error", "interruption"])
def test_f2_linux_query_failure_refuses_without_retry(monkeypatch, failure) -> None:
    from evidentia_core.catalogs import user_dir
    from evidentia_core.models.open_corpora import NativeBudget

    primary = KeyboardInterrupt("owned native interruption") if failure == "interruption" else OSError("query failed")
    calls, library = _fake_linux_statfs(
        monkeypatch,
        result=-1 if failure == "error_return" else 0,
        primary=primary if failure in ("os_error", "interruption") else None,
    )
    if failure == "missing_query":
        del library.fstatfs
    elif failure == "missing_glibc":
        del library.gnu_get_libc_version
    expected = KeyboardInterrupt if failure == "interruption" else user_dir.CatalogStorageError
    with pytest.raises(expected) as caught:
        user_dir._linux_filesystem_type(71, NativeBudget())
    assert len(calls) == (0 if failure.startswith("missing") else 1)
    if failure == "interruption":
        assert caught.value is primary
    if failure == "os_error":
        assert caught.value.__cause__ is primary


@pytest.mark.parametrize("guard", ["machine", "pointer", "long", "int", "structure_size", "alignment"])
def test_f2_linux_unsupported_abi_refuses_before_query(monkeypatch, guard) -> None:
    import ctypes
    import platform

    from evidentia_core.catalogs import user_dir
    from evidentia_core.models.open_corpora import NativeBudget

    calls, _ = _fake_linux_statfs(monkeypatch)
    sizeof = ctypes.sizeof
    if guard == "machine":
        monkeypatch.setattr(platform, "machine", lambda: "aarch64")
    elif guard == "alignment":
        monkeypatch.setattr(ctypes, "alignment", lambda value: 4)
    else:

        def wrong_size(value):
            if (
                (guard == "pointer" and value is ctypes.c_void_p)
                or (guard == "long" and value is ctypes.c_long)
                or (guard == "int" and value is ctypes.c_int)
                or (guard == "structure_size" and getattr(value, "__name__", None) == "StatFs")
            ):
                return 2
            return sizeof(value)

        monkeypatch.setattr(ctypes, "sizeof", wrong_size)
    with pytest.raises(user_dir.CatalogStorageError, match="catalog_storage_unsupported"):
        user_dir._linux_filesystem_type(71, NativeBudget())
    assert calls == []


@pytest.mark.parametrize("expiry", ["before", "after"])
def test_f2_linux_query_keeps_original_deadline(monkeypatch, expiry) -> None:
    import time

    from evidentia_core.catalogs import user_dir
    from evidentia_core.models.open_corpora import NativeBudget, NativeSourceError

    budget = NativeBudget()

    def expire():
        budget._deadline = time.monotonic() - 1

    calls, _ = _fake_linux_statfs(monkeypatch, after=expire if expiry == "after" else None)
    if expiry == "before":
        expire()
    with pytest.raises(NativeSourceError, match="processing_deadline_exceeded"):
        user_dir._linux_filesystem_type(71, budget)
    assert len(calls) == (0 if expiry == "before" else 1)
    assert budget._deadline < time.monotonic()


@pytest.mark.parametrize("exists", [False, True])
def test_f2_linux_admission_refusal_precedes_root_and_lock_creation(tmp_path, monkeypatch, exists) -> None:
    import sys

    from evidentia_core.catalogs import user_dir

    destination = tmp_path / "catalogs"
    if exists:
        destination.mkdir()
    called = []
    primary = user_dir.CatalogStorageError("catalog_storage_unsupported")

    def refuse(self, path, budget):
        called.append(path)
        raise primary

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(user_dir.CatalogManifestTransaction, "_check_local_directory", refuse)
    with pytest.raises(user_dir.CatalogStorageError) as caught:
        user_dir.save_user_manifest(FrameworkManifest(version=1, frameworks=[]), destination)
    assert caught.value is primary
    assert called == [destination if exists else tmp_path]
    assert list(destination.iterdir()) == [] if exists else not destination.exists()


@pytest.mark.parametrize("failure", ["other_device", "primary_and_close"])
def test_f2_linux_owned_directory_refusal_preserves_primary_and_closes(tmp_path, monkeypatch, failure) -> None:
    from evidentia_core.catalogs import user_dir
    from evidentia_core.models.open_corpora import NativeBudget

    observed = tmp_path.stat()
    transaction = user_dir.CatalogManifestTransaction(tmp_path)
    closed, queried = [], []
    primary = KeyboardInterrupt("query cancellation")
    secondary = SystemExit("close interruption")
    for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
        monkeypatch.setattr(user_dir.os, flag, 0, raising=False)
    monkeypatch.setattr(user_dir.os, "open", lambda *args, **kwargs: 901)
    monkeypatch.setattr(user_dir.os, "fstat", lambda fd: observed)
    monkeypatch.setattr(user_dir.os, "get_inheritable", lambda fd: False)

    def query(fd, budget):
        queried.append(fd)
        raise primary

    def close(fd):
        closed.append(fd)
        if failure == "primary_and_close":
            raise secondary

    monkeypatch.setattr(user_dir, "_linux_filesystem_type", query)
    monkeypatch.setattr(user_dir.os, "close", close)
    if failure == "other_device":
        transaction._storage_device = observed.st_dev + 1
    expected = user_dir.CatalogStorageError if failure == "other_device" else KeyboardInterrupt
    with pytest.raises(expected) as caught:
        transaction._check_local_directory(tmp_path, NativeBudget())
    assert closed == [901]
    assert transaction._descriptors == []
    assert queried == ([] if failure == "other_device" else [901])
    if failure == "primary_and_close":
        assert caught.value is primary
        assert transaction._cleanup_failures == [("handle_close_failed", secondary)]


@pytest.mark.parametrize("phase", ["open", "fstat"])
def test_f2_linux_expiry_closes_owned_fd_without_new_path_traversal(tmp_path, monkeypatch, phase) -> None:
    import time
    from pathlib import Path

    from evidentia_core.catalogs import user_dir
    from evidentia_core.models.open_corpora import NativeBudget, NativeSourceError

    observed = tmp_path.stat()
    budget = NativeBudget()
    closed, traversed = [], []
    for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
        monkeypatch.setattr(user_dir.os, flag, 0, raising=False)

    def open_directory(*args):
        if phase == "open":
            budget._deadline = time.monotonic() - 1
        return 901

    def fstat(fd):
        assert phase == "fstat"
        budget._deadline = time.monotonic() - 1
        return observed

    monkeypatch.setattr(user_dir.os, "open", open_directory)
    monkeypatch.setattr(user_dir.os, "fstat", fstat)
    monkeypatch.setattr(user_dir.os, "close", closed.append)
    monkeypatch.setattr(Path, "lstat", lambda self: traversed.append(self))
    transaction = user_dir.CatalogManifestTransaction(tmp_path)
    with pytest.raises(NativeSourceError, match="processing_deadline_exceeded"):
        transaction._check_local_directory(tmp_path, budget)
    assert closed == [901]
    assert traversed == []
    assert transaction._descriptors == []


_LOCK_CHILD = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from evidentia_core.catalogs.user_dir import _NativeLock
from evidentia_core.models.open_corpora import native_operation
with native_operation() as budget:
    owner = _NativeLock(Path(sys.argv[2]))
    owner.acquire(budget)
    print('LOCKED', flush=True)
    sys.stdin.read(1)
    if owner.close():
        raise RuntimeError('child lock cleanup failed')
"""


@pytest.mark.parametrize("termination", ["release", "process_death"])
def test_f2_process_contention_and_native_owner_cleanup(tmp_path, termination, request) -> None:
    import subprocess
    import sys
    from pathlib import Path
    from queue import Queue
    from threading import Thread

    import evidentia_core.catalogs.user_dir as module

    process = subprocess.Popen(
        [sys.executable, "-I", "-B", "-c", _LOCK_CHILD, str(Path(module.__file__).parents[2]), str(tmp_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    request.node.user_properties.extend([("owned_child_pid", process.pid), ("termination", termination)])
    ready = Queue()
    reader = Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True)
    reader.start()
    try:
        assert ready.get(timeout=15) == "LOCKED\n"
        lock = tmp_path / "frameworks.yaml.lock"
        identity = (lock.stat().st_dev, lock.stat().st_ino)
        with pytest.raises(module.CatalogStorageError, match="transaction_conflict"):
            save_user_manifest(FrameworkManifest(version=1, frameworks=[]), tmp_path)
        assert not (tmp_path / "frameworks.yaml").exists()
        if termination == "process_death":
            process.kill()
        else:
            process.stdin.write("x")
            process.stdin.flush()
        process.wait(timeout=15)
        request.node.user_properties.append(("wait_returncode", process.returncode))
        if termination == "release":
            assert process.returncode == 0
            save_user_manifest(FrameworkManifest(version=1, frameworks=[]), tmp_path)
        else:
            # Win32 may defer OS unlock after the waited process has terminated.
            import time

            assert process.poll() is not None
            watchdog = time.monotonic() + 15
            _attempts = 0
            try:
                for _attempts in range(1, 302):
                    assert time.monotonic() < watchdog, "OS lock release exceeded test watchdog"
                    try:
                        save_user_manifest(FrameworkManifest(version=1, frameworks=[]), tmp_path)
                    except module.CatalogStorageError as error:
                        assert error.code == "catalog_transaction_conflict"
                        assert not (tmp_path / "frameworks.yaml").exists()
                        assert identity == (lock.stat().st_dev, lock.stat().st_ino)
                        remaining = watchdog - time.monotonic()
                        assert remaining > 0, "OS lock release exceeded test watchdog"
                        time.sleep(min(0.05, remaining))
                    else:
                        assert time.monotonic() <= watchdog, "OS lock release exceeded test watchdog"
                        break
                else:
                    pytest.fail("OS lock release exceeded finite test attempts")
            finally:
                request.node.user_properties.append(("post_death_acquire_attempts", _attempts))
        assert identity == (lock.stat().st_dev, lock.stat().st_ino)
        assert lock.read_bytes() == b""
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=15)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
        request.node.user_properties.extend(
            [("cleanup_returncode", process.returncode), ("owned_streams_closed", True)]
        )
        reader.join(timeout=15)


def test_f2_capacity_manifest_exact_bytes_and_plus_one(tmp_path) -> None:
    import evidentia_core.catalogs.user_dir as module

    prefix = (
        b"version: 1\nframeworks:\n- id: local\n  name: Local\n  version: one\n  tier: C\n"
        b"  category: control\n  path: local.json\n  license_required: false\n  placeholder: false\n"
        b"  refresh: manual\n  notes: "
    )
    amount = 4_194_304 - len(prefix) - 1
    expected = prefix + b"x" * amount + b"\n"
    assert len(expected) == 4_194_304
    entry = FrameworkManifestEntry(
        id="local", name="Local", version="one", tier="C", path="local.json", notes="x" * amount
    )
    transaction = module.CatalogManifestTransaction(tmp_path)
    transaction._replace_complete(FrameworkManifest(version=1, frameworks=[entry]))
    assert (tmp_path / "frameworks.yaml").read_bytes() == expected
    assert load_user_manifest(tmp_path).frameworks[0].notes == "x" * amount
    entry.notes += "x"
    with pytest.raises(module.CatalogStorageError, match="storage_limit_exceeded"):
        save_user_manifest(FrameworkManifest(version=1, frameworks=[entry]), tmp_path)
    assert (tmp_path / "frameworks.yaml").read_bytes() == expected
    (tmp_path / "frameworks.yaml").write_bytes(expected + b" ")
    with pytest.raises(module.CatalogStorageError, match="storage_limit_exceeded"):
        load_user_manifest(tmp_path)


def test_f2_capacity_manifest_entry_count(tmp_path) -> None:
    import evidentia_core.catalogs.user_dir as module

    entries = [
        FrameworkManifestEntry(id=f"synthetic-{index}", name="Synthetic", version="one", tier="C", path="old.json")
        for index in range(4096)
    ]
    save_user_manifest(FrameworkManifest(version=1, frameworks=entries), tmp_path)
    assert [entry.id for entry in load_user_manifest(tmp_path).frameworks] == [
        f"synthetic-{index}" for index in range(4096)
    ]
    prior = (tmp_path / "frameworks.yaml").read_bytes()
    entries.append(FrameworkManifestEntry(id="excess", name="Synthetic", version="one", tier="C", path="old.json"))
    with pytest.raises(module.CatalogStorageError, match="storage_limit_exceeded"):
        save_user_manifest(FrameworkManifest(version=1, frameworks=entries), tmp_path)
    assert (tmp_path / "frameworks.yaml").read_bytes() == prior


def test_f2_capacity_legacy_exact_bytes_and_plus_one(tmp_path) -> None:
    import hashlib

    import evidentia_core.catalogs.user_dir as module

    prefix = (
        b'{"framework_id":"local","framework_name":"Local","version":"one","source":"synthetic","controls":[],"notes":"'
    )
    raw = prefix + b"x" * (16_777_216 - len(prefix) - 2) + b'"}'
    assert len(raw) == 16_777_216
    entry = FrameworkManifestEntry(id="local", name="Local", version="one", tier="C", path="ignored.json")
    transaction = module.CatalogManifestTransaction(tmp_path)
    result = transaction.commit(module.CatalogMutationIntent.legacy(entry, raw))
    assert result.parent.name == hashlib.sha256(raw).hexdigest()
    assert result.read_bytes() == raw
    prior = (tmp_path / "frameworks.yaml").read_bytes()
    with pytest.raises(module.CatalogStorageError, match="storage_limit_exceeded"):
        module.CatalogManifestTransaction(tmp_path).commit(
            module.CatalogMutationIntent.legacy(entry, raw + b" ", force=True)
        )
    assert (tmp_path / "frameworks.yaml").read_bytes() == prior


def test_f2_expired_closed_generation_does_no_directory_or_scandir_io(tmp_path, monkeypatch) -> None:
    import time

    import evidentia_core.catalogs.user_dir as module
    from evidentia_core.models.open_corpora import NativeBudget, NativeSourceError

    budget = NativeBudget()
    budget._deadline = time.monotonic() - 1
    visits = []
    original = module._directory

    def directory(*args, **kwargs):
        visits.append("directory")
        return original(*args, **kwargs)

    monkeypatch.setattr(module, "_directory", directory)
    with pytest.raises(NativeSourceError, match="processing_deadline_exceeded"):
        module._closed_names(tmp_path, (), budget)
    assert visits == []


def test_f2_windows_remote_drive_refuses_before_storage_creation(tmp_path, monkeypatch) -> None:
    import ctypes
    import sys

    import evidentia_core.catalogs.user_dir as module

    if sys.platform != "win32":
        pytest.skip("Native Windows drive admission is exercised on Windows")
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    queries = []

    def remote_drive(anchor):
        queries.append(anchor)
        return 4

    api.GetDriveTypeW = remote_drive
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: api)
    directory = tmp_path / "absent"
    transaction = module.CatalogManifestTransaction(directory)
    with pytest.raises(module.CatalogStorageError, match="catalog_storage_unsupported"):
        transaction._replace_complete(FrameworkManifest(version=1, frameworks=[]))
    assert queries == [directory.anchor]
    assert not directory.exists()


def test_f2_success_returns_captured_path_without_post_transaction_resolution(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module

    def unexpected(*args):
        pytest.fail("Completed transaction must not resolve a new storage path")

    monkeypatch.setattr(module, "user_manifest_path", unexpected)
    assert save_user_manifest(FrameworkManifest(version=1, frameworks=[]), tmp_path) == tmp_path / "frameworks.yaml"


@pytest.mark.parametrize("boundary", ["manifest", "confirmation"])
@pytest.mark.parametrize("mutation", ["parent_extra", "nested_extra"])
def test_f2_native_storage_egress_retains_forged_field_evidence(tmp_path, boundary, mutation) -> None:
    import evidentia_core.catalogs.user_dir as module

    manifest = FrameworkManifest(version=1, frameworks=[FrameworkManifestEntry.model_validate(_native_entry_data())])
    entry = manifest.frameworks[0]
    target = entry if mutation == "parent_extra" else entry.native_registration
    target.__dict__["unexpected"] = "must remain visible to admission"
    with pytest.raises(ValueError, match="native_source_invalid"):
        if boundary == "manifest":
            save_user_manifest(manifest, tmp_path)
        else:
            module.catalog_entry_sha256(entry)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "boundary",
    [
        ("GetDriveTypeW", 1),
        ("CreateFileW", 1),
        ("GetFileInformationByHandleEx", 1),
        ("GetFileType", 1),
        ("CreateFileW", 2),
        ("GetFileInformationByHandleEx", 4),
        ("GetFileType", 2),
        ("CreateFileW", 3),
        ("GetFileInformationByHandleEx", 7),
        ("GetFileType", 3),
        ("CloseHandle", 1),
        ("LockFileEx", 1),
        ("CreateFileW", 3, "interrupted_close"),
    ],
)
def test_f2_windows_lock_expiry_only_releases_owned_handles(tmp_path, monkeypatch, boundary) -> None:
    import ctypes
    import sys
    import time
    from collections import Counter

    import evidentia_core.catalogs.user_dir as module
    from evidentia_core.models.open_corpora import NativeBudget, NativeSourceError

    if sys.platform != "win32":
        pytest.skip("Actual Win32 lock calls are exercised on Windows")
    budget = NativeBudget()
    owner = module._NativeLock(tmp_path, budget)
    native = ctypes.WinDLL("kernel32", use_last_error=True)
    counts, after_expiry = Counter(), []
    expired = False
    secondary = KeyboardInterrupt()

    class Call:
        def __init__(self, name):
            self.name = name
            self.function = getattr(native, name)

        @property
        def argtypes(self):
            return self.function.argtypes

        @argtypes.setter
        def argtypes(self, value):
            self.function.argtypes = value

        @property
        def restype(self):
            return self.function.restype

        @restype.setter
        def restype(self, value):
            self.function.restype = value

        def __call__(self, *args):
            nonlocal expired
            if expired:
                after_expiry.append(self.name)
            counts[self.name] += 1
            result = self.function(*args)
            if (self.name, counts[self.name]) == boundary[:2]:
                budget._deadline = time.monotonic() - 1
                expired = True
            if len(boundary) == 3 and self.name == "CloseHandle" and counts[self.name] == 1:
                raise secondary
            return result

    class Api:
        def __getattr__(self, name):
            call = Call(name)
            setattr(self, name, call)
            return call

    api = Api()
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: api)
    try:
        with pytest.raises(NativeSourceError, match="processing_deadline_exceeded") as caught:
            owner.acquire(budget)
    finally:
        cleanup = owner.close()
    assert cleanup == ([("handle_close_failed", secondary)] if len(boundary) == 3 else [])
    if len(boundary) == 3:
        assert caught.value.__cause__ is secondary
    assert expired
    assert set(after_expiry) <= {"CloseHandle", "UnlockFileEx"}
    assert owner.handle is None and owner.parent_handle is None and not owner.locked


@pytest.mark.parametrize(
    "boundary",
    [
        ("open", 1),
        ("fstat", 1),
        ("lstat", 1),
        ("filesystem", 1),
        ("fstatvfs", 1),
        ("open", 2),
        ("fstat", 2),
        ("stat", 1),
        ("inheritable", 1),
        ("inheritable", 2),
        ("flock", 1),
    ],
)
def test_f2_posix_lock_expiry_only_releases_owned_descriptors(tmp_path, monkeypatch, boundary) -> None:
    import stat
    import sys
    import time
    from collections import Counter
    from types import SimpleNamespace

    import evidentia_core.catalogs.user_dir as module
    from evidentia_core.models.open_corpora import NativeBudget, NativeSourceError

    budget = NativeBudget()
    owner = module._NativeLock(tmp_path, budget)
    directory = tmp_path.stat()
    leaf = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=0, st_nlink=1, st_dev=directory.st_dev, st_ino=321)
    counts, after_expiry, closed = Counter(), [], []
    expired = False

    def call(name, result):
        nonlocal expired
        if expired:
            after_expiry.append(name)
        counts[name] += 1
        if (name, counts[name]) == boundary:
            budget._deadline = time.monotonic() - 1
            expired = True
        return result

    def open_file(*args, **kwargs):
        return call("open", 101 if counts["open"] == 0 else 102)

    def flock(fd, flags):
        call("unlock" if flags == 8 else "flock", None)

    with monkeypatch.context() as changes:
        changes.setitem(sys.modules, "fcntl", SimpleNamespace(flock=flock, LOCK_EX=2, LOCK_NB=4, LOCK_UN=8))
        changes.setattr(sys, "platform", "linux")
        for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK"):
            changes.setattr(module.os, flag, 0, raising=False)
        changes.setattr(module.os, "open", open_file)
        changes.setattr(module.os, "supports_dir_fd", {open_file})
        changes.setattr(module.os, "fstat", lambda fd: call("fstat", directory if fd == 101 else leaf))
        changes.setattr(type(tmp_path), "lstat", lambda self: call("lstat", directory))
        changes.setattr(module.os, "stat", lambda *args, **kwargs: call("stat", leaf))
        changes.setattr(module.os, "get_inheritable", lambda fd: call("inheritable", False))
        changes.setattr(module.os, "ST_LOCAL", 1, raising=False)
        changes.setattr(module.os, "fstatvfs", lambda fd: call("fstatvfs", SimpleNamespace(f_flag=1)), raising=False)
        changes.setattr(module, "_linux_filesystem_type", lambda *args: call("filesystem", 0xEF53))
        changes.setattr(module.os, "close", lambda fd: closed.append(fd))
        try:
            with pytest.raises(NativeSourceError, match="processing_deadline_exceeded"):
                owner._posix_acquire(budget)
        finally:
            changes.setattr(module.os, "name", "posix")
            assert owner.close() == []
    assert expired
    assert set(after_expiry) <= {"unlock"}
    assert sorted(closed) == ([101] if counts["open"] == 1 else [101, 102])
    assert owner.descriptor is None and owner.directory_fd is None and not owner.locked


def test_f2_generation_scan_close_preserves_primary_and_fixed_cleanup(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module

    primary = KeyboardInterrupt()
    secondary = RuntimeError("synthetic iterator close failure")
    original_scan = module.os.scandir
    closes = []

    class Scan:
        def __init__(self, directory):
            self.iterator = original_scan(directory)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

        def __iter__(self):
            return self

        def __next__(self):
            raise primary

        def close(self):
            self.iterator.close()
            closes.append(True)
            raise secondary

    monkeypatch.setattr(module.os, "scandir", Scan)
    entry = FrameworkManifestEntry(id="local", name="Local", version="one", tier="C", path="old.json")
    raw = b'{"framework_id":"local","framework_name":"Local","version":"one","source":"synthetic","controls":[]}'
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(KeyboardInterrupt) as caught:
        transaction.commit(module.CatalogMutationIntent.legacy(entry, raw))
    assert caught.value is primary
    assert closes == [True]
    assert transaction.observation.cleanup_errors == ("handle_close_failed",)
    assert transaction.observation.primary_kind == "base_exception"
    assert transaction.observation.publication_state == "not_attempted"


def _fake_darwin_storage(monkeypatch, *, flags=None, query_error=None, after_query=None, close_error=None):
    import ctypes
    import platform
    from pathlib import Path
    from types import SimpleNamespace

    import evidentia_core.catalogs.user_dir as module

    synthetic_local_flag = 0x1000
    calls = []
    owned = {}
    monkeypatch.setattr(module.sys, "platform", "darwin")
    for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
        monkeypatch.setattr(module.os, name, 0, raising=False)
    monkeypatch.setattr(platform, "machine", lambda: "arm64")

    def open_directory(path, native_flags):
        descriptor = 900 + len(calls)
        owned[descriptor] = Path(path)
        calls.append(("open", Path(path)))
        return descriptor

    class Query:
        def __call__(self, descriptor, pointer):
            calls.append(("query", owned[descriptor]))
            if query_error is not None:
                raise query_error
            if after_query is not None:
                after_query()
            pointer._obj.f_flags = synthetic_local_flag if flags is None else flags
            return 0

    def close(descriptor):
        calls.append(("close", owned.pop(descriptor)))
        if close_error is not None:
            raise close_error

    monkeypatch.setattr(module.os, "open", open_directory)
    monkeypatch.setattr(module.os, "fstat", lambda descriptor: owned[descriptor].lstat())
    monkeypatch.setattr(module.os, "get_inheritable", lambda descriptor: False)
    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace(fstatfs=Query()))
    monkeypatch.setattr(module.os, "close", close)
    return calls, owned


@pytest.mark.parametrize("failure", ["remote", "missing_query", "unsupported_abi", "query_error"])
def test_f2_darwin_admission_refuses_before_first_mutation(tmp_path, monkeypatch, failure) -> None:
    from pathlib import Path

    import evidentia_core.catalogs.user_dir as module
    from evidentia_core.models.open_corpora import NativeBudget

    primary = OSError("synthetic native filesystem query")
    calls, owned = _fake_darwin_storage(
        monkeypatch,
        flags=0 if failure == "remote" else None,
        query_error=primary if failure == "query_error" else None,
    )
    if failure == "missing_query":
        import ctypes
        from types import SimpleNamespace

        monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace())
    elif failure == "unsupported_abi":
        import platform

        monkeypatch.setattr(platform, "machine", lambda: "unsupported")
    mutations = []
    original_mkdir = Path.mkdir

    def mkdir(path, *args, **kwargs):
        mutations.append(path)
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", mkdir)
    root = tmp_path / "new" / "catalogs"
    transaction = module.CatalogManifestTransaction(root)
    with pytest.raises((module.CatalogStorageError, OSError)) as caught:
        transaction._storage_directory(root, NativeBudget(), create=True)
    if failure == "query_error":
        assert caught.value.__cause__ is primary
    else:
        assert caught.value.code == "catalog_storage_unsupported"
    assert mutations == []
    assert not root.parent.exists()
    assert [kind for kind, _ in calls].count("open") == 1
    assert [kind for kind, _ in calls].count("close") == 1
    assert owned == {} and transaction._descriptors == []


def test_f2_darwin_local_admission_checks_existing_and_new_components(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module
    from evidentia_core.models.open_corpora import NativeBudget

    calls, owned = _fake_darwin_storage(monkeypatch)
    root = tmp_path / "new" / "catalogs"
    transaction = module.CatalogManifestTransaction(root)
    assert transaction._storage_directory(root, NativeBudget(), create=True) == root
    assert [path for kind, path in calls if kind == "query"] == [tmp_path, root.parent, root]
    assert [path for kind, path in calls if kind == "close"] == [tmp_path, root.parent, root]
    assert owned == {} and transaction._descriptors == []
    assert transaction._storage_device == tmp_path.stat().st_dev


def test_f2_darwin_query_expiry_closes_without_mutation_and_keeps_primary(tmp_path, monkeypatch) -> None:
    import time

    import evidentia_core.catalogs.user_dir as module
    from evidentia_core.models.open_corpora import NativeBudget, NativeSourceError

    budget = NativeBudget()
    captured = []
    original_check = NativeBudget.check

    def check(self):
        try:
            return original_check(self)
        except BaseException as error:
            captured.append(error)
            raise

    def expire():
        budget._deadline = time.monotonic() - 1

    cleanup = KeyboardInterrupt("synthetic descriptor close interruption")
    calls, owned = _fake_darwin_storage(monkeypatch, after_query=expire, close_error=cleanup)
    monkeypatch.setattr(NativeBudget, "check", check)
    root = tmp_path / "new" / "catalogs"
    transaction = module.CatalogManifestTransaction(root)
    with pytest.raises(NativeSourceError, match="processing_deadline_exceeded") as caught:
        transaction._storage_directory(root, budget, create=True)
    assert caught.value is captured[0]
    assert caught.value.__cause__ is cleanup
    assert transaction._cleanup_failures == [("handle_close_failed", cleanup)]
    assert not root.parent.exists()
    assert [kind for kind, _ in calls] == ["open", "query", "close"]
    assert owned == {} and transaction._descriptors == []


class _F2BoundaryAbort(BaseException):
    """Identity-distinct cancellation used only at owned storage boundaries."""


@pytest.mark.parametrize("primary_type", [RuntimeError, _F2BoundaryAbort])
@pytest.mark.parametrize(
    "boundary",
    [
        "stage_create",
        "payload_create",
        "payload_write",
        "payload_sync",
        "payload_close",
        "manifest_create",
        "manifest_write",
        "manifest_sync",
        "manifest_close",
        "replace",
        "readback",
        "unlock",
    ],
)
def test_f2_each_owned_io_boundary_preserves_primary(tmp_path, monkeypatch, boundary, primary_type) -> None:
    import os
    from pathlib import Path

    import evidentia_core.catalogs.user_dir as module

    prior = b"version: 1\nframeworks: []\n"
    manifest = tmp_path / "frameworks.yaml"
    manifest.write_bytes(prior)
    primary = primary_type("synthetic owned boundary")
    secondary = _F2BoundaryAbort("distinct synthetic cleanup")
    descriptors = {}
    locks = []
    events = []
    secondary_seen = []
    replaced = False
    original_open, original_write = module.os.open, module.os.write
    original_sync, original_close = module.os.fsync, module.os.close
    original_mkdir, original_replace = Path.mkdir, module.os.replace
    original_read = module._bounded_read
    original_acquire, original_unlock = module._NativeLock.acquire, module._NativeLock.close

    def trip(name):
        if name == boundary and not events:
            events.append(name)
            raise primary

    def mkdir(path, *args, **kwargs):
        if path.name.startswith(".catalog-stage-"):
            trip("stage_create")
        return original_mkdir(path, *args, **kwargs)

    def open_file(path, flags, *args, **kwargs):
        target = Path(path)
        kind = None
        if flags & os.O_CREAT:
            if target.name == "catalog.json" and target.parent.name.startswith(".catalog-stage-"):
                kind = "payload"
            elif target.name.startswith(".frameworks-") and target.suffix == ".yaml":
                kind = "manifest"
        if kind is not None:
            trip(kind + "_create")
        descriptor = original_open(path, flags, *args, **kwargs)
        if kind is not None:
            descriptors[descriptor] = kind
        return descriptor

    def write(descriptor, raw):
        if descriptor in descriptors:
            trip(descriptors[descriptor] + "_write")
        return original_write(descriptor, raw)

    def sync(descriptor):
        if descriptor in descriptors:
            trip(descriptors[descriptor] + "_sync")
        return original_sync(descriptor)

    def close(descriptor):
        kind = descriptors.pop(descriptor, None)
        result = original_close(descriptor)
        if kind is not None:
            if events:
                secondary_seen.append("handle_close_failed")
                raise secondary
            trip(kind + "_close")
        return result

    def replace(source, target):
        nonlocal replaced
        trip("replace")
        result = original_replace(source, target)
        replaced = True
        return result

    def read(path, *args, **kwargs):
        if replaced and path == manifest:
            trip("readback")
        return original_read(path, *args, **kwargs)

    def acquire(lock, budget):
        original_acquire(lock, budget)
        locks.append(lock)
        if boundary != "unlock":
            return
        if os.name == "nt":
            original_api = lock.api

            class ReleaseBoundary:
                def UnlockFileEx(self, *args):
                    result = original_api.UnlockFileEx(*args)
                    trip("unlock")
                    return result

                def CloseHandle(self, *args):
                    return original_api.CloseHandle(*args)

            lock.api = ReleaseBoundary()
        else:
            import fcntl

            flock = fcntl.flock

            def unlock(descriptor, operation):
                result = flock(descriptor, operation)
                if descriptor == lock.descriptor and operation == fcntl.LOCK_UN:
                    trip("unlock")
                return result

            monkeypatch.setattr(fcntl, "flock", unlock)

    def release(lock):
        failures = original_unlock(lock)
        if events:
            secondary_seen.append("handle_close_failed")
            failures.append(("handle_close_failed", secondary))
        return failures

    monkeypatch.setattr(Path, "mkdir", mkdir)
    monkeypatch.setattr(module.os, "open", open_file)
    if original_open in module.os.supports_dir_fd:
        monkeypatch.setattr(module.os, "supports_dir_fd", module.os.supports_dir_fd | {open_file})
    monkeypatch.setattr(module.os, "write", write)
    monkeypatch.setattr(module.os, "fsync", sync)
    monkeypatch.setattr(module.os, "close", close)
    monkeypatch.setattr(module.os, "replace", replace)
    monkeypatch.setattr(module, "_bounded_read", read)
    monkeypatch.setattr(module._NativeLock, "acquire", acquire)
    monkeypatch.setattr(module._NativeLock, "close", release)
    intent, raw = _legacy_import()
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(primary_type) as caught:
        transaction.commit(intent)
    assert caught.value is primary and caught.value is not secondary
    assert events == [boundary]
    assert not descriptors
    assert transaction._descriptors == []
    assert transaction._files == [] and transaction._directories == []
    for lock in locks:
        assert not lock.locked
        assert lock.handle is None and lock.parent_handle is None
        assert lock.descriptor is None and lock.directory_fd is None
    observation = transaction.observation
    assert observation.primary_kind == ("exception" if primary_type is RuntimeError else "base_exception")
    assert len(observation.model_dump_json().encode()) <= 4096
    if secondary_seen:
        assert observation.cleanup_state == "failed"
        assert "handle_close_failed" in observation.cleanup_errors
    if boundary in ("readback", "unlock"):
        assert replaced and observation.publication_state == "committed"
        assert [entry.id for entry in load_user_manifest(tmp_path).frameworks] == ["local"]
        stored = load_user_manifest(tmp_path).frameworks[0]
        assert (tmp_path / stored.path).read_bytes() == raw
    else:
        assert not replaced and manifest.read_bytes() == prior
        assert observation.publication_state == ("not_committed" if boundary == "replace" else "not_attempted")
    assert not list(tmp_path.glob(".frameworks-*.yaml"))
    assert not list(tmp_path.glob(".catalog-stage-*"))


def _f2_named_legacy_intent(identifier):
    import evidentia_core.catalogs.user_dir as module

    entry = FrameworkManifestEntry(id=identifier, name=identifier, version="one", tier="C", path="ignored.json")
    raw = json.dumps(
        {
            "framework_id": identifier,
            "framework_name": identifier,
            "version": "one",
            "source": "synthetic",
            "controls": [],
        }
    ).encode()
    return module.CatalogMutationIntent.legacy(entry, raw), raw


@pytest.mark.parametrize("intervening", ["import", "remove"])
def test_f2_actual_import_remove_interleaving_uses_fresh_manifest(tmp_path, monkeypatch, intervening) -> None:
    import evidentia_core.catalogs.user_dir as module

    initial, initial_raw = _f2_named_legacy_intent("initial")
    initial_path = module.CatalogManifestTransaction(tmp_path).commit(initial)
    outer_intent, outer_raw = _f2_named_legacy_intent("outer")
    inner_intent, inner_raw = _f2_named_legacy_intent("inner")
    outer = module.CatalogManifestTransaction(tmp_path)
    original_stage = module.CatalogManifestTransaction._stage
    intervened = []
    inner_paths = []

    def stage(transaction, directory, files, budget):
        staged = original_stage(transaction, directory, files, budget)
        if transaction is outer:
            assert not intervened
            intervened.append(intervening)
            operation = inner_intent if intervening == "import" else module.CatalogMutationIntent.remove("initial")
            inner = module.CatalogManifestTransaction(tmp_path)
            inner_paths.append(inner.commit(operation))
            assert inner.observation.publication_state == "committed"
        return staged

    monkeypatch.setattr(module.CatalogManifestTransaction, "_stage", stage)
    outer_path = outer.commit(outer_intent)
    assert intervened == [intervening]
    expected_ids = ["initial", "inner", "outer"] if intervening == "import" else ["outer"]
    assert [entry.id for entry in load_user_manifest(tmp_path).frameworks] == expected_ids
    assert initial_path.read_bytes() == initial_raw
    assert outer_path.read_bytes() == outer_raw
    if intervening == "import":
        assert inner_paths[0].read_bytes() == inner_raw
    assert outer.observation.publication_state == "committed"


def test_f2_remove_confirmation_rechecks_after_actual_force_import(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module

    first, first_raw = _legacy_import("one")
    first_path = module.CatalogManifestTransaction(tmp_path).commit(first)
    prior_entry = load_user_manifest(tmp_path).frameworks[0]
    expected_digest = module.catalog_entry_sha256(prior_entry)
    second, second_raw = _legacy_import("two")
    original_acquire = module._NativeLock.acquire
    intervened = []
    winner_bytes = []
    winner_paths = []

    def acquire(lock, budget):
        if not intervened:
            intervened.append("force_import")
            winner_paths.append(
                module.CatalogManifestTransaction(tmp_path).commit(
                    module.CatalogMutationIntent.legacy(second.entry, second_raw, force=True)
                )
            )
            winner_bytes.append((tmp_path / "frameworks.yaml").read_bytes())
        return original_acquire(lock, budget)

    monkeypatch.setattr(module._NativeLock, "acquire", acquire)
    removed = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(module.CatalogStorageError, match="catalog_transaction_conflict"):
        removed.commit(module.CatalogMutationIntent.remove("local", expected_entry_sha256=expected_digest))
    assert intervened == ["force_import"]
    assert (tmp_path / "frameworks.yaml").read_bytes() == winner_bytes[0]
    assert load_user_manifest(tmp_path).frameworks[0].version == "two"
    assert first_path.read_bytes() == first_raw
    assert winner_paths[0].read_bytes() == second_raw
    assert removed.observation.publication_state == "not_attempted"


@pytest.mark.parametrize(
    "prior_present,state,readback,code",
    [
        (False, "not_committed", "matches_prior", "catalog_publication_failed"),
        (True, "indeterminate", "other", "catalog_publication_indeterminate"),
    ],
)
def test_f2_absent_readback_preserves_exact_prior_presence(
    tmp_path, monkeypatch, prior_present, state, readback, code
) -> None:
    import hashlib

    import evidentia_core.catalogs.user_dir as module

    manifest = tmp_path / "frameworks.yaml"
    previous = b"version: 1\nframeworks: []\n"
    if prior_present:
        manifest.write_bytes(previous)
    primary = RuntimeError("synthetic replace followed by absent readback")
    attempts = []

    def replace(source, target):
        attempts.append((source, target))
        assert target == manifest
        target.unlink(missing_ok=True)
        raise primary

    monkeypatch.setattr(module.os, "replace", replace)
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(RuntimeError) as caught:
        transaction._replace_complete(FrameworkManifest(version=2, frameworks=[]))
    assert caught.value is primary
    assert len(attempts) == 1 and not manifest.exists()
    observation = transaction.observation
    assert observation.prior_manifest_state == ("present" if prior_present else "absent")
    assert observation.prior_sha256 == (hashlib.sha256(previous).hexdigest() if prior_present else None)
    assert observation.observed_manifest_state == "absent"
    assert observation.observed_sha256 is None
    assert observation.publication_state == state
    assert observation.readback_result == readback
    assert observation.error_code == code
    assert observation.replace_outcome == "raised"
    assert observation.cleanup_state == "complete" and observation.cleanup_errors == ()
    assert observation.failure_phase == "replace" and observation.primary_kind == "exception"
    assert len(observation.model_dump_json().encode()) <= 4096
    assert {item.name for item in tmp_path.iterdir()} == {"frameworks.yaml.lock"}


def test_f2_returned_replace_with_other_readback_retains_known_commit(tmp_path, monkeypatch) -> None:
    import hashlib

    import evidentia_core.catalogs.user_dir as module

    manifest = tmp_path / "frameworks.yaml"
    previous = b"version: 1\nframeworks: []\n"
    other = b"version: 99\nframeworks: []\n"
    manifest.write_bytes(previous)
    original = module.os.replace

    def replace(source, target):
        original(source, target)
        target.write_bytes(other)

    monkeypatch.setattr(module.os, "replace", replace)
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(module.CatalogStorageError, match="catalog_generation_conflict"):
        transaction._replace_complete(FrameworkManifest(version=2, frameworks=[]))
    observation = transaction.observation
    assert observation.publication_state == "committed"
    assert observation.replace_outcome == "returned" and observation.readback_result == "other"
    assert observation.observed_sha256 == hashlib.sha256(other).hexdigest()
    assert observation.error_code == "catalog_generation_conflict" and observation.failure_phase == "readback"
    assert observation.cleanup_state == "complete" and manifest.read_bytes() == other


def test_f2_reader_spanning_replace_keeps_complete_old_manifest_and_payload(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module
    from evidentia_core.catalogs.loader import load_any_catalog

    first, first_raw = _legacy_import("one")
    old_target = module.CatalogManifestTransaction(tmp_path).commit(first)
    old_manifest = (tmp_path / "frameworks.yaml").read_bytes()
    old_reader = load_user_manifest(tmp_path)
    second, second_raw = _legacy_import("two")
    original = module.os.replace
    observations = []

    def replace(source, target):
        assert target.read_bytes() == old_manifest
        before = load_user_manifest(tmp_path)
        assert before.frameworks[0].version == "one"
        assert (tmp_path / before.frameworks[0].path).read_bytes() == first_raw
        original(source, target)
        after = load_user_manifest(tmp_path)
        assert after.frameworks[0].version == "two"
        assert (tmp_path / after.frameworks[0].path).read_bytes() == second_raw
        observations.append((before, after))

    monkeypatch.setattr(module.os, "replace", replace)
    new_target = module.CatalogManifestTransaction(tmp_path).commit(
        module.CatalogMutationIntent.legacy(second.entry, second_raw, force=True)
    )
    assert len(observations) == 1 and old_target != new_target
    assert (tmp_path / old_reader.frameworks[0].path).read_bytes() == first_raw
    assert load_any_catalog("local", tmp_path / old_reader.frameworks[0].path).version == "one"
    assert load_any_catalog("local", new_target).version == "two"


def test_f2_manifest_depth_refusal_preserves_exact_authoritative_bytes(tmp_path, monkeypatch) -> None:
    import evidentia_core.catalogs.user_dir as module

    # The mapping already contributes one level; 65 nested arrays exceed 64.
    raw = b"version: 1\nframeworks: []\nextra: " + b"[" * 65 + b"0" + b"]" * 65 + b"\n"
    manifest = tmp_path / "frameworks.yaml"
    manifest.write_bytes(raw)
    writes = []
    original = module.os.replace

    def replace(*args):
        writes.append(args)
        return original(*args)

    monkeypatch.setattr(module.os, "replace", replace)
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(module.CatalogStorageError, match="catalog_storage_limit_exceeded"):
        transaction._replace_complete(FrameworkManifest(version=2, frameworks=[]))
    assert manifest.read_bytes() == raw and writes == []
    assert transaction.observation.failure_phase == "manifest_read"
    assert transaction.observation.publication_state == "not_attempted"


def test_f2_invalid_force_import_preserves_registration_and_payload(tmp_path) -> None:
    import evidentia_core.catalogs.user_dir as module

    initial, raw = _legacy_import()
    target = module.CatalogManifestTransaction(tmp_path).commit(initial)
    previous = (tmp_path / "frameworks.yaml").read_bytes()
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(ValueError):
        transaction.commit(module.CatalogMutationIntent.legacy(initial.entry, b"{invalid", force=True))
    assert (tmp_path / "frameworks.yaml").read_bytes() == previous
    assert target.read_bytes() == raw
    assert transaction.observation.publication_state == "not_attempted"
    assert transaction.observation.replace_outcome == "not_called"
    assert not list(tmp_path.glob(".catalog-stage-*"))


def test_f2_actual_remove_restores_bundled_fallback_and_retains_user_bytes(tmp_path) -> None:
    import evidentia_core.catalogs.user_dir as module

    bundled = load_manifest()
    intent, raw = _f2_named_legacy_intent("nist-800-53-mod")
    target = module.CatalogManifestTransaction(tmp_path).commit(intent)
    before = resolve_catalog_path("nist-800-53-mod", bundled_manifest=bundled, user_dir_override=tmp_path)
    assert before[0] == target and before[2] == "user"
    transaction = module.CatalogManifestTransaction(tmp_path)
    transaction.commit(module.CatalogMutationIntent.remove("nist-800-53-mod"))
    after = resolve_catalog_path("nist-800-53-mod", bundled_manifest=bundled, user_dir_override=tmp_path)
    assert after[2] == "bundled" and after[0] != target
    assert after[0].name == "nist-800-53-mod.json"
    assert target.read_bytes() == raw and load_user_manifest(tmp_path).frameworks == []
    assert transaction.observation.publication_state == "committed"


@pytest.mark.parametrize("collision", ["none", "stage", "manifest"])
def test_f2_unrelated_and_colliding_temporary_paths_are_never_adopted_or_deleted(
    tmp_path, monkeypatch, collision
) -> None:
    from types import SimpleNamespace

    import evidentia_core.catalogs.user_dir as module

    stage = tmp_path / (".catalog-stage-" + "a" * 32)
    stage.mkdir()
    retained = stage / "catalog.json"
    retained.write_bytes(b"unrelated stage bytes")
    temporary = tmp_path / (".frameworks-" + "b" * 32 + ".yaml")
    temporary.write_bytes(b"unrelated manifest bytes")
    if collision != "none":
        monkeypatch.setattr(
            module.uuid, "uuid4", lambda: SimpleNamespace(hex=("a" if collision == "stage" else "b") * 32)
        )
    transaction = module.CatalogManifestTransaction(tmp_path)
    if collision == "none":
        transaction._replace_complete(FrameworkManifest(version=1, frameworks=[]))
        assert transaction.observation.publication_state == "committed"
    else:
        with pytest.raises(FileExistsError):
            if collision == "stage":
                intent, _ = _legacy_import()
                transaction.commit(intent)
            else:
                transaction._replace_complete(FrameworkManifest(version=1, frameworks=[]))
        assert transaction.observation.publication_state == "not_attempted"
        assert not (tmp_path / "frameworks.yaml").exists()
    assert retained.read_bytes() == b"unrelated stage bytes"
    assert temporary.read_bytes() == b"unrelated manifest bytes"
    assert {path.name for path in stage.iterdir()} == {"catalog.json"}


@pytest.mark.parametrize("primary_type", [RuntimeError, _F2BoundaryAbort])
@pytest.mark.parametrize("after_move", [False, True])
def test_f2_generation_move_failure_preserves_primary_and_retained_generation(
    tmp_path, monkeypatch, primary_type, after_move
) -> None:
    import hashlib

    import evidentia_core.catalogs.user_dir as module

    previous = b"version: 1\nframeworks: []\n"
    (tmp_path / "frameworks.yaml").write_bytes(previous)
    primary = primary_type("synthetic generation move")
    secondary = _F2BoundaryAbort("distinct cleanup interruption")
    original = module._rename_generation
    close = module._NativeLock.close
    calls = []

    def move(source, target):
        calls.append((source, target))
        if after_move:
            original(source, target)
        raise primary

    def release(owner):
        failures = close(owner)
        failures.append(("handle_close_failed", secondary))
        return failures

    monkeypatch.setattr(module, "_rename_generation", move)
    monkeypatch.setattr(module._NativeLock, "close", release)
    intent, raw = _legacy_import()
    transaction = module.CatalogManifestTransaction(tmp_path)
    with pytest.raises(primary_type) as caught:
        transaction.commit(intent)
    assert caught.value is primary and caught.value is not secondary
    assert len(calls) == 1 and (tmp_path / "frameworks.yaml").read_bytes() == previous
    generation = tmp_path / "legacy" / hashlib.sha256(raw).hexdigest()
    if after_move:
        assert (generation / "catalog.json").read_bytes() == raw
    else:
        assert not generation.exists()
    observation = transaction.observation
    assert observation.publication_state == "not_attempted" and observation.replace_outcome == "not_called"
    assert observation.failure_phase == "generation" and observation.cleanup_state == "failed"
    assert "handle_close_failed" in observation.cleanup_errors
    assert transaction._descriptors == [] and transaction._files == [] and transaction._directories == []
    assert not transaction._lock.locked


@pytest.mark.parametrize("primary_type", [RuntimeError, _F2BoundaryAbort])
@pytest.mark.parametrize("cleanup_boundary", ["unlink", "rmdir"])
def test_f2_actual_temporary_cleanup_failure_cannot_replace_primary(
    tmp_path, monkeypatch, primary_type, cleanup_boundary
) -> None:
    from pathlib import Path

    import evidentia_core.catalogs.user_dir as module

    primary = primary_type("synthetic before publication")
    secondary = _F2BoundaryAbort("distinct owned temporary cleanup")
    original = getattr(Path, cleanup_boundary)
    visited = []

    def finish(*args):
        raise primary

    def cleanup(path, *args, **kwargs):
        if path.name.startswith(".catalog-stage-") or path.parent.name.startswith(".catalog-stage-"):
            visited.append(path)
            raise secondary
        return original(path, *args, **kwargs)

    monkeypatch.setattr(module.CatalogManifestTransaction, "_finish_generation", finish)
    monkeypatch.setattr(Path, cleanup_boundary, cleanup)
    transaction = module.CatalogManifestTransaction(tmp_path)
    intent, _ = _legacy_import()
    with pytest.raises(primary_type) as caught:
        transaction.commit(intent)
    assert caught.value is primary and caught.value is not secondary
    assert visited
    assert transaction.observation.cleanup_errors == ("temporary_cleanup_failed",)
    assert transaction.observation.publication_state == "not_attempted"
    assert transaction._descriptors == [] and transaction._files == [] and transaction._directories == []
    assert transaction._lock.handle is None and transaction._lock.parent_handle is None
    assert transaction._lock.descriptor is None and transaction._lock.directory_fd is None
    assert not transaction._lock.locked and not (tmp_path / "frameworks.yaml").exists()


_F2_NONINHERIT_CHILD = r"""
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from evidentia_core.catalogs.user_dir import _NativeLock, CatalogStorageError
from evidentia_core.models.open_corpora import native_operation
with native_operation() as budget:
    owner = _NativeLock(Path(sys.argv[2]))
    try:
        try:
            owner.acquire(budget)
        except CatalogStorageError as error:
            if error.code != 'catalog_transaction_conflict':
                raise
        else:
            raise AssertionError('child acquired while parent held lock')
    finally:
        if owner.close():
            raise AssertionError('refused child cleanup failed')
print('BLOCKED', flush=True)
if sys.stdin.read(1) != 'x':
    raise AssertionError('missing parent release')
with native_operation() as budget:
    owner = _NativeLock(Path(sys.argv[2]))
    try:
        owner.acquire(budget)
    finally:
        if owner.close():
            raise AssertionError('new child owner cleanup failed')
print('ACQUIRED', flush=True)
"""


def test_f2_lock_is_not_inherited_and_repeated_cleanup_keeps_stable_object(tmp_path, request) -> None:
    import os
    import subprocess
    import sys
    from pathlib import Path
    from queue import Queue
    from threading import Thread

    import evidentia_core.catalogs.user_dir as module
    from evidentia_core.models.open_corpora import NativeBudget

    owner = module._NativeLock(tmp_path)
    process = None
    owner.acquire(NativeBudget())
    lock = tmp_path / "frameworks.yaml.lock"
    identity = (lock.stat().st_dev, lock.stat().st_ino)
    try:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            query = ctypes.WinDLL("kernel32", use_last_error=True).GetHandleInformation
            query.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            query.restype = wintypes.BOOL
            for handle in (owner.handle, owner.parent_handle):
                flags = wintypes.DWORD()
                assert query(handle, ctypes.byref(flags))
                assert flags.value & 1 == 0
        else:
            assert not os.get_inheritable(owner.descriptor)
            assert not os.get_inheritable(owner.directory_fd)
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                _F2_NONINHERIT_CHILD,
                str(Path(module.__file__).parents[2]),
                str(tmp_path),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=False,
        )
        request.node.user_properties.append(("owned_child_pid", process.pid))
        ready = Queue()
        reader = Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True)
        reader.start()
        assert ready.get(timeout=15) == "BLOCKED\n"
        reader.join(timeout=15)
        assert not reader.is_alive() and process.poll() is None
        assert owner.close() == []
        assert owner.close() == []
        assert identity == (lock.stat().st_dev, lock.stat().st_ino)
        output, error = process.communicate("x", timeout=15)
        assert process.returncode == 0 and output == "ACQUIRED\n" and error == ""
        assert owner.handle is None and owner.parent_handle is None
        assert owner.descriptor is None and owner.directory_fd is None and not owner.locked
        assert lock.read_bytes() == b"" and not (tmp_path / "frameworks.yaml").exists()
        assert identity == (lock.stat().st_dev, lock.stat().st_ino)
    finally:
        assert owner.close() == []
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=15)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
            request.node.user_properties.extend(
                [("wait_returncode", process.returncode), ("owned_child_reaped", process.poll() is not None)]
            )


@pytest.mark.parametrize(
    "refusal", ["reparse", "directory", "device", "identity", "query_error", "open_error", "lock_error", "busy"]
)
def test_f2_windows_lock_refusal_is_not_mislabeled_as_contention(tmp_path, monkeypatch, refusal) -> None:
    import ctypes
    import sys
    from collections import Counter

    import evidentia_core.catalogs.user_dir as module

    if sys.platform != "win32":
        pytest.skip("Win32 metadata mutation controls run on Windows")
    native = ctypes.WinDLL("kernel32", use_last_error=True)
    counts = Counter()

    class Call:
        def __init__(self, name):
            self.name = name
            self.function = getattr(native, name)

        @property
        def argtypes(self):
            return self.function.argtypes

        @argtypes.setter
        def argtypes(self, value):
            self.function.argtypes = value

        @property
        def restype(self):
            return self.function.restype

        @restype.setter
        def restype(self, value):
            self.function.restype = value

        def __call__(self, *args):
            counts[self.name] += 1
            count = counts[self.name]
            if self.name == "CreateFileW" and count == 2 and refusal == "open_error":
                ctypes.set_last_error(5)
                return ctypes.c_void_p(-1).value
            if self.name == "GetFileInformationByHandleEx" and count == 4 and refusal == "query_error":
                ctypes.set_last_error(5)
                return 0
            if self.name == "LockFileEx" and refusal in ("lock_error", "busy"):
                ctypes.set_last_error(33 if refusal == "busy" else 5)
                return 0
            result = self.function(*args)
            if self.name == "GetFileInformationByHandleEx" and result:
                value = args[2]._obj
                if count == 4 and refusal == "reparse":
                    value.attributes |= 1024
                elif count == 5 and refusal == "directory":
                    value.directory = 1
                elif count == 9 and refusal == "identity":
                    value.identifier[0] ^= 1
            if self.name == "GetFileType" and count == 2 and refusal == "device":
                return 2
            return result

    class Api:
        def __getattr__(self, name):
            value = Call(name)
            setattr(self, name, value)
            return value

    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: Api())
    transaction = module.CatalogManifestTransaction(tmp_path)
    expected = OSError if refusal in ("open_error", "query_error", "lock_error") else module.CatalogStorageError
    with pytest.raises(expected) as caught:
        transaction._replace_complete(FrameworkManifest(version=1, frameworks=[]))
    observation = transaction.observation
    assert observation.failure_phase == "lock" and observation.publication_state == "not_attempted"
    assert observation.error_code == (
        "catalog_transaction_conflict"
        if refusal == "busy"
        else "catalog_storage_failed"
        if expected is OSError
        else "catalog_storage_unsupported"
    )
    if expected is OSError:
        assert caught.value.winerror == 5
    assert not (tmp_path / "frameworks.yaml").exists()
    assert transaction._lock.handle is None and transaction._lock.parent_handle is None
    assert not transaction._lock.locked and observation.cleanup_state == "complete"


@pytest.mark.parametrize("refusal", ["symlink", "fifo", "device", "missing_flag", "open_error", "lock_error", "busy"])
def test_f2_posix_lock_refuses_nonordinary_targets_and_distinguishes_io(tmp_path, monkeypatch, refusal) -> None:
    import errno
    import stat
    import sys
    from types import SimpleNamespace

    import evidentia_core.catalogs.user_dir as module
    from evidentia_core.models.open_corpora import NativeBudget

    owner = module._NativeLock(tmp_path)
    directory = tmp_path.stat()
    mode = {"symlink": stat.S_IFLNK, "fifo": stat.S_IFIFO, "device": stat.S_IFCHR}.get(refusal, stat.S_IFREG)
    leaf = SimpleNamespace(st_mode=mode | 0o600, st_size=0, st_nlink=1, st_dev=directory.st_dev, st_ino=321)
    opened, closed, locks = [], [], []
    primary = (
        PermissionError(errno.EACCES, "synthetic open refusal")
        if refusal == "open_error"
        else OSError(errno.EIO, "synthetic lock I/O")
    )

    def open_file(*args, **kwargs):
        if opened and refusal == "open_error":
            raise primary
        descriptor = 101 if not opened else 102
        opened.append(descriptor)
        return descriptor

    def flock(descriptor, flags):
        locks.append(flags)
        if flags == 6:
            if refusal == "busy":
                raise OSError(errno.EAGAIN, "synthetic contention")
            if refusal == "lock_error":
                raise primary

    with monkeypatch.context() as changes:
        changes.setitem(sys.modules, "fcntl", SimpleNamespace(flock=flock, LOCK_EX=2, LOCK_NB=4, LOCK_UN=8))
        changes.setattr(sys, "platform", "linux")
        for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK"):
            changes.setattr(module.os, flag, 1, raising=False)
        if refusal == "missing_flag":
            changes.delattr(module.os, "O_NOFOLLOW")
        changes.setattr(module.os, "open", open_file)
        changes.setattr(module.os, "supports_dir_fd", {open_file})
        changes.setattr(module.os, "fstat", lambda descriptor: directory if descriptor == 101 else leaf)
        changes.setattr(type(tmp_path), "lstat", lambda self: directory)
        changes.setattr(module.os, "stat", lambda *args, **kwargs: leaf)
        changes.setattr(module.os, "get_inheritable", lambda descriptor: False)
        changes.setattr(module.os, "ST_LOCAL", 1, raising=False)
        changes.setattr(module.os, "fstatvfs", lambda descriptor: SimpleNamespace(f_flag=1), raising=False)
        changes.setattr(module, "_linux_filesystem_type", lambda *args: 0xEF53)
        changes.setattr(module.os, "close", closed.append)
        expected = OSError if refusal in ("open_error", "lock_error") else module.CatalogStorageError
        try:
            with pytest.raises(expected) as caught:
                owner._posix_acquire(NativeBudget())
            if expected is OSError:
                assert caught.value is primary
            else:
                assert caught.value.code == (
                    "catalog_transaction_conflict" if refusal == "busy" else "catalog_storage_unsupported"
                )
        finally:
            changes.setattr(module.os, "name", "posix")
            assert owner.close() == []
            assert owner.close() == []
    assert closed == list(reversed(opened))
    assert locks == ([6] if refusal in ("lock_error", "busy") else [])
    assert owner.descriptor is None and owner.directory_fd is None and not owner.locked
    assert list(tmp_path.iterdir()) == []


def test_f2_two_actual_transactions_contend_through_independent_handles(tmp_path, monkeypatch) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    import evidentia_core.catalogs.user_dir as module

    acquired, release = Event(), Event()
    original = module._NativeLock.acquire
    first = module.CatalogManifestTransaction(tmp_path)
    second = module.CatalogManifestTransaction(tmp_path)

    def acquire(owner, budget):
        original(owner, budget)
        assert owner is first._lock
        acquired.set()
        assert release.wait(10)

    monkeypatch.setattr(module._NativeLock, "acquire", acquire)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(first._replace_complete, FrameworkManifest(version=1, frameworks=[]))
        try:
            assert acquired.wait(10)
            assert first._lock.locked
            with pytest.raises(module.CatalogStorageError, match="catalog_transaction_conflict"):
                second._replace_complete(FrameworkManifest(version=2, frameworks=[]))
            assert second._lock is not first._lock
            assert second.observation.publication_state == "not_attempted"
            assert second.observation.error_code == "catalog_transaction_conflict"
            assert not second._lock.locked and not (tmp_path / "frameworks.yaml").exists()
            assert first._lock.locked
        finally:
            release.set()
        pending.result(timeout=15)
    assert load_user_manifest(tmp_path).version == 1
    assert first.observation.publication_state == "committed"
    assert not first._lock.locked and not second._lock.locked
