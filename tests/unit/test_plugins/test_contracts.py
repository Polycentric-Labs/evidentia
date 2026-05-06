"""Sanity tests for the v0.8.0 P0.4 plugin contracts.

Verifies that:
1. The 4 ABCs (AuthProvider, StorageBackend, MarketplaceProvider,
   BaseSaaSCollector) are properly abstract — instantiating them
   directly raises TypeError.
2. The 3 reference implementations (LocalTokenAuthProvider,
   FilesystemStorageBackend, LocalDirectoryMarketplaceProvider)
   conform to their respective contracts + work end-to-end.
3. Discovery via importlib.metadata works (returns empty dict
   when no plugins are registered).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia_core.plugins import (
    AuthProvider,
    BaseSaaSCollector,
    MarketplaceProvider,
    StorageBackend,
    discover_plugins,
)
from evidentia_core.plugins.auth import (
    AuthResult,
    LocalTokenAuthProvider,
)
from evidentia_core.plugins.marketplace import (
    LocalDirectoryMarketplaceProvider,
)
from evidentia_core.plugins.storage import FilesystemStorageBackend
from pydantic import BaseModel

# ── ABC abstractness ──────────────────────────────────────────────


class TestABCsAreAbstract:
    def test_auth_provider_is_abstract(self) -> None:
        with pytest.raises(TypeError):
            AuthProvider()  # type: ignore[abstract]

    def test_storage_backend_is_abstract(self) -> None:
        with pytest.raises(TypeError):
            StorageBackend()  # type: ignore[abstract]

    def test_marketplace_provider_is_abstract(self) -> None:
        with pytest.raises(TypeError):
            MarketplaceProvider()  # type: ignore[abstract]

    def test_base_saas_collector_is_abstract(self) -> None:
        with pytest.raises(TypeError):
            BaseSaaSCollector()  # type: ignore[abstract]


# ── LocalTokenAuthProvider ────────────────────────────────────────


class TestLocalTokenAuthProvider:
    def test_authenticates_valid_bearer_token(
        self, tmp_path: Path
    ) -> None:
        token_file = tmp_path / "token.txt"
        token_file.write_text("secret-abc123")
        provider = LocalTokenAuthProvider(token_file=token_file)

        result = provider.authenticate(
            authorization_header="Bearer secret-abc123"
        )
        assert result.authenticated is True
        assert result.principal == "local-operator"
        assert result.reason is None

    def test_rejects_missing_header(self, tmp_path: Path) -> None:
        token_file = tmp_path / "token.txt"
        token_file.write_text("secret")
        provider = LocalTokenAuthProvider(token_file=token_file)

        result = provider.authenticate(authorization_header=None)
        assert result.authenticated is False
        assert result.reason is not None and "missing" in result.reason.lower()

    def test_rejects_malformed_header(self, tmp_path: Path) -> None:
        token_file = tmp_path / "token.txt"
        token_file.write_text("secret")
        provider = LocalTokenAuthProvider(token_file=token_file)

        result = provider.authenticate(
            authorization_header="malformed-no-scheme"
        )
        assert result.authenticated is False
        assert result.reason is not None and "malformed" in result.reason.lower()

    def test_rejects_unsupported_scheme(self, tmp_path: Path) -> None:
        token_file = tmp_path / "token.txt"
        token_file.write_text("secret")
        provider = LocalTokenAuthProvider(token_file=token_file)

        result = provider.authenticate(
            authorization_header="Basic dXNlcjpwYXNz"
        )
        assert result.authenticated is False
        assert result.reason is not None and "Bearer" in result.reason

    def test_rejects_invalid_token(self, tmp_path: Path) -> None:
        token_file = tmp_path / "token.txt"
        token_file.write_text("expected-token")
        provider = LocalTokenAuthProvider(token_file=token_file)

        result = provider.authenticate(
            authorization_header="Bearer wrong-token"
        )
        assert result.authenticated is False
        assert result.reason is not None and "invalid" in result.reason.lower()

    def test_missing_token_file_raises(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(FileNotFoundError):
            LocalTokenAuthProvider(token_file=tmp_path / "nope.txt")

    def test_empty_token_file_raises(self, tmp_path: Path) -> None:
        token_file = tmp_path / "empty.txt"
        token_file.write_text("   \n   ")
        with pytest.raises(ValueError):
            LocalTokenAuthProvider(token_file=token_file)

    def test_symlink_token_file_rejected(self, tmp_path: Path) -> None:
        """v0.8.1 F-V08-S2: symlinks are rejected at construction
        time to prevent TOCTOU swap attacks via a shared parent
        directory.
        """
        import os
        import sys

        if sys.platform == "win32":
            # Windows symlink creation requires elevated privileges
            # by default; skip this OS where the lstat-based
            # rejection still functions but creating the symlink
            # fixture is non-trivial in CI.
            pytest.skip("symlink fixture creation requires elevation on Windows")
        real_target = tmp_path / "real-token.txt"
        real_target.write_text("secret-from-real-target")
        symlink_path = tmp_path / "token-link.txt"
        os.symlink(real_target, symlink_path)
        with pytest.raises(ValueError, match="symbolic link"):
            LocalTokenAuthProvider(token_file=symlink_path)

    def test_default_provider_name(self, tmp_path: Path) -> None:
        token_file = tmp_path / "token.txt"
        token_file.write_text("x")
        provider = LocalTokenAuthProvider(token_file=token_file)
        assert provider.name() == "local-token"

    def test_custom_provider_name(self, tmp_path: Path) -> None:
        token_file = tmp_path / "token.txt"
        token_file.write_text("x")
        provider = LocalTokenAuthProvider(
            token_file=token_file, provider_name="my-auth"
        )
        assert provider.name() == "my-auth"

    def test_auth_result_is_frozen(self) -> None:
        from dataclasses import FrozenInstanceError

        result = AuthResult(authenticated=True, principal="alice")
        with pytest.raises(FrozenInstanceError):
            result.authenticated = False  # type: ignore[misc]


# ── FilesystemStorageBackend ──────────────────────────────────────


class _SampleRecord(BaseModel):
    name: str
    value: int


class TestFilesystemStorageBackend:
    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        backend = FilesystemStorageBackend[_SampleRecord](
            base_dir=tmp_path / "data",
            record_type=_SampleRecord,
        )
        rec = _SampleRecord(name="foo", value=42)
        backend.save(record_id="rec1", record=rec)

        loaded = backend.load("rec1")
        assert loaded.name == "foo"
        assert loaded.value == 42

    def test_load_missing_raises_keyerror(self, tmp_path: Path) -> None:
        backend = FilesystemStorageBackend[_SampleRecord](
            base_dir=tmp_path / "data",
            record_type=_SampleRecord,
        )
        with pytest.raises(KeyError):
            backend.load("nonexistent")

    def test_delete_roundtrip(self, tmp_path: Path) -> None:
        backend = FilesystemStorageBackend[_SampleRecord](
            base_dir=tmp_path / "data",
            record_type=_SampleRecord,
        )
        backend.save(
            record_id="rec1", record=_SampleRecord(name="x", value=1)
        )
        backend.delete("rec1")
        with pytest.raises(KeyError):
            backend.load("rec1")

    def test_delete_missing_raises_keyerror(
        self, tmp_path: Path
    ) -> None:
        backend = FilesystemStorageBackend[_SampleRecord](
            base_dir=tmp_path / "data",
            record_type=_SampleRecord,
        )
        with pytest.raises(KeyError):
            backend.delete("nonexistent")

    def test_list_records_yields_ids(self, tmp_path: Path) -> None:
        backend = FilesystemStorageBackend[_SampleRecord](
            base_dir=tmp_path / "data",
            record_type=_SampleRecord,
        )
        backend.save(
            record_id="alice", record=_SampleRecord(name="a", value=1)
        )
        backend.save(
            record_id="bob", record=_SampleRecord(name="b", value=2)
        )
        ids = sorted(backend.list_records())
        assert ids == ["alice", "bob"]

    def test_invalid_id_with_path_separator_rejected(
        self, tmp_path: Path
    ) -> None:
        backend = FilesystemStorageBackend[_SampleRecord](
            base_dir=tmp_path / "data",
            record_type=_SampleRecord,
        )
        with pytest.raises(ValueError):
            backend.save(
                record_id="../escape",
                record=_SampleRecord(name="x", value=1),
            )

    def test_empty_id_rejected(self, tmp_path: Path) -> None:
        backend = FilesystemStorageBackend[_SampleRecord](
            base_dir=tmp_path / "data",
            record_type=_SampleRecord,
        )
        with pytest.raises(ValueError):
            backend.save(
                record_id="",
                record=_SampleRecord(name="x", value=1),
            )

    def test_corrupt_record_raises_value_error(
        self, tmp_path: Path
    ) -> None:
        base = tmp_path / "data"
        base.mkdir(parents=True)
        # Write a JSON file that doesn't conform to _SampleRecord.
        (base / "corrupt.json").write_text("{")  # not even valid JSON

        backend = FilesystemStorageBackend[_SampleRecord](
            base_dir=base,
            record_type=_SampleRecord,
        )
        with pytest.raises(ValueError):
            backend.load("corrupt")

    def test_name_returns_filesystem(self, tmp_path: Path) -> None:
        backend = FilesystemStorageBackend[_SampleRecord](
            base_dir=tmp_path / "data",
            record_type=_SampleRecord,
        )
        assert backend.name() == "filesystem"


# ── LocalDirectoryMarketplaceProvider ─────────────────────────────


class TestLocalDirectoryMarketplaceProvider:
    def test_lists_catalogs_from_directory(
        self, tmp_path: Path
    ) -> None:
        # Create 2 fake OSCAL catalogs.
        (tmp_path / "catalog-a.json").write_text(
            json.dumps({"catalog": {"uuid": "a", "controls": []}})
        )
        (tmp_path / "catalog-b.json").write_text(
            json.dumps({"catalog": {"uuid": "b", "controls": []}})
        )

        provider = LocalDirectoryMarketplaceProvider(
            base_dir=tmp_path
        )
        manifests = list(provider.list_catalogs())
        ids = sorted(m.catalog_id for m in manifests)
        assert ids == ["catalog-a", "catalog-b"]

    def test_fetch_catalog_returns_dict(self, tmp_path: Path) -> None:
        catalog_data = {"catalog": {"uuid": "test", "controls": []}}
        (tmp_path / "test-cat.json").write_text(
            json.dumps(catalog_data)
        )

        provider = LocalDirectoryMarketplaceProvider(
            base_dir=tmp_path
        )
        result = provider.fetch_catalog("test-cat")
        assert result == catalog_data

    def test_fetch_missing_catalog_raises_keyerror(
        self, tmp_path: Path
    ) -> None:
        provider = LocalDirectoryMarketplaceProvider(
            base_dir=tmp_path
        )
        with pytest.raises(KeyError):
            provider.fetch_catalog("nonexistent")

    def test_manifest_metadata_overrides_inferred(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "my-cat.json").write_text(
            json.dumps({"catalog": {"uuid": "x"}})
        )
        (tmp_path / "manifest.json").write_text(
            json.dumps(
                {
                    "catalogs": [
                        {
                            "catalog_id": "my-cat",
                            "title": "My Custom Title",
                            "version": "2026.05",
                            "license": "Apache-2.0",
                        }
                    ]
                }
            )
        )

        provider = LocalDirectoryMarketplaceProvider(
            base_dir=tmp_path
        )
        manifests = list(provider.list_catalogs())
        assert len(manifests) == 1
        m = manifests[0]
        assert m.title == "My Custom Title"
        assert m.version == "2026.05"
        assert m.license == "Apache-2.0"

    def test_malformed_manifest_falls_back_to_filename(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "my-cat.json").write_text(
            json.dumps({"catalog": {"uuid": "x"}})
        )
        # Malformed manifest.json — should not crash the provider.
        (tmp_path / "manifest.json").write_text("{broken")

        provider = LocalDirectoryMarketplaceProvider(
            base_dir=tmp_path
        )
        manifests = list(provider.list_catalogs())
        assert len(manifests) == 1
        assert manifests[0].catalog_id == "my-cat"
        # Title falls back to filename when manifest is malformed.
        assert manifests[0].title == "my-cat"

    def test_corrupt_catalog_json_raises(self, tmp_path: Path) -> None:
        (tmp_path / "corrupt.json").write_text("not valid json {")
        provider = LocalDirectoryMarketplaceProvider(
            base_dir=tmp_path
        )
        with pytest.raises(ValueError):
            provider.fetch_catalog("corrupt")

    def test_missing_base_dir_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            LocalDirectoryMarketplaceProvider(
                base_dir=tmp_path / "does-not-exist"
            )

    def test_default_provider_name(self, tmp_path: Path) -> None:
        provider = LocalDirectoryMarketplaceProvider(
            base_dir=tmp_path
        )
        assert provider.name() == "local-directory"


# ── BaseSaaSCollector contract ────────────────────────────────────


class _FakeCollector(BaseSaaSCollector):
    """Minimal subclass for testing BaseSaaSCollector contract.

    Provides the required class attributes + a no-op collect()
    that exercises _get() against an injected mock client.
    """

    COLLECTOR_ID = "fake"
    DEFAULT_BASE_URL = "https://api.fake.example"
    TOKEN_ENV_VAR = "FAKE_API_TOKEN"

    def collect(self) -> dict[str, str]:
        return self._get("/v1/things")


class TestBaseSaaSCollectorContract:
    def test_constructs_with_token(self) -> None:
        c = _FakeCollector(api_token="abc")
        assert c._api_token == "abc"
        assert c._base_url == "https://api.fake.example"

    def test_strips_whitespace_from_token(self) -> None:
        c = _FakeCollector(api_token="  abc  \n")
        assert c._api_token == "abc"

    def test_rejects_empty_token(self) -> None:
        from evidentia_core.plugins.collectors import SaaSAuthError

        with pytest.raises(SaaSAuthError):
            _FakeCollector(api_token="")

    def test_rejects_whitespace_only_token(self) -> None:
        from evidentia_core.plugins.collectors import SaaSAuthError

        with pytest.raises(SaaSAuthError):
            _FakeCollector(api_token="   ")

    def test_accepts_pre_built_client_without_token(self) -> None:
        import httpx

        client = httpx.Client(base_url="https://api.fake.example")
        c = _FakeCollector(client=client)
        assert c._client is client
        assert c._owns_client is False

    def test_context_manager_lifecycle(self) -> None:
        with _FakeCollector(api_token="abc") as c:
            # Force client creation.
            client = c._ensure_client()
            assert client is not None
        # After exit, owned client is closed + cleared.
        assert c._client is None


# ── Plugin discovery ──────────────────────────────────────────────


class TestPluginDiscovery:
    def test_discover_plugins_returns_dict(self) -> None:
        plugins = discover_plugins()
        # No plugins registered for the standard
        # `evidentia.plugins` group in the test environment.
        assert isinstance(plugins, dict)
        assert plugins == {}
