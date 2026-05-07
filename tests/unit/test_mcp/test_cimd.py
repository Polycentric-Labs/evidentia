"""Unit tests for the CIMD registry (v0.8.5 P4).

5 test classes mirroring the surface added in v0.8.5 P4:

1. :class:`TestCIMDDocumentModel` — Pydantic validation of
   :class:`CIMDDocument` fields + ``has_scope`` semantics.
2. :class:`TestCIMDRegistryFromFile` — JSON-file loading +
   error paths (malformed JSON, wrong version, missing
   required fields).
3. :class:`TestCIMDRegistryLookup` — registry lookup behavior
   (registered + unregistered client_ids).
4. :class:`TestCIMDInBuildServer` — :func:`build_server`
   accepts a CIMDRegistry + attaches it as
   ``server.evidentia_cimd``.
5. :class:`TestCIMDCLIFlag` — :func:`evidentia mcp serve`
   ``--cimd-registry`` CLI flag round-trip.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia_mcp.cimd import (
    CIMD_REGISTRY_VERSION,
    CIMDDocument,
    CIMDRegistry,
)

# ── 1. CIMDDocument model ────────────────────────────────────────


class TestCIMDDocumentModel:
    def test_minimum_valid_doc(self) -> None:
        doc = CIMDDocument(
            client_id="claude-desktop",
            client_name="Claude Desktop",
        )
        assert doc.client_id == "claude-desktop"
        assert doc.client_name == "Claude Desktop"
        assert doc.scope == ""
        assert doc.redirect_uris == []
        assert doc.policy_uri is None
        assert doc.tos_uri is None

    def test_full_doc_round_trip(self) -> None:
        doc = CIMDDocument(
            client_id="readonly-agent",
            client_name="Read-only research agent",
            scope="list_frameworks get_control",
            redirect_uris=["https://example.test/callback"],
            policy_uri="https://example.test/privacy",
            tos_uri="https://example.test/tos",
        )
        # Serialize + deserialize.
        round_trip = CIMDDocument.model_validate_json(
            doc.model_dump_json()
        )
        assert round_trip == doc

    def test_has_scope_empty_scope_denies_all(self) -> None:
        doc = CIMDDocument(
            client_id="empty-scope-client", client_name="Empty"
        )
        assert doc.has_scope("list_frameworks") is False
        assert doc.has_scope("anything") is False

    def test_has_scope_allowlist_semantics(self) -> None:
        doc = CIMDDocument(
            client_id="readonly-agent",
            client_name="readonly",
            scope="list_frameworks get_control",
        )
        assert doc.has_scope("list_frameworks") is True
        assert doc.has_scope("get_control") is True
        assert doc.has_scope("gap_analyze") is False

    def test_client_id_too_long_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            CIMDDocument(client_id="x" * 201, client_name="x")

    def test_client_id_empty_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            CIMDDocument(client_id="", client_name="x")


# ── 2. CIMDRegistry.from_file ────────────────────────────────────


class TestCIMDRegistryFromFile:
    def _write_registry(
        self, tmp_path: Path, payload: dict[str, object]
    ) -> Path:
        path = tmp_path / "cimd.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_load_two_clients(self, tmp_path: Path) -> None:
        path = self._write_registry(
            tmp_path,
            {
                "version": 1,
                "clients": {
                    "claude-desktop": {
                        "client_id": "claude-desktop",
                        "client_name": "Claude Desktop",
                        "scope": "list_frameworks get_control gap_analyze gap_diff",
                    },
                    "readonly-agent": {
                        "client_id": "readonly-agent",
                        "client_name": "Read-only research agent",
                        "scope": "list_frameworks get_control",
                    },
                },
            },
        )
        registry = CIMDRegistry.from_file(path)
        assert registry.version == CIMD_REGISTRY_VERSION
        assert len(registry.clients) == 2
        assert registry.clients["claude-desktop"].has_scope(
            "gap_analyze"
        )
        assert (
            registry.clients["readonly-agent"].has_scope("gap_analyze")
            is False
        )

    def test_load_empty_clients(self, tmp_path: Path) -> None:
        path = self._write_registry(
            tmp_path, {"version": 1, "clients": {}}
        )
        registry = CIMDRegistry.from_file(path)
        assert registry.clients == {}

    def test_malformed_json_raises_value_error(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "cimd.json"
        path.write_text("not valid json {{{", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid JSON"):
            CIMDRegistry.from_file(path)

    def test_top_level_list_raises_value_error(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "cimd.json"
        path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        with pytest.raises(ValueError, match="JSON object"):
            CIMDRegistry.from_file(path)

    def test_unsupported_version_raises_value_error(
        self, tmp_path: Path
    ) -> None:
        path = self._write_registry(
            tmp_path, {"version": 99, "clients": {}}
        )
        with pytest.raises(
            ValueError, match="Unsupported CIMD registry version"
        ):
            CIMDRegistry.from_file(path)

    def test_validation_failure_in_client_doc(
        self, tmp_path: Path
    ) -> None:
        path = self._write_registry(
            tmp_path,
            {
                "version": 1,
                "clients": {
                    "bad": {
                        # client_name missing → ValidationError
                        "client_id": "bad",
                    }
                },
            },
        )
        with pytest.raises(ValueError, match="failed validation"):
            CIMDRegistry.from_file(path)

    def test_missing_file_raises_file_not_found(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "does_not_exist.json"
        with pytest.raises(FileNotFoundError):
            CIMDRegistry.from_file(path)


# ── 3. Registry lookup ───────────────────────────────────────────


class TestCIMDRegistryLookup:
    def test_get_returns_doc_for_registered_client(self) -> None:
        registry = CIMDRegistry(
            clients={
                "abc": CIMDDocument(
                    client_id="abc",
                    client_name="Alpha Beta Gamma",
                    scope="list_frameworks",
                )
            }
        )
        doc = registry.get("abc")
        assert doc is not None
        assert doc.client_name == "Alpha Beta Gamma"

    def test_get_returns_none_for_unregistered(self) -> None:
        registry = CIMDRegistry(clients={})
        assert registry.get("nope") is None


# ── 4. build_server attaches CIMD ────────────────────────────────


class TestCIMDInBuildServer:
    def test_build_server_without_cimd_attaches_none(self) -> None:
        from evidentia_mcp.server import build_server

        server = build_server()
        # Custom attribute attached for v0.8.5 P4.
        assert server.evidentia_cimd is None  # type: ignore[attr-defined]

    def test_build_server_with_cimd_attaches_registry(self) -> None:
        from evidentia_mcp.server import build_server

        registry = CIMDRegistry(
            clients={
                "test-client": CIMDDocument(
                    client_id="test-client",
                    client_name="Test client",
                    scope="list_frameworks",
                )
            }
        )
        server = build_server(cimd_registry=registry)
        attached = server.evidentia_cimd  # type: ignore[attr-defined]
        assert attached is registry
        assert attached.clients["test-client"].has_scope(
            "list_frameworks"
        )


# ── 5. CLI --cimd-registry round-trip ────────────────────────────


class TestCIMDCLIFlag:
    def test_cimd_registry_flag_advertised_in_help(self) -> None:
        # Use Click introspection (matches v0.8.1 + v0.8.2 patterns
        # for cross-OS robustness; doesn't rely on rendered output).
        from evidentia_mcp.cli import app
        from typer.main import get_command

        cmd = get_command(app)
        # The default command exposed when no group exists is
        # `serve` itself; locate it.
        assert "serve" in cmd.commands  # type: ignore[attr-defined]
        serve_cmd = cmd.commands["serve"]  # type: ignore[attr-defined]
        param_names = {p.name for p in serve_cmd.params}
        assert "cimd_registry_path" in param_names

    def test_cimd_registry_invalid_path_exits_2(
        self, tmp_path: Path
    ) -> None:
        from evidentia_mcp.cli import app
        from typer.testing import CliRunner

        runner = CliRunner()
        # Path doesn't exist → Typer's exists=True check rejects.
        bogus = tmp_path / "nope.json"
        result = runner.invoke(
            app,
            [
                "serve",
                "--transport",
                "stdio",
                "--cimd-registry",
                str(bogus),
            ],
        )
        # Typer's exists=True check fails the option parse → exit 2
        assert result.exit_code == 2
