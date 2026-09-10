"""Keep MCP tests independent of operator catalogs and signing configuration."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path

import pytest
from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.factory_resolver import clear_factory_cache
from evidentia_core.models.control import (
    ControlImplementation,
    ControlInventory,
    ControlStatus,
)


@pytest.fixture(autouse=True)
def isolated_mcp_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Use temporary catalogs and resolve signing only when a test opts in."""
    catalogs = tmp_path / "catalogs"
    catalogs.mkdir()
    monkeypatch.setenv("EVIDENTIA_CATALOG_DIR", str(catalogs))
    monkeypatch.delenv("EVIDENTIA_MCP_SIGN_OUTPUTS", raising=False)
    monkeypatch.delenv("EVIDENTIA_MCP_SIGNER_FACTORY", raising=False)
    FrameworkRegistry.reset_instance()
    clear_factory_cache()
    yield
    FrameworkRegistry.reset_instance()
    clear_factory_cache()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def synthetic_signer(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """Capture canonical bytes with a synthetic digest and no signing service."""
    payloads: list[bytes] = []

    def sign(payload: bytes) -> dict[str, str]:
        payloads.append(payload)
        return {"algorithm": "synthetic-sha256", "digest": hashlib.sha256(payload).hexdigest()}

    monkeypatch.setattr("evidentia_mcp.signatures._resolve_signer_factory", lambda: sign)
    monkeypatch.setattr("evidentia_mcp.signed_dispatch._resolve_signer_factory", lambda: sign)
    return payloads


@pytest.fixture
def mcp_test_inventory(tmp_path: Path) -> Path:
    """Write a synthetic inventory inside the server's allowed root."""
    inventory = ControlInventory(
        organization="Synthetic protocol test",
        system_name="isolated-mcp-test",
        controls=[
            ControlImplementation(
                id="AC-2",
                title="Account Management",
                description="Synthetic account control.",
                status=ControlStatus.IMPLEMENTED,
                frameworks=["nist-800-53-rev5-moderate"],
            )
        ],
    )
    path = tmp_path / "inventory.json"
    path.write_text(inventory.model_dump_json(indent=2) + "\n", encoding="utf-8", newline="\n")
    return path
