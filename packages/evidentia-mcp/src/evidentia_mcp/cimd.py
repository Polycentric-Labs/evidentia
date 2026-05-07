"""Client ID Metadata Document (CIMD) registry — v0.8.5 P4.

Implements MCP CIMD richness deferred 5 cycles (v0.8.0 §5.3 →
v0.8.1 → v0.8.2 → v0.8.3 → v0.8.4 → v0.8.5). Provides a
JSON-file-backed registry of client metadata for multi-tenant
MCP deployments.

Design

CIMD per the OAuth Dynamic Client Registration spec (RFC 7591)
+ MCP authentication conventions: each registered client has
a stable ``client_id`` + descriptive ``client_name`` + a
``scope`` field that gates which tools the client may call.

Evidentia's MCP server uses CIMD to support:

1. **Multi-tenant deployments** — operators host one MCP server
   instance + register multiple clients with different scopes
   (e.g., ``readonly-clients`` get ``list_frameworks`` +
   ``get_control`` only; ``power-clients`` get the full tool
   surface).
2. **Per-client audit trail** — when a tool fires, the server
   logs the calling ``client_id`` so audit trails distinguish
   "Client A invoked gap_analyze" from "Client B invoked the
   same tool".
3. **Future-proofing** — registered clients can declare
   ``policy_uri`` + ``tos_uri`` so the MCP host UI can surface
   privacy/ToS info before the user authorizes the connection.

Loading

Operators provide CIMD via a JSON file:

.. code-block:: json

    {
      "version": 1,
      "clients": {
        "claude-desktop": {
          "client_id": "claude-desktop",
          "client_name": "Claude Desktop",
          "scope": "list_frameworks get_control gap_analyze gap_diff",
          "redirect_uris": [],
          "policy_uri": null,
          "tos_uri": null
        },
        "readonly-agent": {
          "client_id": "readonly-agent",
          "client_name": "Read-only research agent",
          "scope": "list_frameworks get_control",
          "redirect_uris": [],
          "policy_uri": null,
          "tos_uri": null
        }
      }
    }

CIMD is OPTIONAL. When ``cimd_registry`` is ``None`` (default),
the server preserves v0.8.4 behavior — every tool is callable
by every connected client, no per-client gating. CIMD enables
the gating; absence of CIMD does not weaken the trust model.

Threat model

CIMD is NOT authentication — it's a metadata + scope layer
that runs ON TOP of whatever authentication the transport
provides (reverse-proxy auth for HTTP/SSE; UID-based trust
for stdio). A malicious client that bypasses the transport
auth can claim any ``client_id`` it wants. Operators
deploying CIMD MUST also wire transport auth (e.g., reverse-
proxy mTLS or bearer tokens) so clients cannot impersonate
each other's CIMD entries.

Future cycles may add cryptographic CIMD signatures (per the
Webscale OIDC profile of CIMD) to bind ``client_id`` to a
key the client proves possession of. v0.8.5 ships the
metadata registry; signing is a separate concern.

Plan: §28 v0.8.5 P4.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Self

from pydantic import BaseModel, Field

CIMD_REGISTRY_VERSION = 1


class CIMDDocument(BaseModel):
    """One client's metadata per the CIMD spec.

    Fields mirror RFC 7591 (OAuth Dynamic Client Registration)
    plus the MCP-specific convention that ``scope`` is a space-
    separated list of MCP tool names the client is authorized
    to call. The empty string in ``scope`` means "no tools
    authorized" (effectively a deny-all entry; the client can
    connect but cannot call any tool).
    """

    client_id: str = Field(
        min_length=1,
        max_length=200,
        description=(
            "Stable identifier for the client. SHOULD be a "
            "human-readable slug (e.g., 'claude-desktop', "
            "'readonly-agent'); the server emits it in audit "
            "trails so operators trace tool invocations back "
            "to the calling client."
        ),
    )
    client_name: str = Field(
        min_length=1,
        max_length=500,
        description=(
            "Human-friendly client name shown in audit logs + "
            "operator dashboards. May contain spaces."
        ),
    )
    scope: str = Field(
        default="",
        description=(
            "Space-separated MCP tool names the client may "
            "call (e.g., 'list_frameworks get_control'). Empty "
            "string = deny-all. Unknown tool names are ignored "
            "(scope acts as an allowlist; tools not in the "
            "allowlist are denied)."
        ),
    )
    redirect_uris: list[str] = Field(
        default_factory=list,
        description=(
            "Per RFC 7591. Currently unused by Evidentia MCP — "
            "stdio + HTTP/SSE transports don't redirect. "
            "Reserved for future OAuth-flow integration."
        ),
    )
    policy_uri: str | None = Field(
        default=None,
        description=(
            "URL to the client's privacy policy. Future MCP "
            "host UIs may surface this before authorizing the "
            "connection."
        ),
    )
    tos_uri: str | None = Field(
        default=None,
        description=(
            "URL to the client's terms of service. Future MCP "
            "host UIs may surface this before authorizing the "
            "connection."
        ),
    )

    def has_scope(self, tool_name: str) -> bool:
        """Returns True if ``tool_name`` is allowlisted in this
        client's ``scope`` field. Empty scope = deny-all.
        """
        if not self.scope:
            return False
        return tool_name in self.scope.split()


class CIMDRegistry(BaseModel):
    """Registry of registered CIMDs.

    Loaded from a JSON file at server startup. Lookups are by
    ``client_id``; unregistered ``client_id`` values raise
    KeyError (operators preferring the "unknown client = full
    access" pattern can simply not pass a registry to the
    server, which preserves v0.8.4 no-gating behavior).
    """

    version: int = Field(
        default=CIMD_REGISTRY_VERSION,
        description=(
            "Registry format version. Current: 1. Future "
            "additions to the schema (e.g., signed-CIMD "
            "support) will bump this; the server checks the "
            "version field at load time to refuse unsupported "
            "formats."
        ),
    )
    clients: dict[str, CIMDDocument] = Field(
        default_factory=dict,
        description="Map of client_id → CIMDDocument.",
    )

    @classmethod
    def from_file(cls, path: Path) -> Self:
        """Parse a CIMD registry JSON file from disk.

        Raises:
            FileNotFoundError: if ``path`` does not exist.
            ValueError: if the JSON is malformed, the version
                is unsupported, or any CIMDDocument fails
                Pydantic validation.
        """
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON in CIMD registry {path}: {exc}"
            ) from exc

        if not isinstance(raw, dict):
            raise ValueError(
                f"CIMD registry {path} must be a JSON object at "
                f"the top level; got {type(raw).__name__}."
            )

        version = raw.get("version", CIMD_REGISTRY_VERSION)
        if version != CIMD_REGISTRY_VERSION:
            raise ValueError(
                f"Unsupported CIMD registry version "
                f"{version!r} in {path}; this build supports "
                f"version {CIMD_REGISTRY_VERSION}."
            )

        try:
            return cls.model_validate(raw)
        except Exception as exc:
            raise ValueError(
                f"CIMD registry {path} failed validation: {exc}"
            ) from exc

    def get(self, client_id: str) -> CIMDDocument | None:
        """Lookup; returns None if unregistered (callers decide
        whether to deny or fall back to no-gating)."""
        return self.clients.get(client_id)


__all__ = [
    "CIMD_REGISTRY_VERSION",
    "CIMDDocument",
    "CIMDRegistry",
]
