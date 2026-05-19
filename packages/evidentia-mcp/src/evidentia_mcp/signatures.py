"""Cryptographic signatures on MCP tool outputs (v0.9.7 P2.4 — v1.0 prep).

Composes with the v0.7.x supply-chain narrative (Sigstore + PEP 740
+ cosign-signed container). Operators opting in via env vars get
a signed envelope around every MCP tool output; the signature is
verifiable downstream as evidence that the tool result was produced
by the configured Evidentia instance without tampering in transit.

**Design rules**:

1. **Signer-agnostic**. The signing backend is operator-supplied via
   a dotted-path factory (same pattern as
   :mod:`evidentia_core.evidence_store.EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR`).
   Production deployments wire Sigstore-keyless; dev / CI wires HMAC
   for determinism; air-gap deployments wire GPG.
2. **Opt-in**. Default unset → tools emit raw payloads (v0.9.6
   backward-compat). Setting :data:`EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR`
   enables the wrapper.
3. **Envelope format stable**. :class:`SignedToolOutput` is a
   v0.9.7 NORMATIVE Pydantic model frozen against future
   field-name changes (additions only).
4. **Failure surfaces as a structured error**. A signing failure
   does NOT crash the tool; instead the tool emits a SignedToolOutput
   with ``signature=None`` + ``signing_error`` populated. Operators
   relying on signed-only output check ``signature is not None``.

**v0.9.7 partial scope** (what ships now):

- :class:`SignedToolOutput` envelope model
- :func:`sign_tool_output(payload)` helper (resolves signer from env)
- :func:`verify_tool_output(envelope)` verification helper
- :func:`_resolve_signer_factory()` env-var-driven factory loader

**v1.0 follow-up scope** (deferred):

- Auto-wrap at the FastMCP dispatch layer (no per-tool opt-in)
- Sigstore-keyless reference backend in
  :mod:`evidentia_mcp.signatures.sigstore_signer`
- MCP CIMD scope-grant "client-must-verify-signatures" field

**Threat-model boundary**: MCP tool output signatures defend against
in-transit tampering + provide audit-trail provenance. They do NOT
defend against compromise of the signing key — the operator is
responsible for protecting the signer's private material (Sigstore
keyless OIDC avoids the key-material problem entirely).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import datetime
from typing import Any

from evidentia_core.models.common import EvidentiaModel, utc_now
from pydantic import Field

EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR = "EVIDENTIA_MCP_SIGN_OUTPUTS"
"""Set to a non-empty value to enable MCP tool output signing.
Operators wanting per-environment control wire this via the runtime
env (typically the same scope as
:data:`evidentia_core.evidence_store.EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR`).
"""

EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR = "EVIDENTIA_MCP_SIGNER_FACTORY"
"""Dotted-path reference to a callable returning a
``Callable[[bytes], dict[str, str]]`` signer. Format:
``module.submodule:callable_name``. Required when
:data:`EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR` is set.

The factory signature::

    def make_signer() -> Callable[[bytes], dict[str, str]]:
        # Returns a signer that takes canonical JSON bytes +
        # returns a dict carrying the signature payload (e.g.,
        # {"sig": "...", "alg": "ed25519", "key_id": "...",
        #  "rekor_log_index": "12345"}). The dict is opaque to
        # this module — :func:`verify_tool_output` reconstructs
        # the verification path from the dict's fields.
        ...
"""

#: Signer callable type — takes canonical JSON bytes, returns the
#: signature metadata dict that lands in
#: :attr:`SignedToolOutput.signature`.
SignerCallable = Callable[[bytes], dict[str, str]]

#: Verifier callable type — takes (payload_bytes, signature_dict),
#: returns True iff the signature verifies.
VerifierCallable = Callable[[bytes, dict[str, str]], bool]


class SignedToolOutput(EvidentiaModel):
    """Envelope wrapping an MCP tool output + its cryptographic signature.

    The envelope is itself JSON-serializable; downstream MCP
    clients deserialize the ``payload`` field to recover the
    tool's raw output. The ``signature`` field is opaque to
    Evidentia — its contents depend on the operator's signer
    (Sigstore bundle, GPG detached signature, HMAC tag, etc.).

    NORMATIVE per :mod:`docs.api-stability`. Field additions are
    non-breaking; field removals / renames require a major-bump
    deprecation cycle.
    """

    schema_version: int = Field(
        default=1,
        description=(
            "Envelope schema version. Bumped only when the field "
            "structure changes in a way that requires reader-side "
            "adaptation. v0.9.7 initial = 1."
        ),
    )
    payload: dict[str, Any] = Field(
        description=(
            "The MCP tool's raw output, as a JSON-serializable "
            "dict. Identical to what the tool would emit without "
            "wrapping; the wrapper does NOT mutate it."
        ),
    )
    signed_at: datetime = Field(
        default_factory=utc_now,
        description=(
            "UTC timestamp the signature was computed. Auditors "
            "use this for chronological ordering in the audit log."
        ),
    )
    signature: dict[str, str] | None = Field(
        default=None,
        description=(
            "Signature metadata dict produced by the operator's "
            "signer callable. None when signing failed (see "
            "``signing_error`` for context)."
        ),
    )
    signing_error: str | None = Field(
        default=None,
        description=(
            "Populated when signing FAILED + the envelope was "
            "emitted anyway with ``signature=None``. Operators "
            "relying on signed-only output check ``signature is "
            "not None``."
        ),
    )
    tool_name: str | None = Field(
        default=None,
        description=(
            "Optional MCP tool name this envelope wraps. Useful "
            "for downstream filtering when the audit log carries "
            "multiple tool outputs."
        ),
    )


def _resolve_signer_factory() -> SignerCallable | None:
    """Resolve the signer factory from env vars.

    Returns ``None`` when :data:`EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR`
    is unset / empty → tools should emit raw payloads (no signing).
    Returns a :class:`SignerCallable` otherwise.

    Raises:
        RuntimeError: If the sign-outputs env var is set but the
            factory env var is unresolvable.
    """
    if not os.environ.get(EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR):
        return None
    factory_ref = os.environ.get(EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR)
    if not factory_ref:
        raise RuntimeError(
            f"{EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR} is set but "
            f"{EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR} is empty. "
            f"Format: 'module.submodule:callable_name'. The callable "
            f"must return a Callable[[bytes], dict[str, str]] signer."
        )
    if ":" not in factory_ref:
        raise RuntimeError(
            f"{EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR}={factory_ref!r} "
            f"must be of the form 'module.submodule:callable_name'"
        )
    import importlib

    module_path, _, attr = factory_ref.partition(":")
    try:
        module = importlib.import_module(module_path)
    except ImportError as exc:
        raise RuntimeError(
            f"Could not import {module_path!r} for MCP signer "
            f"factory: {exc}"
        ) from exc
    factory = getattr(module, attr, None)
    if factory is None or not callable(factory):
        raise RuntimeError(
            f"{factory_ref!r} did not resolve to a callable in "
            f"{module_path!r}"
        )
    signer = factory()
    if not callable(signer):
        raise RuntimeError(
            f"{factory_ref!r}() returned a non-callable; expected "
            f"Callable[[bytes], dict[str, str]]"
        )
    return signer  # type: ignore[no-any-return]


def sign_tool_output(
    payload: dict[str, Any],
    *,
    tool_name: str | None = None,
    signer: SignerCallable | None = None,
) -> SignedToolOutput:
    """Wrap a tool output in a :class:`SignedToolOutput` envelope.

    When ``signer`` is None, attempts to resolve a signer from env
    vars via :func:`_resolve_signer_factory`. When no signer is
    configured (env unset), returns an envelope with
    ``signature=None`` + no ``signing_error`` — a neutral wrap
    that downstream consumers can still parse uniformly.

    Args:
        payload: The MCP tool's raw output dict.
        tool_name: Optional tool name for the envelope.
        signer: Optional explicit signer (overrides env-resolved).

    Returns:
        A :class:`SignedToolOutput` envelope. The envelope is always
        well-formed; signing failures populate ``signing_error``
        instead of raising.
    """
    import json

    resolved_signer = signer if signer is not None else _resolve_signer_factory()
    envelope = SignedToolOutput(payload=payload, tool_name=tool_name)
    if resolved_signer is None:
        # No signing configured; emit the envelope with
        # signature=None + no error. Tests + downstream callers
        # rely on the always-well-formed shape.
        return envelope

    # Canonical JSON for stable signature. Sort keys + no
    # whitespace = byte-identical bytes for the same payload
    # across Python sessions / hosts.
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    try:
        sig_dict = resolved_signer(canonical)
    except Exception as exc:
        # Signing failure is non-fatal — emit the envelope with
        # signing_error populated. Operators relying on signed-
        # only outputs filter on signature is None.
        envelope_with_err = envelope.model_copy(
            update={"signing_error": str(exc)}
        )
        return envelope_with_err
    return envelope.model_copy(update={"signature": sig_dict})


def verify_tool_output(
    envelope: SignedToolOutput,
    *,
    verifier: VerifierCallable,
) -> bool:
    """Verify a :class:`SignedToolOutput` envelope's signature.

    The verifier is operator-supplied (mirror of the signer path).
    Returns True iff the signature verifies against the canonical
    JSON of the payload. Returns False when:

    - ``envelope.signature`` is None (unsigned envelope)
    - The verifier callable returns False

    Args:
        envelope: The :class:`SignedToolOutput` to verify.
        verifier: Operator-supplied verifier callable.

    Returns:
        True iff signature verification succeeds.
    """
    import json

    if envelope.signature is None:
        return False
    canonical = json.dumps(
        envelope.payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    try:
        return verifier(canonical, envelope.signature)
    except Exception:
        return False


__all__ = [
    "EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR",
    "EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR",
    "SignedToolOutput",
    "SignerCallable",
    "VerifierCallable",
    "sign_tool_output",
    "verify_tool_output",
]
