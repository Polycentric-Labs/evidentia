"""DSSE (Dead Simple Signing Envelope) primitives — pure, no crypto (v0.11).

Hand-rolled per the DSSE spec (secure-systems-lab/dsse) so the air-gap
signing path needs no DSSE/in-toto library dependency. This module does
PAE encoding + envelope (de)serialization ONLY; key handling and signing
live in :mod:`evidentia_core.oscal.keysign`.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass


class DSSEError(Exception):
    """Malformed DSSE envelope or base64 field."""


def pae(payload_type: str, payload: bytes) -> bytes:
    """Pre-Authentication Encoding per the DSSE spec.

    ``DSSEv1 SP LEN(type) SP type SP LEN(payload) SP payload`` where every
    LEN is the ASCII-decimal **UTF-8 byte length** (no leading zeros), SP is
    one 0x20 byte, and ``payload`` is the raw (un-base64) bytes. The signature
    is computed over this byte string.
    """
    type_bytes = payload_type.encode("utf-8")
    return b" ".join(
        [
            b"DSSEv1",
            str(len(type_bytes)).encode("ascii"),
            type_bytes,
            str(len(payload)).encode("ascii"),
            payload,
        ]
    )


def b64encode_std(data: bytes) -> str:
    """Standard base64 (RFC 4648 §4), padded — Evidentia's emit format."""
    return base64.b64encode(data).decode("ascii")


def decode_b64(s: str) -> bytes:
    """Decode standard OR url-safe base64, strictly and canonically.

    DSSE requires verifiers to accept either alphabet. We normalize url-safe
    (``-_`` -> ``+/``), restore ``=`` padding, strict-decode (reject embedded
    whitespace / non-alphabet chars), then reject non-canonical encodings via
    a decode->re-encode byte-equality check (closes base64 malleability).
    """
    if not isinstance(s, str):
        raise DSSEError("base64 field must be a string")
    normalized = s.replace("-", "+").replace("_", "/")
    normalized += "=" * ((-len(normalized)) % 4)
    try:
        decoded = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as e:
        raise DSSEError(f"invalid base64: {e}") from e
    if base64.b64encode(decoded).decode("ascii") != normalized:
        raise DSSEError("non-canonical base64 encoding rejected")
    return decoded


@dataclass(frozen=True)
class Signature:
    keyid: str
    sig: str  # base64


@dataclass(frozen=True)
class Envelope:
    payload_type: str
    payload_b64: str
    signatures: tuple[Signature, ...]


def serialize_envelope(env: Envelope) -> str:
    """Serialize to the canonical DSSE JSON object (pretty, trailing newline)."""
    obj = {
        "payloadType": env.payload_type,
        "payload": env.payload_b64,
        "signatures": [{"keyid": s.keyid, "sig": s.sig} for s in env.signatures],
    }
    return json.dumps(obj, indent=2) + "\n"


def parse_envelope(text: str) -> Envelope:
    """Parse + strict-validate a DSSE envelope. Raises :class:`DSSEError`."""
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError, RecursionError) as e:
        raise DSSEError(f"envelope is not valid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise DSSEError("envelope must be a JSON object")
    ptype = obj.get("payloadType")
    payload = obj.get("payload")
    sigs = obj.get("signatures")
    if not isinstance(ptype, str) or not ptype:
        raise DSSEError("payloadType must be a non-empty string")
    if not isinstance(payload, str) or not payload:
        raise DSSEError("payload must be a non-empty base64 string")
    if not isinstance(sigs, list) or not sigs:
        raise DSSEError("signatures must be a non-empty array")
    parsed_sigs: list[Signature] = []
    for entry in sigs:
        if not isinstance(entry, dict):
            raise DSSEError("each signature must be an object")
        keyid = entry.get("keyid", "")
        sig = entry.get("sig")
        if not isinstance(keyid, str):
            raise DSSEError("signature keyid must be a string")
        if not isinstance(sig, str) or not sig:
            raise DSSEError("signature sig must be a non-empty base64 string")
        parsed_sigs.append(Signature(keyid=keyid, sig=sig))
    return Envelope(
        payload_type=ptype, payload_b64=payload, signatures=tuple(parsed_sigs)
    )
