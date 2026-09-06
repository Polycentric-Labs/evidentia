"""SHA-256 digest helpers for OSCAL evidence chain of custody (v0.7.0).

Pure, deterministic hashing for evidence items and OSCAL documents. No IO
beyond a caller-provided bytes payload or file path — no network, no GPG,
no mutation of input objects.

The digest format used in OSCAL `props[]` is the NIST OSCAL convention
`"sha256:<hex>"` so downstream consumers can distinguish algorithms
(future releases may offer sha384 / sha512 per FIPS 180-4).

Determinism guarantee
---------------------

``digest_model`` serializes the Pydantic model to JSON with sorted keys
and no whitespace. Two callers with the same input produce the same
digest bit-for-bit, regardless of Python dict insertion order. This is
critical for verification: a reader reconstructs the hash by re-serializing
and comparing to the stored prop value.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

DIGEST_ALGO = "sha256"
"""The digest algorithm identifier used in OSCAL prop values. Format
in props: ``"sha256:<64-hex-chars>"``. v0.7.0 ships sha256 only;
add sha384 / sha512 behind an algo parameter in a later release if
FedRAMP High or DoD IL5 customers require them."""


def canonical_json_bytes(data: Any) -> bytes:
    """Serialize ``data`` to Evidentia-canonical JSON *bytes*.

    The single shared canonicalizer. ``sort_keys`` + compact separators give
    bit-for-bit reproducibility; ``default=str`` is a defensive fallback for
    non-JSON-native values; ``ensure_ascii=True`` is pinned so the DSSE PAE's
    byte-length field is deterministic. ``digest_json`` and the DSSE signing
    path both go through this — never re-implement ``json.dumps`` elsewhere.

    NOTE: this is Evidentia-canonical, NOT RFC-8785 JCS. Internal soundness
    does not depend on any other tool reproducing it (the DSSE signature is
    verified over the stored payload bytes).
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=True).encode("utf-8")


def digest_bytes(data: bytes) -> str:
    """Compute the SHA-256 digest of a raw bytes payload.

    Returns the bare hex digest (no algorithm prefix). Use
    :func:`format_digest` to get the OSCAL prop value.
    """
    return hashlib.sha256(data).hexdigest()


def digest_file(path: str | Path, *, chunk_size: int = 8192) -> str:
    """Compute the SHA-256 digest of a file on disk, streamed.

    Streams the file in ``chunk_size`` byte blocks so large evidence
    artifacts (log archives, pcaps, database dumps) don't have to fit
    in memory. Raises :class:`FileNotFoundError` if the path is missing —
    callers should catch and fall back to an "unverifiable" prop rather
    than silently omitting the evidence item.
    """
    p = Path(path)
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def digest_model(model: BaseModel) -> str:
    """Compute the SHA-256 digest of a Pydantic model's canonical JSON.

    "Canonical JSON" = serialized with ``sort_keys=True`` and no
    whitespace between separators. Guarantees bit-for-bit reproducibility
    across runs, platforms, and Pydantic dict-ordering quirks.

    The model is dumped in ``mode="json"`` so datetimes, enums, and UUIDs
    serialize to their canonical string forms rather than Python objects.
    """
    payload = model.model_dump(mode="json")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return digest_bytes(canonical.encode("utf-8"))


def digest_json(data: Any) -> str:
    """Compute the SHA-256 digest of any JSON-serializable Python object.

    Uses the shared :func:`canonical_json_bytes` so the bytes that get hashed
    are identical to the DSSE-signing path's payload canonicalization.
    """
    return digest_bytes(canonical_json_bytes(data))


def format_digest(hex_digest: str) -> str:
    """Return the OSCAL prop-value form of a digest: ``"sha256:<hex>"``."""
    return f"{DIGEST_ALGO}:{hex_digest}"


def parse_digest(prop_value: str) -> tuple[str, str]:
    """Split an OSCAL digest prop value into (algorithm, hex_digest).

    Accepts both forms:

    - ``"sha256:<hex>"`` — new v0.7.0 format with explicit algorithm
    - ``"<hex>"`` — bare hex digest, assumed sha256 for backward-compat
      with any pre-v0.7.0 tooling that might have written the bare form

    Raises :class:`ValueError` on an unsupported algorithm so verification
    tools can surface a clear error instead of silently accepting an
    unknown hash.
    """
    if ":" in prop_value:
        algo, hex_digest = prop_value.split(":", 1)
        algo = algo.lower()
        if algo != DIGEST_ALGO:
            raise ValueError(f"Unsupported digest algorithm {algo!r}; v0.7.0 supports {DIGEST_ALGO!r} only.")
        return algo, hex_digest
    return DIGEST_ALGO, prop_value


def verify_bytes(data: bytes, expected_prop_value: str) -> bool:
    """Return True iff ``data`` hashes to the digest encoded in the prop."""
    _, expected_hex = parse_digest(expected_prop_value)
    return digest_bytes(data) == expected_hex


def verify_file(path: str | Path, expected_prop_value: str) -> bool:
    """Return True iff the file at ``path`` hashes to the expected digest."""
    _, expected_hex = parse_digest(expected_prop_value)
    return digest_file(path) == expected_hex
