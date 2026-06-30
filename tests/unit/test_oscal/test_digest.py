"""Tests for :mod:`evidentia_core.oscal.digest` (v0.7.0).

The digest module is the deterministic-hashing foundation for the
evidence chain-of-custody feature. If the same input produces different
hashes across runs or platforms, verification breaks and the feature is
worthless — these tests nail that property down.
"""

from __future__ import annotations

import hashlib

import pytest
from evidentia_core.models.common import Severity
from evidentia_core.models.finding import SecurityFinding
from evidentia_core.oscal.digest import (
    DIGEST_ALGO,
    digest_bytes,
    digest_file,
    digest_json,
    digest_model,
    format_digest,
    parse_digest,
    verify_bytes,
    verify_file,
)


def _make_finding(
    source: str = "aws-config",
    control_ids: list[str] | None = None,
) -> SecurityFinding:
    return SecurityFinding(
        id="11111111-1111-1111-1111-111111111111",
        title="MFA not enforced on root",
        description="Root account missing MFA.",
        severity=Severity.HIGH,
        source_system=source,
        control_ids=control_ids or ["IA-2"],
    )


# ── digest_bytes ─────────────────────────────────────────────────────────


def test_digest_bytes_matches_stdlib_sha256() -> None:
    """digest_bytes is a thin wrapper; must agree with hashlib exactly."""
    data = b"hello world"
    assert digest_bytes(data) == hashlib.sha256(data).hexdigest()


def test_digest_bytes_different_for_different_inputs() -> None:
    assert digest_bytes(b"a") != digest_bytes(b"b")


def test_digest_bytes_stable_across_calls() -> None:
    data = b"stable"
    assert digest_bytes(data) == digest_bytes(data)


# ── digest_file ──────────────────────────────────────────────────────────


def test_digest_file_matches_digest_bytes(tmp_path):
    content = b"evidence content"
    evidence_file = tmp_path / "evidence.json"
    evidence_file.write_bytes(content)
    assert digest_file(evidence_file) == digest_bytes(content)


def test_digest_file_handles_large_content_without_loading_all(tmp_path):
    """Chunk-streamed reads mean large files don't exhaust memory.

    The assertion is weak (hash correctness) but the loop structure in
    digest_file guarantees chunked IO — this test at least exercises it
    with a payload > chunk_size.
    """
    content = b"X" * 50_000
    large_file = tmp_path / "big.bin"
    large_file.write_bytes(content)
    assert digest_file(large_file) == digest_bytes(content)


def test_digest_file_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        digest_file(tmp_path / "does-not-exist.json")


# ── digest_model + digest_json ────────────────────────────────────────────


def test_digest_model_is_deterministic() -> None:
    """The whole feature hinges on this: same input → same hash.

    Uses ``model_copy()`` to clone instead of ``_make_finding()`` twice
    because ``SecurityFinding.first_observed`` and ``last_observed``
    carry ``default_factory=utc_now`` — two separate instantiations
    capture different microsecond timestamps on any kernel with a
    high-resolution clock (i.e. every Linux / macOS CI runner). The
    test is verifying determinism of ``digest_model`` for identical
    inputs, not that two ``_make_finding()`` calls happen to produce
    bit-identical objects.
    """
    finding_a = _make_finding()
    finding_b = finding_a.model_copy(deep=True)
    assert digest_model(finding_a) == digest_model(finding_b)
    # Call twice on the same object too — hashing must not mutate input.
    assert digest_model(finding_a) == digest_model(finding_a)


def test_digest_model_changes_when_any_field_changes() -> None:
    base = _make_finding()
    modified = base.model_copy(update={"title": "Different title"})
    assert digest_model(base) != digest_model(modified)


def test_digest_model_agrees_with_digest_json() -> None:
    """A model and its ``.model_dump(mode='json')`` produce the same digest."""
    finding = _make_finding()
    assert digest_model(finding) == digest_json(finding.model_dump(mode="json"))


def test_digest_json_invariant_to_key_order() -> None:
    """sort_keys means {'a': 1, 'b': 2} and {'b': 2, 'a': 1} hash the same."""
    a = {"a": 1, "b": 2, "c": 3}
    b = {"c": 3, "a": 1, "b": 2}
    assert digest_json(a) == digest_json(b)


# ── format_digest + parse_digest ─────────────────────────────────────────


def test_format_digest_wraps_with_algorithm_prefix() -> None:
    hex_digest = "a" * 64
    assert format_digest(hex_digest) == f"{DIGEST_ALGO}:{hex_digest}"


def test_parse_digest_splits_prefixed_value() -> None:
    algo, hex_digest = parse_digest("sha256:abcd1234")
    assert algo == "sha256"
    assert hex_digest == "abcd1234"


def test_parse_digest_accepts_bare_hex_as_sha256() -> None:
    """Backward-compat with any pre-v0.7.0 tooling that stored bare hex."""
    algo, hex_digest = parse_digest("abcd1234")
    assert algo == "sha256"
    assert hex_digest == "abcd1234"


def test_parse_digest_rejects_unsupported_algorithm() -> None:
    with pytest.raises(ValueError, match="Unsupported digest algorithm"):
        parse_digest("md5:deadbeef")


def test_format_parse_round_trip() -> None:
    hex_digest = digest_bytes(b"round-trip")
    algo, parsed_hex = parse_digest(format_digest(hex_digest))
    assert algo == DIGEST_ALGO
    assert parsed_hex == hex_digest


# ── verify_bytes + verify_file ───────────────────────────────────────────


def test_verify_bytes_true_for_matching_digest() -> None:
    data = b"verify me"
    prop_value = format_digest(digest_bytes(data))
    assert verify_bytes(data, prop_value) is True


def test_verify_bytes_false_when_content_modified() -> None:
    original = b"original"
    tampered = b"tampered"
    prop_value = format_digest(digest_bytes(original))
    assert verify_bytes(tampered, prop_value) is False


def test_verify_file_round_trip(tmp_path):
    path = tmp_path / "artifact.json"
    path.write_bytes(b'{"key": "value"}')
    prop_value = format_digest(digest_file(path))
    assert verify_file(path, prop_value) is True


def test_verify_file_detects_tamper(tmp_path):
    path = tmp_path / "artifact.json"
    path.write_bytes(b"original")
    original_digest = format_digest(digest_file(path))
    path.write_bytes(b"tampered")
    assert verify_file(path, original_digest) is False


# ── canonical_json_bytes (v0.11 signing path canonicalizer) ──────────────


from evidentia_core.oscal.digest import canonical_json_bytes  # noqa: E402


def test_canonical_json_bytes_is_sorted_compact_bytes():
    assert canonical_json_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonical_json_bytes_ensure_ascii_is_pinned_true():
    # Non-ASCII must be \u-escaped so LEN(payload) in the DSSE PAE is deterministic.
    assert canonical_json_bytes({"k": "café"}) == b'{"k":"caf\\u00e9"}'


def test_digest_json_unchanged_and_routed_through_helper():
    sample = {"z": 1, "a": [3, 2, 1], "m": "x"}
    assert digest_json(sample) == digest_bytes(canonical_json_bytes(sample))
