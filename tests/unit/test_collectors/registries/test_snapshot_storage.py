"""Verify bounded package decompression and distinct stored-source provenance."""

from __future__ import annotations

import gzip
import hashlib
import io
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any, cast

import pytest
from evidentia_collectors.registries import _snapshots as snapshots
from evidentia_collectors.registries._client import RegistryReadSession
from evidentia_collectors.registries._contracts import CertificateTarget


def test_bounded_single_member_accepts_exact_limit_and_rejects_one_more() -> None:
    assert snapshots._decode_gzip(gzip.compress(b"x" * 128, mtime=0), max_bytes=128) == b"x" * 128
    with pytest.raises(snapshots.SnapshotFault):
        snapshots._decode_gzip(gzip.compress(b"x" * 129, mtime=0), max_bytes=128)


@pytest.mark.parametrize("damage", ["header", "truncated", "crc", "trailing", "concatenated", "raw-limit"])
def test_gzip_member_refuses_incomplete_extra_and_corrupt_data(damage: str) -> None:
    raw = gzip.compress(b"synthetic", mtime=0)
    if damage == "header":
        raw = b"not a gzip member"
    elif damage == "truncated":
        raw = raw[:-1]
    elif damage == "crc":
        raw = raw[:-8] + bytes([raw[-8] ^ 1]) + raw[-7:]
    elif damage == "trailing":
        raw += b"extra"
    elif damage == "concatenated":
        raw += gzip.compress(b"second", mtime=0)
    else:
        raw = b"x" * 129
    with pytest.raises(snapshots.SnapshotFault):
        snapshots._decode_gzip(raw, max_bytes=128)


def test_gzip_native_type_gate_invokes_no_foreign_conversion() -> None:
    calls: list[str] = []

    class Foreign:
        def __bytes__(self) -> bytes:
            calls.append("bytes")
            return b""

        def __len__(self) -> int:
            calls.append("length")
            return 0

    with pytest.raises(snapshots.SnapshotFault):
        snapshots._decode_gzip(cast(bytes, Foreign()), max_bytes=128)
    for limit in (True, 0, -1, 16_777_217):
        with pytest.raises(snapshots.SnapshotFault):
            snapshots._decode_gzip(b"", max_bytes=limit)
    assert not calls


class MemoryResource:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.paths: list[str] = []

    def joinpath(self, path: str) -> MemoryResource:
        self.paths.append(path)
        return self

    def open(self, mode: str) -> io.BytesIO:
        assert mode == "rb"
        return io.BytesIO(self.body)


@pytest.mark.parametrize("damage", ["length", "hash", "limit"])
def test_stored_size_and_hash_precede_decoder(monkeypatch: pytest.MonkeyPatch, damage: str) -> None:
    entry = snapshots._index_entry("cmvp")
    storage = entry["storage"]
    if damage == "length":
        raw = b"{}"
    elif damage == "hash":
        raw = b"x" * storage["bytes"]
    else:
        raw = b"x" * (4_194_304 + 1)
    memory = MemoryResource(raw)
    monkeypatch.setattr(snapshots, "_index_entry", lambda registry: entry)
    monkeypatch.setattr(resources, "files", lambda package: memory)
    monkeypatch.setattr(snapshots, "_decode_gzip", lambda *args, **kwargs: pytest.fail("decode before stored hash"))
    with pytest.raises(snapshots.SnapshotFault):
        snapshots.load_snapshot("cmvp")
    assert memory.paths == ["data/cmvp/snapshot.json.gz"]


def test_decoded_hash_and_size_precede_json_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = snapshots._index_entry("cmvp")
    raw = gzip.compress(b"{}", mtime=0)
    entry["storage"]["bytes"] = len(raw)
    entry["storage"]["sha256"] = hashlib.sha256(raw).hexdigest()
    monkeypatch.setattr(snapshots, "_index_entry", lambda registry: entry)
    monkeypatch.setattr(resources, "files", lambda package: MemoryResource(raw))
    monkeypatch.setattr(snapshots, "parse_result_json", lambda value: pytest.fail("parse before decoded hash"))
    with pytest.raises(snapshots.SnapshotFault):
        snapshots.load_snapshot("cmvp")


@pytest.mark.parametrize("path", ["../snapshot.json.gz", "data/fcc/snapshot.json", "https://example.org/file.gz"])
def test_storage_resource_path_is_closed_before_open(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    entry = snapshots._index_entry("cmvp")
    entry["storage"]["path"] = path
    monkeypatch.setattr(snapshots, "_index_entry", lambda registry: entry)
    monkeypatch.setattr(resources, "files", lambda package: pytest.fail("unapproved resource path"))
    with pytest.raises(snapshots.SnapshotFault):
        snapshots.load_snapshot("cmvp")


def test_packaged_cmvp_sources_retain_original_decoded_hashes_and_provenance() -> None:
    entry = snapshots._index_entry("cmvp")
    storage = entry["storage"]
    raw = resources.files("evidentia_collectors.registries").joinpath(storage["path"]).read_bytes()
    decoded = snapshots._decode_gzip(raw, max_bytes=4_194_304)
    assert len(raw) == storage["bytes"] and hashlib.sha256(raw).hexdigest() == storage["sha256"]
    assert len(decoded) == 2_375_089
    assert hashlib.sha256(decoded).hexdigest() == "ad6ecd36279333bc6d2474b7dec8b29482d244610fceac702c83559248fe7a8d"
    root = Path(__file__).resolve().parents[4]
    tuple_storage = entry["tuple_storage"]
    tuple_raw = (root / tuple_storage["path"]).read_bytes()
    tuples = snapshots._decode_gzip(tuple_raw, max_bytes=16_777_216)
    assert len(tuple_raw) == tuple_storage["bytes"]
    assert hashlib.sha256(tuple_raw).hexdigest() == tuple_storage["sha256"]
    assert len(tuples) == 2_112_592
    assert hashlib.sha256(tuples).hexdigest() == "ad9551fb60751454d0206dc4776dba474e56f1735569829cb9001f61f633d91a"
    assert len(raw) < 2_097_152 and len(tuple_raw) < 2_097_152
    assert snapshots.canonical_gzip(decoded) == raw
    assert snapshots.canonical_gzip(tuples) == tuple_raw
    target = CertificateTarget(certificate_number="5517")
    session = RegistryReadSession(
        {"registry": "cmvp", "target": target},
        _utc=lambda: datetime(2026, 9, 11, tzinfo=UTC),
        _monotonic=lambda: 0.0,
        _http_factory=lambda: pytest.fail("local snapshot attempted HTTP"),
    )
    result = session.read_snapshot(target, lambda value: value)
    read = result.source_reads[0]
    assert read.raw_bytes == len(raw) and read.decoded_bytes == len(decoded)
    assert read.snapshot_source == storage["path"] and read.source_digest == storage["sha256"]
    assert read.network_attempts == 0 and read.source_records == 5510 and read.body_complete
    observed: dict[str, Any] = result.observations[0].source_identity
    assert observed["snapshot_sha256"] == entry["sha256"]
    assert observed["snapshot_storage"] == storage


@pytest.mark.parametrize("key", ["bytes", "decoded_bytes"])
@pytest.mark.parametrize("kind", ["float", "bool"])
def test_storage_lengths_require_native_integers_before_open(
    monkeypatch: pytest.MonkeyPatch, key: str, kind: str
) -> None:
    entry = snapshots._index_entry("cmvp")
    entry["storage"][key] = float(entry["storage"][key]) if kind == "float" else True
    monkeypatch.setattr(snapshots, "_index_entry", lambda registry: entry)
    monkeypatch.setattr(resources, "files", lambda package: pytest.fail("invalid length opened resource"))
    with pytest.raises(snapshots.SnapshotFault):
        snapshots.load_snapshot("cmvp")


def test_encoder_native_input_and_exact_input_ceiling() -> None:
    calls: list[str] = []

    class Foreign:
        def __bytes__(self) -> bytes:
            calls.append("bytes")
            return b""

        def __len__(self) -> int:
            calls.append("length")
            return 0

    for value in (Foreign(), bytearray(b"x"), "x"):
        with pytest.raises(ValueError, match="gzip_input_invalid"):
            snapshots.canonical_gzip(cast(bytes, value))
    assert not calls
    maximum = b"x" * 16_777_216
    encoded = snapshots.canonical_gzip(maximum)
    assert snapshots._decode_gzip(encoded, max_bytes=16_777_216) == maximum
    with pytest.raises(ValueError, match="gzip_input_invalid"):
        snapshots.canonical_gzip(maximum + b"x")
