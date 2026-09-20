"""Closed physical source membership and unchanged gate boundaries."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from evidentia_core.catalogs import open_corpora as corpora
from evidentia_core.catalogs.loader import _load_catalog_data
from evidentia_core.models.open_corpora import SourceChunk

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "packages/evidentia-core/src/evidentia_core/catalogs/data"
SOURCE_ROOT = DATA / "sources/au-ism/2026.09.4"


def test_complete_selected_source_files_keep_the_unchanged_physical_gate_contract():
    directories = [SOURCE_ROOT, DATA / "sources/cisa-scuba-m365/7ef9501d7de9804ddb9d6013af6b665cccfb39d9"]
    expected_counts = [5, 12]
    chosen = []
    for directory, count in zip(directories, expected_counts, strict=True):
        files = list(directory.iterdir())
        assert len(files) == count
        assert all(path.is_file() and not path.is_symlink() for path in files)
        chosen.extend(files)
    assert len(chosen) == 17
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf8").splitlines()
    for path in chosen:
        raw = path.read_bytes()
        assert 0 < len(raw) <= 2097152
        assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
        assert b"\r\n" not in raw
        assert path.relative_to(ROOT).as_posix() + " text eol=lf" in attributes
        if path.suffix == ".json":
            json.loads(raw)
    assert not any("bsi" in path.name.lower() for path in (DATA / "sources").iterdir())


def test_converter_manifest_has_exact_non_generated_inputs():
    manifest = json.loads((ROOT / "scripts/catalogs/open_corpora_sources.json").read_bytes())
    expected = [
        "packages/evidentia-core/src/evidentia_core/models/open_corpora.py",
        "packages/evidentia-core/src/evidentia_core/models/catalog.py",
        "packages/evidentia-core/src/evidentia_core/catalogs/loader.py",
        "packages/evidentia-core/src/evidentia_core/catalogs/open_corpora.py",
    ]
    assert manifest["converter_files"] == expected
    assert [row["path"] for row in corpora.converter_manifest()] == expected
    for row in corpora.converter_manifest():
        assert hashlib.sha256((ROOT / row["path"]).read_bytes()).hexdigest() == row["sha256"]
    assert len(manifest["profiles"]) == 3
    assert [p["distribution"] for p in manifest["profiles"]] == ["bundled", "bundled", "external_only"]
    assert sum(len(p["files"]) for p in manifest["profiles"]) == 16


@pytest.mark.parametrize("change", ["changed-byte", "reordered", "missing", "extra"])
def test_package_drift_refuses_before_whole_source_parse(tmp_path, monkeypatch, change):
    destination = tmp_path / "data"
    for relative in ["international/au-ism.json", "notices/ism.txt"]:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(DATA / relative, target)
    target_source = destination / "sources/au-ism/2026.09.4"
    shutil.copytree(SOURCE_ROOT, target_source)
    first = target_source / "ISM_catalog.part-000.json"
    second = target_source / "ISM_catalog.part-001.json"
    if change == "changed-byte":
        raw = first.read_bytes()
        first.write_bytes(b" " + raw[1:])
    elif change == "reordered":
        first.write_bytes(second.read_bytes())
    elif change == "missing":
        first.unlink()
    else:
        (target_source / "unlisted.txt").write_bytes(b"inert")
    original = corpora._load_catalog_data
    modes = []

    def observed(*args, **kwargs):
        modes.append(kwargs.get("mode"))
        return original(*args, **kwargs)

    monkeypatch.setattr(corpora, "_load_catalog_data", observed)
    with pytest.raises((ValueError, OSError)):
        corpora.load_packaged_catalog(destination / "international/au-ism.json")
    assert "source_json" not in modes


@pytest.mark.parametrize(
    "field,value", [("index", True), ("byte_start", False), ("byte_length", 1.0), ("sha256", "0" * 64)]
)
def test_chunk_model_refuses_coerced_or_false_identity(field, value):
    chunk = {
        "schema_version": "catalog-source-chunk-v1",
        "source_key": "ism-catalog",
        "index": 0,
        "byte_start": 0,
        "byte_length": 1,
        "sha256": hashlib.sha256(b"x").hexdigest(),
        "raw_utf8": "x",
    }
    SourceChunk.model_validate(chunk)
    chunk[field] = value
    with pytest.raises(ValueError):
        SourceChunk.model_validate(chunk)


def test_exact_decoded_chunk_and_actual_parser_file_boundaries():
    raw = "x" * 1572864
    chunk = {
        "schema_version": "catalog-source-chunk-v1",
        "source_key": "ism-catalog",
        "index": 0,
        "byte_start": 0,
        "byte_length": len(raw),
        "sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "raw_utf8": raw,
    }
    assert SourceChunk.model_validate(chunk).byte_length == 1572864
    chunk["raw_utf8"] += "x"
    chunk["byte_length"] += 1
    chunk["sha256"] = hashlib.sha256(chunk["raw_utf8"].encode()).hexdigest()
    with pytest.raises(ValueError):
        SourceChunk.model_validate(chunk)
    # This is the parser/file boundary, separately from the closed envelope model.
    exact = b"{}" + b" " * (2097152 - 2)
    assert _load_catalog_data(None, raw_bytes=exact, mode="packaging_json").data == {}
    with pytest.raises(ValueError):
        _load_catalog_data(None, raw_bytes=exact + b" ", mode="packaging_json")
