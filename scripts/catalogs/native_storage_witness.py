"""Native storage witnesses with operator-selected, pinned external inputs."""

import hashlib
import json
import os
from collections import Counter
from pathlib import Path

import evidentia_core.catalogs.open_corpora as corpora
import evidentia_core.catalogs.user_dir as storage


def test_full_pinned_bsi_import_repeat_and_cold_registered_read(tmp_path):
    bindings = json.loads(Path(__file__).with_name("native_ci_inputs.json").read_bytes())
    source_dir = Path(os.environ["EVIDENTIA_NATIVE_CI_INPUTS"])
    sources = {}
    for row in bindings["files"]:
        raw = (source_dir / row["name"]).read_bytes()
        assert len(raw) == row["bytes"]
        assert hashlib.sha256(raw).hexdigest() == row["sha256"]
        sources[row["name"]] = raw
    expected = bindings["expected"]
    assert sum(map(len, sources.values())) == 5_424_451
    corpora._CACHE.clear()
    imported = storage.CatalogManifestTransaction(tmp_path)
    result = imported.commit(storage.CatalogMutationIntent.native(sources))
    assert result.status == "imported" and result.control_count == 1000
    assert result.bundle_sha256 == expected["bundle_sha256"]
    assert result.projection_sha256 == expected["projection_sha256"]
    assert imported.observation.publication_state == "committed"
    assert imported.observation.cleanup_state == "complete"
    directory = tmp_path / "native" / "bsi-grundschutz-plus-plus" / expected["bundle_sha256"]
    names = {"Grundschutz++-resolved_catalog.json", "LICENSE.txt", "README.md", "source-index.json", "catalog.json"}
    assert {item.name for item in directory.iterdir()} == names
    initial = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in names}
    for row in bindings["persisted"]:
        persisted = (directory / row["leaf"]).read_bytes()
        assert persisted.endswith(b"}\n") and not persisted.endswith(b"\n\n")
        assert len(persisted) == row["persisted_bytes"]
        assert hashlib.sha256(persisted).hexdigest() == row["persisted_sha256"]
        assert len(persisted[:-1]) == row["content_bytes"]
        assert hashlib.sha256(persisted[:-1]).hexdigest() == row["content_sha256"]
    assert (directory / "catalog.json").stat().st_size == expected["whole_wire_bytes"] + 1
    assert hashlib.sha256((directory / "catalog.json").read_bytes()[:-1]).hexdigest() == expected["wire_sha256"]
    for original, stored in (
        ("Grundschutz++-resolved_catalog.json", "Grundschutz++-resolved_catalog.json"),
        ("LICENSE", "LICENSE.txt"),
        ("README.md", "README.md"),
    ):
        assert (directory / stored).read_bytes() == sources[original]
    manifest = (tmp_path / "frameworks.yaml").read_bytes()
    corpora._CACHE.clear()
    repeated = storage.CatalogManifestTransaction(tmp_path)
    again = repeated.commit(storage.CatalogMutationIntent.native(sources))
    assert again.status == "already_present"
    assert repeated.observation.publication_state == "unchanged"
    assert repeated.observation.cleanup_state == "complete"
    assert (tmp_path / "frameworks.yaml").read_bytes() == manifest
    assert {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in names} == initial
    corpora._CACHE.clear()
    loaded = storage.load_registered_native_catalog(
        "bsi-grundschutz-plus-plus", bundle_sha256=expected["bundle_sha256"], user_dir_override=tmp_path
    )
    assert loaded.control_count == 1000
    bundle = loaded.native_source
    assert bundle.bundle_sha256 == expected["bundle_sha256"]
    assert Counter(item.kind for item in bundle.data.occurrences) == expected["independent_expected_counts"]
    for document, row in zip(bundle.data.documents, bindings["files"], strict=True):
        assert document.raw_utf8.encode("utf8") == sources[row["name"]]
    assert (tmp_path / "frameworks.yaml").read_bytes() == manifest
    assert {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in names} == initial
