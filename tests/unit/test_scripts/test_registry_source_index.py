"""Keep all committed fixture and snapshot bindings executable in CI."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts.registries.check_source_index import (
    SourceIndexError,
    checked_path,
    verify_fixture_index,
    verify_public_sources,
)


def example(root: Path) -> dict[str, object]:
    path = root / "tests/fixtures/registries/tls/synthetic.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"{}\n")
    return {
        "schema_version": "1",
        "status": "complete_reviewed_fixture_inventory",
        "fixtures": [
            {
                "path": "tests/fixtures/registries/tls/synthetic.json",
                "status": "created",
                "bytes": 3,
                "raw_sha256": hashlib.sha256(b"{}\n").hexdigest(),
                "kind": "synthetic_source_fixture",
                "scenario": "source-index-boundary",
                "contract_url": "https://docs.python.org/3.12/library/ssl.html",
                "contract_version": "Python 3.12",
                "provenance": "Authored synthetic data",
                "exclusions": ["No live assessment"],
            }
        ],
    }


def test_all_real_sources_and_converters_agree_without_writes() -> None:
    assert verify_public_sources() == {"fixtures": 51, "regenerated_snapshots": 3, "field_shapes": 26}


def test_changed_or_unlisted_fixture_is_refused(tmp_path: Path) -> None:
    index = example(tmp_path)
    assert verify_fixture_index(tmp_path, index) == 1
    leaf = tmp_path / "tests/fixtures/registries/tls/synthetic.json"
    leaf.write_bytes(b"[]\n")
    with pytest.raises(SourceIndexError):
        verify_fixture_index(tmp_path, index)
    leaf.write_bytes(b"{}\n")
    leaf.with_name("unlisted.json").write_bytes(b"{}\n")
    with pytest.raises(SourceIndexError):
        verify_fixture_index(tmp_path, index)


@pytest.mark.parametrize(
    "path",
    [
        "tests/fixtures/registries/../private.json",
        "tests/fixtures/registries//x.json",
        "C:/outside.json",
        "tests/fixtures/registries/name:stream",
        "tests\\fixtures\\registries\\x.json",
    ],
)
def test_index_paths_cannot_escape_or_name_alternate_streams(tmp_path: Path, path: str) -> None:
    with pytest.raises(SourceIndexError):
        checked_path(tmp_path, path, "tests/fixtures/registries/")
