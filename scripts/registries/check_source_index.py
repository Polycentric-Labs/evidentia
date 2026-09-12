"""Verify public fixture bytes and regenerate every reviewed snapshot without writes.

Run with python -m scripts.registries.check_source_index from the repository root.
This check uses the committed selected tuples. It does not fetch source documents
or assess whether a publisher has changed a source since the recorded capture.
"""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path, PurePosixPath
from typing import Any, cast

from evidentia_collectors.registries._parsing import canonical_json, checked_json, parse_result_json
from evidentia_collectors.registries._snapshots import SnapshotRegistry, load_bootstrap, load_snapshot
from evidentia_collectors.registries._source_fields import _TABLE_SHA256

from scripts.registries import refresh_cmvp, refresh_fcc, refresh_fedramp

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = Path("packages/evidentia-collectors/src/evidentia_collectors/registries")
FIXTURES = "tests/fixtures/registries/"


class SourceIndexError(ValueError):
    def __init__(self) -> None:
        super().__init__("invalid_registry_source_index")


def object_row(value: object) -> dict[str, Any]:
    if type(value) is not dict:
        raise SourceIndexError()
    return cast(dict[str, Any], value)


def checked_path(root: Path, name: object, prefix: str) -> Path:
    """Resolve only regular, non-reparse files within the selected public subtree."""
    if type(name) is not str or not name.startswith(prefix) or "\\" in name or ":" in name:
        raise SourceIndexError()
    parts = PurePosixPath(name).parts
    if any(part in {".", ".."} for part in parts) or "/".join(parts) != name:
        raise SourceIndexError()
    base = root.resolve()
    path = base.joinpath(*parts)
    current = base
    for part in parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise SourceIndexError()
    if not path.is_file() or not path.resolve().is_relative_to(base):
        raise SourceIndexError()
    return path


def bound_bytes(path: Path, binding: dict[str, Any], *, maximum: int = 16_777_216) -> bytes:
    size, digest = binding.get("bytes"), binding.get("raw_sha256", binding.get("sha256"))
    if type(size) is not int or not 0 < size <= maximum or type(digest) is not str or len(digest) != 64:
        raise SourceIndexError()
    with path.open("rb") as stream:
        content = stream.read(maximum + 1)
    if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
        raise SourceIndexError()
    return content


def verify_fixture_index(root: Path, index: object) -> int:
    if type(index) is not dict or set(index) != {"schema_version", "status", "fixtures"}:
        raise SourceIndexError()
    if index["schema_version"] != "1" or index["status"] != "complete_reviewed_fixture_inventory":
        raise SourceIndexError()
    rows = index["fixtures"]
    if type(rows) is not list or not 1 <= len(rows) <= 100:
        raise SourceIndexError()
    names: set[str] = set()
    for row in rows:
        if type(row) is not dict or row.get("status") != "created":
            raise SourceIndexError()
        path = checked_path(root, row.get("path"), FIXTURES)
        name = row["path"]
        if name in names or path.suffix not in {".json", ".gz", ".xml", ".txt", ".html"}:
            raise SourceIndexError()
        names.add(name)
        bound_bytes(path, row)
        for key in ("kind", "scenario", "contract_url", "contract_version", "provenance"):
            if type(row.get(key)) is not str or not row[key]:
                raise SourceIndexError()
        if type(row.get("exclusions")) is not list or not row["exclusions"]:
            raise SourceIndexError()
    actual = {item.relative_to(root).as_posix() for item in (root / FIXTURES).rglob("*") if item.is_file()}
    actual.discard(FIXTURES + "source-index.json")
    if actual != names:
        raise SourceIndexError()
    return len(names)


def verify_public_sources(root: Path = ROOT) -> dict[str, int]:
    fixture_path = root / FIXTURES / "source-index.json"
    fixture_index = parse_result_json(fixture_path.read_bytes())
    fixture_count = verify_fixture_index(root, fixture_index)
    package = root / PACKAGE
    raw = (package / "data/source-index.json").read_bytes()
    index = object_row(parse_result_json(raw))
    if index.get("field_table_sha256") != _TABLE_SHA256:
        raise SourceIndexError()
    if hashlib.sha256(canonical_json(checked_json(index["field_shapes"]))).hexdigest() != _TABLE_SHA256:
        raise SourceIndexError()
    for name, regenerator in (
        ("fedramp", refresh_fedramp.regenerate),
        ("cmvp", refresh_cmvp.regenerate),
        ("fcc-covered-list", refresh_fcc.regenerate),
    ):
        entry = object_row(object_row(index["snapshot_index"])[name])
        source = checked_path(root, entry["tuple_path"], FIXTURES)
        source_binding = object_row(entry.get("tuple_storage", entry["tuple_input"]))
        tuples = bound_bytes(source, source_binding)
        generated = refresh_fedramp.convert(tuples, index, name, regenerator)
        storage = object_row(entry.get("storage", entry))
        destination = checked_path(package, storage["path"], "data/")
        if generated != bound_bytes(destination, storage):
            raise SourceIndexError()
    load_bootstrap()
    names: tuple[SnapshotRegistry, ...] = ("fedramp", "cmvp", "fcc-covered-list")
    for name in names:
        load_snapshot(name)
    return {"fixtures": fixture_count, "regenerated_snapshots": 3, "field_shapes": len(index["field_shapes"])}


def main() -> int:
    try:
        result = verify_public_sources()
    except (OSError, ValueError, TypeError, KeyError):
        print("invalid_registry_source_index")
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
