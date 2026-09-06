"""The web console's demo fixtures must agree with the catalog manifest.

V13-21: ``packages/evidentia-ui/src/lib/demo/fixtures.ts`` hardcoded
``version: "Rev 5 (2023)"`` for ``fedramp-rev5-moderate`` after the v0.12.0
baseline repair moved the manifest to "Rev 5 (profiles published
2024-09-24)", and nothing caught it: the wiki reference page is generated
from the manifest, but the fixture file had no gate. This test is that
gate: every catalog entry the demo fixtures present must name a real
manifest id and carry the manifest's exact version string.

The extraction regex is guarded by a minimum-count check so a fixtures.ts
refactor cannot silently turn this into a gate that matches nothing (the
v0.12.0 widened-regex lesson).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_TS = REPO_ROOT / "packages" / "evidentia-ui" / "src" / "lib" / "demo" / "fixtures.ts"
FRAMEWORKS_YAML = (
    REPO_ROOT / "packages" / "evidentia-core" / "src" / "evidentia_core" / "catalogs" / "data" / "frameworks.yaml"
)

_ENTRY_RE = re.compile(r'\{\s*id:\s*"(?P<id>[^"]+)",\s*name:\s*"[^"]*",\s*version:\s*"(?P<version>[^"]*)"')


def _manifest_versions() -> dict[str, str]:
    raw = yaml.safe_load(FRAMEWORKS_YAML.read_text(encoding="utf-8"))
    items = raw if isinstance(raw, list) else next(v for v in raw.values() if isinstance(v, list))
    return {entry["id"]: str(entry.get("version", "")) for entry in items}


def _fixture_entries() -> list[tuple[str, str]]:
    text = FIXTURES_TS.read_text(encoding="utf-8")
    return [(m.group("id"), m.group("version")) for m in _ENTRY_RE.finditer(text)]


def test_fixture_extraction_is_not_vacuous() -> None:
    entries = _fixture_entries()
    assert len(entries) >= 5, (
        f"only {len(entries)} catalog entries extracted from fixtures.ts; the "
        "extraction regex no longer matches the file's shape. Fix the regex "
        "rather than weakening or deleting this gate."
    )


def test_every_fixture_catalog_id_exists_in_manifest() -> None:
    manifest = _manifest_versions()
    unknown = sorted({cid for cid, _ in _fixture_entries()} - manifest.keys())
    assert not unknown, f"demo fixtures present catalog ids the manifest does not ship: {unknown}"


def test_fixture_catalog_versions_match_manifest() -> None:
    manifest = _manifest_versions()
    drift = [
        f"{cid}: fixture={version!r} manifest={manifest[cid]!r}"
        for cid, version in _fixture_entries()
        if cid in manifest and version != manifest[cid]
    ]
    assert not drift, "demo fixture catalog versions drifted from frameworks.yaml:\n  " + "\n  ".join(drift)
