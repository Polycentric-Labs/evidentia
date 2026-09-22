"""Small synthetic release facts shared by foundation tests."""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).parents[2] / "fixtures" / "release_cadence"


def artifact(name: str = "publication-101") -> dict:
    fixtures = json.loads((FIXTURES / "expected-identities.json").read_bytes())
    return fixtures["fixtures"][name]["artifact"]


def series_request(**changes) -> dict:
    value = {
        "schema_version": "release-series-request-v1",
        "source_profile": "github-public-releases-2026-03-10",
        "owner": "Example",
        "repository": "Synthetic",
        "channel": "all_published",
        "window_start": "1999-12-31T00:00:00.000000Z",
        "window_end": "2000-01-03T00:00:00.000000Z",
        "interval_days": 1,
        "tolerance_days": 0,
    }
    value.update(changes)
    return value


def write_artifact(root: Path, value: dict) -> Path:
    destination = root / value["id"] / "v1.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes((json.dumps(value, indent=2) + "\n").encode("utf-8"))
    return destination
