"""Tests for ``probe_baselines`` in ``scripts/check_fedramp_upstream_drift.py``.

``probe_rules`` and ``probe_schemas`` predate this cycle and are not
retested here; this file covers only the baseline probe added for V13-20.
No real network access: ``_get_json`` and ``_request`` are monkeypatched
with fakes fed from a small map of URL to payload, and the REAL vendored
file (``scripts/catalogs/upstream/fedramp-rev5-baselines.json``) is used as
the pin, read straight from the repo, so a passing suite here also means
the probe's URL construction matches what the live file actually contains.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_fedramp_upstream_drift.py"
VENDORED_PATH = REPO_ROOT / "scripts" / "catalogs" / "upstream" / "fedramp-rev5-baselines.json"

# A syntactically valid but obviously fake git blob sha (40 hex chars),
# used wherever a test just needs "not the pinned value".
FAKE_SHA = "f" * 40


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cfud() -> Any:
    return _load_module("check_fedramp_upstream_drift_under_test", SCRIPT_PATH)


@pytest.fixture
def vendored() -> dict[str, Any]:
    return json.loads(VENDORED_PATH.read_text(encoding="utf-8"))


def _listing_url(cfud: Any, prov: dict[str, Any]) -> str:
    match = cfud._SOURCE_URL_RE.match(prov["source_url"])
    assert match is not None
    return f"{cfud.API_ROOT}/repos/{match['owner']}/{match['repo']}/contents/{match['dir']}?ref={match['ref']}"


def _raw_url(cfud: Any, prov: dict[str, Any], filename: str) -> str:
    match = cfud._SOURCE_URL_RE.match(prov["source_url"])
    assert match is not None
    return (
        f"{cfud.API_ROOT}/repos/{match['owner']}/{match['repo']}/contents/{match['dir']}/{filename}?ref={match['ref']}"
    )


def _repo_to_oscal_id(repo_id: str) -> str:
    """Inverse of ``build_fedramp_baselines.oscal_to_repo_id``, for building fake profiles."""
    if "(" in repo_id:
        base, _, rest = repo_id.partition("(")
        return f"{base.lower()}.{rest.rstrip(')')}"
    return repo_id.lower()


def _fake_profile_bytes(control_ids_repo_form: list[str]) -> bytes:
    """A minimal OSCAL profile whose membership is exactly the given repo-form ids."""
    with_ids = [_repo_to_oscal_id(cid) for cid in control_ids_repo_form]
    doc = {"profile": {"imports": [{"include-controls": [{"with-ids": with_ids}]}]}}
    return json.dumps(doc).encode("utf-8")


def _install_fakes(
    monkeypatch: pytest.MonkeyPatch,
    cfud: Any,
    *,
    json_map: dict[str, Any],
    raw_map: dict[str, bytes],
) -> None:
    def fake_get_json(url: str) -> Any:
        try:
            return json_map[url]
        except KeyError:
            raise AssertionError(f"unexpected _get_json call: {url}") from None

    def fake_request(url: str, *, raw: bool = False) -> bytes:
        del raw
        try:
            return raw_map[url]
        except KeyError:
            raise AssertionError(f"unexpected _request call: {url}") from None

    monkeypatch.setattr(cfud, "_get_json", fake_get_json)
    monkeypatch.setattr(cfud, "_request", fake_request)


def _listing_payload(prov: dict[str, Any], *, drifted: str | None = None) -> list[dict[str, str]]:
    """A directory listing where every tracked file's sha matches its pin,
    except ``drifted`` (if given), which gets FAKE_SHA."""
    return [
        {"name": entry["file"], "sha": FAKE_SHA if key == drifted else entry["git_blob_sha"], "type": "file"}
        for key, entry in prov["files"].items()
    ]


def test_no_findings_when_all_blobs_match_pins(
    cfud: Any, vendored: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    prov = vendored["provenance"]
    _install_fakes(
        monkeypatch,
        cfud,
        json_map={_listing_url(cfud, prov): _listing_payload(prov)},
        raw_map={},
    )

    findings: list[tuple[str, str]] = []
    cfud.probe_baselines(vendored, findings)
    assert findings == []


def test_missing_profile_is_one_major_naming_it(
    cfud: Any, vendored: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    prov = vendored["provenance"]
    files = prov["files"]
    missing_key = "moderate"
    listing = [
        {"name": entry["file"], "sha": entry["git_blob_sha"], "type": "file"}
        for key, entry in files.items()
        if key != missing_key
    ]
    _install_fakes(monkeypatch, cfud, json_map={_listing_url(cfud, prov): listing}, raw_map={})

    findings: list[tuple[str, str]] = []
    cfud.probe_baselines(vendored, findings)

    assert len(findings) == 1
    severity, text = findings[0]
    assert severity == "MAJOR"
    assert files[missing_key]["file"] in text


def test_blob_drift_with_unchanged_membership_is_one_notice(
    cfud: Any, vendored: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    prov = vendored["provenance"]
    key = "low"
    filename = prov["files"][key]["file"]
    fake_body = _fake_profile_bytes(vendored["baselines"][key])
    _install_fakes(
        monkeypatch,
        cfud,
        json_map={_listing_url(cfud, prov): _listing_payload(prov, drifted=key)},
        raw_map={_raw_url(cfud, prov, filename): fake_body},
    )

    findings: list[tuple[str, str]] = []
    cfud.probe_baselines(vendored, findings)

    assert len(findings) == 1
    severity, text = findings[0]
    assert severity == "NOTICE"
    assert filename in text


def test_blob_drift_that_drops_a_control_is_one_major(
    cfud: Any, vendored: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    prov = vendored["provenance"]
    key = "low"
    filename = prov["files"][key]["file"]
    dropped = vendored["baselines"][key][1:]  # missing the first control
    fake_body = _fake_profile_bytes(dropped)
    _install_fakes(
        monkeypatch,
        cfud,
        json_map={_listing_url(cfud, prov): _listing_payload(prov, drifted=key)},
        raw_map={_raw_url(cfud, prov, filename): fake_body},
    )

    findings: list[tuple[str, str]] = []
    cfud.probe_baselines(vendored, findings)

    assert len(findings) == 1
    severity, text = findings[0]
    assert severity == "MAJOR"
    assert filename in text


def test_unexpected_source_url_shape_raises(cfud: Any) -> None:
    bad_vendored = {"provenance": {"source_url": "https://example.com/not/the/right/shape"}}
    with pytest.raises(RuntimeError, match="source_url"):
        cfud.probe_baselines(bad_vendored, [])
