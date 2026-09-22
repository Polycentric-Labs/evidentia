"""The offline series command uses Core and publishes its complete accepted bytes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia.cli import _rbac_lifecycle, conmon
from typer.testing import CliRunner

ARGS = [
    "release-series",
    "--owner",
    "Example",
    "--repository",
    "Synthetic",
    "--channel",
    "all_published",
    "--window-start",
    "1999-12-31T00:00:00.000000Z",
    "--window-end",
    "2000-01-03T00:00:00.000000Z",
    "--interval-days",
    "1",
    "--tolerance-days",
    "0",
]


@pytest.fixture(autouse=True)
def isolated_authority(monkeypatch):
    for name in ("EVIDENTIA_RBAC_POLICY_FILE", "EVIDENTIA_RBAC_IDENTITY", "EVIDENTIA_RBAC_TENANT"):
        monkeypatch.delenv(name, raising=False)
    _rbac_lifecycle._reset_rbac_cache()
    yield
    _rbac_lifecycle._reset_rbac_cache()


@pytest.mark.parametrize("count", [0, 1, 2])
def test_actual_series_zero_one_two_records_without_collector(monkeypatch, tmp_path, count):
    import builtins

    fixtures = Path(__file__).parents[2] / "fixtures" / "release_cadence"
    expected = json.loads((fixtures / "expected-identities.json").read_bytes())["fixtures"]
    names = [
        name for name, value in expected.items() if value["artifact"]["content"]["record_kind"] == "release_publication"
    ]
    for name in names[:count]:
        artifact = expected[name]["artifact"]
        target = tmp_path / artifact["id"] / "v1.json"
        target.parent.mkdir()
        target.write_text(json.dumps(artifact), encoding="utf-8")
    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.startswith("evidentia_collectors"):
            raise AssertionError("offline series imported collectors")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    result = CliRunner().invoke(conmon.app, [*ARGS, "--evidence-store", str(tmp_path)])
    assert result.exit_code == 0, result.output
    value = json.loads(result.stdout_bytes)
    assert value["state"] in {"continuous", "gapped", "insufficient"}
    assert value["meaning"] == "recorded_upstream_publication_spacing"
    assert value["request"]["window_start"] == ARGS[8]
    assert result.stdout_bytes == json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    assert not result.stderr_bytes


@pytest.mark.parametrize(
    "option,value", [("--interval-days", "0"), ("--tolerance-days", "-1"), ("--window-end", "9999-01-01T00:00:00Z")]
)
def test_series_invalid_policy_or_future_window_before_discovery(monkeypatch, tmp_path, option, value):
    from evidentia_core.release_cadence import _store

    monkeypatch.setattr(_store, "discover", lambda *a, **k: pytest.fail("invalid series read the store"))
    result = CliRunner().invoke(conmon.app, [*ARGS, option, value, "--evidence-store", str(tmp_path)])
    assert result.exit_code == 2
    assert not result.stdout_bytes
