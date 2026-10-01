"""Configuration diagnostics must not disclose routing values or imply live verification."""

from __future__ import annotations

from types import SimpleNamespace

import pytest


class _Table:
    def __init__(self, **kwargs: object) -> None:
        self.rows: list[tuple[str, ...]] = []

    def add_column(self, *args: object, **kwargs: object) -> None:
        pass

    def add_row(self, *cells: str) -> None:
        self.rows.append(cells)


@pytest.mark.parametrize(
    ("model", "base"),
    [
        ("openai/SYNTHETIC_MODEL_MARKER", "http://local-user:SYNTHETIC_ENDPOINT_MARKER@127.0.0.1:8000/v1"),
        ("openai/SYNTHETIC_MODEL_MARKER", "https://example.com/v1?credential=SYNTHETIC_ENDPOINT_MARKER"),
        ("openai/SYNTHETIC_MODEL_MARKER", "http://[SYNTHETIC_ENDPOINT_MARKER"),
        ("ollama/SYNTHETIC_MODEL_MARKER", "http://127.0.0.1/SYNTHETIC_ENDPOINT_MARKER"),
        ("openai/SYNTHETIC_MODEL_MARKER", None),
    ],
    ids=["userinfo", "query", "malformed", "local-prefix", "missing-base"],
)
@pytest.mark.asyncio
async def test_cli_and_api_reports_suppress_configured_values(
    model: str, base: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidentia.cli import main as cli
    from evidentia_api.routers import doctor as api_doctor
    from evidentia_core import config

    monkeypatch.setenv("EVIDENTIA_LLM_MODEL", model)
    monkeypatch.delenv("OPENAI_API_BASE", raising=False)
    if base is None:
        monkeypatch.delenv("EVIDENTIA_LLM_API_BASE", raising=False)
    else:
        monkeypatch.setenv("EVIDENTIA_LLM_API_BASE", base)
    monkeypatch.setattr(config, "load_config", lambda: SimpleNamespace(llm=None))
    monkeypatch.setattr(api_doctor, "load_config", lambda: SimpleNamespace(llm=None))
    emitted: list[object] = []
    monkeypatch.setattr(cli, "Table", _Table)
    monkeypatch.setattr(cli, "console", SimpleNamespace(print=emitted.append))
    cli._render_air_gap_report()
    table = emitted[0]
    assert isinstance(table, _Table)
    cli_text = repr(table.rows) + repr(emitted[1:])
    response = await api_doctor.check_air_gap()
    api_text = response.model_dump_json()
    for marker in ("SYNTHETIC_MODEL_MARKER", "SYNTHETIC_ENDPOINT_MARKER", "local-user"):
        assert marker not in cli_text
        assert marker not in api_text
    assert "selected configuration only" in cli_text
    assert "AIR-GAP READY" not in cli_text
    telemetry = next(row for row in table.rows if row[0] == "AI telemetry")
    assert telemetry[1] == "NOT CHECKED"
    assert "not checked" in telemetry[2]
    api_telemetry = next(row for row in response.checks if row.subsystem == "ai_telemetry")
    assert api_telemetry.status == "skipped"
    assert "not checked" in api_telemetry.detail
    assert set(response.model_dump()) == {"air_gapped", "checks"}
    assert all(row.status in {"ok", "would_leak", "skipped"} for row in response.checks)
