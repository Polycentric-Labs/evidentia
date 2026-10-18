"""BI extracts neutralise spreadsheet formulas and Power BI only treats a 404 as an empty table (v0.13.0 review)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from evidentia_core.security.csv_safety import csv_safe, csv_safe_row


@pytest.mark.parametrize("lead", ["=", "+", "-", "@", "\t", "\r"])
def test_formula_leads_are_quoted(lead: str) -> None:
    assert csv_safe(f"{lead}cmd|' /C calc'!A0") == f"'{lead}cmd|' /C calc'!A0"


def test_plain_values_pass_through() -> None:
    assert csv_safe("AC-2") == "AC-2"
    assert csv_safe(3) == 3
    assert csv_safe(None) is None
    assert csv_safe_row({"a": "=1+1", "b": 2}) == {"a": "'=1+1", "b": 2}


def test_tableau_gap_csv_neutralises_free_text() -> None:
    from evidentia_integrations.tableau.extract import build_gap_dataset_csv

    from .test_tableau_extract import _gap, _report

    gap = _gap(
        control_title='=HYPERLINK("https://evil.example","click")',
        gap_description="-2+3+cmd|' /C calc'!A0",
        remediation_guidance="@SUM(1,2)",
    )
    text = build_gap_dataset_csv(_report([gap])).decode("utf-8")
    assert "'=HYPERLINK" in text
    assert "'-2+3" in text
    assert "'@SUM" in text
    assert ",=HYPERLINK" not in text


def test_powerbi_row_values_neutralise_strings() -> None:
    from evidentia_integrations.powerbi.extract import _row_value

    assert _row_value("=1+1") == "'=1+1"
    assert _row_value(["=a", "b"]) == "'=a;b"
    assert _row_value(7) == 7


class _FakeHttp:
    def __init__(self, status: int) -> None:
        self.status = status

    def delete(self, path: str) -> SimpleNamespace:
        return SimpleNamespace(status_code=self.status, reason_phrase="synthetic")


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_powerbi_clear_table_raises_on_non_404_errors(status: int) -> None:
    from evidentia_integrations.powerbi.client import PowerBIClient, PowerBIPublishError

    client = PowerBIClient.__new__(PowerBIClient)
    client._http = _FakeHttp(status)  # type: ignore[assignment]
    client._config = SimpleNamespace(workspace_id="ws-1")  # type: ignore[assignment]
    with pytest.raises(PowerBIPublishError, match=str(status)):
        client.clear_table(dataset_id="ds-1", table_name="gaps")


def test_powerbi_clear_table_treats_404_as_empty() -> None:
    from evidentia_integrations.powerbi.client import PowerBIClient

    client = PowerBIClient.__new__(PowerBIClient)
    client._http = _FakeHttp(404)  # type: ignore[assignment]
    client._config = SimpleNamespace(workspace_id="ws-1")  # type: ignore[assignment]
    assert client.clear_table(dataset_id="ds-1", table_name="gaps") is None
