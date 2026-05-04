"""Unit tests for the SecurityScorecard portfolio collector
(v0.7.9 P0.4).

Mocks ``httpx.Client`` end-to-end — no live SSC API calls.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from evidentia_collectors.securityscorecard import (
    SecurityScorecardAuthError,
    SecurityScorecardCollector,
)
from evidentia_collectors.securityscorecard.collector import (
    BLIND_SPOTS,
    COLLECTOR_ID,
)

# ── Helpers ────────────────────────────────────────────────────────


def _company_record(
    *,
    domain: str,
    name: str = "Acme Co",
    score: int | None = 85,
    grade: str = "B",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "domain": domain,
        "name": name,
        "industry": "Technology",
    }
    if score is not None:
        rec["score"] = score
    if grade is not None:
        rec["grade"] = grade
    if extra:
        rec.update(extra)
    return rec


def _portfolios_response(
    portfolio_ids: list[str],
) -> MagicMock:
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.json.return_value = {
        "entries": [{"id": pid, "name": f"Portfolio {pid}"} for pid in portfolio_ids],
    }
    response.raise_for_status = MagicMock()
    return response


def _companies_response(
    companies: list[dict[str, Any]],
    *,
    page: int = 1,
    page_count: int = 1,
) -> MagicMock:
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.json.return_value = {
        "entries": companies,
        "page": page,
        "page_count": page_count,
        "total_count": len(companies) * page_count,
    }
    response.raise_for_status = MagicMock()
    return response


def _make_client(responses: list[Any]) -> MagicMock:
    client = MagicMock(spec=httpx.Client)
    client.get = MagicMock(side_effect=responses)
    client.close = MagicMock()
    return client


# ── Tests ──────────────────────────────────────────────────────────


def test_collector_id_and_blind_spots_documented() -> None:
    assert COLLECTOR_ID.startswith("securityscorecard")
    assert isinstance(BLIND_SPOTS, list)
    assert len(BLIND_SPOTS) >= 1


def test_collect_happy_path_with_explicit_portfolio_id() -> None:
    company = _company_record(
        domain="goodco.com", name="GoodCo", score=92, grade="A"
    )
    page = _companies_response([company])
    mock_client = _make_client([page])

    collector = SecurityScorecardCollector(
        api_token="ssc_test",
        portfolio_id="portfolio-1",
        client=mock_client,
    )
    findings = collector.collect()

    assert any(
        (f.source_finding_id or "").startswith("company-inventory:")
        for f in findings
    )
    # 92 > 70 default threshold → no low-score finding
    assert not any(
        (f.source_finding_id or "").startswith("company-low-score:")
        for f in findings
    )
    # Exactly one HTTP call (no portfolio resolution needed)
    assert mock_client.get.call_count == 1


def test_collect_resolves_portfolio_when_id_omitted() -> None:
    portfolio_list = _portfolios_response(["resolved-portfolio-id"])
    company = _company_record(domain="goodco.com", score=85, grade="B")
    page = _companies_response([company])
    mock_client = _make_client([portfolio_list, page])

    collector = SecurityScorecardCollector(
        api_token="ssc_test", client=mock_client
    )
    findings = collector.collect()

    assert any(
        (f.source_finding_id or "").startswith("company-inventory:")
        for f in findings
    )
    assert mock_client.get.call_count == 2


def test_collect_emits_low_score_finding_below_threshold() -> None:
    companies = [
        _company_record(
            domain="lowco.com", name="LowCo", score=55, grade="F"
        ),
        _company_record(
            domain="midco.com", name="MidCo", score=82, grade="B"
        ),
    ]
    mock_client = _make_client([_companies_response(companies)])

    collector = SecurityScorecardCollector(
        api_token="ssc_test",
        portfolio_id="p-1",
        client=mock_client,
    )
    findings = collector.collect()

    low_score = [
        f
        for f in findings
        if (f.source_finding_id or "").startswith("company-low-score:")
    ]
    assert len(low_score) == 1
    assert "LowCo" in (
        low_score[0].title + (low_score[0].description or "")
    )


def test_low_score_threshold_is_configurable() -> None:
    company = _company_record(
        domain="midco.com", score=85, grade="B"
    )
    mock_client = _make_client([_companies_response([company])])

    collector = SecurityScorecardCollector(
        api_token="ssc_test",
        portfolio_id="p-1",
        client=mock_client,
        low_score_threshold=90,  # tighter — 85 now triggers
    )
    findings = collector.collect()

    assert any(
        (f.source_finding_id or "").startswith("company-low-score:")
        for f in findings
    )


def test_unscored_company_still_inventories() -> None:
    company = _company_record(
        domain="newco.com", score=None, grade=""
    )
    mock_client = _make_client([_companies_response([company])])

    collector = SecurityScorecardCollector(
        api_token="ssc_test",
        portfolio_id="p-1",
        client=mock_client,
    )
    findings = collector.collect()

    inv = [
        f
        for f in findings
        if (f.source_finding_id or "").startswith("company-inventory:")
    ]
    assert len(inv) == 1
    # No score → no low-score finding
    assert not any(
        (f.source_finding_id or "").startswith("company-low-score:")
        for f in findings
    )


def test_collect_paginates_via_page_count() -> None:
    page_1 = _companies_response(
        [_company_record(domain="co1.com")],
        page=1,
        page_count=2,
    )
    page_2 = _companies_response(
        [_company_record(domain="co2.com")],
        page=2,
        page_count=2,
    )
    mock_client = _make_client([page_1, page_2])

    collector = SecurityScorecardCollector(
        api_token="ssc_test",
        portfolio_id="p-1",
        client=mock_client,
    )
    findings = collector.collect()

    inventory = [
        f
        for f in findings
        if (f.source_finding_id or "").startswith("company-inventory:")
    ]
    assert len(inventory) == 2


def test_collect_respects_max_companies_ceiling() -> None:
    page_1 = _companies_response(
        [_company_record(domain=f"co-{i}.com") for i in range(3)],
        page=1,
        page_count=2,
    )
    page_2 = _companies_response(
        [_company_record(domain=f"co-{i}.com") for i in range(3, 6)],
        page=2,
        page_count=2,
    )
    mock_client = _make_client([page_1, page_2])

    collector = SecurityScorecardCollector(
        api_token="ssc_test",
        portfolio_id="p-1",
        client=mock_client,
        max_companies=4,
    )
    findings = collector.collect()

    inventory = [
        f
        for f in findings
        if (f.source_finding_id or "").startswith("company-inventory:")
    ]
    assert len(inventory) == 4


def test_collect_raises_auth_error_on_401() -> None:
    response = MagicMock(spec=httpx.Response)
    response.status_code = 401
    response.text = "Unauthorized"
    response.json.return_value = {}
    response.raise_for_status = MagicMock()
    mock_client = _make_client([response])

    collector = SecurityScorecardCollector(
        api_token="ssc_bad",
        portfolio_id="p-1",
        client=mock_client,
    )
    with pytest.raises(SecurityScorecardAuthError):
        collector.collect()


def test_collect_records_query_error_when_no_portfolios_resolvable() -> None:
    """If the operator has no portfolios, the collector surfaces it
    as a manifest-level query error (NOT auth error)."""
    empty_portfolios = _portfolios_response([])
    mock_client = _make_client([empty_portfolios])

    collector = SecurityScorecardCollector(
        api_token="ssc_test",
        client=mock_client,
    )
    findings, manifest = collector.collect_v2()

    assert findings == []
    assert manifest.is_complete is False
    assert any("portfolio" in err for err in manifest.errors)


def test_collect_records_connection_error_in_manifest() -> None:
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get = MagicMock(
        side_effect=httpx.ConnectError("Network unreachable")
    )
    mock_client.close = MagicMock()

    collector = SecurityScorecardCollector(
        api_token="ssc_test",
        portfolio_id="p-1",
        client=mock_client,
    )
    findings, manifest = collector.collect_v2()

    assert findings == []
    assert manifest.is_complete is False


def test_collector_context_manager_does_not_close_injected_client() -> None:
    mock_client = _make_client([_companies_response([])])

    with SecurityScorecardCollector(
        api_token="ssc_test",
        portfolio_id="p-1",
        client=mock_client,
    ) as collector:
        collector.collect()

    mock_client.close.assert_not_called()


def test_collect_empty_portfolio_yields_no_findings() -> None:
    mock_client = _make_client([_companies_response([])])

    collector = SecurityScorecardCollector(
        api_token="ssc_test",
        portfolio_id="p-1",
        client=mock_client,
    )
    findings = collector.collect()

    assert findings == []
