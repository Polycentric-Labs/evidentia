"""Unit tests for the BitSight portfolio collector (v0.7.9 P0.4).

Mocks ``httpx.Client`` end-to-end — no live BitSight API calls.
Covers happy path, pagination via ``next`` URL, max-companies cap,
low-rating threshold emission, auth failure, and connection failure.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from evidentia_collectors.bitsight import (
    BitSightAuthError,
    BitSightCollector,
)
from evidentia_collectors.bitsight.collector import (
    BLIND_SPOTS,
    COLLECTOR_ID,
)

# ── Helpers ────────────────────────────────────────────────────────


def _company_record(
    *,
    guid: str,
    name: str = "Acme Co",
    rating: int | None = 750,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a minimal BitSight-shaped portfolio company record."""
    rec: dict[str, Any] = {
        "guid": guid,
        "name": name,
        "industry": "Technology",
    }
    if rating is not None:
        rec["rating"] = rating
    if extra:
        rec.update(extra)
    return rec


def _page_response(
    companies: list[dict[str, Any]],
    *,
    next_url: str | None = None,
) -> MagicMock:
    """Build a MagicMock response in BitSight's portfolio shape."""
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.json.return_value = {
        "results": companies,
        "next": next_url,
        "previous": None,
        "count": len(companies),
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
    assert COLLECTOR_ID.startswith("bitsight")
    assert isinstance(BLIND_SPOTS, list)
    assert len(BLIND_SPOTS) >= 1


def test_collect_happy_path_emits_inventory_finding() -> None:
    company = _company_record(guid="co-1", name="GoodCo", rating=820)
    page = _page_response([company])
    mock_client = _make_client([page])

    collector = BitSightCollector(api_token="bs_test", client=mock_client)
    findings = collector.collect()

    assert any((f.source_finding_id or "").startswith("company-inventory:") for f in findings)
    # 820 >> 700 default threshold → no low-rating finding
    assert not any((f.source_finding_id or "").startswith("company-low-rating:") for f in findings)


def test_collect_emits_low_rating_finding_below_threshold() -> None:
    companies = [
        _company_record(guid="co-low", name="LowCo", rating=580),  # F
        _company_record(guid="co-mid", name="MidCo", rating=720),  # B
    ]
    mock_client = _make_client([_page_response(companies)])

    collector = BitSightCollector(api_token="bs_test", client=mock_client)
    findings = collector.collect()

    low_rating = [f for f in findings if (f.source_finding_id or "").startswith("company-low-rating:")]
    assert len(low_rating) == 1
    assert "LowCo" in (low_rating[0].title + (low_rating[0].description or ""))


def test_low_rating_threshold_is_configurable() -> None:
    company = _company_record(guid="co-1", name="MidCo", rating=720)
    mock_client = _make_client([_page_response([company])])

    collector = BitSightCollector(
        api_token="bs_test",
        client=mock_client,
        low_rating_threshold=750,  # tighter — 720 now triggers
    )
    findings = collector.collect()

    assert any((f.source_finding_id or "").startswith("company-low-rating:") for f in findings)


def test_company_without_rating_still_inventories() -> None:
    company = _company_record(guid="co-unrated", name="UnratedCo", rating=None)
    mock_client = _make_client([_page_response([company])])

    collector = BitSightCollector(api_token="bs_test", client=mock_client)
    findings = collector.collect()

    inv = [f for f in findings if (f.source_finding_id or "").startswith("company-inventory:")]
    assert len(inv) == 1
    # No rating → no low-rating finding (avoid false-positive
    # over numeric None)
    assert not any((f.source_finding_id or "").startswith("company-low-rating:") for f in findings)


def test_collect_paginates_via_next_url() -> None:
    page_1 = _page_response(
        [_company_record(guid="co-1")],
        next_url="https://api.bitsighttech.com/portfolio?cursor=abc",
    )
    page_2 = _page_response(
        [_company_record(guid="co-2")],
        next_url=None,
    )
    mock_client = _make_client([page_1, page_2])

    collector = BitSightCollector(api_token="bs_test", client=mock_client)
    findings = collector.collect()

    inventory = [f for f in findings if (f.source_finding_id or "").startswith("company-inventory:")]
    assert len(inventory) == 2
    assert mock_client.get.call_count == 2


def test_pagination_refuses_cross_host_next_url() -> None:
    """Defensive: don't follow `next` URLs that point off-host."""
    page_1 = _page_response(
        [_company_record(guid="co-1")],
        next_url="https://attacker.example.com/portfolio?cursor=evil",
    )
    mock_client = _make_client([page_1])

    collector = BitSightCollector(api_token="bs_test", client=mock_client)
    findings = collector.collect()

    inventory = [f for f in findings if (f.source_finding_id or "").startswith("company-inventory:")]
    # Only page 1's record collected; cross-host next ignored
    assert len(inventory) == 1
    assert mock_client.get.call_count == 1


def test_collect_respects_max_companies_ceiling() -> None:
    page_1 = _page_response(
        [_company_record(guid=f"co-{i}") for i in range(3)],
        next_url="https://api.bitsighttech.com/portfolio?cursor=abc",
    )
    page_2 = _page_response(
        [_company_record(guid=f"co-{i}") for i in range(3, 6)],
        next_url=None,
    )
    mock_client = _make_client([page_1, page_2])

    collector = BitSightCollector(
        api_token="bs_test",
        client=mock_client,
        max_companies=4,
    )
    findings = collector.collect()

    inventory = [f for f in findings if (f.source_finding_id or "").startswith("company-inventory:")]
    assert len(inventory) == 4


def test_collect_raises_auth_error_on_401() -> None:
    response = MagicMock(spec=httpx.Response)
    response.status_code = 401
    response.text = "Unauthorized"
    response.json.return_value = {}
    response.raise_for_status = MagicMock()
    mock_client = _make_client([response])

    collector = BitSightCollector(api_token="bs_bad", client=mock_client)
    with pytest.raises(BitSightAuthError):
        collector.collect()


def test_collect_raises_auth_error_on_403() -> None:
    response = MagicMock(spec=httpx.Response)
    response.status_code = 403
    response.text = "Forbidden"
    response.json.return_value = {}
    response.raise_for_status = MagicMock()
    mock_client = _make_client([response])

    collector = BitSightCollector(api_token="bs_bad", client=mock_client)
    with pytest.raises(BitSightAuthError):
        collector.collect()


def test_collect_records_connection_error_in_manifest() -> None:
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get = MagicMock(side_effect=httpx.ConnectError("Network unreachable"))
    mock_client.close = MagicMock()

    collector = BitSightCollector(api_token="bs_test", client=mock_client)
    findings, manifest = collector.collect_v2()

    assert findings == []
    assert manifest.is_complete is False
    assert any("portfolio" in err for err in manifest.errors)


def test_collector_context_manager_does_not_close_injected_client() -> None:
    mock_client = _make_client([_page_response([])])

    with BitSightCollector(api_token="bs_test", client=mock_client) as collector:
        collector.collect()

    mock_client.close.assert_not_called()


def test_collect_empty_portfolio_yields_no_findings() -> None:
    mock_client = _make_client([_page_response([])])

    collector = BitSightCollector(api_token="bs_test", client=mock_client)
    findings = collector.collect()

    assert findings == []


# ── v0.7.10 P3 closures ────────────────────────────────────────────


def test_whitespace_only_token_rejected() -> None:
    """v0.7.9 M-1 closure: whitespace-only api_token rejected."""
    with pytest.raises(BitSightAuthError):
        BitSightCollector(api_token="   ")
    with pytest.raises(BitSightAuthError):
        BitSightCollector(api_token="\n\t")


def test_re_export_blind_spots_and_collector_id() -> None:
    """v0.7.9 L-7 closure."""
    from evidentia_collectors.bitsight import BLIND_SPOTS, COLLECTOR_ID

    assert COLLECTOR_ID == "bitsight-scan"
    assert isinstance(BLIND_SPOTS, list)
    assert len(BLIND_SPOTS) > 0


def test_rating_uses_round_not_trunc() -> None:
    """v0.7.9 M-2 closure: float ratings should round, not trunc.
    A rating of 749.6 must become 750 (not 749) so it doesn't
    silently fall under the 750 low-rating threshold."""
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.json.return_value = {
        "results": [
            {
                "guid": "co-1",
                "name": "Co A",
                "primary_domain": "co-a.com",
                "rating": 749.6,  # rounds to 750 (not trunc to 749)
            }
        ],
        "next": None,
    }
    response.raise_for_status = MagicMock()
    mock_client = _make_client([response])
    collector = BitSightCollector(
        api_token="bs_test",
        client=mock_client,
        low_rating_threshold=750,
    )
    findings = collector.collect()
    # Rating now reads as 750 — at-threshold (>=) so still triggers
    # the low-rating finding under inclusive comparison; key check
    # is that "749" never appears in the formatted output.
    serialized = " ".join(" ".join(str(v) for v in (f.title, f.description or "")) for f in findings)
    assert "749" not in serialized
    assert "750" in serialized
