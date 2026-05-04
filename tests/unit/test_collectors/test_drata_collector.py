"""Unit tests for the Drata vendor-inventory collector (v0.7.9 P0.4).

Mocks ``httpx.Client`` end-to-end — no live Drata API calls. Covers:

- Happy path: vendors page maps to inventory + high-risk findings
- Pagination: cursor-based ``nextPageToken`` traversal
- Auth failure: 401 / 403 surface as ``DrataAuthError``
- Connection failure: httpx network errors surface in manifest
- High-risk detection: defensive across multiple field shapes
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from evidentia_collectors.drata import (
    DrataAuthError,
    DrataCollector,
)
from evidentia_collectors.drata.collector import (
    BLIND_SPOTS,
    COLLECTOR_ID,
)

# ── Helpers ────────────────────────────────────────────────────────


def _vendor_record(
    *,
    vendor_id: str,
    name: str = "Acme SaaS",
    risk_level: str | None = "low",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a minimal Drata-shaped vendor record."""
    rec: dict[str, Any] = {
        "id": vendor_id,
        "name": name,
        "category": "Productivity",
        "owner": "owner-1",
        "url": "https://example.com",
    }
    if risk_level is not None:
        rec["riskLevel"] = risk_level
    if extra:
        rec.update(extra)
    return rec


def _page_response(
    vendors: list[dict[str, Any]],
    *,
    next_page_token: str | None = None,
) -> MagicMock:
    """Build a MagicMock response whose .json() returns a Drata page.

    Mirrors Drata's documented `data` + `nextPageToken` top-level shape.
    """
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    payload: dict[str, Any] = {"data": vendors}
    if next_page_token:
        payload["nextPageToken"] = next_page_token
    response.json.return_value = payload
    response.raise_for_status = MagicMock()
    return response


def _make_client(responses: list[Any]) -> MagicMock:
    """Mock ``httpx.Client`` whose .get() yields each response in order."""
    client = MagicMock(spec=httpx.Client)
    client.get = MagicMock(side_effect=responses)
    client.close = MagicMock()
    return client


# ── Tests ──────────────────────────────────────────────────────────


def test_collector_id_and_blind_spots_documented() -> None:
    """The first-slice collector must declare its identity + blind spots."""
    assert COLLECTOR_ID.startswith("drata")
    assert isinstance(BLIND_SPOTS, list)
    assert len(BLIND_SPOTS) >= 1


def test_collect_happy_path_emits_inventory_finding() -> None:
    vendor = _vendor_record(vendor_id="vendor-low-1", name="LowCo")
    page = _page_response([vendor])
    mock_client = _make_client([page])

    collector = DrataCollector(api_token="dr_test", client=mock_client)
    findings = collector.collect()

    assert any(
        (f.source_finding_id or "").startswith("vendor-inventory:")
        for f in findings
    )
    assert not any(
        (f.source_finding_id or "").startswith("vendor-high-risk:")
        for f in findings
    )


def test_collect_emits_high_risk_finding_on_high_level() -> None:
    vendors = [
        _vendor_record(
            vendor_id="v-high", name="HighCo", risk_level="high"
        ),
        _vendor_record(
            vendor_id="v-low", name="LowCo", risk_level="low"
        ),
    ]
    mock_client = _make_client([_page_response(vendors)])

    collector = DrataCollector(api_token="dr_test", client=mock_client)
    findings = collector.collect()

    high_risk = [
        f
        for f in findings
        if (f.source_finding_id or "").startswith("vendor-high-risk:")
    ]
    assert len(high_risk) == 1
    assert "HighCo" in (
        high_risk[0].title + (high_risk[0].description or "")
    )


def test_collect_emits_high_risk_on_critical_level() -> None:
    vendor = _vendor_record(
        vendor_id="v-crit", name="CritCo", risk_level="critical"
    )
    mock_client = _make_client([_page_response([vendor])])

    collector = DrataCollector(api_token="dr_test", client=mock_client)
    findings = collector.collect()

    assert any(
        (f.source_finding_id or "").startswith("vendor-high-risk:")
        for f in findings
    )


def test_high_risk_detection_handles_alternative_field_shapes() -> None:
    """Drata has surfaced multiple field shapes over time — all map."""
    variants = [
        _vendor_record(
            vendor_id="v-1",
            risk_level=None,
            extra={"risk_level": "high"},
        ),
        _vendor_record(
            vendor_id="v-2",
            risk_level=None,
            extra={"riskTier": "HIGH"},
        ),
        _vendor_record(
            vendor_id="v-3",
            risk_level=None,
            extra={"risk_tier": "critical"},
        ),
        _vendor_record(
            vendor_id="v-4",
            risk_level=None,
            extra={"riskAssessment": {"level": "high"}},
        ),
        _vendor_record(
            vendor_id="v-5",
            risk_level=None,
            extra={"inherentRisk": 4},  # 1-5 scale, 4+ = HIGH
        ),
        _vendor_record(
            vendor_id="v-6",
            risk_level=None,
            extra={"residualRisk": 20},  # 1-25 scale, 16+ = HIGH
        ),
    ]
    mock_client = _make_client([_page_response(variants)])

    collector = DrataCollector(api_token="dr_test", client=mock_client)
    findings = collector.collect()

    high_risk = [
        f
        for f in findings
        if (f.source_finding_id or "").startswith("vendor-high-risk:")
    ]
    assert len(high_risk) == 6


def test_collect_paginates_via_next_page_token() -> None:
    page_1 = _page_response(
        [_vendor_record(vendor_id="v-1")],
        next_page_token="cursor-page-2",
    )
    page_2 = _page_response(
        [_vendor_record(vendor_id="v-2")],
        next_page_token=None,
    )
    mock_client = _make_client([page_1, page_2])

    collector = DrataCollector(api_token="dr_test", client=mock_client)
    findings = collector.collect()

    inventory = [
        f
        for f in findings
        if (f.source_finding_id or "").startswith("vendor-inventory:")
    ]
    assert len(inventory) == 2
    assert mock_client.get.call_count == 2


def test_collect_respects_max_vendors_ceiling() -> None:
    page_1 = _page_response(
        [_vendor_record(vendor_id=f"v-{i}") for i in range(3)],
        next_page_token="cursor-page-2",
    )
    page_2 = _page_response(
        [_vendor_record(vendor_id=f"v-{i}") for i in range(3, 6)],
        next_page_token=None,
    )
    mock_client = _make_client([page_1, page_2])

    collector = DrataCollector(
        api_token="dr_test",
        client=mock_client,
        max_vendors=4,
    )
    findings = collector.collect()

    inventory = [
        f
        for f in findings
        if (f.source_finding_id or "").startswith("vendor-inventory:")
    ]
    assert len(inventory) == 4


def test_collect_raises_auth_error_on_401() -> None:
    response = MagicMock(spec=httpx.Response)
    response.status_code = 401
    response.text = "Unauthorized"
    response.json.return_value = {}
    response.raise_for_status = MagicMock()
    mock_client = _make_client([response])

    collector = DrataCollector(api_token="dr_bad", client=mock_client)
    with pytest.raises(DrataAuthError):
        collector.collect()


def test_collect_raises_auth_error_on_403() -> None:
    response = MagicMock(spec=httpx.Response)
    response.status_code = 403
    response.text = "Forbidden"
    response.json.return_value = {}
    response.raise_for_status = MagicMock()
    mock_client = _make_client([response])

    collector = DrataCollector(api_token="dr_bad", client=mock_client)
    with pytest.raises(DrataAuthError):
        collector.collect()


def test_collect_records_connection_error_in_manifest() -> None:
    """Connection errors are surfaced in the manifest's errors list
    rather than re-raised — auth errors are the only fatal class."""
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get = MagicMock(
        side_effect=httpx.ConnectError("Network unreachable")
    )
    mock_client.close = MagicMock()

    collector = DrataCollector(api_token="dr_test", client=mock_client)
    findings, manifest = collector.collect_v2()

    assert findings == []
    assert manifest.is_complete is False
    assert any("vendors" in err for err in manifest.errors)


def test_collector_context_manager_does_not_close_injected_client() -> None:
    """Caller-owned clients are NOT auto-closed; only collector-owned ones."""
    mock_client = _make_client([_page_response([])])

    with DrataCollector(api_token="dr_test", client=mock_client) as collector:
        collector.collect()

    mock_client.close.assert_not_called()


def test_collect_empty_inventory_yields_no_findings() -> None:
    mock_client = _make_client([_page_response([])])

    collector = DrataCollector(api_token="dr_test", client=mock_client)
    findings = collector.collect()

    assert findings == []


def test_inventory_finding_carries_vendor_metadata() -> None:
    vendor = _vendor_record(
        vendor_id="vendor-a", name="Vendor A", risk_level="low"
    )
    mock_client = _make_client([_page_response([vendor])])

    collector = DrataCollector(api_token="dr_test", client=mock_client)
    findings = collector.collect()

    inv = next(
        f
        for f in findings
        if (f.source_finding_id or "").startswith("vendor-inventory:")
    )
    text = " ".join(filter(None, [inv.title, inv.description or ""]))
    assert "Vendor A" in text or "vendor-a" in text
