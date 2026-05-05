"""Unit tests for the Vanta vendor-inventory collector (v0.7.9 P0.4).

Mocks ``httpx.Client`` end-to-end — no live Vanta API calls. Covers:

- Happy path: vendors page maps to inventory + high-risk findings
- Pagination: cursor-based ``pageInfo.endCursor`` traversal
- Auth failure: 401 surfaces as ``VantaAuthError``
- Connection failure: httpx network errors surface as
  ``VantaConnectionError``
- High-risk detection: defensive across multiple field shapes
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from evidentia_collectors.vanta import (
    VantaAuthError,
    VantaCollector,
)
from evidentia_collectors.vanta.collector import (
    BLIND_SPOTS,
    COLLECTOR_ID,
)

# ── Helpers ────────────────────────────────────────────────────────


def _vendor_record(
    *,
    vendor_id: str,
    name: str = "Acme SaaS",
    risk_tier: str | None = "low",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a minimal Vanta-shaped vendor record."""
    rec: dict[str, Any] = {
        "id": vendor_id,
        "name": name,
        "category": "Productivity",
        "owner": "owner-1",
        "url": "https://example.com",
    }
    if risk_tier is not None:
        rec["riskTier"] = risk_tier
    if extra:
        rec.update(extra)
    return rec


def _page_response(
    vendors: list[dict[str, Any]],
    *,
    end_cursor: str | None = None,
    has_next_page: bool = False,
) -> MagicMock:
    """Build a MagicMock response whose .json() returns a Vanta page.

    Mirrors Vanta's documented `results` + `pageInfo` shape.
    """
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.json.return_value = {
        "results": vendors,
        "pageInfo": {
            "endCursor": end_cursor,
            "hasNextPage": has_next_page,
        },
    }
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
    # COLLECTOR_ID lives in the same `vanta-<surface>` namespacing
    # pattern as other collectors (`okta-scan`, `aws-scan`, etc.)
    assert COLLECTOR_ID.startswith("vanta")
    assert isinstance(BLIND_SPOTS, list)
    assert len(BLIND_SPOTS) >= 1


def test_collect_happy_path_emits_inventory_finding() -> None:
    vendor = _vendor_record(vendor_id="vendor-low-1", name="LowCo")
    page = _page_response([vendor])
    mock_client = _make_client([page])

    collector = VantaCollector(api_token="vt_test", client=mock_client)
    findings = collector.collect()

    assert any(
        (f.source_finding_id or "").startswith("vendor-inventory:")
        for f in findings
    )
    # Single low-risk vendor → no high-risk finding
    assert not any(
        (f.source_finding_id or "").startswith("vendor-high-risk:")
        for f in findings
    )


def test_collect_emits_high_risk_finding_on_high_tier() -> None:
    vendors = [
        _vendor_record(vendor_id="v-high", name="HighCo", risk_tier="high"),
        _vendor_record(vendor_id="v-low", name="LowCo", risk_tier="low"),
    ]
    mock_client = _make_client([_page_response(vendors)])

    collector = VantaCollector(api_token="vt_test", client=mock_client)
    findings = collector.collect()

    high_risk = [
        f for f in findings if (f.source_finding_id or "").startswith("vendor-high-risk:")
    ]
    # One per high-risk vendor
    assert len(high_risk) == 1
    assert "HighCo" in (high_risk[0].title + (high_risk[0].description or ""))


def test_collect_emits_high_risk_on_critical_tier() -> None:
    vendor = _vendor_record(
        vendor_id="v-crit", name="CritCo", risk_tier="critical"
    )
    mock_client = _make_client([_page_response([vendor])])

    collector = VantaCollector(api_token="vt_test", client=mock_client)
    findings = collector.collect()

    assert any(
        (f.source_finding_id or "").startswith("vendor-high-risk:") for f in findings
    )


def test_high_risk_detection_handles_alternative_field_shapes() -> None:
    """Vanta has surfaced multiple field shapes over time — all map."""
    variants = [
        _vendor_record(
            vendor_id="v-1",
            risk_tier=None,
            extra={"risk_tier": "high"},
        ),
        _vendor_record(
            vendor_id="v-2",
            risk_tier=None,
            extra={"riskLevel": "HIGH"},
        ),
        _vendor_record(
            vendor_id="v-3",
            risk_tier=None,
            extra={"risk_level": "critical"},
        ),
        _vendor_record(
            vendor_id="v-4",
            risk_tier=None,
            extra={"riskAssessment": {"tier": "high"}},
        ),
    ]
    mock_client = _make_client([_page_response(variants)])

    collector = VantaCollector(api_token="vt_test", client=mock_client)
    findings = collector.collect()

    high_risk = [
        f for f in findings if (f.source_finding_id or "").startswith("vendor-high-risk:")
    ]
    # Each variant should be picked up as high-risk
    assert len(high_risk) == 4


def test_high_risk_detection_handles_extended_field_shapes_v0_7_13() -> None:
    """v0.7.13 P3 L-2: extended `_is_high_risk` covers more field shapes.

    Adds: top-level `severity`, `tier`, `risk` (bare), `riskRating`,
    `risk_rating`, `riskClass`, `risk_class`. Plus nested
    `assessment.{tier,level,severity,rating,class}` and
    `risk_summary.*` / `riskSummary.*`. Plus a third matched value
    `SEVERE` alongside `HIGH` / `CRITICAL`.
    """
    variants = [
        _vendor_record(
            vendor_id="v-extended-severity",
            risk_tier=None,
            extra={"severity": "high"},
        ),
        _vendor_record(
            vendor_id="v-extended-tier",
            risk_tier=None,
            extra={"tier": "CRITICAL"},
        ),
        _vendor_record(
            vendor_id="v-extended-bare-risk",
            risk_tier=None,
            extra={"risk": "Severe"},
        ),
        _vendor_record(
            vendor_id="v-extended-rating",
            risk_tier=None,
            extra={"riskRating": "high"},
        ),
        _vendor_record(
            vendor_id="v-extended-class",
            risk_tier=None,
            extra={"risk_class": "critical"},
        ),
        _vendor_record(
            vendor_id="v-extended-nested-rating",
            risk_tier=None,
            extra={"riskAssessment": {"rating": "HIGH"}},
        ),
        _vendor_record(
            vendor_id="v-extended-summary-block",
            risk_tier=None,
            extra={"risk_summary": {"severity": "critical"}},
        ),
    ]
    mock_client = _make_client([_page_response(variants)])

    collector = VantaCollector(api_token="vt_test", client=mock_client)
    findings = collector.collect()

    high_risk = [
        f for f in findings if (f.source_finding_id or "").startswith("vendor-high-risk:")
    ]
    assert len(high_risk) == 7, (
        f"Expected all 7 extended-field variants to map to high-risk; "
        f"got {len(high_risk)}: "
        f"{[f.source_finding_id for f in high_risk]}"
    )


def test_collect_paginates_via_endCursor() -> None:
    page_1 = _page_response(
        [_vendor_record(vendor_id="v-1")],
        end_cursor="cursor-page-2",
        has_next_page=True,
    )
    page_2 = _page_response(
        [_vendor_record(vendor_id="v-2")],
        end_cursor=None,
        has_next_page=False,
    )
    mock_client = _make_client([page_1, page_2])

    collector = VantaCollector(api_token="vt_test", client=mock_client)
    findings = collector.collect()

    # 2 pages → 2 inventory findings (one per vendor record)
    inventory = [
        f for f in findings if (f.source_finding_id or "").startswith("vendor-inventory:")
    ]
    assert len(inventory) == 2
    # And the client was called twice
    assert mock_client.get.call_count == 2


def test_collect_respects_max_vendors_ceiling() -> None:
    page_1 = _page_response(
        [_vendor_record(vendor_id=f"v-{i}") for i in range(3)],
        end_cursor="cursor-page-2",
        has_next_page=True,
    )
    page_2 = _page_response(
        [_vendor_record(vendor_id=f"v-{i}") for i in range(3, 6)],
        end_cursor=None,
        has_next_page=False,
    )
    mock_client = _make_client([page_1, page_2])

    collector = VantaCollector(
        api_token="vt_test",
        client=mock_client,
        max_vendors=4,
    )
    findings = collector.collect()

    inventory = [
        f for f in findings if (f.source_finding_id or "").startswith("vendor-inventory:")
    ]
    # Stops at 4 — page 1's 3 vendors + 1 from page 2
    assert len(inventory) == 4


def test_collect_raises_auth_error_on_401() -> None:
    # The collector inspects status_code directly rather than calling
    # raise_for_status() — so a 401 response is sufficient to trigger
    # the auth-error branch.
    response = MagicMock(spec=httpx.Response)
    response.status_code = 401
    response.text = "Unauthorized"
    response.json.return_value = {}
    response.raise_for_status = MagicMock()
    mock_client = _make_client([response])

    collector = VantaCollector(api_token="vt_bad", client=mock_client)
    with pytest.raises(VantaAuthError):
        collector.collect()


def test_collect_raises_auth_error_on_403() -> None:
    response = MagicMock(spec=httpx.Response)
    response.status_code = 403
    response.text = "Forbidden"
    response.json.return_value = {}
    response.raise_for_status = MagicMock()
    mock_client = _make_client([response])

    collector = VantaCollector(api_token="vt_bad", client=mock_client)
    with pytest.raises(VantaAuthError):
        collector.collect()


def test_collect_records_connection_error_in_manifest() -> None:
    """Connection errors are surfaced in the manifest's errors list
    rather than re-raised — auth errors are the only fatal class so
    that intermittent network failure leaves a partial result."""
    mock_client = MagicMock(spec=httpx.Client)
    mock_client.get = MagicMock(
        side_effect=httpx.ConnectError("Network unreachable")
    )
    mock_client.close = MagicMock()

    collector = VantaCollector(api_token="vt_test", client=mock_client)
    findings, manifest = collector.collect_v2()

    assert findings == []
    assert manifest.is_complete is False
    assert any("vendors" in err for err in manifest.errors)


def test_collector_context_manager_does_not_close_injected_client() -> None:
    """Caller-owned clients are NOT auto-closed; only collector-owned ones."""
    mock_client = _make_client([_page_response([])])

    with VantaCollector(api_token="vt_test", client=mock_client) as collector:
        collector.collect()

    # Caller injected the client → caller owns the close.
    mock_client.close.assert_not_called()


def test_collect_empty_inventory_yields_no_findings() -> None:
    mock_client = _make_client([_page_response([])])

    collector = VantaCollector(api_token="vt_test", client=mock_client)
    findings = collector.collect()

    assert findings == []


def test_inventory_finding_carries_vendor_metadata() -> None:
    vendor = _vendor_record(
        vendor_id="vendor-a", name="Vendor A", risk_tier="low"
    )
    mock_client = _make_client([_page_response([vendor])])

    collector = VantaCollector(api_token="vt_test", client=mock_client)
    findings = collector.collect()

    inv = next(
        f for f in findings if (f.source_finding_id or "").startswith("vendor-inventory:")
    )
    # Vendor name + id surfaced in the finding text or evidence
    text = " ".join(filter(None, [inv.title, inv.description or ""]))
    assert "Vendor A" in text or "vendor-a" in text


# ── v0.7.10 P3 closures ────────────────────────────────────────────


def test_whitespace_only_token_rejected() -> None:
    """v0.7.9 M-1 closure: whitespace-only api_token bypasses
    the truthy check (`not "  "` is False); strip-then-validate
    surfaces it as a clear VantaAuthError instead of silently
    issuing a Bearer header with whitespace."""
    with pytest.raises(VantaAuthError):
        VantaCollector(api_token="   ")
    with pytest.raises(VantaAuthError):
        VantaCollector(api_token="\n\t")


def test_re_export_blind_spots_and_collector_id() -> None:
    """v0.7.9 L-7 closure: BLIND_SPOTS + COLLECTOR_ID re-exported
    at the package level."""
    from evidentia_collectors.vanta import BLIND_SPOTS, COLLECTOR_ID

    assert COLLECTOR_ID == "vanta-scan"
    assert isinstance(BLIND_SPOTS, list)
    assert len(BLIND_SPOTS) > 0
