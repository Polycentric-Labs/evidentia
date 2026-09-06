"""Unit tests for the Google Workspace evidence collector (v0.13 batch 7).

Uses httpx.MockTransport to stub the Google Workspace Admin SDK (the
Directory API and the Reports API). No live Google Workspace tenant
required.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from evidentia_collectors.google_workspace import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    GoogleWorkspaceAuthError,
    GoogleWorkspaceCollector,
    GoogleWorkspaceConnectionError,
    GoogleWorkspaceQueryError,
)
from evidentia_collectors.google_workspace.collector import (
    _DIRECTORY_FIELDS,
    _DIRECTORY_PATH,
    _REPORTS_LOGIN_PATH,
)
from evidentia_core.models.common import OLIRRelationship
from evidentia_core.models.finding import ComplianceStatus, FindingStatus, Severity

# ── Fixed clock + timestamp helpers ──────────────────────────────────

_NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)
_EPOCH = "1970-01-01T00:00:00.000Z"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _ago(days: int) -> str:
    return _iso(_NOW - timedelta(days=days))


# ── Baseline tenant fixture (section 3.6 of the batch 7 spec) ────────


def _baseline_users() -> list[dict[str, Any]]:
    """Eight users covering every finding branch: two super admins (one
    not enrolled in 2SV), one delegated admin, one suspended, one
    archived, one active user inactive by lastLoginTime, one active user
    who never signed in with an old creationTime, and one recently
    created user who never signed in and must NOT count as inactive.
    """
    return [
        {
            "id": "u01",
            "primaryEmail": "admin1@example.com",
            "suspended": False,
            "archived": False,
            "isAdmin": True,
            "isDelegatedAdmin": False,
            "isEnrolledIn2Sv": True,
            "isEnforcedIn2Sv": True,
            "lastLoginTime": _ago(1),
            "creationTime": _ago(500),
        },
        {
            "id": "u02",
            "primaryEmail": "admin2@example.com",
            "suspended": False,
            "archived": False,
            "isAdmin": True,
            "isDelegatedAdmin": False,
            "isEnrolledIn2Sv": False,
            "isEnforcedIn2Sv": False,
            "lastLoginTime": _ago(2),
            "creationTime": _ago(500),
        },
        {
            "id": "u03",
            "primaryEmail": "delegated1@example.com",
            "suspended": False,
            "archived": False,
            "isAdmin": False,
            "isDelegatedAdmin": True,
            "isEnrolledIn2Sv": True,
            "isEnforcedIn2Sv": True,
            "lastLoginTime": _ago(3),
            "creationTime": _ago(500),
        },
        {
            "id": "u04",
            "primaryEmail": "suspended1@example.com",
            "suspended": True,
            "archived": False,
            "isAdmin": False,
            "isDelegatedAdmin": False,
            "isEnrolledIn2Sv": False,
            "isEnforcedIn2Sv": False,
            "lastLoginTime": _ago(200),
            "creationTime": _ago(500),
        },
        {
            "id": "u05",
            "primaryEmail": "archived1@example.com",
            "suspended": False,
            "archived": True,
            "isAdmin": False,
            "isDelegatedAdmin": False,
            "isEnrolledIn2Sv": False,
            "isEnforcedIn2Sv": False,
            "lastLoginTime": _ago(400),
            "creationTime": _ago(600),
        },
        {
            # Active, inactive by lastLoginTime (120 days > the 90-day threshold).
            "id": "u06",
            "primaryEmail": "stale1@example.com",
            "suspended": False,
            "archived": False,
            "isAdmin": False,
            "isDelegatedAdmin": False,
            "isEnrolledIn2Sv": True,
            "isEnforcedIn2Sv": False,
            "lastLoginTime": _ago(120),
            "creationTime": _ago(500),
        },
        {
            # Active, never signed in, OLD creationTime -> counts as inactive.
            "id": "u07",
            "primaryEmail": "neversignedin-old@example.com",
            "suspended": False,
            "archived": False,
            "isAdmin": False,
            "isDelegatedAdmin": False,
            "isEnrolledIn2Sv": False,
            "isEnforcedIn2Sv": False,
            "lastLoginTime": _EPOCH,
            "creationTime": _ago(200),
        },
        {
            # Active, never signed in, RECENT creationTime -> must NOT be inactive.
            "id": "u08",
            "primaryEmail": "neversignedin-new@example.com",
            "suspended": False,
            "archived": False,
            "isAdmin": False,
            "isDelegatedAdmin": False,
            "isEnrolledIn2Sv": True,
            "isEnforcedIn2Sv": True,
            "lastLoginTime": _EPOCH,
            "creationTime": _ago(5),
        },
    ]


def _baseline_directory_page() -> httpx.Response:
    return httpx.Response(200, json={"users": _baseline_users()})


def _baseline_reports_pages() -> list[httpx.Response]:
    """Two Reports pages joined by nextPageToken, mixing login_success,
    login_failure and one suspicious_login."""
    page_1 = httpx.Response(
        200,
        json={
            "items": [
                {
                    "actor": {"email": "admin1@example.com"},
                    "events": [{"name": "login_success"}],
                },
                {
                    "actor": {"email": "admin2@example.com"},
                    "events": [{"name": "login_failure"}],
                },
            ],
            "nextPageToken": "reports-page-2",
        },
    )
    page_2 = httpx.Response(
        200,
        json={
            "items": [
                {
                    "actor": {"email": "delegated1@example.com"},
                    "events": [{"name": "suspicious_login"}],
                },
            ],
        },
    )
    return [page_1, page_2]


def _active_users(n: int, enrolled: int) -> list[dict[str, Any]]:
    """n active (not suspended/archived) users; the first `enrolled` of
    them carry isEnrolledIn2Sv and isEnforcedIn2Sv True."""
    return [
        {
            "id": f"u{i:03d}",
            "primaryEmail": f"user{i}@example.com",
            "suspended": False,
            "archived": False,
            "isAdmin": False,
            "isDelegatedAdmin": False,
            "isEnrolledIn2Sv": i < enrolled,
            "isEnforcedIn2Sv": i < enrolled,
            "lastLoginTime": _ago(1),
            "creationTime": _ago(500),
        }
        for i in range(n)
    ]


def _admins(n: int) -> list[dict[str, Any]]:
    """n active super admin users, all 2SV-enrolled (isolates the
    admin-count threshold from the 2SV-enrollment finding)."""
    return [
        {
            "id": f"admin{i:03d}",
            "primaryEmail": f"admin{i}@example.com",
            "suspended": False,
            "archived": False,
            "isAdmin": True,
            "isDelegatedAdmin": False,
            "isEnrolledIn2Sv": True,
            "isEnforcedIn2Sv": True,
            "lastLoginTime": _ago(1),
            "creationTime": _ago(500),
        }
        for i in range(n)
    ]


# ── Mock-transport infrastructure ────────────────────────────────────


def _make_handler(
    *,
    directory_pages: list[httpx.Response] | None = None,
    reports_pages: list[httpx.Response] | None = None,
    probe_response: httpx.Response | None = None,
) -> tuple[httpx.MockTransport, list[httpx.Request]]:
    """Build a MockTransport routing by path.

    On the Directory path, ``maxResults=1`` is test_connection's cheap
    probe (served from ``probe_response``, defaulting to an empty
    200); any other maxResults is the real paginated fetch, served in
    order from ``directory_pages``. The Reports path is served in
    order from ``reports_pages``. An exhausted queue serves an empty
    200 rather than erroring, so a test that doesn't care about a
    given path can simply omit it.
    """
    captured: list[httpx.Request] = []
    directory_queue = list(directory_pages or [])
    reports_queue = list(reports_pages or [])

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        path = request.url.path
        params = parse_qs(urlparse(str(request.url)).query)
        if path == _DIRECTORY_PATH:
            max_results = (params.get("maxResults") or [""])[0]
            if max_results == "1":
                if probe_response is not None:
                    return probe_response
                return httpx.Response(200, json={"users": []})
            if directory_queue:
                return directory_queue.pop(0)
            return httpx.Response(200, json={"users": []})
        if path == _REPORTS_LOGIN_PATH:
            if reports_queue:
                return reports_queue.pop(0)
            return httpx.Response(200, json={"items": []})
        return httpx.Response(404, json={"error": f"path {path!r} not stubbed"})

    return httpx.MockTransport(handler), captured


def _make_collector(transport: httpx.MockTransport, **kwargs: Any) -> GoogleWorkspaceCollector:
    client = httpx.Client(
        transport=transport,
        base_url="https://admin.googleapis.com",
        headers={"Authorization": "Bearer test-token"},
    )
    return GoogleWorkspaceCollector(client=client, now=_NOW, **kwargs)


def _fetch_requests(captured: list[httpx.Request], path: str) -> list[httpx.Request]:
    """Requests to `path`, excluding test_connection's maxResults=1 probe."""
    out = []
    for r in captured:
        if r.url.path != path:
            continue
        if path == _DIRECTORY_PATH:
            params = parse_qs(urlparse(str(r.url)).query)
            if (params.get("maxResults") or [""])[0] == "1":
                continue
        out.append(r)
    return out


def _finding(findings: list[Any], slug: str) -> Any:
    return next(f for f in findings if (f.source_finding_id or "").startswith(f"{slug}:"))


# ── Constants ─────────────────────────────────────────────────────────


def test_collector_id_constant() -> None:
    assert COLLECTOR_ID == "google-workspace-scan"


def test_blind_spots_documented() -> None:
    assert len(BLIND_SPOTS) == 4
    ids = {bs["id"] for bs in BLIND_SPOTS}
    assert ids == {
        "EVIDENTIA-GOOGLE-WORKSPACE-TOKEN-LIFETIME",
        "EVIDENTIA-GOOGLE-WORKSPACE-2SV-METHOD",
        "EVIDENTIA-GOOGLE-WORKSPACE-REPORTS-RETENTION",
        "EVIDENTIA-GOOGLE-WORKSPACE-ENUMERATION-CAP",
    }


# ── Construction validation ──────────────────────────────────────────


def test_constructor_rejects_empty_customer() -> None:
    with pytest.raises(ValueError, match="customer"):
        GoogleWorkspaceCollector(api_token="t", customer="   ")


def test_constructor_rejects_login_window_out_of_range() -> None:
    with pytest.raises(ValueError, match="login_window_days"):
        GoogleWorkspaceCollector(api_token="t", login_window_days=181)
    with pytest.raises(ValueError, match="login_window_days"):
        GoogleWorkspaceCollector(api_token="t", login_window_days=-1)


def test_constructor_missing_token_without_client_raises_auth_error() -> None:
    with pytest.raises(GoogleWorkspaceAuthError):
        GoogleWorkspaceCollector()


def test_constructor_compatible_with_api_token_and_base_url() -> None:
    """The SSRF-guard suite constructs the collector this way; the
    constructor must stay compatible with it."""
    collector = GoogleWorkspaceCollector(api_token="t", base_url="https://admin.googleapis.com")
    assert collector is not None


# ── test_connection ──────────────────────────────────────────────────


def test_test_connection_happy_path() -> None:
    transport, _ = _make_handler()
    collector = _make_collector(transport, customer="my_customer")
    info = collector.test_connection()
    assert info == {"customer": "my_customer", "reachable": True}


def test_test_connection_query_error_reraised_as_connection_error() -> None:
    transport, _ = _make_handler(probe_response=httpx.Response(500, json={"error": "boom"}))
    collector = _make_collector(transport)
    with pytest.raises(GoogleWorkspaceConnectionError):
        collector.test_connection()


def test_test_connection_auth_error_propagates_as_is() -> None:
    transport, _ = _make_handler(probe_response=httpx.Response(401, json={"error": "no"}))
    collector = _make_collector(transport)
    with pytest.raises(GoogleWorkspaceAuthError):
        collector.test_connection()


# ── user-inventory ────────────────────────────────────────────────────


def test_user_inventory_finding() -> None:
    transport, _ = _make_handler(directory_pages=[_baseline_directory_page()])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    inv = _finding(findings, "user-inventory")
    assert inv.raw_data["total"] == 8
    assert inv.raw_data["active"] == 6
    assert inv.raw_data["suspended"] == 1
    assert inv.raw_data["archived"] == 1
    assert inv.raw_data["super_admins"] == 2
    assert inv.raw_data["delegated_admins"] == 1
    assert inv.raw_data["never_signed_in"] == 2
    assert inv.raw_data["truncated"] is False
    assert inv.severity == Severity.INFORMATIONAL
    assert inv.status == FindingStatus.ACTIVE
    assert inv.compliance_status == ComplianceStatus.UNKNOWN
    assert inv.resource_type == "GoogleWorkspace::Customer"


# ── inactive-accounts ─────────────────────────────────────────────────


def test_inactive_account_finding_counts_and_sample() -> None:
    transport, _ = _make_handler(directory_pages=[_baseline_directory_page()])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    f = _finding(findings, "inactive-accounts")
    assert f.raw_data["count"] == 2
    assert f.raw_data["threshold_days"] == 90
    assert "stale1@example.com" in f.raw_data["sample_inactive"]
    assert "neversignedin-old@example.com" in f.raw_data["sample_inactive"]
    assert "neversignedin-new@example.com" not in f.raw_data["sample_inactive"]
    assert f.severity == Severity.MEDIUM
    assert f.status == FindingStatus.ACTIVE
    assert f.compliance_status == ComplianceStatus.WARNING


def test_inactive_account_finding_absent_when_zero() -> None:
    users = [u for u in _baseline_users() if u["id"] not in {"u06", "u07"}]
    transport, _ = _make_handler(directory_pages=[httpx.Response(200, json={"users": users})])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    assert not [f for f in findings if (f.source_finding_id or "").startswith("inactive-accounts:")]


def test_inactive_account_severity_high_above_50() -> None:
    many = [
        {
            "id": f"u{i:03d}",
            "primaryEmail": f"user{i}@example.com",
            "suspended": False,
            "archived": False,
            "isAdmin": False,
            "isDelegatedAdmin": False,
            "isEnrolledIn2Sv": True,
            "isEnforcedIn2Sv": True,
            "lastLoginTime": _ago(120),
            "creationTime": _ago(500),
        }
        for i in range(60)
    ]
    transport, _ = _make_handler(directory_pages=[httpx.Response(200, json={"users": many})])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    f = _finding(findings, "inactive-accounts")
    assert f.raw_data["count"] == 60
    assert f.severity == Severity.HIGH


# ── admin-accounts ────────────────────────────────────────────────────


def test_admin_accounts_informational_at_5() -> None:
    transport, _ = _make_handler(directory_pages=[httpx.Response(200, json={"users": _admins(5)})])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    f = _finding(findings, "admin-accounts")
    assert f.raw_data["super_admins"] == 5
    assert f.severity == Severity.INFORMATIONAL
    assert f.status == FindingStatus.ACTIVE
    assert f.compliance_status == ComplianceStatus.UNKNOWN


def test_admin_accounts_medium_above_5() -> None:
    transport, _ = _make_handler(directory_pages=[httpx.Response(200, json={"users": _admins(6)})])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    f = _finding(findings, "admin-accounts")
    assert f.severity == Severity.MEDIUM
    assert f.compliance_status == ComplianceStatus.WARNING


def test_admin_accounts_high_above_10() -> None:
    transport, _ = _make_handler(directory_pages=[httpx.Response(200, json={"users": _admins(11)})])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    f = _finding(findings, "admin-accounts")
    assert f.severity == Severity.HIGH
    assert f.compliance_status == ComplianceStatus.WARNING
    assert f.status == FindingStatus.ACTIVE


# ── admin-2sv ─────────────────────────────────────────────────────────


def test_admin_2sv_finding_flags_unenrolled_super_admin() -> None:
    transport, _ = _make_handler(directory_pages=[_baseline_directory_page()])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    f = _finding(findings, "admin-2sv")
    assert f.raw_data["super_admins"] == 2
    assert f.raw_data["super_admins_without_2sv"] == 1
    assert "admin2@example.com" in f.raw_data["sample_without_2sv"]
    assert f.severity == Severity.HIGH
    assert f.status == FindingStatus.ACTIVE
    assert f.compliance_status == ComplianceStatus.FAIL


def test_admin_2sv_finding_passes_when_all_enrolled() -> None:
    users = [dict(u) for u in _baseline_users()]
    for u in users:
        if u["isAdmin"]:
            u["isEnrolledIn2Sv"] = True
            u["isEnforcedIn2Sv"] = True
    transport, _ = _make_handler(directory_pages=[httpx.Response(200, json={"users": users})])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    f = _finding(findings, "admin-2sv")
    assert f.raw_data["super_admins_without_2sv"] == 0
    assert f.severity == Severity.INFORMATIONAL
    assert f.status == FindingStatus.RESOLVED
    assert f.compliance_status == ComplianceStatus.PASS


# ── 2sv-enrollment ────────────────────────────────────────────────────


def test_two_sv_enrollment_severity_high_below_0_80() -> None:
    transport, _ = _make_handler(directory_pages=[httpx.Response(200, json={"users": _active_users(5, 3)})])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    f = _finding(findings, "2sv-enrollment")
    assert f.raw_data["enrollment_rate"] == 0.6
    assert f.severity == Severity.HIGH
    assert f.status == FindingStatus.ACTIVE
    assert f.compliance_status == ComplianceStatus.FAIL


def test_two_sv_enrollment_boundary_0_80_is_medium() -> None:
    transport, _ = _make_handler(directory_pages=[httpx.Response(200, json={"users": _active_users(5, 4)})])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    f = _finding(findings, "2sv-enrollment")
    assert f.raw_data["enrollment_rate"] == 0.8
    assert f.severity == Severity.MEDIUM
    assert f.status == FindingStatus.ACTIVE
    assert f.compliance_status == ComplianceStatus.FAIL


def test_two_sv_enrollment_boundary_0_95_is_informational_and_pass() -> None:
    transport, _ = _make_handler(directory_pages=[httpx.Response(200, json={"users": _active_users(20, 19)})])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    f = _finding(findings, "2sv-enrollment")
    assert f.raw_data["enrollment_rate"] == 0.95
    assert f.severity == Severity.INFORMATIONAL
    assert f.status == FindingStatus.RESOLVED
    assert f.compliance_status == ComplianceStatus.PASS


def test_two_sv_enrollment_no_active_users_yields_unknown() -> None:
    users = [{**u, "suspended": True} for u in _active_users(3, 3)]
    transport, _ = _make_handler(directory_pages=[httpx.Response(200, json={"users": users})])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    f = _finding(findings, "2sv-enrollment")
    assert f.raw_data["enrollment_rate"] is None
    assert f.raw_data["active_users"] == 0
    assert f.severity == Severity.INFORMATIONAL
    assert f.status == FindingStatus.RESOLVED
    assert f.compliance_status == ComplianceStatus.UNKNOWN


# ── login-activity ────────────────────────────────────────────────────


def test_login_activity_finding_counts() -> None:
    transport, _ = _make_handler(
        directory_pages=[_baseline_directory_page()],
        reports_pages=_baseline_reports_pages(),
    )
    collector = _make_collector(transport, login_window_days=30)
    findings = collector.collect()
    f = _finding(findings, "login-activity")
    assert f.raw_data["events_scanned"] == 3
    assert f.raw_data["distinct_actors"] == 3
    assert f.raw_data["by_event"] == {
        "login_failure": 1,
        "login_success": 1,
        "suspicious_login": 1,
    }
    assert f.raw_data["suspicious"] == 1
    assert f.raw_data["login_failures"] == 1
    assert f.raw_data["window_days"] == 30
    assert f.severity == Severity.MEDIUM
    assert f.status == FindingStatus.ACTIVE
    assert f.compliance_status == ComplianceStatus.WARNING


def test_login_activity_finding_absent_when_window_zero() -> None:
    transport, captured = _make_handler(directory_pages=[_baseline_directory_page()])
    collector = _make_collector(transport, login_window_days=0)
    findings, manifest = collector.collect_v2()
    assert not [f for f in findings if (f.source_finding_id or "").startswith("login-activity:")]
    assert manifest.empty_categories == ["login_events"]
    assert not [r for r in captured if r.url.path == _REPORTS_LOGIN_PATH]


def test_login_activity_resolved_and_informational_when_clean() -> None:
    clean_reports = [
        httpx.Response(
            200,
            json={
                "items": [
                    {
                        "actor": {"email": "a@example.com"},
                        "events": [{"name": "login_success"}],
                    }
                ]
            },
        )
    ]
    transport, _ = _make_handler(directory_pages=[_baseline_directory_page()], reports_pages=clean_reports)
    collector = _make_collector(transport, login_window_days=30)
    findings = collector.collect()
    f = _finding(findings, "login-activity")
    assert f.raw_data["suspicious"] == 0
    assert f.severity == Severity.INFORMATIONAL
    assert f.status == FindingStatus.RESOLVED
    assert f.compliance_status == ComplianceStatus.UNKNOWN


def test_reports_403_is_non_fatal_and_manifest_incomplete() -> None:
    transport, _ = _make_handler(
        directory_pages=[_baseline_directory_page()],
        reports_pages=[httpx.Response(403, json={"error": "missing scope"})],
    )
    collector = _make_collector(transport, login_window_days=30)
    findings, manifest = collector.collect_v2()
    assert any((f.source_finding_id or "").startswith("user-inventory:") for f in findings)
    assert not any((f.source_finding_id or "").startswith("login-activity:") for f in findings)
    assert manifest.is_complete is False
    assert _REPORTS_LOGIN_PATH in (manifest.incomplete_reason or "")


# ── Directory pagination + params ────────────────────────────────────


def test_directory_request_params() -> None:
    transport, captured = _make_handler(directory_pages=[_baseline_directory_page()])
    collector = _make_collector(transport, customer="acme-customer-id", login_window_days=0)
    collector.collect()
    fetch_requests = _fetch_requests(captured, _DIRECTORY_PATH)
    assert len(fetch_requests) == 1
    params = parse_qs(urlparse(str(fetch_requests[0].url)).query)
    assert params["customer"] == ["acme-customer-id"]
    assert params["orderBy"] == ["email"]
    assert params["maxResults"] == ["500"]
    assert params["fields"] == [_DIRECTORY_FIELDS]


def test_directory_two_pages_joined_by_next_page_token() -> None:
    users = _baseline_users()
    page_1 = httpx.Response(200, json={"users": users[:4], "nextPageToken": "dir-page-2"})
    page_2 = httpx.Response(200, json={"users": users[4:]})
    transport, captured = _make_handler(directory_pages=[page_1, page_2])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    fetch_requests = _fetch_requests(captured, _DIRECTORY_PATH)
    assert len(fetch_requests) == 2
    second_params = parse_qs(urlparse(str(fetch_requests[1].url)).query)
    assert second_params["pageToken"] == ["dir-page-2"]
    inv = _finding(findings, "user-inventory")
    assert inv.raw_data["total"] == 8


def test_max_users_truncates_and_sets_truncated_flag() -> None:
    users = _baseline_users()[:4]
    page_1 = httpx.Response(200, json={"users": users, "nextPageToken": "dir-page-2"})
    transport, captured = _make_handler(directory_pages=[page_1])
    collector = _make_collector(transport, max_users=3, login_window_days=0)
    findings = collector.collect()
    inv = _finding(findings, "user-inventory")
    assert inv.raw_data["total"] == 3
    assert inv.raw_data["truncated"] is True
    # The cap is hit on the first page, so a second page is never requested.
    assert len(_fetch_requests(captured, _DIRECTORY_PATH)) == 1


# ── Errors + retry ────────────────────────────────────────────────────


def test_directory_401_raises_auth_error() -> None:
    transport, _ = _make_handler(directory_pages=[httpx.Response(401, json={"error": "bad token"})])
    collector = _make_collector(transport, login_window_days=0)
    with pytest.raises(GoogleWorkspaceAuthError):
        collector.collect()


def test_directory_429_then_200_retries_and_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVIDENTIA_TEST_MODE", "1")
    transport, captured = _make_handler(
        directory_pages=[
            httpx.Response(429, json={"error": "rate limited"}),
            _baseline_directory_page(),
        ]
    )
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    assert any((f.source_finding_id or "").startswith("user-inventory:") for f in findings)
    assert len(_fetch_requests(captured, _DIRECTORY_PATH)) == 2


def test_directory_400_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVIDENTIA_TEST_MODE", "1")
    transport, captured = _make_handler(directory_pages=[httpx.Response(400, json={"error": "bad request"})])
    collector = _make_collector(transport, login_window_days=0)
    with pytest.raises(GoogleWorkspaceQueryError):
        collector.collect()
    assert len(_fetch_requests(captured, _DIRECTORY_PATH)) == 1


def test_dry_run_returns_empty_list_with_no_requests() -> None:
    transport, captured = _make_handler()
    collector = _make_collector(transport)
    findings = collector.collect(dry_run=True)
    assert findings == []
    assert captured == []


# ── Manifest ──────────────────────────────────────────────────────────


def test_collect_v2_manifest_coverage_counts() -> None:
    transport, _ = _make_handler(
        directory_pages=[_baseline_directory_page()],
        reports_pages=_baseline_reports_pages(),
    )
    collector = _make_collector(transport, login_window_days=30)
    findings, manifest = collector.collect_v2()
    assert manifest.collector_id == COLLECTOR_ID
    assert manifest.is_complete
    assert manifest.total_findings == len(findings)
    by_type = {c.resource_type: c for c in manifest.coverage_counts}
    assert by_type["google-workspace-user"].scanned == 8
    assert by_type["google-workspace-login-event"].scanned == 3
    assert manifest.source_system_ids == [f"google-workspace:{collector._customer}"]


# ── Control mappings + transport identity ────────────────────────────


def test_control_mappings_carry_authored_relationship() -> None:
    transport, _ = _make_handler(directory_pages=[_baseline_directory_page()])
    collector = _make_collector(transport, login_window_days=0)
    findings = collector.collect()
    inv = _finding(findings, "user-inventory")
    assert inv.control_mappings
    assert inv.control_mappings[0].relationship == OLIRRelationship.SUBSET_OF
    assert inv.control_mappings[0].framework == "nist-800-53-rev5"


def test_user_agent_header_set() -> None:
    """The collector identifies itself in the UA header (mirrors the
    Okta collector's equivalent test, avoiding DNS via a real public
    hostname that never gets an actual request sent to it)."""
    collector = GoogleWorkspaceCollector(api_token="t")
    client = collector._ensure_client()
    ua = client.headers.get("User-Agent")
    assert ua and "evidentia-collectors" in ua
    collector.__exit__(None, None, None)
