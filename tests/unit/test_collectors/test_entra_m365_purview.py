"""Retention configuration through the real shared Graph transport."""

from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from evidentia_collectors.entra_m365._client import CredentialGroup, EntraM365GraphReader, _CredentialResolution
from evidentia_collectors.entra_m365._contracts import (
    EntraM365CollectRequest,
    EntraM365CollectResult,
    EntraM365RunContext,
)
from evidentia_collectors.entra_m365.purview import read_retention_labels
from evidentia_core import network_guard
from evidentia_core.models.finding import SecurityFinding

PATH = "/v1.0/security/labels/retentionLabels"
ORIGIN = "https://graph.microsoft.com"
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures/entra_m365/purview"


def source_fields(finding: SecurityFinding) -> dict[str, Any]:
    assert isinstance(finding.raw_data, dict)
    value = finding.raw_data["source"]
    assert isinstance(value, dict)
    return value


class Provider:
    def __init__(self, missing: bool = False) -> None:
        self.calls: list[str] = []
        self.missing = missing

    def resolve(self, group: CredentialGroup) -> _CredentialResolution:
        self.calls.append(group)
        assert group == "retention"
        return _CredentialResolution(
            token=None if self.missing else "SYNTHETIC_RETENTION", declared_auth_mode="delegated"
        )


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("No real DNS or network is allowed")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


def collect(
    monkeypatch: pytest.MonkeyPatch, pages: list[dict[str, Any]], *, max_items: int = 10000, missing: bool = False
) -> tuple[EntraM365CollectResult, list[httpx.Request], Provider]:
    sent: list[httpx.Request] = []
    pinned = False

    def offline(url: str, **kwargs: object) -> None:
        assert url == ORIGIN

    def public(url: str, **kwargs: object) -> list[str]:
        assert url == ORIGIN
        return ["8.8.8.8"]

    @contextmanager
    def pin(host: str, addresses: list[str]) -> Iterator[None]:
        nonlocal pinned
        assert host == "graph.microsoft.com" and addresses == ["8.8.8.8"]
        pinned = True
        try:
            yield
        finally:
            pinned = False

    def handle(request: httpx.Request) -> httpx.Response:
        assert pinned
        assert request.method == "GET" and request.url.path == PATH
        assert request.headers["Authorization"] == "Bearer SYNTHETIC_RETENTION"
        sent.append(request)
        page = pages[len(sent) - 1]
        return httpx.Response(
            page.get("status", 200), stream=httpx.ByteStream(json.dumps(page["body"]).encode("utf-8"))
        )

    monkeypatch.setattr(network_guard, "check_url", offline)
    monkeypatch.setattr(network_guard, "enforce_public_host", public)
    monkeypatch.setattr(network_guard, "pin_resolved_host", pin)
    request = EntraM365CollectRequest(tenant_label="synthetic", capabilities=["retention-labels"], max_items=max_items)
    now = datetime(2026, 1, 31, tzinfo=UTC)
    run = EntraM365RunContext.start(
        request,
        utc_clock=lambda: now,
        monotonic_clock=lambda: 0.0,
        sleep=lambda seconds: None,
        run_id_factory=lambda: "synthetic-retention-run",
    )
    provider = Provider(missing)
    with httpx.Client(
        transport=httpx.MockTransport(handle),
        trust_env=False,
        params={"forbidden_default": "discard"},
        follow_redirects=True,
    ) as client:
        reader = EntraM365GraphReader(credentials=provider, client=client)
        read = read_retention_labels(request, reader, run)
        reader.close()
        assert not client.is_closed
    result = run.build_result([read])
    return EntraM365CollectResult.model_validate_json(result.model_dump_json()), sent, provider


def test_retention_retains_literal_configuration_and_declared_delegated_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = {
        "id": " label-1 ",
        "displayName": "<script>literal</script>",
        "retentionTrigger": "dateLabeled",
        "retentionDuration": {"days": 0, "enabled": False, "unknown": None},
        "behaviorDuringRetentionPeriod": "retainAsRecord",
        "actionAfterRetentionPeriod": "relabel",
        "discarded": "DO_NOT_RETAIN",
    }
    result, sent, provider = collect(monkeypatch, [{"body": {"value": [row]}}])
    assert len(sent) == 1 and sent[0].url.raw_path == PATH.encode()
    assert provider.calls == ["retention"]
    cap = result.capabilities[5]
    assert (cap.state, cap.collected, cap.matched_filter, cap.requests_attempted) == ("complete", 1, 1, 1)
    assert cap.declared_auth_mode == "delegated" and cap.credential_basis == "unverified:retention-token"
    finding = result.findings[0]
    assert finding.source_finding_id == "synthetic:retention-labels: label-1 "
    assert source_fields(finding) == {key: value for key, value in row.items() if key != "discarded"}
    assert finding.raw_data["observation"] == {"scope": "label_configuration"}
    assert finding.compliance_status.value == "unknown" and finding.status.value == "active"
    assert finding.severity.value == "informational"
    assert [item.control_id for item in finding.control_mappings] == ["SI-12"]
    assert "DO_NOT_RETAIN" not in result.model_dump_json()


def test_unknown_absent_and_null_remain_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _, _ = collect(
        monkeypatch,
        [
            {
                "body": {
                    "value": [
                        {"id": "absent"},
                        {"id": "null", "retentionTrigger": None},
                        {"id": "new", "retentionTrigger": "FUTURE_MODE"},
                    ]
                }
            }
        ],
    )
    cap = result.capabilities[5]
    assert result.status == "complete"
    assert cap.field_coverage["retentionTrigger"].model_dump() == {"absent": 1, "null": 1, "known": 0, "unknown": 1}
    assert "retentionTrigger" not in source_fields(result.findings[0])
    assert source_fields(result.findings[1])["retentionTrigger"] is None
    assert source_fields(result.findings[2])["retentionTrigger"] == "FUTURE_MODE"


def test_pagination_keeps_opaque_query_and_final_conflict_set(monkeypatch: pytest.MonkeyPatch) -> None:
    next_link = ORIGIN + PATH + "?$skiptoken=opaque%2f%2F+a%20b"
    result, sent, _ = collect(
        monkeypatch,
        [
            {
                "body": {
                    "value": [{"id": "quarantined", "displayName": "one"}, {"id": "kept"}],
                    "@odata.nextLink": next_link,
                }
            },
            {"body": {"value": [{"id": "kept"}, {"id": "quarantined", "displayName": "two"}]}},
        ],
    )
    assert len(sent) == 2 and sent[1].url.raw_path == (PATH + "?$skiptoken=opaque%2f%2F+a%20b").encode()
    cap = result.capabilities[5]
    assert (cap.scanned, cap.matched_filter, cap.duplicate_records, cap.collected) == (4, 1, 1, 1)
    assert result.status == "partial"
    assert source_fields(result.findings[0]) == {"id": "kept"}
    assert [item.code for item in cap.diagnostics] == ["conflicting_duplicate"]


@pytest.mark.parametrize(
    "bad",
    [
        {"id": "bad", "retentionDuration": []},
        {"id": "bad", "displayName": False},
        {"id": "bad", "retentionTrigger": 1},
        {"id": "bad", "retentionDuration": {"long": "x" * 2049}},
    ],
)
def test_invalid_record_rejects_whole_page(monkeypatch: pytest.MonkeyPatch, bad: dict[str, Any]) -> None:
    result, sent, _ = collect(monkeypatch, [{"body": {"value": [{"id": "good"}, bad]}}])
    assert len(sent) == 1 and not result.findings
    cap = result.capabilities[5]
    assert (result.status, cap.pages_completed, cap.scanned, cap.matched_filter) == ("unavailable", 0, 0, 0)
    assert [item.code for item in cap.diagnostics] == ["invalid_record"]


@pytest.mark.parametrize("status", [401, 403])
def test_permission_failure_preserves_fixed_status_without_source_body(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    result, sent, provider = collect(monkeypatch, [{"status": status, "body": {"message": "SENSITIVE_SOURCE"}}])
    assert len(sent) == 1 and provider.calls == ["retention"]
    assert result.status == "unavailable" and not result.findings
    assert result.capabilities[5].diagnostics[0].http_status == status
    assert "SENSITIVE_SOURCE" not in result.model_dump_json()


def test_missing_retention_credentials_never_fall_back(monkeypatch: pytest.MonkeyPatch) -> None:
    result, sent, provider = collect(monkeypatch, [], missing=True)
    assert not sent and provider.calls == ["retention"]
    assert result.status == "unavailable"
    assert [item.code for item in result.capabilities[5].diagnostics] == ["credentials_missing"]


def test_empty_inventory_is_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    result, sent, _ = collect(monkeypatch, [{"body": {"value": []}}])
    assert len(sent) == 1 and not result.findings
    assert result.status == "complete" and result.manifest.empty_categories == ["retention-labels"]


def test_authored_retention_fixture_records_exact_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = json.loads((FIXTURES / "retention-synthetic.json").read_text(encoding="utf-8"))
    result, sent, _ = collect(monkeypatch, fixture["pages"])
    assert fixture["kind"] == "authored-synthetic" and result.status == "complete"
    assert len(result.findings) == 3 and len(sent) == 2
    for request, page in zip(sent, fixture["pages"], strict=True):
        assert request.method == page["method"]
        assert request.url.path == page["path"]
        assert request.url.query.decode("ascii") == page["query"]
    assert [source_fields(finding) for finding in result.findings] == [
        row for page in fixture["pages"] for row in page["body"]["value"]
    ]


@pytest.mark.parametrize(("count", "status"), [(1, "complete"), (2, "partial")])
def test_retention_item_limit_preserves_only_admitted_labels(
    monkeypatch: pytest.MonkeyPatch, count: int, status: str
) -> None:
    result, sent, _ = collect(
        monkeypatch, [{"body": {"value": [{"id": str(index)} for index in range(count)]}}], max_items=1
    )
    assert len(sent) == 1 and len(result.findings) == 1
    assert source_fields(result.findings[0]) == {"id": "0"}
    assert result.status == status and result.capabilities[5].scanned == count


def test_bad_continuation_rejects_current_page_without_domain_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    result, sent, _ = collect(
        monkeypatch,
        [
            {
                "body": {
                    "value": [{"id": "unadmitted"}],
                    "@odata.nextLink": "https://attacker.invalid/v1.0/security/labels/retentionLabels",
                }
            }
        ],
    )
    assert len(sent) == 1 and not result.findings
    assert result.status == "unavailable" and result.capabilities[5].scanned == 0
    assert [item.code for item in result.capabilities[5].diagnostics] == ["unsafe_destination"]


def test_prior_page_survives_later_malformed_response(monkeypatch: pytest.MonkeyPatch) -> None:
    result, sent, _ = collect(
        monkeypatch,
        [
            {"body": {"value": [{"id": "kept"}], "@odata.nextLink": ORIGIN + PATH + "?$skiptoken=two"}},
            {"body": {"value": [{"id": "bad", "retentionDuration": []}]}},
        ],
    )
    assert len(sent) == 2 and len(result.findings) == 1
    assert result.status == "partial"
    assert source_fields(result.findings[0]) == {"id": "kept"}
    assert result.capabilities[5].pages_completed == 1
