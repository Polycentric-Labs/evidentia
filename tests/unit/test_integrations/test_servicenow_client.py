"""Unit tests for ``evidentia_integrations.servicenow.client``.

Uses ``httpx.MockTransport`` — no real ServiceNow instance.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from evidentia_integrations.servicenow.client import (
    ServiceNowApiError,
    ServiceNowClient,
    ServiceNowRecord,
)
from evidentia_integrations.servicenow.config import ServiceNowConfig


def _config(table_name: str = "incident") -> ServiceNowConfig:
    return ServiceNowConfig(
        instance_url="https://acme.service-now.com",
        user="evidentia.bot",
        password="hunter2",
        table_name=table_name,
    )


def _client(
    handler: Any,
    *,
    table_name: str = "incident",
) -> ServiceNowClient:
    """Build a ServiceNowClient backed by a MockTransport."""
    cfg = _config(table_name)
    transport = httpx.MockTransport(handler)
    http = httpx.Client(
        base_url=cfg.instance_url,
        transport=transport,
        headers={"Authorization": "Basic test"},
    )
    return ServiceNowClient(cfg, http=http)


# ── ServiceNowApiError ──────────────────────────────────────────────


def test_api_error_carries_status_and_message() -> None:
    err = ServiceNowApiError(
        "POST /api/now/table/incident",
        status_code=403,
        error_message="Insufficient privileges",
    )
    assert err.status_code == 403
    assert "403" in str(err)
    assert "Insufficient privileges" in str(err)


# ── Config validation ──────────────────────────────────────────────


def test_config_rejects_http_scheme() -> None:
    with pytest.raises(ValueError, match="must use https"):
        ServiceNowConfig(
            instance_url="http://insecure.example.com",
            user="u",
            password="p",
        )


def test_config_strips_trailing_slash() -> None:
    cfg = ServiceNowConfig(
        instance_url="https://acme.service-now.com/",
        user="u",
        password="p",
    )
    assert cfg.instance_url == "https://acme.service-now.com"


def test_config_excludes_password_from_dump() -> None:
    cfg = _config()
    dump = cfg.model_dump()
    assert "password" not in dump
    # Should still be reachable in-memory
    assert cfg.password == "hunter2"


def test_config_default_table_is_incident() -> None:
    cfg = _config()
    assert cfg.table_name == "incident"


# ── Client / Table API ──────────────────────────────────────────────


def test_create_record_returns_typed_record() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/api/now/table/incident"
        return httpx.Response(
            201,
            json={
                "result": {
                    "sys_id": "abc123",
                    "number": "INC0010001",
                    "short_description": "Test",
                    "state": "1",
                }
            },
        )

    client = _client(handler)
    record = client.create_record(fields={"short_description": "Test"})
    assert isinstance(record, ServiceNowRecord)
    assert record.sys_id == "abc123"
    assert record.number == "INC0010001"
    assert "abc123" in record.url


def test_create_record_handles_403() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={"error": {"message": "ACL denied write to incident"}},
        )

    client = _client(handler)
    with pytest.raises(ServiceNowApiError) as exc_info:
        client.create_record(fields={})
    assert exc_info.value.status_code == 403
    assert "ACL denied" in str(exc_info.value)


def test_test_connection_probes_table() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"result": []})

    client = _client(handler)
    info = client.test_connection()
    assert info["instance_url"] == "https://acme.service-now.com"
    assert info["table_name"] == "incident"
    assert len(captured) == 1
    assert "sysparm_limit" in str(captured[0].url)


def test_get_record() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/abc123")
        return httpx.Response(
            200,
            json={
                "result": {
                    "sys_id": "abc123",
                    "number": "INC0010001",
                    "short_description": "Existing",
                    "state": "2",
                }
            },
        )

    client = _client(handler)
    record = client.get_record("abc123")
    assert record.number == "INC0010001"
    assert record.state == "2"


def test_find_existing_by_correlation_returns_record_when_present() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # The query string should embed the correlation_id (URL-encoded)
        assert "correlation_id" in str(request.url)
        assert "evidentia-gap-x123" in str(request.url)
        return httpx.Response(
            200,
            json={
                "result": [
                    {
                        "sys_id": "abc123",
                        "number": "INC0010001",
                        "short_description": "...",
                        "state": "1",
                    }
                ]
            },
        )

    client = _client(handler)
    record = client.find_existing_by_correlation(correlation_id="evidentia-gap-x123")
    assert record is not None
    assert record.sys_id == "abc123"


def test_find_existing_by_correlation_returns_none_when_empty() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": []})

    client = _client(handler)
    record = client.find_existing_by_correlation(correlation_id="evidentia-gap-nope")
    assert record is None


def test_custom_table_name_used_in_request_paths() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            201,
            json={"result": {"sys_id": "x", "number": "GRC0001"}},
        )

    client = _client(handler, table_name="sn_grc_issue")
    client.create_record(fields={})
    assert captured[0].url.path == "/api/now/table/sn_grc_issue"
