"""Refuse ungranted incident profiles uniformly before resolving credentials."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from evidentia_collectors.incident_clock import _client as source_client
from evidentia_collectors.incident_clock._profiles import ProfileStore
from fastapi.testclient import TestClient

from .test_collectors_incident_clock import AUTH, CONFIG, ROUTE, VALID, Actor, install_transport
from .test_collectors_incident_clock import clients as clients


@pytest.mark.parametrize("field,value", [("profile_alias", "other"), ("clock_alias", "other"), ("record_id", "2" * 32)])
def test_whole_selection_must_be_granted(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, field: str, value: str
) -> None:
    credentials = Mock(side_effect=AssertionError("early credential lookup"))
    monkeypatch.setattr(source_client, "resolve_material", credentials)
    response = clients(Actor(), store=ProfileStore(CONFIG)).post(ROUTE, json={**VALID, field: value}, headers=AUTH)
    assert response.status_code == 403
    assert response.json()["detail"] == {
        "error": "profile_unavailable",
        "message": "The selected collection profile is unavailable.",
    }
    credentials.assert_not_called()


def test_principal_grant_is_exact(clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch) -> None:
    credentials = Mock(side_effect=AssertionError("early credential lookup"))
    monkeypatch.setattr(source_client, "resolve_material", credentials)
    response = clients(Actor("synthetic-other"), store=ProfileStore(CONFIG)).post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 403 and response.json()["detail"]["error"] == "profile_unavailable"
    credentials.assert_not_called()


@pytest.mark.parametrize("configuration", [None, {}, "invalid", 1])
def test_missing_or_non_native_store_is_uniform(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, configuration: Any
) -> None:
    credentials = Mock(side_effect=AssertionError("early credential lookup"))
    monkeypatch.setattr(source_client, "resolve_material", credentials)
    response = clients(Actor(), store=configuration).post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 403 and response.json()["detail"]["error"] == "profile_unavailable"
    credentials.assert_not_called()


@pytest.mark.parametrize(
    "content", [None, b"{", b" " * 65537, b"{}"], ids=["missing", "malformed", "oversized", "empty-store"]
)
def test_bad_profile_file_is_lazy_and_uniform(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: bytes | None
) -> None:
    target = tmp_path / "private-profile.json"
    if content is not None:
        target.write_bytes(content)
    monkeypatch.setenv("EVIDENTIA_INCIDENT_CLOCK_PROFILES_FILE", str(target))
    credentials = Mock(side_effect=AssertionError("early credential lookup"))
    monkeypatch.setattr(source_client, "resolve_material", credentials)
    application = clients(Actor())
    response = application.post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 403 and response.json()["detail"]["error"] == "profile_unavailable"
    assert str(target) not in response.text
    credentials.assert_not_called()


def test_profile_file_load_follows_authentication_and_request_validation(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidentia_api.routers import incident_clock

    loaded = Mock(side_effect=AssertionError("unexpected file read"))
    monkeypatch.setattr(incident_clock, "load_profile_store", loaded)
    monkeypatch.setenv("EVIDENTIA_INCIDENT_CLOCK_PROFILES_FILE", "not-read.json")
    assert clients().post(ROUTE, json=VALID, headers=AUTH).status_code == 403
    assert (
        clients(Actor()).post(ROUTE, content=b"{", headers={**AUTH, "Content-Type": "application/json"}).status_code
        == 400
    )
    loaded.assert_not_called()


def test_valid_file_supports_collection_without_startup_io(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    application = clients(Actor())
    target = tmp_path / "profiles.json"
    target.write_text(json.dumps(CONFIG), encoding="utf-8")
    monkeypatch.setenv("EVIDENTIA_INCIDENT_CLOCK_PROFILES_FILE", str(target))
    calls = install_transport(monkeypatch)
    response = application.post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 200 and response.json()["source_state"] == "complete" and len(calls) == 1


def test_missing_credential_is_authorized_unavailable_result(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = install_transport(monkeypatch, mode="unavailable")
    response = clients(Actor(), store=ProfileStore(CONFIG)).post(ROUTE, json=VALID, headers=AUTH)
    assert response.status_code == 200 and response.json()["source_state"] == "unavailable" and calls == []


def test_injected_store_detaches_mutable_configuration(
    clients: Callable[..., TestClient], monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = copy.deepcopy(CONFIG)
    store = ProfileStore(raw)
    raw["profiles"].clear()
    install_transport(monkeypatch)
    assert clients(Actor(), store=store).post(ROUTE, json=VALID, headers=AUTH).status_code == 200
