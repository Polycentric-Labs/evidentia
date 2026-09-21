"""Actual optional release import classification and authorization precedence."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from evidentia_api.routers import release_cadence as route
from evidentia_core.rbac import RBACPolicy
from fastapi.testclient import TestClient

from tests.unit.test_api.test_release_cadence_authority import POLL, SERIES, make_app, request_value


@pytest.mark.parametrize(
    "missing,spec_absent,expected",
    [
        ("evidentia_collectors", True, (503, "support_unavailable")),
        ("evidentia_collectors.release_cadence", True, (503, "support_unavailable")),
        ("evidentia_collectors", False, (500, "support_broken")),
        ("httpx", True, (500, "support_broken")),
        ("evidentia_collectors.release_cadence.collector", True, (500, "support_broken")),
    ],
)
def test_exact_module_absence_is_independently_proved(monkeypatch, missing, spec_absent, expected):
    app = make_app(monkeypatch)
    calls = []

    def importing(name):
        calls.append(name)
        raise ModuleNotFoundError("synthetic missing module", name=missing)

    monkeypatch.setattr(route.importlib, "import_module", importing)
    monkeypatch.setattr(route.importlib.util, "find_spec", lambda name: None if spec_absent else object())
    result = TestClient(app).post(POLL, json=request_value())
    assert (result.status_code, result.json()["code"]) == expected
    assert calls == ["evidentia_collectors.release_cadence.collector"]
    assert POLL in app.openapi()["paths"] and SERIES in app.openapi()["paths"]


@pytest.mark.parametrize(
    "fault",
    [
        ImportError("synthetic"),
        RuntimeError("synthetic"),
        SimpleNamespace(),
        SimpleNamespace(_prepare_poll_from_clock=None),
    ],
)
def test_broken_exports_never_become_unavailable(monkeypatch, fault):
    app = make_app(monkeypatch)

    def importing(name):
        if isinstance(fault, Exception):
            raise fault
        return fault

    monkeypatch.setattr(route.importlib, "import_module", importing)
    result = TestClient(app).post(POLL, json=request_value())
    assert result.status_code == 500 and result.json()["code"] == "support_broken"


@pytest.mark.parametrize(
    "provider,role,persist,status",
    [(False, "admin", False, 403), (True, "deny", False, 403), (True, "reader", True, 403)],
)
def test_no_support_disclosure_before_actual_authority(monkeypatch, provider, role, persist, status):
    app = make_app(monkeypatch, policy=RBACPolicy(default_role=role), provider=provider)

    def forbidden():
        raise AssertionError("Optional support must not be inspected on denial.")

    monkeypatch.setattr(route, "_load_poll", forbidden)
    result = TestClient(app).post(POLL, json=request_value(persist=persist))
    assert result.status_code == status


def test_offline_series_has_no_optional_collector_dependency(monkeypatch, tmp_path):
    app = make_app(monkeypatch)
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path))

    def forbidden():
        raise AssertionError("Offline series uses only Core.")

    monkeypatch.setattr(route, "_load_poll", forbidden)
    result = TestClient(app).post(SERIES, json=request_value(series=True))
    assert result.status_code == 200 and result.json()["state"] == "insufficient"


def test_support_status_reports_broken_separately(monkeypatch):
    from evidentia_core.release_cadence._limits import ReleaseFailure

    def absent():
        raise ReleaseFailure("support_unavailable")

    monkeypatch.setattr(route, "_load_poll", absent)
    assert route.configuration_status() == {"installed": False, "state": "absent"}

    def broken():
        raise ReleaseFailure("support_broken")

    monkeypatch.setattr(route, "_load_poll", broken)
    assert route.configuration_status() == {"installed": False, "state": "broken"}
