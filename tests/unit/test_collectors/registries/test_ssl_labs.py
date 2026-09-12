"""Keep public SSL Labs lookup disabled and its dormant parser finite."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

import pytest
from evidentia_collectors.registries import ssl_labs
from evidentia_collectors.registries._client import ReadFault, RegistryReadSession
from evidentia_collectors.registries._contracts import RegistryInputError, result_bytes

FIXTURES = Path(__file__).parents[3] / "fixtures/registries/ssl_labs"
ADDRESS = "93.184.216.34"


@pytest.fixture(autouse=True)
def refuse_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: pytest.fail("unexpected DNS"))


def test_ordinary_lookup_is_disabled_before_all_io_and_projection(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("disabled lookup attempted work")

    monkeypatch.setattr(ssl_labs, "_project", forbidden)
    current = RegistryReadSession(
        {"registry": "ssl-labs", "target": {"hostname": "example.test", "endpoint_ip": ADDRESS}},
        _http_factory=forbidden,
        _tls_factory=forbidden,
        _sam_factory=forbidden,
        _sam_resolver=forbidden,
    )
    result = ssl_labs.lookup(current)
    assert result.lookup_outcome == "unavailable" and not result.observations and not result.findings
    assert {item.code for item in result.diagnostics} == {"live_disabled"}
    assert all(read.network_attempts == 0 and read.method == "DISABLED" for read in result.source_reads)
    assert result_bytes(ssl_labs.lookup(current)) == result_bytes(result)


def test_dormant_endpoint_parser_preserves_exact_selected_native_values() -> None:
    value = ssl_labs.parse_endpoint((FIXTURES / "endpoint-ready.json").read_bytes(), ADDRESS)
    assert value == {
        "ipAddress": ADDRESS,
        "statusMessage": "Ready",
        "statusDetails": "Synthetic cached endpoint",
        "grade": "A+",
        "gradeTrustIgnored": "A",
        "futureGrade": "B",
        "hasWarnings": False,
        "isExceptional": True,
        "details": {"hostStartTime": 9007199254740993},
    }
    assert type(value["details"]["hostStartTime"]) is int
    assert not {"engineVersion", "criteriaVersion", "startTime", "testTime", "cacheExpiryTime"} & value.keys()


def test_error_endpoint_preserves_literal_null_without_grade_inference() -> None:
    value = ssl_labs.parse_endpoint((FIXTURES / "endpoint-error.json").read_bytes(), ADDRESS)
    assert value == {
        "ipAddress": ADDRESS,
        "statusMessage": "Error",
        "statusDetails": "Synthetic cached error",
        "grade": None,
        "hasWarnings": True,
        "details": None,
    }


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("endpoint-cache-miss.json", "cache_miss"),
        ("endpoint-identity-mismatch.json", "identity_mismatch"),
    ],
)
def test_dormant_parser_refuses_missing_or_different_endpoint(name: str, code: str) -> None:
    with pytest.raises(ReadFault) as caught:
        ssl_labs.parse_endpoint((FIXTURES / name).read_bytes(), ADDRESS)
    assert caught.value.code == code


@pytest.mark.parametrize(
    ("key", "bad"), [("hasWarnings", 1), ("hasWarnings", "false"), ("grade", False), ("statusMessage", [])]
)
def test_no_scalar_coercion(key: str, bad: object) -> None:
    with pytest.raises(ValueError):
        ssl_labs.parse_endpoint(json.dumps({"ipAddress": ADDRESS, key: bad}).encode(), ADDRESS)


@pytest.mark.parametrize("bad", [True, 0.5, "9007199254740993"])
def test_nested_source_time_requires_a_native_integer(bad: object) -> None:
    with pytest.raises(ValueError):
        ssl_labs.parse_endpoint(json.dumps({"ipAddress": ADDRESS, "details": {"hostStartTime": bad}}).encode(), ADDRESS)


@pytest.mark.parametrize(
    "content", [b'{"ipAddress":"93.184.216.34","ipAddress":"93.184.216.35"}', b'{"x":NaN}', b'{"x":1e-999}', b"[]"]
)
def test_source_parser_refuses_ambiguous_or_non_json_shapes(content: bytes) -> None:
    with pytest.raises(ValueError):
        ssl_labs.parse_endpoint(content, ADDRESS)


def test_source_and_projection_byte_bounds_remain_enforced() -> None:
    with pytest.raises(ValueError):
        ssl_labs.parse_endpoint(b" " * 1_048_577, ADDRESS)
    with pytest.raises(ValueError):
        ssl_labs.parse_endpoint(json.dumps({"ipAddress": ADDRESS, "statusDetails": "x" * 65_536}).encode(), ADDRESS)


def test_empty_nested_object_and_null_are_distinct() -> None:
    for details in ({}, None, {"hostStartTime": None}):
        assert ssl_labs.parse_endpoint(json.dumps({"ipAddress": ADDRESS, "details": details}).encode(), ADDRESS) == {
            "ipAddress": ADDRESS,
            "details": details,
        }


def test_wrong_selector_refuses_dispatch() -> None:
    with pytest.raises(RegistryInputError):
        ssl_labs.lookup(RegistryReadSession({"registry": "tls", "target": {"hostname": "example.test"}}))
