"""Check selected TLS fields through one instrumented, verified handshake."""

from __future__ import annotations

import base64
import copy
import json
import socket
import ssl
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from evidentia_collectors.registries import _tls, tls
from evidentia_collectors.registries._client import RegistryReadSession
from evidentia_collectors.registries._contracts import RegistryInputError
from evidentia_core import network_guard

FIXTURES = Path(__file__).parents[3] / "fixtures/registries/tls"
NOW = datetime(2026, 9, 12, 12, tzinfo=UTC)


def fixture(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((FIXTURES / name).read_bytes().replace(b"\r\n", b"\n")))


def native_tuple(value: Any) -> Any:
    return tuple(native_tuple(item) for item in value) if type(value) is list else value


@pytest.fixture
def handshake(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    state: dict[str, Any] = {"source": fixture("verified.json"), "events": [], "failure": None, "dns": []}
    original = socket.getaddrinfo
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", original)

    def resolve(*args: Any, **kwargs: Any) -> list[Any]:
        state["dns"].append(args[0])
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)

    class RawSocket:
        def settimeout(self, value: float) -> None:
            assert 0 < value <= 5

        def connect(self, value: object) -> None:
            state["events"].append(("connect", value))

        def close(self) -> None:
            state["events"].append(("close", "raw"))

    class SecureSocket(RawSocket):
        def do_handshake(self) -> None:
            state["events"].append(("handshake", None))
            if state["failure"] is not None:
                raise state["failure"]

        def getpeercert(self, binary_form: bool = False) -> Any:
            state["events"].append(("certificate", binary_form))
            if binary_form:
                return base64.b64decode(state["source"]["fixture_public_der_base64"], validate=True)
            value = state["source"]["certificate"]
            return None if value is None else {name: native_tuple(part) for name, part in value.items()}

        def cipher(self) -> Any:
            value = state["source"]["cipher"]
            return None if value is None else (value["name"], value["protocol"], value["secret_bits"])

        def getpeername(self) -> tuple[str, int]:
            return "93.184.216.34", 443

        def version(self) -> str | None:
            return cast(str | None, state["source"]["protocol"])

        def close(self) -> None:
            state["events"].append(("close", "tls"))

    raw, secured = RawSocket(), SecureSocket()
    monkeypatch.setattr(_tls, "_first_socket", lambda approved: (cast(socket.socket, raw), ("93.184.216.34", 443)))
    original_context = _tls.tls_context

    def context() -> ssl.SSLContext:
        configured = original_context()
        assert configured.verify_mode == ssl.CERT_REQUIRED and configured.check_hostname
        assert configured.keylog_filename is None

        def wrap(sock: object, *, server_hostname: str, do_handshake_on_connect: bool) -> ssl.SSLSocket:
            assert sock is raw and do_handshake_on_connect is False
            state["events"].append(("sni", server_hostname))
            return cast(ssl.SSLSocket, secured)

        monkeypatch.setattr(configured, "wrap_socket", wrap)
        return configured

    monkeypatch.setattr(_tls, "tls_context", context)
    with network_guard.offline_mode(False):
        yield state


def session(hostname: str = "example.org") -> RegistryReadSession:
    return RegistryReadSession(
        {"registry": "tls", "target": {"hostname": hostname}}, _utc=lambda: NOW, _monotonic=lambda: 0.0
    )


def expected_verified() -> dict[str, Any]:
    return {
        "protocol": "TLSv1.3",
        "cipher": {"name": "TLS_AES_128_GCM_SHA256", "protocol": "TLSv1.3", "secret_bits": 128},
        "peer_address": "93.184.216.34",
        "der_sha256": fixture("verified.json")["der_sha256"],
        "certificate": {
            "subject": [[["commonName", "example.org"]]],
            "issuer": [[["commonName", "example.org"]]],
            "subjectAltName": [["DNS", "example.org"], ["DNS", "www.example.org"]],
            "notBefore": "Sep  1 00:00:00 2026 GMT",
            "notAfter": "Oct  1 00:00:00 2026 GMT",
        },
    }


def test_projector_selects_named_fields_and_detaches_nested_values() -> None:
    source = fixture("verified.json")
    projected = tls.project_tls(source)
    assert projected == expected_verified()
    projected["certificate"]["subject"][0][0][1] = "changed"
    assert source["certificate"]["subject"][0][0][1] == "example.org"
    assert "fixture_public_der_base64" not in projected


@pytest.mark.parametrize("hostname", ["example.org", "EXAMPLE.ORG", "EXAMPLE.ORG."])
def test_one_verified_negotiation_retains_original_request(hostname: str, handshake: dict[str, Any]) -> None:
    current = session(hostname)
    result = tls.lookup(current)
    assert result.lookup_outcome == "found" and result.collection_status == "complete"
    assert result.request.model_dump(mode="json")["target"]["hostname"] == hostname
    assert result.diagnostics == []
    observation = result.observations[0]
    assert observation.fields == expected_verified()
    assert observation.source_identity == {"hostname": "example.org"}
    assert observation.matched_identity == "example.org"
    assert observation.trust.transport_verified is True
    assert observation.trust.source_signature == "not_applicable"
    assert observation.field_coverage["/certificate/notAfter"] == "present"
    assert [
        (time.path, time.literal, time.representation, time.normalized_utc) for time in observation.source_times
    ] == [
        ("/certificate/notBefore", "Sep  1 00:00:00 2026 GMT", "source_text", None),
        ("/certificate/notAfter", "Oct  1 00:00:00 2026 GMT", "source_text", None),
    ]
    read = result.source_reads[0]
    assert read.network_attempts == 1 and read.raw_bytes is None and read.decoded_bytes is None
    assert read.source_digest == fixture("verified.json")["der_sha256"]
    assert [event for event in handshake["events"] if event[0] == "sni"] == [("sni", "example.org")]
    assert len([event for event in handshake["events"] if event[0] == "handshake"]) == 1
    assert handshake["events"][-2:] == [("close", "tls"), ("close", "raw")]
    serialized = result.model_dump(mode="json")
    assert serialized["findings"][0]["raw_data"]["observation"] == serialized["observations"][0]
    assert serialized["findings"][0]["severity"] == "informational"
    assert serialized["findings"][0]["compliance_status"] == "unknown"
    assert serialized["findings"][0]["control_mappings"] == []
    assert "supported_protocols" not in observation.fields
    assert tls.lookup(current).model_dump(mode="json") == serialized
    assert len([event for event in handshake["events"] if event[0] == "handshake"]) == 1


@pytest.mark.parametrize("condition", ["expired", "wrong_host"])
def test_certificate_validation_failure_never_retries_insecurely(condition: str, handshake: dict[str, Any]) -> None:
    failure = fixture("certificate-failure.json")
    assert condition in failure["conditions"]
    handshake["failure"] = ssl.SSLCertVerificationError("synthetic " + condition)
    result = tls.lookup(session())
    assert result.lookup_outcome == "unavailable" and not result.observations and not result.findings
    assert [item.code for item in result.diagnostics] == [failure["expected_diagnostic"]]
    assert result.source_reads[0].source_digest is None
    assert len([event for event in handshake["events"] if event[0] == "handshake"]) == 1
    assert not [event for event in handshake["events"] if event[0] == "certificate"]
    assert handshake["events"][-2:] == [("close", "tls"), ("close", "raw")]


def test_unavailable_cipher_details_stay_null(handshake: dict[str, Any]) -> None:
    handshake["source"] = fixture("unknown-cipher.json")
    result = tls.lookup(session())
    assert result.lookup_outcome == "found"
    fields = result.observations[0].fields
    assert fields["protocol"] is None and fields["cipher"] is None and fields["certificate"] is None
    assert result.observations[0].field_coverage["/cipher"] == "null"
    assert result.observations[0].field_coverage["/cipher/name"] == "unknown"


def test_cancellation_keeps_identity_and_closes_owned_sockets(handshake: dict[str, Any]) -> None:
    cancellation = KeyboardInterrupt("synthetic cancellation")
    handshake["failure"] = cancellation
    with pytest.raises(KeyboardInterrupt) as caught:
        tls.lookup(session())
    assert caught.value is cancellation
    assert handshake["events"][-2:] == [("close", "tls"), ("close", "raw")]


def test_offline_refusal_precedes_dns(handshake: dict[str, Any]) -> None:
    with network_guard.offline_mode():
        result = tls.lookup(session())
    assert result.lookup_outcome == "unavailable"
    assert [item.code for item in result.diagnostics] == ["offline_refused"]
    assert result.source_reads[0].network_attempts == 0
    assert handshake["dns"] == [] and handshake["events"] == []


def test_wrong_selector_refuses_before_any_handshake(handshake: dict[str, Any]) -> None:
    current = RegistryReadSession({"registry": "gleif", "target": {"lei": "A" * 20}})
    with pytest.raises(RegistryInputError):
        tls.lookup(current)
    assert handshake["events"] == []


def test_absent_and_empty_certificate_are_distinct() -> None:
    source = fixture("verified.json")
    source.pop("certificate")
    without = tls.project_tls(source)
    assert "certificate" not in without
    empty = copy.deepcopy(source)
    empty["certificate"] = {}
    assert tls.project_tls(empty)["certificate"] == {}


def test_generic_tls_failure_stays_distinct_from_certificate_verification(handshake: dict[str, Any]) -> None:
    handshake["failure"] = ssl.SSLError("synthetic generic TLS failure marker")
    result = tls.lookup(session())
    assert result.lookup_outcome == "unavailable" and not result.observations
    assert [item.code for item in result.diagnostics] == ["tls_failure"]
    assert "synthetic generic TLS failure marker" not in result.model_dump_json()
    assert len([event for event in handshake["events"] if event[0] == "handshake"]) == 1
    assert not [event for event in handshake["events"] if event[0] == "certificate"]
    assert handshake["events"][-2:] == [("close", "tls"), ("close", "raw")]
