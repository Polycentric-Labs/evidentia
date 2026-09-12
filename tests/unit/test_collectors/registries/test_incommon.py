"""Project only actual verified roots from synthetic in-memory signatures."""

from __future__ import annotations

import hashlib
import importlib
import json
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from evidentia_collectors.registries import _client, incommon
from evidentia_collectors.registries._client import HttpAttempt, RegistryReadSession
from evidentia_collectors.registries._contracts import RegistryInputError, result_bytes
from evidentia_collectors.registries._xml_signature import XMLSignatureError, _TrustedCertificate
from signxml import methods
from signxml.signer import XMLSigner

FIXTURES = Path(__file__).parents[3] / "fixtures/registries/incommon"
NOW = datetime(2026, 9, 11, 12, tzinfo=UTC)
ENTITY = "urn:synthetic:owner-c:entity"
MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#"


@pytest.fixture(autouse=True)
def refuse_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: pytest.fail("unexpected DNS"))


@pytest.fixture(scope="module")
def signer() -> Any:
    etree = importlib.import_module("lxml.etree")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic owner C test signer")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=20))
        .sign(key, hashes.SHA256())
    )
    trust = _TrustedCertificate(
        certificate.public_bytes(serialization.Encoding.PEM),
        hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest(),
    )

    def sign(content: bytes) -> bytes:
        element = etree.fromstring(content)
        signed = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
            c14n_algorithm=EXCLUSIVE,
        ).sign(element, key=key, cert=[certificate], reference_uri="#" + element.get("ID"), id_attribute="ID")
        return bytes(etree.tostring(signed, encoding="utf-8"))

    return sign, trust


def session(
    content: bytes, trust: _TrustedCertificate | None, entity: str = ENTITY
) -> tuple[RegistryReadSession, list[str]]:
    calls: list[str] = []

    class SyntheticHTTP(HttpAttempt):
        def fetch(self, url: str, **kwargs: Any) -> bytes:
            calls.append(url)
            kwargs["consume"](len(content), len(content))
            self.status_code = 200
            return content

    return RegistryReadSession(
        {"registry": "incommon", "target": {"entity_id": entity}},
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        _http_factory=SyntheticHTTP,
        _xml_trust=trust,
        _sam_resolver=lambda reference: pytest.fail("unexpected registry credentials"),
    ), calls


def expected_fields() -> dict[str, Any]:
    return {
        "entityID": ENTITY,
        "validUntil": "2026-09-12T12:00:00.123456Z",
        "cacheDuration": "PT6H",
        "organization_names": [
            {"value": "Example Research", "language": "en"},
            {"value": "Exemple Recherche", "language": "fr"},
        ],
        "organization_display_names": [
            {"value": "Example Display", "language": "en"},
            {"value": "", "language": "fr"},
        ],
        "registration_info": [
            {
                "registrationAuthority": "urn:synthetic:registration:authority",
                "registrationInstant": "2026-08-01T01:02:03.123456789Z",
            }
        ],
        "role_descriptors": [MD + "IDPSSODescriptor", MD + "SPSSODescriptor"],
    }


def test_verified_adapter_preserves_all_selected_values_and_source_positions(signer: Any) -> None:
    sign, trust = signer
    content = sign((FIXTURES / "entity.xml").read_bytes())
    current, calls = session(content, trust)
    result = incommon.lookup(current)
    assert result.lookup_outcome == "found" and result.collection_status == "complete"
    assert calls == ["https://mdq.incommon.org/entities/urn%3Asynthetic%3Aowner-c%3Aentity"]
    observation = result.observations[0]
    assert observation.fields == expected_fields() and observation.trust.source_signature == "verified"
    assert observation.trust.transport_verified is True
    correspondence = observation.source_identity["source_correspondence"]
    assert isinstance(correspondence, dict)
    assert correspondence["basis"] == "VerifiedEntity.xml"
    times = {item.path: item for item in observation.source_times}
    assert times["/validUntil"].normalized_utc == "2026-09-12T12:00:00.123456Z"
    assert times["/registration_info/0/registrationInstant"].literal == "2026-08-01T01:02:03.123456789Z"
    assert times["/registration_info/0/registrationInstant"].normalized_utc is None
    serialized = result_bytes(result)
    assert b"Synthetic excluded contact" not in serialized and b"OrganizationURL" not in serialized
    assert json.loads(serialized)["findings"][0]["raw_data"]["observation"]["fields"] == expected_fields()
    assert "membership assessment is not performed" in observation.interpretation


def test_partner_registration_does_not_establish_membership(signer: Any) -> None:
    sign, trust = signer
    current, _ = session(sign((FIXTURES / "partner-entity.xml").read_bytes()), trust, "urn:synthetic:owner-c:partner")
    result = incommon.lookup(current)
    assert result.lookup_outcome == "found" and result.observations[0].trust.source_signature == "verified"
    assert result.observations[0].fields["registration_info"] == [
        {
            "registrationAuthority": "urn:synthetic:registration:partner",
            "registrationInstant": "2026-08-01T01:02:03.123456789Z",
        }
    ]
    assert "membership assessment is not performed" in result.observations[0].interpretation


@pytest.mark.parametrize(
    ("name", "signed", "code"),
    [
        ("unsigned-entity.xml", False, "signature_missing"),
        ("expired-entity.xml", True, "signature_expired"),
        ("duplicate-target.xml", True, "identity_mismatch"),
    ],
)
def test_invalid_source_never_reaches_domain_projection(
    name: str, signed: bool, code: str, signer: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    sign, trust = signer
    raw = (FIXTURES / name).read_bytes()
    monkeypatch.setattr(incommon, "_project", lambda value: pytest.fail("unverified projection"))
    current, _ = session(sign(raw) if signed else raw, trust)
    result = incommon.lookup(current)
    assert result.lookup_outcome == "unavailable" and not result.observations
    assert code in {item.code for item in result.diagnostics}


def test_tamper_wrong_entity_and_default_production_pin_are_refused(signer: Any) -> None:
    sign, trust = signer
    content = sign((FIXTURES / "entity.xml").read_bytes())
    for raw, capability, entity, code in (
        (content.replace(b"Example Display", b"Tampered Display"), trust, ENTITY, "signature_invalid"),
        (content, trust, "urn:synthetic:other:entity", "identity_mismatch"),
        (content, None, ENTITY, "signature_invalid"),
    ):
        current, _ = session(raw, capability, entity)
        result = incommon.lookup(current)
        assert result.lookup_outcome == "unavailable" and not result.observations
        assert code in {item.code for item in result.diagnostics}


def test_projector_receives_only_verified_selected_values(signer: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    sign, trust = signer
    views: list[dict[str, Any]] = []
    original = incommon._project

    def record(value: dict[str, Any]) -> dict[str, Any]:
        views.append(value)
        return original(value)

    monkeypatch.setattr(incommon, "_project", record)
    current, _ = session(sign((FIXTURES / "entity.xml").read_bytes()), trust)
    assert incommon.lookup(current).lookup_outcome == "found"
    assert views == [expected_fields()]


def test_reordered_selected_values_fail_correspondence(signer: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    sign, trust = signer
    original = incommon._project

    def reorder(value: dict[str, Any]) -> dict[str, Any]:
        selected = original(value)
        selected["organization_names"].reverse()
        return selected

    monkeypatch.setattr(incommon, "_project", reorder)
    current, _ = session(sign((FIXTURES / "entity.xml").read_bytes()), trust)
    result = incommon.lookup(current)
    assert not result.observations and "projection_mismatch" in {item.code for item in result.diagnostics}


@pytest.mark.parametrize("code", ["missing_extra", "dependency_failure"])
def test_optional_failure_precedes_http_factory(code: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse_extra() -> None:
        raise XMLSignatureError(code)

    monkeypatch.setattr(_client, "require_xml_extra", refuse_extra)
    current = RegistryReadSession(
        {"registry": "incommon", "target": {"entity_id": ENTITY}},
        _http_factory=lambda: pytest.fail("unexpected HTTP creation"),
    )
    result = incommon.lookup(current)
    assert result.lookup_outcome == "unavailable" and {item.code for item in result.diagnostics} == {code}


def test_projection_keeps_absence_and_detaches_localized_arrays() -> None:
    value: dict[str, Any] = {
        "entityID": ENTITY,
        "validUntil": "2026-09-12T12:00:00Z",
        "role_descriptors": [],
        "organization_names": [{"value": "", "language": "en", "unselected": "ignored"}],
        "ignored": 1,
    }
    selected = incommon._project(value)
    assert selected == {
        "entityID": ENTITY,
        "validUntil": "2026-09-12T12:00:00Z",
        "role_descriptors": [],
        "organization_names": [{"value": "", "language": "en"}],
    }
    selected["organization_names"][0]["value"] = "changed"
    assert value["organization_names"][0]["value"] == ""


def test_wrong_selector_refuses_dispatch() -> None:
    with pytest.raises(RegistryInputError):
        incommon.lookup(RegistryReadSession({"registry": "tls", "target": {"hostname": "example.test"}}))
