"""Check public source adapter composition with in-memory signed metadata."""

from __future__ import annotations

import hashlib
import importlib
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from evidentia_collectors.registries._client import HttpAttempt, RegistryReadSession
from evidentia_collectors.registries._contracts import EntityTarget
from evidentia_collectors.registries._source_adapters import AdapterError, adapt_security_txt, mdq_url
from evidentia_collectors.registries._xml_signature import _TrustedCertificate
from signxml import methods
from signxml.signer import XMLSigner

NOW = datetime(2026, 9, 11, 12, tzinfo=UTC)
ENTITY = "urn:synthetic:registry:entity"


@pytest.fixture(scope="module")
def signed_metadata() -> Any:
    etree = importlib.import_module("lxml.etree")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic registry source adapter")])
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
    md = "{urn:oasis:names:tc:SAML:2.0:metadata}"
    root = etree.Element(md + "EntityDescriptor", nsmap={"md": md[1:-1]})
    root.set("ID", "synthetic-adapter-root")
    root.set("entityID", ENTITY)
    root.set("validUntil", "2026-09-12T12:00:00Z")
    organization = etree.SubElement(root, md + "Organization")
    for local, text in [
        ("OrganizationName", ""),
        ("OrganizationDisplayName", "Literal null"),
        ("OrganizationURL", "https://example.com"),
    ]:
        child = etree.SubElement(organization, md + local)
        child.set("{http://www.w3.org/XML/1998/namespace}lang", "en")
        child.text = text
    etree.SubElement(root, md + "IDPSSODescriptor")
    signed = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    ).sign(root, key=key, cert=[certificate], reference_uri="#synthetic-adapter-root", id_attribute="ID")
    return bytes(etree.tostring(signed, encoding="utf-8")), trust


def test_incommon_session_binds_real_signature_and_original_body(signed_metadata: Any) -> None:
    body, trust = cast(tuple[bytes, _TrustedCertificate], signed_metadata)

    class Response(HttpAttempt):
        def fetch(self, url: str, **kwargs: Any) -> bytes:
            assert url == mdq_url(ENTITY)
            self.status_code = 200
            kwargs["consume"](len(body), len(body))
            return body

    target = EntityTarget(entity_id=ENTITY)
    current = RegistryReadSession(
        {"registry": "incommon", "target": target},
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        _http_factory=Response,
        _xml_trust=trust,
    )
    result = current.read_incommon(target, lambda value: value)
    assert result.collection_status == "complete" and result.lookup_outcome == "found"
    read = result.source_reads[0]
    observation = result.observations[0]
    assert read.source_signature == observation.trust.source_signature == "verified"
    assert read.source_digest == hashlib.sha256(body).hexdigest()
    assert observation.fields["organization_names"] == [{"value": "", "language": "en"}]
    assert observation.fields["organization_display_names"] == [{"value": "Literal null", "language": "en"}]
    correspondence = observation.source_identity["source_correspondence"]
    assert isinstance(correspondence, dict) and correspondence["basis"] == "VerifiedEntity.xml"
    assert correspondence["verified_xml_sha256"] != read.source_digest


def test_incommon_tamper_never_reaches_projector(signed_metadata: Any) -> None:
    body, trust = cast(tuple[bytes, _TrustedCertificate], signed_metadata)
    tampered = body.replace(b"Literal null", b"Altered text")

    class Response(HttpAttempt):
        def fetch(self, url: str, **kwargs: Any) -> bytes:
            self.status_code = 200
            kwargs["consume"](len(tampered), len(tampered))
            return tampered

    target = EntityTarget(entity_id=ENTITY)
    current = RegistryReadSession(
        {"registry": "incommon", "target": target},
        _utc=lambda: NOW,
        _monotonic=lambda: 0.0,
        _http_factory=Response,
        _xml_trust=trust,
    )
    result = current.read_incommon(target, lambda value: pytest.fail("unverified source projection"))
    assert result.lookup_outcome == "unavailable" and not result.observations
    assert result.diagnostics[0].code == "signature_invalid"
    assert result.source_reads[0].source_digest == hashlib.sha256(tampered).hexdigest()


@pytest.mark.parametrize(("entity", "suffix"), [("..", "%2E%2E"), ("urn:test:%2F/é", "urn%3Atest%3A%252F%2F%C3%A9")])
def test_mdq_opaque_component_is_encoded_once(entity: str, suffix: str) -> None:
    assert mdq_url(entity) == "https://mdq.incommon.org/entities/" + suffix


def test_security_hidden_separator_does_not_create_a_contact() -> None:
    result = adapt_security_txt(
        "X-Test: value\u2028Contact: mailto:security@example.com\nExpires: 2026-09-12T12:00:00Z\n".encode(),
        "text/plain",
        NOW,
    )
    fields = result.selected["fields"]
    assert type(fields) is list and len(fields) == 2
    assert result.checks["contact_present"] is False and result.checks["syntax"] == "invalid"


@pytest.mark.parametrize(
    "mime", ["text/html", "text/plain; charset=latin1", "text/plain; charset=utf-8; charset=utf-8"]
)
def test_security_mime_refusal_is_fixed(mime: str) -> None:
    with pytest.raises(AdapterError, match=r"^media_type_unsupported$"):
        adapt_security_txt(b"Contact: mailto:security@example.com\n", mime, NOW)
