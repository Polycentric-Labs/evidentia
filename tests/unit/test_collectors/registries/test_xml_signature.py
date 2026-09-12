"""Sign synthetic XML in memory and exercise the actual verification boundary."""

from __future__ import annotations

import hashlib
import importlib
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from evidentia_collectors.registries import _xml_signature as boundary
from signxml import methods
from signxml.signer import XMLSigner

MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
DS = "{http://www.w3.org/2000/09/xmldsig#}"
EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#"
NOW = datetime(2026, 9, 11, 12, tzinfo=UTC)
ENTITY = "urn:synthetic:registry:entity"
MARKER = "synthetic-xml-source-observation"


@pytest.fixture(scope="module")
def signing() -> Any:
    etree = importlib.import_module("lxml.etree")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic registry XML test")])
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
    pem = certificate.public_bytes(serialization.Encoding.PEM)
    trust = boundary._TrustedCertificate(
        pem, hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
    )

    def make(*, expiry: str | None = "2026-09-12T12:00:00Z") -> bytes:
        root = etree.Element(MD + "EntityDescriptor", nsmap={"md": MD[1:-1]})
        root.set("ID", "synthetic-root")
        root.set("entityID", ENTITY)
        if expiry is not None:
            root.set("validUntil", expiry)
        organization = etree.SubElement(root, MD + "Organization")
        label = etree.SubElement(organization, MD + "OrganizationName")
        label.set("{http://www.w3.org/XML/1998/namespace}lang", "en")
        label.text = MARKER
        signed = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
            c14n_algorithm=EXCLUSIVE,
        ).sign(root, key=key, cert=[certificate], reference_uri="#synthetic-root", id_attribute="ID")
        return bytes(etree.tostring(signed, encoding="utf-8"))

    return make, trust


def test_real_signed_root_is_verified_and_detached(signing: Any) -> None:
    make, trust = signing
    source = make()
    result = boundary.verify_entity(source, ENTITY, NOW, _trust=trust)
    assert result.entity_id == ENTITY and result.valid_until == "2026-09-12T12:00:00Z"
    assert MARKER.encode() in result.xml and b"SignatureValue" not in result.xml
    assert source != result.xml


def test_default_production_pin_refuses_synthetic_signature(signing: Any) -> None:
    make, _ = signing
    with pytest.raises(boundary.XMLSignatureError, match=r"^signature_invalid$"):
        boundary.verify_entity(make(), ENTITY, NOW)


def test_signed_content_tampering_is_refused(signing: Any) -> None:
    make, trust = signing
    content = make().replace(MARKER.encode(), b"modified synthetic value")
    with pytest.raises(boundary.XMLSignatureError, match=r"^signature_invalid$"):
        boundary.verify_entity(content, ENTITY, NOW, _trust=trust)


@pytest.mark.parametrize(
    ("expiry", "code"),
    [
        (None, "signature_unsupported"),
        ("2026-09-11T12:00:00Z", "signature_expired"),
        ("2026-09-25T12:00:00.000001Z", "signature_expired"),
        ("2026-09-12T12:00:00.1234567Z", "signature_unsupported"),
        ("2026-09-12T12:00:00-00:00", "signature_unsupported"),
    ],
)
def test_expiry_requires_exact_supported_comparison(expiry: str | None, code: str, signing: Any) -> None:
    make, trust = signing
    with pytest.raises(boundary.XMLSignatureError, match="^" + code + "$"):
        boundary.verify_entity(make(expiry=expiry), ENTITY, NOW, _trust=trust)


@pytest.mark.parametrize("expiry", ["2026-09-25T12:00:00Z", "2026-09-12t12:00:00.123456000z"])
def test_supported_expiry_preserves_literal(expiry: str, signing: Any) -> None:
    make, trust = signing
    assert boundary.verify_entity(make(expiry=expiry), ENTITY, NOW, _trust=trust).valid_until == expiry


@pytest.mark.parametrize(
    "case",
    [
        "extra-signature",
        "duplicate-id",
        "external-reference",
        "extra-reference",
        "unknown-transform",
        "inclusive-prefixes",
        "comments",
        "object",
        "key-value",
        "missing-c14n",
    ],
)
def test_closed_signature_structure_precedes_verifier(case: str, signing: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    make, trust = signing
    etree = importlib.import_module("lxml.etree")
    root = etree.fromstring(make())
    signature = root.find(DS + "Signature")
    signed_info = signature.find(DS + "SignedInfo")
    reference = signed_info.find(DS + "Reference")
    if case == "extra-signature":
        etree.SubElement(root, DS + "Signature")
    elif case == "duplicate-id":
        root.find(MD + "Organization").set("ID", "synthetic-root")
    elif case == "external-reference":
        reference.set("URI", "https://example.org/not-fetched")
    elif case == "extra-reference":
        etree.SubElement(signed_info, DS + "Reference")
    elif case == "unknown-transform":
        reference.find(DS + "Transforms")[1].set("Algorithm", "urn:synthetic:unsupported")
    elif case == "inclusive-prefixes":
        etree.SubElement(reference.find(DS + "Transforms")[1], "{" + EXCLUSIVE + "}InclusiveNamespaces")
    elif case == "comments":
        signed_info.find(DS + "CanonicalizationMethod").set("Algorithm", EXCLUSIVE + "WithComments")
    elif case == "object":
        etree.SubElement(signature, DS + "Object")
    elif case == "key-value":
        etree.SubElement(signature.find(DS + "KeyInfo"), DS + "KeyValue")
    else:
        signed_info.remove(signed_info.find(DS + "CanonicalizationMethod"))
    calls: list[bool] = []
    monkeypatch.setattr(boundary, "_verify", lambda *args: calls.append(True))
    with pytest.raises(boundary.XMLSignatureError, match=r"^signature_unsupported$"):
        boundary.verify_entity(bytes(etree.tostring(root)), ENTITY, NOW, _trust=trust)
    assert calls == []


@pytest.mark.parametrize(
    "content",
    [b'<!DOCTYPE x [<!ENTITY source "synthetic">]><x>&source;</x>', b"<x>" * 17 + b"</x>" * 17, b" " * 1_048_577],
    ids=["dtd", "depth", "byte-limit"],
)
def test_xml_bounds_precede_lxml_verification(content: bytes, signing: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _, trust = signing
    calls: list[bool] = []
    monkeypatch.setattr(boundary, "_verify", lambda *args: calls.append(True))
    with pytest.raises(boundary.XMLSignatureError):
        boundary.verify_entity(content, ENTITY, NOW, _trust=trust)
    assert calls == []


def test_verifier_creates_no_source_bearing_log_record(
    signing: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    make, trust = signing
    content = make()
    records: list[logging.LogRecord] = []
    factory = logging.getLogRecordFactory()

    def observe(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = factory(*args, **kwargs)
        records.append(record)
        return record

    monkeypatch.setattr(logging, "_logRecordFactory", observe)
    logger = logging.getLogger("signxml.processor")
    prior = logger.level
    logger.setLevel(logging.DEBUG)
    try:
        boundary.verify_entity(content, ENTITY, NOW, _trust=trust)
    finally:
        logger.setLevel(prior)
    assert all(MARKER not in record.getMessage() for record in records)
    captured = capsys.readouterr()
    assert MARKER not in captured.out + captured.err


@pytest.mark.parametrize(
    ("root_name", "missing_name", "expected"),
    [
        ("signxml", "signxml", "missing_extra"),
        ("defusedxml", "defusedxml", "missing_extra"),
        ("signxml", "lxml", "dependency_failure"),
        ("defusedxml", "defusedxml.common", "dependency_failure"),
    ],
)
def test_precise_optional_absence(
    root_name: str, missing_name: str, expected: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = importlib.import_module

    def load(name: str, *args: Any) -> Any:
        if name == root_name:
            raise ModuleNotFoundError("synthetic import failure", name=missing_name)
        return original(name, *args)

    monkeypatch.setattr(importlib, "import_module", load)
    with pytest.raises(boundary.XMLSignatureError, match="^" + expected + "$") as raised:
        boundary.require_xml_extra()
    assert raised.value.__context__ is None


def test_primary_cancellation_is_not_replaced(signing: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    make, trust = signing
    content = make()
    cancellation = KeyboardInterrupt("synthetic cancellation")

    def cancel(*args: Any) -> Any:
        raise cancellation

    monkeypatch.setattr(boundary, "_verify", cancel)
    with pytest.raises(KeyboardInterrupt) as raised:
        boundary.verify_entity(content, ENTITY, NOW, _trust=trust)
    assert raised.value is cancellation


def test_pinned_verification_accepts_absent_key_info(signing: Any) -> None:
    make, trust = signing
    etree = importlib.import_module("lxml.etree")
    root = etree.fromstring(make())
    signature = root.find(DS + "Signature")
    signature.remove(signature.find(DS + "KeyInfo"))
    result = boundary.verify_entity(bytes(etree.tostring(root)), ENTITY, NOW, _trust=trust)
    assert result.entity_id == ENTITY


def test_broken_runtime_import_is_operational_failure(signing: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    make, trust = signing
    content = make()

    def broken(*args: Any) -> Any:
        raise ImportError("synthetic broken runtime")

    monkeypatch.setattr(boundary, "_verify", broken)
    with pytest.raises(boundary.XMLSignatureError, match=r"^dependency_failure$") as raised:
        boundary.verify_entity(content, ENTITY, NOW, _trust=trust)
    assert raised.value.__context__ is None


@pytest.mark.parametrize("case", ["duplicate-values", "root-alias", "reference-collision"])
def test_namespaced_id_aliases_never_reach_native_reference_resolution(
    case: str, signing: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    make, trust = signing
    etree = importlib.import_module("lxml.etree")
    root = etree.fromstring(make())
    organization = root.find(MD + "Organization")
    if case == "duplicate-values":
        organization.set("{urn:synthetic:alias}ID", "repeated")
        organization[0].set("{urn:synthetic:alias}ID", "repeated")
    elif case == "root-alias":
        root.set("{urn:synthetic:alias}ID", "synthetic-root")
    else:
        organization.set("{urn:synthetic:alias}ID", "synthetic-root")
    calls: list[bool] = []
    monkeypatch.setattr(boundary, "_verify", lambda *args: calls.append(True))
    with pytest.raises(boundary.XMLSignatureError, match=r"^signature_unsupported$"):
        boundary.verify_entity(bytes(etree.tostring(root)), ENTITY, NOW, _trust=trust)
    assert calls == []
