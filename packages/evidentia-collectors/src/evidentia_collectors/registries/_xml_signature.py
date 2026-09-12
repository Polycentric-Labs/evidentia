"""Verify the supported InCommon signature subset before exposing signed XML."""

from __future__ import annotations

import base64
import hashlib
import importlib
import importlib.metadata
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta
from importlib import resources
from typing import Any, Literal, cast

from evidentia_collectors.retention._parsing import parse_strict_xml

from ._contracts import EntityTarget, clock_text, normalized_source_time
from ._parsing import parse_strict_json

_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
_DS = "http://www.w3.org/2000/09/xmldsig#"
_EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#"
_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_PRODUCTION_DER = "604974d61fe0d7f4d63d6c8db98a857e642ab9b470e3e85dd54d663d0496f900"
_PRODUCTION_PEM = "d7452bc2ddc24e9aa49554aa7a6045e4026be045d0dfd18d408959442816a2f3"
_LIMIT = 1_048_576

XMLFailure = Literal[
    "missing_extra",
    "dependency_failure",
    "signature_missing",
    "signature_invalid",
    "signature_unsupported",
    "signature_expired",
    "identity_mismatch",
]


class XMLSignatureError(ValueError):
    def __init__(self, code: XMLFailure = "signature_invalid") -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class _TrustedCertificate:
    """Private controller capability; public requests never accept trust material."""

    pem: bytes
    der_sha256: str


@dataclass(frozen=True)
class VerifiedEntity:
    """Only the verifier-returned signed root, detached from mutable lxml state."""

    xml: bytes
    entity_id: str
    valid_until: str


def require_xml_extra() -> None:
    """Allow only exact absent optional roots to mean an uninstalled extra."""
    failure: XMLFailure | None = None
    for name in ("defusedxml", "signxml"):
        try:
            importlib.import_module(name)
        except ModuleNotFoundError as error:
            failure = "missing_extra" if error.name == name else "dependency_failure"
        except Exception:
            failure = "dependency_failure"
        if failure is not None:
            raise XMLSignatureError(failure)
    try:
        if importlib.metadata.version("signxml") != "5.1.0":
            failure = "dependency_failure"
        importlib.import_module("lxml.etree")
    except Exception:
        failure = "dependency_failure"
    if failure is not None:
        raise XMLSignatureError(failure)


def _production_certificate() -> _TrustedCertificate:
    path = resources.files("evidentia_collectors.registries").joinpath(
        "data/incommon/production-signing-certificate.json"
    )
    with path.open("rb") as stream:
        raw = stream.read(16_385)
    if len(raw) > 16_384:
        raise XMLSignatureError()
    value = parse_strict_json(raw)
    if type(value) is not dict:
        raise XMLSignatureError()
    pem = value["certificate_pem"]
    if (
        type(pem) is not str
        or not pem.isascii()
        or hashlib.sha256(pem.encode("ascii")).hexdigest() != _PRODUCTION_PEM
        or value["pem_sha256"] != _PRODUCTION_PEM
        or value["der_sha256"] != _PRODUCTION_DER
    ):
        raise XMLSignatureError()
    return _TrustedCertificate(pem.encode("ascii"), _PRODUCTION_DER)


def _children(element: ET.Element, names: tuple[str, ...], attributes: set[str] | None = None) -> None:
    if (
        set(element.attrib) != (attributes or set())
        or tuple(child.tag for child in element) != tuple("{" + _DS + "}" + name for name in names)
        or (element.text is not None and element.text.strip())
        or any(child.tail is not None and child.tail.strip() for child in element)
    ):
        raise XMLSignatureError("signature_unsupported")


def _algorithm(element: ET.Element, expected: str) -> None:
    _children(element, (), {"Algorithm"})
    if element.get("Algorithm") != expected:
        raise XMLSignatureError("signature_unsupported")


def _encoded(element: ET.Element, *, size: int | None = None) -> bytes:
    if element.attrib or len(element) or element.text is None:
        raise XMLSignatureError("signature_unsupported")
    value = "".join(element.text.split())
    if not value.isascii() or len(value) > 16_384:
        raise XMLSignatureError("signature_unsupported")
    decoded = base64.b64decode(value, validate=True)
    if not decoded or (size is not None and len(decoded) != size):
        raise XMLSignatureError()
    return decoded


def _structure(root: ET.Element, entity_id: str) -> bytes | None:
    if root.tag != "{" + _MD + "}EntityDescriptor" or root.get("entityID") != entity_id:
        raise XMLSignatureError("identity_mismatch")
    identifier = root.get("ID")
    if not identifier or any(char.isspace() or char in "#()" for char in identifier):
        raise XMLSignatureError("signature_unsupported")
    ids: set[str] = set()
    signatures: list[ET.Element] = []
    for element in root.iter():
        if element.tag in {"{" + _DS + "}Object", "{" + _DS + "}Manifest"}:
            raise XMLSignatureError("signature_unsupported")
        if element.tag == "{" + _DS + "}Signature":
            signatures.append(element)
        for name, value in element.attrib.items():
            if name.rsplit("}", 1)[-1] in {"ID", "Id", "id"}:
                if name not in {"ID", "Id", "id", "{http://www.w3.org/XML/1998/namespace}id"}:
                    raise XMLSignatureError("signature_unsupported")
                if not value or value in ids:
                    raise XMLSignatureError("signature_unsupported")
                ids.add(value)
    if not signatures:
        raise XMLSignatureError("signature_missing")
    if len(signatures) != 1 or signatures[0] not in list(root):
        raise XMLSignatureError("signature_unsupported")
    signature = signatures[0]
    names = ("SignedInfo", "SignatureValue", "KeyInfo") if len(signature) == 3 else ("SignedInfo", "SignatureValue")
    _children(signature, names)
    if len(signature) not in (2, 3):
        raise XMLSignatureError("signature_unsupported")
    signed_info = signature[0]
    _children(signed_info, ("CanonicalizationMethod", "SignatureMethod", "Reference"))
    _algorithm(signed_info[0], _EXCLUSIVE)
    _algorithm(signed_info[1], _RSA_SHA256)
    reference = signed_info[2]
    _children(reference, ("Transforms", "DigestMethod", "DigestValue"), {"URI"})
    if reference.get("URI") != "#" + identifier:
        raise XMLSignatureError("signature_unsupported")
    _children(reference[0], ("Transform", "Transform"))
    _algorithm(reference[0][0], _DS + "enveloped-signature")
    _algorithm(reference[0][1], _EXCLUSIVE)
    _algorithm(reference[1], _SHA256)
    _encoded(reference[2], size=32)
    _encoded(signature[1])
    if len(signature) == 2:
        return None
    _children(signature[2], ("X509Data",))
    _children(signature[2][0], ("X509Certificate",))
    return _encoded(signature[2][0][0])


def _certificate(trust: _TrustedCertificate, observed_at: datetime) -> Any:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    if (
        type(trust) is not _TrustedCertificate
        or type(trust.pem) is not bytes
        or len(trust.pem) > 16_384
        or type(trust.der_sha256) is not str
        or len(trust.der_sha256) != 64
    ):
        raise XMLSignatureError()
    certificate = x509.load_pem_x509_certificate(trust.pem)
    if certificate.fingerprint(hashes.SHA256()).hex() != trust.der_sha256:
        raise XMLSignatureError()
    key = certificate.public_key()
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise XMLSignatureError("signature_unsupported")
    if not certificate.not_valid_before_utc <= observed_at <= certificate.not_valid_after_utc:
        raise XMLSignatureError("signature_expired")
    return certificate


def _verify(root_bytes: bytes, certificate: Any, observed_at: datetime) -> Any:
    from signxml.algorithms import DigestAlgorithm, SignatureMethod
    from signxml.verifier import SignatureConfiguration, XMLVerifier

    etree = importlib.import_module("lxml.etree")

    class _QuietVerifier(XMLVerifier):
        # SignXML 5.1.0 logs canonicalized source bytes in this private hook.
        # Keep the version-bound adapter identical for the admitted subset.
        def _c14n(self, nodes: Any, algorithm: Any, inclusive_ns_prefixes: Any = None) -> bytes:
            if algorithm.value != _EXCLUSIVE or inclusive_ns_prefixes is not None:
                raise XMLSignatureError("signature_unsupported")
            elements = nodes if isinstance(nodes, list) else [nodes]
            return b"".join(
                cast(bytes, etree.tostring(element, method="c14n", exclusive=True, with_comments=False))
                for element in elements
            )

    def refuse_external(self: Any, url: Any, public_id: Any, context: Any) -> Any:
        raise XMLSignatureError("signature_unsupported")

    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
        remove_blank_text=False,
        collect_ids=False,
    )
    parser.resolvers.add(type("_NoExternal", (etree.Resolver,), {"resolve": refuse_external})())
    configuration = SignatureConfiguration(
        require_x509=True,
        location="./",
        expect_references=1,
        signature_methods=frozenset({SignatureMethod.RSA_SHA256}),
        digest_algorithms=frozenset({DigestAlgorithm.SHA256}),
        ignore_ambiguous_key_info=False,
        verification_time=observed_at,
    )
    result = _QuietVerifier().verify(
        root_bytes,
        x509_cert=certificate,
        parser=parser,
        id_attribute="ID",
        expect_config=configuration,
        # The closed structural check above replaces broader package schema parsing.
        validate_schema=False,
        uri_resolver=None,
        cert_resolver=None,
    )
    if isinstance(result, list):
        raise XMLSignatureError()
    return result.signed_xml


def verify_entity(
    content: bytes,
    entity_id: str,
    observed_at: datetime,
    *,
    _trust: _TrustedCertificate | None = None,
) -> VerifiedEntity:
    """Admit exactly one signed entity with the production pin by default."""
    require_xml_extra()
    failure: XMLFailure = "signature_invalid"
    result: VerifiedEntity | None = None
    try:
        EntityTarget(entity_id=entity_id)
        clock_text(observed_at)
        if type(content) is not bytes or not 1 <= len(content) <= _LIMIT:
            raise XMLSignatureError()
        root = parse_strict_xml(content)
        response_certificate = _structure(root, entity_id)
        trust = _production_certificate() if _trust is None else _trust
        certificate = _certificate(trust, observed_at)
        if response_certificate is not None and hashlib.sha256(response_certificate).hexdigest() != trust.der_sha256:
            raise XMLSignatureError()
        signed = _verify(content, certificate, observed_at)
        if (
            signed.tag != "{" + _MD + "}EntityDescriptor"
            or signed.get("entityID") != entity_id
            or signed.get("ID") != root.get("ID")
        ):
            raise XMLSignatureError("identity_mismatch")
        valid_until = signed.get("validUntil")
        normalized = normalized_source_time(valid_until)
        if normalized is None:
            raise XMLSignatureError("signature_unsupported")
        expiry = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
        if not observed_at < expiry <= observed_at + timedelta(days=14):
            raise XMLSignatureError("signature_expired")
        etree = importlib.import_module("lxml.etree")
        detached = cast(bytes, etree.tostring(signed, encoding="utf-8"))
        if len(detached) > _LIMIT:
            raise XMLSignatureError()
        checked = parse_strict_xml(detached)
        if checked.tag != root.tag or checked.get("entityID") != entity_id or checked.get("ID") != root.get("ID"):
            raise XMLSignatureError("identity_mismatch")
        result = VerifiedEntity(detached, entity_id, valid_until)
    except XMLSignatureError as error:
        failure = error.code
    except ImportError:
        failure = "dependency_failure"
    except Exception:
        pass
    if result is None:
        raise XMLSignatureError(failure)
    return result
