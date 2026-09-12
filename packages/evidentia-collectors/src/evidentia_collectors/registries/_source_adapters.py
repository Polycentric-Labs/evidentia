"""Verified XML and bounded source text adapters for registry sessions.

Public composition functions own syntax, projection and checks in that order.
The underscore helpers are internal, not admission APIs for caller-built state.
No function fetches a URI or builds a domain finding.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import quote_from_bytes, urlsplit

from pydantic import JsonValue

from evidentia_collectors.retention._parsing import parse_strict_xml

from ._contracts import EntityTarget, clock_text, normalized_source_time
from ._parsing import canonical_json, checked_json
from ._xml_signature import VerifiedEntity, _TrustedCertificate, verify_entity

_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
_RPI = "urn:oasis:names:tc:SAML:metadata:rpi"
_XML_LANG = "{http://www.w3.org/XML/1998/namespace}lang"
_ROLES = frozenset(
    "{" + _MD + "}" + name
    for name in (
        "RoleDescriptor",
        "IDPSSODescriptor",
        "SPSSODescriptor",
        "AuthnAuthorityDescriptor",
        "AttributeAuthorityDescriptor",
        "PDPDescriptor",
    )
)
_RAW_LIMIT = 65_536
_LINE_LIMIT = 2_048
_LINE_BYTE_LIMIT = 4_096
_FIELD_LIMIT = 1_024
_START = "-----BEGIN PGP SIGNED MESSAGE-----"
_SIGNATURE = "-----BEGIN PGP SIGNATURE-----"
_END = "-----END PGP SIGNATURE-----"
_DEFINED = frozenset(
    ("contact", "expires", "preferred-languages", "acknowledgments", "canonical", "encryption", "hiring", "policy")
)
_URI_FIELDS = _DEFINED - {"expires", "preferred-languages"}
_MIME_TOKEN = frozenset(chr(i) for i in range(33, 127)) - frozenset('()<>@,;:\\"/[]?=')
_FIELD_NAME = re.compile(r"[\x21-\x39\x3b-\x7e]+")
_DATE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})"
)
_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*")
_LANG = re.compile(r"[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*")


class AdapterError(ValueError):
    """Fixed local failure; source strings never enter the exception."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class AdapterCandidate:
    selected: dict[str, JsonValue]
    diagnostics: tuple[dict[str, JsonValue], ...]
    correspondence: dict[str, JsonValue]
    checks: dict[str, JsonValue]


def _selected(value: dict[str, JsonValue]) -> dict[str, JsonValue]:
    detached = checked_json(value)
    if type(detached) is not dict or len(canonical_json(detached)) > 65_536:
        raise AdapterError("selected_capacity_exceeded")
    return detached


def mdq_url(entity_id: str) -> str:
    """Encode the literal opaque entity ID once, under the fixed production path."""
    literal = EntityTarget.model_validate({"entity_id": entity_id}).entity_id
    encoded = quote_from_bytes(literal.encode("utf-8"), safe="")
    if encoded in (".", ".."):
        encoded = "%2E" * len(encoded)
    return "https://mdq.incommon.org/entities/" + encoded


@dataclass(frozen=True)
class _InCommonSyntax:
    root: ET.Element
    issues: tuple[dict[str, JsonValue], ...]
    organization_positions: tuple[int, ...]
    verified_xml_sha256: str


def _incommon_syntax(verified: VerifiedEntity) -> _InCommonSyntax:
    if (
        type(verified) is not VerifiedEntity
        or type(verified.xml) is not bytes
        or type(verified.entity_id) is not str
        or type(verified.valid_until) is not str
    ):
        raise AdapterError("invalid_verified_state")
    root = parse_strict_xml(verified.xml)
    if (
        root.tag != "{" + _MD + "}EntityDescriptor"
        or root.get("entityID") != verified.entity_id
        or root.get("validUntil") != verified.valid_until
    ):
        raise AdapterError("invalid_verified_state")
    issues: list[dict[str, JsonValue]] = []
    organizations: list[int] = []
    if len(verified.entity_id) > 1_024:
        issues.append({"code": "entity_id_schema_length", "xml_position": []})
    for index, child in enumerate(root):
        if child.tag == "{" + _MD + "}Organization":
            organizations.append(index)
            for local in ("OrganizationName", "OrganizationDisplayName", "OrganizationURL"):
                if not any(item.tag == "{" + _MD + "}" + local for item in child):
                    issues.append(
                        {
                            "code": "organization_required_element_missing",
                            "xml_position": [index],
                            "expected_local_name": local,
                        }
                    )
            for subindex, item in enumerate(child):
                if item.tag in ("{" + _MD + "}OrganizationName", "{" + _MD + "}OrganizationDisplayName"):
                    if len(item):
                        # No flattening or partial text() projection of malformed simple content.
                        raise AdapterError("localized_nested_content")
                    if _XML_LANG not in item.attrib:
                        issues.append({"code": "localized_language_missing", "xml_position": [index, subindex]})
        if child.tag == "{" + _MD + "}Extensions":
            for subindex, item in enumerate(child):
                if item.tag == "{" + _RPI + "}RegistrationInfo" and "registrationAuthority" not in item.attrib:
                    issues.append({"code": "registration_authority_missing", "xml_position": [index, subindex]})
    if len(organizations) > 1:
        issues.append({"code": "organization_cardinality", "xml_position": []})
    return _InCommonSyntax(root, tuple(issues), tuple(organizations), hashlib.sha256(verified.xml).hexdigest())


def _project_incommon(syntax: _InCommonSyntax) -> tuple[dict[str, JsonValue], dict[str, JsonValue]]:
    root = syntax.root
    selected: dict[str, JsonValue] = {"entityID": root.attrib["entityID"], "validUntil": root.attrib["validUntil"]}
    positions: list[JsonValue] = []
    for attribute in ("entityID", "validUntil", "cacheDuration"):
        if attribute in root.attrib:
            selected[attribute] = root.attrib[attribute]
            positions.append({"selected_path": "/" + attribute, "xml_position": [], "attribute": attribute})
    names: list[JsonValue] = []
    displays: list[JsonValue] = []
    registration: list[JsonValue] = []
    roles: list[JsonValue] = []
    for index, child in enumerate(root):
        if child.tag in _ROLES:
            positions.append(
                {
                    "selected_path": "/role_descriptors/" + str(len(roles)),
                    "xml_position": [index],
                    "derived": "expanded_element_name",
                }
            )
            roles.append(child.tag)
        if child.tag == "{" + _MD + "}Organization":
            for subindex, item in enumerate(child):
                if item.tag not in ("{" + _MD + "}OrganizationName", "{" + _MD + "}OrganizationDisplayName"):
                    continue
                is_name = item.tag == "{" + _MD + "}OrganizationName"
                values = names if is_name else displays
                path = ("/organization_names/" if is_name else "/organization_display_names/") + str(len(values))
                value: dict[str, JsonValue] = {"value": "" if item.text is None else item.text}
                positions.append(
                    {"selected_path": path + "/value", "xml_position": [index, subindex], "derived": "element_text"}
                )
                if _XML_LANG in item.attrib:
                    value["language"] = item.attrib[_XML_LANG]
                    positions.append(
                        {"selected_path": path + "/language", "xml_position": [index, subindex], "attribute": _XML_LANG}
                    )
                values.append(value)
        if child.tag == "{" + _MD + "}Extensions":
            for subindex, item in enumerate(child):
                if item.tag != "{" + _RPI + "}RegistrationInfo":
                    continue
                value = {}
                path = "/registration_info/" + str(len(registration))
                positions.append(
                    {"selected_path": path, "xml_position": [index, subindex], "derived": "element_occurrence"}
                )
                for attribute in ("registrationAuthority", "registrationInstant"):
                    if attribute in item.attrib:
                        value[attribute] = item.attrib[attribute]
                        positions.append(
                            {
                                "selected_path": path + "/" + attribute,
                                "xml_position": [index, subindex],
                                "attribute": attribute,
                            }
                        )
                registration.append(value)
    if names:
        selected["organization_names"] = names
    if displays:
        selected["organization_display_names"] = displays
    if registration:
        selected["registration_info"] = registration
    selected["role_descriptors"] = roles
    correspondence: dict[str, JsonValue] = {
        "basis": "VerifiedEntity.xml",
        "verified_xml_sha256": syntax.verified_xml_sha256,
        "organization_positions": list(syntax.organization_positions),
        "positions": positions,
    }
    return _selected(selected), correspondence


def adapt_incommon(
    content: bytes, entity_id: str, observed_at: datetime, *, _trust: _TrustedCertificate | None = None
) -> AdapterCandidate:
    """Obtain the real verified root, then derive selected data only from it."""
    verified = verify_entity(content, entity_id, observed_at, _trust=_trust)
    syntax = _incommon_syntax(verified)
    selected, correspondence = _project_incommon(syntax)
    return AdapterCandidate(selected, syntax.issues, correspondence, {})


@dataclass(frozen=True)
class _Line:
    text: str
    ending: str
    source_line: int


@dataclass(frozen=True)
class _Field:
    name: str
    raw_value: str
    source_line: int
    body_line: int


@dataclass(frozen=True)
class _SecuritySyntax:
    fields: tuple[_Field, ...]
    signed: bool
    issues: tuple[dict[str, JsonValue], ...]
    physical_lines: int
    body_lines: int
    body_source_lines: tuple[int, ...]
    source_sha256: str


def _media_type(value: str) -> None:
    if type(value) is not str or len(value) > 1_024 or not value.isascii():
        raise AdapterError("media_type_unsupported")
    # Finite supported MIME subset. Unknown parameters do not imply a charset.
    if (
        re.fullmatch(
            r'[ \t]*text/plain[ \t]*(?:;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|"utf-8")[ \t]*)?', value, re.IGNORECASE
        )
        is None
    ):
        raise AdapterError("media_type_unsupported")


def _physical_lines(content: bytes) -> list[_Line]:
    if type(content) is not bytes or len(content) > _RAW_LIMIT:
        raise AdapterError("body_capacity_exceeded")
    failed = False
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeError:
        failed = True
        text = ""
    if failed:
        raise AdapterError("body_utf8_invalid")
    # UTF-8 decoding cannot expand the byte count; retain an explicit decoded check.
    if len(text.encode("utf-8")) > _RAW_LIMIT:
        raise AdapterError("body_capacity_exceeded")
    newline_count = content.count(b"\n")
    chunks = content.split(b"\n")
    if chunks[-1] == b"":
        chunks.pop()
    if len(chunks) > _LINE_LIMIT:
        raise AdapterError("line_capacity_exceeded")
    lines: list[_Line] = []
    for index, chunk in enumerate(chunks):
        terminated = index < newline_count
        if len(chunk) + int(terminated) > _LINE_BYTE_LIMIT:
            raise AdapterError("line_byte_capacity_exceeded")
        ending = "\n" if terminated else ""
        if terminated and chunk.endswith(b"\r"):
            chunk = chunk[:-1]
            ending = "\r\n"
        lines.append(_Line(chunk.decode("utf-8"), ending, index + 1))
    return lines


def _token(value: str) -> bool:
    return bool(value) and all(char in _MIME_TOKEN for char in value)


def _signed_body(lines: list[_Line]) -> tuple[list[_Line], bool]:
    if not lines:
        return [], False
    if not lines[0].text.startswith("-----BEGIN PGP"):
        if any(line.text in (_START, _SIGNATURE, _END) for line in lines):
            raise AdapterError("signed_framing_invalid")
        return lines, False
    if lines[0].text != _START or lines[0].ending != "\r\n":
        raise AdapterError("signed_framing_invalid")
    cursor = 1
    hashes = 0
    while cursor < len(lines) and lines[cursor].text.startswith("Hash: "):
        line = lines[cursor]
        if line.ending != "\r\n" or not all(_token(part) for part in line.text[6:].split(",")):
            raise AdapterError("signed_framing_invalid")
        hashes += 1
        cursor += 1
    if not hashes or cursor >= len(lines) or lines[cursor].text or lines[cursor].ending != "\r\n":
        raise AdapterError("signed_framing_invalid")
    cursor += 1
    body: list[_Line] = []
    while cursor < len(lines) and lines[cursor].text != _SIGNATURE:
        line = lines[cursor]
        if not line.ending or "\r" in line.text or (line.text.startswith("-") and not line.text.startswith("- ")):
            raise AdapterError("signed_framing_invalid")
        unescaped = line.text[2:] if line.text.startswith("- ") else line.text
        body.append(_Line(unescaped, line.ending, line.source_line))
        cursor += 1
    if cursor >= len(lines) or lines[cursor].ending != "\r\n":
        raise AdapterError("signed_framing_invalid")
    cursor += 1
    while cursor < len(lines) and lines[cursor].text:
        line = lines[cursor]
        name, separator, value = line.text.partition(": ")
        if (
            not separator
            or not _token(name)
            or line.ending != "\r\n"
            or any(char != "\t" and not 32 <= ord(char) <= 126 for char in value)
        ):
            raise AdapterError("signed_framing_invalid")
        cursor += 1
    if cursor >= len(lines) or lines[cursor].ending != "\r\n":
        raise AdapterError("signed_framing_invalid")
    cursor += 1
    armor: list[str] = []
    while cursor < len(lines) and lines[cursor].text != _END:
        line = lines[cursor]
        if line.ending != "\r\n" or re.fullmatch(r"[A-Za-z0-9=+/]+", line.text) is None:
            raise AdapterError("signed_framing_invalid")
        armor.append(line.text)
        cursor += 1
    if not armor or cursor != len(lines) - 1 or lines[cursor].ending != "\r\n":
        raise AdapterError("signed_framing_invalid")
    # Check only base64 representation, not signature packets, checksum or trust.
    checksum = armor.pop() if armor[-1].startswith("=") else None
    failed = False
    try:
        decoded = base64.b64decode("".join(armor), validate=True)
        if not decoded or (
            checksum is not None and (len(checksum) != 5 or len(base64.b64decode(checksum[1:], validate=True)) != 3)
        ):
            failed = True
    except (ValueError, binascii.Error):
        failed = True
    if failed:
        raise AdapterError("signed_framing_invalid")
    return body, True


def _semantic(field: _Field) -> str | None:
    # Exactly the required SP is removed. Extra leading whitespace is not normalized.
    return field.raw_value[1:].rstrip(" \t") if field.raw_value.startswith(" ") else None


def _uri_lexical(value: str) -> bool:
    if _URI.fullmatch(value) is None or re.search(r"%(?![0-9A-Fa-f]{2})", value):
        return False
    try:
        split = urlsplit(value)
    except ValueError:
        return False
    scheme = split.scheme.lower()
    if scheme in ("http", "https"):
        return scheme == "https" and value[len(split.scheme) :].startswith("://") and bool(split.hostname)
    return True


def _security_syntax(content: bytes, content_type: str) -> _SecuritySyntax:
    _media_type(content_type)
    physical = _physical_lines(content)
    body, signed = _signed_body(physical)
    fields: list[_Field] = []
    issues: list[dict[str, JsonValue]] = []
    for body_index, line in enumerate(body, 1):

        def issue(code: str, line: _Line = line, body_index: int = body_index) -> None:
            issues.append({"code": code, "source_line": line.source_line, "body_line": body_index})

        if not line.ending:
            issue("line_ending_missing")
        if any(
            (ord(char) < 32 and char != "\t") or ord(char) == 127 or char in "\u0085\u2028\u2029\ufeff"
            for char in line.text
        ):
            issue("line_control_or_separator")
        if line.text.strip(" \t") == "" or line.text.startswith("#"):
            continue
        name, colon, raw = line.text.partition(":")
        if not colon or _FIELD_NAME.fullmatch(name) is None:
            issue("field_line_invalid")
            continue
        if len(fields) >= _FIELD_LIMIT:
            raise AdapterError("field_capacity_exceeded")
        field = _Field(name, raw, line.source_line, body_index)
        fields.append(field)
        semantic = _semantic(field)
        if semantic is None or semantic == "":
            issue("field_value_invalid")
            continue
        defined = name.lower()
        if defined in _URI_FIELDS and not _uri_lexical(semantic):
            issue("uri_lexical_invalid")
        elif defined == "expires" and _DATE.fullmatch(semantic) is None:
            issue("expires_lexical_invalid")
        elif defined == "preferred-languages" and not all(
            _LANG.fullmatch(tag.strip(" \t")) for tag in semantic.split(",")
        ):
            issue("language_lexical_invalid")
    return _SecuritySyntax(
        tuple(fields),
        signed,
        tuple(issues),
        len(physical),
        len(body),
        tuple(line.source_line for line in body),
        hashlib.sha256(content).hexdigest(),
    )


def _project_security(syntax: _SecuritySyntax) -> dict[str, JsonValue]:
    fields: list[JsonValue] = [
        {"name": field.name, "value": field.raw_value, "source_line": field.source_line, "body_line": field.body_line}
        for field in syntax.fields
    ]
    return _selected(
        {
            "fields": fields,
            "signed": syntax.signed,
            "signature_state": "unverified" if syntax.signed else "not_applicable",
        }
    )


def _security_checks(syntax: _SecuritySyntax, observed_at: datetime, retrieved_url: str | None) -> dict[str, JsonValue]:
    clock_text(observed_at)
    if retrieved_url is not None and (
        type(retrieved_url) is not str
        or len(retrieved_url) > 8_192
        or not retrieved_url.isascii()
        or any(ord(c) < 33 or ord(c) > 126 for c in retrieved_url)
    ):
        raise AdapterError("invalid_retrieval_uri")
    contacts = tuple(field for field in syntax.fields if field.name.lower() == "contact")
    expires = tuple(field for field in syntax.fields if field.name.lower() == "expires")
    languages = tuple(field for field in syntax.fields if field.name.lower() == "preferred-languages")
    canonical = tuple(field for field in syntax.fields if field.name.lower() == "canonical")
    checks: dict[str, JsonValue] = {
        "syntax": "invalid" if syntax.issues else "within_supported_lexical_subset",
        "contact_present": bool(contacts),
        "expires_count": len(expires),
        "expires_single": len(expires) == 1,
        "preferred_languages_at_most_one": len(languages) <= 1,
        "expires_normalized_utc": None,
        "expiry_relation": "unknown",
        "expires_future": None,
        "expires_stale": None,
        "expiry_beyond_365_days": None,
        "canonical_lists_retrieval_uri": None,
        "uri_semantic_validation": "not_performed",
        "language_registry_validation": "not_performed",
    }
    if len(expires) == 1:
        semantic = _semantic(expires[0])
        normalized = normalized_source_time(semantic)
        if normalized is not None:
            instant = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
            checks["expires_normalized_utc"] = normalized
            checks["expiry_relation"] = (
                "before" if instant < observed_at else "after" if instant > observed_at else "equal"
            )
            checks["expires_future"] = instant > observed_at
            checks["expires_stale"] = instant < observed_at
            try:
                checks["expiry_beyond_365_days"] = instant > observed_at + timedelta(days=365)
            except OverflowError:
                checks["expiry_beyond_365_days"] = None
    if canonical and retrieved_url is not None:
        checks["canonical_lists_retrieval_uri"] = any(_semantic(field) == retrieved_url for field in canonical)
    return checks


def adapt_security_txt(
    content: bytes, content_type: str, observed_at: datetime, *, retrieved_url: str | None = None
) -> AdapterCandidate:
    """Parse bounded source text, select exact occurrences, then assess finite checks."""
    clock_text(observed_at)
    syntax = _security_syntax(content, content_type)
    selected = _project_security(syntax)
    checks = _security_checks(syntax, observed_at, retrieved_url)
    correspondence: dict[str, JsonValue] = {
        "basis": "complete_response_body",
        "source_sha256": syntax.source_sha256,
        "physical_line_count": syntax.physical_lines,
        "body_line_count": syntax.body_lines,
        "body_source_lines": list(syntax.body_source_lines),
    }
    return AdapterCandidate(selected, syntax.issues, correspondence, checks)
