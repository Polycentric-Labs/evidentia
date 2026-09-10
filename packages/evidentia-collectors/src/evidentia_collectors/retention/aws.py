"""Project S3 bucket Object Lock and versioning configuration."""

from __future__ import annotations

import re
from typing import Literal
from xml.etree.ElementTree import Element

from ._client import ClientFault, ComponentResponse, StorageReadSession
from ._contracts import (
    ProjectedComponent,
    S3Target,
    StorageRetentionComponentResult,
    StorageRetentionDiagnostic,
    StorageTarget,
)
from ._parsing import JsonObject

_API_VERSION = "2006-03-01"
_NAMESPACES = {"", "{http://s3.amazonaws.com/doc/2006-03-01/}"}
_XML_WHITESPACE = " \t\r\n"
_KNOWN_FIELDS = {
    "ObjectLockConfiguration",
    "ObjectLockEnabled",
    "Rule",
    "DefaultRetention",
    "Mode",
    "Days",
    "Years",
    "VersioningConfiguration",
    "Status",
    "MfaDelete",
    "MFADelete",
    "Error",
    "Code",
}
DetailCode = Literal["unsupported_source_value", "missing_source_detail"]


def _invalid(status: int) -> ClientFault:
    return ClientFault("invalid_response", status)


def _name(element: Element, status: int) -> tuple[str, str]:
    tag = element.tag
    if type(tag) is not str:
        raise _invalid(status)
    if tag.startswith("{"):
        namespace, separator, local = tag[1:].partition("}")
        if not separator or not local:
            raise _invalid(status)
        return "{" + namespace + "}", local
    return "", tag


def _root(response: ComponentResponse, name: str) -> tuple[Element, str]:
    if not isinstance(response.body, Element):
        raise _invalid(response.http_status)
    namespace, local = _name(response.body, response.http_status)
    if namespace not in _NAMESPACES or local != name:
        raise _invalid(response.http_status)
    return response.body, namespace


def _children(
    element: Element,
    namespace: str,
    names: set[str],
    status: int,
    *,
    allow_unrelated: bool = True,
) -> dict[str, Element]:
    if element.attrib or (element.text or "").strip(_XML_WHITESPACE) or (element.tail or "").strip(_XML_WHITESPACE):
        raise _invalid(status)
    selected: dict[str, Element] = {}
    seen: set[str] = set()
    for child in element:
        child_namespace, name = _name(child, status)
        if child_namespace != namespace or name in seen or (child.tail or "").strip(_XML_WHITESPACE):
            raise _invalid(status)
        seen.add(name)
        if name in names:
            selected[name] = child
        elif name in _KNOWN_FIELDS or not allow_unrelated:
            raise _invalid(status)
    return selected


def _text(element: Element, status: int) -> str:
    if element.attrib or len(element):
        raise _invalid(status)
    return element.text or ""


def _enum(element: Element, allowed: set[str], status: int, details: set[DetailCode]) -> str:
    value = _text(element, status)
    if value not in allowed:
        details.add("unsupported_source_value")
    return value


def _duration(element: Element, status: int, details: set[DetailCode]) -> int:
    value = _text(element, status)
    # XML integer lexical forms are converted to their native value, without unit conversion.
    if re.fullmatch(r"[+-]?[0-9]{1,128}", value) is None:
        raise _invalid(status)
    number = int(value)
    if number <= 0:
        details.add("unsupported_source_value")
    return number


def _projection(response: ComponentResponse, fields: JsonObject, details: set[DetailCode]) -> ProjectedComponent:
    order: tuple[DetailCode, ...] = ("unsupported_source_value", "missing_source_detail")
    diagnostics = tuple(
        StorageRetentionDiagnostic(code=code, http_status=response.http_status) for code in order if code in details
    )
    return ProjectedComponent(_API_VERSION, "bucket", fields, diagnostics, source_etag=response.source_etag)


def _project_lock(response: ComponentResponse, target: StorageTarget) -> ProjectedComponent:
    if not isinstance(target, S3Target) or response.component_id != "s3-object-lock":
        raise _invalid(response.http_status)
    if response.http_status == 404:
        root, namespace = _root(response, "Error")
        children = _children(
            root,
            namespace,
            {"Code", "Message", "Resource", "RequestId", "HostId", "BucketName"},
            response.http_status,
            allow_unrelated=False,
        )
        values = {name: _text(element, response.http_status) for name, element in children.items()}
        if values.get("Code") != "ObjectLockConfigurationNotFoundError":
            raise _invalid(response.http_status)
        # The session admits this exact status/code pair; no source error text is retained.
        return _projection(response, {}, set())
    if response.http_status != 200:
        raise _invalid(response.http_status)
    root, namespace = _root(response, "ObjectLockConfiguration")
    children = _children(root, namespace, {"ObjectLockEnabled", "Rule"}, response.http_status)
    fields: JsonObject = {}
    details: set[DetailCode] = set()
    if "ObjectLockEnabled" in children:
        fields["ObjectLockEnabled"] = _enum(children["ObjectLockEnabled"], {"Enabled"}, response.http_status, details)
    else:
        details.add("missing_source_detail")
    if "Rule" in children:
        rule_children = _children(children["Rule"], namespace, {"DefaultRetention"}, response.http_status)
        rule: JsonObject = {}
        fields["Rule"] = rule
        if "DefaultRetention" not in rule_children:
            details.add("missing_source_detail")
        else:
            retained = _children(
                rule_children["DefaultRetention"], namespace, {"Mode", "Days", "Years"}, response.http_status
            )
            retention: JsonObject = {}
            rule["DefaultRetention"] = retention
            if "Mode" in retained:
                retention["Mode"] = _enum(retained["Mode"], {"GOVERNANCE", "COMPLIANCE"}, response.http_status, details)
            else:
                details.add("missing_source_detail")
            if "Days" in retained and "Years" in retained:
                raise _invalid(response.http_status)
            periods = [name for name in ("Days", "Years") if name in retained]
            if not periods:
                details.add("missing_source_detail")
            for name in periods:
                retention[name] = _duration(retained[name], response.http_status, details)
    return _projection(response, fields, details)


def _project_versioning(response: ComponentResponse, target: StorageTarget) -> ProjectedComponent:
    if not isinstance(target, S3Target) or response.component_id != "s3-versioning" or response.http_status != 200:
        raise _invalid(response.http_status)
    root, namespace = _root(response, "VersioningConfiguration")
    children = _children(root, namespace, {"Status", "MfaDelete"}, response.http_status)
    fields: JsonObject = {}
    details: set[DetailCode] = set()
    if "Status" in children:
        fields["Status"] = _enum(children["Status"], {"Enabled", "Suspended"}, response.http_status, details)
    if "MfaDelete" in children:
        # AWS names the XML element MfaDelete and the API member MFADelete.
        fields["MFADelete"] = _enum(children["MfaDelete"], {"Enabled", "Disabled"}, response.http_status, details)
        if "Status" not in children:
            details.add("missing_source_detail")
    return _projection(response, fields, details)


def read_s3(target: S3Target, session: StorageReadSession) -> list[StorageRetentionComponentResult]:
    """Read Object Lock then versioning without resolving credentials or owning transport."""
    return [
        session.read_component("s3-object-lock", target, _project_lock),
        session.read_component("s3-versioning", target, _project_versioning),
    ]
