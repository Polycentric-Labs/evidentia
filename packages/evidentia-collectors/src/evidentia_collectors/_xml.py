"""Shared ``defusedxml`` loading helper for file-ingest scan collectors.

Both :mod:`evidentia_collectors.nessus` and
:mod:`evidentia_collectors.greenbone` parse a third-party scan-export XML
document with the same trust posture: refuse entity expansion and
external references (XXE / billion-laughs) before any element is read.
This module holds that one shared step so each collector can raise its
own typed error (``NessusIngestError`` / ``GreenboneIngestError``) with
identical wording rather than duplicating the try/except.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import cast

import defusedxml.ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

__all__ = ["parse_defused_xml"]


def parse_defused_xml(xml_bytes: bytes, *, error_cls: type[Exception]) -> ET.Element:
    """Parse ``xml_bytes`` with ``defusedxml``, raising ``error_cls`` on failure.

    Raises ``error_cls(message)``, chained from the original exception,
    when ``defusedxml`` refuses an unsafe construct (a DOCTYPE ``<!ENTITY``
    declaration or an external SYSTEM/PUBLIC reference) or when the bytes
    are not well-formed XML at all. Never raises anything else; the
    caller's own root-element / shape checks happen after this returns.

    ``defusedxml`` ships no type stubs, so ``fromstring`` resolves to
    ``Any``; the ``cast`` here is the one place that boundary is made
    explicit rather than leaking ``Any`` into every caller.
    """
    try:
        return cast(ET.Element, DefusedET.fromstring(xml_bytes))
    except DefusedXmlException as exc:
        raise error_cls(f"refused an unsafe XML construct (entity/external-reference): {exc}") from exc
    except ET.ParseError as exc:
        raise error_cls(f"not valid XML: {exc}") from exc
