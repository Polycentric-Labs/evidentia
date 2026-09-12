"""Regenerate complete CMVP facts with literal text and source memberships.

Run with python -m scripts.registries.refresh_cmvp. Input and output gzip use the
reviewed single-member format. Source HTML extraction is a separate pure function
for the captured layouts; it performs no discovery, fetching or file writes.
"""

from __future__ import annotations

from html.parser import HTMLParser
from typing import Any

from evidentia_collectors.registries import cmvp
from evidentia_collectors.registries._contracts import CertificateTarget

from scripts.registries.refresh_fedramp import (
    MAX_BYTES,
    MAX_RECORDS,
    RefreshError,
    count,
    main,
    obj,
    package,
    rows,
    source_manifest,
    tuple_binding,
    tuple_document,
)

_TABLE = "//*[@id='searchResultsTable']/tbody/tr"
_DETAIL = "//*[@id='module-name']/../.."
_HEADING = "//*[@id='titleRow']/div/div/h3"
_NAMES = ("active", "historical", "revoked", "certificate_5517_detail")
_IDS = ("cmvp-active-all", "cmvp-historical", "cmvp-revoked", "cmvp-certificate-5517")
_HEADERS = ("Certificate Number", "Vendor Name", "Module Name", "Module Type", "Validation Date")
_DETAIL_ROWS = (
    (1, "Module Name"),
    (2, "Standard"),
    (3, "Status"),
    (4, "Sunset Date"),
    (6, "Caveat"),
    (8, "Module Type"),
)
_VOID = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
)


class _Node:
    def __init__(self, tag: str, attrs: list[tuple[str, str | None]], parent: _Node | None) -> None:
        self.tag, self.attrs, self.parent = tag, attrs, parent
        self.children: list[_Node | str] = []

    def elements(self, tag: str) -> list[_Node]:
        return [child for child in self.children if isinstance(child, _Node) and child.tag == tag]

    def text(self) -> str:
        if self.tag == "br":
            return "\n"
        return "".join(child if isinstance(child, str) else child.text() for child in self.children)


class _Document(HTMLParser):
    def __init__(self, raw: bytes) -> None:
        super().__init__(convert_charrefs=True)
        if type(raw) is not bytes or len(raw) > MAX_BYTES:
            raise RefreshError()
        self.root = _Node("document", [], None)
        self.stack = [self.root]
        self.nodes: list[_Node] = []
        try:
            self.feed(raw.decode("utf-8", errors="strict"))
            self.close()
        except (UnicodeError, ValueError, RecursionError):
            raise RefreshError() from None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if len(self.nodes) >= 500_000 or len(self.stack) >= 64:
            raise RefreshError()
        node = _Node(tag, attrs, self.stack[-1])
        self.stack[-1].children.append(node)
        self.nodes.append(node)
        if tag not in _VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                del self.stack[index:]
                return

    def handle_data(self, data: str) -> None:
        self.stack[-1].children.append(data)

    def by_id(self, identity: str) -> _Node:
        matches = [node for node in self.nodes if ("id", identity) in node.attrs]
        if len(matches) != 1 or sum(key == "id" for key, _ in matches[0].attrs) != 1:
            raise RefreshError()
        return matches[0]


def _one(node: _Node, tag: str) -> _Node:
    values = node.elements(tag)
    if len(values) != 1:
        raise RefreshError()
    return values[0]


def _fields(table_id: str, fields: object, *, closed: bool) -> dict[str, Any]:
    selected = cmvp.select_source_fields(table_id, fields)
    expected = (
        set(cmvp.DETAIL_FIELDS)
        if table_id == _NAMES[3]
        else set(_HEADERS) | (set() if table_id == "active" else {"Status"})
    )
    if set(selected) != expected or (closed and selected != fields):
        raise RefreshError()
    if table_id != _NAMES[3]:
        CertificateTarget(certificate_number=selected["Certificate Number"])
        if table_id == "revoked" and selected["Status"] != "Revoked":
            raise RefreshError()
        if table_id == "historical" and selected["Status"] not in {"Historical", "Revoked"}:
            raise RefreshError()
    return selected


def extract_source(raw: bytes, table_id: str) -> list[dict[str, Any]]:
    """Extract only the fixed captured table or the six certificate-5517 values."""
    if type(table_id) is not str or table_id not in _NAMES:
        raise RefreshError()
    document = _Document(raw)
    if table_id == _NAMES[3]:
        heading = _one(_one(_one(document.by_id("titleRow"), "div"), "div"), "h3")
        if heading.text() != "Certificate #5517":
            raise RefreshError()
        value = document.by_id("module-name")
        if value.parent is None or value.parent.parent is None:
            raise RefreshError()
        panel = value.parent.parent
        children = panel.elements("div")
        if len(children) < 8 or any(isinstance(child, _Node) and child.tag != "div" for child in panel.children):
            raise RefreshError()
        fields = {}
        for ordinal, label in _DETAIL_ROWS:
            cells = children[ordinal - 1].elements("div")
            if len(cells) != 2 or cells[0].text().strip() != label:
                raise RefreshError()
            fields[label] = cells[1].text()
        if children[0].elements("div")[1] is not value:
            raise RefreshError()
        return [{"source_index": 0, "fields": _fields(table_id, fields, closed=True)}]
    table = document.by_id("searchResultsTable")
    if table.tag != "table":
        raise RefreshError()
    headers = _HEADERS + (() if table_id == "active" else ("Status",))
    heading = _one(_one(table, "thead"), "tr")
    if tuple(cell.text() for cell in heading.elements("th")) != headers:
        raise RefreshError()
    body = _one(table, "tbody")
    elements = [child for child in body.children if isinstance(child, _Node)]
    if any(child.tag != "tr" for child in elements) or len(elements) > MAX_RECORDS:
        raise RefreshError()
    result = []
    for index, row in enumerate(elements):
        cells = row.elements("td")
        if len(cells) != len(headers) or any(child.tag != "td" for child in row.children if isinstance(child, _Node)):
            raise RefreshError()
        values = [_one(cells[0], "a").text(), *(cell.text() for cell in cells[1:])]
        result.append(
            {"source_index": index, "fields": _fields(table_id, dict(zip(headers, values, strict=True)), closed=True)}
        )
    return result


def _columns(table_id: str) -> list[dict[str, str]]:
    if table_id == _NAMES[3]:
        return [
            {
                "name": label,
                "source_pointer": _DETAIL + "/div[" + str(index) + "]/div[2]",
                "label_pointer": _DETAIL + "/div[" + str(index) + "]/div[1]",
                "native_type": "html_text",
            }
            for index, label in _DETAIL_ROWS
        ]
    headers = _HEADERS + (() if table_id == "active" else ("Status",))
    return [
        {
            "name": name,
            "source_pointer": _TABLE + "/td[" + str(index) + "]" + ("/a" if index == 1 else ""),
            "native_type": "html_text",
        }
        for index, name in enumerate(headers, 1)
    ]


def regenerate(document: object, tuple_input: dict[str, Any]) -> dict[str, Any]:
    """Coalesce only equal selected rows; keep all source memberships in order."""
    value = tuple_document(document, "cmvp", _NAMES)
    binding = tuple_binding(tuple_input, "reviewed-native-tuples")
    sources = source_manifest(rows(value["sources"], limit=4), registry="cmvp")
    if tuple(row["source_id"] for row in sources) != _IDS:
        raise RefreshError()
    certificates: dict[str, dict[str, Any]] = {}
    for index, table in enumerate(value["tables"]):
        obj(table, {"table_id", "source_id", "source_pointer", "scope", "columns", "rows"})
        name = table["table_id"]
        scope = (
            {"query_status": name.title(), "status_basis": "query_scope" if name == "active" else "literal_row_column"}
            if index < 3
            else {"certificate_number": "5517", "source_heading": "Certificate #5517", "heading_pointer": _HEADING}
        )
        if (
            table["source_id"] != _IDS[index]
            or table["source_pointer"] != (_TABLE if index < 3 else _DETAIL)
            or table["scope"] != scope
            or table["columns"] != _columns(name)
        ):
            raise RefreshError()
        seen: set[str] = set()
        if index == 3:
            if len(table["rows"]) != 1 or "5517" not in certificates:
                raise RefreshError()
            row = table["rows"][0]
            fields = _fields(name, row["fields"], closed=True)
            certificates["5517"]["detail"] = {"source_id": _IDS[3], "source_index": 0, "fields": fields}
            continue
        for row in table["rows"]:
            fields = _fields(name, row["fields"], closed=True)
            identity = fields["Certificate Number"]
            if identity in seen:
                raise RefreshError()
            seen.add(identity)
            occurrence = {
                "source_id": _IDS[index],
                "table_id": name,
                "source_index": count(row["source_index"], MAX_RECORDS),
                "query_status": name.title(),
            }
            if identity in certificates:
                if certificates[identity]["fields"] != fields:
                    raise RefreshError()
                certificates[identity]["occurrences"].append(occurrence)
            else:
                certificates[identity] = {
                    "certificate_number": identity,
                    "fields": fields,
                    "status": {"basis": scope["status_basis"], "value": fields.get("Status", name.title())},
                    "occurrences": [occurrence],
                }
    manifest = {
        "as_of": {
            "basis": "publisher_cutoff_not_selected",
            "date": None,
            "literal": None,
            "representation": "source_text",
            "source_ids": list(_IDS),
        },
        "query_scope": "exact_certificate_number",
        "source_occurrence_counts": value["selected_occurrence_counts"],
        "sources": sources,
    }
    return package("cmvp", binding, manifest, {"certificates": list(certificates.values())})


if __name__ == "__main__":
    raise SystemExit(main("cmvp", regenerate))
