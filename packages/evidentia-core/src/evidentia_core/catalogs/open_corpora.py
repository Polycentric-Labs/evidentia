"""Exact offline publisher snapshots and source-backed catalog projections.

Native documents and links remain inert. These finite profiles do not perform
full OSCAL schema validation, assessments, network access, or persistence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple, cast

from evidentia_core.catalogs.loader import CatalogJsonToken, _load_catalog_data, _restore_catalog_capture
from evidentia_core.models.catalog import CatalogControl, ControlCatalog, _normalize_control_id
from evidentia_core.models.open_corpora import NativeBudget, NativeSourceError, native_operation, native_value


class _Source(NamedTuple):
    name: str
    key: str
    role: str
    media: str
    repository: str
    commit: str
    upstream: str
    size: int
    digest: str


_SOURCES: dict[str, tuple[_Source, ...]] = {
    "au-ism-2026.09.4": (
        _Source(
            "ISM_catalog.json",
            "ism-catalog",
            "authoritative",
            "application/json",
            "AustralianCyberSecurityCentre/ism-oscal",
            "9f77120a7f8671c73da02431cdc299fac264edab",
            "ISM_catalog.json",
            2677748,
            "237ea09362b8449ed5c5ee85de4725a0468ee73d13af7cf61c26d4e6ac47f12d",
        ),
        _Source(
            "README.md",
            "readme",
            "publication_context",
            "text/markdown",
            "AustralianCyberSecurityCentre/ism-oscal",
            "9f77120a7f8671c73da02431cdc299fac264edab",
            "README.md",
            3867,
            "3f8036197253160f3aaf517eca7cf478601ac08a68b3470748cfa697a10807f3",
        ),
    ),
    "cisa-scuba-m365-7ef9501d": (
        _Source(
            "aad.md",
            "aad",
            "authoritative",
            "text/markdown",
            "cisagov/ScubaGear",
            "7ef9501d7de9804ddb9d6013af6b665cccfb39d9",
            "PowerShell/ScubaGear/baselines/aad.md",
            85909,
            "ea0fe8dec93fa85ce580280b326b955c11aeb5fa24a18e840186bff05f58c415",
        ),
        _Source(
            "defender.md",
            "defender",
            "authoritative",
            "text/markdown",
            "cisagov/ScubaGear",
            "7ef9501d7de9804ddb9d6013af6b665cccfb39d9",
            "PowerShell/ScubaGear/baselines/defender.md",
            58801,
            "5718b800e9c99ac73f0196a2665ba563e36bfe0236aaf6a54a0eccbcf97f402e",
        ),
        _Source(
            "exo.md",
            "exo",
            "authoritative",
            "text/markdown",
            "cisagov/ScubaGear",
            "7ef9501d7de9804ddb9d6013af6b665cccfb39d9",
            "PowerShell/ScubaGear/baselines/exo.md",
            35917,
            "de6fd5151958383ecaae4f8a0d1092d5bb6d6d885d21afc8f13221dd775d80c1",
        ),
        _Source(
            "powerbi.md",
            "powerbi",
            "authoritative",
            "text/markdown",
            "cisagov/ScubaGear",
            "7ef9501d7de9804ddb9d6013af6b665cccfb39d9",
            "PowerShell/ScubaGear/baselines/powerbi.md",
            41593,
            "f9d22c204fdd11d53800d1da9afece03edcb05dac11878417f5042f73ea66b1f",
        ),
        _Source(
            "powerplatform.md",
            "powerplatform",
            "authoritative",
            "text/markdown",
            "cisagov/ScubaGear",
            "7ef9501d7de9804ddb9d6013af6b665cccfb39d9",
            "PowerShell/ScubaGear/baselines/powerplatform.md",
            29143,
            "e87a2d553aa0390dcce5d9e7d4a69e1cd898080cd5cf1c519e8e72e2a1cc98e5",
        ),
        _Source(
            "securitysuite.md",
            "securitysuite",
            "authoritative",
            "text/markdown",
            "cisagov/ScubaGear",
            "7ef9501d7de9804ddb9d6013af6b665cccfb39d9",
            "PowerShell/ScubaGear/baselines/securitysuite.md",
            76745,
            "55623da97cb70fbee74c0405639d14150c118e7f1446b10c4477b2b3efaf9bbf",
        ),
        _Source(
            "sharepoint.md",
            "sharepoint",
            "authoritative",
            "text/markdown",
            "cisagov/ScubaGear",
            "7ef9501d7de9804ddb9d6013af6b665cccfb39d9",
            "PowerShell/ScubaGear/baselines/sharepoint.md",
            18780,
            "7ea2f414156f2d367924f8a8d5b2267cfd39a679ae65bbfbc2327cafaac2cb10",
        ),
        _Source(
            "teams.md",
            "teams",
            "authoritative",
            "text/markdown",
            "cisagov/ScubaGear",
            "7ef9501d7de9804ddb9d6013af6b665cccfb39d9",
            "PowerShell/ScubaGear/baselines/teams.md",
            46804,
            "0b7d56dfea2f579face7fa94371f88a038c5e4cc7d795d6c3195c5a46dab2d6a",
        ),
        _Source(
            "ScubaBaselines.json",
            "scubabaselines",
            "reference",
            "application/json",
            "cisagov/ScubaGear",
            "7ef9501d7de9804ddb9d6013af6b665cccfb39d9",
            "PowerShell/ScubaGear/schemas/ScubaBaselines.json",
            880055,
            "25c5c6aa260a1dfa911cf18f91a715241a70fd60721d117129207630cb8349bf",
        ),
        _Source(
            "LICENSE",
            "license",
            "license",
            "text/plain",
            "cisagov/ScubaGear",
            "7ef9501d7de9804ddb9d6013af6b665cccfb39d9",
            "LICENSE",
            7048,
            "a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499",
        ),
        _Source(
            "scubabaselineschema.md",
            "scubabaselineschema",
            "publication_context",
            "text/markdown",
            "cisagov/ScubaGear",
            "7ef9501d7de9804ddb9d6013af6b665cccfb39d9",
            "docs/misc/scubabaselineschema.md",
            9221,
            "341cc7f3a1ee0c7d64e8b2ebdc805ebae0dcc2778936a5c4ee486ba9268d801d",
        ),
    ),
    "bsi-grundschutz-plus-plus-367d7750": (
        _Source(
            "Grundschutz++-resolved_catalog.json",
            "bsi-catalog",
            "authoritative",
            "application/json",
            "BSI-Bund/Stand-der-Technik-Bibliothek",
            "367d775010abee641b258926bb482fcd05270059",
            "control_layer/Grundschutz++/Grundschutz++-resolved_catalog.json",
            5400710,
            "691e8ca0af378718a9e4b5876f3e194a449f3214dceab6d86bec3e2388a969df",
        ),
        _Source(
            "LICENSE",
            "license",
            "license",
            "text/plain",
            "BSI-Bund/Stand-der-Technik-Bibliothek",
            "367d775010abee641b258926bb482fcd05270059",
            "LICENSE",
            20137,
            "23ee78c8bae49cf08ea2f0c84945c66b987ebe4520881fb51b3dad4fb43d07c2",
        ),
        _Source(
            "README.md",
            "readme",
            "publication_context",
            "text/markdown",
            "BSI-Bund/Stand-der-Technik-Bibliothek",
            "367d775010abee641b258926bb482fcd05270059",
            "README.md",
            3604,
            "ad2cfde96832b9762b18711bb252d604777131c220588b0206df618ef154ee29",
        ),
    ),
}
_CATALOG_IDS = {
    "au-ism-2026.09.4": "au-ism",
    "cisa-scuba-m365-7ef9501d": "cisa-scuba",
    "bsi-grundschutz-plus-plus-367d7750": "bsi-grundschutz-plus-plus",
}
_CONVERTER_FILES = (
    "models/open_corpora.py",
    "models/catalog.py",
    "catalogs/loader.py",
    "catalogs/open_corpora.py",
)
_DOMAIN = b"evidentia.catalog-native.v1\x00"
_CACHE: OrderedDict[tuple[str, tuple[str, ...], str], tuple[bytes, bytes]] = OrderedDict()


def _compact(value: Any, budget: NativeBudget) -> bytes:
    budget.check()
    text = ""
    encoded = b""
    try:
        text = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        encoded = text.encode("utf-8")
        if len(encoded) > 16_777_216:
            raise NativeSourceError()
        budget.check()
        return encoded
    finally:
        text = ""
        encoded = b""


def _digest(raw: bytes, budget: NativeBudget) -> str:
    value = hashlib.sha256()
    for start in range(0, len(raw), 4096):
        budget.check()
        value.update(raw[start : start + 4096])
    return value.hexdigest()


def converter_manifest() -> tuple[dict[str, str], ...]:
    """Bind the controller-selected production files without generated-file cycles."""
    with native_operation() as budget:
        package = Path(__file__).resolve().parents[1]
        rows = []
        for relative in _CONVERTER_FILES:
            data = _read_file(package / relative, 2_097_152, budget)
            rows.append(
                {"path": "packages/evidentia-core/src/evidentia_core/" + relative, "sha256": _digest(data, budget)}
            )
        return tuple(rows)


def converter_sha256() -> str:
    with native_operation() as budget:
        return _digest(_compact(list(converter_manifest()), budget), budget)


def _source_bindings(profile: str) -> tuple[_Source, ...]:
    if type(profile) is not str or profile not in _SOURCES:
        raise NativeSourceError()
    return _SOURCES[profile]


def _source_snapshot(profile: str, sources: object, budget: NativeBudget) -> tuple[bytes, ...]:
    specs = _source_bindings(profile)
    if type(sources) is not dict:
        raise NativeSourceError()
    mapping = cast(dict[object, object], sources)
    if any(type(key) is not str for key in mapping) or set(mapping) != {s.name for s in specs}:
        raise NativeSourceError()
    owned: list[bytes] = []
    total = 0
    try:
        for spec in specs:
            raw = mapping[spec.name]
            if type(raw) is not bytes:
                raise NativeSourceError()
            data = raw
            total += len(data)
            if len(data) != spec.size or total > 8_388_608 or _digest(data, budget) != spec.digest:
                raise NativeSourceError()
            data.decode("utf-8", "strict")
            owned.append(data)
        return tuple(owned)
    except UnicodeError as exc:
        raise NativeSourceError() from exc
    finally:
        owned.clear()


def _members(node: CatalogJsonToken) -> dict[str, CatalogJsonToken]:
    if node.kind != "json_object":
        raise NativeSourceError()
    return {cast(str, key.value): value for key, value in node.members}


def _text(node: CatalogJsonToken | None) -> str:
    if node is None or node.kind != "json_string" or type(node.value) is not str:
        raise NativeSourceError()
    return node.value


def _items(node: CatalogJsonToken | None) -> tuple[CatalogJsonToken, ...]:
    if node is None:
        return ()
    if node.kind != "json_array":
        raise NativeSourceError()
    return node.items


class _Graph:
    def __init__(self, raw: tuple[bytes, ...], budget: NativeBudget) -> None:
        self.raw = raw
        self.budget = budget
        self.occurrences: list[dict[str, Any]] = []
        self.bindings: list[dict[str, Any]] = []
        self.context: list[int] = []
        self.diagnostics: list[dict[str, Any]] = []
        self._siblings: dict[tuple[int, int | None], int] = {}
        self._digests: dict[tuple[int, int, int], str] = {}
        self.ids: set[str] = set()
        self.normalized: set[str] = set()

    def ref(self, document: int, start: int, end: int, kind: str) -> dict[str, Any]:
        if not 0 <= start < end <= len(self.raw[document]):
            raise NativeSourceError()
        key = document, start, end
        digest = self._digests.get(key)
        if digest is None:
            digest = _digest(self.raw[document][start:end], self.budget)
            self._digests[key] = digest
        return {"document_index": document, "byte_start": start, "byte_end": end, "kind": kind, "sha256": digest}

    def token_ref(self, document: int, token: CatalogJsonToken) -> dict[str, Any]:
        return self.ref(document, token.start, token.end, token.kind)

    def selection(self, role: str, refs: list[dict[str, Any]]) -> dict[str, Any]:
        if len(refs) > 256:
            raise NativeSourceError()
        if not refs:
            value: dict[str, Any] = {"state": "absent"}
        elif len(refs) == 1 and refs[0]["kind"] == "json_null":
            value = {"state": "native_null", "refs": refs}
        else:
            if any(ref["kind"] == "json_null" for ref in refs):
                raise NativeSourceError()
            value = {"state": "present", "refs": refs}
        return {"role": role, "value": value}

    def add(
        self,
        document: int,
        kind: str,
        parent: int | None,
        source: dict[str, Any],
        fields: list[dict[str, Any]],
        selections: list[dict[str, Any]],
    ) -> int:
        self.budget.check()
        index = len(self.occurrences)
        if index >= 4096 or len(fields) > 64 or len(selections) > 32:
            raise NativeSourceError()
        key = document, parent
        ordinal = self._siblings.get(key, 0)
        self._siblings[key] = ordinal + 1
        self.occurrences.append(
            {
                "index": index,
                "kind": kind,
                "parent_index": parent,
                "sibling_ordinal": ordinal,
                "source": source,
                "fields": fields,
                "selections": selections,
            }
        )
        if kind not in ("control", "policy", "reference_policy"):
            self.context.append(index)
        return index

    def json(
        self,
        document: int,
        kind: str,
        parent: int | None,
        node: CatalogJsonToken,
        roles: dict[str, list[CatalogJsonToken]],
    ) -> int:
        return self.add(
            document,
            kind,
            parent,
            self.token_ref(document, node),
            [
                {"name": _text(key), "key": self.token_ref(document, key), "value": self.token_ref(document, value)}
                for key, value in node.members
            ],
            [self.selection(role, [self.token_ref(document, x) for x in values]) for role, values in roles.items()],
        )

    def identity(self, identity: str) -> None:
        normal = _normalize_control_id(identity)
        if not identity or len(identity.encode("utf-8")) > 128 or identity in self.ids or normal in self.normalized:
            raise NativeSourceError()
        self.ids.add(identity)
        self.normalized.add(normal)

    def bind(
        self, identity: str, occurrence: int, family: int | None, parent: str | None, criticality: str | None = None
    ) -> None:
        if len(self.bindings) >= 2048:
            raise NativeSourceError()
        self.bindings.append(
            {
                "control_id": identity,
                "occurrence_index": occurrence,
                "family_occurrence_index": family,
                "parent_control_id": parent,
                "admitted_criticality": criticality,
            }
        )

    def clear(self) -> None:
        self.raw = ()
        self.occurrences.clear()
        self.bindings.clear()
        self.context.clear()
        self.diagnostics.clear()
        self._siblings.clear()
        self._digests.clear()
        self.ids.clear()
        self.normalized.clear()


def _control(
    identity: str,
    title: str,
    description: str,
    family: str | None,
    ordering: int,
    *,
    control_class: str | None = None,
    guidance: str | None = None,
) -> dict[str, Any]:
    return {
        "id": identity,
        "title": title,
        "description": description,
        "family": family,
        "class": control_class,
        "control_class": control_class,
        "priority": None,
        "baseline_impact": [],
        "enhancements": [],
        "related_controls": [],
        "assessment_objectives": [],
        "objective": None,
        "risk_tier": None,
        "applies_to_annex_iii": None,
        "guidance": guidance,
        "examples": [],
        "parameters": {},
        "ordering": ordering,
        "tier": None,
        "license_required": False,
        "license_url": None,
        "placeholder": False,
        "withdrawn": False,
        "properties": {},
        "source_rows": [],
    }


def _catalog(
    profile: str, title: str, version: str, controls: list[dict[str, Any]], families: list[str]
) -> dict[str, Any]:
    return {
        "framework_id": _CATALOG_IDS[profile],
        "framework_name": title,
        "version": version,
        "source": _SOURCES[profile][0].repository + "@" + _SOURCES[profile][0].commit,
        "controls": controls,
        "families": families,
        "family_hierarchy": None,
        "category": "control",
        "tier": None,
        "v0_9_3_note": None,
        "annex_iii_risk_categories": None,
        "license_required": False,
        "license_terms": None,
        "license_url": None,
        "placeholder": False,
        "status": None,
        "notes": (
            "Pinned source projection; native context is retained separately. "
            "No assessment or applicability is inferred."
        ),
        "verified_on": None,
        "superseded_by": None,
        "audit_contexts": {},
        "publication_notices": [],
    }


def _parts(nodes: tuple[CatalogJsonToken, ...], name: str) -> list[CatalogJsonToken]:
    selected = []
    for node in nodes:
        fields = _members(node)
        if _text(fields.get("name")) == name:
            selected.append(node)
        else:
            selected.extend(_parts(_items(fields.get("parts")), name))
    return selected


def _part_prose(node: CatalogJsonToken) -> list[str]:
    fields = _members(node)
    prose = [_text(fields["prose"])] if "prose" in fields else []
    for child in _items(fields.get("parts")):
        prose.extend(_part_prose(child))
    return prose


def _oscal(graph: _Graph, profile: str) -> dict[str, Any]:
    document = _load_catalog_data(None, raw_bytes=graph.raw[0], mode="source_json")
    root = _members(document.root)
    catalog = root.get("catalog")
    if catalog is None:
        raise NativeSourceError()
    fields = _members(catalog)
    root_index = graph.json(0, "catalog", None, catalog, {})
    metadata = fields.get("metadata")
    if metadata is None:
        raise NativeSourceError()
    meta = _members(metadata)
    graph.json(
        0,
        "metadata",
        root_index,
        metadata,
        {
            "title": [meta["title"]] if "title" in meta else [],
            "native_version": [meta["version"]] if "version" in meta else [],
            "schema_version": [meta["oscal-version"]] if "oscal-version" in meta else [],
            "publication_time": [meta["published"]] if "published" in meta else [],
            "last_modified": [meta["last-modified"]] if "last-modified" in meta else [],
        },
    )
    families: list[str] = []
    counts = {"group": 0, "control": 0, "principle": 0}

    def walk(
        node: CatalogJsonToken, kind: str, parent_index: int, family: int | None, parent_control: str | None
    ) -> list[dict[str, Any]]:
        values = _members(node)
        identity = _text(values["id"]) if "id" in values else None
        cls = _text(values["class"]) if "class" in values else None
        if kind == "control" and profile == "au-ism-2026.09.4" and cls == "ISM-principle":
            kind = "principle"
        if kind != "group":
            if identity is None:
                raise NativeSourceError()
            graph.identity(identity)
        parts = _items(values.get("parts"))
        statements = _parts(parts, "statement")
        guides = _parts(parts, "guidance")
        props = _items(values.get("props"))
        roles: dict[str, list[CatalogJsonToken]] = {
            "native_id": [values["id"]] if "id" in values else [],
            "title": [values["title"]] if "title" in values else [],
            "class": [values["class"]] if "class" in values else [],
            "statement": statements,
            "guidance": guides,
            "parameter": [values["params"]] if "params" in values else [],
        }
        for role, name in (
            ("applicability", "applicability"),
            ("essential_eight_applicability", "essential-eight-applicability"),
            ("status", "status"),
        ):
            roles[role] = [p for p in props if _text(_members(p).get("name")) == name]
        index = graph.json(0, kind, parent_index, node, roles)
        counts[kind] += 1
        if kind == "group":
            family = index
            families.append("native-group:" + str(index))
        result: list[dict[str, Any]] = []
        current: dict[str, Any] | None = None
        if kind == "control":
            assert identity is not None
            description = "\n".join(text for part in statements for text in _part_prose(part))
            guidance = "\n".join(text for part in guides for text in _part_prose(part)) if guides else None
            graph.bind(identity, index, family, parent_control)
            current = _control(
                identity,
                _text(values.get("title")),
                description,
                "native-group:" + str(family) if family is not None else None,
                len(graph.bindings) - 1,
                control_class=cls,
                guidance=guidance,
            )
            result.append(current)
            parent_control = identity
        for key, value in node.members:
            if key.value in ("groups", "controls"):
                child_kind = "group" if key.value == "groups" else "control"
                for child in _items(value):
                    nested = walk(child, child_kind, index, family, parent_control)
                    if current is not None:
                        current["enhancements"].extend(nested)
                    else:
                        result.extend(nested)
        return result

    controls: list[dict[str, Any]] = []
    for key, value in catalog.members:
        if key.value in ("groups", "controls"):
            for child in _items(value):
                controls.extend(walk(child, "group" if key.value == "groups" else "control", root_index, None, None))
    expected = (
        {"group": 582, "control": 1143, "principle": 49}
        if profile.startswith("au-")
        else {"group": 160, "control": 1000, "principle": 0}
    )
    if counts != expected:
        raise NativeSourceError()
    return _catalog(profile, _text(meta.get("title")), _text(meta.get("version")), controls, families)


@dataclass(frozen=True, slots=True)
class _Heading:
    level: int
    title: str
    start: int
    end: int
    title_start: int
    title_end: int
    stop: int


def _headings(raw: bytes, budget: NativeBudget) -> tuple[_Heading, ...]:
    entries: list[tuple[int, str, int, int, int, int]] = []
    offset = 0
    fence: bytes | None = None
    pre = False
    for line in raw.splitlines(keepends=True):
        budget.check()
        stripped = line.lstrip(b" \t")
        lower = stripped.lower()
        if pre:
            if b"</pre>" in lower:
                pre = False
        elif fence is not None:
            if stripped.startswith(fence) and not stripped[len(fence) :].strip():
                fence = None
        elif lower.startswith(b"<pre"):
            pre = b"</pre>" not in lower
        elif stripped.startswith((bytes((96,)) * 3, b"~~~")):
            marker = stripped[:1]
            size = len(stripped) - len(stripped.lstrip(marker))
            fence = marker * size
        else:
            match = re.fullmatch(rb"(#{1,6})[ \t]+([^\r\n]+?)[ \t]*(?:\r?\n)?", line)
            if match:
                entries.append(
                    (
                        len(match[1]),
                        match[2].decode("utf-8"),
                        offset,
                        offset + len(line),
                        offset + match.start(2),
                        offset + match.end(2),
                    )
                )
        offset += len(line)
    if pre or fence is not None:
        raise NativeSourceError()
    result = []
    for index, entry in enumerate(entries):
        stop = next((other[2] for other in entries[index + 1 :] if other[0] <= entry[0]), len(raw))
        result.append(_Heading(*entry, stop))
    return tuple(result)


def _view(raw: bytes, start: int, end: int) -> str:
    return raw[start:end].decode("utf-8").replace("\r\n", "\n").strip(" \t\r\n")


_POLICY = re.compile(r"MS\.[A-Z]+\.\d+(?:\.\d+)*v\d+")
_META = tuple(
    re.compile(pattern)
    for pattern in (
        rb"(?m)^[-*][ \t]+_([^_\r\n]+):_[ \t]*",
        rb"(?m)^[-*][ \t]+_([^_\r\n]+)_:[ \t]*",
        rb"(?m)^[-*][ \t]+(Note):[ \t]*",
        rb"(?m)^>[ \t]*(Note):[ \t]*",
    )
)
_CRITICALITY = re.compile(
    rb"<!--Policy:[ \t]*(MS\.[A-Z]+\.\d+(?:\.\d+)*v\d+);[ \t]*Criticality:[ \t]*(SHALL|SHOULD)[ \t]*-->"
)
_META_ROLES = {
    "Rationale": "rationale",
    "Last modified": "last_modified",
    "Last Modified": "last_modified",
    "Note": "note",
    "NIST SP 800-53 Rev. 5 FedRAMP High Baseline Mapping": "nist_mapping",
    "MITRE ATT&CK TTP Mapping": "mitre_mapping",
}


def _markdown_policy(
    graph: _Graph,
    document: int,
    heading: _Heading,
    section: _Heading,
    section_index: int,
    headings: tuple[_Heading, ...],
) -> tuple[dict[str, Any], dict[str, str]]:
    raw = graph.raw[document]
    identity = heading.title
    graph.identity(identity)
    metadata = sorted(
        (match for pattern in _META for match in pattern.finditer(raw, heading.end, heading.stop)),
        key=lambda match: match.start(),
    )
    critical = list(_CRITICALITY.finditer(raw, heading.end, heading.stop))
    if len(critical) != 1 or any(m[1].decode("utf-8") not in _META_ROLES for m in metadata):
        raise NativeSourceError()
    markers = [m.start() for m in metadata] + [critical[0].start()]
    for match in re.finditer(rb"(?m)^(?:\[!\[|<!--)", raw[heading.end : heading.stop]):
        markers.append(heading.end + match.start())
    statement_end = min(markers, default=heading.stop)
    refs: dict[str, list[dict[str, Any]]] = {
        "native_id": [graph.ref(document, heading.title_start, heading.title_end, "utf8_text")],
        "title": [graph.ref(document, heading.title_start, heading.title_end, "utf8_text")],
        "statement": [graph.ref(document, heading.end, statement_end, "markdown_block")],
        "rationale": [],
        "note": [],
        "last_modified": [],
        "implementation": [],
        "criticality": [graph.ref(document, critical[0].start(2), critical[0].end(2), "utf8_text")],
        "criticality_identity": [graph.ref(document, critical[0].start(1), critical[0].end(1), "utf8_text")],
        "resources": [],
        "license_requirements": [],
        "badge": [],
        "nist_mapping": [],
        "mitre_mapping": [],
    }
    fields: list[dict[str, Any]] = [
        {
            "name": identity,
            "key": graph.ref(document, heading.start, heading.title_start, "utf8_text"),
            "value": graph.ref(document, heading.title_start, heading.title_end, "utf8_text"),
        }
    ]
    text_values: dict[str, list[str]] = {"statement": [_view(raw, heading.end, statement_end)]}
    for index, marker in enumerate(metadata):
        label = marker[1].decode("utf-8")
        end = metadata[index + 1].start() if index + 1 < len(metadata) else heading.stop
        role = _META_ROLES[label]
        fields.append(
            {
                "name": label,
                "key": graph.ref(document, marker.start(1), marker.end(1), "utf8_text"),
                "value": graph.ref(document, marker.end(), end, "markdown_block"),
            }
        )
        refs[role].append(graph.ref(document, marker.end(), end, "markdown_block"))
        text_values.setdefault(role, []).append(_view(raw, marker.end(), end))
    for badge in re.finditer(rb"(?m)^\[!\[([^\]\r\n]+)\][^\r\n]+", raw[heading.end : heading.stop]):
        start = heading.end + badge.start()
        end = heading.end + badge.end()
        refs["badge"].append(graph.ref(document, start, end, "markdown_block"))
        fields.append(
            {
                "name": badge[1].decode("utf-8"),
                "key": graph.ref(document, heading.end + badge.start(1), heading.end + badge.end(1), "utf8_text"),
                "value": graph.ref(document, start, end, "markdown_block"),
            }
        )
    instructions = [
        h
        for h in headings
        if h.level == 4 and h.title == identity + " Instructions" and section.start < h.start < section.stop
    ]
    if len(instructions) != 1:
        raise NativeSourceError()
    instruction = instructions[0]
    refs["implementation"].append(graph.ref(document, instruction.end, instruction.stop, "markdown_block"))
    text_values["implementation"] = [_view(raw, instruction.end, instruction.stop)]
    shared: dict[str, str] = {}
    for label, role in (
        ("Resources", "resources"),
        ("License Requirements", "license_requirements"),
        ("Implementation", "implementation_context"),
    ):
        matches = [h for h in headings if h.level == 3 and h.title == label and section.start < h.start < section.stop]
        if len(matches) != 1:
            raise NativeSourceError()
        shared_heading = matches[0]
        end = next(
            (h.start for h in headings if shared_heading.end <= h.start < shared_heading.stop), shared_heading.stop
        )
        if label != "Implementation":
            end = shared_heading.stop
            refs[role].append(graph.ref(document, shared_heading.end, end, "markdown_block"))
        shared[role] = _view(raw, shared_heading.end, end)
    fields.sort(key=lambda field: field["key"]["byte_start"])
    index = graph.add(
        document,
        "policy",
        section_index,
        graph.ref(document, heading.start, heading.stop, "markdown_block"),
        fields,
        [graph.selection(role, values) for role, values in refs.items()],
    )
    comment_identity = critical[0][1].decode("ascii")
    admitted = critical[0][2].decode("ascii") if comment_identity == identity else None
    if admitted is None:
        graph.diagnostics.append(
            {
                "code": "source_identity_conflict",
                "occurrence_index": index,
                "refs": [graph.ref(document, critical[0].start(), critical[0].end(), "markdown_block")],
            }
        )
    graph.bind(identity, index, section_index, None, admitted)
    description = "Statement:\n" + text_values["statement"][0]
    for note in text_values.get("note", []):
        description += "\n\nNote:\n" + note
    guidance_parts = [
        ("Rationale", "\n\n".join(text_values.get("rationale", []))),
        ("Shared implementation", shared["implementation_context"]),
        ("Instructions", text_values["implementation"][0]),
        ("License Requirements", shared["license_requirements"]),
        ("Resources", shared["resources"]),
    ]
    guidance = "\n\n".join(label + ":\n" + value for label, value in guidance_parts)
    control = _control(
        identity,
        identity,
        description,
        "native-section:" + str(section_index),
        len(graph.bindings) - 1,
        guidance=guidance,
    )
    comparisons = {
        "name": text_values["statement"][0],
        "rationale": "\n\n".join(text_values.get("rationale", [])),
        "lastModified": "\n\n".join(text_values.get("last_modified", [])),
        "implementation": text_values["implementation"][0],
        "criticality": critical[0][2].decode("ascii"),
    }
    return control, comparisons


def _scuba(graph: _Graph) -> dict[str, Any]:
    controls: list[dict[str, Any]] = []
    families: list[str] = []
    policy_info: dict[str, tuple[int, dict[str, str]]] = {}
    section_count = 0
    for document, raw in enumerate(graph.raw[:8]):
        headings = _headings(raw, graph.budget)
        root = graph.add(document, "catalog", None, graph.ref(document, 0, len(raw), "markdown_block"), [], [])
        selected_stack: list[tuple[_Heading, int]] = []
        for heading in headings:
            graph.budget.check()
            while selected_stack and heading.start >= selected_stack[-1][0].stop:
                selected_stack.pop()
            section_entry = next(
                ((h, i) for h, i in reversed(selected_stack) if h.level == 2 and re.match(r"\d+\. ", h.title)), None
            )
            parent = selected_stack[-1][1] if selected_stack else root
            if heading.level == 4 and _POLICY.fullmatch(heading.title):
                if section_entry is None:
                    raise NativeSourceError()
                before = len(graph.occurrences)
                control, comparison = _markdown_policy(
                    graph, document, heading, section_entry[0], section_entry[1], headings
                )
                controls.append(control)
                policy_info[heading.title] = before, comparison
                continue
            is_section = heading.level == 2 and re.match(r"\d+\. ", heading.title) is not None
            kind = "section" if is_section else "context_block"
            fields = [
                {
                    "name": heading.title,
                    "key": graph.ref(document, heading.start, heading.title_start, "utf8_text"),
                    "value": graph.ref(document, heading.title_start, heading.title_end, "utf8_text"),
                }
            ]
            roles = {"title": [graph.ref(document, heading.title_start, heading.title_end, "utf8_text")]}
            if heading.title in ("Resources", "License Requirements", "Implementation"):
                role = {
                    "Resources": "resources",
                    "License Requirements": "license_requirements",
                    "Implementation": "implementation",
                }[heading.title]
                end = next((h.start for h in headings if heading.end <= h.start < heading.stop), heading.stop)
                if heading.end < end:
                    roles[role] = [graph.ref(document, heading.end, end, "markdown_block")]
            index = graph.add(
                document,
                kind,
                parent,
                graph.ref(document, heading.start, heading.stop, "markdown_block"),
                fields,
                [graph.selection(role, values) for role, values in roles.items()],
            )
            selected_stack.append((heading, index))
            if is_section:
                section_count += 1
                families.append("native-section:" + str(index))
    if section_count != 51 or len(controls) != 128:
        raise NativeSourceError()
    reference = _load_catalog_data(None, raw_bytes=graph.raw[8], mode="source_json")
    reference_fields = _members(reference.root)
    ref_root = graph.json(
        8,
        "metadata",
        None,
        reference.root,
        {"native_version": [reference_fields["Version"]] if "Version" in reference_fields else []},
    )
    baselines = reference_fields.get("baselines")
    if baselines is None:
        raise NativeSourceError()
    found: set[str] = set()
    for _, product in baselines.members:
        for node in _items(product):
            values = _members(node)
            identity = _text(values.get("id"))
            if identity in found:
                raise NativeSourceError()
            found.add(identity)
            reference_roles = {
                role: [values[key]] if key in values else []
                for role, key in (
                    ("native_id", "id"),
                    ("title", "name"),
                    ("rationale", "rationale"),
                    ("criticality", "criticality"),
                    ("last_modified", "lastModified"),
                    ("implementation", "implementation"),
                    ("resources", "resources"),
                    ("license_requirements", "licenseRequirements"),
                    ("badge", "badges"),
                    ("mitre_mapping", "mitreMapping"),
                )
            }
            graph.json(8, "reference_policy", ref_root, node, reference_roles)
            if identity in policy_info:
                policy_index, comparison = policy_info[identity]
                graph.occurrences[policy_index]["selections"].append(
                    graph.selection("reference_record", [graph.token_ref(8, node)])
                )
                differences = [key for key, value in comparison.items() if _text(values.get(key)) != value]
                if differences:
                    graph.diagnostics.append(
                        {
                            "code": "source_reference_difference",
                            "occurrence_index": policy_index,
                            "refs": [graph.token_ref(8, values[key]) for key in differences[:8]],
                        }
                    )
    missing = set(policy_info) - found
    if missing != {"MS.AAD.9.1v1"} or len(found) != 127:
        raise NativeSourceError()
    for identity in sorted(missing):
        index = policy_info[identity][0]
        graph.occurrences[index]["selections"].append(graph.selection("reference_record", []))
        source = graph.occurrences[index]["source"]
        graph.diagnostics.append(
            {"code": "missing_reference_record", "occurrence_index": index, "refs": [dict(source)]}
        )
    return _catalog(
        "cisa-scuba-m365-7ef9501d",
        "CISA M365 Secure Configuration Baselines",
        "7ef9501d7de9804ddb9d6013af6b665cccfb39d9",
        controls,
        families,
    )


def _derive(profile: str, raw: tuple[bytes, ...], converter: str, budget: NativeBudget) -> tuple[bytes, bytes]:
    graph = _Graph(raw, budget)
    documents: list[dict[str, Any]] = []
    projection: dict[str, Any] = {}
    data: dict[str, Any] = {}
    try:
        for spec, body in zip(_SOURCES[profile], raw, strict=True):
            documents.append(
                {
                    "binding": {
                        "source_key": spec.key,
                        "role": spec.role,
                        "media_type": spec.media,
                        "repository": spec.repository,
                        "commit": spec.commit,
                        "upstream_path": spec.upstream,
                        "raw_bytes": spec.size,
                        "raw_sha256": spec.digest,
                    },
                    "raw_utf8": body.decode("utf-8"),
                }
            )
        projection = _scuba(graph) if profile == "cisa-scuba-m365-7ef9501d" else _oscal(graph, profile)
        first_companion = 9 if profile == "cisa-scuba-m365-7ef9501d" else 1
        for document in range(first_companion, len(raw)):
            graph.add(document, "context_block", None, graph.ref(document, 0, len(raw[document]), "utf8_text"), [], [])
        if profile == "au-ism-2026.09.4":
            graph.diagnostics.append({"code": "legacy_ids_retired", "occurrence_index": None, "refs": []})
        data = {
            "schema_version": "catalog-native-v1",
            "profile": profile,
            "catalog_id": _CATALOG_IDS[profile],
            "converter_id": "evidentia-open-corpora-v1",
            "converter_sha256": converter,
            "documents": documents,
            "occurrences": graph.occurrences,
            "control_bindings": graph.bindings,
            "context_indices": graph.context,
            "diagnostics": graph.diagnostics,
        }
        if len(graph.context) > 1024 or len(graph.diagnostics) > 512:
            raise NativeSourceError()
        native_bytes = _compact(data, budget)
        projection_bytes = _compact(projection, budget)
        return native_bytes, projection_bytes
    finally:
        graph.clear()
        documents.clear()
        projection.clear()
        data.clear()


def _authority(profile: str, raw: tuple[bytes, ...], converter: str, budget: NativeBudget) -> tuple[bytes, bytes]:
    key = profile, tuple(_digest(body, budget) for body in raw), converter
    cached = _CACHE.get(key)
    if cached is not None:
        budget.check()
        _CACHE.move_to_end(key)
        return cached
    captured = _derive(profile, raw, converter, budget)
    # Cache only immutable bytes derived after every pinned source hash passed.
    _CACHE[key] = captured
    while len(_CACHE) > 3:
        _CACHE.popitem(last=False)
    return captured


def _decode(raw: bytes) -> dict[str, Any]:
    return _load_catalog_data(None, raw_bytes=raw, mode="wire_json").data


def _bundle_bytes(data: bytes, budget: NativeBudget) -> tuple[str, bytes]:
    digest = _digest(_DOMAIN + data, budget)
    encoded = b'{"bundle_sha256":"' + digest.encode("ascii") + b'","data":' + data + b"}"
    if len(encoded) > 12_058_624:
        raise NativeSourceError()
    return digest, encoded


def _attach(projection: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any]:
    binding = {row["control_id"]: row["occurrence_index"] for row in bundle["data"]["control_bindings"]}

    def walk(controls: list[dict[str, Any]]) -> None:
        for control in controls:
            control["native_source_ref"] = {
                "bundle_sha256": bundle["bundle_sha256"],
                "occurrence_index": binding[control["id"]],
            }
            walk(control["enhancements"])

    walk(projection["controls"])
    projection["native_source"] = bundle
    return projection


def _measure(projection: dict[str, Any], bundle: dict[str, Any], wire: bytes, budget: NativeBudget) -> None:
    documents = len(_compact(bundle["data"]["documents"], budget))
    occurrences = len(_compact(bundle["data"]["occurrences"], budget))
    controls = len(_compact(projection["controls"], budget))
    remainder = len(wire) - documents - occurrences - controls
    if (
        documents > 7_340_032
        or occurrences > 6_291_456
        or controls > 2_097_152
        or not 0 <= remainder <= 524_288
        or len(wire) > 16_777_216
    ):
        raise NativeSourceError()
    budget.check()


def validate_native_data(value: object) -> None:
    """Reconstruct source and selections; claimed hashes alone do not admit data."""
    with native_operation() as budget:
        data = native_value(value)
        if type(data) is not dict:
            raise NativeSourceError()
        raw: tuple[bytes, ...] = ()
        sources: dict[str, bytes] = {}
        try:
            profile = data["profile"]
            specs = _source_bindings(profile)
            documents = data["documents"]
            if len(documents) != len(specs):
                raise NativeSourceError()
            for spec, document in zip(specs, documents, strict=True):
                if type(document["raw_utf8"]) is not str:
                    raise NativeSourceError()
                sources[spec.name] = document["raw_utf8"].encode("utf-8")
            raw = _source_snapshot(profile, sources, budget)
            converter = converter_sha256()
            expected, _ = _authority(profile, raw, converter, budget)
            if _compact(data, budget) != expected:
                raise NativeSourceError()
        finally:
            raw = ()
            sources.clear()
            data.clear()


def validate_catalog_mapping(data: object) -> bytes:
    """Return captured complete wire only after pinned source correspondence."""
    from evidentia_core.models.open_corpora import _preflight

    with native_operation() as budget:
        _preflight(data)
        if type(data) is not dict:
            raise NativeSourceError()
        mapping = cast(dict[str, Any], data)
        captured = b""
        encoded = b""
        native_bytes = b""
        projection_bytes = b""
        sources: dict[str, bytes] = {}
        raw: tuple[bytes, ...] = ()
        expected_mapping: dict[str, Any] = {}
        try:
            captured = _compact(mapping, budget)
            bundle = mapping.get("native_source")
            if type(bundle) is not dict or type(bundle.get("data")) is not dict:
                raise NativeSourceError()
            native = bundle["data"]
            profile = native.get("profile")
            specs = _source_bindings(profile)
            documents = native.get("documents")
            if type(documents) is not list or len(documents) != len(specs):
                raise NativeSourceError()
            for spec, document in zip(specs, documents, strict=True):
                if type(document) is not dict or type(document.get("raw_utf8")) is not str:
                    raise NativeSourceError()
                sources[spec.name] = document["raw_utf8"].encode("utf-8")
            raw = _source_snapshot(profile, sources, budget)
            native_bytes, projection_bytes = _authority(profile, raw, converter_sha256(), budget)
            _, encoded = _bundle_bytes(native_bytes, budget)
            expected_mapping = _attach(_restore_catalog_capture(projection_bytes), _restore_catalog_capture(encoded))
            if captured != _compact(expected_mapping, budget):
                raise NativeSourceError()
            budget.check()
            return captured
        finally:
            captured = b""
            encoded = b""
            native_bytes = b""
            projection_bytes = b""
            raw = ()
            sources.clear()
            expected_mapping.clear()


@dataclass(frozen=True, slots=True)
class NativeCatalogSnapshot:
    """Accepted immutable wire; each read returns a fresh detached value."""

    wire: bytes
    bundle_sha256: str
    projection_sha256: str

    def data(self) -> dict[str, Any]:
        with native_operation():
            data = _decode(self.wire)
            captured = b""
            try:
                captured = validate_catalog_mapping(data)
                return _restore_catalog_capture(captured)
            finally:
                data.clear()
                captured = b""

    def catalog(self) -> ControlCatalog:
        from evidentia_core.models.catalog import _NativeControlCatalog

        with native_operation():
            data = _decode(self.wire)
            try:
                if type(data.get("native_source")) is not dict:
                    raise NativeSourceError()
                # The ordinary model's wrap validator performs complete source
                # and projection verification on this captured wire mapping.
                return _NativeControlCatalog.model_validate(data)
            finally:
                data.clear()


def derive_native_catalog(profile: str, sources: object) -> NativeCatalogSnapshot:
    """Derive one exact profile from an explicit native mapping of raw source bytes."""
    from evidentia_core.models.open_corpora import NativeBundle

    with native_operation() as budget:
        raw = _source_snapshot(profile, sources, budget)
        projection: dict[str, Any] = {}
        bundle: dict[str, Any] = {}
        wire = b""
        try:
            converter = converter_sha256()
            native_bytes, projection_bytes = _authority(profile, raw, converter, budget)
            digest, bundle_bytes = _bundle_bytes(native_bytes, budget)
            bundle = _restore_catalog_capture(bundle_bytes)
            NativeBundle.model_validate(bundle)
            projection = _attach(_restore_catalog_capture(projection_bytes), bundle)
            wire = _compact(projection, budget)
            _measure(projection, bundle, wire, budget)
            # Verify only the already captured complete wire in the reserved phase.
            with budget.publication():
                validate_catalog_mapping(_restore_catalog_capture(wire))
                if converter != converter_sha256():
                    raise NativeSourceError("catalog_generation_changed")
                budget.check(publication=True)
                return NativeCatalogSnapshot(wire, digest, _digest(projection_bytes, budget))
        finally:
            raw = ()
            projection.clear()
            bundle.clear()
            wire = b""


def catalog_model_data(value: ControlCatalog) -> dict[str, Any]:
    """Copy exact owned model storage without calling overridden serialization."""
    from evidentia_core.models.catalog import _NativeCatalogControl, _NativeControlCatalog
    from evidentia_core.models.open_corpora import _MODEL_TYPES

    known = {id(cls): cls for cls in (CatalogControl, ControlCatalog, _NativeCatalogControl, _NativeControlCatalog)}
    active: set[int] = set()
    count = 0

    def visit(item: Any) -> Any:
        nonlocal count
        count += type(item) is list or type(item) in (str, int, bool, type(None))
        if count > 262144:
            raise NativeSourceError()
        kind = type(item)
        if item is None or kind is str or kind is bool or kind is int:
            return item
        identity = id(item)
        if identity in active:
            raise NativeSourceError()
        active.add(identity)
        try:
            if kind is list:
                return [visit(child) for child in item]
            if kind is dict:
                if any(type(key) is not str for key in item):
                    raise NativeSourceError()
                return {key: visit(child) for key, child in item.items()}
            if _MODEL_TYPES.get(id(kind)) is kind:
                return native_value(item)
            if known.get(id(kind)) is not kind:
                raise NativeSourceError()
            fields = kind.model_fields
            data = object.__getattribute__(item, "__dict__")
            if set(fields) != set(data):
                raise NativeSourceError()
            return {field.alias or name: visit(data[name]) for name, field in fields.items()}
        finally:
            active.remove(identity)

    return cast(dict[str, Any], visit(value))


_PACKAGE_DIRECTORIES = {
    "au-ism-2026.09.4": "sources/au-ism/2026.09.4",
    "cisa-scuba-m365-7ef9501d": "sources/cisa-scuba-m365/7ef9501d7de9804ddb9d6013af6b665cccfb39d9",
}
_CATALOG_PATHS = {"au-ism-2026.09.4": "international/au-ism.json", "cisa-scuba-m365-7ef9501d": "cisa/scuba.json"}
_NOTICES = {
    "au-ism-2026.09.4": (
        "notices/ism.txt",
        "Australian ISM 2026.09.4 is retained as an exact pinned source snapshot.\n"
        "Publisher attribution and licensing context remain in the source README.\n"
        "The 1,143 controls are indexed; 49 principles remain native context.\n"
        "The 24 former heading identifiers are retired without automatic replacements.\n"
        "Select current controls explicitly. Existing evidence is not rewritten.\n",
    ),
    "cisa-scuba-m365-7ef9501d": (
        "notices/scuba.txt",
        "CISA M365 SCuBA source snapshot at commit 7ef9501d7de9804ddb9d6013af6b665cccfb39d9.\n"
        "The eight authoritative Markdown documents provide 128 policy identities.\n"
        "The unchanged reference JSON contains 127 records and remains separate.\n"
        "Repository CC0 and Microsoft-adapted CC BY 4.0 notices are retained verbatim.\n"
        "Per-document attribution and product-license prerequisites remain source data.\n"
        "The SECURITYSUITE.7.2v1 criticality comment names a different identity;\n"
        "its admitted criticality is null. No checks are executed by this catalog.\n",
    ),
}
_LEGACY_ISM = {
    "schema_version": "catalog-native-legacy-migration-v1",
    "catalog_id": "au-ism",
    "old_version": "September 2024",
    "old_catalog_sha256": "d6d06db9f6d06bf81fefbf6350d556c44c5fdd325d003d2e72b526a95b113735",
    "new_profile": "au-ism-2026.09.4",
    "new_source_sha256": "237ea09362b8449ed5c5ee85de4725a0468ee73d13af7cf61c26d4e6ac47f12d",
    "rows": [
        {
            "old_id": "ISM.Gov",
            "old_title": "Cyber security principles — Govern",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.Protect",
            "old_title": "Cyber security principles — Protect",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.Detect",
            "old_title": "Cyber security principles — Detect",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.Respond",
            "old_title": "Cyber security principles — Respond",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.Strategy",
            "old_title": "Guidelines for cyber security roles and governance",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.PhysicalSec",
            "old_title": "Guidelines for physical security",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.Personnel",
            "old_title": "Guidelines for personnel security",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.CommInfra",
            "old_title": "Guidelines for communications infrastructure",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.CommSys",
            "old_title": "Guidelines for communications systems",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.ICTEqpt",
            "old_title": "Guidelines for ICT equipment",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.Media",
            "old_title": "Guidelines for media",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.SysHardening",
            "old_title": "Guidelines for system hardening",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.SysMgmt",
            "old_title": "Guidelines for system management",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.SysMon",
            "old_title": "Guidelines for system monitoring",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.Software",
            "old_title": "Guidelines for software development",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.DbSys",
            "old_title": "Guidelines for database systems",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.Email",
            "old_title": "Guidelines for email",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.Networks",
            "old_title": "Guidelines for networking",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.Crypto",
            "old_title": "Guidelines for cryptography",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.Gateways",
            "old_title": "Guidelines for gateways",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.DataTrans",
            "old_title": "Guidelines for data transfers",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.CyberIncident",
            "old_title": "Guidelines for cyber security incidents",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.OutSysMgmt",
            "old_title": "Guidelines for outsourcing",
            "status": "retired_heading",
            "replacement_ids": [],
        },
        {
            "old_id": "ISM.Procure",
            "old_title": "Guidelines for procurement and outsourcing",
            "status": "retired_heading",
            "replacement_ids": [],
        },
    ],
    "notice": (
        "These old headings are not current assessment-control identities. "
        "Select current native controls explicitly; no automatic aliases or historical evidence rewrites."
    ),
}


def source_manifest() -> dict[str, Any]:
    """Return the finite offline input table without source payloads or host paths."""
    return {
        "schema_version": "open-corpora-sources-v1",
        "converter_id": "evidentia-open-corpora-v1",
        "converter_files": ["packages/evidentia-core/src/evidentia_core/" + p for p in _CONVERTER_FILES],
        "profiles": [
            {
                "profile": profile,
                "catalog_id": _CATALOG_IDS[profile],
                "distribution": "bundled" if profile in _PACKAGE_DIRECTORIES else "external_only",
                "sources": [
                    {
                        "name": s.name,
                        "repository": s.repository,
                        "commit": s.commit,
                        "upstream_path": s.upstream,
                        "raw_bytes": s.size,
                        "raw_sha256": s.digest,
                    }
                    for s in specs
                ],
            }
            for profile, specs in _SOURCES.items()
        ],
    }


_ISM_STORED_CHUNKS = (
    (1711308, "717617f753da6f1a9f498a3b5429d08297cf5519109790608968a9133678483c"),
    (1186531, "1ac6adfa444cd624f5bed6c87dcf668d7a9863f674df966e529a39946c356426"),
)


def _ism_chunks(raw: bytes, budget: NativeBudget) -> tuple[bytes, bytes]:
    from evidentia_core.models.open_corpora import SourceChunk

    spec = _SOURCES["au-ism-2026.09.4"][0]
    if type(raw) is not bytes or len(raw) != spec.size or _digest(raw, budget) != spec.digest:
        raise NativeSourceError()
    start = 0
    result: list[bytes] = []
    try:
        for index in range(2):
            end = len(raw) if len(raw) - start <= 1_572_864 else raw.rfind(b"\n", start, start + 1_572_864) + 1
            if not start < end <= min(start + 1_572_864, len(raw)):
                raise NativeSourceError()
            fragment = raw[start:end]
            envelope = {
                "schema_version": "catalog-source-chunk-v1",
                "source_key": "ism-catalog",
                "index": index,
                "byte_start": start,
                "byte_length": len(fragment),
                "sha256": _digest(fragment, budget),
                "raw_utf8": fragment.decode("utf-8"),
            }
            SourceChunk.model_validate(envelope)
            encoded = _compact(envelope, budget) + b"\n"
            if len(encoded) > 2_097_152:
                raise NativeSourceError()
            result.append(encoded)
            start = end
        if start != len(raw):
            raise NativeSourceError()
        return result[0], result[1]
    finally:
        result.clear()


def package_outputs(profile: str, sources: object) -> dict[str, bytes]:
    """Generate the complete bundled profile output set in memory; never save it."""
    output, _ = _package_snapshot(profile, sources)
    return output


def _package_snapshot(profile: str, sources: object) -> tuple[dict[str, bytes], NativeCatalogSnapshot]:
    """Keep the immutable source-verified snapshot with its packaged projection."""
    from evidentia_core.models.open_corpora import PackagedIndex, PackageRef

    if type(profile) is not str or profile not in _PACKAGE_DIRECTORIES:
        raise NativeSourceError()
    with native_operation() as budget:
        raw: tuple[bytes, ...] = ()
        native_data: dict[str, Any] = {}
        ordinary: dict[str, Any] = {}
        entries: list[dict[str, Any]] = []
        output: dict[str, bytes] = {}
        try:
            snapshot = derive_native_catalog(profile, sources)
            raw = _source_snapshot(profile, sources, budget)
            converter = converter_sha256()
            native, projection = _authority(profile, raw, converter, budget)
            native_data = _restore_catalog_capture(native)
            directory = _PACKAGE_DIRECTORIES[profile]
            for index, (spec, body) in enumerate(zip(_SOURCES[profile], raw, strict=True)):
                if spec.key == "ism-catalog":
                    parts = []
                    for part_index, encoded in enumerate(_ism_chunks(body, budget)):
                        name = "ISM_catalog.part-" + str(part_index).zfill(3) + ".json"
                        envelope = _load_catalog_data(None, raw_bytes=encoded, mode="packaging_json").data
                        output[directory + "/" + name] = encoded
                        parts.append(
                            {
                                "path": name,
                                "stored_bytes": len(encoded),
                                "stored_sha256": _digest(encoded, budget),
                                "index": part_index,
                                "byte_start": envelope["byte_start"],
                                "byte_length": envelope["byte_length"],
                                "decoded_sha256": envelope["sha256"],
                            }
                        )
                    storage: dict[str, Any] = {"kind": "chunks", "parts": parts}
                else:
                    name = "LICENSE.txt" if spec.name == "LICENSE" else spec.name
                    output[directory + "/" + name] = body
                    storage = {"kind": "file", "path": name, "stored_bytes": len(body), "stored_sha256": spec.digest}
                entries.append({"binding": native_data["documents"][index]["binding"], "storage": storage})
            index_value = {
                "schema_version": "catalog-source-index-v1",
                "profile": profile,
                "catalog_id": _CATALOG_IDS[profile],
                "converter_id": "evidentia-open-corpora-v1",
                "converter_sha256": converter,
                "sources": entries,
            }
            PackagedIndex.model_validate(index_value)
            index_bytes = _compact(index_value, budget) + b"\n"
            if len(index_bytes) > 65_536:
                raise NativeSourceError()
            output[directory + "/source-index.json"] = index_bytes
            descriptor = {
                "schema_version": "catalog-native-package-v1",
                "profile": profile,
                "source_manifest_path": directory + "/source-index.json",
                "source_manifest_sha256": _digest(index_bytes, budget),
                "converter_id": "evidentia-open-corpora-v1",
                "converter_sha256": converter,
                "bundle_sha256": snapshot.bundle_sha256,
                "projection_sha256": snapshot.projection_sha256,
            }
            PackageRef.model_validate(descriptor)
            ordinary = _restore_catalog_capture(projection)
            ordinary["native_source_package"] = descriptor
            output[_CATALOG_PATHS[profile]] = _compact(ordinary, budget) + b"\n"
            notice_path, notice = _NOTICES[profile]
            output[notice_path] = notice.encode("utf-8")
            if profile == "au-ism-2026.09.4":
                output[directory + "/legacy-ids.json"] = _compact(_LEGACY_ISM, budget) + b"\n"
            if any(len(body) > 2_097_152 for body in output.values()) or converter != converter_sha256():
                raise NativeSourceError("catalog_generation_changed")
            return output, snapshot
        except BaseException:
            output.clear()
            raise
        finally:
            raw = ()
            native_data.clear()
            ordinary.clear()
            entries.clear()


def _read_file(path: Path, limit: int, budget: NativeBudget) -> bytes:
    from evidentia_core.catalogs.loader import _read_native_catalog

    return _read_native_catalog(path, limit, budget)


def _directory_names(directory: Path, maximum: int, budget: NativeBudget) -> set[str]:
    import os

    from evidentia_core.catalogs.loader import _native_path, _native_stat_identity

    absolute, before = _native_path(directory, directory=True)
    names: set[str] = set()
    iterator = None
    primary: BaseException | None = None
    try:
        budget.check()
        iterator = os.scandir(absolute)
        for entry in iterator:
            budget.check()
            names.add(entry.name)
            if len(names) > maximum:
                raise NativeSourceError()
        _, after = _native_path(absolute, directory=True)
        if _native_stat_identity(before) != _native_stat_identity(after):
            raise NativeSourceError()
        return names
    except BaseException as error:
        primary = error
        names.clear()
        raise
    finally:
        if iterator is not None:
            try:
                iterator.close()
            except BaseException as cleanup:
                if primary is not None:
                    raise primary from cleanup
                raise


def read_source_directory(profile: str, directory: Path) -> dict[str, bytes]:
    """Read only the exact local profile filenames and refuse extra source leaves."""
    if type(directory) is not type(Path()):
        raise NativeSourceError()
    specs = _source_bindings(profile)
    with native_operation() as budget:
        names = {s.name for s in specs}
        if _directory_names(directory, len(names), budget) != names:
            raise NativeSourceError()
        sources = {spec.name: _read_file(directory / spec.name, min(spec.size, 8_388_608), budget) for spec in specs}
        _source_snapshot(profile, sources, budget)
        return sources


def check_package_outputs(profile: str, sources: object, destination: Path) -> bool:
    """Regenerate and compare without creating, replacing, or touching an output."""
    if type(destination) is not type(Path()):
        raise NativeSourceError()
    with native_operation() as budget:
        expected = package_outputs(profile, sources)
        directory = destination / _PACKAGE_DIRECTORIES[profile]
        expected_names = {Path(p).name for p in expected if p.startswith(_PACKAGE_DIRECTORIES[profile] + "/")}
        if _directory_names(directory, len(expected_names), budget) != expected_names:
            return False
        try:
            return all(
                _read_file(destination / relative, len(body), budget) == body for relative, body in expected.items()
            )
        except OSError:
            return False


def load_packaged_catalog(catalog_path: Path) -> ControlCatalog:
    """Validate the closed package inputs and complete ordinary projection afresh."""
    from evidentia_core.models.open_corpora import PackagedIndex, PackageRef, SourceChunk

    with native_operation() as budget:
        original = b""
        index_bytes = b""
        body = b""
        decoded = b""
        sources: dict[str, bytes] = {}
        expected: dict[str, bytes] = {}
        data: dict[str, Any] = {}
        index_data: dict[str, Any] = {}
        try:
            original = _read_file(catalog_path, 2_097_152, budget)
            data = _load_catalog_data(None, raw_bytes=original, mode="wire_json").data
            descriptor_data = data.get("native_source_package")
            descriptor = PackageRef.model_validate(descriptor_data)
            profile = descriptor.profile
            if descriptor.converter_sha256 != converter_sha256():
                raise NativeSourceError("catalog_generation_changed")
            if profile not in _PACKAGE_DIRECTORIES:
                raise NativeSourceError()
            root = catalog_path.parent.parent
            if catalog_path != root / _CATALOG_PATHS[profile]:
                raise NativeSourceError()
            directory = _PACKAGE_DIRECTORIES[profile]
            if descriptor.source_manifest_path != directory + "/source-index.json":
                raise NativeSourceError()
            index_bytes = _read_file(root / descriptor.source_manifest_path, 65_536, budget)
            if _digest(index_bytes, budget) != descriptor.source_manifest_sha256:
                raise NativeSourceError()
            index_data = _load_catalog_data(None, raw_bytes=index_bytes, mode="wire_json").data
            PackagedIndex.model_validate(index_data)
            if _compact(index_data, budget) + b"\n" != index_bytes or index_data["profile"] != profile:
                raise NativeSourceError()
            expected_names = {"source-index.json"} | {
                "LICENSE.txt" if s.name == "LICENSE" else s.name for s in _SOURCES[profile]
            }
            if profile == "au-ism-2026.09.4":
                expected_names.remove("ISM_catalog.json")
                expected_names.update(("ISM_catalog.part-000.json", "ISM_catalog.part-001.json", "legacy-ids.json"))
            if _directory_names(root / directory, len(expected_names), budget) != expected_names:
                raise NativeSourceError()
            for spec in _SOURCES[profile]:
                if spec.key == "ism-catalog":
                    fragments = []
                    start = 0
                    try:
                        for part_index in range(2):
                            name = "ISM_catalog.part-" + str(part_index).zfill(3) + ".json"
                            body = _read_file(root / directory / name, 2_097_152, budget)
                            stored_size, stored_digest = _ISM_STORED_CHUNKS[part_index]
                            if len(body) != stored_size or _digest(body, budget) != stored_digest:
                                raise NativeSourceError()
                            chunk = _load_catalog_data(None, raw_bytes=body, mode="packaging_json").data
                            checked = SourceChunk.model_validate(chunk)
                            if (
                                _compact(chunk, budget) + b"\n" != body
                                or checked.index != part_index
                                or checked.byte_start != start
                            ):
                                raise NativeSourceError()
                            decoded = checked.raw_utf8.encode("utf-8")
                            start += len(decoded)
                            if start > spec.size:
                                raise NativeSourceError()
                            fragments.append(decoded)
                        sources[spec.name] = b"".join(fragments)
                    finally:
                        fragments.clear()
                else:
                    name = "LICENSE.txt" if spec.name == "LICENSE" else spec.name
                    sources[spec.name] = _read_file(root / directory / name, spec.size, budget)
            expected, snapshot = _package_snapshot(profile, sources)
            if (
                expected[_CATALOG_PATHS[profile]] != original
                or expected[directory + "/source-index.json"] != index_bytes
            ):
                raise NativeSourceError()
            for relative, body in expected.items():
                if _read_file(root / relative, len(body), budget) != body:
                    raise NativeSourceError()
            return snapshot.catalog()
        finally:
            original = b""
            index_bytes = b""
            body = b""
            decoded = b""
            sources.clear()
            expected.clear()
            data.clear()
            index_data.clear()
