"""Load complete, pinned registry packages without runtime refresh."""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass
from datetime import date, datetime
from importlib import resources
from typing import Any, Literal, cast

from ._contracts import (
    CertificateTarget,
    FCCOrganizationTarget,
    Freshness,
    ProductTarget,
    clock_text,
    normalized_organization_name,
    normalized_source_time,
)
from ._parsing import canonical_json, checked_json, parse_result_json, parse_strict_json, result_json_bytes
from ._source_fields import _TABLE_SHA256, validate_fields

SnapshotRegistry = Literal["fedramp", "cmvp", "fcc-covered-list"]
SnapshotTarget = ProductTarget | CertificateTarget | FCCOrganizationTarget
_PACKAGE_BYTES = 4_194_304
_INDEX_SHA256 = "b9969a4e6154b22c14bd08705f03b7f7d006375f39b82a720456ca885e265256"
_PATHS = {
    "fedramp": "data/fedramp/snapshot.json",
    "cmvp": "data/cmvp/snapshot.json",
    "fcc-covered-list": "data/fcc/snapshot.json",
}
_FAMILIES = {
    "fedramp": {
        "products": "fedramp_product_record",
        "unmatched_history": "fedramp_unmatched_history",
        "unjoined_packages": "fedramp_unjoined_package",
    },
    "cmvp": {"certificates": "cmvp_certificate_record"},
    "fcc-covered-list": {
        "named_entries": "fcc_named_entries",
        "category_rows": "fcc_category_rows",
        "footnotes": "fcc_footnotes",
        "conditional_approvals": "fcc_conditional_approvals",
        "definition_context": "fcc_definition_context",
        "source_context": "fcc_source_context",
    },
}


class SnapshotFault(ValueError):
    def __init__(self, code: Literal["snapshot_missing", "snapshot_invalid"] = "snapshot_invalid") -> None:
        self.code = code if code == "snapshot_missing" else "snapshot_invalid"
        super().__init__(self.code)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _decode_gzip(content: bytes, *, max_bytes: int) -> bytes:
    """Decode one bounded gzip member without accepting a trailing payload."""
    if type(content) is not bytes or type(max_bytes) is not int or not 0 < max_bytes <= 16_777_216:
        raise SnapshotFault()
    if len(content) > max_bytes:
        raise SnapshotFault()
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        decoded = decoder.decompress(content, max_bytes + 1)
    except zlib.error:
        raise SnapshotFault() from None
    if len(decoded) > max_bytes or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise SnapshotFault()
    return decoded


_GZIP_LIMIT = 16_777_216
_GZIP_HEADER = bytes.fromhex("1f8b08000000000002ff")


def canonical_gzip(raw: bytes) -> bytes:
    """Return canonical storage bytes for the reviewed locked runtimes."""
    if type(raw) is not bytes or len(raw) > _GZIP_LIMIT:
        raise ValueError("gzip_input_invalid")
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS, 8, zlib.Z_HUFFMAN_ONLY)
    parts = [_GZIP_HEADER]
    size = len(_GZIP_HEADER)
    for offset in range(0, len(raw), 65_536):
        encoded = compressor.compress(raw[offset : offset + 65_536])
        if len(encoded) > _GZIP_LIMIT - size - 8:
            raise ValueError("gzip_output_limit")
        parts.append(encoded)
        size += len(encoded)
    encoded = compressor.flush()
    if len(encoded) > _GZIP_LIMIT - size - 8:
        raise ValueError("gzip_output_limit")
    parts.append(encoded)
    parts.append(struct.pack("<II", zlib.crc32(raw) & 0xFFFFFFFF, len(raw)))
    return b"".join(parts)


def _object(raw: bytes) -> dict[str, Any]:
    value = parse_strict_json(raw)
    if type(value) is not dict:
        raise SnapshotFault()
    return value


def _json(value: object) -> bytes:
    return canonical_json(checked_json(value))


@dataclass(frozen=True)
class SnapshotFact:
    family: str
    source_index: int
    selected_bytes: bytes

    def detached(self) -> dict[str, Any]:
        return _object(self.selected_bytes)


@dataclass(frozen=True)
class RegistrySnapshot:
    registry: SnapshotRegistry
    path: str
    sha256: str
    byte_count: int
    tuple_sha256: str
    manifest_bytes: bytes
    counts_bytes: bytes
    facts: tuple[SnapshotFact, ...]
    storage_bytes: bytes | None = None

    def storage(self) -> dict[str, Any] | None:
        return None if self.storage_bytes is None else _object(self.storage_bytes)

    def manifest(self) -> dict[str, Any]:
        return _object(self.manifest_bytes)

    def counts(self) -> dict[str, Any]:
        return _object(self.counts_bytes)

    def family(self, name: str) -> tuple[SnapshotFact, ...]:
        if name not in _FAMILIES[self.registry]:
            raise SnapshotFault()
        return tuple(fact for fact in self.facts if fact.family == name)

    def lookup(self, target: SnapshotTarget) -> tuple[SnapshotFact, ...]:
        if self.registry == "fedramp" and type(target) is ProductTarget:
            target = ProductTarget.model_validate(target)
            return tuple(row for row in self.family("products") if row.detached()["fields"]["id"] == target.product_id)
        if self.registry == "cmvp" and type(target) is CertificateTarget:
            target = CertificateTarget.model_validate(target)
            return tuple(
                row
                for row in self.family("certificates")
                if row.detached()["certificate_number"] == target.certificate_number
            )
        if self.registry == "fcc-covered-list" and type(target) is FCCOrganizationTarget:
            target = FCCOrganizationTarget.model_validate(target)
            name = normalized_organization_name(target.organization_name)
            return tuple(
                row
                for row in self.family("named_entries")
                if name in [normalized_organization_name(value) for value in row.detached()["names_source_literal"]]
            )
        raise SnapshotFault()

    def freshness(self, observed_at: datetime) -> Freshness:
        clock_text(observed_at)
        try:
            value = self.manifest().get("as_of")
        except ValueError:
            return "unknown"
        if type(value) is not dict or type(value.get("literal")) is not str or not value["literal"].strip():
            return "unknown"
        if self.registry == "fcc-covered-list":
            try:
                literal_date = value.get("date")
                if type(literal_date) is not str:
                    return "unknown"
                published_date = date.fromisoformat(literal_date)
                if published_date.isoformat() != literal_date:
                    return "unknown"
            except (ValueError, TypeError):
                return "unknown"
            age_days = (observed_at.date() - published_date).days
            return "unknown" if age_days < 0 else "stale" if age_days > 7 else "dated_snapshot"
        normalized = normalized_source_time(value["literal"], "rfc3339")
        if normalized is None:
            return "unknown"
        age = (observed_at - datetime.fromisoformat(normalized.replace("Z", "+00:00"))).total_seconds()
        limit = (7 if self.registry == "fedramp" else 30) * 86_400
        return "unknown" if age < 0 else "stale" if age > limit else "dated_snapshot"

    def fcc_source(self, row: SnapshotFact) -> dict[str, Any]:
        if self.registry != "fcc-covered-list" or row not in self.family("named_entries"):
            raise SnapshotFault()
        named = row.detached()
        footnotes = [item.detached() for item in self.family("footnotes")]
        linked = []
        for marker in named["applicable_appendix_a_footnote_markers"]:
            matches = [
                item for item in footnotes if item["appendix"] == "A" and item["marker_source_literal"] == marker
            ]
            if len(matches) != 1:
                raise SnapshotFault()
            linked.append(matches[0])
        context = self.family("source_context")
        links = (
            ("named_entity_scope_boundary", "DA 26-786"),
            ("named_entity_scope_boundary", "DA 26-870"),
            ("affiliate_list_not_comprehensive", "DA 26-957"),
            ("affiliate_list_not_comprehensive", "DA 26-870"),
            ("affiliate_list_not_comprehensive", "DA 26-786"),
        )
        selected_context = [context[index].detached() for index in (3, 4, 8, 9, 10)]
        if tuple((item["kind"], item["document"]) for item in selected_context) != links:
            raise SnapshotFault()
        manifest = self.manifest()
        return {
            "named_entry": named,
            "linked_footnotes": linked,
            "named_scope_context": selected_context,
            "scope_limits": {
                "category_applicability": "not_assessed",
                "conditional_approval_applicability": "not_assessed",
                "deployment_applicability": "not_assessed",
                "indirect_affiliate_applicability": "not_assessed",
                "later_currency": "not_established",
                "legal_applicability": "not_assessed",
                "query_scope": "named_organization_entries",
            },
            "snapshot_context": {
                "as_of": manifest["as_of"],
                "fact_counts": self.counts(),
                "full_tuple_sha256": self.tuple_sha256,
                "retention": "complete_packaged_snapshot",
                "snapshot_sha256": self.sha256,
                "sources": manifest["sources"],
            },
        }


def _exact_indices(values: list[int], count: int) -> None:
    if len(values) != count or set(values) != set(range(count)):
        raise SnapshotFault()


def _fedramp_identities(facts: dict[str, Any], counts: dict[str, Any]) -> None:
    products = facts["products"]
    identifiers: set[str] = set()
    history: list[int] = []
    packages: list[int] = []
    for index, row in enumerate(products):
        identity = ProductTarget.model_validate({"product_id": row["fields"]["id"]}).product_id
        if row["source_index"] != index or identity in identifiers:
            raise SnapshotFault()
        identifiers.add(identity)
        for item in row["history"]:
            if item["fields"]["product_id"] != identity:
                raise SnapshotFault()
            history.append(item["source_index"])
        for item in row["package_rows"]:
            fields = item["fields"]
            if (
                fields["ZD_frid_retro"] != identity
                or fields["serviceIdentification"]["fedRampPackageId"] != identity
                or fields["id_matches_expected"] is not True
            ):
                raise SnapshotFault()
            packages.append(item["source_index"])
    if len(products) != counts["products"]:
        raise SnapshotFault()
    for row in facts["unmatched_history"]:
        if row["fields"]["product_id"] in identifiers:
            raise SnapshotFault()
        history.append(row["source_index"])
    packages.extend(row["source_index"] for row in facts["unjoined_packages"])
    _exact_indices(history, counts["history"])
    _exact_indices(packages, counts["packages"])


def _cmvp_identities(facts: dict[str, Any], counts: dict[str, Any]) -> None:
    seen: set[str] = set()
    scopes: dict[str, list[int]] = {name: [] for name in ("active", "historical", "revoked")}
    source_ids = {"active": "cmvp-active-all", "historical": "cmvp-historical", "revoked": "cmvp-revoked"}
    details = 0
    for row in facts["certificates"]:
        identity = CertificateTarget.model_validate(
            {"certificate_number": row["certificate_number"]}
        ).certificate_number
        if identity in seen or row["fields"]["Certificate Number"] != identity or not row["occurrences"]:
            raise SnapshotFault()
        seen.add(identity)
        for occurrence in row["occurrences"]:
            table = occurrence["table_id"]
            if (
                table not in scopes
                or occurrence["source_id"] != source_ids[table]
                or occurrence["query_status"] != table.title()
            ):
                raise SnapshotFault()
            scopes[table].append(occurrence["source_index"])
        basis = "literal_row_column" if "Status" in row["fields"] else "query_scope"
        status = row["fields"].get("Status", row["occurrences"][0]["query_status"])
        if row["status"] != {"basis": basis, "value": status}:
            raise SnapshotFault()
        if "detail" in row:
            if (
                identity != "5517"
                or row["detail"]["source_id"] != "cmvp-certificate-5517"
                or row["detail"]["source_index"] != 0
            ):
                raise SnapshotFault()
            details += 1
    for table, indices in scopes.items():
        _exact_indices(indices, counts[table])
    if details != counts["certificate_5517_detail"]:
        raise SnapshotFault()


def _fcc_identities(facts: dict[str, Any]) -> None:
    ordinals = [
        row["derived_appendix_a_row_ordinal"] for family in ("named_entries", "category_rows") for row in facts[family]
    ]
    if len(ordinals) != 16 or set(ordinals) != set(range(1, 17)):
        raise SnapshotFault()
    names: set[str] = set()
    for row in facts["named_entries"]:
        if row["publisher_row_identifier_presence"] != "absent" or row["applicable_appendix_a_footnote_markers"] != [
            "*",
            "\u00b1",
        ]:
            raise SnapshotFault()
        if not row["names_source_literal"]:
            raise SnapshotFault()
        for value in row["names_source_literal"]:
            name = normalized_organization_name(value)
            if name in names:
                raise SnapshotFault()
            names.add(name)
    footnotes = [(row["appendix"], row["marker_source_literal"]) for row in facts["footnotes"]]
    if len(set(footnotes)) != len(footnotes) or ("A", "*") not in footnotes or ("A", "\u00b1") not in footnotes:
        raise SnapshotFault()
    if len(facts["source_context"]) != 11:
        raise SnapshotFault()


def _index_entry(registry: SnapshotRegistry) -> dict[str, Any]:
    if type(registry) is not str or registry not in _PATHS:
        raise SnapshotFault()
    resource = resources.files("evidentia_collectors.registries").joinpath("data/source-index.json")
    with resource.open("rb") as stream:
        content = stream.read(1_048_577)
    if len(content) > 1_048_576:
        raise SnapshotFault()
    manifest = parse_result_json(content)
    index = manifest["snapshot_index"]
    if _digest(_json(index)) != _INDEX_SHA256:
        raise SnapshotFault()
    if manifest["snapshot_index_sha256"] != _INDEX_SHA256 or set(cast(dict[str, Any], index)) != set(_PATHS):
        raise SnapshotFault()
    entry = cast(dict[str, Any], index)[registry]
    if type(entry) is not dict or entry["path"] != _PATHS[registry] or entry["family_shapes"] != _FAMILIES[registry]:
        raise SnapshotFault()
    return entry


def _validate_package(registry: SnapshotRegistry, content: bytes, entry: dict[str, Any]) -> RegistrySnapshot:
    if (
        type(content) is not bytes
        or len(content) > _PACKAGE_BYTES
        or len(content) != entry["bytes"]
        or _digest(content) != entry["sha256"]
    ):
        raise SnapshotFault()
    package = cast(dict[str, Any], parse_result_json(content))
    if set(package) != {
        "schema_version",
        "snapshot_format",
        "registry",
        "tuple_input",
        "field_table_sha256",
        "source_manifest",
        "fact_counts",
        "facts",
    }:
        raise SnapshotFault()
    if (
        package["schema_version"] != "1"
        or package["snapshot_format"] != "selected_registry_facts_v1"
        or package["registry"] != registry
        or package["field_table_sha256"] != _TABLE_SHA256
        or package["tuple_input"] != entry["tuple_input"]
        or package["fact_counts"] != entry["fact_counts"]
        or _digest(_json(package["source_manifest"])) != entry["source_manifest_sha256"]
        or result_json_bytes(package) + b"\n" != content
    ):
        raise SnapshotFault()
    facts = package["facts"]
    counts = package["fact_counts"]
    if (
        type(facts) is not dict
        or type(counts) is not dict
        or set(facts) != set(_FAMILIES[registry])
        or set(counts) != set(facts)
    ):
        raise SnapshotFault()
    selected: list[SnapshotFact] = []
    for family, shape in _FAMILIES[registry].items():
        rows = facts[family]
        if type(rows) is not list or type(counts[family]) is not int or len(rows) != counts[family]:
            raise SnapshotFault()
        for index, value in enumerate(rows):
            raw = _json(value)
            if _json(validate_fields(registry, shape, value)) != raw:
                raise SnapshotFault()
            selected.append(SnapshotFact(family, index, raw))
    if len(selected) > 50_000:
        raise SnapshotFault()
    source_counts = package["source_manifest"]["source_occurrence_counts"]
    if registry == "fedramp":
        _fedramp_identities(facts, source_counts)
    elif registry == "cmvp":
        _cmvp_identities(facts, source_counts)
    else:
        _fcc_identities(facts)
    return RegistrySnapshot(
        registry,
        _PATHS[registry],
        entry["sha256"],
        len(content),
        package["tuple_input"]["sha256"],
        _json(package["source_manifest"]),
        _json(counts),
        tuple(selected),
        _json(entry["storage"]) if "storage" in entry else None,
    )


def load_snapshot(registry: SnapshotRegistry) -> RegistrySnapshot:
    """Verify one fixed complete package before exposing any matching record."""
    try:
        entry = _index_entry(registry)
        storage = entry.get("storage")
        if storage is not None:
            if (
                registry != "cmvp"
                or type(storage) is not dict
                or set(storage) != {"path", "encoding", "bytes", "sha256", "decoded_bytes", "decoded_sha256"}
                or type(storage["bytes"]) is not int
                or not 0 < storage["bytes"] <= _PACKAGE_BYTES
                or type(storage["decoded_bytes"]) is not int
                or not 0 < storage["decoded_bytes"] <= _PACKAGE_BYTES
                or any(type(storage[key]) is not str for key in ("path", "encoding", "sha256", "decoded_sha256"))
                or storage["path"] != "data/cmvp/snapshot.json.gz"
                or storage["encoding"] != "gzip"
                or storage["decoded_bytes"] != entry["bytes"]
                or storage["decoded_sha256"] != entry["sha256"]
            ):
                raise SnapshotFault()
            resource_path = storage["path"]
        else:
            resource_path = _PATHS[registry]
        resource = resources.files("evidentia_collectors.registries").joinpath(resource_path)
        with resource.open("rb") as stream:
            content = stream.read(_PACKAGE_BYTES + 1)
        if storage is not None:
            if (
                type(content) is not bytes
                or len(content) > _PACKAGE_BYTES
                or len(content) != storage["bytes"]
                or _digest(content) != storage["sha256"]
            ):
                raise SnapshotFault()
            content = _decode_gzip(content, max_bytes=_PACKAGE_BYTES)
        return _validate_package(registry, content, entry)
    except FileNotFoundError:
        raise SnapshotFault("snapshot_missing") from None
    except (OSError, ValueError, KeyError, TypeError, IndexError, OverflowError, RecursionError):
        raise SnapshotFault() from None


_BOOTSTRAP_INDEX_SHA256 = "08141d69c237aeaa989a961c5c9a67227eb025c5f02eeec69a50368f3b3f0f52"


@dataclass(frozen=True)
class BootstrapSelection:
    suffix: str
    service_base: str
    alternatives: tuple[str, ...]
    bootstrap_sha256: str
    publication: str
    source_bytes: bytes


def _service_base(value: str) -> str:
    from urllib.parse import urlsplit

    from ._tls import public_url

    clean, host = public_url(value)
    parts = urlsplit(clean)
    if (
        not clean.startswith("https://")
        or parts.netloc not in {host, host + ":443"}
        or parts.query
        or "?" in clean
        or "#" in clean
        or not parts.path.endswith("/")
        or "%" in parts.path
    ):
        raise SnapshotFault()
    segments = parts.path.split("/")
    if any(part in {".", ".."} for part in segments) or any(not part for part in segments[1:-1]):
        raise SnapshotFault()
    return clean


@dataclass(frozen=True)
class RDAPBootstrap:
    sha256: str
    publication: str
    source_bytes: bytes
    services: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...]

    def select(self, domain: str) -> BootstrapSelection:
        from ._contracts import canonical_hostname

        hostname = canonical_hostname(domain)
        matches = [
            (suffix, urls)
            for suffixes, urls in self.services
            for suffix in suffixes
            if hostname == suffix or hostname.endswith("." + suffix)
        ]
        if not matches:
            raise SnapshotFault()
        depth = max(suffix.count(".") for suffix, _ in matches)
        longest = [(suffix, urls) for suffix, urls in matches if suffix.count(".") == depth]
        if len(longest) != 1:
            raise SnapshotFault()
        suffix, alternatives = longest[0]
        for value in alternatives:
            try:
                selected = _service_base(value)
            except ValueError:
                continue
            return BootstrapSelection(suffix, selected, alternatives, self.sha256, self.publication, self.source_bytes)
        raise SnapshotFault()


def _validate_bootstrap(content: bytes, entry: dict[str, Any]) -> RDAPBootstrap:
    from ._contracts import canonical_hostname

    if (
        type(content) is not bytes
        or len(content) > 1_048_576
        or len(content) != entry["bytes"]
        or _digest(content) != entry["sha256"]
    ):
        raise SnapshotFault()
    value = parse_strict_json(content)
    if type(value) is not dict or set(value) != {"description", "publication", "version", "services"}:
        raise SnapshotFault()
    if (
        type(value["description"]) is not str
        or value["version"] != "1.0"
        or value["publication"] != entry["publication"]
        or normalized_source_time(value["publication"], "rfc3339") is None
        or type(value["services"]) is not list
    ):
        raise SnapshotFault()
    seen: set[str] = set()
    services: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
    suffix_count = url_count = 0
    for service in value["services"]:
        if type(service) is not list or len(service) != 2:
            raise SnapshotFault()
        suffixes, urls = service
        if type(suffixes) is not list or not suffixes or type(urls) is not list or not urls:
            raise SnapshotFault()
        for suffix in suffixes:
            if type(suffix) is not str or canonical_hostname(suffix) != suffix or suffix in seen:
                raise SnapshotFault()
            seen.add(suffix)
        if any(type(url) is not str or not url or len(url) > 8192 for url in urls):
            raise SnapshotFault()
        services.append((tuple(cast(list[str], suffixes)), tuple(cast(list[str], urls))))
        suffix_count += len(suffixes)
        url_count += len(urls)
    if (len(services), suffix_count, url_count) != (entry["service_count"], entry["suffix_count"], entry["url_count"]):
        raise SnapshotFault()
    return RDAPBootstrap(entry["sha256"], cast(str, value["publication"]), _json(entry["source"]), tuple(services))


def load_bootstrap() -> RDAPBootstrap:
    """Load the original IANA bytes and source cache metadata without network I/O."""
    try:
        package = resources.files("evidentia_collectors.registries")
        with package.joinpath("data/source-index.json").open("rb") as stream:
            index_bytes = stream.read(1_048_577)
        if len(index_bytes) > 1_048_576:
            raise SnapshotFault()
        index = parse_result_json(index_bytes)
        entry = index["bootstrap"]
        if (
            _digest(_json(entry)) != _BOOTSTRAP_INDEX_SHA256
            or index["bootstrap_index_sha256"] != _BOOTSTRAP_INDEX_SHA256
        ):
            raise SnapshotFault()
        if type(entry) is not dict or entry["path"] != "data/rdap/bootstrap.json":
            raise SnapshotFault()
        with package.joinpath("data/rdap/bootstrap.json").open("rb") as stream:
            content = stream.read(1_048_577)
        return _validate_bootstrap(content, entry)
    except FileNotFoundError:
        raise SnapshotFault("snapshot_missing") from None
    except (OSError, ValueError, KeyError, TypeError, IndexError, OverflowError, RecursionError):
        raise SnapshotFault() from None
