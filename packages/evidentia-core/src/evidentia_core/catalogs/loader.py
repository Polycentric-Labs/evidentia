"""OSCAL catalog loader.

Loads NIST-published OSCAL JSON catalogs from bundled data files
and parses them into indexed ControlCatalog objects.

Supported catalog formats:
- OSCAL Catalog JSON (NIST 800-53, CSF 2.0)
- Evidentia framework JSON (SOC 2, ISO 27001, CIS, CMMC, PCI DSS)
- **Evidentia framework YAML** (v0.10.3+) — same fields as the JSON
  variant, friendlier for hand-authoring (comments, multi-line
  strings, no escape headaches). The loader auto-detects JSON vs
  YAML by file extension via :func:`_load_catalog_data`.

**IMPORTANT — choke-point invariant (v0.10.4+)**: ALL catalog file
reads in this module MUST go through :func:`_load_catalog_data`.
Never add a sibling ``json.loads`` / ``yaml.safe_load`` call
elsewhere — the helper centralizes extension dispatch + non-mapping-
root rejection, and breaking the invariant would let unsafe input
patterns slip in past the choke point. New loaders (e.g., for new
catalog categories) should accept a ``Path`` and call
``_load_catalog_data`` first, then build their typed model.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast, overload

import yaml

from evidentia_core.catalogs.manifest import load_manifest
from evidentia_core.models.catalog import CatalogControl, ControlCatalog
from evidentia_core.models.open_corpora import NativeBudget, NativeSourceError, native_operation

logger = logging.getLogger(__name__)

# Path to bundled data directory
DATA_DIR = Path(__file__).parent / "data"

# Deprecated framework-id aliases, old id -> canonical id. Every row here has
# a matching "Active deprecations" entry in docs/deprecation-calendar.md and
# is removed at its declared target release.
_FRAMEWORK_ID_ALIASES: dict[str, str] = {
    # v0.13 designator correction: the FRB letter is SR 26-2 (no leading
    # zero) and the OCC bulletin is 2026-13 (no "a" suffix).
    "occ-sr-26-02": "occ-sr-26-2",
}


def resolve_framework_id_alias(framework_id: str) -> str:
    """Translate a deprecated framework id to its canonical id.

    Emits a :class:`DeprecationWarning` when a deprecated id is used; ids
    with no alias entry pass through untouched.
    """
    canonical = _FRAMEWORK_ID_ALIASES.get(framework_id)
    if canonical is None:
        return framework_id
    warnings.warn(
        f"framework id {framework_id!r} is deprecated; use {canonical!r} "
        "(see docs/deprecation-calendar.md - scheduled for removal in "
        "v1.0.0)",
        DeprecationWarning,
        stacklevel=3,
    )
    return canonical


# CWE-674 guard: the OSCAL control/part trees are recursive, so a
# pathologically deep document could exhaust Python's recursion limit
# (RecursionError — a type the fuzz harnesses do not allowlist). Real
# catalogs nest ~2-4 levels; 100 is generous yet well under the interpreter
# default (~1000), so the recursive parsers raise a clean ValueError before
# the stack is exhausted.
_MAX_NEST_DEPTH = 100


@dataclass(frozen=True, slots=True)
class CatalogJsonNumber:
    """A native JSON number retains its exact source spelling."""

    lexeme: str


@dataclass(frozen=True, slots=True)
class CatalogJsonToken:
    kind: str
    start: int
    end: int
    value: Any = None
    members: tuple[tuple[CatalogJsonToken, CatalogJsonToken], ...] = ()
    items: tuple[CatalogJsonToken, ...] = ()

    def native(self) -> Any:
        if self.kind == "json_object":
            return {key.value: value.native() for key, value in self.members}
        if self.kind == "json_array":
            return [value.native() for value in self.items]
        return self.value


@dataclass(frozen=True, slots=True)
class ParsedNativeCatalog:
    raw: bytes
    root: CatalogJsonToken

    @property
    def data(self) -> dict[str, Any]:
        return cast(dict[str, Any], self.root.native())


class _NativeCatalogParser:
    def __init__(self, raw: bytes, mode: str, budget: NativeBudget) -> None:
        self.raw = raw
        self.mode = mode
        self.budget = budget
        self.position = 0
        self.nodes = 0
        self.members = 0
        self.elements = 0
        self.text_bytes = 0
        self.next_poll = 0
        self.owned: list[list[Any]] = []
        self.depth_limit = 4 if mode == "packaging_json" else 64 if mode == "wire_json" else 32
        self.node_limit = 32 if mode == "packaging_json" else 262144 if mode == "wire_json" else 100000

    def poll(self) -> None:
        if self.position >= self.next_poll:
            self.budget.check()
            self.next_poll = self.position + 4096

    def whitespace(self) -> None:
        while self.position < len(self.raw) and self.raw[self.position] in b" \t\r\n":
            self.position += 1
            self.poll()

    def string(self, *, key: bool = False, owner_key: str | None = None) -> CatalogJsonToken:
        start = self.position
        cursor = start + 1
        token_bytes = b""
        decoded = None
        try:
            while True:
                boundary = min(cursor + 4096, len(self.raw))
                quote = self.raw.find(b'"', cursor, boundary)
                self.budget.check()
                if quote < 0:
                    if boundary == len(self.raw):
                        raise NativeSourceError()
                    cursor = boundary
                    continue
                slash = quote - 1
                while slash > start and self.raw[slash] == 92:
                    slash -= 1
                if (quote - slash - 1) % 2:
                    cursor = quote + 1
                    continue
                self.position = quote + 1
                break
            token_bytes = self.raw[start : self.position]
            decoded = json.loads(token_bytes)
            if type(decoded) is not str:
                raise NativeSourceError()
            size = len(decoded.encode("utf8"))
            limit = 1024 if key else 262144
            if owner_key == "raw_utf8" and self.mode != "source_json":
                limit = 1572864 if self.mode == "packaging_json" else 8388608
            self.text_bytes += size
            if size > limit or self.text_bytes > (16777216 if self.mode == "wire_json" else 8388608):
                raise NativeSourceError()
            self.budget.check()
            return CatalogJsonToken("json_string", start, self.position, decoded)
        except NativeSourceError:
            raise
        except (UnicodeError, ValueError):
            raise NativeSourceError() from None
        finally:
            token_bytes = b""
            decoded = None

    def value(self, depth: int = 0, owner_key: str | None = None) -> CatalogJsonToken:
        self.whitespace()
        self.nodes += self.mode != "wire_json" or self.position >= len(self.raw) or self.raw[self.position] != 123
        self.poll()
        if depth > self.depth_limit or self.nodes > self.node_limit or self.position >= len(self.raw):
            raise NativeSourceError()
        start = self.position
        leading = self.raw[start]
        if leading == 34:
            return self.string(owner_key=owner_key)
        if leading == 123:
            self.position += 1
            fields: list[tuple[CatalogJsonToken, CatalogJsonToken]] = []
            self.owned.append(fields)
            names: set[str] = set()
            self.whitespace()
            if self.position < len(self.raw) and self.raw[self.position] == 125:
                self.position += 1
                return CatalogJsonToken("json_object", start, self.position)
            while True:
                self.whitespace()
                if self.position >= len(self.raw) or self.raw[self.position] != 34:
                    raise NativeSourceError()
                name = self.string(key=True)
                if name.value in names:
                    raise NativeSourceError()
                names.add(name.value)
                self.members += 1
                if len(names) > 64 or (self.mode != "wire_json" and self.members > self.node_limit):
                    raise NativeSourceError()
                self.whitespace()
                if self.position >= len(self.raw) or self.raw[self.position] != 58:
                    raise NativeSourceError()
                self.position += 1
                fields.append((name, self.value(depth + 1, name.value)))
                self.whitespace()
                if self.position >= len(self.raw):
                    raise NativeSourceError()
                delimiter = self.raw[self.position]
                self.position += 1
                if delimiter == 125:
                    return CatalogJsonToken("json_object", start, self.position, members=tuple(fields))
                if delimiter != 44:
                    raise NativeSourceError()
        if leading == 91:
            self.position += 1
            items: list[CatalogJsonToken] = []
            self.owned.append(items)
            self.whitespace()
            if self.position < len(self.raw) and self.raw[self.position] == 93:
                self.position += 1
                return CatalogJsonToken("json_array", start, self.position)
            while True:
                items.append(self.value(depth + 1))
                self.elements += 1
                if len(items) > (262144 if self.mode == "wire_json" else 4096) or self.elements > self.node_limit:
                    raise NativeSourceError()
                self.whitespace()
                if self.position >= len(self.raw):
                    raise NativeSourceError()
                delimiter = self.raw[self.position]
                self.position += 1
                if delimiter == 93:
                    return CatalogJsonToken("json_array", start, self.position, items=tuple(items))
                if delimiter != 44:
                    raise NativeSourceError()
        for literal, kind, value in (
            (b"true", "json_boolean", True),
            (b"false", "json_boolean", False),
            (b"null", "json_null", None),
        ):
            if self.raw.startswith(literal, start):
                self.position += len(literal)
                return CatalogJsonToken(kind, start, self.position, value)
        end = start
        while end < len(self.raw) and self.raw[end] not in b" \t\r\n,]}":
            end += 1
            if end - start > 128:
                raise NativeSourceError()
        spelling = self.raw[start:end]
        if re.fullmatch(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", spelling) is None:
            raise NativeSourceError()
        self.position = end
        lexeme = spelling.decode("ascii")
        number: Any = CatalogJsonNumber(lexeme)
        if self.mode != "source_json" and not any(char in lexeme for char in ".eE"):
            number = int(lexeme)
        return CatalogJsonToken("json_number", start, end, number)

    def parse(self) -> ParsedNativeCatalog:
        node = None
        try:
            self.raw.decode("utf8")
            node = self.value()
            self.whitespace()
            self.budget.check()
            if node.kind != "json_object" or self.position != len(self.raw):
                raise NativeSourceError()
            return ParsedNativeCatalog(self.raw, node)
        except UnicodeError:
            raise NativeSourceError() from None
        finally:
            node = None
            self.raw = b""
            for container in self.owned:
                container.clear()
            self.owned.clear()


def _restore_catalog_capture(raw: bytes) -> dict[str, Any]:
    """Restore owned canonical wire; external file admission keeps token validation."""
    from evidentia_core.models.open_corpora import _preflight

    def integer(spelling: str) -> int:
        if len(spelling) > 128:
            raise NativeSourceError()
        return int(spelling)

    def refuse_number(spelling: str) -> Any:
        raise NativeSourceError()

    with native_operation() as budget:
        data: dict[str, Any] = {}
        decoded: Any = None
        value: Any = None
        pending: list[tuple[Any, str | None]] = []
        text = ""
        encoded = b""
        try:
            if type(raw) is not bytes or len(raw) > 16_777_216:
                raise NativeSourceError()
            budget.check()
            decoded = json.loads(raw, parse_int=integer, parse_float=refuse_number, parse_constant=refuse_number)
            if type(decoded) is not dict:
                raise NativeSourceError()
            data = decoded
            budget.check()
            _preflight(data)
            pending.append((data, None))
            elements = 0
            visited = 0
            while pending:
                value, owner = pending.pop()
                visited += 1
                if visited % 256 == 0:
                    budget.check()
                if type(value) is str:
                    if len(value.encode("utf8")) > (8_388_608 if owner == "raw_utf8" else 262_144):
                        raise NativeSourceError()
                elif type(value) is dict:
                    pending.extend((item, key) for key, item in value.items())
                elif type(value) is list:
                    elements += len(value)
                    if elements > 262_144:
                        raise NativeSourceError()
                    pending.extend((item, None) for item in value)
            text = json.dumps(data, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
            encoded = text.encode("utf8")
            budget.check()
            if encoded != raw:
                raise NativeSourceError()
            return data
        except (UnicodeError, ValueError, RecursionError) as error:
            data.clear()
            if isinstance(error, NativeSourceError):
                raise
            raise NativeSourceError() from None
        except BaseException:
            data.clear()
            raise
        finally:
            pending.clear()
            decoded = None
            value = None
            text = ""
            encoded = b""
            raw = b""


def _native_path(path: Path, *, directory: bool = False) -> tuple[Path, os.stat_result]:
    if type(path) is not type(Path()) or ".." in path.parts or path.drive.startswith("\\\\"):
        raise NativeSourceError()
    absolute = path.absolute()
    for parent in reversed(absolute.parents):
        observed = parent.lstat()
        if (
            stat.S_ISLNK(observed.st_mode)
            or getattr(observed, "st_file_attributes", 0) & 1024
            or not stat.S_ISDIR(observed.st_mode)
        ):
            raise NativeSourceError()
    observed = absolute.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        stat.S_ISLNK(observed.st_mode)
        or getattr(observed, "st_file_attributes", 0) & 1024
        or not expected(observed.st_mode)
    ):
        raise NativeSourceError()
    return absolute, observed


def _native_stat_identity(observed: os.stat_result) -> tuple[int, ...]:
    return (
        observed.st_dev,
        observed.st_ino,
        observed.st_mode,
        observed.st_size,
        observed.st_mtime_ns,
        observed.st_ctime_ns,
        observed.st_nlink,
    )


def _same_native_snapshot(path_info: os.stat_result, descriptor_info: os.stat_result) -> bool:
    # Windows path and descriptor ctime can denote different timestamp kinds.
    # Compare each ctime with its own initial snapshot after reading.
    def common(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_size,
            info.st_mtime_ns,
            info.st_nlink,
            getattr(info, "st_birthtime_ns", 0),
        )

    return common(path_info) == common(descriptor_info) and (
        os.name == "nt" or path_info.st_ctime_ns == descriptor_info.st_ctime_ns
    )


def _read_native_catalog(path: Path, limit: int, budget: NativeBudget) -> bytes:
    if type(limit) is not int or not 0 <= limit <= 16777216:
        raise NativeSourceError()
    chunks: list[bytes] = []
    chunk = b""
    descriptor: int | None = None
    primary: BaseException | None = None
    total = 0
    try:
        budget.check()
        absolute, before = _native_path(path)
        parents = tuple(
            (parent, (info.st_dev, info.st_ino, info.st_mode))
            for parent in absolute.parents
            for info in (parent.lstat(),)
        )
        if before.st_size > limit:
            raise NativeSourceError()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(absolute, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or getattr(opened, "st_file_attributes", 0) & 1024
            or not _same_native_snapshot(before, opened)
        ):
            raise NativeSourceError()
        while True:
            budget.check()
            chunk = os.read(descriptor, min(4096, limit + 1 - total))
            if type(chunk) is not bytes:
                raise NativeSourceError()
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise NativeSourceError()
        budget.check()
        _, after = _native_path(absolute)
        if (
            total != before.st_size
            or _native_stat_identity(os.fstat(descriptor)) != _native_stat_identity(opened)
            or _native_stat_identity(after) != _native_stat_identity(before)
        ):
            raise NativeSourceError()
        for parent, identity in parents:
            observed = parent.lstat()
            if (observed.st_dev, observed.st_ino, observed.st_mode) != identity or getattr(
                observed, "st_file_attributes", 0
            ) & 1024:
                raise NativeSourceError()
        return b"".join(chunks)
    except BaseException as error:
        primary = error
        raise
    finally:
        chunks.clear()
        chunk = b""
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as cleanup:
                if primary is not None:
                    raise primary from cleanup
                raise


@overload
def _load_catalog_data(catalog_path: Path) -> dict[str, Any]: ...


@overload
def _load_catalog_data(
    catalog_path: Path | None,
    *,
    raw_bytes: bytes | None = None,
    mode: Literal["source_json", "packaging_json", "wire_json"],
) -> ParsedNativeCatalog: ...


def _load_catalog_data(
    catalog_path: Path | None, *, raw_bytes: bytes | None = None, mode: str = "legacy"
) -> dict[str, Any] | ParsedNativeCatalog:
    """Read a catalog file and return its parsed dict.

    Dispatches on file extension: ``.json`` → :func:`json.load`,
    ``.yaml`` / ``.yml`` → :func:`yaml.safe_load`. Both formats
    produce the same dict shape, so all downstream loaders
    (``load_oscal_catalog``, ``load_evidentia_catalog``,
    ``load_non_control_catalog``) work unchanged from v0.10.3+.

    Added v0.10.3 Phase 1 to lower the contributor barrier for
    new framework catalogs — YAML supports comments + multi-line
    strings + no comma/escape headaches that hand-edited JSON
    catalogs trip on.

    Raises ``ValueError`` for unsupported extensions, ``yaml.YAMLError``
    or ``json.JSONDecodeError`` for malformed content.
    """
    if type(mode) is not str:
        raise NativeSourceError()
    if mode != "legacy":
        if mode not in {"source_json", "packaging_json", "wire_json"}:
            raise NativeSourceError()
        with native_operation() as budget:
            budget.check()
            limit = 2097152 if mode == "packaging_json" else 16777216 if mode == "wire_json" else 8388608
            if raw_bytes is not None:
                if catalog_path is not None or type(raw_bytes) is not bytes or len(raw_bytes) > limit:
                    raise NativeSourceError()
                raw = raw_bytes
            else:
                if catalog_path is None:
                    raise NativeSourceError()
                raw = _read_native_catalog(catalog_path, limit, budget)
            try:
                return _NativeCatalogParser(raw, mode, budget).parse()
            finally:
                raw = b""
    if raw_bytes is not None or catalog_path is None:
        raise ValueError("legacy catalog loading requires a path")
    suffix = catalog_path.suffix.lower()
    text = catalog_path.read_text(encoding="utf-8")
    try:
        if suffix in (".yaml", ".yml"):
            data = yaml.safe_load(text)
        elif suffix == ".json":
            data = json.loads(text)
        else:
            # v0.10.4 P2 polish: when the suffix is empty (operator
            # drag-and-drop or scripted file with no extension), the
            # default {suffix!r} = '' is opaque. Name the case explicitly
            # and tell the operator the fix — rename to .yaml / .yml /
            # .json — so the error is self-resolving.
            if suffix == "":
                raise ValueError(
                    f"Catalog file {catalog_path.name} has no file "
                    f"extension; expected .json, .yaml, or .yml. Rename "
                    f"the file (e.g. mv {catalog_path.name} "
                    f"{catalog_path.name}.yaml) and retry."
                )
            raise ValueError(
                f"Unsupported catalog file extension {suffix!r} for {catalog_path.name}; expected .json, .yaml, or .yml"
            )
    except RecursionError as exc:
        # CWE-674: a pathologically deeply-nested document exhausts the JSON /
        # YAML parser's recursion limit. Convert to the module's typed
        # ValueError rather than leaking RecursionError — defense-in-depth
        # alongside the CWE-248 structural guards. (A coverage-guided fuzzer is
        # unlikely to build the depth, but the class is real.)
        raise ValueError(f"Catalog file {catalog_path.name} is nested too deeply to parse") from exc
    if not isinstance(data, dict):
        raise ValueError(
            f"{suffix} catalog {catalog_path.name} top-level must be a mapping (got {type(data).__name__})"
        )
    if "native_source" in data or "native_source_package" in data:
        raise NativeSourceError()
    return data


def _require_mapping(value: Any, what: str) -> dict[str, Any]:
    """Return ``value`` if it is a JSON object, else raise a clean ``ValueError``.

    OSCAL / Evidentia catalog structures are JSON objects at every nesting
    level. A malformed-but-valid-JSON file can place a string, list, or
    scalar where a mapping is expected (e.g. ``{"catalog": "oops"}`` or
    ``{"groups": [{"controls": "x"}]}``). Without this guard the next
    ``.get(...)`` raises ``AttributeError: 'str' object has no attribute
    'get'`` — an *unexpected* exception type that escapes the parser as an
    uncaught-exception denial-of-service (CWE-248; fuzz-found in the OSCAL
    catalog-import + profile paths). Converting it to ``ValueError`` aligns
    the failure with the module's declared "malformed input" signal (the
    top-level non-mapping guard above already raises ``ValueError``, and
    callers + the fuzz harnesses already treat ``ValueError`` as clean
    rejection). Valid catalogs are unaffected — they never carry a
    non-object where an object is required.
    """
    if not isinstance(value, dict):
        raise ValueError(f"{what} must be a JSON object, got {type(value).__name__}")
    return value


def _iter_mappings(value: Any, what: str) -> list[dict[str, Any]]:
    """Return ``value`` as a list of JSON objects, else raise a clean ``ValueError``.

    Guards the ``for item in data.get("groups", [])`` family of loops. A
    non-list (a string iterates character-by-character; a scalar is not
    iterable at all) or a list holding a non-mapping element both lead to
    ``AttributeError`` on the next ``.get(...)``. Reject with ``ValueError``
    instead — the same CWE-248 hardening as :func:`_require_mapping`. An
    absent key (``.get(key, [])`` → ``[]``) is the empty list and iterates
    zero times, so omitted optional sections stay valid.
    """
    if not isinstance(value, list):
        raise ValueError(f"{what} must be a JSON array, got {type(value).__name__}")
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{what}[{index}] must be a JSON object, got {type(item).__name__}")
    return value


def load_oscal_catalog(catalog_path: Path) -> ControlCatalog:
    """Load an OSCAL Catalog JSON file into a ControlCatalog.

    Parses the OSCAL catalog structure with groups → controls → enhancements.
    Accepts JSON or YAML (v0.10.3+) — file extension dispatches via
    :func:`_load_catalog_data`.
    """
    data = _load_catalog_data(catalog_path)

    catalog_data = _require_mapping(data.get("catalog", data), "catalog")
    metadata = _require_mapping(catalog_data.get("metadata", {}), "catalog.metadata")

    controls: list[CatalogControl] = []
    families: list[str] = []

    for group in _iter_mappings(catalog_data.get("groups", []), "catalog.groups"):
        family_title = group.get("title", "")
        families.append(family_title)

        for oscal_control in _iter_mappings(group.get("controls", []), "group.controls"):
            control = _parse_oscal_control(oscal_control, family_title)
            controls.append(control)

    framework_id = _detect_framework_id(catalog_path, metadata)
    framework_name = metadata.get("title", catalog_path.stem)
    version = metadata.get("version", "unknown")

    catalog = ControlCatalog(
        framework_id=framework_id,
        framework_name=framework_name,
        version=version,
        source=f"OSCAL: {catalog_path.name}",
        controls=controls,
        families=families,
    )

    logger.info(
        "Loaded catalog '%s': %d controls in %d families",
        framework_name,
        catalog.control_count,
        len(families),
    )
    return catalog


def _parse_oscal_control(oscal_control: dict[str, Any], family: str, _depth: int = 0) -> CatalogControl:
    """Parse a single OSCAL control into a CatalogControl.

    Shared by :func:`load_oscal_catalog` and the OSCAL profile resolver, so
    its malformed-input guards protect both fuzz entry points. Every nested
    collection is read through :func:`_iter_mappings`, and the two
    string-only operations (``.upper()`` on ``id``, ``.replace().upper()``
    on a link ``href``) coerce via :func:`str` first — a non-string ``id``
    or ``href`` would otherwise raise an uncaught ``AttributeError``.

    ``_depth`` tracks enhancement (sub-control) nesting; beyond
    :data:`_MAX_NEST_DEPTH` it raises ``ValueError`` rather than recursing into
    a ``RecursionError`` (CWE-674).
    """
    if _depth > _MAX_NEST_DEPTH:
        raise ValueError(f"control nesting exceeds the maximum depth ({_MAX_NEST_DEPTH})")
    oscal_control = _require_mapping(oscal_control, "control")
    control_id = str(oscal_control.get("id", "")).upper()
    title = oscal_control.get("title", "")

    # Extract description from parts
    description = ""
    for part in _iter_mappings(oscal_control.get("parts", []), "control.parts"):
        if part.get("name") == "statement":
            description = _extract_prose(part)
            break

    # Extract assessment objectives
    objectives: list[str] = []
    for part in _iter_mappings(oscal_control.get("parts", []), "control.parts"):
        if part.get("name") == "assessment-objective":
            objectives.append(_extract_prose(part))

    # Parse enhancements (nested controls)
    enhancements: list[CatalogControl] = []
    for sub_control in _iter_mappings(oscal_control.get("controls", []), "control.controls"):
        enhancement = _parse_oscal_control(sub_control, family, _depth + 1)
        enhancements.append(enhancement)

    # Extract priority from properties
    priority = None
    for prop in _iter_mappings(oscal_control.get("props", []), "control.props"):
        if prop.get("name") == "priority":
            priority = prop.get("value")

    # A withdrawn control (the OSCAL ``status`` prop) carries no statement
    # upstream; the flag lets gap analysis and text-depth derivation skip it.
    withdrawn = any(
        prop.get("name") == "status" and str(prop.get("value", "")).strip().lower() == "withdrawn"
        for prop in _iter_mappings(oscal_control.get("props", []), "control.props")
    )

    # Extract baseline impact from properties
    baseline_impact: list[str] = []
    for prop in _iter_mappings(oscal_control.get("props", []), "control.props"):
        if prop.get("name") in ("baseline", "impact"):
            value = prop.get("value", "")
            if value:
                baseline_impact.append(value)

    # Extract related controls from links
    related: list[str] = []
    for link in _iter_mappings(oscal_control.get("links", []), "control.links"):
        if link.get("rel") == "related":
            related.append(str(link.get("href", "")).replace("#", "").upper())

    # Extract parameters
    parameters: dict[str, str] = {}
    for param in _iter_mappings(oscal_control.get("params", []), "control.params"):
        param_id = param.get("id", "")
        default_value = ""
        if "select" in param:
            choices = _require_mapping(param["select"], "param.select").get("choice", [])
            default_value = " | ".join(choices) if choices else ""
        elif "guidelines" in param:
            guidelines = param["guidelines"]
            if isinstance(guidelines, list) and guidelines:
                default_value = _require_mapping(guidelines[0], "param.guidelines[0]").get("prose", "")
        parameters[param_id] = default_value

    return CatalogControl(
        id=control_id,
        title=title,
        description=description,
        family=family,
        priority=priority,
        baseline_impact=baseline_impact,
        enhancements=enhancements,
        related_controls=related,
        assessment_objectives=objectives,
        parameters=parameters,
        withdrawn=withdrawn,
    )


def _extract_prose(part: dict[str, Any], _depth: int = 0) -> str:
    """Recursively extract prose text from an OSCAL part.

    ``_depth`` guards the part-nesting recursion against a CWE-674
    ``RecursionError`` on a pathologically deep document (see
    :data:`_MAX_NEST_DEPTH`).
    """
    if _depth > _MAX_NEST_DEPTH:
        raise ValueError(f"part nesting exceeds the maximum depth ({_MAX_NEST_DEPTH})")
    part = _require_mapping(part, "part")
    prose: str = str(part.get("prose", ""))
    for sub_part in _iter_mappings(part.get("parts", []), "part.parts"):
        sub_prose = _extract_prose(sub_part, _depth + 1)
        if sub_prose:
            prose += "\n" + sub_prose
    return prose.strip()


def _detect_framework_id(path: Path, metadata: dict[str, Any]) -> str:
    """Detect the framework ID from the file path or metadata."""
    stem = path.stem.lower()
    if "800-53" in stem and "rev5" in stem:
        return "nist-800-53-rev5"
    if "800-53" in stem and "mod" in stem:
        return "nist-800-53-mod"
    if "800-53" in stem and "high" in stem:
        return "nist-800-53-high"
    if "csf" in stem and "2.0" in stem:
        return "nist-csf-2.0"
    return stem


def _packaged_native_path(catalog_path: Path) -> bool:
    # These are the two ratified bundled locations. Legacy paths keep their
    # existing parser and identifier behavior.
    return tuple(catalog_path.parts[-2:]) in {("international", "au-ism.json"), ("cisa", "scuba.json")}


def load_native_wire_catalog(catalog_path: Path) -> ControlCatalog:
    """Load a complete native catalog through strict bounded file admission.

    Native generations select this mode explicitly. Generic legacy loading
    refuses native markers instead of discarding their source authority.
    """
    from evidentia_core.models.catalog import _NativeControlCatalog

    with native_operation() as budget:
        parsed: ParsedNativeCatalog | None = None
        data: dict[str, Any] = {}
        try:
            parsed = _load_catalog_data(catalog_path, mode="wire_json")
            data = parsed.data
            if type(data.get("native_source")) is not dict or "native_source_package" in data:
                raise NativeSourceError()
            result = _NativeControlCatalog.model_validate(data)
            budget.check()
            return result
        finally:
            data.clear()
            parsed = None


def load_evidentia_catalog(catalog_path: Path) -> ControlCatalog:
    """Load a Evidentia-format framework catalog.

    Used for frameworks that don't have OSCAL catalogs published by NIST
    (SOC 2, ISO 27001, CIS, CMMC, PCI DSS). These are stored as
    Evidentia format with a simplified structure. Accepts JSON or YAML
    (v0.10.3+) — file extension dispatches via :func:`_load_catalog_data`.
    """
    if _packaged_native_path(catalog_path):
        from evidentia_core.catalogs.open_corpora import load_packaged_catalog

        return load_packaged_catalog(catalog_path)
    data = _load_catalog_data(catalog_path)

    controls = [CatalogControl(**c) for c in data.get("controls", [])]

    return ControlCatalog(
        framework_id=data["framework_id"],
        framework_name=data["framework_name"],
        version=data.get("version", "1.0"),
        source=data.get("source", f"Evidentia: {catalog_path.name}"),
        controls=controls,
        families=data.get("families", []),
        category=data.get("category", "control"),
        family_hierarchy=data.get("family_hierarchy"),
        v0_9_3_note=data.get("v0_9_3_note"),
        annex_iii_risk_categories=data.get("annex_iii_risk_categories"),
        status=data.get("status"),
        notes=data.get("notes"),
        verified_on=data.get("verified_on"),
        superseded_by=data.get("superseded_by"),
        audit_contexts=data.get("audit_contexts", {}),
        publication_notices=data.get("publication_notices", []),
        # Tier / licensing metadata added in v0.1.1 for Tier-C stub
        # catalogs (e.g., SOC 2 TSC). Defaults preserve the v0.1.0 shape
        # for plain Evidentia-format catalogs that omit these fields.
        tier=data.get("tier"),
        license_required=data.get("license_required", False),
        license_terms=data.get("license_terms"),
        license_url=data.get("license_url"),
        placeholder=data.get("placeholder", False),
    )


def load_non_control_catalog(catalog_path: Path) -> object:
    """Load a non-control-type catalog (technique, vulnerability, obligation).

    Returns the appropriate Pydantic model type based on the catalog's
    ``category`` field. These types don't subclass ControlCatalog; callers
    that expect a ControlCatalog should check ``catalog.category`` first.
    Accepts JSON or YAML (v0.10.3+) — file extension dispatches via
    :func:`_load_catalog_data`.
    """
    data = _load_catalog_data(catalog_path)

    category = data.get("category", "control")
    if category == "technique":
        from evidentia_core.models.threat import TechniqueCatalog

        return TechniqueCatalog.model_validate(data)
    if category == "vulnerability":
        from evidentia_core.models.threat import VulnerabilityCatalog

        return VulnerabilityCatalog.model_validate(data)
    if category == "obligation":
        from evidentia_core.models.obligation import ObligationCatalog

        return ObligationCatalog.model_validate(data)
    raise ValueError(f"Unknown catalog category {category!r} in {catalog_path.name}")


def load_catalog(framework_id: str, custom_path: Path | None = None) -> ControlCatalog:
    """Load a catalog by framework ID.

    First checks for a custom path, then looks in the bundled data directory.
    Auto-detects format (OSCAL vs Evidentia) based on file contents.

    Deprecated framework ids are translated to their canonical form (with a
    ``DeprecationWarning``) before resolution, so operator pipelines written
    against a renamed id keep working through the deprecation window.
    """
    framework_id = resolve_framework_id_alias(framework_id)
    if custom_path:
        path = custom_path
    else:
        # Resolve path via the user-dir-aware helper — user-imported
        # catalogs shadow bundled ones with the same framework_id, so an
        # organization's licensed ISO 27001 copy wins over the Tier-C
        # stub. Precedence is logged when a shadow occurs.
        from evidentia_core.catalogs.user_dir import resolve_catalog_path

        manifest = load_manifest()
        path, _entry, _source = resolve_catalog_path(framework_id, bundled_manifest=manifest)

    if not path.exists():
        raise FileNotFoundError(f"Catalog file not found: {path}")

    if _packaged_native_path(path):
        from evidentia_core.catalogs.open_corpora import load_packaged_catalog

        return load_packaged_catalog(path)

    data = _load_catalog_data(path)

    # Auto-detect format: OSCAL (control-only) vs. Evidentia.
    # Evidentia catalogs have a top-level ``category`` field telling us
    # whether this is a control/technique/vulnerability/obligation catalog;
    # non-control categories need a different loader and return type.
    if "catalog" in data:
        return load_oscal_catalog(path)
    category = data.get("category", "control")
    if category != "control":
        # Caller is asking for a control catalog but the on-disk data is a
        # technique/vulnerability/obligation catalog — raise a clear error.
        # Use ``load_any_catalog`` (below) when you don't know the shape.
        raise ValueError(
            f"Catalog {path.name} is a {category!r} catalog, not a control "
            "catalog. Use evidentia_core.catalogs.loader.load_any_catalog() "
            "to load it into the right model type."
        )
    return load_evidentia_catalog(path)


def load_any_catalog(framework_id: str, custom_path: Path | None = None) -> object:
    """Load any catalog by framework ID, returning the right Pydantic type.

    Dispatches on the catalog's ``category`` field:

    - ``"control"`` → :class:`ControlCatalog`
    - ``"technique"`` → :class:`TechniqueCatalog`
    - ``"vulnerability"`` → :class:`VulnerabilityCatalog`
    - ``"obligation"`` → :class:`ObligationCatalog`

    Used by the CLI's ``catalog show`` command and by tooling that works
    across all catalog types.
    """
    if custom_path:
        path = custom_path
    else:
        from evidentia_core.catalogs.user_dir import resolve_catalog_path

        manifest = load_manifest()
        path, _entry, _source = resolve_catalog_path(framework_id, bundled_manifest=manifest)

    if not path.exists():
        raise FileNotFoundError(f"Catalog file not found: {path}")

    if _packaged_native_path(path):
        from evidentia_core.catalogs.open_corpora import load_packaged_catalog

        return load_packaged_catalog(path)

    data = _load_catalog_data(path)

    if "catalog" in data:
        return load_oscal_catalog(path)
    category = data.get("category", "control")
    if category == "control":
        return load_evidentia_catalog(path)
    return load_non_control_catalog(path)
