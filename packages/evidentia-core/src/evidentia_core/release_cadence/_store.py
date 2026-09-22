"""Two-pass strict discovery and descriptor-bound release record reads.

This observes an operator-owned local filesystem. Parent observations do not
claim to prevent hostile ABA replacements between checks.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import sys
import uuid
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from platformdirs import user_data_dir
from pydantic import ValidationError

from evidentia_core.models.evidence import EvidenceArtifact

from ._contracts import (
    DiscoveryResult,
    PublicationContent,
    ReleaseEvidenceMetadata,
    SourceObservationContent,
    native_model,
)
from ._identity import _parent_relations, validate_artifact, verify_parent
from ._json import _discard, canonical_bytes, load_json
from ._limits import PAGE_BYTES, STORE_TOTAL_BYTES, STORED_BYTES, Budget, ReleaseFailure
from ._source import canonical_repository
from ._time import utc_text

_PATH_TYPE = type(Path())
_REPARSE = 0x400
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
_VERSION = re.compile(r"v([1-9][0-9]{0,15})\.json")
_TEMPORARY = re.compile(r"\.v[0-9]+\.json\..*\.tmp")
_STATUS = {
    "store_unavailable": "unavailable",
    "store_changed": "changed",
    "store_limit_exceeded": "limit_exceeded",
    "store_record_invalid": "record_invalid",
    "store_identity_conflict": "identity_conflict",
    "store_digest_conflict": "identity_conflict",
    "store_parent_missing": "identity_conflict",
    "store_parent_conflict": "identity_conflict",
    "deadline_exceeded": "deadline_exceeded",
    "clock_invalid": "unavailable",
}


def _work(budget: Budget, reserve: int) -> None:
    if type(budget) is not Budget or type(reserve) is not int or reserve not in (0, 5, 15):
        raise ReleaseFailure("clock_invalid")
    budget.check(reserve)


def _identity(info: os.stat_result) -> tuple[int, int, int]:
    if info.st_ino == 0:
        raise ReleaseFailure("store_unavailable")
    return info.st_dev, info.st_ino, info.st_mode


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (*_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _same_snapshot(path_info: os.stat_result, descriptor_info: os.stat_result) -> bool:
    def common(info: os.stat_result) -> tuple[int, ...]:
        return (*_identity(info), info.st_size, info.st_mtime_ns, info.st_nlink, getattr(info, "st_birthtime_ns", 0))

    return common(path_info) == common(descriptor_info) and (
        os.name == "nt" or path_info.st_ctime_ns == descriptor_info.st_ctime_ns
    )


def _reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE) or stat.S_ISLNK(info.st_mode)


def _windows_components(text: str) -> None:
    if text.startswith(("//", "\\\\")):
        raise ReleaseFailure("store_unavailable")
    for component in re.split(r"[/\\]", os.path.splitdrive(text)[1]):
        if component in ("", "."):
            continue
        base = component.split(".", 1)[0].upper()
        if ":" in component or component.rstrip(" .") != component or base in _RESERVED:
            raise ReleaseFailure("store_unavailable")


def local_path(value: object) -> Path:
    if type(value) is str:
        text = cast(str, value)
    elif type(value) is _PATH_TYPE:
        text = str(value)
    else:
        raise ReleaseFailure("store_unavailable")
    if not text or "\x00" in text or "://" in text or text.startswith(("//", "\\\\")):
        raise ReleaseFailure("store_unavailable")
    if ".." in re.split(r"[/\\]", text):
        raise ReleaseFailure("store_unavailable")
    if sys.platform == "win32":
        _windows_components(text)
    expanded = os.path.expanduser(text)
    if sys.platform == "win32":
        _windows_components(expanded)
    target = Path(os.path.abspath(expanded))
    if sys.platform == "win32":
        for component in target.parts[1:]:
            base = component.split(".", 1)[0].upper()
            if ":" in component or component.rstrip(" .") != component or base in _RESERVED:
                raise ReleaseFailure("store_unavailable")
        import ctypes

        if ctypes.windll.kernel32.GetDriveTypeW(str(target.anchor)) not in (2, 3, 5, 6):
            raise ReleaseFailure("store_unavailable")
    elif sys.platform not in ("linux", "darwin"):
        raise ReleaseFailure("store_unavailable")
    return target


@dataclass(frozen=True, slots=True)
class _TenantRoot:
    path: Path
    tenant: str


def lexical_store_root(override: object = None, *, tenant: str | None = None) -> Path | _TenantRoot:
    """Capture the lexical precedence before any resolving Core helper."""
    if type(override) is _TenantRoot:
        if tenant is not None:
            raise ReleaseFailure("store_unavailable")
        return override
    selected = override
    if selected is None:
        selected = os.environ.get("EVIDENTIA_EVIDENCE_STORE_DIR") or str(
            Path(user_data_dir("evidentia", "Evidentia")) / "evidence_store"
        )
    root = local_path(selected)
    if tenant is not None:
        if type(tenant) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", tenant) is None:
            raise ReleaseFailure("store_unavailable")
        return _TenantRoot(local_path(root / "tenants" / tenant), tenant)
    return root


@dataclass(frozen=True, slots=True)
class RootBinding:
    path: Path
    components: tuple[tuple[Path, tuple[int, int, int] | None], ...]
    tenant_scope: tuple[Path, str] | None = None
    tenant_budget: Budget | None = None

    def verify(self) -> None:
        for component, expected in self.components:
            try:
                info = component.lstat()
            except FileNotFoundError:
                if expected is not None:
                    raise ReleaseFailure("store_changed") from None
                continue
            if expected is None or _reparse(info) or not stat.S_ISDIR(info.st_mode) or _identity(info) != expected:
                raise ReleaseFailure("store_changed")
        if self.tenant_scope is not None:
            parent, tenant = self.tenant_scope
            _tenant_spelling(parent, tenant, self.tenant_budget)


def _tenant_spelling(parent: Path, tenant: str, budget: Budget | None) -> None:
    if type(tenant) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", tenant) is None:
        raise ReleaseFailure("store_unavailable")
    if type(budget) is not Budget:
        raise ReleaseFailure("clock_invalid")
    budget.check()
    try:
        stream = os.scandir(parent)
    except FileNotFoundError:
        return
    except OSError:
        raise ReleaseFailure("store_unavailable") from None
    primary = None
    try:
        for count, entry in enumerate(stream, 1):
            budget.check()
            if count > 4096:
                raise ReleaseFailure("store_limit_exceeded")
            name = entry.name
            if type(name) is not str:
                raise ReleaseFailure("store_unavailable")
            if name.isascii() and name.lower() == tenant.lower() and name != tenant:
                raise ReleaseFailure("store_identity_conflict")
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            stream.close()
        except BaseException:
            if primary is None:
                raise
    budget.check()


def admit_root(value: object, budget: Budget, *, reserve: int = 5) -> RootBinding:
    _work(budget, reserve)
    tenant_scope = None
    if type(value) is _TenantRoot:
        selection = cast(_TenantRoot, value)
        target = local_path(selection.path)
        if type(selection.tenant) is not str or target.name != selection.tenant or target.parent.name != "tenants":
            raise ReleaseFailure("store_unavailable")
        tenant_scope = (target.parent, selection.tenant)
    else:
        target = local_path(value)
    rows: list[tuple[Path, tuple[int, int, int] | None]] = []
    for component in (*reversed(target.parents), target):
        _work(budget, reserve)
        try:
            info = component.lstat()
        except FileNotFoundError:
            rows.append((component, None))
            continue
        if _reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise ReleaseFailure("store_unavailable")
        rows.append((component, _identity(info)))
    existing = next(component for component, identity in reversed(rows) if identity is not None)
    if sys.platform == "linux":
        _linux_local_mount(existing)
    elif sys.platform == "darwin":
        _darwin_local_mount(existing)
    binding = RootBinding(target, tuple(rows), tenant_scope, Budget(budget.deadline) if tenant_scope else None)
    binding.verify()
    _work(budget, reserve)
    return binding


def _parents(target: Path) -> tuple[tuple[Path, tuple[int, int, int]], ...]:
    rows = []
    for parent in reversed(target.parents):
        info = parent.lstat()
        if _reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise ReleaseFailure("store_unavailable")
        rows.append((parent, _identity(info)))
    return tuple(rows)


def _parents_unchanged(rows: tuple[tuple[Path, tuple[int, int, int]], ...]) -> None:
    for parent, identity in rows:
        info = parent.lstat()
        if _reparse(info) or _identity(info) != identity:
            raise ReleaseFailure("store_changed")


def _handle_path(descriptor: int, expected: Path) -> None:
    if sys.platform != "win32":
        return
    import ctypes
    import msvcrt
    from ctypes import wintypes

    function = ctypes.windll.kernel32.GetFinalPathNameByHandleW
    function.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    function.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    size = function(msvcrt.get_osfhandle(descriptor), buffer, len(buffer), 0)
    if size == 0 or size >= len(buffer):
        raise ReleaseFailure("store_unavailable")
    final = buffer.value
    if final.startswith("\\\\?\\"):
        final = final[4:]
    if os.path.normcase(os.path.normpath(final)) != os.path.normcase(str(expected)):
        raise ReleaseFailure("store_changed")


@dataclass(slots=True)
class StoreReadBudget:
    consumed: int = 0
    reserved: int = 0
    targeted_reads: int = 0

    def charge(self, amount: int) -> None:
        if type(amount) is not int or amount < 0:
            raise ReleaseFailure("store_unavailable")
        self.consumed += amount
        self.reserved = max(0, self.reserved - amount)
        if self.consumed > STORE_TOTAL_BYTES:
            raise ReleaseFailure("store_limit_exceeded")

    def reserve_readback(self, *, observation: bool) -> None:
        if self.reserved:
            raise ReleaseFailure("store_unavailable")
        amount = 262_146 if observation else 131_073
        if STORE_TOTAL_BYTES - self.consumed < amount:
            raise ReleaseFailure("store_limit_exceeded")
        self.reserved = amount

    def finish_readback(self) -> None:
        self.reserved = 0


def read_regular(
    target: Path,
    maximum: int,
    ledger: StoreReadBudget,
    budget: Budget,
    *,
    reserve: int = 5,
) -> tuple[bytes, tuple[int, ...]]:
    """One complete descriptor read, with every delivered byte charged first."""
    descriptor: int | None = None
    primary: BaseException | None = None
    parts: list[bytes] = []
    try:
        _work(budget, reserve)
        parents = _parents(target)
        before = target.lstat()
        if _reparse(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ReleaseFailure("store_unavailable")
        if before.st_size > maximum:
            raise ReleaseFailure("store_limit_exceeded")
        descriptor = os.open(
            target,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        opened = os.fstat(descriptor)
        _handle_path(descriptor, target)
        if not _same_snapshot(before, opened):
            raise ReleaseFailure("store_changed")
        total = 0
        while True:
            _work(budget, reserve)
            request = min(65_536, maximum + 1 - total, STORE_TOTAL_BYTES + 1 - ledger.consumed)
            if request <= 0:
                raise ReleaseFailure("store_limit_exceeded")
            part = os.read(descriptor, request)
            if type(part) is not bytes or len(part) > request:
                raise ReleaseFailure("store_unavailable")
            ledger.charge(len(part))
            total += len(part)
            if total > maximum:
                raise ReleaseFailure("store_limit_exceeded")
            _work(budget, reserve)
            if not part:
                break
            parts.append(part)
        if total != opened.st_size or _fingerprint(os.fstat(descriptor)) != _fingerprint(opened):
            raise ReleaseFailure("store_changed")
        after = target.lstat()
        if _reparse(after) or _fingerprint(after) != _fingerprint(before):
            raise ReleaseFailure("store_changed")
        _parents_unchanged(parents)
        raw = b"".join(parts)
        _work(budget, reserve)
        return raw, _fingerprint(after)
    except BaseException as error:
        primary = error
        if isinstance(error, OSError):
            primary = ReleaseFailure("store_unavailable")
            raise primary from None
        raise
    finally:
        parts.clear()
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as cleanup:
                if primary is None:
                    if not isinstance(cleanup, Exception):
                        raise
                    raise ReleaseFailure("store_unavailable") from None
                with suppress(BaseException):
                    BaseException.add_note(primary, "Release descriptor cleanup also failed.")


@dataclass(frozen=True, slots=True)
class VerifiedRecord:
    relative_path: str
    raw: bytes
    artifact_bytes: bytes
    stored_file_sha256: str
    physical: tuple[int, ...]
    verified_at: str

    def native(self) -> dict[str, object]:
        return cast(dict[str, object], load_json(self.artifact_bytes, 65_536, max_depth=12, max_values=1024))


@dataclass(frozen=True, slots=True)
class DiscoverySnapshot:
    summary_bytes: bytes
    records: tuple[VerifiedRecord, ...]
    binding: RootBinding | None
    ledger: StoreReadBudget

    def summary(self) -> dict[str, object]:
        return cast(dict[str, object], load_json(self.summary_bytes, 4096))


@dataclass(slots=True)
class _Counts:
    passes: int = 0
    root: int = 0
    children: int = 0
    files: int = 0
    releases: int = 0
    ledger: StoreReadBudget = field(default_factory=StoreReadBudget)


def _entries(
    target: Path, maximum: int, counts: _Counts, *, root: bool, budget: Budget, reserve: int
) -> list[tuple[str, tuple[int, ...]]]:
    _work(budget, reserve)
    parents = _parents(target)
    before = target.lstat()
    if _reparse(before) or not stat.S_ISDIR(before.st_mode):
        raise ReleaseFailure("store_unavailable")
    iterator = os.scandir(target)
    primary: BaseException | None = None
    rows: list[tuple[str, tuple[int, ...]]] = []
    try:
        for entry in iterator:
            if root:
                counts.root += 1
            else:
                counts.children += 1
            if len(rows) >= maximum:
                raise ReleaseFailure("store_limit_exceeded")
            _work(budget, reserve)
            if type(entry) is not os.DirEntry or type(entry.name) is not str:
                raise ReleaseFailure("store_unavailable")
            info = (target / entry.name).lstat()
            if _reparse(info):
                raise ReleaseFailure("store_unavailable")
            rows.append((entry.name, _fingerprint(info)))
        _parents_unchanged(parents)
        if _fingerprint(target.lstat()) != _fingerprint(before):
            raise ReleaseFailure("store_changed")
        _work(budget, reserve)
        rows.sort(key=lambda row: os.fsencode(row[0]))
        return rows
    except BaseException as error:
        primary = error
        rows.clear()
        raise
    finally:
        try:
            iterator.close()
        except BaseException as cleanup:
            if primary is None:
                if not isinstance(cleanup, Exception):
                    raise
                raise ReleaseFailure("store_unavailable") from None
            with suppress(BaseException):
                BaseException.add_note(primary, "Release directory cleanup also failed.")


def _release_marker(native: dict[str, object]) -> bool:
    metadata = native.get("metadata")
    return native.get("source_system") == "github-release-cadence" or (
        type(metadata) is dict and cast(dict[str, object], metadata).get("evidentia_domain") == "release-cadence"
    )


def _classify(
    raw: bytes,
    relative: str,
    version: int,
    counts: _Counts,
    budget: Budget,
    reserve: int,
) -> dict[str, object] | None:
    try:
        native = load_json(raw, PAGE_BYTES, budget=budget)
        if type(native) is not dict:
            raise ReleaseFailure("store_record_invalid")
        mapping = cast(dict[str, object], native)
        generic = EvidenceArtifact.model_validate_json(raw, strict=True)
        _work(budget, reserve)
        if generic.version != version or generic.effective_lineage_id != relative.split("/", 1)[0]:
            raise ReleaseFailure("store_record_invalid")
        if not _release_marker(mapping):
            return None
        counts.releases += 1
        if counts.releases > 2048 or len(raw) > STORED_BYTES:
            raise ReleaseFailure("store_limit_exceeded")
        if version != 1:
            content = mapping.get("content")
            metadata = mapping.get("metadata")
            if type(content) is not dict or type(metadata) is not dict:
                raise ReleaseFailure("store_record_invalid")
            kind = cast(dict[str, object], content).get("record_kind")
            if kind == "release_publication":
                checked = native_model(PublicationContent.model_validate(content))
            elif kind == "release_source_observation":
                checked = native_model(SourceObservationContent.model_validate(content))
            else:
                raise ReleaseFailure("store_record_invalid")
            meta = native_model(ReleaseEvidenceMetadata.model_validate(metadata))
            key = cast(dict[str, object], checked["event_key"])
            if any(
                meta[field] != key[field]
                for field in ("source_host", "canonical_owner", "canonical_repository", "release_id")
            ):
                raise ReleaseFailure("store_record_invalid")
            raise ReleaseFailure("store_identity_conflict")
        artifact = validate_artifact(mapping, budget=budget)
        if relative != str(artifact["id"]) + "/v1.json":
            raise ReleaseFailure("store_identity_conflict")
        _work(budget, reserve)
        return artifact
    except ValidationError:
        raise ReleaseFailure("store_record_invalid") from None
    except ReleaseFailure as error:
        if error.reason in _STATUS:
            raise
        raise ReleaseFailure("store_record_invalid") from None


def _version_looking(name: str) -> bool:
    ascii_folded = name.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))
    return bool(
        re.match(r"[vV][0-9+.-]", name)
        or (name[:1] in ("v", "V") and ".json" in ascii_folded)
        or _TEMPORARY.fullmatch(name)
        or (re.match(r"\.[vV][0-9+.-]", name) and ".json" in ascii_folded)
    )


def _inventory_pass(
    binding: RootBinding,
    counts: _Counts,
    budget: Budget,
    reserve: int,
    classify_record: Callable[[bytes, str, int], bytes | None],
) -> tuple[tuple[tuple[object, ...], ...], tuple[VerifiedRecord, ...]]:
    inventory: list[tuple[object, ...]] = []
    records: list[VerifiedRecord] = []
    raw = b""
    artifact_bytes: bytes | None = None
    try:
        binding.verify()
        if binding.components[-1][1] is None:
            _work(budget, reserve)
            binding.verify()
            return (), ()
        root = binding.path
        root_rows = _entries(root, 4096, counts, root=True, budget=budget, reserve=reserve)
        children = 0
        files = 0
        for name, fingerprint in root_rows:
            inventory.append(("root_entry", os.fsencode(name).hex(), fingerprint))
            try:
                identifier = str(uuid.UUID(name))
            except ValueError:
                continue
            if identifier != name or not stat.S_ISDIR(fingerprint[2]):
                raise ReleaseFailure("store_unavailable")
            lineage = root / name
            child_rows = _entries(lineage, 16384 - children, counts, root=False, budget=budget, reserve=reserve)
            children += len(child_rows)
            for filename, child_fingerprint in child_rows:
                relative = name + "/" + filename
                inventory.append(("lineage_entry", os.fsencode(relative).hex(), child_fingerprint))
                if not stat.S_ISREG(child_fingerprint[2]):
                    raise ReleaseFailure("store_unavailable")
                matched = _VERSION.fullmatch(filename)
                if matched is None:
                    if _version_looking(filename):
                        raise ReleaseFailure("store_unavailable")
                    continue
                version = int(matched[1])
                if version > 9_007_199_254_740_991:
                    raise ReleaseFailure("store_unavailable")
                files += 1
                counts.files += 1
                if files > 8192:
                    raise ReleaseFailure("store_limit_exceeded")
                raw, physical = read_regular(lineage / filename, PAGE_BYTES, counts.ledger, budget, reserve=reserve)
                sha = hashlib.sha256(raw).hexdigest()
                inventory.append(("record", relative, physical, len(raw), sha))
                artifact_bytes = classify_record(raw, relative, version)
                if artifact_bytes is not None:
                    records.append(
                        VerifiedRecord(
                            relative,
                            raw,
                            artifact_bytes,
                            sha,
                            physical,
                            utc_text(datetime.now(UTC)),
                        )
                    )
        binding.verify()
        _work(budget, reserve)
        return tuple(inventory), tuple(records)

    finally:
        inventory.clear()
        records.clear()
        raw = b""
        artifact_bytes = None


def _inventory_hash(inventory: tuple[tuple[object, ...], ...], budget: Budget) -> str:
    state = hashlib.sha256(b"evidentia.release-store-inventory.v1\n")
    for row in inventory:
        # Internal physical tuples are intentionally represented as ordered arrays.
        native = [list(item) if type(item) is tuple else item for item in row]
        state.update(canonical_bytes(native, 16_384, budget=budget))
        state.update(b"\n")
    return state.hexdigest()


def discover(
    root: object,
    owner: object,
    repository: object,
    budget: Budget,
    *,
    reserve: int = 5,
    ledger: StoreReadBudget | None = None,
) -> DiscoverySnapshot:
    """Return complete equal passes or a fixed refusal with no partial records."""
    selected_scope = canonical_repository(owner, repository)
    counts = _Counts(ledger=StoreReadBudget() if ledger is None else ledger)
    status = "complete"
    inventory_sha: str | None = None
    binding: RootBinding | None = None
    selected: tuple[VerifiedRecord, ...] = ()
    first_pass_complete = False
    retained: dict[str, tuple[bytes, bytes]] = {}
    first_records: tuple[VerifiedRecord, ...] = ()
    first_record_bytes: tuple[tuple[str, bytes], ...] = ()
    second_records: tuple[VerifiedRecord, ...] = ()

    def classify_record(raw: bytes, relative: str, version: int) -> bytes | None:
        cached: tuple[bytes, bytes] | None = None
        artifact: dict[str, object] | None = None
        encoded: bytes | None = None
        try:
            # Only bytes read and fully classified inside this invocation populate this cache.
            _work(budget, reserve)
            if type(raw) is not bytes or type(relative) is not str or type(version) is not int:
                raise ReleaseFailure("store_record_invalid")
            cached = retained.get(relative) if first_pass_complete else None
            if cached is not None and version == 1 and raw == cached[0]:
                counts.releases += 1
                if counts.releases > 2048 or len(raw) > STORED_BYTES:
                    raise ReleaseFailure("store_limit_exceeded")
                _work(budget, reserve)
                return cached[1]
            artifact = _classify(raw, relative, version, counts, budget, reserve)
            if artifact is None:
                return None
            encoded = canonical_bytes(artifact, 65_536, budget=budget, max_depth=12, max_values=1024)
            if not first_pass_complete:
                retained[relative] = (raw, encoded)
            return encoded

        finally:
            raw = b""
            cached = None
            artifact = None
            encoded = None

    def check_record_parent(child_record: VerifiedRecord | None, parent_record: VerifiedRecord | None) -> None:
        restored: list[dict[str, object]] = []
        native: dict[str, object] | None = None
        cached: tuple[bytes, bytes] | None = None
        record: VerifiedRecord | None = None
        try:
            for record in (child_record, parent_record):
                _work(budget, reserve)
                if (
                    type(record) is not VerifiedRecord
                    or type(record.relative_path) is not str
                    or type(record.raw) is not bytes
                    or type(record.artifact_bytes) is not bytes
                ):
                    raise ReleaseFailure("store_record_invalid")
                cached = retained.get(record.relative_path)
                if cached is None or record.raw != cached[0] or record.artifact_bytes != cached[1]:
                    raise ReleaseFailure("store_changed")
                # Only this invocation's fully classified, byte-bound captures reach this decoder.
                native = cast(dict[str, object], json.loads(cached[1]))
                if type(native) is not dict:
                    raise ReleaseFailure("store_record_invalid")
                restored.append(native)
                _work(budget, reserve)
            _parent_relations(restored[0], restored[1])
            _work(budget, reserve)
        finally:
            with suppress(BaseException):
                _discard(restored)
            with suppress(BaseException):
                _discard(native)
            child_record = None
            parent_record = None
            native = None
            cached = None
            record = None

    try:
        binding = admit_root(root, budget, reserve=reserve)
        first_inventory, first_records = _inventory_pass(binding, counts, budget, reserve, classify_record)
        first_record_bytes = tuple((record.relative_path, record.raw) for record in first_records)
        counts.passes = 1
        first_pass_complete = True
        second_inventory, second_records = _inventory_pass(binding, counts, budget, reserve, classify_record)
        counts.passes = 2
        if first_inventory != second_inventory or first_record_bytes != tuple(
            (record.relative_path, record.raw) for record in second_records
        ):
            raise ReleaseFailure("store_changed")
        inventory_sha = _inventory_hash(second_inventory, budget)
        by_id: dict[str, VerifiedRecord] = {}
        selected_list: list[VerifiedRecord] = []
        for record in second_records:
            artifact = record.native()
            identifier = cast(str, artifact["id"])
            if identifier in by_id:
                raise ReleaseFailure("store_identity_conflict")
            by_id[identifier] = record
            content = cast(dict[str, object], artifact["content"])
            key = cast(dict[str, object], content["event_key"])
            if (key["canonical_owner"], key["canonical_repository"]) == selected_scope:
                selected_list.append(record)
        for record in selected_list:
            artifact = record.native()
            content = cast(dict[str, object], artifact["content"])
            if content["record_kind"] == "release_source_observation":
                parent = by_id.get(cast(str, content["event_id"]))
                if parent is None:
                    raise ReleaseFailure("store_parent_missing")
                check_record_parent(record, parent)
        binding.verify()
        _work(budget, reserve)
        selected = tuple(selected_list)
    except ReleaseFailure as error:
        status = _STATUS.get(error.reason, "record_invalid")
    except (OSError, ValueError):
        status = "unavailable"
    finally:
        retained.clear()
        first_records = ()
        first_record_bytes = ()
        second_records = ()
    summary = {
        "status": status,
        "passes": counts.passes,
        "root_entries_observed": counts.root,
        "child_entries_observed": counts.children,
        "canonical_files_read": counts.files,
        "raw_file_bytes_observed": counts.ledger.consumed,
        "release_records_observed": counts.releases,
        "inventory_sha256": inventory_sha,
        "meaning": "bounded_recorded_store_observation",
    }
    checked_summary = native_model(DiscoveryResult.model_validate(summary))
    return DiscoverySnapshot(canonical_bytes(checked_summary, 4096), selected, binding, counts.ledger)


def _mount_text(value: str) -> str:
    for encoded, decoded in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(encoded, decoded)
    return value


def _linux_local_mount(target: Path) -> None:
    with open("/proc/self/mountinfo", "rb") as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ReleaseFailure("store_unavailable")
    selected_length = -1
    selected_types: set[str] = set()
    for line in raw.decode("utf-8", errors="surrogateescape").splitlines():
        left, separator, right = line.partition(" - ")
        fields, filesystem = left.split(), right.split()
        if not separator or len(fields) < 6 or len(filesystem) < 3:
            raise ReleaseFailure("store_unavailable")
        mount = _mount_text(fields[4])
        if os.path.commonpath((str(target), mount)) == mount:
            if len(mount) > selected_length:
                selected_length = len(mount)
                selected_types = {filesystem[0]}
            elif len(mount) == selected_length:
                selected_types.add(filesystem[0])
    local = {
        "ext2",
        "ext3",
        "ext4",
        "xfs",
        "btrfs",
        "overlay",
        "tmpfs",
        "ramfs",
        "bcachefs",
        "f2fs",
        "zfs",
        "jfs",
        "reiserfs",
        "ufs",
        "vfat",
        "msdos",
        "exfat",
        "ntfs",
        "ntfs3",
        "iso9660",
        "udf",
        "hfs",
        "hfsplus",
        "fuseblk",
    }
    # Ambiguous stacked mounts cannot depend on mountinfo line ordering.
    if not selected_types or not selected_types <= local:
        raise ReleaseFailure("store_unavailable")


def _darwin_local_mount(target: Path) -> None:
    import ctypes

    class MountInfo(ctypes.Structure):
        _fields_ = [
            ("block_size", ctypes.c_uint32),
            ("io_size", ctypes.c_int32),
            ("block_counts", ctypes.c_uint64 * 5),
            ("filesystem_id", ctypes.c_int32 * 2),
            ("owner", ctypes.c_uint32),
            ("filesystem_type", ctypes.c_uint32),
            ("flags", ctypes.c_uint32),
            ("subtype", ctypes.c_uint32),
            ("type_name", ctypes.c_char * 16),
            ("mount_point", ctypes.c_char * 1024),
            ("mount_source", ctypes.c_char * 1024),
            ("extended_flags", ctypes.c_uint32),
            ("reserved", ctypes.c_uint32 * 7),
        ]

    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    machine = platform.machine().lower()
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ReleaseFailure("store_unavailable")
    if machine in {"arm64", "aarch64"}:
        function = library.statfs
    elif machine in {"x86_64", "amd64"}:
        function = library.statfs64
    else:
        raise ReleaseFailure("store_unavailable")
    function.argtypes = [ctypes.c_char_p, ctypes.POINTER(MountInfo)]
    function.restype = ctypes.c_int
    info = MountInfo()
    probe = target if target.exists() else target.parent
    if function(os.fsencode(probe), ctypes.byref(info)) != 0 or not info.flags & 0x1000:
        raise ReleaseFailure("store_unavailable")


def _target_read(
    binding: RootBinding,
    identifier: str,
    ledger: StoreReadBudget,
    budget: Budget,
) -> VerifiedRecord | None:
    if (
        type(identifier) is not str
        or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", identifier) is None
    ):
        raise ReleaseFailure("store_identity_conflict")
    _work(budget, 0)
    binding.verify()
    ledger.targeted_reads += 1
    if ledger.targeted_reads > 4000:
        raise ReleaseFailure("store_limit_exceeded")
    lineage = binding.path / identifier
    target = lineage / "v1.json"
    try:
        lineage_info = lineage.lstat()
    except FileNotFoundError:
        binding.verify()
        try:
            lineage.lstat()
        except FileNotFoundError:
            _work(budget, 0)
            return None
        raise ReleaseFailure("store_changed") from None
    if _reparse(lineage_info) or not stat.S_ISDIR(lineage_info.st_mode):
        raise ReleaseFailure("store_unavailable")
    try:
        target.lstat()
    except FileNotFoundError:
        if _fingerprint(lineage.lstat()) != _fingerprint(lineage_info):
            raise ReleaseFailure("store_changed") from None
        binding.verify()
        try:
            target.lstat()
        except FileNotFoundError:
            _work(budget, 0)
            return None
        raise ReleaseFailure("store_changed") from None
    raw, physical = read_regular(target, STORED_BYTES, ledger, budget, reserve=0)
    try:
        native = validate_artifact(
            load_json(
                raw,
                STORED_BYTES,
                budget=budget,
                max_depth=12,
                max_values=1024,
            ),
            budget=budget,
        )
    except ValidationError:
        raise ReleaseFailure("store_record_invalid") from None
    except ReleaseFailure as error:
        if error.reason in _STATUS:
            raise
        raise ReleaseFailure("store_record_invalid") from None
    if native["id"] != identifier:
        raise ReleaseFailure("store_identity_conflict")
    binding.verify()
    if _fingerprint(lineage.lstat()) != _fingerprint(lineage_info):
        raise ReleaseFailure("store_changed")
    _work(budget, 0)
    captured = canonical_bytes(native, 65_536, budget=budget, max_depth=12, max_values=1024)
    return VerifiedRecord(
        identifier + "/v1.json",
        raw,
        captured,
        hashlib.sha256(raw).hexdigest(),
        physical,
        utc_text(datetime.now(UTC)),
    )


def readback(
    binding: RootBinding,
    identifier: str,
    ledger: StoreReadBudget,
    budget: Budget,
    *,
    expected_parent_bytes: bytes | None = None,
) -> VerifiedRecord | None:
    """Read a canonical target once, and its parent once when required."""
    if type(binding) is not RootBinding or type(ledger) is not StoreReadBudget:
        raise ReleaseFailure("store_unavailable")
    if expected_parent_bytes is not None and (
        type(expected_parent_bytes) is not bytes or not 0 < len(expected_parent_bytes) <= 65_536
    ):
        raise ReleaseFailure("store_parent_conflict")
    try:
        target = _target_read(binding, identifier, ledger, budget)
        if target is None:
            return None
        artifact = target.native()
        content = cast(dict[str, object], artifact["content"])
        if content["record_kind"] == "release_source_observation":
            parent = _target_read(binding, cast(str, content["event_id"]), ledger, budget)
            if parent is None:
                raise ReleaseFailure("store_parent_missing")
            if expected_parent_bytes is not None and parent.artifact_bytes != expected_parent_bytes:
                raise ReleaseFailure("store_changed")
            verify_parent(artifact, parent.native(), budget=budget)
        elif expected_parent_bytes is not None:
            raise ReleaseFailure("store_parent_conflict")
        _work(budget, 0)
        return target
    except OSError:
        raise ReleaseFailure("store_unavailable") from None


def record_reference(record: VerifiedRecord) -> dict[str, object]:
    """Project a verified record while preserving its original source clocks."""
    from ._contracts import StoredRecordReference
    from ._identity import artifact_semantic_digest
    from ._time import parse_window_time

    if type(record) is not VerifiedRecord or type(record.raw) is not bytes or type(record.artifact_bytes) is not bytes:
        raise ReleaseFailure("store_record_invalid")
    artifact = validate_artifact(record.native())
    content = cast(dict[str, object], artifact["content"])
    first = cast(dict[str, object], content["first_observation"])
    if hashlib.sha256(record.raw).hexdigest() != record.stored_file_sha256:
        raise ReleaseFailure("store_digest_conflict")
    raw_native = validate_artifact(load_json(record.raw, STORED_BYTES, max_depth=12, max_values=1024))
    if canonical_bytes(raw_native, 65_536, max_depth=12, max_values=1024) != record.artifact_bytes:
        raise ReleaseFailure("store_changed")
    value = {
        "record_kind": content["record_kind"],
        "artifact_id": artifact["id"],
        "event_id": content["event_id"],
        "version": 1,
        "relative_path": record.relative_path,
        "content_sha256": artifact["content_hash"],
        "selected_facts_sha256": content["selected_facts_sha256"],
        "artifact_semantic_sha256": artifact_semantic_digest(artifact),
        "stored_file_sha256": record.stored_file_sha256,
        "stored_file_bytes": len(record.raw),
        "collected_at": utc_text(parse_window_time(artifact["collected_at"])),
        "first_observation_poll_id": first["poll_id"],
        "verified_at": record.verified_at,
        "first_observed_at": first["retrieved_at"],
    }
    return native_model(StoredRecordReference.model_validate(value))


def prepare_write_root(binding: RootBinding, budget: Budget) -> RootBinding:
    """Create only missing admitted directories, retaining every existing parent."""
    if type(binding) is not RootBinding:
        raise ReleaseFailure("store_unavailable")
    _work(budget, 0)
    binding.verify()
    observed: list[tuple[Path, tuple[int, int, int] | None]] = []
    for component, expected in binding.components:
        _work(budget, 0)
        _parents_unchanged(tuple((parent, identity) for parent, identity in observed if identity is not None))
        if expected is None:
            try:
                os.mkdir(component)
            except FileExistsError:
                raise ReleaseFailure("store_changed") from None
            except OSError:
                raise ReleaseFailure("store_unavailable") from None
            info = component.lstat()
            if _reparse(info) or not stat.S_ISDIR(info.st_mode):
                raise ReleaseFailure("store_changed")
            expected = _identity(info)
        else:
            info = component.lstat()
            if _reparse(info) or not stat.S_ISDIR(info.st_mode) or _identity(info) != expected:
                raise ReleaseFailure("store_changed")
        observed.append((component, expected))
    result = RootBinding(binding.path, tuple(observed), binding.tenant_scope, binding.tenant_budget)
    result.verify()
    _work(budget, 0)
    return result


def admit_save_target(binding: RootBinding, identifier: str, budget: Budget) -> None:
    """Repeat local parent/type observations immediately before the v1 seam."""
    _work(budget, 0)
    binding.verify()
    if (
        type(identifier) is not str
        or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", identifier) is None
    ):
        raise ReleaseFailure("store_identity_conflict")
    lineage = binding.path / identifier
    try:
        info = lineage.lstat()
    except FileNotFoundError:
        binding.verify()
        _work(budget, 0)
        return
    if _reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise ReleaseFailure("store_unavailable")
    target = lineage / "v1.json"
    try:
        target_info = target.lstat()
    except FileNotFoundError:
        target_info = None
    if target_info is not None and (
        _reparse(target_info) or not stat.S_ISREG(target_info.st_mode) or target_info.st_nlink != 1
    ):
        raise ReleaseFailure("store_unavailable")
    if _fingerprint(lineage.lstat()) != _fingerprint(info):
        raise ReleaseFailure("store_changed")
    binding.verify()
    _work(budget, 0)
