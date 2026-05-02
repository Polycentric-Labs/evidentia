"""SQLite evidence collector — main module (v0.7.7 P0.3).

Single-file SQLite database collector. Smaller surface than the
networked adapters: no user system, no privilege grants, no
audit-log infrastructure. Reports filesystem permissions + PRAGMA
state (journal/synchronous/integrity/encryption-extension).
"""

from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Any

from evidentia_core.audit import (
    CollectionContext,
    CollectionManifest,
    CoverageCount,
    EventAction,
    EventCategory,
    EventOutcome,
    EventType,
    get_logger,
    new_run_id,
)
from evidentia_core.models.common import (
    ControlMapping,
    OLIRRelationship,
    Severity,
    current_version,
    utc_now,
)
from evidentia_core.models.finding import FindingStatus, SecurityFinding
from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)

if TYPE_CHECKING:
    import sqlite3  # noqa: F401


_log = get_logger("evidentia.collectors.sql.sqlite")

COLLECTOR_ID = "sql-sqlite-scan"


# ── Typed exception hierarchy ──────────────────────────────────────


class SQLiteCollectorError(Exception):
    """Base class for all SQLite collector failures."""


class SQLiteConnectionError(SQLiteCollectorError):
    """Could not open the SQLite database file."""


class SQLiteQueryError(SQLiteCollectorError):
    """A specific SQL/PRAGMA failed."""


# ── BLIND_SPOTS list ────────────────────────────────────────────────

BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "EVIDENTIA-SQLITE-FILE-ACL-MULTI-HOST",
        "title": "File ACLs are meaningful only on single-host deployments",
        "description": (
            "SQLite is a single-file database; the file's POSIX / "
            "Windows ACL is the access boundary. On distributed "
            "filesystems (NFS, SMB, GlusterFS, Ceph) the host-level "
            "ACLs we read may not reflect the access granted via "
            "the network filesystem layer. The collector reports "
            "what stat() returns; multi-host deployments need "
            "separate evidence at the network-fs layer."
        ),
    },
    {
        "id": "EVIDENTIA-SQLITE-NO-AUDIT-LOG",
        "title": "SQLite has no built-in audit log",
        "description": (
            "SQLite has no equivalent to Postgres pg_audit, MySQL "
            "audit_log_*, or MSSQL Extended Events. AU-2 / AU-3 "
            "evidence for SQLite-backed systems must come from the "
            "application layer (the application that opens the DB "
            "must log its own access events). The collector reports "
            "this gap explicitly so auditors know not to expect "
            "DB-side audit evidence."
        ),
    },
    {
        "id": "EVIDENTIA-SQLITE-ENCRYPTION-EXTENSION-DETECTION",
        "title": "Encryption-extension detection is best-effort",
        "description": (
            "SQLite encryption requires a third-party extension: "
            "SQLite Encryption Extension (SEE; commercial), SQLCipher "
            "(community), or WxSQLite3. Each registers different "
            "PRAGMAs (cipher_version on SEE/SQLCipher; cipher on "
            "WxSQLite3). The collector probes the standard PRAGMAs "
            "and returns 'unknown' if none match. A negative result "
            "doesn't prove the database is unencrypted — it proves "
            "the standard probes didn't recognize the extension."
        ),
    },
]


# ── NIST mappings (inline; smaller surface than other adapters) ─────


def _m(
    control_id: str,
    relationship: OLIRRelationship,
    justification: str,
) -> ControlMapping:
    return ControlMapping(
        framework="nist-800-53-rev5",
        control_id=control_id,
        relationship=relationship,
        justification=justification,
    )


_FILE_ACL_MAPPINGS = [
    _m(
        "AC-3",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-3 Access Enforcement — SQLite file ACLs ARE the access "
        "boundary for the database; intersects with AC-3 evidence "
        "(see BLIND_SPOT for multi-host caveat).",
    ),
]

_INTEGRITY_MAPPINGS = [
    _m(
        "SI-7",
        OLIRRelationship.SUBSET_OF,
        "SI-7 Software, Firmware, and Information Integrity — PRAGMA "
        "integrity_check + foreign_key_check directly evidence "
        "database integrity.",
    ),
]

_ENCRYPTION_MAPPINGS = [
    _m(
        "SC-28",
        OLIRRelationship.RELATED_TO,
        "SC-28 Protection of Information at Rest — encryption-extension "
        "detection (cipher_version PRAGMA) is best-effort; positive "
        "match evidences SC-28; negative is inconclusive (see "
        "BLIND_SPOT EVIDENTIA-SQLITE-ENCRYPTION-EXTENSION-DETECTION).",
    ),
]

_DURABILITY_MAPPINGS = [
    _m(
        "SC-28",
        OLIRRelationship.INTERSECTS_WITH,
        "SC-28 — journal_mode + synchronous settings affect data "
        "durability under crash. WAL + synchronous=FULL is the "
        "strongest combination for in-rest integrity guarantees.",
    ),
]

_WRITE_PRIV_MAPPINGS = [
    _m(
        "AC-6",
        OLIRRelationship.SUBSET_OF,
        "AC-6 Least Privilege — the collector should open SQLite "
        "in read-only mode (file: URI mode=ro). Detected write "
        "capability indicates the calling principal has more "
        "privilege than necessary for evidence collection.",
    ),
]


# ── Main collector class ────────────────────────────────────────────


class SQLiteCollector:
    """SQLite single-file database collector."""

    def __init__(
        self,
        *,
        database_path: str | Path | None = None,
        connection: Any | None = None,
        safe_root: str | Path | None = None,
    ) -> None:
        if database_path is None and connection is None:
            raise SQLiteCollectorError(
                "SQLiteCollector requires either database_path= or "
                "connection= (an injected sqlite3.Connection for testing)."
            )
        self._database_path: Path | None = None
        if database_path is not None:
            candidate = Path(database_path)
            # Optional path containment check — if safe_root is supplied,
            # require the database file to sit within it. Useful in
            # multi-tenant deployments where the collector is run
            # against operator-supplied paths.
            if safe_root is not None:
                try:
                    self._database_path = validate_within(
                        candidate, Path(safe_root)
                    )
                except PathTraversalError as e:
                    raise SQLiteCollectorError(
                        f"database_path resolves outside safe_root: {e}"
                    ) from e
            else:
                self._database_path = candidate.resolve(strict=False)
        self._connection = connection
        self._owns_connection = connection is None
        self._cached_version: str | None = None
        self._cached_journal_mode: str | None = None

    # ── Lifecycle ───────────────────────────────────────────────────

    def __enter__(self) -> SQLiteCollector:
        self._ensure_connected()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_connection and self._connection is not None:
            with contextlib.suppress(Exception):
                self._connection.close()
            self._connection = None

    def _ensure_connected(self) -> Any:
        if self._connection is not None:
            return self._connection
        # Stdlib sqlite3 — no optional extra. Always available on
        # Python 3.12+.
        import sqlite3

        if self._database_path is None:
            raise SQLiteCollectorError(
                "_ensure_connected called without a database_path."
            )
        if not self._database_path.is_file():
            raise SQLiteConnectionError(
                f"SQLite database file not found: {self._database_path}"
            )
        try:
            # Open read-only via URI to enforce the read-only contract
            # at the connection level. PRAGMA writes are still rejected.
            # Quote the path component so paths containing ?, #, or %
            # cannot smuggle URI options (CWE-20 input validation).
            import urllib.parse

            quoted = urllib.parse.quote(str(self._database_path), safe="/")
            uri = f"file:{quoted}?mode=ro"
            self._connection = sqlite3.connect(uri, uri=True)
        except Exception as e:
            raise SQLiteConnectionError(
                f"Could not open SQLite database (driver: {type(e).__name__})"
            ) from e
        return self._connection

    # ── Context + provenance ────────────────────────────────────────

    def _build_context(self, run_id: str) -> CollectionContext:
        path_str = str(self._database_path) if self._database_path else "unknown"
        return CollectionContext(
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            run_id=run_id,
            credential_identity=f"sqlite-fs-process:{os.getpid()}",
            source_system_id=f"sqlite:{path_str}",
            filter_applied={"database_path": path_str},
        )

    def test_connection(self) -> dict[str, Any]:
        conn = self._ensure_connected()
        cur = conn.cursor()
        try:
            cur.execute("SELECT sqlite_version()")
            row = cur.fetchone()
            self._cached_version = str(row[0]) if row else None
        finally:
            cur.close()

        return {
            "version": self._cached_version,
            "database_path": str(self._database_path)
            if self._database_path
            else None,
        }

    # ── High-level orchestration ────────────────────────────────────

    def collect(self, *, dry_run: bool = False) -> list[SecurityFinding]:
        if dry_run:
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message="SQLite dry-run — no DB calls made",
                category=[EventCategory.CONFIGURATION],
                types=[EventType.INFO],
                evidentia={"dry_run": True},
            )
            return []
        findings, _manifest = self.collect_v2()
        return findings

    def collect_v2(
        self,
    ) -> tuple[list[SecurityFinding], CollectionManifest]:
        run_id = new_run_id()
        started_at = utc_now()

        try:
            self.test_connection()
        except SQLiteCollectorError:
            raise

        context = self._build_context(run_id)
        errors: list[str] = []
        findings: list[SecurityFinding] = []

        with _log.scope(
            trace_id=run_id,
            evidentia={
                "run_id": run_id,
                "collector": {
                    "id": COLLECTOR_ID,
                    "version": current_version(),
                },
                "database_path": str(self._database_path)
                if self._database_path
                else None,
            },
        ):
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message=(
                    f"SQLite collection starting for {self._database_path}"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.START],
            )

            # File-level checks (don't need a DB connection but we
            # collect them once we've verified the file exists).
            findings.extend(self._file_acl_findings(context))
            findings.extend(self._write_privilege_findings(context))

            # PRAGMA-based checks
            conn = self._connection
            assert conn is not None
            for sub_check in (
                self._journal_mode_findings,
                self._integrity_findings,
                self._encryption_extension_findings,
            ):
                try:
                    findings.extend(sub_check(conn, context))
                except SQLiteQueryError as e:
                    errors.append(str(e))
                    _log.warning(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=f"Sub-check {sub_check.__name__} failed: {e}",
                        error={"type": "SQLiteQueryError", "message": str(e)},
                    )
                except Exception as e:
                    errors.append(
                        f"{sub_check.__name__}: unexpected error: {e}"
                    )

            _log.info(
                action=EventAction.COLLECT_COMPLETED,
                outcome=(
                    EventOutcome.SUCCESS
                    if not errors
                    else EventOutcome.FAILURE
                ),
                message=(
                    f"SQLite collection completed: {len(findings)} findings"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.END],
                evidentia={
                    "findings_count": len(findings),
                    "errors_count": len(errors),
                },
            )

        manifest = CollectionManifest(
            run_id=run_id,
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            collection_started_at=started_at,
            collection_finished_at=utc_now(),
            source_system_ids=[
                f"sqlite:{self._database_path}"
                if self._database_path
                else "sqlite:unknown"
            ],
            filters_applied={
                "database_path": str(self._database_path)
                if self._database_path
                else "unknown",
            },
            coverage_counts=[
                CoverageCount(
                    resource_type="sqlite-database",
                    scanned=1,
                    matched_filter=1,
                    collected=1,
                ),
            ],
            total_findings=len(findings),
            is_complete=not errors,
            incomplete_reason="; ".join(errors) if errors else None,
            errors=errors,
        )
        return findings, manifest

    # ── Sub-checks ──────────────────────────────────────────────────

    def _file_acl_findings(
        self, context: CollectionContext
    ) -> list[SecurityFinding]:
        if self._database_path is None:
            return []
        try:
            st = self._database_path.stat()
        except OSError as e:
            _log.warning(
                action=EventAction.COLLECT_FAILED,
                message=f"Could not stat database file: {e}",
            )
            return []

        # POSIX: surface mode bits (UNIX-only meaningful info)
        mode_octal = oct(st.st_mode & 0o777)
        world_readable = bool(st.st_mode & stat.S_IROTH)
        world_writable = bool(st.st_mode & stat.S_IWOTH)
        group_writable = bool(st.st_mode & stat.S_IWGRP)

        gaps: list[str] = []
        if world_writable:
            gaps.append("world-writable (mode bit 0o002)")
        if world_readable:
            gaps.append("world-readable (mode bit 0o004)")

        severity = (
            Severity.HIGH
            if world_writable
            else Severity.MEDIUM
            if world_readable
            else Severity.INFORMATIONAL
        )

        return [
            SecurityFinding(
                title=(
                    f"SQLite file ACLs: mode={mode_octal} "
                    f"({'world-writable!' if world_writable else 'world-readable' if world_readable else 'restricted'})"
                ),
                description=(
                    f"Database file {self._database_path}: mode bits "
                    f"{mode_octal}, owner uid={st.st_uid}, gid={st.st_gid}. "
                    + (
                        "Gaps: " + ", ".join(gaps) + ". "
                        if gaps
                        else "Permissions look restrictive. "
                    )
                    + "AC-3 evidence — operator should confirm only the "
                    "intended principal(s) can read/write this file. "
                    "On distributed filesystems, see BLIND_SPOT "
                    "EVIDENTIA-SQLITE-FILE-ACL-MULTI-HOST."
                ),
                severity=severity,
                status=(
                    FindingStatus.ACTIVE if gaps else FindingStatus.RESOLVED
                ),
                source_system="sqlite",
                source_finding_id=f"file-acl:{self._database_path}",
                resource_type="SQLite::File",
                resource_id=str(self._database_path),
                control_ids=[m.control_id for m in _FILE_ACL_MAPPINGS],
                collection_context=context,
                raw_data={
                    "mode": mode_octal,
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "world_readable": world_readable,
                    "world_writable": world_writable,
                    "group_writable": group_writable,
                },
            )
        ]

    def _write_privilege_findings(
        self, context: CollectionContext
    ) -> list[SecurityFinding]:
        # The collector opens read-only via URI. But the underlying
        # filesystem permissions may still allow the calling process
        # to write. Probe os.access() to detect.
        if self._database_path is None:
            return []
        writable = os.access(str(self._database_path), os.W_OK)
        if not writable:
            return []
        return [
            SecurityFinding(
                title=(
                    "SQLite database file is writable by the calling process"
                ),
                description=(
                    f"The collector opened {self._database_path} via "
                    "file:?mode=ro URI (read-only at SQLite level), but "
                    "the underlying filesystem permission allows write "
                    "(os.access W_OK = True). Production deployments "
                    "should restrict the collector's filesystem access "
                    "to read-only via file ACLs or by running under a "
                    "principal without write privilege."
                ),
                severity=Severity.MEDIUM,
                status=FindingStatus.ACTIVE,
                source_system="sqlite",
                source_finding_id=(
                    f"EVIDENTIA-WRITE-PRIV-DETECTED:{self._database_path}"
                ),
                resource_type="SQLite::File",
                resource_id=str(self._database_path),
                control_ids=[m.control_id for m in _WRITE_PRIV_MAPPINGS],
                collection_context=context,
                raw_data={"fs_writable": writable},
            )
        ]

    def _journal_mode_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        cur = conn.cursor()
        try:
            try:
                cur.execute("PRAGMA journal_mode")
                journal = str((cur.fetchone() or [""])[0]).upper()
                cur.execute("PRAGMA synchronous")
                sync = str((cur.fetchone() or [""])[0])
            except Exception as e:
                raise SQLiteQueryError(
                    f"Could not read journal_mode / synchronous: {e}"
                ) from e

            self._cached_journal_mode = journal
            # WAL + FULL is strongest combination
            is_strong = journal == "WAL" and sync.upper() in {"FULL", "2"}
            return [
                SecurityFinding(
                    title=(
                        f"SQLite durability config: journal={journal}, "
                        f"sync={sync}"
                    ),
                    description=(
                        f"PRAGMA journal_mode={journal}, PRAGMA "
                        f"synchronous={sync}. SC-28 evidence — the "
                        "WAL journal mode + synchronous=FULL "
                        "combination provides the strongest crash-"
                        "consistency guarantee. DELETE / synchronous="
                        "OFF combinations risk data loss after a "
                        "power failure."
                    ),
                    severity=Severity.INFORMATIONAL,
                    status=(
                        FindingStatus.RESOLVED
                        if is_strong
                        else FindingStatus.ACTIVE
                    ),
                    source_system="sqlite",
                    source_finding_id=(
                        f"durability:{self._database_path}"
                    ),
                    resource_type="SQLite::Database",
                    resource_id=str(self._database_path),
                    control_ids=[m.control_id for m in _DURABILITY_MAPPINGS],
                    collection_context=context,
                    raw_data={
                        "journal_mode": journal,
                        "synchronous": sync,
                        "strong_durability": is_strong,
                    },
                )
            ]
        finally:
            cur.close()

    def _integrity_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        cur = conn.cursor()
        try:
            try:
                cur.execute("PRAGMA integrity_check(1)")
                integrity = str((cur.fetchone() or [""])[0])
                cur.execute("PRAGMA foreign_key_check")
                fk_violations = list(cur.fetchall())
            except Exception as e:
                raise SQLiteQueryError(
                    f"Could not run PRAGMA integrity_check: {e}"
                ) from e

            ok = integrity.lower() == "ok" and not fk_violations
            return [
                SecurityFinding(
                    title=(
                        f"SQLite integrity: {'OK' if ok else 'violations'}"
                    ),
                    description=(
                        f"PRAGMA integrity_check returned {integrity!r}; "
                        f"foreign_key_check returned "
                        f"{len(fk_violations)} violations. "
                        + (
                            "Database integrity verified clean."
                            if ok
                            else "Integrity issues require operator review."
                        )
                    ),
                    severity=(
                        Severity.INFORMATIONAL
                        if ok
                        else Severity.HIGH
                    ),
                    status=(
                        FindingStatus.RESOLVED if ok else FindingStatus.ACTIVE
                    ),
                    source_system="sqlite",
                    source_finding_id=f"integrity:{self._database_path}",
                    resource_type="SQLite::Database",
                    resource_id=str(self._database_path),
                    control_ids=[m.control_id for m in _INTEGRITY_MAPPINGS],
                    collection_context=context,
                    raw_data={
                        "integrity_check": integrity,
                        "fk_violation_count": len(fk_violations),
                    },
                )
            ]
        finally:
            cur.close()

    def _encryption_extension_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        # Probe well-known encryption-extension PRAGMAs; each error
        # silently falls through to the next since we don't know
        # which extension (if any) is loaded.
        cur = conn.cursor()
        cipher_version: str | None = None
        try:
            for pragma in ("cipher_version", "cipher", "see_version"):
                try:
                    cur.execute(f"PRAGMA {pragma}")
                    row = cur.fetchone()
                    if row and row[0]:
                        cipher_version = f"{pragma}={row[0]!r}"
                        break
                except Exception:
                    continue
        finally:
            cur.close()

        encrypted = cipher_version is not None
        return [
            SecurityFinding(
                title=(
                    f"SQLite encryption extension: "
                    f"{'detected' if encrypted else 'not detected'}"
                ),
                description=(
                    f"Cipher probe result: {cipher_version or 'no extension detected'}. "
                    "SC-28 evidence — positive detection evidences "
                    "encryption-at-rest via SEE / SQLCipher / WxSQLite3. "
                    "Negative result is INCONCLUSIVE (see BLIND_SPOT "
                    "EVIDENTIA-SQLITE-ENCRYPTION-EXTENSION-DETECTION); "
                    "operators with non-standard encryption extensions "
                    "should provide out-of-band evidence."
                ),
                severity=Severity.INFORMATIONAL,
                status=(
                    FindingStatus.RESOLVED
                    if encrypted
                    else FindingStatus.ACTIVE
                ),
                source_system="sqlite",
                source_finding_id=(
                    f"encryption-extension:{self._database_path}"
                ),
                resource_type="SQLite::Database",
                resource_id=str(self._database_path),
                control_ids=[m.control_id for m in _ENCRYPTION_MAPPINGS],
                collection_context=context,
                raw_data={
                    "encrypted": encrypted,
                    "cipher_version": cipher_version,
                },
            )
        ]
