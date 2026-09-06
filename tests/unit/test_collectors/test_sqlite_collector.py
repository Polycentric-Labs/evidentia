"""Unit tests for the SQLite evidence collector (v0.7.7 P0.3).

SQLite uses the stdlib ``sqlite3`` module — no driver to mock. Tests
inject a real in-process ``:memory:`` database via the ``connection=``
constructor parameter for PRAGMA-driven sub-checks, and use ``tmp_path``
for file-ACL / write-privilege checks.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from evidentia_collectors.sql.sqlite import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    SQLiteCollector,
    SQLiteCollectorError,
)
from evidentia_core.models.finding import FindingStatus, Severity


def _make_memory_conn() -> sqlite3.Connection:
    """Return a real in-process sqlite3 connection for PRAGMA tests."""
    return sqlite3.connect(":memory:")


# ── Constants ────────────────────────────────────────────────────────


def test_collector_id_constant() -> None:
    assert COLLECTOR_ID == "sql-sqlite-scan"


def test_blind_spots_documented() -> None:
    assert len(BLIND_SPOTS) == 3
    ids = [bs["id"] for bs in BLIND_SPOTS]
    assert "EVIDENTIA-SQLITE-FILE-ACL-MULTI-HOST" in ids
    assert "EVIDENTIA-SQLITE-NO-AUDIT-LOG" in ids
    assert "EVIDENTIA-SQLITE-ENCRYPTION-EXTENSION-DETECTION" in ids


# ── Construction validation ─────────────────────────────────────────


def test_constructor_requires_path_or_connection() -> None:
    with pytest.raises(SQLiteCollectorError, match="requires either database_path"):
        SQLiteCollector()


def test_constructor_with_safe_root_rejects_outside(tmp_path: Path) -> None:
    safe = tmp_path / "safe"
    safe.mkdir()
    outside = tmp_path / "outside.db"
    outside.write_bytes(b"")

    with pytest.raises(SQLiteCollectorError, match="outside safe_root"):
        SQLiteCollector(database_path=outside, safe_root=safe)


def test_constructor_with_safe_root_accepts_inside(tmp_path: Path) -> None:
    safe = tmp_path / "safe"
    safe.mkdir()
    db = safe / "app.db"
    sqlite3.connect(str(db)).close()

    coll = SQLiteCollector(database_path=db, safe_root=safe)
    assert coll._database_path == db.resolve()


# ── test_connection ─────────────────────────────────────────────────


def test_test_connection_returns_version() -> None:
    coll = SQLiteCollector(connection=_make_memory_conn())
    info = coll.test_connection()
    assert "version" in info
    # sqlite_version() returns something like "3.45.0"
    assert info["version"]


# ── _journal_mode_findings ──────────────────────────────────────────


def test_journal_mode_findings_default_memory_db() -> None:
    """An in-memory DB defaults to journal=MEMORY which is not WAL/FULL.

    The collector reports journal mode as INFORMATIONAL with status
    RESOLVED only for WAL+FULL; everything else is ACTIVE.
    """
    conn = _make_memory_conn()
    coll = SQLiteCollector(connection=conn)
    findings, _ = coll.collect_v2()
    journal_findings = [f for f in findings if "journal=" in f.title.lower()]
    assert len(journal_findings) == 1
    f = journal_findings[0]
    assert f.severity == Severity.INFORMATIONAL
    assert f.status == FindingStatus.ACTIVE  # MEMORY is not WAL+FULL
    assert "raw_data" not in f.model_dump() or "journal_mode" in f.raw_data


def test_journal_mode_wal_full_is_resolved(tmp_path: Path) -> None:
    """A WAL-mode + synchronous=FULL DB should be RESOLVED."""
    db_file = tmp_path / "wal.db"
    setup = sqlite3.connect(str(db_file))
    setup.execute("PRAGMA journal_mode=WAL")
    setup.execute("PRAGMA synchronous=FULL")
    setup.execute("CREATE TABLE t (id INTEGER)")
    setup.commit()
    setup.close()

    # Inject a writable connection (NOT mode=ro) so PRAGMA returns the
    # configured WAL/FULL — read-only mode would coerce.
    conn = sqlite3.connect(str(db_file))
    conn.execute("PRAGMA synchronous=FULL")  # ensure session-level too
    # safe_root=tmp_path: v0.7.8 S1 made path-containment validation
    # mandatory (default Path.cwd()); tmp_path is outside cwd in pytest.
    coll = SQLiteCollector(database_path=db_file, connection=conn, safe_root=tmp_path)
    findings, _ = coll.collect_v2()
    journal_findings = [f for f in findings if "journal=" in f.title.lower()]
    assert len(journal_findings) == 1
    f = journal_findings[0]
    assert f.raw_data["journal_mode"] == "WAL"
    assert f.status == FindingStatus.RESOLVED


# ── _integrity_findings ─────────────────────────────────────────────


def test_integrity_check_clean_db() -> None:
    conn = _make_memory_conn()
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, x TEXT)")
    conn.execute("INSERT INTO t VALUES (1, 'a')")
    conn.commit()

    coll = SQLiteCollector(connection=conn)
    findings, _manifest = coll.collect_v2()
    integrity_findings = [f for f in findings if "integrity" in f.title.lower()]
    assert len(integrity_findings) >= 1
    f = integrity_findings[0]
    assert f.status == FindingStatus.RESOLVED
    assert f.severity == Severity.INFORMATIONAL


def test_integrity_check_with_fk_violation() -> None:
    conn = _make_memory_conn()
    # Build a parent/child schema, insert a child row whose FK doesn't
    # match a parent — only triggers when foreign_keys=ON for the
    # check, but PRAGMA foreign_key_check reports it regardless.
    conn.execute("CREATE TABLE p (id INTEGER PRIMARY KEY)")
    conn.execute("CREATE TABLE c (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES p(id))")
    conn.execute("INSERT INTO c VALUES (1, 99)")  # 99 not in p
    conn.commit()

    coll = SQLiteCollector(connection=conn)
    findings, _ = coll.collect_v2()
    integrity_findings = [f for f in findings if "integrity" in f.title.lower()]
    assert len(integrity_findings) >= 1
    # At least one integrity finding should be ACTIVE (FK violation)
    fk_or_integrity_active = [f for f in integrity_findings if f.status == FindingStatus.ACTIVE]
    assert len(fk_or_integrity_active) >= 1


# ── _encryption_extension_findings ──────────────────────────────────


def test_encryption_extension_no_extension_loaded() -> None:
    """A bare stdlib sqlite3 has no SEE / SQLCipher / WxSQLite3 — the
    finding should report 'no encryption extension detected'.
    """
    conn = _make_memory_conn()
    coll = SQLiteCollector(connection=conn)
    findings, _ = coll.collect_v2()
    enc_findings = [f for f in findings if "encryption" in f.title.lower()]
    assert len(enc_findings) == 1
    f = enc_findings[0]
    # No extension loaded -> ACTIVE (gap) at INFORMATIONAL severity
    assert f.severity == Severity.INFORMATIONAL


# ── _file_acl_findings + _write_privilege_findings ──────────────────


def test_file_acl_findings_for_real_file(tmp_path: Path) -> None:
    db = tmp_path / "app.db"
    sqlite3.connect(str(db)).close()

    coll = SQLiteCollector(database_path=db, safe_root=tmp_path)
    findings, _ = coll.collect_v2()
    acl_findings = [f for f in findings if "file ACLs" in f.title]
    assert len(acl_findings) == 1
    f = acl_findings[0]
    assert f.resource_type == "SQLite::File"
    assert "mode" in f.raw_data


def test_write_privilege_finding_when_writable(tmp_path: Path) -> None:
    """The DB file is writable by the test process by default."""
    db = tmp_path / "writable.db"
    sqlite3.connect(str(db)).close()

    coll = SQLiteCollector(database_path=db, safe_root=tmp_path)
    findings, _ = coll.collect_v2()
    write_priv_findings = [f for f in findings if "writable by the calling process" in f.title]
    assert len(write_priv_findings) == 1
    f = write_priv_findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.status == FindingStatus.ACTIVE
    assert "EVIDENTIA-WRITE-PRIV-DETECTED" in f.source_finding_id


# ── End-to-end manifest ─────────────────────────────────────────────


def test_collect_v2_emits_manifest() -> None:
    coll = SQLiteCollector(connection=_make_memory_conn())
    findings, manifest = coll.collect_v2()

    assert manifest.collector_id == COLLECTOR_ID
    assert manifest.run_id
    assert manifest.collection_started_at <= manifest.collection_finished_at
    assert manifest.total_findings == len(findings)
    assert manifest.coverage_counts[0].resource_type == "sqlite-database"


def test_collect_simple_alias_returns_findings_only() -> None:
    coll = SQLiteCollector(connection=_make_memory_conn())
    findings = coll.collect()
    assert isinstance(findings, list)
    assert all(hasattr(f, "control_ids") for f in findings)


def test_dry_run_returns_empty_list() -> None:
    coll = SQLiteCollector(connection=_make_memory_conn())
    findings = coll.collect(dry_run=True)
    assert findings == []
