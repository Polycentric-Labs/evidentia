"""Unit tests for the MS SQL Server evidence collector (v0.7.7 P0.4).

Mocks the pyodbc connection at the cursor level — no real MSSQL
required. Mirrors the pattern from test_postgres_collector.py /
test_mysql_collector.py.
"""

from __future__ import annotations

from typing import Any

import pytest
from evidentia_collectors.sql.mssql import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    MSSQLCollector,
    MSSQLCollectorError,
)
from evidentia_core.models.finding import FindingStatus, Severity

# ── Mock connection infrastructure ──────────────────────────────────


class _MockCursor:
    """Routes by the LAST query string seen via execute()."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self._last_query = ""
        self.executed: list[tuple[str, Any]] = []

    def execute(self, query: str, *args: Any) -> None:
        self._last_query = query
        self.executed.append((query, args))

    def fetchone(self) -> Any:
        for needle, value in self._responses.items():
            if needle in self._last_query:
                if isinstance(value, list):
                    return value[0] if value else None
                return value
        return None

    def fetchall(self) -> list[Any]:
        for needle, value in self._responses.items():
            if needle in self._last_query:
                return value if isinstance(value, list) else [value]
        return []

    def close(self) -> None:
        pass


class _MockConnection:
    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.closed = False

    def cursor(self) -> _MockCursor:
        return _MockCursor(self._responses)

    def close(self) -> None:
        self.closed = True


def _baseline_responses() -> dict[str, Any]:
    """Default responses representing a hardened MSSQL with read-only
    least-privilege principal."""
    return {
        # test_connection probe
        "SUSER_SNAME()": (
            "evidentia_reader",
            "appdb",
            "16.0.1000.6",
        ),
        # _probe_write_privilege
        "IS_SRVROLEMEMBER('sysadmin')": (0, 0, 0),
        # _privilege_grant_findings — match BEFORE the broader
        # sys.server_principals key since this query contains
        # "sys.server_role_members rm JOIN sys.server_principals r"
        # and we want the join-query to resolve to the COUNT result.
        "sys.server_role_members": (1,),
        # _user_role_inventory_findings
        "sys.server_principals WHERE type": [
            ("evidentia_reader", "SQL_LOGIN", False, "2024-01-01"),
            ("admin", "SQL_LOGIN", False, "2023-01-01"),
            ("DOMAIN\\dba", "WINDOWS_LOGIN", False, "2023-01-01"),
        ],
        # _audit_log_findings
        "sys.server_audits": (1, 1),  # 1 configured, 1 enabled
        # _tde_encryption_findings
        "sys.dm_database_encryption_keys": [
            ("appdb", 3),
            ("reportingdb", 3),
        ],
        # _tls_config_findings
        "CONNECTIONPROPERTY": ("TCP", "SQL", "TRUE"),
        # _connection_limit_findings
        "sys.configurations": ("user connections", 0),
    }


# ── Constants ────────────────────────────────────────────────────────


def test_collector_id_constant() -> None:
    assert COLLECTOR_ID == "sql-mssql-scan"


def test_blind_spots_documented() -> None:
    assert len(BLIND_SPOTS) == 3
    ids = [bs["id"] for bs in BLIND_SPOTS]
    assert "EVIDENTIA-MSSQL-EXTENDED-EVENTS" in ids
    assert "EVIDENTIA-MSSQL-AZURE-SQL-FEATURE-MATRIX" in ids
    assert "EVIDENTIA-MSSQL-ALWAYS-ENCRYPTED-COLUMN-VISIBILITY" in ids


# ── Construction validation ─────────────────────────────────────────


def test_constructor_requires_uri_or_connection() -> None:
    with pytest.raises(MSSQLCollectorError, match="requires either"):
        MSSQLCollector()


def test_constructor_rejects_password_in_uri() -> None:
    with pytest.raises(MSSQLCollectorError, match="must NOT embed a password"):
        MSSQLCollector(connection_uri="mssql://user:secret@host:1433/db")


def test_constructor_accepts_uri_without_password() -> None:
    coll = MSSQLCollector(
        connection_uri="mssql://user@host:1433/db",
        password="should-not-leak",
    )
    assert coll._cached_user is None  # not yet connected


def test_build_connection_string_no_password() -> None:
    coll = MSSQLCollector(connection_uri="mssql://user@host:1433/appdb")
    cs = coll._build_connection_string("mssql://user@host:1433/appdb")
    assert "Server=tcp:host,1433" in cs
    assert "Database=appdb" in cs
    assert "Uid=user" in cs
    assert "Pwd=" not in cs
    assert "Encrypt=yes" in cs


def test_build_connection_string_with_password() -> None:
    coll = MSSQLCollector(
        connection_uri="mssql://user@host:1433/appdb",
        password="hunter2",
    )
    cs = coll._build_connection_string("mssql://user@host:1433/appdb")
    assert "Pwd=hunter2" in cs


# ── test_connection ─────────────────────────────────────────────────


def test_test_connection_caches_metadata() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = MSSQLCollector(connection=conn)
    info = coll.test_connection()
    assert info["user"] == "evidentia_reader"
    assert info["database"] == "appdb"
    assert info["version"] == "16.0.1000.6"
    assert info["is_sysadmin"] is False
    assert info["is_db_owner"] is False
    assert info["is_db_datawriter"] is False


def test_test_connection_detects_sysadmin() -> None:
    responses = _baseline_responses()
    responses["IS_SRVROLEMEMBER('sysadmin')"] = (1, 0, 0)
    conn = _MockConnection(responses)
    coll = MSSQLCollector(connection=conn)
    info = coll.test_connection()
    assert info["is_sysadmin"] is True


# ── Sub-checks ──────────────────────────────────────────────────────


def test_write_priv_finding_fires_on_sysadmin() -> None:
    responses = _baseline_responses()
    responses["IS_SRVROLEMEMBER('sysadmin')"] = (1, 0, 0)
    conn = _MockConnection(responses)
    coll = MSSQLCollector(connection=conn)
    findings = coll.collect()
    write_priv = [f for f in findings if "EVIDENTIA-WRITE-PRIV-DETECTED" in f.source_finding_id]
    assert len(write_priv) == 1
    f = write_priv[0]
    assert f.severity == Severity.HIGH
    assert "sysadmin" in f.title


def test_no_write_priv_finding_when_read_only() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = MSSQLCollector(connection=conn)
    findings = coll.collect()
    write_priv = [f for f in findings if "EVIDENTIA-WRITE-PRIV-DETECTED" in f.source_finding_id]
    assert write_priv == []


def test_user_inventory_finding() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = MSSQLCollector(connection=conn)
    findings = coll.collect()
    inventory = [f for f in findings if "user inventory" in f.title]
    assert len(inventory) == 1
    f = inventory[0]
    assert f.raw_data["total_principals"] == 3
    assert f.raw_data["sql_login_count"] == 2


def test_audit_log_finding_when_enabled() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = MSSQLCollector(connection=conn)
    findings = coll.collect()
    audit_findings = [f for f in findings if "SQL Audit" in f.title]
    assert len(audit_findings) == 1
    f = audit_findings[0]
    assert f.status == FindingStatus.RESOLVED
    assert f.raw_data["enabled_audits"] == 1


def test_audit_log_finding_when_disabled() -> None:
    responses = _baseline_responses()
    responses["sys.server_audits"] = (0, 0)  # nothing configured
    conn = _MockConnection(responses)
    coll = MSSQLCollector(connection=conn)
    findings = coll.collect()
    audit_findings = [f for f in findings if "SQL Audit" in f.title]
    assert len(audit_findings) == 1
    f = audit_findings[0]
    assert f.status == FindingStatus.ACTIVE
    assert f.severity == Severity.MEDIUM


def test_tde_finding_all_encrypted() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = MSSQLCollector(connection=conn)
    findings = coll.collect()
    tde = [f for f in findings if "TDE state" in f.title]
    assert len(tde) == 1
    f = tde[0]
    assert f.status == FindingStatus.RESOLVED
    assert len(f.raw_data["unencrypted_databases"]) == 0


def test_tde_finding_with_unencrypted_db() -> None:
    responses = _baseline_responses()
    responses["sys.dm_database_encryption_keys"] = [
        ("appdb", 3),
        ("legacydb", 0),  # unencrypted
    ]
    conn = _MockConnection(responses)
    coll = MSSQLCollector(connection=conn)
    findings = coll.collect()
    tde = [f for f in findings if "TDE state" in f.title]
    assert len(tde) == 1
    f = tde[0]
    assert f.status == FindingStatus.ACTIVE
    assert "legacydb" in f.raw_data["unencrypted_databases"]


def test_tls_finding_when_encrypted() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = MSSQLCollector(connection=conn)
    findings = coll.collect()
    tls = [f for f in findings if "encrypted=" in f.title]
    assert len(tls) == 1
    f = tls[0]
    assert f.status == FindingStatus.RESOLVED


def test_tls_finding_when_unencrypted() -> None:
    responses = _baseline_responses()
    responses["CONNECTIONPROPERTY"] = ("TCP", "SQL", "FALSE")
    conn = _MockConnection(responses)
    coll = MSSQLCollector(connection=conn)
    findings = coll.collect()
    tls = [f for f in findings if "encrypted=" in f.title]
    assert len(tls) == 1
    f = tls[0]
    assert f.status == FindingStatus.ACTIVE
    assert f.severity == Severity.MEDIUM


# ── End-to-end manifest ─────────────────────────────────────────────


def test_collect_v2_emits_manifest() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = MSSQLCollector(connection=conn)
    findings, manifest = coll.collect_v2()

    assert manifest.collector_id == COLLECTOR_ID
    assert manifest.is_complete
    assert manifest.total_findings == len(findings)
    assert "mssql:evidentia_reader@appdb" in manifest.source_system_ids[0]


def test_dry_run_returns_empty_list() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = MSSQLCollector(connection=conn)
    findings = coll.collect(dry_run=True)
    assert findings == []
