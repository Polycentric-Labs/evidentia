"""Unit tests for the Oracle Database evidence collector (v0.7.7 P0.5).

Mocks the oracledb connection at the cursor level — no real Oracle
required. Mirrors the pattern from test_postgres / test_mysql /
test_mssql collectors.
"""

from __future__ import annotations

from typing import Any

import pytest
from evidentia_collectors.sql.oracle import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    OracleCollector,
    OracleCollectorError,
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
    """Default responses representing a hardened Oracle with read-only
    least-privilege principal."""
    return {
        # test_connection probe
        "SYS_CONTEXT('USERENV','CURRENT_USER')": (
            "EVIDENTIA_READER",
            "ORCL",
            "Oracle Database 19c Enterprise Edition Release 19.0.0.0.0",
        ),
        # _probe_write_privilege
        "session_roles WHERE role = 'DBA'": (0,),
        "session_privs WHERE privilege = 'SYSDBA'": (0,),
        "INSERT ANY TABLE": [],  # no any-table grants
        # _user_role_inventory_findings
        "FROM dba_users": [
            ("EVIDENTIA_READER", "OPEN", "DEFAULT", "2024-01-01"),
            ("APP_USER", "OPEN", "DEFAULT", "2024-01-01"),
            ("SYS", "LOCKED", "DEFAULT", "2020-01-01"),
            ("SYSTEM", "LOCKED", "DEFAULT", "2020-01-01"),
        ],
        # _privilege_grant_findings
        "dba_role_privs": [
            ("APP_DBA",),
        ],
        # _password_policy_findings
        "dba_profiles": [
            ("DEFAULT", "PASSWORD_LIFE_TIME", "180"),
            ("DEFAULT", "FAILED_LOGIN_ATTEMPTS", "5"),
            ("DEFAULT", "PASSWORD_REUSE_TIME", "365"),
            ("DEFAULT", "PASSWORD_VERIFY_FUNCTION", "ORA12C_VERIFY_FUNCTION"),
        ],
        # _audit_log_findings
        "AUDIT_UNIFIED_ENABLED_POLICIES": (3,),
        "name = 'audit_trail'": ("DB",),
        # _tde_encryption_findings
        "v$encryption_wallet": ("OPEN",),
        "encrypted = 'YES'": (1,),
        # _network_encryption_findings
        "sqlnet.encryption": [
            ("sqlnet.encryption_server", "REQUIRED"),
            ("sqlnet.encryption_types_server", "AES256"),
        ],
        # _connection_limit_findings
        "sessions": [
            ("sessions", "528"),
            ("processes", "320"),
        ],
    }


# ── Constants ────────────────────────────────────────────────────────


def test_collector_id_constant() -> None:
    assert COLLECTOR_ID == "sql-oracle-scan"


def test_blind_spots_documented() -> None:
    assert len(BLIND_SPOTS) == 4
    ids = [bs["id"] for bs in BLIND_SPOTS]
    assert "EVIDENTIA-ORACLE-LICENSE-FEATURE" in ids
    assert "EVIDENTIA-ORACLE-AUDIT-MIXED-MODE" in ids
    assert "EVIDENTIA-ORACLE-CDB-PDB-CONTEXT" in ids
    assert "EVIDENTIA-ORACLE-NETWORK-ENCRYPTION-CLIENT" in ids


# ── Construction validation ─────────────────────────────────────────


def test_constructor_requires_uri_or_connection() -> None:
    with pytest.raises(OracleCollectorError, match="requires either"):
        OracleCollector()


def test_constructor_rejects_password_in_uri() -> None:
    with pytest.raises(OracleCollectorError, match="must NOT embed a password"):
        OracleCollector(connection_uri="oracle://user:secret@host:1521/orcl")


def test_constructor_accepts_uri_without_password() -> None:
    coll = OracleCollector(
        connection_uri="oracle://user@host:1521/orcl",
        password="should-not-leak",
    )
    assert coll._cached_user is None


def test_parse_uri_extracts_dsn() -> None:
    coll = OracleCollector(connection_uri="oracle://user@host:1521/orcl")
    kwargs = coll._parse_uri("oracle://user@host:1521/orcl")
    assert kwargs["user"] == "user"
    assert kwargs["dsn"] == "host:1521/orcl"


# ── test_connection ─────────────────────────────────────────────────


def test_test_connection_caches_metadata() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = OracleCollector(connection=conn)
    info = coll.test_connection()
    assert info["user"] == "EVIDENTIA_READER"
    assert info["database"] == "ORCL"
    assert "Oracle Database 19c" in info["version"]
    assert info["is_dba"] is False
    assert info["is_sysdba"] is False
    assert info["any_table_grants"] == []


def test_test_connection_detects_dba_membership() -> None:
    responses = _baseline_responses()
    responses["session_roles WHERE role = 'DBA'"] = (1,)
    conn = _MockConnection(responses)
    coll = OracleCollector(connection=conn)
    info = coll.test_connection()
    assert info["is_dba"] is True


# ── Sub-checks ──────────────────────────────────────────────────────


def test_write_priv_finding_fires_on_dba() -> None:
    responses = _baseline_responses()
    responses["session_roles WHERE role = 'DBA'"] = (1,)
    conn = _MockConnection(responses)
    coll = OracleCollector(connection=conn)
    findings = coll.collect()
    write_priv = [f for f in findings if "EVIDENTIA-WRITE-PRIV-DETECTED" in f.source_finding_id]
    assert len(write_priv) == 1
    f = write_priv[0]
    assert f.severity == Severity.HIGH
    assert "DBA role" in f.description


def test_write_priv_finding_with_any_table_grants() -> None:
    responses = _baseline_responses()
    responses["INSERT ANY TABLE"] = [
        ("INSERT ANY TABLE",),
        ("UPDATE ANY TABLE",),
    ]
    conn = _MockConnection(responses)
    coll = OracleCollector(connection=conn)
    findings = coll.collect()
    write_priv = [f for f in findings if "EVIDENTIA-WRITE-PRIV-DETECTED" in f.source_finding_id]
    assert len(write_priv) == 1
    f = write_priv[0]
    assert f.severity == Severity.MEDIUM  # not DBA, just ANY-table
    assert "ANY-table grants" in f.description


def test_no_write_priv_finding_when_read_only() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = OracleCollector(connection=conn)
    findings = coll.collect()
    write_priv = [f for f in findings if "EVIDENTIA-WRITE-PRIV-DETECTED" in f.source_finding_id]
    assert write_priv == []


def test_user_inventory_finding() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = OracleCollector(connection=conn)
    findings = coll.collect()
    inventory = [f for f in findings if "user inventory" in f.title]
    assert len(inventory) == 1
    f = inventory[0]
    assert f.raw_data["total_users"] == 4
    assert f.raw_data["open_count"] == 2
    assert f.raw_data["locked_count"] == 2


def test_dba_role_grants_finding_clean() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = OracleCollector(connection=conn)
    findings = coll.collect()
    dba = [f for f in findings if "DBA role" in f.title]
    assert len(dba) == 1
    f = dba[0]
    assert f.status == FindingStatus.RESOLVED  # only 1 grantee


def test_dba_role_grants_finding_too_many() -> None:
    responses = _baseline_responses()
    responses["dba_role_privs"] = [(f"APP_DBA_{i}",) for i in range(7)]
    conn = _MockConnection(responses)
    coll = OracleCollector(connection=conn)
    findings = coll.collect()
    dba = [f for f in findings if "DBA role" in f.title]
    f = dba[0]
    assert f.status == FindingStatus.ACTIVE
    assert f.severity == Severity.HIGH


def test_password_policy_finding_strong() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = OracleCollector(connection=conn)
    findings = coll.collect()
    pp = [f for f in findings if "DEFAULT profile" in f.title]
    assert len(pp) == 1
    f = pp[0]
    assert f.status == FindingStatus.RESOLVED


def test_password_policy_finding_weak() -> None:
    responses = _baseline_responses()
    responses["dba_profiles"] = [
        ("DEFAULT", "PASSWORD_LIFE_TIME", "UNLIMITED"),
        ("DEFAULT", "FAILED_LOGIN_ATTEMPTS", "10"),
        ("DEFAULT", "PASSWORD_VERIFY_FUNCTION", "NULL"),
    ]
    conn = _MockConnection(responses)
    coll = OracleCollector(connection=conn)
    findings = coll.collect()
    pp = [f for f in findings if "DEFAULT profile" in f.title]
    f = pp[0]
    assert f.status == FindingStatus.ACTIVE
    assert f.severity == Severity.MEDIUM


def test_audit_log_finding_unified_active() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = OracleCollector(connection=conn)
    findings = coll.collect()
    audit = [f for f in findings if "Oracle Audit" in f.title]
    assert len(audit) == 1
    f = audit[0]
    assert f.status == FindingStatus.RESOLVED


def test_audit_log_finding_no_audit() -> None:
    responses = _baseline_responses()
    responses["AUDIT_UNIFIED_ENABLED_POLICIES"] = (0,)
    responses["name = 'audit_trail'"] = ("NONE",)
    conn = _MockConnection(responses)
    coll = OracleCollector(connection=conn)
    findings = coll.collect()
    audit = [f for f in findings if "Oracle Audit" in f.title]
    f = audit[0]
    assert f.status == FindingStatus.ACTIVE
    assert f.severity == Severity.HIGH


def test_tde_finding_active() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = OracleCollector(connection=conn)
    findings = coll.collect()
    tde = [f for f in findings if "Oracle TDE" in f.title]
    assert len(tde) == 1
    f = tde[0]
    assert f.status == FindingStatus.RESOLVED
    assert f.raw_data["wallet_status"] == "OPEN"


def test_network_encryption_finding_required() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = OracleCollector(connection=conn)
    findings = coll.collect()
    netenc = [f for f in findings if "network encryption" in f.title]
    assert len(netenc) == 1
    f = netenc[0]
    assert f.status == FindingStatus.RESOLVED


def test_network_encryption_finding_unset() -> None:
    responses = _baseline_responses()
    responses["sqlnet.encryption"] = []
    conn = _MockConnection(responses)
    coll = OracleCollector(connection=conn)
    findings = coll.collect()
    netenc = [f for f in findings if "network encryption" in f.title]
    f = netenc[0]
    assert f.status == FindingStatus.ACTIVE
    assert f.severity == Severity.MEDIUM


# ── End-to-end manifest ─────────────────────────────────────────────


def test_collect_v2_emits_manifest() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = OracleCollector(connection=conn)
    findings, manifest = coll.collect_v2()

    assert manifest.collector_id == COLLECTOR_ID
    assert manifest.is_complete
    assert manifest.total_findings == len(findings)
    assert "oracle:EVIDENTIA_READER@ORCL" in manifest.source_system_ids[0]


def test_dry_run_returns_empty_list() -> None:
    conn = _MockConnection(_baseline_responses())
    coll = OracleCollector(connection=conn)
    findings = coll.collect(dry_run=True)
    assert findings == []
