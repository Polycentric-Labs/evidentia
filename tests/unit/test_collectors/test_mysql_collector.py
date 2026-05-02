"""Unit tests for the MySQL evidence collector (v0.7.7 P0.2).

Mocks the pymysql connection at the cursor level — no real MySQL
required. Integration tests against a real Docker MySQL live under
tests/integration/test_sql/test_mysql_real.py.
"""

from __future__ import annotations

from typing import Any

import pytest
from evidentia_collectors.sql.mysql import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    MySQLCollector,
    MySQLCollectorError,
)


class _MockCursor:
    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self._last_query = ""
        self.executed: list[tuple[str, Any]] = []

    def execute(self, query: str, params: Any = None) -> None:
        self._last_query = query
        self.executed.append((query, params))

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
    """Hardened MySQL 8.0 baseline."""
    return {
        # test_connection
        "CURRENT_USER(), DATABASE(), VERSION()": (
            "evidentia_reader@%",
            "appdb",
            "8.0.40",
        ),
        # _probe_write_privilege
        "@@global.read_only": (1, 1),  # both read-only
        # mysql.user enumeration
        "FROM mysql.user": [
            ("root", "localhost", "Y", "N"),
            ("evidentia_reader", "%", "N", "N"),
            ("app_user", "%", "N", "N"),
        ],
        # information_schema.TABLE_PRIVILEGES
        "information_schema.TABLE_PRIVILEGES": [
            ("'app_user'@'%'", 8),
            ("'reader_role'@'%'", 4),
        ],
        # SHOW VARIABLES (full dump; collector filters client-side)
        "SHOW VARIABLES": [
            ("general_log", "OFF"),
            ("general_log_file", "/var/lib/mysql/general.log"),
            ("log_output", "FILE"),
            ("have_ssl", "YES"),
            ("require_secure_transport", "ON"),
            ("ssl_cipher", "ECDHE-RSA-AES256-GCM-SHA384"),
            ("tls_version", "TLSv1.2,TLSv1.3"),
            ("default_authentication_plugin", "caching_sha2_password"),
            ("innodb_encrypt_tables", "ON"),
            ("innodb_encryption_threads", "4"),
            ("default_table_encryption", "ON"),
            ("keyring_file_data", "/var/lib/mysql-keyring/keyring"),
            ("max_connections", "200"),
            ("max_user_connections", "100"),
        ],
    }


class TestConstructorValidation:
    def test_rejects_embedded_password(self) -> None:
        with pytest.raises(MySQLCollectorError, match="must NOT embed a password"):
            MySQLCollector(connection_uri="mysql://user:secret@host/db")

    def test_accepts_uri_without_password(self) -> None:
        c = MySQLCollector(
            connection_uri="mysql://user@host/db", password="x"
        )
        assert c is not None

    def test_rejects_empty_constructor(self) -> None:
        with pytest.raises(MySQLCollectorError, match="requires either"):
            MySQLCollector()

    def test_accepts_injected_connection(self) -> None:
        c = MySQLCollector(connection=_MockConnection({}))
        assert c is not None


class TestUriParsing:
    def test_full_uri(self) -> None:
        c = MySQLCollector(
            connection_uri="mysql://reader@db.example.com:3307/appdb"
        )
        kwargs = c._parse_uri("mysql://reader@db.example.com:3307/appdb")
        assert kwargs["host"] == "db.example.com"
        assert kwargs["port"] == 3307
        assert kwargs["user"] == "reader"
        assert kwargs["database"] == "appdb"

    def test_minimal_uri(self) -> None:
        c = MySQLCollector(connection_uri="mysql://host/db")
        kwargs = c._parse_uri("mysql://host/db")
        assert kwargs["host"] == "host"
        assert kwargs["port"] == 3306  # default
        assert kwargs["user"] == ""
        assert kwargs["database"] == "db"


class TestCollectV2:
    def test_full_collection_clean_baseline(self) -> None:
        conn = _MockConnection(_baseline_responses())
        collector = MySQLCollector(connection=conn)
        findings, manifest = collector.collect_v2()

        assert len(findings) >= 5
        assert manifest.collector_id == COLLECTOR_ID
        assert manifest.is_complete is True
        for f in findings:
            assert f.collection_context is not None
            assert f.collection_context.collector_id == COLLECTOR_ID

    def test_findings_carry_expected_nist_controls(self) -> None:
        conn = _MockConnection(_baseline_responses())
        collector = MySQLCollector(connection=conn)
        findings, _ = collector.collect_v2()

        controls = {c for f in findings for c in (f.control_ids or [])}
        assert "AC-2" in controls
        assert "AC-3" in controls
        assert "AU-2" in controls
        assert "SC-12" in controls
        assert "SC-28" in controls

    def test_crypto_gap_when_ssl_off(self) -> None:
        responses = _baseline_responses()
        # Override SHOW VARIABLES with a weaker config
        responses["SHOW VARIABLES"] = [
            ("have_ssl", "DISABLED"),
            ("require_secure_transport", "OFF"),
            ("default_authentication_plugin", "mysql_native_password"),
            ("innodb_encrypt_tables", "ON"),
            ("default_table_encryption", "ON"),
            ("keyring_file_data", "/var/lib/mysql-keyring/keyring"),
            ("max_connections", "100"),
        ]
        conn = _MockConnection(responses)
        collector = MySQLCollector(connection=conn)
        findings, _ = collector.collect_v2()
        crypto = [
            f for f in findings if "crypto-config" in (f.source_finding_id or "")
        ]
        assert len(crypto) == 1
        from evidentia_core.models.common import Severity
        assert crypto[0].severity == Severity.HIGH


class TestBlindSpots:
    def test_blind_spots_well_formed(self) -> None:
        assert len(BLIND_SPOTS) >= 3
        for entry in BLIND_SPOTS:
            assert entry["id"].startswith("EVIDENTIA-MYSQL-")
            assert "title" in entry
            assert len(entry["description"]) > 50

    def test_unique_ids(self) -> None:
        ids = [e["id"] for e in BLIND_SPOTS]
        assert len(ids) == len(set(ids))


class TestLifecycle:
    def test_close_idempotent(self) -> None:
        collector = MySQLCollector(connection=_MockConnection({}))
        collector.close()
        collector.close()  # second close is a no-op

    def test_does_not_close_injected_connection(self) -> None:
        conn = _MockConnection({})
        collector = MySQLCollector(connection=conn)
        collector.close()
        assert conn.closed is False
