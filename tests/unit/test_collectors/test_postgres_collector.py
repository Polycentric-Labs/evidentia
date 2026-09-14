"""Unit tests for the PostgreSQL evidence collector (v0.7.7 P0.1).

Mocks the psycopg connection at the cursor level — no real Postgres
required. Integration tests against a real Docker Postgres live
under tests/integration/test_sql/ (not yet shipped; v0.7.7 P0.6).
"""

from __future__ import annotations

from typing import Any

import pytest
from evidentia_collectors.sql.postgres import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    PostgresCollector,
    PostgresCollectorError,
    PostgresQueryError,
)
from evidentia_core.models.finding import FindingStatus

# ── Mock connection infrastructure ──────────────────────────────────


class _MockCursor:
    """Minimal psycopg-cursor stand-in. Routes by the LAST query string
    seen via execute(); fetchone()/fetchall() return pre-canned data.
    """

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
    """Minimal psycopg-connection stand-in."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.closed = False

    def cursor(self) -> _MockCursor:
        return _MockCursor(self._responses)

    def close(self) -> None:
        self.closed = True


def _baseline_responses() -> dict[str, Any]:
    """Default responses representing a healthy hardened Postgres."""
    return {
        # test_connection probe
        "current_user, current_database()": (
            "evidentia_reader",
            "appdb",
            "PostgreSQL 16.2",
        ),
        # _probe_write_privilege phase 1
        "default_transaction_read_only": ("on",),
        # pg_roles enumeration
        "FROM pg_roles": [
            ("postgres", True, True, True, True, True),  # superuser
            ("evidentia_reader", False, False, False, True, False),
            ("app_user", False, False, False, True, False),
        ],
        # information_schema.table_privileges enumeration
        "information_schema.table_privileges": [
            ("app_user", 12),
            ("read_only_role", 5),
        ],
        # pg_settings reads — the collector batches these via WHERE name IN
        "pg_settings": [
            ("log_connections", "on"),
            ("log_disconnections", "on"),
            ("log_statement", "ddl"),
            ("log_line_prefix", "%t [%p]: "),
            ("log_destination", "stderr"),
            ("password_encryption", "scram-sha-256"),
            ("ssl", "on"),
            ("ssl_min_protocol_version", "TLSv1.2"),
            ("ssl_ciphers", "HIGH:MEDIUM:+3DES:!aNULL"),
            ("max_connections", "200"),
            ("superuser_reserved_connections", "3"),
        ],
        # pg_extension lookup for pgaudit
        "FROM pg_extension": [],  # pgaudit not installed
    }


# ── Constructor + secret-handling tests ─────────────────────────────


class TestConstructorValidation:
    def test_rejects_embedded_password_in_uri(self) -> None:
        with pytest.raises(PostgresCollectorError, match="must NOT embed a password"):
            PostgresCollector(connection_uri="postgres://user:secret@host/db")

    def test_accepts_uri_without_embedded_password(self) -> None:
        c = PostgresCollector(connection_uri="postgres://user@host/db", password="x")
        assert c is not None

    def test_accepts_uri_with_no_userinfo(self) -> None:
        # URI-only form (host/db, no username embedded) is allowed
        c = PostgresCollector(connection_uri="postgres://host/db", password="x")
        assert c is not None

    def test_rejects_empty_constructor(self) -> None:
        with pytest.raises(PostgresCollectorError, match="requires either"):
            PostgresCollector()

    def test_accepts_injected_connection(self) -> None:
        c = PostgresCollector(connection=_MockConnection({}))
        assert c is not None


# ── Read-only probe tests ───────────────────────────────────────────


class TestReadOnlyProbe:
    def test_read_only_principal_clean(self) -> None:
        responses = _baseline_responses()
        # CREATE TEMP TABLE will succeed in the mock unless we make it
        # fail. The mock has no failure path for CREATE TEMP TABLE,
        # so we rely on default_transaction_read_only=on signal +
        # the savepoint flow always running. To simulate true
        # read-only, set the create-temp behavior to error out.
        # The mock currently just no-ops execute() on unknown
        # queries — so the probe will think CREATE TEMP succeeded.
        # That's expected for this mock; the assertion below tests
        # that the read_only_setting is reported correctly.
        conn = _MockConnection(responses)
        collector = PostgresCollector(connection=conn)
        info = collector.test_connection()
        assert info["user"] == "evidentia_reader"
        assert info["database"] == "appdb"
        assert info["version"].startswith("PostgreSQL 16")
        assert info["read_only"] is True

    def test_write_priv_detected_when_setting_off(self) -> None:
        responses = _baseline_responses()
        responses["default_transaction_read_only"] = ("off",)
        conn = _MockConnection(responses)
        collector = PostgresCollector(connection=conn)
        info = collector.test_connection()
        assert info["read_only"] is False


# ── Full collect_v2 integration via mock ────────────────────────────


class TestCollectV2:
    def test_full_collection_clean_baseline(self) -> None:
        conn = _MockConnection(_baseline_responses())
        collector = PostgresCollector(connection=conn)
        findings, manifest = collector.collect_v2()

        # Every sub-check should produce at least one finding
        assert len(findings) >= 5
        assert manifest.collector_id == COLLECTOR_ID
        assert manifest.is_complete is True
        assert manifest.errors == []
        # CollectionContext threaded through every finding
        for f in findings:
            assert f.collection_context is not None
            assert f.collection_context.collector_id == COLLECTOR_ID
            assert f.collection_context.run_id  # non-empty

    def test_findings_carry_expected_nist_controls(self) -> None:
        conn = _MockConnection(_baseline_responses())
        collector = PostgresCollector(connection=conn)
        findings, _ = collector.collect_v2()

        # Aggregate every NIST control_id across all findings
        controls = {c for f in findings for c in (f.control_ids or [])}
        # The full SC-28 + SC-12 + AU-2/3 + AC-2/3/6 set must surface
        assert "AC-2" in controls  # user/role inventory
        assert "AC-3" in controls  # privilege grants + connection limits
        assert "AC-6" in controls  # privilege grants
        assert "AU-2" in controls  # audit log
        assert "AU-3" in controls  # audit log
        assert "SC-12" in controls  # crypto config
        assert "SC-28" in controls  # encryption-at-rest

    def test_audit_log_gap_drives_severity(self) -> None:
        responses = _baseline_responses()
        # Override pg_settings to surface gaps
        responses["pg_settings"] = [
            ("log_connections", "off"),
            ("log_disconnections", "off"),
            ("log_statement", "none"),
            ("password_encryption", "scram-sha-256"),
            ("ssl", "on"),
            ("max_connections", "100"),
        ]
        conn = _MockConnection(responses)
        collector = PostgresCollector(connection=conn)
        findings, _ = collector.collect_v2()
        audit_findings = [f for f in findings if "audit-log" in (f.source_finding_id or "")]
        assert len(audit_findings) == 1
        # Audit-log gaps should drive non-INFORMATIONAL severity +
        # ACTIVE status (vs RESOLVED for clean baseline)
        assert audit_findings[0].status == FindingStatus.ACTIVE

    def test_crypto_config_gap_drives_high_severity(self) -> None:
        responses = _baseline_responses()
        # Override pg_settings: weak crypto config
        responses["pg_settings"] = [
            ("log_connections", "on"),
            ("log_disconnections", "on"),
            ("log_statement", "ddl"),
            ("password_encryption", "md5"),  # gap: deprecated
            ("ssl", "off"),  # gap: TLS off
            ("max_connections", "100"),
        ]
        conn = _MockConnection(responses)
        collector = PostgresCollector(connection=conn)
        findings, _ = collector.collect_v2()
        crypto_findings = [f for f in findings if "crypto-config" in (f.source_finding_id or "")]
        assert len(crypto_findings) == 1
        # Severity should reflect gaps; the collector emits HIGH when
        # password_encryption is not scram-sha-256 OR ssl is off
        from evidentia_core.models.common import Severity

        assert crypto_findings[0].severity == Severity.HIGH


# ── BLIND_SPOTS list shape ──────────────────────────────────────────


class TestBlindSpots:
    def test_blind_spots_well_formed(self) -> None:
        assert len(BLIND_SPOTS) >= 4
        for entry in BLIND_SPOTS:
            assert "id" in entry
            assert entry["id"].startswith("EVIDENTIA-POSTGRES-")
            assert "title" in entry
            assert "description" in entry
            assert len(entry["description"]) > 50  # substantive

    def test_blind_spot_ids_are_unique(self) -> None:
        ids = [e["id"] for e in BLIND_SPOTS]
        assert len(ids) == len(set(ids))


# ── Lazy psycopg import + lifecycle ─────────────────────────────────


class TestLifecycle:
    def test_close_idempotent(self) -> None:
        conn = _MockConnection({})
        collector = PostgresCollector(connection=conn)
        collector.close()
        # Second close should not raise
        collector.close()

    def test_does_not_close_injected_connection(self) -> None:
        conn = _MockConnection({})
        collector = PostgresCollector(connection=conn)
        collector.close()
        # Injected connection is NOT owned, so close should not have
        # been called on it.
        assert conn.closed is False

    def test_context_manager_lifecycle(self) -> None:
        conn = _MockConnection(_baseline_responses())
        with PostgresCollector(connection=conn) as collector:
            assert collector is not None
        # Same as above — injected connection is not owned
        assert conn.closed is False


# ── v0.10.0: compliance_status + OCSF round-trip ─────────────────────────


class TestComplianceStatus:
    def test_clean_baseline_audit_and_crypto_pass(self) -> None:
        from evidentia_core.models.finding import ComplianceStatus

        findings, _ = PostgresCollector(connection=_MockConnection(_baseline_responses())).collect_v2()
        audit = next(f for f in findings if "audit-log" in (f.source_finding_id or ""))
        crypto = next(f for f in findings if "crypto-config" in (f.source_finding_id or ""))
        assert audit.compliance_status == ComplianceStatus.PASS
        assert crypto.compliance_status == ComplianceStatus.PASS

    def test_audit_log_gap_compliance_status_is_fail(self) -> None:
        from evidentia_core.models.finding import ComplianceStatus

        responses = _baseline_responses()
        responses["pg_settings"] = [
            ("log_connections", "off"),
            ("log_disconnections", "off"),
            ("log_statement", "none"),
            ("password_encryption", "scram-sha-256"),
            ("ssl", "on"),
            ("max_connections", "100"),
        ]
        findings, _ = PostgresCollector(connection=_MockConnection(responses)).collect_v2()
        audit = next(f for f in findings if "audit-log" in (f.source_finding_id or ""))
        assert audit.compliance_status == ComplianceStatus.FAIL

    def test_role_inventory_compliance_status_is_unknown(self) -> None:
        from evidentia_core.models.finding import ComplianceStatus

        findings, _ = PostgresCollector(connection=_MockConnection(_baseline_responses())).collect_v2()
        role_inv = next(f for f in findings if "role-inventory" in (f.source_finding_id or ""))
        assert role_inv.compliance_status == ComplianceStatus.UNKNOWN

    def test_postgres_findings_ocsf_round_trip(self) -> None:
        pytest.importorskip("py_ocsf_models")
        from evidentia_core.ocsf import finding_from_ocsf, finding_to_ocsf

        findings, _ = PostgresCollector(connection=_MockConnection(_baseline_responses())).collect_v2()
        assert findings
        for f in findings:
            assert finding_from_ocsf(finding_to_ocsf(f)) == f


class _PrivilegeScriptCursor:
    """Consume one explicit statement script without a driver or database."""

    def __init__(
        self,
        steps: list[tuple[str, BaseException | None]],
        row: tuple[str, ...] = ("on",),
        *,
        fetch_error: BaseException | None = None,
        close_error: BaseException | None = None,
    ) -> None:
        self.steps = list(steps)
        self.row = row
        self.fetch_error = fetch_error
        self.close_error = close_error
        self.executed: list[str] = []
        self.close_calls = 0

    def execute(self, query: str) -> None:
        self.executed.append(query)
        assert self.steps, "Unexpected statement after the declared script"
        expected, failure = self.steps.pop(0)
        assert query == expected
        if failure is not None:
            raise failure

    def fetchone(self) -> tuple[str, ...]:
        if self.fetch_error is not None:
            raise self.fetch_error
        return self.row

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class _PrivilegeScriptConnection:
    def __init__(self, cursors: list[_PrivilegeScriptCursor]) -> None:
        self.pending = list(cursors)
        self.used: list[_PrivilegeScriptCursor] = []
        self.close_calls = 0

    def cursor(self) -> _PrivilegeScriptCursor:
        assert self.pending, "Unexpected cursor after the declared script"
        cursor = self.pending.pop(0)
        self.used.append(cursor)
        return cursor

    def close(self) -> None:
        self.close_calls += 1


class _PrivilegeProbeCancellation(BaseException):
    """A synthetic cancellation distinct from ordinary query exceptions."""


_PRIVILEGE_SETTING = "SELECT current_setting('default_transaction_read_only', true)"
_PRIVILEGE_SAVEPOINT = "SAVEPOINT evidentia_priv_probe"
_PRIVILEGE_CREATE = "CREATE TEMP TABLE evidentia_priv_probe_temp (id int) ON COMMIT DROP"
_PRIVILEGE_ROLLBACK = "ROLLBACK TO SAVEPOINT evidentia_priv_probe"
_PRIVILEGE_RELEASE = "RELEASE SAVEPOINT evidentia_priv_probe"
_PRIVILEGE_IDENTITY = "SELECT current_user, current_database(), version()"


class TestQ6PrivilegeProbeRecovery:
    @pytest.mark.parametrize("setting, expected", [("on", True), ("off", False)])
    @pytest.mark.parametrize("denied", [False, True])
    def test_normal_and_expected_denial_preserve_exact_script(self, setting: str, expected: bool, denied: bool) -> None:
        failure = PermissionError("synthetic denied query") if denied else None
        steps = [
            (_PRIVILEGE_SETTING, None),
            (_PRIVILEGE_SAVEPOINT, None),
            (_PRIVILEGE_CREATE, failure),
            (_PRIVILEGE_ROLLBACK, None),
            (_PRIVILEGE_RELEASE, None),
        ]
        cursor = _PrivilegeScriptCursor(steps, (setting,))
        connection = _PrivilegeScriptConnection([cursor])
        collector = PostgresCollector(connection=connection)
        assert collector._probe_write_privilege(connection) == (expected, not denied)
        assert cursor.executed == [query for query, _failure in steps]
        assert cursor.steps == []
        assert cursor.close_calls == 1
        assert connection.pending == []
        assert connection.close_calls == 0

    @pytest.mark.parametrize("entry", ["probe", "connection", "collect"])
    @pytest.mark.parametrize(
        "failed_recovery", ["rollback", "release", "savepoint", "initial_rollback", "initial_release"]
    )
    def test_failed_recovery_refuses_before_reporting_or_collection(
        self, entry: str, failed_recovery: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        denied = PermissionError("synthetic denied query")
        recovery_error = RuntimeError("synthetic recovery detail must remain suppressed")
        steps: list[tuple[str, BaseException | None]] = [(_PRIVILEGE_SETTING, None)]
        if failed_recovery == "savepoint":
            steps += [(_PRIVILEGE_SAVEPOINT, denied), (_PRIVILEGE_ROLLBACK, recovery_error)]
        elif failed_recovery == "initial_rollback":
            steps += [
                (_PRIVILEGE_SAVEPOINT, None),
                (_PRIVILEGE_CREATE, None),
                (_PRIVILEGE_ROLLBACK, denied),
                (_PRIVILEGE_ROLLBACK, recovery_error),
            ]
        elif failed_recovery == "initial_release":
            steps += [
                (_PRIVILEGE_SAVEPOINT, None),
                (_PRIVILEGE_CREATE, None),
                (_PRIVILEGE_ROLLBACK, None),
                (_PRIVILEGE_RELEASE, denied),
                (_PRIVILEGE_ROLLBACK, recovery_error),
            ]
        else:
            steps += [(_PRIVILEGE_SAVEPOINT, None), (_PRIVILEGE_CREATE, denied)]
            if failed_recovery == "rollback":
                steps += [(_PRIVILEGE_ROLLBACK, recovery_error)]
            else:
                steps += [(_PRIVILEGE_ROLLBACK, None), (_PRIVILEGE_RELEASE, recovery_error)]
        cursor = _PrivilegeScriptCursor(steps)
        cursors = [cursor]
        if entry != "probe":
            cursors.insert(
                0,
                _PrivilegeScriptCursor(
                    [(_PRIVILEGE_IDENTITY, None)], ("synthetic_reader", "synthetic_db", "synthetic_version")
                ),
            )
        connection = _PrivilegeScriptConnection(cursors)
        collector = PostgresCollector(connection=connection)
        context_calls: list[str] = []

        def refuse_context(run_id: str) -> Any:
            context_calls.append(run_id)
            raise AssertionError("Collection advanced after unconfirmed probe recovery")

        monkeypatch.setattr(collector, "_build_context", refuse_context)
        try:
            with pytest.raises(PostgresQueryError) as caught:
                if entry == "probe":
                    collector._probe_write_privilege(connection)
                elif entry == "connection":
                    collector.test_connection()
                else:
                    collector.collect_v2()
            assert type(caught.value) is PostgresQueryError
            assert str(caught.value) == "Could not restore the Postgres privilege-probe savepoint."
            assert caught.value.__cause__ is None
            assert caught.value.__suppress_context__ is True
        finally:
            assert cursor.executed == [query for query, _failure in steps]
            assert cursor.steps == []
            assert all(item.close_calls == 1 for item in cursors)
            assert connection.pending == []
            assert connection.close_calls == 0
        assert context_calls == []

    @pytest.mark.parametrize("stage", ["execute", "fetch"])
    def test_initial_query_error_propagates_with_cursor_cleanup(self, stage: str) -> None:
        failure = RuntimeError("synthetic setting query failure")
        cursor = _PrivilegeScriptCursor(
            [(_PRIVILEGE_SETTING, failure if stage == "execute" else None)],
            fetch_error=failure if stage == "fetch" else None,
        )
        connection = _PrivilegeScriptConnection([cursor])
        with pytest.raises(RuntimeError) as caught:
            PostgresCollector(connection=connection)._probe_write_privilege(connection)
        assert caught.value is failure
        assert cursor.executed == [_PRIVILEGE_SETTING]
        assert cursor.steps == []
        assert cursor.close_calls == 1
        assert connection.close_calls == 0

    @pytest.mark.parametrize(
        "stage",
        [
            "setting",
            "fetch",
            "savepoint",
            "create",
            "rollback",
            "release",
            "recovery_rollback",
            "recovery_release",
            "close",
        ],
    )
    def test_cancellation_identity_and_cursor_close_attempt(self, stage: str) -> None:
        cancellation = _PrivilegeProbeCancellation("synthetic cancellation")
        prefix: list[tuple[str, BaseException | None]] = [(_PRIVILEGE_SETTING, None)]
        if stage == "setting":
            prefix = [(_PRIVILEGE_SETTING, cancellation)]
        elif stage not in {"fetch"}:
            prefix.append((_PRIVILEGE_SAVEPOINT, cancellation if stage == "savepoint" else None))
            if stage != "savepoint":
                denial = PermissionError("synthetic denied query") if stage.startswith("recovery_") else None
                prefix.append((_PRIVILEGE_CREATE, cancellation if stage == "create" else denial))
                if stage != "create":
                    prefix.append(
                        (_PRIVILEGE_ROLLBACK, cancellation if stage in {"rollback", "recovery_rollback"} else None)
                    )
                    if stage not in {"rollback", "recovery_rollback"}:
                        prefix.append(
                            (_PRIVILEGE_RELEASE, cancellation if stage in {"release", "recovery_release"} else None)
                        )
        cursor = _PrivilegeScriptCursor(
            prefix,
            fetch_error=cancellation if stage == "fetch" else None,
            close_error=cancellation if stage == "close" else None,
        )
        connection = _PrivilegeScriptConnection([cursor])
        with pytest.raises(_PrivilegeProbeCancellation) as caught:
            PostgresCollector(connection=connection)._probe_write_privilege(connection)
        assert caught.value is cancellation
        assert cursor.executed == [query for query, _failure in prefix]
        assert cursor.steps == []
        assert cursor.close_calls == 1
        assert connection.close_calls == 0

    def test_ordinary_close_failure_remains_an_error(self) -> None:
        failure = RuntimeError("synthetic close failure")
        cursor = _PrivilegeScriptCursor(
            [
                (_PRIVILEGE_SETTING, None),
                (_PRIVILEGE_SAVEPOINT, None),
                (_PRIVILEGE_CREATE, None),
                (_PRIVILEGE_ROLLBACK, None),
                (_PRIVILEGE_RELEASE, None),
            ],
            close_error=failure,
        )
        connection = _PrivilegeScriptConnection([cursor])
        with pytest.raises(RuntimeError) as caught:
            PostgresCollector(connection=connection)._probe_write_privilege(connection)
        assert caught.value is failure
        assert cursor.steps == []
        assert cursor.close_calls == 1
        assert connection.close_calls == 0
