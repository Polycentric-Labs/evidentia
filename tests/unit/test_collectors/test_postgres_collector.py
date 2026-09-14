"""Unit tests for the PostgreSQL evidence collector (v0.7.7 P0.1).

Mocks the psycopg connection at the cursor level — no real Postgres
required. Integration tests against a real Docker Postgres live
under tests/integration/test_sql/ (not yet shipped; v0.7.7 P0.6).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from types import SimpleNamespace
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


class _MockTransactionState:
    """Track the native idle/active boundary and owned savepoints."""

    def _init_transaction_state(self) -> None:
        self.autocommit = True
        self.transaction_active = False
        self.savepoints: set[str] = set()
        self.transaction_events: list[str] = []

    def _check_transaction_query(self, query: str) -> None:
        if query.startswith("SAVEPOINT "):
            if not self.transaction_active:
                raise RuntimeError("SAVEPOINT requires an active transaction")
            self.savepoints.add(query.removeprefix("SAVEPOINT "))
        elif query.startswith("ROLLBACK TO SAVEPOINT "):
            name = query.removeprefix("ROLLBACK TO SAVEPOINT ")
            if not self.transaction_active or name not in self.savepoints:
                raise RuntimeError("Rollback requires an existing savepoint")
        elif query.startswith("RELEASE SAVEPOINT "):
            name = query.removeprefix("RELEASE SAVEPOINT ")
            if not self.transaction_active or name not in self.savepoints:
                raise RuntimeError("Release requires an existing savepoint")
            self.savepoints.remove(name)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        previous_active = self.transaction_active
        previous_savepoints = set(self.savepoints)
        self.transaction_events.append("driver_savepoint" if previous_active else "begin")
        self.transaction_active = True
        try:
            yield
        except BaseException:
            self.transaction_events.append("driver_rollback" if previous_active else "rollback")
            self.savepoints = previous_savepoints
            raise
        else:
            assert self.savepoints == previous_savepoints, "Probe did not restore its owned savepoint"
            self.transaction_events.append("driver_release" if previous_active else "commit_empty")
        finally:
            self.transaction_active = previous_active


class _MockCursor:
    """Minimal psycopg-cursor stand-in. Routes by the LAST query string
    seen via execute(); fetchone()/fetchall() return pre-canned data.
    """

    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self._transaction_owner: _MockTransactionState | None = None
        self._last_query = ""
        self.executed: list[tuple[str, Any]] = []

    def execute(self, query: str, params: Any = None) -> None:
        if self._transaction_owner is not None:
            self._transaction_owner._check_transaction_query(query)
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


class _MockConnection(_MockTransactionState):
    """Minimal psycopg-connection stand-in."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self._init_transaction_state()
        self._responses = responses
        self.closed = False

    def cursor(self) -> _MockCursor:
        cursor = _MockCursor(self._responses)
        cursor._transaction_owner = self
        return cursor

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
        self._transaction_owner: _MockTransactionState | None = None
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
        if self._transaction_owner is not None:
            self._transaction_owner._check_transaction_query(query)

    def fetchone(self) -> tuple[str, ...]:
        if self.fetch_error is not None:
            raise self.fetch_error
        return self.row

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class _PrivilegeScriptConnection(_MockTransactionState):
    def __init__(self, cursors: list[_PrivilegeScriptCursor]) -> None:
        self._init_transaction_state()
        self.pending = list(cursors)
        self.used: list[_PrivilegeScriptCursor] = []
        self.close_calls = 0

    def cursor(self) -> _PrivilegeScriptCursor:
        assert self.pending, "Unexpected cursor after the declared script"
        cursor = self.pending.pop(0)
        self.used.append(cursor)
        cursor._transaction_owner = self
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


class TestNativeTransactionScope:
    @pytest.mark.parametrize("caller_active", [False, True])
    def test_scope_precedes_savepoint_and_preserves_caller(self, caller_active: bool) -> None:
        connection = _MockConnection(_baseline_responses())
        connection.transaction_active = caller_active
        expected_savepoints = {"caller_owned"} if caller_active else set()
        connection.savepoints = set(expected_savepoints)
        collector = PostgresCollector(connection=connection)

        assert collector._probe_write_privilege(connection) == (True, True)

        assert connection.autocommit is True
        assert connection.transaction_active is caller_active
        assert connection.savepoints == expected_savepoints
        assert connection.transaction_events == (
            ["driver_savepoint", "driver_release"] if caller_active else ["begin", "commit_empty"]
        )

    @pytest.mark.parametrize("failed_recovery", ["rollback", "release"])
    def test_owned_transaction_restore_error_still_refuses(self, failed_recovery: str) -> None:
        fault = RuntimeError("Synthetic restoration error")
        steps: list[tuple[str, BaseException | None]] = [
            (_PRIVILEGE_SETTING, None),
            (_PRIVILEGE_SAVEPOINT, None),
            (_PRIVILEGE_CREATE, PermissionError("Synthetic denial")),
            (_PRIVILEGE_ROLLBACK, fault if failed_recovery == "rollback" else None),
        ]
        if failed_recovery == "release":
            steps.append((_PRIVILEGE_RELEASE, fault))
        cursor = _PrivilegeScriptCursor(steps)
        connection = _PrivilegeScriptConnection([cursor])
        collector = PostgresCollector(connection=connection)

        with pytest.raises(PostgresQueryError) as caught:
            collector._probe_write_privilege(connection)

        assert str(caught.value) == "Could not restore the Postgres privilege-probe savepoint."
        assert connection.transaction_events == ["begin", "rollback"]
        assert connection.transaction_active is False
        assert not connection.savepoints
        assert not cursor.steps
        assert cursor.close_calls == 1


class _NativeDriverPrepared:
    def clear(self) -> None:
        pass

    def maintain_gen(self, connection: Any) -> Iterator[None]:
        yield from ()


class _NativeDriverCursor:
    def __init__(self, connection: Any) -> None:
        self.connection = connection
        self.close_calls = 0

    def execute(self, query: str) -> None:
        conn = self.connection
        conn.manual.append(query)
        fault = conn.manual_faults.get(query)
        if fault is not None:
            raise fault
        if query == _PRIVILEGE_SAVEPOINT:
            assert conn.pgconn.transaction_status == conn.driver.pq.TransactionStatus.INTRANS
            conn.manual_savepoint = True
        elif query == _PRIVILEGE_CREATE and conn.body_failure is not None:
            raise conn.body_failure
        elif query == _PRIVILEGE_ROLLBACK:
            assert conn.manual_savepoint
        elif query == _PRIVILEGE_RELEASE:
            assert conn.manual_savepoint
            conn.manual_savepoint = False

    def fetchone(self) -> tuple[str]:
        return ("on",)

    def close(self) -> None:
        self.close_calls += 1


class _NativeDriverConnection:
    """Run installed psycopg transaction control with owned in-memory commands."""

    connection = None
    _pipeline = None

    def __init__(self, driver: Any, caller_active: bool) -> None:
        self.driver = driver
        self.pgconn = SimpleNamespace(
            status=driver.pq.ConnStatus.OK,
            transaction_status=(
                driver.pq.TransactionStatus.INTRANS if caller_active else driver.pq.TransactionStatus.IDLE
            ),
            pipeline_status=0,
            host=b"synthetic",
            port=b"5432",
            user=b"synthetic",
            db=b"synthetic",
        )
        self.lock = nullcontext()
        self._num_transactions = 0
        self._prepared = _NativeDriverPrepared()
        self.autocommit = True
        self.body_failure: BaseException | None = None
        self.command_failure: BaseException | None = None
        self.failed_command: str | None = None
        self.manual_faults: dict[str, BaseException] = {}
        self.commands: list[str] = []
        self.manual: list[str] = []
        self.manual_savepoint = False
        self.cursor_instance = _NativeDriverCursor(self)

    def cursor(self) -> _NativeDriverCursor:
        return self.cursor_instance

    def transaction(self) -> Any:
        return self.driver.Connection.transaction(self)

    def wait(self, generator: Any) -> Any:
        try:
            while True:
                next(generator)
        except StopIteration as stop:
            return stop.value

    def _exec_command(self, command: bytes) -> Iterator[None]:
        text = command.decode("ascii")
        self.commands.append(text)
        if self.failed_command is not None and text.startswith(self.failed_command):
            assert self.command_failure is not None
            raise self.command_failure
        if command == b"BEGIN":
            self.pgconn.transaction_status = self.driver.pq.TransactionStatus.INTRANS
        elif command in {b"COMMIT", b"ROLLBACK"}:
            self.pgconn.transaction_status = self.driver.pq.TransactionStatus.IDLE
        yield from ()

    def _get_tx_start_command(self) -> bytes:
        return b"BEGIN"


def _native_driver_connection(caller_active: bool) -> _NativeDriverConnection:
    # The SQL extra is optional; full SQL acceptance requires these cases to run.
    driver = pytest.importorskip("psycopg")
    return _NativeDriverConnection(driver, caller_active)


class TestNativeDriverCleanup:
    @pytest.mark.parametrize("caller_active", [False, True], ids=["idle", "caller"])
    @pytest.mark.parametrize("cleanup", ["clean", "ordinary", "cancel"])
    def test_body_cancellation_identity_survives_driver_cleanup(self, caller_active: bool, cleanup: str) -> None:
        conn = _native_driver_connection(caller_active)
        primary = _PrivilegeProbeCancellation("Synthetic body cancellation")
        conn.body_failure = primary
        if cleanup != "clean":
            conn.failed_command = "ROLLBACK TO " if caller_active else "ROLLBACK"
            conn.command_failure = (
                RuntimeError("Synthetic cleanup error")
                if cleanup == "ordinary"
                else _PrivilegeProbeCancellation("Synthetic cleanup cancellation")
            )

        with pytest.raises(_PrivilegeProbeCancellation) as caught:
            PostgresCollector(connection=conn)._probe_write_privilege(conn)

        assert caught.value is primary
        assert conn.cursor_instance.close_calls == 1
        assert conn.manual == [_PRIVILEGE_SETTING, _PRIVILEGE_SAVEPOINT, _PRIVILEGE_CREATE]
        assert conn.commands[0] == ('SAVEPOINT "_pg3_1"' if caller_active else "BEGIN")
        assert any(command.startswith("ROLLBACK") for command in conn.commands)
        assert conn.autocommit is True

    @pytest.mark.parametrize("caller_active", [False, True], ids=["idle", "caller"])
    def test_restore_refusal_survives_later_driver_cancellation(self, caller_active: bool) -> None:
        conn = _native_driver_connection(caller_active)
        conn.body_failure = PermissionError("Synthetic create denial")
        conn.manual_faults[_PRIVILEGE_ROLLBACK] = RuntimeError("Synthetic restore error")
        conn.failed_command = "ROLLBACK TO " if caller_active else "ROLLBACK"
        conn.command_failure = _PrivilegeProbeCancellation("Synthetic cleanup cancellation")

        with pytest.raises(PostgresQueryError) as caught:
            PostgresCollector(connection=conn)._probe_write_privilege(conn)

        assert type(caught.value) is PostgresQueryError
        assert str(caught.value) == "Could not restore the Postgres privilege-probe savepoint."
        assert caught.value.__cause__ is None
        assert caught.value.__suppress_context__ is True
        assert conn.cursor_instance.close_calls == 1
        assert conn.manual == [_PRIVILEGE_SETTING, _PRIVILEGE_SAVEPOINT, _PRIVILEGE_CREATE, _PRIVILEGE_ROLLBACK]

    @pytest.mark.parametrize("caller_active", [False, True], ids=["idle", "caller"])
    @pytest.mark.parametrize("stage", ["entry", "exit"])
    @pytest.mark.parametrize("fault_kind", ["ordinary", "cancel"])
    def test_first_driver_failure_remains_visible(self, caller_active: bool, stage: str, fault_kind: str) -> None:
        conn = _native_driver_connection(caller_active)
        failure = (
            RuntimeError("Synthetic driver failure")
            if fault_kind == "ordinary"
            else _PrivilegeProbeCancellation("Synthetic driver cancellation")
        )
        conn.command_failure = failure
        conn.failed_command = (
            ("SAVEPOINT " if caller_active else "BEGIN")
            if stage == "entry"
            else ("RELEASE " if caller_active else "COMMIT")
        )

        with pytest.raises(type(failure)) as caught:
            PostgresCollector(connection=conn)._probe_write_privilege(conn)

        assert caught.value is failure
        assert conn.cursor_instance.close_calls == 1
        assert conn.autocommit is True
        assert conn.manual == (
            [_PRIVILEGE_SETTING]
            if stage == "entry"
            else [_PRIVILEGE_SETTING, _PRIVILEGE_SAVEPOINT, _PRIVILEGE_CREATE, _PRIVILEGE_ROLLBACK, _PRIVILEGE_RELEASE]
        )

    @pytest.mark.parametrize("stage", ["entry", "exit"])
    @pytest.mark.parametrize("fault_kind", ["ordinary", "cancel"])
    def test_ambient_handled_cancellation_is_not_probe_authority(self, stage: str, fault_kind: str) -> None:
        conn = _native_driver_connection(True)
        ambient = _PrivilegeProbeCancellation("Synthetic already-handled cancellation")
        failure = (
            RuntimeError("Synthetic current driver failure")
            if fault_kind == "ordinary"
            else _PrivilegeProbeCancellation("Synthetic current driver cancellation")
        )
        conn.command_failure = failure
        conn.failed_command = "SAVEPOINT " if stage == "entry" else "RELEASE "

        try:
            raise ambient
        except _PrivilegeProbeCancellation:
            with pytest.raises(type(failure)) as caught:
                PostgresCollector(connection=conn)._probe_write_privilege(conn)

        assert caught.value is failure
        assert caught.value is not ambient
        assert conn.cursor_instance.close_calls == 1

    @pytest.mark.parametrize("caller_active", [False, True], ids=["idle", "caller"])
    @pytest.mark.parametrize("denied", [False, True])
    def test_native_success_and_expected_denial_preserve_caller(self, caller_active: bool, denied: bool) -> None:
        conn = _native_driver_connection(caller_active)
        if denied:
            conn.body_failure = PermissionError("Synthetic create denial")

        result = PostgresCollector(connection=conn)._probe_write_privilege(conn)

        assert result == (True, not denied)
        assert conn.commands == (['SAVEPOINT "_pg3_1"', 'RELEASE "_pg3_1"'] if caller_active else ["BEGIN", "COMMIT"])
        assert conn.pgconn.transaction_status == (
            conn.driver.pq.TransactionStatus.INTRANS if caller_active else conn.driver.pq.TransactionStatus.IDLE
        )
        assert conn._num_transactions == 0
        assert conn.autocommit is True
        assert not conn.manual_savepoint
        assert conn.cursor_instance.close_calls == 1
        assert conn.manual == [
            _PRIVILEGE_SETTING,
            _PRIVILEGE_SAVEPOINT,
            _PRIVILEGE_CREATE,
            _PRIVILEGE_ROLLBACK,
            _PRIVILEGE_RELEASE,
        ]
