"""Unit tests for the Snowflake evidence collector (v0.7.8 P0.2).

Mocks the snowflake-connector-python connection at the cursor level —
no real Snowflake account required. Integration tests against a real
Snowflake account would require provisioned credentials and live
elsewhere (likely a manual playbook in `docs/cloud-dw-collectors.md`
since the collector is read-only and the cost of a free-tier
Snowflake account for CI is prohibitive).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from evidentia_collectors.snowflake import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    SnowflakeCollector,
    SnowflakeCollectorError,
)
from evidentia_core.audit import CollectionContext, CollectionManifest
from evidentia_core.models.common import Severity
from evidentia_core.models.finding import FindingStatus

# ── Mock cursor / connection infrastructure ────────────────────────


class _MockCursor:
    """Minimal snowflake-cursor stand-in. Routes by substring-match
    against the last query string seen via execute(); fetchone() /
    fetchall() return pre-canned rows. Supports the context-manager
    protocol (`with conn.cursor() as cur:`) used by the policy
    inventory loop after F-V08-CR-H2."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self._last_query = ""
        self.executed: list[tuple[str, Any]] = []

    def __enter__(self) -> _MockCursor:
        return self

    def __exit__(self, *exc: Any) -> None:
        # Mirror snowflake-connector-python semantics — exiting the
        # context closes the cursor; closing twice is a no-op.
        self.close()

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
    """Minimal snowflake-connection stand-in."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.closed = False

    def cursor(self) -> _MockCursor:
        return _MockCursor(self._responses)

    def close(self) -> None:
        self.closed = True


def _baseline_responses() -> dict[str, Any]:
    """Default responses representing a healthy Snowflake account."""
    now = datetime.now(UTC)
    return {
        # test_connection probe
        "CURRENT_ACCOUNT()": (
            "ACME-PROD",
            "EVIDENTIA_AUDIT_RO",
            "EVIDENTIA_AUDIT_RO",
            "8.0.0",
            "EVIDENTIA_AUDIT_WH",
        ),
        # LOGIN_HISTORY — a successful + a failed login
        "LOGIN_HISTORY": [
            (
                "ALICE",
                now - timedelta(days=1),
                "10.0.0.1",
                "PYTHON_DRIVER",
                "3.10",
                "PASSWORD",
                "DUO",
                True,
                None,
                None,
            ),
            (
                "BOB",
                now - timedelta(days=2),
                "192.0.2.1",
                "BROWSER",
                "Chrome",
                "PASSWORD",
                None,
                False,
                "390100",
                "Incorrect username or password.",
            ),
        ],
        # USERS
        "FROM SNOWFLAKE.ACCOUNT_USAGE.USERS": [
            (
                "ALICE",
                "alice",
                "Alice Lastname",
                "alice@example.com",
                False,  # disabled
                True,  # has_mfa
                False,  # has_password (key-pair only)
                True,  # has_rsa
                "ANALYST_ROLE",
                now - timedelta(days=1),  # last_success_login
                now - timedelta(days=180),
            ),
            (
                "BOB",
                "bob",
                "Bob Lastname",
                "bob@example.com",
                False,  # disabled
                False,  # has_mfa  ← MFA gap
                True,  # has_password
                False,  # has_rsa
                "ANALYST_ROLE",
                now - timedelta(days=2),
                now - timedelta(days=10),
            ),
            (
                "CAROL",
                "carol",
                "Carol Lastname",
                "carol@example.com",
                True,  # disabled  ← disabled-account finding
                False,
                True,
                False,
                "PUBLIC",
                None,
                now - timedelta(days=400),
            ),
            (
                "DAVE",
                "dave",
                "Dave Lastname",
                "dave@example.com",
                False,
                True,
                False,  # service user — no password
                True,  # key-pair only
                "SERVICE_ROLE",
                None,  # never logged in  ← never-logged-in finding
                None,
            ),
        ],
        # GRANTS_TO_USERS — Alice has analyst, Bob has analyst,
        # Eve has ACCOUNTADMIN (privileged grant)
        "GRANTS_TO_USERS": [
            ("ALICE", "ANALYST_ROLE", "USER", "SECURITYADMIN", now),
            ("BOB", "ANALYST_ROLE", "USER", "SECURITYADMIN", now),
            ("EVE", "ACCOUNTADMIN", "USER", "ACCOUNTADMIN", now),
        ],
        # SHOW NETWORK POLICIES
        "SHOW NETWORK POLICIES": [
            (now, "PROD_ALLOWLIST", "Production allowlist", 5, 0, "SECURITYADMIN"),
        ],
        # SHOW PARAMETERS LIKE 'NETWORK_POLICY'
        "SHOW PARAMETERS LIKE 'NETWORK_POLICY'": [
            (
                "NETWORK_POLICY",
                "PROD_ALLOWLIST",
                "",
                "ACCOUNT",
                "Network policy for the account",
                "STRING",
            ),
        ],
        # SHOW DATABASES
        "SHOW DATABASES": [
            (now, "ANALYTICS_DB", "ROLE", "SECURITYADMIN"),
            (now, "RAW_DB", "ROLE", "SECURITYADMIN"),
        ],
        # MASKING POLICIES per database
        "MASKING_POLICIES": [
            ("PII_MASK", "PUBLIC", "SECURITYADMIN"),
        ],
        # ROW_ACCESS_POLICIES per database
        "ROW_ACCESS_POLICIES": [
            ("REGION_ROW_FILTER", "PUBLIC", "SECURITYADMIN"),
        ],
    }


def _make_collector(
    responses: dict[str, Any] | None = None,
    **kwargs: Any,
) -> SnowflakeCollector:
    """Build a SnowflakeCollector with a mocked connection."""
    collector = SnowflakeCollector(
        account=kwargs.pop("account", "acme-prod"),
        user=kwargs.pop("user", "EVIDENTIA_AUDIT_RO"),
        password=kwargs.pop("password", "FAKE-PWD-FOR-TESTING-ONLY"),
        **kwargs,
    )
    # Inject the mock connection directly, bypassing _ensure_connected.
    collector._connection = _MockConnection(
        responses or _baseline_responses()
    )
    return collector


# ── TestConstruction ───────────────────────────────────────────────


class TestConstruction:
    def test_construction_smoke(self) -> None:
        c = SnowflakeCollector(
            account="acme-prod",
            user="EVIDENTIA_AUDIT_RO",
            password="FAKE-PWD",
        )
        assert c._account == "acme-prod"
        assert c._user == "EVIDENTIA_AUDIT_RO"
        assert c._connection is None  # lazy-connect

    def test_default_login_window_is_90_days(self) -> None:
        c = SnowflakeCollector(
            account="acme-prod",
            user="u",
            password="p",
        )
        assert c._login_history_window_days == 90

    def test_custom_login_window(self) -> None:
        c = SnowflakeCollector(
            account="acme-prod",
            user="u",
            password="p",
            login_history_window_days=30,
        )
        assert c._login_history_window_days == 30

    def test_close_releases_connection(self) -> None:
        c = _make_collector()
        assert c._connection is not None
        c.close()
        assert c._connection is None

    def test_context_manager_calls_close(self) -> None:
        c = _make_collector()
        connection_before = c._connection
        assert connection_before is not None
        with c:
            assert c._connection is connection_before
        assert c._connection is None


# ── TestPublicSurface ──────────────────────────────────────────────


class TestPublicSurface:
    def test_collector_id(self) -> None:
        assert COLLECTOR_ID == "snowflake-scan"

    def test_blind_spots_minimum_count(self) -> None:
        # Confirm we explicitly disclose the documented latency,
        # private-preview, replication, INFORMATION_SCHEMA scope,
        # password-deprecation, encryption-platform-managed, and
        # LOGIN_HISTORY-edition-window blind spots.
        assert len(BLIND_SPOTS) >= 7

    def test_blind_spots_have_required_fields(self) -> None:
        for bs in BLIND_SPOTS:
            assert "id" in bs
            assert "title" in bs
            assert "description" in bs
            assert bs["id"].startswith("EVIDENTIA-SNOWFLAKE-")

    def test_module_exports_typed_exceptions(self) -> None:
        # Re-export from public surface — ensures consumers can catch
        # the typed exceptions without importing the internal module.
        from evidentia_collectors.snowflake import (
            SnowflakeAuthError,
            SnowflakeCollectorError,
            SnowflakePermissionError,
            SnowflakeQueryError,
        )

        assert issubclass(SnowflakeAuthError, SnowflakeCollectorError)
        assert issubclass(
            SnowflakePermissionError, SnowflakeCollectorError
        )
        assert issubclass(SnowflakeQueryError, SnowflakeCollectorError)


# ── TestImportError ────────────────────────────────────────────────


class TestImportError:
    def test_lazy_import_error_message(self, monkeypatch: Any) -> None:
        """Without snowflake-connector-python installed, attempting
        connect surfaces a typed error pointing at the [snowflake]
        extra. We simulate the missing module via sys.modules pin."""
        import sys

        # Save originals to restore.
        saved_snowflake = sys.modules.get("snowflake")
        saved_connector = sys.modules.get("snowflake.connector")
        sys.modules["snowflake"] = None  # type: ignore[assignment]
        sys.modules["snowflake.connector"] = None  # type: ignore[assignment]
        try:
            c = SnowflakeCollector(
                account="acme-prod",
                user="u",
                password="p",
            )
            with pytest.raises(SnowflakeCollectorError) as exc_info:
                c._ensure_connected()
            assert "[snowflake]" in str(exc_info.value)
        finally:
            if saved_snowflake is None:
                sys.modules.pop("snowflake", None)
            else:
                sys.modules["snowflake"] = saved_snowflake
            if saved_connector is None:
                sys.modules.pop("snowflake.connector", None)
            else:
                sys.modules["snowflake.connector"] = saved_connector


# ── TestLoginHistory ───────────────────────────────────────────────


class TestLoginHistory:
    def test_login_history_emits_inventory_per_user(self) -> None:
        c = _make_collector()
        c.test_connection()
        context = c._build_context("test-run")
        findings, _coverage = c._login_history_findings(context)

        # Two users seen in baseline: ALICE (success) + BOB (fail)
        inventory = [
            f
            for f in findings
            if f.source_finding_id is not None
            and f.source_finding_id.startswith("login-history-inventory:")
        ]
        assert len(inventory) == 2
        users = sorted(
            f.resource_id for f in inventory if f.resource_id
        )
        assert users == ["ALICE", "BOB"]

    def test_login_history_inventory_is_resolved(self) -> None:
        c = _make_collector()
        c.test_connection()
        context = c._build_context("test-run")
        findings, _ = c._login_history_findings(context)
        for f in findings:
            if (
                f.source_finding_id is not None
                and f.source_finding_id.startswith(
                    "login-history-inventory:"
                )
            ):
                assert f.status == FindingStatus.RESOLVED
                assert f.severity == Severity.INFORMATIONAL

    def test_failed_login_emits_active_low_finding(self) -> None:
        c = _make_collector()
        c.test_connection()
        context = c._build_context("test-run")
        findings, _ = c._login_history_findings(context)
        failed = [
            f
            for f in findings
            if f.source_finding_id is not None
            and f.source_finding_id.startswith("login-failed:")
        ]
        assert len(failed) == 1
        assert failed[0].status == FindingStatus.ACTIVE
        assert failed[0].severity == Severity.LOW
        assert failed[0].resource_id == "BOB"
        assert any(
            "AC-7" in m.control_id
            for m in failed[0].control_mappings
        )

    def test_login_history_coverage_count(self) -> None:
        c = _make_collector()
        c.test_connection()
        context = c._build_context("test-run")
        _findings, coverage = c._login_history_findings(context)
        # Two rows in baseline LOGIN_HISTORY
        assert coverage.scanned == 2
        assert coverage.matched_filter == 2
        # 2 users × 1 inventory + 1 failed-login = 3 findings
        assert coverage.collected == 3


# ── TestUserInventory ──────────────────────────────────────────────


class TestUserInventory:
    def test_user_inventory_emits_per_user(self) -> None:
        c = _make_collector()
        c.test_connection()
        context = c._build_context("test-run")
        findings, _ = c._user_inventory_findings(context)
        inventory = [
            f
            for f in findings
            if f.source_finding_id is not None
            and f.source_finding_id.startswith("user-inventory:")
        ]
        # 4 users in baseline
        assert len(inventory) == 4

    def test_mfa_disabled_finding_for_every_password_user_without_mfa(
        self,
    ) -> None:
        c = _make_collector()
        c.test_connection()
        context = c._build_context("test-run")
        findings, _ = c._user_inventory_findings(context)
        mfa_gap = [
            f
            for f in findings
            if f.source_finding_id is not None
            and f.source_finding_id.startswith("mfa-disabled:")
        ]
        # Bob has password + no MFA → MFA-gap finding.
        # Carol has password + no MFA + disabled → ALSO an MFA-gap
        #   finding (a disabled user can be re-enabled; the password+
        #   no-MFA combination remains a gap until the password is
        #   actively revoked, not just the user disabled).
        # Dave is key-pair only (no password) → no MFA finding.
        # Alice has MFA → no finding.
        # So we expect 2 MFA gaps: BOB + CAROL.
        gap_users = sorted(
            f.resource_id for f in mfa_gap if f.resource_id
        )
        assert gap_users == ["BOB", "CAROL"]
        for f in mfa_gap:
            assert f.severity == Severity.MEDIUM
            assert f.status == FindingStatus.ACTIVE
            assert any(
                m.control_id == "IA-2(1)"
                for m in f.control_mappings
            )

    def test_disabled_user_emits_finding(self) -> None:
        c = _make_collector()
        c.test_connection()
        context = c._build_context("test-run")
        findings, _ = c._user_inventory_findings(context)
        disabled = [
            f
            for f in findings
            if f.source_finding_id is not None
            and f.source_finding_id.startswith("user-disabled:")
        ]
        assert len(disabled) == 1
        assert disabled[0].resource_id == "CAROL"

    def test_never_logged_in_finding_only_for_active_users(
        self,
    ) -> None:
        c = _make_collector()
        c.test_connection()
        context = c._build_context("test-run")
        findings, _ = c._user_inventory_findings(context)
        never_loggedin = [
            f
            for f in findings
            if f.source_finding_id is not None
            and f.source_finding_id.startswith("user-never-logged-in:")
        ]
        # Dave never logged in but is enabled → one finding.
        # Carol never logged in but is disabled → suppressed.
        assert len(never_loggedin) == 1
        assert never_loggedin[0].resource_id == "DAVE"


# ── TestGrantInventory ─────────────────────────────────────────────


class TestGrantInventory:
    def test_grant_inventory_per_user(self) -> None:
        c = _make_collector()
        c.test_connection()
        context = c._build_context("test-run")
        findings, _ = c._grant_inventory_findings(context)
        inventory = [
            f
            for f in findings
            if f.source_finding_id is not None
            and f.source_finding_id.startswith("grant-inventory:")
        ]
        # 3 grantees in baseline (ALICE/BOB/EVE)
        assert len(inventory) == 3

    def test_privileged_grant_emits_active_finding(self) -> None:
        c = _make_collector()
        c.test_connection()
        context = c._build_context("test-run")
        findings, _ = c._grant_inventory_findings(context)
        privileged = [
            f
            for f in findings
            if f.source_finding_id is not None
            and f.source_finding_id.startswith("privileged-grant:")
        ]
        # Eve holds ACCOUNTADMIN; one privileged-grant finding
        assert len(privileged) == 1
        assert "EVE" in (privileged[0].resource_id or "")
        assert "ACCOUNTADMIN" in (privileged[0].resource_id or "")
        assert privileged[0].severity == Severity.MEDIUM
        assert privileged[0].status == FindingStatus.ACTIVE


# ── TestNetworkPolicies ────────────────────────────────────────────


class TestNetworkPolicies:
    def test_network_policy_inventory_emitted(self) -> None:
        c = _make_collector()
        c.test_connection()
        context = c._build_context("test-run")
        findings, _ = c._network_policy_findings(context)
        inv = [
            f
            for f in findings
            if f.source_finding_id is not None
            and f.source_finding_id.startswith(
                "network-policy-inventory:"
            )
        ]
        assert len(inv) == 1
        assert inv[0].resource_id == "PROD_ALLOWLIST"

    def test_no_account_policy_emits_active_finding(self) -> None:
        # Override the SHOW PARAMETERS response so the account-level
        # NETWORK_POLICY value is empty.
        responses = _baseline_responses()
        responses["SHOW PARAMETERS LIKE 'NETWORK_POLICY'"] = [
            (
                "NETWORK_POLICY",
                "",
                "",
                "ACCOUNT",
                "Network policy for the account",
                "STRING",
            ),
        ]
        c = _make_collector(responses=responses)
        c.test_connection()
        context = c._build_context("test-run")
        findings, _ = c._network_policy_findings(context)
        gap = [
            f
            for f in findings
            if f.source_finding_id == "network-policy-none-assigned"
        ]
        assert len(gap) == 1
        assert gap[0].severity == Severity.MEDIUM
        assert gap[0].status == FindingStatus.ACTIVE


# ── TestPolicyInventory ────────────────────────────────────────────


class TestPolicyInventory:
    def test_masking_and_row_access_policies_inventoried(self) -> None:
        c = _make_collector()
        c.test_connection()
        context = c._build_context("test-run")
        findings, _ = c._policy_inventory_findings(context)
        masking = [
            f for f in findings if f.resource_type == "snowflake-masking-policy"
        ]
        row_access = [
            f
            for f in findings
            if f.resource_type == "snowflake-row-access-policy"
        ]
        # 2 databases × 1 masking policy each = 2 findings
        assert len(masking) == 2
        # 2 databases × 1 row-access policy each = 2 findings
        assert len(row_access) == 2


# ── TestKeyRotation ────────────────────────────────────────────────


class TestKeyRotation:
    def test_key_rotation_emits_one_resolved_finding(self) -> None:
        c = _make_collector()
        c.test_connection()
        context = c._build_context("test-run")
        findings, coverage = c._key_rotation_findings(context)
        assert len(findings) == 1
        assert findings[0].status == FindingStatus.RESOLVED
        assert findings[0].severity == Severity.INFORMATIONAL
        assert coverage.collected == 1


# ── TestManifest ───────────────────────────────────────────────────


class TestManifest:
    def test_collect_v2_returns_findings_and_manifest(self) -> None:
        c = _make_collector()
        findings, manifest = c.collect_v2()
        assert isinstance(findings, list)
        assert all(
            isinstance(f.collection_context, CollectionContext)
            for f in findings
        )
        assert isinstance(manifest, CollectionManifest)
        assert manifest.collector_id == COLLECTOR_ID
        assert manifest.is_complete is True
        assert manifest.total_findings == len(findings)
        # Manifest carries source_system_ids populated post-test_connection.
        assert any(
            sid.startswith("snowflake:") for sid in manifest.source_system_ids
        )

    def test_collect_v2_coverage_includes_all_categories(self) -> None:
        c = _make_collector()
        _findings, manifest = c.collect_v2()
        types = {cov.resource_type for cov in manifest.coverage_counts}
        # 6 sub-checks scaffolded
        assert "snowflake-login-history-row" in types
        assert "snowflake-user" in types
        assert "snowflake-grant" in types
        assert "snowflake-network-policy" in types
        assert "snowflake-policy" in types
        assert "snowflake-encryption-key" in types

    def test_findings_carry_source_system_snowflake(self) -> None:
        c = _make_collector()
        findings, _ = c.collect_v2()
        for f in findings:
            assert f.source_system == "snowflake"

    def test_collect_returns_findings_only_legacy_surface(self) -> None:
        c = _make_collector()
        findings = c.collect()
        assert isinstance(findings, list)
        assert len(findings) > 0


# ── TestErrorPath ──────────────────────────────────────────────────


class TestErrorPath:
    def test_query_error_marks_manifest_incomplete(self) -> None:
        # Empty responses → fetchall returns [] for every needle.
        # The collect_v2 path catches per-sub-check errors and marks
        # the manifest is_complete=False, so we use a sub-check that
        # raises directly.
        c = _make_collector(responses={})
        # Force test_connection to fail by emptying responses; the
        # connector will return None from fetchone, but build_context
        # tolerates that. Instead, swap the cursor's execute to raise.

        class _RaisingCursor(_MockCursor):
            def execute(
                self, query: str, params: Any = None
            ) -> None:
                if "LOGIN_HISTORY" in query:
                    raise RuntimeError("simulated query failure")
                super().execute(query, params)

        def _new_cursor() -> _MockCursor:
            return _RaisingCursor({})

        c._connection.cursor = _new_cursor  # type: ignore[union-attr]
        _findings, manifest = c.collect_v2()
        assert manifest.is_complete is False
        assert any(
            "login_history" in err for err in manifest.errors
        )
