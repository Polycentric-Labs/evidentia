"""Oracle Database evidence collector — main module (v0.7.7 P0.5).

Read-only collector against Oracle Database 19c+ via the modern
``oracledb`` thin driver (no Oracle Client install needed).
Mirrors the postgres / mysql / mssql shape: typed exceptions,
CollectionContext threaded through findings, CollectionManifest,
ECS audit logging, read-only principal probe, BLIND_SPOTS list.

See ``evidentia_collectors.sql.oracle.__init__`` for the public-
surface walkthrough + credential handling.
"""

from __future__ import annotations

import contextlib
import urllib.parse
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
    Severity,
    current_version,
    utc_now,
)
from evidentia_core.models.finding import FindingStatus, SecurityFinding

from evidentia_collectors.sql.oracle.mapping import (
    AUDIT_LOG_MAPPINGS,
    CONNECTION_LIMIT_MAPPINGS,
    CRYPTO_CONFIG_MAPPINGS,
    ENCRYPTION_AT_REST_MAPPINGS,
    PASSWORD_POLICY_MAPPINGS,
    PRIVILEGE_GRANT_MAPPINGS,
    USER_ROLE_INVENTORY_MAPPINGS,
    WRITE_PRIV_DETECTED_MAPPINGS,
)

if TYPE_CHECKING:
    import oracledb  # noqa: F401


_log = get_logger("evidentia.collectors.sql.oracle")

COLLECTOR_ID = "sql-oracle-scan"


# ── Typed exception hierarchy ──────────────────────────────────────


class OracleCollectorError(Exception):
    """Base class for all Oracle collector failures."""


class OracleConnectionError(OracleCollectorError):
    """Connection / authentication / TLS handshake failure."""


class OracleQueryError(OracleCollectorError):
    """A specific SQL query failed (permission denied, missing
    feature, separately-licensed component, etc.). The collector
    continues with remaining queries; the error is recorded in
    the manifest."""


# ── BLIND_SPOTS list ────────────────────────────────────────────────

BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "EVIDENTIA-ORACLE-LICENSE-FEATURE",
        "title": (
            "Several Oracle features require separately-licensed options"
        ),
        "description": (
            "Transparent Data Encryption (TDE), Database Vault, Audit "
            "Vault, Data Masking, and Real Application Security are "
            "separately-licensed components of Oracle Database "
            "Enterprise Edition. The collector reports their status "
            "where the wallet / DV-status views are accessible. "
            "Operators on Standard Edition or Database Free should "
            "treat negative results as INDETERMINATE rather than "
            "absence of encryption — out-of-band TDE evidence may "
            "exist via filesystem-level encryption."
        ),
    },
    {
        "id": "EVIDENTIA-ORACLE-AUDIT-MIXED-MODE",
        "title": (
            "Unified vs Traditional Audit mode coexistence"
        ),
        "description": (
            "Oracle 12c introduced Unified Auditing as the modern "
            "audit subsystem; older deployments may run in mixed "
            "mode (both Unified and Traditional active) or pure "
            "Traditional mode. The collector queries "
            "AUDIT_UNIFIED_ENABLED_POLICIES first, falling back to "
            "audit_trail parameter + DBA_AUDIT_TRAIL when Unified "
            "Audit is not enabled. Mixed-mode deployments may need "
            "out-of-band review to reconcile both audit trails."
        ),
    },
    {
        "id": "EVIDENTIA-ORACLE-CDB-PDB-CONTEXT",
        "title": (
            "Multitenant Container Database (CDB) vs Pluggable "
            "Database (PDB) context"
        ),
        "description": (
            "Oracle Multitenant deployments have separate audit + "
            "user inventory views per PDB. The collector reports "
            "evidence from the connected container (root CDB or a "
            "single PDB depending on connection target). Multi-PDB "
            "evidence requires per-PDB collection runs and "
            "out-of-band aggregation."
        ),
    },
    {
        "id": "EVIDENTIA-ORACLE-NETWORK-ENCRYPTION-CLIENT",
        "title": (
            "Native Network Encryption is configured per-server"
        ),
        "description": (
            "sqlnet.encryption_server / encryption_client parameters "
            "are set in sqlnet.ora at OS level — not always "
            "queryable via V$PARAMETER. The collector best-effort "
            "queries V$PARAMETER but operators with non-default "
            "sqlnet.ora placement should provide out-of-band "
            "evidence of in-transit encryption posture."
        ),
    },
]


# ── Main collector class ────────────────────────────────────────────


class OracleCollector:
    """Read-only Oracle Database evidence collector."""

    def __init__(
        self,
        *,
        connection_uri: str | None = None,
        password: str | None = None,
        connection: Any | None = None,
    ) -> None:
        if not connection_uri and connection is None:
            raise OracleCollectorError(
                "OracleCollector requires either connection_uri= or "
                "connection= (an injected oracledb.Connection for testing)."
            )
        if connection_uri and "://" in connection_uri:
            authority = connection_uri.split("://", 1)[1].split("/", 1)[0]
            if "@" in authority:
                userinfo = authority.split("@", 1)[0]
                if ":" in userinfo:
                    raise OracleCollectorError(
                        "connection_uri must NOT embed a password. "
                        "Pass the password via the password= kwarg, "
                        "sourced from EVIDENTIA_ORACLE_PASSWORD env var."
                    )
        self._connection_uri = connection_uri
        self._password = password
        self._connection = connection
        self._owns_connection = connection is None
        self._cached_user: str | None = None
        self._cached_db: str | None = None
        self._cached_version: str | None = None

    # ── Lifecycle ───────────────────────────────────────────────────

    def __enter__(self) -> OracleCollector:
        self._ensure_connected()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_connection and self._connection is not None:
            with contextlib.suppress(Exception):
                self._connection.close()
            self._connection = None

    def _parse_uri(self, uri: str) -> dict[str, Any]:
        """Parse oracle://user@host:1521/service into oracledb kwargs.

        oracledb accepts (user, password, dsn) where dsn is
        ``host:port/service_name``. The password is supplied
        separately via the password= kwarg per the secret protocol.
        """
        parsed = urllib.parse.urlparse(uri)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 1521
        user = parsed.username or ""
        service = parsed.path.lstrip("/") if parsed.path else ""
        return {
            "user": user,
            "dsn": f"{host}:{port}/{service}" if service else f"{host}:{port}",
        }

    def _ensure_connected(self) -> Any:
        if self._connection is not None:
            return self._connection
        try:
            import oracledb
        except ImportError as e:
            raise OracleCollectorError(
                "oracledb is not installed. Install via the [sql-oracle] "
                "extra: pip install \"evidentia-collectors[sql-oracle]\""
            ) from e

        if not self._connection_uri:
            raise OracleCollectorError(
                "_ensure_connected called without a connection_uri."
            )
        kwargs = self._parse_uri(self._connection_uri)
        if self._password is not None:
            kwargs["password"] = self._password
        try:
            self._connection = oracledb.connect(**kwargs)
        except Exception as e:
            raise OracleConnectionError(
                f"Could not connect to Oracle (driver: {type(e).__name__})"
            ) from e
        return self._connection

    # ── Context + provenance ────────────────────────────────────────

    def _build_context(self, run_id: str) -> CollectionContext:
        user = self._cached_user or "unknown"
        db = self._cached_db or "unknown"
        return CollectionContext(
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            run_id=run_id,
            credential_identity=f"oracle-user:{user}",
            source_system_id=f"oracle:{user}@{db}",
            filter_applied={"user": user, "database": db},
        )

    def test_connection(self) -> dict[str, Any]:
        conn = self._ensure_connected()
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT "
                "SYS_CONTEXT('USERENV','CURRENT_USER'), "
                "SYS_CONTEXT('USERENV','DB_NAME'), "
                "(SELECT BANNER FROM V$VERSION WHERE ROWNUM = 1) "
                "FROM DUAL"
            )
            row = cur.fetchone()
            self._cached_user = str(row[0]) if row else None
            self._cached_db = str(row[1] or "") if row else None
            self._cached_version = str(row[2]) if row else None
        finally:
            cur.close()

        is_dba, is_sysdba, any_table_grants = (
            self._probe_write_privilege(conn)
        )

        return {
            "user": self._cached_user,
            "database": self._cached_db,
            "version": self._cached_version,
            "is_dba": is_dba,
            "is_sysdba": is_sysdba,
            "any_table_grants": any_table_grants,
        }

    def _probe_write_privilege(
        self, conn: Any
    ) -> tuple[bool, bool, list[str]]:
        """Check DBA role membership + SYSDBA + ANY-table grants.

        Returns (is_dba, is_sysdba, list_of_any_table_privs).
        Any True / non-empty result is a least-privilege violation.
        """
        cur = conn.cursor()
        try:
            try:
                cur.execute(
                    "SELECT COUNT(*) FROM session_roles WHERE role = 'DBA'"
                )
                row = cur.fetchone()
                is_dba = bool((row[0] or 0) > 0) if row else False
            except Exception:
                is_dba = False

            try:
                cur.execute(
                    "SELECT COUNT(*) FROM session_privs "
                    "WHERE privilege = 'SYSDBA'"
                )
                row = cur.fetchone()
                is_sysdba = bool((row[0] or 0) > 0) if row else False
            except Exception:
                is_sysdba = False

            any_table_grants: list[str] = []
            try:
                cur.execute(
                    "SELECT privilege FROM session_privs "
                    "WHERE privilege IN ('INSERT ANY TABLE', "
                    "'UPDATE ANY TABLE', 'DELETE ANY TABLE', "
                    "'CREATE ANY TABLE', 'DROP ANY TABLE')"
                )
                any_table_grants = [str(r[0]) for r in cur.fetchall()]
            except Exception:
                any_table_grants = []

            return is_dba, is_sysdba, any_table_grants
        finally:
            cur.close()

    # ── High-level orchestration ────────────────────────────────────

    def collect(self, *, dry_run: bool = False) -> list[SecurityFinding]:
        if dry_run:
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message="Oracle dry-run — no DB calls made",
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
            probe = self.test_connection()
        except OracleCollectorError:
            raise
        except Exception as e:
            raise OracleConnectionError(
                f"Could not establish + probe Oracle connection: {e}"
            ) from e

        context = self._build_context(run_id)
        errors: list[str] = []
        findings: list[SecurityFinding] = []

        with _log.scope(
            trace_id=run_id,
            user={"id": context.credential_identity},
            evidentia={
                "run_id": run_id,
                "collector": {
                    "id": COLLECTOR_ID,
                    "version": current_version(),
                },
                "database": self._cached_db,
            },
        ):
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message=(
                    f"Oracle collection starting for "
                    f"{self._cached_user}@{self._cached_db}"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.START],
            )

            if (
                probe["is_dba"]
                or probe["is_sysdba"]
                or probe["any_table_grants"]
            ):
                findings.append(
                    self._write_priv_detected_finding(probe, context)
                )

            conn = self._connection
            assert conn is not None
            for sub_check in (
                self._user_role_inventory_findings,
                self._privilege_grant_findings,
                self._password_policy_findings,
                self._audit_log_findings,
                self._tde_encryption_findings,
                self._network_encryption_findings,
                self._connection_limit_findings,
            ):
                try:
                    findings.extend(sub_check(conn, context))
                except OracleQueryError as e:
                    errors.append(str(e))
                    _log.warning(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=f"Sub-check {sub_check.__name__} failed: {e}",
                        error={"type": "OracleQueryError", "message": str(e)},
                    )
                except Exception as e:
                    errors.append(
                        f"{sub_check.__name__}: unexpected error: {e}"
                    )
                    _log.error(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=(
                            f"Sub-check {sub_check.__name__} unexpected error"
                        ),
                        error={"type": type(e).__name__, "message": str(e)},
                    )

            _log.info(
                action=EventAction.COLLECT_COMPLETED,
                outcome=(
                    EventOutcome.SUCCESS
                    if not errors
                    else EventOutcome.FAILURE
                ),
                message=(
                    f"Oracle collection completed: {len(findings)} findings"
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
                f"oracle:{self._cached_user}@{self._cached_db}"
            ],
            filters_applied={
                "user": self._cached_user or "unknown",
                "database": self._cached_db or "unknown",
            },
            coverage_counts=[
                CoverageCount(
                    resource_type="oracle-database",
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

    def _write_priv_detected_finding(
        self,
        probe: dict[str, Any],
        context: CollectionContext,
    ) -> SecurityFinding:
        flags: list[str] = []
        if probe["is_dba"]:
            flags.append("DBA role")
        if probe["is_sysdba"]:
            flags.append("SYSDBA privilege")
        if probe["any_table_grants"]:
            flags.append(
                "ANY-table grants: " + ", ".join(probe["any_table_grants"])
            )
        return SecurityFinding(
            title=(
                f"Oracle principal {self._cached_user!r} has write "
                "privilege"
            ),
            description=(
                f"Principal ({self._cached_user}) has: "
                + "; ".join(flags)
                + ". Production deployments should grant the collector "
                "SELECT_CATALOG_ROLE + CREATE SESSION only — no DBA "
                "role, no SYSDBA, no ANY-table grants. Write privilege "
                "violates AC-6 least-privilege."
            ),
            severity=(
                Severity.HIGH
                if probe["is_dba"] or probe["is_sysdba"]
                else Severity.MEDIUM
            ),
            status=FindingStatus.ACTIVE,
            source_system="oracle",
            source_finding_id=(
                f"EVIDENTIA-WRITE-PRIV-DETECTED:{self._cached_user}@"
                f"{self._cached_db}"
            ),
            resource_type="Oracle::Principal",
            resource_id=str(self._cached_user or "unknown"),
            control_ids=[m.control_id for m in WRITE_PRIV_DETECTED_MAPPINGS],
            collection_context=context,
            raw_data={
                "is_dba": probe["is_dba"],
                "is_sysdba": probe["is_sysdba"],
                "any_table_grants": probe["any_table_grants"],
            },
        )

    def _user_role_inventory_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        cur = conn.cursor()
        try:
            try:
                cur.execute(
                    "SELECT username, account_status, profile, created "
                    "FROM dba_users ORDER BY username"
                )
                rows = list(cur.fetchall())
            except Exception as e:
                raise OracleQueryError(
                    f"Could not enumerate dba_users: {e}"
                ) from e

            open_users = [r[0] for r in rows if str(r[1] or "") == "OPEN"]
            locked_users = [
                r[0] for r in rows if "LOCKED" in str(r[1] or "")
            ]
            return [
                SecurityFinding(
                    title=(
                        f"Oracle user inventory: {len(rows)} accounts, "
                        f"{len(open_users)} OPEN, "
                        f"{len(locked_users)} LOCKED"
                    ),
                    description=(
                        f"dba_users has {len(rows)} accounts: "
                        f"{len(open_users)} OPEN (sample: "
                        f"{open_users[:5]}), {len(locked_users)} LOCKED. "
                        "AC-2 evidence — operators should review the "
                        "OPEN list against the inventory of intended "
                        "human + automation principals; default Oracle "
                        "schemas (SYS, SYSTEM, OUTLN, etc.) should be "
                        "LOCKED unless actively used."
                    ),
                    severity=Severity.INFORMATIONAL,
                    status=FindingStatus.ACTIVE,
                    source_system="oracle",
                    source_finding_id=f"user-inventory:{self._cached_db}",
                    resource_type="Oracle::Database",
                    resource_id=str(self._cached_db or "unknown"),
                    control_ids=[
                        m.control_id for m in USER_ROLE_INVENTORY_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={
                        "total_users": len(rows),
                        "open_count": len(open_users),
                        "locked_count": len(locked_users),
                    },
                )
            ]
        finally:
            cur.close()

    def _privilege_grant_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        cur = conn.cursor()
        try:
            try:
                cur.execute(
                    "SELECT grantee FROM dba_role_privs "
                    "WHERE granted_role = 'DBA' AND grantee NOT IN "
                    "('SYS', 'SYSTEM')"
                )
                rows = list(cur.fetchall())
            except Exception as e:
                raise OracleQueryError(
                    f"Could not enumerate dba_role_privs: {e}"
                ) from e

            non_system_dbas = [str(r[0]) for r in rows]
            return [
                SecurityFinding(
                    title=(
                        f"Oracle DBA role: {len(non_system_dbas)} "
                        "non-system grantees"
                    ),
                    description=(
                        f"{len(non_system_dbas)} principals (excluding "
                        f"SYS / SYSTEM) hold DBA: "
                        f"{non_system_dbas[:5]}"
                        + ("..." if len(non_system_dbas) > 5 else "")
                        + ". AC-6 Least Privilege evidence — DBA "
                        "grants unrestricted access; the count should "
                        "be minimal (1-2 break-glass + automation "
                        "service principals)."
                    ),
                    severity=(
                        Severity.HIGH
                        if len(non_system_dbas) > 5
                        else Severity.MEDIUM
                        if len(non_system_dbas) > 2
                        else Severity.INFORMATIONAL
                    ),
                    status=(
                        FindingStatus.ACTIVE
                        if len(non_system_dbas) > 2
                        else FindingStatus.RESOLVED
                    ),
                    source_system="oracle",
                    source_finding_id=f"dba-role-grants:{self._cached_db}",
                    resource_type="Oracle::Role",
                    resource_id="DBA",
                    control_ids=[
                        m.control_id for m in PRIVILEGE_GRANT_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={
                        "non_system_dba_grantees": non_system_dbas,
                    },
                )
            ]
        finally:
            cur.close()

    def _password_policy_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        cur = conn.cursor()
        try:
            try:
                cur.execute(
                    "SELECT profile, resource_name, limit "
                    "FROM dba_profiles "
                    "WHERE resource_type = 'PASSWORD' "
                    "AND profile = 'DEFAULT'"
                )
                rows = list(cur.fetchall())
            except Exception as e:
                raise OracleQueryError(
                    f"Could not query dba_profiles: {e}"
                ) from e

            settings: dict[str, str] = {
                str(r[1]): str(r[2]) for r in rows
            }
            life_time = settings.get("PASSWORD_LIFE_TIME", "")
            failed_attempts = settings.get("FAILED_LOGIN_ATTEMPTS", "")
            verify_func = settings.get("PASSWORD_VERIFY_FUNCTION", "NULL")

            life_unlimited = life_time.upper() == "UNLIMITED"
            verify_set = (
                verify_func.upper() not in {"NULL", "DEFAULT", ""}
            )
            ok = not life_unlimited and verify_set
            return [
                SecurityFinding(
                    title=(
                        f"Oracle DEFAULT profile: PASSWORD_LIFE_TIME="
                        f"{life_time}, FAILED_LOGIN_ATTEMPTS="
                        f"{failed_attempts}, "
                        f"PASSWORD_VERIFY_FUNCTION={verify_func}"
                    ),
                    description=(
                        "DEFAULT profile password resources: "
                        f"PASSWORD_LIFE_TIME={life_time}, "
                        f"FAILED_LOGIN_ATTEMPTS={failed_attempts}, "
                        f"PASSWORD_REUSE_TIME="
                        f"{settings.get('PASSWORD_REUSE_TIME', '?')}, "
                        f"PASSWORD_VERIFY_FUNCTION={verify_func}. "
                        "IA-5 Authenticator Management — UNLIMITED "
                        "lifetime + missing verify function indicate "
                        "weak password policy."
                    ),
                    severity=(
                        Severity.INFORMATIONAL if ok else Severity.MEDIUM
                    ),
                    status=(
                        FindingStatus.RESOLVED if ok else FindingStatus.ACTIVE
                    ),
                    source_system="oracle",
                    source_finding_id=(
                        f"password-policy:{self._cached_db}"
                    ),
                    resource_type="Oracle::Profile",
                    resource_id="DEFAULT",
                    control_ids=[
                        m.control_id for m in PASSWORD_POLICY_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data=settings,
                )
            ]
        finally:
            cur.close()

    def _audit_log_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        cur = conn.cursor()
        try:
            unified_count = 0
            try:
                cur.execute(
                    "SELECT COUNT(*) FROM "
                    "AUDIT_UNIFIED_ENABLED_POLICIES"
                )
                row = cur.fetchone()
                unified_count = int(row[0]) if row else 0
            except Exception:
                unified_count = 0

            audit_trail_param = ""
            try:
                cur.execute(
                    "SELECT value FROM v$parameter "
                    "WHERE name = 'audit_trail'"
                )
                row = cur.fetchone()
                audit_trail_param = str(row[0] or "NONE") if row else "NONE"
            except Exception as e:
                raise OracleQueryError(
                    f"Could not query v$parameter audit_trail: {e}"
                ) from e

            unified_active = unified_count > 0
            traditional_active = (
                audit_trail_param.upper() not in {"NONE", "FALSE"}
            )
            audit_active = unified_active or traditional_active
            return [
                SecurityFinding(
                    title=(
                        f"Oracle Audit: Unified={unified_count} "
                        f"policies, audit_trail={audit_trail_param}"
                    ),
                    description=(
                        f"AUDIT_UNIFIED_ENABLED_POLICIES count = "
                        f"{unified_count}; v$parameter.audit_trail = "
                        f"{audit_trail_param}. AU-2 Event Logging — "
                        "production deployments should enable Unified "
                        "Audit policies (12c+) or set audit_trail to "
                        "DB or OS. Mixed-mode deployments require "
                        "out-of-band reconciliation."
                    ),
                    severity=(
                        Severity.INFORMATIONAL
                        if audit_active
                        else Severity.HIGH
                    ),
                    status=(
                        FindingStatus.RESOLVED
                        if audit_active
                        else FindingStatus.ACTIVE
                    ),
                    source_system="oracle",
                    source_finding_id=f"audit-config:{self._cached_db}",
                    resource_type="Oracle::Database",
                    resource_id=str(self._cached_db or "unknown"),
                    control_ids=[
                        m.control_id for m in AUDIT_LOG_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={
                        "unified_policy_count": unified_count,
                        "audit_trail": audit_trail_param,
                    },
                )
            ]
        finally:
            cur.close()

    def _tde_encryption_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        cur = conn.cursor()
        try:
            wallet_status = ""
            try:
                cur.execute(
                    "SELECT status FROM v$encryption_wallet "
                    "WHERE ROWNUM = 1"
                )
                row = cur.fetchone()
                wallet_status = str(row[0] or "UNKNOWN") if row else "UNKNOWN"
            except Exception:
                # v$encryption_wallet requires Advanced Security Option;
                # absence means unlicensed or feature-disabled
                wallet_status = "UNAVAILABLE"

            encrypted_tablespaces = 0
            try:
                cur.execute(
                    "SELECT COUNT(*) FROM dba_tablespaces "
                    "WHERE encrypted = 'YES'"
                )
                row = cur.fetchone()
                encrypted_tablespaces = int(row[0]) if row else 0
            except Exception as e:
                raise OracleQueryError(
                    f"Could not query dba_tablespaces: {e}"
                ) from e

            tde_active = (
                wallet_status.upper() == "OPEN" or encrypted_tablespaces > 0
            )
            return [
                SecurityFinding(
                    title=(
                        f"Oracle TDE: wallet={wallet_status}, "
                        f"{encrypted_tablespaces} encrypted tablespaces"
                    ),
                    description=(
                        f"v$encryption_wallet.status = {wallet_status}; "
                        f"{encrypted_tablespaces} tablespaces have "
                        "encrypted = 'YES'. SC-28 Protection of "
                        "Information at Rest — TDE requires Oracle "
                        "Advanced Security Option (separately "
                        "licensed). UNAVAILABLE wallet status often "
                        "indicates the option is unlicensed or "
                        "the wallet is unconfigured."
                    ),
                    severity=(
                        Severity.INFORMATIONAL
                        if tde_active
                        else Severity.MEDIUM
                    ),
                    status=(
                        FindingStatus.RESOLVED
                        if tde_active
                        else FindingStatus.ACTIVE
                    ),
                    source_system="oracle",
                    source_finding_id=f"tde-state:{self._cached_db}",
                    resource_type="Oracle::Database",
                    resource_id=str(self._cached_db or "unknown"),
                    control_ids=[
                        m.control_id for m in ENCRYPTION_AT_REST_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={
                        "wallet_status": wallet_status,
                        "encrypted_tablespace_count": encrypted_tablespaces,
                    },
                )
            ]
        finally:
            cur.close()

    def _network_encryption_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        cur = conn.cursor()
        try:
            try:
                cur.execute(
                    "SELECT name, value FROM v$parameter "
                    "WHERE name LIKE 'sqlnet.encryption%'"
                )
                rows = list(cur.fetchall())
            except Exception as e:
                raise OracleQueryError(
                    f"Could not query v$parameter sqlnet.encryption: {e}"
                ) from e

            settings: dict[str, str] = {
                str(r[0]): str(r[1] or "") for r in rows
            }
            server_setting = settings.get(
                "sqlnet.encryption_server", ""
            ).upper()
            encryption_required = server_setting in {"REQUIRED", "REQUESTED"}
            return [
                SecurityFinding(
                    title=(
                        f"Oracle network encryption: "
                        f"sqlnet.encryption_server={server_setting or 'UNSET'}"
                    ),
                    description=(
                        f"sqlnet.encryption_server = "
                        f"{server_setting or 'UNSET (default REJECTED)'}. "
                        "SC-12 Cryptographic Key Establishment — "
                        "encryption_server should be REQUIRED for "
                        "untrusted-network deployments. UNSET / "
                        "REJECTED means clear-text traffic is "
                        "permitted. See BLIND_SPOT "
                        "EVIDENTIA-ORACLE-NETWORK-ENCRYPTION-CLIENT "
                        "for parameter-availability caveats."
                    ),
                    severity=(
                        Severity.INFORMATIONAL
                        if encryption_required
                        else Severity.MEDIUM
                    ),
                    status=(
                        FindingStatus.RESOLVED
                        if encryption_required
                        else FindingStatus.ACTIVE
                    ),
                    source_system="oracle",
                    source_finding_id=(
                        f"network-encryption:{self._cached_db}"
                    ),
                    resource_type="Oracle::Database",
                    resource_id=str(self._cached_db or "unknown"),
                    control_ids=[
                        m.control_id for m in CRYPTO_CONFIG_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data=settings,
                )
            ]
        finally:
            cur.close()

    def _connection_limit_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        cur = conn.cursor()
        try:
            sessions_limit = ""
            processes_limit = ""
            try:
                cur.execute(
                    "SELECT name, value FROM v$parameter "
                    "WHERE name IN ('sessions', 'processes')"
                )
                rows = list(cur.fetchall())
                m = {str(r[0]): str(r[1] or "") for r in rows}
                sessions_limit = m.get("sessions", "")
                processes_limit = m.get("processes", "")
            except Exception as e:
                raise OracleQueryError(
                    f"Could not query v$parameter sessions/processes: {e}"
                ) from e

            return [
                SecurityFinding(
                    title=(
                        f"Oracle session limits: sessions={sessions_limit}, "
                        f"processes={processes_limit}"
                    ),
                    description=(
                        f"v$parameter sessions={sessions_limit}, "
                        f"processes={processes_limit}. AC-3 Access "
                        "Enforcement — these are absolute upper "
                        "bounds; per-user concurrent-session caps "
                        "live in DBA_PROFILES SESSIONS_PER_USER and "
                        "must be reviewed separately for true "
                        "per-principal enforcement."
                    ),
                    severity=Severity.INFORMATIONAL,
                    status=FindingStatus.ACTIVE,
                    source_system="oracle",
                    source_finding_id=(
                        f"session-limits:{self._cached_db}"
                    ),
                    resource_type="Oracle::Database",
                    resource_id=str(self._cached_db or "unknown"),
                    control_ids=[
                        m.control_id for m in CONNECTION_LIMIT_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={
                        "sessions": sessions_limit,
                        "processes": processes_limit,
                    },
                )
            ]
        finally:
            cur.close()
