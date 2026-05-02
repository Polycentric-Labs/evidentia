"""MS SQL Server evidence collector — main module (v0.7.7 P0.4).

Read-only collector against MS SQL Server 2017+ / Azure SQL via
pyodbc + Microsoft ODBC Driver 18. Mirrors the postgres / mysql
adapter shape: typed exceptions, CollectionContext threaded
through findings, CollectionManifest for completeness, ECS-
structured audit logging, read-only principal probe, BLIND_SPOTS.

See ``evidentia_collectors.sql.mssql.__init__`` for the public-
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

from evidentia_collectors.sql.mssql.mapping import (
    AUDIT_LOG_MAPPINGS,
    CONNECTION_LIMIT_MAPPINGS,
    CRYPTO_CONFIG_MAPPINGS,
    ENCRYPTION_AT_REST_MAPPINGS,
    PRIVILEGE_GRANT_MAPPINGS,
    USER_ROLE_INVENTORY_MAPPINGS,
    WRITE_PRIV_DETECTED_MAPPINGS,
)

if TYPE_CHECKING:
    import pyodbc  # noqa: F401


_log = get_logger("evidentia.collectors.sql.mssql")

COLLECTOR_ID = "sql-mssql-scan"


# ── Typed exception hierarchy ──────────────────────────────────────


class MSSQLCollectorError(Exception):
    """Base class for all MSSQL collector failures."""


class MSSQLConnectionError(MSSQLCollectorError):
    """Connection / authentication / TLS handshake failure."""


class MSSQLQueryError(MSSQLCollectorError):
    """A specific T-SQL query failed (permission denied, missing
    feature, etc.). The collector continues with remaining queries;
    the error is recorded in the manifest."""


# ── BLIND_SPOTS list ────────────────────────────────────────────────

BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "EVIDENTIA-MSSQL-EXTENDED-EVENTS",
        "title": (
            "Extended Events sessions outside the SQL Audit subsystem "
            "are not enumerated"
        ),
        "description": (
            "MS SQL Server has multiple audit-trail mechanisms: SQL "
            "Audit (sys.server_audits), Extended Events sessions, and "
            "the deprecated SQL Trace. The collector reads "
            "sys.server_audits + audit-status DMVs but does NOT "
            "enumerate Extended Events sessions configured for "
            "compliance auditing. Operators using XE for AU-2 "
            "evidence should provide out-of-band collection."
        ),
    },
    {
        "id": "EVIDENTIA-MSSQL-AZURE-SQL-FEATURE-MATRIX",
        "title": (
            "Azure SQL Database / Managed Instance feature differences"
        ),
        "description": (
            "Azure SQL Database lacks server-level objects "
            "(sys.server_audits doesn't return rows for managed "
            "instances; no msdb access). Azure SQL Managed Instance "
            "supports server-level objects but with reduced T-SQL "
            "surface. The collector handles missing system views "
            "gracefully — those checks are recorded as INDETERMINATE "
            "rather than treated as misconfigurations."
        ),
    },
    {
        "id": "EVIDENTIA-MSSQL-ALWAYS-ENCRYPTED-COLUMN-VISIBILITY",
        "title": (
            "Always Encrypted column metadata requires CMK access"
        ),
        "description": (
            "Always Encrypted (column-level encryption) reports the "
            "presence of column master keys in "
            "sys.column_master_keys, but the collector cannot decrypt "
            "to verify per-column protection. Out-of-band review of "
            "the application key-rotation policy is required for "
            "complete SC-28 attestation."
        ),
    },
]


# ── Main collector class ────────────────────────────────────────────


class MSSQLCollector:
    """Read-only MS SQL Server evidence collector."""

    def __init__(
        self,
        *,
        connection_uri: str | None = None,
        password: str | None = None,
        connection: Any | None = None,
        driver: str = "{ODBC Driver 18 for SQL Server}",
        encrypt: str = "yes",
        trust_server_certificate: str = "no",
    ) -> None:
        if not connection_uri and connection is None:
            raise MSSQLCollectorError(
                "MSSQLCollector requires either connection_uri= or "
                "connection= (an injected pyodbc.Connection for testing)."
            )
        if connection_uri and "://" in connection_uri:
            authority = connection_uri.split("://", 1)[1].split("/", 1)[0]
            if "@" in authority:
                userinfo = authority.split("@", 1)[0]
                if ":" in userinfo:
                    raise MSSQLCollectorError(
                        "connection_uri must NOT embed a password. "
                        "Pass the password via the password= kwarg, "
                        "sourced from EVIDENTIA_MSSQL_PASSWORD env var."
                    )
        self._connection_uri = connection_uri
        self._password = password
        self._driver = driver
        self._encrypt = encrypt
        self._trust_server_certificate = trust_server_certificate
        self._connection = connection
        self._owns_connection = connection is None
        self._cached_user: str | None = None
        self._cached_db: str | None = None
        self._cached_version: str | None = None

    # ── Lifecycle ───────────────────────────────────────────────────

    def __enter__(self) -> MSSQLCollector:
        self._ensure_connected()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_connection and self._connection is not None:
            with contextlib.suppress(Exception):
                self._connection.close()
            self._connection = None

    def _build_connection_string(self, uri: str) -> str:
        """Convert mssql://user@host:1433/dbname into a pyodbc
        connection string. The password is supplied separately via
        the password= kwarg (NOT via the URI) per the secret protocol.
        """
        parsed = urllib.parse.urlparse(uri)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 1433
        user = parsed.username or ""
        database = parsed.path.lstrip("/") if parsed.path else ""
        parts = [
            f"Driver={self._driver}",
            f"Server=tcp:{host},{port}",
        ]
        if database:
            parts.append(f"Database={database}")
        if user:
            parts.append(f"Uid={user}")
        if self._password is not None:
            parts.append(f"Pwd={self._password}")
        parts.append(f"Encrypt={self._encrypt}")
        parts.append(f"TrustServerCertificate={self._trust_server_certificate}")
        return ";".join(parts) + ";"

    def _ensure_connected(self) -> Any:
        if self._connection is not None:
            return self._connection
        try:
            import pyodbc
        except ImportError as e:
            raise MSSQLCollectorError(
                "pyodbc is not installed. Install via the [sql-mssql] "
                "extra: pip install \"evidentia-collectors[sql-mssql]\""
            ) from e

        if not self._connection_uri:
            raise MSSQLCollectorError(
                "_ensure_connected called without a connection_uri."
            )
        conn_str = self._build_connection_string(self._connection_uri)
        try:
            self._connection = pyodbc.connect(conn_str, autocommit=True)
        except Exception as e:
            raise MSSQLConnectionError(
                f"Could not connect to MSSQL (driver: {type(e).__name__})"
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
            credential_identity=f"mssql-user:{user}",
            source_system_id=f"mssql:{user}@{db}",
            filter_applied={"user": user, "database": db},
        )

    def test_connection(self) -> dict[str, Any]:
        conn = self._ensure_connected()
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT SUSER_SNAME(), DB_NAME(), "
                "CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128))"
            )
            row = cur.fetchone()
            self._cached_user = str(row[0]) if row else None
            self._cached_db = str(row[1] or "") if row else None
            self._cached_version = str(row[2]) if row else None
        finally:
            cur.close()

        is_sysadmin, is_dbo, is_writer = self._probe_write_privilege(conn)

        return {
            "user": self._cached_user,
            "database": self._cached_db,
            "version": self._cached_version,
            "is_sysadmin": is_sysadmin,
            "is_db_owner": is_dbo,
            "is_db_datawriter": is_writer,
        }

    def _probe_write_privilege(
        self, conn: Any
    ) -> tuple[bool, bool, bool]:
        """Check IS_SRVROLEMEMBER('sysadmin') + IS_ROLEMEMBER('db_owner')
        + IS_ROLEMEMBER('db_datawriter'). Any of the three == True is
        a least-privilege violation."""
        cur = conn.cursor()
        try:
            try:
                cur.execute(
                    "SELECT IS_SRVROLEMEMBER('sysadmin'), "
                    "IS_ROLEMEMBER('db_owner'), "
                    "IS_ROLEMEMBER('db_datawriter')"
                )
                row = cur.fetchone()
                is_sysadmin = bool(row[0]) if row else False
                is_dbo = bool(row[1]) if row else False
                is_writer = bool(row[2]) if row else False
                return is_sysadmin, is_dbo, is_writer
            except Exception:
                return False, False, False
        finally:
            cur.close()

    # ── High-level orchestration ────────────────────────────────────

    def collect(self, *, dry_run: bool = False) -> list[SecurityFinding]:
        if dry_run:
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message="MSSQL dry-run — no DB calls made",
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
        except MSSQLCollectorError:
            raise
        except Exception as e:
            raise MSSQLConnectionError(
                f"Could not establish + probe MSSQL connection: {e}"
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
                    f"MSSQL collection starting for "
                    f"{self._cached_user}@{self._cached_db}"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.START],
            )

            if (
                probe["is_sysadmin"]
                or probe["is_db_owner"]
                or probe["is_db_datawriter"]
            ):
                findings.append(
                    self._write_priv_detected_finding(probe, context)
                )

            conn = self._connection
            assert conn is not None
            for sub_check in (
                self._user_role_inventory_findings,
                self._privilege_grant_findings,
                self._audit_log_findings,
                self._tde_encryption_findings,
                self._tls_config_findings,
                self._connection_limit_findings,
            ):
                try:
                    findings.extend(sub_check(conn, context))
                except MSSQLQueryError as e:
                    errors.append(str(e))
                    _log.warning(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=f"Sub-check {sub_check.__name__} failed: {e}",
                        error={"type": "MSSQLQueryError", "message": str(e)},
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
                    f"MSSQL collection completed: {len(findings)} findings"
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
                f"mssql:{self._cached_user}@{self._cached_db}"
            ],
            filters_applied={
                "user": self._cached_user or "unknown",
                "database": self._cached_db or "unknown",
            },
            coverage_counts=[
                CoverageCount(
                    resource_type="mssql-database",
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
        roles = []
        if probe["is_sysadmin"]:
            roles.append("sysadmin")
        if probe["is_db_owner"]:
            roles.append("db_owner")
        if probe["is_db_datawriter"]:
            roles.append("db_datawriter")
        roles_str = ", ".join(roles)
        return SecurityFinding(
            title=(
                f"MSSQL principal {self._cached_user!r} has write "
                f"privilege ({roles_str})"
            ),
            description=(
                f"Principal ({self._cached_user}) connected to "
                f"{self._cached_db} is a member of: {roles_str}. "
                "Production deployments should grant the collector a "
                "read-only DB role (e.g., db_datareader only); write "
                "privilege violates AC-6 least-privilege and increases "
                "blast radius of credential compromise."
            ),
            severity=(
                Severity.HIGH if probe["is_sysadmin"] else Severity.MEDIUM
            ),
            status=FindingStatus.ACTIVE,
            source_system="mssql",
            source_finding_id=(
                f"EVIDENTIA-WRITE-PRIV-DETECTED:{self._cached_user}@"
                f"{self._cached_db}"
            ),
            resource_type="MSSQL::Principal",
            resource_id=str(self._cached_user or "unknown"),
            control_ids=[m.control_id for m in WRITE_PRIV_DETECTED_MAPPINGS],
            collection_context=context,
            raw_data={
                "is_sysadmin": probe["is_sysadmin"],
                "is_db_owner": probe["is_db_owner"],
                "is_db_datawriter": probe["is_db_datawriter"],
                "roles": roles,
            },
        )

    def _user_role_inventory_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        cur = conn.cursor()
        try:
            try:
                cur.execute(
                    "SELECT name, type_desc, is_disabled, "
                    "create_date FROM sys.server_principals "
                    "WHERE type IN ('S', 'U', 'G') "
                    "ORDER BY name"
                )
                rows = list(cur.fetchall())
            except Exception as e:
                raise MSSQLQueryError(
                    f"Could not enumerate sys.server_principals: {e}"
                ) from e

            disabled_count = sum(1 for r in rows if r[2])
            sql_logins = [r[0] for r in rows if r[1] == "SQL_LOGIN"]
            return [
                SecurityFinding(
                    title=(
                        f"MSSQL user inventory: {len(rows)} principals, "
                        f"{len(sql_logins)} SQL_LOGIN, "
                        f"{disabled_count} disabled"
                    ),
                    description=(
                        f"sys.server_principals has {len(rows)} entries: "
                        f"SQL_LOGINs={len(sql_logins)} (sample: "
                        f"{sql_logins[:5]}), disabled={disabled_count}. "
                        "AC-2 evidence — operators should review the "
                        "SQL_LOGIN list against the inventory of "
                        "DBA-tier human + automation principals; "
                        "Windows / Azure AD logins are typically "
                        "preferred over SQL Authentication."
                    ),
                    severity=(
                        Severity.MEDIUM
                        if len(sql_logins) > 5
                        else Severity.INFORMATIONAL
                    ),
                    status=FindingStatus.ACTIVE,
                    source_system="mssql",
                    source_finding_id=f"user-inventory:{self._cached_db}",
                    resource_type="MSSQL::Server",
                    resource_id=str(self._cached_db or "unknown"),
                    control_ids=[
                        m.control_id for m in USER_ROLE_INVENTORY_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={
                        "total_principals": len(rows),
                        "sql_login_count": len(sql_logins),
                        "disabled_count": disabled_count,
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
                    "SELECT COUNT(*) FROM sys.server_role_members rm "
                    "JOIN sys.server_principals r ON r.principal_id = "
                    "rm.role_principal_id WHERE r.name = 'sysadmin'"
                )
                row = cur.fetchone()
                sysadmin_count = int(row[0]) if row else 0
            except Exception as e:
                raise MSSQLQueryError(
                    f"Could not enumerate server-role members: {e}"
                ) from e

            return [
                SecurityFinding(
                    title=(
                        f"MSSQL sysadmin role has {sysadmin_count} "
                        f"members"
                    ),
                    description=(
                        f"{sysadmin_count} principals are members of "
                        "the server-level sysadmin fixed role. AC-6 "
                        "Least Privilege evidence — sysadmin grants "
                        "unrestricted access; the count should be "
                        "minimal (1-2 break-glass + automation "
                        "service principals)."
                    ),
                    severity=(
                        Severity.HIGH
                        if sysadmin_count > 5
                        else Severity.MEDIUM
                        if sysadmin_count > 2
                        else Severity.INFORMATIONAL
                    ),
                    status=(
                        FindingStatus.ACTIVE
                        if sysadmin_count > 2
                        else FindingStatus.RESOLVED
                    ),
                    source_system="mssql",
                    source_finding_id=(
                        f"sysadmin-membership:{self._cached_db}"
                    ),
                    resource_type="MSSQL::ServerRole",
                    resource_id="sysadmin",
                    control_ids=[
                        m.control_id for m in PRIVILEGE_GRANT_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={"sysadmin_member_count": sysadmin_count},
                )
            ]
        finally:
            cur.close()

    def _audit_log_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        cur = conn.cursor()
        try:
            try:
                cur.execute(
                    "SELECT COUNT(*), "
                    "SUM(CASE WHEN is_state_enabled = 1 THEN 1 ELSE 0 END) "
                    "FROM sys.server_audits"
                )
                row = cur.fetchone()
                total_audits = int(row[0]) if row else 0
                enabled_audits = int(row[1] or 0) if row else 0
            except Exception as e:
                raise MSSQLQueryError(
                    f"Could not enumerate sys.server_audits: {e}"
                ) from e

            audit_configured = total_audits > 0
            audit_enabled = enabled_audits > 0
            return [
                SecurityFinding(
                    title=(
                        f"MSSQL SQL Audit: {total_audits} configured, "
                        f"{enabled_audits} enabled"
                    ),
                    description=(
                        f"sys.server_audits returned {total_audits} "
                        f"audit configurations; {enabled_audits} are "
                        f"currently enabled (is_state_enabled=1). AU-2 "
                        "Event Logging — production deployments "
                        "should have at least one enabled SQL Audit "
                        "writing to a tamper-resistant target (file "
                        "share, Application Log, Security Log)."
                    ),
                    severity=(
                        Severity.INFORMATIONAL
                        if audit_enabled
                        else Severity.MEDIUM
                    ),
                    status=(
                        FindingStatus.RESOLVED
                        if audit_enabled
                        else FindingStatus.ACTIVE
                    ),
                    source_system="mssql",
                    source_finding_id=(
                        f"server-audit:{self._cached_db}"
                    ),
                    resource_type="MSSQL::Server",
                    resource_id=str(self._cached_db or "unknown"),
                    control_ids=[
                        m.control_id for m in AUDIT_LOG_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={
                        "total_audits": total_audits,
                        "enabled_audits": enabled_audits,
                        "audit_configured": audit_configured,
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
            try:
                cur.execute(
                    "SELECT db.name, COALESCE(dek.encryption_state, 0) "
                    "FROM sys.databases db "
                    "LEFT JOIN sys.dm_database_encryption_keys dek "
                    "ON db.database_id = dek.database_id "
                    "WHERE db.database_id NOT IN (1, 2, 3, 4) "
                    "ORDER BY db.name"
                )
                rows = list(cur.fetchall())
            except Exception as e:
                raise MSSQLQueryError(
                    f"Could not query TDE state: {e}"
                ) from e

            # encryption_state values:
            # 0 = no DEK present, no encryption
            # 1 = unencrypted
            # 2 = encryption in progress
            # 3 = encrypted
            # 4 = key change
            # 5 = decryption in progress
            # 6 = protection change in progress
            unencrypted_dbs = [r[0] for r in rows if int(r[1]) in (0, 1)]
            encrypted_dbs = [r[0] for r in rows if int(r[1]) == 3]
            return [
                SecurityFinding(
                    title=(
                        f"MSSQL TDE state: {len(encrypted_dbs)} encrypted, "
                        f"{len(unencrypted_dbs)} unencrypted "
                        f"(of {len(rows)} user databases)"
                    ),
                    description=(
                        f"sys.dm_database_encryption_keys reports "
                        f"{len(encrypted_dbs)} TDE-encrypted databases "
                        f"and {len(unencrypted_dbs)} without TDE. "
                        f"Unencrypted: {unencrypted_dbs[:5]}"
                        + ("..." if len(unencrypted_dbs) > 5 else "")
                        + ". SC-28 Protection of Information at Rest — "
                        "production user databases storing sensitive "
                        "data should have TDE enabled."
                    ),
                    severity=(
                        Severity.MEDIUM
                        if unencrypted_dbs
                        else Severity.INFORMATIONAL
                    ),
                    status=(
                        FindingStatus.ACTIVE
                        if unencrypted_dbs
                        else FindingStatus.RESOLVED
                    ),
                    source_system="mssql",
                    source_finding_id=(
                        f"tde-state:{self._cached_db}"
                    ),
                    resource_type="MSSQL::Server",
                    resource_id=str(self._cached_db or "unknown"),
                    control_ids=[
                        m.control_id for m in ENCRYPTION_AT_REST_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={
                        "encrypted_databases": encrypted_dbs,
                        "unencrypted_databases": unencrypted_dbs,
                        "total_user_databases": len(rows),
                    },
                )
            ]
        finally:
            cur.close()

    def _tls_config_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        cur = conn.cursor()
        try:
            try:
                cur.execute(
                    "SELECT CONNECTIONPROPERTY('protocol_type'), "
                    "CONNECTIONPROPERTY('auth_scheme'), "
                    "CONVERT(NVARCHAR(64), "
                    "CONNECTIONPROPERTY('encrypt_option'))"
                )
                row = cur.fetchone()
                protocol = str(row[0] or "") if row else ""
                auth_scheme = str(row[1] or "") if row else ""
                encrypt_option = str(row[2] or "") if row else ""
            except Exception as e:
                raise MSSQLQueryError(
                    f"Could not read connection properties: {e}"
                ) from e

            encrypted = encrypt_option.upper() in {"TRUE", "1"}
            return [
                SecurityFinding(
                    title=(
                        f"MSSQL connection: protocol={protocol}, "
                        f"auth={auth_scheme}, "
                        f"encrypted={encrypted}"
                    ),
                    description=(
                        f"CONNECTIONPROPERTY: protocol_type={protocol}, "
                        f"auth_scheme={auth_scheme}, "
                        f"encrypt_option={encrypt_option}. SC-12 "
                        "Cryptographic Key Establishment — connections "
                        "must use TLS (encrypt_option=TRUE) when "
                        "traversing untrusted networks; SQL "
                        "Authentication should be paired with strong "
                        "password policy or replaced with Windows / "
                        "Azure AD authentication."
                    ),
                    severity=(
                        Severity.INFORMATIONAL
                        if encrypted
                        else Severity.MEDIUM
                    ),
                    status=(
                        FindingStatus.RESOLVED
                        if encrypted
                        else FindingStatus.ACTIVE
                    ),
                    source_system="mssql",
                    source_finding_id=(
                        f"tls-config:{self._cached_db}"
                    ),
                    resource_type="MSSQL::Connection",
                    resource_id=str(self._cached_db or "unknown"),
                    control_ids=[
                        m.control_id for m in CRYPTO_CONFIG_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={
                        "protocol_type": protocol,
                        "auth_scheme": auth_scheme,
                        "encrypt_option": encrypt_option,
                        "encrypted": encrypted,
                    },
                )
            ]
        finally:
            cur.close()

    def _connection_limit_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        cur = conn.cursor()
        try:
            try:
                cur.execute(
                    "SELECT name, CAST(value_in_use AS INT) "
                    "FROM sys.configurations "
                    "WHERE name = 'user connections'"
                )
                row = cur.fetchone()
                user_conn_limit = int(row[1]) if row else 0
            except Exception as e:
                raise MSSQLQueryError(
                    f"Could not query sys.configurations: {e}"
                ) from e

            # 0 = unlimited (default)
            limit_set = user_conn_limit > 0
            return [
                SecurityFinding(
                    title=(
                        f"MSSQL user_connections: "
                        f"{user_conn_limit if limit_set else 'unlimited'}"
                    ),
                    description=(
                        f"sp_configure 'user connections' = "
                        f"{user_conn_limit} ({'limit set' if limit_set else 'unlimited (default)'}). "
                        "AC-3 Access Enforcement — explicit connection "
                        "limits provide rate-limiting evidence and "
                        "DoS-resistance posture; the unlimited default "
                        "is acceptable when an upstream load balancer "
                        "or firewall enforces session caps."
                    ),
                    severity=Severity.INFORMATIONAL,
                    status=FindingStatus.ACTIVE,
                    source_system="mssql",
                    source_finding_id=(
                        f"connection-limits:{self._cached_db}"
                    ),
                    resource_type="MSSQL::Server",
                    resource_id=str(self._cached_db or "unknown"),
                    control_ids=[
                        m.control_id for m in CONNECTION_LIMIT_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={
                        "user_connections_limit": user_conn_limit,
                        "limit_set": limit_set,
                    },
                )
            ]
        finally:
            cur.close()
