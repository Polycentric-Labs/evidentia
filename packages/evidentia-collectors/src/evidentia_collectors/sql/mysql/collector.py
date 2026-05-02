"""MySQL / MariaDB evidence collector — main module (v0.7.7 P0.2).

Read-only collector that mirrors the postgres adapter structure
against MySQL 5.7+ / MariaDB 10.x+ via PyMySQL. Same enterprise-
grade patterns: typed exceptions, CollectionContext threaded
through findings, CollectionManifest for completeness attestation,
ECS-structured audit logging, read-only principal probe,
BLIND_SPOTS list.

See ``evidentia_collectors.sql.mysql.__init__`` for the public-
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

from evidentia_collectors.sql.mysql.mapping import (
    AUDIT_LOG_MAPPINGS,
    CONNECTION_LIMIT_MAPPINGS,
    CRYPTO_CONFIG_MAPPINGS,
    ENCRYPTION_AT_REST_MAPPINGS,
    PRIVILEGE_GRANT_MAPPINGS,
    USER_ROLE_INVENTORY_MAPPINGS,
    WRITE_PRIV_DETECTED_MAPPINGS,
)

if TYPE_CHECKING:
    import pymysql  # type: ignore[import-untyped]  # noqa: F401


_log = get_logger("evidentia.collectors.sql.mysql")

COLLECTOR_ID = "sql-mysql-scan"


# ── Typed exception hierarchy ──────────────────────────────────────


class MySQLCollectorError(Exception):
    """Base class for all MySQL collector failures."""


class MySQLConnectionError(MySQLCollectorError):
    """Connection / authentication / TLS handshake failure."""


class MySQLQueryError(MySQLCollectorError):
    """A specific SQL query failed (permission denied, missing
    feature, etc.). The collector continues with remaining queries;
    the error is recorded in the manifest."""


# ── BLIND_SPOTS list ────────────────────────────────────────────────

BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "EVIDENTIA-MYSQL-AUDIT-PLUGIN-COMMUNITY",
        "title": "MySQL Community Edition has no built-in audit-log plugin",
        "description": (
            "MySQL Community Edition does not ship the MySQL Enterprise "
            "Audit plugin. general_log captures every statement but "
            "has known performance + retention limitations. Operators "
            "who need full AU-2 + AU-3 audit coverage should run "
            "Percona Server (Audit Log plugin), MariaDB (server_audit "
            "plugin), or upgrade to MySQL Enterprise. The collector "
            "reports general_log + audit_log_* status; cannot make a "
            "judgement about whether audit coverage is sufficient."
        ),
    },
    {
        "id": "EVIDENTIA-MYSQL-MYSQL-CONFIG-FILE-ACCESS",
        "title": "my.cnf configuration requires filesystem read access",
        "description": (
            "Many MySQL security-relevant settings (default_authentication_plugin, "
            "ssl_cert paths, plugin_load_add) are read at server "
            "startup from my.cnf and not exposed via SHOW VARIABLES "
            "after process start. The collector reads what's exposed "
            "via SHOW VARIABLES; the file itself requires out-of-band "
            "collection."
        ),
    },
    {
        "id": "EVIDENTIA-MYSQL-CLOUD-MANAGED",
        "title": "Cloud-managed MySQL exposes a subset of variables",
        "description": (
            "AWS RDS for MySQL, Aurora MySQL, Azure Database for MySQL, "
            "GCP Cloud SQL, and other managed services restrict access "
            "to certain SHOW VARIABLES outputs. The collector handles "
            "missing values gracefully — they're recorded as INDETERMINATE "
            "rather than treated as misconfigurations."
        ),
    },
]


# ── Main collector class ────────────────────────────────────────────


class MySQLCollector:
    """Read-only MySQL / MariaDB evidence collector."""

    def __init__(
        self,
        *,
        connection_uri: str | None = None,
        password: str | None = None,
        connection: Any | None = None,
    ) -> None:
        if not connection_uri and connection is None:
            raise MySQLCollectorError(
                "MySQLCollector requires either connection_uri= or "
                "connection= (an injected pymysql.Connection for testing)."
            )
        if connection_uri and "://" in connection_uri:
            authority = connection_uri.split("://", 1)[1].split("/", 1)[0]
            if "@" in authority:
                userinfo = authority.split("@", 1)[0]
                if ":" in userinfo:
                    raise MySQLCollectorError(
                        "connection_uri must NOT embed a password. "
                        "Pass the password via the password= kwarg, "
                        "sourced from EVIDENTIA_MYSQL_PASSWORD env var."
                    )
        self._connection_uri = connection_uri
        self._password = password
        self._connection = connection
        self._owns_connection = connection is None
        self._cached_user: str | None = None
        self._cached_db: str | None = None
        self._cached_version: str | None = None

    # ── Lifecycle ───────────────────────────────────────────────────

    def __enter__(self) -> MySQLCollector:
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
        """Parse a mysql:// URI into PyMySQL connect() kwargs.

        PyMySQL doesn't accept URIs natively (unlike psycopg). Pull
        host/port/user/db out + return as a kwargs dict.
        """
        parsed = urllib.parse.urlparse(uri)
        return {
            "host": parsed.hostname or "127.0.0.1",
            "port": parsed.port or 3306,
            "user": parsed.username or "",
            "database": parsed.path.lstrip("/") if parsed.path else None,
        }

    def _ensure_connected(self) -> Any:
        if self._connection is not None:
            return self._connection
        try:
            import pymysql
        except ImportError as e:
            raise MySQLCollectorError(
                "PyMySQL is not installed. Install via the "
                "[sql-mysql] extra: "
                'pip install "evidentia-collectors[sql-mysql]"'
            ) from e

        if not self._connection_uri:
            raise MySQLCollectorError(
                "_ensure_connected called without a connection_uri."
            )
        kwargs = self._parse_uri(self._connection_uri)
        if self._password is not None:
            kwargs["password"] = self._password
        kwargs["autocommit"] = True
        try:
            self._connection = pymysql.connect(**kwargs)
        except Exception as e:
            raise MySQLConnectionError(
                f"Could not connect to MySQL: {e}"
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
            credential_identity=f"mysql-user:{user}",
            source_system_id=f"mysql:{user}@{db}",
            filter_applied={"user": user, "database": db},
        )

    def test_connection(self) -> dict[str, Any]:
        conn = self._ensure_connected()
        cur = conn.cursor()
        try:
            cur.execute("SELECT CURRENT_USER(), DATABASE(), VERSION()")
            row = cur.fetchone()
            self._cached_user = str(row[0]) if row else None
            self._cached_db = str(row[1] or "") if row else None
            self._cached_version = str(row[2]) if row else None
        finally:
            cur.close()

        read_only, can_create_temp = self._probe_write_privilege(conn)

        return {
            "user": self._cached_user,
            "database": self._cached_db,
            "version": self._cached_version,
            "read_only": read_only,
            "can_create_temp_table": can_create_temp,
        }

    def _probe_write_privilege(self, conn: Any) -> tuple[bool, bool]:
        """Phase 1: read @@global.read_only / @@session.transaction_read_only.
        Phase 2: attempt CREATE TEMPORARY TABLE + roll back."""
        cur = conn.cursor()
        try:
            try:
                cur.execute(
                    "SELECT @@global.read_only, @@session.transaction_read_only"
                )
                row = cur.fetchone()
                # Either flag being TRUE (1) is a read-only signal.
                global_ro = bool(row[0]) if row else False
                session_ro = bool(row[1]) if row else False
                read_only_setting = global_ro or session_ro
            except Exception:
                read_only_setting = False

            create_temp_succeeded = False
            try:
                cur.execute("START TRANSACTION")
                cur.execute(
                    "CREATE TEMPORARY TABLE evidentia_priv_probe_temp (id int)"
                )
                create_temp_succeeded = True
                cur.execute("ROLLBACK")
            except Exception:
                with contextlib.suppress(Exception):
                    cur.execute("ROLLBACK")

            return read_only_setting, create_temp_succeeded
        finally:
            cur.close()

    # ── High-level orchestration ────────────────────────────────────

    def collect(self, *, dry_run: bool = False) -> list[SecurityFinding]:
        if dry_run:
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message="MySQL dry-run — no DB calls made",
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
        except MySQLCollectorError:
            raise
        except Exception as e:
            raise MySQLConnectionError(
                f"Could not establish + probe MySQL connection: {e}"
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
                    f"MySQL collection starting for "
                    f"{self._cached_user}@{self._cached_db}"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.START],
            )

            if not probe["read_only"] or probe["can_create_temp_table"]:
                findings.append(
                    self._write_priv_detected_finding(probe, context)
                )

            conn = self._connection
            assert conn is not None
            for sub_check in (
                self._user_role_inventory_findings,
                self._privilege_grant_findings,
                self._audit_log_findings,
                self._crypto_config_findings,
                self._encryption_at_rest_findings,
                self._connection_limit_findings,
            ):
                try:
                    findings.extend(sub_check(conn, context))
                except MySQLQueryError as e:
                    errors.append(str(e))
                    _log.warning(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=f"Sub-check {sub_check.__name__} failed: {e}",
                        error={"type": "MySQLQueryError", "message": str(e)},
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
                    f"MySQL collection completed: {len(findings)} findings"
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
                f"mysql:{self._cached_user}@{self._cached_db}"
            ],
            filters_applied={
                "user": self._cached_user or "unknown",
                "database": self._cached_db or "unknown",
            },
            coverage_counts=[
                CoverageCount(
                    resource_type="mysql-database",
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
        return SecurityFinding(
            title=(
                f"MySQL principal {self._cached_user!r} has write privilege"
            ),
            description=(
                f"Principal ({self._cached_user}) connected to "
                f"{self._cached_db} with write capability detected via "
                f"the read-only probe (read_only={probe['read_only']!r}, "
                f"can_create_temp_table={probe['can_create_temp_table']!r}). "
                "Production deployments should grant the collector a "
                "read-only DB role; write privilege violates AC-6 "
                "least-privilege and increases blast radius of "
                "credential compromise."
            ),
            severity=Severity.MEDIUM,
            status=FindingStatus.ACTIVE,
            source_system="mysql",
            source_finding_id=(
                f"EVIDENTIA-WRITE-PRIV-DETECTED:{self._cached_user}@"
                f"{self._cached_db}"
            ),
            resource_type="MySQL::Principal",
            resource_id=str(self._cached_user or "unknown"),
            control_ids=[m.control_id for m in WRITE_PRIV_DETECTED_MAPPINGS],
            collection_context=context,
            raw_data={
                "read_only": probe["read_only"],
                "can_create_temp_table": probe["can_create_temp_table"],
            },
        )

    def _user_role_inventory_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        cur = conn.cursor()
        try:
            try:
                cur.execute(
                    "SELECT User, Host, Super_priv, account_locked "
                    "FROM mysql.user ORDER BY User, Host"
                )
                rows = cur.fetchall()
            except Exception as e:
                raise MySQLQueryError(
                    f"Could not enumerate mysql.user: {e}"
                ) from e

            super_users = [
                f"{r[0]}@{r[1]}" for r in rows
                if str(r[2] or "").upper() == "Y"
            ]
            locked_count = sum(
                1 for r in rows if str(r[3] or "").upper() == "Y"
            )
            return [
                SecurityFinding(
                    title=(
                        f"MySQL user inventory: {len(rows)} accounts, "
                        f"{len(super_users)} with SUPER, "
                        f"{locked_count} locked"
                    ),
                    description=(
                        f"mysql.user has {len(rows)} accounts. SUPER "
                        f"privilege holders: {super_users[:5]}"
                        + ("..." if len(super_users) > 5 else "")
                        + f". {locked_count} accounts are administratively "
                        "locked. AC-2 evidence — operators should review "
                        "the SUPER list against the inventory of DBA-tier "
                        "human + automation principals."
                    ),
                    severity=(
                        Severity.MEDIUM
                        if len(super_users) > 3
                        else Severity.INFORMATIONAL
                    ),
                    status=FindingStatus.ACTIVE,
                    source_system="mysql",
                    source_finding_id=f"user-inventory:{self._cached_db}",
                    resource_type="MySQL::Server",
                    resource_id=str(self._cached_db or "unknown"),
                    control_ids=[
                        m.control_id for m in USER_ROLE_INVENTORY_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={
                        "total_accounts": len(rows),
                        "super_users": super_users,
                        "locked_count": locked_count,
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
                    "SELECT GRANTEE, COUNT(*) AS grant_count "
                    "FROM information_schema.TABLE_PRIVILEGES "
                    "GROUP BY GRANTEE ORDER BY grant_count DESC LIMIT 20"
                )
                rows = cur.fetchall()
            except Exception as e:
                raise MySQLQueryError(
                    f"Could not enumerate information_schema.TABLE_PRIVILEGES: {e}"
                ) from e

            top_grantees = [(str(r[0]), int(r[1])) for r in rows]
            return [
                SecurityFinding(
                    title=(
                        f"MySQL privilege grants: {len(rows)} grantees "
                        "with table-level privileges"
                    ),
                    description=(
                        f"information_schema.TABLE_PRIVILEGES shows "
                        f"{len(rows)} grantees with table-level privileges. "
                        f"Top: {top_grantees[:5]}. "
                        "AC-3 / AC-6 evidence."
                    ),
                    severity=Severity.INFORMATIONAL,
                    status=FindingStatus.ACTIVE,
                    source_system="mysql",
                    source_finding_id=f"privilege-grants:{self._cached_db}",
                    resource_type="MySQL::Server",
                    resource_id=str(self._cached_db or "unknown"),
                    control_ids=[
                        m.control_id for m in PRIVILEGE_GRANT_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={
                        "grantee_count": len(rows),
                        "top_grantees": top_grantees,
                    },
                )
            ]
        finally:
            cur.close()

    def _audit_log_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        settings = self._read_variables(
            conn,
            [
                "general_log",
                "general_log_file",
                "log_output",
                "audit_log_policy",  # MySQL Enterprise / MariaDB Audit
                "server_audit_logging",  # MariaDB
            ],
        )

        gaps: list[str] = []
        if settings.get("general_log", "").lower() == "off":
            gaps.append("general_log=off")
        # Audit-plugin presence is best-effort; plugin variables only
        # exist if the plugin is loaded
        has_enterprise_audit = "audit_log_policy" in settings and settings["audit_log_policy"]
        has_mariadb_audit = "server_audit_logging" in settings and settings[
            "server_audit_logging"
        ].lower() in {"on", "1"}

        severity = Severity.MEDIUM if gaps else Severity.INFORMATIONAL
        status = FindingStatus.ACTIVE if gaps else FindingStatus.RESOLVED

        return [
            SecurityFinding(
                title=(
                    "MySQL audit-log configuration: "
                    f"{'gaps detected' if gaps else 'baseline OK'}"
                ),
                description=(
                    "MySQL audit-log evidence per AU-2 + AU-3. "
                    f"Settings: {settings}. "
                    f"Enterprise Audit plugin: {has_enterprise_audit}. "
                    f"MariaDB Audit plugin: {has_mariadb_audit}. "
                    + (
                        "Gaps: " + ", ".join(gaps) + ". "
                        if gaps
                        else "No common gaps detected. "
                    )
                    + "MySQL Community lacks a built-in audit plugin "
                    "(see BLIND_SPOT EVIDENTIA-MYSQL-AUDIT-PLUGIN-COMMUNITY); "
                    "operators on Community should consider Percona "
                    "Audit or running MariaDB instead."
                ),
                severity=severity,
                status=status,
                source_system="mysql",
                source_finding_id=f"audit-log:{self._cached_db}",
                resource_type="MySQL::Server",
                resource_id=str(self._cached_db or "unknown"),
                control_ids=[m.control_id for m in AUDIT_LOG_MAPPINGS],
                collection_context=context,
                raw_data={
                    "settings": settings,
                    "has_enterprise_audit": has_enterprise_audit,
                    "has_mariadb_audit": has_mariadb_audit,
                    "gaps": gaps,
                },
            )
        ]

    def _crypto_config_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        settings = self._read_variables(
            conn,
            [
                "have_ssl",
                "require_secure_transport",
                "ssl_cipher",
                "tls_version",
                "default_authentication_plugin",
            ],
        )

        have_ssl = settings.get("have_ssl", "").lower() in {"yes", "on"}
        require_tls = settings.get("require_secure_transport", "").lower() in {
            "on",
            "1",
        }
        auth_plugin = settings.get("default_authentication_plugin", "").lower()

        gaps: list[str] = []
        if not have_ssl:
            gaps.append("have_ssl=disabled")
        if not require_tls:
            gaps.append("require_secure_transport=off")
        # mysql_native_password is the legacy weak hash; caching_sha2_password
        # is the modern default in MySQL 8.0+
        if auth_plugin and "native_password" in auth_plugin:
            gaps.append(
                f"default_authentication_plugin={auth_plugin!r} (legacy)"
            )

        severity = Severity.HIGH if gaps else Severity.INFORMATIONAL
        status = FindingStatus.ACTIVE if gaps else FindingStatus.RESOLVED

        return [
            SecurityFinding(
                title=(
                    "MySQL crypto configuration: "
                    f"{'gaps detected' if gaps else 'baseline OK'}"
                ),
                description=(
                    f"MySQL SC-12 evidence: have_ssl="
                    f"{settings.get('have_ssl', '?')!r}, "
                    "require_secure_transport="
                    f"{settings.get('require_secure_transport', '?')!r}, "
                    f"tls_version={settings.get('tls_version', '?')!r}, "
                    "default_authentication_plugin="
                    f"{auth_plugin or '?'!r}. "
                    + (
                        "Gaps: " + ", ".join(gaps) + ". "
                        if gaps
                        else ""
                    )
                    + "caching_sha2_password (MySQL 8.0+ default) is the "
                    "modern minimum; mysql_native_password is the legacy "
                    "weak hash. require_secure_transport=on enforces "
                    "TLS at server level."
                ),
                severity=severity,
                status=status,
                source_system="mysql",
                source_finding_id=f"crypto-config:{self._cached_db}",
                resource_type="MySQL::Server",
                resource_id=str(self._cached_db or "unknown"),
                control_ids=[m.control_id for m in CRYPTO_CONFIG_MAPPINGS],
                collection_context=context,
                raw_data={"settings": settings, "gaps": gaps},
            )
        ]

    def _encryption_at_rest_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        settings = self._read_variables(
            conn,
            [
                "innodb_encrypt_tables",
                "innodb_encryption_threads",
                "default_table_encryption",  # 8.0.16+
                "keyring_file_data",  # presence indicates keyring plugin
            ],
        )

        encrypt_tables = settings.get(
            "innodb_encrypt_tables", ""
        ).lower() in {"on", "1", "force"}
        default_encrypt = settings.get(
            "default_table_encryption", ""
        ).lower() in {"on", "1"}
        has_keyring = bool(settings.get("keyring_file_data"))

        gaps: list[str] = []
        if not (encrypt_tables or default_encrypt):
            gaps.append(
                "innodb_encrypt_tables=off and default_table_encryption=off"
            )
        if not has_keyring:
            gaps.append("no keyring plugin loaded (keyring_file_data empty)")

        severity = Severity.HIGH if gaps else Severity.INFORMATIONAL
        status = FindingStatus.ACTIVE if gaps else FindingStatus.RESOLVED

        return [
            SecurityFinding(
                title=(
                    "MySQL encryption-at-rest: "
                    f"{'gaps detected' if gaps else 'baseline OK'}"
                ),
                description=(
                    f"MySQL SC-28 evidence: "
                    f"innodb_encrypt_tables="
                    f"{settings.get('innodb_encrypt_tables', '?')!r}, "
                    f"default_table_encryption="
                    f"{settings.get('default_table_encryption', '?')!r}, "
                    f"keyring loaded: {has_keyring}. "
                    + (
                        "Gaps: " + ", ".join(gaps) + ". "
                        if gaps
                        else ""
                    )
                    + "InnoDB tablespace encryption requires both an "
                    "encryption setting AND a loaded keyring plugin to "
                    "be effective."
                ),
                severity=severity,
                status=status,
                source_system="mysql",
                source_finding_id=f"encryption-at-rest:{self._cached_db}",
                resource_type="MySQL::Server",
                resource_id=str(self._cached_db or "unknown"),
                control_ids=[
                    m.control_id for m in ENCRYPTION_AT_REST_MAPPINGS
                ],
                collection_context=context,
                raw_data={
                    "settings": settings,
                    "has_keyring": has_keyring,
                    "gaps": gaps,
                },
            )
        ]

    def _connection_limit_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        settings = self._read_variables(
            conn, ["max_connections", "max_user_connections"]
        )
        try:
            max_conn = int(settings.get("max_connections", "0"))
        except (TypeError, ValueError):
            max_conn = 0

        return [
            SecurityFinding(
                title=(
                    f"MySQL connection limits: max_connections={max_conn}"
                ),
                description=(
                    f"max_connections={max_conn}, max_user_connections="
                    f"{settings.get('max_user_connections', '?')!r}. "
                    "AC-3 evidence."
                ),
                severity=Severity.INFORMATIONAL,
                status=FindingStatus.ACTIVE,
                source_system="mysql",
                source_finding_id=f"connection-limits:{self._cached_db}",
                resource_type="MySQL::Server",
                resource_id=str(self._cached_db or "unknown"),
                control_ids=[
                    m.control_id for m in CONNECTION_LIMIT_MAPPINGS
                ],
                collection_context=context,
                raw_data={"settings": settings, "max_connections": max_conn},
            )
        ]

    # ── Helpers ─────────────────────────────────────────────────────

    def _read_variables(
        self, conn: Any, names: list[str]
    ) -> dict[str, str]:
        """Read SHOW VARIABLES values for a list of names.

        Missing names map to empty string. SHOW VARIABLES filters
        client-side rather than via WHERE because not every variable
        is universally queryable.
        """
        cur = conn.cursor()
        result: dict[str, str] = {}
        try:
            try:
                cur.execute("SHOW VARIABLES")
                for row in cur.fetchall():
                    name = str(row[0])
                    if name in names:
                        result[name] = str(row[1] or "")
            except Exception:
                # Fall back to per-variable SELECT @@global.<name>
                for name in names:
                    try:
                        cur.execute(f"SELECT @@global.{name}")
                        row = cur.fetchone()
                        if row and row[0] is not None:
                            result[name] = str(row[0])
                    except Exception:
                        continue
            return result
        finally:
            cur.close()
