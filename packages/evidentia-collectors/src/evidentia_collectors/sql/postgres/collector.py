"""PostgreSQL evidence collector — main module (v0.7.7 P0.1).

Read-only collector that surfaces compliance-relevant evidence from a
running PostgreSQL instance and emits NIST-mapped SecurityFinding
objects for each observation.

See ``evidentia_collectors.sql.postgres.__init__`` for the public-
surface walkthrough + credential handling protocol.

Mirrors the v0.7.0 enterprise-grade collector pattern:

- Typed exception hierarchy (``PostgresCollectorError`` /
  ``PostgresConnectionError`` / ``PostgresQueryError``)
- ``CollectionContext`` threaded through every emitted finding
- ``CollectionManifest`` returned by ``collect_v2()`` for completeness
  attestation
- ECS-structured audit logging via
  ``evidentia_core.audit.get_logger("evidentia.collectors.sql.postgres")``
- Read-only principal verification probe on first connect
- Explicit ``BLIND_SPOTS`` list documenting coverage gaps
"""

from __future__ import annotations

import contextlib
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
from evidentia_core.models.finding import (
    ComplianceStatus,
    FindingStatus,
    SecurityFinding,
)

from evidentia_collectors.sql.postgres.mapping import (
    AUDIT_LOG_MAPPINGS,
    CONNECTION_LIMIT_MAPPINGS,
    CRYPTO_CONFIG_MAPPINGS,
    ENCRYPTION_AT_REST_MAPPINGS,
    PRIVILEGE_GRANT_MAPPINGS,
    USER_ROLE_INVENTORY_MAPPINGS,
    WRITE_PRIV_DETECTED_MAPPINGS,
)

if TYPE_CHECKING:
    # Type-only import; psycopg is in the [sql-postgres] optional
    # extra. The runtime import is lazy in __init__ so that the
    # package itself loads without psycopg installed.
    import psycopg  # noqa: F401


_log = get_logger("evidentia.collectors.sql.postgres")

COLLECTOR_ID = "sql-postgres-scan"


# ── Typed exception hierarchy ──────────────────────────────────────


class PostgresCollectorError(Exception):
    """Base class for all PostgreSQL collector failures."""


class PostgresConnectionError(PostgresCollectorError):
    """Connection / authentication / TLS handshake failure."""


class PostgresQueryError(PostgresCollectorError):
    """A specific SQL query failed (permission denied, missing
    extension, malformed, etc.). The collector continues with
    remaining queries; this error is recorded in the manifest."""


# ── BLIND_SPOTS list ────────────────────────────────────────────────

BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "EVIDENTIA-POSTGRES-FILESYSTEM-TDE",
        "title": "Encryption-at-rest is filesystem-level only",
        "description": (
            "PostgreSQL has no built-in transparent data encryption "
            "(TDE). Encryption-at-rest relies on the underlying "
            "filesystem (LUKS / dm-crypt) or managed-service storage "
            "encryption (AWS RDS / Azure Database for Postgres). The "
            "collector reports the SSL/TLS in-transit posture but "
            "cannot directly attest in-rest encryption from inside "
            "the database. Operators MUST document filesystem-level "
            "encryption out-of-band for SC-28 compliance."
        ),
    },
    {
        "id": "EVIDENTIA-POSTGRES-PG-HBA-FILE-ACCESS",
        "title": "pg_hba.conf rules require filesystem read access",
        "description": (
            "pg_hba.conf encodes host-based authentication rules "
            "(which client/IP can connect with which auth method). "
            "These rules are AC-3 evidence but live on the server's "
            "filesystem. The collector cannot read them through SQL "
            "alone — operators must surface them out-of-band (file "
            "copy, infrastructure-as-code repo, or DB-server-side "
            "evidence collector that has filesystem access)."
        ),
    },
    {
        "id": "EVIDENTIA-POSTGRES-PGAUDIT-EXTENSION",
        "title": "pgaudit configuration requires extension+role grants",
        "description": (
            "The pgaudit extension provides session + object audit "
            "logging beyond Postgres's built-in log_statement. "
            "Detecting whether pgaudit is INSTALLED is straightforward "
            "(query pg_extension); inspecting its configuration "
            "requires SUPERUSER or specific grants the read-only "
            "principal won't have. The collector reports presence + "
            "version; configuration evidence requires a separate "
            "elevated principal."
        ),
    },
    {
        "id": "EVIDENTIA-POSTGRES-CLOUD-MANAGED",
        "title": "Cloud-managed Postgres exposes a subset of pg_settings",
        "description": (
            "AWS RDS, Azure Database for PostgreSQL, GCP Cloud SQL, "
            "and other managed services restrict access to certain "
            "pg_settings parameters (some return SQLSTATE 42501 / "
            "permission denied). The collector handles these "
            "gracefully — missing settings are recorded as INDETERMINATE "
            "findings rather than treated as misconfigurations."
        ),
    },
]


# ── Main collector class ────────────────────────────────────────────


class PostgresCollector:
    """Read-only PostgreSQL evidence collector.

    Construct with a ``connection_uri`` (no embedded password) +
    ``password=`` kwarg. Optionally pass an injected ``connection=``
    object for testing.

    Use as a context manager so the connection is closed cleanly::

        with PostgresCollector(connection_uri="postgres://reader@db/app",
                               password=os.environ["EVIDENTIA_POSTGRES_PASSWORD"]) as c:
            findings, manifest = c.collect_v2()
    """

    def __init__(
        self,
        *,
        connection_uri: str | None = None,
        password: str | None = None,
        connection: Any | None = None,
    ) -> None:
        if not connection_uri and connection is None:
            raise PostgresCollectorError(
                "PostgresCollector requires either connection_uri= or "
                "connection= (an injected psycopg.Connection for testing)."
            )
        if connection_uri and "://" in connection_uri:
            # Reject embedded passwords per CLAUDE.md secret-handling
            # protocol — the URI may carry user + host + dbname only;
            # the password MUST come from a separate kwarg.
            #
            # Detection: postgres://user:PASSWORD@host/db has a colon
            # between the user and the @host segment. We allow the
            # forms postgres://user@host/db and postgres://host/db.
            authority = connection_uri.split("://", 1)[1].split("/", 1)[0]
            if "@" in authority:
                userinfo = authority.split("@", 1)[0]
                if ":" in userinfo:
                    raise PostgresCollectorError(
                        "connection_uri must NOT embed a password. "
                        "Pass the password via the password= kwarg, "
                        "sourced from EVIDENTIA_POSTGRES_PASSWORD env var."
                    )
        self._connection_uri = connection_uri
        self._password = password
        self._connection = connection
        self._owns_connection = connection is None
        # Cached on first call to test_connection() — reduces
        # round-trips during a single collect() invocation.
        self._cached_user: str | None = None
        self._cached_db: str | None = None
        self._cached_version: str | None = None

    # ── Lifecycle ───────────────────────────────────────────────────

    def __enter__(self) -> PostgresCollector:
        self._ensure_connected()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_connection and self._connection is not None:
            with contextlib.suppress(Exception):
                self._connection.close()
            self._connection = None

    def _ensure_connected(self) -> Any:
        """Lazy-connect on first use. Returns the connection object."""
        if self._connection is not None:
            return self._connection
        try:
            import psycopg
        except ImportError as e:
            raise PostgresCollectorError(
                "psycopg is not installed. Install via the "
                "[sql-postgres] extra: "
                'pip install "evidentia-collectors[sql-postgres]"'
            ) from e

        kwargs: dict[str, Any] = {"autocommit": True}
        if self._password is not None:
            kwargs["password"] = self._password
        # __init__ requires a URI unless a connection was injected.
        assert self._connection_uri is not None
        try:
            self._connection = psycopg.connect(
                self._connection_uri,
                **kwargs,
            )
        except Exception as e:
            raise PostgresConnectionError(
                f"Could not connect to Postgres (driver: {type(e).__name__})"
            ) from e
        return self._connection

    # ── Context + provenance ────────────────────────────────────────

    def _build_context(self, run_id: str) -> CollectionContext:
        # Identify the principal + DB for the audit trail. Cached
        # values populated by test_connection() if available; fall
        # back to "unknown" so context is always emittable.
        user = self._cached_user or "unknown"
        db = self._cached_db or "unknown"
        return CollectionContext(
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            run_id=run_id,
            credential_identity=f"postgres-user:{user}",
            source_system_id=f"postgres:{user}@{db}",
            filter_applied={"user": user, "database": db},
        )

    def test_connection(self) -> dict[str, Any]:
        """Probe the connection + cache user / database / version.

        Returns a dict with ``user``, ``database``, ``version``,
        ``read_only`` (bool), ``can_create_temp_table`` (bool).
        """
        conn = self._ensure_connected()
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT current_user, current_database(), version()"
            )
            row = cur.fetchone()
            self._cached_user = str(row[0]) if row else None
            self._cached_db = str(row[1]) if row else None
            self._cached_version = str(row[2]) if row else None
        finally:
            cur.close()

        # Read-only probe — see _check_write_privilege() for full logic.
        read_only, can_create_temp = self._probe_write_privilege(conn)

        return {
            "user": self._cached_user,
            "database": self._cached_db,
            "version": self._cached_version,
            "read_only": read_only,
            "can_create_temp_table": can_create_temp,
        }

    def _probe_write_privilege(self, conn: Any) -> tuple[bool, bool]:
        """Two-phase write-privilege probe.

        Phase 1: read ``default_transaction_read_only`` setting. If
        true, the principal is configured read-only at the role level
        (the strongest signal).

        Phase 2: attempt ``CREATE TEMP TABLE`` in a sub-transaction +
        roll back. If it succeeds, the principal has write privilege
        in this session even if Phase 1 said read-only.

        Returns ``(read_only_setting_true, create_temp_succeeded)``.
        """
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT current_setting('default_transaction_read_only', true)"
            )
            row = cur.fetchone()
            read_only_val = str(row[0]).lower() if row and row[0] else "off"
            read_only_setting = read_only_val in {"on", "true", "1"}

            # Sub-transaction so a failure doesn't poison the parent
            # connection. We always rollback regardless of outcome —
            # we don't want to leave a temp table behind even if the
            # CREATE somehow committed.
            create_temp_succeeded = False
            try:
                cur.execute("SAVEPOINT evidentia_priv_probe")
                cur.execute(
                    "CREATE TEMP TABLE evidentia_priv_probe_temp "
                    "(id int) ON COMMIT DROP"
                )
                create_temp_succeeded = True
                cur.execute("ROLLBACK TO SAVEPOINT evidentia_priv_probe")
                cur.execute("RELEASE SAVEPOINT evidentia_priv_probe")
            except Exception:
                # Permission denied is expected for a read-only
                # principal. Any other error here also means we
                # couldn't write — treat as read-only.
                try:
                    cur.execute(
                        "ROLLBACK TO SAVEPOINT evidentia_priv_probe"
                    )
                    cur.execute(
                        "RELEASE SAVEPOINT evidentia_priv_probe"
                    )
                except Exception:
                    pass

            return read_only_setting, create_temp_succeeded
        finally:
            cur.close()

    # ── High-level orchestration ────────────────────────────────────

    def collect(self, *, dry_run: bool = False) -> list[SecurityFinding]:
        """Run every sub-check and return the merged findings list.

        Backward-compatible v0.6 API. Callers wanting the manifest
        should use :meth:`collect_v2`.
        """
        if dry_run:
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message="Postgres dry-run — no DB calls made",
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
        """Enterprise-grade orchestrator. Returns ``(findings, manifest)``."""
        run_id = new_run_id()
        started_at = utc_now()

        # test_connection populates _cached_user/_cached_db before
        # the context is built so the credential_identity is real.
        try:
            probe = self.test_connection()
        except PostgresCollectorError:
            raise
        except Exception as e:
            raise PostgresConnectionError(
                f"Could not establish + probe Postgres connection: {e}"
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
                    f"Postgres collection starting for "
                    f"{self._cached_user}@{self._cached_db}"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.START],
            )

            # Write-privilege violation — emit BEFORE the read-only
            # collection so it appears at the top of the findings list.
            if not probe["read_only"] or probe["can_create_temp_table"]:
                findings.append(
                    self._write_priv_detected_finding(probe, context)
                )

            # Each sub-check is independently fault-tolerant: a
            # PostgresQueryError gets recorded in errors[] and the
            # overall collection continues. This way a single
            # missing-permission failure doesn't block the rest of
            # the evidence.
            conn = self._connection
            assert conn is not None  # _ensure_connected ran above
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
                except PostgresQueryError as e:
                    errors.append(str(e))
                    _log.warning(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=f"Sub-check {sub_check.__name__} failed: {e}",
                        error={
                            "type": "PostgresQueryError",
                            "message": str(e),
                        },
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
                    f"Postgres collection completed: {len(findings)} findings"
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
                f"postgres:{self._cached_user}@{self._cached_db}"
            ],
            filters_applied={
                "user": self._cached_user or "unknown",
                "database": self._cached_db or "unknown",
            },
            coverage_counts=[
                CoverageCount(
                    resource_type="postgres-database",
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
                f"Postgres principal {self._cached_user!r} has write "
                "privilege"
            ),
            description=(
                f"The collector's principal ({self._cached_user}) "
                f"connected to {self._cached_db} with write capability "
                "detected via the read-only probe ("
                f"default_transaction_read_only="
                f"{probe['read_only']!r}, can_create_temp_table="
                f"{probe['can_create_temp_table']!r}). "
                "Production deployments should grant the collector a "
                "read-only DB role; write privilege violates the "
                "least-privilege principle (NIST AC-6) and increases "
                "the blast radius of credential compromise."
            ),
            severity=Severity.MEDIUM,
            status=FindingStatus.ACTIVE,
            # v0.10.0: write privilege on the audit principal is a
            # failed least-privilege check.
            compliance_status=ComplianceStatus.FAIL,
            source_system="postgres",
            source_finding_id=(
                f"EVIDENTIA-WRITE-PRIV-DETECTED:{self._cached_user}@"
                f"{self._cached_db}"
            ),
            resource_type="Postgres::Principal",
            resource_id=str(self._cached_user or "unknown"),
            control_ids=[m.control_id for m in WRITE_PRIV_DETECTED_MAPPINGS],
            collection_context=context,
            raw_data={
                "default_transaction_read_only": probe["read_only"],
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
                    "SELECT rolname, rolsuper, rolcreaterole, "
                    "rolcreatedb, rolcanlogin, rolreplication "
                    "FROM pg_roles ORDER BY rolname"
                )
                rows = cur.fetchall()
            except Exception as e:
                raise PostgresQueryError(
                    f"Could not enumerate pg_roles: {e}"
                ) from e

            superusers = [r[0] for r in rows if r[1]]
            login_roles = [r[0] for r in rows if r[4]]
            return [
                SecurityFinding(
                    title=(
                        f"Postgres role inventory: {len(rows)} roles, "
                        f"{len(superusers)} superusers, "
                        f"{len(login_roles)} login-enabled"
                    ),
                    description=(
                        f"Database {self._cached_db!r} has {len(rows)} "
                        "roles defined in pg_roles. Of these, "
                        f"{len(superusers)} have the SUPERUSER "
                        "attribute and "
                        f"{len(login_roles)} can log in directly. "
                        f"Superusers: {', '.join(superusers) or '(none)'}. "
                        "AC-2 evidence — operators should review the "
                        "superuser list against the inventory of "
                        "DBA-tier human + automation principals."
                    ),
                    severity=(
                        Severity.MEDIUM
                        if len(superusers) > 3
                        else Severity.INFORMATIONAL
                    ),
                    status=FindingStatus.ACTIVE,
                    # v0.10.0: a role inventory is informational
                    # evidence, not a pass/fail check.
                    compliance_status=ComplianceStatus.UNKNOWN,
                    source_system="postgres",
                    source_finding_id=(
                        f"role-inventory:{self._cached_db}"
                    ),
                    resource_type="Postgres::Database",
                    resource_id=str(self._cached_db or "unknown"),
                    control_ids=[
                        m.control_id for m in USER_ROLE_INVENTORY_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={
                        "total_roles": len(rows),
                        "superusers": superusers,
                        "login_roles_count": len(login_roles),
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
                    "SELECT grantee, COUNT(*) AS grant_count "
                    "FROM information_schema.table_privileges "
                    "WHERE grantee NOT IN ('postgres', 'PUBLIC') "
                    "GROUP BY grantee ORDER BY grant_count DESC LIMIT 20"
                )
                rows = cur.fetchall()
            except Exception as e:
                raise PostgresQueryError(
                    f"Could not enumerate information_schema.table_privileges: {e}"
                ) from e

            # JSON-native (list, not tuple) so raw_data round-trips
            # cleanly through serialization and the OCSF mapping layer.
            top_grantees = [[r[0], int(r[1])] for r in rows]
            return [
                SecurityFinding(
                    title=(
                        f"Postgres privilege grants: {len(rows)} grantees "
                        "with table-level privileges"
                    ),
                    description=(
                        f"information_schema.table_privileges shows "
                        f"{len(rows)} non-system grantees with "
                        "table-level privileges in "
                        f"{self._cached_db!r}. Top grantees: "
                        f"{top_grantees[:5]}. "
                        "AC-3 / AC-6 evidence — operators should "
                        "confirm each grantee maps to an authorized "
                        "principal and that grants follow least-"
                        "privilege scope."
                    ),
                    severity=Severity.INFORMATIONAL,
                    status=FindingStatus.ACTIVE,
                    # v0.10.0: a privilege-grant inventory is
                    # informational evidence, not a pass/fail check.
                    compliance_status=ComplianceStatus.UNKNOWN,
                    source_system="postgres",
                    source_finding_id=(
                        f"privilege-grants:{self._cached_db}"
                    ),
                    resource_type="Postgres::Database",
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
        settings = self._read_pg_settings(
            conn,
            [
                "log_connections",
                "log_disconnections",
                "log_statement",
                "log_line_prefix",
                "log_destination",
            ],
        )

        # pgaudit detection (best-effort; non-fatal on permission denied)
        pgaudit_installed = self._extension_installed(conn, "pgaudit")

        # Audit-log gaps drive the severity:
        # log_connections=off OR log_disconnections=off → AU-2 gap
        # log_statement='none' → AU-2 gap
        # pgaudit absent on a regulated-DB pattern → MEDIUM
        gaps: list[str] = []
        if settings.get("log_connections", "").lower() == "off":
            gaps.append("log_connections=off")
        if settings.get("log_disconnections", "").lower() == "off":
            gaps.append("log_disconnections=off")
        if settings.get("log_statement", "").lower() == "none":
            gaps.append("log_statement=none")

        severity = Severity.MEDIUM if gaps else Severity.INFORMATIONAL
        status = FindingStatus.ACTIVE if gaps else FindingStatus.RESOLVED

        return [
            SecurityFinding(
                title=(
                    "Postgres audit-log configuration: "
                    f"{'gaps detected' if gaps else 'baseline OK'}"
                ),
                description=(
                    "Postgres audit-log evidence per AU-2 + AU-3. "
                    f"Settings: {settings}. "
                    f"pgaudit extension installed: {pgaudit_installed}. "
                    + (
                        "Gaps: " + ", ".join(gaps) + ". "
                        if gaps
                        else "No common gaps detected. "
                    )
                    + "Operators should confirm log destination "
                    "(syslog / file / csvlog) routes to a tamper-"
                    "evident sink for full AU-2 compliance."
                ),
                severity=severity,
                status=status,
                # v0.10.0: audit-log gaps fail the AU-2/AU-3 check;
                # a clean baseline passes.
                compliance_status=ComplianceStatus.FAIL
                if gaps
                else ComplianceStatus.PASS,
                source_system="postgres",
                source_finding_id=f"audit-log:{self._cached_db}",
                resource_type="Postgres::Database",
                resource_id=str(self._cached_db or "unknown"),
                control_ids=[m.control_id for m in AUDIT_LOG_MAPPINGS],
                collection_context=context,
                raw_data={
                    "settings": settings,
                    "pgaudit_installed": pgaudit_installed,
                    "gaps": gaps,
                },
            )
        ]

    def _crypto_config_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        settings = self._read_pg_settings(
            conn,
            [
                "password_encryption",
                "ssl",
                "ssl_min_protocol_version",
                "ssl_ciphers",
            ],
        )

        # Modern Postgres should be scram-sha-256 (post-10).
        # md5 is deprecated; plain is unsafe.
        password_enc = settings.get("password_encryption", "").lower()
        is_secure_hash = password_enc in {"scram-sha-256"}
        ssl_on = settings.get("ssl", "").lower() in {"on", "true"}

        gaps: list[str] = []
        if not is_secure_hash:
            gaps.append(
                f"password_encryption={password_enc!r} (should be scram-sha-256)"
            )
        if not ssl_on:
            gaps.append("ssl=off (TLS not enabled at server)")

        severity = Severity.HIGH if gaps else Severity.INFORMATIONAL
        status = FindingStatus.ACTIVE if gaps else FindingStatus.RESOLVED

        return [
            SecurityFinding(
                title=(
                    "Postgres crypto configuration: "
                    f"{'gaps detected' if gaps else 'baseline OK'}"
                ),
                description=(
                    f"Postgres SC-12 evidence: password_encryption="
                    f"{password_enc!r}, ssl={settings.get('ssl', '?')!r}, "
                    f"ssl_min_protocol_version="
                    f"{settings.get('ssl_min_protocol_version', '?')!r}. "
                    + (
                        "Gaps: " + ", ".join(gaps) + ". "
                        if gaps
                        else ""
                    )
                    + "scram-sha-256 is the modern minimum; md5 + plain "
                    "are insecure. ssl=on is required for in-transit "
                    "protection. ssl_min_protocol_version SHOULD be "
                    "TLSv1.2 or higher."
                ),
                severity=severity,
                status=status,
                # v0.10.0: crypto-config gaps fail the SC-12 check;
                # a clean baseline passes.
                compliance_status=ComplianceStatus.FAIL
                if gaps
                else ComplianceStatus.PASS,
                source_system="postgres",
                source_finding_id=f"crypto-config:{self._cached_db}",
                resource_type="Postgres::Database",
                resource_id=str(self._cached_db or "unknown"),
                control_ids=[m.control_id for m in CRYPTO_CONFIG_MAPPINGS],
                collection_context=context,
                raw_data={"settings": settings, "gaps": gaps},
            )
        ]

    def _encryption_at_rest_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        # Postgres has no built-in TDE — see BLIND_SPOTS. We surface
        # this as an INFORMATIONAL finding so auditors see the gap
        # acknowledged + the operator's documented mitigation can be
        # cross-referenced.
        return [
            SecurityFinding(
                title=(
                    "Postgres encryption-at-rest evidence is filesystem-level"
                ),
                description=(
                    "Postgres has no built-in transparent data "
                    "encryption (TDE). Encryption-at-rest must be "
                    "asserted at the filesystem layer (LUKS / dm-crypt) "
                    "or via the managed-service storage encryption "
                    "(AWS RDS storage encryption, Azure Database for "
                    "Postgres encryption-at-rest, GCP Cloud SQL CMEK). "
                    "The collector cannot directly attest in-rest "
                    "encryption from inside the database. SC-28 "
                    "evidence requires out-of-band documentation. "
                    "See BLIND_SPOT EVIDENTIA-POSTGRES-FILESYSTEM-TDE."
                ),
                severity=Severity.INFORMATIONAL,
                status=FindingStatus.ACTIVE,
                # v0.10.0: encryption-at-rest cannot be attested from
                # inside Postgres (a documented blind spot) — UNKNOWN.
                compliance_status=ComplianceStatus.UNKNOWN,
                source_system="postgres",
                source_finding_id=(
                    f"encryption-at-rest-blind-spot:{self._cached_db}"
                ),
                resource_type="Postgres::Database",
                resource_id=str(self._cached_db or "unknown"),
                control_ids=[
                    m.control_id for m in ENCRYPTION_AT_REST_MAPPINGS
                ],
                collection_context=context,
                raw_data={
                    "blind_spot_id": "EVIDENTIA-POSTGRES-FILESYSTEM-TDE",
                },
            )
        ]

    def _connection_limit_findings(
        self, conn: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        settings = self._read_pg_settings(
            conn,
            ["max_connections", "superuser_reserved_connections"],
        )
        try:
            max_conn = int(settings.get("max_connections", "0"))
        except (TypeError, ValueError):
            max_conn = 0

        return [
            SecurityFinding(
                title=(
                    f"Postgres connection limits: max_connections={max_conn}"
                ),
                description=(
                    f"max_connections={max_conn}, "
                    "superuser_reserved_connections="
                    f"{settings.get('superuser_reserved_connections', '?')!r}. "
                    "AC-3 evidence — operators should confirm the "
                    "limit matches the planned client-pool size + "
                    "leaves room for an emergency superuser session. "
                    "pg_hba.conf rules (host-based auth) live on the "
                    "filesystem and require out-of-band collection — "
                    "see BLIND_SPOT EVIDENTIA-POSTGRES-PG-HBA-FILE-ACCESS."
                ),
                severity=Severity.INFORMATIONAL,
                status=FindingStatus.ACTIVE,
                # v0.10.0: connection-limit settings are informational
                # evidence, not a pass/fail check.
                compliance_status=ComplianceStatus.UNKNOWN,
                source_system="postgres",
                source_finding_id=f"connection-limits:{self._cached_db}",
                resource_type="Postgres::Database",
                resource_id=str(self._cached_db or "unknown"),
                control_ids=[
                    m.control_id for m in CONNECTION_LIMIT_MAPPINGS
                ],
                collection_context=context,
                raw_data={"settings": settings, "max_connections": max_conn},
            )
        ]

    # ── Helpers ─────────────────────────────────────────────────────

    def _read_pg_settings(
        self, conn: Any, keys: list[str]
    ) -> dict[str, str]:
        """Bulk-read pg_settings rows; missing keys map to empty
        string. Permission-denied on a key yields an empty string for
        that key (cloud-managed Postgres restricts certain settings)."""
        cur = conn.cursor()
        result: dict[str, str] = {k: "" for k in keys}
        try:
            placeholders = ",".join(["%s"] * len(keys))
            try:
                cur.execute(
                    f"SELECT name, setting FROM pg_settings "
                    f"WHERE name IN ({placeholders})",
                    keys,
                )
                for row in cur.fetchall():
                    result[str(row[0])] = str(row[1])
            except Exception:
                # Fall back to per-setting current_setting() with
                # missing_ok so we get partial coverage. Each failure
                # leaves an empty string for that key.
                for key in keys:
                    try:
                        cur.execute(
                            "SELECT current_setting(%s, true)", (key,)
                        )
                        row = cur.fetchone()
                        if row and row[0] is not None:
                            result[key] = str(row[0])
                    except Exception:
                        continue
            return result
        finally:
            cur.close()

    def _extension_installed(self, conn: Any, ext_name: str) -> bool:
        cur = conn.cursor()
        try:
            try:
                cur.execute(
                    "SELECT 1 FROM pg_extension WHERE extname = %s",
                    (ext_name,),
                )
                return cur.fetchone() is not None
            except Exception:
                return False
        finally:
            cur.close()
