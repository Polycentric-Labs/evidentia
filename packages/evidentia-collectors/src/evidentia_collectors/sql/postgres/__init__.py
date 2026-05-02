"""PostgreSQL evidence collector for Evidentia (v0.7.7 P0.1).

Read-only collector that surfaces compliance-relevant evidence from a
running PostgreSQL instance: user + role inventory (AC-2), privilege
grants (AC-3, AC-6), audit-log configuration (AU-2, AU-3), encryption
+ TLS posture (SC-12, SC-28), and connection limits (AC-3).

Public surface::

    from evidentia_collectors.sql.postgres import PostgresCollector

    collector = PostgresCollector(
        connection_uri="postgresql://reader@db.example.com/app",
        password=os.environ["EVIDENTIA_POSTGRES_PASSWORD"],
    )
    findings = collector.collect()
    # -> list[SecurityFinding]

Or via context manager (recommended; cleans up the connection)::

    with PostgresCollector(connection_uri=...) as c:
        findings, manifest = c.collect_v2()

Credentials per `~/.claude/CLAUDE.md` secret-handling protocol:

- The connection URI MAY include the username + database + host but
  MUST NOT include the password. Pass the password via the
  ``password=`` constructor kwarg, sourced from the
  ``EVIDENTIA_POSTGRES_PASSWORD`` environment variable.
- The CLI + REST surfaces enforce this — they will refuse a URI with
  an embedded password.

Required principal privileges:

- ``CONNECT`` on the target database
- ``SELECT`` on system catalogs: ``pg_roles``, ``pg_authid``,
  ``pg_auth_members``, ``pg_settings``, ``information_schema.*``
- For the read-only verification probe to pass cleanly, the
  principal SHOULD lack write privileges. If it has write privs the
  collector still works but emits an ``EVIDENTIA-WRITE-PRIV-DETECTED``
  finding mapped to NIST AC-6.

Driver: ``psycopg[binary]>=3.1`` (psycopg 3.x). Install via the
``[sql-postgres]`` extra.
"""

from evidentia_collectors.sql.postgres.collector import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    PostgresCollector,
    PostgresCollectorError,
    PostgresConnectionError,
    PostgresQueryError,
)

__all__ = [
    "BLIND_SPOTS",
    "COLLECTOR_ID",
    "PostgresCollector",
    "PostgresCollectorError",
    "PostgresConnectionError",
    "PostgresQueryError",
]
