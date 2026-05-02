"""MySQL / MariaDB evidence collector for Evidentia (v0.7.7 P0.2).

Read-only collector that surfaces compliance-relevant evidence from a
running MySQL or MariaDB instance: user + role inventory (AC-2),
privilege grants (AC-3, AC-6), audit-log + general-log status
(AU-2, AU-3), TLS / require_secure_transport (SC-12), InnoDB
tablespace encryption (SC-28), and connection limits (AC-3).

Public surface::

    from evidentia_collectors.sql.mysql import MySQLCollector

    collector = MySQLCollector(
        connection_uri="mysql://reader@db.example.com:3306/app",
        password=os.environ["EVIDENTIA_MYSQL_PASSWORD"],
    )
    findings = collector.collect()

Or via context manager::

    with MySQLCollector(connection_uri=...) as c:
        findings, manifest = c.collect_v2()

Credentials per `~/.claude/CLAUDE.md` secret-handling protocol:

- The connection URI MAY include the username + database + host but
  MUST NOT include the password. Pass the password via the
  ``password=`` constructor kwarg, sourced from the
  ``EVIDENTIA_MYSQL_PASSWORD`` environment variable.

Required principal privileges:

- ``SELECT`` on ``mysql.user`` + ``mysql.role_edges`` (8.0+)
- ``SELECT`` on ``information_schema.user_privileges``,
  ``information_schema.schema_privileges``,
  ``information_schema.table_privileges``
- ``SHOW VARIABLES`` (default access)
- For the read-only verification probe to pass cleanly, the
  principal SHOULD lack write privileges. If it has write privs the
  collector still works but emits an
  ``EVIDENTIA-WRITE-PRIV-DETECTED`` finding mapped to NIST AC-6.

Driver: ``PyMySQL>=1.1`` (pure-Python). Install via the
``[sql-mysql]`` extra. MariaDB is supported via the same wire
protocol; both 5.7+ MySQL and 10.x+ MariaDB tested.
"""

from evidentia_collectors.sql.mysql.collector import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    MySQLCollector,
    MySQLCollectorError,
    MySQLConnectionError,
    MySQLQueryError,
)

__all__ = [
    "BLIND_SPOTS",
    "COLLECTOR_ID",
    "MySQLCollector",
    "MySQLCollectorError",
    "MySQLConnectionError",
    "MySQLQueryError",
]
