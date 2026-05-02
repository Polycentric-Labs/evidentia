"""SQL-family evidence collectors (v0.7.7).

Per-adapter sub-packages under this namespace:

- ``evidentia_collectors.sql.postgres`` — PostgreSQL (v0.7.7 P0.1)
- ``evidentia_collectors.sql.mysql`` — MySQL/MariaDB (v0.7.7 P0.2; planned)
- ``evidentia_collectors.sql.sqlite`` — SQLite (v0.7.7 P0.3; planned)
- ``evidentia_collectors.sql.mssql`` — MS SQL Server (v0.7.7 P0.4; planned)
- ``evidentia_collectors.sql.oracle`` — Oracle Database (v0.7.7 P0.5; planned)

Each adapter is gated behind an optional dependency. To use the
PostgreSQL collector::

    pip install "evidentia-collectors[sql-postgres]"

    from evidentia_collectors.sql.postgres import PostgresCollector

The umbrella ``[sql]`` extra installs all five adapter drivers in
one shot::

    pip install "evidentia-collectors[sql]"

All adapters are **read-only by design**. They run a write-privilege
verification probe on first connect; if write privilege is detected,
the adapter emits an ``EVIDENTIA-WRITE-PRIV-DETECTED`` finding mapped
to NIST AC-6 (least privilege violation) and continues read-only
collection. Production deployments should grant the adapter a
read-only DB principal explicitly.
"""
