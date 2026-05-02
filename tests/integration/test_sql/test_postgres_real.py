"""Integration test: PostgresCollector against a real Postgres container.

Spins up postgres:16-alpine via ``docker run``, seeds it with a
compliance-relevant fixture schema (a `users` table + a read-only
role), runs the collector end-to-end, asserts findings shape +
NIST control coverage. Tears down at module exit.

Marked ``@pytest.mark.integration`` — skipped on the default test
run (``uv run pytest -q``). Run with::

    uv run pytest tests/integration/test_sql/test_postgres_real.py -m integration

Skips cleanly when Docker is unavailable.

NOTE: psycopg[binary]>=3.1 must be installed
(``pip install 'evidentia-collectors[sql-postgres]'``).
"""

from __future__ import annotations

import shutil
import subprocess
import time
import uuid

import pytest
from evidentia_collectors.sql.postgres import (
    PostgresCollector,
    PostgresCollectorError,
)

pytestmark = pytest.mark.integration


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _wait_for_postgres(port: int, password: str, timeout_s: int = 30) -> bool:
    """Poll the Postgres port until it accepts connections."""
    try:
        import psycopg
    except ImportError:
        return False

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            conn = psycopg.connect(
                f"postgres://postgres@127.0.0.1:{port}/postgres",
                password=password,
                connect_timeout=2,
            )
            conn.close()
            return True
        except Exception:
            time.sleep(1)
    return False


@pytest.fixture(scope="module")
def postgres_container() -> dict[str, str]:
    """Start postgres:16-alpine on a random port; tear down at end."""
    if not _docker_available():
        pytest.skip("Docker not available on PATH")

    try:
        import psycopg
    except ImportError:
        pytest.skip("psycopg not installed; install via [sql-postgres] extra")

    container_name = f"evidentia-pg-it-{uuid.uuid4().hex[:8]}"
    password = "evidentia_test_pwd"
    # Random ephemeral port via Docker's host-port-0 = OS-picks-free
    proc = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            container_name,
            "-e",
            f"POSTGRES_PASSWORD={password}",
            "-p",
            "0:5432",
            "postgres:16-alpine",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        pytest.skip(f"Could not start postgres container: {proc.stderr}")

    # Look up the host-side port docker assigned
    inspect = subprocess.run(
        ["docker", "port", container_name, "5432/tcp"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if inspect.returncode != 0 or "0.0.0.0:" not in inspect.stdout:
        subprocess.run(
            ["docker", "stop", container_name], capture_output=True, timeout=10
        )
        pytest.skip(f"Could not resolve postgres port: {inspect.stdout}")
    port_line = inspect.stdout.strip().splitlines()[0]
    port = int(port_line.rsplit(":", 1)[1])

    if not _wait_for_postgres(port, password):
        subprocess.run(
            ["docker", "stop", container_name], capture_output=True, timeout=10
        )
        pytest.skip(f"Postgres did not become ready on port {port} within timeout")

    # Seed: create a read-only role with no write privilege
    import psycopg
    conn = psycopg.connect(
        f"postgres://postgres@127.0.0.1:{port}/postgres",
        password=password,
        autocommit=True,
    )
    cur = conn.cursor()
    # NOTE: DDL statements (CREATE ROLE / TABLE / etc.) don't support
    # %s parameter binding in psycopg. The reader_pwd literal is a
    # test fixture only — never a real credential — so inline-quoting
    # is acceptable here. (For non-DDL queries we still use bound
    # parameters; e.g., the GRANT below uses an identifier, not a
    # password.)
    cur.execute(
        "CREATE ROLE evidentia_reader WITH LOGIN PASSWORD 'reader_pwd' "
        "CONNECTION LIMIT 5"
    )
    cur.execute(
        "ALTER ROLE evidentia_reader SET default_transaction_read_only = on"
    )
    cur.execute("CREATE TABLE compliance_users (id int, role text)")
    cur.execute(
        "INSERT INTO compliance_users VALUES (1, 'admin'), (2, 'auditor'), (3, 'app')"
    )
    cur.execute("GRANT SELECT ON compliance_users TO evidentia_reader")
    cur.close()
    conn.close()

    yield {
        "container_name": container_name,
        "port": str(port),
        "superuser_uri": f"postgres://postgres@127.0.0.1:{port}/postgres",
        "superuser_password": password,
        "reader_uri": f"postgres://evidentia_reader@127.0.0.1:{port}/postgres",
        "reader_password": "reader_pwd",
    }

    subprocess.run(
        ["docker", "stop", container_name],
        capture_output=True,
        timeout=10,
    )


def test_collector_reads_real_postgres(
    postgres_container: dict[str, str],
) -> None:
    """End-to-end smoke: read-only principal, full collect_v2 run."""
    with PostgresCollector(
        connection_uri=postgres_container["reader_uri"],
        password=postgres_container["reader_password"],
    ) as collector:
        findings, manifest = collector.collect_v2()

    assert manifest.collector_id == "sql-postgres-scan"
    assert manifest.is_complete is True
    assert manifest.total_findings == len(findings)
    assert len(findings) >= 5

    # Every finding carries provenance
    for f in findings:
        assert f.collection_context is not None
        assert f.collection_context.collector_id == "sql-postgres-scan"

    # NIST coverage spans the full SC + AC + AU expected set
    controls = {c for f in findings for c in (f.control_ids or [])}
    assert "AC-2" in controls
    assert "AC-3" in controls
    assert "AU-2" in controls
    assert "SC-12" in controls
    assert "SC-28" in controls

    # The read-only role doesn't have superuser-level role enumeration
    # access in vanilla pg, so the role-inventory finding should still
    # come through (pg_roles is queryable by any role). At minimum
    # the postgres superuser shows up.
    role_findings = [
        f for f in findings if "role-inventory" in (f.source_finding_id or "")
    ]
    assert len(role_findings) == 1
    raw = role_findings[0].raw_data or {}
    assert int(raw.get("total_roles", 0)) >= 2


def test_write_priv_principal_emits_finding(
    postgres_container: dict[str, str],
) -> None:
    """Connect as the superuser (write privilege) → write-priv finding fires."""
    with PostgresCollector(
        connection_uri=postgres_container["superuser_uri"],
        password=postgres_container["superuser_password"],
    ) as collector:
        findings, _manifest = collector.collect_v2()

    write_priv = [
        f
        for f in findings
        if "WRITE-PRIV-DETECTED" in (f.source_finding_id or "")
    ]
    assert len(write_priv) == 1, (
        "Superuser principal should fire EVIDENTIA-WRITE-PRIV-DETECTED"
    )
    # AC-6 mapping
    assert "AC-6" in (write_priv[0].control_ids or [])


def test_rejects_embedded_password_in_real_uri(
    postgres_container: dict[str, str],
) -> None:
    """Constructor refuses a URI with embedded password even when
    pointed at a real Postgres."""
    bad_uri = (
        f"postgres://postgres:{postgres_container['superuser_password']}"
        f"@127.0.0.1:{postgres_container['port']}/postgres"
    )
    with pytest.raises(PostgresCollectorError, match="must NOT embed a password"):
        PostgresCollector(connection_uri=bad_uri)
