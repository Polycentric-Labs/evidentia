"""Docker-based integration tests for SQL collectors (v0.7.7).

Each test file under this directory uses ``@pytest.mark.integration``
and spins up a real Postgres / MySQL / MSSQL / Oracle container via
``docker run`` (no testcontainers / pytest-docker dependency — these
tests are intentionally heavyweight and rare). Skipped on the
default test run; CI's ``test.yml`` runs them in a separate job.

To run locally:

    uv run pytest tests/integration/test_sql/ -m integration

Requires ``docker`` on PATH. Tests skip cleanly when Docker is
unavailable.
"""
