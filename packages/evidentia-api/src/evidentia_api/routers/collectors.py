"""Collectors router — AWS + GitHub evidence endpoints.

All endpoints are POST-only — running a collector has non-trivial
side-effects (AWS API calls, GitHub rate limits) so a GET shouldn't
trigger them. Response is a list of :class:`SecurityFinding` objects.

Credentials:
- AWS: boto3's standard chain (env, ~/.aws/credentials, instance profile)
- GitHub: $GITHUB_TOKEN environment variable on the server

No credential values ever flow through request/response bodies.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from evidentia_core.models.finding import SecurityFinding
from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/collectors/aws/collect", response_model=list[SecurityFinding])
async def aws_collect(payload: dict[str, Any] | None = None) -> list[SecurityFinding]:
    """Run the AWS collector (Config + Security Hub).

    Request body (optional):

    - ``region``: override region
    - ``profile``: optional AWS profile name
    - ``include_config``: bool (default True)
    - ``include_security_hub``: bool (default True)
    """
    try:
        from evidentia_collectors.aws import AwsCollector, AwsCollectorError
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=(
                "AWS collector not installed. Run "
                "`pip install 'evidentia-collectors[aws]'`."
            ),
        ) from e

    body = payload or {}
    region = body.get("region") if isinstance(body.get("region"), str) else None
    profile = body.get("profile") if isinstance(body.get("profile"), str) else None
    include_config = bool(body.get("include_config", True))
    include_security_hub = bool(body.get("include_security_hub", True))

    try:
        collector = AwsCollector(region=region, profile=profile)
        collector.test_connection()
    except AwsCollectorError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e

    try:
        findings = collector.collect_all(
            include_config=include_config,
            include_security_hub=include_security_hub,
        )
    except Exception as e:
        logger.exception("AWS collector failed")
        raise HTTPException(status_code=500, detail=f"AWS collector failed: {e}") from e

    return findings


@router.post("/collectors/github/collect", response_model=list[SecurityFinding])
async def github_collect(payload: dict[str, Any]) -> list[SecurityFinding]:
    """Run the GitHub collector.

    Request body (required):

    - ``repo``: repository in 'owner/repo' format

    Credentials are sourced from the server's ``$GITHUB_TOKEN`` env var.
    """
    try:
        from evidentia_collectors.github import (
            GitHubApiError,
            GitHubCollector,
            GitHubCollectorError,
        )
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=f"GitHub collector import failed: {e}",
        ) from e

    repo = str(payload.get("repo") or "").strip()
    if "/" not in repo:
        raise HTTPException(
            status_code=400,
            detail="Request body must include 'repo' in 'owner/repo' format.",
        )
    owner, repo_name = repo.split("/", 1)
    token = os.environ.get("GITHUB_TOKEN")

    try:
        with GitHubCollector(
            owner=owner, repo=repo_name, token=token
        ) as collector:
            findings = collector.collect()
    except GitHubCollectorError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except GitHubApiError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e

    return findings


@router.post("/collectors/okta/collect", response_model=list[SecurityFinding])
async def okta_collect(payload: dict[str, Any]) -> list[SecurityFinding]:
    """Run the Okta collector (v0.7.7 C1).

    Request body (required):

    - ``org_url``: ``https://your-org.okta.com``

    Optional:

    - ``inactive_threshold_days``: int, default 90
    - ``max_users``: int, default 10000

    Credentials are sourced from the server's ``$OKTA_API_TOKEN``
    env var. The token MUST be read-only; the request body never
    accepts a token value.
    """
    try:
        from evidentia_collectors.okta import (
            OktaCollector,
            OktaCollectorError,
        )
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=f"Okta collector import failed: {e}",
        ) from e

    org_url = str(payload.get("org_url") or "").strip()
    if not org_url:
        raise HTTPException(
            status_code=400,
            detail="Request body must include 'org_url'.",
        )
    inactive_threshold_days = int(payload.get("inactive_threshold_days") or 90)
    max_users = int(payload.get("max_users") or 10_000)

    api_token = os.environ.get("OKTA_API_TOKEN")
    if api_token is None:
        raise HTTPException(
            status_code=503,
            detail="OKTA_API_TOKEN env var not set on the server.",
        )

    try:
        with OktaCollector(
            org_url=org_url,
            api_token=api_token,
            inactive_threshold_days=inactive_threshold_days,
            max_users=max_users,
        ) as collector:
            findings = collector.collect()
    except OktaCollectorError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except Exception as e:
        logger.exception("Okta collector failed")
        raise HTTPException(
            status_code=500, detail=f"Okta collector failed: {e}"
        ) from e

    return findings


@router.post(
    "/collectors/sql/postgres/collect", response_model=list[SecurityFinding]
)
async def postgres_collect(payload: dict[str, Any]) -> list[SecurityFinding]:
    """Run the PostgreSQL collector (v0.7.7 P0.1).

    Request body (required):

    - ``connection_uri``: Database URI WITHOUT embedded password
      (e.g., ``postgres://reader@db.example.com/app?sslmode=require``).
    - ``password_env``: env-var name to read the password from.
      Default: ``EVIDENTIA_POSTGRES_PASSWORD``. Per CLAUDE.md
      secret-handling protocol, the password value MUST NOT come
      through the request body.

    Response: list of SecurityFinding objects. Read-only by design —
    detected write privilege emits an EVIDENTIA-WRITE-PRIV-DETECTED
    finding mapped to NIST AC-6.
    """
    try:
        from evidentia_collectors.sql.postgres import (
            PostgresCollector,
            PostgresCollectorError,
        )
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=(
                "PostgreSQL collector not installed. Run "
                "`pip install 'evidentia-collectors[sql-postgres]'`."
            ),
        ) from e

    connection_uri = str(payload.get("connection_uri") or "").strip()
    if not connection_uri:
        raise HTTPException(
            status_code=400,
            detail="Request body must include 'connection_uri'.",
        )
    password_env = (
        str(payload.get("password_env") or "EVIDENTIA_POSTGRES_PASSWORD").strip()
        or "EVIDENTIA_POSTGRES_PASSWORD"
    )
    password = os.environ.get(password_env)
    if password is None:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Environment variable {password_env!r} not set on the "
                "server. Set it before invoking this endpoint."
            ),
        )

    try:
        with PostgresCollector(
            connection_uri=connection_uri, password=password
        ) as collector:
            findings = collector.collect()
    except PostgresCollectorError as e:
        # Constructor / auth / connection / TLS failure — 503 because
        # the API surface is up but the upstream DB isn't reachable
        # with the supplied credentials.
        raise HTTPException(status_code=503, detail=str(e)) from e
    except Exception as e:
        logger.exception("Postgres collector failed")
        raise HTTPException(
            status_code=500, detail=f"Postgres collector failed: {e}"
        ) from e

    return findings


@router.post(
    "/collectors/sql/mysql/collect", response_model=list[SecurityFinding]
)
async def mysql_collect(payload: dict[str, Any]) -> list[SecurityFinding]:
    """Run the MySQL / MariaDB collector (v0.7.7 P0.2).

    Request body (required):

    - ``connection_uri``: ``mysql://user@host:3306/dbname`` WITHOUT
      embedded password.
    - ``password_env``: env-var name to read the password from.
      Default: ``EVIDENTIA_MYSQL_PASSWORD``.

    Read-only by design — write privilege fires
    EVIDENTIA-WRITE-PRIV-DETECTED finding mapped to NIST AC-6.
    """
    try:
        from evidentia_collectors.sql.mysql import (
            MySQLCollector,
            MySQLCollectorError,
        )
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=(
                "MySQL collector not installed. Run "
                "`pip install 'evidentia-collectors[sql-mysql]'`."
            ),
        ) from e

    connection_uri = str(payload.get("connection_uri") or "").strip()
    if not connection_uri:
        raise HTTPException(
            status_code=400,
            detail="Request body must include 'connection_uri'.",
        )
    password_env = (
        str(payload.get("password_env") or "EVIDENTIA_MYSQL_PASSWORD").strip()
        or "EVIDENTIA_MYSQL_PASSWORD"
    )
    password = os.environ.get(password_env)
    if password is None:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Environment variable {password_env!r} not set on the "
                "server."
            ),
        )

    try:
        with MySQLCollector(
            connection_uri=connection_uri, password=password
        ) as collector:
            findings = collector.collect()
    except MySQLCollectorError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except Exception as e:
        logger.exception("MySQL collector failed")
        raise HTTPException(
            status_code=500, detail=f"MySQL collector failed: {e}"
        ) from e

    return findings


@router.post(
    "/collectors/sql/mssql/collect", response_model=list[SecurityFinding]
)
async def mssql_collect(payload: dict[str, Any]) -> list[SecurityFinding]:
    """Run the MS SQL Server collector (v0.7.7 P0.4).

    Request body (required):

    - ``connection_uri``: ``mssql://user@host:1433/dbname`` WITHOUT
      embedded password.
    - ``password_env``: env-var name to read the password from.
      Default: ``EVIDENTIA_MSSQL_PASSWORD``.

    Read-only by design — sysadmin / db_owner / db_datawriter
    membership detection fires EVIDENTIA-WRITE-PRIV-DETECTED
    finding mapped to NIST AC-6.
    """
    try:
        from evidentia_collectors.sql.mssql import (
            MSSQLCollector,
            MSSQLCollectorError,
        )
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=(
                "MSSQL collector not installed. Run "
                "`pip install 'evidentia-collectors[sql-mssql]'`. "
                "Note: also requires Microsoft ODBC Driver 18 at OS level."
            ),
        ) from e

    connection_uri = str(payload.get("connection_uri") or "").strip()
    if not connection_uri:
        raise HTTPException(
            status_code=400,
            detail="Request body must include 'connection_uri'.",
        )
    password_env = (
        str(payload.get("password_env") or "EVIDENTIA_MSSQL_PASSWORD").strip()
        or "EVIDENTIA_MSSQL_PASSWORD"
    )
    password = os.environ.get(password_env)
    if password is None:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Environment variable {password_env!r} not set on the "
                "server."
            ),
        )

    try:
        with MSSQLCollector(
            connection_uri=connection_uri, password=password
        ) as collector:
            findings = collector.collect()
    except MSSQLCollectorError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except Exception as e:
        logger.exception("MSSQL collector failed")
        raise HTTPException(
            status_code=500, detail=f"MSSQL collector failed: {e}"
        ) from e

    return findings


@router.post(
    "/collectors/sql/oracle/collect", response_model=list[SecurityFinding]
)
async def oracle_collect(payload: dict[str, Any]) -> list[SecurityFinding]:
    """Run the Oracle Database collector (v0.7.7 P0.5).

    Request body (required):

    - ``connection_uri``: ``oracle://user@host:1521/service_name``
      WITHOUT embedded password.
    - ``password_env``: env-var name to read the password from.
      Default: ``EVIDENTIA_ORACLE_PASSWORD``.

    Read-only by design — DBA / SYSDBA / ANY-table grant detection
    fires EVIDENTIA-WRITE-PRIV-DETECTED finding mapped to NIST AC-6.
    """
    try:
        from evidentia_collectors.sql.oracle import (
            OracleCollector,
            OracleCollectorError,
        )
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=(
                "Oracle collector not installed. Run "
                "`pip install 'evidentia-collectors[sql-oracle]'`."
            ),
        ) from e

    connection_uri = str(payload.get("connection_uri") or "").strip()
    if not connection_uri:
        raise HTTPException(
            status_code=400,
            detail="Request body must include 'connection_uri'.",
        )
    password_env = (
        str(payload.get("password_env") or "EVIDENTIA_ORACLE_PASSWORD").strip()
        or "EVIDENTIA_ORACLE_PASSWORD"
    )
    password = os.environ.get(password_env)
    if password is None:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Environment variable {password_env!r} not set on the "
                "server."
            ),
        )

    try:
        with OracleCollector(
            connection_uri=connection_uri, password=password
        ) as collector:
            findings = collector.collect()
    except OracleCollectorError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except Exception as e:
        logger.exception("Oracle collector failed")
        raise HTTPException(
            status_code=500, detail=f"Oracle collector failed: {e}"
        ) from e

    return findings


@router.post(
    "/collectors/sql/sqlite/collect", response_model=list[SecurityFinding]
)
async def sqlite_collect(payload: dict[str, Any]) -> list[SecurityFinding]:
    """Run the SQLite collector (v0.7.7 P0.3).

    Request body (required):

    - ``database_path``: Absolute path to the SQLite database file
      on the SERVER's filesystem. Must already exist + be readable
      by the API process. SQLite has no built-in user system, so
      no password is required or accepted.

    Read-only by design — the collector opens the file via
    ``file:?mode=ro`` URI. If the underlying filesystem still
    permits write, EVIDENTIA-WRITE-PRIV-DETECTED fires (AC-6).

    Path containment: when the ``EVIDENTIA_SQLITE_SAFE_ROOT`` env
    var is set, the collector refuses any ``database_path`` that
    resolves outside it (path-traversal mitigation; CWE-22). For
    multi-tenant deployments this MUST be set; for single-tenant
    trusted-perimeter deployments it can be left unset.
    """
    try:
        from evidentia_collectors.sql.sqlite import (
            SQLiteCollector,
            SQLiteCollectorError,
        )
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=f"SQLite collector failed to import: {e}",
        ) from e

    database_path = str(payload.get("database_path") or "").strip()
    if not database_path:
        raise HTTPException(
            status_code=400,
            detail="Request body must include 'database_path'.",
        )

    safe_root = os.environ.get("EVIDENTIA_SQLITE_SAFE_ROOT") or None

    try:
        with SQLiteCollector(
            database_path=database_path,
            safe_root=safe_root,
        ) as collector:
            findings = collector.collect()
    except SQLiteCollectorError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except Exception as e:
        logger.exception("SQLite collector failed")
        raise HTTPException(
            status_code=500, detail=f"SQLite collector failed: {e}"
        ) from e

    return findings


@router.post(
    "/collectors/databricks/collect", response_model=list[SecurityFinding]
)
async def databricks_collect(
    payload: dict[str, Any],
) -> list[SecurityFinding]:
    """Run the Databricks collector (v0.7.8 P0.1).

    Request body (required):

    - ``workspace_url``: Databricks workspace URL
      (e.g., ``https://my-workspace.cloud.databricks.com``).

    Auth is delegated to the Databricks SDK's unified-auth
    resolver — credentials come from server-side environment
    variables (``DATABRICKS_TOKEN``, ``DATABRICKS_CLIENT_ID`` +
    ``DATABRICKS_CLIENT_SECRET``, Azure AD, AWS IAM, or
    ``.databrickscfg``). Per CLAUDE.md secret-handling protocol,
    the request body NEVER carries a token.

    Response: list of SecurityFinding objects covering 4 evidence
    sources (PAT inventory, cluster compliance, service principal
    inventory, secret scope inventory).

    Deferred to subsequent v0.7.8 commits:

    - Workspace audit logs + table/column lineage (need SQL
      Warehouse plumbing)
    - Workspace network policies (need Account API auth path)
    """
    try:
        from evidentia_collectors.databricks import (
            DatabricksCollector,
            DatabricksCollectorError,
        )
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=(
                "Databricks collector not installed. Run "
                "`pip install 'evidentia-collectors[databricks]'`."
            ),
        ) from e

    workspace_url = str(payload.get("workspace_url") or "").strip()
    if not workspace_url:
        raise HTTPException(
            status_code=400,
            detail="Request body must include 'workspace_url'.",
        )

    try:
        with DatabricksCollector(host=workspace_url) as collector:
            findings = collector.collect()
    except DatabricksCollectorError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except Exception as e:
        logger.exception("Databricks collector failed")
        raise HTTPException(
            status_code=500,
            detail=f"Databricks collector failed: {e}",
        ) from e

    return findings


@router.post(
    "/collectors/snowflake/collect",
    response_model=list[SecurityFinding],
)
async def snowflake_collect(
    payload: dict[str, Any],
) -> list[SecurityFinding]:
    """Run the Snowflake collector (v0.7.8 P0.2).

    Request body (required):

    - ``account``: Snowflake account locator (e.g. ``acme-prod``).
    - ``user``: Snowflake username for the audit principal.

    Request body (optional):

    - ``password_env``: name of the env var holding the password
      (default ``SNOWFLAKE_PASSWORD``). The API server reads this
      env var server-side; the password NEVER flows through the
      request body.
    - ``private_key_path``: path to a PEM-encoded RSA private key
      for key-pair authentication. When set, password_env is
      ignored.
    - ``warehouse``: optional warehouse name.
    - ``role``: optional role name.
    - ``login_history_window_days``: how many days back to scan in
      LOGIN_HISTORY (default 90).

    Auth modes (per the snowflake-connector-python driver):

    - Password (env-sourced via ``password_env``)
    - Key-pair (preferred for production; Snowflake is deprecating
      password auth)

    Per CLAUDE.md secret-handling protocol, the request body NEVER
    carries a plaintext password. Operators set the password env
    var server-side and reference it by name.

    Response: list of SecurityFinding objects covering 6 evidence
    sources (login history, user inventory, grant inventory,
    network policies, masking + row-access policy inventory,
    operator-attested key-rotation).
    """
    try:
        from evidentia_collectors.snowflake import (
            SnowflakeCollector,
            SnowflakeCollectorError,
        )
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=(
                "Snowflake collector not installed. Run "
                "`pip install 'evidentia-collectors[snowflake]'`."
            ),
        ) from e

    account = str(payload.get("account") or "").strip()
    user = str(payload.get("user") or "").strip()
    if not account:
        raise HTTPException(
            status_code=400,
            detail="Request body must include 'account'.",
        )
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Request body must include 'user'.",
        )

    private_key_path = payload.get("private_key_path")
    private_key_path_str: str | None = (
        str(private_key_path) if private_key_path else None
    )

    password: str | None = None
    if private_key_path_str is None:
        password_env = (
            str(payload.get("password_env") or "SNOWFLAKE_PASSWORD")
            .strip()
            or "SNOWFLAKE_PASSWORD"
        )
        password = os.environ.get(password_env)
        if not password:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Env var '{password_env}' is not set or is "
                    f"empty. Either set it server-side OR pass "
                    f"'private_key_path' for key-pair auth."
                ),
            )

    warehouse = payload.get("warehouse")
    role = payload.get("role")
    login_history_window_days = int(
        payload.get("login_history_window_days") or 90
    )

    try:
        with SnowflakeCollector(
            account=account,
            user=user,
            password=password,
            private_key_path=private_key_path_str,
            warehouse=str(warehouse) if warehouse else None,
            role=str(role) if role else None,
            login_history_window_days=login_history_window_days,
        ) as collector:
            findings = collector.collect()
    except SnowflakeCollectorError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except Exception as e:
        logger.exception("Snowflake collector failed")
        raise HTTPException(
            status_code=500,
            detail=f"Snowflake collector failed: {e}",
        ) from e

    return findings


@router.get("/collectors/status")
async def collectors_status() -> dict[str, Any]:
    """Report which collectors are installed + which credentials are set.

    Never returns token values — only ``configured: bool`` + the env var
    name the token was sourced from.
    """
    aws_installed = False
    github_installed = False
    okta_installed = False
    postgres_installed = False
    mysql_installed = False
    sqlite_installed = False
    mssql_installed = False
    oracle_installed = False
    databricks_installed = False
    snowflake_installed = False
    try:
        import evidentia_collectors.aws

        aws_installed = True
    except ImportError:
        pass
    try:
        import evidentia_collectors.github

        github_installed = True
    except ImportError:
        pass
    try:
        import evidentia_collectors.okta

        okta_installed = True
    except ImportError:
        pass
    try:
        import evidentia_collectors.sql.mysql

        try:
            import pymysql  # type: ignore[import-untyped, unused-ignore]  # noqa: F401

            mysql_installed = True
        except ImportError:
            mysql_installed = False
    except ImportError:
        pass
    try:
        # Postgres adapter loads cleanly without psycopg installed;
        # the actual driver-import happens lazily on first connect.
        # Detect the driver presence separately so the status surface
        # reflects ready-to-use vs adapter-imported-but-driver-missing.
        import evidentia_collectors.sql.postgres

        try:
            import psycopg  # noqa: F401

            postgres_installed = True
        except ImportError:
            postgres_installed = False
    except ImportError:
        pass
    try:
        # SQLite uses stdlib sqlite3 — no extra dependency to detect.
        # The adapter's installed status mirrors module importability.
        import evidentia_collectors.sql.sqlite

        sqlite_installed = True
    except ImportError:
        pass
    try:
        import evidentia_collectors.sql.mssql

        try:
            import pyodbc  # noqa: F401

            mssql_installed = True
        except ImportError:
            mssql_installed = False
    except ImportError:
        pass
    try:
        import evidentia_collectors.sql.oracle

        try:
            import oracledb  # noqa: F401

            oracle_installed = True
        except ImportError:
            oracle_installed = False
    except ImportError:
        pass
    try:
        # Databricks adapter loads cleanly without databricks-sdk
        # installed; the actual SDK import happens lazily on first
        # collect_v2 call.
        import evidentia_collectors.databricks

        try:
            import databricks.sdk  # type: ignore[import-untyped, unused-ignore]  # noqa: F401

            databricks_installed = True
        except ImportError:
            databricks_installed = False
    except ImportError:
        pass
    try:
        # Snowflake adapter loads cleanly without
        # snowflake-connector-python installed; the actual driver
        # import happens lazily on first connect.
        import evidentia_collectors.snowflake  # noqa: F401

        try:
            import snowflake.connector  # type: ignore[import-untyped, unused-ignore]  # noqa: F401

            snowflake_installed = True
        except ImportError:
            snowflake_installed = False
    except ImportError:
        pass

    return {
        "aws": {
            "installed": aws_installed,
            "credentials_hint": (
                "boto3 standard chain (env / ~/.aws / instance profile)"
            ),
        },
        "github": {
            "installed": github_installed,
            "token_configured": bool(os.environ.get("GITHUB_TOKEN")),
            "token_source": "env:GITHUB_TOKEN" if os.environ.get("GITHUB_TOKEN") else None,
        },
        "okta": {
            "installed": okta_installed,
            "token_configured": bool(os.environ.get("OKTA_API_TOKEN")),
            "token_source": (
                "env:OKTA_API_TOKEN"
                if os.environ.get("OKTA_API_TOKEN")
                else None
            ),
        },
        "postgres": {
            "installed": postgres_installed,
            "credentials_hint": (
                "Connection URI WITHOUT embedded password; pass password via "
                "EVIDENTIA_POSTGRES_PASSWORD env var (or override with "
                "password_env in the request body)."
            ),
            "default_password_env_configured": bool(
                os.environ.get("EVIDENTIA_POSTGRES_PASSWORD")
            ),
        },
        "mysql": {
            "installed": mysql_installed,
            "credentials_hint": (
                "Connection URI WITHOUT embedded password; pass password via "
                "EVIDENTIA_MYSQL_PASSWORD env var (or override with "
                "password_env in the request body)."
            ),
            "default_password_env_configured": bool(
                os.environ.get("EVIDENTIA_MYSQL_PASSWORD")
            ),
        },
        "sqlite": {
            "installed": sqlite_installed,
            "credentials_hint": (
                "No password — SQLite has no built-in user system. "
                "Pass database_path in the request body; the API process "
                "must already be able to read the file."
            ),
        },
        "mssql": {
            "installed": mssql_installed,
            "credentials_hint": (
                "Connection URI WITHOUT embedded password; pass password via "
                "EVIDENTIA_MSSQL_PASSWORD env var (or override with "
                "password_env in the request body). Requires Microsoft "
                "ODBC Driver 18 at OS level."
            ),
            "default_password_env_configured": bool(
                os.environ.get("EVIDENTIA_MSSQL_PASSWORD")
            ),
        },
        "oracle": {
            "installed": oracle_installed,
            "credentials_hint": (
                "Connection URI (oracle://user@host:1521/service_name) "
                "WITHOUT embedded password; pass password via "
                "EVIDENTIA_ORACLE_PASSWORD env var. Uses oracledb thin "
                "mode (no Oracle Client install required)."
            ),
            "default_password_env_configured": bool(
                os.environ.get("EVIDENTIA_ORACLE_PASSWORD")
            ),
        },
        "databricks": {
            "installed": databricks_installed,
            "credentials_hint": (
                "Auth via Databricks SDK unified-auth resolver. "
                "Set DATABRICKS_TOKEN (PAT), or DATABRICKS_CLIENT_ID + "
                "DATABRICKS_CLIENT_SECRET (OAuth M2M), or rely on Azure "
                "AD / AWS IAM / .databrickscfg. The collector NEVER "
                "accepts a token via the request body."
            ),
            "default_token_env_configured": bool(
                os.environ.get("DATABRICKS_TOKEN")
            ),
            "oauth_m2m_configured": bool(
                os.environ.get("DATABRICKS_CLIENT_ID")
                and os.environ.get("DATABRICKS_CLIENT_SECRET")
            ),
        },
        "snowflake": {
            "installed": snowflake_installed,
            "credentials_hint": (
                "Pass account + user in the request body; password "
                "is sourced server-side from the env var named via "
                "password_env (default SNOWFLAKE_PASSWORD). For "
                "production, prefer key-pair auth via "
                "private_key_path. The collector NEVER accepts a "
                "plaintext password via the request body."
            ),
            "default_password_env_configured": bool(
                os.environ.get("SNOWFLAKE_PASSWORD")
            ),
        },
    }
