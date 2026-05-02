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
            status_code=422,
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
            status_code=422,
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
            status_code=422,
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


@router.get("/collectors/status")
async def collectors_status() -> dict[str, Any]:
    """Report which collectors are installed + which credentials are set.

    Never returns token values — only ``configured: bool`` + the env var
    name the token was sourced from.
    """
    aws_installed = False
    github_installed = False
    postgres_installed = False
    mysql_installed = False
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
        import evidentia_collectors.sql.mysql

        try:
            import pymysql  # type: ignore[import-untyped]  # noqa: F401

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
        import evidentia_collectors.sql.postgres  # noqa: F401

        try:
            import psycopg  # noqa: F401

            postgres_installed = True
        except ImportError:
            postgres_installed = False
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
    }
