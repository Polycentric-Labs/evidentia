"""Body-named credential env vars are confined to the integration's prefix (review C2).

Each route below lets the request body name the server env var that holds
a credential. The name must look like an environment variable and start
with the integration's own prefix; anything else is refused with 400
before the environment is read, so a body can no longer point a route at
an unrelated secret and ship its value to a host the same body chose.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

UNRELATED = "AWS_SECRET_ACCESS_KEY"
SENTINEL = "unrelated-secret-must-never-leave-the-server"

CASES: list[tuple[str, str, str, dict[str, Any]]] = [
    ("/api/collectors/vanta/collect", "token_env", "VANTA_API_TOKEN_EU", {}),
    ("/api/collectors/drata/collect", "token_env", "DRATA_API_TOKEN_EU", {}),
    ("/api/collectors/bitsight/collect", "token_env", "BITSIGHT_API_TOKEN_2", {}),
    ("/api/collectors/securityscorecard/collect", "token_env", "SECURITYSCORECARD_API_TOKEN_2", {}),
    ("/api/collectors/google-workspace/collect", "token_env", "GOOGLE_WORKSPACE_ACCESS_TOKEN_2", {}),
    (
        "/api/collectors/sql/postgres/collect",
        "password_env",
        "EVIDENTIA_POSTGRES_PASSWORD_RO",
        {"connection_uri": "postgres://reader@db.example.com/app"},
    ),
    (
        "/api/collectors/sql/mysql/collect",
        "password_env",
        "EVIDENTIA_MYSQL_PASSWORD_RO",
        {"connection_uri": "mysql://reader@db.example.com/app"},
    ),
    (
        "/api/collectors/sql/mssql/collect",
        "password_env",
        "EVIDENTIA_MSSQL_PASSWORD_RO",
        {"connection_uri": "mssql://reader@db.example.com/app"},
    ),
    (
        "/api/collectors/sql/oracle/collect",
        "password_env",
        "EVIDENTIA_ORACLE_PASSWORD_RO",
        {"connection_uri": "oracle://reader@db.example.com/app"},
    ),
    (
        "/api/collectors/snowflake/collect",
        "password_env",
        "SNOWFLAKE_PASSWORD_RO",
        {"account": "acme", "user": "svc_reader"},
    ),
    (
        "/api/integrations/tableau/publish/0123456789abcdef",
        "pat_name_env",
        "TABLEAU_PAT_NAME_PROD",
        {"server_url": "https://8.8.8.8/"},
    ),
    (
        "/api/integrations/tableau/publish/0123456789abcdef",
        "pat_secret_env",
        "TABLEAU_PAT_SECRET_PROD",
        {"server_url": "https://8.8.8.8/"},
    ),
    (
        "/api/integrations/powerbi/publish/0123456789abcdef",
        "client_secret_env",
        "POWERBI_CLIENT_SECRET_PROD",
        {"workspace_id": "ws-1", "tenant_id": "t-1", "client_id": "c-1"},
    ),
]

ACCEPTED_OUTCOMES = {
    # The name passed the resolver and the route moved on to the next
    # check: a missing credential, or (for the publish routes) the report
    # lookup, which happens before any credential is read.
    ("credentials_missing", 503),
    ("credentials_missing", 400),
    ("not_found", 404),
}


def _skip_if_extra_missing(response: Any) -> None:
    if response.status_code == 503 and response.json().get("detail", {}).get("error") == "feature_unavailable":
        pytest.skip("optional collector extra not installed in this environment")


@pytest.mark.parametrize(("path", "field", "good", "body"), CASES, ids=[f"{c[0]}:{c[1]}" for c in CASES])
def test_unrelated_env_name_is_refused_before_any_env_read(
    api_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    field: str,
    good: str,
    body: dict[str, Any],
) -> None:
    monkeypatch.setenv(UNRELATED, SENTINEL)
    response = api_client.post(path, json={**body, field: UNRELATED})
    _skip_if_extra_missing(response)
    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert detail["error"] == "invalid_field"
    assert detail["field"] == field
    assert SENTINEL not in response.text
    assert UNRELATED not in str(detail.get("allowed_prefixes"))


@pytest.mark.parametrize(
    ("path", "field", "bad", "body"),
    [
        ("/api/collectors/vanta/collect", "token_env", "vanta_api_token", {}),
        ("/api/collectors/vanta/collect", "token_env", "VANTA_API_TOKEN; rm -rf /", {}),
        ("/api/collectors/vanta/collect", "token_env", "VANTA_" + "A" * 80, {}),
        ("/api/collectors/vanta/collect", "token_env", 42, {}),
    ],
)
def test_malformed_env_names_are_refused(
    api_client: TestClient, path: str, field: str, bad: Any, body: dict[str, Any]
) -> None:
    response = api_client.post(path, json={**body, field: bad})
    _skip_if_extra_missing(response)
    assert response.status_code == 400, response.text
    assert response.json()["detail"]["field"] == field


@pytest.mark.parametrize(("path", "field", "good", "body"), CASES, ids=[f"{c[0]}:{c[1]}" for c in CASES])
def test_prefixed_env_name_is_accepted(
    api_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    field: str,
    good: str,
    body: dict[str, Any],
) -> None:
    monkeypatch.delenv(good, raising=False)
    response = api_client.post(path, json={**body, field: good})
    _skip_if_extra_missing(response)
    detail = response.json()["detail"]
    assert (detail["error"], response.status_code) in ACCEPTED_OUTCOMES, response.text
    if detail["error"] == "credentials_missing":
        assert detail["env_var"] == good


def test_blank_env_name_selects_the_default(api_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VANTA_API_TOKEN", raising=False)
    response = api_client.post("/api/collectors/vanta/collect", json={"token_env": "   "})
    _skip_if_extra_missing(response)
    assert response.status_code == 503, response.text
    assert response.json()["detail"]["env_var"] == "VANTA_API_TOKEN"


def test_integration_flags_must_be_json_booleans(api_client: TestClient) -> None:
    response = api_client.post(
        "/api/integrations/powerbi/publish/0123456789abcdef",
        json={"workspace_id": "ws-1", "tenant_id": "t-1", "client_id": "c-1", "clear_before_push": "false"},
    )
    assert response.status_code == 400, response.text
    assert response.json()["detail"]["field"] == "clear_before_push"
    response = api_client.post(
        "/api/integrations/tableau/publish/0123456789abcdef",
        json={"server_url": "https://8.8.8.8/", "block_private_ips": "false"},
    )
    assert response.status_code == 400, response.text
    assert response.json()["detail"]["field"] == "block_private_ips"
