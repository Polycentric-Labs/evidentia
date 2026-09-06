"""Unit tests for ``evidentia_integrations.jira.client``.

Uses ``httpx.MockTransport`` to intercept every outbound request so the
tests never touch a real Jira server. Each test asserts both the
request shape (URL, method, body) and the response handling.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from evidentia_integrations.jira import JiraApiError, JiraClient, JiraConfig

# ── Fixtures ─────────────────────────────────────────────────────────────


def _config() -> JiraConfig:
    return JiraConfig(
        base_url="https://acme.atlassian.net",
        email="user@example.com",
        api_token="secret-token-never-logged",
        project_key="SEC",
        issue_type="Task",
    )


def _client_with_handler(handler: httpx.MockTransport) -> JiraClient:
    http = httpx.Client(
        base_url="https://acme.atlassian.net",
        transport=handler,
        headers={"Authorization": "Basic x", "Accept": "application/json"},
    )
    return JiraClient(config=_config(), http=http)


# ── JiraConfig ───────────────────────────────────────────────────────────


class TestJiraConfig:
    def test_strips_trailing_slash_on_base_url(self) -> None:
        cfg = JiraConfig(
            base_url="https://acme.atlassian.net/",
            email="u@e.com",
            api_token="t",
            project_key="SEC",
        )
        assert cfg.base_url == "https://acme.atlassian.net"

    def test_model_dump_excludes_token(self) -> None:
        cfg = _config()
        dumped = cfg.model_dump()
        assert "api_token" not in dumped, (
            "api_token must never leak through model_dump() — it's the "
            "secret-handling contract every callsite relies on."
        )

    def test_from_env_raises_when_required_vars_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in (
            "JIRA_BASE_URL",
            "JIRA_EMAIL",
            "JIRA_API_TOKEN",
            "JIRA_PROJECT_KEY",
        ):
            monkeypatch.delenv(var, raising=False)

        with pytest.raises(ValueError) as excinfo:
            JiraConfig.from_env()

        detail = str(excinfo.value)
        assert "JIRA_BASE_URL" in detail
        assert "JIRA_EMAIL" in detail
        assert "JIRA_API_TOKEN" in detail
        assert "JIRA_PROJECT_KEY" in detail

    def test_from_env_loads_all_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JIRA_BASE_URL", "https://env.atlassian.net/")
        monkeypatch.setenv("JIRA_EMAIL", "env@x.com")
        monkeypatch.setenv("JIRA_API_TOKEN", "env-token")
        monkeypatch.setenv("JIRA_PROJECT_KEY", "ENV")
        monkeypatch.setenv("JIRA_ISSUE_TYPE", "Story")
        cfg = JiraConfig.from_env()
        assert cfg.base_url == "https://env.atlassian.net"
        assert cfg.email == "env@x.com"
        assert cfg.project_key == "ENV"
        assert cfg.issue_type == "Story"

    def test_from_env_overrides_beat_env_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JIRA_BASE_URL", "https://env.atlassian.net")
        monkeypatch.setenv("JIRA_EMAIL", "env@x.com")
        monkeypatch.setenv("JIRA_API_TOKEN", "env-token")
        monkeypatch.setenv("JIRA_PROJECT_KEY", "ENV")
        cfg = JiraConfig.from_env(project_key="OVERRIDE")
        assert cfg.project_key == "OVERRIDE"


# ── test_connection ──────────────────────────────────────────────────────


class TestTestConnection:
    def test_success_returns_user_and_project(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/rest/api/3/myself":
                return httpx.Response(
                    200,
                    json={
                        "displayName": "Allen",
                        "emailAddress": "allen@example.com",
                    },
                )
            if request.url.path == "/rest/api/3/project/SEC":
                return httpx.Response(200, json={"key": "SEC", "name": "Security"})
            return httpx.Response(404)

        with _client_with_handler(httpx.MockTransport(handler)) as client:
            info = client.test_connection()

        assert info["user"] == "Allen"
        assert info["project_key"] == "SEC"
        assert info["project_name"] == "Security"
        assert info["base_url"] == "https://acme.atlassian.net"

    def test_401_raises_api_error(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                json={"errorMessages": ["Bad credentials"], "errors": {}},
            )

        with (
            _client_with_handler(httpx.MockTransport(handler)) as client,
            pytest.raises(JiraApiError) as excinfo,
        ):
            client.test_connection()

        assert excinfo.value.status_code == 401
        assert "Bad credentials" in excinfo.value.errors
        # Defense in depth: the raised error must not carry the
        # Authorization header value.
        assert "secret-token-never-logged" not in str(excinfo.value)

    def test_404_on_missing_project(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/myself"):
                return httpx.Response(200, json={"displayName": "A"})
            return httpx.Response(
                404,
                json={"errorMessages": ["No project could be found with key 'SEC'"]},
            )

        with (
            _client_with_handler(httpx.MockTransport(handler)) as client,
            pytest.raises(JiraApiError) as excinfo,
        ):
            client.test_connection()

        assert excinfo.value.status_code == 404
        assert any("No project" in err for err in excinfo.value.errors)


# ── create_issue ─────────────────────────────────────────────────────────


class TestCreateIssue:
    def test_posts_expected_body_and_returns_typed_issue(self) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST" and request.url.path == "/rest/api/3/issue":
                import json

                captured["body"] = json.loads(request.content.decode())
                return httpx.Response(201, json={"id": "10042", "key": "SEC-42"})
            if request.method == "GET" and request.url.path == "/rest/api/3/issue/SEC-42":
                return httpx.Response(
                    200,
                    json={
                        "id": "10042",
                        "key": "SEC-42",
                        "fields": {
                            "summary": "Test gap",
                            "status": {
                                "name": "To Do",
                                "statusCategory": {"key": "new"},
                            },
                        },
                    },
                )
            return httpx.Response(500)

        with _client_with_handler(httpx.MockTransport(handler)) as client:
            issue = client.create_issue(
                summary="Test gap",
                description="Demo description",
                labels=["evidentia", "nist-800-53-rev5-moderate"],
            )

        assert issue.key == "SEC-42"
        assert issue.id == "10042"
        assert issue.status_name == "To Do"
        assert issue.status_category == "new"
        assert issue.url == "https://acme.atlassian.net/browse/SEC-42"

        fields = captured["body"]["fields"]
        assert fields["project"]["key"] == "SEC"
        assert fields["issuetype"]["name"] == "Task"
        assert fields["summary"] == "Test gap"
        assert fields["labels"] == ["evidentia", "nist-800-53-rev5-moderate"]
        # ADF wrapper present
        assert fields["description"]["type"] == "doc"
        assert fields["description"]["content"][0]["content"][0]["text"] == "Demo description"

    def test_merges_extra_fields(self) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                import json

                captured["body"] = json.loads(request.content.decode())
                return httpx.Response(201, json={"id": "1", "key": "SEC-1"})
            return httpx.Response(
                200,
                json={
                    "id": "1",
                    "key": "SEC-1",
                    "fields": {
                        "summary": "x",
                        "status": {
                            "name": "To Do",
                            "statusCategory": {"key": "new"},
                        },
                    },
                },
            )

        with _client_with_handler(httpx.MockTransport(handler)) as client:
            client.create_issue(
                summary="x",
                description="y",
                extra_fields={"priority": {"name": "High"}},
            )

        assert captured["body"]["fields"]["priority"] == {"name": "High"}


# ── transitions ──────────────────────────────────────────────────────────


class TestTransitions:
    def test_lists_transitions(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "transitions": [
                        {"id": "11", "name": "To Do", "to": {"name": "To Do"}},
                        {
                            "id": "21",
                            "name": "In Progress",
                            "to": {"name": "In Progress"},
                        },
                        {"id": "31", "name": "Done", "to": {"name": "Done"}},
                    ]
                },
            )

        with _client_with_handler(httpx.MockTransport(handler)) as client:
            transitions = client.list_transitions("SEC-42")

        assert [t["id"] for t in transitions] == ["11", "21", "31"]

    def test_transition_issue_posts_correct_transition_id(self) -> None:
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and "/transitions" in str(request.url):
                return httpx.Response(
                    200,
                    json={
                        "transitions": [
                            {"id": "21", "to": {"name": "In Progress"}},
                            {"id": "31", "to": {"name": "Done"}},
                        ]
                    },
                )
            if request.method == "POST" and "/transitions" in str(request.url):
                import json

                captured["body"] = json.loads(request.content.decode())
                return httpx.Response(204)
            return httpx.Response(500)

        with _client_with_handler(httpx.MockTransport(handler)) as client:
            client.transition_issue("SEC-42", target_status="Done")

        assert captured["body"]["transition"]["id"] == "31"

    def test_transition_case_insensitive_status_match(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(
                    200,
                    json={"transitions": [{"id": "31", "to": {"name": "Done"}}]},
                )
            return httpx.Response(204)

        with _client_with_handler(httpx.MockTransport(handler)) as client:
            client.transition_issue("SEC-42", target_status="done")

    def test_transition_unavailable_raises(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"transitions": [{"id": "21", "to": {"name": "In Progress"}}]},
            )

        with (
            _client_with_handler(httpx.MockTransport(handler)) as client,
            pytest.raises(JiraApiError) as excinfo,
        ):
            client.transition_issue("SEC-42", target_status="Done")

        assert excinfo.value.status_code == 409
        assert "No transition" in str(excinfo.value)
