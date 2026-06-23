"""Tests for :mod:`evidentia_core.audit.logger` (v0.7.0)."""

from __future__ import annotations

import io
import json
import logging

import pytest
from evidentia_core.audit.events import (
    EventAction,
    EventCategory,
    EventOutcome,
    EventType,
)
from evidentia_core.audit.logger import (
    ECS_VERSION,
    ECSFormatter,
    _reset_for_tests,
    _scrub,
    enable_json_logs,
    get_logger,
    is_json_mode,
)
from evidentia_core.audit.provenance import new_run_id


@pytest.fixture(autouse=True)
def reset_logger_state() -> None:
    _reset_for_tests()
    yield
    _reset_for_tests()


# NOTE: AWS canonical example-credential strings (AKIAIOSFODNN7EXAMPLE,
# ASIAIOSFODNN7EXAMPLE) are intentionally split via concatenation so
# GitHub's secret-scanning regex doesn't false-positive on the literal
# substring at scan time. The runtime values still match our scrubber's
# `\bAKIA[0-9A-Z]{16}\b` and `\bASIA[0-9A-Z]{16}\b` regexes. These are
# the AWS-documented placeholder values, not real credentials — see
# https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html
_AWS_PERM_KEY_EXAMPLE = "AKIA" + "IOSFODNN7EXAMPLE"
_AWS_TEMP_KEY_EXAMPLE = "ASIA" + "IOSFODNN7EXAMPLE"


def test_scrub_redacts_aws_access_key() -> None:
    assert (
        _scrub(f"using {_AWS_PERM_KEY_EXAMPLE} as credential")
        == "using [REDACTED] as credential"
    )


def test_scrub_redacts_aws_session_credential() -> None:
    assert "ASIA" not in _scrub(f"token {_AWS_TEMP_KEY_EXAMPLE} leaked")


def test_scrub_redacts_github_token() -> None:
    # Split the prefix so the literal never matches the pre-push secret-scan's
    # ``ghp_[A-Za-z0-9]{36}`` content pattern in source (mirrors the AWS-example
    # split above) — it's fake test data, not a real PAT.
    redacted = _scrub("ghp_" + "abcdef1234567890abcdef1234567890abcd")
    assert "[REDACTED]" in redacted
    assert "ghp_" not in redacted


def test_scrub_redacts_password_pattern() -> None:
    assert "[REDACTED]" in _scrub('password="hunter2xyz"')
    assert "[REDACTED]" in _scrub("token=abc12345xyz")


def test_scrub_redacts_jwt() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxMjM0NSJ9."
        "signature-bytes-here"
    )
    assert "[REDACTED]" in _scrub(f"bearer {jwt}")


# F-V1012-S41-1: the scrubber must cover the credential shapes this system's
# OWN integrations use (fine-grained PATs, OpenAI/Anthropic keys, DSN
# passwords, bearer tokens), not just the classic AWS/ghp_/JWT shapes.
def test_scrub_redacts_github_fine_grained_pat() -> None:
    pat = "github_pat_" + "11ABCDE0Y0abcdefghijkl" + "_" + "A" * 59
    redacted = _scrub(f"GITHUB_TOKEN={pat}")
    assert "[REDACTED]" in redacted
    assert "github_pat_" not in redacted


def test_scrub_redacts_openai_and_anthropic_keys() -> None:
    assert "[REDACTED]" in _scrub("key sk-" + "A" * 40 + " leaked")
    assert "[REDACTED]" in _scrub("key sk-proj-" + "B" * 40)
    redacted = _scrub("ANTHROPIC_API_KEY=sk-ant-api03-" + "C" * 40)
    assert "[REDACTED]" in redacted
    assert "sk-ant-" not in redacted


def test_scrub_redacts_dsn_userinfo_password() -> None:
    redacted = _scrub("postgres://dbuser:s3cr3tPass@db.internal:5432/evidentia")
    assert "[REDACTED]" in redacted
    assert "s3cr3tPass" not in redacted


def test_scrub_redacts_bearer_token() -> None:
    redacted = _scrub("Authorization: Bearer abcdef0123456789ABCDEF")
    assert "[REDACTED]" in redacted
    assert "abcdef0123456789ABCDEF" not in redacted


def test_scrub_is_idempotent() -> None:
    s = "no secrets here"
    assert _scrub(_scrub(s)) == _scrub(s) == s


def test_emit_produces_ecs_compliant_record() -> None:
    stream = io.StringIO()
    enable_json_logs(stream=stream)

    log = get_logger("evidentia.test")
    log.info(
        action=EventAction.COLLECT_STARTED,
        message="starting collection",
        category=[EventCategory.CONFIGURATION],
        types=[EventType.START],
    )

    record = json.loads(stream.getvalue().strip())
    assert record["@timestamp"]
    assert record["event"]["action"] == "evidentia.collect.started"
    assert record["event"]["category"] == ["configuration"]
    assert record["event"]["type"] == ["start"]
    assert record["event"]["outcome"] == "success"
    assert record["service"]["name"] == "evidentia"
    assert "hostname" in record["host"]
    assert record["log"]["logger"] == "evidentia.test"
    assert record["ecs"]["version"] == ECS_VERSION


def test_emit_populates_event_id_as_ulid() -> None:
    stream = io.StringIO()
    enable_json_logs(stream=stream)
    log = get_logger("evidentia.test")
    log.info(action=EventAction.COLLECT_STARTED, message="x")
    record = json.loads(stream.getvalue().strip())
    assert len(record["event"]["id"]) == 26


def test_emit_includes_service_version() -> None:
    stream = io.StringIO()
    enable_json_logs(stream=stream)
    log = get_logger("evidentia.test")
    log.info(action=EventAction.COLLECT_STARTED, message="x")
    record = json.loads(stream.getvalue().strip())
    assert "." in record["service"]["version"]


def test_emit_with_duration_converts_to_nanoseconds() -> None:
    stream = io.StringIO()
    enable_json_logs(stream=stream)
    log = get_logger("evidentia.test")
    log.info(
        action=EventAction.COLLECT_FINDING_RETRIEVED,
        message="x",
        duration_ms=142.5,
    )
    record = json.loads(stream.getvalue().strip())
    assert record["event"]["duration"] == 142_500_000


def test_emit_error_field_populated() -> None:
    stream = io.StringIO()
    enable_json_logs(stream=stream)
    log = get_logger("evidentia.test")
    log.error(
        action=EventAction.COLLECT_FAILED,
        outcome=EventOutcome.FAILURE,
        message="collection crashed",
        error={"type": "BotoCoreError", "message": "connection refused"},
    )
    record = json.loads(stream.getvalue().strip())
    assert record["error"]["type"] == "BotoCoreError"
    assert record["event"]["outcome"] == "failure"


def test_scope_merges_fields_into_every_emit() -> None:
    stream = io.StringIO()
    enable_json_logs(stream=stream)
    log = get_logger("evidentia.test")
    run_id = new_run_id()
    with log.scope(trace_id=run_id, evidentia={"framework": "nist-800-53-rev5"}):
        log.info(action=EventAction.COLLECT_STARTED, message="x")
        log.info(
            action=EventAction.COLLECT_FINDING_RETRIEVED,
            message="y",
            evidentia={"findings_count": 1},
        )
    records = [json.loads(line) for line in stream.getvalue().strip().splitlines()]
    assert len(records) == 2
    assert all(r["trace"]["id"] == run_id for r in records)
    assert records[0]["evidentia"] == {"framework": "nist-800-53-rev5"}
    assert records[1]["evidentia"]["framework"] == "nist-800-53-rev5"
    assert records[1]["evidentia"]["findings_count"] == 1


def test_scope_nested_inherits_outer_fields() -> None:
    stream = io.StringIO()
    enable_json_logs(stream=stream)
    log = get_logger("evidentia.test")
    with (
        log.scope(evidentia={"outer": "value"}),
        log.scope(evidentia={"inner": "value"}),
    ):
        log.info(action=EventAction.COLLECT_STARTED, message="x")
    record = json.loads(stream.getvalue().strip())
    assert record["evidentia"] == {"outer": "value", "inner": "value"}


def test_scope_is_restored_after_block() -> None:
    stream = io.StringIO()
    enable_json_logs(stream=stream)
    log = get_logger("evidentia.test")
    with log.scope(evidentia={"in_scope": "yes"}):
        pass
    log.info(action=EventAction.COLLECT_COMPLETED, message="done")
    record = json.loads(stream.getvalue().strip())
    assert "evidentia" not in record


def test_is_json_mode_default_false() -> None:
    assert is_json_mode() is False


def test_enable_json_logs_flips_flag() -> None:
    enable_json_logs(stream=io.StringIO())
    assert is_json_mode() is True


def test_enable_json_logs_idempotent() -> None:
    stream = io.StringIO()
    enable_json_logs(stream=stream)
    enable_json_logs(stream=stream)
    log = get_logger("evidentia.test")
    log.info(action=EventAction.COLLECT_STARTED, message="x")
    lines = stream.getvalue().strip().splitlines()
    assert len(lines) == 1


def test_formatter_falls_back_for_third_party_records() -> None:
    formatter = ECSFormatter()
    record = logging.LogRecord(
        name="boto3.client",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="found 42 buckets",
        args=(),
        exc_info=None,
    )
    output = formatter.format(record)
    parsed = json.loads(output)
    assert parsed["log"]["logger"] == "boto3.client"
    assert parsed["message"] == "found 42 buckets"
    assert parsed["event"]["dataset"] == "evidentia.library"


def test_formatter_output_is_single_line() -> None:
    stream = io.StringIO()
    enable_json_logs(stream=stream)
    log = get_logger("evidentia.test")
    log.info(
        action=EventAction.COLLECT_STARTED,
        message="multi\nline\nmessage",
        evidentia={"nested": {"key": "value"}},
    )
    output = stream.getvalue().strip()
    assert "\n" not in output
    parsed = json.loads(output)
    assert parsed["message"] == "multi\nline\nmessage"
