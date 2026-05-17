"""Unit tests for evidentia_integrations.alerting.webhook (v0.9.3 P1.2)."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import date
from unittest.mock import MagicMock, patch

import pytest
from evidentia_core.conmon import CycleObservation, get_cadence
from evidentia_core.conmon.calendar import CycleAttentionState
from evidentia_integrations.alerting import (
    WebhookAlertChannel,
    WebhookConfig,
)


@pytest.fixture()
def sample_observation() -> CycleObservation:
    cadence = get_cadence("nist-800-53-rev5-ca7")
    assert cadence is not None
    return CycleObservation(
        cadence=cadence,
        last_completed=date(2025, 1, 1),
        next_due=date(2025, 2, 1),
        state=CycleAttentionState.OVERDUE,
        days_until_due=-469,
    )


class TestWebhookConfig:
    def test_rejects_empty_url(self) -> None:
        with pytest.raises(ValueError, match="URL required"):
            WebhookConfig(url="", secret="s")

    def test_rejects_non_http_url(self) -> None:
        with pytest.raises(ValueError, match="http"):
            WebhookConfig(url="ftp://example.com", secret="s")

    def test_rejects_empty_secret(self) -> None:
        with pytest.raises(ValueError, match="secret required"):
            WebhookConfig(
                url="https://hooks.example.com/in", secret=""
            )

    def test_accepts_http_url(self) -> None:
        # http:// is allowed (internal networks); operator
        # responsibility to use https in production.
        cfg = WebhookConfig(url="http://hooks.internal", secret="s")
        assert cfg.url == "http://hooks.internal"


class TestWebhookAlertChannel:
    def test_dispatch_sends_signed_post(
        self, sample_observation: CycleObservation
    ) -> None:
        cfg = WebhookConfig(
            url="https://hooks.example.com/in",
            secret="shared-secret",
        )
        channel = WebhookAlertChannel(cfg)

        with patch("urllib.request.urlopen") as urlopen:
            mock_response = MagicMock()
            mock_response.status = 200
            urlopen.return_value.__enter__.return_value = mock_response
            channel.dispatch(sample_observation)

        assert urlopen.call_count == 1
        request_arg = urlopen.call_args[0][0]
        assert request_arg.method == "POST"
        assert request_arg.full_url == "https://hooks.example.com/in"

        # v0.9.3 F-V93-S3 review fix: signed material is
        # f"{timestamp}.{body}", not body alone. The receiver
        # reads X-Evidentia-Timestamp + reconstructs the signed
        # material for verification.
        body = request_arg.data
        timestamp = request_arg.headers["X-evidentia-timestamp"]
        signature_header = request_arg.headers["X-evidentia-signature"]
        signed_material = f"{timestamp}.".encode() + body
        expected = hmac.new(
            b"shared-secret", signed_material, hashlib.sha256
        ).hexdigest()
        assert signature_header == f"sha256={expected}"
        # Timestamp is a unix-epoch integer string (≤ 11 chars
        # until year 5138 — sanity range).
        assert timestamp.isdigit()
        assert 10 <= len(timestamp) <= 11

    def test_payload_shape(
        self, sample_observation: CycleObservation
    ) -> None:
        cfg = WebhookConfig(
            url="https://hooks.example.com/in",
            secret="shared-secret",
        )
        channel = WebhookAlertChannel(cfg)

        with patch("urllib.request.urlopen") as urlopen:
            mock_response = MagicMock()
            mock_response.status = 200
            urlopen.return_value.__enter__.return_value = mock_response
            channel.dispatch(sample_observation)

        body_bytes = urlopen.call_args[0][0].data
        payload = json.loads(body_bytes.decode("utf-8"))
        assert payload["cadence_slug"] == "nist-800-53-rev5-ca7"
        assert payload["framework"] == "nist-800-53-rev5"
        assert payload["state"] == "overdue"
        assert payload["days_until_due"] == -469
        assert payload["last_completed"] == "2025-01-01"
        assert payload["next_due"] == "2025-02-01"

    def test_http_error_raises(
        self, sample_observation: CycleObservation
    ) -> None:
        cfg = WebhookConfig(
            url="https://hooks.example.com/in",
            secret="shared-secret",
        )
        channel = WebhookAlertChannel(cfg)

        with patch("urllib.request.urlopen") as urlopen:
            mock_response = MagicMock()
            mock_response.status = 500
            urlopen.return_value.__enter__.return_value = mock_response
            with pytest.raises(RuntimeError, match="status 500"):
                channel.dispatch(sample_observation)
