"""Unit tests for evidentia_integrations.alerting.webhook (v0.9.3 P1.2)."""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
from datetime import date
from unittest.mock import MagicMock, patch

import pytest
from evidentia_core.conmon import CycleObservation, get_cadence
from evidentia_core.conmon.calendar import CycleAttentionState
from evidentia_integrations.alerting import (
    WebhookAlertChannel,
    WebhookConfig,
)


# v0.9.4 P1.2: WebhookConfig.__post_init__ now resolves the URL
# hostname to check for SSRF (loopback/RFC1918/etc). Tests must
# monkeypatch socket.getaddrinfo so they don't depend on real DNS
# (slow + flaky on offline CI runners + cross-platform variance).
@pytest.fixture(autouse=True)
def _mock_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default DNS mock: any hostname → public IP 93.184.215.14
    (the real example.com IP). Tests that need different behavior
    (loopback, RFC1918, etc.) re-monkeypatch within the test."""

    def _fake_getaddrinfo(
        host: str,
        port: int | None,
        *args: object,
        **kwargs: object,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        # Literal IPs bypass the mock — return as-is so SSRF tests
        # using 127.0.0.1 / 192.168.x.x / 169.254.169.254 are
        # classified correctly by ipaddress.ip_address().
        try:
            socket.inet_pton(socket.AF_INET, host)
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (host, port or 0))]
        except OSError:
            pass
        # Fake DNS: hostnames map to a public IP unless test overrides.
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.215.14", port or 0))
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)


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

    def test_accepts_public_https(self) -> None:
        """Public HTTPS URL is the default-allowed shape (no opt-ins)."""
        cfg = WebhookConfig(
            url="https://hooks.example.com/in", secret="s"
        )
        assert cfg.url == "https://hooks.example.com/in"

    # v0.9.4 P1.2 SSRF mitigation — default-deny tests.

    def test_rejects_http_plaintext_by_default(self) -> None:
        """v0.9.4 F-V93-S2: http:// rejected without explicit opt-in."""
        with pytest.raises(ValueError, match=r"plaintext|allow_plaintext"):
            WebhookConfig(url="http://hooks.example.com/in", secret="s")

    def test_accepts_http_with_allow_plaintext(self) -> None:
        """v0.9.4 F-V93-S2: http:// permitted with opt-in."""
        cfg = WebhookConfig(
            url="http://hooks.example.com/in",
            secret="s",
            allow_plaintext=True,
        )
        assert cfg.url == "http://hooks.example.com/in"

    def test_rejects_loopback_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """v0.9.4 F-V93-S2: 127.0.0.1 rejected without opt-in."""
        with pytest.raises(ValueError, match=r"non-public|loopback|private"):
            WebhookConfig(url="https://127.0.0.1/hook", secret="s")

    def test_rejects_rfc1918_by_default(self) -> None:
        """v0.9.4 F-V93-S2: 192.168.x.x rejected without opt-in."""
        with pytest.raises(ValueError, match=r"non-public|loopback|private"):
            WebhookConfig(url="https://192.168.1.1/hook", secret="s")

    def test_rejects_cloud_metadata_service(self) -> None:
        """v0.9.4 F-V93-S2: 169.254.169.254 (cloud metadata) rejected.
        This is the cloud-IAM-credential-exfiltration vector that
        motivated default-deny."""
        with pytest.raises(
            ValueError, match=r"non-public|link-local|reserved"
        ):
            WebhookConfig(
                url="https://169.254.169.254/latest/meta-data/iam/security-credentials/",
                secret="s",
            )

    def test_accepts_loopback_with_allow_private_network(self) -> None:
        """v0.9.4 F-V93-S2: loopback permitted with explicit opt-in
        (legitimate use case: local proxy/bridge on-host)."""
        cfg = WebhookConfig(
            url="https://127.0.0.1/hook",
            secret="s",
            allow_private_network=True,
        )
        assert cfg.url == "https://127.0.0.1/hook"

    def test_accepts_rfc1918_with_allow_private_network(self) -> None:
        """v0.9.4 F-V93-S2: RFC1918 permitted with explicit opt-in
        (legitimate use case: on-cluster Slack proxy, on-prem PD bridge)."""
        cfg = WebhookConfig(
            url="https://10.0.0.5/hook",
            secret="s",
            allow_private_network=True,
        )
        assert cfg.url == "https://10.0.0.5/hook"

    def test_rejects_unresolvable_hostname(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """v0.9.4 F-V93-S2: hostname resolution failure raises clearly."""

        def _fail_resolve(*args: object, **kwargs: object) -> None:
            raise socket.gaierror("Name or service not known")

        monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)
        with pytest.raises(ValueError, match="did not resolve"):
            WebhookConfig(
                url="https://does-not-exist.invalid/hook", secret="s"
            )


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
