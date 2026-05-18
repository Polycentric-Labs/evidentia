"""Unit tests for evidentia_integrations.alerting.smtp (v0.9.3 P1.2)."""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock, patch

import pytest
from evidentia_core.conmon import CycleObservation, get_cadence
from evidentia_core.conmon.calendar import CycleAttentionState
from evidentia_integrations.alerting import SMTPAlertChannel, SMTPConfig


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


@pytest.fixture()
def valid_config() -> SMTPConfig:
    return SMTPConfig(
        host="smtp.example.com",
        port=587,
        username="alerter",
        password="resolved-password",
        sender="evidentia@example.com",
        recipients=["oncall@example.com"],
    )


class TestSMTPConfig:
    def test_rejects_empty_host(self) -> None:
        with pytest.raises(ValueError, match="SMTP host required"):
            SMTPConfig(
                host="",
                port=587,
                username="u",
                password="p",
                sender="s",
                recipients=["r"],
            )

    def test_rejects_invalid_port(self) -> None:
        with pytest.raises(ValueError, match="port must be"):
            SMTPConfig(
                host="smtp.example.com",
                port=70000,
                username="u",
                password="p",
                sender="s",
                recipients=["r"],
            )

    def test_rejects_empty_recipients(self) -> None:
        with pytest.raises(ValueError, match="recipient"):
            SMTPConfig(
                host="smtp.example.com",
                port=587,
                username="u",
                password="p",
                sender="s",
                recipients=[],
            )

    def test_rejects_plaintext_smtp(self) -> None:
        with pytest.raises(ValueError, match="STARTTLS is required"):
            SMTPConfig(
                host="smtp.example.com",
                port=587,
                username="u",
                password="p",
                sender="s",
                # v0.9.5 F-V93-S8: recipients now RFC 5321-validated;
                # use a real address so this test exercises the
                # STARTTLS-required branch (not the recipient
                # validation that runs first).
                recipients=["alerts@example.com"],
                use_starttls=False,
            )


class TestSMTPAlertChannel:
    def test_dispatch_invokes_starttls_and_login(
        self,
        valid_config: SMTPConfig,
        sample_observation: CycleObservation,
    ) -> None:
        channel = SMTPAlertChannel(valid_config)

        with patch("smtplib.SMTP") as smtp_class:
            smtp_instance = MagicMock()
            smtp_instance.has_extn.return_value = True
            smtp_class.return_value.__enter__.return_value = smtp_instance
            channel.dispatch(sample_observation)

        smtp_class.assert_called_once_with(
            host="smtp.example.com", port=587, timeout=10.0
        )
        smtp_instance.has_extn.assert_called_with("STARTTLS")
        smtp_instance.starttls.assert_called_once()
        smtp_instance.login.assert_called_once_with(
            "alerter", "resolved-password"
        )
        smtp_instance.send_message.assert_called_once()

    def test_dispatch_refuses_when_starttls_stripped(
        self,
        valid_config: SMTPConfig,
        sample_observation: CycleObservation,
    ) -> None:
        """v0.9.3 F-V93-S1 regression: a MITM stripping STARTTLS from
        the server EHLO advertisement (or a misconfigured server)
        must NOT cause plaintext credential transmission. The channel
        raises RuntimeError before login() is reached."""
        channel = SMTPAlertChannel(valid_config)

        with patch("smtplib.SMTP") as smtp_class:
            smtp_instance = MagicMock()
            smtp_instance.has_extn.return_value = False
            smtp_class.return_value.__enter__.return_value = smtp_instance
            with pytest.raises(RuntimeError, match="STARTTLS"):
                channel.dispatch(sample_observation)

        smtp_instance.starttls.assert_not_called()
        smtp_instance.login.assert_not_called()
        smtp_instance.send_message.assert_not_called()

    def test_subject_includes_slug_and_state(
        self,
        valid_config: SMTPConfig,
        sample_observation: CycleObservation,
    ) -> None:
        channel = SMTPAlertChannel(valid_config)
        with patch("smtplib.SMTP") as smtp_class:
            smtp_instance = MagicMock()
            smtp_class.return_value.__enter__.return_value = smtp_instance
            channel.dispatch(sample_observation)
        sent_msg = smtp_instance.send_message.call_args[0][0]
        subject = sent_msg["Subject"]
        assert "nist-800-53-rev5-ca7" in subject
        assert "OVERDUE" in subject

    def test_body_includes_cadence_details(
        self,
        valid_config: SMTPConfig,
        sample_observation: CycleObservation,
    ) -> None:
        channel = SMTPAlertChannel(valid_config)
        with patch("smtplib.SMTP") as smtp_class:
            smtp_instance = MagicMock()
            smtp_class.return_value.__enter__.return_value = smtp_instance
            channel.dispatch(sample_observation)
        sent_msg = smtp_instance.send_message.call_args[0][0]
        body = sent_msg.get_content()
        assert "nist-800-53-rev5" in body
        assert "2025-01-01" in body
        assert "2025-02-01" in body
