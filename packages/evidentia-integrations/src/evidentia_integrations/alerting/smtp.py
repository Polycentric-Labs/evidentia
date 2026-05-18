"""SMTP alert channel (v0.9.3 P1.2).

STARTTLS-only SMTP sender. Plaintext SMTP is unsupported by design —
operators using internal mail relays should still use STARTTLS or
wire their own channel.

Credentials per the v0.9.3 cycle-open sign-off:

- Password resolves via :func:`evidentia_core.conmon.alerting.resolve_secret`
  (file > env > error precedence).
- Never accepts the password as a constructor positional or
  attribute; callers MUST pass the resolved string.
"""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage

from evidentia_core.conmon.daemon import CycleObservation


@dataclass(frozen=True)
class SMTPConfig:
    """Operator-supplied SMTP channel configuration. Immutable.

    Constructed once at CLI parse time; the password value must
    already be resolved via
    :func:`evidentia_core.conmon.alerting.resolve_secret` so we
    never carry the file path around the daemon's runtime state.
    """

    host: str
    port: int
    username: str
    password: str
    sender: str
    recipients: list[str]
    use_starttls: bool = True
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        if not self.host:
            raise ValueError("SMTP host required")
        if self.port <= 0 or self.port > 65535:
            raise ValueError(
                f"SMTP port must be in (0, 65535]; got {self.port}"
            )
        if not self.recipients:
            raise ValueError("at least one recipient required")
        # v0.9.5 F-V93-S8 closure: validate each recipient against
        # the RFC 5321 / RFC 5322 ``local@domain`` shape using
        # stdlib's email.utils parser. Rejects malformed entries
        # (no ``@``, multi-``@``, control chars, leading/trailing
        # whitespace) at config-construction time so the daemon
        # fails loud at boot rather than silently dropping alerts
        # at smtp.send() time. This is light-touch validation —
        # it does NOT verify MX records or mailbox existence;
        # operators wanting that should configure SMTP-level
        # recipient verification at the relay.
        from email.utils import parseaddr

        for recipient in self.recipients:
            _name, addr = parseaddr(recipient)
            if not addr or "@" not in addr or addr.count("@") != 1:
                raise ValueError(
                    f"recipient {recipient!r} is not a valid RFC 5321 "
                    f"address (expected local@domain); parsed addr="
                    f"{addr!r}"
                )
            local, _, domain = addr.partition("@")
            if not local or not domain or "." not in domain:
                raise ValueError(
                    f"recipient {recipient!r} missing local-part or "
                    f"domain-with-dot (got local={local!r} "
                    f"domain={domain!r})"
                )
            # Reject control characters + whitespace embedded in
            # the address — RFC 5321 forbids these in the wire
            # form and they're a common SMTP-injection vector.
            if any(ch.isspace() or ord(ch) < 32 for ch in addr):
                raise ValueError(
                    f"recipient {recipient!r} contains whitespace "
                    f"or control characters; not a valid RFC 5321 "
                    f"address"
                )
        if not self.use_starttls:
            # Plaintext SMTP is unsupported by design.
            raise ValueError(
                "use_starttls=False is unsupported; STARTTLS is required"
            )


class SMTPAlertChannel:
    """:class:`AlertChannel` impl that sends one email per
    observation. Re-establishes the SMTP connection per dispatch —
    keeps the daemon simple at the cost of mild per-call latency,
    which doesn't matter at CONMON polling cadences.
    """

    name = "smtp"

    def __init__(self, config: SMTPConfig) -> None:
        self._config = config

    def dispatch(self, obs: CycleObservation) -> None:
        msg = EmailMessage()
        msg["Subject"] = self._subject(obs)
        msg["From"] = self._config.sender
        msg["To"] = ", ".join(self._config.recipients)
        msg.set_content(self._body(obs))

        with smtplib.SMTP(
            host=self._config.host,
            port=self._config.port,
            timeout=self._config.timeout_seconds,
        ) as client:
            client.ehlo()
            # v0.9.3 F-V93-S1 review fix: refuse to send if the
            # server (or a MITM stripping the STARTTLS advertisement)
            # doesn't offer STARTTLS. Explicit ssl context is passed
            # so cert verification doesn't depend on stdlib defaults
            # being unchanged by process-wide monkey-patches.
            if not client.has_extn("STARTTLS"):
                raise RuntimeError(
                    f"SMTP server {self._config.host}:{self._config.port} "
                    "did not advertise STARTTLS; refusing to send "
                    "credentials over plaintext (set use_starttls=False "
                    "is unsupported; configure a TLS-capable relay)"
                )
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
            if self._config.username:
                client.login(self._config.username, self._config.password)
            client.send_message(msg)

    @staticmethod
    def _subject(obs: CycleObservation) -> str:
        state_label = (
            "OVERDUE" if obs.state.value == "overdue" else "due soon"
        )
        return (
            f"[Evidentia CONMON] {obs.cadence.slug} {state_label} "
            f"(next-due {obs.next_due.isoformat()})"
        )

    @staticmethod
    def _body(obs: CycleObservation) -> str:
        days_phrase = (
            f"{abs(obs.days_until_due)} day(s) past next-due"
            if obs.days_until_due < 0
            else f"due in {obs.days_until_due} day(s)"
        )
        citation = obs.cadence.citation or "(no citation)"
        return (
            f"CONMON cycle attention required.\n"
            f"\n"
            f"  Cadence slug:    {obs.cadence.slug}\n"
            f"  Framework:       {obs.cadence.framework}\n"
            f"  Activity:        {obs.cadence.activity}\n"
            f"  Frequency:       {obs.cadence.frequency}\n"
            f"  State:           {obs.state.value}\n"
            f"  Last completed:  {obs.last_completed.isoformat()}\n"
            f"  Next due:        {obs.next_due.isoformat()}\n"
            f"  Days until due:  {days_phrase}\n"
            f"  Citation:        {citation}\n"
            f"\n"
            f"This alert was generated by the Evidentia CONMON\n"
            f"daemon (evidentia conmon watch).\n"
        )
