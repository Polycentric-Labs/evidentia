"""CONMON daemon alerting channel reference implementations (v0.9.3 P1.2).

SMTP and generic HTTP webhook senders that implement the
:class:`evidentia_core.conmon.alerting.AlertChannel` Protocol.

Operators wire these into ``evidentia conmon watch`` via the
``--smtp-*`` and ``--webhook-*`` CLI flags. Custom channels live
in operator code and just need to match the Protocol signature.

Per the v0.9.3 cycle-open sign-off question-4: credentials resolve
via file > env > error precedence; CLI value flags for secrets are
explicitly rejected.
"""

from __future__ import annotations

from evidentia_integrations.alerting.smtp import (
    SMTPAlertChannel,
    SMTPConfig,
)
from evidentia_integrations.alerting.webhook import (
    WebhookAlertChannel,
    WebhookConfig,
)

__all__ = [
    "SMTPAlertChannel",
    "SMTPConfig",
    "WebhookAlertChannel",
    "WebhookConfig",
]
