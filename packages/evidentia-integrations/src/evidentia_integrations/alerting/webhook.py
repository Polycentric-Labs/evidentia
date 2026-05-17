"""Generic HTTP webhook alert channel (v0.9.3 P1.2).

POSTs a JSON payload with an HMAC-SHA256 signature header so
downstream receivers can verify the message came from this
daemon (vs a spoofed source) using a shared secret.

Payload shape:

    {
      "cadence_slug": "nist-800-53-rev5-ca7",
      "framework":    "nist-800-53-rev5",
      "activity":     "continuous-monitoring",
      "state":        "overdue",
      "days_until_due": -45,
      "last_completed": "2026-01-01",
      "next_due":      "2026-02-01"
    }

Signature headers (v0.9.3 F-V93-S3 review fix — adds replay
protection per Slack/Stripe convention):

    X-Evidentia-Timestamp: <unix-epoch-seconds>
    X-Evidentia-Signature: sha256=<hex digest>

Receivers compute ``HMAC-SHA256(shared_secret, f"{timestamp}.{body}")``
and compare to the signature header. Additionally, receivers MUST
reject requests where ``abs(now - X-Evidentia-Timestamp) > 300``
seconds (5-minute window) to defeat capture-replay attacks. Without
the staleness check, an attacker who captures a valid POST can
replay it indefinitely since CONMON observation payloads are
otherwise stable.

Secrets per the v0.9.3 cycle-open sign-off:

- ``WebhookConfig.secret`` MUST already be resolved via
  :func:`evidentia_core.conmon.alerting.resolve_secret`.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import socket
import time
import urllib.request
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from evidentia_core.conmon.daemon import CycleObservation


@dataclass(frozen=True)
class WebhookConfig:
    """Operator-supplied webhook channel configuration. Immutable.

    SSRF mitigation (v0.9.4 P1.2 closes F-V93-S2 MEDIUM, CWE-918):

    By default, only ``https://`` URLs pointing to publicly-routable
    hosts are accepted. The following are REJECTED at construction:

    - ``http://`` schemes (cleartext) — opt-in via ``allow_plaintext=True``
    - Hostnames resolving to loopback addresses (127/8, ::1)
    - Hostnames resolving to RFC1918 private ranges
      (10/8, 172.16/12, 192.168/16) and RFC6890 reserved ranges
    - Hostnames resolving to link-local addresses (169.254/16, fe80::/10)

    The last three categories are gated by
    ``allow_private_network=True``. Operators with legitimate
    internal-network webhook receivers (e.g., on-cluster Slack
    proxies, on-prem PagerDuty bridges) must opt in explicitly.

    The threat: without this guard, an attacker who can influence
    the webhook URL (via operator config injection, supply-chain
    catalog poisoning, etc.) can force the daemon to POST signed
    JSON containing CONMON state to internal-only endpoints —
    including the cloud-metadata service at ``169.254.169.254``,
    leaking credentials assigned to the daemon's IAM role.

    DNS resolution happens at config-construction time only. If the
    hostname's IP changes after daemon start (DNS rebinding), the
    underlying ``urlopen`` call still hits the new IP and bypasses
    this guard. Operators in adversarial-DNS environments should
    pin the webhook host to a known IP in /etc/hosts or use a
    private DNS resolver that ignores rebinding TTLs.
    """

    url: str
    secret: str
    timeout_seconds: float = 10.0
    allow_plaintext: bool = False
    allow_private_network: bool = False
    # Internal: populated by __post_init__ for diagnostics + tests.
    _resolved_ips: tuple[str, ...] = field(default_factory=tuple, repr=False)

    def __post_init__(self) -> None:
        if not self.url:
            raise ValueError("webhook URL required")
        parsed = urlparse(self.url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"webhook URL must be http:// or https://; "
                f"got {self.url!r}"
            )
        if parsed.scheme == "http" and not self.allow_plaintext:
            raise ValueError(
                f"webhook URL is plaintext http:// ({self.url!r}); "
                "pass allow_plaintext=True (or CLI "
                "--webhook-allow-plaintext) to permit. Cleartext "
                "transmission exposes the HMAC-signed payload + "
                "headers to on-path attackers."
            )
        if not parsed.hostname:
            raise ValueError(
                f"webhook URL has no hostname; got {self.url!r}"
            )
        if not self.secret:
            raise ValueError(
                "webhook secret required (resolve via "
                "evidentia_core.conmon.alerting.resolve_secret)"
            )

        # SSRF guard: resolve hostname → reject private/loopback/
        # link-local/reserved unless opted in. Use getaddrinfo so
        # IPv6 is covered uniformly with IPv4.
        try:
            addrinfo = socket.getaddrinfo(
                parsed.hostname, parsed.port, type=socket.SOCK_STREAM
            )
        except socket.gaierror as exc:
            raise ValueError(
                f"webhook hostname {parsed.hostname!r} did not "
                f"resolve: {exc}"
            ) from exc

        resolved_ips = tuple(sorted({ai[4][0] for ai in addrinfo}))
        # Cannot use object.__setattr__ trick for tuple of mutable
        # default; dataclass(frozen=True) requires it. The field's
        # ``default_factory`` initialized it to (); replace via the
        # frozen-dataclass workaround.
        object.__setattr__(self, "_resolved_ips", resolved_ips)

        if not self.allow_private_network:
            for ip_str in resolved_ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue
                if (
                    ip.is_loopback
                    or ip.is_private
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_multicast
                ):
                    raise ValueError(
                        f"webhook hostname {parsed.hostname!r} "
                        f"resolved to non-public address {ip_str} "
                        f"(loopback/private/link-local/reserved/"
                        f"multicast). Pass allow_private_network="
                        f"True (or CLI --webhook-allow-private-"
                        f"network) to permit. Default-deny prevents "
                        f"SSRF / cloud-metadata-service exfiltration "
                        f"(CWE-918)."
                    )


class WebhookAlertChannel:
    """:class:`AlertChannel` impl that POSTs to a single webhook
    endpoint per observation. Uses stdlib urllib to avoid taking on
    requests/httpx as a runtime dep for a single POST.
    """

    name = "webhook"

    def __init__(self, config: WebhookConfig) -> None:
        self._config = config

    def dispatch(self, obs: CycleObservation) -> None:
        payload = {
            "cadence_slug": obs.cadence.slug,
            "framework": obs.cadence.framework,
            "activity": obs.cadence.activity,
            "state": obs.state.value,
            "days_until_due": obs.days_until_due,
            "last_completed": obs.last_completed.isoformat(),
            "next_due": obs.next_due.isoformat(),
        }
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        # v0.9.3 F-V93-S3 review fix: include unix-epoch timestamp in
        # the signed material so receivers can detect capture-replay.
        timestamp = str(int(time.time()))
        signed_material = f"{timestamp}.".encode() + body
        signature = hmac.new(
            self._config.secret.encode("utf-8"),
            signed_material,
            hashlib.sha256,
        ).hexdigest()

        request = urllib.request.Request(
            url=self._config.url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "evidentia-conmon-daemon/v0.9.3",
                "X-Evidentia-Timestamp": timestamp,
                "X-Evidentia-Signature": f"sha256={signature}",
            },
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self._config.timeout_seconds,
            ) as response:
                if response.status >= 400:
                    raise RuntimeError(
                        f"webhook POST returned status "
                        f"{response.status}"
                    )
        except HTTPError as exc:
            raise RuntimeError(
                f"webhook POST failed with HTTP {exc.code}: "
                f"{exc.reason}"
            ) from exc
        except URLError as exc:
            raise RuntimeError(
                f"webhook POST failed (transport): {exc.reason}"
            ) from exc
