"""Air-gapped mode — network-call guard for v0.4.0's ``--offline`` flag.

Positioning: *"The only open-source GRC tool that runs entirely on your
infrastructure."* This module enforces that claim — when offline mode is
on, any attempted outbound network call that isn't loopback or RFC-1918
raises :class:`OfflineViolationError` **before** the network IO is
issued. The error is structured so the CLI and the GUI can render a
clear explanation (subsystem, target host, remediation).

The guard is consulted from three subsystems:

1. :mod:`evidentia_ai.client` — every LLM completion call checks the
   configured model prefix + ``api_base`` kwarg. Only Ollama-style prefixes
   and custom endpoints pointing at loopback/private IPs are allowed.
2. :mod:`evidentia_core.catalogs.loader` — ``catalog import --from-url``
   refuses non-loopback URLs.
3. :mod:`evidentia.cli.doctor` — ``evidentia doctor --check-air-gap``
   exercises every subsystem and reports its offline posture.

The enabling surface is tiny on purpose. Call :func:`set_offline(True)`
once at process start (the CLI's global callback does this when
``--offline`` is set; the FastAPI app factory does it from
``app.state.offline``) and every subsystem's guard checks become active.
Use :func:`offline_mode()` as a context manager for test fixtures that
need per-block enablement.

Design note: a module-level flag rather than contextvars. Evidentia's
CLI is single-process and the FastAPI server's handlers read request
state at call time, so the flag's lack of per-request isolation doesn't
matter in practice. If a future release adds worker pools with mixed
offline/online tenants, revisit.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

__all__ = [
    "LOCAL_LLM_PREFIXES",
    "OfflineViolationError",
    "SSRFBlockedError",
    "check_llm_model",
    "check_url",
    "enforce_public_host",
    "is_loopback_or_private",
    "is_offline",
    "offline_mode",
    "pin_resolved_host",
    "resolve_host_is_private",
    "set_offline",
]

# ── Module-level state ────────────────────────────────────────────────────

_offline_enabled: bool = False
"""When True, all guard checks raise on non-loopback/RFC-1918 targets."""


def is_offline() -> bool:
    """Return True if offline mode is currently enabled for this process."""
    return _offline_enabled


def set_offline(enabled: bool) -> None:
    """Toggle offline mode process-wide.

    Called exactly once at CLI startup (in the global ``--offline`` flag
    handler) or at FastAPI app creation time (when ``--offline`` was passed
    to ``evidentia serve``). Explicit enable/disable avoids the subtle
    bugs you get from "remember to reset" patterns in tests.
    """
    global _offline_enabled
    _offline_enabled = bool(enabled)
    if _offline_enabled:
        logger.info(
            "Air-gapped mode ENABLED — outbound network calls to non-loopback "
            "hosts will raise OfflineViolationError."
        )


@contextmanager
def offline_mode(enabled: bool = True) -> Iterator[None]:
    """Context manager that toggles offline mode for the duration of a block.

    Useful for test fixtures and short-lived subsystems that need offline
    enforcement without leaking into the rest of the process::

        with offline_mode():
            # guarded region
            ...

    Restores the prior offline state on exit even if an exception fires.
    """
    previous = _offline_enabled
    set_offline(enabled)
    try:
        yield
    finally:
        set_offline(previous)


# ── Exception ─────────────────────────────────────────────────────────────


class OfflineViolationError(Exception):
    """Raised when offline mode is on and a disallowed network target is detected.

    Attributes
    ----------
    subsystem
        Which Evidentia module flagged the violation
        (``'llm_client'``, ``'catalog_loader'``, etc.).
    target
        The host / URL / model string that would have leaked.
    remediation
        One-line hint for the user; rendered in the CLI error path and
        surfaced to the GUI via the /api/*/error response body.
    """

    def __init__(
        self, *, subsystem: str, target: str, remediation: str = ""
    ) -> None:
        self.subsystem = subsystem
        self.target = target
        self.remediation = remediation
        message = (
            f"Air-gapped mode refuses network call from {subsystem}: "
            f"target={target!r}"
        )
        if remediation:
            message += f" -- {remediation}"
        super().__init__(message)


# ── Host allowlisting ─────────────────────────────────────────────────────

# Hostnames that always resolve to loopback; we skip IP resolution for these
# to avoid a DNS round-trip on every guarded call.
_LOOPBACK_HOSTNAMES = frozenset({"localhost", "localhost.localdomain"})


def is_loopback_or_private(host: str) -> bool:
    """Return True if ``host`` is a loopback, link-local, or RFC-1918 address.

    Accepts both hostnames (``localhost``, ``localhost.localdomain``) and
    IP addresses (``127.0.0.1``, ``10.0.0.5``, ``192.168.1.7``, ``::1``,
    ``fd00::1``, etc.). Hostnames that aren't in the reserved-loopback
    set and don't parse as IPs return False — callers should not
    DNS-resolve arbitrary hostnames in offline mode (the DNS query itself
    is a leak).

    Allowed ranges:
    - IPv4 loopback (``127.0.0.0/8``)
    - IPv4 link-local (``169.254.0.0/16``)
    - IPv4 private (RFC-1918): ``10.0.0.0/8``, ``172.16.0.0/12``, ``192.168.0.0/16``
    - IPv6 loopback (``::1``)
    - IPv6 link-local (``fe80::/10``)
    - IPv6 unique-local (``fc00::/7`` — RFC-4193)
    """
    if not host:
        return False

    host_lower = host.lower().strip()
    if host_lower in _LOOPBACK_HOSTNAMES:
        return True

    # Strip IPv6 brackets if present (urlparse gives us "[::1]" hosts).
    if host_lower.startswith("[") and host_lower.endswith("]"):
        host_lower = host_lower[1:-1]

    try:
        ip = ipaddress.ip_address(host_lower)
    except ValueError:
        return False

    return bool(ip.is_loopback or ip.is_private or ip.is_link_local)


# ── URL + LLM guards ──────────────────────────────────────────────────────


def check_url(url: str, *, subsystem: str, remediation: str = "") -> None:
    """Raise :class:`OfflineViolationError` if offline mode is on and URL is external.

    No-op when offline mode is off. When on, parses ``url`` and consults
    :func:`is_loopback_or_private` on the host component.

    Parameters
    ----------
    url
        The full URL about to be fetched (any scheme).
    subsystem
        Human-readable caller label for the error; used for diagnostics.
    remediation
        Optional one-line hint to surface to the user.
    """
    if not _offline_enabled:
        return

    parsed = urlparse(url)
    host = parsed.hostname or ""
    if is_loopback_or_private(host):
        return

    raise OfflineViolationError(
        subsystem=subsystem,
        target=url,
        remediation=remediation
        or "Configure a local endpoint (Ollama, vLLM, mirror proxy) or disable --offline.",
    )


# LLM model prefixes that are always offline-safe — they either route to
# localhost (Ollama) or require explicit api_base (vLLM + custom OpenAI-
# compatible endpoints) which is checked separately.
LOCAL_LLM_PREFIXES: tuple[str, ...] = (
    "ollama/",
    "ollama_chat/",
    "vllm/",
    "text-completion-openai/",  # Aliased route LiteLLM uses for OpenAI-compatible
)


def check_llm_model(
    model: str,
    *,
    api_base: str | None = None,
    subsystem: str = "llm_client",
) -> None:
    """Raise :class:`OfflineViolationError` if offline mode rejects this LLM config.

    Allowed in offline mode:
    - Any model whose prefix is in :data:`LOCAL_LLM_PREFIXES`
      (``ollama/...``, ``vllm/...``, etc.)
    - Any model with an explicit ``api_base`` pointing at a loopback or
      RFC-1918 address (covers self-hosted OpenAI-compatible endpoints).

    Everything else raises. This is intentionally conservative — we'd
    rather fail closed than let a cloud LLM sneak through on a model
    string we don't recognize.
    """
    if not _offline_enabled:
        return

    # If the caller provided a custom api_base, its host determines allowlisting
    # regardless of the model string.
    if api_base:
        parsed = urlparse(api_base)
        host = parsed.hostname or ""
        if is_loopback_or_private(host):
            return
        raise OfflineViolationError(
            subsystem=subsystem,
            target=f"{model} @ {api_base}",
            remediation=(
                "api_base points at a non-loopback host. Use localhost / "
                "RFC-1918 or switch to an ollama/* model."
            ),
        )

    # Without api_base, rely on the model prefix whitelist.
    model_lower = model.lower()
    for prefix in LOCAL_LLM_PREFIXES:
        if model_lower.startswith(prefix):
            return

    raise OfflineViolationError(
        subsystem=subsystem,
        target=model,
        remediation=(
            "Cloud LLM models are refused in air-gapped mode. Switch to "
            "ollama/llama3 (or similar) or set api_base to a local "
            "OpenAI-compatible endpoint."
        ),
    )


# ── SSRF guard (default-on, opposite polarity to the offline guard) ────────
#
# The offline guard above *allows* loopback / RFC-1918 and *blocks* the public
# internet — it enforces the air-gap claim. The SSRF guard below is its mirror
# image: it *blocks* private / loopback / link-local / metadata addresses and
# *allows* the public internet. It exists because every outbound collector that
# accepts an operator-supplied host (Okta org_url, Databricks/GitHub base_url,
# the SQL connection URIs, the four vendor-risk SaaS base_urls) is an SSRF sink
# that could otherwise be pointed at cloud instance-metadata endpoints
# (169.254.169.254) or internal services. This consolidates the per-collector
# refusal that previously lived only in the OCSF URL collector
# (``_refuse_private_host``) into one reusable, default-on helper so the bar is
# uniform across every collector + the API collectors router.
#
# Unlike the offline guard this is NOT gated by a process-wide flag — it is
# always active unless the caller explicitly opts out (``block_private=False``,
# surfaced as the ``--allow-private-ips`` CLI flag), because secure-by-default
# is the whole point of closing threat-model T2.


class SSRFBlockedError(Exception):
    """Raised when an outbound target resolves to a non-public address.

    The SSRF guard refuses, by default, any host that resolves to a
    private (RFC-1918), loopback, link-local (covers the AWS / GCP /
    Azure 169.254.169.254 instance-metadata endpoints), multicast,
    reserved, or unspecified address — closing the server-side request
    forgery surface on every outbound collector.

    Attributes
    ----------
    subsystem
        Which collector flagged the violation (``'okta'``,
        ``'databricks'``, ``'sql-postgres'``, etc.).
    host
        The hostname that was resolved.
    resolved_ip
        The first disallowed address the host resolved to.
    """

    def __init__(
        self, *, subsystem: str, host: str, resolved_ip: str
    ) -> None:
        self.subsystem = subsystem
        self.host = host
        self.resolved_ip = resolved_ip
        super().__init__(
            f"{subsystem}: refusing outbound request — host {host!r} "
            f"resolves to {resolved_ip} (private / loopback / link-local / "
            "multicast / reserved / unspecified address rejected per SSRF "
            "policy). Pass --allow-private-ips (CLI) or block_private=False "
            "(library) to override for trusted internal endpoints."
        )


# RFC 6598 carrier-grade-NAT space (100.64.0.0/10). cpython's
# ``ipaddress`` does NOT flag it as private/reserved, yet some cloud
# fabrics route internal endpoints through it — block it explicitly
# (v0.10.10 pre-release-review SSRF hardening, INFO-2).
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")


def _ip_is_non_public(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Return True if ``ip`` falls in any non-public range.

    Mirrors the ranges the OCSF URL collector rejected (the v0.10.2
    F-V101-L1 close-out): RFC-1918 private, loopback, link-local
    (cloud-metadata services), multicast, reserved, and unspecified —
    plus RFC 6598 carrier-grade NAT (100.64.0.0/10), which cpython's
    ``ipaddress`` does not classify as private but some cloud fabrics
    use for internal endpoints.
    """
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (ip.version == 4 and ip in _CGNAT_V4)
    )


def resolve_host_is_private(host: str) -> tuple[bool, str]:
    """Resolve ``host`` and report whether ANY address is non-public.

    Resolves via :func:`socket.getaddrinfo` (covers IPv4 + IPv6 +
    literal IPs + DNS-rebinding attempts that return private-range
    addresses), walks every returned address, and returns
    ``(True, first_bad_ip)`` as soon as one falls in a non-public range.
    The "any address" check matters because a malicious DNS record can
    return multiple addresses and rely on the client picking the public
    one — we treat the entire host as disallowed if any record points
    internal.

    Returns ``(False, "")`` when every resolved address is public.

    Raises
    ------
    socket.gaierror
        If the hostname cannot be resolved. Callers map this to their
        own connection-error type.
    """
    is_private, bad_ip, _public_ips = _resolve_and_classify(host)
    return is_private, bad_ip


def _resolve_and_classify(host: str) -> tuple[bool, str, list[str]]:
    """Resolve ``host`` once and classify every returned address.

    Returns ``(is_private, first_bad_ip, public_ips)``. The
    ``public_ips`` list is the de-duplicated set of public addresses the
    host resolved to (in resolution order) — the validated set the
    caller pins the subsequent connection to so the connecting library's
    independent re-resolution cannot return a different (rebound) address.

    The classification short-circuits on the FIRST non-public address
    (an "any address is bad" policy — see :func:`resolve_host_is_private`),
    so ``public_ips`` is only meaningful when ``is_private`` is False.

    Calls :func:`socket.getaddrinfo` exactly once — the resolution the
    pin then locks in.

    Raises
    ------
    socket.gaierror
        If the hostname cannot be resolved.
    """
    public_ips: list[str] = []
    for *_unused, sockaddr in socket.getaddrinfo(host, None):
        ip_str = str(sockaddr[0])
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _ip_is_non_public(ip):
            return True, ip_str, []
        if ip_str not in public_ips:
            public_ips.append(ip_str)
    return False, "", public_ips


def enforce_public_host(
    url_or_host: str,
    *,
    subsystem: str,
    block_private: bool = True,
) -> list[str]:
    """Refuse an outbound request whose host resolves to a private address.

    The single reusable SSRF chokepoint for every outbound collector.
    Accepts either a full URL (``https://host/path``) or a bare host
    (``host`` / ``host:port``) and extracts the hostname before
    resolving. No-op when ``block_private`` is False (the deliberate
    opt-out, surfaced as ``--allow-private-ips`` on the CLI).

    Returns the list of validated public IP addresses the host resolved
    to (resolution order, de-duplicated). Callers pass this list — paired
    with the same hostname — to :func:`pin_resolved_host` so the
    connecting library's INDEPENDENT re-resolution is forced to the
    addresses this guard already classified as public. Without that pin a
    low-TTL attacker DNS record can pass validation here as public and
    then re-resolve to ``169.254.169.254`` (cloud-metadata) or an
    internal host at connection time — the DNS-rebinding bypass this
    guard would otherwise leave open. Returns ``[]`` when ``block_private``
    is False (nothing was validated, so nothing is pinnable).

    Parameters
    ----------
    url_or_host
        A full URL or a bare host/host:port string.
    subsystem
        Caller label for the error + diagnostics (e.g. ``'okta'``).
    block_private
        When True (default), enforce the refusal. When False, the
        deliberate opt-out for trusted internal endpoints — secure-by-
        default means internal-endpoint collection now requires this
        flag (a behavior change).

    Returns
    -------
    list[str]
        The validated public IPs the host resolved to. Empty when
        ``block_private`` is False.

    Raises
    ------
    SSRFBlockedError
        If ``block_private`` is True and the host resolves to a
        private / loopback / link-local / multicast / reserved /
        unspecified address, OR if the host cannot be resolved (a
        host that does not resolve cannot be proven public, so it is
        refused fail-closed).
    """
    if not block_private:
        return []

    host = _extract_host(url_or_host)
    if not host:
        raise SSRFBlockedError(
            subsystem=subsystem, host=url_or_host, resolved_ip="(no host)"
        )

    try:
        is_private, bad_ip, public_ips = _resolve_and_classify(host)
    except socket.gaierror as exc:
        # Fail closed: a host we cannot resolve cannot be proven public.
        raise SSRFBlockedError(
            subsystem=subsystem, host=host, resolved_ip="(unresolvable)"
        ) from exc
    if is_private:
        raise SSRFBlockedError(
            subsystem=subsystem, host=host, resolved_ip=bad_ip
        )
    return public_ips


def _extract_host(url_or_host: str) -> str:
    """Pull the hostname out of a URL or a bare host[:port] string.

    Handles ``https://host/path`` (urlparse), ``host:port``, bare
    ``host``, and bracketed IPv6 (``[::1]`` / ``https://[::1]:8443``).
    Returns "" when no host can be extracted.
    """
    candidate = url_or_host.strip()
    if "://" in candidate:
        parsed_host = urlparse(candidate).hostname
        return parsed_host or ""
    # Bare host / host:port. urlparse needs a scheme to populate
    # .hostname, so synthesize one — this also strips a :port and
    # unwraps bracketed IPv6 correctly.
    parsed_host = urlparse(f"//{candidate}").hostname
    return parsed_host or ""


# ── Resolution pinning (DNS-rebinding defeat — F-V1010-S1 close-out) ───────
#
# enforce_public_host resolves + validates a host, but every connecting
# library (httpx, urllib, the SQL drivers, the Databricks / Snowflake SDKs)
# RE-RESOLVES the same hostname independently when it opens its socket. A
# low-TTL attacker DNS record can therefore pass validation as public and
# then re-resolve to 169.254.169.254 / an internal host between the two
# lookups — a classic TOCTOU DNS-rebinding bypass.
#
# The fix pins the validated resolution THROUGH the connection: for the
# current thread only, socket.getaddrinfo(<pinned-host>, ...) returns ONLY
# the addresses enforce_public_host already classified as public. The
# hostname is unchanged, so TLS SNI + the Host header + certificate
# verification all still use the original hostname — only the address the
# socket dials is locked. We install a single process-level getaddrinfo
# wrapper that consults a thread-local registry; unregistered hosts (and
# every other thread) delegate to the real getaddrinfo unchanged, so the
# process-wide resolution behavior is not altered.
#
# Thread-locality is correct on the exposed paths: the CLI is single-process
# and every API collector route invokes its collector SYNCHRONOUSLY inline in
# the async handler (no run_in_threadpool / to_thread / await between the
# enforce_public_host validation and the driver's connect), so the validation
# and the connection share one thread and the pin holds across both.

_pin_state = threading.local()

# The resolver the wrapper delegates to for un-pinned hosts. Set at install
# time to whatever ``socket.getaddrinfo`` was immediately before we replaced
# it (the real resolver in production; a monkeypatched stub under test). The
# wrapper is marked so we can detect + re-wrap if some other library replaces
# ``socket.getaddrinfo`` after us — keeping the delegate current.
_GETADDRINFO_DELEGATE: Any = socket.getaddrinfo
_pin_install_lock = threading.Lock()


def _pinned_getaddrinfo(
    host: object,
    port: object,
    family: int = 0,
    type: int = 0,  # match socket.getaddrinfo's positional signature
    proto: int = 0,
    flags: int = 0,
) -> list[tuple[int, int, int, str, tuple[object, ...]]]:
    """getaddrinfo wrapper that returns pinned addresses for pinned hosts.

    For a host registered on the CURRENT thread via
    :func:`pin_resolved_host`, synthesize addrinfo tuples for the
    pre-validated public IPs at the requested ``port`` (rebuilding the
    tuple shape per address family). Every other host — and every other
    thread — falls through to the delegate resolver untouched.
    """
    registry: dict[str, list[str]] = getattr(_pin_state, "hosts", {})
    pinned_ips = (
        registry.get(host.lower()) if isinstance(host, str) else None
    )
    if not pinned_ips:
        return _GETADDRINFO_DELEGATE(  # type: ignore[no-any-return]
            host, port, family, type, proto, flags
        )

    results: list[tuple[int, int, int, str, tuple[object, ...]]] = []
    socktype = type or socket.SOCK_STREAM
    for ip_str in pinned_ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        af = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        if family not in (0, socket.AF_UNSPEC) and family != af:
            # Caller asked for a specific family that this pinned
            # address doesn't satisfy — skip it.
            continue
        sockaddr: tuple[object, ...] = (
            (ip_str, port, 0, 0)
            if af == socket.AF_INET6
            else (ip_str, port)
        )
        results.append((af, socktype, proto, "", sockaddr))
    if not results:
        # No pinned address matched the requested family — fail the
        # lookup rather than silently delegating (delegating would
        # re-open the rebinding window we just closed).
        raise socket.gaierror(
            socket.EAI_NONAME,
            f"no pinned address for {host!r} in requested family",
        )
    return results


# Marker attribute so _ensure_pin_installed can recognize its own wrapper.
_pinned_getaddrinfo._evidentia_pin_wrapper = True  # type: ignore[attr-defined]


def _ensure_pin_installed() -> None:
    """Install the process-level getaddrinfo wrapper, keeping the delegate.

    Idempotent + thread-safe. Captures whatever ``socket.getaddrinfo`` is
    right now as the delegate for un-pinned lookups, then swaps in the
    wrapper. If the wrapper is already installed it is a no-op — UNLESS
    some other code has since replaced ``socket.getaddrinfo`` with a
    non-wrapper, in which case we re-capture that as the new delegate and
    re-install (so the wrapper never silently shadows a newer resolver).
    The wrapper is a transparent pass-through for any host not pinned on
    the calling thread, so installing it has no effect on un-pinned
    resolution.
    """
    global _GETADDRINFO_DELEGATE
    with _pin_install_lock:
        current = socket.getaddrinfo
        if getattr(current, "_evidentia_pin_wrapper", False):
            return
        _GETADDRINFO_DELEGATE = current
        socket.getaddrinfo = _pinned_getaddrinfo  # type: ignore[assignment]


@contextmanager
def pin_resolved_host(host: str, public_ips: list[str]) -> Iterator[None]:
    """Pin ``host`` to ``public_ips`` for the duration of a block.

    Within the block, on the CURRENT thread, ``socket.getaddrinfo(host,
    ...)`` returns ONLY ``public_ips`` (the addresses
    :func:`enforce_public_host` already validated as public). This closes
    the DNS-rebinding window between validation and connection: a library
    that re-resolves the hostname is forced to the validated addresses
    rather than a freshly-rebound private one.

    Usage::

        validated = enforce_public_host(host, subsystem=..., block_private=...)
        with pin_resolved_host(host, validated):
            ... build the client + issue the request / open the socket ...

    The hostname is NOT changed, so TLS SNI, the Host header, and
    certificate verification still use the original hostname — the pin
    only constrains which IP the socket dials.

    A no-op when ``public_ips`` is empty (the opt-out / not-validated
    path), so callers can pass the ``enforce_public_host`` return value
    through unconditionally. Nested pins for the same host restore the
    outer pin on exit.
    """
    if not public_ips:
        yield
        return

    _ensure_pin_installed()
    key = host.lower()
    registry: dict[str, list[str]] | None = getattr(_pin_state, "hosts", None)
    if registry is None:
        registry = {}
        _pin_state.hosts = registry
    had_previous = key in registry
    previous = registry.get(key)
    registry[key] = list(public_ips)
    try:
        yield
    finally:
        if had_previous and previous is not None:
            registry[key] = previous
        else:
            registry.pop(key, None)
