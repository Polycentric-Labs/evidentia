"""Alert channels honour --offline before any DNS lookup or connection (v0.13.0 review, CWE-693)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
import typer
from evidentia_core.network_guard import set_offline


@pytest.fixture()
def offline() -> Iterator[None]:
    set_offline(True)
    try:
        yield
    finally:
        set_offline(False)


def _build(**overrides: object) -> list[object]:
    from evidentia.cli.conmon import _build_alert_channels

    kwargs: dict[str, object] = {
        "smtp_host": None,
        "smtp_port": 587,
        "smtp_username": None,
        "smtp_password_file": None,
        "smtp_sender": None,
        "smtp_recipients": None,
        "webhook_url": None,
        "webhook_secret_file": None,
    }
    kwargs.update(overrides)
    return _build_alert_channels(**kwargs)  # type: ignore[arg-type]


def test_public_webhook_is_refused_under_offline(offline: None) -> None:
    with pytest.raises(typer.BadParameter, match="conmon-webhook"):
        _build(webhook_url="https://hooks.example.com/services/T000/B000/x")


def test_public_smtp_host_is_refused_under_offline(offline: None) -> None:
    with pytest.raises(typer.BadParameter, match="conmon-smtp"):
        _build(smtp_host="smtp.example.com", smtp_sender="a@example.com", smtp_recipients=["b@example.com"])


def test_loopback_webhook_passes_the_offline_guard(offline: None, monkeypatch: pytest.MonkeyPatch) -> None:
    # The guard passes; the next step (the HMAC secret) is what fails here.
    monkeypatch.delenv("EVIDENTIA_WEBHOOK_SECRET", raising=False)
    with pytest.raises((typer.BadParameter, typer.Exit, SystemExit, ValueError)) as excinfo:
        _build(webhook_url="https://127.0.0.1:8443/hook")
    assert "conmon-webhook" not in str(excinfo.value)
