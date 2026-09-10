"""Function-scoped transport fixtures with explicit network refusal."""

import socket

import httpx
import pytest
from evidentia_collectors.entra_m365 import _client as client
from evidentia_collectors.entra_m365 import _contracts as contracts
from evidentia_core import network_guard

from ._transport_support import Clock, Guards, Provider, Run, Scenario, refuse_real_network


@pytest.fixture
def runtime():
    guards = Guards()
    guards.reset()
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(network_guard, "check_url", guards.check_url)
        patch.setattr(network_guard, "enforce_public_host", guards.enforce_public_host)
        patch.setattr(network_guard, "pin_resolved_host", guards.pin_resolved_host)
        patch.setattr(socket, "getaddrinfo", refuse_real_network)
        patch.setattr(socket.socket, "connect", refuse_real_network)
        patch.setattr(socket, "create_connection", refuse_real_network)
        yield guards, client, contracts


@pytest.fixture
def make_run(runtime):
    guards, target, ledger = runtime
    guards.reset()
    runs = []

    def make(replies, *, capabilities=None, request_fields=None, defaults=None, values=None):
        request = contracts.EntraM365CollectRequest(
            tenant_label="synthetic-reader",
            capabilities=capabilities or ["conditional-access"],
            **(request_fields or {}),
        )
        clock = Clock()
        context = ledger.EntraM365RunContext.start(
            request,
            utc_clock=clock.utc,
            monotonic_clock=clock.monotonic,
            sleep=clock.sleep,
            run_id_factory=lambda: "synthetic-reader-run-" + str(len(runs)),
        )
        scenario = Scenario(guards, replies)
        transport = httpx.Client(transport=httpx.MockTransport(scenario.handle), trust_env=False, **(defaults or {}))
        provider = Provider(target, values)
        reader = target.EntraM365GraphReader(credentials=provider, client=transport)
        run = Run(reader, request, context, clock, provider, transport, scenario)
        runs.append(run)
        return run

    yield make
    for run in reversed(runs):
        run.reader.close()
        run.client.close()
