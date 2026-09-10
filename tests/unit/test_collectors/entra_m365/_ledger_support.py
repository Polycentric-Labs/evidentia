"""Synthetic ledger clocks, requests and source records."""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from evidentia_collectors.entra_m365 import _contracts as c

NOW = datetime(2026, 1, 31, tzinfo=UTC)


@dataclass
class Clock:
    value: float = 0.0
    wall: datetime = NOW
    sleeps: list[float] = field(default_factory=list)

    def utc(self):
        return self.wall

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


def start(names=("sign-ins",), **options):
    clock = Clock()
    request = c.EntraM365CollectRequest(tenant_label="synthetic", capabilities=list(names), **options)
    ctx = c.EntraM365RunContext.start(
        request,
        utc_clock=clock.utc,
        monotonic_clock=clock.monotonic,
        sleep=clock.sleep,
        run_id_factory=lambda: "synthetic-ledger-run",
    )
    return ctx, request, clock


def event(identifier, when="2026-01-15T00:00:00Z", **fields):
    return c.project_record(
        "sign-ins", {"id": identifier, "createdDateTime": when, "appliedConditionalAccessPolicies": [], **fields}
    )


def reading(ctx, name="sign-ins", mode="application"):
    read = ctx.begin(name, mode)
    if name != "dlp-export":
        read.note_attempt()
    return read


def diagnostics(capability):
    return {(item.code, item.http_status): item.count for item in capability.diagnostics}
