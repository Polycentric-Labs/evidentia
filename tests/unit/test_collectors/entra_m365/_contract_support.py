"""Synthetic model builders and the approved recorded DLP fixture location."""

from datetime import UTC, datetime
from pathlib import Path

from evidentia_collectors.entra_m365 import _contracts as contract

START = datetime(2026, 1, 1, tzinfo=UTC)
END = datetime(2026, 1, 2, tzinfo=UTC)
RECORDED_DLP_PATH = Path("tests/fixtures/entra_m365/purview/cisa-dlp-recorded.json")


def capability(name="conditional-access", **changes):
    fields = dict(
        name=name,
        state="complete",
        credential_basis="unverified:primary-token",
        declared_auth_mode="application",
        scanned=0,
        matched_filter=0,
        collected=0,
        duplicate_records=0,
        pages_completed=1,
        requests_attempted=1,
        started_at=datetime(2026, 9, 10, tzinfo=UTC),
        finished_at=datetime(2026, 9, 10, tzinfo=UTC),
        requested_window_start=None,
        requested_window_end=None,
        observed_first=None,
        observed_last=None,
        field_coverage={},
        diagnostics=[],
    )
    return contract.EntraM365CapabilityResult(**(fields | changes))


def event_fields():
    return dict(
        name="sign-ins",
        state="complete",
        credential_basis="unverified:primary-token",
        declared_auth_mode="application",
        scanned=1,
        matched_filter=1,
        collected=1,
        duplicate_records=0,
        pages_completed=1,
        requests_attempted=1,
        started_at=END,
        finished_at=END,
        requested_window_start=START,
        requested_window_end=END,
        observed_first="2026-01-01T12:00:00.000000000001Z",
        observed_last="2026-01-01T12:00:00.000000000001Z",
        field_coverage={
            key: {"absent": 0, "null": 0, "known": 1, "unknown": 0} for key in contract.coverage_fields("sign-ins")
        },
        diagnostics=[],
    )


def dlp_fields():
    return dict(
        schema_version=1,
        source=dict(
            kind="authored-synthetic",
            producer="Synthetic producer",
            producer_version=None,
            captured_at=None,
            parent_sha256=None,
            source_uri=None,
            sanitization="synthetic",
        ),
        policies=[
            dict(
                Guid=" policy ",
                Name=" policy name ",
                Mode=None,
                DistributionStatus=None,
                Workload=None,
                Enabled=None,
                IsValid=None,
            )
        ],
        rules=[
            dict(
                Guid=" rule ",
                Policy=" policy ",
                ParentPolicyName=" policy name ",
                Mode=None,
                Workload=None,
                Disabled=None,
                IsValid=None,
            )
        ],
    )
