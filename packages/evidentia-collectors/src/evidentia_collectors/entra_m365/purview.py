"""Observe retention label configuration without inferring item application."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._contracts import (
    EntraM365CapabilityRead,
    EntraM365CollectRequest,
    EntraM365DlpExport,
    EntraM365RunContext,
)

if TYPE_CHECKING:
    from ._client import EntraM365GraphReader


def read_retention_labels(
    request: EntraM365CollectRequest,
    graph_reader: EntraM365GraphReader,
    run_context: EntraM365RunContext,
    dlp_export: EntraM365DlpExport | None = None,
) -> EntraM365CapabilityRead:
    """Interpret only final records from the shared delegated retention reader."""
    source = graph_reader.read_collection("retention-labels", request, run_context)
    findings = [
        run_context.make_finding(
            source,
            "retention-label-configuration",
            source_id=record.source_id,
            raw_data={"scope": "label_configuration"},
        )
        for record in source.records
    ]
    return run_context.finish_read(source, findings=findings)
