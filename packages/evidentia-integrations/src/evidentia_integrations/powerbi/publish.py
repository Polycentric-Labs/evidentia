"""High-level Power BI publish orchestration (v0.7.8 P1.2)."""

from __future__ import annotations

from collections.abc import Iterable

from evidentia_core.audit import CollectionContext
from evidentia_core.models.gap import GapAnalysisReport
from evidentia_core.models.risk import RiskStatement
from pydantic import BaseModel, Field

from evidentia_integrations.powerbi.client import (
    PowerBIClient,
    PowerBIPublishError,
)
from evidentia_integrations.powerbi.config import PowerBIConfig
from evidentia_integrations.powerbi.extract import (
    COLLECTION_RUN_DATASET_SCHEMA,
    GAP_DATASET_SCHEMA,
    RISK_DATASET_SCHEMA,
    build_collection_run_dataset_rows,
    build_gap_dataset_rows,
    build_risk_dataset_rows,
)


class PowerBIPublishedDataset(BaseModel):
    """One published dataset's outcome."""

    name: str = Field(description="Dataset name on the Power BI side")
    dataset_id: str = Field(description="Power BI dataset ID")
    table_name: str = Field(description="Table name inside the Push Dataset")
    rows: int = Field(
        ge=0,
        description="Row count actually pushed (post-clear).",
    )


class PowerBIPublishResult(BaseModel):
    """The result of a single publish_report invocation."""

    workspace_id: str
    datasets: list[PowerBIPublishedDataset] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)


def publish_report(
    *,
    config: PowerBIConfig,
    report: GapAnalysisReport,
    risks: Iterable[RiskStatement] | None = None,
    collection_runs: Iterable[CollectionContext] | None = None,
    gap_dataset_name: str = "evidentia-gaps",
    risk_dataset_name: str = "evidentia-risks",
    collection_run_dataset_name: str = "evidentia-collection-runs",
    clear_before_push: bool = True,
) -> PowerBIPublishResult:
    """Push gap inventory + risk register + collection-run audit
    trail to a Power BI workspace as three separate Push Datasets.

    Args:
        config: typed :class:`PowerBIConfig`.
        report: the :class:`GapAnalysisReport` whose gaps will be
            pushed.
        risks: optional iterable of :class:`RiskStatement`. When
            None, the risk dataset is skipped.
        collection_runs: optional iterable of
            :class:`CollectionContext`. When None, the
            collection-run dataset is skipped.
        gap_dataset_name / risk_dataset_name /
            collection_run_dataset_name: per-dataset names on the
            Power BI side. Defaults pair with the ships starter
            Power BI ``.pbit`` template.
        clear_before_push: if True (default), clear the dataset's
            rows before pushing the new batch. This implements
            full-refresh semantics — the typical compliance-
            dashboard expectation. Set to False for append-only
            (e.g. when treating the dataset as an event log).

    Raises:
        PowerBIPublishError: if any step fails.

    Returns:
        :class:`PowerBIPublishResult` with per-dataset ID + row count.
    """
    result = PowerBIPublishResult(
        workspace_id=config.workspace_id,
        datasets=[],
        skipped=[],
    )

    with PowerBIClient(config) as client:
        # 1. Gap dataset (always pushed).
        gap_rows = build_gap_dataset_rows(report)
        gap_table = "gaps"
        gap_id = client.ensure_dataset(
            dataset_name=gap_dataset_name,
            table_name=gap_table,
            schema=GAP_DATASET_SCHEMA,
        )
        if clear_before_push:
            client.clear_table(dataset_id=gap_id, table_name=gap_table)
        client.push_rows(
            dataset_id=gap_id,
            table_name=gap_table,
            rows=gap_rows,
        )
        result.datasets.append(
            PowerBIPublishedDataset(
                name=gap_dataset_name,
                dataset_id=gap_id,
                table_name=gap_table,
                rows=len(gap_rows),
            )
        )

        # 2. Risk dataset (optional).
        if risks is not None:
            risk_rows = build_risk_dataset_rows(risks)
            if risk_rows:
                risk_table = "risks"
                risk_id = client.ensure_dataset(
                    dataset_name=risk_dataset_name,
                    table_name=risk_table,
                    schema=RISK_DATASET_SCHEMA,
                )
                if clear_before_push:
                    client.clear_table(
                        dataset_id=risk_id,
                        table_name=risk_table,
                    )
                client.push_rows(
                    dataset_id=risk_id,
                    table_name=risk_table,
                    rows=risk_rows,
                )
                result.datasets.append(
                    PowerBIPublishedDataset(
                        name=risk_dataset_name,
                        dataset_id=risk_id,
                        table_name=risk_table,
                        rows=len(risk_rows),
                    )
                )
            else:
                result.skipped.append(f"{risk_dataset_name} (no risks supplied)")
        else:
            result.skipped.append(f"{risk_dataset_name} (risks=None)")

        # 3. Collection-run dataset (optional).
        if collection_runs is not None:
            ctx_rows = build_collection_run_dataset_rows(collection_runs)
            if ctx_rows:
                ctx_table = "collection_runs"
                ctx_id = client.ensure_dataset(
                    dataset_name=collection_run_dataset_name,
                    table_name=ctx_table,
                    schema=COLLECTION_RUN_DATASET_SCHEMA,
                )
                if clear_before_push:
                    client.clear_table(dataset_id=ctx_id, table_name=ctx_table)
                client.push_rows(
                    dataset_id=ctx_id,
                    table_name=ctx_table,
                    rows=ctx_rows,
                )
                result.datasets.append(
                    PowerBIPublishedDataset(
                        name=collection_run_dataset_name,
                        dataset_id=ctx_id,
                        table_name=ctx_table,
                        rows=len(ctx_rows),
                    )
                )
            else:
                result.skipped.append(f"{collection_run_dataset_name} (no contexts)")
        else:
            result.skipped.append(f"{collection_run_dataset_name} (collection_runs=None)")

    return result


__all__ = [
    "PowerBIPublishError",
    "PowerBIPublishResult",
    "PowerBIPublishedDataset",
    "publish_report",
]
