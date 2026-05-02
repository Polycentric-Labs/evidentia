"""High-level Tableau publish orchestration (v0.7.8 P1.1).

:func:`publish_report` builds the three CSV datasets (gap inventory +
risk register + collection runs) and publishes each to Tableau in a
single sign-in/sign-out cycle.

Returns a structured :class:`TableauPublishResult` so the CLI + REST
endpoints can render a uniform "what was uploaded where" summary.
"""

from __future__ import annotations

from collections.abc import Iterable

from evidentia_core.audit import CollectionContext
from evidentia_core.models.gap import GapAnalysisReport
from evidentia_core.models.risk import RiskStatement
from pydantic import BaseModel, Field

from evidentia_integrations.tableau.client import (
    TableauClient,
    TableauPublishError,
)
from evidentia_integrations.tableau.config import TableauConfig
from evidentia_integrations.tableau.extract import (
    build_collection_run_dataset_csv,
    build_gap_dataset_csv,
    build_risk_dataset_csv,
)


class TableauPublishedDataset(BaseModel):
    """One published dataset's outcome."""

    name: str = Field(description="Dataset name on the Tableau side")
    rows: int = Field(
        ge=0,
        description=(
            "Row count actually written to the CSV (excluding the "
            "header). Useful for sanity-checking whether the "
            "dataset contained data."
        ),
    )
    datasource_id: str = Field(
        description="Tableau-assigned datasource ID after publish"
    )


class TableauPublishResult(BaseModel):
    """The result of a single publish_report invocation."""

    server_url: str
    site_id: str
    project_name: str
    datasets: list[TableauPublishedDataset] = Field(default_factory=list)
    skipped: list[str] = Field(
        default_factory=list,
        description=(
            "Names of datasets that were intentionally skipped — "
            "e.g. risk register skipped when no RiskStatement list "
            "was passed in."
        ),
    )


def _count_csv_rows(csv_bytes: bytes) -> int:
    """Count CSV data rows (excludes the header)."""
    text = csv_bytes.decode("utf-8")
    # Header + N data rows; subtract 1 for header. Empty string → 0.
    if not text.strip():
        return 0
    lines = text.splitlines()
    return max(len(lines) - 1, 0)


def publish_report(
    *,
    config: TableauConfig,
    report: GapAnalysisReport,
    risks: Iterable[RiskStatement] | None = None,
    collection_runs: Iterable[CollectionContext] | None = None,
    gap_dataset_name: str = "evidentia-gaps",
    risk_dataset_name: str = "evidentia-risks",
    collection_run_dataset_name: str = "evidentia-collection-runs",
    overwrite: bool = True,
) -> TableauPublishResult:
    """Publish gap inventory + risk register + collection-run audit
    trail to a Tableau site as three separate data sources.

    Args:
        config: typed :class:`TableauConfig`. Identifies the server
            + site + project to publish into; specifies env-var
            names for the PAT.
        report: the :class:`GapAnalysisReport` whose gaps will be
            published as the gap-inventory dataset.
        risks: optional iterable of :class:`RiskStatement`. When
            None, the risk-register dataset is skipped (and
            recorded in :attr:`TableauPublishResult.skipped`).
        collection_runs: optional iterable of
            :class:`CollectionContext`. When None, the
            collection-run dataset is skipped.
        gap_dataset_name / risk_dataset_name /
            collection_run_dataset_name: per-dataset name on the
            Tableau side. Defaults are the conventional
            ``evidentia-*`` names that pair with the ships
            starter Tableau workbook templates.
        overwrite: if True (default), publish in Overwrite mode —
            re-running the publish updates the existing data
            source in place. If False, publish in CreateNew mode
            and fail if the dataset already exists.

    Raises:
        TableauPublishError: if any step fails. The exception
            message identifies the dataset that failed.

    Returns:
        :class:`TableauPublishResult` with per-dataset ID +
        row-count summary.
    """
    result = TableauPublishResult(
        server_url=config.server_url,
        site_id=config.site_id,
        project_name=config.project_name,
        datasets=[],
        skipped=[],
    )

    with TableauClient(config) as client:
        project_id = client.get_project_id(config.project_name)

        # 1. Gap dataset (always published).
        gap_csv = build_gap_dataset_csv(report)
        gap_id = client.publish_csv_datasource(
            project_id=project_id,
            datasource_name=gap_dataset_name,
            csv_bytes=gap_csv,
            overwrite=overwrite,
        )
        result.datasets.append(
            TableauPublishedDataset(
                name=gap_dataset_name,
                rows=_count_csv_rows(gap_csv),
                datasource_id=gap_id,
            )
        )

        # 2. Risk dataset (optional).
        if risks is not None:
            risk_list = list(risks)
            if risk_list:
                risk_csv = build_risk_dataset_csv(risk_list)
                risk_id = client.publish_csv_datasource(
                    project_id=project_id,
                    datasource_name=risk_dataset_name,
                    csv_bytes=risk_csv,
                    overwrite=overwrite,
                )
                result.datasets.append(
                    TableauPublishedDataset(
                        name=risk_dataset_name,
                        rows=_count_csv_rows(risk_csv),
                        datasource_id=risk_id,
                    )
                )
            else:
                result.skipped.append(
                    f"{risk_dataset_name} (no risks supplied)"
                )
        else:
            result.skipped.append(
                f"{risk_dataset_name} (risks=None — caller did "
                f"not pass a risk register)"
            )

        # 3. Collection-run dataset (optional).
        if collection_runs is not None:
            ctx_list = list(collection_runs)
            if ctx_list:
                ctx_csv = build_collection_run_dataset_csv(ctx_list)
                ctx_id = client.publish_csv_datasource(
                    project_id=project_id,
                    datasource_name=collection_run_dataset_name,
                    csv_bytes=ctx_csv,
                    overwrite=overwrite,
                )
                result.datasets.append(
                    TableauPublishedDataset(
                        name=collection_run_dataset_name,
                        rows=_count_csv_rows(ctx_csv),
                        datasource_id=ctx_id,
                    )
                )
            else:
                result.skipped.append(
                    f"{collection_run_dataset_name} (no contexts "
                    f"supplied)"
                )
        else:
            result.skipped.append(
                f"{collection_run_dataset_name} (collection_runs="
                f"None)"
            )

    return result


__all__ = [
    "TableauPublishError",
    "TableauPublishResult",
    "TableauPublishedDataset",
    "publish_report",
]
