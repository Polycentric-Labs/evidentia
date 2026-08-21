"""FedRAMP CR26 machine-readable submission surfaces.

v0.11 Wave 2: the Security Decision Record (SDR) KSI emitter behind
`evidentia conmon ksi`; v0.12 added the ``fedRampRequirements`` block
(SDR-CSO-FRR). Validated offline against the vendored CR26
schemas in :mod:`evidentia_core.fedramp.schemas` (provenance pins in
``schemas/UPSTREAM.json``; drift is watched by the weekly
``fedramp-schema-watch`` sentinel).
"""

from evidentia_core.fedramp.ksi import (
    FRR_CATALOG_ID,
    KSI_CATALOG_ID,
    KsiCoverage,
    build_sdr_document,
    frr_coverage,
    ksi_coverage,
    load_frr_catalog,
    load_ksi_catalog,
    validate_sdr_document,
)

__all__ = [
    "FRR_CATALOG_ID",
    "KSI_CATALOG_ID",
    "KsiCoverage",
    "build_sdr_document",
    "frr_coverage",
    "ksi_coverage",
    "load_frr_catalog",
    "load_ksi_catalog",
    "validate_sdr_document",
]
