"""FedRAMP CR26 machine-readable submission surfaces.

v0.11 Wave 2: the Security Decision Record (SDR) KSI emitter behind
`evidentia conmon ksi`, validated offline against the vendored CR26
schemas in :mod:`evidentia_core.fedramp.schemas` (provenance pins in
``schemas/UPSTREAM.json``; drift is watched by the weekly
``fedramp-schema-watch`` sentinel).
"""

from evidentia_core.fedramp.ksi import (
    KsiCoverage,
    build_sdr_document,
    ksi_coverage,
    load_ksi_catalog,
    validate_sdr_document,
)

__all__ = [
    "KsiCoverage",
    "build_sdr_document",
    "ksi_coverage",
    "load_ksi_catalog",
    "validate_sdr_document",
]
