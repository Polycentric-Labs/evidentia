"""Model Risk Management overlay (v0.7.10 P0.6).

Documentation + validation-report generators for the
:class:`evidentia_core.models.model_risk.ModelInventory` Pydantic
model. Produces SR 11-7 / SR 26-02 / OCC Bulletin 2011-12 / OCC
Bulletin 2026-13a-aligned artifacts that federally-regulated
model-risk-management programs can present to internal validators,
external auditors, and federal examiners.

Public surface:

  - :func:`generate_model_documentation` — full SR 11-7-aligned
    model documentation in Markdown
  - :func:`generate_validation_report` — validation-cycle report
    in Markdown summarizing conceptual soundness review, outcomes
    analysis, ongoing monitoring, and findings disposition

Both generators emit Markdown by design — the format is portable,
diff-able, version-controllable, and consumable by every standard
auditor toolchain (Word, PDF via pandoc, HTML, plain text).
"""

from __future__ import annotations

from evidentia_core.model_risk.documentation import (
    generate_model_documentation,
)
from evidentia_core.model_risk.validation_report import (
    generate_validation_report,
)

__all__ = [
    "generate_model_documentation",
    "generate_validation_report",
]
