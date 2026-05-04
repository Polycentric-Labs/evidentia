"""Governance primitives — Three Lines of Defense + Effective Challenge.

Introduced in v0.7.10 P1.5 per `docs/v0.7.10-plan.md`. Brings
Evidentia into alignment with the IIA "Three Lines Model" (2020
revision) and SR 11-7 / SR 26-02 §III.D effective-challenge
expectations regulators apply across financial-services
risk-management programs.

Public surface:

  - :class:`LineOfDefense` enum (first / second / third)
  - :class:`Owner` Pydantic model — email + line-of-defense
    classification + optional team / title metadata
  - :func:`generate_lines_report` — aggregates classified owners
    across the vendor + model-risk inventories into a Markdown
    distribution report

Future v0.7.10 sub-slices may extend this module with
``EffectiveChallenge`` primitives (P1.5 G2) and KRI / KPI / KGI
metric schemas (P1.5 G3+).
"""

from __future__ import annotations

from evidentia_core.governance.lines_of_defense import (
    LineOfDefense,
    Owner,
    generate_lines_report,
)

__all__ = [
    "LineOfDefense",
    "Owner",
    "generate_lines_report",
]
