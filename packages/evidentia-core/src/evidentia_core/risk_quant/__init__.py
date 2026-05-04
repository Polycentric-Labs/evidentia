"""Risk quantification primitives (v0.7.11 P1.5 G4).

Currently ships the Open FAIR (Factor Analysis of Information
Risk) taxonomy per the Open Group's `Open Risk Taxonomy
Standard` (O-RT) + `Open FAIR Body of Knowledge` (O-RA). FAIR
quantifies risk in dollar terms by composing loss-event
frequency + loss magnitude:

  - **LEF** (Loss Event Frequency) = TEF × Vulnerability
  - **TEF** (Threat Event Frequency, events/year): how often
    threat actors attempt the attack
  - **Vulnerability**: probability (0-1) the attempt succeeds
    given existing controls
  - **LM** (Loss Magnitude): primary loss (direct) + secondary
    loss (downstream — fines, reputation, customer churn) in $
  - **ALE** (Annualized Loss Expectancy) = LEF × LM

This module ships the deterministic single-point-estimate
form (PERT distribution support deferred to v0.7.12). Operators
supplying ranges (low / most-likely / high) get the PERT-mean
expected value computed deterministically.

Public surface:

  - :class:`OpenFAIRScenario` — risk scenario Pydantic schema
  - :func:`compute_ale` — Annualized Loss Expectancy from a
    scenario
  - :func:`generate_risk_quantification_report` — Markdown
    quantification report
"""

from __future__ import annotations

from evidentia_core.risk_quant.open_fair import (
    OpenFAIRScenario,
    PERTRange,
    compute_ale,
    compute_loss_magnitude,
    generate_risk_quantification_report,
)

__all__ = [
    "OpenFAIRScenario",
    "PERTRange",
    "compute_ale",
    "compute_loss_magnitude",
    "generate_risk_quantification_report",
]
