"""OSCAL schema-version constant (v0.9.6 P4.2).

Single source of truth for the OSCAL schema version Evidentia emits
in catalog / profile / assessment-results / plan-of-action-and-
milestones metadata blocks.

Lives in its own module to break the circular import that would
otherwise arise from the per-emitter modules
(:mod:`evidentia_core.oscal.exporter`,
:mod:`evidentia_core.oscal.poam_exporter`,
:mod:`evidentia_core.oscal.profile`) importing from the package
``__init__.py`` while the package itself re-exports those modules.

Bumping this constant + handling any field renames at the emit
sites is the canonical path for OSCAL minor-version upgrades.
"""

from __future__ import annotations

#: OSCAL schema version. v0.9.6 P4.2 bumped from 1.1.2 to 1.2.1 to
#: align with ``compliance-trestle 4.0.2`` (April 17 2026). The
#: 1.2.0 release renamed observation ``types: ["finding"]`` to
#: ``["implementation-issue"]`` — that rename is applied at the
#: emit site in :mod:`evidentia_core.oscal.exporter`.
OSCAL_SCHEMA_VERSION = "1.2.1"

__all__ = ["OSCAL_SCHEMA_VERSION"]
