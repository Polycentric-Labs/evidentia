"""FedRAMP Significant Change Notification (SCN-CSO-INF) schema validation.

SCN-CSO-INF is the FedRAMP rule requiring cloud service providers to
notify their Authorizing Official of an Adaptive or Transformative
change to an authorized system; Routine Recurring changes are
exempt. The schema this module validates against,
``fedramp-significant-change-notifications-schema-2026-06-24.json``,
is vendored under :mod:`evidentia_core.fedramp.schemas` with upstream
pins recorded in ``schemas/UPSTREAM.json``. Validation is offline: a
local ``$id`` registry resolves the schema's one cross-document
``$ref``, which points into the vendored common-definitions schema,
so no network fetch ever happens.

:meth:`evidentia_core.ai_governance.scr.SCRForm.to_scn_document` is
the writer that produces the documents this module validates.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from evidentia_core.fedramp.ksi import COMMON_SCHEMA_PATH

_SCHEMA_DIR = Path(__file__).parent / "schemas"
SCN_SCHEMA_PATH = _SCHEMA_DIR / "fedramp-significant-change-notifications-schema-2026-06-24.json"


@lru_cache(maxsize=1)
def _scn_validator() -> Draft202012Validator:
    """Build the offline Draft 2020-12 validator for the SCN schema.

    The registry pre-loads both vendored schemas by their ``$id`` so the
    SCN schema's one cross-document ``$ref`` resolves locally.
    """
    scn = json.loads(SCN_SCHEMA_PATH.read_text(encoding="utf-8"))
    common = json.loads(COMMON_SCHEMA_PATH.read_text(encoding="utf-8"))
    registry = Registry().with_resources(
        [
            (scn["$id"], Resource.from_contents(scn)),
            (common["$id"], Resource.from_contents(common)),
        ]
    )
    return Draft202012Validator(scn, registry=registry)


def validate_scn_document(document: dict[str, Any]) -> list[str]:
    """Validate an SCN document against the vendored schema.

    Returns a list of human-readable error strings; empty means valid.
    """
    errors = []
    for err in sorted(_scn_validator().iter_errors(document), key=lambda e: list(e.absolute_path)):
        where = "/".join(str(p) for p in err.absolute_path) or "<document root>"
        errors.append(f"{where}: {err.message}")
    return errors
