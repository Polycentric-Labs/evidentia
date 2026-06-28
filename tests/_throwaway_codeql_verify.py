"""THROWAWAY — verifies code-scanning merge protection. DO NOT MERGE.

Introduces ONE remote-source ``py/path-injection`` (HIGH) so we can confirm the
``code_scanning`` ruleset rule BLOCKS a PR that introduces a new HIGH alert.

The first attempt used ``sys.argv`` (a LOCAL source, which CodeQL's default
*remote* threat model does not flag, so no alert was produced). This uses a
FastAPI query parameter — a REMOTE source — which the stock query does flag.

Intentionally ruff-/mypy-/pytest-clean so the ONLY failing required check is the
code-scanning result. Closed + deleted as soon as the blocking check is observed;
this file never reaches ``main``.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter

_throwaway_router = APIRouter()


@_throwaway_router.get("/_throwaway_codeql_verify")
def _throwaway_endpoint(name: str) -> str:
    # Remote source (the FastAPI query param ``name``) flows straight into a file
    # read with no containment guard -> CodeQL py/path-injection (HIGH). This is
    # the dummy finding that should trip the code_scanning merge-protection rule.
    return Path(name).read_text(encoding="utf-8")
