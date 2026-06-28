"""THROWAWAY — verifies code-scanning merge protection. DO NOT MERGE.

This module deliberately contains a single ``py/path-injection`` finding so we
can confirm the ``code_scanning`` ruleset rule (security_alerts_threshold =
high_or_higher) BLOCKS a pull request that introduces a new HIGH code-scanning
alert. The branch is closed + deleted as soon as the blocking check is observed;
this file never reaches ``main``. It is intentionally ruff-/mypy-/pytest-clean
so that the ONLY failing required check is the code-scanning result.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _throwaway_read(user_arg: str) -> str:
    # Deliberate + unsanitized: CLI input flows straight into read_text with no
    # containment guard, which CodeQL reports as py/path-injection (HIGH). This
    # is the dummy finding that proves merge protection blocks the PR.
    return Path(user_arg).read_text(encoding="utf-8")


if __name__ == "__main__":  # pragma: no cover
    sys.stdout.write(_throwaway_read(sys.argv[1]))
