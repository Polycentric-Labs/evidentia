"""Run real API stream cases without loading the unrelated LLM stack."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from _entra_m365_llm_isolation import isolate_unused_llm

llm = isolate_unused_llm()


class CaseSummary:
    def __init__(self) -> None:
        self.passed = 0
        self.skipped = 0

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.skipped:
            self.skipped += 1
        if report.when == "call" and report.passed:
            self.passed += 1


summary = CaseSummary()
basetemp = Path(sys.argv[1]).resolve()
assert not basetemp.exists()
exit_code = pytest.main(
    [
        str(Path(__file__).with_name("_entra_m365_stream_cases.py")),
        "-q",
        "-p",
        "no:cacheprovider",
        "--tb=short",
        "--basetemp=" + str(basetemp),
    ],
    plugins=[summary],
)
llm.assert_unused()
print(
    json.dumps(
        {
            "exit_code": int(exit_code),
            "passed": summary.passed,
            "skipped": summary.skipped,
            "llm_calls": llm.calls,
            "litellm_loaded": "litellm" in sys.modules,
            "tiktoken_loaded": "tiktoken" in sys.modules,
        }
    )
)
assert exit_code == 0 and summary.passed == 21 and summary.skipped == 0
