"""Child-only isolation of an unused LLM import during API startup."""

from __future__ import annotations

import sys
from types import ModuleType


class UnusedLLM:
    def __init__(self) -> None:
        self.calls = 0

    def get_default_model(self) -> str:
        self.calls += 1
        raise AssertionError("Entra API tests must not invoke the unrelated LLM client")

    def assert_unused(self) -> None:
        assert self.calls == 0
        assert "litellm" not in sys.modules
        assert "tiktoken" not in sys.modules


def isolate_unused_llm() -> UnusedLLM:
    assert "evidentia_ai.client" not in sys.modules
    state = UnusedLLM()
    state.assert_unused()
    stub = ModuleType("evidentia_ai.client")
    stub.__dict__["get_default_model"] = state.get_default_model
    sys.modules["evidentia_ai.client"] = stub
    return state
