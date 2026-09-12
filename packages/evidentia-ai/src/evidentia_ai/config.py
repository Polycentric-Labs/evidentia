"""Model configuration that can be read without loading provider clients."""

from __future__ import annotations

import os


def get_default_model() -> str:
    """Read the configured model name or the existing fallback."""
    return os.environ.get("EVIDENTIA_LLM_MODEL", "gpt-4o")
