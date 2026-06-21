"""Shared helpers for the Evidentia atheris fuzz harnesses.

Atheris is Linux/CI-only (no Windows wheel). These harnesses are NOT
imported by the pytest suite — they are built + run by ClusterFuzzLite
(``.clusterfuzzlite/``) and, later, OSS-Fuzz, using the SAME source.
They are kept dependency-light and deterministic so the fuzzer's
throughput stays high and crashes reproduce.

Each harness in this directory follows the same shape::

    import atheris
    with atheris.instrument_imports():
        import <evidentia parser module>

    def TestOneInput(data: bytes) -> None:
        # feed `data` into the parser, catch ONLY declared exceptions,
        # let anything unexpected crash (that is the finding).

    if __name__ == "__main__":
        atheris.Setup(sys.argv, TestOneInput)
        atheris.Fuzz()

This helper centralizes the "decode fuzz bytes to text" step so every
harness handles the empty / non-UTF-8 / huge-input edge cases the same
way.
"""

from __future__ import annotations


def to_text(data: bytes) -> str:
    """Decode raw fuzz bytes to ``str`` deterministically.

    ``errors="replace"`` means every byte string maps to *some* text,
    so the fuzzer never wastes an execution on a decode-only rejection
    in the harness itself — the bytes always reach the parser under
    test. Empty input maps to the empty string, which the parsers
    reject as malformed (an expected, caught path).
    """
    return data.decode("utf-8", errors="replace")
