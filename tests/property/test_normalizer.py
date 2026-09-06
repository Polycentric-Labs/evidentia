"""Property-based tests for ``evidentia_core.gap_analyzer.normalizer``.

v0.8.2 G2 / §25.2 P2.2 (1): control-id normalization invariants.

The :func:`normalize_control_id` function reshapes user-provided
control identifiers into a canonical form. The hand-written tests
in ``tests/unit/`` cover specific known-shape inputs (e.g., NIST
``AC-2`` vs ``AC2``); these property tests exercise the full
input space (random Unicode strings) against three intrinsic
invariants:

1. **Idempotence** — calling normalize twice produces the same
   result as calling it once. This is the canonical-form contract
   (the function describes itself as returning a canonical form).
2. **Case-folding** — output never contains lowercase ASCII
   letters. The function explicitly documents
   ``Strip whitespace and convert to uppercase``.
3. **Prefix-stripping coverage** — for inputs that start with one
   of the documented prefixes (``NIST``, ``ISO``, ``CIS``,
   ``SOC2``, etc.), the output never re-emits the same prefix at
   the start.
"""

from __future__ import annotations

from evidentia_core.gap_analyzer.normalizer import normalize_control_id
from hypothesis import given
from hypothesis import strategies as st

# Documented prefixes from normalizer.py source (lines 29-32).
# Property test 3 asserts none of these reappear at the head of
# the output when the input started with them.
_DOCUMENTED_PREFIXES: tuple[str, ...] = (
    "NIST ",
    "ISO ",
    "CIS ",
    "SOC2 ",
    "SOC 2 ",
    "PCI ",
    "CMMC ",
)


@given(st.text())
def test_normalize_is_idempotent(raw: str) -> None:
    """``normalize(normalize(x)) == normalize(x)`` for any input.

    Idempotence is the canonical-form contract: once the input is
    in canonical form, additional passes are no-ops. A regression
    that breaks idempotence (e.g., a transformation that flips
    state on every call) surfaces here as a single counter-example
    that hypothesis shrinks to a minimal failing input.
    """
    once = normalize_control_id(raw)
    twice = normalize_control_id(once)
    assert once == twice


@given(st.text())
def test_normalize_output_has_no_lowercase_ascii(raw: str) -> None:
    """Normalize output never contains lowercase ASCII letters.

    The function documents ``Strip whitespace and convert to
    uppercase``. Non-ASCII letters (Unicode case-folding) are
    out-of-scope for this assertion — Python's ``str.upper()``
    handles the documented contract for ASCII; non-ASCII case-
    folding edge cases (Turkish dotless-i, etc.) aren't part of
    Evidentia's input space (control IDs are ASCII by convention).
    """
    out = normalize_control_id(raw)
    for char in out:
        if char.isascii() and char.isalpha():
            assert not char.islower(), (
                f"Lowercase ASCII letter {char!r} in normalize output {out!r} (input was {raw!r})"
            )


@given(st.text(min_size=1, max_size=120))
def test_normalize_strips_documented_prefixes(raw: str) -> None:
    """Inputs that start with a documented prefix don't re-emit it.

    The function strips the first matched prefix from the documented
    list. After stripping, the output's HEAD must not start with the
    same prefix again (i.e., the function strips at most one prefix
    instance — which is intentional per the source: a single
    ``for prefix in [...]: if result.startswith(prefix): result = ...``
    loop with no early-break).

    Edge case: an input like ``"NIST NIST AC-2"`` will have ONE
    ``NIST `` stripped, leaving ``"NIST AC-2"`` — which still starts
    with ``NIST ``. The test must allow that case (the function
    only promises to strip ONE prefix, not all leading prefixes).
    Hypothesis-generated inputs are very unlikely to land on this
    pathological shape, but we still narrow the assertion: we only
    fail when an input starts with prefix P AND the output also
    starts with prefix P AND the input was simple enough that one
    pass should have removed it.
    """
    upper = raw.strip().upper()
    out = normalize_control_id(raw)
    for prefix in _DOCUMENTED_PREFIXES:
        if upper.startswith(prefix):
            # The function should strip the first occurrence. If the
            # remainder ALSO starts with the same prefix, the function
            # only strips one — that's consistent with the source.
            after_strip = upper[len(prefix) :]
            if not after_strip.startswith(prefix):
                # The simple case: input had exactly one occurrence
                # of the prefix at the head. Output must not start
                # with that prefix.
                assert not out.startswith(prefix), (
                    f"Output {out!r} retained prefix {prefix!r} that input {raw!r} had at the head"
                )
            # else: pathological doubled-prefix case; skip assertion.
            break  # only check the first matched prefix
