"""Unit tests for v0.8.3 P1.2 LLM atomic-claim extraction.

Covers the claim-extraction contract:

1. **Empty input → empty list** — no LLM call fires for an
   empty / whitespace-only input.
2. **Line-separated parsing** — LLM output split on newlines;
   empty lines dropped; whitespace stripped.
3. **Bullet/numbering tolerance** — "- claim", "* claim", "• claim",
   "1. claim", "2) claim" all stripped to bare claim text
   (LLMs sometimes ignore the no-numbering directive).
4. **max_claims cap** — output truncated when LLM returns more
   than the operator-configured ceiling.
5. **Mock-injected completion** — tests inject a mock
   ``completion_fn`` so CI runs without LLM provider creds.

Live-LLM integration tests deferred to v0.8.4 polish (gated by
EVIDENTIA_LLM_INTEGRATION env var).
"""

from __future__ import annotations

from unittest import mock

from evidentia_ai.eval.claim_extraction import (
    CLAIM_EXTRACTION_PROMPT,
    extract_claims,
)


def _mock_completion(canned_response: str) -> mock.MagicMock:
    """Return a completion_fn mock that always returns canned text."""
    fn = mock.MagicMock()
    fn.return_value = canned_response
    return fn


class TestExtractClaimsBasics:
    def test_empty_input_returns_empty_list(self) -> None:
        """No LLM call fires for empty / whitespace-only input."""
        fn = _mock_completion("ignored")
        assert extract_claims("", completion_fn=fn) == []
        assert extract_claims("   \n  \t  ", completion_fn=fn) == []
        # No LLM call.
        fn.assert_not_called()

    def test_simple_three_claim_decomposition(self) -> None:
        """LLM returns 3 line-separated claims → 3 claims out."""
        canned = (
            "The system enforces account management procedures.\n"
            "Multi-factor authentication is required for admin accounts.\n"
            "Audit logs are retained for 90 days.\n"
        )
        fn = _mock_completion(canned)
        claims = extract_claims(
            "Some risk statement text",
            model="test-model",
            completion_fn=fn,
        )
        assert len(claims) == 3
        assert claims[0] == "The system enforces account management procedures."
        assert claims[1] == "Multi-factor authentication is required for admin accounts."
        assert claims[2] == "Audit logs are retained for 90 days."

    def test_bullet_prefixes_stripped(self) -> None:
        """"- ", "* ", "• " bullet prefixes are dropped."""
        canned = (
            "- Account management is enforced.\n"
            "* MFA is required for admins.\n"
            "• Audit logs retained 90 days.\n"
        )
        fn = _mock_completion(canned)
        claims = extract_claims("text", completion_fn=fn)
        assert claims == [
            "Account management is enforced.",
            "MFA is required for admins.",
            "Audit logs retained 90 days.",
        ]

    def test_numbered_prefixes_stripped(self) -> None:
        """"N." and "N)" numbering prefixes are dropped."""
        canned = (
            "1. First claim text.\n"
            "2) Second claim text.\n"
            "3. Third claim text.\n"
        )
        fn = _mock_completion(canned)
        claims = extract_claims("text", completion_fn=fn)
        assert claims == [
            "First claim text.",
            "Second claim text.",
            "Third claim text.",
        ]

    def test_empty_lines_dropped(self) -> None:
        """Empty / whitespace-only lines in the LLM response are skipped."""
        canned = (
            "Claim one.\n"
            "\n"
            "  \n"
            "Claim two.\n"
            "\n\n"
            "Claim three.\n"
        )
        fn = _mock_completion(canned)
        claims = extract_claims("text", completion_fn=fn)
        assert claims == ["Claim one.", "Claim two.", "Claim three."]

    def test_max_claims_cap_truncates(self) -> None:
        """Output truncated when LLM returns more than max_claims."""
        canned = "\n".join(f"Claim {i}." for i in range(15))
        fn = _mock_completion(canned)
        claims = extract_claims(
            "text", completion_fn=fn, max_claims=5
        )
        assert len(claims) == 5
        assert claims[0] == "Claim 0."
        assert claims[4] == "Claim 4."

    def test_completion_fn_receives_prompt_with_text(self) -> None:
        """The injected completion_fn sees the text interpolated into the prompt."""
        fn = _mock_completion("c1.\nc2.")
        extract_claims(
            "Test text content",
            model="test-model",
            temperature=0.5,
            completion_fn=fn,
        )
        assert fn.call_count == 1
        # Inspect the kwargs the mock received.
        call_kwargs = fn.call_args.kwargs
        assert call_kwargs["model"] == "test-model"
        assert call_kwargs["temperature"] == 0.5
        # Messages structure: list of role/content dicts.
        messages = call_kwargs["messages"]
        assert isinstance(messages, list)
        assert len(messages) == 1
        assert messages[0]["role"] == "user"
        assert "Test text content" in messages[0]["content"]
        assert "Decompose" in messages[0]["content"]


class TestExtractClaimsEdgeCases:
    def test_single_claim_decomposition(self) -> None:
        """Single-line response → single-element list."""
        fn = _mock_completion("Only one atomic claim.")
        claims = extract_claims("text", completion_fn=fn)
        assert claims == ["Only one atomic claim."]

    def test_llm_returns_empty_response(self) -> None:
        """LLM returns empty string → empty list."""
        fn = _mock_completion("")
        claims = extract_claims("text", completion_fn=fn)
        assert claims == []

    def test_llm_returns_only_whitespace(self) -> None:
        """LLM returns only whitespace → empty list."""
        fn = _mock_completion("\n  \n  \t  \n")
        claims = extract_claims("text", completion_fn=fn)
        assert claims == []

    def test_prompt_template_constant_exposed(self) -> None:
        """CLAIM_EXTRACTION_PROMPT is exported for inspection."""
        assert "{text}" in CLAIM_EXTRACTION_PROMPT
        assert "atomic" in CLAIM_EXTRACTION_PROMPT.lower()
