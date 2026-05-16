# evidentia-ai

LLM-powered features for [Evidentia](https://github.com/polycentric-labs/evidentia): risk statement generation and (in Phase 3) evidence validation.

Uses **LiteLLM** for provider-agnostic LLM calls and **Instructor** for structured output extraction into Pydantic models.

## Provides

- **Risk Statement Generator** — Convert control gaps into NIST SP 800-30-compliant risk statements
- **Evidence Validator** *(Phase 3)* — Assess evidence sufficiency using LLM analysis
- **LLM Client** — Provider-agnostic wrapper around LiteLLM with retry, rate limiting, and structured output

## Supported providers

Any provider supported by LiteLLM:
- Anthropic Claude (default: `claude-sonnet-4-6`)
- OpenAI GPT
- Google Gemini
- AWS Bedrock
- Azure OpenAI
- Local models via Ollama, vLLM, etc.

## Install

```bash
pip install evidentia-ai
```

License: Apache 2.0
