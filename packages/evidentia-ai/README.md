# evidentia-ai

LLM-powered features for [Evidentia](https://github.com/polycentric-labs/evidentia): risk statement generation and (in Phase 3) evidence validation.

Uses **LiteLLM** for provider-agnostic LLM calls and **Instructor** for structured output extraction into Pydantic models.

## Provides

- **Risk Statement Generator** — Convert control gaps into NIST SP 800-30-compliant risk statements
- **Evidence Validator** *(Phase 3)* — Assess evidence sufficiency using LLM analysis
- **LLM Client** — Provider-agnostic wrapper around LiteLLM with retry, rate limiting, and structured output

## Supported providers

When offline mode is disabled, use providers supported by LiteLLM:
- Anthropic Claude (default: `claude-sonnet-4-6`)
- OpenAI GPT
- Google Gemini
- AWS Bedrock
- Azure OpenAI
- Local models via Ollama, vLLM, etc.

Offline AI generation supports Ollama and local OpenAI-compatible servers, including vLLM. These calls use a dedicated HTTP transport with environment proxies disabled and redirects refused. The setting is not a process-wide network sandbox; enforce host or container network isolation as well.
Use `OLLAMA_API_BASE` for Ollama or `OPENAI_API_BASE` for an OpenAI-compatible
API root. Unknown per-call routing extensions and multimodal content are
refused. Text messages, function schemas, structured output and streaming
remain supported. In-process vLLM loading is deferred for v0.13; use a local
server and follow the [qualification roadmap](../../docs/ROADMAP.md#offline-in-process-inference-follow-up).
See [the offline guide](../../docs/air-gapped.md) for precedence and limits.

Generated risks start unreviewed and unaccepted, with treatment pending.
Review decisions and model-inventory bindings cannot be supplied by the
model; generation provenance and configured inventory bindings are set by
the application. Existing stored human-reviewed records remain readable.

## Install

```bash
pip install evidentia-ai
```

License: Apache 2.0
