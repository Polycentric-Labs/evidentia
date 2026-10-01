# Air-gapped deployments

The `--offline` flag enables checks at supported network call sites. Offline AI generation supports Ollama and local OpenAI-compatible servers, including vLLM. These calls use a dedicated HTTP transport with environment proxies disabled and redirects refused. The setting is not a process-wide network sandbox; enforce host or container network isolation as well.

This document covers the design, configuration, and verification of air-gapped deployments.

## Why air-gapped?

Several high-LTV audiences cannot send compliance data to third-party SaaS:

- **CMMC / FedRAMP** — Federal contractors handling CUI face contractual prohibitions on offloading assessment data.
- **Healthcare** — HIPAA-covered entities managing PHI need to avoid any BAA that isn't already in place.
- **Air-gapped environments** — Classified networks, isolated OT / SCADA, some financial back offices.
- **Enterprise procurement** — CISOs who've been burned by data-residency surprises and want hard technical guarantees.

The CLI and web UI run locally, and gap arithmetic runs on-device. AI generation, live collectors, integrations and some signing operations have separate network requirements. Prepare dependencies and model files before disconnecting, and configure only the features your isolated deployment supports.

> *"The only open-source GRC tool that runs entirely on your infrastructure."*

## What `--offline` guards

Enable the process-wide offline setting with the CLI root flag, for example `evidentia --offline serve`, or with `EVIDENTIA_API_OFFLINE=1` for the API. The setting is consulted by explicit call-site guards; it does not intercept every socket operation.

| Subsystem | Guard | Allowed targets |
|---|---|---|
| LLM client | Dedicated sync and async local-server transport | Ollama or OpenAI-compatible protocols at a validated local/private HTTP(S) endpoint; redirects are refused and environment proxies are ignored |
| Catalog loader | `check_url(url)` on any URL-based fetch | Loopback / RFC-1918 only (v0.4.0 loads only from bundled + user-dir catalogs; URL-based `catalog import` is a future feature that will already be guarded) |
| LLM extensions | Offline request validation | Per-call routing and callback extensions are refused; LiteLLM provider dispatch, model discovery and shared client caches are bypassed |
| Gap store | n/a | On-disk under `platformdirs.user_data_dir` — local filesystem only |
| Web UI bind | CLI warning | `evidentia serve` binds to `127.0.0.1` by default; `--host 0.0.0.0` emits a security warning but is permitted |

Allowed hosts in offline mode:

- IPv4 loopback (`127.0.0.0/8`)
- IPv4 link-local (`169.254.0.0/16`)
- IPv4 private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- IPv6 loopback (`::1`)
- IPv6 link-local (`fe80::/10`)
- IPv6 unique-local (`fc00::/7`)
- Hostname `localhost` / `localhost.localdomain`

An unsupported completion route or effective endpoint raises `evidentia_core.network_guard.OfflineViolationError` before a completion request is sent. Diagnostics identify the refused configuration category without echoing endpoint values that might contain credentials.

## Quick start — Ollama on your laptop

```bash
# 1. Install Ollama (https://ollama.com)
# 2. Pull a model with a big enough context window for control text
ollama pull llama3.1:8b

# 3. Configure Evidentia to use it
export EVIDENTIA_LLM_MODEL=ollama/llama3.1:8b

# 4. Inspect configuration diagnostics
evidentia doctor --check-air-gap

# 5. Run analysis in offline mode
evidentia --offline gap analyze --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate --output gap-report.json

# 6. Generate risk drafts through the configured local Ollama service
evidentia --offline risk generate --gap-id GAP-0001 \
  --context system-context.yaml
```

Prepare Ollama and its model files on a connected host before isolation. The doctor report is a configuration diagnostic, not a completion probe or proof of network isolation. Its prefix/base checks do not cover all completion routing options. `CONFIG ONLY` describes a diagnostic result and does not authorize an unsupported route.

## Local inference server configuration

With no override, `ollama/*` and `ollama_chat/*` use `http://localhost:11434`. Both prefixes use Ollama's `/api/chat` protocol, including function schemas and streaming. Prepare the server and model files before disconnecting.

```bash
export EVIDENTIA_LLM_MODEL=ollama_chat/llama3.1:8b
export OLLAMA_API_BASE=http://10.50.1.20:11434
```

For a local OpenAI-compatible server, set its API root, including `/v1` if the server requires it:

```bash
export EVIDENTIA_LLM_MODEL=openai/local-model
export OPENAI_API_BASE=http://127.0.0.1:8000/v1
```

`openai/*`, `hosted_vllm/*`, `vllm/*`, and bare or organization-qualified model IDs use chat completions. `text-completion-openai/*` uses legacy text completions and does not accept function schemas. A non-Ollama route must have a configured local/private endpoint; Evidentia does not infer a public provider or download a model.

For Ollama, the global `litellm.api_base` takes priority over a per-call `api_base` or `base_url`, then `OLLAMA_API_BASE`, then localhost. A global base that conflicts with an explicit base is refused. For OpenAI-compatible routes, the per-call base takes priority over the global base, then `OPENAI_API_BASE` or `OPENAI_BASE_URL`; the vLLM prefixes use `HOSTED_VLLM_API_BASE` instead. Conflicting per-call bases are always refused.

`EVIDENTIA_LLM_API_BASE` is read by diagnostic/status code. It does not configure completions. If the local server requires authentication, supply an explicit API key or the selected provider's `OLLAMA_API_KEY` or `OPENAI_API_KEY`. Keep credentials in your existing secret-management system.

Offline calls support text messages, function schemas, structured output through Instructor, and sync or async streaming. Unknown completion options, aliases, per-call fallbacks, custom clients/callbacks and multimodal message content are refused. The dedicated transport ignores environment proxy settings and refuses redirects. It does not enter LiteLLM provider dispatch or consult its model-discovery, tokenizer-download or shared-client paths. Online routing is unchanged.

**v0.13 compatibility boundary:** `vllm/*` addresses a separately running local server in offline mode. Evidentia does not load a vLLM model inside its process. Operators who used the old in-process adapter must run a local OpenAI-compatible server and configure its API root. In-process loading is deferred pending the [roadmap qualification work](ROADMAP.md#offline-in-process-inference-follow-up).

Keep routing configuration stable during calls and restrict the inference server's own network access. These application controls cannot constrain arbitrary Python code, all dependency import-time activity, or a local server that forwards data elsewhere. Qualify actual workloads under outbound network restrictions.

## Web UI in air-gapped deployments

`evidentia serve` binds to `127.0.0.1` by default and serves the bundled UI and API from one uvicorn process. The React bundle is included in the Python wheel. The configuration diagnostic does not verify dependency telemetry or prove network isolation.

```bash
# Launch in air-gapped mode
evidentia --offline serve

# The Settings page reports configuration status only.
# Configure a supported local server before using LLM-backed features.
```

For multi-user network deployments (a shared CMMC assessor's browser station, for example), bind to `0.0.0.0` and front with an authenticated reverse proxy:

```nginx
server {
  listen 443 ssl;
  server_name evidentia.internal;

  # SSO / LDAP / whatever
  auth_request /auth;

  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
  }
}
```

**Network deployment:** API authentication is optional and the default API is anonymous. Set `EVIDENTIA_API_AUTH_TOKEN_FILE` or `--auth-token-file` before exposing it, configure a deny-by-default RBAC policy for multiple users, and use an authenticated TLS reverse proxy where appropriate. See [Web console security](wiki/3-concepts/web-console-security.md) for the current defaults and controls.

## Verification checklist for auditors

Collect deployment evidence for an external auditor:

1. **Environment.** Disable outbound network on the host. (On Linux: `iptables -A OUTPUT -j DROP` except loopback.)
2. **Preflight.** Run `evidentia --offline doctor --check-air-gap` and investigate warnings. Treat its result as a configuration diagnostic, not proof that a completion or every dependency remains offline.
3. **Run analysis.** `evidentia --offline gap analyze ...` should complete without network errors.
4. **Run risk generation.** With a supported local inference server configured, exercise risk generation under the same network restrictions. Unsupported routing raises `OfflineViolationError`; local service availability and model errors remain separate failure modes.
5. **Web UI.** `evidentia --offline serve` — the Settings page's air-gap posture widget should match the CLI `doctor` output.

Retain the configuration, network policy and observed test results. A refused unsupported route establishes a guard decision; successful local generation alone does not prove the absence of other network activity.

## Architecture notes

The core guard supplies process-wide offline state and host classification. The AI completion boundary validates the local-server request and uses its own HTTP transport. The older standalone `check_llm_model` prefix check is not the completion authorization decision. New network-capable subsystems need their own reviewed call-site enforcement.

The module is covered by 43 unit tests in `tests/unit/test_network_guard.py`. See the [source](../packages/evidentia-core/src/evidentia_core/network_guard.py) for docstrings covering every allowed-range rationale.

## Roadmap

- v0.4.0-alpha.2: GUI Settings-page air-gap toggle wired through every `/api/*` request.
- v0.5.0: First offline-capable collectors — on-premises AWS Config via the AWS SDK with custom endpoints, on-premises GitHub Enterprise, on-premises Okta Identity Cloud for Government.
- v0.6.0: Evidence chain of custody — SHA-256 digests + optional GPG signing of OSCAL Assessment Results exports, tamper-evident audit trails that survive external review.
