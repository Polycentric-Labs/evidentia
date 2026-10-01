# Air-gapped install

High-assurance environments — classified networks, CMMC/FedRAMP enclaves
handling CUI, HIPAA networks, isolated OT/SCADA, some financial back offices —
cannot reach PyPI or send compliance data to third-party SaaS. Evidentia is
built for local operation: gap arithmetic runs on-device, and `--offline`
enables checks at supported network call sites. It is not a process-wide
network sandbox; enforce isolation with host or container network policy.
This guide covers the offline install (wheelhouse
pattern), offline catalog handling, and the GPG-only signing fallback for when
Sigstore's Fulcio/Rekor are unreachable.

## Step 1 — Build a wheelhouse on a connected host

On an internet-connected machine running the **same OS/arch and Python 3.12** as
your target, download Evidentia and all its dependencies as wheels into a local
directory:

```bash
mkdir evidentia-wheelhouse
pip download evidentia -d evidentia-wheelhouse
```

If you need extras offline, download them too (the extra's transitive deps come
along):

```bash
pip download "evidentia-core[ocsf]" -d evidentia-wheelhouse
```

> Build the wheelhouse on a host that matches the target's platform. Wheels can
> be platform-specific; downloading on macOS for a Linux enclave can pull the
> wrong binaries. When in doubt, use the matching container image instead (Step
> 1b).

### Step 1b — (Alternative) transfer the container image

Pull the cosign-signed image on the connected host, save it to a tarball, and
carry the tarball across the air gap:

```bash
docker pull ghcr.io/polycentric-labs/evidentia:v0.13.0
docker save ghcr.io/polycentric-labs/evidentia:v0.13.0 -o evidentia.tar
```

On the air-gapped host: `docker load -i evidentia.tar`.

## Step 2 — Transfer and install offline

Move the `evidentia-wheelhouse/` directory across the air gap (removable media,
data diode, approved transfer process). On the target host, install with the
index disabled so pip never reaches for the network:

**Bash / Linux / macOS**

```bash
python -m venv .venv && source .venv/bin/activate
pip install --no-index --find-links ./evidentia-wheelhouse evidentia
evidentia version
# → Evidentia v0.13.0 / Python 3.12.x
```

**PowerShell (Windows)**

```powershell
python -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install --no-index --find-links ./evidentia-wheelhouse evidentia
evidentia version
# → Evidentia v0.13.0 / Python 3.12.x
```

## Step 3 — Validate the air-gap posture

Inspect the configuration before running a workload:

```bash
evidentia doctor --check-air-gap
```

Investigate warnings, then use the `--offline` global flag. The doctor report
uses selected prefix/base configuration checks; it neither exercises a completion
nor verifies every effective routing option. A `CONFIG ONLY` result is not proof
of network isolation or permission to use an unsupported route. The report
leaves dependency telemetry unverified:

**Bash / Linux / macOS**

```bash
evidentia --offline gap analyze \
  --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate \
  --output gap-report.json
```

**PowerShell (Windows)**

```powershell
evidentia --offline gap analyze `
  --inventory my-controls.yaml `
  --frameworks nist-800-53-rev5-moderate `
  --output gap-report.json
```

The completion guard raises `OfflineViolationError` for unsupported routing
before sending a completion request. Service availability, model errors and deployment
network isolation need separate qualification.

### LLM features offline

Offline AI generation supports Ollama and local OpenAI-compatible servers, including vLLM. These calls use a dedicated HTTP transport with environment proxies disabled and redirects refused. The setting is not a process-wide network sandbox; enforce host or container network isolation as well. Prepare the local server and model files before disconnecting.

**Bash / Linux / macOS**

```bash
# Ollama on the same host
export EVIDENTIA_LLM_MODEL=ollama/llama3.1:8b

# Optional: an Ollama service on a private IP instead of localhost:11434
# export OLLAMA_API_BASE=http://10.50.1.20:11434

evidentia --offline risk generate --gap-id GAP-0001 --context system-context.yaml
```

**PowerShell (Windows)**

```powershell
# Ollama on the same host
$env:EVIDENTIA_LLM_MODEL = "ollama/llama3.1:8b"

# Optional: an Ollama service on a private IP instead of localhost:11434
# $env:OLLAMA_API_BASE = "http://10.50.1.20:11434"

evidentia --offline risk generate --gap-id GAP-0001 --context system-context.yaml
```

To use a local OpenAI-compatible server, select `openai/local-model` and set `OPENAI_API_BASE` to its local API root, for example `http://127.0.0.1:8000/v1`. vLLM servers are supported through the same protocol. In-process vLLM loading is deferred for v0.13; migrate to a separately running local server.

`EVIDENTIA_LLM_API_BASE` only affects diagnostic/status code. Text messages, function schemas, structured output and streaming are supported. Unknown per-call routing options, custom transports/callbacks and multimodal content are refused. Ambient proxies are ignored for these calls; redirects are refused.

Keep routing configuration stable and restrict the inference server's network access. The guard cannot constrain arbitrary in-process code, every dependency import or a server that forwards requests. See [endpoint precedence and the compatibility boundary](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/air-gapped.md#local-inference-server-configuration) and the [in-process qualification follow-up](../6-project/roadmap.md#offline-in-process-inference-follow-up). Online provider behavior is unchanged.

## Offline catalogs

Evidentia loads framework catalogs from two places, both local: the catalogs
**bundled inside the wheel** and a **user catalog directory**. No catalog fetch
touches the network, so `evidentia catalog list` / `show` / `crosswalk` work
unchanged offline. To add a framework in an air-gapped environment, import the
catalog file from local disk:

```bash
evidentia catalog import ./my-framework.json --framework-id my-framework --tier C
```

(`evidentia catalog import` reads a local file path; it does not fetch from a
URL. Any future URL-based import is already routed through the offline guard.)

## Signing offline — GPG only

> **Container vs host install.** The published `ghcr.io/polycentric-labs/evidentia`
> image is distroless and ships **no `gpg` binary** — inside the container, air-gap
> signing uses the binary-free **DSSE** path (`evidentia gap analyze --sign-with-key`
> or `evidentia traceability emit --sign-with-key`; verify with `evidentia oscal
> verify … --verify-key`); `--sign-with-gpg` there fails closed with
> `GPGNotAvailableError`. The GPG recipe below applies to a **host wheelhouse
> install** (a machine with `gpg` on PATH), not to the transferred container image.

Sigstore keyless signing (`--sign-with-sigstore`) needs network access to Fulcio
(the certificate authority) and Rekor (the transparency log), so it is
**refused in `--offline` mode**. Air-gapped chains of custody use **GPG-detached
signatures** instead, which need no network:

**Bash / Linux / macOS**

```bash
evidentia --offline gap analyze \
  --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate \
  --format oscal-ar \
  --output assessment-results.json \
  --sign-with-gpg YOUR_KEY_ID

# Verify (also offline)
evidentia --offline oscal verify assessment-results.json --require-signature
```

**PowerShell (Windows)**

```powershell
evidentia --offline gap analyze `
  --inventory my-controls.yaml `
  --frameworks nist-800-53-rev5-moderate `
  --format oscal-ar `
  --output assessment-results.json `
  --sign-with-gpg YOUR_KEY_ID

# Verify (also offline)
evidentia --offline oscal verify assessment-results.json --require-signature
```

The same fallback applies to MCP tool-output signing: wire a GPG-based signer
factory (not the Sigstore one) when `EVIDENTIA_MCP_SIGN_OUTPUTS` is enabled in an
air-gapped deployment. See [Sign and verify evidence](sign-and-verify-evidence.md)
for the full signing workflow.

## Auditor proof-of-offline checklist

1. **Environment** — disable outbound network on the host (e.g. on Linux,
   `iptables -A OUTPUT -j DROP` except loopback).
2. **Preflight**: run `evidentia --offline doctor --check-air-gap`, investigate
   warnings and inspect effective routing. The report alone is not isolation evidence.
3. **Analysis** — `evidentia --offline gap analyze ...` completes with no
   network errors.
4. **Risk generation**: exercise a supported local-server route under the
   network policy and retain results. Unsupported routing is refused before
   request dispatch; service and model failures are separate.
5. **Signing** — on a host install with gpg present, `--sign-with-gpg` succeeds
   offline; in the distroless container, the equivalent air-gap guarantee is the
   DSSE `--sign-with-key` / `--verify-key` round-trip. `--sign-with-sigstore` is
   correctly refused in both cases.

## What's next

- [Installation](../1-getting-started/installation.md) — the standard
  (connected) install paths + the extras matrix.
- [Sign and verify evidence](sign-and-verify-evidence.md) — the GPG/Sigstore
  signing workflow in depth.
- The in-repo [`docs/air-gapped.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/air-gapped.md)
  has the full guard design, the allowed-host ranges, and a reverse-proxy
  pattern for multi-user network stations.

## Got stuck?

- **`OfflineViolationError`**: inspect the reported configuration category.
  The endpoint may be non-local, or an unsupported provider, routing option,
  callback may be configured. Use the local-server setup above.
- **`pip` still reaches the network** — you omitted `--no-index`. With
  `--no-index --find-links ./evidentia-wheelhouse`, pip installs only from the
  wheelhouse.
- **Wrong-platform wheels** — rebuild the wheelhouse on a host matching the
  target OS/arch, or use the container image (Step 1b).
