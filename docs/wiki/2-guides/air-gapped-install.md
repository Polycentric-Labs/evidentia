# Air-gapped install

High-assurance environments — classified networks, CMMC/FedRAMP enclaves
handling CUI, HIPAA networks, isolated OT/SCADA, some financial back offices —
cannot reach PyPI or send compliance data to third-party SaaS. Evidentia is
built for this: gap arithmetic runs on-device, the only optional outbound calls
are LLM API requests, and a first-class `--offline` flag fails closed on any
non-local network call. This guide covers the offline install (wheelhouse
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
docker pull ghcr.io/polycentric-labs/evidentia:v0.10.6
docker save ghcr.io/polycentric-labs/evidentia:v0.10.6 -o evidentia-v0.10.6.tar
```

On the air-gapped host: `docker load -i evidentia-v0.10.6.tar`.

## Step 2 — Transfer and install offline

Move the `evidentia-wheelhouse/` directory across the air gap (removable media,
data diode, approved transfer process). On the target host, install with the
index disabled so pip never reaches for the network:

```bash
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install --no-index --find-links ./evidentia-wheelhouse evidentia
evidentia version
# → Evidentia v0.10.6 / Python 3.12.x
```

## Step 3 — Validate the air-gap posture

Before running anything that matters, confirm every subsystem reports an
air-gap-ready posture:

```bash
evidentia doctor --check-air-gap
#  LLM client     AIR-GAP READY   model=ollama/llama3.1:8b (local prefix)
#  Catalog loader AIR-GAP READY   loads only from bundled + user-dir catalogs
#  ...
```

Any red entry is a configuration mistake to fix before you start. Then run every
command with the `--offline` global flag, which refuses any outbound call to a
non-loopback / non-RFC-1918 host *before* the network IO is issued:

```bash
evidentia --offline gap analyze \
  --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate \
  --output gap-report.json
```

If a call would leak, Evidentia raises a structured `OfflineViolationError`
(naming the subsystem, target, and remediation) rather than a mystery timeout.
Fail closed, not open.

### LLM features offline

`evidentia risk generate` and other LLM-backed features need a **local**
inference endpoint in offline mode. Point Evidentia at Ollama or a self-hosted
OpenAI-compatible server on a loopback/RFC-1918 address:

```bash
# Ollama on the same host
export EVIDENTIA_LLM_MODEL=ollama/llama3.1:8b

# or a self-hosted vLLM/LocalAI endpoint on a private IP
export EVIDENTIA_LLM_MODEL=gpt-4o-compatible
export EVIDENTIA_LLM_API_BASE=http://10.50.1.20:8000/v1

evidentia --offline risk generate --gap-id GAP-0001 --context system-context.yaml
```

The guard checks the `api_base` host, not the model string — any model name
paired with an RFC-1918 `api_base` is permitted in offline mode.

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

Sigstore keyless signing (`--sign-with-sigstore`) needs network access to Fulcio
(the certificate authority) and Rekor (the transparency log), so it is
**refused in `--offline` mode**. Air-gapped chains of custody use **GPG-detached
signatures** instead, which need no network:

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

The same fallback applies to MCP tool-output signing: wire a GPG-based signer
factory (not the Sigstore one) when `EVIDENTIA_MCP_SIGN_OUTPUTS` is enabled in an
air-gapped deployment. See [Sign and verify evidence](sign-and-verify-evidence.md)
for the full signing workflow.

## Auditor proof-of-offline checklist

1. **Environment** — disable outbound network on the host (e.g. on Linux,
   `iptables -A OUTPUT -j DROP` except loopback).
2. **Preflight** — `evidentia --offline doctor --check-air-gap`; every subsystem
   reports `AIR-GAP READY`.
3. **Analysis** — `evidentia --offline gap analyze ...` completes with no
   network errors.
4. **Risk generation** — with a local LLM configured,
   `evidentia --offline risk generate ...` produces output (a misconfiguration
   yields a clear `OfflineViolationError`, not a hang).
5. **Signing** — `--sign-with-gpg` succeeds offline; `--sign-with-sigstore` is
   correctly refused.

## What's next

- [Installation](../1-getting-started/installation.md) — the standard
  (connected) install paths + the extras matrix.
- [Sign and verify evidence](sign-and-verify-evidence.md) — the GPG/Sigstore
  signing workflow in depth.
- The in-repo [`docs/air-gapped.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/air-gapped.md)
  has the full guard design, the allowed-host ranges, and a reverse-proxy
  pattern for multi-user network stations.

## Got stuck?

- **`OfflineViolationError`** — a subsystem tried to reach a non-local host. The
  payload names the subsystem + target + remediation; fix the configuration
  (usually an LLM endpoint that is not on loopback/RFC-1918).
- **`pip` still reaches the network** — you omitted `--no-index`. With
  `--no-index --find-links ./evidentia-wheelhouse`, pip installs only from the
  wheelhouse.
- **Wrong-platform wheels** — rebuild the wheelhouse on a host matching the
  target OS/arch, or use the container image (Step 1b).
