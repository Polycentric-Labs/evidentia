# Troubleshooting

Common issues you'll hit on first install or first run of Evidentia,
with their fixes.

> **Layout**: each entry has the **symptom** as you'd see it, then the
> **why** in one sentence, then the **fix**. Skim by symptom; read the
> "why" only when the fix doesn't immediately solve it.

---

## Install + first-run

### `evidentia: command not found` after `pip install evidentia`

**Symptom**: `pip install evidentia` succeeds, but `evidentia version`
says command not found.

**Why**: the install landed in a Python user-site `bin/` directory
that isn't on your `PATH`.

**Fix**: either (a) install into a virtualenv where the `bin/` is on
`PATH` automatically (recommended), or (b) add the user-site `bin/`
to `PATH`:

```bash
python -m pip install --user evidentia
python -m site --user-base   # prints e.g. /home/you/.local
export PATH="$(python -m site --user-base)/bin:$PATH"
evidentia version
```

### `No such option: --version` when running `evidentia --version`

**Symptom**: `evidentia --version` returns `No such option: --version
Did you mean --verbose?`

**Why**: `version` is a Typer **subcommand**, not a `--version` flag.
The Typer-driven CLI registers `version` alongside `init`, `doctor`,
`serve`, `gap`, `catalog`, `risk`, `explain`, `integrations`,
`collect`, `oscal`. (Fixed in v0.7.4 across the bundled Dockerfile +
CI smoke tests; the source-of-truth CLI was always correct.)

**Fix**:

```bash
evidentia version           # ✅ correct
evidentia --version         # ❌ errors
```

### `RuntimeError: Python 3.12+ required`

**Symptom**: any `evidentia ...` invocation fails immediately with a
Python-version error.

**Why**: Evidentia requires Python ≥ 3.12. The `pyproject.toml` for
every published wheel pins `requires-python = ">=3.12"`, so `pip
install` will refuse to install on 3.11 or older — but if you're
running from source against a wrong-version venv, the error fires at
import time.

**Fix**: install Python 3.12+ and recreate the virtualenv. On
Windows, `winget install Python.Python.3.12`. On macOS, `brew install
python@3.12`. On Linux, `apt install python3.12` (Ubuntu 24.04+) or
build from source.

```bash
python3.12 -m venv .venv
source .venv/bin/activate    # or .venv/Scripts/activate on Windows
pip install evidentia
```

### `404 Not Found` or `503 spa_not_built` when opening the web UI

**Symptom**: `evidentia serve` starts, but `http://127.0.0.1:8000/`
returns `{"error": "spa_not_built", ...}` (503) or a 404.

**Why**: the React SPA bundle isn't on disk under
`evidentia_api/static/`. Either the install didn't include the
`[gui]` extra, or you installed from a source checkout without
running `npm run build` in `packages/evidentia-ui/`.

**Fix**: re-install with the `[gui]` extra (~50 MB extra; pulls in
the bundled SPA + FastAPI deps):

```bash
pip install --force-reinstall "evidentia[gui]"
```

If you're contributing from a source checkout, run:

```bash
cd packages/evidentia-ui
npm install && npm run build
cd ../..
```

Then `evidentia serve` again. The `--dev` flag (`evidentia serve
--dev`) sets permissive CORS for the Vite dev server on
`http://127.0.0.1:5173` so you can iterate on the UI without a
rebuild.

---

## Sigstore + signing

### `tuf.exceptions.RepositoryError` or TUF metadata fetch failure

**Symptom**: `evidentia oscal sign --sigstore <ar.json>` fails with a
TUF metadata error or a network timeout against `tuf-repo-cdn`.

**Why**: the Sigstore Python SDK fetches TUF metadata on first run to
verify the Fulcio + Rekor public keys. If your network blocks
`https://tuf-repo-cdn.sigstore.dev/` (corporate proxy, air-gapped
network, FedRAMP High enclave), the fetch fails and signing can't
proceed.

**Fix**: switch to the air-gap GPG path documented in
[`air-gapped.md`](air-gapped.md). `evidentia oscal sign --gpg` works
without internet and `evidentia oscal verify` accepts either
signature type interchangeably:

```bash
evidentia oscal sign --gpg --signing-key <fingerprint> ar.json
evidentia oscal verify --require-signature ar.json
```

If the network block is transient (corporate proxy with allowlist),
add `tuf-repo-cdn.sigstore.dev` and `rekor.sigstore.dev` to your
proxy allowlist. The first sign call caches the TUF metadata locally
under `~/.local/share/python-tuf/`, so subsequent sign operations
work even with intermittent connectivity.

### `evidentia oscal verify` returns `FAIL` on a signature-free AR

**Symptom**: running `evidentia oscal verify <ar.json>` against an
Assessment Results document with no embedded evidence and no
signature returns `FAIL` with messaging like "No embedded evidence
resources (digests skipped). No GPG signature checked. No Sigstore
signature checked."

**Why**: the verifier ran 3 checks, all skipped because there was
nothing to verify and no `--require-signature` was supplied. The
`FAIL` verdict is misleading — the right verdict is `PASS (no
verification surface)` when no signature was required.

**Fix**: this is fixed in v0.7.5. If you're on v0.7.4 or earlier,
either supply `--require-signature` so the FAIL is intentional, or
upgrade to v0.7.5+:

```bash
evidentia oscal verify --require-signature ar.json   # FAIL is correct
evidentia oscal verify ar.json                       # v0.7.5+: PASS
```

---

## Docker container

### Container won't start: `permission denied` on bind mount

**Symptom**: `docker run -v "$PWD:/work" evidentia:v0.7.5 gap
analyze ...` fails with `permission denied` when the container tries
to write to a bind-mounted output directory.

**Why**: the Evidentia container runs as uid 1000 (the non-root
`evidentia` user). If the host directory is owned by a different uid
(e.g. root-owned, or your host user is uid 501 on macOS), the
container can read but not write.

**Fix**: chown the host directory to uid 1000 before mounting, or run
with `--user "$(id -u):$(id -g)"` to run the container as your host
user:

```bash
# Option A: chown
sudo chown -R 1000:1000 ./output
docker run -v "$PWD/output:/home/evidentia/reports" evidentia:v0.7.5 ...

# Option B: run-as host user
docker run --user "$(id -u):$(id -g)" \
    -v "$PWD:/work" -w /work \
    evidentia:v0.7.5 gap analyze --inventory my-controls.yaml
```

### `Bind for 0.0.0.0:8000 failed: port is already allocated`

**Symptom**: `docker run -p 8000:8000 evidentia:v0.7.5` fails with a
port-allocation error.

**Why**: another process is already bound to `8000` on the host.
Common culprits: a previous `evidentia serve` left running, another
FastAPI/uvicorn dev server, or a different container.

**Fix**: bind to a different host port:

```bash
docker run -p 8080:8000 evidentia:v0.7.5    # host 8080 -> container 8000
# then open http://127.0.0.1:8080
```

### Healthcheck reports `unhealthy` even though the API responds

**Symptom**: `docker ps` shows the container as `(unhealthy)`, but
`curl http://127.0.0.1:8000/api/health` returns a healthy response.

**Why**: only affects images built before v0.7.5. The Dockerfile
HEALTHCHECK was hitting `/health` (no `/api/` prefix), which fell
through to the SPA fallback handler and returned `index.html` —
which `curl -fsS` accepted as 200, so the check actually passed but
was a false positive masking real API failures. Fixed in v0.7.5.

**Fix**: pull the v0.7.5 image:

```bash
docker pull ghcr.io/polycentric-labs/evidentia:v0.7.5
```

Or build locally from a v0.7.5 `Dockerfile` (the path is corrected
to `/api/health`).

---

## Air-gap mode

For full air-gap setup including offline Sigstore alternatives + GPG
key generation, see [`air-gapped.md`](air-gapped.md). One quick
gotcha:

### `RuntimeError: network egress refused: target 'pypi.org'`

**Symptom**: when running with `--offline` or
`EVIDENTIA_OFFLINE=1`, any operation that tries to reach the
internet fails immediately.

**Why**: `evidentia_core.network_guard.set_offline(True)` flips a
process-wide flag that refuses non-loopback network targets. This
is intentional — it's the air-gap guard.

**Fix**: this is the correct behavior for air-gap deployments. To
satisfy the operation:

- Pre-pull dependencies onto the air-gap host before disconnecting
- Pre-fetch catalog data with `evidentia catalog fetch --offline-bundle`
- Use the `--gpg` signing path instead of Sigstore
- For LLM features, point `EVIDENTIA_LLM_API_BASE` at a local
  Ollama / vLLM instance

---

## Where else to look

- **Build / packaging issues**: [`docs/release-checklist.md`](release-checklist.md)
  Step 6 (test gate) and Step 7 (build sanity).
- **Sigstore verification deep dive**: [`docs/sigstore-quickstart.md`](sigstore-quickstart.md).
- **Air-gap setup**: [`docs/air-gapped.md`](air-gapped.md).
- **OSCAL conformance / catalog questions**: file an issue with the
  output of `evidentia doctor` attached.

If you hit something that isn't on this page, please open an issue
at <https://github.com/polycentric-labs/evidentia/issues> with the output
of `evidentia doctor` and your platform / Python version.
