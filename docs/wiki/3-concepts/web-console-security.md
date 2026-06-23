# Web console security model

Evidentia's web console (`evidentia serve`) is the React single-page app bundled
into the `evidentia-api` wheel and served by the FastAPI app on **your** host. It
drives the same engine as the CLI, including the actions that mutate local state,
use credentials, reach the network, or verify signed artifacts. This page is the
standing security model for that surface: the controls that protect it, their
default postures, what each console exposes, and how to harden a deployment you
intend to share. It is the console-specific companion to the product-level
[`docs/threat-model.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/threat-model.md),
which it references rather than duplicates.

> **Scope, up front.** This is the **self-hosted operator console** model — the
> attacker is *anything that can reach your API*: another local user, a malicious
> web page making cross-origin or DNS-rebind requests, a compromised browser-side
> dependency, plus operator error (an accidental external push, a runaway LLM
> cost). It is **not** the public-demo model (the static demo bundle ships no
> backend and no credentials). And note up front: the API is **anonymous and
> RBAC-permissive by default** — RBAC is authorization, not authentication, and
> with no auth token configured there is no identity to enforce against. The
> "[Default posture](#default-posture-and-the-two-layer-disclosure)" section
> below is the most important part of this page.

## Standing controls

Every control here already exists in the server; the console inherits them. The
"Default" column is what you get out of the box; "Harden" is the opt-in that
tightens it.

| Control | What it does | Default | Harden |
|---|---|---|---|
| **API authentication** | `AuthProviderMiddleware` gates all `/api/*` except liveness probes (`/api/health`, `/api/version`, `/api/openapi.json`, `/api/docs`, `/api/redoc`). | **Off** (anonymous). | Set `EVIDENTIA_API_AUTH_TOKEN_FILE` (or `evidentia serve --auth-token-file`) → every route requires `Authorization: Bearer <token>`. |
| **RBAC** | `require_role("read"\|"write"\|"admin")` maps an authenticated identity to a role. | **Permissive** (anonymous → admin), preserving single-operator backward compatibility. | Point `EVIDENTIA_RBAC_POLICY_FILE` at a deny-by-default policy (see [RBAC and multi-tenancy](rbac-and-multi-tenancy.md)). |
| **SSRF guard** | `evidentia_core.network_guard` rejects private / loopback / link-local / CGNAT / multicast / reserved targets *before* the request, and pins the validated IP through the connection so a DNS-rebind TOCTOU cannot bypass it. | **Secure** — private targets blocked unless an explicit opt-out is passed. | Leave the default; do not expose `--allow-private-ips` to untrusted form users. |
| **Credentials** | Collectors and integrations read secrets **server-side only** (cloud SDK credential chains, `GITHUB_TOKEN`, config). No secret ever appears in a request body, response body, URL, or log. | Hard rule, always on. | Nothing to do — it cannot be disabled. |
| **CORS** | `CORSMiddleware`; production is **localhost-only**, dev mode (`--dev`) is permissive for the Vite dev server. | Locked to the console origin in production. | Keep the default bind; only use `--dev` for frontend development. |
| **Rate limiting** | `RateLimitMiddleware` bounds request volume. | On. | — |
| **Security headers** | `SecurityHeadersMiddleware` injects CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS, Permissions-Policy. | **Auto** — on for a non-loopback `--host`, off for localhost. | Force with `--security-headers`. |
| **Offline mode** | `network_guard.is_offline()` fail-closes all network egress. | Off (opt-in). | Set `EVIDENTIA_API_OFFLINE` / `--offline` for an air-gapped console. |
| **Audit** | Each request carries the authenticated principal (or `anonymous`) for per-action audit events. | On. | Wire authentication so the principal is a real identity, not `anonymous`. |

## Default posture and the two-layer disclosure

Because the API ships anonymous and RBAC-permissive, a mutating or credentialed
button on a default deployment is reachable by anything that can hit the local
API. Rather than silently trust the host or silently disable everything, the
console takes a **hybrid** stance that matches the CLI's host-owner trust model
for local state while putting real auth in front of the genuinely dangerous
actions. It surfaces this in two layers:

1. **A soft, always-visible banner.** The `SecurityPostureBanner` renders an
   *"Unsecured deployment"* strip whenever the server reports
   `auth_configured = false`, naming `EVIDENTIA_API_AUTH_TOKEN_FILE` as the fix.
   It disappears the moment an auth provider is configured (so a secured
   deployment — and the static demo bundle — shows nothing).
2. **A UI guard on the egress consoles.** The two consoles that use credentials
   and reach the network — **Collect** and **Integrations** — *disable* their
   run / push buttons until an auth token is set. This is a UI convenience guard,
   **not** a server-side control: the underlying `/api/collectors` and
   `/api/integrations` endpoints stay reachable until an `AuthProvider` is
   configured (see "Standing controls" above). Setting the token — not the
   disabled button — is the real fix. Local-store and read-only consoles stay
   usable either way.

Setting `--auth-token-file` clears the banner, requires a bearer token on every
`/api/*` route, and unlocks the credentialed buttons. This is the single most
important hardening step before exposing the console beyond `127.0.0.1`.

## What each console exposes

Consoles are surfaced according to their blast radius, not uniformly:

- **Local-store CRUD** (Governance, Retention, Evidence, POA&M, TPRM, Model Risk,
  AI Governance, Catalog management, local Continuous-Monitoring state) — full
  create/update/delete in the browser. Destructive and import actions get a
  confirmation step; Evidence is additionally lineage- and actor-gated.
- **LLM-backed** (Risk Generate, Explain Control) — full, with a cost notice, the
  offline fail-closed behavior, and server-side iteration caps. The provider key
  is read server-side; the Settings console shows per-provider presence as a
  boolean only and never echoes a key value.
- **Verify / emit views** (OSCAL Verify, Traceability) — **read-mostly**. You can
  verify a signed Assessment Result and view the Control↔Threat matrix in the
  browser; **signing stays a CLI / air-gap operation** (see below).
- **Credentialed egress** (Collect, Integrations) — full, but gated behind the
  auth requirement above, with the SSRF guard mandatory and private-IP blocking
  on by default in the form, and an explicit confirmation before an irreversible
  external push.

### Why signing stays on the CLI

Server-side signing (`traceability emit --sign`, `gap analyze --sign-with-*`,
`oscal sign`) would require a long-running server process to hold and unlock your
GPG / Sigstore key — a standing key-exposure surface on a network-facing process.
The console therefore surfaces **verification** and **unsigned emit** only;
signing remains an air-gapped CLI operation. This keeps the signing key off the
server process entirely and preserves the air-gap signing story.

## Credentialed-action guarantees

For the high-risk Collect and Integrations paths specifically:

- **Secrets never transit the browser.** Forms send only non-secret parameters
  (region, repo, host, report key, filters). Tokens, passwords, connection
  strings, and signing keys are read server-side and never placed in a request
  body, response body, URL, browser state, or log.
- **Every user-supplied host is SSRF-checked.** The route calls
  `network_guard.enforce_public_host()` and pins the resolved IP through the
  actual connection, defeating DNS-rebind. The request-body publish target (the
  Tableau host) is covered by the same guard. The guard is defense-in-depth that
  shrinks the SSRF blast radius — it is not a substitute for the auth gate.
- **Irreversible actions confirm first.** An external push or a cost-incurring
  LLM run states plainly what will happen and where it goes before it runs.
- **Errors don't leak.** 4xx / 5xx bodies carry no secrets, keyring contents,
  raw provider errors with embedded credentials, or server file paths.
- **No ambient-credential CSRF.** Auth is bearer-token, not cookie-based, so a
  cross-site POST cannot borrow an ambient session; CORS stays locked to the
  console origin in production.

## Hardening checklist for a shared deployment

If you are exposing the console to anyone other than yourself on a single host:

1. **Set `EVIDENTIA_API_AUTH_TOKEN_FILE`** (or `--auth-token-file`). This is
   non-negotiable — it is what clears the banner and unlocks/gates the
   credentialed consoles.
2. **Set `EVIDENTIA_RBAC_POLICY_FILE`** to a deny-by-default policy so unlisted
   identities get no access.
3. **Keep the default `127.0.0.1` bind** unless you have a reason to route the
   interface; if you must, pair `--host` with the token file and let
   `--security-headers` engage (it does so automatically for a non-loopback host).
4. **Leave the SSRF private-IP block on.** Do not advertise `--allow-private-ips`
   to form users.
5. **Consider `--offline`** if the deployment never needs outbound egress; it
   fail-closes collectors, integrations, and Sigstore, routing signing to GPG.
6. **Verify the posture** with `evidentia doctor --check-air-gap`.

## Related reading

- [Serve the local web UI](../2-guides/serve-the-web-ui.md) — the step-by-step
  guide to starting the console, with the `serve` flag table.
- [RBAC and multi-tenancy](rbac-and-multi-tenancy.md) — the identity→role
  decision layer the auth gate feeds.
- [Evidence integrity](evidence-integrity.md) — the signing / verification chain
  the OSCAL Verify console exercises.
- [`docs/threat-model.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/threat-model.md)
  — the product-level external-input surface map this page sits under.
- [Air-gapped install](../2-guides/air-gapped-install.md) — running the console
  with no network egress at all.
