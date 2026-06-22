# MCP client setup

Evidentia ships a **Model Context Protocol (MCP) server** that exposes its gap
analysis, control lookup, CONMON, TPRM, POA&M, and signed-artifact verification
surface as **13 tools** an AI agent can call directly. This guide gets that
server running and wires it into the MCP hosts you actually use — Claude Desktop,
Claude Code, and Cursor — so an agent can drive Evidentia on your behalf. It
covers the `evidentia mcp` command group (`serve`, `doctor`, `cimd-migrate`), the
canonical **stdio** transport those hosts speak, and the optional per-client
scope-gating registry.

## Prerequisites

- Evidentia installed **with the `mcp` extra**, which pulls in the MCP Python
  SDK and the FastMCP server (see [Installation](../1-getting-started/installation.md)):

  ```bash
  pip install "evidentia[mcp]"
  # or, as an isolated tool on your PATH:
  uv tool install "evidentia[mcp]"
  ```

- The `evidentia` command resolvable on your PATH. Confirm it:

  ```bash
  evidentia version
  ```

  If `evidentia` is not found, your virtualenv's `Scripts/` (Windows) or `bin/`
  (POSIX) directory is not active — re-activate it, or invoke the server as
  `python -m evidentia.cli.main mcp serve`.

> **Note on the examples below.** The `evidentia ...` invocations assume Evidentia
> is on your PATH (the normal `pip install` / `uv tool install` outcome). If you
> are running from a source checkout you can prefix them with `uv run` (e.g.
> `uv run evidentia mcp doctor`); the flags and output are identical.

## Step 1 — Confirm the server is launch-ready (`mcp doctor`)

Before wiring anything into a host, run the built-in preflight. `mcp doctor`
imports the MCP SDK, loads the bundled catalog registry, constructs the FastMCP
server (which registers every tool), and confirms the core tools are present. It
exits `0` on success and `1` on any failure, with a diagnostic on stderr.

```bash
evidentia mcp doctor
```

Real output on a healthy install:

```text
Evidentia MCP doctor: PASS
  • MCP SDK: importable
  • Catalog registry: 95 frameworks loaded
  • FastMCP server: 13 tools registered
```

If you see `1` with an import error instead, the `mcp` extra is missing — re-run
the install from [Prerequisites](#prerequisites). `mcp doctor` takes no flags
beyond `--help`.

## Step 2 — Understand the transport (and why you won't run `serve` by hand)

The server is launched with `evidentia mcp serve`. It **blocks until the client
disconnects** — it is a long-running server, not a one-shot command — so in
normal use you do **not** run it yourself in a terminal. Instead, you register the
launch command with an MCP host (Steps 4–6) and the host spawns, talks to, and
tears down the server for you over **stdio**.

`evidentia mcp serve --help` documents the transports and bind options:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--transport, -t {stdio\|sse\|http}` | `stdio` | `stdio` is the **canonical MCP transport** used by Claude Desktop, Claude Code, etc. `sse` (server-sent events) and `http` (streamable-http) are the non-local transports for browser-based agents and remote clients. |
| `--host` | `127.0.0.1` | Bind address for HTTP / SSE only. `0.0.0.0` binds all interfaces and **requires** a reverse-proxy auth layer in front (the server does not gate file-path tool inputs against an allow-root by itself). |
| `--port, -p` | `8765` | Bind port for HTTP / SSE only. `8765` is chosen to avoid colliding with `evidentia serve`'s default `8000`. |
| `--allow-root PATH` | unset | Bounds file-path tool inputs (`gap_analyze`, `gap_diff`) to a directory; out-of-root paths surface as a tool error rather than crashing the server. **Strongly recommended for non-loopback HTTP/SSE.** Unset is appropriate for stdio + loopback. |
| `--cimd-registry FILE` | unset | Loads a per-client scope registry (see [Step 7](#step-7-optional-gate-tools-per-client-with-cimd)). Pair with `--default-client-id` on stdio. |
| `--default-client-id TEXT` | unset | On stdio the wire protocol carries no per-request client_id, so this flag **is** the client_id for the whole session — set it to a slug in your CIMD registry to enable per-tool scope enforcement. |

> **Do not run `evidentia mcp serve` (stdio) in a foreground terminal to "test"
> it** — with no client attached it simply waits for stdin and appears to hang.
> Use `mcp doctor` (Step 1) to verify readiness instead. If you want to *prove*
> the server boots, start it on an HTTP port in the background — for example
> `evidentia mcp serve --transport http --port 8799` logs
> `Uvicorn running on http://127.0.0.1:8799` and then accepts connections — and
> stop it when you're done.

## Step 3 — Pick the launch command your host will run

Every MCP host config below boils down to one **command + args** pair. For
Evidentia over stdio that is:

- **command**: `evidentia`
- **args**: `["mcp", "serve", "--transport", "stdio"]`

`--transport stdio` is the default, so `["mcp", "serve"]` is equivalent; passing
it explicitly documents intent and survives any future default change. If
`evidentia` is not on the host process's PATH, use an absolute path to the
console script (for example the `Scripts/evidentia.exe` inside your virtualenv on
Windows, or `bin/evidentia` on POSIX) as the `command`.

## Step 4 — Wire it into Claude Desktop

Claude Desktop reads `claude_desktop_config.json` (on Windows:
`%APPDATA%\Claude\claude_desktop_config.json`; on macOS:
`~/Library/Application Support/Claude/claude_desktop_config.json`). Add an
`evidentia` entry under `mcpServers`:

```jsonc
{
  "mcpServers": {
    "evidentia": {
      "command": "evidentia",
      "args": ["mcp", "serve", "--transport", "stdio"]
    }
  }
}
```

Restart Claude Desktop. The 13 Evidentia tools become available to the model.

> **If `evidentia` isn't found**, Claude Desktop launches the command with its own
> environment, which may not include your virtualenv's scripts directory. Replace
> `"command": "evidentia"` with the **absolute path** to the console script — e.g.
> `"command": "C:\\path\\to\\.venv\\Scripts\\evidentia.exe"` on Windows or
> `"command": "/path/to/.venv/bin/evidentia"` on POSIX. (JSON requires the
> doubled backslashes on Windows.)

## Step 5 — Wire it into Claude Code

Claude Code registers MCP servers from the command line. Pass the launch command
after the `--` separator:

```bash
claude mcp add evidentia -- evidentia mcp serve --transport stdio
```

Everything after `--` is the literal command Claude Code will spawn over stdio.
To scope the registration to one project rather than your user config, add
`--scope project`, which writes a `.mcp.json` at the project root that you can
commit:

```jsonc
// .mcp.json
{
  "mcpServers": {
    "evidentia": {
      "command": "evidentia",
      "args": ["mcp", "serve", "--transport", "stdio"]
    }
  }
}
```

Confirm the server is registered and reachable with `claude mcp list`.

## Step 6 — Wire it into Cursor

Cursor reads `mcp.json` (project-level `.cursor/mcp.json`, or the global
`~/.cursor/mcp.json`). It uses the same standard MCP server shape:

```jsonc
{
  "mcpServers": {
    "evidentia": {
      "command": "evidentia",
      "args": ["mcp", "serve", "--transport", "stdio"]
    }
  }
}
```

Reload Cursor (or toggle the server in **Settings → MCP**) to pick it up.

> The `command` / `args` keys are the standard MCP server contract and are
> identical across these three hosts. Other hosts that consume the same
> `mcpServers` shape work the same way. If a particular host uses a config key
> Evidentia does not document here, consult that host's own MCP documentation
> rather than guessing the key — the launch command itself
> (`evidentia mcp serve --transport stdio`) does not change.

## Step 7 — (Optional) Gate tools per client with CIMD

By default every connected client can call every one of the 13 tools. For
multi-client deployments you can restrict which tools a given client may call
with a **CIMD (Client ID Metadata Document) registry** — a JSON file mapping each
`client_id` to a space-separated allowlist of tool names in its `scope`.

```jsonc
// cimd-registry.json
{
  "version": 1,
  "clients": {
    "claude-desktop": {
      "client_id": "claude-desktop",
      "client_name": "Claude Desktop",
      "scope": "list_frameworks get_control gap_analyze gap_diff",
      "redirect_uris": [],
      "policy_uri": null,
      "tos_uri": null
    },
    "readonly-agent": {
      "client_id": "readonly-agent",
      "client_name": "Read-only research agent",
      "scope": "list_frameworks get_control",
      "redirect_uris": [],
      "policy_uri": null,
      "tos_uri": null
    }
  }
}
```

Point the server at it and, on stdio, name the active client (the stdio wire
protocol carries no per-request client_id, so `--default-client-id` is what
identifies the session):

```bash
evidentia mcp serve --transport stdio \
  --cimd-registry cimd-registry.json \
  --default-client-id claude-desktop
```

An empty `scope` means deny-all; tool names not in the allowlist are denied.

> **CIMD is metadata + scope, not authentication.** A client that bypasses the
> transport's auth can claim any `client_id`. On stdio, trust is UID-based; for
> HTTP/SSE you must wire transport auth (reverse-proxy mTLS or bearer tokens) so
> clients cannot impersonate each other's entries.

### Migrating an older registry

If you built a CIMD registry before the four `conmon_*` tools shipped, those
tools are default-rejected for your clients until you grant them.
`evidentia mcp cimd-migrate` adds the `conmon_*` tool set to each client's
`scope`. It is idempotent (a tool already present is reported as no-change) and
rewrites the file in place — preview first with `--dry-run`:

```bash
evidentia mcp cimd-migrate cimd-registry.json --dry-run
```

Real dry-run output against a registry whose `claude-desktop` client predates the
CONMON tools:

```text
CIMD migration plan (DRY RUN) for cimd-registry.json:
  + claude-desktop: adding ['conmon_check_state', 'conmon_health', 'conmon_list_cadences', 'conmon_next_due'] (final scope: ['conmon_check_state', 'conmon_health', 'conmon_list_cadences', 'conmon_next_due', 'gap_analyze', 'gap_diff', 'get_control', 'list_frameworks'])
Dry run: registry file NOT modified. Re-run without --dry-run to apply.
```

Drop `--dry-run` to write the change. Restrict it to one client with
`--client-id <slug>`, or grant a different tool set with
`--tools 'tool_a tool_b'` for future tool additions.

## The 13 MCP tools

Tools are exposed in registration order. Purposes are from the
[MCP tools reference](../4-reference/mcp-tools.md), which is auto-generated from
the live codebase and is authoritative for the exact signatures.

| # | Tool | Purpose |
| --- | --- | --- |
| 1 | `list_frameworks` | List the bundled compliance catalogs + their metadata. |
| 2 | `get_control` | Return the raw catalog entry for a single control. |
| 3 | `gap_analyze` | Run a gap analysis against a local control inventory. |
| 4 | `gap_diff` | Diff two gap analysis reports. |
| 5 | `conmon_list_cadences` | List bundled continuous-monitoring cadences. |
| 6 | `conmon_next_due` | Compute the next-due date for a single CONMON cadence. |
| 7 | `conmon_check_state` | Read a state-file + report attention-state per cadence. |
| 8 | `conmon_health` | Return the CONMON health report for a state-file. |
| 9 | `gap_analyze_sarif` | Run gap analysis + return the report as a SARIF 2.1.0 log. |
| 10 | `collect_ocsf` | Ingest OCSF JSON from a local file → SecurityFinding list. |
| 11 | `tprm_vendor_list` | List every vendor in the local TPRM store. |
| 12 | `poam_list` | List every POA&M in the local store. |
| 13 | `verify_signed_artifact` | Verify an OSCAL Assessment Result file's signatures + digests. |

The tool surface is **append-only** within a major version: new tools may be
added, but existing names, parameters, and return shapes are not removed or
changed incompatibly before the next major release.

## What's next

- **Full flag and signature reference**: [MCP tools](../4-reference/mcp-tools.md)
  and [CLI reference → `evidentia mcp`](../4-reference/cli.md).
- **Verify what an agent produced**: the `verify_signed_artifact` tool checks the
  same signatures the [Sign and verify evidence](sign-and-verify-evidence.md)
  guide produces (including `SignedToolOutput` envelopes on MCP tool output).
- **Drive the CONMON tools end-to-end**: [CONMON deployment](conmon-deployment.md).

## Got stuck?

- **`evidentia: command not found` (in the terminal or from a host)** — the
  install succeeded but the scripts directory is not on PATH. Re-activate your
  virtualenv, run the server as `python -m evidentia.cli.main mcp serve`, or set
  the host's `command` to the absolute path of the `evidentia` console script.
- **`mcp doctor` exits 1 with an import error** — the `mcp` extra is missing.
  Install it: `pip install "evidentia[mcp]"`.
- **`evidentia mcp serve` seems to hang** — that is expected for stdio with no
  client attached; it is waiting on stdin. Don't run it by hand — let the host
  spawn it, and use `mcp doctor` to verify readiness.
- **A host launches but no Evidentia tools appear** — the host couldn't spawn the
  command. Check that `command`/`args` are correct for that host and that
  `evidentia` resolves in the host process's environment (use an absolute path if
  unsure), then restart the host.
- **`--no-stdio` errors out** — that flag is a removed-in-v1.0 backward-compat
  shim; use `--transport stdio` (the default) instead.
- **CIMD client's `conmon_*` calls are rejected** — the registry predates those
  tools; run `evidentia mcp cimd-migrate <registry> --dry-run`, then apply it.
