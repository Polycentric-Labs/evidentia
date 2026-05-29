# CONMON deployment

Continuous Monitoring (CONMON) is the federal-compliance discipline of
re-assessing controls on a recurring cadence rather than once a year. Evidentia
ships a **read-only cadence library** plus a `evidentia conmon` CLI that answers
"what's due, what's overdue?" against a state file you maintain — and an optional
**long-running daemon** (`evidentia conmon watch`) that polls that state and
emits audit events on transitions. This guide covers the cadence library, the
CLI verbs, and both deployment patterns.

## The bundled cadence library

Evidentia bundles **7 cadences** covering the major federal frameworks. Each
cadence pairs a stable slug with a frequency and the regulatory citation that
establishes it:

| Slug | Framework | Frequency | Citation |
| --- | --- | --- | --- |
| `nist-800-53-rev5-ca7` | nist-800-53-rev5 | monthly | NIST SP 800-53 Rev 5 CA-7 |
| `fedramp-conmon-poam` | fedramp-rev5-mod | monthly | FedRAMP ConMon Strategy & Guide v3.0 §3.4 |
| `fedramp-conmon-scans` | fedramp-rev5-mod | monthly | FedRAMP ConMon Strategy & Guide v3.0 §3.3 |
| `fedramp-conmon-annual` | fedramp-rev5-mod | annual | FedRAMP ConMon Strategy & Guide v3.0 §4 |
| `cmmc-l2-triennial` | cmmc-v2 | triennial | DoD CMMC 2.0 Program Rule (48 CFR Part 204) |
| `dod-rmf-annual` | dod-rmf | annual | DoDI 8510.01 §3.5.b |
| `occ-2026-13a-model-risk` | occ-2026-13a | annual | OCC Bulletin 2026-13a; FRB SR 26-02 |

The bundled cadences are immutable templates. Operators with organization-specific
review cycles can register additional cadences at runtime
(`evidentia_core.conmon.register_cadence`) — see the
[CLI reference](../4-reference/cli.md) and the source docstrings.

List what's available, optionally filtered by framework:

```bash
evidentia conmon list
evidentia conmon list --framework fedramp-rev5-mod
evidentia conmon list --json
```

## The state file

The `evidentia conmon` query verbs are driven by a **state file**: a YAML mapping
of `{cadence_slug: ISO-8601-date}` recording when each cycle was last completed.

```yaml
# conmon-state.yaml
nist-800-53-rev5-ca7: 2026-05-01
fedramp-conmon-poam: 2026-05-15
fedramp-conmon-annual: 2025-09-30
```

You can maintain this file by hand, or let Evidentia append to it:

```bash
evidentia conmon mark-completed nist-800-53-rev5-ca7 \
  --when 2026-05-28 \
  --state-file conmon-state.yaml
```

## Read-only deployment — the CLI query verbs

The lightest deployment is no daemon at all: run the query verbs on demand (from
a cron job, a CI step, or interactively) against your state file.

**What's due soon or overdue** (`--window-days` sets the due-soon horizon;
overdue cycles always surface):

```bash
evidentia conmon check --state-file conmon-state.yaml --window-days 14
```

**Aggregate cycle health by framework** (good for a dashboard or a status
report):

```bash
evidentia conmon health --state-file conmon-state.yaml --json
evidentia conmon health --state-file conmon-state.yaml --framework nist-800-53-rev5
```

**Compute the next-due date** for a single cadence from its last completion:

```bash
evidentia conmon next nist-800-53-rev5-ca7 --last-completed 2026-05-01
```

For deterministic CI snapshots, pass `--today YYYY-MM-DD` to `check` / `health`
so the output does not depend on the wall clock. Pipe the `--json` output into
your alerting or reporting pipeline.

## Daemon deployment — `evidentia conmon watch`

For hands-off monitoring, `evidentia conmon watch` runs as a long-lived process
that re-reads the state file on a configurable interval and emits audit events
when a cycle enters due-soon or overdue. It runs in the **foreground** (no
fork) — you delegate process supervision to systemd / launchd / Windows Service
Manager.

```bash
evidentia conmon watch \
  --state-file /var/lib/evidentia/conmon-state.yaml \
  --poll-interval 3600 \
  --window-days 14
```

- `--poll-interval` — seconds between polls; minimum 60, default 3600 (1 hour).
  For monthly/quarterly CONMON cadences, one hour is the practical sweet spot.
- The daemon re-loads the state file each poll, so you can run
  `evidentia conmon mark-completed` without restarting it.
- It handles SIGINT (and SIGTERM on POSIX) with graceful shutdown.

### Alerting

Wire SMTP and/or webhook alerting so transitions reach a human. Alerting flags
require an `--alert-dedup-file` so the same `(slug, state)` does not re-alert on
every poll within the suppression window:

```bash
evidentia conmon watch \
  --state-file /var/lib/evidentia/conmon-state.yaml \
  --alert-dedup-file /var/lib/evidentia/conmon-dedup.json \
  --webhook-url https://hooks.example.com/conmon \
  --webhook-secret-file /etc/evidentia/secrets/webhook-secret
```

Secrets are passed via `--*-file` paths or env vars
(`EVIDENTIA_SMTP_PASSWORD`, `EVIDENTIA_WEBHOOK_SECRET`) — never as a CLI value
flag. Webhook URLs are validated at startup: `http://` (cleartext) and
private-network destinations are rejected by default to close an SSRF /
cloud-metadata-exfiltration vector — opt in with `--webhook-allow-plaintext` /
`--webhook-allow-private-network` only for legitimate internal receivers.

Inspect the dedup state at any time:

```bash
evidentia conmon dedup-list --alert-dedup-file /var/lib/evidentia/conmon-dedup.json
```

### Running under a service manager

The daemon is meant to be supervised. Reference units for **systemd** (Linux),
**launchd** (macOS), and **Windows Service Manager** (`sc.exe`) — plus
credential-injection patterns, the webhook SSRF threat model, and the lifecycle
audit events — are in the in-repo runbook
[`docs/conmon-daemon-deployment.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/conmon-daemon-deployment.md).

> **Windows shutdown latency**: on Windows, a Ctrl+C / service-stop may take up
> to one `--poll-interval` to react (signal delivery during a blocking wait is
> deferred). For interactive testing set `--poll-interval 60`.

### Daemon health visibility

For operator health-checks, point the daemon at a status sidecar and a rolling
history file, then read them back via the REST API:

```bash
evidentia conmon watch \
  --state-file /var/lib/evidentia/conmon-state.yaml \
  --status-file /var/lib/evidentia/conmon-status.json \
  --history-file /var/lib/evidentia/conmon-history.jsonl
```

Configure the web server with the matching `EVIDENTIA_CONMON_DAEMON_STATUS_FILE`
/ `EVIDENTIA_CONMON_DAEMON_HISTORY_FILE` env vars to expose
`GET /api/conmon/daemon-status` and `/api/conmon/daemon-history`.

## What's next

- **Track remediation alongside cadences**: [Manage POA&M](manage-poam.md) —
  POA&M items are the work CONMON cycles surface.
- **Full flag reference**: [CLI reference → `evidentia conmon`](../4-reference/cli.md).

## Got stuck?

- **`Unknown CONMON cadence slug`** — run `evidentia conmon list` to confirm the
  exact slug; only the 7 bundled (plus any runtime-registered) slugs are valid.
- **Daemon exits immediately with `ValueError`** — a webhook URL was rejected by
  the SSRF guard. The error names the rejected IP and the opt-in flag that would
  permit it.
- **Alerting flag set but no `--alert-dedup-file`** — the dedup file is required
  whenever any `--smtp-*` / `--webhook-*` flag is set.
