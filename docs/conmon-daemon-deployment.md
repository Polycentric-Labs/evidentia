# CONMON daemon deployment (v0.9.3 P1.1)

> Operator deployment guide for `evidentia conmon watch --poll`.
> Covers systemd (Linux), launchd (macOS), and Windows Service Manager.
> All examples are REFERENCES — operators retain full control over
> service-manager choice + lifecycle.

## What the daemon does

`evidentia conmon watch` is a long-running process that re-reads
the operator-supplied state file at a configurable interval
(default 1 hour) and emits audit events when CONMON cycles enter
due-soon or overdue states. Operators wire alerting (email,
webhook, etc.) via the v0.9.3 P1.2 alerting plug points.

The daemon:

- Runs in the foreground (no fork, no background mode) — operators
  delegate process supervision to systemd / launchd / Windows
  Service Manager.
- Re-loads the state file each poll cycle, so operators can run
  `evidentia conmon mark-completed <slug>` without daemon restart.
- Handles SIGINT (Ctrl+C) and SIGTERM (POSIX only) with graceful
  shutdown — finishes the current poll, fires
  `CONMON_DAEMON_STOPPED`, exits 0.
- Tolerates a missing state file (logs + retries at next interval)
  so brief operator file edits don't crash the daemon.

## Common configuration

```bash
evidentia conmon watch \
    --state-file /var/lib/evidentia/conmon-state.yaml \
    --poll-interval 3600 \
    --window-days 14
```

- `--state-file` — YAML mapping `{cadence_slug: ISO-8601-date}` of
  last-completed dates. Same schema as `evidentia conmon check
  --last-completed-file`. Re-read every poll.
- `--poll-interval` — seconds between polls; min 60, default 3600
  (1 hour). For CONMON cadences (daily/weekly/monthly), 1 hour is
  the practical sweet spot.
- `--window-days` — days ahead of today() to surface as "due soon"
  (default 14). Overdue cycles always surface regardless.

## Linux — systemd unit

Recommended for RHEL / Ubuntu / Debian / Amazon Linux 2+. Drop the
following into `/etc/systemd/system/evidentia-conmon.service`:

```ini
[Unit]
Description=Evidentia CONMON cycle-attention daemon
Documentation=https://github.com/Polycentric-Labs/evidentia
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=evidentia
Group=evidentia
WorkingDirectory=/var/lib/evidentia

# Adjust paths per your deployment.
ExecStart=/usr/local/bin/evidentia conmon watch \
    --state-file /var/lib/evidentia/conmon-state.yaml \
    --poll-interval 3600 \
    --window-days 14

# Restart policy: restart on crash, with backoff so a configuration
# bug doesn't spam systemd's journal.
Restart=on-failure
RestartSec=30s

# Resource limits — adjust per your audit-log retention budget.
LimitNOFILE=4096

# Security hardening. Daemon only reads the state file + writes
# audit logs; nothing else needs FS access.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/var/lib/evidentia /var/log/evidentia

# When P1.2 alerting is wired with SMTP/webhook credentials, use
# systemd's LoadCredential for file-based secret injection:
# LoadCredential=smtp-password:/etc/evidentia/secrets/smtp-password
# Then pass --smtp-password-file ${CREDENTIALS_DIRECTORY}/smtp-password

[Install]
WantedBy=multi-user.target
```

Activate:

```bash
sudo systemctl daemon-reload
sudo systemctl enable evidentia-conmon.service
sudo systemctl start evidentia-conmon.service
sudo systemctl status evidentia-conmon.service
journalctl -u evidentia-conmon.service -f
```

Verify lifecycle events landed:

```bash
journalctl -u evidentia-conmon.service \
    | grep -E "(daemon_started|daemon_stopped|cycle_due|cycle_overdue)"
```

## macOS — launchd plist

Drop into `~/Library/LaunchAgents/com.evidentia.conmon.plist` (per-user)
or `/Library/LaunchDaemons/com.evidentia.conmon.plist` (system-wide,
requires root):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.evidentia.conmon</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/evidentia</string>
        <string>conmon</string>
        <string>watch</string>
        <string>--state-file</string>
        <string>/usr/local/var/evidentia/conmon-state.yaml</string>
        <string>--poll-interval</string>
        <string>3600</string>
        <string>--window-days</string>
        <string>14</string>
    </array>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>RunAtLoad</key>
    <true/>

    <key>StandardOutPath</key>
    <string>/usr/local/var/log/evidentia/conmon.log</string>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/evidentia/conmon.err</string>

    <key>WorkingDirectory</key>
    <string>/usr/local/var/evidentia</string>
</dict>
</plist>
```

Activate:

```bash
launchctl load ~/Library/LaunchAgents/com.evidentia.conmon.plist
launchctl list | grep evidentia
tail -f /usr/local/var/log/evidentia/conmon.log
```

Stop / reload:

```bash
launchctl unload ~/Library/LaunchAgents/com.evidentia.conmon.plist
```

## Windows — Service Manager via sc.exe

Windows lacks a built-in process-supervisor with the same shape as
systemd. The lightweight path is to wrap `evidentia conmon watch`
in a Windows Service using `sc.exe`.

Save as `Install-EvidentiaConmonService.ps1`:

```powershell
# Install-EvidentiaConmonService.ps1 — run as Administrator
$ServiceName = "EvidentiaConmon"
$DisplayName = "Evidentia CONMON cycle-attention daemon"
$Description = "Polls CONMON cycle state and emits audit events on overdue/due-soon transitions."

# Adjust to your install location.
$EvidentiaExe = "C:\Program Files\Evidentia\evidentia.exe"
$StateFile = "C:\ProgramData\Evidentia\conmon-state.yaml"

$BinPath = "`"$EvidentiaExe`" conmon watch " +
           "--state-file `"$StateFile`" " +
           "--poll-interval 3600 " +
           "--window-days 14"

sc.exe create $ServiceName `
    binPath= $BinPath `
    DisplayName= $DisplayName `
    start= auto

sc.exe description $ServiceName $Description

# Recovery: restart on failure with 30s delay (3 failure threshold).
sc.exe failure $ServiceName reset= 86400 actions= restart/30000/restart/30000/restart/30000

sc.exe start $ServiceName
sc.exe query $ServiceName
```

Inspect logs via the Windows Event Viewer (Applications and
Services Logs → Evidentia) or wherever your structured-log shipper
is configured to ship.

Uninstall:

```powershell
sc.exe stop EvidentiaConmon
sc.exe delete EvidentiaConmon
```

### Note on Windows + SIGTERM

The CONMON daemon registers a SIGTERM handler on POSIX platforms
only — Windows uses different process-termination signals (SIGBREAK
on Ctrl+Break, the service-manager-issued stop request). SIGINT
(Ctrl+C) IS supported. Windows Service Manager's stop request
sends the equivalent of SIGINT to the daemon's process group,
which triggers the graceful shutdown path.

## Credential injection (P1.2 forward-looking)

When the v0.9.3 P1.2 alerting flags are wired (SMTP, webhook),
follow these credential-handling rules:

- Pass credentials via `--smtp-password-file <path>` or
  `--webhook-secret-file <path>` flags, OR via env vars
  (`EVIDENTIA_SMTP_PASSWORD`, `EVIDENTIA_WEBHOOK_SECRET`).
- NEVER use a `--smtp-password <value>` or `--webhook-secret
  <value>` CLI flag — those leak to shell history + process
  listings. The CLI parser rejects such flags by design.
- systemd: prefer `LoadCredential=<name>:<path>` + the
  `${CREDENTIALS_DIRECTORY}` env var. See the systemd unit example
  above.
- launchd: use `~/.evidentia/secrets/` with restrictive permissions
  (`chmod 600`) and pass via `--*-file`.
- Windows: use a secured directory like
  `C:\ProgramData\Evidentia\secrets\` with ACL restricted to the
  service account, and pass via `--*-file`.

## Webhook SSRF threat model (v0.9.4 P1.2)

`evidentia conmon watch --webhook-url <URL>` POSTs HMAC-signed JSON
to the operator-supplied URL on every alert. Without guard rails,
an attacker who can influence the URL (via operator-config
injection, supply-chain catalog poisoning, environment-variable
manipulation, etc.) can force the daemon to POST CONMON state to
internal-only endpoints — most notably the cloud-metadata service
at `169.254.169.254`, which would leak the IAM role credentials
assigned to the daemon's runtime environment.

v0.9.4 P1.2 closes this vector (F-V93-S2, CWE-918) with default-
deny construction-time validation:

- **`http://` schemes are REJECTED** unless `--webhook-allow-plaintext`
  is set. Cleartext exposes the HMAC-signed payload + headers to
  on-path attackers.
- **Loopback / RFC1918 / link-local / reserved IP destinations are
  REJECTED** unless `--webhook-allow-private-network` is set. Includes
  `127.0.0.1`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16`
  (cloud metadata), `fe80::/10`, and IPv4/IPv6 reserved ranges.

Both opt-ins exist because legitimate operator setups exist:

- Cleartext: closed networks where TLS termination happens at the
  ingress proxy upstream of the receiver
- Private network: on-host service-mesh bridge (e.g., local
  PagerDuty proxy), on-cluster Slack-bridge, or RFC1918-internal
  webhook endpoint

**DNS rebinding caveat**: the SSRF guard resolves the hostname at
config-construction time. If the IP changes after daemon start
(intentional DNS rebinding), the underlying `urlopen` hits the new
IP and bypasses the guard. Operators in adversarial-DNS
environments should pin the host to a known IP in `/etc/hosts` or
configure their resolver to reject TTL-0 responses for non-local
hostnames.

**Diagnostic**: rejection raises `ValueError` at daemon startup
(BEFORE the poll loop), with a message naming the rejected IP and
the opt-in flag that would permit it. The daemon exits with code 1
and the operator sees the actionable error.

## Lifecycle audit events

The daemon emits these `EventAction` values (auditor-visible):

| Event | When |
|---|---|
| `evidentia.conmon.daemon_started` | At boot, with config payload |
| `evidentia.conmon.daemon_stopped` | At graceful shutdown |
| `evidentia.conmon.cycle_due` | Per due-soon cycle, each poll |
| `evidentia.conmon.cycle_overdue` | Per overdue cycle, each poll |
| `evidentia.conmon.cycle_marked_completed` | When operator runs `mark-completed` |

**Auditor signal**: a `daemon_started` without a matching
`daemon_stopped` indicates the daemon crashed or was killed.
Configure your log shipper to alert on this pattern.

## See also

- [`docs/ROADMAP.md`](ROADMAP.md) — v0.9.3 P1 CONMON daemon scope
- [`docs/conmon-runbook.md`](conmon-runbook.md) — operator workflows
  for the v0.9.0 read-only library + CLI
- [`docs/v0.9.3-plan.md`](v0.9.3-plan.md) — full v0.9.3 cycle plan
