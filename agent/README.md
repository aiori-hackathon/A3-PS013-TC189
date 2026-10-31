# CyberTrace endpoint agent

The CyberTrace agent collects new bytes from configured Linux authentication and
web-access logs, hashes each segment locally, buffers batches in SQLite, and
uploads them to a CyberTrace server over HTTPS. It is Linux-oriented, has no
third-party Python dependencies, and does not modify or delete source logs.

The agent is a collection component, not an endpoint detection or response tool.
It does not execute commands, inspect processes, or collect arbitrary files.

## How collection works

- Each configured source is a regular file. The agent stores a byte cursor and
  the file's device/inode identity in its local state directory.
- On first sight, `start_position` decides whether existing bytes are collected:
  `end` (default) skips the current file content; `beginning` collects it.
- New content is read in bounded segments, written to a spool file, hashed with
  SHA-256, and only then added to a durable batch. A crash cannot silently
  advance the cursor past bytes that were never queued.
- Rotation or truncation is detected by device/inode change or a smaller file
  size. The agent reads the replacement file from the beginning.
- The local buffer is bounded by `max_buffer_bytes`. When full, collection stops
  and the source reports a `buffer_full` error until uploads free space.
- Batches are retried with bounded exponential backoff. Server, TLS, and network
  failures do not discard data.
- Non-retryable server rejections and oversized payloads are moved to
  `quarantine/` with a `QUARANTINE.txt` reason so the queue cannot loop forever.

Only complete lines are collected for oversized segments: when a segment boundary
would split a line, the agent backs up to the last newline in that read.

## Requirements

- Linux with systemd (the supplied unit is a starting point; other supervisors
  are possible).
- Python 3.11 or newer.
- Read access to each configured log file and write access to the state directory.
- A CyberTrace server reachable over HTTPS with a trusted certificate.
- An investigation UUID and the server's `AGENT_ENROLLMENT_TOKEN`.

The agent may also run in a lab on other platforms for testing, but the supplied
service hardening and file paths target Linux.

## Server preparation

1. Generate a long random enrollment token and set it in the server environment:

   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

   Set `AGENT_ENROLLMENT_TOKEN` in the server `.env` and restart the server.
   Registration is disabled while this value is unset.

2. Create an investigation in the dashboard or API and copy its UUID.

3. Serve the API over HTTPS. The agent refuses plain HTTP except for loopback
   labs with `allow_insecure_localhost=true`. A reverse proxy such as nginx or
   Caddy can terminate TLS in front of uvicorn.

The enrollment token is a shared registration secret. Do not reuse it as an
agent bearer token or put it in shell history. The server stores only the
SHA-256 hash of each per-agent bearer token it issues.

## Install

The commands below assume Debian/Ubuntu-style paths. Adjust package names for
your distribution.

```bash
sudo useradd --system --home /var/lib/cybertrace-agent \
  --shell /usr/sbin/nologin cybertrace
sudo install -d -o root -g root -m 0755 /opt/cybertrace-agent
sudo install -d -o root -g cybertrace -m 0750 /etc/cybertrace-agent

sudo python3 -m venv /opt/cybertrace-agent/venv
sudo /opt/cybertrace-agent/venv/bin/pip install --upgrade pip
sudo /opt/cybertrace-agent/venv/bin/pip install /path/to/Cyber_Trace/agent
```

Copy the example configuration and edit it:

```bash
sudo install -o root -g cybertrace -m 0640 \
  /path/to/Cyber_Trace/agent/config.example.json \
  /etc/cybertrace-agent/config.json
sudo editor /etc/cybertrace-agent/config.json
```

At minimum set:

- `server_url`: HTTPS origin only, without `/api` or a trailing path.
- `investigation_id`: the investigation UUID from the server.
- `state_dir`: `/var/lib/cybertrace-agent`.
- `display_name`: a human label for the dashboard.
- `sources`: each file to collect with a stable unique `key`.
- `start_position`: `beginning` for existing content, `end` to start with new
  lines only. The example uses `beginning` for evidence collection.

Write the enrollment token to a separate file:

```bash
sudo install -o cybertrace -g cybertrace -m 0600 /dev/null \
  /etc/cybertrace-agent/enrollment.token
printf '%s\n' 'PASTE_ENROLLMENT_TOKEN_HERE' | \
  sudo tee /etc/cybertrace-agent/enrollment.token >/dev/null
```

The agent reads the token only when enrollment is needed. It never writes the
enrollment token into its state directory. Per-agent bearer tokens are stored in
`agent-token` with mode `0600`.

### Log permissions

The service runs as `cybertrace`. Grant only the read access it needs. Options
include:

- Debian/Ubuntu: add the account to the `adm` group and add a systemd drop-in
  with `SupplementaryGroups=adm`.
- Use POSIX ACLs, for example:
  `sudo setfacl -m u:cybertrace:r /var/log/auth.log`.
- Use a dedicated log-forwarding path readable only by the agent account.

The supplied unit mounts `/var/log` read-only. Logrotate-created replacement
files need the same permissions, or collection will report `permission_denied`.

## Configuration reference

The JSON schema is strict: unknown keys are rejected so typos do not silently
disable collection.

| Key | Default | Meaning |
| --- | --- | --- |
| `server_url` | required | HTTPS origin, e.g. `https://cybertrace.example.internal:8443` |
| `api_prefix` | `/api` | API prefix on the server |
| `enrollment_token_file` | none | Path to the enrollment token; required only for first enrollment or re-enrollment |
| `state_dir` | required | Absolute directory for SQLite state, spool, quarantine, lock and agent token |
| `investigation_id` | required | Investigation UUID; must match the server |
| `agent_uid` | derived | Optional stable identifier; if omitted the agent derives one from `/etc/machine-id` and stores it |
| `display_name` | hostname | Dashboard label |
| `heartbeat_interval_seconds` | `60` | Heartbeat cadence, 5-86400 |
| `collection_interval_seconds` | `30` | Collection cadence, 1-86400 |
| `flush_interval_seconds` | `30` | Upload cadence, 1-86400 |
| `max_backoff_seconds` | `300` | Maximum retry delay |
| `http_timeout_seconds` | `30` | Per-request timeout |
| `max_batch_bytes` | `1048576` | Max bytes per upload batch |
| `max_batch_files` | `20` | Max segments per upload batch |
| `max_segment_bytes` | `262144` | Max bytes per spooled segment |
| `max_buffer_bytes` | `268435456` | Max spooled bytes awaiting upload |
| `start_position` | `end` | `beginning` or `end` for a source with no cursor |
| `allow_insecure_localhost` | `false` | Permit HTTP only for `127.0.0.1`, `::1`, or `localhost` |
| `tls.ca_file` | system trust | Optional CA bundle path |
| `tls.client_cert_file` / `tls.client_key_file` | none | Optional mutual-TLS client certificate pair |
| `sources` | required | Non-empty list of source objects |

Each source object supports:

| Key | Meaning |
| --- | --- |
| `key` | Stable unique key, 1-64 characters, letters/digits/`.`/`_`/`-` |
| `name` | Dashboard label |
| `source_type` | `linux_auth` or `web_access` |
| `path` | Absolute path to a regular file |
| `timezone_hint` | Optional IANA zone for timestamps without an offset |
| `default_year` | Optional year for classic syslog lines without a year |
| `clock_offset_seconds` | Optional explicit offset (-86400 to 86400) applied by the server to normalized events |
| `expected_collection_interval_seconds` | Optional expected cycle interval (5-86400) used for coverage evaluation |
| `enabled` | Set `false` to keep a source registered but stop collecting it |

`max_segment_bytes` must not exceed `max_batch_bytes`, and `max_buffer_bytes`
must be at least `max_batch_bytes`.

## TLS

By default the agent uses the operating system trust store. For a private CA:

```json
{
  "tls": {
    "ca_file": "/etc/cybertrace-agent/ca.pem"
  }
}
```

For mutual TLS, also set `tls.client_cert_file` and `tls.client_key_file`. The
server must be configured to require and validate client certificates at the
reverse proxy; the agent's bearer token remains a separate authorization layer.

Certificate files must exist and be readable by the agent account. Do not disable
verification in production; the agent has no option to do so.

## Validate and run

```bash
sudo -u cybertrace /opt/cybertrace-agent/venv/bin/cybertrace-agent check \
  --config /etc/cybertrace-agent/config.json
sudo -u cybertrace /opt/cybertrace-agent/venv/bin/cybertrace-agent run \
  --config /etc/cybertrace-agent/config.json --log-level INFO
```

The check command prints the effective non-secret configuration and source list.
It does not contact the server. The run command blocks until SIGTERM/SIGINT.

Install the supplied unit:

```bash
sudo install -o root -g root -m 0644 \
  /path/to/Cyber_Trace/agent/systemd/cybertrace-agent.service \
  /etc/systemd/system/cybertrace-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now cybertrace-agent
sudo journalctl -u cybertrace-agent -f
```

The unit uses `StateDirectory=cybertrace-agent`, which creates
`/var/lib/cybertrace-agent` for the service account. If you change `state_dir`
in the config, keep it consistent with the unit and directory ownership.

## Dashboard

The server exposes a fleet dashboard at `/agents`. It lists agents by
investigation and health (online, stale, never seen, disabled), shows each
agent's latest heartbeat, buffered queue, source health, recent batches and
reported errors. The `/quality` dashboard adds coverage evaluation: heartbeat
and collection intervals, last successful cycle, observed bytes/events, source
availability, and open collection gaps. Measured server-time offsets are reported
for visibility; only an explicitly configured `clock_offset_seconds` is applied
to event timestamps.

Disable, enable and delete actions send `X-Enrollment-Token` from the dashboard's
in-memory administration field. The token is not persisted by the dashboard. For
routine operations, prefer the server API and a secrets manager over typing the
enrollment token into a browser.

Disabling an agent immediately rejects its bearer token, but does not delete
local buffered data. Deleting the server registration removes delivery history
and inventory; already preserved evidence and timeline events remain. Use
disable, not delete, to block a running agent: deletion alone allows an agent
that still has the enrollment token to enroll again.

## Enrollment and identity

- On first contact the agent registers with the enrollment token and receives a
  per-agent bearer token. Re-registration rotates that token.
- The agent stores its `agent_uid` and bearer token in `state_dir`. Keep the
  directory on durable storage; it is not a cache.
- Reinstalling the agent with a preserved state directory does not create a
  duplicate registration.
- If `state_dir` is lost, the agent derives a new identity and registers as a new
  endpoint. If the old registration should be reused, restore the state directory
  or set a matching `agent_uid` and use the server's enrollment token.
- A server-side token rejection triggers re-enrollment. A `403` (for example,
  disabled agent) is treated as an administrative block and retried with the
  maximum backoff rather than bypassed.

## Operations and troubleshooting

| Symptom | Check |
| --- | --- |
| Dashboard shows never seen or stale | `systemctl status`, journal, network/TLS reachability, `state_dir` permissions |
| Source status `permission_denied` | Agent account read access to the current and rotated file; ACL/group membership |
| Source status `source_missing` | Configured path; logrotate may have moved it before the next collection |
| Source status `buffer_full` | Server reachability and upload errors; inspect spool and quarantine sizes |
| `invalid_enrollment_token` | Server `AGENT_ENROLLMENT_TOKEN`, token file contents and permissions |
| `agent_investigation_conflict` | The agent UID is registered to another investigation; use a fresh state directory or fix the server record |
| Agent appears disabled | Re-enable it in the dashboard; the agent retries with maximum backoff |
| Upload repeatedly fails with 422 | Check server time skew, manifest validation, source inventory sync, file hashes and batch size limits |
| Disk use grows | Inspect `<state_dir>/spool` and `<state_dir>/quarantine`; do not delete a live spool without stopping the agent |

Local state files:

```text
<state_dir>/
  agent-state.sqlite3   cursors, batch queue metadata, unreported errors
  agent-token           per-agent bearer token (0600)
  agent.lock            single-instance lock
  spool/<batch_id>/     queued segment files
  quarantine/           rejected batches plus QUARANTINE.txt
```

The agent does not delete quarantined data automatically. Review and remove it
according to the investigation's evidence-handling policy.

## Security notes

- Run as a dedicated, unprivileged account. Do not run the agent as root.
- Keep the enrollment token file at mode `0600`, owned by the agent account.
- Protect `state_dir`: it contains a bearer token and buffered log data. Use
  filesystem permissions and disk encryption where appropriate.
- The agent sends only configured log segments and operational metadata. It does
  not send the enrollment token in heartbeats or batch uploads.
- Agent bearer tokens are accepted over TLS. Plain HTTP is limited to loopback
  labs and is not suitable for evidence collection.
- The agent has no remote command execution, shell, file upload, or self-update
  capability.
- Rotate the server enrollment token if it leaks, then re-enroll affected agents.
- Review the systemd hardening directives against your distribution before
  deployment. `ProtectHome`, `ProtectSystem`, and `ReadOnlyPaths` can block paths
  that are not part of the supplied layout.

## Tests

The agent tests live in `agent/tests` and do not require a running server or
PostgreSQL:

```bash
cd agent
..\.venv\Scripts\python.exe -m pytest -q
..\.venv\Scripts\ruff.exe check cybertrace_agent tests
node --check ..\backend\app\static\agents.js
```

On Linux use `.venv/bin/python` and `.venv/bin/ruff` instead. Tests cover
incremental collection, rotation/truncation, cursor persistence, batching,
authentication error mapping, retry backoff, and transient uploads.
