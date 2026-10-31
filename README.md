# CyberTrace — Digital Forensics Timeline Analyzer

**AIORI-3 Hackathon | Problem Statement PS-013**

**Team Name:** Team Ignite
**Team Code:** `A3-PS013-TC189`
**Institution:** Karunya Institute of Technology & Science

Resources: [Project presentation](CyberTrace-Hackathon-Presentation.pdf) ·
[Team introduction video](https://youtu.be/WXXLueNYNnc)

CyberTrace is a small-team digital forensics timeline analyzer for PS-013. It
imports Linux authentication logs and Apache/nginx access logs, preserves the
original evidence with SHA-256 hashes, and builds a normalized, searchable
timeline while keeping timestamp uncertainty and parsing gaps explicit.

Phase 2 adds an optional Linux endpoint agent. The agent reads configured logs
incrementally, hashes each collected segment, buffers batches durably, retries
transient delivery failures, and uploads authenticated batches to one
investigation. A fleet dashboard at `/agents` shows agent health, source
inventory, buffered delivery state, batch outcomes, and reported errors.

Phase 3 adds evidence-quality analysis: collection coverage and gap tracking,
timestamp/clock-offset confidence, parsing transparency, integrity checks and
manifest export, non-destructive duplicate reconciliation, and an evidence audit
trail. The `/quality` dashboard presents these signals for one investigation.

Phase 4.1 adds an investigation dashboard and unified timeline at `/`. It keeps
collection coverage, parsing failures, timestamp uncertainty, evidence
integrity, and the searchable event timeline on one screen, while the original
evidence workspace remains available at `/workspace`.

The dashboard and API are intended for local or trusted-network use. This is a
prototype for small teams, not a production endpoint monitoring or response
platform.

## Problem statement and objectives

PS-013 asks for incident timeline and evidence collection support for small
investigation teams, whose work is typically slowed down by scattered log
files, manual analysis, inconsistent timestamps across systems, and evidence
whose integrity is hard to demonstrate.

CyberTrace implements one organized workflow for this problem:

1. **Collect** evidence from supported log sources, both by manual upload and
   by an optional Linux endpoint agent.
2. **Preserve** original bytes unchanged and bind them to SHA-256 hashes.
3. **Normalize** timestamps only when the source metadata is sufficient, and
   flag everything else instead of guessing.
4. **Reconstruct** a searchable, sortable incident timeline.
5. **Correlate** related events across sources with explainable rules.
6. **Report** and export findings as PDF and CSV.

## Phase 1 capabilities

- Create investigations and import evidence into one of them.
- Parse two log families:
  - Linux authentication syslog (RFC 3164 and ISO/journald-style lines).
  - Apache/nginx common and combined access logs.
- Store original uploads outside the database under a generated evidence path,
  hash them with SHA-256 while streaming, and make the files read-only.
- Refuse duplicate evidence within an investigation unless explicitly allowed.
- Normalize timestamps to UTC only when the source provides an offset or the
  investigator supplies a timezone; never guess an unknown timezone or year.
- Keep the original timestamp text, timezone information, normalized UTC value,
  and timestamp status on every event.
- Record malformed, unsupported, and flagged records as parsing issues instead of
  silently dropping them.
- Search and filter the unified timeline by time, source, event type, hostname,
  username, source IP, HTTP status, and free text.
- Verify stored evidence against its collection-time SHA-256 hash.
- Reparse only from the preserved original after hash verification.
- Serve a built-in evidence workspace at `/workspace`, with the Phase 4.1
  investigation dashboard at `/`, and OpenAPI documentation at `/docs`.

## Phase 2 capabilities

- Enroll Linux endpoints with a server-wide enrollment token. The server issues
  per-agent bearer tokens and stores only their SHA-256 hashes.
- Collect new bytes from configured authentication and web-access logs without
  modifying or deleting the originals.
- Detect rotation and truncation, persist byte cursors, and spool each collected
  segment before advancing the cursor.
- Buffer batches in SQLite while the server is unavailable and retry with bounded
  exponential backoff.
- Upload idempotent, authenticated batches over HTTPS with a manifest, per-item
  SHA-256, size, collection time, and byte range.
- Map each agent source to an evidence source so timeline, evidence integrity,
  reparse, and duplicate detection work unchanged.
- Report heartbeats, queue depth, source health, runtime status, and errors.
- Inspect online, stale, never-seen, and disabled agents in a fleet dashboard at
  `/agents`, including sources, batches, and recent errors.
- Disable, enable, or delete agent registrations without deleting preserved
  evidence or timeline events.

The agent is optional. Manual evidence upload from the original dashboard and
API remains fully supported.

## Phase 3 capabilities

- Report per-source collection coverage from agent heartbeats and collection
  windows: expected versus observed cycles, missing cycles, byte volumes, event
  counts, and reporting/idle/not-reporting/error/disabled/unknown states.
- Derive open and closed collection gaps for missed intervals, byte-range gaps,
  agent silence, and reported collection failures. Gap basis distinguishes
  observed facts from inferred intervals.
- Keep manual-upload sources explicitly `unknown` rather than treating them as
  healthy coverage; zero collected bytes never implies zero host activity.
- Record timestamp status, precision, original text, applied or merely measured
  clock offsets, and timeline ordering ties without inventing UTC values.
- Expose parser counters for accepted, rejected, malformed, unsupported,
  missing-required/optional-field, duplicate, timestamp-flagged, and ordering
  records, including issues suppressed by the retention cap.
- Verify preserved evidence on demand, record every verification, and export a
  canonical SHA-256 manifest for an investigation or one evidence file.
- Detect duplicate events non-destructively: duplicates are linked to a canonical
  event and can be reconciled again; no original evidence or event row is deleted.
- Record an evidence audit trail for preservation, parsing, download,
  verification/mismatch, reparse, duplicate rejection/reconciliation, and manifest
  export.
- Serve the quality dashboard at `/quality` and the documented APIs under
  `/api/quality`.

## Phase 4.2 capabilities

- Generate transparent, rule-based correlations between events from different sources.
- Match events on shared source IP, username, or hostname, with configurable time windows.
- Detect possible authentication-to-web activity relationships.
- Store correlation records and event links in the database without changing original events.
- Explain each correlation with events, source systems, matching fields, time relationship, rule, confidence, and timestamp uncertainty.
- Allow investigators to inspect linked events and dismiss suggested correlations with a reason.
- Integrate correlations into the Phase 4.1 dashboard with highlighting and detail cards.

## Phase 4.1 capabilities

- Serve an investigation dashboard at `/` (also `/dashboard`) with a case
  overview, summary metrics, registered sources, agent coverage, collection
  gaps, parser outcomes, uncertain timestamps, and evidence integrity.
- Keep incident quality explicit: open gaps, parsing failures/rejections,
  timestamp uncertainty, and unverified or mismatched evidence stay visible
  instead of being reduced to a single health score.
- Search and filter the unified timeline by free text, source, source type,
  event type, hostname, timestamp status, and local time range, with pagination
  and optional inclusion of unresolved-time and duplicate events.
- Open any event in a detail drawer that separates observed source fields from
  CyberTrace-derived analysis, shows the preserved raw line, and exposes
  evidence SHA-256, collection/receipt times, integrity state, HTTP fields, and
  clock-offset/ordering notes.
- Verify preserved evidence directly from the integrity table or event drawer
  and refresh the summary, integrity, and timeline views.
- Preserve the Phase 1 evidence workspace at `/workspace`; the Phase 2 agent
  fleet dashboard remains at `/agents` and the Phase 3 quality dashboard at
  `/quality`.
- Add `GET /api/investigations/{id}/sources` for timeline source filtering and
  expose earliest/latest evidence collection timestamps in the investigation
  summary.

## Out of scope

Agent auto-update, Windows/macOS service installers, remote command execution,
central log shipping, endpoint response actions, RBAC and
multi-tenant case collaboration, IOC enrichment, automated clock-skew correction,
signed manifests, and production hardening remain future work. The built-in
HTML/CSS/JavaScript dashboards are intentionally small and dependency-free.
PDF/CSV export is implemented (see Phase 4.3 below), but interactive timezone
resolution, actor-level correlation, and report signing remain future work.

## Architecture

```text
Linux endpoint agent                         Browser / API client
  source files -> cursors -> spool               |
  hashing -> SQLite queue -> HTTPS               v
        |                                  FastAPI routers
        |        investigations | evidence | timeline | health | agents | quality
        |                                       |
        +-------- authenticated batches ------>|
                                                v
                                          IngestService
                              validate -> stream to temp -> SHA-256
                                       -> preserve read-only
                                       -> detect parser -> parse -> events
                                       -> coverage/audit/dedup metadata
                                                |
                                +---------------+---------------+
                                v                               v
                          PostgreSQL                     Evidence storage
              metadata, agents, batches, coverage,      immutable original bytes
              audits, derived events and errors
```

PostgreSQL stores investigation metadata, evidence metadata and hashes, parsing
counters and issues, normalized events, agent registration and health, source
inventory, collection windows and gaps, integrity verifications, duplicate
reconciliation runs, evidence audit events, batch delivery history, and agent
error reports. Raw evidence bytes stay on disk and are referenced only by an
application-generated relative path. Reparsing and agent ingestion preserve the
original file; reparsing deletes and recreates derived parsing/event rows only.

## Requirements

- Python 3.11+ (this implementation was verified with Python 3.13.15).
- PostgreSQL 15+ (verified with PostgreSQL 18.6).
- Windows PowerShell examples below; the same commands work with POSIX paths.
- No Docker is required for the verified local setup.
- For endpoint collection: Linux with Python 3.11+, read access to the selected
  logs, and HTTPS access to the server. See `agent/README.md`.

## Quick start

From the project root:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r backend\requirements-dev.txt
Copy-Item .env.example .env
```

Create a least-privilege database role and the development/test databases. Run
these as a PostgreSQL administrator and replace the placeholder password:

```powershell
psql -U postgres -c "CREATE ROLE cybertrace_app LOGIN PASSWORD '<replace-me>';"
psql -U postgres -c "CREATE DATABASE cybertrace OWNER cybertrace_app;"
psql -U postgres -c "CREATE DATABASE cybertrace_test OWNER cybertrace_app;"
```

Update both URLs in `.env` with the same role and password. Percent-encode any
special characters in the URL. `.env` is gitignored; never commit it.

Apply the database migration:

```powershell
cd backend
..\.venv\Scripts\alembic.exe -c alembic.ini upgrade head
```

Start the application:

```powershell
..\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000
```

Open:

- Investigation dashboard and unified timeline: `http://127.0.0.1:8000/`
- Evidence workspace (upload, reparse, issue detail): `http://127.0.0.1:8000/workspace`
- Agent fleet dashboard: `http://127.0.0.1:8000/agents`
- Evidence quality dashboard: `http://127.0.0.1:8000/quality`
- API documentation: `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/api/health`

Bind to `127.0.0.1` by default. The investigator-facing API and dashboards have
no login, authorization, or tenancy layer and must not be exposed to an
untrusted network. Agent endpoints require a bearer token, but they still need
TLS and a trusted reverse-proxy boundary before leaving localhost.

## Configuration

Configuration is read from the process environment and the project-root `.env`.

| Variable | Purpose | Default |
| --- | --- | --- |
| `DATABASE_URL` | SQLAlchemy PostgreSQL URL | required |
| `TEST_DATABASE_URL` | Dedicated test database URL | none |
| `STORAGE_ROOT` | Evidence and temporary upload root | `backend/storage` |
| `MAX_UPLOAD_SIZE_BYTES` | Maximum upload size | 50 MiB |
| `MAX_LINE_BYTES` | Analysis cap for one physical line | 1 MiB |
| `MAX_STORED_RAW_LINE_CHARS` | Raw-line characters kept in analysis tables | 8000 |
| `MAX_PARSING_ISSUES` | Issues retained per file; further issues are counted as suppressed | 10000 |
| `ALLOWED_EXTENSIONS` | Accepted upload extensions | see `.env.example` |
| `CORS_ORIGINS` | Optional comma-separated browser origins | empty |
| `API_PREFIX` | API route prefix | `/api` |
| `LOG_LEVEL` | Python log level | `INFO` |
| `AGENT_ENROLLMENT_TOKEN` | Shared registration secret; empty disables registration | empty |
| `AGENT_STALE_AFTER_SECONDS` | Age after which an agent is shown as stale | 300 |
| `AGENT_DEFAULT_HEARTBEAT_INTERVAL_SECONDS` | Heartbeat interval used for coverage when not reported | 60 |
| `AGENT_DEFAULT_COLLECTION_INTERVAL_SECONDS` | Collection interval used for coverage when not reported | 60 |
| `AGENT_BATCH_MAX_FILES` | Maximum files in one agent batch | 50 |
| `AGENT_BATCH_MAX_BYTES` | Maximum total bytes in one agent batch | 50 MiB |
| `AGENT_MANIFEST_MAX_BYTES` | Maximum manifest JSON size | 512 KiB |
| `QUALITY_DEFAULT_WINDOW_HOURS` | Default coverage/gap lookback window (1–720) | 24 |

Storage paths are resolved from the project root when relative. The database
connection uses UTC for every PostgreSQL session so API timestamps are emitted in
UTC rather than the server's local offset.

Generate `AGENT_ENROLLMENT_TOKEN` with a cryptographically secure random value
and keep it out of source control:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Registration is disabled while the value is empty. Treat it as a shared
registration secret, not an agent token. Rotate it if it leaks and re-enroll the
affected agents.

## Endpoint agents

Phase 2 agent setup, permissions, TLS, configuration, systemd installation, and
troubleshooting are documented in [`agent/README.md`](agent/README.md). The
short version:

1. Set `AGENT_ENROLLMENT_TOKEN` on the server and serve the API over HTTPS.
2. Create an investigation and copy its UUID.
3. Install the agent package on a Linux host, write
   `/etc/cybertrace-agent/config.json`, and protect the enrollment token file.
4. Run `cybertrace-agent check --config ...`, then start the supplied systemd
   unit.
5. Open `/agents` to confirm enrollment, heartbeat, sources, and batch delivery.

The agent collects only configured regular files. It records byte cursors and
device/inode identity so log rotation and truncation are handled explicitly. It
does not execute shell commands, perform endpoint response, delete source logs,
or upload arbitrary paths.

Agent batches enter the same `IngestService` used by manual uploads: original
bytes are preserved, SHA-256 is verified against the manifest, timestamps follow
the same uncertainty policy, duplicate evidence within an investigation is
detected, and reparse still works from the preserved original. An agent batch
replay is idempotent by agent and batch ID.

## Supported logs

### Linux authentication

Accepted line shapes:

```text
Oct 31 10:05:00 web01 sshd[2403]: Failed password for alice from 198.51.100.7 port 44321 ssh2
2026-10-31T10:05:00+05:30 web01 sshd[2403]: Accepted password for alice from 192.168.1.10 port 51234 ssh2
```

Recognized records include accepted passwords, failed passwords, invalid-user
attempts, session open/close, sudo commands, and SSH disconnect messages. Other
well-formed authentication lines are retained as `auth_other`. Fields such as
source IP, username, process, PID, source port, sudo target user, command, TTY,
and working directory are extracted when present.

RFC 3164 lines (`Oct 31 10:05:00`) have no year or timezone. Supply both a
`timezone_hint` and `default_year` at upload time to normalize them. Otherwise
their events are kept with `timestamp_utc = null` and an explicit status.

### Web access logs

Accepted Apache/nginx common or combined lines:

```text
203.0.113.77 - - [31/Oct/2026:09:55:12 +0530] "POST /login HTTP/1.1" 401 87 "https://example.test/login" "Mozilla/5.0"
192.0.2.10 - - [31/Oct/2026:04:32:00 +0000] "GET /login HTTP/1.0" 200 512
```

The parser extracts client IP, remote user, timestamp, request method/path/protocol,
status, response bytes, referer, and user agent. A source hostname supplied at
upload time is used as the event hostname fallback because access logs do not
contain a hostname.

### Detection and unsupported files

Auto-detection samples up to 100 non-blank lines. If a file matches neither
family, the original is still preserved and hashed, the evidence status becomes
`failed`, and an `unsupported_format` issue is recorded. Extension checks are an
allowlist, not a substitute for content detection.

## Timestamp policy

| Status | Meaning | `timestamp_utc` |
| --- | --- | --- |
| `normalized` | Explicit offset or supplied timezone made UTC conversion possible | set |
| `missing_timezone` | Wall-clock time is known but no offset/timezone is available | `null` |
| `missing_year` | RFC 3164 record has no year and none was supplied | `null` |
| `ambiguous` | DST fold maps to two instants, or the local time does not exist | `null` |
| `invalid` | Timestamp text is malformed or out of range | `null` |

`collected_at` is separate from event time. It defaults to the ingestion time and
must include an offset/timezone when supplied by the client. It is stored in UTC.

The timeline shows unresolved-time events last in ascending order. Use
`include_unknown_time=false` to exclude them or `timestamp_status=` to isolate
one uncertainty class. CyberTrace does not estimate clock skew or infer missing
timezones. A source-level `clock_offset_seconds` may be configured explicitly;
it is applied to normalized event timestamps and recorded as applied. An agent's
offset measured against server time is recorded for visibility but never applied
automatically.

## Collection coverage

Coverage is computed from agent heartbeats, source status reports, and byte-range
collection windows. Each registered source is classified as `reporting`, `idle`,
`not_reporting`, `error`, `disabled`, or `unknown`. Manual uploads and sources
without agent telemetry remain `unknown`; they are not counted as healthy.

Collection gaps have a scope, reason, basis, and status. Reasons include missed
heartbeat cycles, reported collection failures, byte-range gaps between segments,
and silence from a previously reporting source. `observed` gaps come from
explicit reports; `inferred` gaps describe intervals where expected collection
did not appear. Inferred gaps are evidence-quality warnings, not proof that the
host produced no activity. Zero bytes reported in a cycle does not establish that
no events occurred.

Coverage and gaps can be queried for a selected time window and are summarized in
the `/quality` dashboard. Coverage summaries are investigative context, not a
claim of uninterrupted endpoint visibility.

## Evidence integrity

1. Uploads are streamed to a temporary file while SHA-256 is computed.
2. Empty files, NUL-containing/binary uploads, bad extensions, and oversized
   files are rejected.
3. Filenames are sanitized and stored inside a generated
   `evidence/{investigation_id}/{evidence_id}/` directory.
4. The final file is made read-only. PostgreSQL stores the hash, size, original
   filename, collection time, source, and relative path.
5. A duplicate SHA-256 in the same investigation returns HTTP 409 unless
   `allow_duplicate=true`.
6. `POST /api/evidence/{id}/verify` recomputes the hash and records the result.
7. `POST /api/evidence/{id}/reparse` verifies the hash first, then replaces only
   derived parsing rows. A mismatch refuses reparse.
8. `GET /api/quality/investigations/{id}/manifest` and
   `GET /api/evidence/{id}/manifest` export a canonical manifest whose SHA-256
   covers the scope, investigation ID, and recorded item metadata.

Read-only permissions are best-effort on Windows. The application itself never
opens an evidence file for writing after preservation. Verification proves that
stored bytes match the hash recorded at ingestion; it does not prove the bytes
were authentic before collection. Audit events record preservation, download,
parsing, reparse, verification outcomes, duplicate reconciliation, and manifest
export, but they are not signed or tamper-evident at the database level.

## API summary

All routes use the `/api` prefix.

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Database, schema, storage, and version status |
| `POST` | `/investigations` | Create an investigation |
| `GET` | `/investigations` | List investigations with counts |
| `GET` | `/investigations/{id}` | Investigation detail |
| `GET` | `/investigations/{id}/summary` | Aggregated evidence/event/issue counters and collection range |
| `GET` | `/investigations/{id}/sources` | Registered evidence sources for timeline filtering |
| `POST` | `/investigations/{id}/evidence` | Upload, hash, preserve, detect, parse |
| `GET` | `/evidence?investigation_id=` | List evidence in an investigation |
| `GET` | `/evidence/{id}` | Evidence metadata and parsing summary |
| `GET` | `/evidence/{id}/status` | Event and issue counters |
| `GET` | `/evidence/{id}/issues` | Parsing issues with severity/type filters |
| `GET` | `/evidence/{id}/download` | Download the preserved original |
| `POST` | `/evidence/{id}/verify` | Recompute and record SHA-256 verification |
| `POST` | `/evidence/{id}/reparse` | Verify and reparse from the original |
| `GET` | `/timeline?investigation_id=` | Search, filter, sort, paginate events |
| `GET` | `/events/{id}` | Full normalized event with raw source line |
| `POST` | `/agents/register` | Enroll or re-enroll an agent; requires enrollment token |
| `GET` | `/agents/me` | Agent identity, health, and source inventory; agent bearer |
| `PUT` | `/agents/sources` | Synchronize configured source inventory; agent bearer |
| `POST` | `/agents/heartbeat` | Runtime status, queue depth, source health, errors; agent bearer |
| `POST` | `/agents/batches` | Upload a manifest and files; agent bearer |
| `GET` | `/agents` | List agents by investigation and health |
| `GET` | `/agents/health` | Fleet health and queue counters |
| `GET` | `/agents/{id}` | Agent detail with sources, recent batches, and errors |
| `GET` | `/agents/{id}/sources` | Source inventory for one agent |
| `GET` | `/agents/{id}/batches` | Batch delivery history for one agent |
| `POST` | `/agents/{id}/disable` | Disable an agent; requires enrollment token |
| `POST` | `/agents/{id}/enable` | Re-enable an agent; requires enrollment token |
| `DELETE` | `/agents/{id}` | Delete registration and delivery history; preserved evidence remains |
| `GET` | `/quality/overview` | Investigation-level coverage, timestamp, duplicate and integrity totals |
| `GET` | `/quality/investigations/{id}/coverage` | Per-source coverage for a time window |
| `GET` | `/quality/investigations/{id}/gaps` | Open and closed collection gaps |
| `GET` | `/quality/investigations/{id}/parsing` | Parser counters and per-evidence outcomes |
| `GET` | `/quality/investigations/{id}/timestamps` | Timestamp status, ordering, offset, and uncertain samples |
| `GET` | `/quality/investigations/{id}/integrity` | Integrity status and per-evidence verification state |
| `GET` | `/quality/investigations/{id}/duplicates` | Duplicate groups and canonical links |
| `POST` | `/quality/investigations/{id}/reconcile` | Rebuild duplicate links without deleting events |
| `GET` | `/quality/investigations/{id}/audit` | Evidence audit events with filters |
| `GET` | `/quality/evidence/{id}/audit` | Audit events for one evidence file |
| `GET` | `/quality/investigations/{id}/manifest` | Canonical investigation manifest with SHA-256 |
| `GET` | `/evidence/{id}/manifest` | Canonical manifest for one evidence file |

Manual upload multipart fields: `file` (required), `source_type` (`auto`,
`linux_auth`, or `web_access`), `source_id`, `source_name`, `hostname`,
`source_ip`, `timezone_hint`, `default_year`, `collected_at`, `notes`, and
`allow_duplicate`.

Agent batch upload is multipart `manifest=<JSON>` plus zero or more `files`
parts. The manifest contains `batch_id`, `investigation_id`, `created_at`,
optional `agent_version`, item entries with `item_id`, `source_key`,
`source_type`, `filename`, `sha256`, `size_bytes`, `collected_at`, optional
`range_start`/`range_end`, optional `collection_started_at`/
`collection_ended_at` and `lines_collected`, and optional agent-reported
`errors`. Heartbeats may include heartbeat/collection intervals, reported and
measured clock offset, and per-source collection availability and observed byte
counts. The agent API uses `Authorization: Bearer <agent_token>`; management
routes use `X-Enrollment-Token`.

Example:

```powershell
$base = "http://127.0.0.1:8000/api"
$case = Invoke-RestMethod -Method Post -Uri "$base/investigations" `
  -ContentType "application/json" `
  -Body '{"name":"Synthetic incident","description":"Phase 1 demo"}'

curl.exe -s -X POST "$base/investigations/$($case.id)/evidence" `
  -F "file=@samples/scenario_1_ssh_bruteforce/auth.log" `
  -F "source_type=linux_auth" `
  -F "source_name=bastion-auth" `
  -F "hostname=bastion"
```

## Tests

Run backend tests from `backend`:

```powershell
..\.venv\Scripts\python.exe -m pytest -q
..\.venv\Scripts\ruff.exe check app tests
..\.venv\Scripts\python.exe -m compileall -q app tests
node --check app\static\app.js
node --check app\static\dashboard.js
node --check app\static\agents.js
node --check app\static\quality.js
```

The test configuration requires `TEST_DATABASE_URL`. It refuses to run if the
database name does not end in `_test`, then drops and recreates the known tables
in that dedicated test database. Test uploads use a temporary storage root, not
`backend/storage`.

The backend suite covers valid and malformed parsing, timestamp uncertainty and
DST, hashing/verification/tamper detection, duplicates, reparsing, upload
validation, database persistence, timeline filtering and ordering, the three
synthetic scenarios in `samples/`, live API serialization, agent enrollment and
token rotation, source inventory and heartbeat errors, agent management, batch
hashing/parsing/idempotency, manifest validation failures, coverage and gap
derivation, timestamp uncertainty and clock offsets, integrity verification and
tamper detection, duplicate linking and reconciliation, evidence audit and
manifests, the Phase 4.1 investigation summary/sources timeline fields, and all
four dashboards.

Run agent tests from `agent`:

```powershell
..\.venv\Scripts\python.exe -m pytest -q
..\.venv\Scripts\ruff.exe check cybertrace_agent tests
```

Agent tests use a local loopback HTTP fixture and temporary state directories;
they do not require PostgreSQL or a running CyberTrace server. They cover
configuration validation, incremental collection and rotation detection, cursor
persistence, buffering and delivery, retry/backoff, quarantine, authentication
error mapping, state identity conflicts, and Phase 3 collection/heartbeat
reporting fields.

## Project layout

```text
agent/
  cybertrace_agent/         Python agent (client, collector, runner, state, CLI)
  tests/                    agent pytest suite
  systemd/                  hardened service unit example
  config.example.json       Linux agent configuration template
  README.md                 agent installation and operations guide
backend/
  app/
    main.py                 FastAPI app, static dashboards, lifespan checks
    models.py               SQLAlchemy schema
    schemas.py              investigator API request/response models
    agent_schemas.py        agent API request/response models
    routers/                API endpoints, including agents and quality
    services/               ingest, storage, timestamp, analytics, parsers,
                            agent authentication, coverage, quality and health
    static/                 dependency-free dashboard, workspace, fleet and quality UIs
  alembic/                  migration environment and Phase 1/2/3 revisions
  tests/                    backend pytest suite and fixtures
  requirements.txt
  requirements-dev.txt
  pytest.ini
  pyproject.toml            ruff configuration
samples/                    three synthetic incident scenarios
docs/                       documentation set (installation, architecture, API, ...)
.env.example                placeholder configuration
```

## Synthetic scenarios

The `samples/` directory contains three synthetic incident datasets and usage
notes:

1. SSH brute force followed by successful login and web probing.
2. Web intrusion indicators correlated with authentication failures and sudo.
3. Yearless/timezone-less legacy logs that demonstrate explicit uncertainty.

See `samples/README.md` for expected counts and upload hints.

## Security notes and limitations

- The investigator dashboard, evidence, timeline, investigation, and quality APIs
  have no login, authorization, or tenancy. Evidence lifecycle actions are
  recorded in an application audit table, but it is not a signed, tamper-evident,
  or complete API access log. Keep these surfaces on localhost or a trusted
  network.
- Agent registration uses one shared enrollment token. It disables registration
  when unset, but it is not a substitute for TLS, proxy access control, or
  network segmentation. Per-agent tokens are stored only as SHA-256 hashes and
  are rejected immediately when an agent is disabled.
- The dashboard administration field holds the enrollment token in page memory
  only; it is not persisted. For routine operations, use a secrets manager and
  the API instead of browser entry.
- Uploaded text is never executed or shelled out. Raw log lines and agent error
  messages are rendered as text and escaped by the dashboards.
- No malware scanning is performed; only size, extension, emptiness, and NUL-byte
  checks are applied.
- Evidence is not encrypted at rest by the application. Use OS/disk encryption
  and restrictive filesystem permissions for real cases. Agent state directories
  contain a bearer token and buffered logs; protect them accordingly.
- The application does not delete evidence files. A database failure after
  preservation can leave a valid orphaned file; the error reports its relative
  path so it can be reconciled.
- The free-text search uses `ILIKE`; it is suitable for small cases, not large
  full-text search workloads.
- Auto-detection samples the first 100 non-blank lines and can misclassify very
  unusual mixed files. Explicit `source_type` is available.
- Issue retention is capped; suppressed issues are counted but not stored.
- Agent collection is Linux-oriented and has no auto-update, remote shell, or
  response capability. It reads only configured regular files.
- Agent enrollment does not add investigator authentication; a compromised agent
  token can submit batches to its assigned investigation.
- Disable an agent to block it. Deleting its registration removes history, but a
  running agent that still has the enrollment token can enroll again.
- PDF/CSV export exists, but interactive timezone resolution, actor
  correlation, and automatic clock-skew correction do not. Measured offsets are
  advisory only.
- Coverage depends on agent reporting cadence. Inferred gaps and zero-byte cycles
  are quality signals, not proof of host inactivity or collection failure.
- Duplicate fingerprints may link distinct legitimate identical log lines; review
  canonical choices before relying on unique-event counts.
- Manifest hashes demonstrate stored-byte consistency and canonical metadata, not
  chain of custody, signatures, or pre-collection authenticity.
- Verified locally on Windows with PostgreSQL and loopback agent tests. No
  production deployment, Linux end-to-end soak test, backup/restore drill, or
  load test has been performed.

## Phase 4.2 correlation rules

Rules are transparent and configurable through the `time_window_seconds` API parameter (default 1800 seconds):

- `auth_web_shared_identifier`: an authentication event and a web-access event from different sources share a source IP or username.
- `cross_source_shared_identifier`: events from different sources share a source IP or username.
- `cross_source_shared_hostname`: events from different sources share a hostname (reported as low confidence).

Matching behavior:

- Events must come from different evidence sources.
- Shared IP, username, or hostname values are compared case-insensitively.
- If both events have normalized UTC timestamps, their absolute difference must be within the configured window.
- If either timestamp is missing, only strong identifiers (IP or username) can create a correlation, and the timestamp is not used as ordering evidence.
- Hostname-only matches are reported as low confidence to reduce coincidental matches.
- Duplicate events are retained and may appear in correlations; duplicates are never deleted.

Confidence categories:

- `high`: strong shared identifier across different source types, both timestamps normalized, events within 5 minutes.
- `medium`: strong shared identifier with normalized timestamps within the configured window.
- `low`: shared identifier with missing/uncertain timestamps or hostname-only matching; treated as a possible correlation.

Timestamp uncertainty is included in every correlation. Missing or uncertain timestamps are never used as precise ordering evidence.
## Phase 4.3 report generation

Generate a PDF investigation report:

```bash
curl -OJ "http://localhost:8000/api/investigations/{investigation_id}/report.pdf"
```

Export CSV datasets:

```bash
curl -OJ "http://localhost:8000/api/investigations/{investigation_id}/export/timeline.csv"
curl -OJ "http://localhost:8000/api/investigations/{investigation_id}/export/evidence.csv"
curl -OJ "http://localhost:8000/api/investigations/{investigation_id}/export/coverage.csv"
curl -OJ "http://localhost:8000/api/investigations/{investigation_id}/export/gaps.csv"
curl -OJ "http://localhost:8000/api/investigations/{investigation_id}/export/parsing.csv"
curl -OJ "http://localhost:8000/api/investigations/{investigation_id}/export/correlations.csv"
```

Reports are generated from stored investigation data. Original evidence files remain separate under storage. Reports include evidence hashes, collection gaps, parsing failures, timestamp uncertainty, integrity status, and correlation explanations.

## Documentation

See the `docs/` directory for installation, architecture, database, API, agent deployment, user guide, investigation workflow, synthetic scenarios, testing and evaluation, limitations, security, troubleshooting, and demo instructions.

## Verified state

Final automated checks performed on this exact repository state, on a Windows
workstation with PostgreSQL 18.6 and Python 3.13.15:

- Backend test suite: 81 passed.
- Agent test suite: 10 passed.
- Live synthetic end-to-end check: 31/31 passed
  (`scripts/e2e_synthetic_check.py` against a running server).
- `ruff check`: clean for `backend/app`, `backend/tests`,
  `agent/cybertrace_agent`, and `agent/tests`.
- JavaScript syntax checks: `app.js`, `dashboard.js`, `agents.js`, and
  `quality.js` pass `node --check`.
- Alembic head: `f42a00000001` (applied and current on the development
  database).

## Team

| S. No. | Team Member | Contribution |
| --- | --- | --- |
| 1 | Kishore Parasuraman | Technical development, Python-based processing, log analysis, timestamp normalization, and evidence integrity verification. |
| 2 | Jabez Gabrilraj | Contributing to the development of CyberTrace. |

Both team members aim to build a practical and reliable solution for digital
forensic investigations.

## References

1. **NIST SP 800-86:** Guide to Integrating Forensic Techniques into Incident
   Response — <https://csrc.nist.gov/pubs/sp/800/86/final>
2. **OWASP Logging Cheat Sheet** —
   <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
3. **Wazuh Documentation** — <https://documentation.wazuh.com/>
4. **Velociraptor Documentation** — <https://docs.velociraptor.app/>
5. **Timesketch** — <https://timesketch.org/>
6. **Plaso (log2timeline) Documentation** — <https://plaso.readthedocs.io/>

---

**AIORI-3 Hackathon | Team Ignite | PS-013 | CyberTrace**

*From Scattered Logs to an Evidence-Backed Incident Timeline.*
