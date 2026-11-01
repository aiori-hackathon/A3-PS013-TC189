# CyberTrace — Docker Setup and Verification Report

**Scope:** containerization and deployment readiness for the existing CyberTrace
Digital Forensics Timeline Analyzer (PS-013, Team Ignite, `A3-PS013-TC189`).

**Application code: unchanged.** No features, models, migrations, parsers, or
endpoints were modified. This work adds Docker deployment files and
documentation only.

- Date: 2026-11-01
- Branch: `main` (with the Docker work committed on top)
- Verification host: Windows 11 workstation (PowerShell 5.1), PostgreSQL 18.6
  local server, Python 3.13.15 venv
- **Docker Engine was not installed** on the verification host
  (`docker`/`podman` not on PATH, no Docker Desktop), so all Docker-runtime
  checks listed in §10 could not be executed. Everything else listed in §5
  was actually executed and passed.

## 1. Files created or modified

| File | Status | Purpose |
| --- | --- | --- |
| `docker-compose.yml` | new | Compose stack: `db` (PostgreSQL 18.6) + `api` (backend + dashboards) |
| `backend/Dockerfile` | new | Production backend image (Python 3.13.15-slim, non-root user) |
| `backend/docker-entrypoint.sh` | new | Container entrypoint: wait for DB → `alembic upgrade head` → uvicorn (no reload) |
| `backend/.dockerignore` | new | Keeps the `./backend` build context clean (caches, tests, `storage/`, venvs) |
| `.dockerignore` | new | Root hygiene for any root-context builds (`.git`, `.env`, venvs, storage, agent) |
| `.env.example` | modified | Added Docker Compose variables: `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_HOST`, `POSTGRES_PORT`, `APP_PORT` (placeholders only) |
| `.gitattributes` | modified | Added `*.sh text eol=lf` so the entrypoint keeps LF endings |
| `README.md` | modified | New "Running with Docker" section, requirements note, project-listing update |
| `reports/DOCKER_SETUP_AND_VERIFICATION.md` | new | This report |

Deliberately **not** created, to avoid redundancy:

- A **frontend Dockerfile/nginx service**. The frontend is
  dependency-free static HTML/CSS/JS under `backend/app/static/`, served by
  FastAPI itself (`/`, `/dashboard`, `/workspace`, `/agents`, `/quality`),
  and all dashboard JavaScript uses a same-origin relative API base
  (`const API = "/api"`, e.g. `backend/app/static/dashboard.js:3`). There is
  no Node build, lockfile, or package manager, so the "frontend container"
  requirement is already satisfied by the backend image. A separate nginx
  container would duplicate serving and add a rewrite layer for no benefit.
- An **endpoint-agent container service**. The agent (`agent/`) is a Linux
  endpoint daemon that reads real log files (e.g. `/var/log/auth.log`) on the
  machine being monitored and uploads to the server. In a container it would
  collect the container's own logs, not endpoint logs, and collecting real
  host logs would require bind-mounting `/var/log` read-only — that is a
  host-level permission grant with real security implications
  (see `agent/systemd/cybertrace-agent.service` for the intended hardened
  install). It therefore stays out of Compose; the documented install path is
  systemd on a Linux endpoint, exactly as before. If someone deliberately
  containerizes it for a lab, it needs at minimum
  `-v /var/log:/var/log:ro` (or a bind of specific log files) and a
  `--server-url`/config pointing at the `api` service; no privileged mode is
  required and none is granted by this setup.

## 2. Architecture and service overview

```text
                                    docker compose (project name: cybertrace)
Browser (host) ── :8000 ──────────> api  [image: cybertrace-api:local]
                                    build: ./backend → python:3.13.15-slim
                                    runs:  docker-entrypoint.sh
                                             1. wait for DB (SQLAlchemy ping)
                                             2. alembic -c alembic.ini upgrade head
                                             3. exec uvicorn app.main:app --host 0.0.0.0 --port 8000
                                    env:   DATABASE_URL (assembled from POSTGRES_*), STORAGE_ROOT=/data/storage
                                    healthcheck: GET /api/health == 200
                                    restart: unless-stopped
                                        │ depends_on: db (condition: service_healthy)
                                        │ portmaps only 8000; 5432 stays internal
                                        v
                                   db  [image: postgres:18.6-alpine]
                                        env: POSTGRES_USER/POSTGRES_PASSWORD/POSTGRES_DB (from .env),
                                             PGDATA=/var/lib/postgresql/data, PGTZ=UTC
                                        volume: db_data:/var/lib/postgresql/data (named volume)
                                        healthcheck: pg_isready …
                                        restart: unless-stopped
                                   named volume: evidence_data:/data/storage (API: preserved evidence bytes)
```

- Compose project name: `cybertrace` → containers `cybertrace-db-1`,
  `cybertrace-api-1`; volumes `cybertrace_db_data`, `cybertrace_evidence_data`.
- Service-name DNS is used everywhere internally: `db` (Postgres host for the
  API), `api` (for future agents on a Compose network).
- The`api` service name was chosen instead of `backend` because the built-in
  dashboards and docs call the UI surface "backend + frontend"; Compose
  exposes one host port named by `APP_PORT`.

Images and pins (both tags verified to exist on Docker Hub on 2026-11-01):

- `python:3.13.15-slim` (digest `sha256:7c61056e61ac…` published 2026-09-25) —
  matches the Python version the project was verified with (3.13.15).
- `postgres:18.6-alpine` (digest `sha256:10a5c69a8303…` published 2026-10-26) —
  matches the PostgreSQL version verified locally (18.6; README requires
  PostgreSQL 15+). `PGDATA` is pinned explicitly to `/var/lib/postgresql/data`
  so the named volume location is unambiguous across image variants.

## 3. Environment variables

`docker compose` reads `.env` in the repository root (created from
`.env.example`). The `api` container additionally receives values with sane
defaults, so only the password is effectively mandatory.

| Variable | Required | Used by | Purpose / default |
| --- | --- | --- | --- |
| `POSTGRES_DB` | no (default `cybertrace`) | db + api | Database name created on first boot |
| `POSTGRES_USER` | no (default `cybertrace_app`) | db + api | Least-privilege role name |
| `POSTGRES_PASSWORD` | **yes (no default)** | db + api | Password; Compose fails fast (`:?` interpolation) if unset. Must be URL-safe (letters, digits, `_`, `-`) because it is embedded in the assembled `DATABASE_URL` |
| `POSTGRES_HOST` | no | documentation only | Compose service name (`db`); kept in `.env.example` for clarity |
| `POSTGRES_PORT` | no (default `5432`) | api | Internal container-network port; keep 5432 |
| `APP_PORT` | no (default `8000`) | api (host port map) | Host port for dashboard/API access |
| `LOG_LEVEL` | no (`INFO`) | api | Python log level |
| `ENVIRONMENT` | no (`production`) | api | Only passed through (app metadata) |
| `API_PREFIX` | no (`/api`) | api | API route prefix |
| `CORS_ORIGINS` | no (empty) | api | Only needed for cross-origin browser clients |
| `MAX_UPLOAD_SIZE_BYTES`, `ALLOWED_EXTENSIONS`, `AGENT_*`, `QUALITY_DEFAULT_WINDOW_HOURS` | no | api | Passed through with existing defaults |
| `AGENT_ENROLLMENT_TOKEN` | no (empty = registration disabled) | api | Shared agent enrollment secret (≥24 chars when set) |

Assembled inside Compose (not manually edited):

- `DATABASE_URL: postgresql+psycopg://$POSTGRES_USER:$POSTGRES_PASSWORD@db:$POSTGRES_PORT/$POSTGRES_DB`
  (computed by Compose interpolation; the localhost URL from `.env` used for
  non-Docker development is overridden inside Compose).
- `STORAGE_ROOT=/data/storage` (evidence bytes go to the named volume
  `evidence_data`).
- `TEST_DATABASE_URL` is intentionally not set in the container (tests are not
  shipped in the runtime image).

Secrets handling: `.env` is gitignored (`!​.env.example` whitelisted, verified);
no real credentials exist in any file added by this work; the Compose file
requires an explicitly set password and contains no default password.

## 4. Build and startup commands

```powershell
git clone https://github.com/aiori-hackathon/A3-PS013-TC189.git
cd A3-PS013-TC189
Copy-Item .env.example .env          # then edit POSTGRES_PASSWORD inside

docker compose build                 # build the api image
docker compose up -d                 # start db + api; entrypoint migrates then serves
docker compose ps                    # wait for both to report (healthy)
docker compose logs -f api           # watch migration + startup output
```

Runtime commands:

```powershell
docker compose stop                  # stop containers (volumes preserved)
docker compose start                 # resume
docker compose restart api           # restart one service
docker compose down                  # remove containers (volumes preserved)
docker compose down -v               # ⚠ remove containers AND database/evidence data
```

Manual one-off migration (normally unnecessary — the entrypoint does it):

```powershell
docker compose exec api alembic -c alembic.ini upgrade head
```

Read the migration state:

```powershell
docker compose exec api alembic -c alembic.ini current   # expect f42a00000001 (head)
```

## 5. Test commands and actual results

All commands in this section were executed on the verification host.

### 5.1 Static configuration checks (executed)

| Check | Result |
| --- | --- |
| `docker-compose.yml` parses as valid YAML (PyYAML `safe_load`) | PASS — services `['api','db']`, volumes `['db_data','evidence_data']` |
| Compose env references ↔ `.env.example` cross-reference (scripted) | PASS — every `${VAR}` referenced by Compose is defined in `.env.example`; `POSTGRES_PASSWORD` has no fallback default (required at startup) |
| `POSTGRES_PASSWORD` uses required interpolation in both `db` and `api` services (`:?`) | PASS — verified by inspecting lines 16 and 44 of `docker-compose.yml` |
| `sh -n backend/docker-entrypoint.sh` (POSIX syntax check via Git-Bash sh) | PASS — syntax OK; file contains no BOM and zero CR bytes (0 CRLF) |
| Docker Hub tag existence API check | PASS — `postgres:18.6-alpine` and `python:3.13.15-slim` both resolve (dates listed in §2) |

### 5.2 Fresh-database migration test — the Compose init path (executed)

Simulated exactly what the container entrypoint does on first boot (fresh DB +
`DATABASE_URL` via environment), without touching the existing local
development database `cybertrace`:

```text
CREATE DATABASE cybertrace_docker_check OWNER cybertrace_app;   (psql, admin)
set DATABASE_URL=postgresql+psycopg://…@localhost:5432/cybertrace_docker_check
alembic -c alembic.ini upgrade head        (from backend/, exit 0)
alembic -c alembic.ini current             → f42a00000001 (head)
```

Output (abbreviated):

```text
Running upgrade -> 9b97903dc807, initial phase 1 schema
Running upgrade 9b97903dc807 -> 18a9ef7686d1, phase 2 agent collection
Running upgrade 18a9ef7686d1 -> ed8244c03365, phase 3 evidence quality
Running upgrade ed8244c03365 -> f42a00000001, phase 4.2 event correlation
f42a00000001 (head)
```

Confirmed migration chain is linear with a single head:
`9b97903dc807 → 18a9ef7686d1 → ed8244c03365 → f42a00000001`.
No `alembic stamp` was used anywhere.

### 5.3 Application boot + readiness on the fresh schema (executed)

Started uvicorn on the fresh database with an isolated storage root:

```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8931   (no reload)
GET http://127.0.0.1:8931/api/health
```

Result:

```json
{"status":"ok","database":"ok","schema_status":"ok","storage":"ok","version":"0.4.3"}
```

This is the same signal the Compose `api` healthcheck relies on.

### 5.4 Synthetic end-to-end workflow (executed, 31/31 PASS)

`python scripts\e2e_synthetic_check.py` (project's own E2E script, default
port 8931) against the fresh, migrated database:

```text
31/31 checks passed, exit code 0:
health 200 + version 0.4.3; dashboards / /agents /quality /workspace all 200;
investigation creation 201; 6 evidence uploads 201 (scenarios 1–3);
summary events = 24 (12+9+3); timeline search OK; scenario 3 timezone hint
normalized (2026-10-31T18:10:01Z visible); correlation run + list 200;
quality overview 200; report.pdf 200 starting with %PDF (valid, size > 1 KB);
CSV exports timeline/evidence/coverage/gaps/parsing/correlations all non-empty.
```

This covers the synthetic investigation workflow, PDF export, and CSV exports
required by the verification task.

### 5.5 Restart persistence (executed)

Killed the server, restarted it against the same fresh database and storage
path (equivalent to `docker compose restart` with named volumes):

```text
GET /api/investigations → the E2E investigation is still present:
  "id":"93ead090-7156-429d-b436-964c6a995f6f",
  "source_count":6, "evidence_count":6, "event_count":24
GET /report.pdf → 200, starts with %PDF, 43,787 bytes (regenerated from
  preserved evidence bytes)
```

PASS — database rows and preserved evidence both survive a full process
restart against the same data location.

### 5.6 Existing project test suites (executed)

From `backend/`: `python -m pytest -q` → **81 passed** (1 unrelated
Starlette/httpx deprecation warning), exit 0.
From `agent/`: `python -m pytest -q` → **10 passed**, exit 0.
(These run against the dedicated `cybertrace_test` database per project test
policy; the verification database from §5.2 was already dropped.)

### 5.7 Lint and compile checks (executed)

- `ruff check app tests` (backend) — All checks passed
- `ruff check cybertrace_agent tests` (agent) — All checks passed
- `node --check` on `app/static/app.js`, `dashboard.js`, `agents.js`,
  `quality.js` — all pass
- `python -m compileall -q app tests` — clean

### 5.8 Cleanup of verification artifacts (executed)

Verification database `cybertrace_docker_check` dropped via
`DROP DATABASE IF EXISTS`; temporary evidence/storage directory
`%TEMP%\ct_docker_storage` deleted; background uvicorn process stopped. The
developer's existing local database `cybertrace` and `backend/storage` were
never read, reset, or imported anywhere.

## 6. Ports and service URLs

| Purpose | URL / port |
| --- | --- |
| Investigation dashboard (unified timeline) | `http://localhost:8000/` (also `/dashboard`) |
| Evidence workspace | `http://localhost:8000/workspace` |
| Agent fleet dashboard | `http://localhost:8000/agents` |
| Quality dashboard | `http://localhost:8000/quality` |
| OpenAPI docs | `http://localhost:8000/docs` (Swagger), `/redoc`, `/openapi.json` |
| Health | `http://localhost:8000/api/health` |
| Host port map | `${APP_PORT:-8000} → 8000` inside the api container |
| PostgreSQL | **not published** — reachable only on the Compose network as `db:5432`; for maintenance use `docker compose exec db psql …` |

Change `APP_PORT` in `.env` if port 8000 is already in use on the host.

## 7. Migration behavior

- The `api` entrypoint runs `alembic -c alembic.ini upgrade head` after the
  database is reachable and before uvicorn starts. Startup ordering is double
  protection: Compose `depends_on: db (service_healthy)` via `pg_isready`, and
  the entrypoint's own 60-second SQLAlchemy wait loop.
- First boot on an empty volume creates the full schema (verified in §5.2:
  4 revisions applied on a real fresh PostgreSQL). Subsequent boots make
  `upgrade head` a no-op.
- Migrations run before the healthcheck can pass, so `docker compose ps`
  reports `healthy` only when the API, the schema, and storage are all ready
  (`GET /api/health` returns 200 only in that case — it returns 503 with
  `schema_status: missing` otherwise).
- `alembic stamp` is not used and not needed for a fresh deployment. Existing
  local databases (non-Docker) are never imported, mounted, or reset by this
  setup.
- Version expectations: `docker compose exec api alembic -c alembic.ini current`
  must print `f42a00000001 (head)`.

## 8. Database persistence, backup, restore

Data lives in two named volumes (`docker volume`), not in the image and not on
host bind mounts:

- `cybertrace_db_data` → `/var/lib/postgresql/data` (all investigation data)
- `cybertrace_evidence_data` → `/data/storage` (original evidence bytes,
  SHA-256 preserved) — populated from the image path so ownership is correct
  for the unprivileged runtime user

`docker compose down` preserves both. `docker compose down -v` destroys both
(destructive — documented warning in README).

Backup (SQL dump, works from PowerShell or bash):

```powershell
docker compose exec db sh -lc 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"' > cybertrace_db_backup.sql
```

Custom-format alternative (compressed, selective restore):

```powershell
docker compose exec db sh -lc 'pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' > cybertrace_db_backup.dump
```

Restore into a schema-empty database (e.g. fresh volume after `down -v`,
run `docker compose up -d db healthcheck-passes` first):

```powershell
# SQL dump:
docker compose exec -T db sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < cybertrace_db_backup.sql
# Custom-format (-Fc) dump restores over stdin the same way:
docker compose exec -T db sh -lc 'pg_restore -U "$POSTGRES_USER" --clean --if-exists -d "$POSTGRES_DB"' < cybertrace_db_backup.dump
```

Raw-evidence volume backup (tar the named volume; stop the api first so no
new evidence lands mid-copy):

```powershell
docker compose stop api
docker run --rm -v cybertrace_evidence_data:/data:ro -v "${PWD}:/backup" alpine sh -c "tar cf /backup/cybertrace_evidence_backup.tar -C /data/storage ."
docker compose start api                   # resume service
```

## 9. Security considerations

1. **Non-root runtime.** The api image runs as user `cybertrace`
   (uid/gid 10001) with `nologin`; only `/data` and `/opt/cybertrace` are
   owned by it. No container runs privileged; no host Docker socket mounted;
   no host bind mounts of sensitive directories in the default stack.
2. **PostgreSQL is not published.** Only port 8000 (configurable) reaches a
   container. The database has no host exposure; `pg_isready` checks run
   inside the `db` container.
3. **Credentials.** Password comes only from `.env` (gitignored), required by
   Compose interpolation with no fallback value and no password baked into
   any file or image. Documented constraint: URL-safe characters so the
   assembled SQLAlchemy URL cannot be silently mis-parsed. Agent enrollment
   token defaults to unset (registration disabled). Long-lived agent API
   tokens remain server-generated and hashed, unchanged from the application
   design.
4. **Least surface.** The image contains only `requirements`-installed deps,
   `app/`, `alembic/`, `alembic.ini`, and the entrypoint — no tests, dev
   tools, caches (`PIP_NO_CACHE_DIR`, `--no-cache-dir`, no bytecode
   `PYTHONDONTWRITEBYTECODE`), and never the local `backend/storage`
   evidence, `tests/`, or pytest caches (`.dockerignore`).
5. **Application auth stance unchanged:** the dashboards and investigator
   APIs remain unauthenticated by design; Compose exposes them on a
   configurable host port for local/trusted-network demonstration. Nothing in
   this setup makes the deployment more public than the documented local
   setup. Keep it off untrusted networks (existing README security notes
   continue to apply).
6. **Evidence hygiene.** Real evidence is not mounted from the host by
   default; uploads go to a container volume (`evidence_data`). This keeps
   real-case files off the image and out of accidental host bind exposure,
   while remaining a forensic-preservation tradeoff the investigator must
   own (a volume is not an OS-level chain-of-custody filesystem).
7. **Agent privileges.** The agent is deliberately not in Compose.
   Containerizing it while reading real host logs would require
   `:/var/log:...` read-only bind mounts (documented in §1); no privileged
   mode is granted by files in this repository.

## 10. Known limitations and checks that could not be performed

**Constraint:** Docker Engine/Desktop is not installed on the verification
host (confirmed: `docker`, `docker compose`, `docker info`, and
`docker-compose`/`podman` all unavailable; only WSL bootstrapping present).
Per the task rules, no Docker runtime result is claimed from static checks.
Everything below is *expected but unverified here*:

| Unexecuted check | What would validate it |
| --- | --- |
| `docker compose config` validation through the real Compose binary | `docker compose config --quiet && docker compose config` |
| api image build (dependency resolution, layer caching) | `docker compose build` |
| db/api container startup, entrypoint execution, `pg_isready` + `/api/health` healthchecks | `docker compose up -d` then `docker compose ps` |
| `restart: unless-stopped` and `restart` persistence under real engine restarts | `docker compose restart`, engine restart test |
| Named-volume persistence across `down`/`up` with real Docker volumes | `docker compose down && docker compose up -d` → data still present |
| pg_dump backup/restore in-container | commands in §8 |
| Browser access from host via published port | open `http://localhost:8000/` |
| Compose host-name resolution `db` between containers | covered implicitly by startup; confirm via `docker compose exec api python -c "…connect…" ` or service logs |
| Image size / permission sanity under real pull | `docker images`, `docker run --user` test |

Mitigating verification actually performed (§5): migration on a genuine
PostgreSQL 18.6 fresh database, full E2E synthetic workflow (31 checks incl.
PDF/CSV), restart persistence, and both test suites all passed locally with
the exact commands and env-variable contract the containers use.

Other known limitations:

- `POSTGRES_PASSWORD` with URL-hostile characters (`@`, `:`, `/`, `%`) would
  mis-parse the assembled `DATABASE_URL`; documented, and error surfaces
  early in `docker compose config`/logs.
- The `postgres:18.6-alpine` and `python:3.13.15-slim` pins are verified to
  exist as of 2026-11-01 (digests listed in §2); rebuilds after upstream image
  changes may require updating these pins. Using the alias `postgres:18` /
  `python:3.13-slim` is an alternative but pins less.
- Compose `name: cybertrace` top-level key requires Compose v2 (Compose
  Specification-compatible CLI, Docker Desktop 4.22+ / docker-compose 2.20+).
- Windows anti-virus/Defender may slow first image builds; WSL2 backend is
  required for Docker Desktop on this class of hardware (confirmed present on
  the verification host).

## 11. Checklist against the task requirements

- [x] Root `docker-compose.yml`, `.dockerignore`, `.env.example`
- [x] Backend Dockerfile + non-root user + production startup (no reload)
- [x] Health checks (db `pg_isready`, api `/api/health` 200-only) + `depends_on: service_healthy`
- [x] PostgreSQL named volume persistence; no host port for Postgres
- [x] Alembic migrations run automatically and safely; stamp not used; fresh init verified on real PostgreSQL
- [x] Frontend: requirement inherently satisfied by backend-served static SPA (documented, not duplicated)
- [x] Endpoint agent: documented decision to keep it out of Compose with security rationale
- [x] `.env` gitignored; placeholders only committed; no real secrets
- [x] Restart policies for local demonstration; only necessary ports exposed
- [x] No privileged containers, no sensitive bind mounts, no local data imported
- [x] README Docker workflow (setup, migrations, access, stop/logs/restart, backup/restore, rebuild, troubleshooting)
- [x] This verification report with actually-executed results and explicit unverified list
