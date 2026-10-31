# Database

CyberTrace uses PostgreSQL with SQLAlchemy and Alembic.

## Core tables

- `investigations`
- `evidence_sources`
- `evidence_files`
- `parsed_events`
- `parsing_results`
- `parsing_issues`
- `event_correlations`
- `event_correlation_members`
- `reconciliation_runs`
- `agents`, `agent_sources`, `agent_batches`, `agent_batch_items`
- `source_collection_windows`, `collection_gaps`
- `evidence_audit_events`

## Key relationships

- An investigation has many sources, evidence files, events, correlations, and audit events.
- Evidence files have parsing results, events, hashes, and verifications.
- Events link to evidence files and sources.
- Correlations link to multiple events.

## Migrations

Run:

```powershell
cd backend
python -m alembic upgrade head
```

## Test database

The test database name must end with `_test`. Tests truncate and recreate data for each test.
