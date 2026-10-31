# Architecture

CyberTrace is a FastAPI application with a PostgreSQL database, SQLAlchemy ORM, Alembic migrations, and a browser dashboard served from static files.

## Main components

- `backend/app/main.py`: application factory and route registration.
- `backend/app/routers/`: HTTP endpoints.
- `backend/app/services/`: ingestion, parsing, correlation, coverage, reporting, and storage logic.
- `backend/app/models.py`: ORM models.
- `backend/app/static/`: dashboard HTML, CSS, and JavaScript.
- `agent/`: optional Linux log collection agent.
- `samples/`: synthetic incident datasets.

## Data flow

1. Evidence is uploaded or collected by an agent.
2. Original bytes are hashed and preserved.
3. Parsers create normalized events and parsing issues.
4. Ordering, deduplication, and correlation records are generated.
5. The dashboard and reports read stored data.

## Design principles

- Original evidence is immutable.
- Derived data can be regenerated.
- Timestamp uncertainty is explicit.
- Correlations are inferred, not proof of an attack.
- Reports are generated on demand.
