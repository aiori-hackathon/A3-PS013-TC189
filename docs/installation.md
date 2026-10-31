# Installation and Setup

## Requirements

- Python 3.11 or newer.
- PostgreSQL 14 or newer.
- Node.js is optional and only used for JavaScript syntax checks.

## Backend setup

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Create the application and test databases:

```sql
CREATE USER cybertrace_app WITH PASSWORD 'change_me';
CREATE DATABASE cybertrace OWNER cybertrace_app;
CREATE DATABASE cybertrace_test OWNER cybertrace_app;
```

Configure environment variables in `.env`:

```text
DATABASE_URL=postgresql+psycopg://cybertrace_app:change_me@localhost:5432/cybertrace
TEST_DATABASE_URL=postgresql+psycopg://cybertrace_app:change_me@localhost:5432/cybertrace_test
STORAGE_ROOT=backend/storage
```

Run migrations:

```powershell
cd backend
python -m alembic upgrade head
```

Start the API and dashboard:

```powershell
cd backend
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open:

- Dashboard: `http://127.0.0.1:8000/`
- Evidence workspace: `http://127.0.0.1:8000/workspace`
- API docs: `http://127.0.0.1:8000/docs`

## Agent setup

See [Agent Deployment](agent-deployment.md).

## Tests

```powershell
cd backend
python -m pytest -q
python -m ruff check app tests
node --check app/static/dashboard.js
```

Agent tests:

```powershell
cd agent
python -m pytest -q
```
