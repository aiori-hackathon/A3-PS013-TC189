# Testing and Evaluation

## Automated tests

Backend:

```powershell
cd backend
python -m pytest -q
python -m ruff check app tests
```

Agent:

```powershell
cd agent
python -m pytest -q
```

Frontend syntax:

```powershell
node --check backend/app/static/app.js
node --check backend/app/static/dashboard.js
node --check backend/app/static/agents.js
node --check backend/app/static/quality.js
```

## Latest measured results

- Backend: 81 passed, 1 warning.
- Agent: 10 passed.
- Lint: passed.
- JavaScript syntax: passed.
- End-to-end synthetic walkthrough (`scripts/e2e_synthetic_check.py`): all checks passed.

## Evaluation datasets

- Scenario 1: 12 generated events, 12 recovered.
- Scenario 2: 9 generated events, 9 recovered.
- Scenario 3: 3 generated events, 3 recovered with explicit timezone and year.
- Evidence tampering: hash mismatch detected.
- Report generation: PDF and CSV endpoints return valid files.

## Methodology

Tests use synthetic logs and the PostgreSQL test database. Metrics are recorded from actual command output. No benchmark claims are made.
