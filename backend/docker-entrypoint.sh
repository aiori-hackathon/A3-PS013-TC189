#!/bin/sh
# CyberTrace container entrypoint.
#
# 1. Wait until PostgreSQL accepts connections (Compose already gates on the
#    db health check; this loop tolerates longer recovery).
# 2. Apply Alembic migrations with "alembic upgrade head". This is idempotent:
#    on a fresh database it builds the full schema; on an already-migrated
#    database it is a no-op.
# 3. Start uvicorn on 0.0.0.0:8000 in production mode (no --reload).
set -eu

if [ -z "${DATABASE_URL:-}" ]; then
    echo "FATAL: DATABASE_URL is not set for this container." >&2
    exit 1
fi

echo "[cybertrace] Waiting for PostgreSQL to accept connections ..."
python - <<'PYCODE'
import os
import sys
import time

from sqlalchemy import create_engine, text

url = os.environ["DATABASE_URL"]
deadline = time.monotonic() + 60.0
last_error = None
while True:
    try:
        engine = create_engine(url, connect_args={"options": "-c timezone=UTC"})
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001
        last_error = exc
        if time.monotonic() >= deadline:
            print(f"FATAL: database not reachable within 60s: {last_error}", file=sys.stderr)
            sys.exit(1)
        time.sleep(2)
PYCODE

echo "[cybertrace] Applying Alembic migrations (upgrade head) ..."
alembic -c alembic.ini upgrade head

echo "[cybertrace] Starting CyberTrace API on 0.0.0.0:8000 ..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
