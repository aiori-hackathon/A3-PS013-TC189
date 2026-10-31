# Troubleshooting

## Database connection errors

Verify PostgreSQL is running and `DATABASE_URL`/`TEST_DATABASE_URL` are correct. The test database name must end with `_test`.

## Missing test database

Create the database and role documented in `docs/installation.md`.

## Storage errors

Ensure `STORAGE_ROOT` is writable.

## Agent not reporting

Check enrollment token, agent token, network connectivity, and source paths.

## Report generation failures

Check that the investigation exists and the database is reachable. Review server logs.
