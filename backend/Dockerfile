# CyberTrace backend (FastAPI API + built-in dashboards).
#
# Build context is the backend/ directory (see docker-compose.yml):
#   docker compose build
# or manually:
#   docker build -t cybertrace-api:local backend/
#
# Runtime configuration comes from environment variables only; Settings reads
# it through pydantic-settings (see backend/app/config.py). The container
# entrypoint waits for PostgreSQL, applies Alembic migrations, and starts
# uvicorn in production mode (no --reload).

# Pinned to the Python version the project was verified with (3.13.15).
FROM python:3.13.15-slim

LABEL org.opencontainers.image.title="CyberTrace API" \
      org.opencontainers.image.description="Digital forensics timeline analyzer backend" \
      org.opencontainers.image.source="https://github.com/aiori-hackathon/A3-PS013-TC189"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Unprivileged runtime user (uid/gid 10001). Evidence storage under /data
# is owned by this user.
RUN groupadd --system --gid 10001 cybertrace && \
    useradd --system --uid 10001 --gid cybertrace --home /opt/cybertrace \
            --shell /usr/sbin/nologin cybertrace

WORKDIR /opt/cybertrace/backend

# Install pinned dependencies first so this layer is cached independently.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application code and Alembic migrations. backend/app/static (the
# dependency-free dashboards) is part of app/ and is served by FastAPI.
COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app
COPY docker-entrypoint.sh /usr/local/bin/cybertrace-entrypoint

RUN chmod 0755 /usr/local/bin/cybertrace-entrypoint && \
    mkdir -p /data/storage && \
    chown -R cybertrace:cybertrace /data /opt/cybertrace

USER cybertrace

EXPOSE 8000

ENTRYPOINT ["cybertrace-entrypoint"]
