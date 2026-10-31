from __future__ import annotations

import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent
AGENT_ROOT = PROJECT_ROOT / "agent"
for entry in (AGENT_ROOT, BACKEND_ROOT):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

os.environ.setdefault(
    "AGENT_ENROLLMENT_TOKEN", "test-enrollment-token-0123456789abcdef"
)

from app.config import Settings

BOOTSTRAP_SETTINGS = Settings()
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL") or BOOTSTRAP_SETTINGS.test_database_url
if not TEST_DATABASE_URL:
    pytest.exit(
        "TEST_DATABASE_URL is not configured. Copy .env.example to .env and set a "
        "dedicated PostgreSQL test database.",
        returncode=2,
    )

_database_name = make_url(TEST_DATABASE_URL).database or ""
if not _database_name.endswith("_test"):
    pytest.exit(
        f"Refusing to run destructive tests against database {_database_name!r}; "
        "the test database name must end with '_test'.",
        returncode=2,
    )

_SESSION_TMP = Path(tempfile.mkdtemp(prefix="cybertrace-tests-"))
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ["TEST_DATABASE_URL"] = TEST_DATABASE_URL
os.environ["STORAGE_ROOT"] = str(_SESSION_TMP / "storage")
os.environ["MAX_UPLOAD_SIZE_BYTES"] = str(5 * 1024 * 1024)
os.environ.setdefault("LOG_LEVEL", "WARNING")

from app import models  # noqa: E402,F401
from app.config import get_settings  # noqa: E402
from app.database import Base, get_db  # noqa: E402

get_settings.cache_clear()
SETTINGS = get_settings()
FIXTURES = Path(__file__).resolve().parent / "fixtures"

test_engine = create_engine(
    TEST_DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"options": "-c timezone=UTC"},
)
TestingSessionLocal = sessionmaker(bind=test_engine, autoflush=False, expire_on_commit=False)

try:
    with test_engine.connect() as connection:
        connection.execute(text("SELECT 1"))
except OperationalError as exc:
    pytest.exit(
        f"Cannot connect to test database {_database_name!r}: {exc}. "
        "Create the database and role as documented in README.md.",
        returncode=2,
    )

with test_engine.begin() as connection:
    Base.metadata.drop_all(connection)
    Base.metadata.create_all(connection)


def _force_remove(function, path, exc_info) -> None:
    try:
        os.chmod(path, 0o666)
        function(path)
    except OSError:
        pass


def _remove_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, onerror=_force_remove)


def _truncate_all() -> None:
    table_names = ", ".join(f'"{table.name}"' for table in reversed(Base.metadata.sorted_tables))
    with test_engine.begin() as connection:
        connection.execute(text(f"TRUNCATE TABLE {table_names} RESTART IDENTITY CASCADE"))


def _clear_storage() -> None:
    _remove_tree(SETTINGS.evidence_root)
    _remove_tree(SETTINGS.temp_root)
    SETTINGS.evidence_root.mkdir(parents=True, exist_ok=True)
    SETTINGS.temp_root.mkdir(parents=True, exist_ok=True)


@pytest.fixture(scope="session", autouse=True)
def cleanup_session_storage() -> Iterator[None]:
    yield
    _remove_tree(_SESSION_TMP)


@pytest.fixture(autouse=True)
def clean_database() -> Iterator[None]:
    _truncate_all()
    _clear_storage()
    yield
    _clear_storage()


def _override_db() -> Iterator[Session]:
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(clean_database) -> Iterator[TestClient]:
    from app.main import app

    app.dependency_overrides.clear()
    app.dependency_overrides[get_db] = _override_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def db_session(clean_database) -> Iterator[Session]:
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def make_investigation(client: TestClient):
    def factory(name: str = "Test investigation", description: str | None = "Synthetic test case"):
        response = client.post(
            "/api/investigations",
            json={"name": name, "description": description},
        )
        assert response.status_code == 201, response.text
        return response.json()

    return factory


@pytest.fixture
def investigation(make_investigation):
    return make_investigation()


@pytest.fixture
def upload_log(client: TestClient):
    def factory(
        investigation_id: str,
        content: str | bytes,
        *,
        filename: str = "auth.log",
        **form: Any,
    ):
        body = content.encode("utf-8") if isinstance(content, str) else content
        data: dict[str, str] = {}
        for key, value in form.items():
            if value is None:
                continue
            if isinstance(value, datetime):
                data[key] = value.isoformat()
            elif isinstance(value, bool):
                if value:
                    data[key] = "true"
            else:
                data[key] = str(value)
        return client.post(
            f"/api/investigations/{investigation_id}/evidence",
            files={"file": (filename, body, "text/plain")},
            data=data,
        )

    return factory


@pytest.fixture
def fixture_text():
    def load(name: str) -> str:
        return (FIXTURES / name).read_text(encoding="utf-8")

    return load


@pytest.fixture
def settings():
    return SETTINGS
