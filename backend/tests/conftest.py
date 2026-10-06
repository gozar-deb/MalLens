"""
Shared pytest fixtures.

Full API tests (test_api.py) need Postgres + Redis, matching CI's docker
services (see .github/workflows/ci.yml). The static-analysis / IOC /
scoring / validation unit tests have zero external dependencies and always
run, even without a database.
"""
import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://mallens:mallens_pass@localhost:5432/mallens_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("REQUIRE_AUTH", "false")

import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
