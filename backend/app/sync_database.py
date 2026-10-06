"""Synchronous SQLAlchemy session for use inside Celery tasks (Celery workers
are simplest as sync code; the FastAPI side uses the async engine in
database.py against the same Postgres database)."""
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

settings = get_settings()

_sync_url = settings.DATABASE_URL.replace("+asyncpg", "")
sync_engine = create_engine(_sync_url, future=True)
SyncSessionLocal = sessionmaker(bind=sync_engine, class_=Session, expire_on_commit=False)
