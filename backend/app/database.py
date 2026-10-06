"""Async SQLAlchemy engine/session setup."""
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

settings = get_settings()

engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG, future=True)
AsyncSessionLocal = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def init_models():
    """Create tables if they don't exist. For a real deployment, use Alembic
    migrations instead (see SETUP.md)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
