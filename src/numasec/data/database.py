"""
NumaSec - Database Connection

Async SQLAlchemy 2.0 engine and session management.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from numasec.config.settings import get_settings
from numasec.data.models import Base

# Global engine and session maker
_engine: AsyncEngine | None = None
_session_maker: async_sessionmaker[AsyncSession] | None = None


def get_database_url(path: Path | None = None) -> str:
    """
    Get the SQLite database URL.

    Args:
        path: Optional database path. Uses settings if not provided.

    Returns:
        Async SQLite URL string.
    """
    if path is None:
        settings = get_settings()
        path = settings.database.path

    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # SQLite async URL format
    return f"sqlite+aiosqlite:///{path}"


async def create_engine(
    path: Path | None = None,
    echo: bool | None = None,
) -> AsyncEngine:
    """
    Create async SQLAlchemy engine.

    Args:
        path: Optional database path.
        echo: Enable SQL logging.

    Returns:
        Async engine instance.
    """
    settings = get_settings()

    if echo is None:
        echo = settings.database.echo

    url = get_database_url(path)

    engine = create_async_engine(
        url,
        echo=echo,
        future=True,
        # SQLite-specific settings
        connect_args={"check_same_thread": False},
    )

    return engine


async def init_database(
    engine: AsyncEngine | None = None,
    path: Path | None = None,
) -> AsyncEngine:
    """
    Initialize database with all tables.

    Creates all tables defined in models.py if they don't exist.

    Args:
        engine: Optional existing engine.
        path: Optional database path.

    Returns:
        The engine used for initialization.
    """
    global _engine, _session_maker

    if engine is None:
        engine = await create_engine(path)

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Store globally
    _engine = engine
    _session_maker = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    return engine


async def get_engine() -> AsyncEngine:
    """
    Get the global database engine.

    Initializes if not already done.

    Returns:
        The global async engine.
    """
    global _engine

    if _engine is None:
        await init_database()

    assert _engine is not None
    return _engine


def get_session_maker() -> async_sessionmaker[AsyncSession]:
    """
    Get the global session maker.

    Raises:
        RuntimeError: If database not initialized.

    Returns:
        Session maker instance.
    """
    global _session_maker

    if _session_maker is None:
        raise RuntimeError(
            "Database not initialized. Call init_database() first."
        )

    return _session_maker


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Get an async database session.

    Usage:
        async with get_session() as session:
            result = await session.execute(query)

    Yields:
        Async session with automatic commit/rollback.
    """
    session_maker = get_session_maker()

    async with session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def close_database() -> None:
    """Close the database connection."""
    global _engine, _session_maker

    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_maker = None


# ══════════════════════════════════════════════════════════════════════════════
# Utility Functions
# ══════════════════════════════════════════════════════════════════════════════


async def reset_database(engine: AsyncEngine | None = None) -> None:
    """
    Drop and recreate all tables.

    WARNING: This deletes all data!

    Args:
        engine: Optional engine to use.
    """
    if engine is None:
        engine = await get_engine()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


async def check_database_connection() -> bool:
    """
    Check if database is accessible.

    Returns:
        True if connection successful.
    """
    try:
        engine = await get_engine()
        async with engine.connect() as conn:
            await conn.execute("SELECT 1")
        return True
    except Exception:
        return False
