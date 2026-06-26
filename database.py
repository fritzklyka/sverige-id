import os
from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

# Default to local SQLite database using aiosqlite driver
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./eid_platform.db")

# Setup SQLAlchemy engine and sessionmaker
engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to retrieve database session."""
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()
