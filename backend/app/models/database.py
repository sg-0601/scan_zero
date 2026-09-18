from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings
import logging

logger = logging.getLogger(__name__)

Base = declarative_base()

try:
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=False,
        future=True
    )
    AsyncSessionLocal = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
except Exception as e:
    logger.info(f"Async database engine skipped (resilient in-memory mode active): {e}")
    engine = None
    AsyncSessionLocal = None

async def get_db():
    if AsyncSessionLocal:
        async with AsyncSessionLocal() as session:
            yield session

async def create_tables():
    if engine and Base:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
