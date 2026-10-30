"""Pytest fixtures for CyberDuel API test suite."""

from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from apps.api.app.core.config import Settings, get_settings
from apps.api.app.core.rate_limit import limiter
from apps.api.app.db.session import get_db_session
from apps.api.app.main import create_app
from apps.api.app.models.base import Base


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> None:
    """Reset rate limiter buckets between tests."""
    limiter.reset()


@pytest.fixture
def test_settings() -> Settings:
    """Return test settings with in-memory SQLite and mock AI provider."""
    return Settings(
        ENVIRONMENT="test",
        DEBUG=False,
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        DATABASE_URL_SYNC="sqlite:///:memory:",
        AI_PROVIDER_TYPE="mock",
        SECRET_KEY="test_secret_key_at_least_32_characters_for_testing",
        RATE_LIMIT_ENABLED=True,
        RATE_LIMIT_PER_MINUTE=100,
        MAX_REQUEST_BODY_BYTES=10_000,
    )


@pytest_asyncio.fixture
async def test_db_engine(test_settings: Settings) -> AsyncGenerator[AsyncEngine, None]:
    """Create in-memory SQLite async engine and build schema."""
    engine = create_async_engine(
        test_settings.DATABASE_URL,
        connect_args={"check_same_thread": False},
        future=True,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def test_db_session(
    test_db_engine: AsyncEngine,
) -> AsyncGenerator[AsyncSession, None]:
    """Provide an isolated database session per test."""
    session_factory = async_sessionmaker(
        bind=test_db_engine,
        autoflush=False,
        expire_on_commit=False,
        class_=AsyncSession,
    )
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def async_client(
    test_settings: Settings,
    test_db_session: AsyncSession,
) -> AsyncGenerator[AsyncClient, None]:
    """Async test client with overridden settings and database session."""
    app = create_app()

    # Override dependencies
    app.dependency_overrides[get_settings] = lambda: test_settings
    app.dependency_overrides[get_db_session] = lambda: test_db_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client

    app.dependency_overrides.clear()
