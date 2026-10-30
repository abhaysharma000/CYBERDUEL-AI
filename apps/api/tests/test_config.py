"""Tests for application settings and configuration validation."""

import pytest
from pydantic import ValidationError

from apps.api.app.core.config import Settings


def test_default_settings_valid() -> None:
    settings = Settings()
    assert settings.APP_NAME == "CyberDuel AI"
    assert settings.API_PORT == 8000
    assert settings.AI_PROVIDER_TYPE in ["mock", "local", "openai", "anthropic"]


def test_cors_origins_parsing() -> None:
    # Test list input
    s1 = Settings(CORS_ORIGINS=["http://localhost:3000", "http://test.com"])
    assert len(s1.CORS_ORIGINS) == 2

    # Test comma-separated string input
    s2 = Settings(CORS_ORIGINS="http://localhost:3000, http://test.com, ")  # type: ignore[arg-type]
    assert len(s2.CORS_ORIGINS) == 2
    assert "http://test.com" in s2.CORS_ORIGINS


def test_environment_flags() -> None:
    s_prod = Settings(ENVIRONMENT="production")
    assert s_prod.is_production is True
    assert s_prod.is_testing is False

    s_test = Settings(ENVIRONMENT="test")
    assert s_test.is_production is False
    assert s_test.is_testing is True


def test_invalid_environment_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(ENVIRONMENT="invalid_env_name")  # type: ignore[arg-type]


def test_invalid_port_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(API_PORT="not_a_number")  # type: ignore[arg-type]
