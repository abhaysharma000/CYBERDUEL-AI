"""Unit and contract tests for the Real Qwen Provider abstraction.

Validates:
1. QwenProvider request formation, OpenAI-compatible payload structure, and timeout enforcement.
2. Structured JSON generation and markdown code fence stripping.
3. Strict fail-closed error handling (timeouts, HTTP 429 rate limits, HTTP 500 server errors, malformed envelopes).
4. Zero silent mock fallbacks when Qwen inference fails.
5. Factory instantiation of QwenProvider vs. prohibition of mock provider in production.
6. Accurate, transparent reporting of AI provider status in readiness probe.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from apps.api.app.core.config import Settings, get_settings
from apps.api.app.main import create_app
from apps.api.app.providers.base import (
    ProviderInferenceError,
    ProviderRateLimitError,
    ProviderUnavailableError,
)
from apps.api.app.providers.factory import get_ai_provider
from apps.api.app.providers.qwen_provider import QwenProvider


@pytest.mark.asyncio
async def test_qwen_provider_initialization() -> None:
    """Verify QwenProvider initializes with explicit or default settings."""
    provider = QwenProvider(
        api_base="https://custom.qwen.api/v1",
        api_key="test-key-123",
        model_name="Qwen/Qwen2.5-Coder-7B-Instruct",
        timeout_seconds=20.0,
    )
    assert provider.api_base == "https://custom.qwen.api/v1"
    assert provider.api_key == "test-key-123"
    assert provider.model_name == "Qwen/Qwen2.5-Coder-7B-Instruct"
    assert provider.timeout == 20.0


@pytest.mark.asyncio
async def test_qwen_provider_generate_response_success() -> None:
    """Verify standard chat completion request format and response extraction."""
    provider = QwenProvider(
        api_base="https://mock.qwen.endpoint/v1",
        api_key="secret-qwen-key",
        model_name="Qwen/Qwen2.5-Coder-7B-Instruct",
    )

    fake_response_data = {
        "id": "chatcmpl-test-01",
        "object": "chat.completion",
        "created": 1730000000,
        "model": "Qwen/Qwen2.5-Coder-7B-Instruct",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Analysis: The target URL exhibits homoglyphic mimicry.",
                },
                "finish_reason": "stop",
            }
        ],
    }

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_response_data

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        result = await provider.generate_response(
            prompt="Analyze URL: http://bank.example.test",
            system_instruction="You are a security reasoning model.",
            temperature=0.2,
        )

        assert result == "Analysis: The target URL exhibits homoglyphic mimicry."
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args.kwargs
        assert call_kwargs["json"]["model"] == "Qwen/Qwen2.5-Coder-7B-Instruct"
        assert call_kwargs["json"]["temperature"] == 0.2
        assert "Authorization" in call_kwargs["headers"]


@pytest.mark.asyncio
async def test_qwen_provider_structured_json_strips_code_fences() -> None:
    """Verify structured JSON output correctly strips markdown fences."""
    provider = QwenProvider(api_base="https://mock.qwen.endpoint/v1")

    # Simulate Qwen wrapping JSON in markdown fences
    markdown_wrapped_json = (
        "```json\n"
        '{\n  "title": "Homoglyph Attack",\n  "expected_decision": "block",\n  "test_url": "http://evil.example.test"\n}\n'
        "```"
    )

    fake_response = {"choices": [{"message": {"content": markdown_wrapped_json}}]}

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_response

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        data = await provider.generate_structured_json("Generate attack scenario")

        assert isinstance(data, dict)
        assert data["title"] == "Homoglyph Attack"
        assert data["expected_decision"] == "block"
        assert data["test_url"] == "http://evil.example.test"


@pytest.mark.asyncio
async def test_qwen_provider_fails_closed_on_timeout() -> None:
    """Verify Qwen provider fails closed on timeout and never falls back to mock."""
    provider = QwenProvider(api_base="https://mock.qwen.endpoint/v1")

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = httpx.TimeoutException("Connection timed out")

        with pytest.raises(ProviderUnavailableError) as exc_info:
            await provider.generate_response("Generate scenario")

        assert "timed out" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_qwen_provider_fails_closed_on_rate_limit() -> None:
    """Verify Qwen provider raises ProviderRateLimitError on HTTP 429."""
    provider = QwenProvider(api_base="https://mock.qwen.endpoint/v1")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 429
    mock_resp.text = "Too many requests"

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        with pytest.raises(ProviderRateLimitError) as exc_info:
            await provider.generate_response("Test prompt")

        assert "rate limit" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_qwen_provider_fails_closed_on_server_error() -> None:
    """Verify Qwen provider raises ProviderUnavailableError on HTTP 500+ upstream errors."""
    provider = QwenProvider(api_base="https://mock.qwen.endpoint/v1")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 502
    mock_resp.text = "Bad Gateway"

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        with pytest.raises(ProviderUnavailableError) as exc_info:
            await provider.generate_response("Test prompt")

        assert "HTTP 502" in str(exc_info.value)


@pytest.mark.asyncio
async def test_qwen_provider_fails_closed_on_malformed_json() -> None:
    """Verify Qwen provider raises ProviderInferenceError when model returns invalid JSON."""
    provider = QwenProvider(api_base="https://mock.qwen.endpoint/v1")

    fake_response = {"choices": [{"message": {"content": "I am not a JSON object: {malformed"}}]}

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_response

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        with pytest.raises(ProviderInferenceError) as exc_info:
            await provider.generate_structured_json("Prompt")

        assert "invalid json" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_factory_returns_qwen_provider() -> None:
    """Verify get_ai_provider() instantiates QwenProvider when AI_PROVIDER_TYPE='qwen'."""
    qwen_settings = Settings(
        AI_PROVIDER_TYPE="qwen",
        QWEN_API_BASE="https://hosted.qwen.endpoint/v1",
        QWEN_MODEL_NAME="Qwen/Qwen2.5-Coder-7B-Instruct",
    )

    get_ai_provider.cache_clear()
    with patch("apps.api.app.providers.factory.get_settings", return_value=qwen_settings):
        provider = get_ai_provider()
        assert isinstance(provider, QwenProvider)
        assert provider.model_name == "Qwen/Qwen2.5-Coder-7B-Instruct"
    get_ai_provider.cache_clear()


@pytest.mark.asyncio
async def test_factory_prohibits_mock_provider_in_production() -> None:
    """Verify factory strictly rejects mock provider in production mode."""
    prod_mock_settings = Settings(
        ENVIRONMENT="production",
        AI_PROVIDER_TYPE="mock",
    )

    get_ai_provider.cache_clear()
    with patch("apps.api.app.providers.factory.get_settings", return_value=prod_mock_settings):
        with pytest.raises(RuntimeError) as exc_info:
            get_ai_provider()

        assert "prohibited in production" in str(exc_info.value).lower()
    get_ai_provider.cache_clear()


@pytest.mark.asyncio
async def test_readiness_probe_reporting_honesty() -> None:
    """Verify readiness probe honestly reports Qwen model identity vs. mock non-LLM status."""
    # 1. Test Qwen configuration reporting
    qwen_settings = Settings(
        AI_PROVIDER_TYPE="qwen",
        QWEN_MODEL_NAME="Qwen/Qwen2.5-Coder-7B-Instruct",
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
    )

    app = create_app()
    app.dependency_overrides[get_settings] = lambda: qwen_settings

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/health/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert "qwen (Qwen/Qwen2.5-Coder-7B-Instruct)" in data["checks"]["ai_provider"]

    # 2. Test Mock configuration reporting
    mock_settings = Settings(
        AI_PROVIDER_TYPE="mock",
        AI_MODEL_NAME="deterministic-mock-v1",
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
    )
    app.dependency_overrides[get_settings] = lambda: mock_settings

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/health/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert "mock" in data["checks"]["ai_provider"]
        assert "offline non-llm" in data["checks"]["ai_provider"]

    app.dependency_overrides.clear()
