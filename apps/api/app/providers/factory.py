"""Provider factory for instantiating AI and classification backends."""

from functools import lru_cache

from apps.api.app.core.config import get_settings
from apps.api.app.providers.base import (
    BaseEvaluationProvider,
    BaseReasoningProvider,
    BaseScenarioGeneratorProvider,
    BaseThreatClassificationProvider,
)
from apps.api.app.providers.mock_provider import DeterministicMockProvider
from apps.api.app.providers.qwen_provider import QwenProvider


@lru_cache
def get_ai_provider() -> (
    BaseReasoningProvider
    | BaseThreatClassificationProvider
    | BaseScenarioGeneratorProvider
    | BaseEvaluationProvider
):
    """Instantiate and return the configured AI provider singleton.

    Invariants:
    1. If AI_PROVIDER_TYPE == 'qwen', returns real QwenProvider targeting QWEN_API_BASE.
    2. If AI_PROVIDER_TYPE == 'mock', allows DeterministicMockProvider ONLY in development/test.
    3. In production mode, mock AI is strictly prohibited and fails closed.
    """
    settings = get_settings()

    if settings.AI_PROVIDER_TYPE == "qwen":
        return QwenProvider(
            api_base=settings.QWEN_API_BASE,
            api_key=settings.QWEN_API_KEY,
            model_name=settings.QWEN_MODEL_NAME,
            timeout_seconds=settings.QWEN_TIMEOUT_SECONDS,
        )

    if settings.AI_PROVIDER_TYPE == "mock":
        if settings.is_production:
            raise RuntimeError(
                "CRITICAL SECURITY VIOLATION: Mock AI provider is strictly prohibited in production mode. "
                "Configure a real Qwen inference endpoint (AI_PROVIDER_TYPE=qwen, QWEN_API_BASE, QWEN_API_KEY) "
                "or fail closed."
            )
        return DeterministicMockProvider(model_name=settings.AI_MODEL_NAME)

    raise ValueError(f"Unsupported AI_PROVIDER_TYPE: '{settings.AI_PROVIDER_TYPE}'")
