"""Abstract base classes and protocols defining AI model provider interfaces."""

from abc import ABC, abstractmethod
from typing import Any

from cyberduel_contracts.analysis import ThreatAnalysisResult
from cyberduel_contracts.evaluation import EvaluationResult
from cyberduel_contracts.lab import LaboratoryScenario
from cyberduel_contracts.policy import CandidateDefense


class ProviderError(Exception):
    """Base exception for all AI provider errors."""
    pass


class ProviderUnavailableError(ProviderError):
    """Raised when an AI provider endpoint cannot be reached or times out."""
    pass


class ProviderRateLimitError(ProviderError):
    """Raised when an AI provider returns HTTP 429 rate limit exceeded."""
    pass


class ProviderInferenceError(ProviderError):
    """Raised when an AI provider returns an error, invalid response, or schema validation fails."""
    pass


class BaseReasoningProvider(ABC):
    """Interface for generative or reasoning models (e.g. Red/Blue planning agents)."""

    @abstractmethod
    async def generate_response(
        self,
        prompt: str,
        system_instruction: str = "",
        temperature: float = 0.2,
    ) -> str:
        """Produce reasoning output given a prompt and system context."""
        ...


class BaseThreatClassificationProvider(ABC):
    """Interface for threat scoring and verdict generation."""

    @abstractmethod
    async def classify_resource(
        self,
        normalized_identifier: str,
        resource_url: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> ThreatAnalysisResult:
        """Analyze a normalized resource and emit a calibrated threat decision and evidence."""
        ...


class BaseScenarioGeneratorProvider(ABC):
    """Interface for Red AI adversarial scenario generation."""

    @abstractmethod
    async def generate_scenario(
        self,
        target_vulnerability: str,
        difficulty: str = "intermediate",
    ) -> LaboratoryScenario:
        """Generate a controlled, safe synthetic security challenge."""
        ...


class BaseEvaluationProvider(ABC):
    """Interface for running benchmark regression tests against candidate defenses."""

    @abstractmethod
    async def evaluate_candidate(
        self,
        candidate: CandidateDefense,
        scenario_suite_id: str,
    ) -> EvaluationResult:
        """Execute benchmark suite and return an independent verdict."""
        ...
