"""Scenario Validator enforcing strict schema, bounds, and laboratory safety constraints."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from cyberduel_contracts.enums import Decision, ExpectedClass, ScenarioFamily
from cyberduel_contracts.lab import ScenarioContract


@dataclass(frozen=True)
class ScenarioValidationResult:
    """Outcome of validating a synthetic scenario contract."""

    is_valid: bool
    scenario_id: str
    error_code: str | None = None
    error_message: str | None = None


class ScenarioValidator:
    """Validates structural and safety invariants for laboratory threat scenarios."""

    MAX_URL_LENGTH = 4096
    MAX_NAME_LENGTH = 128
    MAX_DESC_LENGTH = 512
    ALLOWED_SCHEMES = {"http", "https"}

    @classmethod
    def validate(cls, scenario: ScenarioContract) -> ScenarioValidationResult:
        """Validate a scenario contract against all bounds and laboratory safety invariants."""
        sid = str(scenario.scenario_id)

        # 1. Title / Name bounds
        if not (3 <= len(scenario.scenario_name) <= cls.MAX_NAME_LENGTH):
            return ScenarioValidationResult(
                is_valid=False,
                scenario_id=sid,
                error_code="INVALID_NAME_LENGTH",
                error_message=f"Scenario name length must be between 3 and {cls.MAX_NAME_LENGTH} chars.",
            )

        # 2. Description bounds
        if len(scenario.description) > cls.MAX_DESC_LENGTH:
            return ScenarioValidationResult(
                is_valid=False,
                scenario_id=sid,
                error_code="DESC_TOO_LONG",
                error_message=f"Description exceeds maximum length of {cls.MAX_DESC_LENGTH} chars.",
            )

        # 3. Family validation
        valid_families = {f.value for f in ScenarioFamily}
        if scenario.scenario_family not in valid_families:
            return ScenarioValidationResult(
                is_valid=False,
                scenario_id=sid,
                error_code="UNKNOWN_SCENARIO_FAMILY",
                error_message=f"Scenario family '{scenario.scenario_family}' is not recognized.",
            )

        # 4. Expected class validation
        valid_classes = {c.value for c in ExpectedClass}
        if scenario.expected_class not in valid_classes:
            return ScenarioValidationResult(
                is_valid=False,
                scenario_id=sid,
                error_code="INVALID_EXPECTED_CLASS",
                error_message=f"Expected class '{scenario.expected_class}' is invalid.",
            )

        # 5. Expected decision validation
        if scenario.expected_decision not in {Decision.ALLOW, Decision.WARN, Decision.BLOCK}:
            return ScenarioValidationResult(
                is_valid=False,
                scenario_id=sid,
                error_code="INVALID_EXPECTED_DECISION",
                error_message=f"Expected decision '{scenario.expected_decision}' is invalid.",
            )

        # 6. Safety classification
        if scenario.safety_classification != "harmless_synthetic":
            return ScenarioValidationResult(
                is_valid=False,
                scenario_id=sid,
                error_code="UNSAFE_CLASSIFICATION",
                error_message="Only 'harmless_synthetic' scenarios are permitted in the laboratory.",
            )

        # 7. URL Fixture Validation
        raw_url = scenario.input_fixture.get("raw_url")
        if not isinstance(raw_url, str) or not raw_url.strip():
            return ScenarioValidationResult(
                is_valid=False,
                scenario_id=sid,
                error_code="MISSING_RAW_URL",
                error_message="input_fixture must contain a non-empty 'raw_url' string.",
            )

        if len(raw_url) > cls.MAX_URL_LENGTH:
            return ScenarioValidationResult(
                is_valid=False,
                scenario_id=sid,
                error_code="URL_TOO_LONG",
                error_message=f"URL exceeds ceiling of {cls.MAX_URL_LENGTH} characters.",
            )

        parsed = urlparse(raw_url)
        if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
            return ScenarioValidationResult(
                is_valid=False,
                scenario_id=sid,
                error_code="UNSUPPORTED_SCHEME",
                error_message=f"Scheme '{parsed.scheme}' is unsupported. Only http and https permitted.",
            )

        # 8. Provenance requirement
        if not scenario.provenance:
            return ScenarioValidationResult(
                is_valid=False,
                scenario_id=sid,
                error_code="MISSING_PROVENANCE",
                error_message="Scenario must include provenance metadata.",
            )

        return ScenarioValidationResult(is_valid=True, scenario_id=sid)
