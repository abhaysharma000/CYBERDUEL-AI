"""Defensive URL structural and semantic validation."""

from __future__ import annotations

from dataclasses import dataclass

from cyberduel_threat_intel.normalizer import (
    NormalizedURL,
    URLNormalizationError,
    URLNormalizer,
)


@dataclass(frozen=True)
class ValidationResult:
    """Result of structural URL validation."""

    is_valid: bool
    normalized: NormalizedURL | None = None
    error_message: str | None = None
    error_code: str | None = None


class URLValidator:
    """Validates URL structure, schemes, lengths, and character encodings."""

    @classmethod
    def validate(cls, raw_url: str) -> ValidationResult:
        """Validate raw URL and return structured validation outcome."""
        try:
            normalized = URLNormalizer.normalize(raw_url)
            return ValidationResult(is_valid=True, normalized=normalized)
        except URLNormalizationError as e:
            return ValidationResult(
                is_valid=False,
                error_message=e.message,
                error_code=e.code,
            )
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"Unexpected validation error: {e}",
                error_code="VALIDATION_FAILED",
            )
