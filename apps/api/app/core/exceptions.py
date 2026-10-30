"""Domain-specific exception hierarchy for CyberDuel AI."""

from typing import Any


class CyberDuelException(Exception):
    """Base exception for all domain and platform errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "INTERNAL_ERROR",
        status_code: int = 500,
        details: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or []


class ResourceNotFoundError(CyberDuelException):
    """Raised when an entity or resource is not found."""

    def __init__(self, message: str, resource_type: str = "resource") -> None:
        super().__init__(
            message=message,
            error_code="RESOURCE_NOT_FOUND",
            status_code=404,
            details=[{"code": "NOT_FOUND", "message": f"{resource_type} not found"}],
        )


class PolicyValidationError(CyberDuelException):
    """Raised when a candidate policy or release payload violates schema/integrity."""

    def __init__(self, message: str, details: list[dict[str, Any]] | None = None) -> None:
        super().__init__(
            message=message,
            error_code="POLICY_VALIDATION_FAILED",
            status_code=422,
            details=details or [],
        )


class RateLimitExceededError(CyberDuelException):
    """Raised when client quota is exceeded."""

    def __init__(self, message: str = "Request rate limit exceeded. Please retry later.") -> None:
        super().__init__(
            message=message,
            error_code="RATE_LIMIT_EXCEEDED",
            status_code=429,
        )


class SecurityViolationError(CyberDuelException):
    """Raised when a request violates security constraints or isolation bounds."""

    def __init__(self, message: str) -> None:
        super().__init__(
            message=message,
            error_code="SECURITY_VIOLATION",
            status_code=403,
        )


class ServiceUnavailableError(CyberDuelException):
    """Raised when a required dependent service (e.g. database, queue) is unavailable."""

    def __init__(self, message: str = "Required service is temporarily unavailable.") -> None:
        super().__init__(
            message=message,
            error_code="SERVICE_UNAVAILABLE",
            status_code=503,
        )
