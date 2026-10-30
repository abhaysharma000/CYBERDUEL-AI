"""Rate limiting abstraction with in-memory fallback for local development and tests."""

import time
from collections import defaultdict
from threading import Lock

from fastapi import Request

from apps.api.app.core.config import get_settings
from apps.api.app.core.exceptions import RateLimitExceededError


class InMemoryRateLimiter:
    """Sliding-window rate limiter for development and local testing."""

    def __init__(self, requests_per_minute: int = 120) -> None:
        self.requests_per_minute = requests_per_minute
        self.window_seconds = 60
        self._history: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def check(self, key: str) -> None:
        settings = get_settings()
        if not settings.RATE_LIMIT_ENABLED:
            return

        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            # Prune expired timestamps
            timestamps = [t for t in self._history[key] if t > cutoff]
            if len(timestamps) >= self.requests_per_minute:
                raise RateLimitExceededError(
                    f"Rate limit exceeded: maximum {self.requests_per_minute} requests per minute."
                )
            timestamps.append(now)
            self._history[key] = timestamps

    def reset(self) -> None:
        with self._lock:
            self._history.clear()


limiter = InMemoryRateLimiter()


def rate_limit_dependency(request: Request) -> None:
    """FastAPI dependency to enforce rate limiting by client IP or client ID."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    client_id = request.headers.get("X-Client-ID", client_ip)
    limiter.check(client_id)
