"""Rate limiter module for controlling request timing."""

import time
from typing import Optional


class RateLimiter:
    """Rate limiter that enforces minimum delay between requests."""

    def __init__(self, delay_seconds: float = 0.0) -> None:
        """Initialize rate limiter.

        Args:
            delay_seconds: Minimum delay between requests in seconds.
                          If 0, no rate limiting is applied.
        """
        self.delay_seconds = delay_seconds
        self._last_request: Optional[float] = None

    def wait(self) -> None:
        """Wait if necessary to maintain the configured delay.

        If delay is 0 or this is the first request, returns immediately.
        Otherwise, sleeps for the remaining time since the last request.
        """
        if self.delay_seconds <= 0:
            return

        now = time.time()

        if self._last_request is not None:
            elapsed = now - self._last_request
            remaining = self.delay_seconds - elapsed

            if remaining > 0:
                time.sleep(remaining)

        self._last_request = time.time()


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def configure_rate_limiter(delay_seconds: float) -> None:
    """Configure the global rate limiter.

    Args:
        delay_seconds: Minimum delay between requests in seconds.
    """
    global _rate_limiter
    _rate_limiter = RateLimiter(delay_seconds)


def rate_limit() -> None:
    """Apply rate limiting if configured.

    Calls the global rate limiter's wait() method if one has been configured.
    Does nothing if no rate limiter has been set up.
    """
    if _rate_limiter is not None:
        _rate_limiter.wait()


def reset_rate_limiter() -> None:
    """Reset the global rate limiter (for testing purposes)."""
    global _rate_limiter
    _rate_limiter = None
