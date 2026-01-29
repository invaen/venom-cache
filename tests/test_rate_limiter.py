"""Tests for rate limiter module."""

import time

import pytest

from venom_cache.rate_limiter import (
    RateLimiter,
    configure_rate_limiter,
    rate_limit,
    reset_rate_limiter,
)


class TestRateLimiter:
    """Tests for RateLimiter class."""

    def test_rate_limiter_zero_delay_returns_immediately(self):
        """RateLimiter with delay=0 should return immediately."""
        limiter = RateLimiter(delay_seconds=0.0)

        start = time.time()
        limiter.wait()
        limiter.wait()
        limiter.wait()
        elapsed = time.time() - start

        # Should be nearly instant
        assert elapsed < 0.05

    def test_rate_limiter_negative_delay_returns_immediately(self):
        """RateLimiter with negative delay should return immediately."""
        limiter = RateLimiter(delay_seconds=-1.0)

        start = time.time()
        limiter.wait()
        limiter.wait()
        elapsed = time.time() - start

        assert elapsed < 0.05

    def test_rate_limiter_first_request_returns_immediately(self):
        """First request should not wait regardless of delay setting."""
        limiter = RateLimiter(delay_seconds=1.0)

        start = time.time()
        limiter.wait()  # First request
        elapsed = time.time() - start

        # First request should be nearly instant
        assert elapsed < 0.05

    def test_rate_limiter_enforces_delay(self):
        """Subsequent requests should wait for the configured delay."""
        delay = 0.1  # 100ms delay
        limiter = RateLimiter(delay_seconds=delay)

        limiter.wait()  # First request

        start = time.time()
        limiter.wait()  # Second request - should wait
        elapsed = time.time() - start

        # Should have waited approximately the delay time
        assert elapsed >= delay * 0.9  # Allow 10% tolerance
        assert elapsed < delay * 1.5  # But not too long

    def test_rate_limiter_respects_elapsed_time(self):
        """If enough time has passed, should not wait."""
        delay = 0.05  # 50ms
        limiter = RateLimiter(delay_seconds=delay)

        limiter.wait()  # First request

        # Wait longer than delay
        time.sleep(delay * 1.5)

        start = time.time()
        limiter.wait()  # Should not wait since delay already passed
        elapsed = time.time() - start

        assert elapsed < delay * 0.5  # Should be nearly instant

    def test_rate_limiter_multiple_requests(self):
        """Multiple requests should each be delayed."""
        delay = 0.05
        limiter = RateLimiter(delay_seconds=delay)
        num_requests = 4

        start = time.time()
        for _ in range(num_requests):
            limiter.wait()
        elapsed = time.time() - start

        # Total time should be at least (num_requests - 1) * delay
        # First request is instant, subsequent ones wait
        expected_min = delay * (num_requests - 1) * 0.9
        assert elapsed >= expected_min


class TestGlobalRateLimiter:
    """Tests for global rate limiter functions."""

    def setup_method(self):
        """Reset global state before each test."""
        reset_rate_limiter()

    def teardown_method(self):
        """Clean up global state after each test."""
        reset_rate_limiter()

    def test_rate_limit_does_nothing_when_not_configured(self):
        """rate_limit() should do nothing when no limiter is configured."""
        start = time.time()
        rate_limit()
        rate_limit()
        rate_limit()
        elapsed = time.time() - start

        assert elapsed < 0.05

    def test_configure_rate_limiter_sets_global(self):
        """configure_rate_limiter() should set up global state."""
        configure_rate_limiter(0.1)

        # First call should be instant
        start = time.time()
        rate_limit()
        elapsed = time.time() - start
        assert elapsed < 0.05

        # Second call should wait
        start = time.time()
        rate_limit()
        elapsed = time.time() - start
        assert elapsed >= 0.09

    def test_rate_limit_calls_global_wait(self):
        """rate_limit() should call the configured limiter's wait()."""
        delay = 0.05
        configure_rate_limiter(delay)

        rate_limit()  # First request

        start = time.time()
        rate_limit()  # Should trigger wait
        elapsed = time.time() - start

        assert elapsed >= delay * 0.9

    def test_reset_rate_limiter_clears_global(self):
        """reset_rate_limiter() should clear the global limiter."""
        configure_rate_limiter(1.0)
        reset_rate_limiter()

        # Should not wait since limiter is cleared
        start = time.time()
        rate_limit()
        rate_limit()
        elapsed = time.time() - start

        assert elapsed < 0.05

    def test_configure_rate_limiter_with_zero_delay(self):
        """Configuring with zero delay should allow instant requests."""
        configure_rate_limiter(0.0)

        start = time.time()
        rate_limit()
        rate_limit()
        rate_limit()
        elapsed = time.time() - start

        assert elapsed < 0.05
