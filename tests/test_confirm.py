"""Tests for confirm mode verification functions."""

from dataclasses import dataclass
from typing import Dict, List
from unittest.mock import MagicMock, patch, call

import pytest

from venom_cache.confirm import confirm_header_poisoning, confirm_param_poisoning


@dataclass
class MockResponseDiff:
    """Mock ResponseDiff for testing."""
    significant: bool = False


@dataclass
class MockHeaderFinding:
    """Mock HeaderFinding for testing."""
    header_name: str
    canary: str
    reflected_in_body: bool = True
    reflected_in_headers: List[str] = None
    response_diff: MockResponseDiff = None
    is_significant: bool = True

    def __post_init__(self):
        if self.reflected_in_headers is None:
            self.reflected_in_headers = []
        if self.response_diff is None:
            self.response_diff = MockResponseDiff()


@dataclass
class MockParamFinding:
    """Mock ParamFinding for testing."""
    param_name: str
    canary: str
    reflected_in_body: bool = True
    reflected_in_headers: List[str] = None
    response_diff: MockResponseDiff = None
    is_significant: bool = True

    def __post_init__(self):
        if self.reflected_in_headers is None:
            self.reflected_in_headers = []
        if self.response_diff is None:
            self.response_diff = MockResponseDiff()


class TestConfirmHeaderPoisoning:
    """Tests for confirm_header_poisoning()."""

    def test_returns_tuple(self):
        """confirm_header_poisoning should return a tuple of (bool, str)."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            mock_request.return_value = (200, {}, b"response body")

            finding = MockHeaderFinding(
                header_name="X-Forwarded-Host",
                canary="venom-abc123",
            )
            result = confirm_header_poisoning("https://example.com", finding)

            assert isinstance(result, tuple)
            assert len(result) == 2
            assert isinstance(result[0], bool)
            assert isinstance(result[1], str)

    def test_confirmed_when_canary_in_victim_body(self):
        """Should return True when canary found in victim response body."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            # First call: poison request (doesn't matter what it returns)
            # Second call: victim request with canary in body
            mock_request.side_effect = [
                (200, {}, b"poison response"),
                (200, {}, b"response with venom-abc123 canary"),
            ]

            finding = MockHeaderFinding(
                header_name="X-Forwarded-Host",
                canary="venom-abc123",
            )
            confirmed, msg = confirm_header_poisoning("https://example.com", finding)

            assert confirmed is True
            assert "CONFIRMED" in msg
            assert "body" in msg

    def test_confirmed_when_canary_in_victim_headers(self):
        """Should return True when canary found in victim response headers."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            mock_request.side_effect = [
                (200, {}, b"poison response"),
                (200, {"X-Reflected": "venom-abc123"}, b"clean body"),
            ]

            finding = MockHeaderFinding(
                header_name="X-Forwarded-Host",
                canary="venom-abc123",
            )
            confirmed, msg = confirm_header_poisoning("https://example.com", finding)

            assert confirmed is True
            assert "CONFIRMED" in msg
            assert "headers" in msg

    def test_not_confirmed_when_canary_missing(self):
        """Should return False when canary not in victim response."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            mock_request.side_effect = [
                (200, {}, b"poison response"),
                (200, {}, b"clean victim response"),
            ]

            finding = MockHeaderFinding(
                header_name="X-Forwarded-Host",
                canary="venom-abc123",
            )
            confirmed, msg = confirm_header_poisoning("https://example.com", finding)

            assert confirmed is False
            assert "NOT CONFIRMED" in msg

    def test_uses_cache_buster_false(self):
        """Both requests should use use_cache_buster=False to hit shared cache."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            mock_request.return_value = (200, {}, b"response")

            finding = MockHeaderFinding(
                header_name="X-Forwarded-Host",
                canary="venom-abc123",
            )
            confirm_header_poisoning("https://example.com", finding)

            # Verify both calls used use_cache_buster=False
            assert mock_request.call_count == 2
            for call_args in mock_request.call_args_list:
                _, kwargs = call_args
                assert kwargs.get("use_cache_buster") is False, \
                    "All confirm requests must use use_cache_buster=False"

    def test_poison_request_includes_canary_header(self):
        """Poison request should include the finding's header with canary value."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            mock_request.return_value = (200, {}, b"response")

            finding = MockHeaderFinding(
                header_name="X-Forwarded-Host",
                canary="venom-xyz789",
            )
            confirm_header_poisoning("https://example.com", finding)

            # First call is poison request
            poison_call = mock_request.call_args_list[0]
            _, kwargs = poison_call
            headers = kwargs.get("headers", {})
            assert headers.get("X-Forwarded-Host") == "venom-xyz789"

    def test_victim_request_no_canary_header(self):
        """Victim request should NOT include the poison header."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            mock_request.return_value = (200, {}, b"response")

            finding = MockHeaderFinding(
                header_name="X-Forwarded-Host",
                canary="venom-abc123",
            )
            confirm_header_poisoning("https://example.com", finding)

            # Second call is victim request
            victim_call = mock_request.call_args_list[1]
            _, kwargs = victim_call
            headers = kwargs.get("headers", {})
            assert "X-Forwarded-Host" not in headers or headers.get("X-Forwarded-Host") != "venom-abc123"

    def test_custom_headers_included(self):
        """Custom headers should be included in both requests."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            mock_request.return_value = (200, {}, b"response")

            finding = MockHeaderFinding(
                header_name="X-Forwarded-Host",
                canary="venom-abc123",
            )
            custom = {"Authorization": "Bearer token123"}
            confirm_header_poisoning("https://example.com", finding, custom_headers=custom)

            for call_args in mock_request.call_args_list:
                _, kwargs = call_args
                headers = kwargs.get("headers", {})
                assert headers.get("Authorization") == "Bearer token123"


class TestConfirmParamPoisoning:
    """Tests for confirm_param_poisoning()."""

    def test_returns_tuple(self):
        """confirm_param_poisoning should return a tuple of (bool, str)."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            mock_request.return_value = (200, {}, b"response body")

            finding = MockParamFinding(
                param_name="callback",
                canary="venom-abc123",
            )
            result = confirm_param_poisoning("https://example.com", finding)

            assert isinstance(result, tuple)
            assert len(result) == 2
            assert isinstance(result[0], bool)
            assert isinstance(result[1], str)

    def test_confirmed_when_canary_in_victim_body(self):
        """Should return True when canary found in victim response body."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            mock_request.side_effect = [
                (200, {}, b"poison response"),
                (200, {}, b"response with venom-abc123 canary"),
            ]

            finding = MockParamFinding(
                param_name="callback",
                canary="venom-abc123",
            )
            confirmed, msg = confirm_param_poisoning("https://example.com", finding)

            assert confirmed is True
            assert "CONFIRMED" in msg

    def test_not_confirmed_when_canary_missing(self):
        """Should return False when canary not in victim response."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            mock_request.side_effect = [
                (200, {}, b"poison response"),
                (200, {}, b"clean victim response"),
            ]

            finding = MockParamFinding(
                param_name="callback",
                canary="venom-abc123",
            )
            confirmed, msg = confirm_param_poisoning("https://example.com", finding)

            assert confirmed is False
            assert "NOT CONFIRMED" in msg

    def test_uses_cache_buster_false(self):
        """Both requests should use use_cache_buster=False to hit shared cache."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            mock_request.return_value = (200, {}, b"response")

            finding = MockParamFinding(
                param_name="callback",
                canary="venom-abc123",
            )
            confirm_param_poisoning("https://example.com", finding)

            # Verify both calls used use_cache_buster=False
            assert mock_request.call_count == 2
            for call_args in mock_request.call_args_list:
                _, kwargs = call_args
                assert kwargs.get("use_cache_buster") is False, \
                    "All confirm requests must use use_cache_buster=False"

    def test_poison_request_includes_param_in_url(self):
        """Poison request should inject the param into URL."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            mock_request.return_value = (200, {}, b"response")

            finding = MockParamFinding(
                param_name="callback",
                canary="venom-xyz789",
            )
            confirm_param_poisoning("https://example.com/api", finding)

            # First call is poison request
            poison_call = mock_request.call_args_list[0]
            args, _ = poison_call
            poisoned_url = args[0]
            assert "callback=venom-xyz789" in poisoned_url

    def test_victim_request_uses_original_url(self):
        """Victim request should use original URL without injected param."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            mock_request.return_value = (200, {}, b"response")

            finding = MockParamFinding(
                param_name="callback",
                canary="venom-abc123",
            )
            original_url = "https://example.com/api"
            confirm_param_poisoning(original_url, finding)

            # Second call is victim request
            victim_call = mock_request.call_args_list[1]
            args, _ = victim_call
            victim_url = args[0]
            assert victim_url == original_url

    def test_uses_detect_reflection_for_check(self):
        """Should use detect_reflection to check for canary in victim response."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            with patch("venom_cache.confirm.detect_reflection") as mock_detect:
                mock_request.return_value = (200, {"X-Test": "value"}, b"body content")
                mock_detect.return_value = (True, [])

                finding = MockParamFinding(
                    param_name="callback",
                    canary="venom-abc123",
                )
                confirm_param_poisoning("https://example.com", finding)

                # detect_reflection should be called with canary and victim response
                mock_detect.assert_called()
                call_args = mock_detect.call_args
                assert call_args[0][0] == "venom-abc123"  # canary
                assert call_args[0][1] == b"body content"  # body


class TestConfirmUsesDetectReflection:
    """Tests verifying detect_reflection is used correctly."""

    def test_header_confirm_uses_detect_reflection(self):
        """confirm_header_poisoning should use detect_reflection for checking."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            with patch("venom_cache.confirm.detect_reflection") as mock_detect:
                mock_request.return_value = (200, {"X-Test": "value"}, b"victim body")
                mock_detect.return_value = (False, [])

                finding = MockHeaderFinding(
                    header_name="X-Forwarded-Host",
                    canary="venom-test123",
                )
                confirm_header_poisoning("https://example.com", finding)

                mock_detect.assert_called_once()
                args = mock_detect.call_args[0]
                assert args[0] == "venom-test123"  # canary
                assert args[1] == b"victim body"  # body
                assert args[2] == {"X-Test": "value"}  # headers

    def test_param_confirm_uses_detect_reflection(self):
        """confirm_param_poisoning should use detect_reflection for checking."""
        with patch("venom_cache.confirm.make_request") as mock_request:
            with patch("venom_cache.confirm.detect_reflection") as mock_detect:
                mock_request.return_value = (200, {"Content-Type": "text/html"}, b"victim response")
                mock_detect.return_value = (True, ["content-type"])

                finding = MockParamFinding(
                    param_name="cb",
                    canary="venom-param123",
                )
                confirmed, _ = confirm_param_poisoning("https://example.com", finding)

                mock_detect.assert_called_once()
                args = mock_detect.call_args[0]
                assert args[0] == "venom-param123"
                assert confirmed is True
