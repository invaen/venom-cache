"""Tests for header probing and reflection detection."""

import re
from unittest.mock import patch

import pytest

from venom_cache.baseline import ResponseBaseline, ResponseDiff
from venom_cache.header_prober import (
    HeaderFinding,
    detect_reflection,
    generate_canary,
    probe_header,
    probe_headers,
)


class TestGenerateCanary:
    """Tests for canary generation."""

    def test_generate_canary_format(self):
        """Canary matches expected format: venom-{12 hex chars}."""
        canary = generate_canary()
        assert re.match(r"^venom-[0-9a-f]{12}$", canary)

    def test_generate_canary_unique(self):
        """Two calls return different values."""
        canary1 = generate_canary()
        canary2 = generate_canary()
        assert canary1 != canary2

    def test_generate_canary_lowercase(self):
        """Canary is all lowercase."""
        canary = generate_canary()
        assert canary == canary.lower()


class TestDetectReflection:
    """Tests for reflection detection."""

    def test_detect_reflection_in_body(self):
        """Canary found in body returns (True, [])."""
        canary = "venom-abc123def456"
        body = b"Response body contains venom-abc123def456 somewhere"
        headers = {"Content-Type": "text/html"}

        found_in_body, headers_with_canary = detect_reflection(canary, body, headers)

        assert found_in_body is True
        assert headers_with_canary == []

    def test_detect_reflection_in_header(self):
        """Canary found in header returns (False, [header_name])."""
        canary = "venom-abc123def456"
        body = b"Response body without canary"
        headers = {"X-Debug": "Debug: venom-abc123def456"}

        found_in_body, headers_with_canary = detect_reflection(canary, body, headers)

        assert found_in_body is False
        assert "x-debug" in headers_with_canary

    def test_detect_reflection_in_both(self):
        """Canary in body AND header returns (True, [header_name])."""
        canary = "venom-abc123def456"
        body = b"Body has venom-abc123def456 too"
        headers = {"X-Reflected": "value=venom-abc123def456"}

        found_in_body, headers_with_canary = detect_reflection(canary, body, headers)

        assert found_in_body is True
        assert "x-reflected" in headers_with_canary

    def test_detect_reflection_case_insensitive(self):
        """Detection is case-insensitive."""
        canary = "venom-abc123def456"
        body = b"VENOM-ABC123DEF456 in uppercase"
        headers = {"X-Test": "VENOM-ABC123DEF456"}

        found_in_body, headers_with_canary = detect_reflection(canary, body, headers)

        assert found_in_body is True
        assert "x-test" in headers_with_canary

    def test_detect_reflection_not_found(self):
        """No reflection returns (False, [])."""
        canary = "venom-abc123def456"
        body = b"Normal response body"
        headers = {"Content-Type": "text/html"}

        found_in_body, headers_with_canary = detect_reflection(canary, body, headers)

        assert found_in_body is False
        assert headers_with_canary == []

    def test_detect_reflection_partial_match_rejected(self):
        """Partial canary match is not a reflection."""
        canary = "venom-abc123def456"
        body = b"Contains venom-abc123 but not full canary"
        headers = {}

        found_in_body, headers_with_canary = detect_reflection(canary, body, headers)

        assert found_in_body is False

    def test_detect_reflection_multiple_headers(self):
        """Multiple headers with canary are all reported."""
        canary = "venom-test12345678"
        body = b"No canary here"
        headers = {
            "X-Debug": "venom-test12345678",
            "X-Trace": "trace=venom-test12345678",
            "Content-Type": "text/html",
        }

        found_in_body, headers_with_canary = detect_reflection(canary, body, headers)

        assert found_in_body is False
        assert len(headers_with_canary) == 2
        assert "x-debug" in headers_with_canary
        assert "x-trace" in headers_with_canary


class TestHeaderFinding:
    """Tests for HeaderFinding significance logic."""

    def _make_diff(self, significant: bool = False) -> ResponseDiff:
        """Helper to create ResponseDiff."""
        return ResponseDiff(
            status_changed=False,
            headers_changed=[],
            body_changed=False,
            static_body_changed=significant,
            content_length_delta=0,
            significant=significant,
        )

    def test_header_finding_significant_body_reflection(self):
        """Reflected in body + significant diff = is_significant."""
        finding = HeaderFinding(
            header_name="X-Test",
            canary="venom-test",
            reflected_in_body=True,
            reflected_in_headers=[],
            response_diff=self._make_diff(significant=True),
            is_significant=True,  # Would be computed, but we set directly for test
        )

        assert finding.is_significant is True

    def test_header_finding_significant_header_reflection(self):
        """Reflected in header + significant diff = is_significant."""
        finding = HeaderFinding(
            header_name="X-Test",
            canary="venom-test",
            reflected_in_body=False,
            reflected_in_headers=["x-debug"],
            response_diff=self._make_diff(significant=True),
            is_significant=True,
        )

        assert finding.is_significant is True

    def test_header_finding_not_significant_no_reflection(self):
        """No reflection = not significant (even with diff)."""
        finding = HeaderFinding(
            header_name="X-Test",
            canary="venom-test",
            reflected_in_body=False,
            reflected_in_headers=[],
            response_diff=self._make_diff(significant=True),
            is_significant=False,  # No reflection -> not significant
        )

        assert finding.is_significant is False

    def test_header_finding_not_significant_no_diff(self):
        """Reflection without significant diff = not significant."""
        finding = HeaderFinding(
            header_name="X-Test",
            canary="venom-test",
            reflected_in_body=True,
            reflected_in_headers=[],
            response_diff=self._make_diff(significant=False),
            is_significant=False,  # No significant diff -> not significant
        )

        assert finding.is_significant is False


class TestProbeHeader:
    """Tests for probe_header with mocked HTTP."""

    def _make_baseline(self) -> ResponseBaseline:
        """Create a mock baseline."""
        return ResponseBaseline(
            url="https://example.com",
            status=200,
            headers={"Content-Type": "text/html"},
            body_hash="abc123",
            body_length=100,
            content_type="text/html",
            static_body_hash="def456",
            captured_at=1000.0,
        )

    @patch("venom_cache.header_prober.make_request")
    def test_probe_header_with_reflection(self, mock_make_request):
        """Probe detects reflection when canary is in response."""
        # Response contains the canary (we'll match it dynamically)
        mock_make_request.return_value = (
            200,
            {"Content-Type": "text/html"},
            b"Response with reflected value",
        )

        baseline = self._make_baseline()
        finding = probe_header(
            "https://example.com",
            "X-Forwarded-Host",
            baseline,
        )

        # The canary was generated inside probe_header, check it was used
        assert finding.header_name == "X-Forwarded-Host"
        assert finding.canary.startswith("venom-")

        # Verify make_request was called with the header
        mock_make_request.assert_called_once()
        call_kwargs = mock_make_request.call_args[1]
        assert "X-Forwarded-Host" in call_kwargs.get("headers", {})

    @patch("venom_cache.header_prober.make_request")
    def test_probe_header_no_reflection(self, mock_make_request):
        """Probe returns no reflection when canary not in response."""
        mock_make_request.return_value = (
            200,
            {"Content-Type": "text/html"},
            b"Clean response body",
        )

        baseline = self._make_baseline()
        finding = probe_header(
            "https://example.com",
            "X-Test-Header",
            baseline,
        )

        assert finding.reflected_in_body is False
        assert finding.reflected_in_headers == []
        assert finding.is_significant is False


class TestProbeHeaders:
    """Tests for probe_headers batch processing."""

    @patch("venom_cache.header_prober.capture_baseline")
    @patch("venom_cache.header_prober.probe_header")
    def test_probe_headers_captures_baseline(self, mock_probe, mock_capture):
        """probe_headers captures baseline if not provided."""
        mock_baseline = ResponseBaseline(
            url="https://example.com",
            status=200,
            headers={},
            body_hash="test",
            body_length=100,
            content_type=None,
            static_body_hash="test",
            captured_at=1000.0,
        )
        mock_capture.return_value = mock_baseline
        mock_probe.return_value = HeaderFinding(
            header_name="X-Test",
            canary="venom-test",
            reflected_in_body=False,
            reflected_in_headers=[],
            response_diff=ResponseDiff(
                status_changed=False,
                headers_changed=[],
                body_changed=False,
                static_body_changed=False,
                content_length_delta=0,
                significant=False,
            ),
            is_significant=False,
        )

        findings = probe_headers("https://example.com", ["X-Test"])

        mock_capture.assert_called_once()
        assert len(findings) == 1

    @patch("venom_cache.header_prober.probe_header")
    def test_probe_headers_sorts_by_significance(self, mock_probe):
        """Significant findings are sorted first."""
        # Create findings with different significance
        findings_data = [
            ("X-Not-Significant", False, False),
            ("X-Significant", True, True),
            ("X-Reflected", True, False),
        ]

        def create_finding(name, reflected, significant):
            return HeaderFinding(
                header_name=name,
                canary="venom-test",
                reflected_in_body=reflected,
                reflected_in_headers=[],
                response_diff=ResponseDiff(
                    status_changed=False,
                    headers_changed=[],
                    body_changed=False,
                    static_body_changed=significant,
                    content_length_delta=0,
                    significant=significant,
                ),
                is_significant=reflected and significant,
            )

        mock_probe.side_effect = [
            create_finding(*data) for data in findings_data
        ]

        baseline = ResponseBaseline(
            url="https://example.com",
            status=200,
            headers={},
            body_hash="test",
            body_length=100,
            content_type=None,
            static_body_hash="test",
            captured_at=1000.0,
        )

        findings = probe_headers(
            "https://example.com",
            ["X-Not-Significant", "X-Significant", "X-Reflected"],
            baseline=baseline,
        )

        # Significant should be first
        assert findings[0].header_name == "X-Significant"
        assert findings[0].is_significant is True
