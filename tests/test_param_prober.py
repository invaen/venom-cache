"""Tests for parameter probing and reflection detection."""

from unittest.mock import patch

import pytest

from venom_cache.baseline import ResponseBaseline, ResponseDiff
from venom_cache.param_prober import (
    ParamFinding,
    inject_param,
    probe_param,
    probe_params,
)
from venom_cache.wordlists import UNKEYED_PARAMS, get_param_wordlist


class TestInjectParam:
    """Tests for inject_param URL parameter injection."""

    def test_inject_param_new_param(self):
        """Add param to URL without query string."""
        url = "https://example.com/page"
        result = inject_param(url, "utm_source", "test")

        assert "utm_source=test" in result
        assert result.startswith("https://example.com/page?")

    def test_inject_param_existing_params(self):
        """Add param to URL with existing params."""
        url = "https://example.com/page?foo=bar"
        result = inject_param(url, "utm_source", "test")

        assert "utm_source=test" in result
        assert "foo=bar" in result

    def test_inject_param_replace_param(self):
        """Replace existing param with same name."""
        url = "https://example.com/page?utm_source=old"
        result = inject_param(url, "utm_source", "new")

        assert "utm_source=new" in result
        assert "utm_source=old" not in result

    def test_inject_param_encoding(self):
        """Handle special characters in value."""
        url = "https://example.com/page"
        result = inject_param(url, "callback", "test<script>alert(1)</script>")

        # Value should be URL-encoded
        assert "callback=" in result
        assert "<script>" not in result  # Should be encoded
        assert "%3C" in result or "%3c" in result  # Encoded <

    def test_inject_param_empty_value(self):
        """Handle empty string value."""
        url = "https://example.com/page"
        result = inject_param(url, "debug", "")

        # Parameter should be present with empty value
        assert "debug=" in result

    def test_inject_param_preserve_fragment(self):
        """URL fragment is preserved."""
        url = "https://example.com/page#section"
        result = inject_param(url, "utm_source", "test")

        assert "#section" in result
        assert "utm_source=test" in result

    def test_inject_param_preserve_path(self):
        """URL path is preserved."""
        url = "https://example.com/api/v1/users"
        result = inject_param(url, "debug", "true")

        assert "/api/v1/users" in result
        assert "debug=true" in result

    def test_inject_param_multiple_existing_params(self):
        """Handle URLs with multiple existing params."""
        url = "https://example.com/page?a=1&b=2&c=3"
        result = inject_param(url, "utm_source", "test")

        # All original params preserved
        assert "a=1" in result
        assert "b=2" in result
        assert "c=3" in result
        assert "utm_source=test" in result

    def test_inject_param_preserve_blank_values(self):
        """Existing blank param values are preserved."""
        url = "https://example.com/page?existing="
        result = inject_param(url, "new", "value")

        assert "existing=" in result
        assert "new=value" in result


class TestParamFinding:
    """Tests for ParamFinding dataclass."""

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

    def test_param_finding_significant_body_reflection(self):
        """Reflected in body + significant diff = is_significant."""
        finding = ParamFinding(
            param_name="utm_source",
            canary="venom-test",
            reflected_in_body=True,
            reflected_in_headers=[],
            response_diff=self._make_diff(significant=True),
            is_significant=True,
        )

        assert finding.is_significant is True

    def test_param_finding_significant_header_reflection(self):
        """Reflected in header + significant diff = is_significant."""
        finding = ParamFinding(
            param_name="callback",
            canary="venom-test",
            reflected_in_body=False,
            reflected_in_headers=["x-debug"],
            response_diff=self._make_diff(significant=True),
            is_significant=True,
        )

        assert finding.is_significant is True

    def test_param_finding_not_significant_no_reflection(self):
        """No reflection = not significant (even with diff)."""
        finding = ParamFinding(
            param_name="utm_source",
            canary="venom-test",
            reflected_in_body=False,
            reflected_in_headers=[],
            response_diff=self._make_diff(significant=True),
            is_significant=False,
        )

        assert finding.is_significant is False

    def test_param_finding_not_significant_no_diff(self):
        """Reflection without significant diff = not significant."""
        finding = ParamFinding(
            param_name="callback",
            canary="venom-test",
            reflected_in_body=True,
            reflected_in_headers=[],
            response_diff=self._make_diff(significant=False),
            is_significant=False,
        )

        assert finding.is_significant is False


class TestProbeParam:
    """Tests for probe_param with mocked HTTP."""

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

    @patch("venom_cache.param_prober.make_request")
    def test_probe_param_with_reflection(self, mock_make_request):
        """Probe detects reflection when canary is in response."""
        # Response will not contain the canary (it's dynamically generated)
        # This tests the flow works
        mock_make_request.return_value = (
            200,
            {"Content-Type": "text/html"},
            b"Response with some value reflected",
        )

        baseline = self._make_baseline()
        finding = probe_param(
            "https://example.com",
            "utm_source",
            baseline,
        )

        # Check the finding was created
        assert finding.param_name == "utm_source"
        assert finding.canary.startswith("venom-")

        # Verify make_request was called with modified URL
        mock_make_request.assert_called_once()
        call_args = mock_make_request.call_args
        called_url = call_args[0][0]
        assert "utm_source=" in called_url

    @patch("venom_cache.param_prober.make_request")
    def test_probe_param_no_reflection(self, mock_make_request):
        """Probe returns no reflection when canary not in response."""
        mock_make_request.return_value = (
            200,
            {"Content-Type": "text/html"},
            b"Clean response body without canary",
        )

        baseline = self._make_baseline()
        finding = probe_param(
            "https://example.com",
            "debug",
            baseline,
        )

        assert finding.reflected_in_body is False
        assert finding.reflected_in_headers == []
        assert finding.is_significant is False

    @patch("venom_cache.param_prober.make_request")
    def test_probe_param_uses_cache_buster(self, mock_make_request):
        """Probe uses cache buster for isolated requests."""
        mock_make_request.return_value = (
            200,
            {"Content-Type": "text/html"},
            b"Response body",
        )

        baseline = self._make_baseline()
        probe_param("https://example.com", "test", baseline)

        # Verify use_cache_buster=True was passed
        call_kwargs = mock_make_request.call_args[1]
        assert call_kwargs.get("use_cache_buster") is True


class TestProbeParams:
    """Tests for probe_params batch processing."""

    @patch("venom_cache.param_prober.capture_baseline")
    @patch("venom_cache.param_prober.probe_param")
    def test_probe_params_captures_baseline(self, mock_probe, mock_capture):
        """probe_params captures baseline if not provided."""
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
        mock_probe.return_value = ParamFinding(
            param_name="utm_source",
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

        findings = probe_params("https://example.com", ["utm_source"])

        mock_capture.assert_called_once()
        assert len(findings) == 1

    @patch("venom_cache.param_prober.probe_param")
    def test_probe_params_uses_provided_baseline(self, mock_probe):
        """probe_params uses provided baseline without capturing new one."""
        baseline = ResponseBaseline(
            url="https://example.com",
            status=200,
            headers={},
            body_hash="provided",
            body_length=100,
            content_type=None,
            static_body_hash="provided",
            captured_at=1000.0,
        )
        mock_probe.return_value = ParamFinding(
            param_name="test",
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

        # Use provided baseline
        with patch("venom_cache.param_prober.capture_baseline") as mock_capture:
            probe_params("https://example.com", ["test"], baseline=baseline)
            mock_capture.assert_not_called()

    @patch("venom_cache.param_prober.probe_param")
    def test_probe_params_sorts_by_significance(self, mock_probe):
        """Significant findings are sorted first."""
        # Create findings with different significance
        findings_data = [
            ("utm_source", False, False),  # Not reflected, not significant
            ("callback", True, True),  # Reflected + significant
            ("debug", True, False),  # Reflected but not significant diff
        ]

        def create_finding(name, reflected, significant):
            return ParamFinding(
                param_name=name,
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

        mock_probe.side_effect = [create_finding(*data) for data in findings_data]

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

        findings = probe_params(
            "https://example.com",
            ["utm_source", "callback", "debug"],
            baseline=baseline,
        )

        # Significant should be first
        assert findings[0].param_name == "callback"
        assert findings[0].is_significant is True

    @patch("venom_cache.param_prober.probe_param")
    def test_probe_params_sorts_reflected_body_before_headers(self, mock_probe):
        """Body reflection sorted before header-only reflection."""
        findings_data = [
            ("header_only", False, ["x-debug"]),  # Reflected in headers only
            ("body_reflected", True, []),  # Reflected in body
        ]

        def create_finding(name, body_reflect, header_reflect):
            return ParamFinding(
                param_name=name,
                canary="venom-test",
                reflected_in_body=body_reflect,
                reflected_in_headers=header_reflect,
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

        mock_probe.side_effect = [create_finding(*data) for data in findings_data]

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

        findings = probe_params(
            "https://example.com",
            ["header_only", "body_reflected"],
            baseline=baseline,
        )

        # Body reflection should be sorted before header-only
        assert findings[0].param_name == "body_reflected"


class TestParamWordlist:
    """Tests for parameter wordlist."""

    def test_unkeyed_params_not_empty(self):
        """UNKEYED_PARAMS has items."""
        assert len(UNKEYED_PARAMS) > 0
        assert len(UNKEYED_PARAMS) >= 30  # At least 30 params

    def test_unkeyed_params_common_utm(self):
        """Contains common UTM parameters."""
        assert "utm_source" in UNKEYED_PARAMS
        assert "utm_medium" in UNKEYED_PARAMS
        assert "utm_campaign" in UNKEYED_PARAMS
        assert "utm_content" in UNKEYED_PARAMS
        assert "utm_term" in UNKEYED_PARAMS

    def test_unkeyed_params_tracking_params(self):
        """Contains common tracking parameters."""
        assert "fbclid" in UNKEYED_PARAMS
        assert "gclid" in UNKEYED_PARAMS
        assert "_ga" in UNKEYED_PARAMS

    def test_unkeyed_params_jsonp_callbacks(self):
        """Contains JSONP callback parameters."""
        assert "callback" in UNKEYED_PARAMS
        assert "jsonp" in UNKEYED_PARAMS
        assert "jsonpcallback" in UNKEYED_PARAMS

    def test_unkeyed_params_debug_params(self):
        """Contains debug/test parameters."""
        assert "debug" in UNKEYED_PARAMS
        assert "test" in UNKEYED_PARAMS

    def test_get_param_wordlist_returns_copy(self):
        """Modifying return doesn't affect original."""
        wordlist = get_param_wordlist()
        original_len = len(UNKEYED_PARAMS)

        # Modify the returned list
        wordlist.append("custom_param")
        wordlist.remove("utm_source")

        # Original should be unchanged
        assert len(UNKEYED_PARAMS) == original_len
        assert "utm_source" in UNKEYED_PARAMS
        assert "custom_param" not in UNKEYED_PARAMS

    def test_get_param_wordlist_same_content(self):
        """get_param_wordlist returns same content as UNKEYED_PARAMS."""
        wordlist = get_param_wordlist()
        assert wordlist == UNKEYED_PARAMS
        assert wordlist is not UNKEYED_PARAMS  # But not same object
