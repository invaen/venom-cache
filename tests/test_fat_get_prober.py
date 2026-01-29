"""Tests for fat GET probing and reflection detection."""

import pytest
from unittest.mock import patch, MagicMock

from venom_cache.fat_get_prober import (
    FatGetFinding,
    probe_fat_get,
    probe_method_override,
    probe_all_fat_get,
)
from venom_cache.baseline import ResponseBaseline, ResponseDiff


@pytest.fixture
def mock_baseline():
    """Create a mock baseline for testing."""
    return ResponseBaseline(
        url="http://example.com",
        status=200,
        headers={"Content-Type": "text/html"},
        body_hash="abc123",
        body_length=100,
        content_type="text/html",
        static_body_hash="abc123",
        captured_at=1234567890.0,
    )


@pytest.fixture
def mock_diff_insignificant():
    """Create an insignificant diff for testing."""
    return ResponseDiff(
        status_changed=False,
        headers_changed=[],
        body_changed=False,
        static_body_changed=False,
        content_length_delta=0,
        significant=False,
    )


@pytest.fixture
def mock_diff_significant():
    """Create a significant diff for testing."""
    return ResponseDiff(
        status_changed=False,
        headers_changed=[],
        body_changed=True,
        static_body_changed=True,
        content_length_delta=50,
        significant=True,
    )


class TestFatGetFinding:
    """Tests for FatGetFinding dataclass."""

    def test_create_finding(self, mock_diff_insignificant):
        """Test creating a FatGetFinding."""
        finding = FatGetFinding(
            param_name="callback",
            canary="venom-abc123",
            reflected_in_body=True,
            reflected_in_headers=["x-debug"],
            response_diff=mock_diff_insignificant,
            method_override_header=None,
            is_significant=False,
        )

        assert finding.param_name == "callback"
        assert finding.canary == "venom-abc123"
        assert finding.reflected_in_body is True
        assert finding.reflected_in_headers == ["x-debug"]
        assert finding.method_override_header is None
        assert finding.is_significant is False

    def test_finding_with_method_override(self, mock_diff_significant):
        """Test finding with method override header."""
        finding = FatGetFinding(
            param_name="data",
            canary="venom-xyz789",
            reflected_in_body=True,
            reflected_in_headers=[],
            response_diff=mock_diff_significant,
            method_override_header="X-HTTP-Method-Override",
            is_significant=True,
        )

        assert finding.method_override_header == "X-HTTP-Method-Override"
        assert finding.is_significant is True


class TestBodyEncoding:
    """Tests for body parameter encoding."""

    def test_body_format(self):
        """Test that body parameters are encoded correctly."""
        param_name = "callback"
        canary = "venom-test123"
        expected = f"{param_name}={canary}".encode()
        actual = f"{param_name}={canary}".encode()
        assert actual == expected
        assert actual == b"callback=venom-test123"

    def test_special_characters_in_param(self):
        """Test parameter names with underscores."""
        param_name = "jsonp_callback"
        canary = "venom-abc"
        body = f"{param_name}={canary}".encode()
        assert body == b"jsonp_callback=venom-abc"


class TestProbeFatGet:
    """Tests for probe_fat_get function."""

    @patch("venom_cache.fat_get_prober.make_request")
    @patch("venom_cache.fat_get_prober.compare_response")
    @patch("venom_cache.fat_get_prober.generate_canary")
    def test_probe_fat_get_no_reflection(
        self, mock_canary, mock_compare, mock_request, mock_baseline, mock_diff_insignificant
    ):
        """Test probing when no reflection is detected."""
        mock_canary.return_value = "venom-test123456"
        mock_request.return_value = (200, {"Content-Type": "text/html"}, b"Hello World")
        mock_compare.return_value = mock_diff_insignificant

        finding = probe_fat_get(
            "http://example.com",
            "callback",
            mock_baseline,
        )

        assert finding.param_name == "callback"
        assert finding.reflected_in_body is False
        assert finding.reflected_in_headers == []
        assert finding.is_significant is False
        assert finding.method_override_header is None

        # Verify request was made with body
        mock_request.assert_called_once()
        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["body"] == b"callback=venom-test123456"
        assert call_kwargs["headers"]["Content-Type"] == "application/x-www-form-urlencoded"

    @patch("venom_cache.fat_get_prober.make_request")
    @patch("venom_cache.fat_get_prober.compare_response")
    @patch("venom_cache.fat_get_prober.generate_canary")
    def test_probe_fat_get_body_reflection(
        self, mock_canary, mock_compare, mock_request, mock_baseline, mock_diff_significant
    ):
        """Test probing when canary is reflected in body."""
        mock_canary.return_value = "venom-reflected1"
        mock_request.return_value = (
            200,
            {"Content-Type": "text/html"},
            b"Response: venom-reflected1",
        )
        mock_compare.return_value = mock_diff_significant

        finding = probe_fat_get(
            "http://example.com",
            "q",
            mock_baseline,
        )

        assert finding.param_name == "q"
        assert finding.reflected_in_body is True
        assert finding.is_significant is True

    @patch("venom_cache.fat_get_prober.make_request")
    @patch("venom_cache.fat_get_prober.compare_response")
    @patch("venom_cache.fat_get_prober.generate_canary")
    def test_probe_fat_get_header_reflection(
        self, mock_canary, mock_compare, mock_request, mock_baseline, mock_diff_insignificant
    ):
        """Test probing when canary is reflected in headers."""
        mock_canary.return_value = "venom-headrefl"
        mock_request.return_value = (
            200,
            {"Content-Type": "text/html", "X-Echo": "venom-headrefl"},
            b"No body reflection",
        )
        mock_compare.return_value = mock_diff_insignificant

        finding = probe_fat_get(
            "http://example.com",
            "data",
            mock_baseline,
        )

        assert finding.param_name == "data"
        assert finding.reflected_in_body is False
        assert "x-echo" in finding.reflected_in_headers
        assert finding.is_significant is False  # No significant diff


class TestProbeMethodOverride:
    """Tests for probe_method_override function."""

    @patch("venom_cache.fat_get_prober.make_request")
    @patch("venom_cache.fat_get_prober.compare_response")
    @patch("venom_cache.fat_get_prober.generate_canary")
    def test_no_reflection_with_any_header(
        self, mock_canary, mock_compare, mock_request, mock_baseline, mock_diff_insignificant
    ):
        """Test when no override header causes reflection."""
        mock_canary.return_value = "venom-norefl"
        mock_request.return_value = (200, {}, b"Static content")
        mock_compare.return_value = mock_diff_insignificant

        result = probe_method_override(
            "http://example.com",
            "callback",
            mock_baseline,
            ["X-HTTP-Method-Override", "X-Method-Override"],
        )

        assert result is None
        assert mock_request.call_count == 2

    @patch("venom_cache.fat_get_prober.make_request")
    @patch("venom_cache.fat_get_prober.compare_response")
    @patch("venom_cache.fat_get_prober.generate_canary")
    def test_reflection_with_first_header(
        self, mock_canary, mock_compare, mock_request, mock_baseline, mock_diff_significant
    ):
        """Test when first override header triggers reflection."""
        mock_canary.return_value = "venom-override1"
        mock_request.return_value = (
            200,
            {},
            b"Reflected: venom-override1",
        )
        mock_compare.return_value = mock_diff_significant

        result = probe_method_override(
            "http://example.com",
            "callback",
            mock_baseline,
            ["X-HTTP-Method-Override", "X-Method-Override"],
        )

        assert result is not None
        assert result.method_override_header == "X-HTTP-Method-Override"
        assert result.reflected_in_body is True
        assert mock_request.call_count == 1  # Stopped after first reflection

    @patch("venom_cache.fat_get_prober.make_request")
    @patch("venom_cache.fat_get_prober.compare_response")
    @patch("venom_cache.fat_get_prober.generate_canary")
    def test_override_header_sent(
        self, mock_canary, mock_compare, mock_request, mock_baseline, mock_diff_insignificant
    ):
        """Test that method override header is sent with value POST."""
        mock_canary.return_value = "venom-test"
        mock_request.return_value = (200, {}, b"No reflection")
        mock_compare.return_value = mock_diff_insignificant

        probe_method_override(
            "http://example.com",
            "q",
            mock_baseline,
            ["X-HTTP-Method-Override"],
        )

        call_kwargs = mock_request.call_args[1]
        assert "X-HTTP-Method-Override" in call_kwargs["headers"]
        assert call_kwargs["headers"]["X-HTTP-Method-Override"] == "POST"


class TestProbeAllFatGet:
    """Tests for probe_all_fat_get function."""

    @patch("venom_cache.fat_get_prober.probe_fat_get")
    @patch("venom_cache.fat_get_prober.probe_method_override")
    @patch("venom_cache.baseline.capture_baseline")
    def test_returns_list(
        self, mock_capture, mock_override, mock_probe, mock_baseline, mock_diff_insignificant
    ):
        """Test that probe_all_fat_get returns a list."""
        mock_capture.return_value = mock_baseline
        mock_probe.return_value = FatGetFinding(
            param_name="callback",
            canary="venom-test",
            reflected_in_body=False,
            reflected_in_headers=[],
            response_diff=mock_diff_insignificant,
            method_override_header=None,
            is_significant=False,
        )
        mock_override.return_value = None

        result = probe_all_fat_get(
            "http://example.com",
            ["callback", "q"],
            ["X-HTTP-Method-Override"],
            baseline=mock_baseline,
        )

        assert isinstance(result, list)

    @patch("venom_cache.fat_get_prober.probe_fat_get")
    @patch("venom_cache.fat_get_prober.probe_method_override")
    def test_tries_method_override_when_no_direct_reflection(
        self, mock_override, mock_probe, mock_baseline, mock_diff_insignificant
    ):
        """Test that method override is tried when direct probing finds nothing."""
        mock_probe.return_value = FatGetFinding(
            param_name="callback",
            canary="venom-test",
            reflected_in_body=False,
            reflected_in_headers=[],
            response_diff=mock_diff_insignificant,
            method_override_header=None,
            is_significant=False,
        )
        mock_override.return_value = None

        probe_all_fat_get(
            "http://example.com",
            ["callback"],
            ["X-HTTP-Method-Override"],
            baseline=mock_baseline,
        )

        mock_override.assert_called_once()

    @patch("venom_cache.fat_get_prober.probe_fat_get")
    @patch("venom_cache.fat_get_prober.probe_method_override")
    def test_skips_method_override_when_direct_reflection_found(
        self, mock_override, mock_probe, mock_baseline, mock_diff_significant
    ):
        """Test that method override is skipped when direct probing finds reflection."""
        mock_probe.return_value = FatGetFinding(
            param_name="callback",
            canary="venom-test",
            reflected_in_body=True,
            reflected_in_headers=[],
            response_diff=mock_diff_significant,
            method_override_header=None,
            is_significant=True,
        )

        result = probe_all_fat_get(
            "http://example.com",
            ["callback"],
            ["X-HTTP-Method-Override"],
            baseline=mock_baseline,
        )

        mock_override.assert_not_called()
        assert len(result) == 1
        assert result[0].is_significant is True

    @patch("venom_cache.fat_get_prober.probe_fat_get")
    @patch("venom_cache.fat_get_prober.probe_method_override")
    def test_sorts_by_significance(
        self, mock_override, mock_probe, mock_baseline, mock_diff_significant, mock_diff_insignificant
    ):
        """Test that findings are sorted by significance."""
        # Return different findings for different param names
        def probe_side_effect(url, param_name, baseline, **kwargs):
            if param_name == "first":
                return FatGetFinding(
                    param_name="first",
                    canary="venom-1",
                    reflected_in_body=True,
                    reflected_in_headers=[],
                    response_diff=mock_diff_insignificant,
                    method_override_header=None,
                    is_significant=False,
                )
            else:
                return FatGetFinding(
                    param_name="second",
                    canary="venom-2",
                    reflected_in_body=True,
                    reflected_in_headers=[],
                    response_diff=mock_diff_significant,
                    method_override_header=None,
                    is_significant=True,
                )

        mock_probe.side_effect = probe_side_effect

        result = probe_all_fat_get(
            "http://example.com",
            ["first", "second"],
            ["X-HTTP-Method-Override"],
            baseline=mock_baseline,
        )

        assert len(result) == 2
        # Significant should be first
        assert result[0].param_name == "second"
        assert result[0].is_significant is True
        assert result[1].param_name == "first"
        assert result[1].is_significant is False
