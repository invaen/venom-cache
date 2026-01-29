"""Tests for WCD (Web Cache Deception) probing module."""

import pytest

from venom_cache.wcd_prober import (
    WcdFinding,
    build_confused_urls,
    is_likely_cache_hit,
)


class TestWcdFinding:
    """Tests for WcdFinding dataclass."""

    def test_create_finding(self):
        """Test creating a WCD finding."""
        finding = WcdFinding(
            confused_path="/account;foo.css",
            delimiter=";",
            extension=".css",
            first_request_cached=True,
            second_request_hit=True,
            content_matches_baseline=True,
            is_significant=True,
        )
        assert finding.confused_path == "/account;foo.css"
        assert finding.delimiter == ";"
        assert finding.extension == ".css"
        assert finding.first_request_cached is True
        assert finding.second_request_hit is True
        assert finding.content_matches_baseline is True
        assert finding.is_significant is True

    def test_finding_not_significant(self):
        """Test finding that's not significant (no cache hit)."""
        finding = WcdFinding(
            confused_path="/account;foo.css",
            delimiter=";",
            extension=".css",
            first_request_cached=False,
            second_request_hit=False,
            content_matches_baseline=True,
            is_significant=False,
        )
        assert finding.is_significant is False

    def test_finding_cached_but_different_content(self):
        """Test finding that's cached but content doesn't match baseline."""
        finding = WcdFinding(
            confused_path="/account%00foo.js",
            delimiter="%00",
            extension=".js",
            first_request_cached=True,
            second_request_hit=True,
            content_matches_baseline=False,
            is_significant=False,
        )
        assert finding.second_request_hit is True
        assert finding.content_matches_baseline is False
        assert finding.is_significant is False


class TestBuildConfusedUrls:
    """Tests for build_confused_urls function."""

    def test_basic_url_confusion(self):
        """Test generating confused URLs from a basic URL."""
        results = build_confused_urls(
            "https://example.com/account",
            delimiters=[";", "%00"],
            extensions=[".css", ".js"],
        )

        # Should generate 2 delimiters x 2 extensions = 4 combinations
        assert len(results) == 4

        # Each result is (url, delimiter, extension)
        for confused_url, delimiter, extension in results:
            assert delimiter in [";", "%00"]
            assert extension in [".css", ".js"]
            assert "example.com" in confused_url
            assert "/account" in confused_url

    def test_preserves_scheme_and_host(self):
        """Test that scheme and host are preserved."""
        results = build_confused_urls(
            "https://secure.example.com:8443/api/user",
            delimiters=[";"],
            extensions=[".css"],
        )

        assert len(results) == 1
        confused_url, _, _ = results[0]
        assert "https://" in confused_url
        assert "secure.example.com:8443" in confused_url

    def test_preserves_query_string(self):
        """Test that query string is preserved."""
        results = build_confused_urls(
            "https://example.com/profile?id=123",
            delimiters=[";"],
            extensions=[".css"],
        )

        assert len(results) == 1
        confused_url, _, _ = results[0]
        assert "id=123" in confused_url

    def test_handles_root_path(self):
        """Test handling URLs with root path only."""
        results = build_confused_urls(
            "https://example.com/",
            delimiters=[";"],
            extensions=[".css"],
        )

        assert len(results) == 1
        confused_url, _, _ = results[0]
        # Should have path like /;cbXXXXXXXX.css
        assert ";cb" in confused_url
        assert ".css" in confused_url

    def test_handles_no_path(self):
        """Test handling URLs with no path."""
        results = build_confused_urls(
            "https://example.com",
            delimiters=[";"],
            extensions=[".js"],
        )

        assert len(results) == 1
        confused_url, _, _ = results[0]
        assert ".js" in confused_url

    def test_unique_suffix_per_url(self):
        """Test that each confused URL has a unique suffix."""
        results = build_confused_urls(
            "https://example.com/account",
            delimiters=[";"],
            extensions=[".css", ".js"],
        )

        urls = [url for url, _, _ in results]
        # All URLs should be unique (different cache busters)
        assert len(urls) == len(set(urls))

    def test_delimiter_extension_tracking(self):
        """Test that delimiter and extension are correctly tracked."""
        results = build_confused_urls(
            "https://example.com/page",
            delimiters=[";", "%00", "."],
            extensions=[".css", ".js", ".png"],
        )

        # 3 delimiters x 3 extensions = 9 combinations
        assert len(results) == 9

        # Verify each combination is correctly tracked
        delimiters_seen = set()
        extensions_seen = set()
        for _, delimiter, extension in results:
            delimiters_seen.add(delimiter)
            extensions_seen.add(extension)

        assert delimiters_seen == {";", "%00", "."}
        assert extensions_seen == {".css", ".js", ".png"}


class TestIsLikelyCacheHit:
    """Tests for is_likely_cache_hit function."""

    def test_x_cache_hit(self):
        """Test detection of X-Cache HIT."""
        headers = {"X-Cache": "HIT"}
        assert is_likely_cache_hit(headers) is True

    def test_x_cache_hit_from_cloudfront(self):
        """Test detection of CloudFront-style X-Cache HIT."""
        headers = {"X-Cache": "Hit from cloudfront"}
        assert is_likely_cache_hit(headers) is True

    def test_x_cache_miss(self):
        """Test X-Cache MISS is not a hit."""
        headers = {"X-Cache": "MISS"}
        assert is_likely_cache_hit(headers) is False

    def test_cf_cache_status_hit(self):
        """Test detection of Cloudflare CF-Cache-Status HIT."""
        headers = {"CF-Cache-Status": "HIT"}
        assert is_likely_cache_hit(headers) is True

    def test_cf_cache_status_miss(self):
        """Test CF-Cache-Status MISS is not a hit."""
        headers = {"CF-Cache-Status": "MISS"}
        assert is_likely_cache_hit(headers) is False

    def test_cf_cache_status_dynamic(self):
        """Test CF-Cache-Status DYNAMIC is not a hit."""
        headers = {"CF-Cache-Status": "DYNAMIC"}
        assert is_likely_cache_hit(headers) is False

    def test_x_cache_status_hit(self):
        """Test detection of Nginx X-Cache-Status HIT."""
        headers = {"X-Cache-Status": "HIT"}
        assert is_likely_cache_hit(headers) is True

    def test_x_cache_status_miss(self):
        """Test X-Cache-Status MISS is not a hit."""
        headers = {"X-Cache-Status": "MISS"}
        assert is_likely_cache_hit(headers) is False

    def test_age_header_positive(self):
        """Test that Age > 0 indicates cache hit."""
        headers = {"Age": "300"}
        assert is_likely_cache_hit(headers) is True

    def test_age_header_zero(self):
        """Test that Age = 0 is not a hit."""
        headers = {"Age": "0"}
        assert is_likely_cache_hit(headers) is False

    def test_age_header_invalid(self):
        """Test handling of invalid Age header."""
        headers = {"Age": "invalid"}
        assert is_likely_cache_hit(headers) is False

    def test_no_cache_headers(self):
        """Test response with no cache headers."""
        headers = {"Content-Type": "text/html"}
        assert is_likely_cache_hit(headers) is False

    def test_case_insensitive_headers(self):
        """Test case-insensitive header matching."""
        headers = {"x-cache": "HIT", "content-type": "text/html"}
        assert is_likely_cache_hit(headers) is True

    def test_multiple_cache_indicators(self):
        """Test response with multiple cache indicators."""
        headers = {
            "X-Cache": "HIT",
            "CF-Cache-Status": "HIT",
            "Age": "100",
        }
        assert is_likely_cache_hit(headers) is True


class TestProbeWcd:
    """Tests for probe_wcd function - integration tests."""

    def test_import_probe_wcd(self):
        """Test that probe_wcd can be imported."""
        from venom_cache.wcd_prober import probe_wcd

        assert callable(probe_wcd)

    def test_probe_wcd_signature(self):
        """Test probe_wcd function signature."""
        from venom_cache.wcd_prober import probe_wcd
        import inspect

        sig = inspect.signature(probe_wcd)
        params = list(sig.parameters.keys())
        assert "url" in params
        assert "baseline" in params
        assert "delimiters" in params
        assert "extensions" in params
        assert "timeout" in params
        assert "insecure" in params
