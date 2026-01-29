"""Tests for cache detection from response headers."""

import pytest

from venom_cache.cache_detector import CacheStatus, detect_cache_headers, get_cache_info


class TestCloudflareDetection:
    """Tests for Cloudflare cache header parsing."""

    def test_cf_cache_hit(self):
        headers = {"CF-Cache-Status": "HIT"}
        status = detect_cache_headers(headers)
        assert status.detected is True
        assert status.hit is True
        assert status.provider == "cloudflare"

    def test_cf_cache_miss(self):
        headers = {"CF-Cache-Status": "MISS"}
        status = detect_cache_headers(headers)
        assert status.detected is True
        assert status.hit is False
        assert status.provider == "cloudflare"

    def test_cf_cache_dynamic(self):
        headers = {"CF-Cache-Status": "DYNAMIC"}
        status = detect_cache_headers(headers)
        assert status.detected is True
        assert status.hit is False  # Not cached
        assert status.provider == "cloudflare"

    def test_cf_cache_bypass(self):
        headers = {"CF-Cache-Status": "BYPASS"}
        status = detect_cache_headers(headers)
        assert status.detected is True
        assert status.hit is False
        assert status.provider == "cloudflare"


class TestVarnishDetection:
    """Tests for Varnish cache header parsing."""

    def test_varnish_single_id_miss(self):
        headers = {"X-Varnish": "123456"}
        status = detect_cache_headers(headers)
        assert status.detected is True
        assert status.hit is False  # Single ID = miss
        assert status.provider == "varnish"

    def test_varnish_two_ids_hit(self):
        headers = {"X-Varnish": "123456 789012"}
        status = detect_cache_headers(headers)
        assert status.detected is True
        assert status.hit is True  # Two IDs = hit
        assert status.provider == "varnish"


class TestAgeHeader:
    """Tests for Age header parsing."""

    def test_age_zero_miss(self):
        headers = {"Age": "0"}
        status = detect_cache_headers(headers)
        assert status.detected is True
        assert status.hit is False  # Just cached
        assert status.age == 0

    def test_age_positive_hit(self):
        headers = {"Age": "300"}
        status = detect_cache_headers(headers)
        assert status.detected is True
        assert status.hit is True  # Served from cache
        assert status.age == 300


class TestGenericXCache:
    """Tests for generic X-Cache header parsing."""

    def test_x_cache_hit(self):
        headers = {"X-Cache": "HIT"}
        status = detect_cache_headers(headers)
        assert status.detected is True
        assert status.hit is True

    def test_x_cache_miss(self):
        headers = {"X-Cache": "MISS"}
        status = detect_cache_headers(headers)
        assert status.detected is True
        assert status.hit is False

    def test_x_cache_hit_from_cloudfront(self):
        headers = {"X-Cache": "HIT from cloudfront"}
        status = detect_cache_headers(headers)
        assert status.detected is True
        assert status.hit is True
        assert status.provider == "cloudfront"

    def test_x_cache_case_insensitive(self):
        headers = {"x-cache": "hit"}
        status = detect_cache_headers(headers)
        assert status.detected is True
        assert status.hit is True


class TestNoCacheHeaders:
    """Tests for responses without cache headers."""

    def test_empty_headers(self):
        headers = {}
        status = detect_cache_headers(headers)
        assert status.detected is False
        assert status.hit is None

    def test_only_content_headers(self):
        headers = {"Content-Type": "text/html", "Content-Length": "1234"}
        status = detect_cache_headers(headers)
        assert status.detected is False
        assert status.hit is None


class TestCombinedHeaders:
    """Tests for responses with multiple cache headers."""

    def test_cf_with_age(self):
        headers = {"CF-Cache-Status": "HIT", "Age": "300"}
        status = detect_cache_headers(headers)
        assert status.detected is True
        assert status.provider == "cloudflare"
        assert status.age == 300
        assert len(status.evidence) == 2


class TestGetCacheInfo:
    """Tests for human-readable cache info."""

    def test_not_detected(self):
        headers = {}
        info = get_cache_info(headers)
        assert info == "Cache: Not detected"

    def test_detected_hit_with_provider(self):
        headers = {"CF-Cache-Status": "HIT", "Age": "300"}
        info = get_cache_info(headers)
        assert "Cache: Detected" in info
        assert "cloudflare" in info
        assert "HIT" in info
        assert "Age: 300s" in info

    def test_detected_miss(self):
        headers = {"X-Cache": "MISS"}
        info = get_cache_info(headers)
        assert "Cache: Detected" in info
        assert "MISS" in info
