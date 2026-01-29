"""Cache detection from HTTP response headers."""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class CacheStatus:
    """Cache detection result from response headers."""

    detected: bool
    hit: Optional[bool] = None  # True=HIT, False=MISS, None=unknown
    provider: Optional[str] = None
    age: Optional[int] = None
    evidence: List[str] = field(default_factory=list)


def _parse_x_cache(value: str) -> tuple[Optional[bool], Optional[str]]:
    """Parse generic X-Cache header."""
    value_lower = value.lower()
    if "hit" in value_lower:
        # Extract provider from "HIT from cloudfront" pattern
        provider = None
        if " from " in value_lower:
            provider = value_lower.split(" from ")[-1].strip()
        return (True, provider)
    if "miss" in value_lower:
        return (False, None)
    return (None, None)


def _parse_cf_cache(value: str) -> tuple[Optional[bool], str]:
    """Parse Cloudflare CF-Cache-Status header."""
    value_upper = value.upper()
    if value_upper == "HIT":
        return (True, "cloudflare")
    if value_upper in ("MISS", "EXPIRED", "STALE", "UPDATING", "REVALIDATED"):
        return (False, "cloudflare")
    if value_upper in ("DYNAMIC", "BYPASS"):
        return (False, "cloudflare")  # Not cached
    return (None, "cloudflare")


def _parse_varnish(value: str) -> tuple[Optional[bool], str]:
    """Parse Varnish X-Varnish header.

    Single ID = MISS (first request)
    Two IDs = HIT (second ID is from cache)
    """
    parts = value.split()
    if len(parts) >= 2:
        return (True, "varnish")
    return (False, "varnish")


def _parse_nginx_cache(value: str) -> tuple[Optional[bool], str]:
    """Parse Nginx X-Cache-Status header."""
    value_upper = value.upper()
    if value_upper == "HIT":
        return (True, "nginx")
    if value_upper in ("MISS", "BYPASS", "EXPIRED", "STALE", "UPDATING"):
        return (False, "nginx")
    return (None, "nginx")


def _parse_age(value: str) -> tuple[Optional[bool], Optional[int]]:
    """Parse Age header."""
    try:
        age = int(value)
        # Age > 0 means served from cache
        return (age > 0, age)
    except ValueError:
        return (None, None)


def _parse_cache_control(value: str) -> tuple[bool, None]:
    """Parse Cache-Control header for cacheability."""
    value_lower = value.lower()
    # These indicate caching is configured
    cacheable_directives = ["max-age", "s-maxage", "public"]
    for directive in cacheable_directives:
        if directive in value_lower:
            return (True, None)  # Cache configured, but can't determine hit/miss
    return (False, None)


def detect_cache_headers(headers: Dict[str, str]) -> CacheStatus:
    """Detect cache presence and status from response headers.

    Args:
        headers: Response headers dict (case-insensitive matching applied)

    Returns:
        CacheStatus with detection results
    """
    # Normalize header names to lowercase for matching
    headers_lower = {k.lower(): v for k, v in headers.items()}

    evidence = []
    detected = False
    hit: Optional[bool] = None
    provider: Optional[str] = None
    age: Optional[int] = None

    # Check CDN-specific headers first (most reliable)

    # Cloudflare
    if "cf-cache-status" in headers_lower:
        val = headers_lower["cf-cache-status"]
        evidence.append(f"CF-Cache-Status: {val}")
        h, p = _parse_cf_cache(val)
        detected = True
        if hit is None:
            hit = h
        provider = p

    # Varnish
    if "x-varnish" in headers_lower:
        val = headers_lower["x-varnish"]
        evidence.append(f"X-Varnish: {val}")
        h, p = _parse_varnish(val)
        detected = True
        if hit is None:
            hit = h
        if provider is None:
            provider = p

    # Nginx
    if "x-cache-status" in headers_lower:
        val = headers_lower["x-cache-status"]
        evidence.append(f"X-Cache-Status: {val}")
        h, p = _parse_nginx_cache(val)
        detected = True
        if hit is None:
            hit = h
        if provider is None:
            provider = p

    # Generic X-Cache (CloudFront, generic caches)
    if "x-cache" in headers_lower:
        val = headers_lower["x-cache"]
        evidence.append(f"X-Cache: {val}")
        h, p = _parse_x_cache(val)
        detected = True
        if hit is None:
            hit = h
        if provider is None and p:
            provider = p

    # Age header (standard)
    if "age" in headers_lower:
        val = headers_lower["age"]
        evidence.append(f"Age: {val}")
        h, a = _parse_age(val)
        detected = True
        age = a
        if hit is None:
            hit = h

    # Cache-Control (indicates caching configured)
    if "cache-control" in headers_lower:
        val = headers_lower["cache-control"]
        is_cacheable, _ = _parse_cache_control(val)
        if is_cacheable:
            evidence.append(f"Cache-Control: {val}")
            detected = True

    # Via header (proxy chain)
    if "via" in headers_lower:
        val = headers_lower["via"]
        # Via often reveals CDN/proxy presence
        if any(cdn in val.lower() for cdn in ["varnish", "cloudfront", "akamai", "fastly"]):
            evidence.append(f"Via: {val}")
            detected = True

    # X-Served-By (Fastly)
    if "x-served-by" in headers_lower:
        val = headers_lower["x-served-by"]
        evidence.append(f"X-Served-By: {val}")
        detected = True
        if provider is None:
            provider = "fastly"

    # X-Cache-Hits
    if "x-cache-hits" in headers_lower:
        val = headers_lower["x-cache-hits"]
        evidence.append(f"X-Cache-Hits: {val}")
        detected = True
        try:
            hits = int(val)
            if hits > 0 and hit is None:
                hit = True
        except ValueError:
            pass

    return CacheStatus(
        detected=detected,
        hit=hit,
        provider=provider,
        age=age,
        evidence=evidence,
    )


def get_cache_info(headers: Dict[str, str]) -> str:
    """Get human-readable cache status summary.

    Args:
        headers: Response headers dict

    Returns:
        Formatted string like "Cache: Detected (cloudflare) - HIT (Age: 300s)"
    """
    status = detect_cache_headers(headers)

    if not status.detected:
        return "Cache: Not detected"

    parts = ["Cache: Detected"]

    if status.provider:
        parts.append(f"({status.provider})")

    if status.hit is True:
        parts.append("- HIT")
    elif status.hit is False:
        parts.append("- MISS")
    else:
        parts.append("- status unknown")

    if status.age is not None:
        parts.append(f"(Age: {status.age}s)")

    return " ".join(parts)
