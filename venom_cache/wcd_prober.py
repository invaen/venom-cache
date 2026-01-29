"""Web Cache Deception probing for path confusion vulnerabilities."""

import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

from venom_cache.baseline import ResponseBaseline, compare_response
from venom_cache.cache_detector import detect_cache_headers
from venom_cache.http_transport import make_request


@dataclass
class WcdFinding:
    """Result of probing for web cache deception vulnerability."""

    confused_path: str  # Full confused path tested
    delimiter: str  # Delimiter used (;, %00, etc.)
    extension: str  # Extension used (.css, .js, etc.)
    first_request_cached: bool  # Was first request a cache miss then stored?
    second_request_hit: bool  # Did second request get cache hit?
    content_matches_baseline: bool  # Does cached content match original?
    is_significant: bool  # True if cached AND content matches (vulnerable)


def build_confused_urls(
    base_url: str,
    delimiters: List[str],
    extensions: List[str],
) -> List[Tuple[str, str, str]]:
    """Generate path-confused URLs for WCD testing.

    Args:
        base_url: Original URL to confuse
        delimiters: Path delimiters to test
        extensions: Static extensions to append

    Returns:
        List of (confused_url, delimiter, extension) tuples
    """
    parsed = urlparse(base_url)
    base_path = parsed.path or "/"

    results = []
    for delimiter in delimiters:
        for extension in extensions:
            # Generate unique suffix to avoid cache key collision between tests
            unique_suffix = uuid.uuid4().hex[:8]

            # Build confused path: {base_path}{delimiter}cb{unique}{extension}
            confused_path = f"{base_path}{delimiter}cb{unique_suffix}{extension}"

            # Reconstruct URL with confused path
            confused_parsed = parsed._replace(path=confused_path)
            confused_url = urlunparse(confused_parsed)

            results.append((confused_url, delimiter, extension))

    return results


def is_likely_cache_hit(headers: Dict[str, str]) -> bool:
    """Check if response headers indicate a cache hit.

    Simplified cache hit detection for WCD probing.

    Args:
        headers: Response headers dict

    Returns:
        True if any cache hit indicator found
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Check x-cache for "hit"
    x_cache = headers_lower.get("x-cache", "").lower()
    if "hit" in x_cache:
        return True

    # Check cf-cache-status for "HIT"
    cf_status = headers_lower.get("cf-cache-status", "").upper()
    if cf_status == "HIT":
        return True

    # Check x-cache-status for "HIT" (Nginx)
    x_cache_status = headers_lower.get("x-cache-status", "").upper()
    if x_cache_status == "HIT":
        return True

    # Check age > 0
    try:
        age = int(headers_lower.get("age", "0"))
        if age > 0:
            return True
    except ValueError:
        pass

    return False


def probe_wcd(
    url: str,
    baseline: ResponseBaseline,
    delimiters: Optional[List[str]] = None,
    extensions: Optional[List[str]] = None,
    timeout: float = 10.0,
    insecure: bool = False,
) -> List[WcdFinding]:
    """Probe for Web Cache Deception vulnerabilities.

    Tests path confusion using delimiter+extension combinations to detect
    when caches store dynamic content as static files.

    Args:
        url: Target URL to probe
        baseline: Previously captured baseline response
        delimiters: Path delimiters to test (uses wordlist defaults if None)
        extensions: Static extensions to test (uses wordlist defaults if None)
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification

    Returns:
        List of WcdFinding sorted by significance (is_significant=True first)
    """
    # Import wordlists lazily to avoid circular imports
    from venom_cache.wordlists import get_path_delimiters, get_static_extensions

    if delimiters is None:
        delimiters = get_path_delimiters()
    if extensions is None:
        extensions = get_static_extensions()

    # Build confused URLs
    confused_urls = build_confused_urls(url, delimiters, extensions)

    findings = []
    for confused_url, delimiter, extension in confused_urls:
        # Request 1: Make request (should be MISS - primes cache)
        # use_cache_buster=False because we WANT caching behavior
        status1, headers1, body1 = make_request(
            confused_url,
            timeout=timeout,
            insecure=insecure,
            use_cache_buster=False,
        )

        # Check if first request was stored (cache miss that gets stored)
        first_is_hit = is_likely_cache_hit(headers1)

        # Request 2: Make same request (check for HIT)
        status2, headers2, body2 = make_request(
            confused_url,
            timeout=timeout,
            insecure=insecure,
            use_cache_buster=False,
        )

        second_is_hit = is_likely_cache_hit(headers2)

        # Compare response to baseline
        diff = compare_response(baseline, status2, headers2, body2)

        # If static_body_changed is False, content matches baseline = vulnerable
        content_matches = not diff.static_body_changed

        # Significant if: cached AND content matches baseline
        # This indicates the cache stored the dynamic response as static
        is_significant = second_is_hit and content_matches

        # Extract just the path from the confused URL for reporting
        confused_path = urlparse(confused_url).path

        finding = WcdFinding(
            confused_path=confused_path,
            delimiter=delimiter,
            extension=extension,
            first_request_cached=not first_is_hit,  # MISS = stored
            second_request_hit=second_is_hit,
            content_matches_baseline=content_matches,
            is_significant=is_significant,
        )
        findings.append(finding)

    # Sort by significance (significant first)
    def sort_key(f: WcdFinding) -> tuple:
        return (
            not f.is_significant,  # Significant first
            not f.second_request_hit,  # Cached second
            not f.content_matches_baseline,  # Content matches third
        )

    findings.sort(key=sort_key)

    return findings
