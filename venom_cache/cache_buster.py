"""Cache buster generation and verification for safe cache probing."""

import hashlib
import http.client
import random
import string
from typing import Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


def generate_cache_buster(length: int = 8) -> str:
    """Generate a random cache buster string.

    Args:
        length: Length of the cache buster string (default: 8)

    Returns:
        Random alphanumeric lowercase string
    """
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=length))


def inject_cache_buster(url: str, param_name: str = "_cb") -> str:
    """Inject a unique cache buster parameter into a URL.

    Args:
        url: Target URL to modify
        param_name: Query parameter name for the cache buster (default: _cb)

    Returns:
        URL with cache buster parameter added/replaced
    """
    parsed = urlparse(url)

    # Parse existing query string
    query_params = parse_qs(parsed.query, keep_blank_values=True)

    # Add/replace cache buster (use list for parse_qs compatibility)
    query_params[param_name] = [generate_cache_buster()]

    # Rebuild query string (doseq=True for list values)
    new_query = urlencode(query_params, doseq=True)

    # Rebuild URL
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)


def verify_cache_buster_isolation(
    url: str,
    timeout: float = 10.0,
    insecure: bool = False,
    headers: dict = None,
) -> Tuple[bool, str]:
    """Verify that cache busters create isolated cache entries.

    Makes three requests to verify that different cache busters don't
    serve each other's cached responses:
    1. Request with cache buster cb1 -> response hash h1
    2. Request with cache buster cb2 -> response hash h2
    3. Request with cache buster cb1 again -> response hash h3

    If h3 == h2, cache busters are not isolated (FAIL).
    If h3 == h1 or all hashes unique, cache busters are isolated (PASS).

    Args:
        url: Target URL to test
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification
        headers: Optional custom headers to include in requests

    Returns:
        Tuple of (is_safe: bool, message: str)
    """
    # Import here to avoid circular import
    from venom_cache.http_transport import make_request

    def hash_body(body: bytes) -> str:
        return hashlib.sha256(body).hexdigest()[:16]

    try:
        # Generate two distinct cache busters
        cb1 = generate_cache_buster()
        cb2 = generate_cache_buster()

        # Build URLs with specific cache busters
        url1 = inject_cache_buster(url, "_cb")
        # Replace the generated cache buster with our known cb1
        url1 = url1.rsplit("=", 1)[0] + "=" + cb1

        url2 = inject_cache_buster(url, "_cb")
        url2 = url2.rsplit("=", 1)[0] + "=" + cb2

        # Request 1: cb1
        _, _, body1 = make_request(url1, timeout=timeout, insecure=insecure, use_cache_buster=False, headers=headers)
        h1 = hash_body(body1)

        # Request 2: cb2
        _, _, body2 = make_request(url2, timeout=timeout, insecure=insecure, use_cache_buster=False, headers=headers)
        h2 = hash_body(body2)

        # Request 3: cb1 again
        _, _, body3 = make_request(url1, timeout=timeout, insecure=insecure, use_cache_buster=False, headers=headers)
        h3 = hash_body(body3)

        # Verification logic
        if h3 == h2 and h1 != h2:
            # cb1 returned cb2's response - cache busters not isolated!
            return (False, "Cache buster isolation FAILED - different cache busters served same response")

        if h1 == h2 == h3:
            # All same - might be no caching or static content, still safe
            return (True, "Cache buster isolation verified - responses consistent")

        if h1 == h3:
            # cb1 returned cb1's response (cache HIT), cb2 different - isolated
            return (True, "Cache buster isolation verified - responses isolated")

        # All unique - no caching detected, still safe
        return (True, "Cache buster isolation verified - no caching detected")

    except (OSError, http.client.HTTPException, ValueError) as e:
        return (False, f"Verification failed: {e}")
