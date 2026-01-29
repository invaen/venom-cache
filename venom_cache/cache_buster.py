"""Cache buster generation and verification for safe cache probing."""

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
