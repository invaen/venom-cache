"""Built-in wordlists for cache poisoning detection."""

from typing import List

# Headers commonly excluded from cache keys (unkeyed headers)
# These are potential cache poisoning vectors
UNKEYED_HEADERS: List[str] = [
    # Forwarded headers (most common vectors)
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "X-Forwarded-Scheme",
    "X-Forwarded-For",
    "X-Forwarded-Port",
    "X-Forwarded-Server",
    "X-Forwarded-Prefix",
    # Original URL headers
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Original-Host",
    # Host override headers
    "X-Host",
    "X-HTTP-Host-Override",
    "Forwarded",
    # Protocol override
    "X-Forwarded-SSL",
    "X-URL-Scheme",
    "X-Scheme",
    "Front-End-Https",
    "X-Forwarded-Protocol",
    # Real IP headers
    "X-Real-IP",
    "X-Client-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Cluster-Client-IP",
    "Fastly-Client-IP",
    "X-Originating-IP",
    # Custom/Debug headers
    "X-Custom-IP-Authorization",
    "X-Debug",
    "X-Akamai-Debug",
    "Pragma",
    # Path override
    "X-Original-Path",
    "X-Rewritten-Path",
    "X-Rewritten-URL",
    # Method override
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-HTTP-Method",
    # WAF bypass
    "X-WAF-Bypass",
    "X-Bypass",
    # CDN-specific
    "X-Akamai-Config",
    "X-Fastly-Debug",
    "X-Varnish-Debug",
]


def get_header_wordlist() -> List[str]:
    """Return the default list of headers to probe for cache poisoning.

    Returns:
        Copy of the UNKEYED_HEADERS list (safe to modify)
    """
    return UNKEYED_HEADERS.copy()
