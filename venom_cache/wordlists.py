"""Built-in wordlists for cache poisoning detection."""

import pathlib
from typing import List, Optional

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


# Query parameters commonly excluded from cache keys (unkeyed parameters)
# These are potential cache poisoning vectors
UNKEYED_PARAMS: List[str] = [
    # UTM parameters (Google Analytics / marketing)
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_content",
    "utm_term",
    "utm_expid",
    # Facebook tracking
    "fbclid",
    "fb_action_ids",
    "fb_action_types",
    "fb_source",
    # Google tracking
    "gclid",
    "dclid",
    "_ga",
    # Marketing automation
    "mc_cid",
    "mc_eid",
    "mkt_tok",
    # Other analytics/tracking
    "epik",
    "_ke",
    "ck_subscriber_id",
    "campaignid",
    "adgroupid",
    # JSONP callback parameters
    "callback",
    "jsonp",
    "cb",
    "_callback",
    "jsonpcallback",
    # Debug/test parameters
    "debug",
    "test",
    "dev",
    # Referrer/source tracking
    "ref",
    "source",
    "affiliate",
    "partner",
]


def get_param_wordlist() -> List[str]:
    """Return the default list of parameters to probe for cache poisoning.

    Returns:
        Copy of the UNKEYED_PARAMS list (safe to modify)
    """
    return UNKEYED_PARAMS.copy()


# Static file extensions commonly cached by CDNs
STATIC_EXTENSIONS: List[str] = [
    # Most commonly cached
    ".css",
    ".js",
    ".ico",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    # Fonts (often cached)
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    # Other static
    ".pdf",
    ".webp",
    ".avif",
]


# Path delimiters for web cache deception testing
# Based on PortSwigger research on framework behaviors
PATH_DELIMITERS: List[str] = [
    ";",      # Java Spring matrix variables
    "%00",    # Null byte - OpenLiteSpeed
    "%0a",    # Newline - Nginx with rewrites
    "%23",    # Hash encoded
    "%3f",    # Question mark encoded
    ".",      # Dot - Ruby on Rails formatter
    "/",      # Slash
    "%2f",    # Slash encoded
]


def get_static_extensions() -> List[str]:
    """Return default static extensions for WCD testing.

    Returns:
        Copy of the STATIC_EXTENSIONS list (safe to modify)
    """
    return STATIC_EXTENSIONS.copy()


def get_path_delimiters() -> List[str]:
    """Return path delimiters for WCD testing.

    Returns:
        Copy of the PATH_DELIMITERS list (safe to modify)
    """
    return PATH_DELIMITERS.copy()


# Body parameter names for fat GET testing
# These are commonly reflected when servers process GET request bodies
FAT_GET_PARAMS: List[str] = [
    "callback",  # JSONP often reflected
    "param",     # Generic
    "q",         # Search
    "query",
    "data",
    "input",
    "value",
    "body",
    "content",
    "message",
]


# Method override headers for fat GET testing
# Used to convince servers to process GET body as POST
METHOD_OVERRIDE_HEADERS: List[str] = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
]


def get_fat_get_params() -> List[str]:
    """Return default body parameter names for fat GET testing.

    Returns:
        Copy of the FAT_GET_PARAMS list (safe to modify)
    """
    return FAT_GET_PARAMS.copy()


def get_method_override_headers() -> List[str]:
    """Return method override headers for fat GET testing.

    Returns:
        Copy of the METHOD_OVERRIDE_HEADERS list (safe to modify)
    """
    return METHOD_OVERRIDE_HEADERS.copy()


def load_wordlist_from_file(filepath: str) -> List[str]:
    """Load wordlist from file, one entry per line.

    Args:
        filepath: Path to wordlist file

    Returns:
        List of entries (stripped, non-empty, non-comment lines)

    Raises:
        FileNotFoundError: If file does not exist
        ValueError: If file is empty after filtering or not a file
    """
    path = pathlib.Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Wordlist not found: {filepath}")
    if not path.is_file():
        raise ValueError(f"Not a file: {filepath}")

    entries = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.append(line)

    if not entries:
        raise ValueError(f"Wordlist is empty: {filepath}")

    return entries


def get_header_wordlist_with_custom(custom_path: Optional[str] = None) -> List[str]:
    """Get header wordlist - custom if specified, otherwise built-in.

    Args:
        custom_path: Optional path to custom wordlist file

    Returns:
        List of header names to probe
    """
    if custom_path:
        return load_wordlist_from_file(custom_path)
    return get_header_wordlist()
