"""Baseline response capture and comparison for cache behavior analysis."""

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from venom_cache.http_transport import make_request


@dataclass
class ResponseBaseline:
    """Captured baseline response for comparison."""

    url: str
    status: int
    headers: Dict[str, str]
    body_hash: str  # SHA256 of raw body
    body_length: int
    content_type: Optional[str]
    static_body_hash: str  # Hash of body with dynamic content stripped
    captured_at: float  # time.time()


@dataclass
class ResponseDiff:
    """Difference between baseline and current response."""

    status_changed: bool
    headers_changed: List[str]  # Header names that differ
    body_changed: bool  # Raw body differs
    static_body_changed: bool  # Differs even after stripping dynamic content
    content_length_delta: int  # Difference in body length
    significant: bool  # True if changes indicate poisoning potential


# Headers that are expected to change between requests
VOLATILE_HEADERS = {
    "date",
    "age",
    "x-request-id",
    "x-trace-id",
    "x-amzn-requestid",
    "x-correlation-id",
    "set-cookie",
    "cf-ray",
    "x-served-by",
    "x-cache",
    "x-cache-hits",
    "x-timer",
    "server-timing",
}

# Patterns for dynamic content that changes between requests
DYNAMIC_PATTERNS = [
    # ISO timestamps: 2024-01-29T10:30:00
    re.compile(rb"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"),
    # RFC timestamps: Mon, 29 Jan 2024 10:30:00 GMT
    re.compile(
        rb"(Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}"
    ),
    # Unix timestamps (reasonable range 2020-2030)
    re.compile(rb"\b1[5-9]\d{8}\b"),
    # UUIDs
    re.compile(
        rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    ),
    # CSRF tokens in various formats
    re.compile(rb'csrf[_-]?token["\s:=]+["\']?[a-zA-Z0-9_-]{16,}'),
    # Session IDs
    re.compile(rb'session[_-]?id["\s:=]+["\']?[a-zA-Z0-9_-]{16,}'),
    # Nonces
    re.compile(rb'nonce["\s:=]+["\']?[a-zA-Z0-9_-]{8,}'),
    # Generic hex tokens (32+ chars)
    re.compile(rb'"[a-fA-F0-9]{32,}"'),
]


def _hash_body(body: bytes) -> str:
    """Compute SHA256 hash of body, truncated to 16 chars."""
    return hashlib.sha256(body).hexdigest()[:16]


def strip_dynamic_content(body: bytes) -> bytes:
    """Strip dynamic content from response body for stable comparison.

    Replaces timestamps, UUIDs, tokens, etc. with placeholders so that
    responses can be compared without false positives from dynamic content.

    Args:
        body: Raw response body

    Returns:
        Body with dynamic content replaced by placeholders
    """
    result = body
    for pattern in DYNAMIC_PATTERNS:
        result = pattern.sub(b"__DYNAMIC__", result)
    return result


def capture_baseline(
    url: str,
    timeout: float = 10.0,
    insecure: bool = False,
    headers: Optional[Dict[str, str]] = None,
) -> ResponseBaseline:
    """Capture a baseline response for later comparison.

    Args:
        url: Target URL to request
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification
        headers: Optional custom headers to include in request

    Returns:
        ResponseBaseline with captured response data
    """
    status, resp_headers, body = make_request(
        url, timeout=timeout, insecure=insecure, use_cache_buster=True, headers=headers
    )

    content_type = resp_headers.get("Content-Type") or resp_headers.get("content-type")

    body_hash = _hash_body(body)
    static_body = strip_dynamic_content(body)
    static_body_hash = _hash_body(static_body)

    return ResponseBaseline(
        url=url,
        status=status,
        headers=resp_headers,
        body_hash=body_hash,
        body_length=len(body),
        content_type=content_type,
        static_body_hash=static_body_hash,
        captured_at=time.time(),
    )


def compare_response(
    baseline: ResponseBaseline,
    status: int,
    headers: Dict[str, str],
    body: bytes,
) -> ResponseDiff:
    """Compare a response against the baseline.

    Args:
        baseline: Previously captured baseline
        status: Current response status code
        headers: Current response headers
        body: Current response body

    Returns:
        ResponseDiff describing the differences
    """
    # Status comparison
    status_changed = baseline.status != status

    # Header comparison (ignore volatile headers)
    headers_changed = []
    baseline_headers_lower = {k.lower(): v for k, v in baseline.headers.items()}
    current_headers_lower = {k.lower(): v for k, v in headers.items()}

    all_keys = set(baseline_headers_lower.keys()) | set(current_headers_lower.keys())
    for key in all_keys:
        if key in VOLATILE_HEADERS:
            continue  # Skip expected volatile headers
        baseline_val = baseline_headers_lower.get(key)
        current_val = current_headers_lower.get(key)
        if baseline_val != current_val:
            headers_changed.append(key)

    # Body comparison
    body_hash = _hash_body(body)
    body_changed = baseline.body_hash != body_hash

    static_body = strip_dynamic_content(body)
    static_body_hash = _hash_body(static_body)
    static_body_changed = baseline.static_body_hash != static_body_hash

    content_length_delta = len(body) - baseline.body_length

    # Determine significance
    # Significant if: status changed, non-volatile headers changed, or static body changed
    significant = status_changed or bool(headers_changed) or static_body_changed

    return ResponseDiff(
        status_changed=status_changed,
        headers_changed=headers_changed,
        body_changed=body_changed,
        static_body_changed=static_body_changed,
        content_length_delta=content_length_delta,
        significant=significant,
    )


def check_response_stability(
    url: str,
    timeout: float = 10.0,
    insecure: bool = False,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[ResponseBaseline, ResponseDiff, bool]:
    """Check if responses are stable between requests.

    Makes two requests and compares them to determine if the response
    is stable (consistent between requests) or unstable (changes each time).

    Args:
        url: Target URL to test
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification
        headers: Optional custom headers to include in requests

    Returns:
        Tuple of (baseline, diff, is_stable)
    """
    # Capture baseline
    baseline = capture_baseline(url, timeout=timeout, insecure=insecure, headers=headers)

    # Make second request
    status, resp_headers, body = make_request(
        url, timeout=timeout, insecure=insecure, use_cache_buster=True, headers=headers
    )

    # Compare
    diff = compare_response(baseline, status, resp_headers, body)

    # Response is stable if no significant changes
    is_stable = not diff.significant

    return (baseline, diff, is_stable)
