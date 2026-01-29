"""Header probing and reflection detection for cache poisoning."""

import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from venom_cache.baseline import (
    ResponseBaseline,
    ResponseDiff,
    capture_baseline,
    compare_response,
)
from venom_cache.http_transport import make_request


@dataclass
class HeaderFinding:
    """Result of probing a single header for cache poisoning."""

    header_name: str
    canary: str
    reflected_in_body: bool
    reflected_in_headers: List[str]  # Header names where canary was found
    response_diff: ResponseDiff
    is_significant: bool  # True if reflected AND response differs


def generate_canary() -> str:
    """Generate a unique canary value for header probing.

    Returns:
        String in format "venom-{12 hex chars}" that's unlikely to appear naturally.
    """
    return f"venom-{uuid.uuid4().hex[:12]}"


def detect_reflection(
    canary: str,
    body: bytes,
    headers: Dict[str, str],
) -> Tuple[bool, List[str]]:
    """Detect if a canary value is reflected in the response.

    Args:
        canary: The canary value to search for
        body: Response body bytes
        headers: Response headers dict

    Returns:
        Tuple of (found_in_body, list_of_header_names_containing_canary)
    """
    canary_lower = canary.lower()

    # Check body (case-insensitive)
    found_in_body = canary_lower.encode() in body.lower()

    # Check headers (case-insensitive on values)
    headers_with_canary = []
    for name, value in headers.items():
        if canary_lower in value.lower():
            headers_with_canary.append(name.lower())

    return (found_in_body, headers_with_canary)


def probe_header(
    url: str,
    header_name: str,
    baseline: ResponseBaseline,
    timeout: float = 10.0,
    insecure: bool = False,
) -> HeaderFinding:
    """Probe a single header for cache poisoning potential.

    Args:
        url: Target URL to probe
        header_name: Name of header to inject
        baseline: Previously captured baseline response
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification

    Returns:
        HeaderFinding with evidence of reflection and response diff
    """
    canary = generate_canary()

    # Make request with the injected header
    status, headers, body = make_request(
        url,
        headers={header_name: canary},
        timeout=timeout,
        insecure=insecure,
        use_cache_buster=True,
    )

    # Detect reflection
    found_in_body, headers_with_canary = detect_reflection(canary, body, headers)

    # Compare to baseline
    diff = compare_response(baseline, status, headers, body)

    # Determine significance:
    # - Reflected (in body or headers) AND response differs significantly
    has_reflection = found_in_body or len(headers_with_canary) > 0
    is_significant = has_reflection and diff.significant

    return HeaderFinding(
        header_name=header_name,
        canary=canary,
        reflected_in_body=found_in_body,
        reflected_in_headers=headers_with_canary,
        response_diff=diff,
        is_significant=is_significant,
    )


def probe_headers(
    url: str,
    headers: List[str],
    timeout: float = 10.0,
    insecure: bool = False,
    baseline: Optional[ResponseBaseline] = None,
) -> List[HeaderFinding]:
    """Probe multiple headers for cache poisoning potential.

    Args:
        url: Target URL to probe
        headers: List of header names to test
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification
        baseline: Optional pre-captured baseline (captures new one if None)

    Returns:
        List of HeaderFinding sorted by significance (significant first)
    """
    # Capture baseline if not provided
    if baseline is None:
        baseline = capture_baseline(url, timeout=timeout, insecure=insecure)

    # Probe each header
    findings = []
    for header_name in headers:
        finding = probe_header(
            url,
            header_name,
            baseline,
            timeout=timeout,
            insecure=insecure,
        )
        findings.append(finding)

    # Sort by significance (significant first), then by reflection
    def sort_key(f: HeaderFinding) -> tuple:
        return (
            not f.is_significant,  # Significant first (False < True when negated)
            not f.reflected_in_body,  # Body reflection second
            -len(f.reflected_in_headers),  # More header reflections third
        )

    findings.sort(key=sort_key)

    return findings
