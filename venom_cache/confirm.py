"""Confirm mode verification for cache poisoning detection.

WARNING: These functions affect shared caches and may serve poisoned responses
to real users. Only use on targets you have explicit permission to test.

Confirm mode verifies that detected cache poisoning actually persists and affects
other users by using a three-request pattern:
1. Poison request: Inject canary without cache buster (hits shared cache)
2. Victim request: Clean request without cache buster (fetches from shared cache)
3. Check: Verify if canary appears in victim response
"""

from typing import Dict, Optional, Tuple

from venom_cache.header_prober import HeaderFinding, detect_reflection
from venom_cache.http_transport import make_request
from venom_cache.param_prober import ParamFinding, inject_param


def confirm_header_poisoning(
    url: str,
    finding: HeaderFinding,
    timeout: float = 10.0,
    insecure: bool = False,
    custom_headers: Optional[Dict[str, str]] = None,
) -> Tuple[bool, str]:
    """Verify that header poisoning actually persists in shared cache.

    WARNING: This function affects shared caches and may serve poisoned
    responses to real users. Only use on targets you have permission to test.

    Uses three-request pattern:
    1. Poison: Send request with finding.header_name: finding.canary
    2. Victim: Send clean request (no poison header)
    3. Check: Verify if canary appears in victim response

    CRITICAL: Both poison and victim requests use use_cache_buster=False
    to ensure they hit the shared cache.

    Args:
        url: Target URL to verify
        finding: HeaderFinding with detected reflection
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification
        custom_headers: Optional base headers (auth, cookies, etc.)

    Returns:
        Tuple of (confirmed: bool, message: str)
        - confirmed=True: Cache poisoning persists for victims
        - confirmed=False: Canary not found in victim response
    """
    # Step 1: Poison request - inject canary without cache buster
    poison_headers = {}
    if custom_headers:
        poison_headers.update(custom_headers)
    poison_headers[finding.header_name] = finding.canary

    _status, _resp_headers, _body = make_request(
        url,
        headers=poison_headers,
        timeout=timeout,
        insecure=insecure,
        use_cache_buster=False,  # CRITICAL: Hit shared cache
    )

    # Step 2: Victim request - clean headers, no poison
    victim_headers = custom_headers if custom_headers else {}

    _v_status, victim_resp_headers, victim_body = make_request(
        url,
        headers=victim_headers,
        timeout=timeout,
        insecure=insecure,
        use_cache_buster=False,  # CRITICAL: Hit shared cache
    )

    # Step 3: Check if canary persists in victim response
    found_in_body, headers_with_canary = detect_reflection(
        finding.canary, victim_body, victim_resp_headers
    )

    if found_in_body or headers_with_canary:
        locations = []
        if found_in_body:
            locations.append("body")
        if headers_with_canary:
            locations.append(f"headers({', '.join(headers_with_canary)})")
        return (
            True,
            f"CONFIRMED: Canary persists in victim response ({', '.join(locations)})",
        )
    else:
        return (
            False,
            f"NOT CONFIRMED: Canary not found in victim response",
        )


def confirm_param_poisoning(
    url: str,
    finding: ParamFinding,
    timeout: float = 10.0,
    insecure: bool = False,
    custom_headers: Optional[Dict[str, str]] = None,
) -> Tuple[bool, str]:
    """Verify that parameter poisoning actually persists in shared cache.

    WARNING: This function affects shared caches and may serve poisoned
    responses to real users. Only use on targets you have permission to test.

    Uses three-request pattern:
    1. Poison: Send request with finding.param_name=finding.canary in URL
    2. Victim: Send clean request (original URL, no injected param)
    3. Check: Verify if canary appears in victim response

    CRITICAL: Both poison and victim requests use use_cache_buster=False
    to ensure they hit the shared cache.

    Args:
        url: Target URL to verify (original URL without the poisoned param)
        finding: ParamFinding with detected reflection
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification
        custom_headers: Optional base headers (auth, cookies, etc.)

    Returns:
        Tuple of (confirmed: bool, message: str)
        - confirmed=True: Cache poisoning persists for victims
        - confirmed=False: Canary not found in victim response
    """
    # Step 1: Poison request - inject canary param without cache buster
    poisoned_url = inject_param(url, finding.param_name, finding.canary)

    _status, _resp_headers, _body = make_request(
        poisoned_url,
        headers=custom_headers,
        timeout=timeout,
        insecure=insecure,
        use_cache_buster=False,  # CRITICAL: Hit shared cache
    )

    # Step 2: Victim request - original URL, no injected param
    _v_status, victim_resp_headers, victim_body = make_request(
        url,
        headers=custom_headers,
        timeout=timeout,
        insecure=insecure,
        use_cache_buster=False,  # CRITICAL: Hit shared cache
    )

    # Step 3: Check if canary persists in victim response
    found_in_body, headers_with_canary = detect_reflection(
        finding.canary, victim_body, victim_resp_headers
    )

    if found_in_body or headers_with_canary:
        locations = []
        if found_in_body:
            locations.append("body")
        if headers_with_canary:
            locations.append(f"headers({', '.join(headers_with_canary)})")
        return (
            True,
            f"CONFIRMED: Canary persists in victim response ({', '.join(locations)})",
        )
    else:
        return (
            False,
            f"NOT CONFIRMED: Canary not found in victim response",
        )
