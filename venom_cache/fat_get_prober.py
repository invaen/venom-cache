"""Fat GET probing for cache poisoning via request body content."""

from dataclasses import dataclass
from typing import Dict, List, Optional

from venom_cache.baseline import ResponseBaseline, ResponseDiff, compare_response
from venom_cache.header_prober import detect_reflection, generate_canary
from venom_cache.http_transport import make_request


@dataclass
class FatGetFinding:
    """Result of probing for fat GET vulnerability."""

    param_name: str  # Body parameter name tested
    canary: str
    reflected_in_body: bool
    reflected_in_headers: List[str]  # Header names where canary was found
    response_diff: ResponseDiff
    method_override_header: Optional[str]  # If method override was needed
    is_significant: bool  # True if reflected AND response differs


def probe_fat_get(
    url: str,
    param_name: str,
    baseline: ResponseBaseline,
    timeout: float = 10.0,
    insecure: bool = False,
    custom_headers: Optional[Dict[str, str]] = None,
) -> FatGetFinding:
    """Probe a single body parameter for fat GET vulnerability.

    Sends a GET request with a URL-encoded body parameter and checks
    if the canary value is reflected in the response.

    Args:
        url: Target URL to probe
        param_name: Body parameter name to inject
        baseline: Previously captured baseline response
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification
        custom_headers: Optional base headers (auth, cookies, etc.) to include

    Returns:
        FatGetFinding with evidence of reflection and response diff
    """
    canary = generate_canary()

    # Build form-encoded body
    body = f"{param_name}={canary}".encode()

    # Build headers: custom_headers as base, probe headers override
    request_headers = {}
    if custom_headers:
        request_headers.update(custom_headers)
    request_headers["Content-Type"] = "application/x-www-form-urlencoded"

    # Make GET request with body (fat GET)
    status, headers, resp_body = make_request(
        url,
        headers=request_headers,
        timeout=timeout,
        insecure=insecure,
        use_cache_buster=True,
        body=body,
    )

    # Detect reflection
    found_in_body, headers_with_canary = detect_reflection(canary, resp_body, headers)

    # Compare to baseline
    diff = compare_response(baseline, status, headers, resp_body)

    # Determine significance
    has_reflection = found_in_body or len(headers_with_canary) > 0
    is_significant = has_reflection and diff.significant

    return FatGetFinding(
        param_name=param_name,
        canary=canary,
        reflected_in_body=found_in_body,
        reflected_in_headers=headers_with_canary,
        response_diff=diff,
        method_override_header=None,
        is_significant=is_significant,
    )


def probe_method_override(
    url: str,
    param_name: str,
    baseline: ResponseBaseline,
    method_override_headers: List[str],
    timeout: float = 10.0,
    insecure: bool = False,
    custom_headers: Optional[Dict[str, str]] = None,
) -> Optional[FatGetFinding]:
    """Probe for fat GET using method override headers.

    Some servers ignore body on GET unless told via method override header
    that the request should be treated as POST.

    Args:
        url: Target URL to probe
        param_name: Body parameter name to inject
        baseline: Previously captured baseline response
        method_override_headers: List of headers to try (e.g., X-HTTP-Method-Override)
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification
        custom_headers: Optional base headers (auth, cookies, etc.) to include

    Returns:
        FatGetFinding if reflection detected with method override, None otherwise
    """
    canary = generate_canary()
    body = f"{param_name}={canary}".encode()

    for override_header in method_override_headers:
        # Build headers: custom_headers as base, probe headers override
        request_headers = {}
        if custom_headers:
            request_headers.update(custom_headers)
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        request_headers[override_header] = "POST"

        status, headers, resp_body = make_request(
            url,
            headers=request_headers,
            timeout=timeout,
            insecure=insecure,
            use_cache_buster=True,
            body=body,
        )

        found_in_body, headers_with_canary = detect_reflection(
            canary, resp_body, headers
        )

        if found_in_body or headers_with_canary:
            diff = compare_response(baseline, status, headers, resp_body)
            has_reflection = found_in_body or len(headers_with_canary) > 0
            is_significant = has_reflection and diff.significant

            return FatGetFinding(
                param_name=param_name,
                canary=canary,
                reflected_in_body=found_in_body,
                reflected_in_headers=headers_with_canary,
                response_diff=diff,
                method_override_header=override_header,
                is_significant=is_significant,
            )

    return None


def probe_all_fat_get(
    url: str,
    param_names: List[str],
    method_override_headers: List[str],
    timeout: float = 10.0,
    insecure: bool = False,
    baseline: Optional[ResponseBaseline] = None,
    custom_headers: Optional[Dict[str, str]] = None,
) -> List[FatGetFinding]:
    """Probe all body parameters for fat GET vulnerabilities.

    First tries direct fat GET (GET with body), then if no reflections
    are found, tries with method override headers.

    Args:
        url: Target URL to probe
        param_names: List of body parameter names to test
        method_override_headers: List of method override headers to try
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification
        baseline: Optional pre-captured baseline (captures new one if None)
        custom_headers: Optional base headers (auth, cookies, etc.) to include

    Returns:
        List of FatGetFinding sorted by significance (significant first)
    """
    from venom_cache.baseline import capture_baseline

    # Capture baseline if not provided
    if baseline is None:
        baseline = capture_baseline(url, timeout=timeout, insecure=insecure)

    findings: List[FatGetFinding] = []
    direct_reflections = False

    # First, try direct fat GET for all params
    for param_name in param_names:
        finding = probe_fat_get(
            url,
            param_name,
            baseline,
            timeout=timeout,
            insecure=insecure,
            custom_headers=custom_headers,
        )
        if finding.reflected_in_body or finding.reflected_in_headers:
            findings.append(finding)
            direct_reflections = True

    # If no direct reflections, try method override on all params
    if not direct_reflections:
        for param_name in param_names:
            finding = probe_method_override(
                url,
                param_name,
                baseline,
                method_override_headers,
                timeout=timeout,
                insecure=insecure,
                custom_headers=custom_headers,
            )
            if finding is not None:
                findings.append(finding)

    # Sort by significance
    def sort_key(f: FatGetFinding) -> tuple:
        return (
            not f.is_significant,  # Significant first
            not f.reflected_in_body,  # Body reflection second
            -len(f.reflected_in_headers),  # More header reflections third
        )

    findings.sort(key=sort_key)

    return findings
