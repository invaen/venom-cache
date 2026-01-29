"""Parameter probing and reflection detection for cache poisoning."""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from venom_cache.baseline import (
    ResponseBaseline,
    ResponseDiff,
    capture_baseline,
    compare_response,
)
from venom_cache.header_prober import detect_reflection, generate_canary
from venom_cache.http_transport import make_request


@dataclass
class ParamFinding:
    """Result of probing a single parameter for cache poisoning."""

    param_name: str
    canary: str
    reflected_in_body: bool
    reflected_in_headers: List[str]  # Header names where canary was found
    response_diff: ResponseDiff
    is_significant: bool  # True if reflected AND response differs


def inject_param(url: str, param_name: str, param_value: str) -> str:
    """Inject a query parameter into a URL.

    Args:
        url: Target URL to modify
        param_name: Name of the parameter to inject
        param_value: Value to set for the parameter

    Returns:
        URL with parameter added/replaced
    """
    parsed = urlparse(url)

    # Parse existing query string (keep_blank_values preserves empty params)
    query_params = parse_qs(parsed.query, keep_blank_values=True)

    # Add/replace parameter (use list for parse_qs compatibility)
    query_params[param_name] = [param_value]

    # Rebuild query string (doseq=True for list values)
    new_query = urlencode(query_params, doseq=True)

    # Rebuild URL preserving fragment
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)


def probe_param(
    url: str,
    param_name: str,
    baseline: ResponseBaseline,
    timeout: float = 10.0,
    insecure: bool = False,
) -> ParamFinding:
    """Probe a single parameter for cache poisoning potential.

    Args:
        url: Target URL to probe
        param_name: Name of query parameter to inject
        baseline: Previously captured baseline response
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification

    Returns:
        ParamFinding with evidence of reflection and response diff
    """
    canary = generate_canary()

    # Inject parameter into URL
    probed_url = inject_param(url, param_name, canary)

    # Make request with the injected parameter
    status, headers, body = make_request(
        probed_url,
        timeout=timeout,
        insecure=insecure,
        use_cache_buster=True,
    )

    # Detect reflection (reuse from header_prober)
    found_in_body, headers_with_canary = detect_reflection(canary, body, headers)

    # Compare to baseline
    diff = compare_response(baseline, status, headers, body)

    # Determine significance:
    # - Reflected (in body or headers) AND response differs significantly
    has_reflection = found_in_body or len(headers_with_canary) > 0
    is_significant = has_reflection and diff.significant

    return ParamFinding(
        param_name=param_name,
        canary=canary,
        reflected_in_body=found_in_body,
        reflected_in_headers=headers_with_canary,
        response_diff=diff,
        is_significant=is_significant,
    )


def probe_params(
    url: str,
    params: List[str],
    timeout: float = 10.0,
    insecure: bool = False,
    baseline: Optional[ResponseBaseline] = None,
) -> List[ParamFinding]:
    """Probe multiple parameters for cache poisoning potential.

    Args:
        url: Target URL to probe
        params: List of parameter names to test
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification
        baseline: Optional pre-captured baseline (captures new one if None)

    Returns:
        List of ParamFinding sorted by significance (significant first)
    """
    # Capture baseline if not provided
    if baseline is None:
        baseline = capture_baseline(url, timeout=timeout, insecure=insecure)

    # Probe each parameter
    findings = []
    for param_name in params:
        finding = probe_param(
            url,
            param_name,
            baseline,
            timeout=timeout,
            insecure=insecure,
        )
        findings.append(finding)

    # Sort by significance (significant first), then by reflection
    def sort_key(f: ParamFinding) -> tuple:
        return (
            not f.is_significant,  # Significant first (False < True when negated)
            not f.reflected_in_body,  # Body reflection second
            -len(f.reflected_in_headers),  # More header reflections third
        )

    findings.sort(key=sort_key)

    return findings
