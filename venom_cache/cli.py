"""Command-line interface for venom-cache."""

import argparse
import pathlib
import socket
import ssl
import sys
from typing import Tuple

from venom_cache import __version__
from venom_cache.baseline import check_response_stability
from venom_cache.cache_buster import verify_cache_buster_isolation
from venom_cache.cache_detector import detect_cache_headers, get_cache_info
from venom_cache.confirm import confirm_header_poisoning, confirm_param_poisoning
from venom_cache.fat_get_prober import probe_all_fat_get
from venom_cache.header_prober import probe_headers
from venom_cache.http_transport import make_request
from venom_cache.output import Output, OutputMode, Severity
from venom_cache.param_prober import probe_params
from venom_cache.wcd_prober import probe_wcd
from venom_cache.wordlists import (
    get_fat_get_params,
    get_header_wordlist_with_custom,
    get_method_override_headers,
    get_param_wordlist,
    get_path_delimiters,
    get_static_extensions,
)


def parse_header(header_string: str) -> Tuple[str, str]:
    """Parse 'Name: Value' header format.

    Args:
        header_string: Header in 'Name: Value' format

    Returns:
        Tuple of (name, value) with whitespace stripped

    Raises:
        argparse.ArgumentTypeError: If format is invalid (no colon)
    """
    if ":" not in header_string:
        raise argparse.ArgumentTypeError(
            f"Invalid header format '{header_string}' - expected 'Name: Value'"
        )
    name, value = header_string.split(":", 1)
    return (name.strip(), value.strip())


def parse_cookie(cookie_string: str) -> Tuple[str, str]:
    """Parse 'name=value' cookie format.

    Args:
        cookie_string: Cookie in 'name=value' format

    Returns:
        Tuple of (name, value) with whitespace stripped

    Raises:
        argparse.ArgumentTypeError: If format is invalid (no equals)
    """
    if "=" not in cookie_string:
        raise argparse.ArgumentTypeError(
            f"Invalid cookie format '{cookie_string}' - expected 'name=value'"
        )
    # Split on first = only to handle values containing =
    name, value = cookie_string.split("=", 1)
    return (name.strip(), value.strip())


def validate_wordlist_path(filepath: str) -> str:
    """Validate wordlist file exists.

    Args:
        filepath: Path to wordlist file

    Returns:
        Resolved path string

    Raises:
        argparse.ArgumentTypeError: If file doesn't exist or isn't a file
    """
    path = pathlib.Path(filepath)
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Wordlist not found: {filepath}")
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"Not a file: {filepath}")
    return str(path)


def build_request_headers(
    custom_headers: list,
    cookies: list,
) -> dict:
    """Build headers dict from custom headers and cookies.

    Args:
        custom_headers: List of (name, value) tuples for headers
        cookies: List of (name, value) tuples for cookies

    Returns:
        Dictionary of headers ready for HTTP request
    """
    headers = {}
    for name, value in custom_headers:
        headers[name] = value
    if cookies:
        cookie_str = "; ".join(f"{n}={v}" for n, v in cookies)
        headers["Cookie"] = cookie_str
    return headers


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="venom-cache",
        description="Detect web cache poisoning vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://target.com
  %(prog)s --timeout 30 https://target.com
  %(prog)s --insecure https://self-signed.target.com
  %(prog)s -v https://target.com
  %(prog)s -f urls.txt
  cat urls.txt | %(prog)s -f -
        """,
    )

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="Target URL to scan (must start with http:// or https://)",
    )

    parser.add_argument(
        "-f",
        "--file",
        type=argparse.FileType("r"),
        metavar="FILE",
        help="File containing URLs to scan (one per line, use - for stdin)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10.0)",
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL certificate verification",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv, -vvv)",
    )

    parser.add_argument(
        "--wcd",
        action="store_true",
        help="Enable web cache deception (path confusion) detection",
    )

    parser.add_argument(
        "--fat-get",
        action="store_true",
        help="Enable fat GET body poisoning detection",
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Enable all detection techniques (headers, params, fat-get, wcd)",
    )

    parser.add_argument(
        "-H",
        "--header",
        action="append",
        type=parse_header,
        dest="headers",
        default=[],
        metavar="HEADER",
        help="Custom header 'Name: Value' (repeatable)",
    )

    parser.add_argument(
        "-c",
        "--cookie",
        action="append",
        type=parse_cookie,
        dest="cookies",
        default=[],
        metavar="COOKIE",
        help="Cookie 'name=value' (repeatable)",
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        type=validate_wordlist_path,
        metavar="FILE",
        help="Custom header wordlist file (default: built-in)",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Quiet mode - show only vulnerability findings",
    )

    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Output results as JSON (for pipeline integration)",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="Delay between requests in seconds (default: 0, no delay)",
    )

    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Verify actual cache poisoning persists (WARNING: affects shared cache)",
    )

    return parser


def get_target_urls(args: argparse.Namespace) -> list[str]:
    """Extract target URLs from command line arguments.

    Args:
        args: Parsed command line arguments

    Returns:
        List of URLs to scan

    Raises:
        ValueError: If neither URL nor file input provided
    """
    urls = []

    if args.url:
        urls.append(args.url)

    if args.file:
        try:
            for line in args.file:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue
                urls.append(line)
        finally:
            args.file.close()

    if not urls:
        raise ValueError("Error: Provide a URL or use -f/--file to specify a URL file")

    return urls


def scan_url(
    url: str,
    args: argparse.Namespace,
    out: Output,
    custom_headers: dict = None,
) -> int:
    """Scan a single URL for cache poisoning vulnerabilities.

    Args:
        url: Target URL to scan
        args: Parsed command line arguments
        out: Output handler for formatted output
        custom_headers: Optional custom headers to include in all requests

    Returns:
        0 on success, 1 on error
    """
    if custom_headers is None:
        custom_headers = {}

    # Validate URL scheme
    if not url.startswith(("http://", "https://")):
        out.error(f"Error: URL must start with http:// or https:// (got: {url})")
        return 1

    # Set metadata for JSON output
    out.set_metadata(url)

    # Verify cache buster isolation FIRST
    out.info("Verifying cache buster isolation...")
    is_safe, message = verify_cache_buster_isolation(
        url, args.timeout, args.insecure, headers=custom_headers
    )
    if not is_safe:
        out.error(f"ERROR: {message}")
        out.error("Cache buster isolation is required for safe operation. Aborting.")
        return 1
    out.debug(f"OK: {message}", level=1)

    # Proceed with scanning
    out.info(f"\nScanning {url}...")

    try:
        # Establish baseline and check response stability
        baseline, diff, is_stable = check_response_stability(
            url,
            timeout=args.timeout,
            insecure=args.insecure,
            headers=custom_headers,
        )

        out.info(f"Status: {baseline.status}")

        # Detect and display cache status
        cache_status = detect_cache_headers(baseline.headers)
        out.info(get_cache_info(baseline.headers))

        out.info(f"Response size: {baseline.body_length} bytes")

        # Report baseline info
        out.info(f"\nBaseline established ({baseline.body_length} bytes, sha256:{baseline.body_hash}...)")
        out.debug(f"Baseline hash: {baseline.body_hash[:16]}...", level=1)
        out.debug(f"Baseline headers: {len(baseline.headers)} headers", level=2)

        if is_stable:
            out.info("Response stability: Stable (no significant changes between requests)")
        else:
            out.warning("Response unstable - content changes between requests")
            out.info("This may cause false positives during poisoning detection")

        if args.verbose >= 1:
            # Show cache evidence
            if cache_status.evidence:
                out.info("\nCache evidence:")
                for ev in cache_status.evidence:
                    out.info(f"  {ev}")

            # Show response comparison details
            out.info("\nResponse comparison:")
            out.info(f"  Status: {'changed' if diff.status_changed else 'unchanged'} ({baseline.status})")
            if diff.headers_changed:
                out.info(f"  Headers changed: {', '.join(diff.headers_changed)}")
            else:
                out.info("  Headers: no significant changes")
            out.info(f"  Body: {baseline.body_length} -> {baseline.body_length + diff.content_length_delta} bytes ({diff.content_length_delta:+d})")
            out.info(f"  Static content: {'changed' if diff.static_body_changed else 'identical'}")

        # Header poisoning scan
        wordlist = get_header_wordlist_with_custom(args.wordlist)
        out.info(f"\nProbing {len(wordlist)} headers for reflection...")
        out.debug(f"Header wordlist: {len(wordlist)} headers to probe", level=1)

        findings = probe_headers(
            url,
            wordlist,
            timeout=args.timeout,
            insecure=args.insecure,
            baseline=baseline,
            custom_headers=custom_headers,
        )

        # Categorize findings
        significant = [f for f in findings if f.is_significant]
        reflected = [f for f in findings if f.reflected_in_body or f.reflected_in_headers]
        out.debug(f"Header probe results: {len(reflected)} reflected, {len(significant)} significant", level=1)
        for f in reflected:
            out.debug(f"  {f.header_name}: canary={f.canary[:8]}..., body={f.reflected_in_body}, headers={f.reflected_in_headers}", level=2)

        # Collect findings for JSON output (only reflected/significant ones)
        for f in reflected:
            out.add_finding(f, "header_poisoning")

        # Report findings
        if significant:
            out.info(f"\n{len(significant)} POTENTIALLY VULNERABLE headers found:")
            for f in significant:
                loc = []
                if f.reflected_in_body:
                    loc.append("body")
                if f.reflected_in_headers:
                    loc.append(f"headers({', '.join(f.reflected_in_headers)})")
                out.finding(
                    finding_type="Header Poisoning",
                    name=f.header_name,
                    severity=Severity.MEDIUM,
                    details=f"Reflected in {', '.join(loc)}",
                    extra={"canary": f.canary} if args.verbose >= 1 else None,
                )
        elif reflected:
            out.info(f"\n{len(reflected)} headers reflected (no significant diff):")
            for f in reflected:
                loc = []
                if f.reflected_in_body:
                    loc.append("body")
                if f.reflected_in_headers:
                    loc.append(f"headers({', '.join(f.reflected_in_headers)})")
                out.finding(
                    finding_type="Header Reflection",
                    name=f.header_name,
                    severity=Severity.LOW,
                    details=f"Reflected in {', '.join(loc)}",
                )
        else:
            out.info("\nNo header reflection detected")

        # Summary for headers
        out.info(f"\nHeader summary: {len(findings)} headers tested, {len(reflected)} reflected, {len(significant)} potentially vulnerable")

        # Confirm header poisoning if --confirm and significant findings exist
        if args.confirm and significant:
            out.info("\nConfirming header poisoning...")
            for f in significant:
                confirmed, msg = confirm_header_poisoning(
                    url,
                    f,
                    timeout=args.timeout,
                    insecure=args.insecure,
                    custom_headers=custom_headers,
                )
                if confirmed:
                    out.finding(
                        finding_type="CONFIRMED Header Poisoning",
                        name=f.header_name,
                        severity=Severity.HIGH,
                        details=msg,
                    )
                else:
                    out.debug(f"{f.header_name}: {msg}", level=1)

        # Parameter poisoning scan
        param_wordlist = get_param_wordlist()
        out.info(f"\nProbing {len(param_wordlist)} parameters for reflection...")
        out.debug(f"Parameter wordlist: {len(param_wordlist)} params to probe", level=1)

        param_findings = probe_params(
            url,
            param_wordlist,
            timeout=args.timeout,
            insecure=args.insecure,
            baseline=baseline,
            custom_headers=custom_headers,
        )

        # Categorize parameter findings
        param_significant = [f for f in param_findings if f.is_significant]
        param_reflected = [f for f in param_findings if f.reflected_in_body or f.reflected_in_headers]
        out.debug(f"Param probe results: {len(param_reflected)} reflected, {len(param_significant)} significant", level=1)

        # Collect findings for JSON output
        for f in param_reflected:
            out.add_finding(f, "parameter_poisoning")

        # Report parameter findings
        if param_significant:
            out.info(f"\n{len(param_significant)} POTENTIALLY VULNERABLE parameters found:")
            for f in param_significant:
                loc = []
                if f.reflected_in_body:
                    loc.append("body")
                if f.reflected_in_headers:
                    loc.append(f"headers({', '.join(f.reflected_in_headers)})")
                out.finding(
                    finding_type="Parameter Poisoning",
                    name=f.param_name,
                    severity=Severity.MEDIUM,
                    details=f"Reflected in {', '.join(loc)}",
                    extra={"canary": f.canary} if args.verbose >= 1 else None,
                )
        elif param_reflected:
            out.info(f"\n{len(param_reflected)} parameters reflected (no significant diff):")
            for f in param_reflected:
                loc = []
                if f.reflected_in_body:
                    loc.append("body")
                if f.reflected_in_headers:
                    loc.append(f"headers({', '.join(f.reflected_in_headers)})")
                out.finding(
                    finding_type="Parameter Reflection",
                    name=f.param_name,
                    severity=Severity.LOW,
                    details=f"Reflected in {', '.join(loc)}",
                )
        else:
            out.info("\nNo parameter reflection detected")

        # Summary for parameters
        out.info(f"\nParameter summary: {len(param_findings)} parameters tested, {len(param_reflected)} reflected, {len(param_significant)} potentially vulnerable")

        # Confirm parameter poisoning if --confirm and significant findings exist
        if args.confirm and param_significant:
            out.info("\nConfirming parameter poisoning...")
            for f in param_significant:
                confirmed, msg = confirm_param_poisoning(
                    url,
                    f,
                    timeout=args.timeout,
                    insecure=args.insecure,
                    custom_headers=custom_headers,
                )
                if confirmed:
                    out.finding(
                        finding_type="CONFIRMED Parameter Poisoning",
                        name=f.param_name,
                        severity=Severity.HIGH,
                        details=msg,
                    )
                else:
                    out.debug(f"{f.param_name}: {msg}", level=1)

        # Fat GET scan - only if enabled
        fat_get_findings = []
        fat_get_significant = []
        fat_get_reflected = []
        if args.fat_get:
            fat_get_params = get_fat_get_params()
            method_override_headers = get_method_override_headers()
            out.info(f"\nProbing {len(fat_get_params)} body parameters for fat GET...")
            out.debug(f"Fat GET: testing {len(fat_get_params)} params with {len(method_override_headers)} method override headers", level=1)

            fat_get_findings = probe_all_fat_get(
                url,
                fat_get_params,
                method_override_headers,
                timeout=args.timeout,
                insecure=args.insecure,
                baseline=baseline,
                custom_headers=custom_headers,
            )

            # Categorize fat GET findings
            fat_get_significant = [f for f in fat_get_findings if f.is_significant]
            fat_get_reflected = [f for f in fat_get_findings if f.reflected_in_body or f.reflected_in_headers]
            out.debug(f"Fat GET results: {len(fat_get_reflected)} reflected, {len(fat_get_significant)} significant", level=1)

            # Collect findings for JSON output
            for f in fat_get_reflected:
                out.add_finding(f, "fat_get")

            # Report fat GET findings
            if fat_get_significant:
                out.info(f"\n{len(fat_get_significant)} FAT GET vulnerabilities found:")
                for f in fat_get_significant:
                    loc = []
                    if f.reflected_in_body:
                        loc.append("body")
                    if f.reflected_in_headers:
                        loc.append(f"headers({', '.join(f.reflected_in_headers)})")
                    override_info = f" (via {f.method_override_header})" if f.method_override_header else ""
                    extra = {"canary": f.canary} if args.verbose >= 1 else None
                    if f.method_override_header and extra:
                        extra["override_header"] = f.method_override_header
                    elif f.method_override_header:
                        extra = {"override_header": f.method_override_header}
                    out.finding(
                        finding_type="Fat GET Poisoning",
                        name=f.param_name,
                        severity=Severity.MEDIUM,
                        details=f"Reflected in {', '.join(loc)}{override_info}",
                        extra=extra if extra else None,
                    )
            elif fat_get_reflected:
                out.info(f"\n{len(fat_get_reflected)} body params reflected (no significant diff):")
                for f in fat_get_reflected:
                    loc = []
                    if f.reflected_in_body:
                        loc.append("body")
                    if f.reflected_in_headers:
                        loc.append(f"headers({', '.join(f.reflected_in_headers)})")
                    override_info = f" (via {f.method_override_header})" if f.method_override_header else ""
                    out.finding(
                        finding_type="Fat GET Reflection",
                        name=f.param_name,
                        severity=Severity.LOW,
                        details=f"Reflected in {', '.join(loc)}{override_info}",
                    )
            else:
                out.info("\nNo fat GET reflection detected")

            # Summary for fat GET
            out.info(f"\nFat GET summary: {len(fat_get_params)} params tested, {len(fat_get_reflected)} reflected, {len(fat_get_significant)} vulnerable")

        # WCD (Web Cache Deception) scan - only if enabled
        wcd_findings = []
        wcd_significant = []
        wcd_cached = []
        if args.wcd:
            delimiters = get_path_delimiters()
            extensions = get_static_extensions()
            total_combos = len(delimiters) * len(extensions)
            out.info(f"\nProbing {total_combos} path confusion combinations for WCD...")
            out.debug(f"WCD: testing {len(delimiters)} delimiters x {len(extensions)} extensions", level=1)

            wcd_findings = probe_wcd(
                url,
                baseline,
                delimiters=delimiters,
                extensions=extensions,
                timeout=args.timeout,
                insecure=args.insecure,
                custom_headers=custom_headers,
            )

            # Categorize WCD findings
            wcd_significant = [f for f in wcd_findings if f.is_significant]
            wcd_cached = [f for f in wcd_findings if f.second_request_hit]
            out.debug(f"WCD results: {len(wcd_cached)} cached, {len(wcd_significant)} significant", level=1)

            # Collect findings for JSON output (only cached/significant ones)
            for f in wcd_cached:
                out.add_finding(f, "web_cache_deception")

            # Report WCD findings
            if wcd_significant:
                out.info(f"\n{len(wcd_significant)} WEB CACHE DECEPTION paths found:")
                for f in wcd_significant:
                    extra = {"delimiter": repr(f.delimiter), "extension": f.extension}
                    if args.verbose >= 1:
                        extra["cached"] = f.second_request_hit
                        extra["content_matches"] = f.content_matches_baseline
                    out.finding(
                        finding_type="Web Cache Deception",
                        name=f.confused_path,
                        severity=Severity.HIGH,
                        details=f"Vulnerable path confusion with {repr(f.delimiter)} delimiter",
                        extra=extra,
                    )
            elif wcd_cached:
                out.info(f"\n{len(wcd_cached)} paths cached (content mismatch):")
                for f in wcd_cached:
                    out.finding(
                        finding_type="Web Cache Deception",
                        name=f.confused_path,
                        severity=Severity.MEDIUM,
                        details=f"Cached but content mismatch",
                        extra={"delimiter": repr(f.delimiter), "extension": f.extension},
                    )
            else:
                out.info("\nNo WCD vulnerabilities detected")

            # Summary for WCD
            out.info(f"\nWCD summary: {len(wcd_findings)} paths tested, {len(wcd_cached)} cached, {len(wcd_significant)} vulnerable")

        # Overall summary
        total_significant = len(significant) + len(param_significant) + len(fat_get_significant) + len(wcd_significant)
        total_reflected = len(reflected) + len(param_reflected) + len(fat_get_reflected)
        out.info(f"\n--- Overall ---")
        total_probes = len(findings) + len(param_findings)
        probe_breakdown = f"{len(findings)} headers + {len(param_findings)} parameters"
        if args.fat_get:
            total_probes += len(fat_get_findings)
            probe_breakdown += f" + {len(fat_get_findings)} fat GET"
        if args.wcd:
            total_probes += len(wcd_findings)
            probe_breakdown += f" + {len(wcd_findings)} WCD paths"
        out.info(f"Total probes: {probe_breakdown} = {total_probes}")
        reflected_breakdown = f"{len(reflected)} headers, {len(param_reflected)} parameters"
        if args.fat_get:
            reflected_breakdown += f", {len(fat_get_reflected)} fat GET"
        out.info(f"Reflected: {total_reflected} ({reflected_breakdown})")
        vuln_breakdown = f"{len(significant)} headers, {len(param_significant)} parameters"
        if args.fat_get:
            vuln_breakdown += f", {len(fat_get_significant)} fat GET"
        if args.wcd:
            vuln_breakdown += f", {len(wcd_significant)} WCD"
        out.info(f"Potentially vulnerable: {total_significant} ({vuln_breakdown})")

        if args.verbose >= 1:
            out.info("\nResponse headers:")
            for name, value in baseline.headers.items():
                out.info(f"  {name}: {value}")

        return 0

    except ssl.SSLCertVerificationError:
        out.error("Error: SSL certificate verification failed (use --insecure to skip)")
        return 1

    except socket.timeout:
        out.error("Error: Request timed out")
        return 1

    except ConnectionRefusedError:
        out.error("Error: Connection refused")
        return 1

    except socket.gaierror as e:
        out.error(f"Error: Could not resolve hostname ({e})")
        return 1

    except OSError as e:
        out.error(f"Error: {e}")
        return 1

    except Exception as e:
        out.error(f"Error: {e}")
        return 1


def main() -> int:
    """Main entry point for venom-cache CLI."""
    parser = build_parser()
    args = parser.parse_args()

    # Handle --all flag to enable all detection modes
    if args.all:
        args.wcd = True
        args.fat_get = True

    # Determine output mode first (needed for confirm warning)
    if args.json:
        mode = OutputMode.JSON
    elif args.quiet:
        mode = OutputMode.QUIET
    else:
        mode = OutputMode.NORMAL

    # Create output handler early for warnings
    out = Output(mode, args.verbose)

    # Display warning if confirm mode enabled
    if args.confirm:
        out.warning("CONFIRM MODE ENABLED")
        out.warning("This will affect shared caches and may serve poisoned responses to real users.")
        out.warning("Only use on targets you have permission to test.")

    # Configure rate limiting if delay specified
    if args.delay > 0:
        from venom_cache.rate_limiter import configure_rate_limiter

        configure_rate_limiter(args.delay)

    # Build custom headers from -H and -c flags
    custom_headers = build_request_headers(args.headers, args.cookies)

    # Get target URLs from either positional arg or file
    try:
        urls = get_target_urls(args)
    except ValueError as e:
        out.error(str(e))
        return 1

    # Batch scanning
    total_urls = len(urls)
    success_count = 0
    failure_count = 0

    for i, url in enumerate(urls, 1):
        if total_urls > 1:
            out.info(f"\n{'=' * 60}")
            out.info(f"Scanning URL {i} of {total_urls}: {url}")
            out.info("=" * 60)

        result = scan_url(url, args, out, custom_headers)

        if result == 0:
            success_count += 1
        else:
            failure_count += 1

    # Batch summary if multiple URLs
    if total_urls > 1:
        out.info(f"\n{'=' * 60}")
        out.info("BATCH SUMMARY")
        out.info("=" * 60)
        out.info(f"URLs scanned: {total_urls}")
        out.info(f"Successful: {success_count}")
        out.info(f"Failed: {failure_count}")

    # Finalize output (prints JSON if in JSON mode)
    out.finalize()

    # Return 0 if any succeeded, 1 if all failed
    return 0 if success_count > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
