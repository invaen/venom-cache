"""Command-line interface for venom-cache."""

import argparse
import pathlib
import socket
import ssl
import sys
from typing import Tuple

from venom_cache.baseline import check_response_stability
from venom_cache.cache_buster import verify_cache_buster_isolation
from venom_cache.cache_detector import detect_cache_headers, get_cache_info
from venom_cache.fat_get_prober import probe_all_fat_get
from venom_cache.header_prober import probe_headers
from venom_cache.http_transport import make_request
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
        "--json",
        action="store_true",
        help="JSON output mode (machine-readable)",
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


def scan_url(url: str, args: argparse.Namespace, custom_headers: dict = None) -> int:
    """Scan a single URL for cache poisoning vulnerabilities.

    Args:
        url: Target URL to scan
        args: Parsed command line arguments
        custom_headers: Optional custom headers to include in all requests

    Returns:
        0 on success, 1 on error
    """
    if custom_headers is None:
        custom_headers = {}

    # Validate URL scheme
    if not url.startswith(("http://", "https://")):
        print(
            f"Error: URL must start with http:// or https:// (got: {url})",
            file=sys.stderr,
        )
        return 1

    # Verify cache buster isolation FIRST
    print("Verifying cache buster isolation...")
    is_safe, message = verify_cache_buster_isolation(
        url, args.timeout, args.insecure, headers=custom_headers
    )
    if not is_safe:
        print(f"ERROR: {message}", file=sys.stderr)
        print(
            "Cache buster isolation is required for safe operation. Aborting.",
            file=sys.stderr,
        )
        return 1
    if args.verbose >= 1:
        print(f"OK: {message}")

    # Proceed with scanning
    print(f"\nScanning {url}...")

    try:
        # Establish baseline and check response stability
        baseline, diff, is_stable = check_response_stability(
            url,
            timeout=args.timeout,
            insecure=args.insecure,
            headers=custom_headers,
        )

        print(f"Status: {baseline.status}")

        # Detect and display cache status
        cache_status = detect_cache_headers(baseline.headers)
        print(get_cache_info(baseline.headers))

        print(f"Response size: {baseline.body_length} bytes")

        # Report baseline info
        print(f"\nBaseline established ({baseline.body_length} bytes, sha256:{baseline.body_hash}...)")

        if is_stable:
            print("Response stability: Stable (no significant changes between requests)")
        else:
            print("WARNING: Response unstable - content changes between requests")
            print("This may cause false positives during poisoning detection")

        if args.verbose >= 1:
            # Show cache evidence
            if cache_status.evidence:
                print("\nCache evidence:")
                for ev in cache_status.evidence:
                    print(f"  {ev}")

            # Show response comparison details
            print("\nResponse comparison:")
            print(f"  Status: {'changed' if diff.status_changed else 'unchanged'} ({baseline.status})")
            if diff.headers_changed:
                print(f"  Headers changed: {', '.join(diff.headers_changed)}")
            else:
                print("  Headers: no significant changes")
            print(f"  Body: {baseline.body_length} -> {baseline.body_length + diff.content_length_delta} bytes ({diff.content_length_delta:+d})")
            print(f"  Static content: {'changed' if diff.static_body_changed else 'identical'}")

        # Header poisoning scan
        wordlist = get_header_wordlist_with_custom(args.wordlist)
        print(f"\nProbing {len(wordlist)} headers for reflection...")

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

        # Report findings
        if significant:
            print(f"\n[!] {len(significant)} POTENTIALLY VULNERABLE headers found:")
            for f in significant:
                loc = []
                if f.reflected_in_body:
                    loc.append("body")
                if f.reflected_in_headers:
                    loc.append(f"headers({', '.join(f.reflected_in_headers)})")
                print(f"    {f.header_name} -> reflected in {', '.join(loc)}")
                if args.verbose >= 1:
                    print(f"        Canary: {f.canary}")
        elif reflected:
            print(f"\n[*] {len(reflected)} headers reflected (no significant diff):")
            for f in reflected:
                loc = []
                if f.reflected_in_body:
                    loc.append("body")
                if f.reflected_in_headers:
                    loc.append(f"headers({', '.join(f.reflected_in_headers)})")
                print(f"    {f.header_name} -> {', '.join(loc)}")
        else:
            print("\n[+] No header reflection detected")

        # Summary for headers
        print(f"\nHeader summary: {len(findings)} headers tested, {len(reflected)} reflected, {len(significant)} potentially vulnerable")

        # Parameter poisoning scan
        param_wordlist = get_param_wordlist()
        print(f"\nProbing {len(param_wordlist)} parameters for reflection...")

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

        # Report parameter findings
        if param_significant:
            print(f"\n[!] {len(param_significant)} POTENTIALLY VULNERABLE parameters found:")
            for f in param_significant:
                loc = []
                if f.reflected_in_body:
                    loc.append("body")
                if f.reflected_in_headers:
                    loc.append(f"headers({', '.join(f.reflected_in_headers)})")
                print(f"    {f.param_name} -> reflected in {', '.join(loc)}")
                if args.verbose >= 1:
                    print(f"        Canary: {f.canary}")
        elif param_reflected:
            print(f"\n[*] {len(param_reflected)} parameters reflected (no significant diff):")
            for f in param_reflected:
                loc = []
                if f.reflected_in_body:
                    loc.append("body")
                if f.reflected_in_headers:
                    loc.append(f"headers({', '.join(f.reflected_in_headers)})")
                print(f"    {f.param_name} -> {', '.join(loc)}")
        else:
            print("\n[+] No parameter reflection detected")

        # Summary for parameters
        print(f"\nParameter summary: {len(param_findings)} parameters tested, {len(param_reflected)} reflected, {len(param_significant)} potentially vulnerable")

        # Fat GET scan - only if enabled
        fat_get_findings = []
        fat_get_significant = []
        fat_get_reflected = []
        if args.fat_get:
            fat_get_params = get_fat_get_params()
            method_override_headers = get_method_override_headers()
            print(f"\nProbing {len(fat_get_params)} body parameters for fat GET...")

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

            # Report fat GET findings
            if fat_get_significant:
                print(f"\n[!] {len(fat_get_significant)} FAT GET vulnerabilities found:")
                for f in fat_get_significant:
                    loc = []
                    if f.reflected_in_body:
                        loc.append("body")
                    if f.reflected_in_headers:
                        loc.append(f"headers({', '.join(f.reflected_in_headers)})")
                    override_info = f" (via {f.method_override_header})" if f.method_override_header else ""
                    print(f"    {f.param_name}{override_info} -> reflected in {', '.join(loc)}")
                    if args.verbose >= 1:
                        print(f"        Canary: {f.canary}")
            elif fat_get_reflected:
                print(f"\n[*] {len(fat_get_reflected)} body params reflected (no significant diff):")
                for f in fat_get_reflected:
                    loc = []
                    if f.reflected_in_body:
                        loc.append("body")
                    if f.reflected_in_headers:
                        loc.append(f"headers({', '.join(f.reflected_in_headers)})")
                    override_info = f" (via {f.method_override_header})" if f.method_override_header else ""
                    print(f"    {f.param_name}{override_info} -> {', '.join(loc)}")
            else:
                print("\n[+] No fat GET reflection detected")

            # Summary for fat GET
            print(f"\nFat GET summary: {len(fat_get_params)} params tested, {len(fat_get_reflected)} reflected, {len(fat_get_significant)} vulnerable")

        # WCD (Web Cache Deception) scan - only if enabled
        wcd_findings = []
        wcd_significant = []
        wcd_cached = []
        if args.wcd:
            delimiters = get_path_delimiters()
            extensions = get_static_extensions()
            total_combos = len(delimiters) * len(extensions)
            print(f"\nProbing {total_combos} path confusion combinations for WCD...")

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

            # Report WCD findings
            if wcd_significant:
                print(f"\n[!] {len(wcd_significant)} WEB CACHE DECEPTION paths found:")
                for f in wcd_significant:
                    print(f"    {f.confused_path}")
                    print(f"        delimiter: {repr(f.delimiter)}, extension: {f.extension}")
                    if args.verbose >= 1:
                        print(f"        cached: {f.second_request_hit}, content matches: {f.content_matches_baseline}")
            elif wcd_cached:
                print(f"\n[*] {len(wcd_cached)} paths cached (content mismatch):")
                for f in wcd_cached:
                    print(f"    {f.confused_path} (delimiter: {repr(f.delimiter)}, extension: {f.extension})")
            else:
                print("\n[+] No WCD vulnerabilities detected")

            # Summary for WCD
            print(f"\nWCD summary: {len(wcd_findings)} paths tested, {len(wcd_cached)} cached, {len(wcd_significant)} vulnerable")

        # Overall summary
        total_significant = len(significant) + len(param_significant) + len(fat_get_significant) + len(wcd_significant)
        total_reflected = len(reflected) + len(param_reflected) + len(fat_get_reflected)
        print(f"\n--- Overall ---")
        total_probes = len(findings) + len(param_findings)
        probe_breakdown = f"{len(findings)} headers + {len(param_findings)} parameters"
        if args.fat_get:
            total_probes += len(fat_get_findings)
            probe_breakdown += f" + {len(fat_get_findings)} fat GET"
        if args.wcd:
            total_probes += len(wcd_findings)
            probe_breakdown += f" + {len(wcd_findings)} WCD paths"
        print(f"Total probes: {probe_breakdown} = {total_probes}")
        reflected_breakdown = f"{len(reflected)} headers, {len(param_reflected)} parameters"
        if args.fat_get:
            reflected_breakdown += f", {len(fat_get_reflected)} fat GET"
        print(f"Reflected: {total_reflected} ({reflected_breakdown})")
        vuln_breakdown = f"{len(significant)} headers, {len(param_significant)} parameters"
        if args.fat_get:
            vuln_breakdown += f", {len(fat_get_significant)} fat GET"
        if args.wcd:
            vuln_breakdown += f", {len(wcd_significant)} WCD"
        print(f"Potentially vulnerable: {total_significant} ({vuln_breakdown})")

        if args.verbose >= 1:
            print("\nResponse headers:")
            for name, value in baseline.headers.items():
                print(f"  {name}: {value}")

        return 0

    except ssl.SSLCertVerificationError:
        print(
            "Error: SSL certificate verification failed (use --insecure to skip)",
            file=sys.stderr,
        )
        return 1

    except socket.timeout:
        print("Error: Request timed out", file=sys.stderr)
        return 1

    except ConnectionRefusedError:
        print("Error: Connection refused", file=sys.stderr)
        return 1

    except socket.gaierror as e:
        print(f"Error: Could not resolve hostname ({e})", file=sys.stderr)
        return 1

    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """Main entry point for venom-cache CLI."""
    parser = build_parser()
    args = parser.parse_args()

    # Handle --all flag to enable all detection modes
    if args.all:
        args.wcd = True
        args.fat_get = True

    # Build custom headers from -H and -c flags
    custom_headers = build_request_headers(args.headers, args.cookies)

    # Get target URLs from either positional arg or file
    try:
        urls = get_target_urls(args)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 1

    # Batch scanning
    total_urls = len(urls)
    success_count = 0
    failure_count = 0

    for i, url in enumerate(urls, 1):
        if total_urls > 1:
            print(f"\n{'=' * 60}")
            print(f"Scanning URL {i} of {total_urls}: {url}")
            print("=" * 60)

        result = scan_url(url, args, custom_headers)

        if result == 0:
            success_count += 1
        else:
            failure_count += 1

    # Batch summary if multiple URLs
    if total_urls > 1:
        print(f"\n{'=' * 60}")
        print("BATCH SUMMARY")
        print("=" * 60)
        print(f"URLs scanned: {total_urls}")
        print(f"Successful: {success_count}")
        print(f"Failed: {failure_count}")

    # Return 0 if any succeeded, 1 if all failed
    return 0 if success_count > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
