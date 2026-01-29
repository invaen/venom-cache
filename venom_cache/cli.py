"""Command-line interface for venom-cache."""

import argparse
import socket
import ssl
import sys

from venom_cache.baseline import check_response_stability
from venom_cache.cache_buster import verify_cache_buster_isolation
from venom_cache.cache_detector import detect_cache_headers, get_cache_info
from venom_cache.http_transport import make_request


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
        """,
    )

    parser.add_argument(
        "url",
        help="Target URL to scan (must start with http:// or https://)",
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

    return parser


def main() -> int:
    """Main entry point for venom-cache CLI."""
    parser = build_parser()
    args = parser.parse_args()

    # Validate URL scheme
    if not args.url.startswith(("http://", "https://")):
        print(
            f"Error: URL must start with http:// or https:// (got: {args.url})",
            file=sys.stderr,
        )
        return 1

    # Verify cache buster isolation FIRST
    print("Verifying cache buster isolation...")
    is_safe, message = verify_cache_buster_isolation(
        args.url, args.timeout, args.insecure
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
    print(f"\nScanning {args.url}...")

    try:
        # Establish baseline and check response stability
        baseline, diff, is_stable = check_response_stability(
            args.url,
            timeout=args.timeout,
            insecure=args.insecure,
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


if __name__ == "__main__":
    raise SystemExit(main())
