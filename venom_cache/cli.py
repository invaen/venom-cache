"""Command-line interface for venom-cache."""

import argparse
import socket
import ssl
import sys

from venom_cache.cache_buster import verify_cache_buster_isolation
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
        status, headers, body = make_request(
            args.url,
            timeout=args.timeout,
            insecure=args.insecure,
        )

        print(f"Status: {status}")
        print(f"Response size: {len(body)} bytes")

        if args.verbose >= 1:
            print("\nResponse headers:")
            for name, value in headers.items():
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
