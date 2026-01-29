"""Command-line interface for venom-cache."""

import argparse
import sys


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

    # Placeholder output until HTTP transport is implemented
    print(f"Scanning {args.url}...")
    print("HTTP transport not yet implemented")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
