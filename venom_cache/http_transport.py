"""HTTP transport layer using http.client for raw header control."""

import http.client
import ssl
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

from venom_cache.cache_buster import inject_cache_buster
from venom_cache.rate_limiter import rate_limit


class TargetConnection:
    """Reusable connection to a single target with connection pooling."""

    def __init__(
        self,
        url: str,
        timeout: float = 10.0,
        insecure: bool = False,
        use_cache_buster: bool = True,
    ) -> None:
        """Initialize connection parameters.

        Args:
            url: Target URL to connect to
            timeout: Request timeout in seconds
            insecure: If True, disable SSL certificate verification
            use_cache_buster: If True, inject unique cache buster into URL
        """
        # Inject cache buster BEFORE parsing to ensure it's in the path
        if use_cache_buster:
            url = inject_cache_buster(url)

        parsed = urlparse(url)
        self.scheme = parsed.scheme
        self.host = parsed.netloc
        self.path = parsed.path or "/"
        if parsed.query:
            self.path = f"{self.path}?{parsed.query}"
        self.timeout = timeout
        self.insecure = insecure
        self._conn: Optional[http.client.HTTPConnection] = None

    def _get_connection(self) -> http.client.HTTPConnection:
        """Get or create HTTP connection."""
        if self._conn is not None:
            return self._conn

        if self.scheme == "https":
            if self.insecure:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            else:
                context = ssl.create_default_context()

            self._conn = http.client.HTTPSConnection(
                self.host,
                timeout=self.timeout,
                context=context,
            )
        else:
            self._conn = http.client.HTTPConnection(
                self.host,
                timeout=self.timeout,
            )

        return self._conn

    def request(
        self,
        method: str = "GET",
        path: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> Tuple[int, Dict[str, str], bytes]:
        """Make HTTP request and return response.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path (uses stored path if None)
            headers: Optional headers to include
            body: Optional request body (for POST, PUT, or fat GET)

        Returns:
            Tuple of (status_code, response_headers, body)
        """
        # Apply rate limiting before making request
        rate_limit()

        if path is None:
            path = self.path

        if headers is None:
            headers = {}

        # Add Content-Length header if body provided and not already set
        if body is not None:
            headers_lower = {k.lower(): k for k in headers}
            if "content-length" not in headers_lower:
                headers["Content-Length"] = str(len(body))

        conn = self._get_connection()

        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()

            status = response.status
            resp_headers = dict(response.getheaders())
            resp_body = response.read()

            return (status, resp_headers, resp_body)

        except (http.client.HTTPException, ConnectionError, OSError):
            # Connection died, reset and retry once
            self.close()
            conn = self._get_connection()
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()

            status = response.status
            resp_headers = dict(response.getheaders())
            resp_body = response.read()

            return (status, resp_headers, resp_body)

    def close(self) -> None:
        """Close the connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def __enter__(self) -> "TargetConnection":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.close()


def make_request(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
    insecure: bool = False,
    use_cache_buster: bool = True,
    body: Optional[bytes] = None,
) -> Tuple[int, Dict[str, str], bytes]:
    """Make a one-off HTTP request.

    Convenience function that creates a connection, makes the request,
    and closes the connection.

    Args:
        url: Full URL to request
        headers: Optional headers to include
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification
        use_cache_buster: If True, inject unique cache buster into URL
        body: Optional request body (for POST, PUT, or fat GET)

    Returns:
        Tuple of (status_code, response_headers, body)
    """
    with TargetConnection(
        url, timeout=timeout, insecure=insecure, use_cache_buster=use_cache_buster
    ) as conn:
        return conn.request(headers=headers, body=body)
