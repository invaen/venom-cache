"""HTTP transport layer using http.client for raw header control."""

import http.client
import ssl
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse


class TargetConnection:
    """Reusable connection to a single target with connection pooling."""

    def __init__(
        self,
        url: str,
        timeout: float = 10.0,
        insecure: bool = False,
    ) -> None:
        """Initialize connection parameters.

        Args:
            url: Target URL to connect to
            timeout: Request timeout in seconds
            insecure: If True, disable SSL certificate verification
        """
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
    ) -> Tuple[int, Dict[str, str], bytes]:
        """Make HTTP request and return response.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path (uses stored path if None)
            headers: Optional headers to include

        Returns:
            Tuple of (status_code, response_headers, body)
        """
        if path is None:
            path = self.path

        if headers is None:
            headers = {}

        conn = self._get_connection()

        try:
            conn.request(method, path, headers=headers)
            response = conn.getresponse()

            status = response.status
            resp_headers = dict(response.getheaders())
            body = response.read()

            return (status, resp_headers, body)

        except (http.client.HTTPException, ConnectionError, OSError):
            # Connection died, reset and retry once
            self.close()
            conn = self._get_connection()
            conn.request(method, path, headers=headers)
            response = conn.getresponse()

            status = response.status
            resp_headers = dict(response.getheaders())
            body = response.read()

            return (status, resp_headers, body)

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
) -> Tuple[int, Dict[str, str], bytes]:
    """Make a one-off HTTP request.

    Convenience function that creates a connection, makes the request,
    and closes the connection.

    Args:
        url: Full URL to request
        headers: Optional headers to include
        timeout: Request timeout in seconds
        insecure: If True, disable SSL certificate verification

    Returns:
        Tuple of (status_code, response_headers, body)
    """
    with TargetConnection(url, timeout=timeout, insecure=insecure) as conn:
        return conn.request(headers=headers)
