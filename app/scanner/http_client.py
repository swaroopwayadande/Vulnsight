"""Bounded HTTP client that pins each connection to an approved DNS answer."""
import http.client
import socket
import ssl
from urllib.parse import urlsplit

from .target_validation import resolve_addresses, validate_target


class HeaderCollection(dict):
    """Case-preserving headers with access to duplicate fields such as Set-Cookie."""
    def __init__(self, pairs):
        super().__init__(pairs)
        self._pairs = pairs

    def getlist(self, name: str) -> list[str]:
        return [value for key, value in self._pairs if key.lower() == name.lower()]


class ScanResponse:
    def __init__(self, status_code: int, pairs: list[tuple[str, str]], content: bytes):
        self.status_code = status_code
        self.headers = HeaderCollection(pairs)
        self.raw = type("RawHeaders", (), {"headers": self.headers})()
        self.content = content
        self.is_redirect = 300 <= status_code < 400


class SafeClient:
    def __init__(self, *, local_lab: bool = False, timeout: float = 5, max_bytes: int = 65536):
        self.local_lab, self.timeout, self.max_bytes = local_lab, timeout, max_bytes

    def get(self, url: str) -> ScanResponse:
        """Make one bounded GET, validating and pinning the selected network address."""
        target = validate_target(url, local_lab=self.local_lab)
        parts = urlsplit(target)
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
        records = resolve_addresses(host, port, local_lab=self.local_lab)
        family, socktype, proto, _canonname, sockaddr = records[0]
        pinned_ip = sockaddr[0]

        class PinnedHTTPConnection(http.client.HTTPConnection):
            def connect(self):
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(self.timeout)
                sock.connect(sockaddr)
                self.sock = sock

        class PinnedHTTPSConnection(http.client.HTTPSConnection):
            def connect(self):
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(self.timeout)
                sock.connect(sockaddr)
                self.sock = self._context.wrap_socket(sock, server_hostname=host)

        connection_type = PinnedHTTPSConnection if parts.scheme == "https" else PinnedHTTPConnection
        kwargs = {"timeout": self.timeout}
        if parts.scheme == "https":
            kwargs["context"] = ssl.create_default_context()
        connection = connection_type(host, port, **kwargs)
        host_header = f"[{host}]" if ":" in host else host
        if parts.port:
            host_header += f":{parts.port}"
        request_target = parts.path or "/"
        if parts.query:
            request_target += "?" + parts.query
        try:
            connection.request("GET", request_target, headers={
                "Host": host_header,
                "User-Agent": "VulnSight/0.1 (authorized assessment)",
                "Accept-Encoding": "identity",
                "Connection": "close",
            })
            response = connection.getresponse()
            body = response.read(self.max_bytes + 1)
            if len(body) > self.max_bytes:
                raise ValueError("Response exceeded configured size limit.")
            return ScanResponse(response.status, response.getheaders(), body)
        finally:
            connection.close()
