"""Standard certificate-validated TLS connection check."""
import socket, ssl
from urllib.parse import urlsplit
from .target_validation import resolve_addresses

def inspect_tls(url: str, timeout: float = 5.0, *, local_lab: bool = False) -> dict:
    parts = urlsplit(url); host = parts.hostname; port = parts.port or 443
    if parts.scheme != "https" or not host:
        return {"used": False, "ok": False, "detail": "HTTPS is not in use for the submitted URL."}
    try:
        context = ssl.create_default_context()
        family, socktype, proto, _canonname, sockaddr = resolve_addresses(host, port, local_lab=local_lab)[0]
        raw = socket.socket(family, socktype, proto)
        raw.settimeout(timeout)
        raw.connect(sockaddr)
        with raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                return {"used": True, "ok": True, "subject": cert.get("subject", ()), "notAfter": cert.get("notAfter"), "tls_version": tls.version()}
    except (OSError, ssl.SSLError, TimeoutError, ValueError) as exc:
        return {"used": True, "ok": False, "detail": f"TLS validation/connection failed: {type(exc).__name__}."}
