"""Standard certificate-validated TLS connection check."""

import socket
import ssl
from urllib.parse import urlsplit

from .target_validation import resolve_addresses


def inspect_tls(url: str, timeout: float = 5.0, *, local_lab: bool = False) -> dict:
    """Validate a TLS connection using the platform certificate store."""
    parts = urlsplit(url)
    host = parts.hostname
    port = parts.port or 443
    if parts.scheme != "https" or not host:
        return {
            "used": False,
            "ok": False,
            "detail": "HTTPS is not in use for the submitted URL.",
        }

    try:
        context = ssl.create_default_context()
        address_record = resolve_addresses(host, port, local_lab=local_lab)[0]
        family, socket_type, protocol, _canonname, sockaddr = address_record
        raw_socket = socket.socket(family, socket_type, protocol)
        raw_socket.settimeout(timeout)
        raw_socket.connect(sockaddr)
        with raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
                return {
                    "used": True,
                    "ok": True,
                    "certificate_valid": True,
                    "expired": False,
                    "hostname_match": True,
                    "subject": certificate.get("subject", ()),
                    "notAfter": certificate.get("notAfter"),
                    "tls_version": tls_socket.version(),
                }
    except ssl.SSLCertVerificationError as exc:
        message = getattr(exc, "verify_message", None) or "Certificate verification failed."
        normalized_message = message.lower()
        return {
            "used": True,
            "ok": False,
            "certificate_valid": False,
            "expired": True if "expired" in normalized_message else None,
            "hostname_match": (
                False
                if any(term in normalized_message for term in ("hostname", "ip address mismatch"))
                else None
            ),
            "detail": message,
        }
    except (OSError, ssl.SSLError, TimeoutError, ValueError) as exc:
        return {
            "used": True,
            "ok": False,
            "certificate_valid": False,
            "detail": f"TLS validation/connection failed: {type(exc).__name__}.",
        }
