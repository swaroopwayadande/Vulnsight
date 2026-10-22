"""URL normalization and public-network scope validation."""

import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit


class TargetError(ValueError):
    """Raised when a target is malformed or outside permitted scope."""


def resolve_addresses(host: str, port: int, *, local_lab: bool = False):
    """Resolve and validate addresses, returning records that can be pinned to sockets."""
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = [ipaddress.ip_address(record[4][0]) for record in records]
    except (OSError, ValueError) as exc:
        raise TargetError("The hostname could not be resolved safely.") from exc

    if not addresses:
        raise TargetError("The hostname returned no usable addresses.")
    if local_lab:
        unsafe = any(not (address.is_loopback or address.is_global) for address in addresses)
    else:
        unsafe = any(not address.is_global for address in addresses)
    if unsafe:
        raise TargetError("The target resolves to a non-public address and is blocked by default.")
    return records


def validate_target(raw: str, *, local_lab: bool = False, resolve: bool = True) -> str:
    """Normalize one HTTP(S) URL and reject unsafe or ambiguous target scope."""
    value = raw.strip()
    has_control_chars = any(ord(char) < 32 or ord(char) == 127 for char in value)
    if not value or len(value) > 2048 or has_control_chars:
        raise TargetError("Enter a valid HTTP or HTTPS URL (maximum 2048 characters).")

    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise TargetError("The URL contains an invalid host or port.") from exc

    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise TargetError("Only complete HTTP or HTTPS URLs are accepted.")
    if parts.username is not None or parts.password is not None:
        raise TargetError("Credentials embedded in URLs are not allowed.")

    host = parts.hostname.rstrip(".").lower()
    if not host or any(char.isspace() for char in host):
        raise TargetError("The URL contains an invalid hostname.")
    if port is not None and not 1 <= port <= 65535:
        raise TargetError("The URL contains an invalid port.")
    if (host == "localhost" or host.endswith(".localhost")) and not local_lab:
        raise TargetError("Localhost requires explicit local-lab mode.")

    try:
        literal_address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise TargetError("The hostname is not valid internationalized domain syntax.") from exc
        labels = host.split(".")
        valid_label = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
        if len(host) > 253 or any(not valid_label.fullmatch(label) for label in labels):
            raise TargetError("The URL contains an invalid hostname.")
        if resolve:
            default_port = 443 if parts.scheme.lower() == "https" else 80
            resolve_addresses(host, port or default_port, local_lab=local_lab)
    else:
        if local_lab:
            permitted = literal_address.is_loopback or literal_address.is_global
        else:
            permitted = literal_address.is_global
        if not permitted:
            raise TargetError(
                "The target resolves to a non-public address and is blocked by default."
            )

    normalized_host = f"[{host}]" if ":" in host else host
    netloc = normalized_host + (f":{port}" if port is not None else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def validate_redirect(source: str, destination: str, *, local_lab: bool = False) -> str:
    """Allow redirects only to the original hostname and revalidate the destination."""
    normalized = validate_target(destination, local_lab=local_lab)
    if urlsplit(source).hostname != urlsplit(normalized).hostname:
        raise TargetError("Cross-host redirects are outside the authorized scope.")
    return normalized
