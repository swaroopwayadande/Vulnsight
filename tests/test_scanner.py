import io
import socket
import ssl

import pytest

from app.scanner.cookies import check_cookies
from app.scanner.exposed_paths import classify_path_response
from app.scanner.findings import Finding, severity_summary
from app.scanner.headers import check_headers
from app.scanner.http_client import SafeClient
from app.scanner.target_validation import TargetError, validate_redirect, validate_target
from app.scanner.tls_checks import inspect_tls
from app.scanner import tls_checks


def test_rejects_bad_scheme_and_embedded_credentials():
    with pytest.raises(TargetError):
        validate_target("file:///etc/passwd", resolve=False)
    with pytest.raises(TargetError):
        validate_target("https://user:pass@example.com", resolve=False)


def test_blocks_private_and_loopback_literals():
    unsafe_urls = (
        "http://127.0.0.1",
        "http://10.0.0.1",
        "http://169.254.169.254",
    )
    for url in unsafe_urls:
        with pytest.raises(TargetError):
            validate_target(url)


def test_local_lab_is_explicit():
    target = validate_target("http://127.0.0.1:9000", local_lab=True)
    assert target == "http://127.0.0.1:9000/"
    with pytest.raises(TargetError):
        validate_target("http://127.0.0.1")


def test_redirect_must_stay_on_same_host(monkeypatch):
    public_answer = [(None, None, None, None, ("93.184.216.34", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: public_answer)
    with pytest.raises(TargetError):
        validate_redirect("https://example.com", "https://other.example")


def test_hostname_with_private_dns_answer_is_rejected(monkeypatch):
    private_answer = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.2", 80))
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: private_answer)
    with pytest.raises(TargetError):
        validate_target("http://private.test")


def test_non_https_tls_check_is_informational():
    result = inspect_tls("http://example.test")
    assert result["used"] is False


class FakeSocket:
    """Minimal fake socket for exercising the bounded HTTP transport."""

    def __init__(self, response: bytes):
        self.response = response
        self.sent = []
        self.address = None
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.address = address

    def sendall(self, data):
        self.sent.append(data)

    def makefile(self, *_args, **_kwargs):
        return io.BytesIO(self.response)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def test_http_response_is_size_limited_and_redirect_not_followed(monkeypatch):
    large_body = b"x" * 100
    large_response = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + large_body
    fake_socket = FakeSocket(large_response)
    monkeypatch.setattr(
        "app.scanner.http_client.socket.socket",
        lambda *_args: fake_socket,
    )
    client = SafeClient(local_lab=True, timeout=1, max_bytes=10)
    with pytest.raises(ValueError, match="size limit"):
        client.get("http://127.0.0.1:8080/large")
    assert fake_socket.address[0] == "127.0.0.1"

    redirect_response = (
        b"HTTP/1.1 302 Found\r\n"
        b"Location: /elsewhere\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    redirect_socket = FakeSocket(redirect_response)
    monkeypatch.setattr(
        "app.scanner.http_client.socket.socket",
        lambda *_args: redirect_socket,
    )
    response = SafeClient(local_lab=True, timeout=1).get(
        "http://127.0.0.1:8080/redirect"
    )
    assert response.is_redirect
    assert response.status_code == 302
    assert len(redirect_socket.sent) == 1


def test_http_transport_applies_timeout(monkeypatch):
    fake_socket = FakeSocket(b"")
    def timeout_on_connect(_address):
        raise TimeoutError("connection timed out")
    fake_socket.connect = timeout_on_connect
    monkeypatch.setattr(
        "app.scanner.http_client.socket.socket",
        lambda *_args: fake_socket,
    )
    with pytest.raises(TimeoutError):
        SafeClient(local_lab=True, timeout=2).get("http://127.0.0.1:8080/")
    assert fake_socket.timeout == 2


def test_tls_success_uses_hostname_and_reports_certificate(monkeypatch):
    raw_socket = FakeSocket(b"")
    tls_socket = FakeSocket(b"")
    tls_socket.getpeercert = lambda: {
        "subject": ((('commonName', 'example.test'),),),
        "notAfter": "Dec 31 23:59:59 2030 GMT",
    }
    tls_socket.version = lambda: "TLSv1.3"

    class FakeContext:
        def wrap_socket(self, _raw, *, server_hostname):
            assert server_hostname == "example.test"
            return tls_socket

    public_answer = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
    ]
    monkeypatch.setattr(
        tls_checks,
        "resolve_addresses",
        lambda *args, **kwargs: public_answer,
    )
    monkeypatch.setattr(tls_checks.ssl, "create_default_context", FakeContext)
    monkeypatch.setattr(tls_checks.socket, "socket", lambda *_args: raw_socket)
    result = inspect_tls("https://example.test")
    assert result["ok"] is True
    assert result["hostname_match"] is True
    assert result["tls_version"] == "TLSv1.3"


def test_tls_hostname_mismatch_is_reported(monkeypatch):
    error = ssl.SSLCertVerificationError(62, "certificate verify failed")
    error.verify_message = "Hostname mismatch"
    raw_socket = FakeSocket(b"")

    class FakeContext:
        def wrap_socket(self, _raw, *, server_hostname):
            raise error

    public_answer = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
    ]
    monkeypatch.setattr(
        tls_checks,
        "resolve_addresses",
        lambda *args, **kwargs: public_answer,
    )
    monkeypatch.setattr(tls_checks.ssl, "create_default_context", FakeContext)
    monkeypatch.setattr(tls_checks.socket, "socket", lambda *_args: raw_socket)
    result = inspect_tls("https://example.test")
    assert result["ok"] is False
    assert result["hostname_match"] is False


def test_header_findings_observe_present_values():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
    }
    findings = check_headers(headers, https=True)
    finding_ids = {finding.id for finding in findings}
    assert "header.content-security-policy" not in finding_ids
    assert "header.strict-transport-security" in finding_ids


def test_header_checks_detect_ineffective_protective_values():
    headers = {
        "Strict-Transport-Security": "max-age=0",
        "X-Frame-Options": "ALLOWALL",
    }
    findings = check_headers(headers, https=True)
    finding_ids = {finding.id for finding in findings}
    assert "header.strict-transport-security" in finding_ids
    assert "header.framing" in finding_ids


def test_cookie_values_are_redacted():
    findings = check_cookies(["session=secret-value; Path=/"], https=True)
    assert findings
    assert all("secret-value" not in finding.evidence for finding in findings)


def test_samesite_none_requires_secure():
    findings = check_cookies(["auth=hidden; SameSite=None"], https=False)
    assert any(
        "SameSite=None without Secure" in finding.evidence for finding in findings
    )
    assert all("hidden" not in finding.evidence for finding in findings)


def test_invalid_samesite_value_is_reported():
    findings = check_cookies(["prefs=value; SameSite=unexpected"], https=True)
    assert any("SameSite value is invalid" in finding.evidence for finding in findings)


def test_severity_summary_and_finding_serialization():
    item = Finding("a", "title", "cat", "Low", "why", "proof", "impact", "fix")
    assert severity_summary([item])["Low"] == 1
    assert item.to_dict()["evidence"] == "proof"


def test_exposed_path_requires_success_and_is_only_informational():
    assert classify_path_response("/robots.txt", 404, "text/plain", 0) is None
    finding = classify_path_response("/sitemap.xml", 200, "application/xml", 123)
    assert finding is not None
    assert finding.severity == "Informational"
    assert "123 bytes" in finding.evidence
