import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest
from app.scanner.target_validation import TargetError, validate_target, validate_redirect
from app.scanner.headers import check_headers
from app.scanner.cookies import check_cookies
from app.scanner.findings import Finding, severity_summary
from app.scanner.http_client import SafeClient
from app.scanner.tls_checks import inspect_tls

def test_rejects_bad_scheme_and_embedded_credentials():
    with pytest.raises(TargetError): validate_target("file:///etc/passwd", resolve=False)
    with pytest.raises(TargetError): validate_target("https://user:pass@example.com", resolve=False)

def test_blocks_private_and_loopback_literals():
    for url in ("http://127.0.0.1", "http://10.0.0.1", "http://169.254.169.254"):
        with pytest.raises(TargetError): validate_target(url)

def test_local_lab_is_explicit():
    assert validate_target("http://127.0.0.1:9000", local_lab=True) == "http://127.0.0.1:9000/"
    with pytest.raises(TargetError): validate_target("http://127.0.0.1")

def test_redirect_must_stay_on_same_host(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(None,None,None,None,("93.184.216.34",0))])
    with pytest.raises(TargetError): validate_redirect("https://example.com", "https://other.example")

def test_hostname_with_private_dns_answer_is_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.2", 80))])
    with pytest.raises(TargetError): validate_target("http://private.test")

def test_non_https_tls_check_is_informational():
    assert inspect_tls("http://example.test")["used"] is False

@pytest.fixture
def local_http_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/redirect":
                self.send_response(302); self.send_header("Location", "/large"); self.end_headers(); return
            body = b"x" * 100
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            try: self.wfile.write(body)
            except BrokenPipeError: pass
        def log_message(self, *_args): pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)

def test_http_response_is_size_limited_and_redirect_not_followed(local_http_server):
    client = SafeClient(local_lab=True, timeout=1, max_bytes=10)
    with pytest.raises(ValueError, match="size limit"):
        client.get(local_http_server + "/large")
    response = SafeClient(local_lab=True, timeout=1).get(local_http_server + "/redirect")
    assert response.is_redirect and response.status_code == 302

def test_header_findings_observe_present_values():
    findings = check_headers({"Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff"}, https=True)
    assert "header.content-security-policy" not in {f.id for f in findings}
    assert "header.strict-transport-security" in {f.id for f in findings}

def test_cookie_values_are_redacted():
    findings = check_cookies(["session=secret-value; Path=/"], https=True)
    assert findings and all("secret-value" not in f.evidence for f in findings)

def test_severity_summary():
    item = Finding("a", "title", "cat", "Low", "why", "proof", "impact", "fix")
    assert severity_summary([item])["Low"] == 1
