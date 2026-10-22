import socket
from types import SimpleNamespace

from app.scanner import engine


def test_scan_limits_http_requests_skips_disabled_paths_and_redacts_url_query(monkeypatch):
    public_answer = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
    ]
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: public_answer,
    )

    class FakeResponse:
        status_code = 200
        headers = {"Content-Type": "text/html"}
        content = b"<html></html>"
        is_redirect = False
        raw = SimpleNamespace(headers=SimpleNamespace(getlist=lambda _name: []))

    class FakeClient:
        requests = []

        def __init__(self, **_kwargs):
            pass

        def get(self, url):
            self.requests.append(url)
            return FakeResponse()

    monkeypatch.setattr(engine, "SafeClient", FakeClient)
    monkeypatch.setattr(
        engine,
        "inspect_tls",
        lambda *_args, **_kwargs: {"used": True, "ok": True},
    )
    result = engine.run_scan(
        "https://example.test/?token=private-value",
        path_checks=False,
    )

    assert FakeClient.requests == ["https://example.test/?token=private-value"]
    assert result["target"] == "https://example.test/"
    assert result["checks_skipped"] == [
        "fixed public metadata paths (disabled by operator)"
    ]
    assert "private-value" not in str(result)
