import pytest
from fastapi import HTTPException

from app import main


def test_api_requires_authorization_confirmation():
    payload = main.ScanRequest(url="https://example.test", authorized=False)
    with pytest.raises(HTTPException) as error:
        main.create_scan(payload)
    assert error.value.status_code == 400


def test_api_rejects_loopback_without_lab_mode():
    payload = main.ScanRequest(url="http://127.0.0.1", authorized=True)
    with pytest.raises(HTTPException) as error:
        main.create_scan(payload)
    assert error.value.status_code == 422


def test_api_saves_scan_result(monkeypatch):
    expected = {"scan_id": "test-id", "hostname": "example.test"}
    saved = []
    monkeypatch.setattr(main, "run_scan", lambda *args, **kwargs: expected)
    monkeypatch.setattr(main, "save_scan", saved.append)
    result = main.create_scan(main.ScanRequest(url="https://example.test", authorized=True))
    assert result == expected
    assert saved == [expected]
