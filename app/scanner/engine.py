"""Bounded orchestration for passive, low-impact checks."""
from datetime import datetime, timezone
import http.client
from uuid import uuid4
from urllib.parse import urlsplit, urlunsplit
from .cookies import check_cookies
from .exposed_paths import SAFE_PATHS
from .findings import Finding, severity_summary
from .headers import check_headers
from .http_client import SafeClient
from .target_validation import validate_target
from .tls_checks import inspect_tls

VERSION = "0.1.0"
MAX_HTTP_REQUESTS = 3

def run_scan(raw_url: str, *, local_lab: bool = False, path_checks: bool = True) -> dict:
    target = validate_target(raw_url, local_lab=local_lab)
    parts = urlsplit(target)
    client = SafeClient(local_lab=local_lab)
    findings: list[Finding] = []
    errors: list[str] = []
    checks = ["target validation", "HTTP security headers", "cookie attributes", "TLS certificate connection"]
    if path_checks: checks.append("fixed public metadata paths")
    try:
        response = client.get(target)
        findings.extend(check_headers(dict(response.headers), https=parts.scheme == "https"))
        findings.extend(check_cookies(response.raw.headers.getlist("Set-Cookie"), https=parts.scheme == "https"))
        if response.is_redirect:
            errors.append("A redirect was observed and not followed; destination remains unassessed.")
    except (http.client.HTTPException, ValueError, OSError) as exc:
        errors.append(f"Main request incomplete: {type(exc).__name__}.")
    tls = inspect_tls(target, local_lab=local_lab) if parts.scheme == "https" else {"used": False, "ok": False, "detail": "HTTPS is not in use."}
    if path_checks:
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        for path in SAFE_PATHS[:MAX_HTTP_REQUESTS - 1]:
            try:
                result = client.get(origin + path)
                if result.status_code == 200:
                    findings.append(Finding("path." + path.strip("/"), f"Public metadata path responds: {path}", "Exposed paths", "Informational", "A fixed, commonly public path returned HTTP 200; this is a review signal only.", f"Path: {path}; status: 200; content type: {result.headers.get('Content-Type', 'unknown')}; body size: {len(result.content)} bytes.", "Public metadata may be expected and does not establish exposure of sensitive data.", "Review that the response contains only intended public information.", "Low", "The body was not stored or inspected."))
            except (http.client.HTTPException, ValueError, OSError) as exc:
                errors.append(f"Path check {path} incomplete: {type(exc).__name__}.")
    return {"scan_id": str(uuid4()), "timestamp_utc": datetime.now(timezone.utc).isoformat(), "target": target, "hostname": parts.hostname, "permitted_scope": parts.hostname, "tool_version": VERSION, "checks_performed": checks, "checks_skipped": [], "summary": severity_summary(findings), "findings": [f.to_dict() for f in findings], "errors": errors, "tls": tls, "disclaimer": "Automated limited assessment; findings require human validation. Severity is an estimate, not a confirmed business-impact rating."}
