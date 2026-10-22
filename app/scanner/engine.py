"""Bounded orchestration for passive, low-impact checks."""

import http.client
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from .cookies import check_cookies
from .exposed_paths import SAFE_PATHS, classify_path_response
from .findings import severity_summary
from .headers import check_headers
from .http_client import SafeClient
from .target_validation import validate_target
from .tls_checks import inspect_tls

VERSION = "0.1.0"
MAX_HTTP_REQUESTS = 3


def run_scan(raw_url: str, *, local_lab: bool = False, path_checks: bool = True) -> dict:
    """Run one fixed set of checks with bounded requests and response handling."""
    target = validate_target(raw_url, local_lab=local_lab)
    parts = urlsplit(target)
    report_target = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
    client = SafeClient(local_lab=local_lab)
    findings = []
    errors = []
    checks = [
        "target validation",
        "HTTP security headers",
        "cookie attributes",
        "TLS certificate connection",
    ]
    skipped = []
    if path_checks:
        checks.append("fixed public metadata paths")
    else:
        skipped.append("fixed public metadata paths (disabled by operator)")

    try:
        response = client.get(target)
        findings.extend(check_headers(dict(response.headers), https=parts.scheme == "https"))
        findings.extend(
            check_cookies(
                response.raw.headers.getlist("Set-Cookie"),
                https=parts.scheme == "https",
            )
        )
        if response.is_redirect:
            errors.append(
                "A redirect was observed and not followed; its destination remains unassessed."
            )
    except (http.client.HTTPException, ValueError, OSError) as exc:
        errors.append(f"Main request incomplete: {type(exc).__name__}.")

    if parts.scheme == "https":
        tls_result = inspect_tls(target, local_lab=local_lab)
    else:
        tls_result = {
            "used": False,
            "ok": False,
            "detail": "HTTPS is not in use.",
        }

    if path_checks:
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        path_budget = max(0, MAX_HTTP_REQUESTS - 1)
        for path in SAFE_PATHS[:path_budget]:
            try:
                response = client.get(origin + path)
                finding = classify_path_response(
                    path,
                    response.status_code,
                    response.headers.get("Content-Type", ""),
                    len(response.content),
                )
                if finding is not None:
                    findings.append(finding)
            except (http.client.HTTPException, ValueError, OSError) as exc:
                errors.append(f"Path check {path} incomplete: {type(exc).__name__}.")

    return {
        "scan_id": str(uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "target": report_target,
        "hostname": parts.hostname,
        "permitted_scope": parts.hostname,
        "tool_version": VERSION,
        "checks_performed": checks,
        "checks_skipped": skipped,
        "summary": severity_summary(findings),
        "findings": [finding.to_dict() for finding in findings],
        "errors": errors,
        "tls": tls_result,
        "disclaimer": (
            "Automated limited assessment; findings require human validation. "
            "Severity is an estimate, not a confirmed business-impact rating."
        ),
    }
