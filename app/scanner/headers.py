"""Evidence-based HTTP security header checks."""
from .findings import Finding

def check_headers(headers: dict[str, str], *, https: bool) -> list[Finding]:
    h = {k.lower(): v for k, v in headers.items()}
    out: list[Finding] = []
    checks = [
        ("Content-Security-Policy", "Medium", "A policy can reduce the impact of script injection and framing risks.", "Define a restrictive policy suited to the application."),
        ("X-Content-Type-Options", "Low", "Without nosniff, browsers may interpret content using inferred types.", "Set X-Content-Type-Options: nosniff."),
        ("Referrer-Policy", "Low", "Browser navigation may disclose more referrer information than intended.", "Set a policy such as strict-origin-when-cross-origin."),
        ("Permissions-Policy", "Informational", "Browser capabilities are not explicitly constrained by this response.", "Disable features the application does not use."),
    ]
    if https:
        checks.append(("Strict-Transport-Security", "Medium", "HTTPS responses do not advertise a browser-enforced HTTPS policy.", "After confirming HTTPS is available site-wide, set an appropriate Strict-Transport-Security policy."))
    for name, severity, impact, fix in checks:
        value = h.get(name.lower())
        weak = name.lower() == "x-content-type-options" and value and value.lower().strip() != "nosniff"
        if value is None or weak:
            out.append(Finding(f"header.{name.lower()}", f"{name} {'is missing' if value is None else 'has an unexpected value'}", "HTTP headers", severity, impact, f"Observed: {value if value is not None else 'absent'}", impact, fix, "High" if value is None else "Medium"))
    csp = h.get("content-security-policy", "")
    if csp and "frame-ancestors" not in csp.lower() and "x-frame-options" not in h:
        out.append(Finding("header.framing", "No explicit framing restriction observed", "HTTP headers", "Low", "Neither CSP frame-ancestors nor X-Frame-Options was observed.", "CSP frame-ancestors and X-Frame-Options are absent.", "Framing restrictions can reduce clickjacking exposure where relevant.", "Set CSP frame-ancestors according to intended embedding behavior.", "Medium"))
    return out
