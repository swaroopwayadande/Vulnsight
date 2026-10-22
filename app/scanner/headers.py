"""Evidence-based HTTP security header checks."""

from .findings import Finding


def _has_positive_hsts_max_age(value: str) -> bool:
    """Return whether HSTS declares a positive, numeric max-age directive."""
    for directive in value.split(";"):
        name, separator, raw_age = directive.partition("=")
        if name.strip().lower() != "max-age" or not separator:
            continue
        age = raw_age.strip()
        if age.isascii() and age.isdecimal() and int(age) > 0:
            return True
    return False


def check_headers(headers: dict[str, str], *, https: bool) -> list[Finding]:
    """Return contextual observations about relevant response headers."""
    observed = {name.lower(): value.strip() for name, value in headers.items()}
    findings: list[Finding] = []
    checks = [
        (
            "Content-Security-Policy",
            "Medium",
            "A policy can reduce the impact of script injection and framing risks.",
            "Define a restrictive policy suited to the application.",
            False,
        ),
        (
            "X-Content-Type-Options",
            "Low",
            "Without nosniff, browsers may interpret content using inferred types.",
            "Set X-Content-Type-Options: nosniff.",
            True,
        ),
        (
            "Referrer-Policy",
            "Low",
            "Browser navigation may disclose more referrer information than intended.",
            "Set a policy such as strict-origin-when-cross-origin.",
            False,
        ),
        (
            "Permissions-Policy",
            "Informational",
            "Browser capabilities are not explicitly constrained by this response.",
            "Disable features the application does not use.",
            False,
        ),
    ]
    if https:
        checks.append(
            (
                "Strict-Transport-Security",
                "Medium",
                "HTTPS responses do not advertise an effective browser-enforced HTTPS policy.",
                "After confirming HTTPS is available site-wide, set a suitable HSTS max-age.",
                True,
            )
        )

    for name, severity, impact, remediation, validate_value in checks:
        value = observed.get(name.lower())
        weak = False
        if value and validate_value:
            if name == "X-Content-Type-Options":
                weak = value.lower() != "nosniff"
            elif name == "Strict-Transport-Security":
                weak = not _has_positive_hsts_max_age(value)
        if value is None or weak:
            reason = (
                impact
                if value is None
                else f"{name} was present but did not contain an accepted protective value."
            )
            findings.append(
                Finding(
                    id=f"header.{name.lower()}",
                    title=f"{name} {'is missing' if value is None else 'may be ineffective'}",
                    category="HTTP headers",
                    severity=severity,
                    rationale=reason,
                    evidence=f"Observed: {value if value is not None else 'absent'}",
                    impact=impact,
                    remediation=remediation,
                    confidence="High" if value is None else "Medium",
                )
            )

    csp_has_ancestors = "frame-ancestors" in observed.get("content-security-policy", "").lower()
    xfo_value = observed.get("x-frame-options", "").lower()
    xfo_is_valid = xfo_value in {"deny", "sameorigin"}
    if not csp_has_ancestors and not xfo_is_valid:
        evidence = (
            f"X-Frame-Options observed: {xfo_value or 'absent'}; "
            "CSP frame-ancestors absent."
        )
        findings.append(
            Finding(
                id="header.framing",
                title="No valid framing restriction observed",
                category="HTTP headers",
                severity="Low",
                rationale=(
                    "Neither a valid X-Frame-Options value nor CSP frame-ancestors "
                    "was observed."
                ),
                evidence=evidence,
                impact="Framing restrictions can reduce clickjacking exposure where relevant.",
                remediation="Set CSP frame-ancestors according to intended embedding behavior.",
                confidence="Medium",
            )
        )
    return findings
