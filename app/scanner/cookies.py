"""Cookie flag checks that never retain or report cookie values."""

from .findings import Finding


def check_cookies(set_cookie_headers: list[str], *, https: bool) -> list[Finding]:
    """Inspect cookie attributes and include only cookie names in evidence."""
    findings: list[Finding] = []
    for index, raw_cookie in enumerate(set_cookie_headers):
        pieces = [piece.strip() for piece in raw_cookie.split(";")]
        name = pieces[0].split("=", 1)[0][:80] if pieces else "cookie"
        attributes: dict[str, str | None] = {}
        for piece in pieces[1:]:
            key, separator, value = piece.partition("=")
            attributes[key.lower()] = value.strip() if separator else None

        session_like = any(
            marker in name.lower() for marker in ("session", "auth", "token", "sid")
        )
        missing: list[tuple[str, str]] = []
        if https and "secure" not in attributes:
            missing.append(("Secure", "Low"))
        if session_like and "httponly" not in attributes:
            missing.append(("HttpOnly", "Medium"))
        same_site = attributes.get("samesite")
        if same_site is None:
            missing.append(("SameSite", "Low"))
        elif same_site.lower() == "none" and "secure" not in attributes:
            missing.append(("SameSite=None without Secure", "Medium"))
        elif same_site.lower() not in {"lax", "strict", "none"}:
            missing.append(("SameSite value is invalid", "Low"))

        for flag, severity in missing:
            findings.append(
                Finding(
                    id=f"cookie.{index}.{flag.lower().replace(' ', '-')}",
                    title=f"Cookie {name}: {flag} not safely configured",
                    category="Cookies",
                    severity=severity,
                    rationale=(
                        f"The {flag} attribute was not observed or is used without "
                        "its required companion flag."
                    ),
                    evidence=f"Cookie name: {name}; value redacted; issue: {flag}.",
                    impact=(
                        "Cookie protections depend on the cookie's purpose and "
                        "application context."
                    ),
                    remediation=(
                        f"Review whether {flag} is appropriate and configure it "
                        "for this cookie when applicable."
                    ),
                    confidence="Medium",
                    limitations=(
                        "Cookie names and flags are observed from response headers; "
                        "application context is unknown."
                    ),
                )
            )
    return findings
