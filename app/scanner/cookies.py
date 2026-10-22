"""Cookie flag checks with value redaction."""
from .findings import Finding

def check_cookies(set_cookie_headers: list[str], *, https: bool) -> list[Finding]:
    findings: list[Finding] = []
    for index, raw in enumerate(set_cookie_headers):
        pieces = [p.strip() for p in raw.split(";")]
        name = pieces[0].split("=", 1)[0][:80] if pieces else "cookie"
        attrs = {p.split("=", 1)[0].lower() for p in pieces[1:]}
        session_like = any(word in name.lower() for word in ("session", "auth", "token", "sid"))
        missing = []
        if https and "secure" not in attrs: missing.append("Secure")
        if session_like and "httponly" not in attrs: missing.append("HttpOnly")
        if "samesite" not in attrs: missing.append("SameSite")
        for flag in missing:
            severity = "Medium" if flag == "HttpOnly" and session_like else "Low"
            findings.append(Finding(f"cookie.{index}.{flag.lower()}", f"Cookie {name}: {flag} not set", "Cookies", severity, f"The {flag} attribute was not observed.", f"Cookie name: {name}; value redacted; missing attribute: {flag}.", "Cookie protections depend on the cookie's purpose and application context.", f"Review whether {flag} is appropriate and set it for this cookie when applicable.", "Medium", "Cookie names and flags are observed from response headers; application context is unknown."))
    return findings
