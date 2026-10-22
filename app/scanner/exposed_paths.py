"""Short fixed list of low-risk public metadata paths."""

from .findings import Finding

SAFE_PATHS = ("/robots.txt", "/sitemap.xml")


def classify_path_response(
    path: str,
    status: int,
    content_type: str,
    body_size: int,
) -> Finding | None:
    """Return an informational signal for a successfully returned public path."""
    if status != 200:
        return None
    return Finding(
        id="path." + path.strip("/"),
        title=f"Public metadata path responds: {path}",
        category="Exposed paths",
        severity="Informational",
        rationale="A fixed, commonly public path returned HTTP 200; this is a review signal only.",
        evidence=(
            f"Path: {path}; status: 200; content type: {content_type or 'unknown'}; "
            f"body size: {body_size} bytes."
        ),
        impact="Public metadata may be expected and does not establish exposure of sensitive data.",
        remediation="Review that the response contains only intended public information.",
        confidence="Low",
        limitations="The body was not stored or inspected.",
    )
