from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


def test_report_template_escapes_untrusted_content():
    template_directory = Path(__file__).parents[1] / "app" / "templates"
    environment = Environment(
        loader=FileSystemLoader(template_directory),
        autoescape=select_autoescape(["html"]),
    )
    template = environment.get_template("report.html")
    report = {
        "target": "https://example.test",
        "hostname": "<script>alert(1)</script>",
        "timestamp_utc": "now",
        "scan_id": "test-id",
        "tool_version": "0.1.0",
        "permitted_scope": "x",
        "disclaimer": "limited",
        "summary": {},
        "checks_performed": ["headers"],
        "checks_skipped": [],
        "findings": [],
        "errors": [],
        "tls": {"ok": False, "detail": "not checked"},
    }
    rendered = template.render(report=report)
    assert "&lt;script&gt;" in rendered
    assert "<script>alert(1)</script>" not in rendered
