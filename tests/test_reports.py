from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path

def test_report_template_escapes_untrusted_content():
    env = Environment(loader=FileSystemLoader(Path(__file__).parents[1] / "app" / "templates"), autoescape=select_autoescape(["html"]))
    template = env.get_template("report.html")
    html = template.render(report={"hostname":"<script>alert(1)</script>","timestamp_utc":"now","permitted_scope":"x","disclaimer":"limited","summary":{},"findings":[],"errors":[]})
    assert "&lt;script&gt;" in html and "<script>alert(1)</script>" not in html
