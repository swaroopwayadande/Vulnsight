# Resume Project Summary

## VulnSight — Web Application Security Assessment Toolkit

**Python · FastAPI · SQLite · SQLAlchemy · Pydantic · Jinja2 · HTML/CSS/JavaScript**

Built a local-first security assessment application that reviews HTTP security configuration for one explicitly authorized target and produces evidence-based, actionable findings.

### Resume bullets

- Implemented scope validation and SSRF protections that reject private and reserved destinations, pin outbound sockets to validated DNS answers, and block redirects by default.
- Built low-impact checks for HTTP security headers, cookie attributes, TLS certificate validation, and a fixed list of public metadata paths, with request, timeout, and response-size limits.
- Designed normalized findings with severity, evidence, confidence, impact, remediation guidance, and explicit false-positive limitations.
- Added a FastAPI dashboard and API with authorization confirmation, local SQLite scan history, and escaped JSON/HTML report delivery.
- Added mocked tests for target validation, finding rules, response limits, redirect behavior, API validation, cookie-value redaction, and HTML escaping.

### Demo flow

1. Start the local server using the setup steps in the project README.
2. Enter a lab URL and confirm the exact hostname displayed as scope.
3. Submit with explicit authorization confirmation and review the findings and severity summary.
4. Reopen a result from local history and view or download the report.

Use a local lab target for demonstrations. Do not scan a system without authorization. The tool provides a limited configuration review, not a penetration test or a claim that an application is secure.

### Validation status

The project source compiles and mocked scanner smoke checks pass. Automated pytest and Ruff runs remain pending because this development environment could not reach the Python package index to install the virtual-environment dependencies.
