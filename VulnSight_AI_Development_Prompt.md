# VulnSight — Complete AI Development Prompt

> **Tagline:** See vulnerabilities. Understand risk. Secure applications.

## Your role

Act as a senior Python engineer, application-security engineer, and security-tooling architect. Build a complete, usable, well-documented project named **VulnSight: Web Application Security Assessment Toolkit**.

Do not stop at a proposal or a collection of snippets. Inspect the existing workspace first, make a short implementation plan, then implement and test the project. If a repository already exists, preserve unrelated user work and inspect before editing. Do not delete or overwrite existing files without a clear need.

## 1. Project goal

VulnSight is a defensive web-application security assessment tool for **systems the operator owns or is explicitly authorized to test**. It should assess security configuration, collect evidence, explain risk, and provide practical remediation guidance.

The MVP should focus on safe, low-impact checks—not exploitation. Do not implement credential attacks, brute force, destructive payloads, stealth, evasion, persistence, arbitrary command execution, or exploit chaining.

## 2. Mandatory laptop-safety and Python environment rules

**These requirements are non-negotiable.**

1. Use a project-local Python virtual environment named `.venv`.
2. Never install Python packages globally. Do not use `sudo pip`, `pip install --user`, or modify system Python.
3. Use the active interpreter explicitly:
   - Linux/macOS: `python3 -m venv .venv`, then `source .venv/bin/activate`
   - Windows PowerShell: `py -m venv .venv`, then `.venv\Scripts\Activate.ps1`
   - Install dependencies only after activation, using `python -m pip install -r requirements.txt`.
4. If virtual-environment creation fails, stop and explain the issue. Do not attempt global installation or system-level changes as a workaround.
5. Keep all project files, generated reports, local database, temporary files, and test artifacts inside the project directory (or a clearly documented subdirectory). Do not write to system directories or alter system configuration.
6. Do not run commands that remove files, change permissions broadly, modify firewall/network settings, alter shell startup files, or use `sudo` unless the user explicitly approves a specific need. Prefer no elevated privileges.
7. Never automatically install operating-system packages, start persistent services, add startup tasks, change DNS, or modify network configuration.
8. Do not download or execute remote scripts such as `curl ... | bash`. Use pinned or bounded Python dependencies and explain any dependency installation.
9. Do not automatically scan the internet, local network, LAN ranges, or discovered hosts. Only scan the exact target the user enters and authorizes.
10. Add safe timeouts, response-size limits, request limits, redirect controls, and graceful error handling. Never let a scan run indefinitely.
11. Make the scanner's default mode conservative. Do not follow redirects to a different host without revalidating the destination and authorization scope.
12. Do not embed secrets, API keys, passwords, tokens, or personal data in source control. Include `.env.example` only if needed and ignore real `.env` files.
13. Add `.venv/`, `__pycache__/`, `.pytest_cache/`, generated reports, local database files, and environment files to `.gitignore` as appropriate.
14. Do not run scans against a real target by default. Tests must use mocked responses or a local, explicitly started test fixture.
15. Before executing commands, explain briefly what they do when they could install packages or start services. Avoid destructive commands.
16. Provide clear setup, activation, testing, running, and deactivation instructions. Deactivating the environment should be `deactivate`; no system cleanup should be required.

A virtual environment isolates Python packages; it does not itself sandbox network access or make arbitrary code safe. Keep the tool's network behavior restricted and explicit.

## 3. Preferred technology stack

Use a simple, maintainable Python-first stack:

- Python 3.11 or newer (use the version already installed if it is compatible; do not upgrade system Python).
- FastAPI for the local API.
- Uvicorn to serve the app locally.
- Requests for bounded synchronous HTTP requests.
- BeautifulSoup4 for optional HTML parsing.
- Pydantic for input and output validation.
- SQLAlchemy with SQLite for local scan history.
- Jinja2 for HTML report templates.
- pytest for tests.
- Ruff for linting and formatting.
- Standard-library `ssl`, `socket`, `ipaddress`, `urllib.parse`, and `logging` where appropriate.
- Plain HTML, CSS, and JavaScript for a lightweight dashboard. Avoid adding a JavaScript build system unless genuinely necessary.

Prefer fewer dependencies. Do not add a package just because it is popular. Pin dependencies to compatible versions or use sensible bounded version ranges and explain the choice. Include `requirements.txt` and, if useful, `requirements-dev.txt`.

## 4. Core features

### A. Target input and scope controls

- Accept a single HTTP or HTTPS URL at a time.
- Normalize the URL and validate the scheme, hostname, port, and syntax.
- Reject malformed URLs, unsupported schemes, credentials embedded in URLs, and dangerous or ambiguous inputs.
- Require the operator to confirm that they own or have permission to assess the target.
- Display the exact hostname and scope before starting a scan.
- Do not scan sibling domains, discovered links, subdomains, or other hosts automatically.
- Enforce a configurable request cap and per-request timeout.
- Limit response body size and avoid downloading large files.
- Restrict redirects by default. If redirects are supported, validate every redirect destination against the allowed scope and network restrictions.
- Protect against SSRF: reject loopback, private, link-local, multicast, reserved, unspecified, and cloud metadata destinations by default. Revalidate DNS results and redirects to reduce DNS-rebinding risks. Do not rely on a single hostname string check.
- Provide an explicit, documented local-lab mode for testing against localhost. Local-lab mode must be opt-in and must not silently enable LAN or public-network scanning.
- Make the UI clear that authorization is the operator's responsibility.

### B. HTTP security-header checks

Check for relevant headers, including:

- `Strict-Transport-Security` (evaluate only when appropriate for HTTPS).
- `Content-Security-Policy`.
- `X-Content-Type-Options`.
- `Referrer-Policy`.
- `Permissions-Policy`.
- `X-Frame-Options` where relevant, while explaining that CSP `frame-ancestors` may be the more flexible control.
- `Cache-Control` in context-sensitive cases rather than treating every missing header as a vulnerability.

For every finding, include:
- Stable finding ID.
- Title and category.
- Severity and rationale.
- Evidence, such as the observed header value or its absence.
- A short explanation of impact.
- A concrete remediation suggestion.
- Confidence and limitations.

Avoid claiming that a missing header alone proves exploitability. Avoid blanket rules that create misleading findings.

### C. Cookie security checks

Inspect cookies returned by the server and flag relevant omissions or risky values for:

- `Secure`.
- `HttpOnly`.
- `SameSite`.
- Session-related cookie naming/contexts where detectable.

Do not send, store, or display cookie values unnecessarily. Redact values in logs, findings, and reports. Explain that cookie requirements depend on context; do not label every cookie as a critical vulnerability.

### D. HTTPS and TLS checks

- Determine whether the submitted URL uses HTTPS and whether the TLS connection and certificate validation succeed.
- Use safe standard-library TLS inspection and normal certificate validation.
- Report certificate validity, expiration status, hostname mismatch, and clear connection errors when they can be established reliably.
- Do not disable certificate validation just to make a scan succeed.
- Do not claim to provide a complete TLS cryptographic audit unless the implementation actually supports it.
- If an HTTP URL is supplied, report that HTTPS is not in use and optionally check a conservative HTTPS counterpart only if the operator has explicitly enabled that behavior and scope controls permit it.
- Do not run aggressive cipher enumeration or stress tests in the MVP.

### E. Conservative exposed-path checks

- Provide a short, fixed, documented list of common low-risk paths, for example `/robots.txt`, `/sitemap.xml`, and a small set of common public metadata or configuration-related paths only where safe.
- Do not request sensitive paths likely to expose credentials, backups, source code, environment files, cloud metadata, or private keys.
- Do not brute-force directories, crawl the site, or use large wordlists.
- Never download or save response bodies that could contain secrets. Record only minimal metadata and carefully redacted evidence.
- Treat `200 OK` as a signal to review, not proof of a vulnerability. Consider content type, response length, redirects, and known benign behavior before producing a finding.
- Apply strict request caps, timeouts, and response-size limits.
- Let users disable path checks entirely.

### F. Findings and severity model

- Use consistent severity levels: Informational, Low, Medium, High, and Critical.
- Explain that severity is an estimate, not a confirmed business-impact rating.
- Use evidence-based rules and avoid overstating findings.
- Support confidence levels and false-positive notes.
- Include a scan summary with counts by severity.
- Provide remediation advice in plain language.
- Avoid claiming formal OWASP compliance or a complete penetration test.

### G. Reports

Generate:
- JSON reports suitable for automation.
- HTML reports using Jinja2 with readable layout and print styles.
- Optional PDF export only if it can be implemented cleanly without making the MVP fragile.

Reports should contain:
- Scan ID and UTC timestamp.
- Target hostname and permitted scope.
- Checks performed and checks skipped.
- Tool/version information.
- Summary by severity.
- Individual findings with evidence, impact, remediation, confidence, and limitations.
- Errors and incomplete checks.
- A disclaimer that this is an automated, limited assessment and requires human validation.

Escape all untrusted target content before rendering HTML. Prevent stored or reflected XSS in the dashboard and reports. Do not put credentials, cookie values, or sensitive response bodies in reports.

### H. Local dashboard and API

Build a clean, accessible dashboard with:
- URL input and authorization confirmation.
- Visible scan progress or status.
- Findings grouped by severity.
- Scan history.
- Finding detail view.
- Download buttons for JSON and HTML reports.
- Clear validation and error messages.
- Keyboard-accessible controls, labels, visible focus, and sensible color contrast.

FastAPI endpoints should be simple and documented, for example:
- `GET /` — dashboard.
- `GET /health` — local health check.
- `POST /api/scans` — validate and start a scan.
- `GET /api/scans/{scan_id}` — scan status and results.
- `GET /api/scans/{scan_id}/report.json` — JSON report.
- `GET /api/scans/{scan_id}/report.html` — HTML report.

Do not expose the API to the public internet by default. Bind Uvicorn to `127.0.0.1`, not `0.0.0.0`. Do not add authentication that falsely suggests the tool is safe for public deployment. Document that it is a local tool.

Avoid complex background infrastructure for the MVP. If asynchronous scan jobs are used, keep them bounded and make shutdown behavior safe.

## 5. Suggested project structure

Use a clear structure similar to:

```text
vulnsight/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── models/
│   ├── schemas/
│   ├── api/
│   ├── scanner/
│   │   ├── target_validation.py
│   │   ├── http_client.py
│   │   ├── headers.py
│   │   ├── cookies.py
│   │   ├── tls_checks.py
│   │   ├── exposed_paths.py
│   │   └── findings.py
│   ├── reports/
│   │   ├── json_report.py
│   │   └── html_report.py
│   ├── templates/
│   └── static/
├── tests/
├── reports/                 # generated reports; ignored by Git
├── data/                    # local SQLite database; ignored by Git
├── .venv/                   # local virtual environment; ignored by Git
├── .env.example
├── .gitignore
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── README.md
└── LICENSE                  # choose an appropriate license or ask first
```

Adapt this structure where needed, but keep scanning logic separate from the API, UI, persistence, and report rendering.

## 6. Testing requirements

Write meaningful automated tests for:

- URL parsing and scheme validation.
- Private, loopback, link-local, and metadata destination blocking.
- Redirect validation and scope enforcement.
- Timeouts and request/response size limits.
- Header checks for present, absent, and weak values.
- Cookie flags and redaction.
- TLS success and error cases where testable.
- Exposed-path response classification.
- Severity and finding serialization.
- HTML escaping and report generation.
- API input validation and error handling.
- Ensuring tests do not contact public websites.

Use mocked HTTP responses and local test fixtures. Tests must not need administrator privileges or modify system settings. Use pytest. Include instructions to run `python -m pytest`.

## 7. Code quality and engineering standards

- Use type hints and focused functions.
- Keep modules small and readable.
- Add docstrings for public functions and meaningful comments for security-sensitive logic.
- Use structured logging without sensitive data.
- Catch expected exceptions and present helpful errors; do not silently swallow all exceptions.
- Avoid global mutable state.
- Do not hard-code secrets.
- Keep configuration explicit and safe by default.
- Make findings reproducible and explain detection limitations.
- Add linting configuration and instructions for `ruff check .` and `ruff format --check .`.
- Avoid TODO-only implementations, fake scan results, or UI buttons that do nothing.
- Do not claim a feature works unless it is implemented and tested.

## 8. UI and visual design

Build a polished, professional security-tool dashboard:
- Dark, low-glare interface with restrained blue/cyan accents.
- Neutral surfaces and readable typography.
- Clear severity indicators that do not rely on color alone.
- Compact scan summary cards and a readable findings table.
- Responsive layout for laptop and mobile screens.
- Accessible labels, focus states, and adequate contrast.
- No excessive animations, fake terminal output, or decorative hacker imagery.
- Include empty, loading, success, partial-result, and error states.

Use plain CSS unless a framework materially improves the project. Keep the UI dependency-light.

## 9. README requirements

Write a complete README that includes:
- Project overview and non-goals.
- Features and limitations.
- Architecture and project tree.
- Prerequisites.
- Exact virtual-environment setup steps for Linux/macOS and Windows PowerShell.
- Dependency installation commands that use the virtual environment.
- How to run locally and stop the app.
- How to run tests and lint checks.
- How to generate and inspect reports.
- Safe usage and authorization requirements.
- SSRF and network-safety design notes.
- Example findings using synthetic/local-lab data.
- Troubleshooting.
- A roadmap for future improvements.

For Linux/macOS, document commands such as:

```bash
cd vulnsight
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pytest
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

If the development requirements file overlaps with the main requirements, avoid unnecessary duplicate installs and document the cleanest sequence.

Open `http://127.0.0.1:8000` in the browser. Stop the server with `Ctrl+C`, then leave the environment with `deactivate`.

For Windows PowerShell, document the corresponding `.venv` activation command. If PowerShell's execution policy blocks activation, offer a session-only, non-admin alternative or explain how to invoke `.venv`'s Python directly; do not recommend weakening the machine-wide policy.

## 10. Implementation sequence

Work in this order:

1. Inspect the workspace and available Python version without modifying the system.
2. Create the project directory only if needed.
3. Create and activate `.venv`; confirm the active Python executable belongs to `.venv`.
4. Add `.gitignore` before creating generated files.
5. Create a minimal dependency set and install only inside `.venv`.
6. Implement URL/scope validation and safe HTTP client first.
7. Implement header and cookie checks.
8. Implement conservative TLS and exposed-path checks.
9. Implement finding normalization and severity summaries.
10. Add JSON/HTML reports.
11. Add SQLite persistence and the FastAPI API.
12. Build the dashboard.
13. Add tests and run them.
14. Run lint checks and fix real issues.
15. Verify setup/run instructions and ensure the server binds only to localhost.
16. Summarize what was implemented, tests run, commands to start it, known limitations, and any remaining work.

Do not run a scan against a public website as part of development or demonstration. Use mocks or an explicit local test fixture.

## 11. Definition of done

The project is complete only when:
- A fresh clone can be set up using `.venv` without global Python changes.
- The app starts locally and binds to `127.0.0.1`.
- The user can submit a valid, authorized target and receive real, evidence-based results.
- Invalid or unsafe targets are rejected.
- Request count, timeouts, response size, redirects, and scope are bounded.
- Findings include severity, evidence, impact, remediation, confidence, and limitations.
- JSON and HTML reports work and escape untrusted content.
- Scan history persists locally.
- Automated tests pass without contacting public sites.
- The README accurately explains setup, safety, operation, and limitations.
- No fake findings, nonfunctional controls, global package installs, or system-level changes are left behind.

## 12. Final response from the coding agent

When finished, report:
1. Main features implemented.
2. Important security safeguards.
3. Exact setup and run commands.
4. Test and lint results.
5. Files or features not completed.
6. Known limitations and suggested next steps.

**Start by inspecting the workspace, then implement the project. Keep every Python dependency inside `.venv` and do not make system-level changes.**
