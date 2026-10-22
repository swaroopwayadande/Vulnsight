# VulnSight

**See vulnerabilities. Understand risk. Secure applications.**

VulnSight is a local, low-impact web application security assessment toolkit for systems you own or are explicitly authorized to assess. It reviews HTTP security headers and cookie attributes, checks a certificate-validated TLS connection, and optionally requests only `robots.txt` and `sitemap.xml`. It is not a penetration test, vulnerability scanner for networks, or proof of OWASP compliance.

The project is distributed under the MIT License; see [LICENSE](LICENSE).

## Features and limits

- One HTTP or HTTPS URL per scan, explicit authorization confirmation, exact-host scope display, and public-address checks by default.
- Loopback targets require the explicit Local lab mode. It does not grant permission to test a LAN or other hosts.
- Redirects are not followed. DNS names resolving to non-public addresses are blocked outside local-lab mode, and sockets are pinned to an approved address.
- HTTP response bodies are capped at 64 KiB and never stored. Cookies are reported by name and missing attributes; values are redacted.
- A maximum of three small HTTP requests is made per scan (main URL plus two fixed metadata paths). Path checks are optional. Requests use a five-second timeout.
- Results are stored in `data/vulnsight.db` and can be downloaded as JSON or viewed as escaped HTML.
- Severity is an estimate. Context-dependent controls may not apply to every application, and all findings need human review.

The scanner does not follow links, crawl, brute-force, test credentials, exploit vulnerabilities, or scan hosts automatically. TLS checking uses normal certificate verification and does not enumerate ciphers. This is intended for local use only; do not expose the API to the public internet.

## Architecture

```text
app/
  main.py                 FastAPI routes
  database.py             SQLite history
  scanner/                Target checks, bounded HTTP, findings
  templates/              Dashboard and HTML report
  static/                 Plain CSS and JavaScript
tests/                    Mocked/local unit tests
data/                     Local SQLite database (ignored by Git)
reports/                  Project report; generated exports are ignored by Git
```

The dashboard uses FastAPI and Jinja templates. Scanning logic is separate from the API and persistence. The API currently runs each scan synchronously in the request, so keep the app local and submit one scan at a time.

## Prerequisites

Python 3.11 or newer. Python 3.13.5 was used during initial implementation. No system Python packages are required.

## Setup

All Python packages belong in the project `.venv`. Never use `sudo pip`, `pip install --user`, or install project dependencies globally.

### Linux or macOS

```bash
cd Vulnsight
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

### Windows PowerShell

```powershell
cd Vulnsight
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

If activation is blocked, invoke `.venv\Scripts\python.exe -m pip ...` and `.venv\Scripts\python.exe -m uvicorn ...` directly. This avoids changing the machine-wide PowerShell execution policy.

The dependencies are bounded to compatible major versions. If package installation is unavailable in your environment, keep the virtual environment and retry when a package index is reachable; do not install packages into system Python.

## Run locally

With `.venv` active:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The API is bound only to loopback. Stop it with `Ctrl+C`, then exit the environment with:

```bash
deactivate
```

## Safe use

Only assess systems you own or have explicit permission to test. Enter one exact URL and verify the hostname shown before starting. Public targets are checked for non-public DNS answers before each connection, and the socket is pinned to an approved resolved address. Redirects remain unvisited. The local-lab checkbox permits loopback targets for a test fixture; it does not enable LAN access. Never put passwords or tokens in the URL.

DNS answers are validated and each socket is pinned to an approved resolved address, reducing DNS-rebinding risk. Do not use this MVP with untrusted target input or in a multi-user/public service. The app has no authentication because it is designed to run locally, not as a shared hosted service. Scanner traffic uses direct sockets and is not redirected by ambient proxy settings.

Reports contain the target origin and hostname, checks, evidence, severity, remediation, confidence, limitations, and incomplete-check errors. They do not store the submitted URL's path or query, response bodies, or cookie values. HTML output uses autoescaping.

## Tests and lint

Tests use unit inputs, mocked DNS and HTTP transport, and synthetic report content; they do not contact public websites or open network sockets.

```bash
python -m pytest
ruff check .
ruff format --check .
```

## Reports and history

Each completed scan is saved in the ignored local database `data/vulnsight.db`. The dashboard history lets you reopen a result. Use **Download JSON** for automation or **View HTML report** for a printable report. PDF export is not included in this MVP.

See [reports/PROJECT_REPORT.md](reports/PROJECT_REPORT.md) for the full project guide, including architecture, startup instructions, detection coverage, severity interpretation, and limitations.
For a concise, accurate portfolio description, see [reports/RESUME_SUMMARY.md](reports/RESUME_SUMMARY.md).

Example synthetic finding: a response without `X-Content-Type-Options` may receive a Low-severity observation suggesting `X-Content-Type-Options: nosniff`. This is not proof of exploitability; confirm that the header is appropriate for the application.

## Troubleshooting

- **Target blocked:** private, loopback, link-local, reserved, or unresolved destinations are denied by default. Use Local lab mode only for an explicitly authorized loopback fixture.
- **Request incomplete:** the target may be unreachable, slow, or have a certificate/connection problem. Requests time out after five seconds; retry only when appropriate.
- **Could not install packages:** verify that `.venv` is active and that your package index is reachable. Do not switch to global installation.
- **Port unavailable:** choose a different local port, such as `--port 8010`, while keeping `--host 127.0.0.1`.

## Roadmap

- Expand local TLS fixture coverage and transport error diagnostics.
- Add robust isolated test fixtures for TLS and API flows.
- Add bounded asynchronous jobs and progress reporting.
- Add context-aware policies and optional, carefully scoped HTTPS counterpart checks.
- Consider PDF output only after stable HTML and JSON report workflows.
