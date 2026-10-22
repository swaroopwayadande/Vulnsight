# VulnSight — Complete Project Report

**Project:** VulnSight: Web Application Security Assessment Toolkit

**Version:** 0.1.0

**Purpose:** Low-impact security configuration review of one explicitly authorized web target

**Status:** MVP implementation

## 1. What VulnSight does

VulnSight accepts one HTTP or HTTPS URL, displays its hostname as the assessment scope, requires an authorization confirmation, and performs a small set of evidence-based checks. It presents findings in a local dashboard, stores scan history in a project-local SQLite database, and produces JSON and HTML reports.

It is a configuration review aid. It is not a penetration test, a full vulnerability scanner, a compliance certification, or a substitute for human validation.

## 2. How to start

### Linux and macOS

From the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pytest
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. Stop the server with `Ctrl+C`, then run `deactivate` to leave the virtual environment.

### Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pytest
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

If activation is unavailable, use `.venv\Scripts\python.exe -m pip ...` and `.venv\Scripts\python.exe -m uvicorn ...` directly. This does not require changing system execution policy.

Dependencies are installed only in `.venv`; do not use global or administrator package installation. The scanner binds directly to destinations, validates and pins an approved DNS answer, and does not use system proxy variables.

## 3. Architecture

```text
Browser
  │
  ├── GET /                  Dashboard (Jinja template + static CSS/JS)
  ├── POST /api/scans        Authorization, validation, bounded scan
  ├── GET /api/scans/{id}    Persisted result
  └── GET .../report.*       JSON or escaped HTML report
          │
          ├── app/scanner/target_validation.py  URL, DNS and address scope
          ├── app/scanner/http_client.py        Pinned, bounded HTTP requests
          ├── app/scanner/headers.py            Header observations
          ├── app/scanner/cookies.py            Cookie flag observations
          ├── app/scanner/tls_checks.py          Certificate-validated TLS check
          ├── app/scanner/exposed_paths.py       Fixed safe path list
          └── app/scanner/engine.py              Scan orchestration and report data
                  │
                  └── app/database.py             Local SQLite scan history
```

FastAPI serves the local interface and API. The scan engine is separate from routing and persistence. The MVP runs the scan synchronously in the API request and does not use a task queue or persistent server process.

## 4. Checks and findings

The scanner can report the following observations:

| Area | What is checked | Typical interpretation |
| --- | --- | --- |
| Content Security Policy | Whether `Content-Security-Policy` is present | Missing policy is a Medium configuration observation; a policy's quality still needs review. |
| MIME sniffing | Whether `X-Content-Type-Options` is `nosniff` | Missing or unexpected value is Low severity. |
| Referrer behavior | Whether `Referrer-Policy` is present | Missing policy is Low severity; impact depends on navigation and data in URLs. |
| Browser capabilities | Whether `Permissions-Policy` is present | Missing policy is Informational; unused features may be disabled where appropriate. |
| HTTPS transport policy | On HTTPS only, whether HSTS is present | Missing HSTS is Medium; enable only after validating the HTTPS deployment. |
| Framing protection | Whether CSP `frame-ancestors` or `X-Frame-Options` is observed | Their absence is a Low review signal, not proof of clickjacking. CSP is more flexible. |
| Cookie attributes | `Secure` on HTTPS cookies, `HttpOnly` on session-like cookies, and `SameSite` | Missing flags are Low, or Medium for a session-like cookie missing `HttpOnly`; context matters. Cookie values are never included. |
| TLS connection | Standard certificate validation, connection outcome, TLS version, and certificate expiration field | A failed validation is reported as a connection result, not as a complete cryptographic audit. |
| Public metadata paths | Only `/robots.txt` and `/sitemap.xml` are optionally requested | HTTP 200 is Informational and means review the public response; it does not imply a vulnerability. |

Each finding contains a stable ID, title, category, severity, rationale, evidence, impact, remediation, confidence, and limitations. Severity counts are included in the summary. Missing headers are not treated as proof of exploitability. `Cache-Control` is not currently scored because its correct value is application and response specific.

### Severity scale

- **Critical:** reserved for a confirmed, severe issue; the current MVP does not generate Critical findings.
- **High:** reserved for a clearly high-impact, well-supported issue; the current checks do not generate High findings.
- **Medium:** a material configuration gap that warrants review, such as missing CSP or HSTS.
- **Low:** a useful defense-in-depth improvement, such as missing `nosniff` or cookie flags.
- **Informational:** context for review, such as a public metadata path responding successfully.

Severity is a screening estimate, not a business-impact rating. Findings need to be reviewed against the application architecture, data sensitivity, and intended browser behavior.

## 5. Scope and network safeguards

- Only a single entered URL is assessed; no links, neighboring domains, subdomains, or host discovery are scanned.
- HTTP and HTTPS are the only supported schemes. Embedded credentials, malformed hostnames, invalid ports, control characters, and non-public addresses are rejected.
- Loopback is permitted only after the operator checks Local lab mode. Other private, link-local, reserved, multicast, unspecified, and metadata-network destinations remain blocked.
- DNS answers are checked and the selected socket address is pinned. TLS still verifies the certificate against the original hostname.
- Redirects are never followed, so a redirect destination is not contacted.
- At most three HTTP requests are made: one for the submitted URL and up to two fixed metadata paths. Path checks can be disabled.
- Each request has a five-second timeout and reads no more than 64 KiB of response body. Bodies are not saved or included in reports.
- The app binds to `127.0.0.1`. It has no authentication and must not be deployed as a shared or public service.
- Authorization remains the operator's responsibility.

## 6. Reports and stored data

Every result includes a scan ID, UTC timestamp, target hostname and scope, tool version, performed and skipped checks, severity summary, findings, TLS outcome, errors, and a limited-assessment disclaimer. JSON is available for automation. HTML uses template autoescaping and print styles.

Completed scans are stored in `data/vulnsight.db`, which is ignored by Git. Reports downloaded from the dashboard may be saved by the operator under `reports/generated/`, also ignored by Git. This project report is maintained in `reports/PROJECT_REPORT.md`.

Cookie values are redacted. The scanner does not store response bodies. Avoid adding secrets or personal data to target URLs.

## 7. What it does not detect

The current checks do not test for SQL injection, cross-site scripting, server-side request forgery in the target application, authentication or authorization flaws, CSRF, business-logic issues, vulnerable dependencies, known CVEs, exposed credentials, sensitive files, backup files, source code, cloud metadata, or unsafe server-side behavior. It does not crawl, fuzz, brute-force, exploit, enumerate ciphers, or verify that a control is correctly enforced in every application path.

The fixed path list is intentionally short. A 200 response from `robots.txt` or `sitemap.xml` is not a vulnerability verdict. No finding means only that these limited checks did not produce a finding; it does not mean that the site is secure.

## 8. Tests and quality checks

The test suite covers URL and scope validation, private-address blocking, redirect scope, header and cookie observations, severity summaries, response size limits, disabled redirect following, and HTML escaping. The HTTP transport test uses an explicitly started loopback fixture; tests do not contact public websites.

Run:

```bash
python -m pytest
ruff check .
ruff format --check .
```

## 9. Current implementation status and next steps

The initial application, dashboard, API, SQLite history, JSON/HTML reports, safe bounded transport, setup documentation, and unit tests are present. Python syntax compilation and target-validation smoke checks passed. Dependency installation timed out while reaching the package index, so pytest and Ruff could not be run; this execution sandbox also blocked opening a loopback test socket. Install the dependencies inside `.venv` and run the test commands above when package-index access is available. PDF export, background scan jobs, deeper policy validation, and a richer TLS certificate detail view are not part of this MVP.

Recommended next work is to restore package-index access, install dependencies into `.venv`, run and repair the test/lint checks, then validate the complete UI/API flow against a local lab fixture. Continue to avoid public-target scans during development.
