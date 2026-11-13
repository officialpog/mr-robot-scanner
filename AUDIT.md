# Project review — 2026-11-12

Scope: every source/configuration/documentation file in this copy of the project,
including the complete frontend HTML/CSS/JavaScript. No live targets were scanned.
This directory is not a Git repository. A pre-edit copy is available for this
session at `/tmp/mrrobot-review-original/project`.

## Fixed

- Removed fabricated scan results and fake admin login. API failures now show an
  error, expired credentials trigger logout, and scans require login in the UI.
  Old stored `demo-token-*` credentials are discarded.
- Hid local mode and removed automatic claims that local tools are available.
  The local endpoint now returns 501 instead of silently doing a light scan.
  Unimplemented dashboard features are labelled accordingly.
- Escaped dashboard/report/history values before HTML rendering. Terminal output
  permits only span/strong elements and class attributes; scanned banners and
  entered commands cannot insert executable markup through that output path.
- Fixed duplicate Enter handling and command-prefix parsing. Plain help/status/etc.
  commands now work as the UI advertises; they no longer also start a scan.
- Removed simulated progress delays after results already arrived.
- Replaced the known shared default signing secret with a random temporary key;
  explicitly supplied secrets must have at least 32 characters. Documented that a
  stable unique key is required across processes and restarts.
- Added registration field validation, email validation, and bcrypt byte limits
  for registration/login. Concurrent duplicate registrations now roll back and
  return a conflict instead of an uncaught database error.
- Missing bearer credentials now return 401 with the authentication challenge.
- Added domain/IP validation and normalization, including IDNA domain names.
  Schemes, paths, ports, malformed labels, and blank targets are rejected.
- Fixed HTTPS prefix detection for domains beginning with "http" and bracketed
  IPv6 hosts when building HTTP URLs.
- WHOIS nameservers remain a list rather than being collapsed to a string;
  missing dates remain null. Certificate issuer/subject are readable strings.
- Fixed certificate expiry calculation using UTC epoch time, preserving zero
  remaining days and rounding negative/sub-day intervals consistently.
- Distinguished certificate verification failures from DNS, connection, and
  handshake failures. Only confirmed certificate errors produce that finding.
- Failed header requests no longer claim every security header is missing.
  Duplicate missing-HSTS findings are suppressed.
- DNS requests have an explicit per-query deadline; NXDOMAIN stops further
  lookups and DNS failures are visible instead of silently returning no records.
- Fixed the PHP opening-tag regex and technology deduplication that collapsed
  distinct server/powered-by banners. Removed repeated regex work.
- Dashboard data resets between scans, check errors are visible, zero-day
  expiry displays correctly, and corrupt JSON history no longer stops startup.
- Scan completion timestamps are saved; failed transactions are rolled back
  before saving failure status. Unexpected API failures are logged server-side
  without returning internal exception details.
- Reload follows DEBUG, corrected deprecated SQLAlchemy import, declared the
  directly imported certifi dependency, removed unused aiofiles, multipart, and
  explicit websockets requirements (uvicorn[standard] manages its own extras).
- Updated setup/account/local-mode documentation and ignored `.venv/`.

## Remaining findings for review

| Priority | Location | Finding and suggested decision |
| --- | --- | --- |
| High | `api/scan.py`, HTTP scanners | Authenticated users can reach private, loopback, and cloud metadata addresses from the backend. Redirects and DNS rebinding also matter. Decide whether this is a trusted internal scanner or a public service. For public hosting, enforce destination restrictions at connection time and an outbound network policy; input syntax validation alone does not prevent SSRF. |
| High | `config.py`, auth/scan routes | RATE_LIMIT is unused, despite the slowapi dependency. Login, registration, and expensive scans have no enforced rate or concurrency limits. Choose limits and a shared backend for multi-process deployments. See [SlowAPI setup](https://slowapi.readthedocs.io/en/latest/). |
| High | `requirements.txt` | Dependency pins date from the original project and need an advisory audit and coordinated upgrade. No claim of dependency security is made here; package installation was blocked. Declare supported Python versions and verify the bcrypt/passlib combination and PostgreSQL driver on that runtime. |
| High | `scanners/vuln_analyzer.py` | Missing CSP is classified critical without evidence of an exploit; merely detecting WordPress/jQuery is treated as a vulnerability. PHP checks only flag major versions below 7 and recommend a hardcoded version. Choose a defensible severity/evidence policy and a maintained lifecycle/advisory source before using scores operationally. |
| Medium | HTTP scanners, `api/scan.py` | Headers and technology detection fetch the same page twice. Fetch once and share the response, with response-size and redirect limits. This also avoids comparing different responses from a changing site. |
| Medium | `api/scan.py`, WHOIS/DNS | Work runs in request-bound threads. No global job deadline, cancellation handling, queue, or recovery for scans left running after restart. WHOIS has no explicit timeout here; DNS can take several sequential deadlines. Choose synchronous bounded requests or durable background jobs. |
| Medium | `api/scan.py`, database layer | Synchronous SQLAlchemy calls run inside async scan handlers and can block the event loop. Transactions also span network work. Use a dedicated worker/session boundary or async persistence when making the job architecture decision. |
| Medium | `api/scan.py`, frontend results | A scan is marked completed even if every component fails. Technology errors are represented as strings in the technology list. Introduce explicit per-check status and a partial/failed scan policy; distinguish unknown from negative results. |
| Medium | `ssl_scanner.py` | Only the negotiated TLS version/cipher is inspected; the UI's "Weak Ciphers: NO" is not proof that the server cannot negotiate weak suites. Modern client defaults may prevent connecting to legacy servers entirely. Rename to negotiated configuration or implement a separate compatibility assessment. |
| Medium | `headers_scanner.py` | Presence alone does not establish a valid policy. HSTS directive checks are simplistic; the checklist also includes legacy X-XSS-Protection. Review policy requirements and replace simplistic missing/present findings with parsed, contextual checks. |
| Medium | `tech_scanner.py` | Broad HTML regexes can misidentify frameworks/languages from unrelated page text; several regex dots are unescaped. Technology detection is heuristic and should include evidence/confidence rather than imply certainty. |
| Medium | frontend history/reports | Browser history is shared across accounts on the same origin and is separate from server history. Logout does not clear it. The API cannot retrieve a saved full report by ID, and the last report is lost on reload. Decide retention/privacy and implement authenticated server history/report retrieval. |
| Medium | frontend configuration | Deployed API URL remains a placeholder. Configure a real backend URL and matching CORS origins before hosting. The localhost URL is not sufficient for remote-device access. |
| Medium | auth/frontend | Registration exists only in API docs. There is no account management, password reset, email verification, or server-side token revocation. Logout only removes the browser token. Decide which account features are required for the intended users. |
| Medium | models/database | Schema uses nullable account/scan fields, integer admin flags, no migrations, and naive UTC timestamps. SQLite foreign-key enforcement is not explicitly enabled. Decide constraints, deletion/retention behavior, migrations, and timezone conventions before changing existing databases. |
| Low | reports | Frontend now captures request start and result receipt time and preserves them in reports. Return authoritative scan ID/mode/timestamps from the backend for reports retrieved across sessions. |
| Low | frontend accessibility | Labels, native buttons, dialog semantics, focus trapping/restoration, keyboard dismissal, and reduced-motion rules are now implemented. Complete a browser and screen-reader accessibility review. |
| Low | frontend storage/assets | Token/history storage still assumes localStorage access is allowed. Font/icon assets require external CDNs; matrix animation runs continuously. Consider storage-denied behavior, offline assets, and pausing animations on hidden pages. |
| Low | health/deployment | Health only reports process responsiveness, not DB readiness. No deployment config, CI pipeline, or automated browser checks. README claims MIT but there is no LICENSE file; confirm the intended license/owner before adding one. |
| Low | configuration/cleanup | slowapi and RATE_LIMIT remain intentionally pending the rate-limit decision. is_admin and some local-mode UI scaffolding are currently unused. Remove or implement after deciding scope. Separate frontend CSS/JS if ongoing maintenance warrants it. |

Paths in the table are relative to `backend/`, except frontend and root docs.

## Validation and limits

- Python compilation: passed for all backend source files.
- Extracted frontend JavaScript: `node --check` passed.
- `cd backend && python -m unittest discover -s tests -v`: 5 analysis regression
  tests passed; 5 API integration tests skipped because dependencies are absent.
- API tests cover registration, credential handling, target validation, local
  mode rejection, scan persistence, timestamps, and user isolation, using a
  temporary database and mocked scanner calls. They still need to run with the
  actual dependencies installed.
- Attempted isolated Python 3.13 dependency installation in `/tmp/mrrobot-venv`;
  it failed because `pypi.org` DNS resolution was unavailable. No global packages
  were changed.
- No browser runtime, PostgreSQL integration, deployment, dependency vulnerability
  audit, or live network scan was validated. Syntax checks do not prove those flows.

## Frontend design update

Implemented a quieter terminal-inspired design, higher-contrast secondary text,
removed animated background and decorative glow, added reduced-motion styles,
and moved findings ahead of supporting data. Target, request start time, result
receipt time, and collection coverage are prominent. Status badges distinguish
Completed, Failed, and Inconclusive; a completed check is not presented as a
security verdict. Certificate validation alone uses a green positive outcome.

Findings expand with observation, supporting scan evidence, and suggested fix.
Reports reuse the same evidence view. Navigation uses native buttons and the login
form has labels, dialog semantics, Tab trapping, Escape dismissal, background
inertness, focus restoration, and inline errors.

Validation: JavaScript syntax and HTML nesting/unique-ID/label/ARIA-reference
checks passed. A Node harness exercised initialization, full/partial/failed/empty
responses, certificate-error distinction, zero-day expiry, stale-result reset,
and escaped evidence. Attempted headless Firefox and Chromium execution failed
under environment restrictions (Chromium reported a prohibited socket operation).
Visual layout, keyboard interaction, and screen-reader behavior still need an
actual browser verification. No live scan results were used for UI checks.

## ReconScope assessment milestone

The product is renamed ReconScope; the legacy database filename and token key
are preserved for compatibility. Added structured evidence, confidence, impact,
category, rule identifiers, and analysis versioning. Technology-only detections
are informational; CSP absence is no longer critical; legacy X-XSS-Protection is
not required; CSP frame-ancestors avoids a duplicate missing-XFO finding.

Backend-generated check statuses and UTC timestamps are stored in the report.
Partial and wholly failed collections have distinct persisted statuses. Added
owned report retrieval and account identity endpoints. Frontend registration and
server history/report reopening replace browser-only history. Logout clears
loaded account results, and account-change checks prevent stale scan/report
responses from rendering into another session. Old reports remain labelled as
legacy analysis rather than being silently reassessed.

These changes supersede the earlier findings about inflated technology/CSP
severity, missing registration UI, saved-report retrieval, browser-only history,
and reports using only render time. Header policy validation, live version/advisory
matching, background jobs, retesting, SSRF protections, and production limits
remain open; see ROADMAP.md.

Validation: 17 pure-Python analysis/collection tests pass; 5 API integration tests
remain skipped because required packages cannot be installed in this environment.
The API tests now include owned report reopening, metadata preservation, and
cross-account 404 responses. Python compilation, frontend JavaScript syntax,
HTML structure, and Node state/rendering checks pass. Browser interaction, live
scanning, and full API execution remain unverified.
