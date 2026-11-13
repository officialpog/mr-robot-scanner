# 🤖 ReconScope

An evidence-based security assessment platform for domains and internet-facing services. Collect observations, review weaknesses and hardening recommendations, and reopen account-owned reports.

## Features

- **WHOIS Lookup** - Domain registration info
- **DNS Enumeration** - A, AAAA, MX, NS, TXT records
- **SSL/TLS Analysis** - Certificate validity, expiry, TLS version
- **Security Headers** - CSP, HSTS, X-Frame-Options, etc.
- **Technology Detection** - CMS, frameworks, libraries
- **Assessment Findings** - Evidence, confidence, impact, and specific recommendations
- **Collection Status** - Distinguishes completed, failed, and inconclusive checks
- **JWT Authentication** - Secure user management
- **Scan History** - Authenticated server history with saved report retrieval
- **JSON Reports** - Export scan results

## Tech Stack

**Frontend:** Vanilla HTML/CSS/JS (no framework needed)
**Backend:** Python + FastAPI
**Database:** SQLite (dev) / PostgreSQL (prod)
**Auth:** JWT + bcrypt

## Quick Start

### 1. Backend

Use Python 3.12 with the pinned dependencies below.
```bash
cd backend
python3.12 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Copy env file
cp .env.example .env

# Run server
python main.py
```

Backend runs at `http://localhost:8000`

### 2. Frontend
Serve the frontend over HTTP:
```bash
cd frontend
python -m http.server 5500
```

Frontend runs at `http://localhost:5500`

### 3. API Docs
Visit `http://localhost:8000/docs` for interactive API documentation.

## Assessment workflow

1. Create an account or log in.
2. Enter an authorized domain or IP and start a light scan.
3. Review collection status and expand findings for evidence, confidence,
   potential impact, and suggested remediation.
4. Open **History** to retrieve a saved report; view collected data or export JSON.

Reports retain the scan's UTC timestamps and analysis policy version. Existing
reports are not silently re-analyzed. The `vulnerabilities` JSON field is retained
for compatibility; it contains weaknesses, hardening observations, and
informational detections. Technology presence alone is informational. Scores
use local weights and are not CVSS scores.

Registration lookup falls back to HTTPS RDAP via https://rdap.org when legacy
WHOIS returns no usable data or fails. The report identifies the source. If both
services are unavailable, registration collection is marked failed and other
checks still return their results. IP targets do not trigger domain registration
lookups. A 401 at login means the supplied credentials were rejected; create an
account first and log in with its username, rather than its email address.

API endpoints:

- `GET /api/auth/me`: current account identity.
- `POST /api/scan/light`: run and persist a passive assessment.
- `GET /api/scan/history`: current account's latest 50 scans.
- `GET /api/scan/{scan_id}`: owned saved report; other accounts receive 404.

## Rename compatibility

The product is now ReconScope. The default SQLite filename is `reconscope.db`. To reuse a legacy
`mrrobot.db` database, set `DATABASE_URL=sqlite:///./mrrobot.db`. The legacy
browser token key remains unchanged. Old browser-only history is no longer displayed; authenticated server
history is authoritative. No schema migration is required for this milestone.

## Analysis policy

Header recommendations are informed by the
[OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
and TLS recommendations by the
[OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).
Severity and confidence assignments are ReconScope's own prioritization policy.
The scanner does not establish exploitability, enumerate all TLS configurations,
or verify software advisories. See [ROADMAP.md](ROADMAP.md) for the next stages.

## Deployment

### Backend (Render/Railway/VPS)
```bash
git push your-repo
# Set environment variables on your platform
# DATABASE_URL, SECRET_KEY, CORS_ORIGINS
```

### Frontend (Vercel/Netlify)
Upload the `frontend/` folder as a static site.

**Important:** Update the `API_URL` in `frontend/index.html` to point to your deployed backend.

## Accounts and configuration

There is no built-in demo account. Choose **Login → Create an account** in the
frontend, or use `POST /api/auth/register` in the API docs. Passwords must be at least 8
characters and at most 72 UTF-8 bytes.

Set a unique, random `SECRET_KEY` of at least 32 characters in `backend/.env`.
If omitted, a temporary key is generated; tokens become invalid after a restart
and will not work across multiple server processes. The example value must be
replaced for deployment.

Serve the frontend over HTTP using the command above; opening it as a file is
not supported by the default CORS configuration. Local mode, Nmap, Nuclei, and
Subfinder integrations are not implemented. `/api/scan/local` returns HTTP 501.

Results are passive observations, not proof of exploitable vulnerabilities. See
[AUDIT.md](AUDIT.md) for remaining issues and deployment decisions.

## Verification

From `backend/`, after installing requirements:

```bash
python -m unittest discover -s tests -v
```

From the project root, verify frontend state/rendering logic:

```bash
node frontend/tests/check-ui.cjs
```

This Node check uses a small DOM stub; it does not replace browser testing.

## ⚠️ Legal Notice

**Only scan systems you own or have explicit written permission to test.**
Unauthorized scanning may be illegal in your jurisdiction.

## License

MIT
