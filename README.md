# HypenSec Astra — DPDPA Readiness

Compliance readiness by [HypenSec](https://hypensec.com): framework self-assessments (ISO 27001, PCI DSS, DPDP Act, SOC 2, NIST CSF, ISO/IEC 42001) and an automated **DPDP Act website scan** that proves, with evidence, how a site handles consent and what its privacy notice says.

## What the website scan does

For each site, the scanner runs up to four clean, headless Chromium visits:

1. **Before consent:** records every network request and cookie (including HttpOnly and third-party cookies) before any choice, and names the vendor behind each (Google Ads, Meta Pixel, Clarity, CleverTap, …).
2. **Reject:** clicks the banner's reject option (or settings, then reject), reloads, and checks whether tracking stops. It reads the consent state the site stores, so a "save" button that actually grants everything is caught.
3. **Accept:** records what consent switches on.
4. **Browse:** scrolls like a visitor (catches banners that treat scrolling as consent and lazy-loaded footers), finds the privacy notice, and analyses it clause by clause against the DPDP Act: data and purposes, withdrawal, Data Protection Board, access, correction/erasure, grievance, nomination, contact person, sharing, retention and children (under 18). Every pass quotes the sentence it relied on.

Results come with a score, a **coverage** figure (how many checks could actually be tested), screenshots, a prioritised fix list and a branded PDF report.

**Accuracy.** Measured on 21 Indian websites with every failed check verified by hand: wrong fails went from 12.0% to 1.0% during development (see [`scanner-service/benchmark/REPORT.md`](scanner-service/benchmark/REPORT.md)). Those sites were also used to fix the scanner, so re-measure on new sites before quoting the figure.

## Architecture

```
Browser ──HTTPS──▶ Caddy (TLS, Let's Encrypt) ──▶ astra container (Node 20)
                                                   ├─ serves the web app (index.html, grc.js, grc.css, fonts)
                                                   ├─ POST /scan        → headless Chromium (Playwright)
                                                   ├─ POST /report.pdf  → Chromium renders the PDF (no network)
                                                   └─ data/audit.log    (who scanned what, when, authorised)
```

One process serves both the app and the API. Scan reports are stored in the user's browser, not on the server; the server keeps only the audit log.

## Deploying to production

Tested with Docker 29 on Windows; the steps below are for a Linux server.

### 1. Server

- Ubuntu 22.04/24.04 (or any Linux with Docker), **2 vCPU and 4 GB RAM minimum**. Each running scan uses 3–4 Chromium contexts for 30–100 s; `MAX_CONCURRENT=2` fits this size. Add 1 vCPU and 1.5 GB RAM per extra concurrent scan.
- Ports 80 and 443 open to the internet.
- A domain name, e.g. `astra.hypensec.com`, with a DNS **A record** pointing at the server's IP.
- Host in India if you want processing to stay in India (and say so in `HOSTING_LOCATION`).

Install Docker:

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER   # log out and back in
```

### 2. Get the code and configure

```bash
git clone https://github.com/HypenSec/DPDPA-Readiness.git
cd DPDPA-Readiness
cp .env.example .env
```

Generate one access key per customer or team (16+ characters):

```bash
docker run --rm node:20-alpine node -e "console.log(require('crypto').randomBytes(24).toString('base64url'))"
```

Edit `.env`:

| Setting | Required | Meaning |
|---|---|---|
| `ASTRA_DOMAIN` | yes | Public domain, e.g. `astra.hypensec.com` (Caddy gets its certificate) |
| `ACCESS_KEYS` | yes | `label:secret` pairs, comma-separated, e.g. `hypensec-team:…,acme-ltd:…`. The label is written to the audit log |
| `LEGAL_ENTITY` | yes | Registered company name shown on the privacy notice and terms |
| `PRIVACY_EMAIL` | yes | Privacy and grievance email address |
| `GRIEVANCE_OFFICER` | yes | Name and designation of the Grievance Officer |
| `POSTAL_ADDRESS` | recommended | Registered office address |
| `HOSTING_LOCATION` | recommended | Where the server runs, e.g. `India (Mumbai)` |
| `AUDIT_RETENTION` | no | Retention stated in the notice (default `one year`) |
| `LEGAL_LAST_UPDATED` | no | Date shown on the legal pages |
| `SCANS_PER_HOUR` / `SCANS_PER_HOUR_PER_IP` / `PDFS_PER_HOUR` | no | Rate limits (defaults 30 / 60 / 120) |
| `MAX_CONCURRENT` / `MAX_QUEUE` | no | Parallel scans and queue length (defaults 2 / 10) |
| `SCANNER_IDENTIFY` | no | `1` (default): user agent contains `HypenSecAstra`. `0`: plain Chrome, only for sites you own |
| `ALLOWED_ORIGIN` | no | Leave empty (app and API share an origin) |

The service **refuses to start in production** without `ACCESS_KEYS`, `LEGAL_ENTITY`, `PRIVACY_EMAIL` and `GRIEVANCE_OFFICER`, or if a key still contains the example value.

### 3. Start

```bash
mkdir -p data
docker compose up -d --build
docker compose logs -f astra     # expect: "HypenSec Astra listening on http://0.0.0.0:8787 (production, N access key(s) …)"
```

Caddy obtains the HTTPS certificate on first start (DNS must already point at the server).

### 4. Verify

```bash
curl -s https://astra.hypensec.com/health                       # {"ok":true,...}
curl -sI https://astra.hypensec.com/ | grep -i strict-transport  # security headers present
curl -s -X POST https://astra.hypensec.com/scan -H 'Content-Type: application/json' \
  -H 'X-Access-Key: <your key>' -d '{"url":"your-own-site.in","authorised":true}' | head -c 300
```

Then open `https://astra.hypensec.com`, go to **Website Scan**, tick the authorisation box, and scan a site you own. The first scan asks for the access key; it is stored only in that browser.

### Operating it

- **Update:** `git pull && docker compose up -d --build`
- **Add or revoke a customer:** edit `ACCESS_KEYS` in `.env`, then `docker compose up -d` (restarts in a few seconds).
- **Audit log:** `data/audit.log`, one JSON line per scan (`time, key, ip, target, authorised, outcome, score`). Back it up and keep it for the period stated in the privacy notice (one year by default), then delete older lines.
- **Rate limits** are held in memory and reset on restart.
- **Blocked sites:** some sites (Akamai, Cloudflare) refuse automated browsers; the scan then reports "blocked" instead of a score. Site owners can allow-list user agents containing `HypenSecAstra`.
- **Restart on crash:** handled by `restart: unless-stopped`; health is checked every 30 s.

### Before opening to the public

- Have counsel review [`privacy.html`](privacy.html) and [`terms.html`](terms.html).
- Re-measure accuracy on 20+ sites the scanner has not seen (`npm run benchmark` in `scanner-service`).
- Keep scanning limited to sites users are authorised to test; owner verification (DNS record) is on the roadmap.

## Local development

```bash
cd scanner-service
npm run setup        # npm install + Playwright's Chromium
npm start            # http://localhost:8787 (development: no access key needed, listens on 127.0.0.1 only)
npm test             # 21 tests: notice analysis, coverage, access control, and our own privacy notice
npm run scan -- example.com    # scan from the terminal, writes the full JSON
```

## Security model

- **Access keys** (`X-Access-Key` header), compared in constant time; 20 wrong attempts per IP per 10 minutes are locked out.
- **Rate limits** per key and per IP; at most `MAX_CONCURRENT` scans at once.
- **Authorisation**: every scan must carry `authorised: true` (the app's checkbox); the confirmation is recorded in the audit log.
- **SSRF guard**: targets resolving to private, loopback, link-local or metadata addresses are refused, including after redirects.
- **Isolation**: runs as an unprivileged user in the container; the API port is reachable only through Caddy.
- **Headers**: strict Content-Security-Policy, HSTS, nosniff, no-referrer, Permissions-Policy.
- **Untrusted content**: everything taken from scanned sites is escaped; PDFs render with JavaScript off and no network access.
- **Privacy**: no cookies, analytics or third-party requests in the app; fonts are self-hosted.

## Project layout

```
index.html, grc.js, grc.css       Web app (HypenSec brand), served by the scanner
privacy.html, terms.html          Legal pages (filled from LEGAL_* settings)
fonts/, icons/                    Self-hosted fonts (SIL OFL 1.1) and HypenSec mark
Dockerfile, docker-compose.yml    Container and HTTPS deployment
deploy/Caddyfile                  Reverse proxy config
scanner-service/
  src/server.js                   HTTP server, access control, static files
  src/scan.js                     Consent journeys (Playwright)
  src/cmp.js                      Consent banner detection and clicking
  src/trackers.js                 Tracker and cookie knowledge base
  src/notice.js                   Privacy notice analysis
  src/findings.js                 DPDP-mapped checks, score, coverage
  src/pdf.js                      PDF report
  src/access.js                   Keys, rate limits, audit log
  src/guard.js                    SSRF guard
  test/                           Automated tests
  benchmark/                      Accuracy benchmark, audit report, competitor comparison
```

The remaining files at the root (`manifest.json`, `background.js`, `popup.*`, …) are the earlier AI-endpoint-scanner Chrome extension. They are not part of the service and are excluded from the Docker image.

## Licence

Proprietary. © HypenSec. All rights reserved. Fonts in `fonts/` are under the SIL Open Font License 1.1 (see the licence files there).
