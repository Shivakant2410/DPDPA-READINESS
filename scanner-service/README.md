# DPDP consent scanner service

Loads a website in a clean headless Chromium, the way a first-time visitor sees it, and records what actually happens:

1. **Before consent**: every network request and every cookie (including HttpOnly and third-party cookies), plus a screenshot.
2. **After Reject**: clicks the banner's reject option (or settings, then reject), reloads, and records again.
3. **After Accept**: in a separate clean profile, clicks accept, reloads, and records again.
4. **Privacy notice**: opens the linked notice in its own clean profile and checks it against DPDP requirements: data and purposes, withdrawal, Data Protection Board, access, correction and erasure, grievance, nomination, contact person, sharing, retention, children (under 18), and whether trackers seen on the site are named.

Requests and cookies are matched to named vendors (Google Ads, Meta Pixel, Hotjar, CleverTap and others) in `src/trackers.js`. The results become DPDP-mapped checks with evidence in `src/findings.js`.

## Run

```bash
cd scanner-service
npm run setup        # installs Playwright and downloads Chromium (once)
npm start            # http://localhost:8787
```

Then open **http://localhost:8787** in your browser and use **Website Scan**. The service serves the Astra app and the scan API from the same address.

After changing any file in `src/`, stop the server (Ctrl+C) and run `npm start` again; Node does not reload code on its own. To host the app elsewhere, set `window.ASTRA_SCANNER_URL` before `grc.js` loads.

From the terminal:

```bash
npm run scan -- example.com    # prints checks, writes full JSON with screenshots
```

## API

`POST /scan` with `{ "url": "example.com" }` returns the full result. Add `?screenshots=0` to leave out images. `GET /health` reports load.

`POST /report.pdf` with `{ "report": <scan result>, "screenshots": {...}, "theme": "dark" | "light" }` returns an A4 PDF styled like the Astra app (`src/pdf.js`). The app's **Download PDF** button uses it and passes the current theme. Everything taken from the scanned site is escaped, and the PDF is rendered with JavaScript off and no network access except Google Fonts.

| Env var | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8787` | Listen port |
| `ALLOWED_ORIGIN` | `*` | CORS origin; set to your app's origin in production |
| `MAX_CONCURRENT` / `MAX_QUEUE` | `2` / `10` | Parallel scans and queue depth |
| `SCAN_TIMEOUT_MS` | `150000` | Hard stop per scan |
| `ALLOW_PRIVATE_TARGETS` | unset | `1` allows internal/private addresses (dev only) |

## Check statuses

- **pass / fail**: tested; these are the only statuses that count toward the score, weighted High 3, Medium 2, Low 1.
- **review**: observed but needs a human decision, for example Google Consent Mode "denied" pings or cookies that aren't in the database.
- **not-evaluated**: could not be tested, for example no reject button to click.

## Known limits

- Sites behind strict bot protection (Akamai, some Cloudflare setups) refuse headless browsers. The scan fails with a clear message instead of scoring a block page.
- Banners that only appear for certain countries depend on the server's IP location.
- Privacy notice analysis (`src/notice.js`) reads English HTML notices only. PDF, non-English, or login-protected notices are reported as "not tested". It matches wording sentence by sentence and quotes the sentence it relied on, so check the quote when a result looks wrong. `npm test` covers the known false-positive cases.
- The tracker list is curated. Merge the Open Cookie Database for wider coverage.

## Deploying

The service drives a real browser to user-supplied URLs. Keep the SSRF guard (`src/guard.js`) on, put it behind authentication and rate limiting, and run it in a container with no access to internal networks.

## Score and coverage

`score` is weighted over checks that were actually tested (passed or failed; High 3, Medium 2, Low 1). `coverage` says how much the score rests on: `{ tested, total, percent, level, reasons, byArea }`, where `level` is `full` (80% or more tested), `partial` (50–79%) or `limited` (under 50%), and `reasons` groups the checks that could not run by why. The app and PDF show both, for example "32 / 100 · 7 of 20 checks tested · Limited coverage". Untested checks never lower the score; coverage makes a thinly evidenced score visible instead.
