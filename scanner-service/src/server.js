// HypenSec Astra: the web app plus the DPDP consent scanner API, in one process.
//
//   GET  /                     Astra app (index.html and assets from the project root)
//   GET  /terms.html, /privacy.html   legal pages, filled in from LEGAL_* settings
//   GET  /health               { ok: true }
//   POST /scan                 { url, authorised: true }  -> scan result   (access key required)
//   POST /report.pdf           { report, screenshots?, theme? } -> PDF     (access key required)
//
// Settings (environment variables) are documented in .env.example and README.md.

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { closeBrowser, getBrowser, scanSite } from './scan.js';
import { renderReportPdf } from './pdf.js';
import { ScanError } from './guard.js';
import { clientIp, createAuditLog, createRateLimiter, matchAccessKey, parseAccessKeys } from './access.js';

const env = process.env;
const PRODUCTION = env.NODE_ENV === 'production';
const PORT = Number(env.PORT || 8787);
const HOST = env.HOST || (PRODUCTION ? '0.0.0.0' : '127.0.0.1');
const ALLOWED_ORIGIN = env.ALLOWED_ORIGIN || ''; // empty: same-origin only (the app is served from here)
const MAX_CONCURRENT = Number(env.MAX_CONCURRENT || 2);
const MAX_QUEUE = Number(env.MAX_QUEUE || 10);
const TRUST_PROXY = env.TRUST_PROXY === '1';
const AUDIT_LOG = env.AUDIT_LOG ?? path.resolve('data/audit.log');
const ACCESS_KEYS = parseAccessKeys(env.ACCESS_KEYS || '');
const LEGAL = {
  LEGAL_ENTITY: env.LEGAL_ENTITY || '',
  PRIVACY_EMAIL: env.PRIVACY_EMAIL || '',
  GRIEVANCE_OFFICER: env.GRIEVANCE_OFFICER || '',
  POSTAL_ADDRESS: env.POSTAL_ADDRESS || '',
  AUDIT_RETENTION: env.AUDIT_RETENTION || 'one year',
  HOSTING_LOCATION: env.HOSTING_LOCATION || '',
  LAST_UPDATED: env.LEGAL_LAST_UPDATED || '26 September 2026',
};

if (PRODUCTION) {
  const missing = [
    !ACCESS_KEYS.length && 'ACCESS_KEYS',
    !LEGAL.LEGAL_ENTITY && 'LEGAL_ENTITY',
    !LEGAL.PRIVACY_EMAIL && 'PRIVACY_EMAIL',
    !LEGAL.GRIEVANCE_OFFICER && 'GRIEVANCE_OFFICER',
  ].filter(Boolean);
  if (missing.length) {
    console.error(`Refusing to start in production without: ${missing.join(', ')}. See .env.example.`);
    process.exit(1);
  }
  if (/CHANGE-ME/i.test(env.ACCESS_KEYS || '')) {
    console.error('Refusing to start: ACCESS_KEYS still contains the example key from .env.example. Generate real secrets.');
    process.exit(1);
  }
}
if (!ACCESS_KEYS.length) console.warn('WARNING: ACCESS_KEYS is empty, so scans are open to anyone. Only use this on your own machine.');

const scanLimitPerKey = createRateLimiter({ limit: Number(env.SCANS_PER_HOUR || 30), windowMs: 3_600_000 });
const scanLimitPerIp = createRateLimiter({ limit: Number(env.SCANS_PER_HOUR_PER_IP || 60), windowMs: 3_600_000 });
const pdfLimitPerKey = createRateLimiter({ limit: Number(env.PDFS_PER_HOUR || 120), windowMs: 3_600_000 });
const failedKeyPerIp = createRateLimiter({ limit: 20, windowMs: 600_000 });
const audit = createAuditLog(AUDIT_LOG);

// ---------- static app ----------

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
// Allow-list rather than a directory listing, so nothing else in the project is exposed.
const APP_FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/terms.html': ['terms.html', 'text/html; charset=utf-8'],
  '/privacy.html': ['privacy.html', 'text/html; charset=utf-8'],
  '/grc.js': ['grc.js', 'text/javascript; charset=utf-8'],
  '/grc.css': ['grc.css', 'text/css; charset=utf-8'],
  '/fonts/SpaceGrotesk-latin.woff2': ['fonts/SpaceGrotesk-latin.woff2', 'font/woff2'],
  '/fonts/JetBrainsMono-latin.woff2': ['fonts/JetBrainsMono-latin.woff2', 'font/woff2'],
  '/icons/hypensec-mark.png': ['icons/hypensec-mark.png', 'image/png'],
  '/icons/favicon-64.png': ['icons/favicon-64.png', 'image/png'],
};

// The same headers our scanner checks other sites for.
const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  ...(PRODUCTION ? { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } : {}),
};

const escHtml = (value) => String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function serveApp(res, pathname, headOnly = false) {
  const [file, type] = APP_FILES[pathname];
  let body = await readFile(path.join(APP_ROOT, file));
  if (file === 'terms.html' || file === 'privacy.html') {
    body = body.toString('utf8').replace(/\{\{(\w+)\}\}/g, (_, name) => escHtml(LEGAL[name] || '[not configured]'));
  }
  const cache = /\.(woff2|png)$/.test(file) ? 'public, max-age=604800' : 'no-cache';
  res.writeHead(200, { 'Content-Type': type, 'Cache-Control': cache, ...SECURITY_HEADERS });
  res.end(headOnly ? undefined : body);
}

// ---------- helpers ----------

let running = 0;
const waiting = [];

async function withSlot(fn) {
  if (running >= MAX_CONCURRENT) {
    if (waiting.length >= MAX_QUEUE) throw new ScanError('The scanner is busy. Try again in a minute.', 429);
    await new Promise((resolve) => waiting.push(resolve));
  }
  running += 1;
  try {
    return await fn();
  } finally {
    running -= 1;
    waiting.shift()?.();
  }
}

function corsHeaders() {
  return ALLOWED_ORIGIN ? {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Access-Key',
    Vary: 'Origin',
  } : {};
}

function send(res, status, body, extra = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...SECURITY_HEADERS, ...corsHeaders(), ...extra });
  res.end(JSON.stringify(body));
}

function readJson(req, limit = 10_000) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) { reject(new ScanError('Request body too large.', 413)); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { reject(new ScanError('Body must be JSON.')); }
    });
    req.on('error', reject);
  });
}

/** Returns the caller's key label, or sends 401/429 and returns null. */
function authenticate(req, res, ip) {
  if (!ACCESS_KEYS.length) return 'open';
  const label = matchAccessKey(ACCESS_KEYS, req.headers['x-access-key']);
  if (label) return label;
  const limited = failedKeyPerIp.take(ip);
  if (!limited.ok) {
    send(res, 429, { error: 'Too many attempts with a wrong access key. Try again later.' }, { 'Retry-After': String(limited.retryAfterSeconds) });
  } else {
    send(res, 401, { error: 'An access key is required. Ask HypenSec for one, then enter it in the app.', code: 'access-key' });
  }
  return null;
}

function limitOrSend(res, ...checks) {
  for (const check of checks) {
    if (!check.ok) {
      send(res, 429, { error: `Rate limit reached. Try again in ${Math.ceil(check.retryAfterSeconds / 60)} minute(s).` }, { 'Retry-After': String(check.retryAfterSeconds) });
      return false;
    }
  }
  return true;
}

// ---------- routes ----------

async function handleScan(req, res, url, ip) {
  const who = authenticate(req, res, ip);
  if (!who) return;
  const body = await readJson(req);
  if (body.authorised !== true) {
    throw new ScanError('Confirm that you own this website or are authorised by its owner to test it.', 400);
  }
  if (!limitOrSend(res, scanLimitPerKey.take(who), scanLimitPerIp.take(ip))) return;
  const started = Date.now();
  try {
    const result = await withSlot(() => scanSite(body.url, { screenshots: url.searchParams.get('screenshots') !== '0' }));
    await audit({ event: 'scan', key: who, ip, target: String(body.url).slice(0, 300), authorised: true, outcome: 'completed', score: result.score, durationMs: Date.now() - started });
    send(res, 200, result);
  } catch (error) {
    await audit({ event: 'scan', key: who, ip, target: String(body.url).slice(0, 300), authorised: true, outcome: 'failed', reason: error.message.slice(0, 200), durationMs: Date.now() - started });
    throw error;
  }
}

async function handlePdf(req, res, ip) {
  const who = authenticate(req, res, ip);
  if (!who) return;
  if (!limitOrSend(res, pdfLimitPerKey.take(who))) return;
  // Body: { report, screenshots?, theme?: 'dark' | 'light' }. Reports with three screenshots are ~1 MB.
  const body = await readJson(req, 12_000_000);
  if (!body.report || !Array.isArray(body.report.checks)) throw new ScanError('Send the scan result as "report".');
  const pdf = await withSlot(async () => renderReportPdf(await getBrowser(), body.report, {
    screenshots: body.screenshots || {},
    theme: body.theme === 'light' ? 'light' : 'dark',
  }));
  res.writeHead(200, { 'Content-Type': 'application/pdf', 'Content-Length': pdf.length, 'Cache-Control': 'no-store', ...SECURITY_HEADERS, ...corsHeaders() });
  res.end(pdf);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const ip = clientIp(req, TRUST_PROXY);
  try {
    if (req.method === 'OPTIONS') return send(res, 204, {});
    const isRead = req.method === 'GET' || req.method === 'HEAD';
    if (isRead && APP_FILES[url.pathname]) return await serveApp(res, url.pathname, req.method === 'HEAD');
    if (isRead && url.pathname === '/health') return send(res, 200, { ok: true, running, queued: waiting.length });
    if (req.method === 'POST' && url.pathname === '/scan') return await handleScan(req, res, url, ip);
    if (req.method === 'POST' && url.pathname === '/report.pdf') return await handlePdf(req, res, ip);
    if (url.pathname === '/scan' || url.pathname === '/report.pdf') return send(res, 405, { error: `Use POST ${url.pathname}.` });
    return send(res, 404, { error: 'Not found.' });
  } catch (error) {
    const status = error instanceof ScanError ? error.status : 500;
    if (status === 500) console.error(error);
    if (!res.headersSent) send(res, status, { error: status === 500 ? 'Something went wrong. Please try again.' : error.message });
  }
});

server.requestTimeout = 200_000;
server.listen(PORT, HOST, () => {
  console.log(`HypenSec Astra listening on http://${HOST}:${PORT} (${PRODUCTION ? 'production' : 'development'}, ${ACCESS_KEYS.length} access key(s), audit log: ${AUDIT_LOG || 'off'})`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, async () => {
    server.close();
    await closeBrowser();
    process.exit(0);
  });
}
