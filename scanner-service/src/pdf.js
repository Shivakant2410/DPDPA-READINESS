// PDF export of a scan report in the HypenSec brand (same tokens as grc.css): deep navy, cyan → blue →
// violet gradient, Space Grotesk / JetBrains Mono, the HypenSec mark, dark or light theme.
//
// Everything in a report that came from the scanned site (banner text, URLs, cookie names, policy
// quotes) is untrusted, so it is escaped here and the PDF page runs with JavaScript disabled and
// no network access except Google Fonts.

import { readFileSync } from 'node:fs';
import { computeCoverage } from './findings.js';

const COVERAGE_LABEL = { full: 'Full coverage', partial: 'Partial coverage', limited: 'Limited coverage' };

const THEMES = {
  dark: {
    bg: '#0a0f1c', panel: '#0f1729', panelSoft: '#141e34', border: '#223049', text: '#f1f5f9', muted: '#9aa8bd', faint: '#66758c',
    accent: '#67e8f9', wordmark: 'linear-gradient(90deg, #ffffff 0%, #22d3ee 55%, #c084fc 100%)',
    ok: '#34d399', warn: '#fbbf24', bad: '#fb7185', info: '#7cb4fb', okSoft: 'rgba(52,211,153,.12)', warnSoft: 'rgba(251,191,36,.12)', badSoft: 'rgba(251,113,133,.12)', infoSoft: 'rgba(96,165,250,.13)',
  },
  light: {
    bg: '#f4f7fb', panel: '#ffffff', panelSoft: '#f6f8fc', border: '#e2e8f0', text: '#0b1220', muted: '#4b5870', faint: '#6b778c',
    accent: '#0e7490', wordmark: 'linear-gradient(90deg, #0b1220 0%, #0891b2 55%, #9333ea 100%)',
    ok: '#047857', warn: '#b45309', bad: '#be123c', info: '#1d4ed8', okSoft: 'rgba(5,150,105,.10)', warnSoft: 'rgba(217,119,6,.10)', badSoft: 'rgba(225,29,72,.09)', infoSoft: 'rgba(37,99,235,.09)',
  },
};
const GRADIENT = 'linear-gradient(90deg, #22d3ee 0%, #60a5fa 50%, #c084fc 100%)';
// The PDF page has no network access, so the logo is embedded.
let MARK = '';
// Fonts are embedded from the app's own copies, so rendering needs no network access at all.
const fontData = (file) => {
  try { return `data:font/woff2;base64,${readFileSync(new URL(`../../fonts/${file}`, import.meta.url)).toString('base64')}`; } catch { return ''; }
};
const FONT_FACES = [['Space Grotesk', 'SpaceGrotesk-latin.woff2', '300 700'], ['JetBrains Mono', 'JetBrainsMono-latin.woff2', '100 800']]
  .map(([family, file, weight]) => [family, fontData(file), weight])
  .filter(([, src]) => src)
  .map(([family, src, weight]) => `@font-face { font-family: '${family}'; font-weight: ${weight}; src: url(${src}) format('woff2'); }`)
  .join('\n');
try { MARK = `data:image/png;base64,${readFileSync(new URL('../../icons/hypensec-mark.png', import.meta.url)).toString('base64')}`; } catch { /* logo optional */ }
const AREAS = ['Consent & cookies', 'Privacy notice', 'Data principal rights', 'Data handling & sharing', "Children's data", 'Governance & security'];
const STATUS_LABEL = { fail: 'Failed', review: 'Needs review', 'not-evaluated': 'Not tested', pass: 'Passed' };
const STATUS_ORDER = { fail: 0, review: 1, 'not-evaluated': 2, pass: 3 };
const SEVERITY_ORDER = { High: 0, Medium: 1, Low: 2 };
const MAX_EVIDENCE = 8;

const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeImage = (value) => (typeof value === 'string' && /^data:image\/(jpeg|png);base64,[A-Za-z0-9+/=]+$/.test(value) ? value : null);

function hostOf(report) {
  try { return new URL(report.finalUrl || report.target).hostname; } catch { return 'website'; }
}

function verdict(score) {
  if (score === null || score === undefined) return 'Not enough tested checks';
  if (score >= 85) return 'Strong consent posture';
  if (score >= 60) return 'Gaps to fix';
  return 'Significant consent gaps';
}

function checkCard(check) {
  const evidence = check.evidence || [];
  const shown = evidence.slice(0, MAX_EVIDENCE);
  const more = evidence.length - shown.length;
  return `<article class="finding">
    <div class="finding-head">
      <span class="mono">${esc(check.controlId)}</span>
      <b class="sev ${esc(String(check.severity).toLowerCase())}">${esc(check.severity)}</b>
      <b class="status ${esc(check.status)}">${esc(STATUS_LABEL[check.status] || check.status)}</b>
    </div>
    <h3>${esc(check.title)}</h3>
    <p>${esc(check.detail)}</p>
    ${shown.length ? `<div class="block"><strong>Evidence</strong><ul class="evidence">${shown.map((line) => `<li>${esc(line)}</li>`).join('')}${more > 0 ? `<li class="more">…and ${more} more in the JSON export</li>` : ''}</ul></div>` : ''}
    ${check.status === 'pass' ? '' : `<div class="block"><strong>How to fix</strong><p>${esc(check.fix)}</p></div><div class="block"><strong>How to verify manually</strong><p>${esc(check.verify)}</p></div>`}
    <small><b>Mapping:</b> ${esc(check.legal)} · <b>Confidence:</b> ${esc(check.confidence)}</small>
  </article>`;
}

export function renderReportHtml(report, { screenshots = {}, theme = 'dark' } = {}) {
  const t = THEMES[theme] || THEMES.dark;
  const checks = Array.isArray(report.checks) ? report.checks : [];
  // Recomputed from the checks sent, which may be a subset of areas chosen in the app.
  const coverage = computeCoverage(checks);
  const host = hostOf(report);
  const count = (status) => checks.filter((c) => c.status === status).length;
  const pre = report.phases?.preConsent || { trackers: [], cookies: [] };
  const preTrackers = (pre.trackers || []).filter((x) => x.nonEssential && !x.deniedPingsOnly).length;
  const preCookies = (pre.cookies || []).filter((x) => x.nonEssential).length;
  const enabledByAccept = report.summary?.trackersEnabledByAccept || [];
  const priorities = checks.filter((c) => c.status === 'fail')
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
    .slice(0, 8);
  const shots = [['preConsent', 'Before any choice'], ['afterReject', 'After Reject, reloaded'], ['afterAccept', 'After Accept, reloaded']]
    .map(([key, label]) => [safeImage(screenshots[key]), label]).filter(([src]) => src);
  const scanned = report.scannedAt ? new Date(report.scannedAt) : new Date();
  const scannedText = scanned.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Asia/Kolkata' });
  const byArea = AREAS.map((area) => [area, checks.filter((c) => c.area === area)
    .sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])])
    .filter(([, list]) => list.length);

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(host)} — DPDPA readiness report</title>
<style>
${FONT_FACES}
@page { size: A4; }
* { box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
html, body { margin: 0; background: ${t.bg}; color: ${t.text}; }
body { font: 10.5px/1.55 'Space Grotesk', system-ui, sans-serif; padding: 0 14mm; }
.mono { font-family: 'JetBrains Mono', monospace; }
.brand { display: flex; align-items: center; gap: 12px; padding-bottom: 14px; border-bottom: 1px solid ${t.border}; }
.mark { width: 26px; height: 26px; border-radius: 7px; }
.wordmark { font: 700 19px/1 'Space Grotesk', system-ui, sans-serif; letter-spacing: -.03em; background: ${t.wordmark}; -webkit-background-clip: text; background-clip: text; color: transparent; }
.tag { padding: 2px 7px; border: 1px solid ${t.border}; border-radius: 999px; color: ${t.muted}; font: 500 7.5px/1.4 'JetBrains Mono', monospace; letter-spacing: .08em; text-transform: uppercase; }
.brand-site { margin-left: auto; color: ${t.faint}; font: 8px 'JetBrains Mono', monospace; }
.eyebrow { margin-top: 22px; color: ${t.muted}; font: 9px 'JetBrains Mono', monospace; text-transform: uppercase; letter-spacing: .08em; }
h1 { margin: 6px 0 4px; font-size: 30px; letter-spacing: -.04em; line-height: 1.1; overflow-wrap: anywhere; }
.sub { color: ${t.muted}; margin: 0; }
.card { margin-top: 18px; padding: 18px; border: 1px solid ${t.border}; border-radius: 14px; background: ${t.panel}; }
.score { display: grid; grid-template-columns: 38% 62%; }
.score-main { display: grid; align-content: center; gap: 2px; }
.label { color: ${t.muted}; font: 9px 'JetBrains Mono', monospace; text-transform: uppercase; letter-spacing: .08em; }
.score-num { font: 500 46px/1 'JetBrains Mono', monospace; background: ${GRADIENT}; -webkit-background-clip: text; background-clip: text; color: transparent; }
.score-num span { font-size: 14px; color: ${t.muted}; -webkit-text-fill-color: ${t.muted}; margin-left: 4px; }
.verdict { color: ${t.ok}; font-weight: 600; margin-top: 6px; }
.verdict.warn { color: ${t.warn}; } .verdict.bad { color: ${t.bad}; }
.stats { display: grid; grid-template-columns: repeat(2, 1fr); }
.stats div { padding: 8px 12px; border-left: 1px solid ${t.border}; display: grid; gap: 4px; }
.stats div:nth-child(n+3) { border-top: 1px solid ${t.border}; }
.stats span { color: ${t.muted}; font-size: 9.5px; }
.stats strong { font: 20px 'JetBrains Mono', monospace; overflow-wrap: anywhere; }
.stats strong.text { font: 600 12px/1.3 'Space Grotesk', system-ui, sans-serif; }
.counts { display: flex; flex-wrap: wrap; gap: 4px 12px; margin-top: 10px; color: ${t.muted}; }
.counts span { white-space: nowrap; }
.coverage { justify-self: start; margin-top: 8px; padding: 3px 9px; border-radius: 999px; font: 500 8.5px 'JetBrains Mono', monospace; }
.coverage.full { color: ${t.ok}; background: ${t.okSoft}; } .coverage.partial { color: ${t.warn}; background: ${t.warnSoft}; } .coverage.limited { color: ${t.bad}; background: ${t.badSoft}; }
.coverage-note { display: grid; gap: 3px; margin-top: 10px; padding: 10px 14px; border-radius: 12px; border: 1px solid ${t.border}; background: ${t.warnSoft}; color: ${t.muted}; font-size: 9.5px; }
.coverage-note.limited { background: ${t.badSoft}; }
.coverage-note strong { color: ${t.warn}; font-size: 10.5px; } .coverage-note.limited strong { color: ${t.bad}; }
.counts b { color: ${t.text}; font-family: 'JetBrains Mono', monospace; }
h2 { margin: 26px 0 10px; font-size: 16px; letter-spacing: -.02em; break-after: avoid; }
h2 small { color: ${t.muted}; font-weight: 400; font-size: 10px; margin-left: 6px; }
.priorities { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
.priorities li { display: grid; grid-template-columns: 22px 1fr auto; gap: 10px; align-items: start; padding: 10px 12px; border: 1px solid ${t.border}; border-radius: 12px; background: ${t.panel}; break-inside: avoid; }
.priorities .n { font: 500 11px 'JetBrains Mono', monospace; color: ${t.accent}; }
.priorities p { margin: 2px 0 0; color: ${t.muted}; }
.shots { display: grid; grid-template-columns: repeat(${Math.max(shots.length, 1)}, 1fr); gap: 8px; }
.shots figure { margin: 0; border: 1px solid ${t.border}; border-radius: 12px; overflow: hidden; background: ${t.panel}; break-inside: avoid; }
.shots img { display: block; width: 100%; max-height: 92mm; object-fit: cover; object-position: top; }
.shots figcaption { padding: 6px 10px; color: ${t.muted}; font-size: 9px; }
.finding { padding: 14px 16px; margin-bottom: 8px; border: 1px solid ${t.border}; border-radius: 14px; background: ${t.panel}; break-inside: avoid; }
.finding-head { display: flex; align-items: center; gap: 8px; color: ${t.muted}; font: 9px 'JetBrains Mono', monospace; }
.finding-head b { padding: 2px 6px; border-radius: 999px; font-weight: 500; }
.sev.high { color: ${t.bad}; background: ${t.badSoft}; } .sev.medium { color: ${t.warn}; background: ${t.warnSoft}; } .sev.low { color: ${t.info}; background: ${t.infoSoft}; }
.status { background: ${t.panelSoft}; border: 1px solid ${t.border}; } .status.fail { color: ${t.bad}; } .status.review { color: ${t.warn}; } .status.not-evaluated { color: ${t.muted}; } .status.pass { color: ${t.ok}; }
.finding h3 { margin: 8px 0 4px; font-size: 13px; letter-spacing: -.01em; }
.finding > p { margin: 0 0 6px; color: ${t.muted}; }
.block { padding: 7px 0; border-top: 1px solid ${t.border}; }
.block strong { font-size: 9.5px; }
.block p { margin: 2px 0 0; color: ${t.muted}; }
.evidence { margin: 4px 0 0; padding-left: 14px; display: grid; gap: 2px; color: ${t.muted}; font: 8.5px/1.5 'JetBrains Mono', monospace; overflow-wrap: anywhere; }
.evidence .more { list-style: none; margin-left: -14px; color: ${t.faint}; }
.finding small { display: block; margin-top: 6px; color: ${t.faint}; font-size: 8.5px; line-height: 1.5; }
.area { break-before: auto; }
.disclaimer { margin: 22px 0 6px; padding: 12px 14px; border: 1px solid ${t.border}; border-radius: 12px; background: ${t.warnSoft}; color: ${t.muted}; font-size: 9px; }
.disclaimer strong { color: ${t.warn}; }
</style></head><body>
  <header class="brand">
    ${MARK ? `<img class="mark" src="${MARK}" alt="">` : ''}
    <span class="wordmark">HypenSec</span>
    <span class="tag">Astra</span>
    <span class="brand-site">hypensec.com</span>
  </header>
  <div class="eyebrow">DPDPA readiness report · DPDP Act, 2023 &amp; Rules, 2025</div>
  <h1>${esc(host)}</h1>
  <p class="sub">Scanned ${esc(scannedText)} IST in ${Math.round((report.durationMs || 0) / 1000)}s · ${esc(report.finalUrl || report.target)}</p>

  <section class="card score">
    <div class="score-main">
      <div class="label">DPDPA consent readiness</div>
      <div class="score-num">${report.score ?? '–'}<span>/ 100</span></div>
      <div class="verdict ${report.score >= 85 ? '' : report.score >= 60 ? 'warn' : 'bad'}">${esc(verdict(report.score))}</div>
      <div class="counts"><span><b>${count('fail')}</b> failed</span><span><b>${count('review')}</b> to review</span><span><b>${count('pass')}</b> passed</span><span><b>${count('not-evaluated')}</b> not tested</span></div>
      <div class="coverage ${coverage.level}">${coverage.tested} of ${coverage.total} checks tested · ${COVERAGE_LABEL[coverage.level]}</div>
    </div>
    <div class="stats">
      <div><span>Trackers before consent</span><strong>${preTrackers}</strong></div>
      <div><span>Tracking cookies before consent</span><strong>${preCookies}</strong></div>
      <div><span>Consent banner</span><strong class="text">${esc(report.banner?.cmp || 'None found')}</strong></div>
      <div><span>Trackers enabled by Accept</span><strong>${enabledByAccept.length}</strong></div>
    </div>
  </section>
  ${coverage.reasons.length ? `<div class="coverage-note ${coverage.level}"><strong>${coverage.level === 'limited' ? 'This score rests on few checks' : 'Some checks could not run'}</strong>${coverage.reasons.map((item) => `<span>${item.count} check${item.count === 1 ? '' : 's'} couldn’t run: ${esc(item.reason)}</span>`).join('')}</div>` : ''}

  ${priorities.length ? `<h2>Fix these first <small>failed checks, most severe first</small></h2>
  <ol class="priorities">${priorities.map((c, i) => `<li><span class="n">${String(i + 1).padStart(2, '0')}</span><div><strong>${esc(c.title)}</strong><p>${esc(c.fix)}</p></div><b class="sev ${esc(String(c.severity).toLowerCase())}" style="padding:2px 6px;border-radius:5px;font:9px 'JetBrains Mono',monospace">${esc(c.severity)}</b></li>`).join('')}</ol>` : ''}

  ${shots.length ? `<h2>What a first-time visitor sees</h2><div class="shots">${shots.map(([src, label]) => `<figure><img src="${src}" alt=""><figcaption>${esc(label)}</figcaption></figure>`).join('')}</div>` : ''}

  ${byArea.map(([area, list]) => `<section class="area"><h2>${esc(area)} <small>${list.filter((c) => c.status === 'fail').length} failed · ${list.filter((c) => c.status === 'pass' || c.status === 'fail').length} of ${list.length} tested</small></h2>${list.map(checkCard).join('')}</section>`).join('')}

  <div class="disclaimer"><strong>Automated readiness check.</strong> This report records what an automated browser observed on ${esc(scannedText)} IST and what the published privacy notice says. It is not legal advice or a certification. Checks marked "Not tested" could not be evaluated automatically and should be reviewed by hand.</div>
</body></html>`;
}

// Header and footer fill the page margins with the theme background, so dark PDFs have no white
// edges. Chrome pads #header/#footer by default, which made the strip taller than its margin and
// cover the top of each page; the reset below removes that.
function chrome(theme, host) {
  const t = THEMES[theme] || THEMES.dark;
  const reset = '<style>#header, #footer { padding: 0 !important; } html, body { margin: 0; padding: 0; }</style>';
  const box = `-webkit-print-color-adjust:exact;print-color-adjust:exact;background:${t.bg};width:100%;margin:0;padding:0 14mm;box-sizing:border-box;font-family:'JetBrains Mono',monospace;font-size:7.5px;color:${t.faint};display:flex;align-items:center;justify-content:space-between`;
  return {
    headerTemplate: `${reset}<div style="${box};height:calc(12mm + 2px);margin-bottom:-2px"></div>`,
    footerTemplate: `${reset}<div style="${box};height:calc(14mm + 2px);margin-top:-2px"><span>HypenSec Astra · DPDPA readiness report · hypensec.com · ${esc(host)}</span><span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>`,
  };
}

/** Renders the report to a PDF buffer using an existing Playwright browser. */
export async function renderReportPdf(browser, report, { screenshots = {}, theme = 'dark' } = {}) {
  const context = await browser.newContext({ javaScriptEnabled: false });
  try {
    // Nothing is fetched while rendering: fonts, logo and screenshots are all embedded.
    await context.route('**/*', (route) => route.abort());
    const page = await context.newPage();
    await page.setContent(renderReportHtml(report, { screenshots, theme }), { waitUntil: 'networkidle', timeout: 30_000 }).catch(() => {});
    const host = hostOf(report);
    return await page.pdf({
      format: 'A4',
      printBackground: true,
      displayHeaderFooter: true,
      ...chrome(theme, host),
      margin: { top: '12mm', bottom: '14mm', left: '0', right: '0' },
    });
  } finally {
    await context.close();
  }
}
