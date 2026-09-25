// Consent journey scanner.
//
// Journey 1 (clean profile): load -> capture pre-consent state -> click Reject -> reload -> capture.
// Journey 2 (clean profile): load -> click Accept -> reload -> capture.
//
// Cookies come from the browser context, so HttpOnly and third-party cookies are included,
// unlike document.cookie. Requests are recorded from the network layer with timings
// relative to navigation start.

import { chromium } from 'playwright';
import { classifyCookie, classifyRequest, NON_ESSENTIAL, registrableDomain } from './trackers.js';
import { describeBanner, detectBanner, makeChoice, waitForBanner } from './cmp.js';
import { assertPublicUrl, ScanError } from './guard.js';
import { buildChecks } from './findings.js';
import { detectLanguage } from './notice.js';

const IDENTIFY = process.env.SCANNER_IDENTIFY !== '0';
const SCANNER_TOKEN = 'HypenSecAstra/1.0 (+https://hypensec.com)';
const NAV_TIMEOUT_MS = 45_000;
const SCAN_TIMEOUT_MS = Number(process.env.SCAN_TIMEOUT_MS || 150_000);
const SECURITY_HEADERS = ['strict-transport-security', 'content-security-policy', 'x-content-type-options', 'referrer-policy', 'permissions-policy'];

let browserPromise = null;

export async function getBrowser() {
  if (!browserPromise) {
    // Identified mode (default) leaves the automation flag visible; SCANNER_IDENTIFY=0 hides it, for sites you own.
    browserPromise = chromium.launch({ headless: true, args: IDENTIFY ? [] : ['--disable-blink-features=AutomationControlled'] });
    browserPromise.then((browser) => browser.on('disconnected', () => { browserPromise = null; }))
      .catch(() => { browserPromise = null; });
  }
  return browserPromise;
}

export async function closeBrowser() {
  if (browserPromise) await (await browserPromise).close().catch(() => {});
}

export function normalizeTarget(input) {
  const raw = String(input || '').trim();
  if (!raw) throw new ScanError('Enter a website address.');
  return /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
}

async function newContext(browser) {
  // A desktop Chrome in India (sites geo-target banners), identified as HypenSec's scanner by default so site
  // owners can see who is visiting and allow-list it.
  const version = browser.version();
  const context = await browser.newContext({
    userAgent: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version} Safari/537.36${IDENTIFY ? ` ${SCANNER_TOKEN}` : ''}`,
    locale: 'en-IN',
    timezoneId: 'Asia/Kolkata',
    viewport: { width: 1366, height: 900 },
  });
  // Re-check every top-level navigation (redirects included) against the SSRF guard.
  await context.route('**/*', async (route) => {
    const request = route.request();
    let isTopLevel = false;
    try { isTopLevel = request.isNavigationRequest() && request.frame().parentFrame() === null; } catch { /* service worker */ }
    if (isTopLevel) {
      try { await assertPublicUrl(request.url()); } catch { return route.abort('blockedbyclient'); }
    }
    return route.continue();
  });
  return context;
}

function attachRecorder(page) {
  const start = Date.now();
  const log = [];
  page.on('request', (request) => {
    log.push({ url: request.url(), type: request.resourceType(), method: request.method(), t: Date.now() - start });
  });
  return log;
}

async function settle(page) {
  // Slow sites: many banners and tags are injected only after the load event.
  await page.waitForLoadState('load', { timeout: 30_000 }).catch(() => {});
  await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => {});
  await page.waitForTimeout(3000);
}

// Bot-protection interstitials often return HTTP 200 (practo.com served Akamai's "Processing your
// request" page), and scoring one as the real site produced both false fails and false passes.
const CHALLENGE = /processing your request|powered and protected by akamai|just a moment|checking (if the site connection is secure|your browser)|attention required|verify you are (a )?human|pardon our interruption|request unsuccessful\. incapsula|please enable js and disable any ad blocker|access denied|are you a robot|security check to access/i;

async function blockedReason(page) {
  const info = await page.evaluate(() => ({
    title: document.title,
    text: (document.body?.innerText || '').replace(/\s+/g, ' ').trim(),
    links: document.querySelectorAll('a[href]').length,
    challengeMarkup: Boolean(document.querySelector('#challenge-form, #cf-challenge-running, .cf-browser-verification, #px-captcha, iframe[src*="captcha-delivery"], iframe[src*="hcaptcha"], iframe[src*="challenges.cloudflare"]')),
  })).catch(() => null);
  if (!info) return null;
  if (info.challengeMarkup) return 'a bot-protection challenge';
  if (info.text.length < 600 && CHALLENGE.test(`${info.title} ${info.text}`)) return `a bot-protection page ("${info.text.slice(0, 60)}")`;
  if (info.text.length < 80 && info.links < 3) return 'an empty page';
  return null;
}

async function screenshot(page) {
  try {
    const buffer = await page.screenshot({ type: 'jpeg', quality: 55 });
    return `data:image/jpeg;base64,${buffer.toString('base64')}`;
  } catch {
    return null;
  }
}

function summarizeRequests(requests, siteDomain) {
  const trackers = new Map();
  const thirdPartyHosts = new Set();
  for (const request of requests) {
    let host;
    try { host = new URL(request.url).hostname; } catch { continue; }
    if (!/^https?:/.test(request.url)) continue;
    const firstParty = registrableDomain(host) === siteDomain;
    if (!firstParty) thirdPartyHosts.add(host);
    const match = classifyRequest(request.url);
    if (!match) continue;
    const key = `${match.vendor}|${match.category}`;
    const entry = trackers.get(key) || {
      vendor: match.vendor, category: match.category, hosts: new Set(), requests: 0,
      firstSeenMs: request.t, sampleUrl: request.url.slice(0, 240), consentMode: { denied: 0, granted: 0, absent: 0 },
    };
    entry.hosts.add(host);
    entry.requests += 1;
    entry.firstSeenMs = Math.min(entry.firstSeenMs, request.t);
    if (!match.consentMode) entry.consentMode.absent += 1;
    else if (match.consentMode.adStorage || match.consentMode.analyticsStorage) entry.consentMode.granted += 1;
    else entry.consentMode.denied += 1;
    trackers.set(key, entry);
  }
  return {
    requestCount: requests.length,
    thirdPartyHosts: [...thirdPartyHosts].sort(),
    trackers: [...trackers.values()].map((entry) => ({
      ...entry,
      hosts: [...entry.hosts],
      nonEssential: NON_ESSENTIAL.has(entry.category),
      // Only Consent Mode "denied" pings and nothing else: cookieless, weaker signal.
      deniedPingsOnly: entry.consentMode.denied > 0 && entry.consentMode.granted === 0 && entry.consentMode.absent === 0,
    })).sort((a, b) => a.firstSeenMs - b.firstSeenMs),
  };
}

function summarizeCookies(cookies, siteDomain) {
  const now = Date.now() / 1000;
  return cookies.map((cookie) => {
    const domain = cookie.domain.replace(/^\./, '');
    const thirdParty = registrableDomain(domain) !== siteDomain;
    const match = classifyCookie(cookie);
    const category = match?.category || (thirdParty ? 'unclassified-third-party' : 'unclassified');
    return {
      name: cookie.name,
      domain: cookie.domain,
      thirdParty,
      vendor: match?.vendor || null,
      category,
      nonEssential: NON_ESSENTIAL.has(category),
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite,
      expiresInDays: cookie.expires > 0 ? Math.max(0, Math.round((cookie.expires - now) / 86400)) : 'session',
    };
  }).sort((a, b) => Number(b.nonEssential) - Number(a.nonEssential) || a.name.localeCompare(b.name));
}

async function capture(page, context, requests, siteDomain) {
  return {
    ...summarizeRequests(requests, siteDomain),
    cookies: summarizeCookies(await context.cookies(), siteDomain),
  };
}

async function findPrivacyLinks(page, siteDomain) {
  // Ranked so "Privacy Policy" in the footer beats marketing pages that merely mention privacy.
  // strength: 'strong' = same-site link that looks like the notice itself, 'weak' = anything else.
  return page.evaluate((site) => {
    const sameSite = (href) => { try { const host = new URL(href).hostname; return host === site || host.endsWith(`.${site}`); } catch { return false; } };
    // Only a real overlay counts as the banner. Matching "cookie" in any ancestor's class is wrong:
    // e.g. the Cookie Notice plugin puts "cookies-not-set" on <body>, which would exclude every link.
    const inBanner = (a) => {
      for (let el = a.parentElement; el && el !== document.body; el = el.parentElement) {
        const style = getComputedStyle(el);
        const overlay = style.position === 'fixed' || style.position === 'sticky'
          || ['dialog', 'alertdialog'].includes(el.getAttribute('role')) || el.getAttribute('aria-modal') === 'true';
        // A banner covers part of the screen. App shells such as chatgpt.com are fixed and full-height,
        // and treating them as a banner discarded the footer's "Privacy Policy" link.
        const partial = el.getBoundingClientRect().height < window.innerHeight * 0.6;
        if (overlay && partial && /cookie|consent/i.test(el.textContent || '')) return true;
      }
      return false;
    };
    const loose = /privacy|data\s*protection|personal\s*data|गोपनीयता|निजता/i;
    const strongText = /^(our\s+)?(privacy|data\s+protection|data\s+privacy)(\s+(policy|notice|statement|centre|center))?$|privacy\s+(policy|notice|statement)|गोपनीयता\s+नीति/i;
    const strongHref = /privacy[-_]?(policy|notice|statement)|\/privacy\/?(\?|#|$)|data[-_]protection[-_]policy/i;
    const seen = new Set();
    return [...document.querySelectorAll('a[href]')]
      .map((a) => {
        const text = (a.innerText || a.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim().slice(0, 80);
        const inFooter = Boolean(a.closest('footer, [role="contentinfo"], [class*="footer" i], [id*="footer" i]'));
        const banner = inBanner(a);
        const eligible = sameSite(a.href) && !banner;
        // Off-site policy (chatgpt.com -> openai.com/policies/privacy-policy): accept only a link labelled
        // exactly "Privacy Policy/Notice", pointing at a privacy URL, outside any cookie banner. Scored
        // below same-site links so a site's own policy still wins.
        const offSitePolicy = !eligible && !banner && /^(our\s+)?privacy\s+(policy|notice|statement)$/i.test(text) && /privacy/i.test(a.href);
        const score = eligible
          ? (strongText.test(text) ? 3 : 0) + (strongHref.test(a.href) ? 2 : 0) + (inFooter ? 1 : 0)
          : offSitePolicy ? 2 : 0;
        return { text, href: a.href, inFooter, score };
      })
      .filter((link) => /^https?:/.test(link.href) && loose.test(`${link.text} ${link.href}`))
      .filter((link) => !seen.has(link.href) && seen.add(link.href))
      .sort((a, b) => b.score - a.score)
      .slice(0, 5)
      .map(({ score, ...link }) => ({ ...link, strength: score >= 2 ? 'strong' : 'weak' }));
  }, siteDomain).catch(() => []);
}

async function rejectJourney(browser, target, track) {
  const context = track(await newContext(browser));
  const page = await context.newPage();
  const log = attachRecorder(page);
  const response = await page.goto(target, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT_MS }).catch((error) => {
    const reason = error.message.split('\n')[0];
    if (/ERR_HTTP2_PROTOCOL_ERROR|ERR_CONNECTION_RESET|ERR_CONNECTION_CLOSED|ERR_EMPTY_RESPONSE/.test(reason)) {
      throw new ScanError(`${target} refused the automated browser (likely bot protection such as Akamai or Cloudflare). Allow-list user agents containing "HypenSecAstra" (or the scanner's IP) for this site and retry.`, 502);
    }
    throw new ScanError(`Could not load ${target}: ${reason}`, 502);
  });
  if (!response) throw new ScanError(`No response from ${target}.`, 502);
  // A 4xx/5xx page is usually a bot challenge or error page; scoring it would be misleading.
  if (response.status() >= 400) {
    throw new ScanError(`${target} returned HTTP ${response.status()} to the automated browser, so its real consent behaviour could not be observed. If this is bot protection, allow-list user agents containing "HypenSecAstra" and retry.`, 502);
  }
  await settle(page);
  const blocked = await blockedReason(page);
  if (blocked) throw new ScanError(`${target} showed ${blocked} to the automated browser, so its real consent behaviour could not be observed. Allow-list user agents containing "HypenSecAstra" and retry.`, 502);

  const finalUrl = page.url();
  const siteDomain = registrableDomain(new URL(finalUrl).hostname);
  const headers = response.headers();
  // No scrolling here: some banners treat scrolling as consent (freshworks.com), which would
  // contaminate the reject test. Scrolling is measured separately in browseJourney.
  const banner = await waitForBanner(page, 6000);
  const preConsent = await capture(page, context, log, siteDomain);
  const preShot = await screenshot(page);

  let afterReject = null;
  let rejectShot = null;
  if (banner) {
    const choice = await makeChoice(page, 'reject').catch((error) => ({ clicked: false, note: `Click failed: ${error.message.split('\n')[0]}` }));
    if (choice.clicked) {
      const mark = log.length;
      await settle(page);
      // Reload: many trackers only fire on the next page view, which is where reject violations show up.
      await page.reload({ waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT_MS }).catch(() => {});
      await settle(page);
      afterReject = {
        choice,
        bannerReshown: Boolean(await detectBanner(page)),
        consentState: await readConsentState(page, context),
        ...(await capture(page, context, log.slice(mark), siteDomain)),
      };
      rejectShot = await screenshot(page);
    } else {
      afterReject = { choice };
    }
  }

  return {
    finalUrl, siteDomain, status: response.status(), headers, banner: describeBanner(banner),
    preConsent, afterReject, screenshots: { preConsent: preShot, afterReject: rejectShot },
  };
}

// What the site recorded after our "reject": a refusal-looking button can still store consent.
// lenskart.com's "Allow Selection" saved gotrust_consent_v1 with every category true.
const OPTIONAL_CATEGORY = /analytic|statistic|performance|marketing|advertis|target|functional|preference|social|personali[sz]/i;
const ONETRUST_GROUPS = { C0002: 'performance', C0003: 'functional', C0004: 'targeting', C0005: 'social media' };

async function readConsentState(page, context) {
  const cookies = await context.cookies();
  const storage = await page.evaluate(() => Object.fromEntries(Object.keys(localStorage).map((k) => [k, localStorage.getItem(k)]))).catch(() => ({}));
  const granted = new Set();
  const denied = new Set();
  const sources = new Set();
  const mark = (name, on, source) => {
    if (!OPTIONAL_CATEGORY.test(name)) return;
    (on ? granted : denied).add(name);
    sources.add(source);
  };
  const cookie = (name) => cookies.find((c) => c.name === name);
  const decode = (value) => { try { return decodeURIComponent(value); } catch { return value; } };

  const onetrust = cookie('OptanonConsent');
  const groups = onetrust && decode(onetrust.value).match(/groups=([^&]*)/);
  if (groups) {
    for (const pair of groups[1].split(',')) {
      const [id, value] = pair.split(':');
      if (ONETRUST_GROUPS[id]) mark(ONETRUST_GROUPS[id], value === '1', 'OptanonConsent cookie');
    }
  }
  const cookiebot = cookie('CookieConsent');
  if (cookiebot) for (const m of decode(cookiebot.value).matchAll(/(preferences|statistics|marketing):(true|false)/g)) mark(m[1], m[2] === 'true', 'CookieConsent cookie');
  const cookieyes = cookie('cookieyes-consent');
  if (cookieyes) for (const m of decode(cookieyes.value).matchAll(/(functional|analytics|performance|advertisement):(yes|no)/g)) mark(m[1], m[2] === 'yes', 'cookieyes-consent cookie');

  const records = [...Object.entries(storage).map(([k, v]) => [k, v, 'localStorage']), ...cookies.map((c) => [c.name, decode(c.value), 'cookie'])]
    .filter(([key]) => /consent|cookie|gdpr|privacy|cmp/i.test(key) && !/^(OptanonConsent|CookieConsent|cookieyes-consent)$/.test(key));
  for (const [key, value, where] of records) {
    let parsed;
    try { parsed = JSON.parse(value); } catch { continue; }
    const scan = (obj, depth) => {
      if (!obj || typeof obj !== 'object' || depth > 2) return;
      for (const [k, v] of Object.entries(obj)) {
        if (typeof v === 'boolean') mark(k, v, `${key} (${where})`);
        else scan(v, depth + 1);
      }
    };
    scan(parsed, 0);
  }
  return sources.size ? { granted: [...granted], denied: [...denied], sources: [...sources] } : null;
}

const CONSENT_COOKIE =/^(OptanonAlertBoxClosed|OptanonConsent|CookieConsent|cookieyes-consent|didomi_token|euconsent-v2|cmplz_\w+|uc_\w+|osano_consentmanager\w*|notice_behavior|cookie_notice_accepted|cookielawinfo-\w+|moove_gdpr_popup)$/;

// Journey 3 (clean profile): browse like a visitor without touching the banner. Scroll with the
// mouse wheel to the bottom so lazy footers render (1mg.com), then:
//  - collect the privacy and cookie policy links
//  - record whether scrolling alone dismissed the banner or stored consent (freshworks.com)
async function browseJourney(browser, target, siteDomain, track) {
  const context = track(await newContext(browser));
  const page = await context.newPage();
  await page.goto(target, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT_MS });
  await settle(page);
  const bannerBefore = await waitForBanner(page, 6000);
  const consentBefore = new Set((await context.cookies()).filter((c) => CONSENT_COOKIE.test(c.name)).map((c) => `${c.name}=${c.value}`));

  const blocked = await blockedReason(page);
  if (blocked) throw new Error(`The homepage showed ${blocked} on the browsing visit.`);

  // Keep going until we have sat at the bottom with an unchanged height three times: lazy footers
  // can take a moment to render (1mg.com missed its privacy link on one of two runs otherwise).
  let lastHeight = 0;
  let stableAtBottom = 0;
  for (let i = 0; i < 40 && stableAtBottom < 3; i += 1) {
    await page.mouse.wheel(0, 1600);
    await page.waitForTimeout(stableAtBottom ? 700 : 350);
    const { height, bottom } = await page.evaluate(() => ({
      height: document.documentElement.scrollHeight,
      bottom: window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 5,
    })).catch(() => ({ height: 0, bottom: true }));
    stableAtBottom = bottom && height === lastHeight ? stableAtBottom + 1 : 0;
    lastHeight = height;
  }
  await page.waitForTimeout(1500);

  let scrollConsent = null;
  if (bannerBefore) {
    const bannerAfter = await detectBanner(page);
    const stored = (await context.cookies())
      .filter((c) => CONSENT_COOKIE.test(c.name) && !consentBefore.has(`${c.name}=${c.value}`))
      .map((c) => `${c.name}=${decodeURIComponent(c.value).slice(0, 120)}`);
    if (!bannerAfter || stored.length) scrollConsent = { bannerDismissed: !bannerAfter, stored };
  }

  const privacyLinks = await findPrivacyLinks(page, siteDomain);
  // A cookie policy is not a DPDP s.5 notice, but its presence changes what we tell the site owner.
  const cookiePolicyLinks = await page.evaluate(() => [...document.querySelectorAll('a[href]')]
    .filter((a) => /cookies?[\s_-]*(policy|notice)/i.test(`${a.textContent} ${a.href}`))
    .map((a) => a.href).filter((href, i, all) => all.indexOf(href) === i).slice(0, 3)).catch(() => []);
  return { privacyLinks, cookiePolicyLinks, scrollConsent };
}

async function acceptJourney(browser, target, siteDomain, track) {
  const context = track(await newContext(browser));
  const page = await context.newPage();
  const log = attachRecorder(page);
  await page.goto(target, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT_MS });
  await settle(page);
  const choice = await makeChoice(page, 'accept').catch((error) => ({ clicked: false, note: `Click failed: ${error.message.split('\n')[0]}` }));
  if (!choice.clicked) return { afterAccept: { choice }, screenshot: null };
  const mark = log.length;
  await settle(page);
  await page.reload({ waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT_MS }).catch(() => {});
  await settle(page);
  return { afterAccept: { choice, ...(await capture(page, context, log.slice(mark), siteDomain)) }, screenshot: await screenshot(page) };
}

// Loads one page and returns its main text (collapsed sections included) and the same-site
// links inside that main content, for following policy hubs.
async function readPolicyPage(page, url) {
  const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT_MS }).catch(() => null);
  if (!response) return { error: 'The privacy notice page could not be loaded.' };
  if (response.status() >= 400) return { status: response.status(), error: `The privacy notice returned HTTP ${response.status()}.` };
  await page.waitForLoadState('load', { timeout: 20_000 }).catch(() => {});
  await page.waitForTimeout(1500);

  // The page is throwaway, so strip navigation and banners in place and read the main content.
  // Not innerText: it skips collapsed accordions and applies CSS text-transform.
  const { text, links } = await page.evaluate(() => {
    document.querySelectorAll('script, style, noscript, nav, header, [role="navigation"], [role="banner"], #onetrust-consent-sdk, #CybotCookiebotDialog, #cookie-notice, .cky-consent-container, [class*="cookie-banner" i], [id*="cookie-banner" i]')
      .forEach((el) => el.remove());
    const BLOCK = new Set(['P', 'DIV', 'LI', 'UL', 'OL', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'SECTION', 'ARTICLE', 'TR', 'TD', 'TH', 'DT', 'DD', 'BR', 'SUMMARY', 'DETAILS', 'BLOCKQUOTE', 'PRE', 'TABLE', 'MAIN', 'ASIDE', 'FIGCAPTION', 'LABEL', 'BUTTON']);
    const SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'SVG', 'SELECT', 'IFRAME', 'CANVAS']);
    const textOf = (root) => {
      const out = [];
      const walk = (node) => {
        if (node.nodeType === Node.TEXT_NODE) { out.push(node.nodeValue); return; }
        if (node.nodeType !== Node.ELEMENT_NODE) return;
        const tag = node.tagName.toUpperCase();
        if (SKIP.has(tag)) return;
        const block = BLOCK.has(tag);
        if (block) out.push('\n');
        node.childNodes.forEach(walk);
        if (block) out.push('\n');
      };
      walk(root);
      return out.join('').replace(/[ \t\u00a0]+/g, ' ').replace(/ *\n[\s\n]*/g, '\n').trim();
    };
    const linksOf = (root) => [...root.querySelectorAll('a[href]')]
      .map((a) => ({ text: (a.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 80), href: a.href }));
    const candidates = [...document.querySelectorAll('main, article, [role="main"], #content, .content, .entry-content, .post-content, .page-content')]
      .map((el) => ({ el, text: textOf(el) })).sort((a, b) => b.text.length - a.text.length);
    if (candidates[0] && candidates[0].text.length >= 1500) return { text: candidates[0].text, links: linksOf(candidates[0].el) };
    document.querySelectorAll('footer, [role="contentinfo"]').forEach((el) => el.remove());
    return document.body ? { text: textOf(document.body), links: linksOf(document.body) } : { text: '', links: [] };
  }).catch(() => ({ text: '', links: [] }));
  return { status: response.status(), finalUrl: page.url(), text, links };
}

const wordCount = (text) => text.split(/\s+/).filter(Boolean).length;

// A short "privacy" page is often a hub or a highlights summary that links to the real policy
// (groww.in -> "Privacy Policy - General", cred.club -> "read it"). Pick the best same-site link.
function fullPolicyLink(links, currentUrl, siteDomain) {
  const current = currentUrl.split('#')[0].replace(/\/$/, '');
  const scored = links.map((link, index) => {
    let href;
    try { href = new URL(link.href); } catch { return null; }
    if (!/^https?:$/.test(href.protocol) || registrableDomain(href.hostname) !== siteDomain) return null;
    if (`${href.origin}${href.pathname}`.replace(/\/$/, '') === current) return null;
    if (/\.pdf$/i.test(href.pathname)) return null;
    let score = 0;
    if (/privacy|data[-_]?protection/i.test(href.pathname)) score += 2;
    if (/privacy\s+(policy|notice|statement)|data\s+protection\s+policy/i.test(link.text)) score += 2;
    if (/\bgeneral\b|\bfull\b|complete|read\s+(it|more|the)|\bhere\b/i.test(link.text)) score += 1;
    return score >= 3 ? { href: href.href, score, index } : null;
  }).filter(Boolean);
  scored.sort((a, b) => b.score - a.score || a.index - b.index);
  return scored[0]?.href || null;
}

// Opens the privacy notice in its own clean context, so its trackers and cookies cannot
// leak into the consent-journey measurements. Returns { notice, text }.
const COMMON_POLICY_PATHS = ['/privacy-policy', '/privacy', '/privacy-notice', '/privacy-policy/', '/legal/privacy'];

// Before concluding a site has no privacy notice, try the usual addresses. A soft 404 (HTTP 200 with
// "Page not found") or a page that never mentions privacy does not count.
async function probeCommonPolicyPaths(browser, homeUrl, track) {
  const origin = new URL(homeUrl).origin;
  const context = track(await newContext(browser));
  const page = await context.newPage();
  const tried = [];
  for (const path of COMMON_POLICY_PATHS) {
    const url = origin + path;
    tried.push(url);
    const read = await readPolicyPage(page, url).catch(() => ({ error: 'failed' }));
    if (read.error) continue;
    const title = await page.title().catch(() => '');
    const softNotFound = /not\s*found|404|page\s+doesn.?t\s+exist/i.test(`${title} ${read.text.slice(0, 400)}`);
    if (!softNotFound && /privacy/i.test(`${title} ${read.text.slice(0, 2000)}`) && wordCount(read.text) >= 150) return { url: read.finalUrl, tried };
  }
  return { url: null, tried };
}

async function readNotice(browser, privacyLinks, siteDomain, track, homeUrl) {
  let link = privacyLinks.find((candidate) => candidate.strength === 'strong');
  let foundBy = 'homepage link';
  if (!link && homeUrl) {
    const probe = await probeCommonPolicyPaths(browser, homeUrl, track);
    if (probe.url) {
      link = { href: probe.url };
      foundBy = 'common address (not linked from the homepage)';
    } else {
      // Confident absence: the browsing visit succeeded, no link was found, and no usual address works.
      // With no notice at all, the notice requirements are not met, so these checks fail (not "not tested").
      return {
        notice: { missing: true, checked: ['Links on the homepage, after scrolling to the footer', ...probe.tried], error: 'No privacy notice was found on this site.' },
        text: '',
      };
    }
  }
  if (!link) return { notice: { error: 'No privacy notice link was found on the homepage.' }, text: '' };
  const url = link.href;
  if (/\.pdf([?#]|$)/i.test(url)) return { notice: { url, error: 'The privacy notice is a PDF, which is not analysed yet.' }, text: '' };
  try { await assertPublicUrl(url); } catch (error) { return { notice: { url, error: error.message }, text: '' }; }

  const context = track(await newContext(browser));
  const page = await context.newPage();
  let read = await readPolicyPage(page, url);
  // Single-page apps can still be rendering after the load event (in.bookmyshow.com/privacy gave
  // 53 words on one run and 2,576 on the next). Give a thin page one more chance.
  if (!read.error && wordCount(read.text) < 150) {
    await page.waitForTimeout(4000);
    const retry = await readPolicyPage(page, url);
    if (!retry.error && wordCount(retry.text) > wordCount(read.text)) read = retry;
  }
  if (read.error) return { notice: { url, status: read.status, error: read.error }, text: '' };

  let hubUrl = null;
  if (wordCount(read.text) < 1500) {
    const next = fullPolicyLink(read.links, read.finalUrl, siteDomain);
    if (next) {
      const deeper = await readPolicyPage(page, next);
      if (!deeper.error && wordCount(deeper.text) > wordCount(read.text)) {
        hubUrl = read.finalUrl;
        read = deeper;
      }
    }
  }

  const { text } = read;
  const words = wordCount(text);
  const language = detectLanguage(text);
  const notice = { url: read.finalUrl, status: read.status, words, language, foundBy, ...(hubUrl ? { hubUrl } : {}) };
  if (words < 150) return { notice: { ...notice, error: `The privacy notice page had only ${words} words of readable text (it may need a login or be blocked).` }, text: '' };
  if (language !== 'en') {
    return { notice: { ...notice, error: `The notice appears to be in ${language === 'hi' ? 'Hindi' : 'a language other than English'}; only English notices are analysed so far.` }, text: '' };
  }
  return { notice, text };
}

// includeNoticeText is for the benchmark audit; the API never returns the full notice.
export async function scanSite(input, { screenshots = true, includeNoticeText = false } = {}) {
  const target = normalizeTarget(input);
  await assertPublicUrl(target);
  const browser = await getBrowser();
  const started = Date.now();
  const contexts = [];
  const track = (context) => { contexts.push(context); return context; };

  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new ScanError(`Scan exceeded ${SCAN_TIMEOUT_MS / 1000}s and was stopped.`, 504)), SCAN_TIMEOUT_MS);
  });

  try {
    const work = (async () => {
      const first = await rejectJourney(browser, target, track);
      // Accept and browse (then notice) are independent of each other, so run them together.
      const failedBrowse = (error) => ({ privacyLinks: [], cookiePolicyLinks: [], scrollConsent: null, error: error.message.split('\n')[0] });
      const [second, { browse, noticeRead }] = await Promise.all([
        first.banner
          ? acceptJourney(browser, target, first.siteDomain, track).catch((error) => ({ afterAccept: { choice: { clicked: false, note: error.message.split('\n')[0] } }, screenshot: null }))
          : { afterAccept: null, screenshot: null },
        (async () => {
          const browsed = await browseJourney(browser, target, first.siteDomain, track).catch(failedBrowse);
          // A blocked browsing visit says nothing about the notice; do not report it as missing.
          const read = browsed.error
            ? { notice: { error: browsed.error }, text: '' }
            : await readNotice(browser, browsed.privacyLinks, first.siteDomain, track, first.finalUrl)
              .catch((error) => ({ notice: { error: `Reading the notice failed: ${error.message.split('\n')[0]}` }, text: '' }));
          return { browse: browsed, noticeRead: read };
        })(),
      ]);
      return { first, second, browse, noticeRead };
    })();
    const { first, second, browse, noticeRead } = await Promise.race([work, timeout]);

    const result = {
      target,
      finalUrl: first.finalUrl,
      siteDomain: first.siteDomain,
      scannedAt: new Date(started).toISOString(),
      durationMs: Date.now() - started,
      engine: { browser: 'chromium', version: browser.version(), method: 'playwright-consent-journey-v1' },
      http: {
        status: first.status,
        https: first.finalUrl.startsWith('https:'),
        securityHeaders: Object.fromEntries(SECURITY_HEADERS.map((name) => [name, first.headers[name] || null])),
      },
      banner: first.banner,
      privacyLinks: browse.privacyLinks,
      cookiePolicyLinks: browse.cookiePolicyLinks,
      scrollConsent: browse.scrollConsent,
      browseError: browse.error || null,
      notice: noticeRead.notice,
      phases: { preConsent: first.preConsent, afterReject: first.afterReject, afterAccept: second.afterAccept },
      screenshots: screenshots ? { ...first.screenshots, afterAccept: second.screenshot } : undefined,
    };
    const checks = buildChecks(result, { noticeText: noticeRead.text });
    return { ...result, ...checks, ...(includeNoticeText ? { noticeText: noticeRead.text } : {}) };
  } finally {
    clearTimeout(timer);
    await Promise.all(contexts.map((context) => context.close().catch(() => {})));
  }
}
