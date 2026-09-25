// Turns raw consent-journey observations into DPDP-mapped checks.
//
// Status values:
//   pass           - tested and the site behaved correctly
//   fail           - tested and the site did not; evidence says exactly what was seen
//   review         - something was observed that needs a human decision (not scored)
//   not-evaluated  - the scanner could not test it, e.g. no reject button to click (not scored)
//
// Legal references are to the Digital Personal Data Protection Act, 2023. Keep them in sync
// with counsel's reading; this is a readiness check, not legal advice.

import { analyzeNotice } from './notice.js';

const WEIGHT ={ High: 3, Medium: 2, Low: 1 };

const LEGAL = {
  consent: 'DPDP Act 2023, s.6(1): consent must be free, specific, informed, unconditional and unambiguous, given by a clear affirmative action; s.4: processing needs consent or a legitimate use.',
  withdrawal: 'DPDP Act 2023, s.6(1) and s.6(4): withdrawing consent must be as easy as giving it.',
  notice: 'DPDP Act 2023, s.5: a notice must accompany or precede every request for consent.',
  security: 'DPDP Act 2023, s.8(5): reasonable security safeguards to prevent personal data breach.',
};

function ms(value) {
  return value < 1000 ? `${value} ms` : `${(value / 1000).toFixed(1)} s`;
}

function trackerLine(tracker) {
  return `${tracker.vendor} (${tracker.category}): ${tracker.requests} request(s) to ${tracker.hosts.join(', ')}, first at ${ms(tracker.firstSeenMs)}. Example: ${tracker.sampleUrl}`;
}

function cookieLine(cookie) {
  const who = cookie.vendor ? `${cookie.vendor}, ${cookie.category}` : cookie.category;
  const life = cookie.expiresInDays === 'session' ? 'session cookie'
    : cookie.expiresInDays === 0 ? 'expires within a day' : `expires in ${cookie.expiresInDays} day(s)`;
  return `Cookie "${cookie.name}" on ${cookie.domain} (${who}; ${life}${cookie.httpOnly ? '; HttpOnly' : ''})`;
}

const cookieKey = (cookie) => `${cookie.name}@${cookie.domain}`;

// "By continuing to browse…", "If you continue to use this site we will assume…", "…deemed to consent".
const IMPLIED_CONSENT = /\bby\s+(continu\w*|browsing|navigating|scrolling|staying|remaining|proceeding)\b|\b(if|when)\s+you\s+(continue|keep|carry\s+on|proceed|stay|remain|browse|scroll|navigate)\b|\bby\s+using\s+(this|our|the)\s+(site|website|web\s*site|portal|app|platform|services?)\b|we('|\s+wi)ll\s+assume|\bdeemed\s+to\s+(have\s+)?(consent|accept|agree)|your\s+continued\s+use|continued\s+use\s+of\s+(this|our|the)\s+(site|website)/i;

function sentenceAround(text, index) {
  const start = Math.max(text.lastIndexOf('.', index) + 1, 0);
  const end = text.indexOf('.', index);
  return text.slice(start, end === -1 ? undefined : end + 1).trim().slice(0, 240);
}

const COVERAGE_AREAS = ['Consent & cookies', 'Privacy notice', 'Data principal rights', 'Data handling & sharing', "Children's data", 'Governance & security'];

/**
 * How much of the site the score rests on. Only passed/failed checks feed the score, so a site where
 * little could be tested can look better than it is (chatgpt.com scored 90 on 4 of 17 checks before
 * its policy link was found). Coverage makes that visible.
 * The web app (grc.js) mirrors this function for area-filtered reports; keep them in step.
 */
export function computeCoverage(checks) {
  const total = checks.length;
  const tested = checks.filter((c) => c.status === 'pass' || c.status === 'fail').length;
  const review = checks.filter((c) => c.status === 'review').length;
  const untested = checks.filter((c) => c.status === 'not-evaluated');
  const percent = total ? Math.round((tested / total) * 100) : 0;
  const level = percent >= 80 ? 'full' : percent >= 50 ? 'partial' : 'limited';
  const grouped = new Map();
  for (const check of untested) {
    const reason = String(check.detail || '').replace(/^Not tested:\s*/i, '').trim() || 'The scanner could not run this check.';
    grouped.set(reason, (grouped.get(reason) || 0) + 1);
  }
  const reasons = [...grouped].map(([reason, count]) => ({ reason, count })).sort((a, b) => b.count - a.count);
  const byArea = COVERAGE_AREAS.map((area) => {
    const inArea = checks.filter((c) => c.area === area);
    return { area, total: inArea.length, tested: inArea.filter((c) => c.status === 'pass' || c.status === 'fail').length, failed: inArea.filter((c) => c.status === 'fail').length };
  }).filter((a) => a.total);
  return { tested, total, review, notTested: untested.length, percent, level, reasons, byArea };
}

export function buildChecks(result, { noticeText = '' } = {}) {
  const { preConsent, afterReject, afterAccept } = result.phases;
  const checks = [];
  const add = (check) => checks.push({ confidence: 'high', evidence: [], ...check });

  const preTrackers = preConsent.trackers.filter((t) => t.nonEssential && !t.deniedPingsOnly);
  const preDeniedPings = preConsent.trackers.filter((t) => t.nonEssential && t.deniedPingsOnly);
  const preCookies = preConsent.cookies.filter((c) => c.nonEssential);
  const preUnclassified = preConsent.cookies.filter((c) => c.category === 'unclassified-third-party');
  const tagManagers = preConsent.trackers.filter((t) => t.category === 'tag-manager');

  // 1. Tracking before any choice.
  add({
    id: 'pre-consent-tracking',
    controlId: 'DPDP-CONSENT-002',
    area: 'Consent & cookies',
    title: 'No non-essential tracking before consent',
    severity: 'High',
    status: preTrackers.length || preCookies.length ? 'fail' : 'pass',
    detail: preTrackers.length || preCookies.length
      ? `Before the visitor made any choice, ${preTrackers.length} non-essential tracker(s) sent requests and ${preCookies.length} non-essential cookie(s) were set.`
      : 'No known advertising, analytics, session-replay or marketing trackers fired, and no such cookies were set, before a consent choice.',
    evidence: [...preTrackers.map(trackerLine), ...preCookies.map(cookieLine)],
    legal: LEGAL.consent,
    fix: 'Load these tags only after an affirmative "Accept". In Google Tag Manager, add a consent-based trigger (or Consent Mode with default "denied") to each listed tag; for hard-coded pixels, move them behind your consent platform\'s callback.',
    verify: 'Open the site in a private window, do not touch the banner, and check DevTools > Network and Application > Cookies for the listed vendors.',
  });

  if (preDeniedPings.length) {
    add({
      id: 'consent-mode-pings',
      controlId: 'DPDP-CONSENT-002',
      area: 'Consent & cookies',
      title: 'Google Consent Mode pings sent before consent',
      severity: 'Low',
      status: 'review',
      confidence: 'medium',
      detail: 'Google tags sent cookieless pings with consent "denied" before a choice. No cookies were set by these hits, but data such as IP address and page URL still reaches Google. Decide with counsel whether this is acceptable under your notice.',
      evidence: preDeniedPings.map(trackerLine),
      legal: LEGAL.consent,
      fix: 'If you do not want any data sent before consent, use Consent Mode "basic" (tags blocked until consent) rather than "advanced".',
      verify: 'In DevTools > Network, filter for "collect" and check the gcs parameter (G100 = denied).',
    });
  }

  if (preUnclassified.length) {
    add({
      id: 'unclassified-cookies',
      controlId: 'DPDP-CONSENT-002',
      area: 'Consent & cookies',
      title: 'Unclassified third-party cookies before consent',
      severity: 'Medium',
      status: 'review',
      confidence: 'medium',
      detail: `${preUnclassified.length} third-party cookie(s) were set before consent that are not in the scanner's database. Confirm each one is strictly necessary.`,
      evidence: preUnclassified.map(cookieLine),
      legal: LEGAL.consent,
      fix: 'Document the purpose of each cookie. Block anything that is not strictly necessary until consent.',
      verify: 'Look up each cookie in your consent platform\'s cookie scan or the vendor documentation.',
    });
  }

  // 2. Banner presence.
  const hasBanner = Boolean(result.banner);
  const needsBanner = preTrackers.length > 0 || preCookies.length > 0
    || (afterAccept?.trackers || []).some((t) => t.nonEssential);
  add({
    id: 'consent-banner',
    controlId: 'DPDP-CONSENT-001',
    area: 'Consent & cookies',
    title: 'Consent banner shown to first-time visitors',
    severity: 'High',
    status: hasBanner || !needsBanner ? 'pass' : 'fail',
    confidence: hasBanner ? 'high' : 'medium',
    detail: hasBanner
      ? `A consent banner was detected (${result.banner.cmp}).`
      : needsBanner
        ? 'No consent banner was found, but non-essential tracking is running.'
        : 'No consent banner was found, and no non-essential tracking was observed, so a cookie banner may not be required.',
    evidence: hasBanner
      ? [`Platform: ${result.banner.cmp}`, `Buttons found: ${Object.entries(result.banner.buttons).filter(([, v]) => v).map(([k, v]) => `${k} = "${v}"`).join(', ') || 'none recognised'}`, `Banner text: "${result.banner.text.slice(0, 300)}"`]
      : ['No known consent platform or cookie/consent overlay was found in any frame after waiting for the page to settle.'],
    legal: LEGAL.notice,
    fix: 'Show a consent notice on first visit that names the purposes and offers Accept and Reject with equal prominence.',
    verify: 'Open the site in a private window and confirm the banner appears before any interaction.',
  });

  // 2b. Consent must be an affirmative act, not inferred from browsing or closing the banner.
  if (hasBanner) {
    const impliedWording = result.banner.text.match(IMPLIED_CONSENT);
    const evidence = [];
    if (impliedWording) evidence.push(`Banner says: "${sentenceAround(result.banner.text, impliedWording.index)}"`);
    if (result.banner.closeAccepts) evidence.push('The banner\'s close (✕) control is configured to record acceptance, so dismissing the banner counts as consent.');
    // Measured in a separate clean browser that only scrolled (freshworks.com: OneTrust closed
    // the banner and stored consent for every category).
    const scroll = result.scrollConsent;
    if (scroll?.bannerDismissed || scroll?.stored?.length) {
      evidence.push(`Scrolling the page without clicking anything ${scroll.bannerDismissed ? 'closed the banner' : 'left the banner open'}${scroll.stored.length ? ' and stored consent' : ''}.`);
      evidence.push(...scroll.stored.map((cookie) => `Consent cookie written by scrolling: ${cookie}`));
    }
    add({
      id: 'affirmative-consent',
      controlId: 'DPDP-CONSENT-005',
      area: 'Consent & cookies',
      title: 'Consent requires a clear affirmative action',
      severity: 'High',
      status: evidence.length ? 'fail' : 'pass',
      confidence: impliedWording ? 'high' : evidence.length ? 'high' : 'medium',
      detail: evidence.length
        ? 'The banner treats continued browsing or closing the banner as consent. Under the DPDP Act, silence, inactivity or continued use is not consent.'
        : 'The banner wording does not claim consent from continued browsing, and closing it is not recorded as acceptance.',
      evidence,
      legal: LEGAL.consent,
      fix: 'Remove "by continuing to use this site you agree" wording. Record consent only when the visitor clicks Accept, and keep tracking off until then. Make the close control equivalent to Reject, or remove it.',
      verify: 'Scroll and click around without touching the banner, then check Application > Cookies: no tracking cookies should appear.',
    });
  }

  // What the site stored after our reject. A "save"/"allow selection" control that stores consent
  // as granted is not a way to reject (lenskart.com: every GoTrust category saved as true).
  const rejectChoice = afterReject?.choice;
  const grantedOnReject = afterReject?.consentState?.granted || [];
  const explicitReject = ['layer1', 'layer2-reject'].includes(rejectChoice?.method);
  const falseReject = Boolean(rejectChoice?.clicked && grantedOnReject.length && !explicitReject);
  const consentStateLine = afterReject?.consentState
    ? `Stored after clicking "${rejectChoice?.label}": granted = ${grantedOnReject.join(', ') || 'none'}; refused = ${afterReject.consentState.denied.join(', ') || 'none'} (read from ${afterReject.consentState.sources.join(', ')})`
    : null;

  // 3. Reject as easy as accept.
  if (hasBanner) {
    let status;
    let severity = 'High';
    let detail;
    if (result.banner.buttons.reject) {
      status = 'pass';
      detail = `The first layer offers "${result.banner.buttons.reject}" alongside "${result.banner.buttons.accept || 'accept'}".`;
    } else if (falseReject) {
      status = 'fail';
      detail = `There is no working way to reject. The only refusal-looking control, "${rejectChoice.label}", stored consent as granted for ${grantedOnReject.join(', ')}.`;
    } else if (rejectChoice?.clicked && rejectChoice.method === 'layer1-selection') {
      // One click refuses optional cookies, but only because nothing is ticked, and the button is
      // not called Reject. Visitors may read "Allow selection" as agreeing. (lenskart.com)
      status = 'review';
      severity = 'Medium';
      detail = `There is no button labelled Reject. "${rejectChoice.label}" refuses optional cookies only when nothing is ticked, which visitors may not realise.`;
    } else if (rejectChoice?.clicked && rejectChoice.layer === 2) {
      status = 'fail';
      severity = 'Medium';
      detail = `Rejecting requires an extra step: open "${rejectChoice.settingsLabel}", then "${rejectChoice.label}". Accepting takes one click.`;
    } else {
      status = 'fail';
      detail = `No way to reject was found. ${rejectChoice?.note || ''}`.trim();
    }
    add({
      id: 'reject-parity',
      controlId: 'DPDP-CONSENT-003',
      area: 'Consent & cookies',
      title: 'Reject is as easy as Accept',
      severity,
      status,
      detail,
      evidence: [
        `Buttons on first layer: ${(result.banner.labels || Object.values(result.banner.buttons).filter(Boolean)).map((l) => `"${l}"`).join(', ')}`,
        ...(consentStateLine && !result.banner.buttons.reject ? [consentStateLine] : []),
      ],
      legal: LEGAL.withdrawal,
      fix: 'Put a "Reject all" button on the first layer with the same size and styling as "Accept all".',
      verify: 'Count the clicks needed to reject compared with accept.',
    });
  }

  // 3b. Pre-ticked optional categories are not consent.
  const preTicked = afterReject?.choice?.preTicked || [];
  if (hasBanner && preTicked.length) {
    add({
      id: 'pre-ticked',
      controlId: 'DPDP-CONSENT-006',
      area: 'Consent & cookies',
      title: 'Optional categories are off until the visitor turns them on',
      severity: 'High',
      status: 'fail',
      detail: `${preTicked.length} optional categor${preTicked.length === 1 ? 'y is' : 'ies are'} switched on by default in the consent settings, so saving the settings without changes counts as consent.`,
      evidence: preTicked.map((name) => `Switched on by default: ${name}`),
      legal: LEGAL.consent,
      fix: 'Set every optional category (analytics, advertising, functional) to off by default. Only strictly necessary cookies may be on without a choice.',
      verify: 'Open the cookie settings in a private window and check the default state of each switch.',
    });
  }

  // 4. Reject actually stops tracking.
  if (hasBanner) {
    if (!afterReject?.choice?.clicked || falseReject) {
      add({
        id: 'reject-honoured',
        controlId: 'DPDP-CONSENT-004',
        area: 'Consent & cookies',
        title: 'Rejecting consent stops tracking',
        severity: 'High',
        status: 'not-evaluated',
        confidence: 'low',
        detail: falseReject
          ? `Not tested: there is no genuine reject option. "${rejectChoice.label}" stored consent as granted, so tracking afterwards is expected.`
          : `The scanner could not click a reject option, so this was not tested. ${afterReject?.choice?.note || ''}`.trim(),
        evidence: consentStateLine ? [consentStateLine] : [],
        legal: LEGAL.withdrawal,
        fix: 'Add a reject option, then re-scan.',
        verify: 'Reject manually in a private window and check Network and Cookies after reloading.',
      });
    } else {
      const postTrackers = afterReject.trackers.filter((t) => t.nonEssential && !t.deniedPingsOnly);
      const preKeys = new Set(preConsent.cookies.map(cookieKey));
      const newCookies = afterReject.cookies.filter((c) => c.nonEssential && !preKeys.has(cookieKey(c)));
      const leftover = afterReject.cookies.filter((c) => c.nonEssential && preKeys.has(cookieKey(c)));
      add({
        id: 'reject-honoured',
        controlId: 'DPDP-CONSENT-004',
        area: 'Consent & cookies',
        title: 'Rejecting consent stops tracking',
        severity: 'High',
        // An explicit Reject button that stores consent as granted is itself a failure.
        status: postTrackers.length || newCookies.length || grantedOnReject.length ? 'fail' : 'pass',
        confidence: afterReject.choice.method === 'layer1-selection' ? 'medium' : 'high',
        detail: postTrackers.length || newCookies.length || grantedOnReject.length
          ? `After clicking "${afterReject.choice.label}" and reloading, ${postTrackers.length} non-essential tracker(s) still fired and ${newCookies.length} new non-essential cookie(s) were set${grantedOnReject.length ? `, and the site stored consent as granted for ${grantedOnReject.join(', ')}` : ''}.`
          : `After clicking "${afterReject.choice.label}" and reloading, no non-essential trackers fired and no new non-essential cookies were set.`,
        evidence: [
          `Reject method: ${afterReject.choice.method}${afterReject.choice.note ? ` (${afterReject.choice.note})` : ''}`,
          ...(consentStateLine ? [consentStateLine] : []),
          ...postTrackers.map(trackerLine),
          ...newCookies.map((c) => `New after reject: ${cookieLine(c)}`),
        ],
        legal: LEGAL.withdrawal,
        fix: 'Make sure every listed tag checks the stored consent state on each page load, not only when the banner is first shown.',
        verify: 'Reject in a private window, reload, and confirm none of the listed requests or cookies appear.',
      });
      if (leftover.length) {
        add({
          id: 'reject-cleanup',
          controlId: 'DPDP-CONSENT-004',
          area: 'Consent & cookies',
          title: 'Cookies set before consent are removed on reject',
          severity: 'Medium',
          status: 'fail',
          detail: `${leftover.length} non-essential cookie(s) set before consent were still present after rejecting.`,
          evidence: leftover.map(cookieLine),
          legal: LEGAL.withdrawal,
          fix: 'Stop setting these before consent (see the pre-consent finding). If any must exist, delete them when the visitor rejects.',
          verify: 'After rejecting, check Application > Cookies for the listed names.',
        });
      }
      if (afterReject.bannerReshown) {
        add({
          id: 'reject-remembered',
          controlId: 'DPDP-CONSENT-004',
          area: 'Consent & cookies',
          title: 'Reject choice is remembered',
          severity: 'Low',
          status: 'review',
          confidence: 'medium',
          detail: 'The banner appeared again after rejecting and reloading. Re-asking on every page can pressure visitors into accepting.',
          legal: LEGAL.consent,
          fix: 'Store the reject choice and do not show the banner again until the notice changes or the stored choice expires.',
          verify: 'Reject, reload, and check whether the banner reappears.',
        });
      }
    }
  }

  // 5. Privacy notice reachable.
  const strongLinks = result.privacyLinks.filter((link) => link.strength === 'strong');
  if (result.browseError) {
    // The browsing visit was blocked or failed; absence of a link would be a guess.
    add({
      id: 'privacy-link', controlId: 'DPDP-NOTICE-001', area: 'Privacy notice', title: 'Privacy notice linked from the homepage',
      severity: 'High', status: 'not-evaluated', confidence: 'low',
      detail: `Not tested: ${result.browseError}`,
      legal: LEGAL.notice, fix: 'Allow-list the scanner and re-scan.', verify: 'Check the footer for a visible privacy notice link.',
    });
  } else add({
    id: 'privacy-link',
    controlId: 'DPDP-NOTICE-001',
    area: 'Privacy notice',
    title: 'Privacy notice linked from the homepage',
    severity: 'High',
    status: strongLinks.length ? 'pass' : result.privacyLinks.length ? 'review' : 'fail',
    confidence: strongLinks.length ? 'high' : 'medium',
    detail: strongLinks.length
      ? 'A privacy notice link was found on the rendered homepage. Its content is not yet analysed.'
      : result.privacyLinks.length
        ? 'Links mentioning privacy were found, but none clearly points to the privacy notice. Confirm one does.'
        : result.cookiePolicyLinks?.length
          ? 'Only a cookie policy is linked. A cookie policy does not replace a DPDP privacy notice, which must cover all personal data you collect (forms, accounts, email), the purposes, how to withdraw consent, and how to complain to the Data Protection Board.'
          : 'No link to a privacy notice was found on the rendered homepage.',
    evidence: [
      ...result.privacyLinks.map((link) => `"${link.text || '(no text)'}" -> ${link.href} (${link.strength}${link.inFooter ? ', footer' : ''})`),
      ...(result.cookiePolicyLinks || []).map((href) => `Cookie policy link (not a privacy notice): ${href}`),
      ...(result.notice?.foundBy?.startsWith('common') ? [`A privacy notice exists at ${result.notice.url} but is not linked from the homepage, so visitors cannot find it.`] : []),
      ...(result.notice?.missing ? [`No privacy notice at the usual addresses either: ${(result.notice.checked || []).slice(1).join(', ')}`] : []),
    ],
    legal: LEGAL.notice,
    fix: 'Link the privacy notice from the site footer and from every form that collects personal data.',
    verify: 'Check the footer and forms for a visible privacy notice link.',
  });

  // 6. Transport security.
  add({
    id: 'https',
    controlId: 'DPDP-SECURITY-001',
    area: 'Governance & security',
    title: 'Site served over HTTPS',
    severity: 'High',
    status: result.http.https ? 'pass' : 'fail',
    detail: result.http.https ? `Final URL uses HTTPS: ${result.finalUrl}` : `Final URL is not HTTPS: ${result.finalUrl}`,
    legal: LEGAL.security,
    fix: 'Serve every page over HTTPS and redirect HTTP to HTTPS.',
    verify: 'Visit the http:// address and confirm it redirects to https://.',
  });

  const missing = Object.entries(result.http.securityHeaders).filter(([, value]) => !value).map(([name]) => name);
  add({
    id: 'security-headers',
    controlId: 'DPDP-SECURITY-002',
    area: 'Governance & security',
    title: 'Security response headers present',
    severity: 'Low',
    status: missing.length ? 'fail' : 'pass',
    detail: missing.length ? `Missing on the homepage response: ${missing.join(', ')}.` : 'All checked security headers are present.',
    evidence: Object.entries(result.http.securityHeaders).map(([name, value]) => `${name}: ${value ? value.slice(0, 120) : '(missing)'}`),
    legal: `${LEGAL.security} Headers are a hygiene indicator, not an explicit statutory requirement.`,
    fix: 'Add the missing headers at your CDN or web server.',
    verify: 'Inspect the homepage response headers in DevTools > Network.',
  });

  if (tagManagers.length) {
    add({
      id: 'tag-manager',
      controlId: 'DPDP-CONSENT-002',
      area: 'Consent & cookies',
      title: 'Tag manager loaded before consent',
      severity: 'Low',
      status: 'review',
      confidence: 'medium',
      detail: 'A tag manager loaded before consent. That is normal, but it can fire any tag, so its consent triggers need review.',
      evidence: tagManagers.map(trackerLine),
      legal: LEGAL.consent,
      fix: 'Confirm every tag in the container has a consent-based trigger.',
      verify: 'Use Tag Assistant in a private window and check which tags fire before consent.',
    });
  }

  // Notice content: rights, sharing, retention, children, contact. Vendors are the trackers
  // actually seen on the site, so the notice can be checked for naming them.
  const seenVendors = new Map();
  for (const tracker of [...preConsent.trackers, ...(afterAccept?.trackers || [])]) {
    if (tracker.nonEssential && !seenVendors.has(tracker.vendor)) seenVendors.set(tracker.vendor, { vendor: tracker.vendor, category: tracker.category });
  }
  for (const check of analyzeNotice(result.notice, noticeText, [...seenVendors.values()])) add(check);

  const scored = checks.filter((c) => c.status === 'pass' || c.status === 'fail');
  const possible = scored.reduce((sum, c) => sum + WEIGHT[c.severity], 0);
  const earned = scored.filter((c) => c.status === 'pass').reduce((sum, c) => sum + WEIGHT[c.severity], 0);

  return {
    checks,
    score: possible ? Math.round((earned / possible) * 100) : null,
    coverage: computeCoverage(checks),
    summary: {
      passed: checks.filter((c) => c.status === 'pass').length,
      failed: checks.filter((c) => c.status === 'fail').length,
      review: checks.filter((c) => c.status === 'review').length,
      notEvaluated: checks.filter((c) => c.status === 'not-evaluated').length,
      trackersEnabledByAccept: (afterAccept?.trackers || []).filter((t) => t.nonEssential).map((t) => t.vendor),
    },
  };
}
