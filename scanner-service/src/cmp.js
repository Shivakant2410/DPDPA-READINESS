// Consent banner detection and interaction.
//
// Strategy: try known consent-management platforms (CMPs) by selector first, since their
// buttons are reliable. Fall back to a generic heuristic that finds a visible overlay
// mentioning cookies/consent and classifies its buttons by label. Every frame is searched,
// because several CMPs (TrustArc, Sourcepoint) render inside iframes.

const KNOWN_CMPS = [
  {
    name: 'OneTrust',
    banner: '#onetrust-banner-sdk',
    accept: '#onetrust-accept-btn-handler',
    reject: '#onetrust-reject-all-handler',
    settings: '#onetrust-pc-btn-handler',
    layer2Reject: '#onetrust-pc-sdk .ot-pc-refuse-all-handler',
    layer2Save: '#onetrust-pc-sdk .save-preference-btn-handler',
  },
  {
    name: 'Cookiebot',
    banner: '#CybotCookiebotDialog',
    accept: '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll, #CybotCookiebotDialogBodyButtonAccept',
    reject: '#CybotCookiebotDialogBodyButtonDecline',
    settings: '#CybotCookiebotDialogBodyButtonDetails',
  },
  {
    name: 'CookieYes',
    banner: '.cky-consent-container',
    accept: '.cky-consent-container .cky-btn-accept',
    reject: '.cky-consent-container .cky-btn-reject',
    settings: '.cky-consent-container .cky-btn-customize',
    layer2Reject: '.cky-preference-center .cky-btn-reject',
    layer2Save: '.cky-preference-center .cky-btn-preferences',
  },
  {
    name: 'Didomi',
    banner: '#didomi-notice',
    accept: '#didomi-notice-agree-button',
    reject: '#didomi-notice-disagree-button, .didomi-continue-without-agreeing',
    settings: '#didomi-notice-learn-more-button',
  },
  {
    name: 'Usercentrics',
    banner: '#usercentrics-root [data-testid="uc-default-banner"], #usercentrics-cmp-ui',
    accept: '[data-testid="uc-accept-all-button"]',
    reject: '[data-testid="uc-deny-all-button"]',
    settings: '[data-testid="uc-more-button"]',
  },
  {
    name: 'Complianz',
    banner: '.cmplz-cookiebanner',
    accept: '.cmplz-cookiebanner .cmplz-accept',
    reject: '.cmplz-cookiebanner .cmplz-deny',
    settings: '.cmplz-cookiebanner .cmplz-view-preferences',
  },
  {
    name: 'Osano',
    banner: '.osano-cm-dialog',
    accept: '.osano-cm-accept-all, .osano-cm-accept',
    reject: '.osano-cm-denyAll, .osano-cm-deny',
    settings: '.osano-cm-manage',
  },
  {
    name: 'Termly',
    banner: '[data-tid="banner"], #termly-code-snippet-support',
    accept: '[data-tid="banner-accept"]',
    reject: '[data-tid="banner-decline"]',
    settings: '[data-tid="banner-preferences"]',
  },
  {
    name: 'TrustArc',
    banner: '#truste-consent-track',
    accept: '#truste-consent-button',
    reject: '#truste-consent-required',
    settings: '#truste-show-consent',
  },
  {
    name: 'iubenda',
    banner: '#iubenda-cs-banner',
    accept: '.iubenda-cs-accept-btn',
    reject: '.iubenda-cs-reject-btn',
    settings: '.iubenda-cs-customize-btn',
  },
  {
    name: 'Cookie Notice (WordPress)',
    banner: '#cookie-notice',
    accept: '#cn-accept-cookie',
    reject: '#cn-refuse-cookie',
    // The plugin's close icon can be configured to record acceptance.
    closeAccepts: '#cn-close-notice[data-cookie-set="accept"]',
  },
  {
    name: 'GDPR Cookie Compliance (WordPress)',
    banner: '#moove_gdpr_cookie_info_bar',
    accept: '.moove-gdpr-infobar-allow-all',
    reject: '.moove-gdpr-infobar-reject-btn',
    settings: '.moove-gdpr-infobar-settings-btn',
  },
  {
    name: 'Klaro',
    banner: '.klaro .cookie-notice, .klaro .cookie-modal',
    accept: '.klaro .cm-btn-accept-all, .klaro .cm-btn-success',
    reject: '.klaro .cn-decline, .klaro .cm-btn-decline',
    settings: '.klaro .cn-learn-more',
  },
];

const TAG_ATTR = 'data-dpdp-scan';
// Serialisable subset passed into the page for the generic detector.
const KNOWN_CMP_SIGNATURES = KNOWN_CMPS.map(({ name, banner, closeAccepts }) => ({ name, banner, closeAccepts: closeAccepts || null }));

// Runs inside the page. Finds the most likely consent overlay and tags its buttons.
// Kept self-contained because it is serialised into the browser.
function tagGenericBanner({ tagAttr, layer, known }) {
  const ACCEPT = /^\s*(accept(\s+all)?(\s+cookies)?|allow(\s+all)?(\s+cookies)?|i\s+accept|i\s+agree|agree(\s+(and|&)\s+(close|continue|proceed))?|yes,?\s+i\s+agree|got\s+it|ok(ay)?|understood|स्वीकार(\s+करें)?|सहमत(\s+हूँ)?)\s*[!.]?\s*$/i;
  const REJECT = /(reject|decline|deny|refuse|disagree|do\s+not\s+(accept|agree)|don'?t\s+(accept|agree)|(strictly\s+)?necessary(\s+cookies)?\s+only|only\s+(strictly\s+)?(necessary|essential)|essential(\s+cookies)?\s+only|continue\s+without\s+(accepting|agreeing)|अस्वीकार)/i;
  const SETTINGS = /(settings|preferences|customi[sz]e|manage|more\s+options|cookie\s+choices|let\s+me\s+choose|प्राथमिकताएं|सेटिंग्स)/i;
  // Includes "Allow selection" (GoTrust on lenskart.com): with nothing ticked it refuses optional cookies.
  const SAVE = /^((save|confirm)(\s+(my|your))?(\s+(choices?|preferences|settings|selection))?|allow\s+(selection|selected))(\s+(and|&)\s+(exit|close))?$/i;
  const KEYWORDS = /cookie|consent|tracking|personal\s+data|privacy|कुकी|सहमति|गोपनीयता/i;
  const CLICKABLE = 'button, a, [role="button"], input[type="button"], input[type="submit"]';

  document.querySelectorAll(`[${tagAttr}]`).forEach((el) => el.removeAttribute(tagAttr));

  const all = [];
  const walk = (root) => {
    for (const el of root.querySelectorAll('*')) {
      all.push(el);
      if (el.shadowRoot) walk(el.shadowRoot);
    }
  };
  walk(document);

  const isVisible = (el) => {
    const rect = el.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) return false;
    const style = getComputedStyle(el);
    return style.visibility !== 'hidden' && style.display !== 'none' && Number(style.opacity) > 0.05;
  };
  const labelOf = (el) => (el.innerText || el.value || el.getAttribute('aria-label') || el.title || '').replace(/\s+/g, ' ').trim();
  const hintOf = (el) => `${el.id} ${typeof el.className === 'string' ? el.className : ''} ${el.getAttribute('aria-label') || ''}`;
  // Must match noticeTextOf below; duplicated because this function is serialised into the page.
  const noticeText = (root) => {
    const parts = [];
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      if (node.parentElement?.closest(CLICKABLE)) continue;
      const text = node.textContent.replace(/\s+/g, ' ').trim();
      if (text) parts.push(text);
    }
    return parts.join(' ').slice(0, 600);
  };

  const containers = all.filter((el) => {
    const style = getComputedStyle(el);
    const overlay = style.position === 'fixed' || style.position === 'sticky'
      || el.getAttribute('role') === 'dialog' || el.getAttribute('role') === 'alertdialog'
      || el.getAttribute('aria-modal') === 'true';
    return (overlay || /cookie|consent|gdpr|cmp|privacy/i.test(hintOf(el))) && isVisible(el);
  });

  let best = null;
  for (const el of containers) {
    const text = (el.innerText || '').trim();
    if (!KEYWORDS.test(text) || text.length > 5000) continue;
    const buttons = [...el.querySelectorAll(CLICKABLE)].filter(isVisible);
    if (!buttons.length) continue;
    const labels = buttons.map(labelOf);
    const hasChoice = labels.some((l) => ACCEPT.test(l) || REJECT.test(l) || (layer === 2 && SAVE.test(l)));
    if (!hasChoice) continue;
    // Prefer the tightest container that still holds the choice buttons.
    if (!best || text.length < best.text.length) best = { el, text, buttons };
  }
  if (!best) return null;

  // If this overlay belongs to a known platform, say so, so the result does not depend on
  // which detector happened to see the banner first (they race while a slow page settles).
  let knownCmp = null;
  let closeAccepts = false;
  for (const cmp of known) {
    let root = null;
    try { root = best.el.closest(cmp.banner) || best.el.querySelector(cmp.banner); } catch { continue; }
    if (!root) continue;
    knownCmp = cmp.name;
    try { closeAccepts = Boolean(cmp.closeAccepts && (root.matches(cmp.closeAccepts) || root.querySelector(cmp.closeAccepts))); } catch { /* bad selector */ }
    break;
  }

  const result = { knownCmp, closeAccepts, text: noticeText(best.el), accept: null, reject: null, settings: null, save: null, allLabels: [] };
  for (const button of best.buttons) {
    const label = labelOf(button);
    if (!label || label.length > 60) continue;
    result.allLabels.push(label);
    let role = null;
    if (REJECT.test(label)) role = 'reject';
    else if (ACCEPT.test(label)) role = 'accept';
    else if (SAVE.test(label)) role = 'save';
    else if (SETTINGS.test(label)) role = 'settings';
    // Prefer "Allow all" / "Accept all" over a plain "OK" when both are present.
    const upgradeAccept = role === 'accept' && result.accept && !/\ball\b/i.test(result.accept) && /\ball\b/i.test(label);
    if (upgradeAccept) document.querySelectorAll(`[${tagAttr}="accept"]`).forEach((el) => el.removeAttribute(tagAttr));
    if (role && (!result[role] || upgradeAccept)) {
      button.setAttribute(tagAttr, role);
      result[role] = label;
    }
  }
  return result;
}

async function visibleLocator(frame, selector) {
  if (!selector) return null;
  try {
    const locator = frame.locator(selector);
    const count = Math.min(await locator.count(), 5);
    for (let i = 0; i < count; i += 1) {
      const candidate = locator.nth(i);
      if (await candidate.isVisible()) return candidate;
    }
  } catch {
    // Detached frames and cross-origin quirks: treat as not found.
  }
  return null;
}

async function labelOf(locator) {
  try {
    const text = (await locator.innerText({ timeout: 1000 })).replace(/\s+/g, ' ').trim();
    return text || (await locator.getAttribute('aria-label')) || (await locator.getAttribute('value')) || '(unlabelled)';
  } catch {
    return '(unlabelled)';
  }
}

/**
 * Find the consent banner on the page.
 * Returns null, or { cmp, frameUrl, text, controls: { accept, reject, settings, save } }
 * where each control is { label, locator } or null.
 */
export async function detectBanner(page, { layer = 1 } = {}) {
  for (const frame of page.frames()) {
    for (const cmp of KNOWN_CMPS) {
      const banner = await visibleLocator(frame, cmp.banner);
      // Layer 2 (preference centre) often replaces the banner, so do not require it there.
      if (!banner && layer === 1) continue;
      const selectors = layer === 1
        ? { accept: cmp.accept, reject: cmp.reject, settings: cmp.settings }
        : { reject: cmp.layer2Reject || cmp.reject, save: cmp.layer2Save };
      const controls = {};
      for (const [role, selector] of Object.entries(selectors)) {
        const locator = await visibleLocator(frame, selector);
        controls[role] = locator ? { label: await labelOf(locator), locator } : null;
      }
      if (!banner && !Object.values(controls).some(Boolean)) continue;
      let text = '';
      try { text = banner ? await banner.evaluate(noticeTextOf) : ''; } catch { /* ignore */ }
      const closeAccepts = Boolean(await visibleLocator(frame, cmp.closeAccepts));
      return { cmp: cmp.name, frameUrl: frame.url(), text, controls, closeAccepts };
    }
  }

  for (const frame of page.frames()) {
    let found = null;
    try {
      found = await frame.evaluate(tagGenericBanner, { tagAttr: TAG_ATTR, layer, known: KNOWN_CMP_SIGNATURES });
    } catch {
      continue;
    }
    if (!found) continue;
    const controls = {};
    for (const role of ['accept', 'reject', 'settings', 'save']) {
      controls[role] = found[role] ? { label: found[role], locator: frame.locator(`[${TAG_ATTR}="${role}"]`).first() } : null;
    }
    return {
      cmp: found.knownCmp || 'Generic / custom banner', frameUrl: frame.url(), text: found.text, controls, labels: found.allLabels,
      closeAccepts: found.closeAccepts,
    };
  }
  return null;
}

/** Wait for a banner to appear; many load a few seconds after the page. */
export async function waitForBanner(page, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const banner = await detectBanner(page);
    if (banner) return banner;
    await page.waitForTimeout(750);
  }
  return null;
}

async function click(control) {
  await control.locator.scrollIntoViewIfNeeded({ timeout: 2000 }).catch(() => {});
  await control.locator.click({ timeout: 5000 });
}

/**
 * Make a consent choice. Returns
 * { clicked, layer, label, method, note }
 * method: 'layer1' | 'layer2-reject' | 'layer2-save-defaults'
 */
export async function makeChoice(page, choice) {
  const banner = await waitForBanner(page);
  if (!banner) return { clicked: false, note: 'No consent banner found.' };

  const direct = banner.controls[choice];
  if (direct) {
    await click(direct);
    return { clicked: true, layer: 1, label: direct.label, method: 'layer1', cmp: banner.cmp };
  }
  if (choice === 'accept') return { clicked: false, cmp: banner.cmp, note: 'Banner found but no accept button could be identified.' };

  // No Reject button, but a first-layer "Allow selection": untick everything optional and use it.
  if (banner.controls.save) {
    const preTicked = await untickOptional(page);
    await click(banner.controls.save);
    return {
      clicked: true, layer: 1, label: banner.controls.save.label, method: 'layer1-selection', cmp: banner.cmp, preTicked,
      note: `No button labelled Reject; used "${banner.controls.save.label}" with every optional category unticked.`,
    };
  }

  // No first-layer reject: open the settings layer and look for reject, then for save-with-defaults.
  if (!banner.controls.settings) {
    return { clicked: false, cmp: banner.cmp, note: 'Banner offers no reject option and no settings layer.' };
  }
  await click(banner.controls.settings);
  await page.waitForTimeout(1500);
  const layer2 = await detectBanner(page, { layer: 2 });
  if (layer2?.controls.reject) {
    await click(layer2.controls.reject);
    return { clicked: true, layer: 2, label: layer2.controls.reject.label, method: 'layer2-reject', cmp: banner.cmp, settingsLabel: banner.controls.settings.label };
  }
  if (layer2?.controls.save) {
    // Saving the defaults is only a reject if the defaults are off. On freshworks.com every
    // optional category was pre-ticked, so "Confirm My Choices" accepted everything.
    const preTicked = await untickOptional(page);
    await click(layer2.controls.save);
    return {
      clicked: true, layer: 2, label: layer2.controls.save.label, method: 'layer2-save-unticked', cmp: banner.cmp,
      settingsLabel: banner.controls.settings.label, preTicked,
      note: preTicked.length
        ? `No reject button; ${preTicked.length} optional categor${preTicked.length === 1 ? 'y was' : 'ies were'} switched on by default, so the scanner switched them off before saving.`
        : 'No reject button; saved the settings layer with every optional category off.',
    };
  }
  return { clicked: false, cmp: banner.cmp, note: `Opened "${banner.controls.settings.label}" but found no reject or save option.` };
}

// Switches off every optional consent category that is on, across all frames, and returns the
// names of those that were pre-ticked. Strictly-necessary and locked categories are left alone.
async function untickOptional(page) {
  const names = [];
  for (const frame of page.frames()) {
    const found = await frame.evaluate(() => {
      const inConsentUi = (el) => el.closest('[id*="onetrust" i], [id*="consent" i], [class*="consent" i], [id*="cookie" i], [class*="cookie" i], [id*="cmp" i], [class*="cmp" i], [id*="usercentrics" i], [role="dialog"], [aria-modal="true"]');
      const nameOf = (el) => {
        const label = el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
        if (label && label.textContent.trim()) return label.textContent;
        for (let node = el.parentElement, i = 0; node && i < 5; node = node.parentElement, i += 1) {
          const heading = node.querySelector('h2, h3, h4, h5, strong, [class*="title" i], [class*="header" i]');
          if (heading && heading.textContent.trim()) return heading.textContent;
        }
        return el.getAttribute('aria-label') || el.id || 'optional category';
      };
      const toggles = [
        ...[...document.querySelectorAll('input[type="checkbox"]')].filter((i) => i.checked && !i.disabled),
        ...[...document.querySelectorAll('[role="switch"][aria-checked="true"]')].filter((s) => s.getAttribute('aria-disabled') !== 'true'),
      ].filter((el) => inConsentUi(el) && !/vendor|select-all|leg-|legitimate/i.test(`${el.id} ${el.className}`));
      const unticked = [];
      for (const el of toggles) {
        const name = nameOf(el).replace(/\s+/g, ' ').trim().slice(0, 60);
        if (/necessary|essential|required|always\s+active|C0001/i.test(`${name} ${el.id}`)) continue;
        el.click();
        unticked.push(name);
      }
      return unticked;
    }).catch(() => []);
    names.push(...found);
  }
  return [...new Set(names)];
}

export function describeBanner(banner) {
  if (!banner) return null;
  const summary = {};
  for (const [role, control] of Object.entries(banner.controls)) summary[role] = control ? control.label : null;
  return {
    cmp: banner.cmp, frameUrl: banner.frameUrl, text: banner.text, buttons: summary, labels: banner.labels,
    closeAccepts: Boolean(banner.closeAccepts),
  };
}

// The banner's notice wording without button labels, with spaces between elements.
// innerText on inline/flex layouts runs "…happy with it.Accept Cookies" together.
function noticeTextOf(root) {
  const parts = [];
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    if (node.parentElement?.closest('button, a, [role="button"], input')) continue;
    const text = node.textContent.replace(/\s+/g, ' ').trim();
    if (text) parts.push(text);
  }
  return parts.join(' ').slice(0, 600);
}
