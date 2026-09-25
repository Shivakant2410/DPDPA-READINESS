// Tracker and cookie knowledge base.
//
// Categories:
//   advertising, analytics, session-replay, social, marketing  -> non-essential, need consent
//   tag-manager                                                  -> loader only; flagged as info
//   essential, consent, monitoring, functional                   -> not treated as tracking
//
// This is a curated starter list. To widen coverage, load the Open Cookie Database
// (https://github.com/jkwakman/Open-Cookie-Database) or DuckDuckGo Tracker Radar and
// merge them into DOMAIN_RULES / COOKIE_RULES at startup.

export const NON_ESSENTIAL = new Set(['advertising', 'analytics', 'session-replay', 'social', 'marketing']);

// Matched against the request hostname (suffix match). Optional `path` narrows the match.
const DOMAIN_RULES = [
  // Google
  { host: 'google-analytics.com', vendor: 'Google Analytics', category: 'analytics' },
  { host: 'analytics.google.com', vendor: 'Google Analytics', category: 'analytics' },
  { host: 'googletagmanager.com', path: /\/gtag\/js/, vendor: 'Google gtag.js (loader)', category: 'tag-manager' },
  { host: 'googletagmanager.com', vendor: 'Google Tag Manager', category: 'tag-manager' },
  { host: 'doubleclick.net', vendor: 'Google Ads (DoubleClick)', category: 'advertising' },
  { host: 'googleadservices.com', vendor: 'Google Ads', category: 'advertising' },
  { host: 'googlesyndication.com', vendor: 'Google AdSense', category: 'advertising' },
  { host: 'google.com', path: /^\/(pagead|ads|ccm)\//, vendor: 'Google Ads', category: 'advertising' },
  { host: 'google.co.in', path: /^\/(pagead|ads)\//, vendor: 'Google Ads', category: 'advertising' },
  // Meta
  { host: 'connect.facebook.net', vendor: 'Meta Pixel', category: 'advertising' },
  { host: 'facebook.com', path: /^\/tr\/?/, vendor: 'Meta Pixel', category: 'advertising' },
  { host: 'facebook.com', path: /^\/plugins\//, vendor: 'Facebook social plugin', category: 'social' },
  // Microsoft
  { host: 'clarity.ms', vendor: 'Microsoft Clarity', category: 'session-replay' },
  { host: 'bat.bing.com', vendor: 'Microsoft Advertising (UET)', category: 'advertising' },
  // Social ad pixels
  { host: 'snap.licdn.com', vendor: 'LinkedIn Insight Tag', category: 'advertising' },
  { host: 'px.ads.linkedin.com', vendor: 'LinkedIn Insight Tag', category: 'advertising' },
  { host: 'analytics.tiktok.com', vendor: 'TikTok Pixel', category: 'advertising' },
  { host: 'ct.pinterest.com', vendor: 'Pinterest Tag', category: 'advertising' },
  { host: 's.pinimg.com', path: /\/ct\//, vendor: 'Pinterest Tag', category: 'advertising' },
  { host: 'sc-static.net', vendor: 'Snap Pixel', category: 'advertising' },
  { host: 'tr.snapchat.com', vendor: 'Snap Pixel', category: 'advertising' },
  { host: 'redditstatic.com', path: /\/ads\//, vendor: 'Reddit Pixel', category: 'advertising' },
  { host: 'alb.reddit.com', vendor: 'Reddit Pixel', category: 'advertising' },
  { host: 'static.ads-twitter.com', vendor: 'X (Twitter) Pixel', category: 'advertising' },
  { host: 'ads-twitter.com', vendor: 'X (Twitter) Pixel', category: 'advertising' },
  { host: 't.co', vendor: 'X (Twitter) Pixel', category: 'advertising' },
  { host: 'platform.twitter.com', vendor: 'X (Twitter) widgets', category: 'social' },
  // Ad networks / retargeting
  { host: 'criteo.com', vendor: 'Criteo', category: 'advertising' },
  { host: 'criteo.net', vendor: 'Criteo', category: 'advertising' },
  { host: 'taboola.com', vendor: 'Taboola', category: 'advertising' },
  { host: 'outbrain.com', vendor: 'Outbrain', category: 'advertising' },
  { host: 'adnxs.com', vendor: 'Xandr (AppNexus)', category: 'advertising' },
  { host: 'quantserve.com', vendor: 'Quantcast', category: 'advertising' },
  { host: 'scorecardresearch.com', vendor: 'Comscore', category: 'analytics' },
  { host: 'amazon-adsystem.com', vendor: 'Amazon Ads', category: 'advertising' },
  { host: 'rubiconproject.com', vendor: 'Magnite', category: 'advertising' },
  { host: 'pubmatic.com', vendor: 'PubMatic', category: 'advertising' },
  { host: 'inmobi.com', vendor: 'InMobi', category: 'advertising' },
  { host: 'id5-sync.com', vendor: 'ID5', category: 'advertising' },
  { host: 'cxense.com', vendor: 'Piano (Cxense)', category: 'advertising' },
  { host: 'dotmetrics.net', vendor: 'DotMetrics', category: 'analytics' },
  { host: 'casalemedia.com', vendor: 'Index Exchange', category: 'advertising' },
  { host: 'openx.net', vendor: 'OpenX', category: 'advertising' },
  { host: '3lift.com', vendor: 'TripleLift', category: 'advertising' },
  { host: 'bidswitch.net', vendor: 'BidSwitch', category: 'advertising' },
  { host: 'rlcdn.com', vendor: 'LiveRamp', category: 'advertising' },
  { host: 'adsrvr.org', vendor: 'The Trade Desk', category: 'advertising' },
  { host: 'demdex.net', vendor: 'Adobe Audience Manager', category: 'advertising' },
  { host: 'omtrdc.net', vendor: 'Adobe Analytics', category: 'analytics' },
  { host: 'everesttech.net', vendor: 'Adobe Advertising', category: 'advertising' },
  { host: 'moatads.com', vendor: 'Oracle Moat', category: 'advertising' },
  { host: 'adsafeprotected.com', vendor: 'Integral Ad Science', category: 'advertising' },
  { host: 'doubleverify.com', vendor: 'DoubleVerify', category: 'advertising' },
  { host: 'teads.tv', vendor: 'Teads', category: 'advertising' },
  { host: 'smartadserver.com', vendor: 'Equativ', category: 'advertising' },
  { host: 'yieldmo.com', vendor: 'Yieldmo', category: 'advertising' },
  { host: 'sharethrough.com', vendor: 'Sharethrough', category: 'advertising' },
  { host: 'media.net', vendor: 'Media.net', category: 'advertising' },
  { host: 'colombiaonline.com', vendor: 'Colombia (Times Internet)', category: 'advertising' },
  { host: 'izooto.com', vendor: 'iZooto', category: 'marketing' },
  { host: 'onesignal.com', vendor: 'OneSignal', category: 'marketing' },
  // Product analytics
  { host: 'segment.com', vendor: 'Segment', category: 'analytics' },
  { host: 'segment.io', vendor: 'Segment', category: 'analytics' },
  { host: 'mixpanel.com', vendor: 'Mixpanel', category: 'analytics' },
  { host: 'mxpnl.com', vendor: 'Mixpanel', category: 'analytics' },
  { host: 'amplitude.com', vendor: 'Amplitude', category: 'analytics' },
  { host: 'heapanalytics.com', vendor: 'Heap', category: 'analytics' },
  { host: 'heap.io', vendor: 'Heap', category: 'analytics' },
  { host: 'posthog.com', vendor: 'PostHog', category: 'analytics' },
  { host: 'mc.yandex.ru', vendor: 'Yandex Metrica', category: 'analytics' },
  { host: 'plausible.io', vendor: 'Plausible', category: 'analytics' },
  { host: 'visualwebsiteoptimizer.com', vendor: 'VWO', category: 'analytics' },
  { host: 'optimizely.com', vendor: 'Optimizely', category: 'analytics' },
  // Session replay / heatmaps
  { host: 'hotjar.com', vendor: 'Hotjar', category: 'session-replay' },
  { host: 'hotjar.io', vendor: 'Hotjar', category: 'session-replay' },
  { host: 'fullstory.com', vendor: 'FullStory', category: 'session-replay' },
  { host: 'mouseflow.com', vendor: 'Mouseflow', category: 'session-replay' },
  { host: 'crazyegg.com', vendor: 'Crazy Egg', category: 'session-replay' },
  { host: 'smartlook.com', vendor: 'Smartlook', category: 'session-replay' },
  { host: 'luckyorange.com', vendor: 'Lucky Orange', category: 'session-replay' },
  { host: 'luckyorange.net', vendor: 'Lucky Orange', category: 'session-replay' },
  // Marketing automation / engagement (common in India)
  { host: 'hs-analytics.net', vendor: 'HubSpot', category: 'marketing' },
  { host: 'hs-scripts.com', vendor: 'HubSpot', category: 'marketing' },
  { host: 'hsadspixel.net', vendor: 'HubSpot Ads', category: 'advertising' },
  { host: 'track.hubspot.com', vendor: 'HubSpot', category: 'marketing' },
  { host: 'clevertap-prod.com', vendor: 'CleverTap', category: 'marketing' },
  { host: 'wzrkt.com', vendor: 'CleverTap', category: 'marketing' },
  { host: 'moengage.com', vendor: 'MoEngage', category: 'marketing' },
  { host: 'webengage.com', vendor: 'WebEngage', category: 'marketing' },
  { host: 'webengage.co', vendor: 'WebEngage', category: 'marketing' },
  { host: 'netcoresmartech.com', vendor: 'Netcore Smartech', category: 'marketing' },
  { host: 'marketo.net', vendor: 'Marketo', category: 'marketing' },
  { host: 'mktoresp.com', vendor: 'Marketo', category: 'marketing' },
  { host: 'pardot.com', vendor: 'Salesforce Pardot', category: 'marketing' },
  { host: 'zoho.in', path: /\/(salesiq|pagesense)/, vendor: 'Zoho SalesIQ / PageSense', category: 'marketing' },
  // Attribution
  { host: 'branch.io', vendor: 'Branch', category: 'advertising' },
  { host: 'appsflyer.com', vendor: 'AppsFlyer', category: 'advertising' },
  { host: 'adjust.com', vendor: 'Adjust', category: 'advertising' },
  // Consent platforms (loading these is expected)
  { host: 'cookielaw.org', vendor: 'OneTrust', category: 'consent' },
  { host: 'onetrust.com', vendor: 'OneTrust', category: 'consent' },
  { host: 'cookiebot.com', vendor: 'Cookiebot', category: 'consent' },
  { host: 'cookieyes.com', vendor: 'CookieYes', category: 'consent' },
  { host: 'privacy-mgmt.com', vendor: 'Sourcepoint', category: 'consent' },
  { host: 'usercentrics.eu', vendor: 'Usercentrics', category: 'consent' },
  { host: 'didomi.io', vendor: 'Didomi', category: 'consent' },
  { host: 'osano.com', vendor: 'Osano', category: 'consent' },
  { host: 'iubenda.com', vendor: 'iubenda', category: 'consent' },
  { host: 'consently.in', vendor: 'Consently', category: 'consent' },
  // Monitoring / functional (not tracking by default)
  { host: 'sentry.io', vendor: 'Sentry', category: 'monitoring' },
  { host: 'nr-data.net', vendor: 'New Relic', category: 'monitoring' },
  { host: 'intercom.io', vendor: 'Intercom', category: 'functional' },
  { host: 'intercomcdn.com', vendor: 'Intercom', category: 'functional' },
  { host: 'tawk.to', vendor: 'tawk.to', category: 'functional' },
  { host: 'razorpay.com', vendor: 'Razorpay', category: 'essential' },
  { host: 'recaptcha.net', vendor: 'Google reCAPTCHA', category: 'essential' },
  { host: 'gstatic.com', vendor: 'Google static assets', category: 'essential' },
  { host: 'fonts.googleapis.com', vendor: 'Google Fonts', category: 'functional' },
];

// Matched against cookie names.
const COOKIE_RULES = [
  { name: /^_ga(_.*)?$/, vendor: 'Google Analytics', category: 'analytics' },
  { name: /^_gid$/, vendor: 'Google Analytics', category: 'analytics' },
  { name: /^_gat/, vendor: 'Google Analytics', category: 'analytics' },
  { name: /^__utm[abcvz]$/, vendor: 'Google Analytics (legacy)', category: 'analytics' },
  { name: /^_gcl_(au|aw|dc|gb)$/, vendor: 'Google Ads', category: 'advertising' },
  { name: /^(IDE|DSID|test_cookie|__gads|__gpi|__eoi)$/, vendor: 'Google Ads', category: 'advertising' },
  { name: /^(NID|1P_JAR|AEC)$/, vendor: 'Google', category: 'advertising' },
  { name: /^_fb[pc]$/, vendor: 'Meta Pixel', category: 'advertising' },
  { name: /^fr$/, vendor: 'Meta', category: 'advertising' },
  { name: /^_hj/, vendor: 'Hotjar', category: 'session-replay' },
  { name: /^_cl(ck|sk)$/, vendor: 'Microsoft Clarity', category: 'session-replay' },
  { name: /^(MUID|ANONCHK|SM|CLID)$/, vendor: 'Microsoft', category: 'advertising' },
  { name: /^_uet(sid|vid)$/, vendor: 'Microsoft Advertising (UET)', category: 'advertising' },
  { name: /^(li_sugr|bcookie|bscookie|lidc|UserMatchHistory|AnalyticsSyncHistory|li_fat_id|ln_or)$/, vendor: 'LinkedIn', category: 'advertising' },
  { name: /^_ttp$|^_tt_enable_cookie$|^ttcsid/, vendor: 'TikTok Pixel', category: 'advertising' },
  { name: /^_pin_unauth$|^_pinterest_/, vendor: 'Pinterest Tag', category: 'advertising' },
  { name: /^_scid|^_sctr$/, vendor: 'Snap Pixel', category: 'advertising' },
  { name: /^_rdt_uuid$/, vendor: 'Reddit Pixel', category: 'advertising' },
  { name: /^(cto_bundle|cto_bidid)$/, vendor: 'Criteo', category: 'advertising' },
  { name: /^__qca$/, vendor: 'Quantcast', category: 'advertising' },
  { name: /^ajs_(anonymous|user)_id$/, vendor: 'Segment', category: 'analytics' },
  { name: /^mp_.*_mixpanel$/, vendor: 'Mixpanel', category: 'analytics' },
  { name: /^(amp_|AMP_)/, vendor: 'Amplitude', category: 'analytics' },
  { name: /^_hp2_/, vendor: 'Heap', category: 'analytics' },
  { name: /^ph_.*_posthog$/, vendor: 'PostHog', category: 'analytics' },
  { name: /^_ym_/, vendor: 'Yandex Metrica', category: 'analytics' },
  { name: /^_vwo|^_vis_opt/, vendor: 'VWO', category: 'analytics' },
  { name: /^(hubspotutk|__hstc|__hssc|__hssrc)$/, vendor: 'HubSpot', category: 'marketing' },
  { name: /^_mkto_trk$/, vendor: 'Marketo', category: 'marketing' },
  { name: /^WZRK_/, vendor: 'CleverTap', category: 'marketing' },
  { name: /^_we_/, vendor: 'WebEngage', category: 'marketing' },
  { name: /^_fs_|^fs_uid$/, vendor: 'FullStory', category: 'session-replay' },
  // Consent-state cookies are expected before and after a choice.
  { name: /^(OptanonConsent|OptanonAlertBoxClosed)$/, vendor: 'OneTrust', category: 'consent' },
  { name: /^CookieConsent$/, vendor: 'Cookiebot', category: 'consent' },
  { name: /^cookieyes-consent$/, vendor: 'CookieYes', category: 'consent' },
  { name: /^(didomi_token|euconsent-v2)$/, vendor: 'Didomi / IAB TCF', category: 'consent' },
  { name: /^cmplz_/, vendor: 'Complianz', category: 'consent' },
  { name: /^(uc_|usercentrics)/, vendor: 'Usercentrics', category: 'consent' },
  { name: /^osano_consentmanager/, vendor: 'Osano', category: 'consent' },
  { name: /^(notice_behavior|notice_gdpr_prefs|cmapi_)/, vendor: 'TrustArc', category: 'consent' },
  { name: /^cookie_notice_accepted$/, vendor: 'Cookie Notice', category: 'consent' },
  // Common essential cookies
  { name: /^(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid|laravel_session|sessionid)$/i, vendor: 'Session', category: 'essential' },
  { name: /^(csrftoken|XSRF-TOKEN|_csrf|csrf_token)$/i, vendor: 'CSRF protection', category: 'essential' },
  { name: /^(__cf_bm|cf_clearance|_cfuvid|__cflb)$/, vendor: 'Cloudflare', category: 'essential' },
  { name: /^(AWSALB|AWSALBCORS|AWSELB)/, vendor: 'AWS load balancer', category: 'essential' },
  { name: /^(ak_bmsc|bm_sz|_abck|bm_sv|bm_mi)$/, vendor: 'Akamai Bot Manager', category: 'essential' },
];

// Second-level suffixes where the registrable domain has three labels.
const MULTI_PART_SUFFIXES = new Set([
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'edu.in', 'res.in', 'firm.in', 'gen.in', 'ind.in',
  // RBI moved Indian banks to *.bank.in (icici.bank.in, hdfc.bank.in) and other regulated
  // financial entities to *.fin.in. Without these, every bank was treated as one site.
  'bank.in', 'fin.in',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'com.sg', 'com.br', 'co.jp', 'com.cn',
]);

export function registrableDomain(hostname) {
  const labels = hostname.toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length <= 2 || /^\d+$/.test(labels.at(-1))) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  return MULTI_PART_SUFFIXES.has(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
}

function hostMatches(hostname, ruleHost) {
  return hostname === ruleHost || hostname.endsWith(`.${ruleHost}`);
}

export function classifyRequest(url) {
  let parsed;
  try { parsed = new URL(url); } catch { return null; }
  const host = parsed.hostname.toLowerCase();
  for (const rule of DOMAIN_RULES) {
    if (!hostMatches(host, rule.host)) continue;
    if (rule.path && !rule.path.test(parsed.pathname)) continue;
    return { vendor: rule.vendor, category: rule.category, consentMode: googleConsentMode(parsed) };
  }
  return null;
}

export function classifyCookie(cookie) {
  for (const rule of COOKIE_RULES) {
    if (rule.name.test(cookie.name)) return { vendor: rule.vendor, category: rule.category };
  }
  // Unknown name: fall back to who set it, using host-wide domain rules only.
  const domain = cookie.domain.replace(/^\./, '').toLowerCase();
  for (const rule of DOMAIN_RULES) {
    if (!rule.path && hostMatches(domain, rule.host)) return { vendor: rule.vendor, category: rule.category };
  }
  return null;
}

// Google Consent Mode sends `gcs=G1xy` on GA / Ads hits: x = ad_storage, y = analytics_storage.
// G100 means both denied: a cookieless ping. That is a much weaker signal than a full hit,
// so we report it separately instead of calling it tracking.
function googleConsentMode(parsed) {
  const gcs = parsed.searchParams.get('gcs');
  if (!gcs || !/^G1[01-]{2}$/.test(gcs)) return null;
  return { raw: gcs, adStorage: gcs[2] === '1', analyticsStorage: gcs[3] === '1' };
}
